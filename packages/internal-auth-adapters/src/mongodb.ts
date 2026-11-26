import {
  MongoServerError,
  ObjectId,
  type Db,
  type IndexDescriptionInfo,
  type Collection,
} from 'mongodb';
import { decodeBytes32 } from '@pichu/internal-auth';
import { internalCallerNameSchema, internalEnvironmentSchema } from '@pichu/contracts';
import { NonceStoreUnavailable, type NonceStore, type NonceReservation } from './types.js';
import { performance } from 'node:perf_hooks';

export const NONCE_COLLECTION = 'internal_request_nonces';
export const NONCE_INDEXES = [
  {
    name: 'internal_nonce_unique',
    key: { environment: 1, sender: 1, audience: 1, nonce: 1 },
    unique: true,
  },
  { name: 'internal_nonce_expiry', key: { expiresAt: 1 }, expireAfterSeconds: 0 },
] as const;

export interface NonceDocument {
  environment: string;
  sender: string;
  audience: string;
  nonce: string;
  acceptedAt: Date;
  expiresAt: Date;
}

function matchesKey(index: IndexDescriptionInfo, expected: Record<string, number>): boolean {
  return JSON.stringify(Object.entries(index.key)) === JSON.stringify(Object.entries(expected));
}

/** Checks actual listIndexes output, including options that could weaken coverage. */
export function validateNonceIndexes(indexes: readonly IndexDescriptionInfo[]): void {
  const complete = (index: IndexDescriptionInfo) =>
    !index.sparse &&
    !index.partialFilterExpression &&
    (!index.collation || index.collation.locale === 'simple');
  const unique = indexes.some(
    (index) =>
      matchesKey(index, NONCE_INDEXES[0].key) &&
      index.unique === true &&
      complete(index) &&
      index.expireAfterSeconds === undefined,
  );
  const ttl = indexes.some(
    (index) =>
      matchesKey(index, NONCE_INDEXES[1].key) &&
      index.expireAfterSeconds === 0 &&
      !index.unique &&
      complete(index),
  );
  if (!unique || !ttl) throw new NonceStoreUnavailable();
}

/** Explicit deployment operation; never called by readiness or request admission. */
export async function createNonceIndexes(db: Db): Promise<void> {
  try {
    await db
      .collection<NonceDocument>(NONCE_COLLECTION, {
        writeConcern: { w: 'majority', journal: true, wtimeoutMS: 500 },
      })
      .createIndexes(
        NONCE_INDEXES.map((index) => ({ ...index, key: { ...index.key } })),
        { timeoutMS: 5000 },
      );
  } catch {
    throw new NonceStoreUnavailable();
  }
}

/** The receiver supplies its OWN Db. No URI, environment loading or shared connection. */
export class MongoNonceStore implements NonceStore {
  constructor(private readonly dbProvider: Db | (() => Db)) {}

  private get db(): Db {
    const db = typeof this.dbProvider === 'function' ? this.dbProvider() : this.dbProvider;
    if (!db) throw new NonceStoreUnavailable();
    return db;
  }

  private get collection(): Collection<NonceDocument> {
    return this.db.collection<NonceDocument>(NONCE_COLLECTION);
  }

  async assertReady(): Promise<void> {
    try {
      const hello = await this.db.admin().command({ hello: 1 }, { timeoutMS: 500 });
      if (typeof hello.setName !== 'string' || hello.isWritablePrimary !== true)
        throw new NonceStoreUnavailable();
      validateNonceIndexes(await this.collection.listIndexes({ timeoutMS: 500 }).toArray());
    } catch {
      throw new NonceStoreUnavailable();
    }
  }

  async reserve(input: NonceReservation, signal: AbortSignal): Promise<'reserved' | 'replay'> {
    const end = performance.now() + 500;
    const controller = new AbortController();
    const combined = AbortSignal.any([signal, controller.signal]);
    let timer: ReturnType<typeof setTimeout> | undefined;
    let abort: (() => void) | undefined;
    try {
      const result = await Promise.race([
        this.performReservation(input, combined),
        new Promise<never>((_resolve, reject) => {
          abort = () => reject(new NonceStoreUnavailable());
          combined.addEventListener('abort', abort, { once: true });
          if (combined.aborted) abort();
          timer = setTimeout(() => controller.abort(), 500);
        }),
      ]);
      if (combined.aborted || performance.now() >= end) throw new NonceStoreUnavailable();
      return result;
    } finally {
      if (timer) clearTimeout(timer);
      if (abort) combined.removeEventListener('abort', abort);
    }
  }

  private async performReservation(
    input: NonceReservation,
    signal: AbortSignal,
  ): Promise<'reserved' | 'replay'> {
    try {
      signal.throwIfAborted();
      if (
        !internalEnvironmentSchema.safeParse(input.environment).success ||
        !internalCallerNameSchema.safeParse(input.sender).success ||
        !internalCallerNameSchema.safeParse(input.audience).success ||
        !Number.isSafeInteger(input.timestamp) ||
        !Number.isSafeInteger(input.acceptedAt) ||
        input.timestamp <= 0 ||
        input.acceptedAt < 0 ||
        input.acceptedAt > 8640000000000000 ||
        input.timestamp + 120000 > 8640000000000000
      )
        throw new NonceStoreUnavailable();
      decodeBytes32(input.nonce);
      // Recheck effective indexes on admission: readiness alone can become stale.
      await this.assertReady();
      signal.throwIfAborted();
      // Run the single-document insert command explicitly: insertOne + CSOT strips
      // wtimeout in driver 7.7. RunCommand preserves it, supports AbortSignal and
      // does not enable retryable writes. Check ALL command-level write results.
      const result = await this.db.command(
        {
          insert: NONCE_COLLECTION,
          ordered: true,
          documents: [
            {
              _id: new ObjectId(),
              environment: input.environment,
              sender: input.sender,
              audience: input.audience,
              nonce: input.nonce,
              acceptedAt: new Date(input.acceptedAt),
              expiresAt: new Date(input.timestamp + 120000),
            },
          ],
          writeConcern: { w: 'majority', j: true, wtimeout: 500 },
        },
        { timeoutMS: 500, signal, readPreference: 'primary' },
      );
      signal.throwIfAborted();
      if (result.ok !== 1 || result.writeConcernError) throw new NonceStoreUnavailable();
      if (Array.isArray(result.writeErrors) && result.writeErrors.length > 0) {
        if (
          result.n === 0 &&
          result.writeErrors.length === 1 &&
          result.writeErrors[0].code === 11000
        )
          return 'replay';
        throw new NonceStoreUnavailable();
      }
      if (result.n !== 1) throw new NonceStoreUnavailable();
      return 'reserved';
    } catch (error) {
      if (
        !signal.aborted &&
        error instanceof MongoServerError &&
        error.code === 11000 &&
        !error.writeConcernError
      )
        return 'replay';
      throw new NonceStoreUnavailable();
    }
  }
}
