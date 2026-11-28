import mongoose from 'mongoose';
import { DeviceCredentialModel } from '../models/device-credential.model.js';
import { DeviceLinkChallengeModel } from '../models/device-link-challenge.model.js';
import { DeviceRevocationModel } from '../models/device-revocation.model.js';
import { DeviceModel } from '../models/device.model.js';

export type MongoDb = NonNullable<typeof mongoose.connection.db>;

export const DEVICE_DOMAIN_MODELS = [
  DeviceModel,
  DeviceCredentialModel,
  DeviceRevocationModel,
  DeviceLinkChallengeModel,
] as const;

export const DEVICE_MIGRATION_COLLECTION = 'device_migrations';
export const DEVICE_FOUNDATION_MIGRATION_ID = 'tkt-014-device-credentials';

export class DeviceSchemaNotReadyError extends Error {
  constructor(
    message: string,
    readonly reasons: readonly string[] = [message],
  ) {
    super(message);
    this.name = 'DeviceSchemaNotReadyError';
  }
}

interface RawIndexInfo {
  name?: string;
  key?: Record<string, unknown>;
  unique?: boolean;
  sparse?: boolean;
  expireAfterSeconds?: number;
  partialFilterExpression?: Record<string, unknown>;
  collation?: { locale?: string };
}

interface ExpectedIndex {
  name: string;
  key: Record<string, number>;
  unique?: boolean;
  partialFilterExpression?: Record<string, unknown>;
}

const CRITICAL_INDEXES: ReadonlyArray<{ collection: string; indexes: readonly ExpectedIndex[] }> = [
  {
    collection: DeviceModel.collection.name,
    indexes: [
      { name: 'identifier_1', key: { identifier: 1 }, unique: true },
      { name: 'device_vehicle_status_idx', key: { vehicleId: 1, status: 1 } },
      { name: 'device_vehicle_created_id_idx', key: { vehicleId: 1, createdAt: 1, _id: 1 } },
    ],
  },
  {
    collection: DeviceCredentialModel.collection.name,
    indexes: [
      { name: 'device_credential_fingerprint_unique', key: { fingerprint: 1 }, unique: true },
      { name: 'device_credential_key_id_unique', key: { keyId: 1 }, unique: true },
      {
        name: 'device_credential_active_device_unique',
        key: { deviceId: 1 },
        unique: true,
        partialFilterExpression: { status: 'ACTIVE' },
      },
      { name: 'device_credential_device_status_idx', key: { deviceId: 1, status: 1 } },
    ],
  },
  {
    collection: DeviceRevocationModel.collection.name,
    indexes: [
      {
        name: 'device_revocation_device_target_unique',
        key: { deviceId: 1 },
        unique: true,
        partialFilterExpression: { targetType: 'DEVICE' },
      },
      {
        name: 'device_revocation_credential_target_unique',
        key: { credentialId: 1 },
        unique: true,
        partialFilterExpression: { targetType: 'CREDENTIAL' },
      },
      { name: 'device_revocation_device_history_idx', key: { deviceId: 1, revokedAt: -1 } },
      { name: 'device_revocation_vehicle_history_idx', key: { vehicleId: 1, revokedAt: -1 } },
    ],
  },
  {
    collection: DeviceLinkChallengeModel.collection.name,
    indexes: [{ name: 'challengeHash_1', key: { challengeHash: 1 }, unique: true }],
  },
];

/** Durable collections whose records must never be purged automatically. */
const NO_TTL_COLLECTIONS = [
  DeviceModel.collection.name,
  DeviceCredentialModel.collection.name,
  DeviceRevocationModel.collection.name,
];

function sameOrderedKeys(actual: Record<string, unknown> | undefined, expected: object): boolean {
  return (
    !!actual && JSON.stringify(Object.entries(actual)) === JSON.stringify(Object.entries(expected))
  );
}

function sameDocumentShape(actual: unknown, expected: Record<string, unknown>): boolean {
  if (typeof actual !== 'object' || actual === null) return false;
  const record = actual as Record<string, unknown>;
  const keys = Object.keys(expected);
  return (
    Object.keys(record).length === keys.length &&
    keys.every((key) => JSON.stringify(record[key]) === JSON.stringify(expected[key]))
  );
}

function matchesExactly(index: RawIndexInfo, expected: ExpectedIndex): boolean {
  return (
    index.name === expected.name &&
    sameOrderedKeys(index.key, expected.key) &&
    (index.unique === true) === (expected.unique === true) &&
    (expected.partialFilterExpression
      ? sameDocumentShape(index.partialFilterExpression, expected.partialFilterExpression)
      : !index.partialFilterExpression) &&
    !index.sparse &&
    index.expireAfterSeconds === undefined &&
    (!index.collation || index.collation.locale === 'simple')
  );
}

async function listCollectionIndexes(db: MongoDb, collection: string): Promise<RawIndexInfo[]> {
  try {
    return (await db
      .collection(collection)
      .listIndexes({ maxTimeMS: 500 })
      .toArray()) as RawIndexInfo[];
  } catch (error) {
    if (error instanceof Error && /NamespaceNotFound|ns does not exist/i.test(error.message)) {
      return [];
    }
    throw error;
  }
}

/** Read-only, exact verification of names, ordered keys, uniqueness, partial filters and options. */
export async function findCriticalDeviceIndexIssues(db: MongoDb): Promise<string[]> {
  const issues: string[] = [];
  const listed = new Map<string, RawIndexInfo[]>();
  for (const { collection } of CRITICAL_INDEXES) {
    listed.set(collection, await listCollectionIndexes(db, collection));
  }
  for (const { collection, indexes } of CRITICAL_INDEXES) {
    const actual = listed.get(collection) ?? [];
    for (const expected of indexes) {
      if (!actual.some((index) => matchesExactly(index, expected))) {
        issues.push(`Missing or invalid index ${collection}.${expected.name}`);
      }
    }
  }
  for (const collection of NO_TTL_COLLECTIONS) {
    if ((listed.get(collection) ?? []).some((index) => index.expireAfterSeconds !== undefined)) {
      issues.push(`Illegal TTL index on ${collection}`);
    }
  }
  const allowedDeviceUnique = new Set(['_id_', 'identifier_1']);
  if (
    (listed.get(DeviceModel.collection.name) ?? []).some(
      (index) => index.unique === true && !allowedDeviceUnique.has(index.name ?? ''),
    )
  ) {
    issues.push('Illegal unique index on devices restricts devices per vehicle');
  }
  return issues;
}

export async function assertCriticalDeviceIndexes(db: MongoDb): Promise<void> {
  let issues: string[];
  try {
    issues = await findCriticalDeviceIndexIssues(db);
  } catch {
    throw new DeviceSchemaNotReadyError('Unable to verify critical Device database indexes');
  }
  if (issues.length > 0) {
    throw new DeviceSchemaNotReadyError(
      `Critical Device database indexes are not ready: ${issues.join('; ')}`,
      issues,
    );
  }
}

export async function isDeviceFoundationMigrationRecorded(db: MongoDb): Promise<boolean> {
  const marker = await db
    .collection<{ _id: string }>(DEVICE_MIGRATION_COLLECTION)
    .findOne({ _id: DEVICE_FOUNDATION_MIGRATION_ID }, { maxTimeMS: 500 });
  return marker !== null;
}

export async function assertDeviceFoundationMigrationRecorded(db: MongoDb): Promise<void> {
  let recorded: boolean;
  try {
    recorded = await isDeviceFoundationMigrationRecorded(db);
  } catch {
    throw new DeviceSchemaNotReadyError('Unable to verify Device migration state');
  }
  if (!recorded) {
    throw new DeviceSchemaNotReadyError('Device foundation migration has not been applied');
  }
}

/**
 * Readiness: connected client, writable replica-set primary, exact critical indexes and the
 * recorded TKT-014 migration. Liveness must never call this.
 */
export async function assertDeviceDatabaseReady(client: typeof mongoose = mongoose): Promise<void> {
  const db = client.connection.db;
  if (client.connection.readyState !== 1 || !db) {
    throw new DeviceSchemaNotReadyError('Device database connection is unavailable');
  }
  let hello: { setName?: unknown; isWritablePrimary?: unknown };
  try {
    hello = await db.admin().command({ hello: 1 }, { timeoutMS: 500 });
  } catch {
    throw new DeviceSchemaNotReadyError('Device database is unreachable');
  }
  if (typeof hello.setName !== 'string' || hello.isWritablePrimary !== true) {
    throw new DeviceSchemaNotReadyError('Device database is not a writable replica-set primary');
  }
  await assertCriticalDeviceIndexes(db);
  await assertDeviceFoundationMigrationRecorded(db);
}

/**
 * Creates missing collections and declared indexes outside production. Never runs destructive
 * syncIndexes() or drops existing indexes.
 */
export async function ensureDevelopmentDatabaseSchema(
  log: (message: string) => void = console.info,
): Promise<void> {
  for (const model of DEVICE_DOMAIN_MODELS) {
    log(`Verifying collection: ${model.collection.name}`);
    try {
      await model.createCollection();
    } catch (error) {
      if (!(error instanceof Error) || !/already exists|NamespaceExists/i.test(error.message)) {
        throw error;
      }
    }
    log(`Verifying indexes: ${model.collection.name}`);
    await model.createIndexes();
    log(`Database schema ready: ${model.collection.name}`);
  }
}
