import mongoose, { type ClientSession } from 'mongoose';
import { databaseUnavailableError, isDatabaseUnavailableError } from '../services/device-errors.js';

const TRANSACTION_OPTIONS = {
  readPreference: 'primary',
  readConcern: { level: 'snapshot' },
  writeConcern: { w: 'majority' },
} as const;

/** Object seam so unit tests can stub connectivity without patching Mongoose internals. */
export const deviceDatabaseConnection = {
  isConnected: (): boolean => mongoose.connection.readyState === 1,
};

export function assertDatabaseConnected(): void {
  if (!deviceDatabaseConnection.isConnected()) throw databaseUnavailableError();
}

/**
 * Runs work in a replica-set transaction. Connectivity failures are classified only after
 * `withTransaction` has exhausted its retries; domain and programming errors propagate unchanged.
 * The callback may run more than once and must not perform non-transactional side effects.
 */
export async function runInDeviceTransaction<T>(
  work: (session: ClientSession) => Promise<T>,
): Promise<T> {
  assertDatabaseConnected();
  let session: ClientSession;
  try {
    session = await mongoose.connection.startSession();
  } catch (error) {
    throw isDatabaseUnavailableError(error) ? databaseUnavailableError(error) : error;
  }
  try {
    let outcome!: T;
    await session.withTransaction(async () => {
      outcome = await work(session);
    }, TRANSACTION_OPTIONS);
    return outcome;
  } catch (error) {
    throw isDatabaseUnavailableError(error) ? databaseUnavailableError(error) : error;
  } finally {
    await session.endSession();
  }
}

export async function guardedDeviceRead<T>(read: () => Promise<T>): Promise<T> {
  assertDatabaseConnected();
  try {
    return await read();
  } catch (error) {
    throw isDatabaseUnavailableError(error) ? databaseUnavailableError(error) : error;
  }
}
