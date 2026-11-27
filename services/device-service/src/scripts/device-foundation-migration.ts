import mongoose from 'mongoose';
import { loadEnv } from '../config/env.js';
import { closeDatabase, connectDatabase } from '../database/connection.js';
import {
  applyDeviceFoundationMigration,
  DeviceMigrationBlockedError,
  inspectDeviceMigrationPreflight,
} from '../database/migration.js';

/**
 * Operator entry point. `--preflight` is read-only; `--apply` must be requested explicitly.
 * Reports contain identifiers and counts only, never key material or connection strings.
 */
const mode = process.argv.includes('--apply')
  ? 'apply'
  : process.argv.includes('--preflight')
    ? 'preflight'
    : undefined;

if (!mode) {
  console.error('Usage: device-foundation-migration (--preflight | --apply)');
  process.exit(2);
}

try {
  const env = loadEnv();
  await connectDatabase(env.DATABASE_URL);
  const db = mongoose.connection.db;
  if (!db) throw new Error('Device database is not connected');
  const report =
    mode === 'apply'
      ? await applyDeviceFoundationMigration(db, { log: (message) => console.info(message) })
      : await inspectDeviceMigrationPreflight(db);
  console.info(JSON.stringify({ mode, report }, null, 2));
} catch (error) {
  if (error instanceof DeviceMigrationBlockedError) {
    console.error(JSON.stringify({ mode, blocked: true, report: error.report }, null, 2));
  } else {
    console.error('Device migration failed', {
      errorType: error instanceof Error ? error.name : 'UnknownError',
    });
  }
  process.exitCode = 1;
} finally {
  await closeDatabase().catch(() => undefined);
}
