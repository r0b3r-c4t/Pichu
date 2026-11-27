import { createApp } from './app.js';
import { loadEnv, parseInternalKeyring } from './config/env.js';
import { closeDatabase, connectDatabase } from './database/connection.js';
import {
  assertCriticalDeviceIndexes,
  assertDeviceDatabaseReady,
  assertDeviceFoundationMigrationRecorded,
  ensureDevelopmentDatabaseSchema,
} from './database/bootstrap.js';
import { recordDeviceMigrationIfNothingToMigrate } from './database/migration.js';
import { ZodError } from 'zod';
import mongoose from 'mongoose';
import { MongoNonceStore, createNonceIndexes } from '@pichu/internal-auth-adapters/mongodb';
import { readTlsServerOptions } from '@pichu/internal-auth-adapters/tls';

function loadStartupConfiguration() {
  try {
    const env = loadEnv();
    const keyring = parseInternalKeyring(env);
    return { env, keyring };
  } catch (error) {
    const issues =
      error instanceof ZodError
        ? error.issues.map(({ path, code }) => ({ field: path.join('.'), code }))
        : [];
    console.error('Invalid service configuration', { issues });
    process.exitCode = 1;
    return undefined;
  }
}

const startup = loadStartupConfiguration();

if (!startup) {
  process.exit(1);
}
const { env, keyring } = startup;
const nonces = new MongoNonceStore(() => {
  if (!mongoose.connection.db) throw new Error('Device database is not connected');
  return mongoose.connection.db;
});
const app = createApp({
  ...(env.TLS_CERT_PATH && env.TLS_KEY_PATH && env.TLS_CA_PATH
    ? {
        https: readTlsServerOptions({
          certPath: env.TLS_CERT_PATH,
          keyPath: env.TLS_KEY_PATH,
          caPath: env.TLS_CA_PATH,
        }),
      }
    : {}),
  internalAuth: {
    environment: env.INTERNAL_AUTH_ENVIRONMENT,
    keyring,
    nonces,
    bodyLimit: env.INTERNAL_AUTH_BODY_LIMIT,
  },
  readinessCheck: () => assertDeviceDatabaseReady(mongoose),
});

function sanitizedErrorMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : 'Unknown startup error';
  return message.replace(/(mongodb(?:\+srv)?:\/\/)([^@\s]+)@/gi, '$1***@').slice(0, 300);
}

let shutdownPromise: Promise<void> | undefined;

function shutdown(signal: string): Promise<void> {
  if (shutdownPromise) {
    return shutdownPromise;
  }

  shutdownPromise = (async () => {
    app.log.info({ signal }, 'Closing server');

    try {
      await app.close();
      await closeDatabase();
      app.log.info({ signal }, 'Server closed');
    } catch (error) {
      const errorType = error instanceof Error ? error.name : 'UnknownError';
      app.log.error({ errorType, signal }, 'Failed to close server');
      process.exitCode = 1;
    }
  })();

  return shutdownPromise;
}

process.once('SIGINT', () => void shutdown('SIGINT'));
process.once('SIGTERM', () => void shutdown('SIGTERM'));

try {
  app.log.info({ phase: 'mongodb', status: 'connecting' }, 'Startup phase started');
  await connectDatabase(env.DATABASE_URL);
  app.log.info({ phase: 'mongodb', status: 'connected' }, 'Startup phase completed');

  const db = mongoose.connection.db;
  if (!db) throw new Error('Device database is not connected');

  if (env.NODE_ENV !== 'production') {
    app.log.info({ phase: 'database-schema', status: 'verifying' }, 'Startup phase started');
    await ensureDevelopmentDatabaseSchema((message) =>
      app.log.info({ phase: 'database-schema' }, message),
    );
    if (!(await recordDeviceMigrationIfNothingToMigrate(db))) {
      app.log.warn(
        { phase: 'database-migration' },
        'Legacy device data requires the explicit TKT-014 migration; readiness stays unready',
      );
    }
    app.log.info({ phase: 'database-schema', status: 'ready' }, 'Startup phase completed');
  }

  app.log.info({ phase: 'critical-indexes', status: 'verifying' }, 'Startup phase started');
  await assertCriticalDeviceIndexes(db);
  if (env.NODE_ENV === 'production') await assertDeviceFoundationMigrationRecorded(db);
  await createNonceIndexes(db);
  app.log.info({ phase: 'critical-indexes', status: 'ready' }, 'Startup phase completed');

  app.log.info({ phase: 'http-server', status: 'starting' }, 'Startup phase started');
  await app.listen({
    host: env.HOST,
    port: env.PORT,
  });
  app.log.info({ phase: 'http-server', status: 'ready' }, 'Startup phase completed');

  const documentationUrl = `http://localhost:${env.PORT}/docs`;

  console.log(`
┌──────────────────────────────────────────────┐
│                 PICHU DEVICE                 │
├──────────────────────────────────────────────┤
│  Status:         Corriendo                   │
│  Port:           ${String(env.PORT).padEnd(27)} │
│  Server:         ${String(env.HOST).padEnd(27)} │
│  Database:       MongoDB Connected           │
│  Documentation:  ${documentationUrl.padEnd(27)} │
└──────────────────────────────────────────────┘
`);
} catch (error) {
  const startupError =
    error instanceof Error ? (error as Error & { code?: string | number }) : undefined;
  app.log.error(
    {
      errorType: startupError?.name ?? 'UnknownError',
      errorCode: startupError?.code,
      message: sanitizedErrorMessage(error),
    },
    'Failed during startup phase',
  );

  process.exitCode = 1;
  await shutdown('startup failure');
}
