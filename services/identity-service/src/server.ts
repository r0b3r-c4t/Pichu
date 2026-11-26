import { createApp } from './app.js';
import { loadEnvironment, parseInternalAuthKeyring, type Environment } from './config/env.js';
import { closeDatabase, connectDatabase } from './database/connection.js';
import { ZodError } from 'zod';
import mongoose from 'mongoose';
import { MongoNonceStore } from '@pichu/internal-auth-adapters/mongodb';
import { readTlsServerOptions } from '@pichu/internal-auth-adapters/tls';
import { ResendEmailProvider } from './email/resend-email.provider.js';
import { JwtService } from './security/jwt.js';
import { LoginService } from './services/login.service.js';
import { SessionService } from './services/session.service.js';
import {
  createMongoosePasswordRecoveryRepository,
  PasswordRecoveryService,
} from './services/password-recovery.service.js';

let environment: Environment;
let internalKeyring: ReturnType<typeof parseInternalAuthKeyring>;
try {
  environment = loadEnvironment();
  internalKeyring = parseInternalAuthKeyring(environment);
  console.info('Startup phase completed', { phase: 'configuration', status: 'ready' });
} catch (error) {
  const issues =
    error instanceof ZodError
      ? error.issues.map(({ path, code }) => ({ field: path.join('.'), code }))
      : [];
  console.error('Invalid service configuration', { issues });
  process.exit(1);
}

const emailProvider = new ResendEmailProvider({
  apiKey: environment.RESEND_API_KEY,
  fromEmail: environment.RESEND_FROM_EMAIL,
  fromName: environment.RESEND_FROM_NAME,
});
const jwtService = new JwtService({
  secret: environment.JWT_SECRET,
  issuer: environment.JWT_ISSUER,
  audience: environment.JWT_AUDIENCE,
  accessTokenTtlSeconds: environment.ACCESS_TOKEN_TTL_SECONDS,
});
const sessionService = new SessionService({
  refreshTokenTtlMs: environment.REFRESH_TOKEN_TTL_SECONDS * 1000,
});
const loginService = new LoginService({ sessionService, jwtService });
const passwordRecoveryService = new PasswordRecoveryService({
  repository: createMongoosePasswordRecoveryRepository({ sessionService }),
  emailProvider,
  resetUrl: environment.PASSWORD_RESET_URL,
  tokenTtlMs: environment.PASSWORD_RESET_TOKEN_TTL_SECONDS * 1000,
});
const internalNonceStore = new MongoNonceStore(() => {
  if (!mongoose.connection.db) throw new Error('Identity database is not connected');
  return mongoose.connection.db;
});
const app = createApp({
  ...(environment.TLS_CERT_PATH && environment.TLS_KEY_PATH && environment.TLS_CA_PATH
    ? {
        https: readTlsServerOptions({
          certPath: environment.TLS_CERT_PATH,
          keyPath: environment.TLS_KEY_PATH,
          caPath: environment.TLS_CA_PATH,
        }),
      }
    : {}),
  emailProvider,
  verificationUrl: environment.EMAIL_VERIFICATION_URL,
  tokenTtlMs: environment.EMAIL_VERIFICATION_TOKEN_TTL_SECONDS * 1000,
  loginService,
  sessionService,
  jwtService,
  cookieSecure: environment.NODE_ENV === 'production',
  cookieOrigin: new URL(environment.AUTH_COOKIE_ORIGIN).origin,
  passwordRecoveryService,
  internalAuth: {
    environment: environment.INTERNAL_AUTH_ENVIRONMENT!,
    keyring: internalKeyring,
    nonces: internalNonceStore,
    bodyLimit: environment.INTERNAL_AUTH_BODY_LIMIT,
  },
});

let shutdownPromise: Promise<void> | undefined;
let shutdownRequested = false;

function safeErrorDetails(error: unknown): { errorType: string; code?: string | number } {
  const knownErrorTypes = new Set([
    'Error',
    'MongooseError',
    'MongoServerSelectionError',
    'MongoNetworkError',
    'MongoParseError',
    'MongoServerError',
    'FastifyError',
  ]);
  const errorType =
    error instanceof Error && knownErrorTypes.has(error.name) ? error.name : 'UnknownError';

  if (typeof error === 'object' && error !== null && 'code' in error) {
    const code = (error as { code: unknown }).code;
    if (
      typeof code === 'number' ||
      (typeof code === 'string' && /^[A-Z][A-Z0-9_]{0,31}$/.test(code))
    ) {
      return { errorType, code };
    }
  }

  return { errorType };
}

function sanitizedErrorMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : 'Unknown startup error';
  return message.replace(/(mongodb(?:\+srv)?:\/\/)([^@\s]+)@/gi, '$1***@').slice(0, 300);
}

function shutdown(signal: string): Promise<void> {
  if (shutdownPromise) {
    return shutdownPromise;
  }

  shutdownRequested = true;
  shutdownPromise = (async () => {
    app.log.info({ signal }, 'Closing server');

    try {
      await app.close();
    } catch {
      app.log.error({ signal }, 'Failed to close server');
      process.exitCode = 1;
    }

    try {
      await closeDatabase();
      app.log.info({ signal }, 'Server shutdown complete');
    } catch {
      app.log.error({ signal }, 'Failed to close database connection');
      process.exitCode = 1;
    }
  })();

  return shutdownPromise;
}

process.once('SIGINT', () => void shutdown('SIGINT'));
process.once('SIGTERM', () => void shutdown('SIGTERM'));

let startupPhase = 'MongoDB connection';
try {
  app.log.info({ phase: 'mongodb', status: 'connecting' }, 'Startup phase started');
  await connectDatabase(environment.DATABASE_URL);
  app.log.info({ phase: 'mongodb', status: 'connected' }, 'Startup phase completed');
  if (!mongoose.connection.db) throw new Error('Identity database is not connected');
  app.log.info({ phase: 'internal-security-schema', status: 'verifying' }, 'Startup phase started');
  const { createNonceIndexes } = await import('@pichu/internal-auth-adapters/mongodb');
  await createNonceIndexes(mongoose.connection.db);
  app.log.info({ phase: 'internal-security-schema', status: 'ready' }, 'Startup phase completed');

  if (!shutdownRequested) {
    startupPhase = 'HTTP server';
    app.log.info({ phase: 'http-server', status: 'starting' }, 'Startup phase started');
    await app.listen({ host: environment.HOST, port: environment.PORT });
    app.log.info({ phase: 'http-server', status: 'ready' }, 'Startup phase completed');

    console.log(`
┌──────────────────────────────────────────────┐
│                  PICHU IDENTITY              │
├──────────────────────────────────────────────┤
│  Status:         Corriendo                   │
│  Port:           ${String(environment.PORT).padEnd(27)} │
│  Server:         ${String(environment.HOST).padEnd(27)} │
│  Documentation:  ${String(environment.DOCUMENTATION_URL).padEnd(27)} │
└──────────────────────────────────────────────┘
`);
  }
} catch (error) {
  app.log.error(
    { ...safeErrorDetails(error), message: sanitizedErrorMessage(error) },
    `Failed during startup phase: ${startupPhase}`,
  );
  process.exitCode = 1;
  await shutdown('startup failure');
}
