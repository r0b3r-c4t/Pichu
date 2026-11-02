import { createApp } from './app.js';
import { loadEnvironment, type Environment } from './config/env.js';
import { closeDatabase, connectDatabase } from './database/connection.js';
import { ZodError } from 'zod';
import { ResendEmailProvider } from './email/resend-email.provider.js';

let environment: Environment;
try {
  environment = loadEnvironment();
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
const app = createApp({
  emailProvider,
  verificationUrl: environment.EMAIL_VERIFICATION_URL,
  tokenTtlMs: environment.EMAIL_VERIFICATION_TOKEN_TTL_SECONDS * 1000,
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
  const errorType = error instanceof Error && knownErrorTypes.has(error.name) ? error.name : 'UnknownError';

  if (typeof error === 'object' && error !== null && 'code' in error) {
    const code = (error as { code: unknown }).code;
    if (typeof code === 'number' || (typeof code === 'string' && /^[A-Z][A-Z0-9_]{0,31}$/.test(code))) {
      return { errorType, code };
    }
  }

  return { errorType };
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
  await connectDatabase(environment.DATABASE_URL);

  if (!shutdownRequested) {
    startupPhase = 'HTTP server';
    await app.listen({ host: environment.HOST, port: environment.PORT });

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
  app.log.error(safeErrorDetails(error), `Failed during startup phase: ${startupPhase}`);
  process.exitCode = 1;
  await shutdown('startup failure');
}
