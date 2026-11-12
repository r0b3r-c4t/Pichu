import { createApp } from './app.js';
import { loadGatewayEnv } from './config/env.js';

let app: ReturnType<typeof createApp> | undefined;
let shutdownPromise: Promise<void> | undefined;

function sanitizedErrorMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : 'Unknown startup error';
  return message.replace(/(https?:\/\/)([^@\s]+)@/gi, '$1***@').slice(0, 300);
}

function shutdown(signal: string): Promise<void> {
  if (shutdownPromise) {
    return shutdownPromise;
  }

  shutdownPromise = (async () => {
    const currentApp = app;
    currentApp?.log.info({ signal }, 'Closing server');

    try {
      if (currentApp) {
        await currentApp.close();
        currentApp.log.info({ signal }, 'Server closed');
      }
    } catch (error) {
      console.error('[API Gateway] Shutdown failed', {
        errorType: error instanceof Error ? error.name : 'UnknownError',
      });
      process.exitCode = 1;
    }
  })();

  return shutdownPromise;
}

process.once('SIGINT', () => void shutdown('SIGINT'));
process.once('SIGTERM', () => void shutdown('SIGTERM'));

try {
  const env = loadGatewayEnv();
  console.info('Startup phase completed', { phase: 'configuration', status: 'ready' });

  const runningApp = createApp({ env });
  app = runningApp;

  runningApp.log.info({ phase: 'http-server', status: 'starting' }, 'Startup phase started');
  await runningApp.listen({
    host: env.HOST,
    port: env.PORT,
  });
  runningApp.log.info({ phase: 'http-server', status: 'ready' }, 'Startup phase completed');

  const baseUrl = `http://localhost:${env.PORT}`;

  console.log(`
┌──────────────────────────────────────────────────┐
│                 PICHU API GATEWAY                │
├──────────────────────────────────────────────────┤
│  Status:         Running                         │
│  Port:           ${String(env.PORT).padEnd(32)}│
│  Host:           ${env.HOST.padEnd(32)}│
│  Swagger UI:     ${`${baseUrl}/docs`.padEnd(32)}│
│  Health:         ${`${baseUrl}/health`.padEnd(32)}│
└──────────────────────────────────────────────────┘
`);
} catch (error) {
  const startupError =
    error instanceof Error ? (error as Error & { code?: string | number }) : undefined;
  console.error('[API Gateway] Startup failed', {
    errorType: startupError?.name ?? 'UnknownError',
    errorCode: startupError?.code,
    message: sanitizedErrorMessage(error),
  });

  process.exitCode = 1;
  await shutdown('startup failure');
}
