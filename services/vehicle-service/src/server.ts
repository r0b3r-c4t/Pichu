import { createApp } from './app.js';

const app = createApp();

let shutdownPromise: Promise<void> | undefined;

function shutdown(signal: string): Promise<void> {
  if (shutdownPromise) {
    return shutdownPromise;
  }

  shutdownPromise = (async () => {
    app.log.info({ signal }, 'Closing server');

    try {
      await app.close();
      app.log.info({ signal }, 'Server closed');
    } catch (error) {
      app.log.error({ err: error, signal }, 'Failed to close server');
      process.exitCode = 1;
    }
  })();

  return shutdownPromise;
}

process.once('SIGINT', () => void shutdown('SIGINT'));
process.once('SIGTERM', () => void shutdown('SIGTERM'));

try {
  await app.listen({
    host: process.env.HOST ?? '0.0.0.0',
    port: Number(process.env.PORT ?? 3002),
  });
} catch (error) {
  app.log.error({ err: error }, 'Failed to start server');
  process.exitCode = 1;
  await shutdown('startup failure');
}
