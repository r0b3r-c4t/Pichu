import Fastify, { type FastifyInstance } from 'fastify';
import { healthRoutes } from './routes/health.js';

export function createApp(): FastifyInstance {
  const app = Fastify({ logger: true });
  void app.register(healthRoutes);
  return app;
}
