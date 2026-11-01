import type { FastifyPluginAsync } from 'fastify';
import { checkDatabaseConnection } from '../database/connection.js';

export const healthRoutes: FastifyPluginAsync = async (fastify) => {
  fastify.get('/health', async () => ({ status: 'ok' }));

  fastify.get('/health/db', async (_request, reply) => {
    const connected = await checkDatabaseConnection();

    if (!connected) {
      return reply.code(503).send({ status: 'error', database: 'disconnected' });
    }

    return { status: 'ok', database: 'connected' };
  });
};
