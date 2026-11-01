import Fastify, { type FastifyInstance } from 'fastify';

export function createApp(): FastifyInstance {
  return Fastify({ logger: true });
}
