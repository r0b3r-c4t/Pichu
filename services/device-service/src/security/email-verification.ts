import type { FastifyReply, FastifyRequest } from 'fastify';
import { parseInternalKeyring, loadEnv } from '../config/env.js';
import { signedHeaders } from './internal-v2.js';
import { internalJsonRequest } from '@pichu/internal-auth-adapters/tls';

export async function requireVerifiedEmail(
  request: FastifyRequest,
  reply: FastifyReply,
  userId: string,
): Promise<boolean> {
  const correlationId =
    typeof request.headers['x-request-id'] === 'string'
      ? request.headers['x-request-id']
      : request.id;
  reply.header('x-request-id', correlationId);
  const path = `/internal/users/${userId}/verified`;
  try {
    const env = loadEnv();
    const authorization =
      typeof request.headers.authorization === 'string' ? request.headers.authorization : undefined;
    const headers = signedHeaders(
      {
        environment: env.INTERNAL_AUTH_ENVIRONMENT,
        keyring: parseInternalKeyring(env),
        sender: 'device-service',
      },
      'identity-service',
      'GET',
      path,
      Buffer.alloc(0),
      authorization,
    );
    const response = await internalJsonRequest({
      url: `${env.IDENTITY_SERVICE_URL}${path}`,
      signal: AbortSignal.timeout(4_000),
      headers,
      timeoutMs: 4_000,
      tls: { caPath: env.TLS_CA_PATH ?? '' },
    });
    if (response.status < 200 || response.status >= 300)
      throw new Error('Verification lookup failed');
    const result: unknown = response.body;
    if (typeof result !== 'object' || result === null || !('verified' in result))
      throw new Error('Invalid verification response');
    if (result.verified === true) return true;
    if (result.verified !== false) throw new Error('Invalid verification response');
    await reply.code(403).send({
      error: 'EMAIL_NOT_VERIFIED',
      message: 'Debes verificar tu correo electrónico para continuar.',
      requestId: correlationId,
    });
    return false;
  } catch {
    await reply.code(503).send({ message: 'Identity service unavailable' });
    return false;
  }
}
