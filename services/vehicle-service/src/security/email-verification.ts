import type { FastifyReply, FastifyRequest } from 'fastify';
import {
  executeSignedInternalRequest,
  OutboundDeadlineExceededError,
  type InternalClientConfig,
} from './internal-v2.js';

const EMAIL_NOT_VERIFIED_MESSAGE = 'Debes verificar tu correo electrónico para continuar.';

export async function requireVerifiedEmail(
  request: FastifyRequest,
  reply: FastifyReply,
  userId: string,
  clientConfig: InternalClientConfig,
): Promise<boolean> {
  const correlationId =
    typeof request.headers['x-request-id'] === 'string'
      ? request.headers['x-request-id']
      : request.id;
  reply.header('x-request-id', correlationId);

  const path = `/internal/users/${userId}/verified`;
  const identityBaseUrl =
    clientConfig.identityServiceUrl ?? process.env.IDENTITY_SERVICE_URL ?? 'http://127.0.0.1:3001';

  try {
    const response = await executeSignedInternalRequest(request, clientConfig, {
      audience: 'identity-service',
      baseUrl: identityBaseUrl,
      method: 'GET',
      path,
    });

    if (response.status === 504) {
      await reply.code(504).send({
        error: 'GATEWAY_TIMEOUT',
        message: 'Identity verification timed out',
        requestId: correlationId,
      });
      return false;
    }

    if (response.status === 401) {
      await reply.code(401).send({
        error: 'AUTHENTICATION_REQUIRED',
        message: 'Authentication required',
        requestId: correlationId,
      });
      return false;
    }

    if (response.status === 403) {
      await reply.code(403).send({
        error: 'FORBIDDEN',
        message: 'Forbidden',
        requestId: correlationId,
      });
      return false;
    }

    if (response.status < 200 || response.status >= 300) {
      throw new Error('Verification lookup failed');
    }

    const result: unknown = response.body;
    if (typeof result !== 'object' || result === null || !('verified' in result)) {
      throw new Error('Invalid verification response');
    }
    if (result.verified === true) {
      return true;
    }
    if (result.verified !== false) {
      throw new Error('Invalid verification response');
    }

    await reply.code(403).send({
      error: 'EMAIL_NOT_VERIFIED',
      message: EMAIL_NOT_VERIFIED_MESSAGE,
      requestId: correlationId,
    });
    return false;
  } catch (error) {
    if (error instanceof OutboundDeadlineExceededError) {
      await reply.code(504).send({
        error: 'GATEWAY_TIMEOUT',
        message: 'Internal request deadline exceeded',
        requestId: correlationId,
      });
      return false;
    }
    await reply.code(503).send({
      message: 'Identity service unavailable',
      requestId: correlationId,
    });
    return false;
  }
}
