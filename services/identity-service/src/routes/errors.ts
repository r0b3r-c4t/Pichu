import type { FastifyInstance, FastifyRequest } from 'fastify';
import { randomUUID } from 'node:crypto';
import type { ZodType } from 'zod';
import {
  passwordRecoveryConfirmSchema,
  passwordRecoveryRequestSchema,
  loginSchema,
  refreshSchema,
  registerSchema,
  resendVerificationSchema,
  verifyEmailSchema,
} from '../schemas/auth.schema.js';
import { apiErrorCodeSchema, type ApiErrorResponse } from '../schemas/error.schema.js';

const requestSchemas: Record<string, ZodType> = {
  '/auth/register': registerSchema,
  '/auth/login': loginSchema,
  '/auth/refresh': refreshSchema,
  '/auth/verify-email': verifyEmailSchema,
  '/auth/verification/resend': resendVerificationSchema,
  '/auth/password-reset/request': passwordRecoveryRequestSchema,
  '/auth/password-reset/confirm': passwordRecoveryConfirmSchema,
};

function errorCode(status: number, message: string): ApiErrorResponse['error'] {
  if (status === 400) {
    if (message.includes('token') && message.includes('expired')) return 'INVALID_TOKEN';
    return 'VALIDATION_ERROR';
  }
  if (status === 401) {
    if (message === 'Invalid credentials') return 'INVALID_CREDENTIALS';
    if (message === 'Invalid refresh token') return 'INVALID_TOKEN';
    return 'UNAUTHORIZED';
  }
  if (status === 403) return 'FORBIDDEN';
  if (status === 404) return 'RESOURCE_NOT_FOUND';
  if (status === 409) return 'CONFLICT';
  if (status === 429) return 'RATE_LIMIT_EXCEEDED';
  if (status === 413) return 'PAYLOAD_TOO_LARGE';
  if (status === 415) return 'UNSUPPORTED_MEDIA_TYPE';
  if (status === 503) return 'SERVICE_UNAVAILABLE';
  return 'INTERNAL_SERVER_ERROR';
}

function validationDetails(request: FastifyRequest): ApiErrorResponse['details'] {
  const path = request.url.split('?')[0];
  const schema = requestSchemas[path];
  if (schema) {
    const parsed = schema.safeParse(request.body);
    if (!parsed.success) {
      return parsed.error.issues.map((issue) => ({
        field: issue.path.join('.') || 'body',
        message:
          issue.path[0] === 'password'
            ? issue.message
            : path === '/auth/password-reset/confirm'
              ? 'Expected 64 lowercase hexadecimal characters'
              : issue.code === 'invalid_type'
                ? 'Required or invalid type'
                : 'Invalid value',
      }));
    }
  }
  return undefined;
}

export function installIdentityErrorResponses(app: FastifyInstance): void {
  app.addHook('onRequest', async (request, reply) => {
    reply.header('x-request-id', request.id);
  });

  app.addHook('onSend', async (request, reply, payload) => {
    if (reply.statusCode < 400) return payload;

    let original: unknown;
    try {
      original = typeof payload === 'string' ? JSON.parse(payload) : undefined;
    } catch {
      original = undefined;
    }
    const body =
      typeof original === 'object' && original !== null
        ? (original as Record<string, unknown>)
        : {};
    const rawMessage =
      typeof body.message === 'string' ? body.message : 'Request could not be completed';
    const message =
      reply.statusCode === 404 && rawMessage.startsWith('Route ')
        ? 'Resource not found'
        : rawMessage;
    const path = request.url.split('?')[0];
    const schema = requestSchemas[path];
    const invalidBody =
      reply.statusCode === 400 && schema !== undefined && !schema.safeParse(request.body).success;
    const explicitCode = apiErrorCodeSchema.safeParse(body.error);
    const code = invalidBody
      ? 'VALIDATION_ERROR'
      : explicitCode.success
        ? explicitCode.data
        : errorCode(reply.statusCode, message);
    const details =
      code === 'VALIDATION_ERROR'
        ? (validationDetails(request) ?? [{ field: 'body', message: 'Invalid request body' }])
        : undefined;
    const response: ApiErrorResponse = {
      error: code,
      message,
      ...(details && details.length > 0 ? { details } : {}),
      requestId: request.id,
    };
    reply.header('x-request-id', request.id);
    return JSON.stringify(response);
  });
}

export function identityRequestId(request: import('node:http').IncomingMessage): string {
  const supplied = request.headers['x-request-id'];
  return typeof supplied === 'string' && /^[A-Za-z0-9._:-]{1,128}$/.test(supplied)
    ? supplied
    : randomUUID();
}
