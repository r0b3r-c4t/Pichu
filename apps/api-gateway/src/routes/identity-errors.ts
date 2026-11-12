import type { FastifyInstance } from 'fastify';
import { z, type ZodType } from 'zod';
import {
  gatewayErrorResponseSchema,
  revokedResponseSchema,
  sessionsResponseSchema,
} from '@pichu/contracts';
import {
  loginBodySchema,
  registerBodySchema,
  passwordResetConfirmBodySchema,
  passwordResetRequestBodySchema,
  emailVerificationBodySchema,
  verificationResendBodySchema,
} from '../schemas/gateway.schema.js';
import { jsonSchema } from '../lib/openapi.js';

const errorSchema = gatewayErrorResponseSchema;
const bodies: Record<string, ZodType> = {
  '/api/auth/login': loginBodySchema,
  '/api/auth/register': registerBodySchema,
  '/api/auth/password-reset/confirm': passwordResetConfirmBodySchema,
  '/api/auth/password-reset/request': passwordResetRequestBodySchema,
  '/api/auth/verify-email': emailVerificationBodySchema,
  '/api/auth/verification/resend': verificationResendBodySchema,
};
const codes: Record<number, string> = {
  400: 'VALIDATION_ERROR',
  401: 'UNAUTHORIZED',
  403: 'FORBIDDEN',
  404: 'RESOURCE_NOT_FOUND',
  409: 'CONFLICT',
  413: 'PAYLOAD_TOO_LARGE',
  415: 'UNSUPPORTED_MEDIA_TYPE',
  429: 'RATE_LIMIT_EXCEEDED',
  500: 'INTERNAL_SERVER_ERROR',
  502: 'BAD_GATEWAY',
  503: 'SERVICE_UNAVAILABLE',
  504: 'GATEWAY_TIMEOUT',
};
const descriptions: Record<number, string> = {
  400: 'Invalid fields or refresh transport',
  401: 'Missing or invalid credentials',
  403: 'Origin not allowed',
  404: 'Resource not found',
  409: 'Email or username already in use',
  413: 'Payload too large',
  415: 'Unsupported media type',
  429: 'Rate limit exceeded',
  500: 'Internal error',
  502: 'Upstream unavailable',
  503: 'Service unavailable',
  504: 'Upstream timeout',
};
const cookieDescription =
  'Login sets an HttpOnly refresh cookie scoped to /api/auth. The browser sends it automatically on refresh; include credentials and use the configured allowed Origin. Swagger curl may omit browser cookies. Refresh requires no request body. Bearer access tokens cannot refresh a session.';

export function installGatewayIdentityResponses(app: FastifyInstance): void {
  app.addHook('onRoute', (route) => {
    if (!route.url.startsWith('/api/auth') && !route.url.startsWith('/api/sessions')) return;
    route.schema ??= {};
    const response: Record<string, unknown> = {
      ...(typeof route.schema.response === 'object' ? route.schema.response : {}),
    };
    if (
      route.url === '/api/sessions' ||
      route.url.includes(':sessionId') ||
      route.url === '/api/auth/logout' ||
      route.url === '/api/auth/logout-all'
    ) {
      response[200] = jsonSchema(
        route.url === '/api/sessions' ? sessionsResponseSchema : revokedResponseSchema,
      );
      route.schema.tags = ['Identity'];
      route.schema.security = [{ bearerAuth: [] }];
    }
    for (const [status, schema] of Object.entries(response)) {
      if (Number(status) < 400 && typeof schema === 'object' && schema !== null) {
        response[status] = {
          ...schema,
          description:
            Number(status) === 202 ? 'Request accepted' : 'Operation completed successfully',
        };
      }
    }
    const statuses = [400, 403, 413, 415, 429, 500, 502, 503, 504];
    if (
      ![
        '/api/auth/register',
        '/api/auth/password-reset/request',
        '/api/auth/password-reset/confirm',
        '/api/auth/verify-email',
        '/api/auth/verification/resend',
      ].includes(route.url)
    )
      statuses.push(401);
    if (route.url.includes(':sessionId')) statuses.push(404);
    if (route.url === '/api/auth/register') statuses.push(409);
    for (const status of statuses) {
      response[status] = {
        ...jsonSchema(errorSchema),
        description: descriptions[status],
        example: { error: codes[status], message: descriptions[status], requestId: 'request-123' },
      };
    }
    if (route.url === '/api/auth/register') {
      response[409] = {
        ...jsonSchema(
          errorSchema.extend({ error: z.enum(['USER_ALREADY_EXISTS', 'USERNAME_ALREADY_EXISTS']) }),
        ),
        description: 'Email or username already in use',
        example: {
          error: 'USER_ALREADY_EXISTS',
          message: 'Email already in use',
          requestId: 'request-123',
        },
      };
    }
    route.schema.response = response;
    if (route.url === '/api/auth/login' || route.url === '/api/auth/refresh')
      route.schema.description = cookieDescription;
    if (route.url === '/api/auth/refresh') route.schema.security = [{ refreshCookie: [] }];
    if (route.url === '/api/auth/logout' || route.url === '/api/auth/logout-all')
      route.schema.description =
        'Requires a Bearer access token and the configured allowed Origin. Revokes the session and clears the HttpOnly refresh cookie.';
    if (
      ['/api/auth/login', '/api/auth/refresh', '/api/auth/logout', '/api/auth/logout-all'].includes(
        route.url,
      )
    ) {
      const success = response[200] as Record<string, unknown>;
      response[200] = {
        ...success,
        headers: {
          'Set-Cookie': {
            description: 'HttpOnly refresh cookie, scoped to /api/auth, rotated or cleared',
            schema: { type: 'string' },
          },
        },
      };
    }
    if (route.url.endsWith('/password-reset/confirm')) {
      route.schema.description =
        'Use the token from the password recovery email (64 lowercase hexadecimal characters), not an access JWT or email verification token. Send password (8–256 characters). Invalid, expired and used recovery tokens return the same error.';
    }
  });
  app.addHook('preSerialization', async (request, reply, payload) => {
    if (
      reply.statusCode < 400 ||
      (!request.url.startsWith('/api/auth') && !request.url.startsWith('/api/sessions'))
    )
      return payload;
    const body =
      typeof payload === 'object' && payload !== null ? (payload as Record<string, unknown>) : {};
    const path = request.url.split('?')[0];
    const parsed = bodies[path]?.safeParse(request.body);
    const details =
      reply.statusCode === 400 && parsed && !parsed.success
        ? parsed.error.issues.map((issue) => ({
            field: issue.path.join('.') || 'body',
            message:
              issue.path[0] === 'password' && path !== '/api/auth/login'
                ? issue.message
                : issue.path[0] === 'token'
                  ? 'Expected 64 lowercase hexadecimal characters'
                  : 'Required or invalid value',
          }))
        : body.details;
    return {
      error: body.error ?? codes[reply.statusCode] ?? 'INTERNAL_SERVER_ERROR',
      message: body.message ?? 'Request could not be completed',
      ...(details ? { details } : {}),
      requestId: reply.getHeader('x-request-id'),
    };
  });
}
