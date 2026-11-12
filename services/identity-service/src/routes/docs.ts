import type { FastifyPluginAsync } from 'fastify';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import type { OpenAPIV3 } from 'openapi-types';
import { z, type ZodType } from 'zod';
import { usernameSchema } from '@pichu/contracts';
import {
  loginSchema,
  passwordRecoveryConfirmSchema,
  passwordRecoveryRequestSchema,
  registerSchema,
  resendVerificationSchema,
  verifyEmailSchema,
} from '../schemas/auth.schema.js';
import { apiErrorResponseSchema } from '../schemas/error.schema.js';

function jsonSchema(schema: ZodType): OpenAPIV3.SchemaObject {
  const generated = z.toJSONSchema(schema, { target: 'draft-7' }) as Record<string, unknown>;
  delete generated.$schema;
  return generated as OpenAPIV3.SchemaObject;
}

const accepted = z.strictObject({ accepted: z.literal(true) });
const access = z.strictObject({ accessToken: z.string() });
const revoked = z.strictObject({ revoked: z.literal(true) });
const session = z.strictObject({
  sessionId: z.string(),
  createdAt: z.string(),
  lastActivityAt: z.string(),
  expiresAt: z.string(),
  userAgent: z.string().nullable().optional(),
  revokedAt: z.string().nullable(),
  current: z.boolean(),
});
const authenticatedUserResponseSchema = z.strictObject({
  id: z.string().regex(/^[a-f0-9]{24}$/),
  name: z.string(),
  username: usernameSchema.nullable(),
  email: z.string().email(),
  emailVerified: z.boolean(),
  emailVerifiedAt: z.string().datetime().nullable(),
});

function response(description: string, schema: ZodType): OpenAPIV3.ResponseObject {
  return { description, content: { 'application/json': { schema: jsonSchema(schema) } } };
}

function errors(...statuses: number[]): OpenAPIV3.ResponsesObject {
  const descriptions: Record<number, string> = {
    400: 'Invalid request',
    401: 'Authentication failed',
    403: 'Forbidden',
    404: 'Not found',
    409: 'Email or username already in use',
    429: 'Rate limit exceeded',
    413: 'Payload too large',
    415: 'Unsupported media type',
    500: 'Internal error',
    503: 'Service unavailable',
  };
  return Object.fromEntries(
    statuses.map((status) => [
      status,
      response(descriptions[status] ?? 'Request failed', apiErrorResponseSchema),
    ]),
  );
}

function body(schema: ZodType): OpenAPIV3.RequestBodyObject {
  return { required: true, content: { 'application/json': { schema: jsonSchema(schema) } } };
}

const cookie: OpenAPIV3.HeaderObject = {
  description: 'HttpOnly refresh token cookie for cookie transport',
  schema: { type: 'string' },
};
const bearer: OpenAPIV3.SecurityRequirementObject[] = [{ bearerAuth: [] }];

const document: OpenAPIV3.Document = {
  openapi: '3.0.3',
  info: { title: 'PICHU Identity Service', version: '0.1.0' },
  tags: [
    'Health',
    'Registration',
    'Authentication',
    'Sessions',
    'Email verification',
    'Password recovery',
  ].map((name) => ({ name })),
  components: {
    securitySchemes: {
      bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
      refreshCookie: { type: 'apiKey', in: 'cookie', name: 'pichu_refresh_token' },
    },
  },
  paths: {
    '/health': {
      get: {
        tags: ['Health'],
        summary: 'Service health',
        responses: { 200: response('Running', z.strictObject({ status: z.literal('ok') })) },
      },
    },
    '/health/db': {
      get: {
        tags: ['Health'],
        summary: 'MongoDB health',
        responses: {
          200: response(
            'Connected',
            z.strictObject({ status: z.literal('ok'), database: z.literal('connected') }),
          ),
          ...errors(503),
        },
      },
    },
    '/auth/register': {
      post: {
        tags: ['Registration'],
        summary: 'Register account',
        description: 'New passwords must contain at least 8 characters and no more than 256.',
        requestBody: body(registerSchema),
        responses: {
          200: response('New account accepted for email verification', accepted),
          ...errors(400, 413, 415, 429, 500, 503),
          409: {
            description: 'Email or username already in use',
            content: {
              'application/json': {
                schema: jsonSchema(apiErrorResponseSchema),
                examples: {
                  email: {
                    summary: 'Email is already registered',
                    value: {
                      error: 'USER_ALREADY_EXISTS',
                      message: 'Email already in use',
                      requestId: 'request-123',
                    },
                  },
                  username: {
                    summary: 'Username is already registered',
                    value: {
                      error: 'USERNAME_ALREADY_EXISTS',
                      message: 'Username already in use',
                      requestId: 'request-123',
                    },
                  },
                },
              },
            },
          },
        },
      },
    },
    '/auth/login': {
      post: {
        tags: ['Authentication'],
        summary: 'Login (email verification is not required)',
        description:
          'Sets an HttpOnly refresh cookie. Requires the configured Origin. Returns only an access token in JSON.',
        requestBody: body(loginSchema),
        responses: {
          200: {
            ...response('Access token; refresh cookie set separately', access),
            headers: { 'Set-Cookie': cookie },
          },
          ...errors(400, 401, 403, 413, 415, 429, 500, 503),
        },
      },
    },
    '/auth/refresh': {
      post: {
        tags: ['Authentication'],
        summary: 'Rotate refresh token',
        description:
          'The browser sends the HttpOnly refresh cookie automatically. Requires the configured Origin. No request body is needed; an empty JSON object is accepted. The cookie is rotated on success.',
        security: [{ refreshCookie: [] }],
        responses: {
          200: {
            ...response('New access token and rotated refresh cookie', access),
            headers: { 'Set-Cookie': cookie },
          },
          ...errors(400, 401, 403, 413, 415, 429, 500, 503),
        },
      },
    },
    '/auth/logout': {
      post: {
        tags: ['Authentication'],
        summary: 'Revoke current session',
        description:
          'Requires the access token and configured Origin. Revokes the session and clears the refresh cookie.',
        security: bearer,
        responses: {
          200: { ...response('Revoked', revoked), headers: { 'Set-Cookie': cookie } },
          ...errors(401, 403, 500, 503),
        },
      },
    },
    '/auth/me': {
      get: {
        tags: ['Authentication'],
        summary: 'Get the authenticated user and current email verification status',
        description: 'Reads the current user state. An unverified user may call this endpoint.',
        security: bearer,
        responses: {
          200: response('Public user profile', authenticatedUserResponseSchema),
          ...errors(401, 500, 503),
        },
      },
    },
    '/auth/logout-all': {
      post: {
        tags: ['Authentication'],
        summary: 'Revoke all sessions',
        description:
          'Requires the access token and configured Origin. Revokes all sessions and clears the refresh cookie.',
        security: bearer,
        responses: {
          200: { ...response('Revoked', revoked), headers: { 'Set-Cookie': cookie } },
          ...errors(401, 403, 500, 503),
        },
      },
    },
    '/sessions': {
      get: {
        tags: ['Sessions'],
        summary: 'List active sessions',
        security: bearer,
        responses: {
          200: response('Sessions', z.strictObject({ sessions: z.array(session) })),
          ...errors(401, 500, 503),
        },
      },
    },
    '/sessions/{sessionId}': {
      delete: {
        tags: ['Sessions'],
        summary: 'Revoke owned session',
        security: bearer,
        parameters: [
          {
            name: 'sessionId',
            in: 'path',
            required: true,
            schema: { type: 'string', pattern: '^[a-f0-9]{24}$' },
          },
        ],
        responses: { 200: response('Revoked', revoked), ...errors(401, 404, 500, 503) },
      },
    },
    '/auth/verify-email': {
      post: {
        tags: ['Email verification'],
        summary: 'Verify email',
        requestBody: body(verifyEmailSchema),
        responses: {
          200: response('Verified', z.strictObject({ verified: z.literal(true) })),
          ...errors(400, 413, 415, 500, 503),
        },
      },
    },
    '/auth/verification/resend': {
      post: {
        tags: ['Email verification'],
        summary: 'Request verification email',
        requestBody: body(resendVerificationSchema),
        responses: {
          202: response('Accepted regardless of account existence', accepted),
          ...errors(400, 413, 415, 429, 500, 503),
        },
      },
    },
    '/auth/verification/resend/me': {
      post: {
        tags: ['Email verification'],
        summary: 'Request a verification email for the authenticated user',
        security: bearer,
        responses: {
          202: response('Accepted regardless of verification state', accepted),
          ...errors(401, 429, 500, 503),
        },
      },
    },
    '/auth/password-reset/request': {
      post: {
        tags: ['Password recovery'],
        summary: 'Request password reset',
        requestBody: body(passwordRecoveryRequestSchema),
        responses: {
          202: response('Accepted regardless of account existence', accepted),
          ...errors(400, 413, 415, 429, 500, 503),
        },
      },
    },
    '/auth/password-reset/confirm': {
      post: {
        tags: ['Password recovery'],
        summary: 'Confirm password reset',
        description:
          'Send {token, password}: use the recovery email token (64 lowercase hexadecimal characters), not an email verification token or JWT. New passwords must contain at least 8 characters and no more than 256. Invalid, expired and used tokens have the same response.',
        requestBody: body(passwordRecoveryConfirmSchema),
        responses: {
          200: response('Reset', z.strictObject({ reset: z.literal(true) })),
          ...errors(400, 413, 415, 500, 503),
        },
      },
    },
  },
};

export const docsRoutes: FastifyPluginAsync = async (fastify) => {
  await fastify.register(swagger, { mode: 'static', specification: { document } });
  await fastify.register(swaggerUi, {
    routePrefix: '/docs',
    uiConfig: {
      docExpansion: 'list',
      deepLinking: true,
      tryItOutEnabled: true,
      withCredentials: true,
    },
  });
};
