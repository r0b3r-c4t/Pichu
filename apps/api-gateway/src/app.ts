import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import { randomUUID } from 'node:crypto';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import { gatewayOpenApiOptions, gatewaySwaggerUiOptions } from './routes/docs.js';
import { installGatewayIdentityResponses } from './routes/identity-errors.js';
import {
  configuredCorsOrigins,
  gatewayEnvSchema,
  loadGatewayEnv,
  type GatewayEnv,
} from './config/env.js';
import {
  bearerAuthorizationSchema,
  deviceLinkBodySchema,
  invitationAcceptBodySchema,
  invitationCreateBodySchema,
  invitationIdParamsInputSchema,
  loginBodySchema,
  passwordResetConfirmBodySchema,
  passwordResetRequestBodySchema,
  registerBodySchema,
  refreshRequestBodySchema,
  emailVerificationBodySchema,
  verificationResendBodySchema,
  vehicleCreateBodySchema,
  vehicleIdParamsInputSchema,
  vehicleListQueryInputSchema,
  vehicleErrorResponseSchema,
} from './schemas/gateway.schema.js';
import { proxyRequest, ProxyRequestError } from './lib/proxy.js';
import { jsonSchema } from './lib/openapi.js';
import { signInternalRequest } from './security/internal-auth.js';
import { GatewayJwtError, verifyGatewayAccessToken } from './security/jwt.js';
import {
  CONTRACTS_VERSION,
  invitationAcceptResponseSchema,
  invitationCreateResponseSchema,
  vehicleCreateResponseSchema,
  vehicleDetailResponseSchema,
  vehicleDeviceRegistrationResponseSchema,
  vehicleListResponseSchema,
  authenticatedUserResponseSchema,
  acceptedResponseSchema,
  deviceSummarySchema,
  deviceReferenceParamsSchema,
  requestIdSchema,
  gatewayErrorResponseSchema,
  healthResponseSchema,
} from '@pichu/contracts';
import { InMemoryRateLimiter } from './lib/rate-limiter.js';

const requestIds = new WeakMap<FastifyRequest, string>();
const emailNotVerifiedMessage = 'Debes verificar tu correo electrónico para continuar.';
const vehicleResponseExample = {
  id: '507f1f77bcf86cd799439011',
  name: 'Mazda 3',
  make: 'Mazda',
  model: '3',
  year: 2011,
  engine: '2.0',
  ownerUserId: '507f1f77bcf86cd799439012',
};
const vehicleErrorResponse = jsonSchema(vehicleErrorResponseSchema);
function vehicleErrorResponseWithExample(error: string, message: string) {
  return {
    ...vehicleErrorResponse,
    example: { error, message, requestId: 'request-1' },
  };
}

const vehicleNotFoundErrorResponse = {
  ...vehicleErrorResponseWithExample('NOT_FOUND', 'Requested resource not found'),
};
const vehicleCommonErrors = {
  400: vehicleErrorResponseWithExample('VALIDATION_ERROR', 'Invalid request'),
  401: vehicleErrorResponseWithExample('AUTHENTICATION_REQUIRED', 'Authentication required'),
  403: vehicleErrorResponseWithExample('EMAIL_NOT_VERIFIED', emailNotVerifiedMessage),
  500: vehicleErrorResponseWithExample('OPERATION_FAILED', 'Internal server error'),
  502: vehicleErrorResponseWithExample('BAD_GATEWAY', 'Upstream service unavailable'),
  503: vehicleErrorResponseWithExample('SERVICE_UNAVAILABLE', 'Service unavailable'),
  504: vehicleErrorResponseWithExample('GATEWAY_TIMEOUT', 'Upstream service timed out'),
  429: vehicleErrorResponseWithExample('RATE_LIMITED', 'Too many requests'),
};

const errorCodes: Record<number, string> = {
  400: 'VALIDATION_ERROR',
  401: 'AUTHENTICATION_REQUIRED',
  403: 'FORBIDDEN',
  404: 'NOT_FOUND',
  409: 'CONFLICT',
  413: 'PAYLOAD_TOO_LARGE',
  415: 'UNSUPPORTED_MEDIA_TYPE',
  429: 'RATE_LIMITED',
  500: 'OPERATION_FAILED',
  502: 'BAD_GATEWAY',
  503: 'SERVICE_UNAVAILABLE',
  504: 'GATEWAY_TIMEOUT',
};

const errorMessages: Record<number, string> = {
  400: 'Invalid request',
  401: 'Authentication required',
  403: 'Forbidden',
  404: 'Route not found',
  409: 'Request conflicts with existing data',
  413: 'Payload too large',
  415: 'Unsupported media type',
  429: 'Too many requests',
  500: 'Internal server error',
  502: 'Upstream service unavailable',
  503: 'Service unavailable',
  504: 'Upstream service timed out',
};

function normalizeErrorResponse(
  status: number,
  payload: unknown,
  requestId: string,
): {
  error: string;
  message: string;
  details?: Array<{ field: string; message: string }>;
  requestId: string;
} {
  const body =
    typeof payload === 'object' && payload !== null ? (payload as Record<string, unknown>) : {};
  const nestedError =
    typeof body.error === 'object' && body.error !== null
      ? (body.error as Record<string, unknown>)
      : undefined;
  const errorCandidate =
    typeof body.error === 'string'
      ? body.error
      : typeof nestedError?.code === 'string'
        ? nestedError.code
        : (errorCodes[status] ?? 'OPERATION_FAILED');
  const error =
    status >= 500
      ? (errorCodes[status] ?? 'OPERATION_FAILED')
      : errorCandidate.trim().slice(0, 64) || (errorCodes[status] ?? 'OPERATION_FAILED');
  const messageCandidate =
    status >= 500
      ? (errorMessages[status] ?? 'Request could not be completed')
      : typeof body.message === 'string'
        ? body.message
        : typeof nestedError?.message === 'string'
          ? nestedError.message
          : (errorMessages[status] ?? 'Request could not be completed');
  const message =
    messageCandidate.trim().slice(0, 500) ||
    (errorMessages[status] ?? 'Request could not be completed');
  const details =
    status < 500 && Array.isArray(body.details)
      ? body.details.slice(0, 50).flatMap((detail) => {
          if (typeof detail !== 'object' || detail === null) return [];
          const item = detail as Record<string, unknown>;
          if (typeof item.message !== 'string' || !item.message.trim()) return [];
          return [
            {
              field:
                typeof item.field === 'string' && item.field.trim()
                  ? item.field.trim().slice(0, 128)
                  : 'body',
              message: item.message.trim().slice(0, 200),
            },
          ];
        })
      : undefined;

  return {
    error,
    message,
    ...(details?.length ? { details } : {}),
    requestId,
  };
}

function extractUserId(
  authorization: string | undefined,
  secret: string,
  env: GatewayEnv,
): string | undefined {
  const parsedAuthorization = bearerAuthorizationSchema.safeParse(authorization);
  if (!parsedAuthorization.success) return undefined;
  try {
    return verifyGatewayAccessToken(
      parsedAuthorization.data.slice(7),
      secret,
      env.JWT_ISSUER,
      env.JWT_AUDIENCE,
    ).userId;
  } catch (error) {
    if (!(error instanceof GatewayJwtError)) return undefined;
    return undefined;
  }
}

function getRequestId(request: FastifyRequest): string {
  return requestIds.get(request) ?? randomUUID();
}

function requiresVerifiedEmail(path: string | undefined): boolean {
  if (!path) return false;
  return ['/api/vehicles', '/api/invitations', '/api/devices', '/api/automation'].some(
    (prefix) => path === prefix || path.startsWith(`${prefix}/`),
  );
}

function sendProxyResult(
  reply: FastifyReply,
  requestId: string,
  status: number,
  body: unknown,
  setCookies: string[] = [],
) {
  reply.header('x-request-id', requestId).code(status);
  if (setCookies.length > 0) reply.header('set-cookie', setCookies);
  return body === undefined ? reply.send() : reply.send(body);
}

function sendProxyError(reply: FastifyReply, requestId: string, error: unknown) {
  const status = error instanceof ProxyRequestError && error.kind === 'timeout' ? 504 : 502;
  return sendProxyResult(reply, requestId, status, {
    message: status === 504 ? 'Upstream service timed out' : 'Upstream service unavailable',
    requestId,
  });
}

export interface GatewayAppOptions {
  env?: GatewayEnv;
  fetchImpl?: typeof fetch;
}

export function createApp(options: GatewayAppOptions = {}): FastifyInstance {
  const env = options.env ? gatewayEnvSchema.parse(options.env) : loadGatewayEnv();
  const fetchImpl = options.fetchImpl;
  const app = Fastify({
    logger: true,
    bodyLimit: env.MAX_PAYLOAD_BYTES,
    ajv: { customOptions: { removeAdditional: false } },
  });
  const corsOrigins = configuredCorsOrigins(env);
  installGatewayIdentityResponses(app);
  const rateLimiter = new InMemoryRateLimiter();
  app.addHook('onSend', async (_request, reply, payload) => {
    reply
      .header('x-content-type-options', 'nosniff')
      .header('x-frame-options', 'DENY')
      .header('referrer-policy', 'strict-origin-when-cross-origin')
      .header('permissions-policy', 'camera=(), microphone=(), geolocation=()');
    return payload;
  });
  app.addHook('preSerialization', async (request, reply, payload) => {
    if (reply.statusCode < 400) return payload;
    return normalizeErrorResponse(reply.statusCode, payload, getRequestId(request));
  });
  app.addHook('onRoute', (route) => {
    if (route.url.startsWith('/health') || route.url.startsWith('/docs')) return;
    route.schema ??= {};
    const responses: Record<string, unknown> = {
      ...(typeof route.schema.response === 'object' ? route.schema.response : {}),
    };
    responses[429] = jsonSchema(gatewayErrorResponseSchema);
    responses.default ??= jsonSchema(gatewayErrorResponseSchema);
    route.schema.response = responses;
  });
  app.setErrorHandler((error, request, reply) => {
    const requestId = getRequestId(request);
    const code = error instanceof Error && 'code' in error ? String(error.code) : undefined;
    const status =
      code === 'FST_ERR_CTP_BODY_TOO_LARGE'
        ? 413
        : code === 'FST_ERR_CTP_INVALID_MEDIA_TYPE'
          ? 415
          : code === 'FST_ERR_VALIDATION' ||
              code === 'FST_ERR_CTP_INVALID_JSON_BODY' ||
              code === 'FST_ERR_CTP_EMPTY_JSON_BODY'
            ? 400
            : 500;
    if (status >= 500) request.log.error({ code }, 'Gateway request failed');
    reply
      .code(status)
      .header('x-request-id', requestId)
      .send(normalizeErrorResponse(status, { message: errorMessages[status] }, requestId));
  });
  app.setNotFoundHandler((request, reply) => {
    const requestId = getRequestId(request);
    return reply
      .code(404)
      .header('x-request-id', requestId)
      .send(normalizeErrorResponse(404, undefined, requestId));
  });

  app.addHook('onRequest', async (request, reply) => {
    const incoming = request.headers['x-request-id'];
    const candidate =
      typeof incoming === 'string' && /^[A-Za-z0-9._:-]{1,128}$/.test(incoming)
        ? incoming
        : randomUUID();
    requestIds.set(request, candidate);
    request.log = request.log.child({ requestId: candidate });
    reply.header('x-request-id', candidate);

    const origin = request.headers.origin;
    if (origin !== undefined) {
      if (!corsOrigins.has(origin)) {
        await reply
          .code(403)
          .send(
            normalizeErrorResponse(
              403,
              { error: 'FORBIDDEN', message: 'Origin not allowed' },
              candidate,
            ),
          );
        return;
      }
      reply.header('access-control-allow-origin', origin);
      reply.header('vary', 'Origin');
      reply.header('access-control-allow-credentials', 'true');
      reply.header('access-control-allow-methods', 'GET,POST,DELETE,OPTIONS');
      reply.header('access-control-allow-headers', 'authorization,content-type,x-request-id');
      reply.header('access-control-expose-headers', 'x-request-id,retry-after');
    }
    if (request.method === 'OPTIONS') {
      await reply.code(204).send();
      return;
    }

    if (request.url.startsWith('/health') || request.url.startsWith('/docs')) return;
    const key = `${request.ip}:${request.url.startsWith('/api/auth') ? 'sensitive' : 'global'}`;
    const limit = key.endsWith('sensitive') ? env.SENSITIVE_RATE_LIMIT_MAX : env.RATE_LIMIT_MAX;
    const retryAfter = rateLimiter.consume(key, limit, env.RATE_LIMIT_WINDOW_SECONDS * 1000);
    if (retryAfter !== undefined) {
      reply.header('retry-after', retryAfter);
      await reply
        .code(429)
        .send(
          normalizeErrorResponse(
            429,
            { error: 'RATE_LIMITED', message: 'Too many requests' },
            candidate,
          ),
        );
    }
  });
  app.addHook('preHandler', async (request, reply) => {
    if (!requiresVerifiedEmail(request.routeOptions.url)) return;
    const requestId = getRequestId(request);
    const userId = extractUserId(request.headers.authorization, env.JWT_SECRET, env);
    if (!userId) {
      await sendProxyResult(reply, requestId, 401, {
        message: 'Authentication required',
        requestId,
      });
      return;
    }
    try {
      const profileResponse = await proxyRequest({
        url: `${env.IDENTITY_SERVICE_URL}/auth/me`,
        method: 'GET',
        headers: {
          authorization: request.headers.authorization!,
          'x-request-id': requestId,
        },
        timeoutMs: env.PROXY_TIMEOUT_MS,
        fetchImpl,
      });
      if (profileResponse.status === 401) {
        await sendProxyResult(reply, requestId, 401, {
          message: 'Authentication required',
          requestId,
        });
        return;
      }
      const profile = authenticatedUserResponseSchema.safeParse(profileResponse.body);
      if (profileResponse.status !== 200 || !profile.success || profile.data.id !== userId) {
        await sendProxyResult(reply, requestId, 503, {
          message: 'Authentication service unavailable',
          requestId,
        });
        return;
      }
      if (!profile.data.emailVerified) {
        await sendProxyResult(reply, requestId, 403, {
          error: 'EMAIL_NOT_VERIFIED',
          message: emailNotVerifiedMessage,
          requestId,
        });
      }
    } catch (error) {
      await sendProxyError(reply, requestId, error);
    }
  });
  void app.register(swagger, gatewayOpenApiOptions);
  void app.register(swaggerUi, gatewaySwaggerUiOptions);

  app.decorate('createInternalHeaders', (method: string, url: string, body: unknown) => {
    const requestId = randomUUID();
    const timestamp = String(Date.now());
    return {
      'x-service-name': 'api-gateway',
      'x-contract-version': CONTRACTS_VERSION,
      'x-request-id': requestId,
      'x-timestamp': timestamp,
      'x-signature': signInternalRequest(
        env.INTERNAL_SERVICE_SECRET,
        method,
        url,
        body,
        timestamp,
        requestId,
      ),
    };
  });

  app.after(() => {
    const livenessHandler = async (request: FastifyRequest, reply: FastifyReply) => {
      const requestId = getRequestId(request);
      reply.header('x-request-id', requestId);
      return { status: 'ok', service: 'api-gateway', requestId };
    };
    app.get(
      '/health',
      {
        schema: {
          tags: ['Health'],
          summary: 'Gateway liveness (legacy alias)',
          response: { 200: jsonSchema(healthResponseSchema) },
        },
      },
      livenessHandler,
    );
    app.get(
      '/health/live',
      {
        schema: {
          tags: ['Health'],
          summary: 'Gateway liveness',
          response: { 200: jsonSchema(healthResponseSchema) },
        },
      },
      livenessHandler,
    );

    app.get(
      '/health/ready',
      {
        schema: {
          tags: ['Health'],
          summary: 'Gateway readiness',
          response: {
            200: jsonSchema(healthResponseSchema),
            503: jsonSchema(gatewayErrorResponseSchema),
          },
        },
      },
      async (request, reply) => {
        const requestId = getRequestId(request);
        const checks = await Promise.allSettled(
          [env.IDENTITY_SERVICE_URL, env.VEHICLE_SERVICE_URL, env.DEVICE_SERVICE_URL].map(
            (baseUrl) =>
              proxyRequest({
                url: `${baseUrl}/health`,
                method: 'GET',
                timeoutMs: env.PROXY_TIMEOUT_MS,
                fetchImpl,
              }),
          ),
        );
        const ready = checks.every(
          (check) =>
            check.status === 'fulfilled' && check.value.status >= 200 && check.value.status < 300,
        );
        if (!ready)
          return reply
            .header('x-request-id', requestId)
            .code(503)
            .send(
              normalizeErrorResponse(
                503,
                { error: 'SERVICE_UNAVAILABLE', message: 'A required service is unavailable' },
                requestId,
              ),
            );
        return sendProxyResult(reply, requestId, 200, {
          status: 'ok',
          service: 'api-gateway',
          requestId,
        });
      },
    );

    const proxyVehicle = async (
      request: FastifyRequest,
      reply: FastifyReply,
      method: string,
      path: string,
      body: unknown = {},
      serviceUrl = env.VEHICLE_SERVICE_URL,
    ) => {
      const requestId = getRequestId(request);
      const userId = extractUserId(request.headers.authorization, env.JWT_SECRET, env);
      if (!userId)
        return sendProxyResult(reply, requestId, 401, { message: 'Authentication required' });

      const payload =
        method === 'GET'
          ? {}
          : { ...(typeof body === 'object' && body !== null ? body : {}), userId };
      const timestamp = String(Date.now());
      const signature = signInternalRequest(
        env.INTERNAL_SERVICE_SECRET,
        method,
        path,
        payload,
        timestamp,
        requestId,
      );
      try {
        const response = await proxyRequest({
          url: `${serviceUrl}${path}`,
          method,
          body: method === 'GET' ? undefined : payload,
          headers: {
            'content-type': 'application/json',
            'x-service-name': 'api-gateway',
            'x-contract-version': CONTRACTS_VERSION,
            'x-request-id': requestId,
            'x-timestamp': timestamp,
            'x-signature': signature,
          },
          timeoutMs: env.PROXY_TIMEOUT_MS,
          fetchImpl,
        });
        return sendProxyResult(reply, requestId, response.status, response.body);
      } catch (error) {
        return sendProxyError(reply, requestId, error);
      }
    };

    const proxyIdentity = async (
      request: FastifyRequest,
      reply: FastifyReply,
      method: string,
      path: string,
      body?: unknown,
    ) => {
      const requestId = getRequestId(request);
      const headers: Record<string, string> = {
        'x-request-id': requestId,
      };
      if (body !== undefined) headers['content-type'] = 'application/json';
      for (const name of ['authorization', 'cookie', 'origin', 'user-agent']) {
        const value = request.headers[name];
        if (typeof value === 'string') headers[name] = value;
      }
      try {
        const response = await proxyRequest({
          url: `${env.IDENTITY_SERVICE_URL}${path}`,
          method,
          body,
          headers,
          timeoutMs: env.PROXY_TIMEOUT_MS,
          fetchImpl,
        });
        if (response.retryAfter) reply.header('retry-after', response.retryAfter);
        return sendProxyResult(
          reply,
          requestId,
          response.status,
          response.body,
          response.setCookies.map((cookie) =>
            cookie.startsWith('pichu_refresh_token=')
              ? cookie.replace(/;\s*Path=\/auth(?=;|$)/i, '; Path=/api/auth')
              : cookie,
          ),
        );
      } catch (error) {
        return sendProxyError(reply, requestId, error);
      }
    };

    app.post(
      '/api/auth/register',
      {
        schema: {
          tags: ['Identity'],
          summary: 'Register user',
          body: jsonSchema(registerBodySchema),
          response: {
            200: {
              type: 'object',
              properties: { accepted: { const: true } },
              required: ['accepted'],
              additionalProperties: false,
            },
          },
        },
      },
      async (request, reply) => {
        const parsed = registerBodySchema.safeParse(request.body);
        if (!parsed.success)
          return sendProxyResult(reply, getRequestId(request), 400, {
            message: 'Invalid registration data',
          });
        return proxyIdentity(request, reply, 'POST', '/auth/register', parsed.data);
      },
    );

    app.post(
      '/api/auth/login',
      {
        schema: {
          tags: ['Identity'],
          summary: 'Login user (email verification is not required)',
          body: jsonSchema(loginBodySchema),
          response: {
            200: {
              type: 'object',
              properties: {
                accessToken: { type: 'string' },
              },
              required: ['accessToken'],
              additionalProperties: false,
            },
          },
        },
      },
      async (request, reply) => {
        const parsed = loginBodySchema.safeParse(request.body);
        if (!parsed.success)
          return sendProxyResult(reply, getRequestId(request), 400, {
            message: 'Invalid login request',
          });
        return proxyIdentity(request, reply, 'POST', '/auth/login', parsed.data);
      },
    );

    app.post(
      '/api/auth/refresh',
      {
        schema: {
          tags: ['Identity'],
          summary: 'Refresh session',
          response: {
            200: {
              type: 'object',
              properties: {
                accessToken: { type: 'string' },
              },
              required: ['accessToken'],
              additionalProperties: false,
            },
          },
        },
      },
      async (request, reply) => {
        const parsed = refreshRequestBodySchema.safeParse(request.body);
        if (!parsed.success)
          return sendProxyResult(reply, getRequestId(request), 400, {
            message: 'Invalid refresh request body',
            details: [
              {
                field: 'body',
                message: 'Refresh does not accept token data in the request body',
              },
            ],
          });
        return proxyIdentity(request, reply, 'POST', '/auth/refresh', parsed.data);
      },
    );

    app.post(
      '/api/auth/verify-email',
      {
        schema: {
          tags: ['Identity'],
          summary: 'Verify email',
          body: jsonSchema(emailVerificationBodySchema),
          response: {
            200: {
              type: 'object',
              properties: { verified: { const: true } },
              required: ['verified'],
              additionalProperties: false,
            },
          },
        },
      },
      async (request, reply) => {
        const parsed = emailVerificationBodySchema.safeParse(request.body);
        if (!parsed.success)
          return sendProxyResult(reply, getRequestId(request), 400, {
            message: 'Invalid verification token',
          });
        return proxyIdentity(request, reply, 'POST', '/auth/verify-email', parsed.data);
      },
    );

    app.post(
      '/api/auth/verification/resend',
      {
        schema: {
          tags: ['Identity'],
          summary: 'Resend verification',
          body: jsonSchema(verificationResendBodySchema),
          response: {
            202: {
              type: 'object',
              properties: { accepted: { const: true } },
              required: ['accepted'],
              additionalProperties: false,
            },
          },
        },
      },
      async (request, reply) => {
        const parsed = verificationResendBodySchema.safeParse(request.body);
        if (!parsed.success)
          return sendProxyResult(reply, getRequestId(request), 400, {
            message: 'Invalid email address',
          });
        return proxyIdentity(request, reply, 'POST', '/auth/verification/resend', parsed.data);
      },
    );

    app.post(
      '/api/auth/password-reset/request',
      {
        schema: {
          tags: ['Identity'],
          summary: 'Request password reset',
          body: jsonSchema(passwordResetRequestBodySchema),
          response: {
            202: {
              type: 'object',
              properties: { accepted: { const: true } },
              required: ['accepted'],
              additionalProperties: false,
            },
          },
        },
      },
      async (request, reply) => {
        const parsed = passwordResetRequestBodySchema.safeParse(request.body);
        if (!parsed.success)
          return sendProxyResult(reply, getRequestId(request), 400, {
            message: 'Invalid email address',
          });
        return proxyIdentity(request, reply, 'POST', '/auth/password-reset/request', parsed.data);
      },
    );

    app.get(
      '/api/auth/me',
      {
        schema: {
          tags: ['Identity'],
          summary: 'Read current profile and email verification state',
          security: [{ bearerAuth: [] }],
          response: {
            200: jsonSchema(authenticatedUserResponseSchema),
            401: vehicleErrorResponse,
            503: vehicleErrorResponse,
          },
        },
      },
      async (request, reply) => proxyIdentity(request, reply, 'GET', '/auth/me'),
    );
    app.post(
      '/api/auth/verification/resend/me',
      {
        schema: {
          tags: ['Identity'],
          summary: 'Request verification email for the authenticated account',
          security: [{ bearerAuth: [] }],
          response: {
            202: jsonSchema(acceptedResponseSchema),
            401: vehicleErrorResponse,
            429: vehicleErrorResponse,
            503: vehicleErrorResponse,
          },
        },
      },
      async (request, reply) =>
        proxyIdentity(request, reply, 'POST', '/auth/verification/resend/me'),
    );

    app.post(
      '/api/auth/password-reset/confirm',
      {
        schema: {
          tags: ['Identity'],
          summary: 'Confirm password reset',
          body: jsonSchema(passwordResetConfirmBodySchema),
          response: {
            200: {
              type: 'object',
              properties: { reset: { const: true } },
              required: ['reset'],
              additionalProperties: false,
            },
          },
        },
      },
      async (request, reply) => {
        const parsed = passwordResetConfirmBodySchema.safeParse(request.body);
        if (!parsed.success)
          return sendProxyResult(reply, getRequestId(request), 400, {
            message: 'Invalid password reset request',
          });
        return proxyIdentity(request, reply, 'POST', '/auth/password-reset/confirm', parsed.data);
      },
    );

    app.post('/api/auth/logout', async (request, reply) =>
      proxyIdentity(request, reply, 'POST', '/auth/logout'),
    );
    app.post('/api/auth/logout-all', async (request, reply) =>
      proxyIdentity(request, reply, 'POST', '/auth/logout-all'),
    );
    app.get('/api/sessions', async (request, reply) =>
      proxyIdentity(request, reply, 'GET', '/sessions'),
    );
    app.delete<{ Params: { sessionId: string } }>(
      '/api/sessions/:sessionId',
      async (request, reply) => {
        if (!/^[a-f0-9]{24}$/.test(request.params.sessionId))
          return sendProxyResult(reply, getRequestId(request), 404, {
            message: 'Session not found',
          });
        return proxyIdentity(request, reply, 'DELETE', `/sessions/${request.params.sessionId}`);
      },
    );

    app.post(
      '/api/vehicles',
      {
        schema: {
          tags: ['Vehicles'],
          summary: 'Create vehicle (verified email required)',
          security: [{ bearerAuth: [] }],
          body: jsonSchema(vehicleCreateBodySchema),
          response: {
            ...vehicleCommonErrors,
            201: {
              ...jsonSchema(vehicleCreateResponseSchema),
              example: {
                vehicleId: vehicleResponseExample.id,
                message: 'Vehicle created',
                data: vehicleResponseExample,
                requestId: 'request-1',
              },
            },
          },
        },
      },
      async (request, reply) => {
        const parsed = vehicleCreateBodySchema.safeParse(request.body);
        if (!parsed.success)
          return sendProxyResult(reply, getRequestId(request), 400, {
            message: 'Invalid vehicle data',
          });
        return proxyVehicle(request, reply, 'POST', '/vehicles', parsed.data);
      },
    );

    app.get(
      '/api/vehicles',
      {
        schema: {
          tags: ['Vehicles'],
          summary: 'List vehicles (verified email required)',
          security: [{ bearerAuth: [] }],
          querystring: jsonSchema(vehicleListQueryInputSchema),
          response: {
            ...vehicleCommonErrors,
            200: {
              ...jsonSchema(vehicleListResponseSchema),
              example: { vehicles: [vehicleResponseExample], requestId: 'request-1' },
            },
          },
        },
      },
      async (request, reply) => {
        const parsed = vehicleListQueryInputSchema.safeParse(request.query);
        if (!parsed.success)
          return sendProxyResult(reply, getRequestId(request), 400, {
            message: 'Invalid vehicle query',
          });
        const userId = extractUserId(request.headers.authorization, env.JWT_SECRET, env);
        const query = new URLSearchParams({ userId: userId ?? '' });
        if (parsed.data.limit !== undefined) query.set('limit', String(parsed.data.limit));
        if (parsed.data.cursor !== undefined) query.set('cursor', parsed.data.cursor);
        return proxyVehicle(request, reply, 'GET', `/vehicles?${query.toString()}`);
      },
    );

    app.get<{ Params: { vehicleId: string } }>(
      '/api/vehicles/:vehicleId',
      {
        schema: {
          tags: ['Vehicles'],
          summary: 'Get vehicle (verified email required)',
          security: [{ bearerAuth: [] }],
          params: jsonSchema(vehicleIdParamsInputSchema),
          response: {
            ...vehicleCommonErrors,
            404: vehicleNotFoundErrorResponse,
            200: {
              ...jsonSchema(vehicleDetailResponseSchema),
              example: { ...vehicleResponseExample, requestId: 'request-1' },
            },
          },
        },
      },
      async (request, reply) => {
        const params = vehicleIdParamsInputSchema.safeParse(request.params);
        if (!params.success || !zodEmptyQuery(request.query))
          return sendProxyResult(reply, getRequestId(request), 400, {
            message: 'Invalid vehicle request',
          });
        const userId = extractUserId(request.headers.authorization, env.JWT_SECRET, env);
        return proxyVehicle(
          request,
          reply,
          'GET',
          `/vehicles/${params.data.vehicleId}?userId=${userId ?? ''}`,
        );
      },
    );

    app.post<{ Params: { vehicleId: string } }>(
      '/api/vehicles/:vehicleId/invitations',
      {
        schema: {
          tags: ['Invitations'],
          summary: 'Create invitation (verified email required)',
          security: [{ bearerAuth: [] }],
          params: jsonSchema(vehicleIdParamsInputSchema),
          body: jsonSchema(invitationCreateBodySchema),
          response: {
            ...vehicleCommonErrors,
            404: vehicleNotFoundErrorResponse,
            201: {
              ...jsonSchema(invitationCreateResponseSchema),
              example: {
                invitationId: '507f1f77bcf86cd799439013',
                status: 'PENDING',
                message: 'Invitation created',
                data: {
                  id: '507f1f77bcf86cd799439013',
                  vehicleId: vehicleResponseExample.id,
                  inviteeUserId: '507f1f77bcf86cd799439014',
                  permissions: ['vehicle:read'],
                  status: 'PENDING',
                  expiresAt: '2026-11-10T12:00:00.000Z',
                },
                requestId: 'request-1',
              },
            },
          },
        },
      },
      async (request, reply) => {
        const params = vehicleIdParamsInputSchema.safeParse(request.params);
        const body = invitationCreateBodySchema.safeParse(request.body);
        if (!params.success || !body.success)
          return sendProxyResult(reply, getRequestId(request), 400, {
            message: 'Invalid invitation data',
          });
        return proxyVehicle(
          request,
          reply,
          'POST',
          `/vehicles/${params.data.vehicleId}/invitations`,
          body.data,
        );
      },
    );

    app.post<{ Params: { invitationId: string } }>(
      '/api/invitations/:invitationId/accept',
      {
        schema: {
          tags: ['Invitations'],
          summary: 'Accept invitation (verified email required)',
          security: [{ bearerAuth: [] }],
          params: jsonSchema(invitationIdParamsInputSchema),
          body: jsonSchema(invitationAcceptBodySchema),
          response: {
            ...vehicleCommonErrors,
            404: vehicleNotFoundErrorResponse,
            200: {
              ...jsonSchema(invitationAcceptResponseSchema),
              example: {
                accepted: true,
                vehicleId: vehicleResponseExample.id,
                message: 'Invitation accepted',
                data: {
                  vehicleId: vehicleResponseExample.id,
                  userId: '507f1f77bcf86cd799439014',
                  role: 'MEMBER',
                  permissions: ['vehicle:read'],
                },
                requestId: 'request-1',
              },
            },
          },
        },
      },
      async (request, reply) => {
        const params = invitationIdParamsInputSchema.safeParse(request.params);
        const body = invitationAcceptBodySchema.safeParse(request.body);
        if (!params.success || !body.success)
          return sendProxyResult(reply, getRequestId(request), 400, {
            message: 'Invalid invitation data',
          });
        return proxyVehicle(
          request,
          reply,
          'POST',
          `/invitations/${params.data.invitationId}/accept`,
          body.data,
        );
      },
    );

    app.post<{ Params: { vehicleId: string } }>(
      '/api/vehicles/:vehicleId/devices/link',
      {
        schema: {
          tags: ['Vehicles'],
          summary: 'Link device to vehicle (verified email required)',
          security: [{ bearerAuth: [] }],
          params: jsonSchema(vehicleIdParamsInputSchema),
          body: jsonSchema(deviceLinkBodySchema),
          response: {
            ...vehicleCommonErrors,
            404: vehicleNotFoundErrorResponse,
            201: {
              ...jsonSchema(vehicleDeviceRegistrationResponseSchema),
              example: {
                deviceId: '507f1f77bcf86cd799439015',
                status: 'PENDING',
                message: 'Device registration accepted',
                data: {
                  deviceId: '507f1f77bcf86cd799439015',
                  vehicleId: vehicleResponseExample.id,
                  status: 'PENDING',
                },
                requestId: 'request-1',
              },
            },
          },
        },
      },
      async (request, reply) => {
        const params = vehicleIdParamsInputSchema.safeParse(request.params);
        const body = deviceLinkBodySchema.safeParse(request.body);
        if (!params.success || !body.success)
          return sendProxyResult(reply, getRequestId(request), 400, {
            message: 'Invalid linking data',
          });
        return proxyVehicle(
          request,
          reply,
          'POST',
          `/vehicles/${params.data.vehicleId}/devices/link`,
          body.data,
        );
      },
    );
    app.get<{ Params: { deviceId: string } }>(
      '/api/devices/:deviceId',
      {
        schema: {
          tags: ['Devices'],
          summary: 'Get an active device linked by the authenticated user',
          security: [{ bearerAuth: [] }],
          params: jsonSchema(deviceReferenceParamsSchema),
          response: {
            ...vehicleCommonErrors,
            404: vehicleNotFoundErrorResponse,
            200: jsonSchema(deviceSummarySchema.extend({ requestId: requestIdSchema })),
          },
        },
      },
      async (request, reply) => {
        const params = deviceReferenceParamsSchema.safeParse(request.params);
        if (!params.success || !zodEmptyQuery(request.query))
          return sendProxyResult(reply, getRequestId(request), 400, {
            message: 'Invalid device request',
          });
        const userId = extractUserId(request.headers.authorization, env.JWT_SECRET, env);
        return proxyVehicle(
          request,
          reply,
          'GET',
          `/devices/${params.data.deviceId}?userId=${userId ?? ''}`,
          {},
          env.DEVICE_SERVICE_URL,
        );
      },
    );
  });
  return app;
}

function zodEmptyQuery(value: unknown): boolean {
  return typeof value === 'object' && value !== null && Object.keys(value).length === 0;
}
