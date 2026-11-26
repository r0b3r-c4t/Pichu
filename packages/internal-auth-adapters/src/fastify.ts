import { performance } from 'node:perf_hooks';
import type { FastifyInstance, FastifyPluginAsync, FastifyRequest } from 'fastify';
import {
  internalCallerNameSchema,
  internalEnvironmentSchema,
  type InternalCallerName,
  type InternalEnvironment,
  type InternalRequestHeadersV2,
} from '@pichu/contracts';
import {
  InternalAuthError,
  parseRequestHeaders,
  validateRequestTarget,
  validateTimestampAndDeadline,
  verifyRequest,
  validateKeyring,
  type Keyring,
} from '@pichu/internal-auth';
import {
  NonceStoreUnavailable,
  type InternalPrincipal,
  type NonceStore,
  type OperationPolicy,
} from './types.js';

declare module 'fastify' {
  interface FastifyContextConfig {
    internalOperation?: string;
  }
}

export interface InternalAuthPluginOptions {
  readonly environment: InternalEnvironment;
  readonly audience: InternalCallerName;
  readonly keyring: () => Keyring;
  readonly nonces: NonceStore;
  readonly policies: Readonly<Record<string, OperationPolicy>>;
  readonly bodyLimit?: number;
  /** Register only protected routes in this encapsulated scope. */
  readonly routes: (scope: FastifyInstance) => Promise<void>;
}

interface State {
  headers: InternalRequestHeadersV2;
  rawHeaders: string[];
  method: string;
  target: string;
  body: Buffer;
  end: number;
  controller: AbortController;
  timer: ReturnType<typeof setTimeout>;
  principal?: InternalPrincipal;
}
const states = new WeakMap<FastifyRequest, State>();

export function getInternalPrincipal(request: FastifyRequest): InternalPrincipal {
  const principal = states.get(request)?.principal;
  if (!principal) throw new AdmissionError(401);
  return principal;
}

/** Downstream work MUST cooperate with cancellation; a timeout cannot undo side effects. */
export function getInternalSignal(request: FastifyRequest): AbortSignal {
  const state = states.get(request);
  if (!state?.principal) throw new AdmissionError(401);
  return state.controller.signal;
}

class AdmissionError extends Error {
  constructor(readonly statusCode: number) {
    super('Internal request rejected');
  }
}

function checkBudget(state: State): void {
  if (state.controller.signal.aborted || performance.now() >= state.end)
    throw new AdmissionError(504);
}

function statusFor(error: unknown): number {
  if (error instanceof AdmissionError) return error.statusCode;
  if (error instanceof NonceStoreUnavailable) return 503;
  if (error instanceof InternalAuthError)
    return {
      INVALID_FORMAT: 400,
      INVALID_AUTH: 401,
      DEADLINE_EXCEEDED: 504,
      INVALID_CONFIG: 503,
    }[error.code];
  if (
    error &&
    typeof error === 'object' &&
    'statusCode' in error &&
    [400, 413, 415].includes(Number(error.statusCode))
  )
    return Number(error.statusCode);
  return 500;
}

/** Plain encapsulated Fastify plugin, deliberately NOT wrapped in fastify-plugin. */
export const internalAuthPlugin: FastifyPluginAsync<InternalAuthPluginOptions> = async (
  app,
  options,
) => {
  const bodyLimit = options.bodyLimit ?? 1048576;
  if (
    !Number.isSafeInteger(bodyLimit) ||
    bodyLimit < 1 ||
    bodyLimit > 1048576 ||
    !internalEnvironmentSchema.safeParse(options.environment).success ||
    !internalCallerNameSchema.safeParse(options.audience).success
  )
    throw new InternalAuthError('INVALID_CONFIG');
  const currentKeyring = (): Keyring => {
    try {
      const keys = options.keyring();
      validateKeyring(keys);
      return keys;
    } catch {
      throw new InternalAuthError('INVALID_CONFIG');
    }
  };
  currentKeyring();
  const policies = new Map<string, OperationPolicy>();
  for (const [id, policy] of Object.entries(options.policies)) {
    if (
      !id ||
      !/^[A-Z]+$/.test(policy.method) ||
      !policy.route.startsWith('/') ||
      policy.senders.some((sender) => !internalCallerNameSchema.safeParse(sender).success)
    )
      throw new InternalAuthError('INVALID_CONFIG');
    policies.set(id, Object.freeze({ ...policy, senders: Object.freeze([...policy.senders]) }));
  }
  const jsonParser = app.getDefaultJsonParser('error', 'error');
  app.removeAllContentTypeParsers();
  app.addContentTypeParser('*', { parseAs: 'buffer', bodyLimit }, (request, body, done) => {
    const state = states.get(request);
    if (!state) return done(new AdmissionError(401));
    state.body = Buffer.from(body);
    done(null, body);
  });
  app.addHook('onReady', async () => {
    try {
      await options.nonces.assertReady();
    } catch {
      throw new NonceStoreUnavailable();
    }
  });
  app.setErrorHandler((error, request, reply) => {
    const state = states.get(request);
    const status = statusFor(error);
    void reply.code(status).send({
      error: status >= 500 ? 'INTERNAL_SECURITY_UNAVAILABLE' : 'INTERNAL_REQUEST_REJECTED',
      message: 'Internal request failed',
      ...(state ? { requestId: state.headers['x-request-id'] } : {}),
    });
  });
  app.addHook('onRequest', async (request, reply) => {
    const rawHeaders = [...request.raw.rawHeaders];
    const headers = parseRequestHeaders(rawHeaders);
    const target = validateRequestTarget(request.raw.url ?? '');
    const now = Date.now();
    validateTimestampAndDeadline(headers['x-timestamp'], headers['x-internal-deadline'], now);
    const length = request.headers['content-length'];
    const chunked = request.headers['transfer-encoding'];
    if (
      (request.method === 'GET' || request.method === 'HEAD') &&
      (chunked !== undefined || (length !== undefined && length !== '0'))
    )
      throw new AdmissionError(400);
    if (length !== undefined && Number(length) > bodyLimit) throw new AdmissionError(413);
    const attemptLimit = request.method === 'GET' || request.method === 'HEAD' ? 1000 : 2000;
    const budget = Math.min(attemptLimit, Number(headers['x-internal-deadline']) - now);
    const controller = new AbortController();
    const timer = setTimeout(() => {
      controller.abort();
      if (!reply.sent) {
        reply.header('connection', 'close');
        reply.raw.once('finish', () => {
          request.raw.destroy();
        });
        void reply.code(504).send({
          error: 'INTERNAL_SECURITY_UNAVAILABLE',
          message: 'Internal request failed',
          requestId: headers['x-request-id'],
        });
      }
    }, budget);
    timer.unref();
    const state: State = {
      headers,
      rawHeaders,
      target,
      method: request.method,
      body: Buffer.alloc(0),
      end: performance.now() + budget,
      controller,
      timer,
    };
    states.set(request, state);
    request.raw.once('aborted', () => {
      controller.abort();
      clearTimeout(timer);
    });
  });
  app.addHook('preParsing', async (request, _reply, payload) => {
    if (payload !== request.raw) throw new AdmissionError(400);
    return payload;
  });
  app.addHook('onRoute', (route) => {
    if (route.preParsing) throw new InternalAuthError('INVALID_CONFIG');
    route.bodyLimit = Math.min(route.bodyLimit ?? bodyLimit, bodyLimit);
    // Last route hook also detects stream replacements from scope/ancestor hooks.
    route.preParsing = async (request, _reply, payload) => {
      if (payload !== request.raw) throw new AdmissionError(400);
      return payload;
    };
    const handler = route.handler;
    route.handler = function (request, reply) {
      const state = states.get(request);
      if (!state?.principal) throw new AdmissionError(401);
      checkBudget(state);
      return handler.call(this, request, reply);
    };
  });
  app.addHook('preValidation', async (request) => {
    const state = states.get(request);
    if (!state) throw new AdmissionError(401);
    checkBudget(state);
    if ((request.raw.rawTrailers ?? []).length !== 0) throw new AdmissionError(400);
    verifyRequest(
      {
        environment: options.environment,
        sender: state.headers['x-service-name'],
        audience: options.audience,
        keyring: currentKeyring(),
        now: Date.now(),
      },
      state.rawHeaders,
      { method: state.method, target: state.target, body: state.body },
    );
    const operationId = request.routeOptions.config.internalOperation;
    const policy = operationId ? policies.get(operationId) : undefined;
    if (
      !operationId ||
      !policy ||
      policy.method !== state.method ||
      policy.route !== request.routeOptions.url ||
      !policy.senders.includes(state.headers['x-service-name'])
    )
      throw new AdmissionError(403);
    const reservationController = new AbortController();
    const signal = AbortSignal.any([state.controller.signal, reservationController.signal]);
    const reservationEnd = performance.now() + 500;
    let timeout: ReturnType<typeof setTimeout> | undefined;
    try {
      const result = await Promise.race([
        options.nonces.reserve(
          {
            environment: options.environment,
            sender: state.headers['x-service-name'],
            audience: options.audience,
            nonce: state.headers['x-nonce'],
            timestamp: Number(state.headers['x-timestamp']),
            acceptedAt: Date.now(),
          },
          signal,
        ),
        new Promise<never>((_resolve, reject) => {
          timeout = setTimeout(
            () => {
              reservationController.abort();
              reject(new NonceStoreUnavailable());
            },
            Math.min(500, Math.max(1, state.end - performance.now())),
          );
        }),
      ]);
      checkBudget(state);
      if (performance.now() >= reservationEnd) throw new NonceStoreUnavailable();
      if (result === 'replay') throw new AdmissionError(401);
      if (result !== 'reserved') throw new NonceStoreUnavailable();
    } catch (error) {
      checkBudget(state);
      if (error instanceof AdmissionError) throw error;
      throw new NonceStoreUnavailable();
    } finally {
      if (timeout) clearTimeout(timeout);
    }
    if (state.body.length > 0) {
      request.body = await new Promise<unknown>((resolve, reject) => {
        const done = (error: Error | null, body?: unknown) =>
          error ? reject(new AdmissionError(400)) : resolve(body);
        jsonParser(request, state.body.toString('utf8'), done);
      });
    } else request.body = undefined;
    checkBudget(state);
    state.principal = Object.freeze({
      environment: options.environment,
      sender: state.headers['x-service-name'],
      audience: options.audience,
      keyId: state.headers['x-service-key-id'],
      operationId,
      requestId: state.headers['x-request-id'],
      nonce: state.headers['x-nonce'],
      timestamp: Number(state.headers['x-timestamp']),
      deadline: Number(state.headers['x-internal-deadline']),
    });
  });
  app.addHook('preHandler', async (request) => {
    const state = states.get(request);
    if (!state?.principal) throw new AdmissionError(401);
    checkBudget(state);
  });
  app.addHook('onResponse', async (request) => {
    const state = states.get(request);
    if (state) {
      clearTimeout(state.timer);
      state.controller.abort();
    }
    states.delete(request);
  });
  await options.routes(app);
};
