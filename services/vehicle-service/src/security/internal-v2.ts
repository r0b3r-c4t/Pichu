import { randomInt, randomUUID } from 'node:crypto';
import type { FastifyRequest } from 'fastify';
import type { InternalUnsignedHeadersV2 } from '@pichu/contracts';
import { generateNonce, signRequest, type Keyring } from '@pichu/internal-auth';
import { getInternalPrincipal, getInternalSignal } from '@pichu/internal-auth-adapters/fastify';
import { internalJsonRequest, type HttpsJsonResponse } from '@pichu/internal-auth-adapters/tls';

export interface InternalClientConfig {
  readonly environment: 'development' | 'test' | 'staging' | 'production';
  readonly keyring: Keyring;
  readonly sender: 'vehicle-service';
  readonly identityServiceUrl?: string;
  readonly deviceServiceUrl?: string;
  readonly tlsCaPath?: string;
}

export interface SignedHeadersOptions {
  readonly requestId?: string;
  readonly deadline?: number;
  readonly now?: number;
}

export class OutboundDeadlineExceededError extends Error {
  constructor() {
    super('Internal request deadline exceeded');
    this.name = 'OutboundDeadlineExceededError';
  }
}

const VALID_INTERNAL_ID_REGEX = /^[A-Za-z0-9_-]{1,128}$/;

export function signedHeaders(
  config: InternalClientConfig,
  audience: 'identity-service' | 'device-service',
  method: string,
  target: string,
  body: Buffer,
  authorization?: string,
  options: SignedHeadersOptions = {},
): Record<string, string> {
  const now = options.now ?? Date.now();
  const key = config.keyring.find(
    (entry) =>
      entry.environment === config.environment &&
      entry.sender === config.sender &&
      entry.audience === audience &&
      entry.state === 'active' &&
      entry.notBefore <= now &&
      now < entry.notAfter,
  );
  if (!key) {
    throw new Error('Internal authentication unavailable');
  }

  const effectiveDeadline =
    options.deadline !== undefined ? Math.min(options.deadline, now + 5_000) : now + 4_000;
  if (effectiveDeadline <= now) {
    throw new OutboundDeadlineExceededError();
  }

  const requestId =
    options.requestId && VALID_INTERNAL_ID_REGEX.test(options.requestId)
      ? options.requestId
      : randomUUID();

  const headers: InternalUnsignedHeadersV2 = {
    'x-internal-auth-version': '2',
    'x-service-name': config.sender,
    'x-service-audience': audience,
    'x-service-key-id': key.keyId,
    'x-contract-version': 'v1',
    'x-timestamp': String(now),
    'x-nonce': generateNonce(),
    'x-request-id': requestId,
    'x-internal-deadline': String(effectiveDeadline),
    ...(authorization ? { authorization } : {}),
    ...(body.byteLength ? { 'content-type': 'application/json' as const } : {}),
  };

  return {
    ...headers,
    'x-signature': signRequest(
      {
        environment: config.environment,
        sender: config.sender,
        audience,
        keyring: config.keyring,
        now,
      },
      headers,
      { method, target, body },
    ),
  };
}

function waitWithSignal(ms: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) {
    return Promise.reject(new OutboundDeadlineExceededError());
  }
  return new Promise((resolve, reject) => {
    const onAbort = () => {
      clearTimeout(timer);
      reject(new OutboundDeadlineExceededError());
    };
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    signal.addEventListener('abort', onAbort, { once: true });
  });
}

function parseRetryAfterMs(headers: Record<string, string>): number {
  const raw = headers['retry-after'];
  if (!raw) {
    return 0;
  }
  const seconds = Number(raw);
  return Number.isFinite(seconds) && seconds > 0 ? Math.ceil(seconds * 1_000) : 0;
}

/**
 * Executes a signed v2 outbound call preserving TKT-009 deadlines, cancellation signals,
 * and retry rules (GET: up to 2 attempts on network/502/503/504 if budget permits;
 * POST/PATCH mutations: 1 attempt, never retried).
 */
export async function executeSignedInternalRequest(
  request: FastifyRequest,
  config: InternalClientConfig,
  input: {
    audience: 'identity-service' | 'device-service';
    baseUrl: string;
    method: 'GET' | 'POST' | 'PATCH';
    path: string;
    body?: Buffer;
  },
): Promise<HttpsJsonResponse> {
  const principal = getInternalPrincipal(request);
  const inboundSignal = getInternalSignal(request);
  const payload = input.body ?? Buffer.alloc(0);
  const authorization =
    typeof request.headers.authorization === 'string' ? request.headers.authorization : undefined;

  const isGet = input.method === 'GET';
  const maxAttemptBudgetMs = isGet ? 1_000 : 2_000;
  const maxAttempts = isGet ? 2 : 1;
  const deadline = principal.deadline;
  const url = `${input.baseUrl.replace(/\/+$/, '')}${input.path}`;

  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    if (inboundSignal.aborted) {
      throw new OutboundDeadlineExceededError();
    }

    const now = Date.now();
    const remainingMs = deadline - now;
    if (remainingMs <= 0) {
      throw new OutboundDeadlineExceededError();
    }

    const attemptTimeoutMs = Math.min(maxAttemptBudgetMs, remainingMs);
    const headers = signedHeaders(
      config,
      input.audience,
      input.method,
      input.path,
      payload,
      authorization,
      {
        requestId: principal.requestId,
        deadline,
        now,
      },
    );

    const attemptSignal = AbortSignal.any([inboundSignal, AbortSignal.timeout(attemptTimeoutMs)]);

    let response: HttpsJsonResponse;
    try {
      response = await internalJsonRequest({
        url,
        method: input.method,
        headers,
        body: isGet ? undefined : payload,
        signal: attemptSignal,
        timeoutMs: attemptTimeoutMs,
        tls: { caPath: config.tlsCaPath ?? '' },
      });
    } catch (error) {
      if (inboundSignal.aborted || deadline - Date.now() <= 0) {
        throw new OutboundDeadlineExceededError();
      }
      if (attempt + 1 >= maxAttempts) {
        throw error;
      }
      const backoffMs = randomInt(100, 301);
      if (deadline - Date.now() < backoffMs + 1_000) {
        throw error;
      }
      await waitWithSignal(backoffMs, inboundSignal);
      continue;
    }

    const isRetryableStatus =
      response.status === 502 || response.status === 503 || response.status === 504;
    if (!isRetryableStatus || attempt + 1 >= maxAttempts) {
      return response;
    }

    const backoffMs = randomInt(100, 301);
    const waitMs = Math.max(backoffMs, parseRetryAfterMs(response.headers));
    if (deadline - Date.now() < waitMs + 1_000) {
      return response;
    }
    await waitWithSignal(waitMs, inboundSignal);
  }

  throw new OutboundDeadlineExceededError();
}
