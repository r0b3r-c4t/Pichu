import Fastify, { type FastifyInstance } from 'fastify';
import { request as httpRequest } from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';
import { generateNonce, signRequest, type KeyEntry } from '@pichu/internal-auth';
import type { InternalUnsignedHeadersV2 } from '@pichu/contracts';
import { internalAuthPlugin, getInternalPrincipal, getInternalSignal } from '../src/fastify.js';
import type { NonceReservation, NonceStore } from '../src/types.js';

export const key: KeyEntry = {
  environment: 'test',
  sender: 'api-gateway',
  audience: 'vehicle-service',
  keyId: 'synthetic-key',
  secret: Buffer.alloc(32, 42),
  state: 'active',
  notBefore: 1,
  notAfter: 8000000000000000,
};

/** HTTP test double only. Never used as evidence of MongoDB persistence semantics. */
export class RecordingStore implements NonceStore {
  readonly inputs: NonceReservation[] = [];
  ready = true;
  async assertReady(): Promise<void> {
    if (!this.ready) throw new Error('synthetic storage failure');
  }
  async reserve(input: NonceReservation, signal: AbortSignal): Promise<'reserved' | 'replay'> {
    signal.throwIfAborted();
    this.inputs.push(input);
    return 'reserved';
  }
}

export function signedHeaders(
  body: Buffer,
  method = 'POST',
  target = '/probe',
  extra: Partial<InternalUnsignedHeadersV2> = {},
): string[] {
  const now = Date.now();
  const headers: InternalUnsignedHeadersV2 = {
    'x-internal-auth-version': '2',
    'x-service-name': key.sender,
    'x-service-audience': key.audience,
    'x-service-key-id': key.keyId,
    'x-contract-version': 'v1',
    'x-timestamp': String(now),
    'x-nonce': generateNonce(),
    'x-request-id': 'request-1',
    'x-internal-deadline': String(now + 5000),
    ...(body.length ? { 'content-type': 'application/json' as const } : {}),
    ...extra,
  };
  const signature = signRequest({ ...key, keyring: [key], now }, headers, { method, target, body });
  return Object.entries({ ...headers, 'x-signature': signature }).flatMap(([k, v]) => [k, v]);
}

export interface HttpResult {
  status: number;
  body: string;
}
export async function wire(
  port: number,
  headers: string[],
  body = Buffer.alloc(0),
  options: {
    method?: string;
    target?: string;
    chunked?: boolean;
    delayMs?: number;
    trailers?: boolean;
  } = {},
): Promise<HttpResult> {
  return new Promise((resolve, reject) => {
    const raw = [...headers, 'Host', '127.0.0.1', 'Connection', 'close'];
    if (options.chunked) raw.push('Transfer-Encoding', 'chunked');
    else raw.push('Content-Length', String(body.length));
    const req = httpRequest(
      {
        hostname: '127.0.0.1',
        port,
        method: options.method ?? 'POST',
        path: options.target ?? '/probe',
        headers: raw,
        agent: false,
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer) => chunks.push(chunk));
        response.on('end', () =>
          resolve({ status: response.statusCode ?? 0, body: Buffer.concat(chunks).toString() }),
        );
        response.on('error', reject);
      },
    );
    req.on('error', reject);
    req.setTimeout(4000, () => req.destroy(new Error('HTTP test timed out')));
    if (options.chunked || options.delayMs) {
      req.flushHeaders();
      req.write(body.subarray(0, 1));
      void delay(options.delayMs ?? 1).then(() => {
        if (req.destroyed) return;
        req.write(body.subarray(1));
        if (options.trailers) req.addTrailers({ 'x-extra': 'trailer' });
        req.end();
      });
    } else req.end(body);
  });
}

export async function httpFixture(
  store: NonceStore = new RecordingStore(),
  configure?: (scope: FastifyInstance) => Promise<void>,
) {
  const app = Fastify({ logger: false, routerOptions: { maxParamLength: 4096 } });
  let business = 0;
  app.post('/public', async (req) => ({ body: req.body }));
  await app.register(internalAuthPlugin, {
    environment: 'test',
    audience: 'vehicle-service',
    keyring: () => [key],
    nonces: store,
    policies: {
      probe: { method: 'POST', route: '/probe', senders: ['api-gateway'] },
      read: { method: 'GET', route: '/probe', senders: ['api-gateway'] },
      denied: { method: 'POST', route: '/denied', senders: ['device-service'] },
      mismatch: { method: 'GET', route: '/elsewhere', senders: ['api-gateway'] },
      small: { method: 'POST', route: '/small', senders: ['api-gateway'] },
      typed: { method: 'POST', route: '/typed', senders: ['api-gateway'] },
    },
    routes: async (scope) => {
      const handler = async (req: Parameters<typeof getInternalPrincipal>[0]) => {
        business++;
        const principal = getInternalPrincipal(req);
        return {
          body: req.body ?? null,
          principal,
          frozen: Object.isFrozen(principal),
          aborted: getInternalSignal(req).aborted,
        };
      };
      scope.post('/probe', { config: { internalOperation: 'probe' } }, handler);
      scope.get('/probe', { config: { internalOperation: 'read' } }, handler);
      scope.post('/denied', { config: { internalOperation: 'denied' } }, handler);
      scope.post('/missing', handler);
      scope.post('/mismatch', { config: { internalOperation: 'mismatch' } }, handler);
      scope.post('/unknown', { config: { internalOperation: 'unknown' } }, handler);
      scope.post('/small', { bodyLimit: 8, config: { internalOperation: 'small' } }, handler);
      scope.post(
        '/typed',
        {
          config: { internalOperation: 'typed' },
          schema: {
            body: {
              type: 'object',
              required: ['value'],
              properties: { value: { type: 'integer' } },
              additionalProperties: false,
            },
          },
        },
        handler,
      );
      if (configure) await configure(scope);
    },
  });
  await app.listen({ host: '127.0.0.1', port: 0 });
  const address = app.server.address();
  if (!address || typeof address === 'string') throw new Error('Expected TCP address');
  return { app, port: address.port, business: () => business };
}
