import assert from 'node:assert/strict';
import { test } from 'node:test';
import { proxyRequest, ProxyRequestError } from '../src/lib/proxy.js';
import { createHmac } from 'node:crypto';
import { createApp } from '../src/app.js';

function createToken(secret: string): string {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({
      sub: '507f1f77bcf86cd799439011',
      sid: '507f1f77bcf86cd799439012',
      iss: 'issuer',
      aud: 'audience',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 60,
    }),
  ).toString('base64url');
  const signature = createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64url');
  return `${header}.${payload}.${signature}`;
}

function identityProfile(emailVerified: boolean): Response {
  return new Response(
    JSON.stringify({
      id: '507f1f77bcf86cd799439011',
      name: 'Ada',
      username: 'ada_01',
      email: 'ada@example.com',
      emailVerified,
      emailVerifiedAt: emailVerified ? '2026-11-04T12:00:00.000Z' : null,
    }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
}

test('proxy preserves upstream status and parses JSON', async () => {
  const result = await proxyRequest({
    url: 'http://upstream.test/resource',
    method: 'GET',
    timeoutMs: 100,
    fetchImpl: async () =>
      new Response(JSON.stringify({ accepted: true }), {
        status: 202,
        headers: { 'content-type': 'application/json' },
      }),
  });

  assert.equal(result.status, 202);
  assert.deepEqual(result.body, { accepted: true });
});

test('proxy handles an empty response body', async () => {
  const result = await proxyRequest({
    url: 'http://upstream.test/resource',
    method: 'DELETE',
    timeoutMs: 100,
    fetchImpl: async () => new Response(null, { status: 204 }),
  });

  assert.equal(result.status, 204);
  assert.equal(result.body, undefined);
});

test('proxy does not expose non-JSON upstream content', async () => {
  const result = await proxyRequest({
    url: 'http://upstream.test/resource',
    method: 'GET',
    timeoutMs: 100,
    fetchImpl: async () =>
      new Response('internal stack trace', {
        status: 500,
        headers: { 'content-type': 'text/plain' },
      }),
  });

  assert.equal(result.status, 500);
  assert.deepEqual(result.body, { message: 'Upstream returned an unsupported response' });
});

test('proxy converts a network failure to a generic error', async () => {
  await assert.rejects(
    proxyRequest({
      url: 'http://upstream.test/resource',
      method: 'GET',
      timeoutMs: 100,
      fetchImpl: async () => {
        throw new Error('dns details must not escape');
      },
    }),
    (error: unknown) => error instanceof ProxyRequestError && error.kind === 'network',
  );
});

test('proxy aborts an upstream request after the timeout', async () => {
  await assert.rejects(
    proxyRequest({
      url: 'http://upstream.test/resource',
      method: 'GET',
      timeoutMs: 5,
      fetchImpl: (_url, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () =>
            reject(new DOMException('aborted', 'AbortError')),
          );
        }),
    }),
    (error: unknown) => error instanceof ProxyRequestError && error.kind === 'timeout',
  );
});

test('gateway propagates a validated request id to the upstream service', async () => {
  const secret = 'j'.repeat(32);
  let upstreamRequestId: string | undefined;
  const app = createApp({
    env: {
      HOST: '127.0.0.1',
      PORT: 3000,
      NODE_ENV: 'test',
      INTERNAL_SERVICE_SECRET: 'i'.repeat(32),
      JWT_SECRET: secret,
      JWT_ISSUER: 'issuer',
      JWT_AUDIENCE: 'audience',
      VEHICLE_SERVICE_URL: 'http://vehicle.test',
      DEVICE_SERVICE_URL: 'http://device.test',
      PROXY_TIMEOUT_MS: 100,
    },
    fetchImpl: async (url, init) => {
      upstreamRequestId = new Headers(init?.headers).get('x-request-id') ?? undefined;
      if (String(url).endsWith('/auth/me')) return identityProfile(true);
      return new Response(JSON.stringify({ vehicleId: '507f1f77bcf86cd799439012' }), {
        status: 201,
        headers: { 'content-type': 'application/json' },
      });
    },
  });

  const response = await app.inject({
    method: 'POST',
    url: '/api/vehicles',
    headers: {
      authorization: `Bearer ${createToken(secret)}`,
      'x-request-id': 'client-request-42',
    },
    payload: { name: 'Mazda 3' },
  });
  await app.close();

  assert.equal(response.statusCode, 201);
  assert.equal(response.headers['x-request-id'], 'client-request-42');
  assert.equal(upstreamRequestId, 'client-request-42');
});

test('gateway preserves persisted public vehicle data and excludes private fields', async () => {
  const secret = 'j'.repeat(32);
  const vehicleId = '507f1f77bcf86cd799439012';
  const app = createApp({
    env: {
      HOST: '127.0.0.1',
      PORT: 3000,
      NODE_ENV: 'test',
      INTERNAL_SERVICE_SECRET: 'i'.repeat(32),
      JWT_SECRET: secret,
      JWT_ISSUER: 'issuer',
      JWT_AUDIENCE: 'audience',
      VEHICLE_SERVICE_URL: 'http://vehicle.test',
      DEVICE_SERVICE_URL: 'http://device.test',
      PROXY_TIMEOUT_MS: 100,
    },
    fetchImpl: async (url) =>
      String(url).endsWith('/auth/me')
        ? identityProfile(true)
        : new Response(
            JSON.stringify({
              vehicleId,
              message: 'Vehicle created',
              data: {
                id: vehicleId,
                name: 'Persisted Mazda 3',
                make: 'Mazda',
                model: '3',
                year: 2011,
                engine: '2.0',
                ownerUserId: '507f1f77bcf86cd799439011',
                __v: 4,
                privateAuditNote: 'must not reach client',
              },
              requestId: 'request-42',
            }),
            { status: 201, headers: { 'content-type': 'application/json' } },
          ),
  });
  const response = await app.inject({
    method: 'POST',
    url: '/api/vehicles',
    headers: { authorization: `Bearer ${createToken(secret)}`, 'x-request-id': 'request-42' },
    payload: { name: 'Input name' },
  });
  await app.close();
  assert.equal(response.statusCode, 201);
  const body = response.json() as { data: { name: string }; requestId: string };
  assert.equal(body.data.name, 'Persisted Mazda 3');
  assert.equal(body.requestId, response.headers['x-request-id']);
  assert.equal(response.body.includes('__v'), false);
  assert.equal(response.body.includes('privateAuditNote'), false);
});

test('gateway rejects unknown public fields before proxying', async () => {
  const app = createApp({
    env: {
      HOST: '127.0.0.1',
      PORT: 3000,
      NODE_ENV: 'test',
      INTERNAL_SERVICE_SECRET: 'i'.repeat(32),
      JWT_SECRET: 'j'.repeat(32),
      JWT_ISSUER: 'issuer',
      JWT_AUDIENCE: 'audience',
      VEHICLE_SERVICE_URL: 'http://vehicle.test',
      DEVICE_SERVICE_URL: 'http://device.test',
      PROXY_TIMEOUT_MS: 100,
    },
    fetchImpl: async () => new Response('{}', { status: 201 }),
  });

  const response = await app.inject({
    method: 'POST',
    url: '/api/vehicles',
    headers: { authorization: `Bearer ${createToken('j'.repeat(32))}` },
    payload: { name: 'Mazda 3', userId: '507f1f77bcf86cd799439011' },
  });
  await app.close();

  assert.equal(response.statusCode, 400);
});

test('gateway exposes dynamic OpenAPI routes and bearer security', async () => {
  const app = createApp({
    env: {
      HOST: '127.0.0.1',
      PORT: 3000,
      NODE_ENV: 'test',
      INTERNAL_SERVICE_SECRET: 'i'.repeat(32),
      JWT_SECRET: 'j'.repeat(32),
      JWT_ISSUER: 'issuer',
      JWT_AUDIENCE: 'audience',
      VEHICLE_SERVICE_URL: 'http://vehicle.test',
      DEVICE_SERVICE_URL: 'http://device.test',
      PROXY_TIMEOUT_MS: 100,
    },
  });
  const response = await app.inject({ method: 'GET', url: '/docs/json' });
  const document = response.json() as {
    paths: Record<string, unknown>;
    components: { securitySchemes: Record<string, unknown> };
  };
  await app.close();

  assert.equal(response.statusCode, 200);
  assert.ok(document.paths['/api/vehicles']);
  assert.ok(document.paths['/api/auth/login']);
  const register = document.paths['/api/auth/register'] as {
    post: { responses: Record<string, unknown> };
  };
  assert.ok(register.post.responses['200']);
  assert.equal(register.post.responses['202'], undefined);
  const vehicles = document.paths['/api/vehicles'] as {
    post: {
      responses: Record<
        string,
        {
          content?: Record<
            string,
            { schema?: { properties?: Record<string, unknown>; example?: unknown } }
          >;
        }
      >;
    };
  };
  const createResponse = vehicles.post.responses['201'].content?.['application/json'].schema;
  assert.ok(createResponse?.properties?.data);
  assert.ok(createResponse?.properties?.requestId);
  assert.ok(createResponse?.example);
  assert.ok(vehicles.post.responses['400'].content?.['application/json'].schema?.example);
  assert.ok(document.components.securitySchemes.bearerAuth);
});

test('gateway enforces CORS, rate limiting and payload limits', async () => {
  const app = createApp({
    env: {
      HOST: '127.0.0.1',
      PORT: 3000,
      NODE_ENV: 'test',
      INTERNAL_SERVICE_SECRET: 'i'.repeat(32),
      JWT_SECRET: 'j'.repeat(32),
      JWT_ISSUER: 'issuer',
      JWT_AUDIENCE: 'audience',
      VEHICLE_SERVICE_URL: 'http://vehicle.test',
      DEVICE_SERVICE_URL: 'http://device.test',
      PROXY_TIMEOUT_MS: 100,
      CORS_ORIGINS: 'https://allowed.test',
      RATE_LIMIT_MAX: 1,
      RATE_LIMIT_WINDOW_SECONDS: 60,
      SENSITIVE_RATE_LIMIT_MAX: 1,
      MAX_PAYLOAD_BYTES: 1024,
    },
    fetchImpl: async () => new Response('{}', { status: 200 }),
  });

  const denied = await app.inject({
    method: 'GET',
    url: '/health',
    headers: { origin: 'https://blocked.test' },
  });
  assert.equal(denied.statusCode, 403);

  const first = await app.inject({
    method: 'GET',
    url: '/api/vehicles',
    headers: { origin: 'https://allowed.test' },
  });
  const limited = await app.inject({ method: 'GET', url: '/api/vehicles' });
  assert.equal(first.statusCode, 401);
  assert.equal(limited.statusCode, 429);
  assert.equal(limited.headers['retry-after'], '60');
  await app.close();
});

test('gateway forwards Identity cookie transport and Set-Cookie headers', async () => {
  let receivedOrigin: string | null = null;
  const app = createApp({
    env: {
      HOST: '127.0.0.1',
      PORT: 3000,
      NODE_ENV: 'test',
      INTERNAL_SERVICE_SECRET: 'i'.repeat(32),
      JWT_SECRET: 'j'.repeat(32),
      JWT_ISSUER: 'issuer',
      JWT_AUDIENCE: 'audience',
      VEHICLE_SERVICE_URL: 'http://vehicle.test',
      DEVICE_SERVICE_URL: 'http://device.test',
      IDENTITY_SERVICE_URL: 'http://identity.test',
      CORS_ORIGINS: 'http://localhost:3000',
      PROXY_TIMEOUT_MS: 100,
    },
    fetchImpl: async (_url, init) => {
      receivedOrigin = new Headers(init?.headers).get('origin');
      return new Response(JSON.stringify({ accessToken: 'access-token' }), {
        status: 200,
        headers: {
          'content-type': 'application/json',
          'set-cookie': 'pichu_refresh_token=opaque; HttpOnly; SameSite=Lax',
        },
      });
    },
  });
  const response = await app.inject({
    method: 'POST',
    url: '/api/auth/login',
    headers: {
      origin: 'http://localhost:3000',
    },
    payload: { email: 'user@example.com', password: 'password' },
  });
  await app.close();

  assert.equal(response.statusCode, 200);
  assert.equal(receivedOrigin, 'http://localhost:3000');
  assert.match(String(response.headers['set-cookie']), /pichu_refresh_token/);
});

test('gateway preserves Identity error status, body and request id', async () => {
  const identityError = {
    error: 'VALIDATION_ERROR',
    message: 'Invalid registration data',
    details: [{ field: 'email', message: 'Invalid value' }],
    requestId: 'gateway-identity-42',
  };
  let forwardedRequestId: string | null = null;
  const app = createApp({
    env: {
      HOST: '127.0.0.1',
      PORT: 3000,
      NODE_ENV: 'test',
      INTERNAL_SERVICE_SECRET: 'i'.repeat(32),
      JWT_SECRET: 'j'.repeat(32),
      JWT_ISSUER: 'issuer',
      JWT_AUDIENCE: 'audience',
      VEHICLE_SERVICE_URL: 'http://vehicle.test',
      DEVICE_SERVICE_URL: 'http://device.test',
      IDENTITY_SERVICE_URL: 'http://identity.test',
      PROXY_TIMEOUT_MS: 100,
    },
    fetchImpl: async (_url, init) => {
      forwardedRequestId = new Headers(init?.headers).get('x-request-id');
      return new Response(JSON.stringify(identityError), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      });
    },
  });
  const response = await app.inject({
    method: 'POST',
    url: '/api/auth/register',
    headers: { 'x-request-id': 'gateway-identity-42' },
    payload: {
      name: 'Ada',
      username: 'ada_01',
      email: 'ada@example.com',
      password: 'correct horse battery staple',
    },
  });
  await app.close();
  assert.equal(response.statusCode, 400);
  assert.deepEqual(response.json(), identityError);
  assert.equal(response.headers['x-request-id'], identityError.requestId);
  assert.equal(forwardedRequestId, identityError.requestId);
});
