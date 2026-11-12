import assert from 'node:assert/strict';
import test from 'node:test';
import { createApp } from '../src/app.js';

function environment() {
  return {
    HOST: '127.0.0.1',
    PORT: 3000,
    NODE_ENV: 'test' as const,
    INTERNAL_SERVICE_SECRET: 'i'.repeat(32),
    JWT_SECRET: 'j'.repeat(32),
    JWT_ISSUER: 'issuer',
    JWT_AUDIENCE: 'audience',
    IDENTITY_SERVICE_URL: 'http://identity.test',
    VEHICLE_SERVICE_URL: 'http://vehicle.test',
    DEVICE_SERVICE_URL: 'http://device.test',
    PROXY_TIMEOUT_MS: 100,
  };
}

test('readiness requires Identity, Vehicle and Device independently', async (context) => {
  for (const failedService of ['identity', 'vehicle', 'device']) {
    const checkedServices = new Set<string>();
    const app = createApp({
      env: environment(),
      fetchImpl: async (url) => {
        const service = new URL(String(url)).hostname.split('.')[0];
        checkedServices.add(service);
        return new Response('{}', {
          status: service === failedService ? 503 : 200,
          headers: { 'content-type': 'application/json' },
        });
      },
    });
    context.after(async () => app.close());

    const response = await app.inject('/health/ready');
    assert.equal(response.statusCode, 503, `${failedService} should block readiness`);
    assert.equal(response.json().error, 'SERVICE_UNAVAILABLE');
    assert.equal(response.json().message, 'Service unavailable');
    assert.deepEqual([...checkedServices].sort(), ['device', 'identity', 'vehicle']);
  }
});

test('liveness does not depend on upstream service health', async (context) => {
  let upstreamCalls = 0;
  const app = createApp({
    env: environment(),
    fetchImpl: async () => {
      upstreamCalls += 1;
      return new Response('{}', { status: 503 });
    },
  });
  context.after(async () => app.close());

  for (const url of ['/health', '/health/live']) {
    const response = await app.inject(url);
    assert.equal(response.statusCode, 200);
    assert.equal(response.json().status, 'ok');
  }
  assert.equal(upstreamCalls, 0);
});

test('rate limiting is bounded, ignores untrusted forwarded IPs and emits a standard error', async (context) => {
  const app = createApp({
    env: {
      ...environment(),
      RATE_LIMIT_MAX: 1,
      RATE_LIMIT_WINDOW_SECONDS: 60,
    },
    fetchImpl: async () => new Response('{}', { status: 200 }),
  });
  context.after(async () => app.close());

  const first = await app.inject({ method: 'GET', url: '/api/vehicles' });
  const limited = await app.inject({
    method: 'GET',
    url: '/api/vehicles',
    headers: { 'x-forwarded-for': '203.0.113.99' },
  });
  assert.equal(first.statusCode, 401);
  assert.equal(limited.statusCode, 429);
  assert.equal(limited.headers['retry-after'], '60');
  assert.deepEqual(Object.keys(limited.json()).sort(), ['error', 'message', 'requestId']);
  assert.equal(limited.json().error, 'RATE_LIMITED');
});

test('local and not-found errors use the common envelope without exposing the request URL', async (context) => {
  const app = createApp({ env: environment() });
  context.after(async () => app.close());

  const unauthorized = await app.inject({ method: 'GET', url: '/api/vehicles' });
  assert.equal(unauthorized.statusCode, 401);
  assert.deepEqual(Object.keys(unauthorized.json()).sort(), ['error', 'message', 'requestId']);
  assert.equal(unauthorized.json().error, 'AUTHENTICATION_REQUIRED');

  const missing = await app.inject({
    method: 'GET',
    url: '/not-a-route?private=value',
    headers: { 'x-request-id': 'missing-route-123' },
  });
  assert.equal(missing.statusCode, 404);
  assert.deepEqual(missing.json(), {
    error: 'NOT_FOUND',
    message: 'Route not found',
    requestId: 'missing-route-123',
  });
  assert.equal(missing.body.includes('private=value'), false);
});

test('upstream server errors are normalized without forwarding internal messages', async (context) => {
  const app = createApp({
    env: environment(),
    fetchImpl: async () =>
      new Response(
        JSON.stringify({
          error: 'INTERNAL_DATABASE_FAILURE',
          message: 'database password and stack trace',
        }),
        { status: 500, headers: { 'content-type': 'application/json' } },
      ),
  });
  context.after(async () => app.close());

  const response = await app.inject({
    method: 'POST',
    url: '/api/auth/login',
    payload: { email: 'user@example.com', password: 'valid-password' },
  });
  assert.equal(response.statusCode, 500);
  assert.deepEqual(Object.keys(response.json()).sort(), ['error', 'message', 'requestId']);
  assert.equal(response.json().error, 'OPERATION_FAILED');
  assert.equal(response.json().message, 'Internal server error');
  assert.equal(response.body.includes('database password'), false);
});

test('security headers are applied to API and Swagger without a restrictive CSP', async (context) => {
  const app = createApp({ env: environment() });
  context.after(async () => app.close());

  for (const url of ['/docs', '/docs/json', '/health']) {
    const response = await app.inject(url);
    assert.equal(response.headers['x-content-type-options'], 'nosniff');
    assert.equal(response.headers['x-frame-options'], 'DENY');
    assert.equal(response.headers['referrer-policy'], 'strict-origin-when-cross-origin');
    assert.equal(response.headers['content-security-policy'], undefined);
  }
});

test('OpenAPI documents readiness failures and rate-limited operations', async (context) => {
  const app = createApp({ env: environment() });
  context.after(async () => app.close());

  const response = await app.inject('/docs/json');
  const document = response.json();
  assert.ok(document.paths['/health/ready'].get.responses['503']);
  assert.ok(document.paths['/health/live'].get.responses['200']);
  assert.equal(document.paths['/health/live'].get.responses['429'], undefined);
  assert.ok(document.paths['/api/vehicles'].get.responses['429']);
  assert.ok(document.paths['/api/auth/register'].post.responses['429']);
  assert.ok(document.paths['/api/vehicles'].get.responses.default);
  const registration =
    document.paths['/api/auth/register'].post.requestBody.content['application/json'].schema;
  assert.ok(registration.required.includes('username'));
  assert.equal(registration.properties.password.minLength, 8);
  assert.equal(registration.properties.password.maxLength, 256);
});
