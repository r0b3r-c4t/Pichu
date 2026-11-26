import assert from 'node:assert/strict';
import test from 'node:test';
import { createHmac } from 'node:crypto';
import { createApp } from '../src/app.js';
import { testInternalAuthEnv } from './test-env.js';

function token(secret: string): string {
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
  return `${header}.${payload}.${createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64url')}`;
}

function env(secret: string) {
  return {
    HOST: '127.0.0.1',
    PORT: 3000,
    NODE_ENV: 'test' as const,
    ...testInternalAuthEnv,
    JWT_SECRET: secret,
    JWT_ISSUER: 'issuer',
    JWT_AUDIENCE: 'audience',
    VEHICLE_SERVICE_URL: 'http://vehicle.test',
    DEVICE_SERVICE_URL: 'http://device.test',
    IDENTITY_SERVICE_URL: 'http://identity.test',
    PROXY_TIMEOUT_MS: 100,
  };
}

function identityProfile() {
  return new Response(
    JSON.stringify({
      id: '507f1f77bcf86cd799439011',
      name: 'Ada',
      username: 'ada_01',
      email: 'ada@example.com',
      emailVerified: true,
      emailVerifiedAt: '2026-11-04T12:00:00.000Z',
    }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
}

test('Gateway emits a complete v2 Vehicle request with original JWT and exact body bytes', async () => {
  const secret = 'j'.repeat(32);
  let captured: { url: string; init?: RequestInit } | undefined;
  const app = createApp({
    env: env(secret),
    fetchImpl: async (url, init) => {
      captured = { url: String(url), init };
      return String(url).endsWith('/auth/me')
        ? identityProfile()
        : new Response(JSON.stringify({ vehicleId: '507f1f77bcf86cd799439012' }), {
            status: 201,
            headers: { 'content-type': 'application/json' },
          });
    },
  });
  const authorization = `Bearer ${token(secret)}`;
  const response = await app.inject({
    method: 'POST',
    url: '/api/vehicles',
    headers: { authorization, 'x-request-id': 'gateway-v2-1' },
    payload: { name: 'Mazda 3' },
  });
  await app.close();
  assert.equal(response.statusCode, 201);
  assert.ok(captured);
  const headers = new Headers(captured.init?.headers);
  assert.equal(headers.get('x-internal-auth-version'), '2');
  assert.equal(headers.get('x-service-name'), 'api-gateway');
  assert.equal(headers.get('x-service-audience'), 'vehicle-service');
  assert.equal(headers.get('authorization'), authorization);
  assert.match(headers.get('x-nonce') ?? '', /^[A-Za-z0-9_-]{43}$/);
  assert.match(headers.get('x-signature') ?? '', /^[A-Za-z0-9_-]{43}$/);
  assert.equal(
    await new Response(captured.init?.body).text(),
    JSON.stringify({ name: 'Mazda 3', userId: '507f1f77bcf86cd799439011' }),
  );
});

test('Gateway rejects upstream redirects and does not fall back to v1', async () => {
  const secret = 'j'.repeat(32);
  const app = createApp({
    env: env(secret),
    fetchImpl: async (url) => {
      if (String(url).endsWith('/auth/me')) return identityProfile();
      return new Response(null, { status: 302, headers: { location: 'http://attacker.test' } });
    },
  });
  const response = await app.inject({
    method: 'POST',
    url: '/api/vehicles',
    headers: { authorization: `Bearer ${token(secret)}` },
    payload: { name: 'Mazda 3' },
  });
  await app.close();
  assert.equal(response.statusCode, 502);
  assert.equal(response.body.includes('x-signature'), false);
});
