import assert from 'node:assert/strict';
import test from 'node:test';
import { createHmac } from 'node:crypto';
import { createApp } from '../src/app.js';
import { gatewayEnvSchema, type GatewayEnv } from '../src/config/env.js';
import { testInternalAuthEnv } from './test-env.js';

const userId = '507f1f77bcf86cd799439011';
const vehicleId = '507f1f77bcf86cd799439013';
const secret = 'j'.repeat(32);

function token(): string {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({
      sub: userId,
      sid: '507f1f77bcf86cd799439012',
      iss: 'issuer',
      aud: 'audience',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 900,
    }),
  ).toString('base64url');
  const signature = createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64url');
  return `${header}.${payload}.${signature}`;
}

function environment(): GatewayEnv {
  return gatewayEnvSchema.parse({
    HOST: '127.0.0.1',
    PORT: 3000,
    NODE_ENV: 'test',
    ...testInternalAuthEnv,
    JWT_SECRET: secret,
    JWT_ISSUER: 'issuer',
    JWT_AUDIENCE: 'audience',
    VEHICLE_SERVICE_URL: 'http://vehicle.test',
    DEVICE_SERVICE_URL: 'http://device.test',
    IDENTITY_SERVICE_URL: 'http://identity.test',
    PROXY_TIMEOUT_MS: 100,
  });
}

test('unverified accounts are blocked across Vehicle, invitation and Device routes; verification unlocks the same token', async (context) => {
  let verified = false;
  let resourceCalls = 0;
  const app = createApp({
    env: environment(),
    fetchImpl: async (url, init) => {
      const path = String(url);
      if (path.endsWith('/auth/me'))
        return new Response(
          JSON.stringify({
            id: userId,
            name: 'Ada',
            username: 'ada_01',
            email: 'ada@example.com',
            emailVerified: verified,
            emailVerifiedAt: verified ? new Date().toISOString() : null,
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      resourceCalls += 1;
      if (path.includes('/devices/'))
        return new Response(
          JSON.stringify({
            deviceId: '507f1f77bcf86cd799439015',
            vehicleId,
            identifier: 'esp32-test',
            status: 'ACTIVE',
            operational: true,
            credential: {
              credentialId: '507f1f77bcf86cd799439017',
              keyId: 'dk_AAAAAAAAAAAAAAAAAAAAAA',
              algorithm: 'Ed25519',
              fingerprint: `sha256:${'a'.repeat(64)}`,
              status: 'ACTIVE',
              usable: true,
              activatedAt: '2026-11-26T12:00:00.000Z',
              expiresAt: null,
              revokedAt: null,
            },
            connectivity: { lastSeenAt: null },
            metadata: {
              name: null,
              manufacturer: null,
              hardwareModel: null,
              hardwareRevision: null,
              firmwareVersion: null,
              serialNumber: null,
            },
            createdAt: '2026-11-26T12:00:00.000Z',
            updatedAt: '2026-11-26T12:00:00.000Z',
            linkedAt: '2026-11-26T12:01:00.000Z',
            revokedAt: null,
            revocationReason: null,
            requestId: 'verification-request',
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      if (path.includes('/vehicles?'))
        return new Response(JSON.stringify({ vehicles: [], page: { nextCursor: null } }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      if (init?.method === 'PATCH')
        return new Response(
          JSON.stringify({
            vehicleId,
            data: {
              id: vehicleId,
              name: 'Mazda',
              make: null,
              model: null,
              generation: null,
              trim: null,
              year: null,
              bodyStyle: null,
              engine: null,
              transmission: null,
              fuelType: null,
              ownerUserId: userId,
              role: 'OWNER',
            },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      if (init?.method === 'DELETE')
        return new Response(
          JSON.stringify({
            vehicleId,
            status: 'ARCHIVED',
            archivedAt: '2026-11-26T12:00:00.000Z',
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      return new Response(JSON.stringify({ vehicleId }), {
        status: 201,
        headers: { 'content-type': 'application/json' },
      });
    },
  });
  context.after(async () => app.close());
  const headers = { authorization: `Bearer ${token()}`, 'x-request-id': 'verification-request' };
  const attempts = [
    { method: 'POST' as const, url: '/api/vehicles', payload: { name: 'Mazda' } },
    { method: 'GET' as const, url: '/api/vehicles' },
    { method: 'GET' as const, url: `/api/vehicles/${vehicleId}` },
    { method: 'PATCH' as const, url: `/api/vehicles/${vehicleId}`, payload: { name: 'Daily' } },
    { method: 'DELETE' as const, url: `/api/vehicles/${vehicleId}` },
    { method: 'DELETE' as const, url: `/api/vehicles/${vehicleId}`, payload: { reason: 'Sold' } },
    {
      method: 'POST' as const,
      url: `/api/vehicles/${vehicleId}/invitations`,
      payload: {
        inviteeUserId: '507f1f77bcf86cd799439014',
        permissions: ['vehicle:read'],
      },
    },
    { method: 'GET' as const, url: '/api/devices/507f1f77bcf86cd799439015' },
    {
      method: 'POST' as const,
      url: `/api/vehicles/${vehicleId}/devices`,
      payload: {
        identifier: 'esp32-test',
        publicKey: 'A'.repeat(64),
      },
    },
    {
      method: 'POST' as const,
      url: '/api/invitations/507f1f77bcf86cd799439016/accept',
      payload: {},
    },
  ];
  for (const attempt of attempts) {
    const response = await app.inject({
      ...attempt,
      headers: { ...headers, 'x-email-verified': 'true' },
    });
    assert.equal(response.statusCode, 403);
    assert.equal(response.json().error, 'EMAIL_NOT_VERIFIED');
    assert.equal(response.json().message, 'Debes verificar tu correo electrónico para continuar.');
    assert.equal(response.json().requestId, response.headers['x-request-id']);
  }
  assert.equal(resourceCalls, 0);

  verified = true;
  const create = await app.inject({
    method: 'POST',
    url: '/api/vehicles',
    headers,
    payload: { name: 'Mazda' },
  });
  assert.equal(create.statusCode, 201);
  const list = await app.inject({ method: 'GET', url: '/api/vehicles', headers });
  assert.equal(list.statusCode, 200);
  const device = await app.inject({
    method: 'GET',
    url: '/api/devices/507f1f77bcf86cd799439015',
    headers,
  });
  assert.equal(device.statusCode, 200);
  assert.equal(device.json().status, 'ACTIVE');
  const update = await app.inject({
    method: 'PATCH',
    url: `/api/vehicles/${vehicleId}`,
    headers,
    payload: { name: 'Mazda' },
  });
  assert.equal(update.statusCode, 200);
  const archive = await app.inject({
    method: 'DELETE',
    url: `/api/vehicles/${vehicleId}`,
    headers,
  });
  assert.equal(archive.statusCode, 200);
  assert.equal(archive.json().status, 'ARCHIVED');
  assert.equal(resourceCalls, 5);
});

test('invalid JWT stays 401 and an unavailable profile fails closed', async (context) => {
  let calls = 0;
  const app = createApp({
    env: environment(),
    fetchImpl: async () => {
      calls += 1;
      return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
    },
  });
  context.after(async () => app.close());
  const invalid = await app.inject({
    method: 'GET',
    url: '/api/vehicles',
    headers: { authorization: 'Bearer invalid' },
  });
  assert.equal(invalid.statusCode, 401);
  assert.equal(calls, 0);
  const unavailable = await app.inject({
    method: 'GET',
    url: '/api/vehicles',
    headers: { authorization: `Bearer ${token()}` },
  });
  assert.equal(unavailable.statusCode, 503);
  assert.equal(calls, 1);
});

test('profile and recovery remain available to unverified accounts through Gateway', async (context) => {
  const app = createApp({
    env: environment(),
    fetchImpl: async (url) => {
      if (String(url).endsWith('/auth/me'))
        return new Response(
          JSON.stringify({
            id: userId,
            name: 'Ada',
            username: 'ada_01',
            email: 'ada@example.com',
            emailVerified: false,
            emailVerifiedAt: null,
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      if (String(url).endsWith('/auth/refresh'))
        return new Response(
          JSON.stringify({
            accessToken: 'new-access-token',
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      if (String(url).endsWith('/auth/logout'))
        return new Response(JSON.stringify({ revoked: true }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      return new Response(JSON.stringify({ accepted: true }), {
        status: 202,
        headers: { 'content-type': 'application/json' },
      });
    },
  });
  context.after(async () => app.close());
  const profile = await app.inject({
    method: 'GET',
    url: '/api/auth/me',
    headers: { authorization: `Bearer ${token()}` },
  });
  assert.equal(profile.statusCode, 200);
  assert.equal(profile.json().emailVerified, false);
  const resend = await app.inject({
    method: 'POST',
    url: '/api/auth/verification/resend/me',
    headers: { authorization: `Bearer ${token()}` },
  });
  assert.equal(resend.statusCode, 202);
  const recovery = await app.inject({
    method: 'POST',
    url: '/api/auth/password-reset/request',
    payload: { email: 'ada@example.com' },
  });
  assert.equal(recovery.statusCode, 202);
  const refresh = await app.inject({
    method: 'POST',
    url: '/api/auth/refresh',
    headers: { origin: 'http://localhost:3000', cookie: `pichu_refresh_token=${'a'.repeat(64)}` },
  });
  assert.equal(refresh.statusCode, 200);
  const logout = await app.inject({
    method: 'POST',
    url: '/api/auth/logout',
    headers: { authorization: `Bearer ${token()}`, origin: 'http://localhost:3000' },
  });
  assert.equal(logout.statusCode, 200);
  const docs = await app.inject({ method: 'GET', url: '/docs/json' });
  const document = docs.json() as {
    paths: Record<
      string,
      Record<
        string,
        {
          responses: Record<
            string,
            {
              content?: Record<string, { schema?: { example?: { error?: string } } }>;
            }
          >;
        }
      >
    >;
  };
  assert.ok(document.paths['/api/auth/me'].get.responses['200']);
  assert.equal(
    document.paths['/api/vehicles'].post.responses['403'].content?.['application/json'].schema
      ?.example?.error,
    'EMAIL_NOT_VERIFIED',
  );
});
