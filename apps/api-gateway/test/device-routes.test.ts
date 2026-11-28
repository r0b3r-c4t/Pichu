import assert from 'node:assert/strict';
import test from 'node:test';
import { createHmac } from 'node:crypto';
import { createApp } from '../src/app.js';
import { gatewayEnvSchema, type GatewayEnv } from '../src/config/env.js';
import { testInternalAuthEnv } from './test-env.js';

const userId = '507f1f77bcf86cd799439011';
const vehicleId = '507f1f77bcf86cd799439013';
const deviceId = '507f1f77bcf86cd799439015';
const challengeId = '507f1f77bcf86cd799439018';
const credentialId = '507f1f77bcf86cd799439017';
const secret = 'j'.repeat(32);

function token(sub = userId): string {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({
      sub,
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
    PROXY_TIMEOUT_MS: 200,
  });
}

const sampleDetail = {
  deviceId,
  vehicleId,
  identifier: 'esp32-sunroof-01',
  status: 'ACTIVE' as const,
  operational: true,
  credential: {
    credentialId,
    keyId: 'dk_AAAAAAAAAAAAAAAAAAAAAA',
    algorithm: 'Ed25519' as const,
    fingerprint: `sha256:${'a'.repeat(64)}`,
    status: 'ACTIVE' as const,
    usable: true,
    activatedAt: '2026-11-26T12:00:00.000Z',
    expiresAt: null,
    revokedAt: null,
  },
  connectivity: { lastSeenAt: null },
  metadata: {
    name: 'Sunroof Node',
    manufacturer: 'Espressif',
    hardwareModel: 'ESP32-S3',
    hardwareRevision: 'rev-1.0',
    firmwareVersion: '1.0.0',
    serialNumber: 'SN-001',
  },
  createdAt: '2026-11-26T12:00:00.000Z',
  updatedAt: '2026-11-26T12:00:00.000Z',
  linkedAt: '2026-11-26T12:02:00.000Z',
  revokedAt: null,
  revocationReason: null,
};

test('Gateway routes all 8 public device endpoints exclusively to Vehicle, retires /devices/link, and validates inputs before upstream', async (context) => {
  const upstreamCalls: Array<{
    url: string;
    method: string;
    audience: string | null;
    body: unknown;
  }> = [];
  let force503 = false;

  const app = createApp({
    env: environment(),
    fetchImpl: async (url, init) => {
      const target = String(url);
      if (target.endsWith('/auth/me')) {
        return new Response(
          JSON.stringify({
            id: userId,
            name: 'Owner',
            username: 'owner_01',
            email: 'owner@example.com',
            emailVerified: true,
            emailVerifiedAt: '2026-11-26T12:00:00.000Z',
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }

      const headers = new Headers(init?.headers);
      const rawBody =
        typeof init?.body === 'string'
          ? JSON.parse(init.body)
          : init?.body instanceof Uint8Array
            ? JSON.parse(Buffer.from(init.body).toString('utf8'))
            : undefined;
      upstreamCalls.push({
        url: target,
        method: init?.method ?? 'GET',
        audience: headers.get('x-service-audience'),
        body: rawBody,
      });

      if (force503) {
        return new Response(
          JSON.stringify({
            error: 'SERVICE_UNAVAILABLE',
            message: 'Device service unavailable',
            requestId: 'req-503',
          }),
          { status: 503, headers: { 'content-type': 'application/json' } },
        );
      }

      if (target.endsWith(`/vehicles/${vehicleId}/devices`) && init?.method === 'POST') {
        return new Response(
          JSON.stringify({
            deviceId,
            status: 'PENDING',
            message: 'Device registration accepted',
            data: { ...sampleDetail, status: 'PENDING', operational: false, linkedAt: null },
            requestId: 'req-reg',
          }),
          { status: 201, headers: { 'content-type': 'application/json' } },
        );
      }
      if (target.includes(`/vehicles/${vehicleId}/devices?`) && (init?.method ?? 'GET') === 'GET') {
        return new Response(
          JSON.stringify({
            devices: [sampleDetail],
            page: { nextCursor: null },
            requestId: 'req-list',
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      if (
        (target.includes(`/vehicles/${vehicleId}/devices/${deviceId}?`) ||
          target.includes(`/devices/${deviceId}?`)) &&
        (init?.method ?? 'GET') === 'GET'
      ) {
        return new Response(JSON.stringify({ ...sampleDetail, requestId: 'req-get' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (init?.method === 'PATCH') {
        return new Response(
          JSON.stringify({
            deviceId,
            status: 'ACTIVE',
            message: 'Device metadata updated',
            data: sampleDetail,
            requestId: 'req-patch',
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      if (target.endsWith('/challenge')) {
        return new Response(
          JSON.stringify({
            challengeId,
            status: 'PENDING',
            message: 'Device enrollment challenge issued',
            data: {
              protocol: 'pichu-device-link-v1',
              challengeId,
              deviceId,
              vehicleId,
              credentialId,
              requestedByUserId: userId,
              challenge: 'ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8',
              expiresAt: '2026-11-26T12:05:00.000Z',
            },
            requestId: 'req-chal',
          }),
          { status: 201, headers: { 'content-type': 'application/json' } },
        );
      }
      if (target.endsWith('/link')) {
        return new Response(
          JSON.stringify({
            deviceId,
            status: 'ACTIVE',
            message: 'Device linked',
            data: sampleDetail,
            requestId: 'req-link',
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      if (target.endsWith('/revoke')) {
        return new Response(
          JSON.stringify({
            deviceId,
            status: 'REVOKED',
            message: 'Device revoked',
            data: {
              ...sampleDetail,
              status: 'REVOKED',
              operational: false,
              revokedAt: '2026-11-26T12:10:00.000Z',
              revocationReason: 'ADMINISTRATIVE',
            },
            requestId: 'req-rev',
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }

      throw new Error(`Unexpected upstream call: ${init?.method} ${target}`);
    },
  });
  context.after(async () => app.close());

  const headers = { authorization: `Bearer ${token()}`, 'x-request-id': 'gw-dev-test' };

  // 1) Retired alias POST /api/vehicles/:vehicleId/devices/link returns 404 and is absent from OpenAPI
  const retired = await app.inject({
    method: 'POST',
    url: `/api/vehicles/${vehicleId}/devices/link`,
    headers,
    payload: { identifier: 'esp32-01', publicKey: 'A'.repeat(64) },
  });
  assert.equal(retired.statusCode, 404);
  assert.equal(upstreamCalls.length, 0);

  const docs = await app.inject({ method: 'GET', url: '/docs/json' });
  assert.equal(docs.statusCode, 200);
  const spec = docs.json() as { paths: Record<string, Record<string, unknown>> };
  assert.equal(spec.paths['/api/vehicles/{vehicleId}/devices/link'], undefined);
  for (const [route, method] of [
    ['/api/vehicles/{vehicleId}/devices', 'post'],
    ['/api/vehicles/{vehicleId}/devices', 'get'],
    ['/api/vehicles/{vehicleId}/devices/{deviceId}', 'get'],
    ['/api/devices/{deviceId}', 'get'],
    ['/api/vehicles/{vehicleId}/devices/{deviceId}', 'patch'],
    ['/api/vehicles/{vehicleId}/devices/{deviceId}/challenge', 'post'],
    ['/api/vehicles/{vehicleId}/devices/{deviceId}/link', 'post'],
    ['/api/vehicles/{vehicleId}/devices/{deviceId}/revoke', 'post'],
  ] as const) {
    assert.ok(spec.paths[route]?.[method], `OpenAPI documents ${method.toUpperCase()} ${route}`);
  }

  // 2) Input rejections before upstream: client-supplied userId, empty PATCH, control chars, unknown fields
  const badPayloads: Array<{
    method: 'POST' | 'PATCH';
    url: string;
    payload: Record<string, unknown>;
  }> = [
    {
      method: 'POST',
      url: `/api/vehicles/${vehicleId}/devices`,
      payload: { identifier: 'esp32-01', publicKey: 'A'.repeat(64), userId },
    },
    {
      method: 'POST',
      url: `/api/vehicles/${vehicleId}/devices`,
      payload: {
        identifier: 'esp32-01',
        publicKey: 'A'.repeat(64),
        metadata: { name: 'bad\u0000name' },
      },
    },
    {
      method: 'PATCH',
      url: `/api/vehicles/${vehicleId}/devices/${deviceId}`,
      payload: {},
    },
    {
      method: 'PATCH',
      url: `/api/vehicles/${vehicleId}/devices/${deviceId}`,
      payload: { name: 'Valid', unknownField: 'nope' },
    },
    {
      method: 'POST',
      url: `/api/vehicles/${vehicleId}/devices/${deviceId}/revoke`,
      payload: { reason: 'NOT_A_VALID_REASON' },
    },
  ];
  for (const bad of badPayloads) {
    const res = await app.inject({ ...bad, headers });
    assert.equal(res.statusCode, 400, `${bad.method} ${bad.url}`);
  }
  assert.equal(upstreamCalls.length, 0, 'invalid requests never reach Vehicle');

  // 3) Exercise all 8 public endpoints and verify every single one targets vehicle-service
  const regRes = await app.inject({
    method: 'POST',
    url: `/api/vehicles/${vehicleId}/devices`,
    headers,
    payload: {
      identifier: '  esp32-sunroof-01  ',
      publicKey: `  ${'A'.repeat(64)}  `,
      metadata: {
        name: '  Sunroof Node  ',
        hardwareRevision: ' rev-1.0 ',
      },
    },
  });
  assert.equal(regRes.statusCode, 201);
  assert.deepEqual(upstreamCalls.at(-1)?.body, {
    userId,
    identifier: 'esp32-sunroof-01',
    publicKey: 'A'.repeat(64),
    metadata: { name: 'Sunroof Node', hardwareRevision: 'rev-1.0' },
  });

  const listRes = await app.inject({
    method: 'GET',
    url: `/api/vehicles/${vehicleId}/devices?limit=10&status=ACTIVE`,
    headers,
  });
  assert.equal(listRes.statusCode, 200);

  const scopedGetRes = await app.inject({
    method: 'GET',
    url: `/api/vehicles/${vehicleId}/devices/${deviceId}`,
    headers,
  });
  assert.equal(scopedGetRes.statusCode, 200);

  const directGetRes = await app.inject({
    method: 'GET',
    url: `/api/devices/${deviceId}`,
    headers,
  });
  assert.equal(directGetRes.statusCode, 200);
  assert.equal(
    upstreamCalls.at(-1)?.url,
    `http://vehicle.test/devices/${deviceId}?userId=${userId}`,
    'GET /api/devices/:deviceId always queries Vehicle, never Device directly',
  );

  const patchRes = await app.inject({
    method: 'PATCH',
    url: `/api/vehicles/${vehicleId}/devices/${deviceId}`,
    headers,
    payload: { firmwareVersion: ' 1.1.0 ', serialNumber: null },
  });
  assert.equal(patchRes.statusCode, 200);
  assert.deepEqual(upstreamCalls.at(-1)?.body, {
    userId,
    firmwareVersion: '1.1.0',
    serialNumber: null,
  });

  const chalRes = await app.inject({
    method: 'POST',
    url: `/api/vehicles/${vehicleId}/devices/${deviceId}/challenge`,
    headers,
  });
  assert.equal(chalRes.statusCode, 201);

  const linkRes = await app.inject({
    method: 'POST',
    url: `/api/vehicles/${vehicleId}/devices/${deviceId}/link`,
    headers,
    payload: {
      challengeId,
      challenge: 'ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8',
      signature:
        'pobMhCedEBz-1oaWKnuirWj96o5UNkmbADvBNgNkBiI-x3RD1u0PzJ-TVXsE1P0h4udxA0izS_3vUtn4DeYpDw',
    },
  });
  assert.equal(linkRes.statusCode, 200);

  const revRes = await app.inject({
    method: 'POST',
    url: `/api/vehicles/${vehicleId}/devices/${deviceId}/revoke`,
    headers,
    payload: { reason: 'ADMINISTRATIVE' },
  });
  assert.equal(revRes.statusCode, 200);

  assert.equal(upstreamCalls.length, 8);
  assert.ok(
    upstreamCalls.every(
      (call) => call.url.startsWith('http://vehicle.test/') && call.audience === 'vehicle-service',
    ),
    'zero device-service calls from Gateway on resource endpoints',
  );

  // 4) PATCH mutation is never retried on 503
  force503 = true;
  const before503 = upstreamCalls.length;
  const patch503 = await app.inject({
    method: 'PATCH',
    url: `/api/vehicles/${vehicleId}/devices/${deviceId}`,
    headers,
    payload: { name: 'NoRetry' },
  });
  assert.equal(patch503.statusCode, 503);
  assert.equal(upstreamCalls.length - before503, 1);
});
