import assert from 'node:assert/strict';
import test from 'node:test';
import { createHmac } from 'node:crypto';
import { createApp } from '../src/app.js';
import { gatewayEnvSchema, type GatewayEnv } from '../src/config/env.js';
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

function env(secret: string): GatewayEnv {
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

test('Gateway derives inviterUserId from authenticated JWT when proxying invitation creation', async () => {
  const secret = 'j'.repeat(32);
  const vehicleId = '507f1f77bcf86cd799439013';
  const inviteeUserId = '507f1f77bcf86cd799439014';
  const invitationId = '507f1f77bcf86cd799439015';
  let capturedBodyText: string | undefined;

  const app = createApp({
    env: env(secret),
    fetchImpl: async (url, init) => {
      if (String(url).endsWith('/auth/me')) return identityProfile();
      capturedBodyText = await new Response(init?.body).text();
      return new Response(
        JSON.stringify({
          invitationId,
          status: 'PENDING',
          message: 'Invitation created',
          data: {
            invitationId,
            vehicleId,
            inviterUserId: '507f1f77bcf86cd799439011',
            inviteeUserId,
            permissions: ['vehicle:read'],
            status: 'PENDING',
            expiresAt: '2026-12-01T00:00:00.000Z',
            createdAt: '2026-11-24T00:00:00.000Z',
            acceptedAt: null,
            revokedAt: null,
            revokeReason: null,
          },
          requestId: 'gateway-inv-1',
        }),
        { status: 201, headers: { 'content-type': 'application/json' } },
      );
    },
  });

  const authorization = `Bearer ${token(secret)}`;

  // Public client attempting to supply inviterUserId must be rejected by strict schema
  const spoofed = await app.inject({
    method: 'POST',
    url: `/api/vehicles/${vehicleId}/invitations`,
    headers: { authorization },
    payload: {
      inviterUserId: inviteeUserId,
      inviteeUserId,
      permissions: ['vehicle:read'],
    },
  });
  assert.equal(spoofed.statusCode, 400);

  const valid = await app.inject({
    method: 'POST',
    url: `/api/vehicles/${vehicleId}/invitations`,
    headers: { authorization, 'x-request-id': 'gateway-inv-1' },
    payload: {
      inviteeUserId,
      permissions: ['vehicle:read'],
    },
  });
  await app.close();

  assert.equal(valid.statusCode, 201);
  assert.ok(capturedBodyText);
  assert.deepEqual(JSON.parse(capturedBodyText), {
    inviteeUserId,
    permissions: ['vehicle:read'],
    inviterUserId: '507f1f77bcf86cd799439011',
  });
});

const authenticatedUserId = '507f1f77bcf86cd799439011';
const managedVehicleId = '507f1f77bcf86cd799439013';

function ownerVehicleData(overrides: Record<string, unknown> = {}) {
  return {
    id: managedVehicleId,
    name: 'Mazda 3',
    make: 'Mazda',
    model: '3',
    generation: 'BL',
    trim: 'XLE',
    year: 2011,
    bodyStyle: 'sedan',
    engine: null,
    transmission: 'automatic',
    fuelType: 'gasoline',
    ownerUserId: authenticatedUserId,
    role: 'OWNER',
    ...overrides,
  };
}

interface CapturedUpstream {
  url: string;
  method: string;
  headers: Headers;
  body: string;
}

function vehicleUpstream(respond: (call: CapturedUpstream) => Response) {
  const calls: CapturedUpstream[] = [];
  const fetchImpl = async (url: string | URL | Request, init?: RequestInit) => {
    if (String(url).endsWith('/auth/me')) return identityProfile();
    const call = {
      url: String(url),
      method: init?.method ?? 'GET',
      headers: new Headers(init?.headers),
      body: init?.body === undefined ? '' : await new Response(init.body).text(),
    };
    calls.push(call);
    return respond(call);
  };
  return { calls, fetchImpl };
}

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

test('Gateway PATCH signs only validated fields plus the JWT-derived userId and never retries', async () => {
  const secret = 'j'.repeat(32);
  const upstream = vehicleUpstream((call) =>
    call.body.includes('Retry')
      ? json(503, { message: 'temporary' })
      : json(200, {
          vehicleId: managedVehicleId,
          message: 'Vehicle updated',
          data: ownerVehicleData({ privateAuditNote: 'hidden' }),
          requestId: 'gateway-patch-1',
        }),
  );
  const app = createApp({ env: env(secret), fetchImpl: upstream.fetchImpl });
  const authorization = `Bearer ${token(secret)}`;
  const response = await app.inject({
    method: 'PATCH',
    url: `/api/vehicles/${managedVehicleId}`,
    headers: { authorization, 'x-request-id': 'gateway-patch-1' },
    payload: { engine: null, trim: ' XLE ' },
  });
  assert.equal(response.statusCode, 200);
  assert.equal(response.json().data.role, 'OWNER');
  assert.equal(response.body.includes('privateAuditNote'), false);
  assert.equal(upstream.calls.length, 1);
  const [call] = upstream.calls;
  assert.equal(call?.method, 'PATCH');
  assert.equal(call?.url, `http://vehicle.test/vehicles/${managedVehicleId}`);
  assert.equal(call?.headers.get('content-type'), 'application/json');
  assert.equal(call?.headers.get('x-internal-auth-version'), '2');
  assert.equal(call?.headers.get('authorization'), authorization);
  assert.deepEqual(JSON.parse(call?.body ?? ''), {
    trim: 'XLE',
    engine: null,
    userId: authenticatedUserId,
  });

  const rejectedPayloads: unknown[] = [
    {},
    { userId: authenticatedUserId },
    { name: 'Car', userId: '507f1f77bcf86cd799439099' },
    { name: 'Car', ownerUserId: authenticatedUserId },
    { name: 'Car', status: 'ARCHIVED' },
    { name: 'Car', role: 'OWNER' },
    { name: null },
    { name: '   ' },
    { model: 'Mazda\t3' },
    { year: 1885 },
  ];
  for (const payload of rejectedPayloads) {
    const rejected = await app.inject({
      method: 'PATCH',
      url: `/api/vehicles/${managedVehicleId}`,
      headers: { authorization },
      payload: payload as Record<string, unknown>,
    });
    assert.equal(rejected.statusCode, 400, `Expected 400 for ${JSON.stringify(payload)}`);
  }
  const withQuery = await app.inject({
    method: 'PATCH',
    url: `/api/vehicles/${managedVehicleId}?userId=${authenticatedUserId}`,
    headers: { authorization },
    payload: { name: 'Car' },
  });
  assert.equal(withQuery.statusCode, 400);
  const invalidId = await app.inject({
    method: 'PATCH',
    url: '/api/vehicles/not-an-object-id',
    headers: { authorization },
    payload: { name: 'Car' },
  });
  assert.equal(invalidId.statusCode, 400);
  assert.equal(upstream.calls.length, 1);

  const transient = await app.inject({
    method: 'PATCH',
    url: `/api/vehicles/${managedVehicleId}`,
    headers: { authorization },
    payload: { name: 'Retry' },
  });
  await app.close();
  assert.equal(transient.statusCode, 503);
  assert.equal(upstream.calls.length, 2);
});

test('Gateway DELETE accepts no body or a strict reason, signs the derived userId, and never retries', async () => {
  const secret = 'j'.repeat(32);
  const upstream = vehicleUpstream((call) =>
    call.body.includes('Retry')
      ? json(503, { message: 'temporary' })
      : json(200, {
          vehicleId: managedVehicleId,
          status: 'ARCHIVED',
          archivedAt: '2026-11-26T12:00:00.000Z',
          message: 'Vehicle archived',
          requestId: 'gateway-delete-1',
          archiveReason: 'must not leak',
        }),
  );
  const app = createApp({ env: env(secret), fetchImpl: upstream.fetchImpl });
  const authorization = `Bearer ${token(secret)}`;

  const withoutBody = await app.inject({
    method: 'DELETE',
    url: `/api/vehicles/${managedVehicleId}`,
    headers: { authorization, 'x-request-id': 'gateway-delete-1' },
  });
  assert.equal(withoutBody.statusCode, 200);
  assert.equal(withoutBody.json().status, 'ARCHIVED');
  assert.equal(withoutBody.body.includes('must not leak'), false);
  assert.equal(upstream.calls[0]?.method, 'DELETE');
  assert.equal(upstream.calls[0]?.url, `http://vehicle.test/vehicles/${managedVehicleId}`);
  assert.equal(upstream.calls[0]?.headers.get('content-type'), 'application/json');
  assert.equal(upstream.calls[0]?.body, JSON.stringify({ userId: authenticatedUserId }));
  assert.equal(
    upstream.calls[0]?.headers.get('content-length'),
    String(Buffer.byteLength(JSON.stringify({ userId: authenticatedUserId }))),
  );

  const withReason = await app.inject({
    method: 'DELETE',
    url: `/api/vehicles/${managedVehicleId}`,
    headers: { authorization },
    payload: { reason: ' Vehicle sold ' },
  });
  assert.equal(withReason.statusCode, 200);
  assert.equal(
    upstream.calls[1]?.body,
    JSON.stringify({ reason: 'Vehicle sold', userId: authenticatedUserId }),
  );

  const rejectedPayloads: Array<Record<string, unknown>> = [
    { reason: '' },
    { reason: 'x'.repeat(257) },
    { reason: 'Sold\n' },
    { reason: null },
    { userId: authenticatedUserId },
    { status: 'ARCHIVED' },
  ];
  for (const payload of rejectedPayloads) {
    const rejected = await app.inject({
      method: 'DELETE',
      url: `/api/vehicles/${managedVehicleId}`,
      headers: { authorization },
      payload,
    });
    assert.equal(rejected.statusCode, 400, `Expected 400 for ${JSON.stringify(payload)}`);
  }
  assert.equal(upstream.calls.length, 2);

  const transient = await app.inject({
    method: 'DELETE',
    url: `/api/vehicles/${managedVehicleId}`,
    headers: { authorization },
    payload: { reason: 'Retry' },
  });
  await app.close();
  assert.equal(transient.statusCode, 503);
  assert.equal(upstream.calls.length, 3);
});

test('Gateway declares content-length as the exact UTF-8 byte length of signed multibyte bodies', async () => {
  const secret = 'j'.repeat(32);
  const upstream = vehicleUpstream((call) =>
    call.method === 'DELETE'
      ? json(200, {
          vehicleId: managedVehicleId,
          status: 'ARCHIVED',
          archivedAt: '2026-11-26T12:00:00.000Z',
          message: 'Vehicle archived',
        })
      : call.method === 'GET'
        ? json(200, { vehicles: [], page: { nextCursor: null } })
        : json(call.method === 'POST' ? 201 : 200, {
            vehicleId: managedVehicleId,
            message: 'ok',
            data: ownerVehicleData(),
          }),
  );
  const app = createApp({ env: env(secret), fetchImpl: upstream.fetchImpl });
  const authorization = `Bearer ${token(secret)}`;
  const multibyte = 'Mazda 3 — Ñandú 🚗 東京';
  const attempts = [
    { method: 'POST' as const, url: '/api/vehicles', payload: { name: multibyte } },
    {
      method: 'PATCH' as const,
      url: `/api/vehicles/${managedVehicleId}`,
      payload: { trim: multibyte },
    },
    {
      method: 'DELETE' as const,
      url: `/api/vehicles/${managedVehicleId}`,
      payload: { reason: multibyte },
    },
  ];
  for (const attempt of attempts) {
    const response = await app.inject({ ...attempt, headers: { authorization } });
    assert.ok(response.statusCode < 300, `${attempt.method} ${response.statusCode}`);
  }
  const listed = await app.inject({
    method: 'GET',
    url: '/api/vehicles',
    headers: { authorization },
  });
  await app.close();
  assert.equal(listed.statusCode, 200);

  assert.equal(upstream.calls.length, 4);
  for (const call of upstream.calls.slice(0, 3)) {
    const byteLength = Buffer.byteLength(call.body, 'utf8');
    assert.ok(call.body.includes(multibyte));
    assert.notEqual(byteLength, call.body.length, 'multibyte bytes differ from JS length');
    assert.equal(call.headers.get('content-length'), String(byteLength), call.method);
    assert.equal(call.headers.get('transfer-encoding'), null);
    assert.equal(call.headers.get('content-type'), 'application/json');
  }
  const getCall = upstream.calls[3]!;
  assert.equal(getCall.method, 'GET');
  assert.equal(getCall.body, '');
  assert.equal(getCall.headers.get('content-length'), null);
  assert.equal(getCall.headers.get('content-type'), null);
});

test('Gateway applies text limits after trimming exactly like the contract used by Vehicle', async () => {
  const secret = 'j'.repeat(32);
  const upstream = vehicleUpstream((call) =>
    json(call.method === 'POST' ? 201 : 200, {
      vehicleId: managedVehicleId,
      message: 'ok',
      data: ownerVehicleData(),
    }),
  );
  const app = createApp({ env: env(secret), fetchImpl: upstream.fetchImpl });
  const authorization = `Bearer ${token(secret)}`;
  const padded = (length: number) => `   ${'n'.repeat(length)}   `;

  const acceptedPatch = await app.inject({
    method: 'PATCH',
    url: `/api/vehicles/${managedVehicleId}`,
    headers: { authorization },
    payload: { name: padded(120), make: padded(80), trim: padded(80), fuelType: padded(60) },
  });
  assert.equal(acceptedPatch.statusCode, 200);
  assert.deepEqual(JSON.parse(upstream.calls[0]!.body), {
    name: 'n'.repeat(120),
    make: 'n'.repeat(80),
    trim: 'n'.repeat(80),
    fuelType: 'n'.repeat(60),
    userId: authenticatedUserId,
  });
  const acceptedCreate = await app.inject({
    method: 'POST',
    url: '/api/vehicles',
    headers: { authorization },
    payload: { name: padded(120), generation: padded(60) },
  });
  assert.equal(acceptedCreate.statusCode, 201);
  assert.deepEqual(JSON.parse(upstream.calls[1]!.body), {
    name: 'n'.repeat(120),
    generation: 'n'.repeat(60),
    userId: authenticatedUserId,
  });

  const rejected = [
    { method: 'PATCH' as const, payload: { name: padded(121) } },
    { method: 'PATCH' as const, payload: { make: padded(81) } },
    { method: 'PATCH' as const, payload: { name: '     ' } },
    { method: 'PATCH' as const, payload: { model: '\tCX-5' } },
    { method: 'POST' as const, payload: { name: padded(121) } },
    { method: 'POST' as const, payload: { name: 'Car', engine: `${padded(80)}\u0000` } },
    { method: 'POST' as const, payload: { name: 'Car', userId: authenticatedUserId } },
  ];
  for (const attempt of rejected) {
    const response = await app.inject({
      method: attempt.method,
      url: attempt.method === 'POST' ? '/api/vehicles' : `/api/vehicles/${managedVehicleId}`,
      headers: { authorization },
      payload: attempt.payload,
    });
    assert.equal(response.statusCode, 400, JSON.stringify(attempt.payload));
  }
  const docs = await app.inject({ method: 'GET', url: '/docs/json' });
  await app.close();
  assert.equal(upstream.calls.length, 2, 'rejected payloads never reach Vehicle');
  const patchSchema = docs.json().paths['/api/vehicles/{vehicleId}'].patch.requestBody.content[
    'application/json'
  ].schema as { properties: Record<string, unknown>; additionalProperties: unknown };
  assert.equal(patchSchema.additionalProperties, false);
  assert.match(JSON.stringify(patchSchema.properties.name), /1-120 characters after trimming/);
  assert.doesNotMatch(JSON.stringify(patchSchema.properties), /maxLength/);
});

test('Gateway propagates owner-only and visibility errors from Vehicle with a uniform shape', async () => {
  const secret = 'j'.repeat(32);
  const statuses: Array<[number, string, string]> = [
    [403, 'FORBIDDEN', 'Only the canonical vehicle owner may perform this operation'],
    [404, 'NOT_FOUND', 'Vehicle not found'],
    [409, 'CONFLICT', 'Archived vehicles cannot be modified'],
  ];
  let next = 0;
  const upstream = vehicleUpstream(() => {
    const [status, error, message] = statuses[next % statuses.length]!;
    next += 1;
    return json(status, { error, message, requestId: 'upstream-id' });
  });
  const app = createApp({ env: env(secret), fetchImpl: upstream.fetchImpl });
  const authorization = `Bearer ${token(secret)}`;
  for (const [status, error, message] of statuses) {
    const response = await app.inject({
      method: 'PATCH',
      url: `/api/vehicles/${managedVehicleId}`,
      headers: { authorization, 'x-request-id': `error-${status}` },
      payload: { name: 'Car' },
    });
    assert.equal(response.statusCode, status);
    assert.deepEqual(response.json(), { error, message, requestId: `error-${status}` });
  }
  await app.close();
});

test('Gateway list forwards role, limit and cursor inside the signed target and rejects tampering', async () => {
  const secret = 'j'.repeat(32);
  const upstream = vehicleUpstream(() =>
    json(200, {
      vehicles: [ownerVehicleData({ role: 'MEMBER', ownerUserId: '507f1f77bcf86cd799439099' })],
      page: { nextCursor: 'eyJ2IjoxfQ' },
      requestId: 'list-1',
    }),
  );
  const app = createApp({ env: env(secret), fetchImpl: upstream.fetchImpl });
  const authorization = `Bearer ${token(secret)}`;
  const response = await app.inject({
    method: 'GET',
    url: '/api/vehicles?limit=5&cursor=eyJ2IjoxfQ&role=MEMBER',
    headers: { authorization },
  });
  assert.equal(response.statusCode, 200);
  assert.equal(response.json().vehicles[0].role, 'MEMBER');
  assert.equal(response.json().page.nextCursor, 'eyJ2IjoxfQ');
  assert.equal(
    upstream.calls[0]?.url,
    `http://vehicle.test/vehicles?userId=${authenticatedUserId}&limit=5&cursor=eyJ2IjoxfQ&role=MEMBER`,
  );
  assert.equal(upstream.calls[0]?.body, '');

  for (const query of [
    `userId=${authenticatedUserId}`,
    'role=ADMIN',
    'limit=0',
    'limit=101',
    'cursor=abc%2B%2F',
    `cursor=${'a'.repeat(257)}`,
  ]) {
    const rejected = await app.inject({
      method: 'GET',
      url: `/api/vehicles?${query}`,
      headers: { authorization },
    });
    assert.equal(rejected.statusCode, 400, `Expected 400 for ${query}`);
  }
  await app.close();
  assert.equal(upstream.calls.length, 1);
});

test('Gateway CORS allows PATCH and Swagger documents the five vehicle endpoints', async () => {
  const secret = 'j'.repeat(32);
  const app = createApp({ env: env(secret), fetchImpl: async () => json(500, {}) });
  const preflight = await app.inject({
    method: 'OPTIONS',
    url: `/api/vehicles/${managedVehicleId}`,
    headers: { origin: 'http://localhost:3000', 'access-control-request-method': 'PATCH' },
  });
  assert.equal(preflight.statusCode, 204);
  assert.equal(preflight.headers['access-control-allow-methods'], 'GET,POST,PATCH,DELETE,OPTIONS');
  const docs = await app.inject({ method: 'GET', url: '/docs/json' });
  await app.close();
  const document = docs.json() as {
    paths: Record<string, Record<string, { responses: Record<string, unknown> }>>;
  };
  assert.ok(document.paths['/api/vehicles']?.post?.responses['201']);
  assert.ok(document.paths['/api/vehicles']?.get?.responses['200']);
  const item = document.paths['/api/vehicles/{vehicleId}'];
  assert.ok(item?.get?.responses['200']);
  assert.ok(item?.patch?.responses['200']);
  assert.ok(item?.patch?.responses['403']);
  assert.ok(item?.patch?.responses['409']);
  assert.ok(item?.delete?.responses['200']);
  assert.ok(item?.delete?.responses['404']);
});
