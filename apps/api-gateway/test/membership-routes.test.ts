import assert from 'node:assert/strict';
import test from 'node:test';
import { createHmac } from 'node:crypto';
import { createApp } from '../src/app.js';
import { gatewayEnvSchema, type GatewayEnv } from '../src/config/env.js';
import { testInternalAuthEnv } from './test-env.js';

const secret = 'j'.repeat(32);
const ownerUserId = '507f1f77bcf86cd799439011';
const otherUserId = '507f1f77bcf86cd799439021';
const vehicleId = '507f1f77bcf86cd799439013';
const inviteeUserId = '507f1f77bcf86cd799439014';
const invitationId = '507f1f77bcf86cd799439015';
const membershipId = '507f1f77bcf86cd799439016';

function token(sub: string): string {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const payload = Buffer.from(
    JSON.stringify({
      sub,
      sid: '507f1f77bcf86cd799439012',
      iss: 'issuer',
      aud: 'audience',
      iat: now,
      exp: now + 60,
    }),
  ).toString('base64url');
  const signature = createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64url');
  return `Bearer ${header}.${payload}.${signature}`;
}

function env(overrides: Partial<GatewayEnv> = {}): GatewayEnv {
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
    ...overrides,
  });
}

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function subjectOf(authorization: string | null): string {
  const encoded = authorization?.split('.')[1] ?? '';
  return (JSON.parse(Buffer.from(encoded, 'base64url').toString()) as { sub: string }).sub;
}

interface CapturedUpstream {
  url: string;
  method: string;
  headers: Headers;
  body: string;
}

function upstream(
  respond: (call: CapturedUpstream) => Response,
  options: { emailVerified?: boolean } = {},
) {
  const calls: CapturedUpstream[] = [];
  const fetchImpl = async (url: string | URL | Request, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    if (String(url).endsWith('/auth/me'))
      return json(200, {
        id: subjectOf(headers.get('authorization')),
        name: 'Ada',
        username: 'ada_01',
        email: 'ada@example.com',
        emailVerified: options.emailVerified ?? true,
        emailVerifiedAt: options.emailVerified === false ? null : '2026-11-04T12:00:00.000Z',
      });
    const call = {
      url: String(url),
      method: init?.method ?? 'GET',
      headers,
      body: init?.body === undefined ? '' : await new Response(init.body).text(),
    };
    calls.push(call);
    return respond(call);
  };
  return { calls, fetchImpl };
}

const invitationView = {
  invitationId,
  vehicleId,
  inviterUserId: ownerUserId,
  inviteeUserId,
  permissions: ['vehicle:read'],
  status: 'PENDING',
  expiresAt: '2026-12-03T12:00:00.000Z',
  createdAt: '2026-11-26T12:00:00.000Z',
  acceptedAt: null,
  revokedAt: null,
  revokeReason: null,
};
const membershipView = {
  membershipId,
  vehicleId,
  userId: inviteeUserId,
  role: 'MEMBER',
  permissions: ['vehicle:read'],
  status: 'ACTIVE',
};
const memberView = {
  ...membershipView,
  createdAt: '2026-11-26T12:00:00.000Z',
  suspendedAt: null,
  revokedAt: null,
};
const leakedFields = {
  issuerMembershipId: membershipId,
  revokedByUserId: ownerUserId,
  suspendedByUserId: ownerUserId,
  revokeReason: 'internal audit note',
};

interface MutationCase {
  name: string;
  method: 'POST' | 'PATCH' | 'DELETE';
  url: string;
  payload?: Record<string, unknown>;
  upstreamPath: string;
  signedBody: Record<string, unknown>;
  response: Record<string, unknown>;
  status: number;
}

const memberPath = `/vehicles/${vehicleId}/members/${membershipId}`;
const mutationCases: MutationCase[] = [
  {
    name: 'create invitation',
    method: 'POST',
    url: `/api/vehicles/${vehicleId}/invitations`,
    payload: { inviteeUserId, permissions: ['vehicle:read'] },
    upstreamPath: `/vehicles/${vehicleId}/invitations`,
    signedBody: { inviteeUserId, permissions: ['vehicle:read'], inviterUserId: ownerUserId },
    response: {
      invitationId,
      status: 'PENDING',
      data: { ...invitationView, issuerMembershipId: membershipId },
    },
    status: 201,
  },
  {
    name: 'accept invitation',
    method: 'POST',
    url: `/api/invitations/${invitationId}/accept`,
    payload: {},
    upstreamPath: `/invitations/${invitationId}/accept`,
    signedBody: { userId: ownerUserId },
    response: { accepted: true, vehicleId, data: { ...membershipView, ...leakedFields } },
    status: 200,
  },
  {
    name: 'revoke invitation',
    method: 'DELETE',
    url: `/api/vehicles/${vehicleId}/invitations/${invitationId}`,
    payload: { reason: ' Wrong recipient ' },
    upstreamPath: `/vehicles/${vehicleId}/invitations/${invitationId}`,
    signedBody: { reason: 'Wrong recipient', userId: ownerUserId },
    response: {
      invitationId,
      status: 'REVOKED',
      data: {
        ...invitationView,
        status: 'REVOKED',
        revokedAt: '2026-11-26T13:00:00.000Z',
        revokeReason: 'Wrong recipient',
        revokedByUserId: ownerUserId,
      },
    },
    status: 200,
  },
  {
    name: 'update member permissions',
    method: 'PATCH',
    url: `/api/vehicles/${vehicleId}/members/${membershipId}`,
    payload: { permissions: [] },
    upstreamPath: memberPath,
    signedBody: { permissions: [], userId: ownerUserId },
    response: {
      membershipId,
      status: 'ACTIVE',
      data: { ...memberView, permissions: [], ...leakedFields },
    },
    status: 200,
  },
  {
    name: 'suspend member',
    method: 'POST',
    url: `/api/vehicles/${vehicleId}/members/${membershipId}/suspend`,
    payload: { reason: 'Lost phone' },
    upstreamPath: `${memberPath}/suspend`,
    signedBody: { reason: 'Lost phone', userId: ownerUserId },
    response: {
      membershipId,
      status: 'SUSPENDED',
      data: {
        ...memberView,
        status: 'SUSPENDED',
        suspendedAt: '2026-11-26T13:00:00.000Z',
        ...leakedFields,
      },
    },
    status: 200,
  },
  {
    name: 'reactivate member',
    method: 'POST',
    url: `/api/vehicles/${vehicleId}/members/${membershipId}/reactivate`,
    upstreamPath: `${memberPath}/reactivate`,
    signedBody: { userId: ownerUserId },
    response: { membershipId, status: 'ACTIVE', data: { ...memberView, ...leakedFields } },
    status: 200,
  },
  {
    name: 'revoke member',
    method: 'DELETE',
    url: `/api/vehicles/${vehicleId}/members/${membershipId}`,
    upstreamPath: memberPath,
    signedBody: { userId: ownerUserId },
    response: {
      membershipId,
      status: 'REVOKED',
      data: {
        ...memberView,
        status: 'REVOKED',
        revokedAt: '2026-11-26T13:00:00.000Z',
        ...leakedFields,
      },
    },
    status: 200,
  },
  {
    name: 'leave vehicle',
    method: 'POST',
    url: `/api/vehicles/${vehicleId}/members/leave`,
    payload: { membershipId },
    upstreamPath: `/vehicles/${vehicleId}/members/leave`,
    signedBody: { membershipId, userId: ownerUserId },
    response: {
      membershipId,
      status: 'REVOKED',
      data: { ...membershipView, status: 'REVOKED', ...leakedFields },
    },
    status: 200,
  },
];

test('Gateway signs every membership mutation with the JWT-derived actor, strips audit fields and never retries', async () => {
  for (const testCase of mutationCases) {
    let transient = false;
    const fake = upstream(() =>
      transient ? json(503, { message: 'temporary' }) : json(testCase.status, testCase.response),
    );
    const app = createApp({ env: env(), fetchImpl: fake.fetchImpl });
    const authorization = token(ownerUserId);
    const response = await app.inject({
      method: testCase.method,
      url: testCase.url,
      headers: { authorization },
      ...(testCase.payload ? { payload: testCase.payload } : {}),
    });
    assert.equal(response.statusCode, testCase.status, `${testCase.name}: ${response.body}`);
    for (const field of Object.keys(leakedFields))
      if (field !== 'revokeReason' || !testCase.name.includes('invitation'))
        assert.equal(response.body.includes(`"${field}"`), false, `${testCase.name} ${field}`);
    assert.equal(response.body.includes('internal audit note'), false, testCase.name);
    assert.equal(fake.calls.length, 1, testCase.name);
    const [call] = fake.calls;
    assert.equal(call?.method, testCase.method, testCase.name);
    assert.equal(call?.url, `http://vehicle.test${testCase.upstreamPath}`, testCase.name);
    assert.equal(call?.headers.get('x-internal-auth-version'), '2', testCase.name);
    assert.equal(call?.headers.get('x-service-name'), 'api-gateway', testCase.name);
    assert.equal(call?.headers.get('authorization'), authorization, testCase.name);
    assert.equal(
      call?.headers.get('content-length'),
      String(Buffer.byteLength(call?.body ?? '')),
      testCase.name,
    );
    assert.deepEqual(JSON.parse(call?.body ?? ''), testCase.signedBody, testCase.name);

    transient = true;
    const retried = await app.inject({
      method: testCase.method,
      url: testCase.url,
      headers: { authorization },
      ...(testCase.payload ? { payload: testCase.payload } : {}),
    });
    await app.close();
    assert.equal(retried.statusCode, 503, testCase.name);
    assert.equal(fake.calls.length, 2, `${testCase.name} must not retry`);
  }
});

test('Gateway rejects forged actors, reserved fields and malformed membership requests before Vehicle', async () => {
  const fake = upstream(() => json(500, {}));
  const app = createApp({ env: env(), fetchImpl: fake.fetchImpl });
  const authorization = token(ownerUserId);
  const rejected: Array<{ method: 'POST' | 'PATCH' | 'DELETE'; url: string; payload?: unknown }> = [
    {
      method: 'POST',
      url: `/api/vehicles/${vehicleId}/invitations`,
      payload: { inviteeUserId, permissions: ['vehicle:read'], userId: otherUserId },
    },
    {
      method: 'POST',
      url: `/api/vehicles/${vehicleId}/invitations?userId=${otherUserId}`,
      payload: { inviteeUserId, permissions: ['vehicle:read'] },
    },
    {
      method: 'POST',
      url: `/api/vehicles/${vehicleId}/invitations`,
      payload: { inviteeUserId, permissions: ['vehicle:read'], status: 'ACCEPTED' },
    },
    {
      method: 'POST',
      url: `/api/invitations/${invitationId}/accept`,
      payload: { userId: otherUserId },
    },
    { method: 'POST', url: '/api/invitations/not-an-id/accept', payload: {} },
    {
      method: 'DELETE',
      url: `/api/vehicles/${vehicleId}/invitations/${invitationId}`,
      payload: { revokedByUserId: otherUserId },
    },
    {
      method: 'DELETE',
      url: `/api/vehicles/${vehicleId}/invitations/${invitationId}`,
      payload: { reason: 'x'.repeat(257) },
    },
    {
      method: 'PATCH',
      url: `/api/vehicles/${vehicleId}/members/${membershipId}`,
      payload: { permissions: ['vehicle:read'], role: 'OWNER' },
    },
    {
      method: 'PATCH',
      url: `/api/vehicles/${vehicleId}/members/${membershipId}`,
      payload: { permissions: ['vehicle:read'], status: 'ACTIVE' },
    },
    {
      method: 'PATCH',
      url: `/api/vehicles/${vehicleId}/members/${membershipId}`,
      payload: { permissions: ['vehicle:read'], userId: otherUserId },
    },
    {
      method: 'PATCH',
      url: `/api/vehicles/${vehicleId}/members/${membershipId}`,
      payload: { permissions: ['   '] },
    },
    {
      method: 'PATCH',
      url: `/api/vehicles/${vehicleId}/members/${membershipId}`,
      payload: { permissions: Array.from({ length: 101 }, () => 'vehicle:read') },
    },
    { method: 'PATCH', url: `/api/vehicles/${vehicleId}/members/${membershipId}`, payload: {} },
    {
      method: 'POST',
      url: `/api/vehicles/${vehicleId}/members/${membershipId}/suspend`,
      payload: { suspendedByUserId: otherUserId },
    },
    {
      method: 'POST',
      url: `/api/vehicles/${vehicleId}/members/${membershipId}/reactivate`,
      payload: { reason: 'not accepted' },
    },
    {
      method: 'DELETE',
      url: `/api/vehicles/${vehicleId}/members/${membershipId}`,
      payload: { userId: otherUserId },
    },
    {
      method: 'POST',
      url: `/api/vehicles/${vehicleId}/members/leave`,
      payload: { userId: otherUserId },
    },
    {
      method: 'POST',
      url: `/api/vehicles/${vehicleId}/members/leave`,
      payload: { membershipId: 'bad' },
    },
    { method: 'POST', url: `/api/vehicles/${vehicleId}/members/leave`, payload: {} },
    { method: 'POST', url: `/api/vehicles/${vehicleId}/members/leave` },
    {
      method: 'POST',
      url: `/api/vehicles/${vehicleId}/members/leave`,
      payload: { membershipId, userId: otherUserId },
    },
    { method: 'POST', url: `/api/vehicles/${vehicleId}/members/bad-id/suspend`, payload: {} },
  ];
  for (const request of rejected) {
    const response = await app.inject({
      method: request.method,
      url: request.url,
      headers: { authorization },
      ...(request.payload === undefined ? {} : { payload: request.payload as object }),
    });
    assert.equal(
      response.statusCode,
      400,
      `${request.method} ${request.url} ${JSON.stringify(request.payload)}`,
    );
  }
  const unauthenticated = await app.inject({
    method: 'POST',
    url: `/api/vehicles/${vehicleId}/members/leave`,
    payload: { membershipId },
  });
  await app.close();
  assert.equal(unauthenticated.statusCode, 401);
  assert.equal(fake.calls.length, 0);
});

test('Gateway lists forward the JWT actor, pagination and filters and reject tampered queries', async () => {
  const fake = upstream((call) => {
    if (call.url.includes('/members'))
      return json(200, {
        members: [{ ...memberView, ...leakedFields }],
        page: { nextCursor: 'eyJ2IjoxfQ' },
      });
    if (call.url.startsWith('http://vehicle.test/invitations'))
      return json(200, {
        invitations: [
          {
            invitationId,
            vehicleId,
            vehicleName: 'Mazda 3',
            permissions: ['vehicle:read'],
            status: 'PENDING',
            expiresAt: invitationView.expiresAt,
            createdAt: invitationView.createdAt,
            inviterUserId: ownerUserId,
          },
        ],
        page: { nextCursor: null },
      });
    return json(200, {
      invitations: [{ ...invitationView, issuerMembershipId: membershipId }],
      page: { nextCursor: null },
    });
  });
  const app = createApp({ env: env(), fetchImpl: fake.fetchImpl });
  const authorization = token(ownerUserId);
  const lists = [
    {
      url: `/api/vehicles/${vehicleId}/invitations?limit=5&cursor=eyJ2IjoxfQ&status=EXPIRED`,
      upstream: `http://vehicle.test/vehicles/${vehicleId}/invitations?userId=${ownerUserId}&limit=5&cursor=eyJ2IjoxfQ&status=EXPIRED`,
      hidden: 'issuerMembershipId',
    },
    {
      url: '/api/invitations?status=ACCEPTED',
      upstream: `http://vehicle.test/invitations?userId=${ownerUserId}&limit=20&status=ACCEPTED`,
      hidden: 'inviterUserId',
    },
    {
      url: `/api/vehicles/${vehicleId}/members?limit=100&status=REVOKED`,
      upstream: `http://vehicle.test/vehicles/${vehicleId}/members?userId=${ownerUserId}&limit=100&status=REVOKED`,
      hidden: 'suspendedByUserId',
    },
  ];
  for (const list of lists) {
    const response = await app.inject({ method: 'GET', url: list.url, headers: { authorization } });
    assert.equal(response.statusCode, 200, `${list.url}: ${response.body}`);
    assert.equal(response.body.includes(list.hidden), false, list.url);
    const call = fake.calls.at(-1);
    assert.equal(call?.method, 'GET');
    assert.equal(call?.url, list.upstream);
    assert.equal(call?.body, '');
  }
  const callsBefore = fake.calls.length;
  for (const url of [
    `/api/vehicles/${vehicleId}/invitations?userId=${otherUserId}`,
    `/api/vehicles/${vehicleId}/invitations?status=ACTIVE`,
    `/api/vehicles/${vehicleId}/invitations?limit=0`,
    `/api/vehicles/${vehicleId}/invitations?limit=101`,
    `/api/vehicles/${vehicleId}/invitations?cursor=abc%2B%2F`,
    `/api/invitations?userId=${otherUserId}`,
    '/api/invitations?status=SUSPENDED',
    `/api/invitations?cursor=${'a'.repeat(257)}`,
    `/api/vehicles/${vehicleId}/members?status=PENDING`,
    `/api/vehicles/${vehicleId}/members?role=OWNER`,
    `/api/vehicles/${vehicleId}/members?userId=${otherUserId}`,
    '/api/vehicles/not-an-id/members',
  ]) {
    const rejected = await app.inject({ method: 'GET', url, headers: { authorization } });
    assert.equal(rejected.statusCode, 400, url);
  }
  await app.close();
  assert.equal(fake.calls.length, callsBefore);
});

test('Gateway requires a verified email for every membership endpoint before contacting Vehicle', async () => {
  const fake = upstream(() => json(500, {}), { emailVerified: false });
  const app = createApp({ env: env(), fetchImpl: fake.fetchImpl });
  const authorization = token(inviteeUserId);
  for (const testCase of mutationCases) {
    const response = await app.inject({
      method: testCase.method,
      url: testCase.url,
      headers: { authorization },
      ...(testCase.payload ? { payload: testCase.payload } : {}),
    });
    assert.equal(response.statusCode, 403, testCase.name);
    assert.equal(response.json().error, 'EMAIL_NOT_VERIFIED', testCase.name);
  }
  for (const url of [
    `/api/vehicles/${vehicleId}/invitations`,
    '/api/invitations',
    `/api/vehicles/${vehicleId}/members`,
  ]) {
    const response = await app.inject({ method: 'GET', url, headers: { authorization } });
    assert.equal(response.statusCode, 403, url);
  }
  await app.close();
  assert.equal(fake.calls.length, 0);
});

test('Gateway limits invitation issuance per authenticated user with Retry-After', async () => {
  const fake = upstream(() => json(201, { invitationId, status: 'PENDING', data: invitationView }));
  const app = createApp({
    env: env({ INVITATION_RATE_LIMIT_MAX: 2, INVITATION_IP_RATE_LIMIT_MAX: 50 }),
    fetchImpl: fake.fetchImpl,
  });
  const issue = (authorization: string) =>
    app.inject({
      method: 'POST',
      url: `/api/vehicles/${vehicleId}/invitations`,
      headers: { authorization, 'x-request-id': 'limit-1' },
      payload: { inviteeUserId, permissions: ['vehicle:read'] },
    });
  assert.equal((await issue(token(ownerUserId))).statusCode, 201);
  assert.equal((await issue(token(ownerUserId))).statusCode, 201);
  const limited = await issue(token(ownerUserId));
  assert.equal(limited.statusCode, 429);
  assert.deepEqual(limited.json(), {
    error: 'RATE_LIMITED',
    message: 'Too many invitation requests',
    requestId: 'limit-1',
  });
  const retryAfter = Number(limited.headers['retry-after']);
  assert.ok(Number.isInteger(retryAfter) && retryAfter >= 1 && retryAfter <= 60);
  assert.equal(fake.calls.length, 2);

  assert.equal((await issue(token(otherUserId))).statusCode, 201);
  const reads = await app.inject({
    method: 'GET',
    url: `/api/vehicles/${vehicleId}/invitations`,
    headers: { authorization: token(ownerUserId) },
  });
  assert.notEqual(reads.statusCode, 429);
  const accept = await app.inject({
    method: 'POST',
    url: `/api/invitations/${invitationId}/accept`,
    headers: { authorization: token(ownerUserId) },
    payload: {},
  });
  await app.close();
  assert.notEqual(accept.statusCode, 429);
});

test('Gateway also limits invitation issuance per client IP, including unauthenticated attempts', async () => {
  const fake = upstream(() => json(201, { invitationId, status: 'PENDING', data: invitationView }));
  const app = createApp({
    env: env({ INVITATION_RATE_LIMIT_MAX: 10, INVITATION_IP_RATE_LIMIT_MAX: 2 }),
    fetchImpl: fake.fetchImpl,
  });
  const issue = (authorization?: string) =>
    app.inject({
      method: 'POST',
      url: `/api/vehicles/${vehicleId}/invitations`,
      ...(authorization ? { headers: { authorization } } : {}),
      payload: { inviteeUserId, permissions: ['vehicle:read'] },
    });
  assert.equal((await issue()).statusCode, 401);
  assert.equal((await issue(token(ownerUserId))).statusCode, 201);
  const limited = await issue(token(otherUserId));
  await app.close();
  assert.equal(limited.statusCode, 429);
  assert.ok(Number(limited.headers['retry-after']) >= 1);
  assert.equal(fake.calls.length, 1);
});

test('Gateway invitation limits cannot be evaded by switching IP, user, or forwarding headers', async () => {
  const fake = upstream(() => json(201, { invitationId, status: 'PENDING', data: invitationView }));
  const issue = (
    app: ReturnType<typeof createApp>,
    authorization: string,
    remoteAddress: string,
    forwardedFor?: string,
  ) =>
    app.inject({
      method: 'POST',
      url: `/api/vehicles/${vehicleId}/invitations`,
      remoteAddress,
      headers: {
        authorization,
        ...(forwardedFor ? { 'x-forwarded-for': forwardedFor, 'x-real-ip': forwardedFor } : {}),
      },
      payload: { inviteeUserId, permissions: ['vehicle:read'] },
    });

  const perUser = createApp({
    env: env({ INVITATION_RATE_LIMIT_MAX: 2, INVITATION_IP_RATE_LIMIT_MAX: 50 }),
    fetchImpl: fake.fetchImpl,
  });
  assert.equal((await issue(perUser, token(ownerUserId), '10.0.0.1')).statusCode, 201);
  assert.equal((await issue(perUser, token(ownerUserId), '10.0.0.2')).statusCode, 201);
  const userLimited = await issue(perUser, token(ownerUserId), '10.0.0.3', '10.9.9.9');
  await perUser.close();
  assert.equal(userLimited.statusCode, 429);
  assert.equal(userLimited.json().message, 'Too many invitation requests');
  assert.equal(fake.calls.length, 2);

  const perIp = createApp({
    env: env({ INVITATION_RATE_LIMIT_MAX: 50, INVITATION_IP_RATE_LIMIT_MAX: 2 }),
    fetchImpl: fake.fetchImpl,
  });
  assert.equal((await issue(perIp, token(ownerUserId), '10.0.1.1', '10.1.0.1')).statusCode, 201);
  assert.equal((await issue(perIp, token(otherUserId), '10.0.1.1', '10.1.0.2')).statusCode, 201);
  const ipLimited = await issue(perIp, token(inviteeUserId), '10.0.1.1', '10.1.0.3');
  assert.equal(ipLimited.statusCode, 429);
  assert.ok(Number(ipLimited.headers['retry-after']) >= 1);
  assert.equal((await issue(perIp, token(inviteeUserId), '10.0.1.2')).statusCode, 201);
  await perIp.close();
  assert.equal(fake.calls.length, 5);

  const global = createApp({
    env: env({
      RATE_LIMIT_MAX: 1,
      INVITATION_RATE_LIMIT_MAX: 50,
      INVITATION_IP_RATE_LIMIT_MAX: 50,
    }),
    fetchImpl: fake.fetchImpl,
  });
  assert.equal((await issue(global, token(ownerUserId), '10.0.2.1')).statusCode, 201);
  const globalLimited = await issue(global, token(otherUserId), '10.0.2.1');
  await global.close();
  assert.equal(globalLimited.statusCode, 429);
  assert.equal(globalLimited.json().message, 'Too many requests');
  assert.ok(Number(globalLimited.headers['retry-after']) >= 1);
  assert.equal(fake.calls.length, 6);
});

test('Gateway Swagger documents the eleven membership endpoints with their error responses', async () => {
  const app = createApp({ env: env(), fetchImpl: async () => json(500, {}) });
  const docs = await app.inject({ method: 'GET', url: '/docs/json' });
  await app.close();
  const document = docs.json() as {
    tags: Array<{ name: string }>;
    paths: Record<string, Record<string, { tags: string[]; responses: Record<string, unknown> }>>;
  };
  assert.ok(document.tags.some((tag) => tag.name === 'Members'));
  const expected: Array<[string, string, string, string[]]> = [
    [
      '/api/vehicles/{vehicleId}/invitations',
      'post',
      '201',
      ['400', '401', '403', '404', '409', '429'],
    ],
    ['/api/vehicles/{vehicleId}/invitations', 'get', '200', ['400', '401', '403', '404']],
    ['/api/invitations', 'get', '200', ['400', '401']],
    ['/api/invitations/{invitationId}/accept', 'post', '200', ['400', '401', '404', '409']],
    [
      '/api/vehicles/{vehicleId}/invitations/{invitationId}',
      'delete',
      '200',
      ['403', '404', '409'],
    ],
    ['/api/vehicles/{vehicleId}/members', 'get', '200', ['400', '403', '404']],
    [
      '/api/vehicles/{vehicleId}/members/{membershipId}',
      'patch',
      '200',
      ['400', '403', '404', '409'],
    ],
    [
      '/api/vehicles/{vehicleId}/members/{membershipId}/suspend',
      'post',
      '200',
      ['403', '404', '409'],
    ],
    [
      '/api/vehicles/{vehicleId}/members/{membershipId}/reactivate',
      'post',
      '200',
      ['403', '404', '409'],
    ],
    ['/api/vehicles/{vehicleId}/members/{membershipId}', 'delete', '200', ['403', '404', '409']],
    ['/api/vehicles/{vehicleId}/members/leave', 'post', '200', ['400', '401', '404', '409']],
  ];
  for (const [path, method, success, errors] of expected) {
    const operation = document.paths[path]?.[method];
    assert.ok(operation, `${method} ${path}`);
    assert.ok(operation.responses[success], `${method} ${path} ${success}`);
    for (const status of errors)
      assert.ok(operation.responses[status], `${method} ${path} ${status}`);
  }
});
