import assert from 'node:assert/strict';
import test from 'node:test';
import { Types } from 'mongoose';
import { VehicleModel } from '../src/models/vehicle.model.js';
import { MembershipModel } from '../src/models/membership.model.js';
import { createVehicleTestApp, v2Headers } from './v2-fixture.js';
import {
  invitationAdminViewData,
  memberViewData,
  membershipPublicData,
  receivedInvitationViewData,
  vehicleAccessPublicData,
  vehicleArchivePublicData,
  vehicleOwnerPublicData,
  vehiclePublicData,
} from '../src/schemas/vehicle-response.schema.js';

test('vehicle DTO uses persisted values and excludes MongoDB, audit, and internal fields', () => {
  const id = new Types.ObjectId();
  const ownerUserId = new Types.ObjectId();
  const persisted = {
    _id: id,
    ownerUserId,
    name: 'Persisted Touring Hatchback',
    make: 'Honda',
    model: 'Civic',
    generation: 'FK7',
    trim: 'Sport',
    year: 2019,
    bodyStyle: 'hatchback',
    engine: '1.5 Turbo',
    transmission: 'cvt',
    fuelType: 'gasoline',
    status: 'ACTIVE',
    createdByUserId: ownerUserId,
    archivedAt: null,
    __v: 7,
    passwordHash: 'private',
    privateAuditNote: 'private',
  };
  const result = vehiclePublicData(persisted);
  assert.deepEqual(result, {
    id: String(id),
    ownerUserId: String(ownerUserId),
    name: 'Persisted Touring Hatchback',
    make: 'Honda',
    model: 'Civic',
    generation: 'FK7',
    trim: 'Sport',
    year: 2019,
    bodyStyle: 'hatchback',
    engine: '1.5 Turbo',
    transmission: 'cvt',
    fuelType: 'gasoline',
  });
  assert.equal(JSON.stringify(result).includes('private'), false);
  assert.equal(JSON.stringify(result).includes('__v'), false);
  assert.equal(JSON.stringify(result).includes('createdByUserId'), false);
  assert.equal(JSON.stringify(result).includes('status'), false);
  assert.equal(JSON.stringify(result).includes('role'), false);

  assert.deepEqual(vehicleAccessPublicData(persisted, 'MEMBER'), { ...result, role: 'MEMBER' });
  assert.deepEqual(vehicleOwnerPublicData(persisted), { ...result, role: 'OWNER' });
  assert.throws(() => vehicleAccessPublicData(persisted, 'ADMIN'));

  const legacy = vehiclePublicData({ _id: id, ownerUserId, name: 'Legacy' });
  assert.equal(legacy.generation, null);
  assert.equal(legacy.fuelType, null);

  const archivedAt = new Date('2026-11-26T12:00:00.000Z');
  assert.deepEqual(
    vehicleArchivePublicData({
      _id: id,
      status: 'ARCHIVED',
      archivedAt,
    }),
    { vehicleId: String(id), status: 'ARCHIVED', archivedAt: archivedAt.toISOString() },
  );
  assert.throws(() => vehicleArchivePublicData({ _id: id, status: 'ACTIVE', archivedAt: null }));
});

test('invitation and membership DTOs expose only persisted public state', () => {
  const id = new Types.ObjectId();
  const vehicleId = new Types.ObjectId();
  const userId = new Types.ObjectId();
  const inviterUserId = new Types.ObjectId();
  const source = {
    _id: id,
    vehicleId,
    inviterUserId,
    inviteeUserId: userId,
    issuerMembershipId: new Types.ObjectId(),
    permissions: ['vehicle:read'],
    status: 'PENDING',
    expiresAt: new Date('2026-11-10T12:00:00.000Z'),
    createdAt: new Date('2026-11-03T12:00:00.000Z'),
    acceptedAt: null,
    revokedAt: null,
    revokedByUserId: null,
    revokeReason: null,
    updatedByUserId: inviterUserId,
  };
  const invitation = invitationAdminViewData(source, 'EXPIRED');
  assert.deepEqual(Object.keys(invitation).sort(), [
    'acceptedAt',
    'createdAt',
    'expiresAt',
    'invitationId',
    'inviteeUserId',
    'inviterUserId',
    'permissions',
    'revokeReason',
    'revokedAt',
    'status',
    'vehicleId',
  ]);
  assert.equal(invitation.invitationId, String(id));
  assert.equal(invitation.status, 'EXPIRED');
  const received = receivedInvitationViewData(source, 'PENDING', 'Mazda');
  assert.deepEqual(Object.keys(received).sort(), [
    'createdAt',
    'expiresAt',
    'invitationId',
    'permissions',
    'status',
    'vehicleId',
    'vehicleName',
  ]);
  assert.equal(receivedInvitationViewData(source, 'PENDING', null).vehicleName, null);

  const membershipId = new Types.ObjectId();
  const membership = {
    _id: membershipId,
    vehicleId,
    userId,
    role: 'MEMBER',
    permissions: ['vehicle:read'],
    status: 'SUSPENDED',
    createdAt: new Date('2026-11-03T12:00:00.000Z'),
    suspendedAt: new Date('2026-11-04T12:00:00.000Z'),
    suspendedByUserId: inviterUserId,
    suspensionReason: 'internal note',
    revokedAt: null,
  };
  assert.deepEqual(membershipPublicData(membership), {
    membershipId: String(membershipId),
    vehicleId: String(vehicleId),
    userId: String(userId),
    role: 'MEMBER',
    permissions: ['vehicle:read'],
    status: 'SUSPENDED',
  });
  assert.deepEqual(memberViewData(membership), {
    membershipId: String(membershipId),
    vehicleId: String(vehicleId),
    userId: String(userId),
    role: 'MEMBER',
    permissions: ['vehicle:read'],
    status: 'SUSPENDED',
    createdAt: '2026-11-03T12:00:00.000Z',
    suspendedAt: '2026-11-04T12:00:00.000Z',
    revokedAt: null,
  });
  assert.throws(() => membershipPublicData({ ...membership, status: 'DELETED' }));
});

test('Vehicle Swagger exposes the public result schemas and examples', async (context) => {
  const app = createVehicleTestApp();
  context.after(async () => app.close());
  const response = await app.inject({ method: 'GET', url: '/docs/json' });
  assert.equal(response.statusCode, 200);
  const document = response.json() as {
    paths: Record<
      string,
      Record<
        string,
        {
          responses: Record<
            string,
            {
              content?: Record<
                string,
                { schema: { properties?: Record<string, unknown> }; example?: unknown }
              >;
            }
          >;
        }
      >
    >;
  };
  const create = document.paths['/vehicles'].post.responses['201'].content?.['application/json'];
  assert.ok(create?.schema.properties?.data);
  assert.ok(create?.schema.properties?.requestId);
  assert.ok(create?.example);
  assert.ok(document.paths['/health/ready'].get.responses['200']);
  assert.ok(document.paths['/vehicles/{vehicleId}/invitations'].post.responses['201']);
  assert.ok(document.paths['/vehicles/{vehicleId}/devices/link'].post.responses['201']);

  const list = document.paths['/vehicles'].get.responses['200'].content?.['application/json'];
  assert.ok(list?.schema.properties?.page);
  const item = document.paths['/vehicles/{vehicleId}'];
  assert.ok(item?.get.responses['404']);
  for (const method of ['patch', 'delete']) {
    const operation = item?.[method];
    assert.ok(operation?.responses['200'], `${method} 200 documented`);
    assert.ok(operation?.responses['403'], `${method} 403 documented`);
    assert.ok(operation?.responses['404'], `${method} 404 documented`);
    assert.ok(operation?.responses['409'], `${method} 409 documented`);
  }
  const updateData = item?.patch.responses['200'].content?.['application/json'];
  assert.ok(updateData?.schema.properties?.data);

  const documented: Array<[string, string, string[]]> = [
    ['/vehicles/{vehicleId}/invitations', 'post', ['201', '400', '403', '404', '409']],
    ['/vehicles/{vehicleId}/invitations', 'get', ['200', '400', '403', '404']],
    ['/invitations', 'get', ['200', '400']],
    ['/invitations/{invitationId}/accept', 'post', ['200', '400', '404', '409']],
    ['/vehicles/{vehicleId}/invitations/{invitationId}', 'delete', ['200', '403', '404', '409']],
    ['/vehicles/{vehicleId}/members', 'get', ['200', '400', '403', '404']],
    ['/vehicles/{vehicleId}/members/{membershipId}', 'patch', ['200', '400', '403', '404', '409']],
    ['/vehicles/{vehicleId}/members/{membershipId}', 'delete', ['200', '403', '404', '409']],
    ['/vehicles/{vehicleId}/members/{membershipId}/suspend', 'post', ['200', '403', '404', '409']],
    [
      '/vehicles/{vehicleId}/members/{membershipId}/reactivate',
      'post',
      ['200', '403', '404', '409'],
    ],
    ['/vehicles/{vehicleId}/members/leave', 'post', ['200', '400', '404', '409']],
  ];
  for (const [path, method, statuses] of documented) {
    const operation = document.paths[path]?.[method];
    assert.ok(operation, `${method.toUpperCase()} ${path} documented`);
    for (const status of statuses) {
      assert.ok(operation.responses[status], `${method.toUpperCase()} ${path} ${status}`);
    }
  }
  const memberData =
    document.paths['/vehicles/{vehicleId}/members'].get.responses['200'].content?.[
      'application/json'
    ];
  assert.ok(memberData?.schema.properties?.members);
});

function verifiedIdentityFetch(calls: { count: number }) {
  return async () => {
    calls.count += 1;
    return new Response(JSON.stringify({ verified: true }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };
}

test('Vehicle PATCH and DELETE reject invalid internal payloads before identity or persistence', async (context) => {
  const identityCalls = { count: 0 };
  context.mock.method(globalThis, 'fetch', verifiedIdentityFetch(identityCalls));
  let writes = 0;
  context.mock.method(VehicleModel, 'findOneAndUpdate', () => {
    writes += 1;
    throw new Error('persistence must not be reached');
  });
  const app = createVehicleTestApp();
  context.after(async () => app.close());
  const vehicleId = String(new Types.ObjectId());
  const userId = String(new Types.ObjectId());

  const cases: Array<{ method: 'PATCH' | 'DELETE'; url: string; body?: unknown }> = [
    { method: 'PATCH', url: `/vehicles/${vehicleId}`, body: { userId } },
    { method: 'PATCH', url: `/vehicles/${vehicleId}`, body: { name: 'Car' } },
    { method: 'PATCH', url: `/vehicles/${vehicleId}`, body: { userId, name: null } },
    { method: 'PATCH', url: `/vehicles/${vehicleId}`, body: { userId, name: ' ' } },
    { method: 'PATCH', url: `/vehicles/${vehicleId}`, body: { userId, make: '\tMazda' } },
    { method: 'PATCH', url: `/vehicles/${vehicleId}`, body: { userId, status: 'ARCHIVED' } },
    { method: 'PATCH', url: `/vehicles/${vehicleId}`, body: { userId, ownerUserId: userId } },
    { method: 'PATCH', url: '/vehicles/aaaaaaaaaaaa', body: { userId, name: 'Car' } },
    { method: 'DELETE', url: `/vehicles/${vehicleId}` },
    { method: 'DELETE', url: `/vehicles/${vehicleId}`, body: {} },
    { method: 'DELETE', url: `/vehicles/${vehicleId}`, body: { userId, reason: '' } },
    { method: 'DELETE', url: `/vehicles/${vehicleId}`, body: { userId, reason: 'Sold\n' } },
    { method: 'DELETE', url: `/vehicles/${vehicleId}`, body: { userId, status: 'ARCHIVED' } },
  ];
  for (const [index, attempt] of cases.entries()) {
    const payload =
      attempt.body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(attempt.body));
    const requestId = `invalid-${index}`;
    const response = await app.inject({
      method: attempt.method,
      url: attempt.url,
      headers: v2Headers(payload, attempt.method, attempt.url, { requestId }),
      ...(payload.length ? { payload } : {}),
    });
    assert.equal(response.statusCode, 400, `${attempt.method} ${JSON.stringify(attempt.body)}`);
    assert.equal(response.json().error, 'VALIDATION_ERROR');
    assert.equal(response.json().requestId, requestId);
  }

  const createAttempts = [
    { userId, name: 'Mazda\n3' },
    { userId, name: '   ' },
    { userId, name: 'Car', status: 'ARCHIVED' },
    { userId, name: 'Car', ownerUserId: userId },
  ];
  for (const body of createAttempts) {
    const payload = Buffer.from(JSON.stringify(body));
    const response = await app.inject({
      method: 'POST',
      url: '/vehicles',
      headers: v2Headers(payload, 'POST', '/vehicles'),
      payload,
    });
    assert.equal(response.statusCode, 400, JSON.stringify(body));
  }

  for (const target of [
    `/vehicles?userId=${userId}&cursor=abc%2B`,
    `/vehicles?userId=${userId}&role=ADMIN`,
    `/vehicles?userId=${userId}&limit=0`,
    `/vehicles?userId=${userId}&cursor=${'a'.repeat(257)}`,
    `/vehicles/${vehicleId}?userId=${userId}&extra=1`,
  ]) {
    const response = await app.inject({
      method: 'GET',
      url: target,
      headers: v2Headers(Buffer.alloc(0), 'GET', target),
    });
    assert.equal(response.statusCode, 400, target);
  }

  assert.equal(identityCalls.count, 0);
  assert.equal(writes, 0);
});

test('Vehicle rejects manipulated internal PATCH and DELETE requests before any handler effect', async (context) => {
  const identityCalls = { count: 0 };
  context.mock.method(globalThis, 'fetch', verifiedIdentityFetch(identityCalls));
  const app = createVehicleTestApp();
  context.after(async () => app.close());
  const vehicleId = String(new Types.ObjectId());
  const userId = String(new Types.ObjectId());
  const target = `/vehicles/${vehicleId}`;
  const body = Buffer.from(JSON.stringify({ userId, name: 'Signed name' }));

  const tamperedBody = await app.inject({
    method: 'PATCH',
    url: target,
    headers: v2Headers(body, 'PATCH', target),
    payload: Buffer.from(
      JSON.stringify({ userId: String(new Types.ObjectId()), name: 'Signed name' }),
    ),
  });
  assert.equal(tamperedBody.statusCode, 401);

  const methodSwap = await app.inject({
    method: 'DELETE',
    url: target,
    headers: v2Headers(body, 'PATCH', target),
    payload: body,
  });
  assert.equal(methodSwap.statusCode, 401);

  const otherTarget = `/vehicles/${String(new Types.ObjectId())}`;
  const targetSwap = await app.inject({
    method: 'PATCH',
    url: otherTarget,
    headers: v2Headers(body, 'PATCH', target),
    payload: body,
  });
  assert.equal(targetSwap.statusCode, 401);

  const unsigned = await app.inject({
    method: 'DELETE',
    url: target,
    headers: { 'content-type': 'application/json' },
    payload: Buffer.from(JSON.stringify({ userId })),
  });
  assert.equal(unsigned.statusCode >= 400 && unsigned.statusCode < 500, true);

  const replayHeaders = v2Headers(body, 'PATCH', target);
  context.mock.method(VehicleModel, 'findOne', () => {
    throw new Error('stop after admission');
  });
  await app.inject({ method: 'PATCH', url: target, headers: replayHeaders, payload: body });
  const replay = await app.inject({
    method: 'PATCH',
    url: target,
    headers: replayHeaders,
    payload: body,
  });
  assert.equal(replay.statusCode, 401);
  assert.equal(identityCalls.count, 1);
});

test('vehicle creation responds with the persisted public resource', async (context) => {
  const id = new Types.ObjectId();
  const ownerUserId = new Types.ObjectId();
  context.mock.method(
    VehicleModel,
    'create',
    async () =>
      ({
        _id: id,
        ownerUserId,
        name: 'Persisted Electric SUV',
        make: 'BYD',
        model: 'Yuan Plus',
        year: 2024,
        engine: '150 kW EV',
        __v: 4,
        privateAuditNote: 'private',
      }) as never,
  );
  context.mock.method(MembershipModel, 'create', async () => ({}) as never);
  context.mock.method(
    globalThis,
    'fetch',
    async () =>
      new Response(JSON.stringify({ verified: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
  );
  const app = createVehicleTestApp();
  context.after(async () => app.close());
  const body = { userId: String(ownerUserId), name: 'Input name' };
  const payload = Buffer.from(JSON.stringify(body));
  const response = await app.inject({
    method: 'POST',
    url: '/vehicles',
    headers: v2Headers(payload, 'POST', '/vehicles'),
    payload: body,
  });
  assert.equal(response.statusCode, 201);
  const result = response.json() as {
    vehicleId: string;
    data: { name: string };
    requestId: string;
  };
  assert.equal(result.vehicleId, String(id));
  assert.equal(result.data.name, 'Persisted Electric SUV');
  assert.equal(result.requestId, response.headers['x-request-id']);
  assert.equal(response.body.includes('Input name'), false);
  assert.equal(response.body.includes('__v'), false);
  assert.equal(response.body.includes('privateAuditNote'), false);
});

test('Vehicle rejects a signed direct call when Identity reports an unverified user', async (context) => {
  let created = false;
  context.mock.method(VehicleModel, 'create', async () => {
    created = true;
    return {} as never;
  });
  context.mock.method(
    globalThis,
    'fetch',
    async () =>
      new Response(JSON.stringify({ verified: false }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
  );
  const app = createVehicleTestApp();
  context.after(async () => app.close());
  const body = { userId: String(new Types.ObjectId()), name: 'Fleet Pickup' };
  const payload = Buffer.from(JSON.stringify(body));
  const response = await app.inject({
    method: 'POST',
    url: '/vehicles',
    payload: body,
    headers: v2Headers(payload, 'POST', '/vehicles'),
  });
  assert.equal(response.statusCode, 403);
  assert.equal(response.json().error, 'EMAIL_NOT_VERIFIED');
  assert.equal(response.json().requestId, response.headers['x-request-id']);
  assert.equal(created, false);
});

test('outbound GET to Identity retries once on 503 with fresh nonce while preserving requestId and deadline', async (context) => {
  const id = new Types.ObjectId();
  const ownerUserId = new Types.ObjectId();
  context.mock.method(
    VehicleModel,
    'create',
    async () =>
      ({
        _id: id,
        ownerUserId,
        name: 'Resilient Sedan',
        make: null,
        model: null,
        year: null,
        engine: null,
      }) as never,
  );
  context.mock.method(MembershipModel, 'create', async () => ({}) as never);

  const outboundCalls: Array<{ nonce: string; requestId: string; deadline: string }> = [];
  context.mock.method(
    globalThis,
    'fetch',
    async (_url: string | URL | Request, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      outboundCalls.push({
        nonce: headers.get('x-nonce') ?? '',
        requestId: headers.get('x-request-id') ?? '',
        deadline: headers.get('x-internal-deadline') ?? '',
      });
      if (outboundCalls.length === 1) {
        return new Response(JSON.stringify({ message: 'temporary' }), {
          status: 503,
          headers: { 'content-type': 'application/json' },
        });
      }
      return new Response(JSON.stringify({ verified: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    },
  );

  const app = createVehicleTestApp();
  context.after(async () => app.close());
  const body = { userId: String(ownerUserId), name: 'Resilient Sedan' };
  const payload = Buffer.from(JSON.stringify(body));
  const response = await app.inject({
    method: 'POST',
    url: '/vehicles',
    payload: body,
    headers: v2Headers(payload, 'POST', '/vehicles', { requestId: 'corr-id-99' }),
  });

  assert.equal(response.statusCode, 201);
  assert.equal(outboundCalls.length, 2);
  assert.notEqual(outboundCalls[0]?.nonce, outboundCalls[1]?.nonce);
  assert.equal(outboundCalls[0]?.requestId, 'corr-id-99');
  assert.equal(outboundCalls[1]?.requestId, 'corr-id-99');
  assert.equal(outboundCalls[0]?.deadline, outboundCalls[1]?.deadline);
});

test('invitation endpoint rejects self-invitations and unknown/wildcard permissions with 400', async (context) => {
  context.mock.method(globalThis, 'fetch', async (url: string | URL | Request) => {
    if (String(url).endsWith('/verified')) {
      return new Response(JSON.stringify({ verified: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    return new Response(JSON.stringify({ exists: true }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  });

  const app = createVehicleTestApp();
  context.after(async () => app.close());
  const vehicleId = String(new Types.ObjectId());
  const actorId = String(new Types.ObjectId());
  const inviteeId = String(new Types.ObjectId());

  const selfBody = {
    inviterUserId: actorId,
    inviteeUserId: actorId,
    permissions: ['vehicle:read'],
  };
  const selfPayload = Buffer.from(JSON.stringify(selfBody));
  const selfRes = await app.inject({
    method: 'POST',
    url: `/vehicles/${vehicleId}/invitations`,
    payload: selfBody,
    headers: v2Headers(selfPayload, 'POST', `/vehicles/${vehicleId}/invitations`),
  });
  assert.equal(selfRes.statusCode, 400);

  for (const invalidPerm of ['*', 'vehicle:*', 'vehicle:owner', 'unknown:perm']) {
    const badBody = {
      inviterUserId: actorId,
      inviteeUserId: inviteeId,
      permissions: [invalidPerm],
    };
    const badPayload = Buffer.from(JSON.stringify(badBody));
    const badRes = await app.inject({
      method: 'POST',
      url: `/vehicles/${vehicleId}/invitations`,
      payload: badBody,
      headers: v2Headers(badPayload, 'POST', `/vehicles/${vehicleId}/invitations`),
    });
    assert.equal(badRes.statusCode, 400, `Expected 400 for invalid permission ${invalidPerm}`);
  }
});

test('membership and invitation administration routes reject forged or reserved fields before Identity', async (context) => {
  let outboundCalls = 0;
  context.mock.method(globalThis, 'fetch', async () => {
    outboundCalls += 1;
    return new Response(JSON.stringify({ verified: true, exists: true }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  });
  const app = createVehicleTestApp();
  context.after(async () => app.close());
  const vehicleId = String(new Types.ObjectId());
  const membershipId = String(new Types.ObjectId());
  const invitationId = String(new Types.ObjectId());
  const userId = String(new Types.ObjectId());
  const attempts: Array<{
    method: 'POST' | 'PATCH' | 'DELETE' | 'GET';
    url: string;
    body?: unknown;
  }> = [
    {
      method: 'PATCH',
      url: `/vehicles/${vehicleId}/members/${membershipId}`,
      body: { userId, permissions: ['vehicle:read'], role: 'OWNER' },
    },
    {
      method: 'PATCH',
      url: `/vehicles/${vehicleId}/members/${membershipId}`,
      body: { userId, permissions: ['vehicle:read'], status: 'ACTIVE' },
    },
    {
      method: 'POST',
      url: `/vehicles/${vehicleId}/members/${membershipId}/suspend`,
      body: { userId, suspendedByUserId: userId },
    },
    {
      method: 'POST',
      url: `/vehicles/${vehicleId}/members/${membershipId}/reactivate`,
      body: { userId, reason: 'not accepted' },
    },
    {
      method: 'DELETE',
      url: `/vehicles/${vehicleId}/members/${membershipId}`,
      body: { userId, revokedByUserId: userId },
    },
    {
      method: 'POST',
      url: `/vehicles/${vehicleId}/members/leave`,
      body: { userId, targetUserId: String(new Types.ObjectId()) },
    },
    { method: 'POST', url: `/vehicles/${vehicleId}/members/leave`, body: { userId } },
    {
      method: 'DELETE',
      url: `/vehicles/${vehicleId}/invitations/${invitationId}`,
      body: { userId, status: 'REVOKED' },
    },
    { method: 'POST', url: `/vehicles/${vehicleId}/members/not-an-id/suspend`, body: { userId } },
    { method: 'GET', url: `/vehicles/${vehicleId}/members?userId=${userId}&limit=101` },
    { method: 'GET', url: `/vehicles/${vehicleId}/invitations?userId=${userId}&status=OPEN` },
    { method: 'GET', url: `/invitations?userId=${userId}&cursor=${'a'.repeat(257)}` },
    { method: 'GET', url: '/invitations' },
  ];
  for (const attempt of attempts) {
    const payload =
      attempt.body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(attempt.body));
    const response = await app.inject({
      method: attempt.method,
      url: attempt.url,
      ...(attempt.body === undefined ? {} : { payload }),
      headers: v2Headers(payload, attempt.method, attempt.url),
    });
    assert.equal(response.statusCode, 400, `${attempt.method} ${attempt.url}`);
    assert.equal(response.json().error, 'VALIDATION_ERROR');
  }
  assert.equal(outboundCalls, 0);
});
