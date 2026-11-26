import assert from 'node:assert/strict';
import test from 'node:test';
import { Types } from 'mongoose';
import { VehicleModel } from '../src/models/vehicle.model.js';
import { MembershipModel } from '../src/models/membership.model.js';
import { createVehicleTestApp, v2Headers } from './v2-fixture.js';
import {
  invitationPublicData,
  membershipPublicData,
  vehiclePublicData,
} from '../src/schemas/vehicle-response.schema.js';

test('vehicle DTO uses persisted values and excludes MongoDB, audit, and extended internal fields', () => {
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
    year: 2019,
    engine: '1.5 Turbo',
  });
  assert.equal(JSON.stringify(result).includes('private'), false);
  assert.equal(JSON.stringify(result).includes('__v'), false);
  assert.equal(JSON.stringify(result).includes('createdByUserId'), false);
  assert.equal(JSON.stringify(result).includes('status'), false);
});

test('invitation and membership DTOs expose only persisted public state', () => {
  const id = new Types.ObjectId();
  const vehicleId = new Types.ObjectId();
  const userId = new Types.ObjectId();
  const invitation = invitationPublicData({
    _id: id,
    vehicleId,
    inviteeUserId: userId,
    permissions: ['vehicle:read'],
    status: 'PENDING',
    expiresAt: new Date('2026-11-10T12:00:00.000Z'),
  });
  assert.equal(invitation.id, String(id));
  assert.equal(invitation.vehicleId, String(vehicleId));
  assert.equal(invitation.status, 'PENDING');
  assert.deepEqual(
    membershipPublicData({
      vehicleId,
      userId,
      role: 'MEMBER',
      permissions: ['vehicle:read'],
    }),
    {
      vehicleId: String(vehicleId),
      userId: String(userId),
      role: 'MEMBER',
      permissions: ['vehicle:read'],
    },
  );
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
