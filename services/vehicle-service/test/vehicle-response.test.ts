import assert from 'node:assert/strict';
import test from 'node:test';
import { Types } from 'mongoose';
import { VehicleModel } from '../src/models/vehicle.model.js';
import { MembershipModel } from '../src/models/membership.model.js';
import { InternalRequestModel } from '../src/models/internal-request.model.js';
import { createVehicleTestApp, v2Headers } from './v2-fixture.js';
import {
  invitationPublicData,
  membershipPublicData,
  vehiclePublicData,
} from '../src/schemas/vehicle-response.schema.js';

test('vehicle DTO uses persisted values and excludes MongoDB and private fields', () => {
  const id = new Types.ObjectId();
  const ownerUserId = new Types.ObjectId();
  const persisted = {
    _id: id,
    ownerUserId,
    name: 'Persisted Mazda 3',
    make: 'Mazda',
    model: '3',
    year: 2011,
    engine: '2.0',
    __v: 7,
    passwordHash: 'private',
    privateAuditNote: 'private',
  };
  const result = vehiclePublicData(persisted);
  assert.deepEqual(result, {
    id: String(id),
    ownerUserId: String(ownerUserId),
    name: 'Persisted Mazda 3',
    make: 'Mazda',
    model: '3',
    year: 2011,
    engine: '2.0',
  });
  assert.equal(JSON.stringify(result).includes('private'), false);
  assert.equal(JSON.stringify(result).includes('__v'), false);
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
  assert.ok(document.paths['/vehicles/{vehicleId}/invitations'].post.responses['201']);
  assert.ok(document.paths['/vehicles/{vehicleId}/devices/link'].post.responses['201']);
});

test('vehicle creation responds with the persisted public resource', async (context) => {
  const id = new Types.ObjectId();
  const ownerUserId = new Types.ObjectId();
  context.mock.method(InternalRequestModel, 'create', async () => ({}) as never);
  context.mock.method(
    VehicleModel,
    'create',
    async () =>
      ({
        _id: id,
        ownerUserId,
        name: 'Persisted Mazda 3',
        make: 'Mazda',
        model: '3',
        year: 2011,
        engine: '2.0',
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
  assert.equal(result.data.name, 'Persisted Mazda 3');
  assert.equal(result.requestId, response.headers['x-request-id']);
  assert.equal(response.body.includes('Input name'), false);
  assert.equal(response.body.includes('__v'), false);
  assert.equal(response.body.includes('privateAuditNote'), false);
});

test('Vehicle rejects a signed direct call when Identity reports an unverified user', async (context) => {
  context.mock.method(InternalRequestModel, 'create', async () => ({}) as never);
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
  const body = { userId: String(new Types.ObjectId()), name: 'Mazda 3' };
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
