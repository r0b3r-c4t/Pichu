import assert from 'node:assert/strict';
import test from 'node:test';
import mongoose, { Types } from 'mongoose';
import { generateKeyPairSync } from 'node:crypto';
import { z } from 'zod';
import { deviceDatabaseConnection } from '../src/database/transaction.js';
import { parseDevicePublicKey } from '../src/security/device-public-key.js';
import { DeviceModel } from '../src/models/device.model.js';
import { DeviceCredentialModel } from '../src/models/device-credential.model.js';
import { createDeviceTestApp, v2Headers } from './v2-fixture.js';

function mockIdentity(context: test.TestContext, verified: () => boolean) {
  let calls = 0;
  context.mock.method(globalThis, 'fetch', async () => {
    calls += 1;
    return new Response(JSON.stringify({ verified: verified() }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  });
  return () => calls;
}

function connected(context: test.TestContext) {
  context.mock.method(deviceDatabaseConnection, 'isConnected', () => true);
}

test('Device metadata requires a signed request, verified email and the legacy link audit', async (context) => {
  let verified = false;
  mockIdentity(context, () => verified);
  connected(context);
  const deviceId = new Types.ObjectId();
  const userId = new Types.ObjectId();
  const vehicleId = new Types.ObjectId();
  let lookupCount = 0;
  context.mock.method(DeviceModel, 'findOne', async (query: { linkedByUserId: string }) => {
    lookupCount += 1;
    assert.equal(query.linkedByUserId, String(userId));
    return {
      _id: deviceId,
      identifier: 'esp32-mazda',
      vehicleId,
      status: 'ACTIVE',
      lastSeenAt: null,
      publicKey: 'must-not-appear',
    } as never;
  });
  const app = createDeviceTestApp();
  context.after(async () => app.close());
  const path = `/devices/${deviceId}?userId=${userId}`;
  const unsigned = await app.inject({ method: 'GET', url: path });
  assert.equal(unsigned.statusCode, 401);
  const signed = async () => {
    const headers = v2Headers(Buffer.alloc(0), 'GET', path);
    return app.inject({
      method: 'GET',
      url: path,
      headers,
    });
  };
  const denied = await signed();
  assert.equal(denied.statusCode, 403);
  assert.equal(denied.json().error, 'EMAIL_NOT_VERIFIED');
  assert.equal(denied.json().requestId, denied.headers['x-request-id']);
  assert.equal(lookupCount, 0);
  verified = true;
  const allowed = await signed();
  assert.equal(allowed.statusCode, 200);
  assert.equal(allowed.json().deviceId, String(deviceId));
  assert.equal(allowed.body.includes('publicKey'), false);
  assert.equal(lookupCount, 1);
});

test('device read classifies availability, programming and generic Mongoose errors', async (context) => {
  mockIdentity(context, () => true);
  const app = createDeviceTestApp();
  context.after(async () => app.close());
  const path = `/devices/${new Types.ObjectId()}?userId=${new Types.ObjectId()}`;
  const read = () =>
    app.inject({ method: 'GET', url: path, headers: v2Headers(Buffer.alloc(0), 'GET', path) });

  const disconnected = await read();
  assert.equal(disconnected.statusCode, 503);
  assert.equal(disconnected.json().error, 'DEVICE_DATABASE_UNAVAILABLE');

  connected(context);
  const failures: Array<[Error, number]> = [
    [new mongoose.mongo.MongoNetworkError('socket closed'), 503],
    [new mongoose.Error.MongooseServerSelectionError('no primary'), 503],
    [new mongoose.Error('generic mongoose failure'), 500],
    [new TypeError('programming error'), 500],
  ];
  for (const [failure, status] of failures) {
    const findOne = context.mock.method(DeviceModel, 'findOne', async () => {
      throw failure;
    });
    const response = await read();
    assert.equal(response.statusCode, status, failure.name);
    assert.equal(response.body.includes(failure.message), false);
    findOne.mock.restore();
  }
});

test('internal registration rejects unverified accounts and private keys before persistence', async (context) => {
  let verified = false;
  const identityCalls = mockIdentity(context, () => verified);
  connected(context);
  let created = 0;
  context.mock.method(DeviceModel, 'create', async () => {
    created += 1;
    return [] as never;
  });
  context.mock.method(DeviceCredentialModel, 'create', async () => {
    created += 1;
    return [] as never;
  });
  const app = createDeviceTestApp();
  context.after(async () => app.close());
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const path = '/internal/devices/register';
  const send = (body: Record<string, unknown>, sender = 'vehicle-service') => {
    const payload = Buffer.from(JSON.stringify(body));
    return app.inject({
      method: 'POST',
      url: path,
      payload,
      headers: v2Headers(payload, 'POST', path, sender),
    });
  };
  const body = {
    identifier: 'esp32-test',
    publicKey: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    vehicleId: String(new Types.ObjectId()),
    userId: String(new Types.ObjectId()),
  };

  const unverified = await send(body);
  assert.equal(unverified.statusCode, 403);
  assert.equal(unverified.json().error, 'EMAIL_NOT_VERIFIED');

  verified = true;
  const callsBefore = identityCalls();
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const privateKeyResponse = await send({ ...body, publicKey: privatePem });
  assert.equal(privateKeyResponse.statusCode, 400);
  assert.equal(privateKeyResponse.json().message, 'Invalid device key');
  assert.equal(privateKeyResponse.body.includes('PRIVATE'), false);
  assert.equal(identityCalls(), callsBefore);

  const extraField = await send({ ...body, requestedByUserId: String(new Types.ObjectId()) });
  assert.equal(extraField.statusCode, 400);

  const gatewaySender = await send(body, 'api-gateway');
  assert.equal(gatewaySender.statusCode, 403);
  assert.equal(created, 0);
});

test('internal registration keeps HMAC v2: unsigned, tampered and replayed requests are rejected', async (context) => {
  const identityCalls = mockIdentity(context, () => true);
  let created = 0;
  context.mock.method(DeviceModel, 'create', async () => {
    created += 1;
    return [] as never;
  });
  const app = createDeviceTestApp();
  context.after(async () => app.close());
  const path = '/internal/devices/register';
  const payload = Buffer.from(
    JSON.stringify({
      identifier: 'esp32-hmac',
      publicKey: generateKeyPairSync('ed25519')
        .publicKey.export({ type: 'spki', format: 'pem' })
        .toString(),
      vehicleId: String(new Types.ObjectId()),
      userId: String(new Types.ObjectId()),
    }),
  );
  const unsigned = await app.inject({
    method: 'POST',
    url: path,
    payload,
    headers: { 'content-type': 'application/json' },
  });
  assert.equal(unsigned.statusCode, 401);

  const headers = v2Headers(payload, 'POST', path, 'vehicle-service');
  const tampered = await app.inject({
    method: 'POST',
    url: path,
    payload: Buffer.from(payload.toString().replace('esp32-hmac', 'esp32-evil')),
    headers,
  });
  assert.equal(tampered.statusCode, 401);

  const replayHeaders = v2Headers(Buffer.from('{}'), 'POST', path, 'vehicle-service');
  const first = await app.inject({
    method: 'POST',
    url: path,
    payload: '{}',
    headers: replayHeaders,
  });
  assert.equal(first.statusCode, 400);
  const replayed = await app.inject({
    method: 'POST',
    url: path,
    payload: '{}',
    headers: replayHeaders,
  });
  assert.equal(replayed.statusCode, 401);
  assert.equal(identityCalls(), 0);
  assert.equal(created, 0);
});

const RETIRED_ROUTES = [
  '/devices/:deviceId/challenge',
  '/devices/:deviceId/link',
  '/internal/devices/:deviceId/rotate-key',
  '/internal/devices/:deviceId/revoke',
  '/internal/devices/:deviceId/challenge',
  '/internal/devices/:deviceId/link',
] as const;
const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] as const;

for (const nodeEnv of ['development', 'production'] as const) {
  test(`retired link, challenge, rotation and revocation routes return 404 (${nodeEnv})`, async (context) => {
    const previous = process.env.NODE_ENV;
    process.env.NODE_ENV = nodeEnv;
    context.after(() => {
      if (previous === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = previous;
    });
    const app = createDeviceTestApp();
    context.after(async () => app.close());
    await app.ready();
    const deviceId = String(new Types.ObjectId());
    for (const route of RETIRED_ROUTES) {
      const url = route.replace(':deviceId', deviceId);
      for (const method of HTTP_METHODS) {
        assert.equal(app.hasRoute({ method, url: route }), false, `${method} ${route}`);
        const payload = Buffer.from('{}');
        const signed = await app.inject({
          method,
          url,
          payload: method === 'GET' ? undefined : payload,
          headers: v2Headers(
            method === 'GET' ? Buffer.alloc(0) : payload,
            method,
            url,
            'vehicle-service',
          ),
        });
        assert.equal(signed.statusCode, 404, `${method} ${url}`);
      }
    }
    const routes = app.printRoutes({ commonPrefix: false });
    assert.doesNotMatch(routes, /challenge|link|rotate|revoke/i);
  });
}

test('Swagger documents exactly the routes that exist', async (context) => {
  const app = createDeviceTestApp();
  context.after(async () => app.close());
  await app.ready();
  const response = await app.inject({ method: 'GET', url: '/docs/json' });
  assert.equal(response.statusCode, 200);
  const spec = z
    .object({ paths: z.record(z.string(), z.record(z.string(), z.unknown())) })
    .parse(JSON.parse(response.body));
  const documented = Object.entries(spec.paths).flatMap(([path, operations]) =>
    Object.keys(operations).map((method) => ({ method: method.toUpperCase(), path })),
  );
  assert.deepEqual(documented.map(({ method, path }) => `${method} ${path}`).sort(), [
    'GET /devices/{deviceId}',
    'GET /health',
    'GET /health/ready',
    'POST /internal/devices/register',
  ]);
  for (const { method, path } of documented) {
    assert.ok(method === 'GET' || method === 'POST');
    const url = path.replace('{deviceId}', ':deviceId');
    assert.equal(app.hasRoute({ method, url }), true, `${method} ${path}`);
  }
  assert.doesNotMatch(response.body, /challenge|\/link|rotate|revoke|Linking/i);

  const example = z
    .object({
      post: z.object({
        requestBody: z.object({
          content: z.object({
            'application/json': z.object({ example: z.object({ publicKey: z.string() }) }),
          }),
        }),
      }),
    })
    .parse(spec.paths['/internal/devices/register']).post.requestBody.content['application/json']
    .example.publicKey;
  assert.doesNotThrow(() => parseDevicePublicKey(example), 'the documented example is accepted');
});
