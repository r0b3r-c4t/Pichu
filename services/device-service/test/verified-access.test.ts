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

function connected(context: test.TestContext) {
  context.mock.method(deviceDatabaseConnection, 'isConnected', () => true);
}

test('Device exposes no direct end-user routes (/devices/*) in development or production', async (context) => {
  const retiredRoutes = [
    '/devices/:deviceId',
    '/devices/:deviceId/challenge',
    '/devices/:deviceId/link',
    '/devices/:deviceId/revoke',
    '/internal/devices/:deviceId/rotate-key',
  ] as const;
  const methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] as const;

  for (const nodeEnv of ['development', 'production'] as const) {
    const previous = process.env.NODE_ENV;
    process.env.NODE_ENV = nodeEnv;
    context.after(() => {
      if (previous === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = previous;
    });

    const app = createDeviceTestApp();
    await app.ready();
    try {
      const deviceId = String(new Types.ObjectId());
      for (const route of retiredRoutes) {
        const url = route.replace(':deviceId', deviceId);
        for (const method of methods) {
          assert.equal(app.hasRoute({ method, url: route }), false, `${method} ${route}`);
          const payload = Buffer.from('{}');
          const response = await app.inject({
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
          assert.equal(response.statusCode, 404, `${method} ${url}`);
        }
      }
      // Gateway directly calling legacy GET /devices/:deviceId?userId=... also receives 404
      const legacyUrl = `/devices/${deviceId}?userId=${new Types.ObjectId()}`;
      const legacyGatewayRead = await app.inject({
        method: 'GET',
        url: legacyUrl,
        headers: v2Headers(Buffer.alloc(0), 'GET', legacyUrl, 'api-gateway'),
      });
      assert.equal(legacyGatewayRead.statusCode, 404);
    } finally {
      await app.close();
    }
  }
});

test('every internal Device data endpoint admits only vehicle-service and never duplicates Identity calls', async (context) => {
  let identityCalls = 0;
  context.mock.method(globalThis, 'fetch', async () => {
    identityCalls += 1;
    return new Response(JSON.stringify({ verified: true }), { status: 200 });
  });

  const app = createDeviceTestApp();
  context.after(async () => app.close());

  const deviceId = String(new Types.ObjectId());
  const vehicleId = String(new Types.ObjectId());

  const operations: Array<{ method: 'GET' | 'POST' | 'PATCH'; url: string; body?: unknown }> = [
    { method: 'POST', url: '/internal/devices/register', body: {} },
    { method: 'GET', url: `/internal/devices/${deviceId}` },
    { method: 'GET', url: `/internal/vehicles/${vehicleId}/devices` },
    { method: 'PATCH', url: `/internal/devices/${deviceId}`, body: {} },
    { method: 'POST', url: `/internal/devices/${deviceId}/challenge`, body: {} },
    { method: 'POST', url: `/internal/devices/${deviceId}/link`, body: {} },
    { method: 'POST', url: `/internal/devices/${deviceId}/revoke`, body: {} },
  ];

  for (const op of operations) {
    const payload = op.body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(op.body));

    // Unsigned -> 401
    const unsigned = await app.inject({
      method: op.method,
      url: op.url,
      ...(op.body === undefined
        ? {}
        : { payload, headers: { 'content-type': 'application/json' } }),
    });
    assert.equal(unsigned.statusCode, 401, `unsigned ${op.method} ${op.url}`);

    // Authenticated api-gateway caller -> 403 (sender allowlist restricts to vehicle-service)
    const fromGateway = await app.inject({
      method: op.method,
      url: op.url,
      ...(op.body === undefined ? {} : { payload }),
      headers: v2Headers(payload, op.method, op.url, 'api-gateway'),
    });
    assert.equal(fromGateway.statusCode, 403, `api-gateway caller ${op.method} ${op.url}`);
  }
  assert.equal(identityCalls, 0);
});

test('internal device read classifies availability, programming and generic Mongoose errors', async (context) => {
  const app = createDeviceTestApp();
  context.after(async () => app.close());
  const path = `/internal/devices/${new Types.ObjectId()}`;
  const read = () =>
    app.inject({
      method: 'GET',
      url: path,
      headers: v2Headers(Buffer.alloc(0), 'GET', path, 'vehicle-service'),
    });

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
    const startSession = context.mock.method(mongoose.connection, 'startSession', async () => {
      throw failure;
    });
    const response = await read();
    assert.equal(response.statusCode, status, failure.name);
    assert.equal(response.body.includes(failure.message), false);
    startSession.mock.restore();
  }
});

test('internal registration rejects private keys and unknown fields before persistence and enforces HMAC v2 replay protection', async (context) => {
  let identityCalls = 0;
  context.mock.method(globalThis, 'fetch', async () => {
    identityCalls += 1;
    return new Response(JSON.stringify({ verified: true }), { status: 200 });
  });
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
    membershipId: String(new Types.ObjectId()),
  };

  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const privateKeyResponse = await send({ ...body, publicKey: privatePem });
  assert.equal(privateKeyResponse.statusCode, 400);
  assert.equal(privateKeyResponse.json().message, 'Invalid device key');
  assert.equal(privateKeyResponse.body.includes('PRIVATE'), false);

  const controlCharMeta = await send({ ...body, metadata: { name: 'bad\u0007name' } });
  assert.equal(controlCharMeta.statusCode, 400);

  const extraField = await send({ ...body, requestedByUserId: String(new Types.ObjectId()) });
  assert.equal(extraField.statusCode, 400);

  const missingMembership = await send({
    identifier: body.identifier,
    publicKey: body.publicKey,
    vehicleId: body.vehicleId,
    userId: body.userId,
  });
  assert.equal(missingMembership.statusCode, 400);

  // Tampered payload & replay rejection
  const signedPayload = Buffer.from(JSON.stringify(body));
  const headers = v2Headers(signedPayload, 'POST', path, 'vehicle-service');
  const tampered = await app.inject({
    method: 'POST',
    url: path,
    payload: Buffer.from(signedPayload.toString().replace('esp32-test', 'esp32-evil')),
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

  assert.equal(identityCalls, 0);
  assert.equal(created, 0);
});

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
    'GET /health',
    'GET /health/ready',
    'GET /internal/devices/{deviceId}',
    'GET /internal/vehicles/{vehicleId}/devices',
    'PATCH /internal/devices/{deviceId}',
    'POST /internal/devices/register',
    'POST /internal/devices/{deviceId}/challenge',
    'POST /internal/devices/{deviceId}/link',
    'POST /internal/devices/{deviceId}/revoke',
  ]);
  for (const { method, path } of documented) {
    assert.ok(method === 'GET' || method === 'POST' || method === 'PATCH');
    const url = path.replace('{deviceId}', ':deviceId').replace('{vehicleId}', ':vehicleId');
    assert.equal(app.hasRoute({ method, url }), true, `${method} ${path}`);
  }
  assert.equal(Object.hasOwn(spec.paths, '/devices/{deviceId}'), false);

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
