import assert from 'node:assert/strict';
import test from 'node:test';
import { Types } from 'mongoose';
import { generateKeyPairSync } from 'node:crypto';
import { DeviceModel } from '../src/models/device.model.js';
import { InternalRequestModel } from '../src/models/internal-request.model.js';
import { createDeviceTestApp, v2Headers } from './v2-fixture.js';

test('Device metadata requires a signed request, verified email and ownership', async (context) => {
  context.mock.method(InternalRequestModel, 'create', async () => ({}) as never);
  let verified = false;
  context.mock.method(
    globalThis,
    'fetch',
    async () =>
      new Response(JSON.stringify({ verified }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
  );
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

test('direct internal provisioning does not create a device for an unverified account', async (context) => {
  context.mock.method(InternalRequestModel, 'create', async () => ({}) as never);
  context.mock.method(
    globalThis,
    'fetch',
    async () =>
      new Response(JSON.stringify({ verified: false }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
  );
  let created = false;
  context.mock.method(DeviceModel, 'create', async () => {
    created = true;
    return {} as never;
  });
  const app = createDeviceTestApp();
  context.after(async () => app.close());
  const { publicKey } = generateKeyPairSync('ed25519');
  const body = {
    identifier: 'esp32-test',
    publicKey: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    vehicleId: String(new Types.ObjectId()),
    userId: String(new Types.ObjectId()),
  };
  const path = '/internal/devices/register';
  const payload = Buffer.from(JSON.stringify(body));
  const response = await app.inject({
    method: 'POST',
    url: path,
    payload: body,
    headers: v2Headers(payload, 'POST', path, 'vehicle-service'),
  });
  assert.equal(response.statusCode, 403);
  assert.equal(response.json().error, 'EMAIL_NOT_VERIFIED');
  assert.equal(created, false);
});
