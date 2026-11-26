import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { generateKeyPairSync } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import mongoose from '../services/vehicle-service/node_modules/mongoose/index.js';
import { generateNonce, signRequest, type KeyEntry } from '../packages/internal-auth/src/index.js';
import {
  MongoNonceStore,
  createNonceIndexes,
  NONCE_COLLECTION,
} from '../packages/internal-auth-adapters/src/mongodb.js';
import { createApp as createVehicleApp } from '../services/vehicle-service/src/app.js';
import { createApp as createDeviceApp } from '../services/device-service/src/app.js';
import { VehicleModel } from '../services/vehicle-service/src/models/vehicle.model.js';
import { MembershipModel } from '../services/vehicle-service/src/models/membership.model.js';
import { DeviceModel } from '../services/device-service/src/models/device.model.js';
import {
  loadEnv as loadVehicleEnv,
  parseInternalKeyring as parseVehicleKeyring,
} from '../services/vehicle-service/src/config/env.js';

const { MongoClient } = mongoose.mongo;

const run = promisify(execFile);
const docker = (...args: string[]) =>
  run('docker', args, { timeout: 30_000, maxBuffer: 1_048_576 });
const image = 'mongo:8.0.17';
const id = randomUUID();
const name = `pichu-tkt0095b-${id}`;
const jwt = 'Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.c2ln';
const nowKey = (
  sender: KeyEntry['sender'],
  audience: KeyEntry['audience'],
  fill: number,
): KeyEntry => ({
  environment: 'test',
  sender,
  audience,
  keyId: `${sender}-${audience}`,
  secret: Buffer.alloc(32, fill),
  state: 'active',
  notBefore: 1,
  notAfter: 8_000_000_000_000_000,
});
const vehicleGateway = nowKey('api-gateway', 'vehicle-service', 11);
const deviceGateway = nowKey('api-gateway', 'device-service', 12);
const vehicleIdentity = nowKey('vehicle-service', 'identity-service', 13);
const deviceIdentity = nowKey('device-service', 'identity-service', 14);
const vehicleDevice = nowKey('vehicle-service', 'device-service', 15);
const vehicleKeys = [vehicleGateway, vehicleIdentity, vehicleDevice];
const deviceKeys = [deviceGateway, deviceIdentity, vehicleDevice];

function headers(
  key: KeyEntry,
  method: string,
  target: string,
  body: Buffer,
  nonce = generateNonce(),
) {
  const timestamp = Date.now();
  const unsigned = {
    'x-internal-auth-version': '2',
    'x-service-name': key.sender,
    'x-service-audience': key.audience,
    'x-service-key-id': key.keyId,
    'x-contract-version': 'v1',
    'x-timestamp': String(timestamp),
    'x-nonce': nonce,
    'x-request-id': `integration-${generateNonce()}`,
    'x-internal-deadline': String(timestamp + 5_000),
    authorization: jwt,
    ...(body.length ? { 'content-type': 'application/json' } : {}),
  } as const;
  return {
    ...unsigned,
    'x-signature': signRequest({ ...key, keyring: [key], now: timestamp }, unsigned, {
      method,
      target,
      body,
    }),
  };
}

async function listen(app: Awaited<ReturnType<typeof createVehicleApp>>) {
  await app.listen({ host: '127.0.0.1', port: 0 });
  const address = app.server.address();
  assert.ok(address && typeof address === 'object');
  return `http://127.0.0.1:${address.port}`;
}

async function main() {
  let created = false;
  let client: MongoClient | undefined;
  const originalFetch = globalThis.fetch;
  const httpFetch = originalFetch;
  const originals = {
    vehicleCreate: VehicleModel.create,
    membershipCreate: MembershipModel.create,
    deviceFind: DeviceModel.findOne,
    deviceCreate: DeviceModel.create,
  };
  try {
    await docker('info', '--format', '{{.ServerVersion}}');
    await docker('image', 'inspect', image, '--format', '{{.Id}}');
    await docker(
      'run',
      '--detach',
      '--rm',
      '--name',
      name,
      '--label',
      `pichu.tkt0095b=${id}`,
      '--publish',
      '127.0.0.1::27017',
      '--tmpfs',
      '/data/db',
      '--tmpfs',
      '/data/configdb',
      image,
      '--replSet',
      'pichu_test',
      '--bind_ip_all',
    );
    created = true;
    for (let attempt = 0; attempt < 30; attempt++) {
      try {
        await docker(
          'exec',
          name,
          'mongosh',
          '--quiet',
          '--eval',
          'rs.initiate({_id:"pichu_test",members:[{_id:0,host:"localhost:27017"}]})',
        );
        break;
      } catch {
        if (attempt === 29) throw new Error('replica set did not initialize');
        await delay(250);
      }
    }
    const binding = (await docker('port', name, '27017/tcp')).stdout.trim();
    assert.match(binding, /^127\.0\.0\.1:[0-9]+$/);
    const uri = `mongodb://${binding}/?replicaSet=pichu_test&directConnection=true`;
    client = new MongoClient(uri, { serverSelectionTimeoutMS: 2_000, retryWrites: false });
    await client.connect();
    const vehicleDb = client.db(`vehicle_${id.replaceAll('-', '')}`);
    const deviceDb = client.db(`device_${id.replaceAll('-', '')}`);
    await Promise.all([createNonceIndexes(vehicleDb), createNonceIndexes(deviceDb)]);
    for (const db of [vehicleDb, deviceDb]) {
      const indexes = await db.collection(NONCE_COLLECTION).listIndexes().toArray();
      assert.equal(
        indexes.some((x) => x.name === 'internal_nonce_unique' && x.unique),
        true,
      );
      assert.equal(
        indexes.some((x) => x.name === 'internal_nonce_expiry' && x.expireAfterSeconds === 0),
        true,
      );
    }
    process.env.INTERNAL_AUTH_ENVIRONMENT = 'test';
    process.env.DATABASE_URL = uri;
    process.env.TEST_DATABASE_URL = uri;
    process.env.INTERNAL_AUTH_KEYRING_JSON = JSON.stringify(
      [...vehicleKeys, deviceGateway, deviceIdentity].map((k) => {
        const { secret: _secret, ...rest } = k;
        return { ...rest, secretBase64Url: k.secret.toString('base64url') };
      }),
    );
    parseVehicleKeyring(loadVehicleEnv());
    globalThis.fetch = async () => {
      return new Response(JSON.stringify({ verified: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };
    const vehicleId = '507f1f77bcf86cd799439011';
    const userId = '507f1f77bcf86cd799439012';
    let vehicleEffects = 0;
    VehicleModel.create = (async () => {
      vehicleEffects++;
      return {
        _id: vehicleId,
        ownerUserId: userId,
        name: 'Mongo test',
        make: null,
        model: null,
        year: null,
        engine: null,
      };
    }) as never;
    MembershipModel.create = (async () => ({})) as never;
    const vehicleApp = createVehicleApp({
      internalAuth: {
        environment: 'test',
        keyring: vehicleKeys,
        nonces: new MongoNonceStore(vehicleDb),
      },
    });
    const vehicleUrl = await listen(vehicleApp);
    const vehicleBody = Buffer.from(JSON.stringify({ userId, name: 'Input' }));
    const vehicleHeaders = headers(vehicleGateway, 'POST', '/vehicles', vehicleBody);
    const validVehicle = await httpFetch(`${vehicleUrl}/vehicles`, {
      method: 'POST',
      headers: vehicleHeaders,
      body: vehicleBody,
    });
    if (validVehicle.status !== 201)
      console.error('vehicle response', validVehicle.status, await validVehicle.text());
    assert.equal(validVehicle.status, 201);
    assert.equal(vehicleEffects, 1);
    const replayVehicle = await httpFetch(`${vehicleUrl}/vehicles`, {
      method: 'POST',
      headers: vehicleHeaders,
      body: vehicleBody,
    });
    assert.equal(replayVehicle.status, 401);
    assert.equal(vehicleEffects, 1);
    const invalidVehicleHeaders = {
      ...headers(vehicleGateway, 'POST', '/vehicles', vehicleBody),
      'x-signature': 'invalid',
    };
    assert.equal(
      (
        await httpFetch(`${vehicleUrl}/vehicles`, {
          method: 'POST',
          headers: invalidVehicleHeaders,
          body: vehicleBody,
        })
      ).status,
      400,
    );
    assert.equal(vehicleEffects, 1);
    const deniedVehicle = headers(deviceGateway, 'POST', '/vehicles', vehicleBody);
    assert.equal(
      (
        await httpFetch(`${vehicleUrl}/vehicles`, {
          method: 'POST',
          headers: deniedVehicle,
          body: vehicleBody,
        })
      ).status,
      401,
    );
    assert.equal(vehicleEffects, 1);
    await vehicleApp.close();
    await vehicleDb.dropCollection(NONCE_COLLECTION);
    const unavailableVehicleApp = createVehicleApp({
      internalAuth: {
        environment: 'test',
        keyring: vehicleKeys,
        nonces: new MongoNonceStore(vehicleDb),
      },
    });
    await assert.rejects(listen(unavailableVehicleApp));
    assert.equal(vehicleEffects, 1);
    await unavailableVehicleApp.close().catch(() => undefined);

    let deviceEffects = 0;
    let deviceAuthorized = true;
    const deviceId = '507f1f77bcf86cd799439013';
    DeviceModel.findOne = (async () => {
      deviceEffects++;
      return deviceAuthorized
        ? {
            _id: deviceId,
            identifier: 'mongo-device',
            vehicleId,
            status: 'ACTIVE',
            lastSeenAt: null,
          }
        : null;
    }) as never;
    DeviceModel.create = (async () => {
      deviceEffects++;
      return { _id: deviceId, status: 'PENDING' };
    }) as never;
    const deviceApp = createDeviceApp({
      internalAuth: {
        environment: 'test',
        keyring: deviceKeys,
        nonces: new MongoNonceStore(deviceDb),
      },
    });
    const deviceUrl = await listen(deviceApp);
    const deviceTarget = `/devices/${deviceId}?userId=${userId}`;
    const deviceHeaders = headers(deviceGateway, 'GET', deviceTarget, Buffer.alloc(0));
    assert.equal(
      (await httpFetch(`${deviceUrl}${deviceTarget}`, { headers: deviceHeaders })).status,
      200,
    );
    assert.equal(deviceEffects, 1);
    assert.equal(
      (await httpFetch(`${deviceUrl}${deviceTarget}`, { headers: deviceHeaders })).status,
      401,
    );
    assert.equal(deviceEffects, 1);
    assert.equal(
      (
        await httpFetch(`${deviceUrl}${deviceTarget}`, {
          headers: {
            ...headers(deviceGateway, 'GET', deviceTarget, Buffer.alloc(0)),
            'x-signature': 'invalid',
          },
        })
      ).status,
      400,
    );
    assert.equal(deviceEffects, 1);
    deviceAuthorized = false;
    assert.equal(
      (
        await httpFetch(`${deviceUrl}${deviceTarget}`, {
          headers: headers(deviceGateway, 'GET', deviceTarget, Buffer.alloc(0)),
        })
      ).status,
      404,
    );
    assert.equal(deviceEffects, 2);
    const { publicKey } = generateKeyPairSync('ed25519');
    const registerBody = Buffer.from(
      JSON.stringify({
        identifier: 'mongo-register',
        publicKey: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        vehicleId,
        userId,
      }),
    );
    const registerTarget = '/internal/devices/register';
    assert.equal(
      (
        await httpFetch(`${deviceUrl}${registerTarget}`, {
          method: 'POST',
          headers: headers(vehicleDevice, 'POST', registerTarget, registerBody),
          body: registerBody,
        })
      ).status,
      201,
    );
    assert.equal(deviceEffects, 3);
    await deviceApp.close();
    await deviceDb.dropCollection(NONCE_COLLECTION);
    const unavailableDeviceApp = createDeviceApp({
      internalAuth: {
        environment: 'test',
        keyring: deviceKeys,
        nonces: new MongoNonceStore(deviceDb),
      },
    });
    await assert.rejects(listen(unavailableDeviceApp));
    assert.equal(deviceEffects, 3);
    await unavailableDeviceApp.close().catch(() => undefined);
    console.log('TKT-009.5B HTTP+Mongo integration: PASS (Vehicle and Device, isolated databases)');
  } finally {
    globalThis.fetch = originalFetch;
    VehicleModel.create = originals.vehicleCreate;
    MembershipModel.create = originals.membershipCreate;
    DeviceModel.findOne = originals.deviceFind;
    DeviceModel.create = originals.deviceCreate;
    await client?.close();
    if (created) await docker('rm', '--force', '--volumes', name);
  }
}
void main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
