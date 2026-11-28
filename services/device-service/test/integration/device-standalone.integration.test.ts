import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:net';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import mongoose, { Types } from 'mongoose';
import {
  MongoNonceStore,
  NONCE_COLLECTION,
  createNonceIndexes,
} from '@pichu/internal-auth-adapters/mongodb';
import { createApp } from '../../src/app.js';
import {
  assertCriticalDeviceIndexes,
  assertDeviceDatabaseReady,
  DeviceSchemaNotReadyError,
  ensureDevelopmentDatabaseSchema,
  findCriticalDeviceIndexIssues,
} from '../../src/database/bootstrap.js';
import { closeDatabase, connectDatabase } from '../../src/database/connection.js';
import { recordDeviceMigrationIfNothingToMigrate } from '../../src/database/migration.js';
import { DeviceCredentialModel } from '../../src/models/device-credential.model.js';
import { DeviceLinkChallengeModel } from '../../src/models/device-link-challenge.model.js';
import { DeviceRevocationModel } from '../../src/models/device-revocation.model.js';
import { DeviceModel } from '../../src/models/device.model.js';
import { findEffectiveDeviceBinding } from '../../src/services/device-binding.service.js';
import { createDeviceChallenge } from '../../src/services/device-link.service.js';
import { registerDevice } from '../../src/services/device-registration.service.js';
import {
  revokeDevice,
  systemRevocationActor,
} from '../../src/services/device-revocation.service.js';
import { setupDeviceTestAuth, v2Headers } from '../v2-fixture.js';

const execFileAsync = promisify(execFile);
const docker = (...args: string[]) =>
  execFileAsync('docker', args, { timeout: 60_000, maxBuffer: 4_194_304 });
const serviceRoot = fileURLToPath(new URL('../../', import.meta.url));

let container: string | undefined;
let deviceUri = '';
let devicePassword = '';

function db() {
  const current = mongoose.connection.db;
  assert.ok(current, 'Device database must be connected');
  return current;
}

async function retry<T>(label: string, attempt: () => Promise<T>): Promise<T> {
  for (let index = 0; ; index += 1) {
    try {
      return await attempt();
    } catch (error) {
      if (index >= 119) throw new Error(`${label} did not become ready`, { cause: error });
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  }
}

before(async () => {
  await docker('info', '--format', '{{.ServerVersion}}');
  const id = randomUUID().replaceAll('-', '');
  container = `pichu-tkt014-standalone-${id}`;
  const rootUser = `root_${id.slice(0, 8)}`;
  const rootPassword = randomBytes(24).toString('base64url');
  const deviceUser = `device_${id.slice(0, 8)}`;
  devicePassword = randomBytes(24).toString('base64url');
  // Standalone (no --replSet) with authentication enabled by the official entrypoint.
  await docker(
    'run',
    '--detach',
    '--name',
    container,
    '--label',
    `pichu.tkt014=${id}`,
    '--publish',
    '127.0.0.1::27017',
    '--tmpfs',
    '/data/db',
    '--tmpfs',
    '/data/configdb',
    '--env',
    `MONGO_INITDB_ROOT_USERNAME=${rootUser}`,
    '--env',
    `MONGO_INITDB_ROOT_PASSWORD=${rootPassword}`,
    'mongo:8.0.17',
  );
  const name = container;
  await retry('MongoDB standalone initialization', async () => {
    const { stdout, stderr } = await docker('logs', name);
    assert.match(`${stdout}${stderr}`, /MongoDB init process complete; ready for start up/);
  });
  const admin = ['exec', name, 'mongosh', '--quiet', '--username', rootUser, '--password'];
  await retry('MongoDB standalone authentication', () =>
    docker(...admin, rootPassword, '--authenticationDatabase', 'admin', '--eval', 'db.hello()'),
  );
  await docker(
    ...admin,
    rootPassword,
    '--authenticationDatabase',
    'admin',
    '--eval',
    `db.getSiblingDB("device_db").createUser({user:"${deviceUser}",pwd:"${devicePassword}",roles:[{role:"readWrite",db:"device_db"}]})`,
  );
  const binding = (await docker('port', name, '27017/tcp')).stdout.trim();
  assert.match(binding, /^127\.0\.0\.1:[0-9]+$/);
  deviceUri = `mongodb://${deviceUser}:${encodeURIComponent(devicePassword)}@${binding}/device_db?authSource=device_db&directConnection=true`;
  await retry('MongoDB standalone device user', async () => {
    await connectDatabase(deviceUri);
    await db().command({ ping: 1 });
  });
  const hello = await db().admin().command({ hello: 1 });
  assert.equal(hello.setName, undefined, 'the deployment must be a standalone server');
});

after(async () => {
  await closeDatabase().catch(() => undefined);
  if (container) await docker('rm', '--force', container).catch(() => undefined);
});

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      server.close(() =>
        typeof address === 'object' && address ? resolve(address.port) : reject(new Error('port')),
      );
    });
  });
}

test('the real server fails closed on a standalone MongoDB before exposing HTTP', async () => {
  setupDeviceTestAuth();
  const keyring = process.env.INTERNAL_AUTH_KEYRING_JSON;
  assert.ok(keyring);
  const port = await freePort();
  const child = spawn(process.execPath, ['--import', 'tsx', 'src/server.ts'], {
    cwd: serviceRoot,
    env: {
      ...process.env,
      NODE_ENV: 'test',
      HOST: '127.0.0.1',
      PORT: String(port),
      DATABASE_URL: deviceUri,
      INTERNAL_AUTH_ENVIRONMENT: 'test',
      INTERNAL_AUTH_KEYRING_JSON: keyring,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '';
  child.stdout.on('data', (chunk: Buffer) => (output += chunk.toString()));
  child.stderr.on('data', (chunk: Buffer) => (output += chunk.toString()));
  const exited = new Promise<number | null>((resolve) => child.once('exit', resolve));

  let httpResponses = 0;
  let running = true;
  const probe = (async () => {
    while (running) {
      try {
        await fetch(`http://127.0.0.1:${port}/health`, { signal: AbortSignal.timeout(200) });
        httpResponses += 1;
      } catch {
        // Connection refused: no listener is bound.
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  })();
  const timeout = setTimeout(() => child.kill(), 90_000);
  const code = await exited;
  clearTimeout(timeout);
  running = false;
  await probe;

  assert.equal(code, 1, output.slice(-2000));
  assert.match(output, /Failed during startup phase/);
  assert.equal(output.includes('"phase":"http-server","status":"ready"'), false);
  assert.equal(httpResponses, 0, 'liveness is never exposed when startup fails closed');
  assert.equal(output.includes(devicePassword), false);
});

test('readiness rejects a standalone deployment even with exact indexes and migration marker', async () => {
  await ensureDevelopmentDatabaseSchema(() => undefined);
  assert.equal(await recordDeviceMigrationIfNothingToMigrate(db()), true);
  await createNonceIndexes(db());
  await assertCriticalDeviceIndexes(db());

  await assert.rejects(
    () => assertDeviceDatabaseReady(),
    (error: unknown) =>
      error instanceof DeviceSchemaNotReadyError &&
      /not a writable replica-set primary/.test(error.message),
  );
  const nonces = new MongoNonceStore(() => db());
  await assert.rejects(() => nonces.assertReady());

  const testAuth = setupDeviceTestAuth().internalAuth;
  assert.ok(testAuth);
  const app = createApp({ internalAuth: { ...testAuth, nonces } });
  try {
    await assert.rejects(async () => {
      await app.ready();
    }, 'the application refuses to start with a non-transactional nonce store');
  } finally {
    await app.close().catch(() => undefined);
  }
});

test('mutations that require transactions are rejected on standalone without partial writes', async (context) => {
  await ensureDevelopmentDatabaseSchema(() => undefined);
  const count = async () => ({
    devices: await db().collection(DeviceModel.collection.name).countDocuments(),
    credentials: await db().collection(DeviceCredentialModel.collection.name).countDocuments(),
    revocations: await db().collection(DeviceRevocationModel.collection.name).countDocuments(),
    challenges: await db().collection(DeviceLinkChallengeModel.collection.name).countDocuments(),
  });
  const pem = generateKeyPairSync('ed25519')
    .publicKey.export({ type: 'spki', format: 'pem' })
    .toString();
  const before = await count();

  await assert.rejects(
    registerDevice({
      identifier: 'esp32-standalone',
      publicKey: pem,
      vehicleId: String(new Types.ObjectId()),
      requestedByUserId: String(new Types.ObjectId()),
    }),
  );
  assert.deepEqual(await count(), before);

  context.mock.method(
    globalThis,
    'fetch',
    async () =>
      new Response(JSON.stringify({ verified: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
  );
  // In-memory nonce store only so the route can be reached; the topology itself is real.
  const app = createApp(setupDeviceTestAuth());
  try {
    const path = '/internal/devices/register';
    const payload = Buffer.from(
      JSON.stringify({
        identifier: 'esp32-standalone-http',
        publicKey: pem,
        vehicleId: String(new Types.ObjectId()),
        userId: String(new Types.ObjectId()),
        membershipId: String(new Types.ObjectId()),
      }),
    );
    const response = await app.inject({
      method: 'POST',
      url: path,
      payload,
      headers: v2Headers(payload, 'POST', path, 'vehicle-service'),
    });
    assert.equal(response.statusCode, 500, 'a misconfigured topology is not reported as success');
    assert.equal(response.body.includes('Transaction'), false);
  } finally {
    await app.close();
  }
  assert.deepEqual(await count(), before);

  const legacyId = new Types.ObjectId();
  const legacyVehicleId = new Types.ObjectId();
  const legacyRequesterId = new Types.ObjectId();
  const legacyMembershipId = new Types.ObjectId();
  await db().collection(DeviceModel.collection.name).insertOne({
    _id: legacyId,
    identifier: 'esp32-standalone-raw',
    vehicleId: legacyVehicleId,
    requestedByUserId: legacyRequesterId,
    requestedByMembershipId: legacyMembershipId,
    linkedByUserId: null,
    linkedAt: null,
    status: 'PENDING',
    revokedAt: null,
    revocationId: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  });
  await assert.rejects(
    revokeDevice({
      deviceId: String(legacyId),
      reason: 'ADMINISTRATIVE',
      actor: systemRevocationActor(),
      requestId: 'req-standalone',
    }),
  );
  await assert.rejects(
    createDeviceChallenge({
      deviceId: legacyId,
      vehicleId: legacyVehicleId,
      requestedByUserId: legacyRequesterId,
      requestedByMembershipId: legacyMembershipId,
    }),
  );
  await assert.rejects(findEffectiveDeviceBinding(String(legacyId)));
  const raw = await db().collection(DeviceModel.collection.name).findOne({ _id: legacyId });
  assert.equal(raw?.status, 'PENDING');
  assert.equal(await db().collection(DeviceRevocationModel.collection.name).countDocuments(), 0);
});

test('incorrect critical indexes are detected and never dropped; only challenges and nonces expire', async () => {
  await ensureDevelopmentDatabaseSchema(() => undefined);
  await createNonceIndexes(db());
  assert.deepEqual(await findCriticalDeviceIndexIssues(db()), []);

  const credentials = db().collection(DeviceCredentialModel.collection.name);
  const indexName = 'device_credential_active_device_unique';
  await credentials.deleteMany({});
  await credentials.dropIndex(indexName);
  await credentials.createIndex({ deviceId: 1 }, { name: indexName, unique: true });
  const weakened = async () =>
    (await credentials.listIndexes().toArray()).find((index) => index.name === indexName);
  try {
    assert.deepEqual(await findCriticalDeviceIndexIssues(db()), [
      `Missing or invalid index device_credentials.${indexName}`,
    ]);
    await assert.rejects(() => assertCriticalDeviceIndexes(db()), DeviceSchemaNotReadyError);
    await assert.rejects(() => ensureDevelopmentDatabaseSchema(() => undefined));
    const stillPresent = await weakened();
    assert.ok(stillPresent, 'the incorrect index is never dropped automatically');
    assert.equal(stillPresent.partialFilterExpression, undefined);
  } finally {
    await credentials.dropIndex(indexName);
    await DeviceCredentialModel.createIndexes();
  }
  assert.deepEqual(await findCriticalDeviceIndexIssues(db()), []);

  const ttl = async (collection: string) =>
    (await db().collection(collection).listIndexes().toArray()).filter(
      (index) => index.expireAfterSeconds !== undefined,
    );
  assert.deepEqual(await ttl(DeviceCredentialModel.collection.name), []);
  assert.deepEqual(await ttl(DeviceRevocationModel.collection.name), []);
  assert.deepEqual(await ttl(DeviceModel.collection.name), []);
  assert.deepEqual(
    (await ttl(DeviceLinkChallengeModel.collection.name)).map((index) => index.name),
    ['expiresAt_1'],
  );
  assert.deepEqual(
    (await ttl(NONCE_COLLECTION)).map((index) => index.name),
    ['internal_nonce_expiry'],
  );
});
