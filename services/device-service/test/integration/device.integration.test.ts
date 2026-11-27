import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { after, before, beforeEach, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import mongoose, { Types } from 'mongoose';
import { MongoNonceStore, createNonceIndexes } from '@pichu/internal-auth-adapters/mongodb';
import type { InternalPrincipal } from '@pichu/internal-auth-adapters/types';
import { startAuthenticatedMongo } from '../../../../scripts/helpers/authenticated-mongo.js';
import { createApp } from '../../src/app.js';
import {
  assertCriticalDeviceIndexes,
  assertDeviceDatabaseReady,
  assertDeviceFoundationMigrationRecorded,
  DEVICE_FOUNDATION_MIGRATION_ID,
  DEVICE_MIGRATION_COLLECTION,
  DeviceSchemaNotReadyError,
  ensureDevelopmentDatabaseSchema,
  findCriticalDeviceIndexIssues,
} from '../../src/database/bootstrap.js';
import { closeDatabase, connectDatabase } from '../../src/database/connection.js';
import {
  applyDeviceFoundationMigration,
  DeviceMigrationBlockedError,
  inspectDeviceMigrationPreflight,
  recordDeviceMigrationIfNothingToMigrate,
} from '../../src/database/migration.js';
import { DeviceCredentialModel } from '../../src/models/device-credential.model.js';
import { DeviceLinkChallengeModel } from '../../src/models/device-link-challenge.model.js';
import { DeviceRevocationModel } from '../../src/models/device-revocation.model.js';
import { DeviceModel } from '../../src/models/device.model.js';
import { parseDevicePublicKey } from '../../src/security/device-public-key.js';
import { findEffectiveDeviceBinding } from '../../src/services/device-binding.service.js';
import { DeviceServiceError } from '../../src/services/device-errors.js';
import {
  completeDeviceLink,
  createDeviceChallenge,
} from '../../src/services/device-link.service.js';
import { registerDevice } from '../../src/services/device-registration.service.js';
import {
  revocationActorFromInternalPrincipal,
  revokeDevice,
  revokeDeviceCredential,
  systemRevocationActor,
  type RevocationActor,
} from '../../src/services/device-revocation.service.js';
import { setupDeviceTestAuth, v2Headers } from '../v2-fixture.js';

const execFileAsync = promisify(execFile);
let mongoCluster: Awaited<ReturnType<typeof startAuthenticatedMongo>> | undefined;

function db() {
  const current = mongoose.connection.db;
  assert.ok(current, 'Device database must be connected');
  return current;
}

before(async () => {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      mongoCluster = await startAuthenticatedMongo();
      break;
    } catch (error) {
      if (attempt === 1) throw error;
    }
  }
  assert.ok(mongoCluster);
  await connectDatabase(mongoCluster.uri('device'));
  assert.equal(db().databaseName, 'device_db');
  await ensureDevelopmentDatabaseSchema(() => undefined);
  await createNonceIndexes(db());
});

after(async () => {
  await closeDatabase().catch(() => undefined);
  await mongoCluster?.cleanup().catch(() => undefined);
});

beforeEach(async () => {
  // Raw driver cleanup: the Mongoose append-only guard intentionally rejects deleteMany.
  for (const name of [
    'devices',
    'device_credentials',
    'device_revocations',
    DeviceLinkChallengeModel.collection.name,
    DEVICE_MIGRATION_COLLECTION,
  ]) {
    await db().collection(name).deleteMany({});
  }
});

function keyPair(): { pem: string; privateKey: KeyObject } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { pem: publicKey.export({ type: 'spki', format: 'pem' }).toString().trim(), privateKey };
}

function signChallenge(privateKey: KeyObject, challenge: string): string {
  return sign(null, Buffer.from(challenge), privateKey).toString('base64url');
}

let identifierSequence = 0;
async function register(overrides: Partial<Parameters<typeof registerDevice>[0]> = {}) {
  const key = keyPair();
  const input = {
    identifier: `esp32-${(identifierSequence += 1)}`,
    publicKey: key.pem,
    vehicleId: String(new Types.ObjectId()),
    requestedByUserId: String(new Types.ObjectId()),
    ...overrides,
  };
  const result = await registerDevice(input);
  return { ...result, input, key };
}

async function linkedDevice() {
  const device = await register();
  const challenge = await createDeviceChallenge({
    deviceId: device.deviceId,
    requestedByUserId: device.input.requestedByUserId,
  });
  assert.ok(challenge);
  const result = await completeDeviceLink({
    challengeId: challenge.challengeId,
    challenge: challenge.challenge,
    signature: signChallenge(device.key.privateKey, challenge.challenge),
    actorUserId: device.input.requestedByUserId,
  });
  assert.equal(result.linked, true);
  return device;
}

function principal(sender: InternalPrincipal['sender'] = 'vehicle-service'): InternalPrincipal {
  return Object.freeze({
    environment: 'test',
    sender,
    audience: 'device-service',
    keyId: 'k',
    operationId: 'deviceRevoke',
    requestId: 'req-principal',
    nonce: 'n',
    timestamp: Date.now(),
    deadline: Date.now() + 5_000,
  });
}

function userActor(userId = String(new Types.ObjectId())): RevocationActor {
  return revocationActorFromInternalPrincipal(principal(), userId);
}

async function rejectsWithCode(promise: Promise<unknown>, code: DeviceServiceError['code']) {
  await assert.rejects(
    promise,
    (error: unknown) => error instanceof DeviceServiceError && error.code === code,
  );
}

async function counts() {
  return {
    devices: await db().collection('devices').countDocuments(),
    credentials: await db().collection('device_credentials').countDocuments(),
    revocations: await db().collection('device_revocations').countDocuments(),
  };
}

test('critical indexes are exact, durable collections have no TTL and per-vehicle uniqueness is illegal', async () => {
  await assertCriticalDeviceIndexes(db());
  assert.deepEqual(await findCriticalDeviceIndexIssues(db()), []);
  assert.equal(DeviceLinkChallengeModel.collection.name, 'devicelinkchallenges');
  const challengeIndexes = await db()
    .collection(DeviceLinkChallengeModel.collection.name)
    .listIndexes()
    .toArray();
  assert.ok(challengeIndexes.some((index) => index.expireAfterSeconds === 0));

  await db()
    .collection('device_revocations')
    .createIndex({ createdAt: 1 }, { name: 'illegal_ttl', expireAfterSeconds: 60 });
  await db()
    .collection('devices')
    .createIndex({ vehicleId: 1 }, { name: 'illegal_one_per_vehicle', unique: true, sparse: true });
  try {
    const issues = await findCriticalDeviceIndexIssues(db());
    assert.ok(issues.includes('Illegal TTL index on device_revocations'));
    assert.ok(issues.includes('Illegal unique index on devices restricts devices per vehicle'));
    await assert.rejects(() => assertCriticalDeviceIndexes(db()), DeviceSchemaNotReadyError);
    await ensureDevelopmentDatabaseSchema(() => undefined);
    await assert.rejects(() => assertDeviceDatabaseReady(), /indexes are not ready/);
    const names = async (collection: string) =>
      (await db().collection(collection).listIndexes().toArray()).map((index) => index.name);
    assert.ok((await names('device_revocations')).includes('illegal_ttl'), 'never auto-dropped');
    assert.ok((await names('devices')).includes('illegal_one_per_vehicle'), 'never auto-dropped');
  } finally {
    await db().collection('device_revocations').dropIndex('illegal_ttl');
    await db().collection('devices').dropIndex('illegal_one_per_vehicle');
  }
  await db().collection('device_credentials').dropIndex('device_credential_active_device_unique');
  try {
    assert.deepEqual(await findCriticalDeviceIndexIssues(db()), [
      'Missing or invalid index device_credentials.device_credential_active_device_unique',
    ]);
  } finally {
    await DeviceCredentialModel.createIndexes();
  }
});

test('readiness requires replica set, indexes, migration marker and nonce store; liveness does not', async () => {
  await assert.rejects(() => assertDeviceDatabaseReady(), /migration has not been applied/);
  assert.equal(await recordDeviceMigrationIfNothingToMigrate(db()), true);
  await assertDeviceDatabaseReady();

  const nonces = new MongoNonceStore(() => db());
  const testAuth = setupDeviceTestAuth().internalAuth;
  assert.ok(testAuth);
  const app = createApp({ internalAuth: { ...testAuth, nonces } });
  try {
    assert.equal((await app.inject('/health/ready')).statusCode, 200);
    await db().collection(DEVICE_MIGRATION_COLLECTION).deleteMany({});
    assert.equal((await app.inject('/health/ready')).statusCode, 503);
    assert.equal((await app.inject('/health')).statusCode, 200);
  } finally {
    await app.close();
  }
});

test('registration atomically creates a PENDING device and an ACTIVE canonical credential', async () => {
  const device = await register();
  const rawDevice = await db().collection('devices').findOne({ _id: device.deviceId });
  assert.ok(rawDevice);
  assert.equal(rawDevice.status, 'PENDING');
  assert.equal(String(rawDevice.requestedByUserId), device.input.requestedByUserId);
  assert.equal(String(rawDevice.vehicleId), device.input.vehicleId);
  assert.equal(rawDevice.linkedByUserId, null);
  assert.equal(rawDevice.linkedAt, null);
  assert.equal('publicKey' in rawDevice, false);
  assert.equal('algorithm' in rawDevice, false);

  const rawCredential = await db()
    .collection('device_credentials')
    .findOne({ _id: device.credentialId });
  assert.ok(rawCredential);
  const canonical = parseDevicePublicKey(device.key.pem);
  assert.equal(rawCredential.publicKey, canonical.publicKeyPem);
  assert.notEqual(rawCredential.publicKey, device.key.pem);
  assert.equal(rawCredential.fingerprint, canonical.fingerprint);
  assert.match(rawCredential.keyId, /^dk_[A-Za-z0-9_-]{22}$/);
  assert.equal(rawCredential.status, 'ACTIVE');
  assert.equal(rawCredential.expiresAt, null);
  assert.equal(JSON.stringify(rawCredential).includes('PRIVATE'), false);
});

test('a vehicle may own multiple devices; identifiers and keys stay globally unique', async () => {
  const vehicleId = String(new Types.ObjectId());
  await register({ vehicleId });
  const second = await register({ vehicleId });
  assert.equal(await DeviceModel.countDocuments({ vehicleId }), 2);

  const before = await counts();
  await rejectsWithCode(
    register({ identifier: second.input.identifier }),
    'DEVICE_ALREADY_REGISTERED',
  );
  await rejectsWithCode(
    registerDevice({ ...second.input, identifier: 'other-identifier' }),
    'DEVICE_ALREADY_REGISTERED',
  );
  assert.deepEqual(await counts(), before, 'no orphan device or credential after rollback');

  await revokeDevice({
    deviceId: String(second.deviceId),
    reason: 'REPLACED',
    actor: userActor(),
    requestId: 'req-replace',
  });
  await rejectsWithCode(
    register({ identifier: second.input.identifier }),
    'DEVICE_ALREADY_REGISTERED',
  );
  await rejectsWithCode(
    registerDevice({ ...second.input, identifier: 'reuses-revoked-key' }),
    'DEVICE_ALREADY_REGISTERED',
  );
});

test('keyId collisions are retried, unique at the index and never leave orphans', async () => {
  const first = await register();
  const firstKeyId = first.keyId;
  let calls = 0;
  const retried = await registerDevice(
    {
      identifier: 'keyid-retry',
      publicKey: keyPair().pem,
      vehicleId: String(new Types.ObjectId()),
      requestedByUserId: String(new Types.ObjectId()),
    },
    { generateKeyId: () => (calls++ === 0 ? firstKeyId : `dk_${'B'.repeat(22)}`) },
  );
  assert.equal(retried.keyId, `dk_${'B'.repeat(22)}`);

  const before = await counts();
  await assert.rejects(
    registerDevice(
      {
        identifier: 'keyid-exhausted',
        publicKey: keyPair().pem,
        vehicleId: String(new Types.ObjectId()),
        requestedByUserId: String(new Types.ObjectId()),
      },
      { generateKeyId: () => firstKeyId },
    ),
    (error: unknown) =>
      !(error instanceof DeviceServiceError) && (error as { code?: number }).code === 11000,
  );
  assert.deepEqual(await counts(), before);
});

test('a programming error during registration rolls back the device', async (context) => {
  const create = context.mock.method(DeviceCredentialModel, 'create', async () => {
    throw new TypeError('credential writer bug');
  });
  const before = await counts();
  await assert.rejects(register(), TypeError);
  create.mock.restore();
  assert.deepEqual(await counts(), before);
});

test('HTTP registration keeps the contract and maps 201, 409, 400, 503 and 500', async (context) => {
  context.mock.method(globalThis, 'fetch', async () =>
    Response.json({ verified: true }, { status: 200 }),
  );
  const app = createApp(setupDeviceTestAuth());
  context.after(async () => app.close());
  const path = '/internal/devices/register';
  const send = (body: Record<string, unknown>) => {
    const payload = Buffer.from(JSON.stringify(body));
    return app.inject({
      method: 'POST',
      url: path,
      payload,
      headers: v2Headers(payload, 'POST', path, 'vehicle-service'),
    });
  };
  const key = keyPair();
  const body = {
    identifier: 'http-esp32',
    publicKey: key.pem,
    vehicleId: String(new Types.ObjectId()),
    userId: String(new Types.ObjectId()),
  };
  const created = await send(body);
  assert.equal(created.statusCode, 201);
  assert.deepEqual(Object.keys(created.json()).sort(), ['deviceId', 'status']);
  assert.equal(created.json().status, 'PENDING');
  const stored = await DeviceModel.findById(created.json().deviceId);
  assert.equal(String(stored?.requestedByUserId), body.userId);

  const duplicate = await send(body);
  assert.equal(duplicate.statusCode, 409);
  assert.equal(duplicate.json().error, 'DEVICE_ALREADY_REGISTERED');
  assert.equal(duplicate.body.includes(key.pem), false);

  const before = await counts();
  const privatePem = key.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const privateResponse = await send({ ...body, identifier: 'priv', publicKey: privatePem });
  assert.equal(privateResponse.statusCode, 400);
  assert.deepEqual(await counts(), before);

  const startSession = context.mock.method(mongoose.connection, 'startSession', async () => {
    throw new mongoose.mongo.MongoNetworkError('connection reset');
  });
  const unavailable = await send({ ...body, identifier: 'down', publicKey: keyPair().pem });
  assert.equal(unavailable.statusCode, 503);
  assert.equal(unavailable.json().error, 'DEVICE_DATABASE_UNAVAILABLE');
  startSession.mock.restore();

  const create = context.mock.method(DeviceCredentialModel, 'create', async () => {
    throw new TypeError('bug');
  });
  const failed = await send({ ...body, identifier: 'bug', publicKey: keyPair().pem });
  assert.equal(failed.statusCode, 500);
  assert.equal(failed.body.includes('bug'), false);
  create.mock.restore();
  assert.deepEqual(await counts(), before);
});

test('challenges are bound to requester, vehicle, device and usable credential; only hashes are stored', async () => {
  const device = await register();
  assert.equal(
    await createDeviceChallenge({
      deviceId: device.deviceId,
      requestedByUserId: String(new Types.ObjectId()),
    }),
    null,
  );
  const issued = await createDeviceChallenge({
    deviceId: String(device.deviceId),
    requestedByUserId: device.input.requestedByUserId,
  });
  assert.ok(issued);
  const raw = await db()
    .collection(DeviceLinkChallengeModel.collection.name)
    .findOne({ _id: new Types.ObjectId(issued.challengeId) });
  assert.ok(raw);
  assert.equal(String(raw.deviceId), String(device.deviceId));
  assert.equal(String(raw.credentialId), String(device.credentialId));
  assert.equal(String(raw.vehicleId), device.input.vehicleId);
  assert.equal(String(raw.requestedByUserId), device.input.requestedByUserId);
  assert.equal(JSON.stringify(raw).includes(issued.challenge), false);
  assert.match(raw.challengeHash, /^[0-9a-f]{64}$/);

  await db()
    .collection('device_credentials')
    .updateOne({ _id: device.credentialId }, { $set: { expiresAt: new Date(Date.now() - 1) } });
  assert.equal(
    await createDeviceChallenge({
      deviceId: device.deviceId,
      requestedByUserId: device.input.requestedByUserId,
    }),
    null,
    'expired credential',
  );
  const revokedCredential = await register();
  await revokeDeviceCredential({
    deviceId: String(revokedCredential.deviceId),
    credentialId: String(revokedCredential.credentialId),
    reason: 'SECURITY_COMPROMISE',
    actor: userActor(),
    requestId: 'req-c',
  });
  assert.equal(
    await createDeviceChallenge({
      deviceId: revokedCredential.deviceId,
      requestedByUserId: revokedCredential.input.requestedByUserId,
    }),
    null,
    'revoked credential',
  );
  const linked = await linkedDevice();
  assert.equal(
    await createDeviceChallenge({
      deviceId: linked.deviceId,
      requestedByUserId: linked.input.requestedByUserId,
    }),
    null,
    'ACTIVE devices are not re-linkable',
  );
});

test('link completion verifies with DeviceCredential only and records the completing actor', async () => {
  const device = await register();
  const legacyKey = keyPair();
  await db()
    .collection('devices')
    .updateOne(
      { _id: device.deviceId },
      { $set: { publicKey: legacyKey.pem, algorithm: 'Ed25519' } },
    );
  const issued = await createDeviceChallenge({
    deviceId: device.deviceId,
    requestedByUserId: device.input.requestedByUserId,
  });
  assert.ok(issued);
  const attempt = (signature: string, actorUserId = device.input.requestedByUserId) =>
    completeDeviceLink({
      challengeId: issued.challengeId,
      challenge: issued.challenge,
      signature,
      actorUserId,
    });

  assert.deepEqual(await attempt(signChallenge(legacyKey.privateKey, issued.challenge)), {
    linked: false,
    reason: 'INVALID_PROOF',
  });
  assert.deepEqual(
    await attempt(
      signChallenge(device.key.privateKey, issued.challenge),
      String(new Types.ObjectId()),
    ),
    { linked: false, reason: 'ACTOR_MISMATCH' },
  );
  assert.equal(await findEffectiveDeviceBinding(String(device.deviceId)), null, 'PENDING');

  const linked = await attempt(signChallenge(device.key.privateKey, issued.challenge));
  assert.equal(linked.linked, true);
  const stored = await DeviceModel.findById(device.deviceId);
  assert.equal(stored?.status, 'ACTIVE');
  assert.equal(String(stored?.linkedByUserId), device.input.requestedByUserId);
  assert.equal(String(stored?.requestedByUserId), device.input.requestedByUserId);
  assert.ok(stored?.linkedAt instanceof Date);
  const challenge = await DeviceLinkChallengeModel.findById(issued.challengeId);
  assert.ok(challenge?.usedAt instanceof Date);
  assert.deepEqual(await attempt(signChallenge(device.key.privateKey, issued.challenge)), {
    linked: false,
    reason: 'INVALID_CHALLENGE',
  });

  const binding = await findEffectiveDeviceBinding(String(device.deviceId));
  assert.ok(binding);
  assert.equal(binding.vehicleId, device.input.vehicleId);
  assert.equal(binding.credentialId, String(device.credentialId));
  assert.equal(binding.fingerprint, device.fingerprint);
  assert.equal(Object.isFrozen(binding), true);
  const legacyRaw = await db().collection('devices').findOne({ _id: device.deviceId });
  assert.equal(legacyRaw?.publicKey, legacyKey.pem, 'legacy field preserved, never used');

  await db()
    .collection('device_credentials')
    .updateOne({ _id: device.credentialId }, { $set: { expiresAt: new Date(Date.now() - 1) } });
  assert.equal(
    await findEffectiveDeviceBinding(String(device.deviceId)),
    null,
    'an ACTIVE but expired credential is not evidence',
  );
});

test('expired challenges and expired, revoked or cascaded credentials never complete a link', async () => {
  const scenarios: Array<
    [string, (device: Awaited<ReturnType<typeof register>>) => Promise<void>]
  > = [
    [
      'CREDENTIAL_UNAVAILABLE',
      async (device) => {
        await revokeDeviceCredential({
          deviceId: String(device.deviceId),
          credentialId: String(device.credentialId),
          reason: 'LOST',
          actor: userActor(),
          requestId: 'req-lost',
        });
      },
    ],
    [
      'CREDENTIAL_UNAVAILABLE',
      async (device) => {
        await db()
          .collection('device_credentials')
          .updateOne(
            { _id: device.credentialId },
            { $set: { expiresAt: new Date(Date.now() - 1_000) } },
          );
      },
    ],
    [
      'CREDENTIAL_UNAVAILABLE',
      async (device) => {
        await revokeDevice({
          deviceId: String(device.deviceId),
          reason: 'REGISTRATION_CANCELLED',
          actor: userActor(),
          requestId: 'req-cancel',
        });
      },
    ],
  ];
  for (const [reason, mutate] of scenarios) {
    const device = await register();
    const issued = await createDeviceChallenge({
      deviceId: device.deviceId,
      requestedByUserId: device.input.requestedByUserId,
    });
    assert.ok(issued);
    await mutate(device);
    const result = await completeDeviceLink({
      challengeId: issued.challengeId,
      challenge: issued.challenge,
      signature: signChallenge(device.key.privateKey, issued.challenge),
      actorUserId: device.input.requestedByUserId,
    });
    assert.deepEqual(result, { linked: false, reason });
    assert.notEqual((await DeviceModel.findById(device.deviceId))?.status, 'ACTIVE');
  }

  const device = await register();
  const issued = await createDeviceChallenge({
    deviceId: device.deviceId,
    requestedByUserId: device.input.requestedByUserId,
  });
  assert.ok(issued);
  const late = await completeDeviceLink(
    {
      challengeId: issued.challengeId,
      challenge: issued.challenge,
      signature: signChallenge(device.key.privateKey, issued.challenge),
      actorUserId: device.input.requestedByUserId,
    },
    { now: new Date(issued.expiresAt.getTime() + 1) },
  );
  assert.deepEqual(late, { linked: false, reason: 'INVALID_CHALLENGE' });
});

test('concurrent completion consumes the challenge exactly once', async () => {
  const device = await register();
  const issued = await createDeviceChallenge({
    deviceId: device.deviceId,
    requestedByUserId: device.input.requestedByUserId,
  });
  assert.ok(issued);
  const signature = signChallenge(device.key.privateKey, issued.challenge);
  const results = await Promise.all(
    Array.from({ length: 6 }, () =>
      completeDeviceLink({
        challengeId: issued.challengeId,
        challenge: issued.challenge,
        signature,
        actorUserId: device.input.requestedByUserId,
      }),
    ),
  );
  assert.equal(results.filter((result) => result.linked).length, 1);
  assert.ok(
    results
      .filter((result) => !result.linked)
      .every((result) => !result.linked && result.reason === 'INVALID_CHALLENGE'),
  );
});

test('revocation actors must come from a verified trusted principal or the system', async () => {
  const device = await register();
  const forged = Object.freeze({
    type: 'SERVICE',
    userId: null,
    service: 'vehicle-service',
  }) as RevocationActor;
  await rejectsWithCode(
    revokeDevice({
      deviceId: String(device.deviceId),
      reason: 'LOST',
      actor: forged,
      requestId: 'r',
    }),
    'UNTRUSTED_REVOCATION_ACTOR',
  );
  assert.throws(
    () => revocationActorFromInternalPrincipal(principal('api-gateway')),
    (error: unknown) =>
      error instanceof DeviceServiceError && error.code === 'UNTRUSTED_REVOCATION_ACTOR',
  );
  assert.throws(() => revocationActorFromInternalPrincipal(principal(), 'not-an-id'));
  await rejectsWithCode(
    revokeDevice({
      deviceId: String(device.deviceId),
      reason: 'because' as never,
      actor: userActor(),
      requestId: 'r',
    }),
    'INVALID_REVOCATION_REQUEST',
  );
  await rejectsWithCode(
    revokeDevice({
      deviceId: String(device.deviceId),
      reason: 'LOST',
      actor: userActor(),
      requestId: 'bad id',
    }),
    'INVALID_REVOCATION_REQUEST',
  );
  await rejectsWithCode(
    revokeDevice({
      deviceId: String(new Types.ObjectId()),
      reason: 'LOST',
      actor: userActor(),
      requestId: 'r',
    }),
    'DEVICE_NOT_FOUND',
  );
  assert.equal((await counts()).revocations, 0);
});

test('device revocation is atomic, terminal, idempotent and preserves the original audit', async () => {
  const device = await linkedDevice();
  const actorUserId = String(new Types.ObjectId());
  const revokedAt = new Date('2026-11-01T10:00:00.000Z');
  const first = await revokeDevice(
    {
      deviceId: String(device.deviceId),
      reason: 'SECURITY_COMPROMISE',
      actor: userActor(actorUserId),
      requestId: 'req-original',
    },
    { now: revokedAt },
  );
  assert.equal(first.created, true);
  assert.equal(first.revocation.targetType, 'DEVICE');
  assert.equal(first.revocation.credentialId, null);
  assert.equal(first.revocation.fingerprint, device.fingerprint);
  assert.equal(String(first.revocation.vehicleId), device.input.vehicleId);
  assert.deepEqual(
    { ...first.revocation.actor, userId: String(first.revocation.actor.userId) },
    { type: 'USER', userId: actorUserId, service: 'vehicle-service' },
  );

  const stored = await DeviceModel.findById(device.deviceId);
  assert.equal(stored?.status, 'REVOKED');
  assert.deepEqual(stored?.revokedAt, revokedAt);
  assert.equal(String(stored?.revocationId), String(first.revocation._id));
  const credential = await DeviceCredentialModel.findById(device.credentialId);
  assert.equal(credential?.status, 'REVOKED');
  assert.equal(String(credential?.revocationId), String(first.revocation._id));
  assert.equal(await findEffectiveDeviceBinding(String(device.deviceId)), null);

  const repeat = await revokeDevice({
    deviceId: String(device.deviceId),
    reason: 'LOST',
    actor: systemRevocationActor(),
    requestId: 'req-repeat',
  });
  assert.equal(repeat.created, false);
  assert.equal(String(repeat.revocation._id), String(first.revocation._id));
  assert.equal(repeat.revocation.reason, 'SECURITY_COMPROMISE');
  assert.equal(repeat.revocation.requestId, 'req-original');
  assert.equal((await counts()).revocations, 1);
  assert.equal(
    await createDeviceChallenge({
      deviceId: device.deviceId,
      requestedByUserId: device.input.requestedByUserId,
    }),
    null,
    'no reactivation path',
  );
});

test('concurrent device revocations create exactly one record', async () => {
  const device = await linkedDevice();
  const outcomes = await Promise.all(
    Array.from({ length: 6 }, (_, index) =>
      revokeDevice({
        deviceId: String(device.deviceId),
        reason: 'LOST',
        actor: userActor(),
        requestId: `req-race-${index}`,
      }),
    ),
  );
  assert.equal(outcomes.filter((outcome) => outcome.created).length, 1);
  assert.equal(new Set(outcomes.map((outcome) => String(outcome.revocation._id))).size, 1);
  assert.equal((await counts()).revocations, 1);
});

test('credential revocation is distinct, membership-checked, idempotent and race-safe', async () => {
  const device = await linkedDevice();
  const other = await register();
  await rejectsWithCode(
    revokeDeviceCredential({
      deviceId: String(other.deviceId),
      credentialId: String(device.credentialId),
      reason: 'LOST',
      actor: userActor(),
      requestId: 'req-wrong-device',
    }),
    'CREDENTIAL_NOT_FOUND',
  );

  const outcomes = await Promise.all(
    Array.from({ length: 5 }, (_, index) =>
      revokeDeviceCredential({
        deviceId: String(device.deviceId),
        credentialId: String(device.credentialId),
        reason: 'SECURITY_COMPROMISE',
        actor: revocationActorFromInternalPrincipal(principal()),
        requestId: `req-cred-${index}`,
      }),
    ),
  );
  assert.equal(outcomes.filter((outcome) => outcome.created).length, 1);
  const record = outcomes[0]!.revocation;
  assert.equal(record.targetType, 'CREDENTIAL');
  assert.equal(String(record.credentialId), String(device.credentialId));
  assert.equal(record.fingerprint, device.fingerprint);
  assert.equal(record.actor.type, 'SERVICE');

  const deviceAfter = await DeviceModel.findById(device.deviceId);
  assert.equal(deviceAfter?.status, 'ACTIVE', 'link state is unchanged');
  assert.equal(
    await findEffectiveDeviceBinding(String(device.deviceId)),
    null,
    'not operational without a usable credential',
  );
  await rejectsWithCode(
    revokeDeviceCredential({
      deviceId: String(other.deviceId),
      credentialId: String(device.credentialId),
      reason: 'LOST',
      actor: userActor(),
      requestId: 'req-wrong-device-again',
    }),
    'CREDENTIAL_NOT_FOUND',
  );

  const deviceRevocation = await revokeDevice({
    deviceId: String(device.deviceId),
    reason: 'REPLACED',
    actor: userActor(),
    requestId: 'req-device-after',
  });
  assert.equal(deviceRevocation.revocation.fingerprint, null);
  const credential = await DeviceCredentialModel.findById(device.credentialId);
  assert.equal(String(credential?.revocationId), String(record._id), 'original audit preserved');

  const cascaded = await linkedDevice();
  const cascade = await revokeDevice({
    deviceId: String(cascaded.deviceId),
    reason: 'LOST',
    actor: userActor(),
    requestId: 'req-cascade',
  });
  const viaCredential = await revokeDeviceCredential({
    deviceId: String(cascaded.deviceId),
    credentialId: String(cascaded.credentialId),
    reason: 'SECURITY_COMPROMISE',
    actor: userActor(),
    requestId: 'req-after-cascade',
  });
  assert.equal(viaCredential.created, false);
  assert.equal(String(viaCredential.revocation._id), String(cascade.revocation._id));
});

test('revocation records are append-only through Mongoose and have no TTL', async () => {
  const device = await register();
  const { revocation } = await revokeDevice({
    deviceId: String(device.deviceId),
    reason: 'ADMINISTRATIVE',
    actor: systemRevocationActor(),
    requestId: 'req-admin',
  });
  const filter = { _id: revocation._id };
  await assert.rejects(
    DeviceRevocationModel.updateOne(filter, { $set: { reason: 'LOST' } }).exec(),
  );
  await assert.rejects(DeviceRevocationModel.findOneAndUpdate(filter, { reason: 'LOST' }).exec());
  await assert.rejects(DeviceRevocationModel.replaceOne(filter, {}).exec());
  await assert.rejects(DeviceRevocationModel.deleteOne(filter).exec());
  await assert.rejects(DeviceRevocationModel.deleteMany({}).exec());
  await assert.rejects(DeviceRevocationModel.findOneAndDelete(filter).exec());
  await assert.rejects(DeviceRevocationModel.bulkWrite([{ deleteOne: { filter } }]));
  const document = await DeviceRevocationModel.findById(revocation._id);
  assert.ok(document);
  await assert.rejects(document.deleteOne());
  document.set('requestId', 'changed');
  await assert.rejects(document.save());

  const persisted = await db().collection('device_revocations').findOne(filter);
  assert.equal(persisted?.reason, 'ADMINISTRATIVE');
  assert.equal(persisted?.actor.type, 'SYSTEM');
  const indexes = await db().collection('device_revocations').listIndexes().toArray();
  assert.ok(indexes.every((index) => index.expireAfterSeconds === undefined));
});

function assertNoKeyMaterial(serialized: string, pems: readonly string[]) {
  assert.equal(/BEGIN|PRIVATE KEY|PUBLIC KEY/.test(serialized), false);
  for (const pem of pems) {
    for (const line of pem.split(/\r?\n/)) {
      if (line.length >= 16 && !line.startsWith('-----')) {
        assert.equal(serialized.includes(line), false, 'report contains key material');
      }
    }
  }
}

async function issueSignedChallenge(device: Awaited<ReturnType<typeof register>>) {
  const issued = await createDeviceChallenge({
    deviceId: device.deviceId,
    requestedByUserId: device.input.requestedByUserId,
  });
  assert.ok(issued);
  return {
    challengeId: issued.challengeId,
    challenge: issued.challenge,
    signature: signChallenge(device.key.privateKey, issued.challenge),
    actorUserId: device.input.requestedByUserId,
  };
}

test('concurrent link completion and full device revocation always end REVOKED and unusable', async () => {
  const outcomes = { linkedBeforeRevocation: 0, rejected: 0 };
  for (let round = 0; round < 8; round += 1) {
    const device = await register();
    const proof = await issueSignedChallenge(device);
    const [link, revocation] = await Promise.all([
      completeDeviceLink(proof),
      revokeDevice({
        deviceId: String(device.deviceId),
        reason: 'SECURITY_COMPROMISE',
        actor: userActor(),
        requestId: `req-link-race-${round}`,
      }),
    ]);
    assert.equal(revocation.created, true);
    const stored = await db().collection('devices').findOne({ _id: device.deviceId });
    const credential = await db()
      .collection('device_credentials')
      .findOne({ _id: device.credentialId });
    assert.equal(stored?.status, 'REVOKED');
    assert.equal(String(stored?.revocationId), String(revocation.revocation._id));
    assert.equal(credential?.status, 'REVOKED');
    assert.equal(String(credential?.revocationId), String(revocation.revocation._id));
    assert.equal(await findEffectiveDeviceBinding(String(device.deviceId)), null);
    if (link.linked) {
      outcomes.linkedBeforeRevocation += 1;
      assert.ok(stored?.linkedAt instanceof Date);
    } else {
      outcomes.rejected += 1;
      assert.ok(['CREDENTIAL_UNAVAILABLE', 'DEVICE_NOT_LINKABLE'].includes(link.reason));
      assert.equal(stored?.linkedAt ?? null, null);
    }
    assert.deepEqual(await completeDeviceLink(proof), {
      linked: false,
      reason: link.linked ? 'INVALID_CHALLENGE' : 'CREDENTIAL_UNAVAILABLE',
    });
  }
  assert.equal(outcomes.linkedBeforeRevocation + outcomes.rejected, 8);
});

test('concurrent link completion and credential revocation never yield an effective binding', async () => {
  for (let round = 0; round < 8; round += 1) {
    const device = await register();
    const proof = await issueSignedChallenge(device);
    const [link, revocation] = await Promise.all([
      completeDeviceLink(proof),
      revokeDeviceCredential({
        deviceId: String(device.deviceId),
        credentialId: String(device.credentialId),
        reason: 'LOST',
        actor: userActor(),
        requestId: `req-credential-race-${round}`,
      }),
    ]);
    assert.equal(revocation.created, true);
    const stored = await db().collection('devices').findOne({ _id: device.deviceId });
    const credential = await db()
      .collection('device_credentials')
      .findOne({ _id: device.credentialId });
    assert.equal(credential?.status, 'REVOKED');
    assert.equal(await findEffectiveDeviceBinding(String(device.deviceId)), null);
    if (link.linked) {
      assert.equal(stored?.status, 'ACTIVE', 'link committed before the revocation');
    } else {
      assert.equal(link.reason, 'CREDENTIAL_UNAVAILABLE');
      assert.equal(stored?.status, 'PENDING');
      assert.equal(stored?.linkedByUserId, null);
    }
  }
});

test('a challenge bound to a credential other than the current one never completes', async () => {
  const device = await register();
  const proof = await issueSignedChallenge(device);
  await revokeDeviceCredential({
    deviceId: String(device.deviceId),
    credentialId: String(device.credentialId),
    reason: 'REPLACED',
    actor: userActor(),
    requestId: 'req-replaced',
  });
  // Raw fixture standing in for a future rotation API: a new ACTIVE credential for the device.
  const replacement = keyPair();
  const replacementKey = parseDevicePublicKey(replacement.pem);
  const replacementId = new Types.ObjectId();
  await db().collection('device_credentials').insertOne({
    _id: replacementId,
    deviceId: device.deviceId,
    keyId: 'dk_REPLACEMENTxxxxxxxxxxx',
    algorithm: 'Ed25519',
    publicKey: replacementKey.publicKeyPem,
    fingerprint: replacementKey.fingerprint,
    status: 'ACTIVE',
    activatedAt: new Date(),
    expiresAt: null,
    revokedAt: null,
    revocationId: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  });
  assert.deepEqual(await completeDeviceLink(proof), {
    linked: false,
    reason: 'CREDENTIAL_UNAVAILABLE',
  });
  assert.deepEqual(
    await completeDeviceLink({
      ...proof,
      signature: signChallenge(replacement.privateKey, proof.challenge),
    }),
    { linked: false, reason: 'CREDENTIAL_UNAVAILABLE' },
    'the current credential cannot satisfy a challenge bound to the revoked one',
  );
  assert.equal((await DeviceModel.findById(device.deviceId))?.status, 'PENDING');

  const current = await createDeviceChallenge({
    deviceId: device.deviceId,
    requestedByUserId: device.input.requestedByUserId,
  });
  assert.ok(current);
  const rawChallenge = await db()
    .collection(DeviceLinkChallengeModel.collection.name)
    .findOne({ _id: new Types.ObjectId(current.challengeId) });
  assert.equal(String(rawChallenge?.credentialId), String(replacementId));
  assert.deepEqual(
    await completeDeviceLink({
      challengeId: current.challengeId,
      challenge: current.challenge,
      signature: signChallenge(device.key.privateKey, current.challenge),
      actorUserId: device.input.requestedByUserId,
    }),
    { linked: false, reason: 'INVALID_PROOF' },
    'the revoked key cannot satisfy a challenge bound to the current credential',
  );
});

test('REVOKED devices and credentials are terminal through every Mongoose write path', async () => {
  const device = await linkedDevice();
  await revokeDevice({
    deviceId: String(device.deviceId),
    reason: 'LOST',
    actor: userActor(),
    requestId: 'req-terminal',
  });

  const revokedDevice = await DeviceModel.findById(device.deviceId);
  assert.ok(revokedDevice);
  revokedDevice.status = 'ACTIVE';
  revokedDevice.revokedAt = null;
  revokedDevice.revocationId = null;
  await assert.rejects(revokedDevice.save(), /REVOKED devices are terminal/);

  const revokedCredential = await DeviceCredentialModel.findById(device.credentialId);
  assert.ok(revokedCredential);
  revokedCredential.status = 'ACTIVE';
  revokedCredential.revokedAt = null;
  revokedCredential.revocationId = null;
  await assert.rejects(revokedCredential.save(), /REVOKED credentials are terminal/);

  const reactivateDevice = {
    $set: { status: 'ACTIVE' as const, revokedAt: null, revocationId: null },
  };
  assert.equal(
    (await DeviceModel.updateOne({ _id: device.deviceId }, reactivateDevice)).matchedCount,
    0,
  );
  assert.equal(
    (await DeviceModel.updateMany({ _id: device.deviceId }, reactivateDevice)).matchedCount,
    0,
  );
  assert.equal(
    await DeviceModel.findOneAndUpdate({ _id: device.deviceId }, reactivateDevice),
    null,
  );
  assert.equal(
    (await DeviceModel.updateOne({ _id: device.deviceId }, { $unset: { revokedAt: 1 } }))
      .matchedCount,
    0,
  );
  assert.equal(
    (
      await DeviceModel.updateOne(
        { _id: device.deviceId },
        [{ $set: { status: 'ACTIVE', revokedAt: null, revocationId: null } }],
        { updatePipeline: true },
      )
    ).matchedCount,
    0,
  );
  assert.equal(
    (
      await DeviceCredentialModel.updateOne(
        { _id: device.credentialId },
        { $set: { status: 'ACTIVE', revokedAt: null, revocationId: null } },
      )
    ).matchedCount,
    0,
  );
  assert.equal(
    (await DeviceModel.updateOne({ _id: device.deviceId }, { $set: { lastSeenAt: new Date() } }))
      .matchedCount,
    1,
    'non-lifecycle metadata stays writable',
  );

  const raw = await db().collection('devices').findOne({ _id: device.deviceId });
  assert.equal(raw?.status, 'REVOKED');
  const rawCredential = await db()
    .collection('device_credentials')
    .findOne({ _id: device.credentialId });
  assert.equal(rawCredential?.status, 'REVOKED');
  assert.equal(
    await createDeviceChallenge({
      deviceId: device.deviceId,
      requestedByUserId: device.input.requestedByUserId,
    }),
    null,
  );
});

test('findEffectiveDeviceBinding denies inconsistent states and unusable credentials', async () => {
  const baseline = await linkedDevice();
  const binding = await findEffectiveDeviceBinding(String(baseline.deviceId));
  assert.equal(binding?.credentialId, String(baseline.credentialId));
  assert.ok(Object.isFrozen(binding));
  assert.equal(await findEffectiveDeviceBinding('not-an-object-id'), null);
  assert.equal(await findEffectiveDeviceBinding(String(new Types.ObjectId())), null);
  assert.equal(await findEffectiveDeviceBinding(String((await register()).deviceId)), null);

  const cases: Array<[string, (device: Awaited<ReturnType<typeof register>>) => Promise<unknown>]> =
    [
      [
        'ACTIVE device carrying revokedAt',
        (device) =>
          db()
            .collection('devices')
            .updateOne({ _id: device.deviceId }, { $set: { revokedAt: new Date() } }),
      ],
      [
        'ACTIVE device carrying revocationId',
        (device) =>
          db()
            .collection('devices')
            .updateOne({ _id: device.deviceId }, { $set: { revocationId: new Types.ObjectId() } }),
      ],
      [
        'ACTIVE device without vehicle',
        (device) =>
          db()
            .collection('devices')
            .updateOne({ _id: device.deviceId }, { $set: { vehicleId: null } }),
      ],
      [
        'ACTIVE device without link actor',
        (device) =>
          db()
            .collection('devices')
            .updateOne({ _id: device.deviceId }, { $set: { linkedByUserId: null } }),
      ],
      [
        'unknown device status',
        (device) =>
          db()
            .collection('devices')
            .updateOne({ _id: device.deviceId }, { $set: { status: 'LINKED' } }),
      ],
      [
        'expired credential',
        (device) =>
          db()
            .collection('device_credentials')
            .updateOne(
              { _id: device.credentialId },
              { $set: { expiresAt: new Date(Date.now() - 1) } },
            ),
      ],
      [
        'credential not yet activated',
        (device) =>
          db()
            .collection('device_credentials')
            .updateOne(
              { _id: device.credentialId },
              { $set: { activatedAt: new Date(Date.now() + 60_000) } },
            ),
      ],
      [
        'ACTIVE credential carrying revocation fields',
        (device) =>
          db()
            .collection('device_credentials')
            .updateOne(
              { _id: device.credentialId },
              { $set: { revokedAt: new Date(), revocationId: new Types.ObjectId() } },
            ),
      ],
      [
        'credential with an unexpected algorithm',
        (device) =>
          db()
            .collection('device_credentials')
            .updateOne({ _id: device.credentialId }, { $set: { algorithm: 'RSA' } }),
      ],
      [
        'credential owned by another device',
        (device) =>
          db()
            .collection('device_credentials')
            .updateOne({ _id: device.credentialId }, { $set: { deviceId: new Types.ObjectId() } }),
      ],
      [
        'two ACTIVE credentials without the unique partial index',
        async (device) => {
          await db()
            .collection('device_credentials')
            .dropIndex('device_credential_active_device_unique');
          const extra = parseDevicePublicKey(keyPair().pem);
          await db()
            .collection('device_credentials')
            .insertOne({
              deviceId: device.deviceId,
              keyId: 'dk_SECONDACTIVExxxxxxxxx',
              algorithm: 'Ed25519',
              publicKey: extra.publicKeyPem,
              fingerprint: extra.fingerprint,
              status: 'ACTIVE',
              activatedAt: new Date(Date.now() - 1_000),
              expiresAt: null,
              revokedAt: null,
              revocationId: null,
            });
        },
      ],
    ];
  try {
    for (const [label, mutate] of cases) {
      const device = await linkedDevice();
      assert.ok(await findEffectiveDeviceBinding(String(device.deviceId)), label);
      await mutate(device);
      assert.equal(await findEffectiveDeviceBinding(String(device.deviceId)), null, label);
    }
  } finally {
    await db().collection('device_credentials').deleteMany({});
    await DeviceCredentialModel.createIndexes();
  }
  await assertCriticalDeviceIndexes(db());
});

async function insertLegacyDevice(fields: Record<string, unknown>) {
  const _id = new Types.ObjectId();
  await db()
    .collection('devices')
    .insertOne({
      _id,
      identifier: `legacy-${_id}`,
      algorithm: 'Ed25519',
      vehicleId: new Types.ObjectId(),
      linkedByUserId: null,
      status: 'PENDING',
      lastSeenAt: null,
      createdAt: new Date('2026-01-01T00:00:00.000Z'),
      updatedAt: new Date('2026-01-01T00:00:00.000Z'),
      ...fields,
    });
  return _id;
}

test('migration is explicit, idempotent, never invents history and leaves legacy keys untouched', async () => {
  const pendingKey = keyPair();
  const activeKey = keyPair();
  const revokedKey = keyPair();
  const pendingId = await insertLegacyDevice({ publicKey: pendingKey.pem });
  const activeId = await insertLegacyDevice({
    publicKey: activeKey.pem,
    status: 'ACTIVE',
    linkedByUserId: new Types.ObjectId(),
  });
  const revocationId = new Types.ObjectId();
  const revokedAt = new Date('2026-02-01T00:00:00.000Z');
  const revokedId = await insertLegacyDevice({
    publicKey: revokedKey.pem,
    status: 'REVOKED',
    revokedAt,
    revocationId,
  });
  await db()
    .collection('device_revocations')
    .insertOne({
      _id: revocationId,
      targetType: 'DEVICE',
      deviceId: revokedId,
      credentialId: null,
      fingerprint: null,
      vehicleId: null,
      reason: 'ADMINISTRATIVE',
      actor: { type: 'SYSTEM', userId: null, service: null },
      requestId: 'legacy-evidence',
      revokedAt,
      createdAt: revokedAt,
    });

  const preflight = await inspectDeviceMigrationPreflight(db());
  assert.equal(preflight.canMigrateSafely, true);
  assert.equal(preflight.legacyDevicesPendingCredential.length, 3);
  assert.deepEqual(
    preflight.insufficientLinkHistoryDeviceIds.sort(),
    [String(activeId), String(pendingId)].sort(),
  );
  assert.equal(JSON.stringify(preflight).includes('BEGIN'), false);
  assert.equal((await counts()).credentials, 0, 'preflight is read-only');
  await assert.rejects(() => assertDeviceDatabaseReady(), /migration has not been applied/);

  const report = await applyDeviceFoundationMigration(db());
  assert.equal(report.migrationRecorded, true);
  assert.equal(report.legacyDevicesAlreadyMigrated.length, 3);
  assertNoKeyMaterial(JSON.stringify(report), [pendingKey.pem, activeKey.pem, revokedKey.pem]);
  await assertDeviceDatabaseReady();
  assert.equal((await counts()).revocations, 1, 'no audit record is invented');
  const revokedRaw = await db().collection('devices').findOne({ _id: revokedId });
  assert.equal(revokedRaw?.status, 'REVOKED');
  assert.equal(revokedRaw?.linkedByUserId, null, 'no actor is invented');
  assert.equal(
    await findEffectiveDeviceBinding(String(revokedId)),
    null,
    'revoked devices never gain a usable credential',
  );
  assert.equal(
    await DeviceCredentialModel.countDocuments({ deviceId: revokedId, status: 'ACTIVE' }),
    0,
  );
  const legacyBinding = await findEffectiveDeviceBinding(String(activeId));
  assert.equal(legacyBinding?.linkedAt, null, 'missing link date stays null, never invented');

  const credentials = await db().collection('device_credentials').find().toArray();
  const byDevice = new Map(
    credentials.map((credential) => [String(credential.deviceId), credential]),
  );
  assert.equal(byDevice.get(String(pendingId))?.status, 'ACTIVE');
  assert.equal(
    byDevice.get(String(pendingId))?.fingerprint,
    parseDevicePublicKey(pendingKey.pem).fingerprint,
  );
  assert.deepEqual(
    byDevice.get(String(pendingId))?.activatedAt,
    new Date('2026-01-01T00:00:00.000Z'),
  );
  assert.equal(byDevice.get(String(revokedId))?.status, 'REVOKED');
  assert.deepEqual(byDevice.get(String(revokedId))?.revokedAt, revokedAt);
  assert.equal(String(byDevice.get(String(revokedId))?.revocationId), String(revocationId));

  const legacy = await db().collection('devices').findOne({ _id: pendingId });
  assert.equal(legacy?.publicKey, pendingKey.pem);
  assert.equal(legacy?.requestedByUserId, undefined, 'requester is not invented');
  const active = await db().collection('devices').findOne({ _id: activeId });
  assert.equal(active?.linkedAt, undefined, 'link date is not invented');

  await revokeDeviceCredential({
    deviceId: String(activeId),
    credentialId: String(byDevice.get(String(activeId))?._id),
    reason: 'SECURITY_COMPROMISE',
    actor: userActor(),
    requestId: 'req-post-migration',
  });
  const keyIdsBefore = credentials.map((credential) => credential.keyId).sort();
  const storedBefore = await db()
    .collection('device_credentials')
    .find()
    .sort({ _id: 1 })
    .toArray();
  await applyDeviceFoundationMigration(db(), {
    now: new Date('2030-01-01T00:00:00.000Z'),
    generateKeyId: () => 'dk_MUSTNOTBEWRITTENxxxx',
  });
  const after = await db().collection('device_credentials').find().sort({ _id: 1 }).toArray();
  assert.deepEqual(after, storedBefore, 'a repeated migration never rewrites credentials');
  assert.deepEqual(after.map((credential) => credential.keyId).sort(), keyIdsBefore);
  assert.equal(
    after.find((credential) => String(credential.deviceId) === String(activeId))?.status,
    'REVOKED',
    'revoked credentials are not resurrected',
  );
  assert.equal(
    await createDeviceChallenge({ deviceId: pendingId, requestedByUserId: new Types.ObjectId() }),
    null,
    'legacy PENDING devices without a requester cannot request a challenge',
  );
});

test('an interrupted migration resumes without duplicating credentials', async () => {
  await insertLegacyDevice({ publicKey: keyPair().pem });
  await insertLegacyDevice({ publicKey: keyPair().pem });
  let created = 0;
  await assert.rejects(
    applyDeviceFoundationMigration(db(), {
      onStep: (step) => {
        if (step === 'after_credential' && (created += 1) === 1) throw new Error('crash');
      },
    }),
    /crash/,
  );
  assert.equal((await counts()).credentials, 1);
  assert.equal(
    await db()
      .collection(DEVICE_MIGRATION_COLLECTION)
      .countDocuments({
        _id: DEVICE_FOUNDATION_MIGRATION_ID as never,
      }),
    0,
  );
  await assert.rejects(() => assertDeviceDatabaseReady(), /migration has not been applied/);
  assert.equal(
    await recordDeviceMigrationIfNothingToMigrate(db()),
    false,
    'the development bootstrap cannot shortcut an interrupted migration',
  );
  await assert.rejects(() => assertDeviceDatabaseReady(), /migration has not been applied/);
  const partial = await inspectDeviceMigrationPreflight(db());
  assert.equal(partial.legacyDevicesAlreadyMigrated.length, 1);
  assert.equal(partial.legacyDevicesPendingCredential.length, 1);

  const firstCredential = await db().collection('device_credentials').findOne({});
  const resumed = await applyDeviceFoundationMigration(db());
  assert.equal(resumed.legacyDevicesAlreadyMigrated.length, 2);
  assert.equal((await counts()).credentials, 2);
  assert.deepEqual(
    await db().collection('device_credentials').findOne({ _id: firstCredential?._id }),
    firstCredential,
    'the credential created before the interruption is not rewritten',
  );
  await assertDeviceDatabaseReady();
});

test('the migration marker is recorded only after a successful postflight', async () => {
  await insertLegacyDevice({ publicKey: keyPair().pem });
  await assert.rejects(
    applyDeviceFoundationMigration(db(), {
      onStep: async (step) => {
        if (step !== 'after_credential') return;
        await db()
          .collection('device_credentials')
          .insertOne({
            deviceId: new Types.ObjectId(),
            keyId: 'dk_ORPHANxxxxxxxxxxxxxxx',
            fingerprint: `sha256:${'0'.repeat(64)}`,
            status: 'REVOKED',
          });
      },
    }),
    (error: unknown) =>
      error instanceof DeviceMigrationBlockedError &&
      /postflight failed/.test(error.message) &&
      error.report.orphanCredentialIds.length === 1 &&
      error.report.migrationRecorded === false,
  );
  assert.equal(await db().collection(DEVICE_MIGRATION_COLLECTION).countDocuments(), 0);
  await assert.rejects(() => assertDeviceDatabaseReady(), /migration has not been applied/);

  await db().collection('device_credentials').deleteMany({ keyId: 'dk_ORPHANxxxxxxxxxxxxxxx' });
  await assert.rejects(
    applyDeviceFoundationMigration(db(), {
      onStep: async (step) => {
        if (step === 'after_indexes') {
          await db()
            .collection('device_revocations')
            .dropIndex('device_revocation_device_history_idx');
        }
      },
    }),
    DeviceSchemaNotReadyError,
  );
  assert.equal(await db().collection(DEVICE_MIGRATION_COLLECTION).countDocuments(), 0);
  await assert.rejects(() => assertDeviceDatabaseReady(), DeviceSchemaNotReadyError);

  const completed = await applyDeviceFoundationMigration(db());
  assert.equal(completed.migrationRecorded, true);
  await assertDeviceDatabaseReady();
});

test('migration blocks without mutations on unverifiable or inconsistent data', async () => {
  const blockedBy = async (
    field: keyof Awaited<ReturnType<typeof inspectDeviceMigrationPreflight>>,
    setup: () => Promise<void>,
  ) => {
    for (const name of ['devices', 'device_credentials', 'device_revocations']) {
      await db().collection(name).deleteMany({});
    }
    await setup();
    const before = await counts();
    const storedKeys = (await db().collection('devices').find().toArray())
      .map((device) => device.publicKey)
      .filter((value): value is string => typeof value === 'string');
    const error = await applyDeviceFoundationMigration(db()).then(
      () => assert.fail(`migration should block on ${String(field)}`),
      (failure: unknown) => failure,
    );
    assert.ok(error instanceof DeviceMigrationBlockedError, String(field));
    const value = error.report[field];
    assert.ok(Array.isArray(value) && value.length > 0, String(field));
    assertNoKeyMaterial(`${error.message}${JSON.stringify(error.report)}`, storedKeys);
    assertNoKeyMaterial(JSON.stringify(await inspectDeviceMigrationPreflight(db())), storedKeys);
    assert.deepEqual(await counts(), before);
    assert.equal(error.report.migrationRecorded, false);
    assert.equal(
      await recordDeviceMigrationIfNothingToMigrate(db()),
      false,
      `bootstrap must not enable the service with ${String(field)}`,
    );
    await assert.rejects(() => assertDeviceFoundationMigrationRecorded(db()));
    await assert.rejects(() => assertDeviceDatabaseReady(), /migration has not been applied/);
  };

  const key = keyPair();
  await blockedBy('suspectedPrivateKeyDeviceIds', async () => {
    await insertLegacyDevice({
      publicKey: key.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    });
  });
  await blockedBy('invalidLegacyKeyDeviceIds', async () => {
    await insertLegacyDevice({ publicKey: 'not-a-key' });
  });
  await blockedBy('duplicateLegacyFingerprintDeviceIds', async () => {
    await insertLegacyDevice({ publicKey: key.pem });
    await insertLegacyDevice({ publicKey: `${key.pem}\n` });
  });
  await blockedBy('legacyFingerprintConflictDeviceIds', async () => {
    const owner = await register();
    await insertLegacyDevice({ publicKey: owner.key.pem });
  });
  await blockedBy('partiallyMigratedMismatchDeviceIds', async () => {
    const device = await register();
    await db()
      .collection('devices')
      .updateOne({ _id: device.deviceId }, { $set: { publicKey: keyPair().pem } });
  });
  await blockedBy('orphanCredentialIds', async () => {
    const device = await register();
    await db().collection('devices').deleteOne({ _id: device.deviceId });
  });
  await blockedBy('devicesWithoutCredentialIds', async () => {
    await insertLegacyDevice({});
  });
  await blockedBy('inconsistentStateDeviceIds', async () => {
    await insertLegacyDevice({ publicKey: keyPair().pem, status: 'ACTIVE' });
  });
  await blockedBy('inconsistentStateDeviceIds', async () => {
    await insertLegacyDevice({ publicKey: keyPair().pem, status: 'REVOKED' });
  });
  await blockedBy('inconsistentStateDeviceIds', async () => {
    await insertLegacyDevice({ publicKey: keyPair().pem, status: 'LINKED' });
  });
  await blockedBy('legacyDevicesMissingCreatedAtIds', async () => {
    await insertLegacyDevice({ publicKey: keyPair().pem, createdAt: undefined });
  });
});

test('legacy Device key fields never participate in challenges, proofs or bindings', async () => {
  const legacy = keyPair();
  const requester = new Types.ObjectId();
  const pendingId = await insertLegacyDevice({
    publicKey: legacy.pem,
    requestedByUserId: requester,
  });
  const activeId = await insertLegacyDevice({
    publicKey: legacy.pem,
    status: 'ACTIVE',
    linkedByUserId: new Types.ObjectId(),
    linkedAt: new Date('2026-01-02T00:00:00.000Z'),
  });
  assert.equal(
    await createDeviceChallenge({ deviceId: pendingId, requestedByUserId: requester }),
    null,
    'a legacy key without DeviceCredential cannot obtain a challenge',
  );
  assert.equal(
    await findEffectiveDeviceBinding(String(activeId)),
    null,
    'a legacy ACTIVE device without DeviceCredential is never operational',
  );
});

test('a new empty database is initialized by the documented explicit procedure', async () => {
  const cluster = mongoCluster;
  assert.ok(cluster);
  const domainCollections = [
    DeviceModel.collection.name,
    DeviceCredentialModel.collection.name,
    DeviceRevocationModel.collection.name,
    DeviceLinkChallengeModel.collection.name,
    DEVICE_MIGRATION_COLLECTION,
  ];
  for (const name of domainCollections) {
    await db()
      .collection(name)
      .drop()
      .catch(() => undefined);
  }
  const existing = async () =>
    (
      await db()
        .listCollections({ name: { $in: domainCollections } })
        .toArray()
    ).length;
  assert.equal(await existing(), 0);
  await assert.rejects(() => assertDeviceDatabaseReady(), DeviceSchemaNotReadyError);

  const serviceRoot = fileURLToPath(new URL('../../', import.meta.url));
  const runMigrationCli = async (mode: '--preflight' | '--apply') => {
    const { stdout, stderr } = await execFileAsync(
      process.execPath,
      ['--import', 'tsx', 'src/scripts/device-foundation-migration.ts', mode],
      {
        cwd: serviceRoot,
        timeout: 60_000,
        env: {
          ...process.env,
          NODE_ENV: 'test',
          INTERNAL_AUTH_ENVIRONMENT: 'test',
          INTERNAL_AUTH_KEYRING_JSON: '[]',
          DATABASE_URL: cluster.uri('device'),
        },
      },
    );
    const output = `${stdout}${stderr}`;
    assert.equal(output.includes(cluster.users.device.password), false);
    assert.equal(/BEGIN|PRIVATE KEY/.test(output), false);
    return JSON.parse(stdout.slice(stdout.indexOf('{'))) as {
      mode: string;
      report: Awaited<ReturnType<typeof inspectDeviceMigrationPreflight>>;
    };
  };

  const preflight = await runMigrationCli('--preflight');
  assert.equal(preflight.report.canMigrateSafely, true);
  assert.equal(preflight.report.totalDevices, 0);
  assert.equal(preflight.report.migrationRecorded, false);
  assert.ok(preflight.report.missingOrInvalidIndexIssues.length > 0);
  assert.equal(await existing(), 0, 'preflight is read-only');

  const applied = await runMigrationCli('--apply');
  assert.equal(applied.report.migrationRecorded, true);
  assert.deepEqual(applied.report.blockingReasons, []);
  // The production startup gates are satisfied without starting the HTTP service first.
  await assertCriticalDeviceIndexes(db());
  await assertDeviceFoundationMigrationRecorded(db());
  await assertDeviceDatabaseReady();

  const repeated = await runMigrationCli('--apply');
  assert.equal(repeated.report.migrationRecorded, true);
  const device = await register();
  assert.equal(device.status, 'PENDING');
  await assertDeviceDatabaseReady();
});
