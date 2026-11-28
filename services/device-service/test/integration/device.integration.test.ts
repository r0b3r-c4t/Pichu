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
import {
  buildDeviceLinkProofMessage,
  parseDevicePublicKey,
  type DeviceLinkProofMessageFields,
} from '../../src/security/device-public-key.js';
import { findEffectiveDeviceBinding } from '../../src/services/device-binding.service.js';
import { DeviceServiceError } from '../../src/services/device-errors.js';
import {
  completeDeviceLink,
  createDeviceChallenge,
} from '../../src/services/device-link.service.js';
import { updateDeviceMetadata } from '../../src/services/device-metadata.service.js';
import {
  getInternalDeviceById,
  listInternalVehicleDevices,
} from '../../src/services/device-query.service.js';
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

function signCanonicalChallenge(
  privateKey: KeyObject,
  fields: DeviceLinkProofMessageFields,
): string {
  return sign(null, buildDeviceLinkProofMessage(fields), privateKey).toString('base64url');
}

function signBareChallenge(privateKey: KeyObject, challenge: string): string {
  return sign(null, Buffer.from(challenge), privateKey).toString('base64url');
}

let identifierSequence = 0;
async function register(overrides: Partial<Parameters<typeof registerDevice>[0]> = {}) {
  const key = keyPair();
  const requestedByMembershipId = overrides.requestedByMembershipId ?? String(new Types.ObjectId());
  const input = {
    identifier: `esp32-${(identifierSequence += 1)}`,
    publicKey: key.pem,
    vehicleId: String(new Types.ObjectId()),
    requestedByUserId: String(new Types.ObjectId()),
    requestedByMembershipId,
    ...overrides,
  };
  const result = await registerDevice(input);
  return { ...result, input: { ...input, requestedByMembershipId }, key };
}

async function linkedDevice() {
  const device = await register();
  const challenge = await createDeviceChallenge({
    deviceId: device.deviceId,
    vehicleId: device.input.vehicleId,
    requestedByUserId: device.input.requestedByUserId,
    requestedByMembershipId: device.input.requestedByMembershipId!,
  });
  assert.equal(challenge.ok, true);
  const result = await completeDeviceLink({
    deviceId: String(device.deviceId),
    vehicleId: device.input.vehicleId,
    challengeId: challenge.challengeId,
    challenge: challenge.challenge,
    signature: signCanonicalChallenge(device.key.privateKey, challenge.data),
    actorUserId: device.input.requestedByUserId,
    actorMembershipId: device.input.requestedByMembershipId!,
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
    membershipId: String(new Types.ObjectId()),
  };
  const created = await send(body);
  assert.equal(created.statusCode, 201);
  assert.deepEqual(Object.keys(created.json()).sort(), ['data', 'deviceId', 'status']);
  assert.equal(created.json().status, 'PENDING');
  const stored = await DeviceModel.findById(created.json().deviceId);
  assert.equal(String(stored?.requestedByUserId), body.userId);
  assert.equal(String(stored?.requestedByMembershipId), body.membershipId);

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

test('challenges are bound to requester, membership, vehicle, device and usable credential; only hashes are stored', async () => {
  const device = await register();
  assert.deepEqual(
    await createDeviceChallenge({
      deviceId: device.deviceId,
      vehicleId: device.input.vehicleId,
      requestedByUserId: String(new Types.ObjectId()),
      requestedByMembershipId: device.input.requestedByMembershipId!,
    }),
    { ok: false, reason: 'ACTOR_MISMATCH' },
  );
  assert.deepEqual(
    await createDeviceChallenge({
      deviceId: device.deviceId,
      vehicleId: device.input.vehicleId,
      requestedByUserId: device.input.requestedByUserId,
      requestedByMembershipId: String(new Types.ObjectId()),
    }),
    { ok: false, reason: 'ACTOR_MISMATCH' },
  );
  const issued = await createDeviceChallenge({
    deviceId: String(device.deviceId),
    vehicleId: device.input.vehicleId,
    requestedByUserId: device.input.requestedByUserId,
    requestedByMembershipId: device.input.requestedByMembershipId!,
  });
  assert.equal(issued.ok, true);
  const raw = await db()
    .collection(DeviceLinkChallengeModel.collection.name)
    .findOne({ _id: new Types.ObjectId(issued.challengeId) });
  assert.ok(raw);
  assert.equal(String(raw.deviceId), String(device.deviceId));
  assert.equal(String(raw.credentialId), String(device.credentialId));
  assert.equal(String(raw.vehicleId), device.input.vehicleId);
  assert.equal(String(raw.requestedByUserId), device.input.requestedByUserId);
  assert.equal(String(raw.requestedByMembershipId), device.input.requestedByMembershipId);
  assert.equal(JSON.stringify(raw).includes(issued.challenge), false);
  assert.match(raw.challengeHash, /^[0-9a-f]{64}$/);

  await db()
    .collection('device_credentials')
    .updateOne({ _id: device.credentialId }, { $set: { expiresAt: new Date(Date.now() - 1) } });
  assert.deepEqual(
    await createDeviceChallenge({
      deviceId: device.deviceId,
      vehicleId: device.input.vehicleId,
      requestedByUserId: device.input.requestedByUserId,
      requestedByMembershipId: device.input.requestedByMembershipId!,
    }),
    { ok: false, reason: 'CREDENTIAL_UNAVAILABLE' },
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
  assert.deepEqual(
    await createDeviceChallenge({
      deviceId: revokedCredential.deviceId,
      vehicleId: revokedCredential.input.vehicleId,
      requestedByUserId: revokedCredential.input.requestedByUserId,
      requestedByMembershipId: revokedCredential.input.requestedByMembershipId!,
    }),
    { ok: false, reason: 'CREDENTIAL_UNAVAILABLE' },
    'revoked credential',
  );
  const linked = await linkedDevice();
  assert.deepEqual(
    await createDeviceChallenge({
      deviceId: linked.deviceId,
      vehicleId: linked.input.vehicleId,
      requestedByUserId: linked.input.requestedByUserId,
      requestedByMembershipId: linked.input.requestedByMembershipId!,
    }),
    { ok: false, reason: 'DEVICE_NOT_LINKABLE' },
    'ACTIVE devices are not re-linkable',
  );
});

test('link completion verifies canonical domain-separated proof with DeviceCredential only and records the completing actor', async () => {
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
    vehicleId: device.input.vehicleId,
    requestedByUserId: device.input.requestedByUserId,
    requestedByMembershipId: device.input.requestedByMembershipId!,
  });
  assert.equal(issued.ok, true);
  const attempt = (
    signature: string,
    actorUserId = device.input.requestedByUserId,
    actorMembershipId = device.input.requestedByMembershipId!,
  ) =>
    completeDeviceLink({
      deviceId: String(device.deviceId),
      vehicleId: device.input.vehicleId,
      challengeId: issued.challengeId,
      challenge: issued.challenge,
      signature,
      actorUserId,
      actorMembershipId,
    });

  // Legacy bare-nonce signature MUST fail
  assert.deepEqual(await attempt(signBareChallenge(device.key.privateKey, issued.challenge)), {
    linked: false,
    reason: 'INVALID_PROOF',
  });
  // Legacy device key MUST fail
  assert.deepEqual(await attempt(signCanonicalChallenge(legacyKey.privateKey, issued.data)), {
    linked: false,
    reason: 'INVALID_PROOF',
  });
  assert.deepEqual(
    await attempt(
      signCanonicalChallenge(device.key.privateKey, issued.data),
      String(new Types.ObjectId()),
    ),
    { linked: false, reason: 'ACTOR_MISMATCH' },
  );
  assert.deepEqual(
    await attempt(
      signCanonicalChallenge(device.key.privateKey, issued.data),
      device.input.requestedByUserId,
      String(new Types.ObjectId()),
    ),
    { linked: false, reason: 'ACTOR_MISMATCH' },
  );
  assert.equal(await findEffectiveDeviceBinding(String(device.deviceId)), null, 'PENDING');

  const linked = await attempt(signCanonicalChallenge(device.key.privateKey, issued.data));
  assert.equal(linked.linked, true);
  const stored = await DeviceModel.findById(device.deviceId);
  assert.equal(stored?.status, 'ACTIVE');
  assert.equal(String(stored?.linkedByUserId), device.input.requestedByUserId);
  assert.equal(String(stored?.requestedByUserId), device.input.requestedByUserId);
  assert.ok(stored?.linkedAt instanceof Date);
  const challenge = await DeviceLinkChallengeModel.findById(issued.challengeId);
  assert.ok(challenge?.usedAt instanceof Date);
  assert.deepEqual(await attempt(signCanonicalChallenge(device.key.privateKey, issued.data)), {
    linked: false,
    reason: 'DEVICE_NOT_LINKABLE',
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
      'DEVICE_NOT_LINKABLE',
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
      vehicleId: device.input.vehicleId,
      requestedByUserId: device.input.requestedByUserId,
      requestedByMembershipId: device.input.requestedByMembershipId!,
    });
    assert.equal(issued.ok, true);
    await mutate(device);
    const result = await completeDeviceLink({
      deviceId: String(device.deviceId),
      vehicleId: device.input.vehicleId,
      challengeId: issued.challengeId,
      challenge: issued.challenge,
      signature: signCanonicalChallenge(device.key.privateKey, issued.data),
      actorUserId: device.input.requestedByUserId,
      actorMembershipId: device.input.requestedByMembershipId!,
    });
    assert.deepEqual(result, { linked: false, reason });
    assert.notEqual((await DeviceModel.findById(device.deviceId))?.status, 'ACTIVE');
  }

  const device = await register();
  const issued = await createDeviceChallenge({
    deviceId: device.deviceId,
    vehicleId: device.input.vehicleId,
    requestedByUserId: device.input.requestedByUserId,
    requestedByMembershipId: device.input.requestedByMembershipId!,
  });
  assert.equal(issued.ok, true);
  const late = await completeDeviceLink(
    {
      deviceId: String(device.deviceId),
      vehicleId: device.input.vehicleId,
      challengeId: issued.challengeId,
      challenge: issued.challenge,
      signature: signCanonicalChallenge(device.key.privateKey, issued.data),
      actorUserId: device.input.requestedByUserId,
      actorMembershipId: device.input.requestedByMembershipId!,
    },
    { now: new Date(issued.expiresAt.getTime() + 1) },
  );
  assert.deepEqual(late, { linked: false, reason: 'INVALID_CHALLENGE' });
});

test('concurrent completion consumes the challenge exactly once', async () => {
  const device = await register();
  const issued = await createDeviceChallenge({
    deviceId: device.deviceId,
    vehicleId: device.input.vehicleId,
    requestedByUserId: device.input.requestedByUserId,
    requestedByMembershipId: device.input.requestedByMembershipId!,
  });
  assert.equal(issued.ok, true);
  const signature = signCanonicalChallenge(device.key.privateKey, issued.data);
  const results = await Promise.all(
    Array.from({ length: 6 }, () =>
      completeDeviceLink({
        deviceId: String(device.deviceId),
        vehicleId: device.input.vehicleId,
        challengeId: issued.challengeId,
        challenge: issued.challenge,
        signature,
        actorUserId: device.input.requestedByUserId,
        actorMembershipId: device.input.requestedByMembershipId!,
      }),
    ),
  );
  assert.equal(results.filter((result) => result.linked).length, 1);
  assert.ok(
    results
      .filter((result) => !result.linked)
      .every(
        (result) =>
          !result.linked &&
          (result.reason === 'INVALID_CHALLENGE' || result.reason === 'DEVICE_NOT_LINKABLE'),
      ),
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
  assert.deepEqual(
    await createDeviceChallenge({
      deviceId: device.deviceId,
      vehicleId: device.input.vehicleId,
      requestedByUserId: device.input.requestedByUserId,
      requestedByMembershipId: device.input.requestedByMembershipId!,
    }),
    { ok: false, reason: 'DEVICE_NOT_LINKABLE' },
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
    vehicleId: device.input.vehicleId,
    requestedByUserId: device.input.requestedByUserId,
    requestedByMembershipId: device.input.requestedByMembershipId!,
  });
  assert.equal(issued.ok, true);
  return {
    deviceId: String(device.deviceId),
    vehicleId: device.input.vehicleId,
    challengeId: issued.challengeId,
    challenge: issued.challenge,
    data: issued.data,
    signature: signCanonicalChallenge(device.key.privateKey, issued.data),
    actorUserId: device.input.requestedByUserId,
    actorMembershipId: device.input.requestedByMembershipId!,
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
      assert.ok(
        ['CREDENTIAL_UNAVAILABLE', 'DEVICE_NOT_LINKABLE', 'INVALID_CHALLENGE'].includes(
          link.reason,
        ),
      );
      assert.equal(stored?.linkedAt ?? null, null);
    }
    assert.deepEqual(await completeDeviceLink(proof), {
      linked: false,
      reason: 'DEVICE_NOT_LINKABLE',
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
      signature: signCanonicalChallenge(replacement.privateKey, proof.data),
    }),
    { linked: false, reason: 'CREDENTIAL_UNAVAILABLE' },
    'the current credential cannot satisfy a challenge bound to the revoked one',
  );
  assert.equal((await DeviceModel.findById(device.deviceId))?.status, 'PENDING');

  const current = await createDeviceChallenge({
    deviceId: device.deviceId,
    vehicleId: device.input.vehicleId,
    requestedByUserId: device.input.requestedByUserId,
    requestedByMembershipId: device.input.requestedByMembershipId!,
  });
  assert.equal(current.ok, true);
  const rawChallenge = await db()
    .collection(DeviceLinkChallengeModel.collection.name)
    .findOne({ _id: new Types.ObjectId(current.challengeId) });
  assert.equal(String(rawChallenge?.credentialId), String(replacementId));
  assert.deepEqual(
    await completeDeviceLink({
      deviceId: String(device.deviceId),
      vehicleId: device.input.vehicleId,
      challengeId: current.challengeId,
      challenge: current.challenge,
      signature: signCanonicalChallenge(device.key.privateKey, current.data),
      actorUserId: device.input.requestedByUserId,
      actorMembershipId: device.input.requestedByMembershipId!,
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
  assert.deepEqual(
    await createDeviceChallenge({
      deviceId: device.deviceId,
      vehicleId: device.input.vehicleId,
      requestedByUserId: device.input.requestedByUserId,
      requestedByMembershipId: device.input.requestedByMembershipId!,
    }),
    { ok: false, reason: 'DEVICE_NOT_LINKABLE' },
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
  const pendingRaw = await db().collection('devices').findOne({ _id: pendingId });
  assert.deepEqual(
    await createDeviceChallenge({
      deviceId: pendingId,
      vehicleId: String(pendingRaw?.vehicleId),
      requestedByUserId: new Types.ObjectId(),
      requestedByMembershipId: new Types.ObjectId(),
    }),
    { ok: false, reason: 'UNVERIFIABLE_ENROLLMENT_CONTEXT' },
    'legacy PENDING devices without requester/membership context cannot request a challenge',
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
  const pendingLegacyRaw = await db().collection('devices').findOne({ _id: pendingId });
  assert.deepEqual(
    await createDeviceChallenge({
      deviceId: pendingId,
      vehicleId: String(pendingLegacyRaw?.vehicleId),
      requestedByUserId: requester,
      requestedByMembershipId: new Types.ObjectId(),
    }),
    { ok: false, reason: 'UNVERIFIABLE_ENROLLMENT_CONTEXT' },
    'a legacy key without verifiable enrollment context cannot obtain a challenge',
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

test('concurrent challenge issuances serialize on Device write barrier and leave at most one unused challenge', async () => {
  await ensureDevelopmentDatabaseSchema(() => undefined);
  for (let round = 0; round < 5; round += 1) {
    const device = await register();
    const outcomes = await Promise.all(
      Array.from({ length: 6 }, () =>
        createDeviceChallenge({
          deviceId: device.deviceId,
          vehicleId: device.input.vehicleId,
          requestedByUserId: device.input.requestedByUserId,
          requestedByMembershipId: device.input.requestedByMembershipId!,
        }),
      ),
    );
    assert.ok(outcomes.every((outcome) => outcome.ok));
    const unused = await db()
      .collection(DeviceLinkChallengeModel.collection.name)
      .find({ deviceId: device.deviceId, usedAt: null })
      .toArray();
    assert.equal(
      unused.length,
      1,
      'write barrier guarantees at most one active pending challenge per device',
    );
    const total = await db()
      .collection(DeviceLinkChallengeModel.collection.name)
      .countDocuments({ deviceId: device.deviceId });
    assert.equal(total, 6);

    // Only the single remaining unused challenge can complete linking; invalidated ones fail
    const winningId = String(unused[0]!._id);
    const losingOutcome = outcomes.find((o) => o.ok && o.challengeId !== winningId);
    assert.ok(losingOutcome && losingOutcome.ok);
    assert.deepEqual(
      await completeDeviceLink({
        deviceId: String(device.deviceId),
        vehicleId: device.input.vehicleId,
        challengeId: losingOutcome.challengeId,
        challenge: losingOutcome.challenge,
        signature: signCanonicalChallenge(device.key.privateKey, losingOutcome.data),
        actorUserId: device.input.requestedByUserId,
        actorMembershipId: device.input.requestedByMembershipId!,
      }),
      { linked: false, reason: 'INVALID_CHALLENGE' },
    );

    const winningOutcome = outcomes.find((o) => o.ok && o.challengeId === winningId);
    assert.ok(winningOutcome && winningOutcome.ok);
    const linked = await completeDeviceLink({
      deviceId: String(device.deviceId),
      vehicleId: device.input.vehicleId,
      challengeId: winningOutcome.challengeId,
      challenge: winningOutcome.challenge,
      signature: signCanonicalChallenge(device.key.privateKey, winningOutcome.data),
      actorUserId: device.input.requestedByUserId,
      actorMembershipId: device.input.requestedByMembershipId!,
    });
    assert.equal(linked.linked, true);
  }
});

test('wrong-context signatures, mismatched deviceId/vehicleId and historical PENDING records without membership fail closed', async () => {
  await ensureDevelopmentDatabaseSchema(() => undefined);
  const device = await register();
  const otherDevice = await register({
    vehicleId: device.input.vehicleId,
    requestedByUserId: device.input.requestedByUserId,
    requestedByMembershipId: device.input.requestedByMembershipId,
  });
  const issued = await createDeviceChallenge({
    deviceId: device.deviceId,
    vehicleId: device.input.vehicleId,
    requestedByUserId: device.input.requestedByUserId,
    requestedByMembershipId: device.input.requestedByMembershipId!,
  });
  assert.equal(issued.ok, true);

  // Valid signature over wrong context fields must be rejected without consuming the challenge
  for (const badFields of [
    { ...issued.data, vehicleId: String(new Types.ObjectId()) },
    { ...issued.data, deviceId: String(otherDevice.deviceId) },
    { ...issued.data, credentialId: String(new Types.ObjectId()) },
    { ...issued.data, requestedByUserId: String(new Types.ObjectId()) },
  ]) {
    const result = await completeDeviceLink({
      deviceId: String(device.deviceId),
      vehicleId: device.input.vehicleId,
      challengeId: issued.challengeId,
      challenge: issued.challenge,
      signature: signCanonicalChallenge(device.key.privateKey, badFields),
      actorUserId: device.input.requestedByUserId,
      actorMembershipId: device.input.requestedByMembershipId!,
    });
    assert.deepEqual(result, { linked: false, reason: 'INVALID_PROOF' });
  }

  // Supplying expectedDeviceId / expectedVehicleId that disagrees with challenge fails closed
  assert.deepEqual(
    await completeDeviceLink({
      deviceId: String(otherDevice.deviceId),
      vehicleId: device.input.vehicleId,
      challengeId: issued.challengeId,
      challenge: issued.challenge,
      signature: signCanonicalChallenge(device.key.privateKey, issued.data),
      actorUserId: device.input.requestedByUserId,
      actorMembershipId: device.input.requestedByMembershipId!,
    }),
    { linked: false, reason: 'INVALID_CHALLENGE' },
  );
  assert.deepEqual(
    await completeDeviceLink({
      deviceId: String(device.deviceId),
      vehicleId: String(new Types.ObjectId()),
      challengeId: issued.challengeId,
      challenge: issued.challenge,
      signature: signCanonicalChallenge(device.key.privateKey, issued.data),
      actorUserId: device.input.requestedByUserId,
      actorMembershipId: device.input.requestedByMembershipId!,
    }),
    { linked: false, reason: 'DEVICE_NOT_FOUND' },
  );

  // Historical pre-TKT-015 PENDING device lacking requestedByMembershipId fails closed for link,
  // yet remains administratively revocable without inventing enrollment context.
  const preTkt015 = await registerDevice({
    identifier: 'pre-tkt015-pending',
    publicKey: keyPair().pem,
    vehicleId: String(new Types.ObjectId()),
    requestedByUserId: String(new Types.ObjectId()),
    requestedByMembershipId: null,
  });
  assert.deepEqual(
    await createDeviceChallenge({
      deviceId: preTkt015.deviceId,
      vehicleId: preTkt015.record.vehicleId,
      requestedByUserId: preTkt015.record.requestedByUserId!,
      requestedByMembershipId: String(new Types.ObjectId()),
    }),
    { ok: false, reason: 'UNVERIFIABLE_ENROLLMENT_CONTEXT' },
  );
  const adminRevoked = await revokeDevice({
    deviceId: String(preTkt015.deviceId),
    expectedVehicleId: preTkt015.record.vehicleId,
    reason: 'ADMINISTRATIVE',
    actor: userActor(),
    requestId: 'req-pre015-admin',
  });
  assert.equal(adminRevoked.created, true);
  assert.equal(adminRevoked.record?.status, 'REVOKED');
});

test('REGISTRATION_CANCELLED is rejected on ACTIVE devices, allowed on PENDING, and metadata PATCH races safely with revocation', async () => {
  await ensureDevelopmentDatabaseSchema(() => undefined);
  const active = await linkedDevice();
  await rejectsWithCode(
    revokeDevice({
      deviceId: String(active.deviceId),
      expectedVehicleId: active.input.vehicleId,
      reason: 'REGISTRATION_CANCELLED',
      actor: userActor(active.input.requestedByUserId),
      requestId: 'req-bad-cancel',
    }),
    'INVALID_REVOCATION_STATE',
  );
  assert.equal((await DeviceModel.findById(active.deviceId))?.status, 'ACTIVE');

  // Partial metadata update: trims, preserves omitted fields, clears null fields
  const patched = await updateDeviceMetadata({
    deviceId: String(active.deviceId),
    vehicleId: active.input.vehicleId,
    metadata: {
      name: '  Mazda Sunroof  ',
      manufacturer: 'Espressif',
      firmwareVersion: '1.0.0',
    },
  });
  assert.equal(patched.metadata.name, 'Mazda Sunroof');
  assert.equal(patched.metadata.manufacturer, 'Espressif');
  assert.equal(patched.metadata.hardwareModel, null);

  const cleared = await updateDeviceMetadata({
    deviceId: String(active.deviceId),
    vehicleId: active.input.vehicleId,
    metadata: { manufacturer: null, serialNumber: 'SN-2026' },
  });
  assert.equal(cleared.metadata.name, 'Mazda Sunroof');
  assert.equal(cleared.metadata.manufacturer, null);
  assert.equal(cleared.metadata.serialNumber, 'SN-2026');

  // Concurrent PATCH and revokeDevice: always ends REVOKED and rejects any subsequent PATCH
  for (let round = 0; round < 6; round += 1) {
    const target = await linkedDevice();
    const [patchOutcome, revokeOutcome] = await Promise.allSettled([
      updateDeviceMetadata({
        deviceId: String(target.deviceId),
        vehicleId: target.input.vehicleId,
        metadata: { name: `Race-${round}` },
      }),
      revokeDevice({
        deviceId: String(target.deviceId),
        expectedVehicleId: target.input.vehicleId,
        reason: 'LOST',
        actor: userActor(),
        requestId: `req-patch-race-${round}`,
      }),
    ]);
    assert.equal(revokeOutcome.status, 'fulfilled');
    if (patchOutcome.status === 'rejected') {
      assert.ok(
        patchOutcome.reason instanceof DeviceServiceError &&
          patchOutcome.reason.code === 'DEVICE_REVOKED',
      );
    }
    const finalDetail = await getInternalDeviceById(String(target.deviceId));
    assert.equal(finalDetail?.status, 'REVOKED');
    assert.equal(finalDetail?.operational, false);
    await rejectsWithCode(
      updateDeviceMetadata({
        deviceId: String(target.deviceId),
        vehicleId: target.input.vehicleId,
        metadata: { name: 'After-Revoke' },
      }),
      'DEVICE_REVOKED',
    );
  }
});

test('listInternalVehicleDevices orders stably by (createdAt ASC, _id ASC) and handles legacy documents without metadata', async () => {
  await ensureDevelopmentDatabaseSchema(() => undefined);
  const vehicleId = String(new Types.ObjectId());
  const sameTime = new Date('2026-11-10T12:00:00.000Z');
  const laterTime = new Date('2026-11-10T12:01:00.000Z');

  const d1 = await register({ vehicleId, metadata: { name: 'Node A' } });
  const d2 = await register({ vehicleId, metadata: { name: 'Node B' } });
  const d3 = await register({ vehicleId });

  // Force identical createdAt on d1 and d2 plus strip metadata from d3 to simulate historical doc
  await db()
    .collection('devices')
    .updateMany({ _id: { $in: [d1.deviceId, d2.deviceId] } }, { $set: { createdAt: sameTime } });
  await db()
    .collection('devices')
    .updateOne({ _id: d3.deviceId }, { $set: { createdAt: laterTime }, $unset: { metadata: '' } });

  const expectedTieOrder = [String(d1.deviceId), String(d2.deviceId)].sort();
  const page1 = await listInternalVehicleDevices({ vehicleId, limit: 2 });
  assert.equal(page1.hasMore, true);
  assert.deepEqual(
    page1.devices.map((d) => d.deviceId),
    expectedTieOrder,
  );

  const cursor = page1.devices[1]!;
  const page2 = await listInternalVehicleDevices({
    vehicleId,
    limit: 2,
    afterCreatedAt: cursor.createdAt,
    afterId: cursor.deviceId,
  });
  assert.equal(page2.hasMore, false);
  assert.equal(page2.devices.length, 1);
  assert.equal(page2.devices[0]!.deviceId, String(d3.deviceId));
  assert.equal(page2.devices[0]!.metadata.name, null);
});

test('upgrades a valid TKT-014 database non-destructively to TKT-015 indexes while preserving historical records, credentials, and revocations', async () => {
  assert.ok(mongoCluster);
  const currentDb = db();

  // Recreate exact TKT-014 index set (all TKT-014 critical indexes EXCEPT TKT-015's device_vehicle_created_id_idx)
  await currentDb
    .collection('devices')
    .dropIndex('device_vehicle_created_id_idx')
    .catch(() => undefined);

  await currentDb
    .collection('devices')
    .createIndex({ identifier: 1 }, { name: 'identifier_1', unique: true });
  await currentDb
    .collection('devices')
    .createIndex({ vehicleId: 1, status: 1 }, { name: 'device_vehicle_status_idx' });
  await currentDb
    .collection('device_credentials')
    .createIndex(
      { fingerprint: 1 },
      { name: 'device_credential_fingerprint_unique', unique: true },
    );
  await currentDb
    .collection('device_credentials')
    .createIndex({ keyId: 1 }, { name: 'device_credential_key_id_unique', unique: true });
  await currentDb.collection('device_credentials').createIndex(
    { deviceId: 1 },
    {
      name: 'device_credential_active_device_unique',
      unique: true,
      partialFilterExpression: { status: 'ACTIVE' },
    },
  );
  await currentDb
    .collection('device_credentials')
    .createIndex({ deviceId: 1, status: 1 }, { name: 'device_credential_device_status_idx' });
  await currentDb.collection('device_revocations').createIndex(
    { deviceId: 1 },
    {
      name: 'device_revocation_device_target_unique',
      unique: true,
      partialFilterExpression: { targetType: 'DEVICE' },
    },
  );
  await currentDb.collection('device_revocations').createIndex(
    { credentialId: 1 },
    {
      name: 'device_revocation_credential_target_unique',
      unique: true,
      partialFilterExpression: { targetType: 'CREDENTIAL' },
    },
  );
  await currentDb
    .collection('device_revocations')
    .createIndex({ deviceId: 1, revokedAt: -1 }, { name: 'device_revocation_device_history_idx' });
  await currentDb
    .collection('device_revocations')
    .createIndex(
      { vehicleId: 1, revokedAt: -1 },
      { name: 'device_revocation_vehicle_history_idx' },
    );
  await currentDb
    .collection(DeviceLinkChallengeModel.collection.name)
    .createIndex({ challengeHash: 1 }, { name: 'challengeHash_1', unique: true });
  await currentDb.collection(DEVICE_MIGRATION_COLLECTION).insertOne({
    _id: DEVICE_FOUNDATION_MIGRATION_ID as never,
    appliedAt: new Date('2026-11-20T00:00:00.000Z'),
    mode: 'tkt-014-seed',
  });

  // Seed historical TKT-014 documents without `metadata` or `requestedByMembershipId`
  const vehicleId = new Types.ObjectId();
  const ownerUserId = new Types.ObjectId();
  const requesterUserId = new Types.ObjectId();
  const t1 = new Date('2026-11-20T10:00:00.000Z');
  const t2 = new Date('2026-11-20T10:05:00.000Z');
  const t3 = new Date('2026-11-20T10:10:00.000Z');

  const histPendingId = new Types.ObjectId();
  const histActiveId = new Types.ObjectId();
  const histRevokedId = new Types.ObjectId();
  const credPendingId = new Types.ObjectId();
  const credActiveId = new Types.ObjectId();
  const credRevokedId = new Types.ObjectId();
  const revocationId = new Types.ObjectId();

  const k1 = parseDevicePublicKey(keyPair().pem);
  const k2 = parseDevicePublicKey(keyPair().pem);
  const k3 = parseDevicePublicKey(keyPair().pem);

  await currentDb.collection('devices').insertMany([
    {
      _id: histPendingId,
      vehicleId,
      identifier: 'tkt014-legacy-pending',
      status: 'PENDING',
      requestedByUserId: requesterUserId,
      linkedByUserId: null,
      linkedAt: null,
      revokedAt: null,
      revocationId: null,
      lastSeenAt: null,
      createdAt: t1,
      updatedAt: t1,
    },
    {
      _id: histActiveId,
      vehicleId,
      identifier: 'tkt014-legacy-active',
      status: 'ACTIVE',
      requestedByUserId: ownerUserId,
      linkedByUserId: ownerUserId,
      linkedAt: t2,
      revokedAt: null,
      revocationId: null,
      lastSeenAt: t2,
      createdAt: t2,
      updatedAt: t2,
    },
    {
      _id: histRevokedId,
      vehicleId,
      identifier: 'tkt014-legacy-revoked',
      status: 'REVOKED',
      requestedByUserId: ownerUserId,
      linkedByUserId: ownerUserId,
      linkedAt: t3,
      revokedAt: new Date(t3.getTime() + 60_000),
      revocationId,
      lastSeenAt: null,
      createdAt: t3,
      updatedAt: new Date(t3.getTime() + 60_000),
    },
  ]);

  await currentDb.collection('device_credentials').insertMany([
    {
      _id: credPendingId,
      deviceId: histPendingId,
      vehicleId,
      keyId: `dk_${'P'.repeat(22)}`,
      algorithm: 'Ed25519',
      publicKey: k1.publicKeyPem,
      fingerprint: k1.fingerprint,
      status: 'ACTIVE',
      activatedAt: t1,
      expiresAt: null,
      revokedAt: null,
      revocationId: null,
      createdAt: t1,
      updatedAt: t1,
    },
    {
      _id: credActiveId,
      deviceId: histActiveId,
      vehicleId,
      keyId: `dk_${'A'.repeat(22)}`,
      algorithm: 'Ed25519',
      publicKey: k2.publicKeyPem,
      fingerprint: k2.fingerprint,
      status: 'ACTIVE',
      activatedAt: t2,
      expiresAt: null,
      revokedAt: null,
      revocationId: null,
      createdAt: t2,
      updatedAt: t2,
    },
    {
      _id: credRevokedId,
      deviceId: histRevokedId,
      vehicleId,
      keyId: `dk_${'R'.repeat(22)}`,
      algorithm: 'Ed25519',
      publicKey: k3.publicKeyPem,
      fingerprint: k3.fingerprint,
      status: 'REVOKED',
      activatedAt: t3,
      expiresAt: null,
      revokedAt: new Date(t3.getTime() + 60_000),
      revocationId,
      createdAt: t3,
      updatedAt: new Date(t3.getTime() + 60_000),
    },
  ]);

  await currentDb.collection('device_revocations').insertOne({
    _id: revocationId,
    targetType: 'DEVICE',
    deviceId: histRevokedId,
    credentialId: null,
    fingerprint: k3.fingerprint,
    vehicleId,
    reason: 'ADMINISTRATIVE',
    actor: {
      type: 'USER',
      userId: ownerUserId,
      service: null,
    },
    requestId: 'tkt014-legacy-revoke',
    revokedAt: new Date(t3.getTime() + 60_000),
    createdAt: new Date(t3.getTime() + 60_000),
  });

  const beforeIndexes = {
    devices: (await currentDb.collection('devices').indexes()).map((i) => i.name).sort(),
    device_credentials: (await currentDb.collection('device_credentials').indexes())
      .map((i) => i.name)
      .sort(),
    device_revocations: (await currentDb.collection('device_revocations').indexes())
      .map((i) => i.name)
      .sort(),
  };
  assert.equal(beforeIndexes.devices.includes('device_vehicle_created_id_idx'), false);

  const snapshotRawDocs = async () => ({
    devices: await currentDb.collection('devices').find({}).sort({ _id: 1 }).toArray(),
    credentials: await currentDb
      .collection('device_credentials')
      .find({})
      .sort({ _id: 1 })
      .toArray(),
    revocations: await currentDb
      .collection('device_revocations')
      .find({})
      .sort({ _id: 1 })
      .toArray(),
  });
  const beforeDocs = await snapshotRawDocs();

  // Readiness BEFORE upgrade must fail strictly due to missing TKT-015 index
  const preIssues = await findCriticalDeviceIndexIssues(currentDb);
  assert.deepEqual(preIssues, ['Missing or invalid index devices.device_vehicle_created_id_idx']);
  await assert.rejects(() => assertDeviceDatabaseReady(), DeviceSchemaNotReadyError);

  const serviceRoot = fileURLToPath(new URL('../../', import.meta.url));
  const runCli = async (mode: '--preflight' | '--apply') => {
    const { stdout } = await execFileAsync(
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
          DATABASE_URL: mongoCluster!.uri('device'),
        },
      },
    );
    return JSON.parse(stdout.slice(stdout.indexOf('{'))) as {
      mode: string;
      report: Awaited<ReturnType<typeof inspectDeviceMigrationPreflight>>;
    };
  };

  // Preflight is strictly read-only and preserves indexes and historical docs
  const preflight = await runCli('--preflight');
  assert.equal(preflight.report.canMigrateSafely, true);
  assert.equal(preflight.report.migrationRecorded, true);
  assert.deepEqual(preflight.report.blockingReasons, []);
  assert.deepEqual(preflight.report.missingOrInvalidIndexIssues, [
    'Missing or invalid index devices.device_vehicle_created_id_idx',
  ]);
  assert.deepEqual(
    (await currentDb.collection('devices').indexes()).map((i) => i.name).sort(),
    beforeIndexes.devices,
  );
  assert.deepEqual(await snapshotRawDocs(), beforeDocs);

  // Apply upgrades indexes non-destructively while preserving all prior indexes and docs
  const applied = await runCli('--apply');
  assert.equal(applied.report.migrationRecorded, true);
  assert.deepEqual(applied.report.blockingReasons, []);
  assert.deepEqual(applied.report.missingOrInvalidIndexIssues, []);

  // Readiness AFTER upgrade passes
  await assertCriticalDeviceIndexes(currentDb);
  await assertDeviceFoundationMigrationRecorded(currentDb);
  await assertDeviceDatabaseReady();

  const afterIndexes = {
    devices: (await currentDb.collection('devices').indexes()).map((i) => i.name).sort(),
    device_credentials: (await currentDb.collection('device_credentials').indexes())
      .map((i) => i.name)
      .sort(),
    device_revocations: (await currentDb.collection('device_revocations').indexes())
      .map((i) => i.name)
      .sort(),
  };
  for (const name of beforeIndexes.devices) {
    assert.ok(afterIndexes.devices.includes(name), `existing index ${name} must be preserved`);
  }
  assert.ok(afterIndexes.devices.includes('device_vehicle_created_id_idx'));
  assert.deepEqual(afterIndexes.device_credentials, beforeIndexes.device_credentials);
  assert.deepEqual(afterIndexes.device_revocations, beforeIndexes.device_revocations);

  // All historical documents, credentials, and revocations remain bit-identical in MongoDB
  assert.deepEqual(await snapshotRawDocs(), beforeDocs);

  // Queries & effective binding behave safely on upgraded historical records
  const listed = await listInternalVehicleDevices({ vehicleId: String(vehicleId), limit: 10 });
  assert.equal(listed.hasMore, false);
  assert.deepEqual(
    listed.devices.map((d) => String(d.deviceId)),
    [String(histPendingId), String(histActiveId), String(histRevokedId)],
  );
  for (const entry of listed.devices) {
    assert.equal(entry.requestedByMembershipId, null);
    assert.deepEqual(entry.metadata, {
      name: null,
      manufacturer: null,
      hardwareModel: null,
      hardwareRevision: null,
      firmwareVersion: null,
      serialNumber: null,
    });
  }

  const activeBinding = await findEffectiveDeviceBinding(String(histActiveId));
  assert.ok(activeBinding, 'historical ACTIVE device retains effective runtime binding');
  assert.equal(activeBinding.vehicleId, String(vehicleId));
  assert.equal(activeBinding.credentialId, String(credActiveId));

  const activeDetail = await getInternalDeviceById(String(histActiveId));
  assert.ok(activeDetail);
  assert.equal(activeDetail.operational, true);

  const pendingDetail = await getInternalDeviceById(String(histPendingId));
  assert.ok(pendingDetail);
  assert.equal(pendingDetail.requestedByMembershipId, null);

  // Historical PENDING without requestedByMembershipId fails closed on enrollment challenge
  assert.deepEqual(
    await createDeviceChallenge({
      deviceId: String(histPendingId),
      vehicleId: String(vehicleId),
      requestedByUserId: String(requesterUserId),
      requestedByMembershipId: String(new Types.ObjectId()),
    }),
    { ok: false, reason: 'UNVERIFIABLE_ENROLLMENT_CONTEXT' },
  );
});
