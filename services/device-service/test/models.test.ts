import assert from 'node:assert/strict';
import test from 'node:test';
import { Types, type Document } from 'mongoose';
import {
  DeviceCredentialModel,
  isCredentialUsable,
} from '../src/models/device-credential.model.js';
import { DeviceLinkChallengeModel } from '../src/models/device-link-challenge.model.js';
import { DeviceRevocationModel } from '../src/models/device-revocation.model.js';
import { DeviceModel, updateTouchesLifecyclePaths } from '../src/models/device.model.js';

const fingerprint = `sha256:${'a'.repeat(64)}`;

/** `validate()` runs the schema's pre('validate') invariants; `validateSync()` does not. */
async function assertValid(document: Document) {
  await assert.doesNotReject(() => document.validate());
}
async function assertInvalid(document: Document) {
  await assert.rejects(() => document.validate());
}

test('new devices must be PENDING with a requested vehicle and requester; legacy keys are not schema paths', async () => {
  const valid = new DeviceModel({
    identifier: 'esp32-a',
    vehicleId: new Types.ObjectId(),
    requestedByUserId: new Types.ObjectId(),
  });
  await assertValid(valid);
  assert.equal(valid.status, 'PENDING');
  assert.equal(DeviceModel.schema.path('publicKey'), undefined);
  assert.equal(DeviceModel.schema.path('algorithm'), undefined);

  for (const invalid of [
    { identifier: 'esp32-b', vehicleId: new Types.ObjectId() },
    { identifier: 'esp32-c', requestedByUserId: new Types.ObjectId() },
    {
      identifier: 'esp32-d',
      vehicleId: new Types.ObjectId(),
      requestedByUserId: new Types.ObjectId(),
      status: 'ACTIVE',
    },
    {
      identifier: 'esp32-e',
      vehicleId: new Types.ObjectId(),
      requestedByUserId: new Types.ObjectId(),
      linkedByUserId: new Types.ObjectId(),
    },
    { identifier: '', vehicleId: new Types.ObjectId(), requestedByUserId: new Types.ObjectId() },
  ]) {
    await assertInvalid(new DeviceModel(invalid));
  }
});

test('device indexes keep identifier globally unique and allow many devices per vehicle', () => {
  const indexes = DeviceModel.schema.indexes().map(([key, options]) => ({
    key,
    name: options.name,
    unique: options.unique === true,
    partial: options.partialFilterExpression,
  }));
  assert.deepEqual(indexes, [
    { key: { identifier: 1 }, name: 'identifier_1', unique: true, partial: undefined },
    {
      key: { vehicleId: 1, status: 1 },
      name: 'device_vehicle_status_idx',
      unique: false,
      partial: undefined,
    },
    {
      key: { vehicleId: 1, createdAt: 1, _id: 1 },
      name: 'device_vehicle_created_id_idx',
      unique: false,
      partial: undefined,
    },
  ]);
});

test('credential invariants: canonical fields, revocation coherence and partial ACTIVE uniqueness', async () => {
  const base = {
    deviceId: new Types.ObjectId(),
    keyId: `dk_${'A'.repeat(22)}`,
    algorithm: 'Ed25519',
    publicKey: '-----BEGIN PUBLIC KEY-----\nX\n-----END PUBLIC KEY-----\n',
    fingerprint,
    status: 'ACTIVE',
    activatedAt: new Date(1_000),
  };
  await assertValid(new DeviceCredentialModel(base));
  for (const invalid of [
    { ...base, keyId: 'predictable' },
    { ...base, fingerprint: 'a'.repeat(64) },
    { ...base, algorithm: 'RSA' },
    { ...base, status: 'REVOKED' },
    { ...base, revokedAt: new Date() },
    { ...base, expiresAt: new Date(500) },
  ]) {
    await assertInvalid(new DeviceCredentialModel(invalid));
  }
  const partial = DeviceCredentialModel.schema
    .indexes()
    .find(([, options]) => options.name === 'device_credential_active_device_unique');
  assert.deepEqual(partial?.[1].partialFilterExpression, { status: 'ACTIVE' });
  assert.equal(partial?.[1].unique, true);
});

test('revocation records validate target and trusted actor combinations without TTL', async () => {
  const base = {
    targetType: 'DEVICE',
    deviceId: new Types.ObjectId(),
    reason: 'LOST',
    actor: { type: 'SERVICE', userId: null, service: 'vehicle-service' },
    requestId: 'req-1',
    revokedAt: new Date(),
  };
  await assertValid(new DeviceRevocationModel(base));
  await assertValid(
    new DeviceRevocationModel({
      ...base,
      targetType: 'CREDENTIAL',
      credentialId: new Types.ObjectId(),
      fingerprint,
      actor: { type: 'USER', userId: new Types.ObjectId(), service: 'vehicle-service' },
    }),
  );
  await assertValid(
    new DeviceRevocationModel({ ...base, actor: { type: 'SYSTEM', userId: null, service: null } }),
  );
  for (const invalid of [
    { ...base, credentialId: new Types.ObjectId() },
    { ...base, targetType: 'CREDENTIAL' },
    { ...base, reason: 'because' },
    { ...base, requestId: 'has spaces' },
    { ...base, actor: { type: 'USER', userId: null, service: 'vehicle-service' } },
    { ...base, actor: { type: 'SERVICE', userId: null, service: 'api-gateway' } },
    {
      ...base,
      actor: { type: 'SERVICE', userId: new Types.ObjectId(), service: 'vehicle-service' },
    },
    { ...base, actor: { type: 'SYSTEM', userId: null, service: 'vehicle-service' } },
    { ...base, actor: { type: 'CLIENT', userId: null, service: null } },
  ]) {
    await assertInvalid(new DeviceRevocationModel(invalid));
  }
  for (const [, options] of DeviceRevocationModel.schema.indexes()) {
    assert.equal(options.expireAfterSeconds, undefined);
  }
});

test('challenges bind device, credential, vehicle, requester and membership and expire by TTL only', async () => {
  const fields = {
    challengeHash: 'h'.repeat(64),
    deviceId: new Types.ObjectId(),
    credentialId: new Types.ObjectId(),
    vehicleId: new Types.ObjectId(),
    requestedByUserId: new Types.ObjectId(),
    requestedByMembershipId: new Types.ObjectId(),
    expiresAt: new Date(),
  };
  await assertValid(new DeviceLinkChallengeModel(fields));
  await assertInvalid(new DeviceLinkChallengeModel({ ...fields, credentialId: undefined }));
  await assertInvalid(
    new DeviceLinkChallengeModel({ ...fields, requestedByMembershipId: undefined }),
  );
  const ttl = DeviceLinkChallengeModel.schema
    .indexes()
    .find(([, options]) => options.expireAfterSeconds !== undefined);
  assert.deepEqual(ttl?.[0], { expiresAt: 1 });
});

test('lifecycle update detection covers operators, plain paths and pipelines', () => {
  assert.equal(updateTouchesLifecyclePaths({ $set: { status: 'ACTIVE' } }), true);
  assert.equal(updateTouchesLifecyclePaths({ $unset: { revokedAt: 1 } }), true);
  assert.equal(updateTouchesLifecyclePaths({ $rename: { revocationId: 'x' } }), true);
  assert.equal(updateTouchesLifecyclePaths({ status: 'ACTIVE' }), true);
  assert.equal(updateTouchesLifecyclePaths([{ $set: { lastSeenAt: '$$NOW' } }]), true);
  assert.equal(updateTouchesLifecyclePaths({ $set: { lastSeenAt: new Date() } }), false);
  assert.equal(updateTouchesLifecyclePaths({ $currentDate: { updatedAt: true } }), false);
  assert.equal(updateTouchesLifecyclePaths(null), false);
});

test('device write guard rejects unsafe Mongoose modalities before reaching MongoDB', async () => {
  const isGuardError = (error: unknown) =>
    error instanceof Error && error.name === 'DeviceWriteProtectionError';
  for (const path of ['identifier', 'vehicleId', 'requestedByUserId', 'requestedByMembershipId']) {
    assert.equal(DeviceModel.schema.path(path).options.immutable, true, path);
  }

  const filter = { _id: new Types.ObjectId() };
  const rejected: Array<[string, () => Promise<unknown>]> = [
    [
      'pipeline',
      () =>
        DeviceModel.updateOne(filter, [{ $set: { lastSeenAt: '$$NOW' } }], {
          updatePipeline: true,
        }).exec(),
    ],
    [
      'upsert',
      () =>
        DeviceModel.updateOne(
          filter,
          { $set: { lastSeenAt: new Date() } },
          { upsert: true },
        ).exec(),
    ],
    [
      'overwriteImmutable',
      () =>
        DeviceModel.updateOne(
          filter,
          { $set: { lastSeenAt: new Date() } },
          { overwriteImmutable: true },
        ).exec(),
    ],
    ['partial link', () => DeviceModel.updateOne(filter, { $set: { status: 'ACTIVE' } }).exec()],
    [
      'rename destination',
      () => DeviceModel.updateOne(filter, { $rename: { lastSeenAt: 'linkedAt' } }).exec(),
    ],
    [
      'multi-document revocation',
      () =>
        DeviceModel.updateMany(filter, {
          $set: { status: 'REVOKED', revokedAt: new Date(), revocationId: new Types.ObjectId() },
        }).exec(),
    ],
    ['replacement', () => DeviceModel.replaceOne(filter, {}).exec()],
    ['bulkWrite', () => DeviceModel.bulkWrite([{ deleteOne: { filter } }])],
    [
      'insertMany',
      () =>
        DeviceModel.insertMany([
          {
            identifier: 'esp32-bulk',
            vehicleId: new Types.ObjectId(),
            requestedByUserId: new Types.ObjectId(),
          },
        ]),
    ],
    ['deleteOne', () => DeviceModel.deleteOne(filter).exec()],
    ['deleteMany', () => DeviceModel.deleteMany({}).exec()],
    ['findOneAndDelete', () => DeviceModel.findOneAndDelete(filter).exec()],
    ['findByIdAndDelete', () => DeviceModel.findByIdAndDelete(filter._id).exec()],
    [
      'document deleteOne',
      () =>
        DeviceModel.hydrate({
          _id: filter._id,
          identifier: 'esp32-hydrated',
          vehicleId: new Types.ObjectId(),
          requestedByUserId: new Types.ObjectId(),
          status: 'PENDING',
        }).deleteOne(),
    ],
  ];
  const registration = {
    identifier: 'esp32-forged',
    vehicleId: new Types.ObjectId(),
    requestedByUserId: new Types.ObjectId(),
  };
  for (const [label, fields] of [
    ['ACTIVE', { status: 'ACTIVE' }],
    ['REVOKED', { status: 'REVOKED', revokedAt: new Date(), revocationId: new Types.ObjectId() }],
    ['without vehicleId', { vehicleId: null }],
    ['without requester', { requestedByUserId: null }],
    ['PENDING with link actor', { linkedByUserId: new Types.ObjectId() }],
    ['PENDING with linkedAt', { linkedAt: new Date() }],
    ['PENDING with revokedAt', { revokedAt: new Date() }],
    ['PENDING with revocationId', { revocationId: new Types.ObjectId() }],
  ] as Array<[string, Record<string, unknown>]>) {
    rejected.push([
      `unvalidated insert: ${label}`,
      () => new DeviceModel({ ...registration, ...fields }).save({ validateBeforeSave: false }),
    ]);
  }
  for (const [label, run] of rejected) {
    await assert.rejects(run, isGuardError, label);
  }
});

test('a usable credential is ACTIVE, consistent, already activated and unexpired', () => {
  const now = new Date('2026-06-01T00:00:00.000Z');
  const usable = {
    status: 'ACTIVE' as const,
    activatedAt: new Date('2026-05-01T00:00:00.000Z'),
    expiresAt: null,
    revokedAt: null,
    revocationId: null,
  };
  assert.equal(isCredentialUsable(usable, now), true);
  assert.equal(
    isCredentialUsable({ ...usable, expiresAt: new Date(now.getTime() + 1) }, now),
    true,
  );
  for (const unusable of [
    { ...usable, status: 'REVOKED' as const },
    { ...usable, expiresAt: now },
    { ...usable, activatedAt: new Date(now.getTime() + 1) },
    { ...usable, revokedAt: now },
    { ...usable, revocationId: new Types.ObjectId() },
  ]) {
    assert.equal(isCredentialUsable(unusable, now), false);
  }
});
