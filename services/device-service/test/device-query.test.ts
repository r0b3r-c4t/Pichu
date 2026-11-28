import assert from 'node:assert/strict';
import test from 'node:test';
import { Types } from 'mongoose';
import { DeviceServiceError } from '../src/services/device-errors.js';
import {
  assembleInternalDeviceRecord,
  normalizePersistedMetadata,
  type PersistedCredentialDoc,
  type PersistedDeviceDoc,
  type PersistedRevocationDoc,
} from '../src/services/device-query.service.js';

const now = new Date('2026-11-27T01:00:00.000Z');
const createdAt = new Date('2026-11-01T10:00:00.000Z');
const updatedAt = new Date('2026-11-02T10:00:00.000Z');
const fingerprintA = `sha256:${'a'.repeat(64)}`;
const fingerprintB = `sha256:${'b'.repeat(64)}`;
const fingerprintC = `sha256:${'c'.repeat(64)}`;

function baseDevice(overrides: Partial<PersistedDeviceDoc> = {}): PersistedDeviceDoc {
  return {
    _id: new Types.ObjectId('674600000000000000000010'),
    identifier: 'esp32-sunroof',
    vehicleId: new Types.ObjectId('674600000000000000000020'),
    requestedByUserId: new Types.ObjectId('674600000000000000000030'),
    requestedByMembershipId: new Types.ObjectId('674600000000000000000040'),
    linkedByUserId: new Types.ObjectId('674600000000000000000030'),
    linkedAt: new Date('2026-11-01T11:00:00.000Z'),
    status: 'ACTIVE',
    revokedAt: null,
    revocationId: null,
    lastSeenAt: null,
    metadata: {
      name: 'Sunroof Module',
      manufacturer: 'Espressif',
      hardwareModel: 'ESP32-S3',
      hardwareRevision: 'rev-1.0',
      firmwareVersion: '1.0.0',
      serialNumber: 'SN-001',
    },
    createdAt,
    updatedAt,
    ...overrides,
  };
}

function baseCredential(
  deviceId: Types.ObjectId,
  overrides: Partial<PersistedCredentialDoc> = {},
): PersistedCredentialDoc {
  return {
    _id: new Types.ObjectId('674600000000000000000050'),
    deviceId,
    keyId: `dk_${'A'.repeat(22)}`,
    algorithm: 'Ed25519',
    publicKey:
      '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAA6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=\n-----END PUBLIC KEY-----\n',
    fingerprint: fingerprintA,
    status: 'ACTIVE',
    activatedAt: createdAt,
    expiresAt: null,
    revokedAt: null,
    revocationId: null,
    createdAt,
    updatedAt,
    ...overrides,
  };
}

test('normalizePersistedMetadata backfills null on historical documents without metadata', () => {
  assert.deepEqual(normalizePersistedMetadata(undefined), {
    name: null,
    manufacturer: null,
    hardwareModel: null,
    hardwareRevision: null,
    firmwareVersion: null,
    serialNumber: null,
  });
  assert.deepEqual(normalizePersistedMetadata({ name: 'Cabin Node' }), {
    name: 'Cabin Node',
    manufacturer: null,
    hardwareModel: null,
    hardwareRevision: null,
    firmwareVersion: null,
    serialNumber: null,
  });
});

test('assembleInternalDeviceRecord separates status, credential state, operational and observational connectivity without exposing secrets', () => {
  const dev = baseDevice({ lastSeenAt: null, metadata: undefined });
  const cred = baseCredential(dev._id);
  const record = assembleInternalDeviceRecord(dev, [cred], null, now);

  assert.equal(record.status, 'ACTIVE');
  assert.equal(record.operational, true);
  assert.equal(record.credential.status, 'ACTIVE');
  assert.equal(record.credential.usable, true);
  assert.equal(
    record.connectivity.lastSeenAt,
    null,
    'ACTIVE + operational never infers connectivity',
  );
  assert.equal(JSON.stringify(record).includes('BEGIN PUBLIC KEY'), false);
  assert.equal('publicKey' in record.credential, false);

  // Expired ACTIVE credential -> status remains ACTIVE, credential.status is EXPIRED, operational is false
  const expiredCred = baseCredential(dev._id, {
    expiresAt: new Date(now.getTime() - 1),
  });
  const degraded = assembleInternalDeviceRecord(dev, [expiredCred], null, now);
  assert.equal(degraded.status, 'ACTIVE');
  assert.equal(degraded.credential.status, 'EXPIRED');
  assert.equal(degraded.credential.usable, false);
  assert.equal(degraded.operational, false);
});

test('deterministic credential selection prefers ACTIVE, then device-revocation match, then latest revokedAt/_id regardless of input order', () => {
  const dev = baseDevice();
  const olderRevoked = baseCredential(dev._id, {
    _id: new Types.ObjectId('674600000000000000000051'),
    keyId: `dk_${'1'.repeat(22)}`,
    fingerprint: fingerprintA,
    status: 'REVOKED',
    activatedAt: new Date('2026-10-01T00:00:00.000Z'),
    revokedAt: new Date('2026-10-10T00:00:00.000Z'),
    revocationId: new Types.ObjectId('674600000000000000000091'),
  });
  const newerRevoked = baseCredential(dev._id, {
    _id: new Types.ObjectId('674600000000000000000052'),
    keyId: `dk_${'2'.repeat(22)}`,
    fingerprint: fingerprintB,
    status: 'REVOKED',
    activatedAt: new Date('2026-10-11T00:00:00.000Z'),
    revokedAt: new Date('2026-10-20T00:00:00.000Z'),
    revocationId: new Types.ObjectId('674600000000000000000092'),
  });
  const currentActive = baseCredential(dev._id, {
    _id: new Types.ObjectId('674600000000000000000053'),
    keyId: `dk_${'3'.repeat(22)}`,
    fingerprint: fingerprintC,
    status: 'ACTIVE',
    activatedAt: new Date('2026-10-21T00:00:00.000Z'),
  });

  // 1) Even if revoked credentials appear first, the ACTIVE credential is always chosen
  const withActiveFirst = assembleInternalDeviceRecord(
    dev,
    [olderRevoked, newerRevoked, currentActive],
    null,
    now,
  );
  const withActiveLast = assembleInternalDeviceRecord(
    dev,
    [currentActive, newerRevoked, olderRevoked],
    null,
    now,
  );
  assert.equal(withActiveFirst.credential.credentialId, String(currentActive._id));
  assert.equal(withActiveLast.credential.credentialId, String(currentActive._id));

  // 2) Degraded ACTIVE device with only revoked credentials picks latest revokedAt deterministically
  const degradedA = assembleInternalDeviceRecord(dev, [olderRevoked, newerRevoked], null, now);
  const degradedB = assembleInternalDeviceRecord(dev, [newerRevoked, olderRevoked], null, now);
  assert.equal(degradedA.credential.credentialId, String(newerRevoked._id));
  assert.equal(degradedB.credential.credentialId, String(newerRevoked._id));
  assert.equal(degradedA.operational, false);

  // 3) REVOKED device selects the credential revoked as part of the device revocation
  const devRevId = new Types.ObjectId('674600000000000000000099');
  const devRevAt = new Date('2026-11-05T00:00:00.000Z');
  const revokedWithDevice = baseCredential(dev._id, {
    _id: new Types.ObjectId('674600000000000000000054'),
    keyId: `dk_${'4'.repeat(22)}`,
    fingerprint: fingerprintC,
    status: 'REVOKED',
    activatedAt: new Date('2026-10-21T00:00:00.000Z'),
    revokedAt: devRevAt,
    revocationId: devRevId,
  });
  const revDoc: PersistedRevocationDoc = {
    _id: devRevId,
    targetType: 'DEVICE',
    deviceId: dev._id,
    credentialId: null,
    fingerprint: fingerprintC,
    vehicleId: dev.vehicleId,
    reason: 'LOST',
    actor: {
      type: 'USER',
      userId: new Types.ObjectId('674600000000000000000030'),
      service: 'vehicle-service',
    },
    requestId: 'req-dev-rev',
    revokedAt: devRevAt,
    createdAt: devRevAt,
  };
  const revokedDev = baseDevice({
    status: 'REVOKED',
    revokedAt: devRevAt,
    revocationId: devRevId,
  });
  const revokedProjection = assembleInternalDeviceRecord(
    revokedDev,
    [olderRevoked, revokedWithDevice, newerRevoked],
    revDoc,
    now,
  );
  assert.equal(revokedProjection.credential.credentialId, String(revokedWithDevice._id));
  assert.equal(revokedProjection.revocationReason, 'LOST');
  assert.equal(revokedProjection.operational, false);
});

test('inconsistent persistence documents fail closed with INCONSISTENT_DEVICE_STATE', () => {
  const dev = baseDevice();
  const cred = baseCredential(dev._id);

  const failClosedCases: Array<[string, () => unknown]> = [
    ['zero credentials', () => assembleInternalDeviceRecord(dev, [], null, now)],
    [
      'two ACTIVE credentials',
      () =>
        assembleInternalDeviceRecord(
          dev,
          [
            cred,
            baseCredential(dev._id, { _id: new Types.ObjectId(), keyId: `dk_${'Z'.repeat(22)}` }),
          ],
          null,
          now,
        ),
    ],
    [
      'missing vehicleId',
      () => assembleInternalDeviceRecord(baseDevice({ vehicleId: null }), [cred], null, now),
    ],
    [
      'PENDING device with linkedAt',
      () =>
        assembleInternalDeviceRecord(
          baseDevice({ status: 'PENDING', linkedByUserId: null, linkedAt: now }),
          [cred],
          null,
          now,
        ),
    ],
    [
      'REVOKED device without DeviceRevocation record',
      () =>
        assembleInternalDeviceRecord(
          baseDevice({
            status: 'REVOKED',
            revokedAt: now,
            revocationId: new Types.ObjectId(),
          }),
          [
            baseCredential(dev._id, {
              status: 'REVOKED',
              revokedAt: now,
              revocationId: new Types.ObjectId(),
            }),
          ],
          null,
          now,
        ),
    ],
    [
      'REVOKED device still holding an ACTIVE credential',
      () => {
        const revId = new Types.ObjectId();
        const revDoc: PersistedRevocationDoc = {
          _id: revId,
          targetType: 'DEVICE',
          deviceId: dev._id,
          credentialId: null,
          fingerprint: fingerprintA,
          vehicleId: dev.vehicleId,
          reason: 'ADMINISTRATIVE',
          actor: { type: 'SYSTEM', userId: null, service: null },
          requestId: 'req-bad',
          revokedAt: now,
          createdAt: now,
        };
        return assembleInternalDeviceRecord(
          baseDevice({ status: 'REVOKED', revokedAt: now, revocationId: revId }),
          [cred],
          revDoc,
          now,
        );
      },
    ],
  ];

  for (const [label, fn] of failClosedCases) {
    assert.throws(
      fn,
      (err: unknown) =>
        err instanceof DeviceServiceError && err.code === 'INCONSISTENT_DEVICE_STATE',
      label,
    );
  }
});
