import { Types } from 'mongoose';
import {
  assertCriticalDeviceIndexes,
  DEVICE_DOMAIN_MODELS,
  DEVICE_FOUNDATION_MIGRATION_ID,
  DEVICE_MIGRATION_COLLECTION,
  findCriticalDeviceIndexIssues,
  isDeviceFoundationMigrationRecorded,
  type MongoDb,
} from './bootstrap.js';
import { DeviceCredentialModel } from '../models/device-credential.model.js';
import { DeviceRevocationModel } from '../models/device-revocation.model.js';
import { DEVICE_STATUSES, DeviceModel } from '../models/device.model.js';
import { parseDevicePublicKey } from '../security/device-public-key.js';
import { generateDeviceKeyId } from '../services/device-registration.service.js';
import { duplicateKeyIndexName, isDuplicateKeyError } from '../services/device-errors.js';

/**
 * Raw legacy view of a device. `publicKey`/`algorithm` are pre-TKT-014 paths that the Mongoose
 * schema no longer declares; they are read here only to migrate them into DeviceCredential.
 */
interface RawDevice {
  _id: Types.ObjectId;
  status?: unknown;
  vehicleId?: Types.ObjectId | null;
  publicKey?: unknown;
  requestedByUserId?: Types.ObjectId | null;
  linkedByUserId?: Types.ObjectId | null;
  linkedAt?: Date | null;
  revokedAt?: Date | null;
  revocationId?: Types.ObjectId | null;
  createdAt?: unknown;
}

interface RawCredential {
  _id: Types.ObjectId;
  deviceId: Types.ObjectId;
  fingerprint: string;
  status: string;
}

interface RawRevocation {
  _id: Types.ObjectId;
  targetType: string;
  deviceId: Types.ObjectId;
}

interface PlannedCredential {
  deviceId: Types.ObjectId;
  publicKeyPem: string;
  fingerprint: string;
  status: 'ACTIVE' | 'REVOKED';
  activatedAt: Date;
  revokedAt: Date | null;
  revocationId: Types.ObjectId | null;
}

/** Contains identifiers and counts only; never key material. */
export interface DeviceMigrationReport {
  totalDevices: number;
  legacyDevicesPendingCredential: string[];
  legacyDevicesAlreadyMigrated: string[];
  suspectedPrivateKeyDeviceIds: string[];
  invalidLegacyKeyDeviceIds: string[];
  duplicateLegacyFingerprintDeviceIds: string[];
  legacyFingerprintConflictDeviceIds: string[];
  partiallyMigratedMismatchDeviceIds: string[];
  orphanCredentialIds: string[];
  devicesWithoutCredentialIds: string[];
  inconsistentStateDeviceIds: string[];
  legacyDevicesMissingCreatedAtIds: string[];
  /** Non-blocking: history that cannot be reconstructed and is left null, never invented. */
  insufficientLinkHistoryDeviceIds: string[];
  missingOrInvalidIndexIssues: string[];
  migrationRecorded: boolean;
  canMigrateSafely: boolean;
  blockingReasons: string[];
}

export class DeviceMigrationBlockedError extends Error {
  constructor(
    message: string,
    readonly report: DeviceMigrationReport,
  ) {
    super(message);
    this.name = 'DeviceMigrationBlockedError';
  }
}

const KNOWN_STATUSES = new Set<unknown>(DEVICE_STATUSES);

async function analyze(db: MongoDb): Promise<{
  report: DeviceMigrationReport;
  plan: PlannedCredential[];
}> {
  const [devices, credentials, revocations, indexIssues, migrationRecorded] = await Promise.all([
    db
      .collection<RawDevice>(DeviceModel.collection.name)
      .find(
        {},
        {
          projection: {
            _id: 1,
            status: 1,
            vehicleId: 1,
            publicKey: 1,
            requestedByUserId: 1,
            linkedByUserId: 1,
            linkedAt: 1,
            revokedAt: 1,
            revocationId: 1,
            createdAt: 1,
          },
        },
      )
      .toArray(),
    db
      .collection<RawCredential>(DeviceCredentialModel.collection.name)
      .find({}, { projection: { _id: 1, deviceId: 1, fingerprint: 1, status: 1 } })
      .toArray(),
    db
      .collection<RawRevocation>(DeviceRevocationModel.collection.name)
      .find({ targetType: 'DEVICE' }, { projection: { _id: 1, targetType: 1, deviceId: 1 } })
      .toArray(),
    findCriticalDeviceIndexIssues(db),
    isDeviceFoundationMigrationRecorded(db),
  ]);

  const report: DeviceMigrationReport = {
    totalDevices: devices.length,
    legacyDevicesPendingCredential: [],
    legacyDevicesAlreadyMigrated: [],
    suspectedPrivateKeyDeviceIds: [],
    invalidLegacyKeyDeviceIds: [],
    duplicateLegacyFingerprintDeviceIds: [],
    legacyFingerprintConflictDeviceIds: [],
    partiallyMigratedMismatchDeviceIds: [],
    orphanCredentialIds: [],
    devicesWithoutCredentialIds: [],
    inconsistentStateDeviceIds: [],
    legacyDevicesMissingCreatedAtIds: [],
    insufficientLinkHistoryDeviceIds: [],
    missingOrInvalidIndexIssues: indexIssues,
    migrationRecorded,
    canMigrateSafely: false,
    blockingReasons: [],
  };

  const deviceIds = new Set(devices.map((device) => String(device._id)));
  const credentialsByDevice = new Map<string, RawCredential[]>();
  const credentialOwnerByFingerprint = new Map<string, string>();
  for (const credential of credentials) {
    const owner = String(credential.deviceId);
    if (!deviceIds.has(owner)) report.orphanCredentialIds.push(String(credential._id));
    credentialsByDevice.set(owner, [...(credentialsByDevice.get(owner) ?? []), credential]);
    credentialOwnerByFingerprint.set(credential.fingerprint, owner);
  }
  const deviceRevocationByDevice = new Map(
    revocations.map((revocation) => [String(revocation.deviceId), revocation]),
  );

  const candidates: PlannedCredential[] = [];
  const legacyFingerprintOwners = new Map<string, string[]>();
  for (const device of devices) {
    const id = String(device._id);
    const owned = credentialsByDevice.get(id) ?? [];
    const activeCount = owned.filter((credential) => credential.status === 'ACTIVE').length;
    const revocation = deviceRevocationByDevice.get(id);
    const revokedWithEvidence =
      device.status === 'REVOKED' &&
      !!revocation &&
      !!device.revocationId &&
      revocation._id.equals(device.revocationId) &&
      device.revokedAt instanceof Date;

    const inconsistent =
      !KNOWN_STATUSES.has(device.status) ||
      activeCount > 1 ||
      (device.status === 'PENDING' && !device.vehicleId) ||
      (device.status === 'ACTIVE' && (!device.vehicleId || !device.linkedByUserId)) ||
      (device.status === 'REVOKED' && (!revokedWithEvidence || activeCount > 0));
    if (inconsistent) report.inconsistentStateDeviceIds.push(id);
    if (
      (device.status === 'PENDING' && !device.requestedByUserId) ||
      (device.status === 'ACTIVE' && !(device.linkedAt instanceof Date))
    ) {
      report.insufficientLinkHistoryDeviceIds.push(id);
    }

    if (typeof device.publicKey !== 'string') {
      if (device.publicKey !== undefined && device.publicKey !== null) {
        report.invalidLegacyKeyDeviceIds.push(id);
      } else if (owned.length === 0) {
        report.devicesWithoutCredentialIds.push(id);
      }
      continue;
    }
    if (/PRIVATE KEY/i.test(device.publicKey)) {
      report.suspectedPrivateKeyDeviceIds.push(id);
      continue;
    }
    let key: ReturnType<typeof parseDevicePublicKey>;
    try {
      key = parseDevicePublicKey(device.publicKey);
    } catch {
      report.invalidLegacyKeyDeviceIds.push(id);
      continue;
    }
    if (owned.some((credential) => credential.fingerprint === key.fingerprint)) {
      report.legacyDevicesAlreadyMigrated.push(id);
      continue;
    }
    if (owned.length > 0) {
      report.partiallyMigratedMismatchDeviceIds.push(id);
      continue;
    }
    const otherOwner = credentialOwnerByFingerprint.get(key.fingerprint);
    if (otherOwner !== undefined && otherOwner !== id) {
      report.legacyFingerprintConflictDeviceIds.push(id);
      continue;
    }
    if (!(device.createdAt instanceof Date)) {
      report.legacyDevicesMissingCreatedAtIds.push(id);
      continue;
    }
    if (inconsistent) continue;
    legacyFingerprintOwners.set(key.fingerprint, [
      ...(legacyFingerprintOwners.get(key.fingerprint) ?? []),
      id,
    ]);
    candidates.push({
      deviceId: device._id,
      publicKeyPem: key.publicKeyPem,
      fingerprint: key.fingerprint,
      status: device.status === 'REVOKED' ? 'REVOKED' : 'ACTIVE',
      activatedAt: device.createdAt,
      revokedAt: device.status === 'REVOKED' ? (device.revokedAt ?? null) : null,
      revocationId: device.status === 'REVOKED' ? (device.revocationId ?? null) : null,
    });
  }

  const plan: PlannedCredential[] = [];
  for (const candidate of candidates) {
    const owners = legacyFingerprintOwners.get(candidate.fingerprint) ?? [];
    if (owners.length > 1) {
      report.duplicateLegacyFingerprintDeviceIds.push(String(candidate.deviceId));
    } else {
      plan.push(candidate);
      report.legacyDevicesPendingCredential.push(String(candidate.deviceId));
    }
  }

  const blocking: Array<[string[], string]> = [
    [report.suspectedPrivateKeyDeviceIds, 'legacy device(s) store suspected private key material'],
    [report.invalidLegacyKeyDeviceIds, 'legacy device(s) with an invalid public key'],
    [report.duplicateLegacyFingerprintDeviceIds, 'legacy device(s) sharing a public key'],
    [
      report.legacyFingerprintConflictDeviceIds,
      'legacy device(s) whose key belongs to another device credential',
    ],
    [
      report.partiallyMigratedMismatchDeviceIds,
      'device(s) whose credential does not match the legacy key',
    ],
    [report.orphanCredentialIds, 'orphan credential(s) without a device'],
    [report.devicesWithoutCredentialIds, 'device(s) without any credential or legacy key'],
    [report.inconsistentStateDeviceIds, 'device(s) with inconsistent state or revocation evidence'],
    [
      report.legacyDevicesMissingCreatedAtIds,
      'legacy device(s) without createdAt; activation dates cannot be invented',
    ],
  ];
  for (const [ids, label] of blocking) {
    if (ids.length > 0) report.blockingReasons.push(`Found ${ids.length} ${label}`);
  }
  report.canMigrateSafely = report.blockingReasons.length === 0;
  return { report, plan };
}

/** Read-only preflight. Never mutates documents or indexes and never prints key material. */
export async function inspectDeviceMigrationPreflight(db: MongoDb): Promise<DeviceMigrationReport> {
  return (await analyze(db)).report;
}

export async function ensureDeclaredDeviceIndexesOnDb(db: MongoDb): Promise<void> {
  for (const model of DEVICE_DOMAIN_MODELS) {
    const collectionName = model.collection.name;
    try {
      await db.createCollection(collectionName);
    } catch (error) {
      if (!(error instanceof Error) || !/already exists|NamespaceExists/i.test(error.message)) {
        throw error;
      }
    }
    for (const [fields, indexOptions] of model.schema.indexes()) {
      await db.collection(collectionName).createIndex(fields as Record<string, 1 | -1>, {
        ...(typeof indexOptions.name === 'string' ? { name: indexOptions.name } : {}),
        ...(indexOptions.unique === true ? { unique: true } : {}),
        ...(indexOptions.partialFilterExpression
          ? { partialFilterExpression: indexOptions.partialFilterExpression }
          : {}),
        ...(typeof indexOptions.expireAfterSeconds === 'number'
          ? { expireAfterSeconds: indexOptions.expireAfterSeconds }
          : {}),
      });
    }
  }
}

async function insertPlannedCredential(
  db: MongoDb,
  planned: PlannedCredential,
  now: Date,
  generateKeyId: () => string,
): Promise<void> {
  const collection = db.collection(DeviceCredentialModel.collection.name);
  for (let attempt = 1; ; attempt += 1) {
    try {
      // $setOnInsert only: an existing credential is never overwritten or resurrected.
      await collection.updateOne(
        { fingerprint: planned.fingerprint },
        {
          $setOnInsert: {
            deviceId: planned.deviceId,
            keyId: generateKeyId(),
            algorithm: 'Ed25519',
            publicKey: planned.publicKeyPem,
            fingerprint: planned.fingerprint,
            status: planned.status,
            activatedAt: planned.activatedAt,
            expiresAt: null,
            revokedAt: planned.revokedAt,
            revocationId: planned.revocationId,
            createdAt: now,
            updatedAt: now,
          },
        },
        { upsert: true },
      );
      return;
    } catch (error) {
      if (
        isDuplicateKeyError(error) &&
        duplicateKeyIndexName(error) === 'device_credential_key_id_unique' &&
        attempt < 3
      ) {
        continue;
      }
      throw error;
    }
  }
}

async function recordMigration(db: MongoDb, now: Date): Promise<void> {
  await db
    .collection<{ _id: string }>(DEVICE_MIGRATION_COLLECTION)
    .updateOne(
      { _id: DEVICE_FOUNDATION_MIGRATION_ID },
      { $setOnInsert: { completedAt: now, version: 1 } },
      { upsert: true },
    );
}

/**
 * Explicit, idempotent TKT-014 migration:
 * 1. Aborts without mutations when the preflight finds anything not verifiably resolvable.
 * 2. Creates missing collections and declared indexes (never drops or syncs indexes).
 * 3. Creates one credential per legacy key with $setOnInsert. Revoked devices only receive a
 *    REVOKED credential backed by their existing revocation record.
 * 4. Postflight: re-inspects, asserts critical indexes and records the migration marker.
 * Legacy `publicKey`/`algorithm` fields are left untouched on Device and never used to authorize.
 */
export async function applyDeviceFoundationMigration(
  db: MongoDb,
  options: {
    now?: Date;
    log?: (message: string) => void;
    generateKeyId?: () => string;
    onStep?: (step: string) => Promise<void> | void;
  } = {},
): Promise<DeviceMigrationReport> {
  const now = options.now ?? new Date();
  const log = options.log ?? (() => undefined);
  const { report, plan } = await analyze(db);
  if (!report.canMigrateSafely) {
    throw new DeviceMigrationBlockedError(
      `Device migration aborted: ${report.blockingReasons.join('; ')}`,
      report,
    );
  }

  await ensureDeclaredDeviceIndexesOnDb(db);
  await options.onStep?.('after_indexes');

  if (plan.length > 0) log(`Creating ${plan.length} credential(s) from legacy device keys`);
  for (const planned of plan) {
    await insertPlannedCredential(db, planned, now, options.generateKeyId ?? generateDeviceKeyId);
    await options.onStep?.('after_credential');
  }

  const postflight = (await analyze(db)).report;
  if (!postflight.canMigrateSafely || postflight.legacyDevicesPendingCredential.length > 0) {
    throw new DeviceMigrationBlockedError(
      'Device migration postflight failed; migration marker was not recorded',
      postflight,
    );
  }
  await assertCriticalDeviceIndexes(db);
  await recordMigration(db, now);
  return { ...postflight, migrationRecorded: true };
}

/**
 * Non-production bootstrap helper: records the marker only when there is nothing to migrate.
 * Legacy data always requires the explicit migration.
 */
export async function recordDeviceMigrationIfNothingToMigrate(db: MongoDb): Promise<boolean> {
  const { report, plan } = await analyze(db);
  if (report.migrationRecorded) return true;
  if (!report.canMigrateSafely || plan.length > 0) return false;
  await assertCriticalDeviceIndexes(db);
  await recordMigration(db, new Date());
  return true;
}
