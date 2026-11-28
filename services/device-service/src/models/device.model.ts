import mongoose, { type HydratedDocument, type Model, Schema, Types, model } from 'mongoose';
import { DEVICE_METADATA_LIMITS, type DeviceMetadata } from '@pichu/contracts';

export const DEVICE_STATUSES = ['PENDING', 'ACTIVE', 'REVOKED'] as const;
export type DeviceStatus = (typeof DEVICE_STATUSES)[number];

export function emptyDeviceMetadata(): DeviceMetadata {
  return {
    name: null,
    manufacturer: null,
    hardwareModel: null,
    hardwareRevision: null,
    firmwareVersion: null,
    serialNumber: null,
  };
}

/**
 * Device identity and link state. ACTIVE describes the link only: a device is operational solely
 * while it also holds an ACTIVE, unexpired DeviceCredential. REVOKED is terminal.
 *
 * Legacy documents created before TKT-014 may still carry `publicKey`/`algorithm`. Those paths are
 * intentionally absent from this schema so they can never be read for authorization; they are
 * preserved untouched in MongoDB and consumed only by the explicit migration through the driver.
 */
export interface Device {
  identifier: string;
  vehicleId: Types.ObjectId | null;
  /** Audit/context only: user whose authorization Vehicle asserted when requesting registration. */
  requestedByUserId: Types.ObjectId | null;
  /**
   * Enrollment context: Vehicle membership ID under which registration was authorized.
   * Device stores and compares this identifier for enrollment continuity; it never evaluates
   * whether the membership grants permissions. Historical pre-TKT-015 documents may have `null`.
   */
  requestedByMembershipId: Types.ObjectId | null;
  /** Audit only: actor that completed the proof-of-possession link. Never an access grant. */
  linkedByUserId: Types.ObjectId | null;
  linkedAt: Date | null;
  status: DeviceStatus;
  revokedAt: Date | null;
  revocationId: Types.ObjectId | null;
  lastSeenAt: Date | null;
  /** Descriptive metadata only; never used for authorization, crypto trust, or attestation. */
  metadata: DeviceMetadata;
  createdAt: Date;
  updatedAt: Date;
}

export type DeviceDocument = HydratedDocument<Device>;

const deviceMetadataSubschema = new Schema<DeviceMetadata>(
  {
    name: { type: String, default: null, maxlength: DEVICE_METADATA_LIMITS.name },
    manufacturer: { type: String, default: null, maxlength: DEVICE_METADATA_LIMITS.manufacturer },
    hardwareModel: { type: String, default: null, maxlength: DEVICE_METADATA_LIMITS.hardwareModel },
    hardwareRevision: {
      type: String,
      default: null,
      maxlength: DEVICE_METADATA_LIMITS.hardwareRevision,
    },
    firmwareVersion: {
      type: String,
      default: null,
      maxlength: DEVICE_METADATA_LIMITS.firmwareVersion,
    },
    serialNumber: { type: String, default: null, maxlength: DEVICE_METADATA_LIMITS.serialNumber },
  },
  { _id: false },
);

const deviceSchema = new Schema<Device>(
  {
    identifier: {
      type: String,
      required: true,
      trim: true,
      minlength: 1,
      maxlength: 128,
      immutable: true,
    },
    vehicleId: { type: Schema.Types.ObjectId, default: null, immutable: true },
    requestedByUserId: { type: Schema.Types.ObjectId, default: null, immutable: true },
    requestedByMembershipId: { type: Schema.Types.ObjectId, default: null, immutable: true },
    linkedByUserId: { type: Schema.Types.ObjectId, default: null },
    linkedAt: { type: Date, default: null },
    status: { type: String, enum: DEVICE_STATUSES, required: true, default: 'PENDING' },
    revokedAt: { type: Date, default: null },
    revocationId: { type: Schema.Types.ObjectId, default: null },
    lastSeenAt: { type: Date, default: null },
    metadata: { type: deviceMetadataSubschema, default: emptyDeviceMetadata },
  },
  { timestamps: true },
);

const LIFECYCLE_PATHS = ['status', 'revokedAt', 'revocationId'] as const;

/**
 * Identity, enrollment context, link audit and lifecycle paths. Through Mongoose they change only
 * in the two atomic transitions below; every other write touching them is rejected.
 */
const PROTECTED_DEVICE_PATHS = [
  '_id',
  'identifier',
  'vehicleId',
  'requestedByUserId',
  'requestedByMembershipId',
  'linkedByUserId',
  'linkedAt',
  'status',
  'revokedAt',
  'revocationId',
] as const;
const LINK_TRANSITION_PATHS = ['status', 'linkedByUserId', 'linkedAt'] as const;
const REVOCATION_TRANSITION_PATHS = ['status', 'revokedAt', 'revocationId'] as const;

class DeviceWriteProtectionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DeviceWriteProtectionError';
  }
}

function touchesPath(path: string, root: string): boolean {
  return path === root || path.startsWith(`${root}.`);
}

function isProtectedDevicePath(path: string): boolean {
  return PROTECTED_DEVICE_PATHS.some((root) => touchesPath(path, root));
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isValidDate(value: unknown): value is Date {
  return value instanceof Date && !Number.isNaN(value.getTime());
}

/** Every path an update document reads or writes, including both sides of `$rename`. */
function updatePaths(update: Record<string, unknown>): string[] {
  const paths: string[] = [];
  for (const [key, value] of Object.entries(update)) {
    if (!key.startsWith('$')) {
      paths.push(key);
      continue;
    }
    if (!isPlainObject(value)) {
      throw new DeviceWriteProtectionError('Unsupported device update operator shape');
    }
    for (const [path, operand] of Object.entries(value)) {
      paths.push(path);
      if (key === '$rename') {
        if (typeof operand !== 'string') {
          throw new DeviceWriteProtectionError('Unsupported device $rename target');
        }
        paths.push(operand);
      }
    }
  }
  return paths;
}

/**
 * Returns the `$set` of an update consisting solely of `$set` with exactly `paths` (plus the
 * timestamp plugin's `updatedAt`), or `null` for any other shape.
 */
function exactTransitionSet(
  update: Record<string, unknown>,
  paths: readonly string[],
): Record<string, unknown> | null {
  if (Object.keys(update).some((key) => key !== '$set')) return null;
  const set = update.$set;
  if (!isPlainObject(set)) return null;
  const keys = Object.keys(set).filter((key) => key !== 'updatedAt');
  return keys.length === paths.length && paths.every((path) => Object.hasOwn(set, path))
    ? set
    : null;
}

type DeviceUpdateKind = 'NEUTRAL' | 'METADATA' | 'LINK' | 'REVOCATION';

function classifyDeviceUpdate(update: unknown): DeviceUpdateKind {
  if (Array.isArray(update)) {
    throw new DeviceWriteProtectionError('Update pipelines are not allowed on devices');
  }
  if (!isPlainObject(update)) return 'NEUTRAL';
  const paths = updatePaths(update);
  if (!paths.some(isProtectedDevicePath)) {
    return paths.some((path) => touchesPath(path, 'metadata')) ? 'METADATA' : 'NEUTRAL';
  }

  const link = exactTransitionSet(update, LINK_TRANSITION_PATHS);
  if (
    link?.status === 'ACTIVE' &&
    mongoose.isObjectIdOrHexString(link.linkedByUserId) &&
    isValidDate(link.linkedAt)
  ) {
    return 'LINK';
  }
  const revocation = exactTransitionSet(update, REVOCATION_TRANSITION_PATHS);
  if (
    revocation?.status === 'REVOKED' &&
    isValidDate(revocation.revokedAt) &&
    mongoose.isObjectIdOrHexString(revocation.revocationId)
  ) {
    return 'REVOCATION';
  }
  throw new DeviceWriteProtectionError(
    'Device identity, link and lifecycle fields change only through atomic link or revocation',
  );
}

/** True when an update document could change lifecycle paths. Pipelines are treated as such. */
export function updateTouchesLifecyclePaths(update: unknown): boolean {
  if (Array.isArray(update)) return true;
  if (typeof update !== 'object' || update === null) return false;
  return Object.entries(update).some(([key, value]) =>
    key.startsWith('$')
      ? typeof value === 'object' &&
        value !== null &&
        LIFECYCLE_PATHS.some((path) => Object.hasOwn(value, path))
      : (LIFECYCLE_PATHS as readonly string[]).includes(key),
  );
}

deviceSchema.post('init', function rememberPersistedStatus() {
  this.$locals.persistedStatus = this.status;
});
deviceSchema.post('save', function rememberSavedStatus() {
  this.$locals.persistedStatus = this.status;
});

/**
 * Application-level write guard. Protected paths change only through:
 *
 * - Link: `$set` of exactly `status: 'ACTIVE'`, `linkedByUserId` and `linkedAt`, applied to one
 *   document that is still PENDING, bound to a vehicle, carries no link or revocation audit, and
 *   whose original requester (with enrollment membership) is the linking actor.
 * - Revocation: `$set` of exactly `status: 'REVOKED'`, `revokedAt` and `revocationId`, applied to
 *   one PENDING or ACTIVE document without revocation audit. Link audit is left untouched.
 *
 * Preconditions are appended to the same filter, so they are evaluated atomically against the
 * persisted document rather than against a previously read copy. Metadata updates never match a
 * REVOKED device. Pipelines, upserts, `overwriteImmutable`, replacements, `bulkWrite` and
 * `insertMany` are rejected outright. None of this protects against the raw MongoDB driver,
 * database administrators, or calls that opt out of middleware (`middleware: false`).
 */
interface GuardedDeviceUpdateQuery {
  getOptions(): { upsert?: unknown };
  mongooseOptions(): { overwriteImmutable?: unknown };
  getUpdate(): unknown;
  and(conditions: Record<string, unknown>[]): unknown;
}

function guardDeviceUpdate(query: GuardedDeviceUpdateQuery, singleDocument: boolean): void {
  if (query.getOptions().upsert) {
    throw new DeviceWriteProtectionError('Device upserts are not allowed');
  }
  if (query.mongooseOptions().overwriteImmutable) {
    throw new DeviceWriteProtectionError('Device immutable paths cannot be overwritten');
  }

  const kind = classifyDeviceUpdate(query.getUpdate());
  if (kind === 'NEUTRAL') return;
  if (kind === 'METADATA') {
    query.and([{ status: { $ne: 'REVOKED' } }]);
    return;
  }
  if (!singleDocument) {
    throw new DeviceWriteProtectionError('Device transitions apply to a single document');
  }
  if (kind === 'LINK') {
    const update = query.getUpdate() as { $set: { linkedByUserId: unknown } };
    query.and([
      {
        status: 'PENDING',
        vehicleId: { $ne: null },
        requestedByUserId: update.$set.linkedByUserId,
        requestedByMembershipId: { $ne: null },
        linkedByUserId: null,
        linkedAt: null,
        revokedAt: null,
        revocationId: null,
      },
    ]);
    return;
  }
  query.and([{ status: { $in: ['PENDING', 'ACTIVE'] }, revokedAt: null, revocationId: null }]);
}

deviceSchema.pre(['updateOne', 'findOneAndUpdate'], function guardSingleDeviceUpdate() {
  guardDeviceUpdate(this, true);
});
deviceSchema.pre('updateMany', function guardDeviceUpdateMany() {
  guardDeviceUpdate(this, false);
});

function rejectDeviceWrite(): never {
  throw new DeviceWriteProtectionError('Device documents cannot be replaced or bulk-written');
}

deviceSchema.pre(['replaceOne', 'findOneAndReplace'], rejectDeviceWrite);
deviceSchema.pre('bulkWrite', rejectDeviceWrite);
deviceSchema.pre('insertMany', rejectDeviceWrite);

function rejectDeviceDeletion(): never {
  throw new DeviceWriteProtectionError('Devices are never deleted; revocation is terminal');
}

/**
 * Deleting a Device would erase its revocation history and free its globally unique identifier,
 * so every Mongoose deletion path is rejected (`findByIdAndDelete` runs as `findOneAndDelete`).
 * Like the rest of this guard, it does not cover the raw driver, database administrators, or
 * calls that opt out of middleware.
 */
deviceSchema.pre(
  ['deleteOne', 'deleteMany', 'findOneAndDelete'],
  { document: false, query: true },
  rejectDeviceDeletion,
);
deviceSchema.pre('deleteOne', { document: true, query: false }, rejectDeviceDeletion);

/**
 * Document saves may create PENDING registrations and change unprotected paths only. Metadata
 * changes are conditioned on the persisted status through `$where`, so a document loaded before
 * a concurrent revocation fails with `DocumentNotFoundError` instead of writing.
 */
deviceSchema.pre('save', function guardDeviceSave() {
  if (this.isNew) {
    if (
      this.status !== 'PENDING' ||
      !this.vehicleId ||
      !this.requestedByUserId ||
      this.linkedByUserId !== null ||
      this.linkedAt !== null ||
      this.revokedAt !== null ||
      this.revocationId !== null
    ) {
      throw new DeviceWriteProtectionError(
        'New devices must be persisted as PENDING registrations',
      );
    }
    return;
  }

  const protectedModified = PROTECTED_DEVICE_PATHS.some((path) => this.isModified(path));
  const metadataModified = this.isModified('metadata');
  if (this.$locals.persistedStatus === 'REVOKED' && (protectedModified || metadataModified)) {
    throw new DeviceWriteProtectionError('REVOKED devices are terminal');
  }
  if (protectedModified) {
    throw new DeviceWriteProtectionError(
      'Device identity, link and lifecycle fields change only through atomic link or revocation',
    );
  }
  if (metadataModified) {
    this.$where = { ...this.$where, status: { $ne: 'REVOKED' } };
  }
});

deviceSchema.pre('validate', function validateDeviceInvariants() {
  if (
    !this.isNew &&
    this.$locals.persistedStatus === 'REVOKED' &&
    (LIFECYCLE_PATHS.some((path) => this.isModified(path)) || this.isModified('metadata'))
  ) {
    this.invalidate('status', 'REVOKED devices are terminal');
  }
  if (this.isNew && (this.status !== 'PENDING' || !this.vehicleId || !this.requestedByUserId)) {
    this.invalidate('status', 'New devices must be PENDING with vehicleId and requestedByUserId');
  }
  if (this.status === 'PENDING' && (this.linkedByUserId !== null || this.linkedAt !== null)) {
    this.invalidate('status', 'PENDING devices cannot carry link audit fields');
  }
  if (this.status === 'ACTIVE' && !this.vehicleId) {
    this.invalidate('vehicleId', 'ACTIVE devices require vehicleId');
  }
  if (this.status === 'REVOKED' && (!this.revokedAt || !this.revocationId)) {
    this.invalidate('status', 'REVOKED devices require revokedAt and revocationId');
  }
  if (this.status !== 'REVOKED' && (this.revokedAt !== null || this.revocationId !== null)) {
    this.invalidate('status', 'Only REVOKED devices can carry revocation fields');
  }
});

/** Name preserved from the pre-TKT-014 `unique: true` path option; global, including REVOKED. */
deviceSchema.index({ identifier: 1 }, { name: 'identifier_1', unique: true });
/** Supports per-vehicle device lookups and future vehicle-scoped revocation sweeps. */
deviceSchema.index({ vehicleId: 1, status: 1 }, { name: 'device_vehicle_status_idx' });
/** Supports deterministic `(createdAt ASC, _id ASC)` keyset pagination per vehicle without SORT. */
deviceSchema.index(
  { vehicleId: 1, createdAt: 1, _id: 1 },
  { name: 'device_vehicle_created_id_idx' },
);

export const DeviceModel: Model<Device> =
  (mongoose.models.Device as Model<Device> | undefined) ?? model<Device>('Device', deviceSchema);
