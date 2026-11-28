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
    vehicleId: { type: Schema.Types.ObjectId, default: null },
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

function isProtectedRevokedPath(path: string): boolean {
  return (
    (LIFECYCLE_PATHS as readonly string[]).includes(path) ||
    path === 'metadata' ||
    path.startsWith('metadata.')
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

function updateTouchesRevokedProtectedPaths(update: unknown): boolean {
  if (Array.isArray(update)) return true;
  if (typeof update !== 'object' || update === null) return false;
  return Object.entries(update).some(([key, value]) =>
    key.startsWith('$')
      ? typeof value === 'object' &&
        value !== null &&
        Object.keys(value).some(isProtectedRevokedPath)
      : isProtectedRevokedPath(key),
  );
}

deviceSchema.post('init', function rememberPersistedStatus() {
  this.$locals.persistedStatus = this.status;
});
deviceSchema.post('save', function rememberSavedStatus() {
  this.$locals.persistedStatus = this.status;
});

/**
 * Application-level guard: Mongoose updates touching lifecycle or metadata paths never match a
 * REVOKED device. It does not protect against the raw driver or database administrators.
 */
deviceSchema.pre(
  ['updateOne', 'updateMany', 'findOneAndUpdate'],
  function keepRevokedDevicesTerminal() {
    if (updateTouchesRevokedProtectedPaths(this.getUpdate())) {
      this.and([{ status: { $ne: 'REVOKED' } }]);
    }
  },
);
deviceSchema.pre(['replaceOne', 'findOneAndReplace'], function keepRevokedDevicesTerminal() {
  this.and([{ status: { $ne: 'REVOKED' } }]);
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
