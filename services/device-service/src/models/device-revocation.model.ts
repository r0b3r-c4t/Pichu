import mongoose, { type HydratedDocument, type Model, Schema, Types, model } from 'mongoose';
import { DEVICE_KEY_FINGERPRINT_PATTERN } from '../security/device-public-key.js';

export const DEVICE_REVOCATION_TARGET_TYPES = ['DEVICE', 'CREDENTIAL'] as const;
export type DeviceRevocationTargetType = (typeof DEVICE_REVOCATION_TARGET_TYPES)[number];

/** Closed catalog; free text is deliberately not stored to keep secrets and PII out of audit. */
export const DEVICE_REVOCATION_REASONS = [
  'SECURITY_COMPROMISE',
  'LOST',
  'REPLACED',
  'REGISTRATION_CANCELLED',
  'ADMINISTRATIVE',
] as const;
export type DeviceRevocationReason = (typeof DEVICE_REVOCATION_REASONS)[number];

export const DEVICE_REVOCATION_ACTOR_TYPES = ['USER', 'SERVICE', 'SYSTEM'] as const;
export type DeviceRevocationActorType = (typeof DEVICE_REVOCATION_ACTOR_TYPES)[number];
/** Internal callers whose authenticated requests may originate a revocation. */
export const TRUSTED_REVOCATION_SERVICES = ['vehicle-service'] as const;
export type TrustedRevocationService = (typeof TRUSTED_REVOCATION_SERVICES)[number];
export const DEVICE_REVOCATION_REQUEST_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;

export interface DeviceRevocationActorRecord {
  type: DeviceRevocationActorType;
  userId: Types.ObjectId | null;
  service: TrustedRevocationService | null;
}

/**
 * Durable, append-only revocation record. Mongoose middleware rejects ordinary updates and
 * deletes, but this is an application-level guard only: MongoDB administrators and direct driver
 * access can still modify the collection.
 */
export interface DeviceRevocation {
  targetType: DeviceRevocationTargetType;
  deviceId: Types.ObjectId;
  credentialId: Types.ObjectId | null;
  /** CREDENTIAL: the revoked key. DEVICE: the active key revoked with it, or null if none. */
  fingerprint: string | null;
  /** Historical snapshot of the device binding when revoked; not an authorization fact. */
  vehicleId: Types.ObjectId | null;
  reason: DeviceRevocationReason;
  actor: DeviceRevocationActorRecord;
  requestId: string;
  revokedAt: Date;
  createdAt: Date;
}

export type DeviceRevocationDocument = HydratedDocument<DeviceRevocation>;

const actorSchema = new Schema<DeviceRevocationActorRecord>(
  {
    type: { type: String, enum: DEVICE_REVOCATION_ACTOR_TYPES, required: true, immutable: true },
    userId: { type: Schema.Types.ObjectId, default: null, immutable: true },
    service: {
      type: String,
      enum: [...TRUSTED_REVOCATION_SERVICES, null],
      default: null,
      immutable: true,
    },
  },
  { _id: false },
);

const deviceRevocationSchema = new Schema<DeviceRevocation>(
  {
    targetType: {
      type: String,
      enum: DEVICE_REVOCATION_TARGET_TYPES,
      required: true,
      immutable: true,
    },
    deviceId: { type: Schema.Types.ObjectId, required: true, immutable: true },
    credentialId: { type: Schema.Types.ObjectId, default: null, immutable: true },
    fingerprint: {
      type: String,
      default: null,
      immutable: true,
      match: DEVICE_KEY_FINGERPRINT_PATTERN,
    },
    vehicleId: { type: Schema.Types.ObjectId, default: null, immutable: true },
    reason: { type: String, enum: DEVICE_REVOCATION_REASONS, required: true, immutable: true },
    actor: { type: actorSchema, required: true, immutable: true },
    requestId: {
      type: String,
      required: true,
      immutable: true,
      match: DEVICE_REVOCATION_REQUEST_ID_PATTERN,
    },
    revokedAt: { type: Date, required: true, immutable: true },
  },
  {
    timestamps: { createdAt: true, updatedAt: false },
    collection: 'device_revocations',
  },
);

deviceRevocationSchema.pre('validate', function validateRevocationInvariants() {
  if (this.targetType === 'DEVICE' && this.credentialId !== null) {
    this.invalidate('credentialId', 'DEVICE revocations cannot target a single credential');
  }
  if (this.targetType === 'CREDENTIAL' && (!this.credentialId || !this.fingerprint)) {
    this.invalidate('credentialId', 'CREDENTIAL revocations require credentialId and fingerprint');
  }
  const actor = this.actor;
  const validActor =
    !!actor &&
    ((actor.type === 'USER' && !!actor.userId && actor.service === 'vehicle-service') ||
      (actor.type === 'SERVICE' && actor.userId === null && actor.service === 'vehicle-service') ||
      (actor.type === 'SYSTEM' && actor.userId === null && actor.service === null));
  if (!validActor) this.invalidate('actor', 'Invalid revocation actor combination');
});

class AppendOnlyRevocationError extends Error {
  constructor() {
    super('Device revocation records are append-only');
    this.name = 'AppendOnlyRevocationError';
  }
}

function rejectMutation(): never {
  throw new AppendOnlyRevocationError();
}

deviceRevocationSchema.pre(
  [
    'updateOne',
    'updateMany',
    'findOneAndUpdate',
    'replaceOne',
    'findOneAndReplace',
    'deleteOne',
    'deleteMany',
    'findOneAndDelete',
  ],
  { document: false, query: true },
  rejectMutation,
);
deviceRevocationSchema.pre(
  ['deleteOne', 'updateOne'],
  { document: true, query: false },
  rejectMutation,
);
deviceRevocationSchema.pre('save', function rejectExistingSave() {
  if (!this.isNew) rejectMutation();
});
deviceRevocationSchema.pre('bulkWrite', rejectMutation);

deviceRevocationSchema.index(
  { deviceId: 1 },
  {
    name: 'device_revocation_device_target_unique',
    unique: true,
    partialFilterExpression: { targetType: 'DEVICE' },
  },
);
deviceRevocationSchema.index(
  { credentialId: 1 },
  {
    name: 'device_revocation_credential_target_unique',
    unique: true,
    partialFilterExpression: { targetType: 'CREDENTIAL' },
  },
);
deviceRevocationSchema.index(
  { deviceId: 1, revokedAt: -1 },
  { name: 'device_revocation_device_history_idx' },
);
deviceRevocationSchema.index(
  { vehicleId: 1, revokedAt: -1 },
  { name: 'device_revocation_vehicle_history_idx' },
);

export const DeviceRevocationModel: Model<DeviceRevocation> =
  (mongoose.models.DeviceRevocation as Model<DeviceRevocation> | undefined) ??
  model<DeviceRevocation>('DeviceRevocation', deviceRevocationSchema);
