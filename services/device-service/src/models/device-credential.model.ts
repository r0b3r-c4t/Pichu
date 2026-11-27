import mongoose, { type HydratedDocument, type Model, Schema, Types, model } from 'mongoose';
import { DEVICE_KEY_FINGERPRINT_PATTERN } from '../security/device-public-key.js';
import { updateTouchesLifecyclePaths } from './device.model.js';

export const DEVICE_CREDENTIAL_STATUSES = ['ACTIVE', 'REVOKED'] as const;
export type DeviceCredentialStatus = (typeof DEVICE_CREDENTIAL_STATUSES)[number];
export const DEVICE_KEY_ID_PATTERN = /^dk_[A-Za-z0-9_-]{22}$/;

/**
 * Sole source of truth for an ESP32 cryptographic identity. Stores only the canonical public key;
 * the private key is generated and kept on the device. An ACTIVE credential whose `expiresAt` has
 * elapsed authorizes nothing.
 */
export interface DeviceCredential {
  deviceId: Types.ObjectId;
  keyId: string;
  algorithm: 'Ed25519';
  publicKey: string;
  fingerprint: string;
  status: DeviceCredentialStatus;
  activatedAt: Date;
  expiresAt: Date | null;
  revokedAt: Date | null;
  revocationId: Types.ObjectId | null;
  createdAt: Date;
  updatedAt: Date;
}

export type DeviceCredentialDocument = HydratedDocument<DeviceCredential>;

const deviceCredentialSchema = new Schema<DeviceCredential>(
  {
    deviceId: { type: Schema.Types.ObjectId, required: true, immutable: true },
    keyId: {
      type: String,
      required: true,
      immutable: true,
      match: DEVICE_KEY_ID_PATTERN,
    },
    algorithm: { type: String, enum: ['Ed25519'], required: true, immutable: true },
    publicKey: { type: String, required: true, immutable: true, select: false },
    fingerprint: {
      type: String,
      required: true,
      immutable: true,
      match: DEVICE_KEY_FINGERPRINT_PATTERN,
    },
    status: { type: String, enum: DEVICE_CREDENTIAL_STATUSES, required: true },
    activatedAt: { type: Date, required: true, immutable: true },
    expiresAt: { type: Date, default: null, immutable: true },
    revokedAt: { type: Date, default: null },
    revocationId: { type: Schema.Types.ObjectId, default: null },
  },
  { timestamps: true, collection: 'device_credentials' },
);

deviceCredentialSchema.post('init', function rememberPersistedStatus() {
  this.$locals.persistedStatus = this.status;
});
deviceCredentialSchema.post('save', function rememberSavedStatus() {
  this.$locals.persistedStatus = this.status;
});

/**
 * Application-level guard: Mongoose updates touching lifecycle paths never match a REVOKED
 * credential. It does not protect against the raw driver or database administrators.
 */
deviceCredentialSchema.pre(
  ['updateOne', 'updateMany', 'findOneAndUpdate'],
  function keepRevokedCredentialsTerminal() {
    if (updateTouchesLifecyclePaths(this.getUpdate())) {
      this.and([{ status: { $ne: 'REVOKED' } }]);
    }
  },
);
deviceCredentialSchema.pre(
  ['replaceOne', 'findOneAndReplace'],
  function keepRevokedCredentialsTerminal() {
    this.and([{ status: { $ne: 'REVOKED' } }]);
  },
);

deviceCredentialSchema.pre('validate', function validateCredentialInvariants() {
  if (
    !this.isNew &&
    this.$locals.persistedStatus === 'REVOKED' &&
    (['status', 'revokedAt', 'revocationId'] as const).some((path) => this.isModified(path))
  ) {
    this.invalidate('status', 'REVOKED credentials are terminal');
  }
  if (this.status === 'ACTIVE' && (this.revokedAt !== null || this.revocationId !== null)) {
    this.invalidate('status', 'ACTIVE credentials cannot carry revocation fields');
  }
  if (this.status === 'REVOKED' && (!this.revokedAt || !this.revocationId)) {
    this.invalidate('status', 'REVOKED credentials require revokedAt and revocationId');
  }
  if (this.expiresAt && this.activatedAt && this.expiresAt <= this.activatedAt) {
    this.invalidate('expiresAt', 'expiresAt must be after activatedAt');
  }
});

/** Global, including REVOKED credentials: a key can never be reused by another device. */
deviceCredentialSchema.index(
  { fingerprint: 1 },
  { name: 'device_credential_fingerprint_unique', unique: true },
);
deviceCredentialSchema.index(
  { keyId: 1 },
  { name: 'device_credential_key_id_unique', unique: true },
);
deviceCredentialSchema.index(
  { deviceId: 1 },
  {
    name: 'device_credential_active_device_unique',
    unique: true,
    partialFilterExpression: { status: 'ACTIVE' },
  },
);
deviceCredentialSchema.index(
  { deviceId: 1, status: 1 },
  { name: 'device_credential_device_status_idx' },
);

/** ACTIVE, consistent (no revocation fields), already activated and not expired. */
export function isCredentialUsable(
  credential: Pick<
    DeviceCredential,
    'status' | 'expiresAt' | 'activatedAt' | 'revokedAt' | 'revocationId'
  >,
  now: Date,
): boolean {
  return (
    credential.status === 'ACTIVE' &&
    credential.revokedAt == null &&
    credential.revocationId == null &&
    credential.activatedAt instanceof Date &&
    credential.activatedAt.getTime() <= now.getTime() &&
    (credential.expiresAt == null || credential.expiresAt.getTime() > now.getTime())
  );
}

export const DeviceCredentialModel: Model<DeviceCredential> =
  (mongoose.models.DeviceCredential as Model<DeviceCredential> | undefined) ??
  model<DeviceCredential>('DeviceCredential', deviceCredentialSchema);
