import mongoose, { type HydratedDocument, type Model, Schema, Types, model } from 'mongoose';
import {
  ACCESS_GRANT_CHANNELS,
  ACCESS_GRANT_SCOPE_TYPES,
  ACCESS_GRANT_STATUSES,
  containsControlCharacter,
  isAccessGrantPermissionForScope,
  isKnownPermission,
  isOwnerReservedPermission,
  normalizeOptionalText,
  validatePermissionSet,
  type AccessGrantChannel,
  type AccessGrantScopeType,
  type AccessGrantStatus,
} from './vehicle-constants.js';

export interface AccessGrant {
  vehicleId: Types.ObjectId;
  membershipId: Types.ObjectId;
  subjectUserId: Types.ObjectId;
  scopeType: AccessGrantScopeType;
  scopeResourceId: Types.ObjectId | null;
  channel: AccessGrantChannel;
  permissions: string[];
  status: AccessGrantStatus;
  startsAt: Date;
  expiresAt: Date | null;
  grantedByUserId: Types.ObjectId;
  updatedByUserId: Types.ObjectId | null;
  revokedAt: Date | null;
  revokedByUserId: Types.ObjectId | null;
  revokeReason: string | null;
  expiredAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export type AccessGrantDocument = HydratedDocument<AccessGrant>;

const accessGrantSchema = new Schema<AccessGrant>(
  {
    vehicleId: {
      type: Schema.Types.ObjectId,
      ref: 'Vehicle',
      required: true,
      immutable: true,
    },
    membershipId: {
      type: Schema.Types.ObjectId,
      ref: 'Membership',
      required: true,
      immutable: true,
    },
    subjectUserId: {
      type: Schema.Types.ObjectId,
      required: true,
      immutable: true,
    },
    scopeType: {
      type: String,
      enum: ACCESS_GRANT_SCOPE_TYPES,
      required: true,
      immutable: true,
    },
    scopeResourceId: {
      type: Schema.Types.ObjectId,
      default: null,
      immutable: true,
    },
    channel: {
      type: String,
      enum: ACCESS_GRANT_CHANNELS,
      required: true,
      default: 'ONLINE',
      immutable: true,
    },
    permissions: {
      type: [String],
      required: true,
      validate: {
        validator: (permissions: string[]): boolean =>
          validatePermissionSet(permissions, {
            minItems: 1,
            maxItems: 50,
            allowPermission: (permission) =>
              isKnownPermission(permission) && !isOwnerReservedPermission(permission),
          }),
        message:
          'AccessGrant permissions must be non-empty, unique, known, non-wildcard, and non-owner-reserved',
      },
    },
    status: {
      type: String,
      enum: ACCESS_GRANT_STATUSES,
      required: true,
      default: 'ACTIVE',
    },
    startsAt: {
      type: Date,
      required: true,
      default: Date.now,
      immutable: true,
    },
    expiresAt: {
      type: Date,
      default: null,
      immutable: true,
    },
    grantedByUserId: {
      type: Schema.Types.ObjectId,
      required: true,
      immutable: true,
    },
    updatedByUserId: {
      type: Schema.Types.ObjectId,
      default: null,
    },
    revokedAt: {
      type: Date,
      default: null,
    },
    revokedByUserId: {
      type: Schema.Types.ObjectId,
      default: null,
    },
    revokeReason: {
      type: String,
      default: null,
      set: normalizeOptionalText,
      maxlength: 256,
      validate: {
        validator: (value: string | null): boolean =>
          value === null || (value.length >= 1 && !containsControlCharacter(value)),
        message: 'Revoke reason must not contain control characters',
      },
    },
    expiredAt: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
    collection: 'access_grants',
  },
);

accessGrantSchema.pre('validate', function validateAccessGrantInvariants() {
  if (
    !ACCESS_GRANT_SCOPE_TYPES.includes(this.scopeType) ||
    !validatePermissionSet(this.permissions, {
      minItems: 1,
      maxItems: 50,
      allowPermission: (permission) => isAccessGrantPermissionForScope(this.scopeType, permission),
    })
  ) {
    this.invalidate(
      'permissions',
      'AccessGrant permissions must be valid for the specified scopeType',
    );
  }

  if (this.scopeType === 'VEHICLE' && this.scopeResourceId !== null) {
    this.invalidate('scopeResourceId', 'VEHICLE scope grants must have scopeResourceId = null');
  } else if (
    (this.scopeType === 'DEVICE' || this.scopeType === 'MODULE') &&
    this.scopeResourceId === null
  ) {
    this.invalidate(
      'scopeResourceId',
      `${this.scopeType} scope grants require a concrete scopeResourceId`,
    );
  }

  if (
    (this.channel === 'BLE_OFFLINE' || this.channel === 'ANY') &&
    !(this.expiresAt instanceof Date)
  ) {
    this.invalidate('expiresAt', `${this.channel} grants require a bounded expiresAt timestamp`);
  }

  if (this.startsAt instanceof Date && this.expiresAt instanceof Date) {
    if (this.expiresAt.getTime() <= this.startsAt.getTime()) {
      this.invalidate('expiresAt', 'expiresAt must be strictly greater than startsAt');
    }
  }

  if (this.status === 'ACTIVE') {
    if (
      this.revokedAt !== null ||
      this.revokedByUserId !== null ||
      this.revokeReason !== null ||
      this.expiredAt !== null
    ) {
      this.invalidate(
        'status',
        'ACTIVE grant cannot contain revocation or expiration audit fields',
      );
    }
  } else if (this.status === 'REVOKED') {
    if (
      !(this.revokedAt instanceof Date) ||
      this.revokedByUserId === null ||
      this.expiredAt !== null
    ) {
      this.invalidate('status', 'REVOKED grant requires revokedAt and revokedByUserId');
    }
  } else if (this.status === 'EXPIRED') {
    if (
      !(this.expiredAt instanceof Date) ||
      this.revokedAt !== null ||
      this.revokedByUserId !== null ||
      this.revokeReason !== null
    ) {
      this.invalidate('status', 'EXPIRED grant requires expiredAt without revocation fields');
    }
  }
});

// Multiple active grants per resource/channel are intentionally allowed (no unique scope index).
accessGrantSchema.index(
  { vehicleId: 1, subjectUserId: 1, status: 1, scopeType: 1, scopeResourceId: 1, expiresAt: 1 },
  { name: 'access_grant_lookup_idx' },
);
accessGrantSchema.index(
  { membershipId: 1, status: 1 },
  { name: 'access_grant_membership_status_idx' },
);
accessGrantSchema.index(
  { vehicleId: 1, scopeType: 1, scopeResourceId: 1, status: 1 },
  { name: 'access_grant_resource_status_idx' },
);
accessGrantSchema.index({ status: 1, expiresAt: 1 }, { name: 'access_grant_status_expires_idx' });

export const AccessGrantModel: Model<AccessGrant> =
  (mongoose.models.AccessGrant as Model<AccessGrant> | undefined) ??
  model<AccessGrant>('AccessGrant', accessGrantSchema);
