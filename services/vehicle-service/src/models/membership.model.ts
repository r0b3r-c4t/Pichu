import mongoose, { type HydratedDocument, type Model, Schema, Types, model } from 'mongoose';
import {
  containsControlCharacter,
  isDelegableMembershipPermission,
  isKnownPermission,
  MEMBERSHIP_ROLES,
  MEMBERSHIP_STATUSES,
  normalizeOptionalText,
  validatePermissionSet,
  type MembershipRole,
  type MembershipStatus,
} from './vehicle-constants.js';

export interface Membership {
  vehicleId: Types.ObjectId;
  userId: Types.ObjectId;
  role: MembershipRole;
  permissions: string[];
  status: MembershipStatus;
  sourceInvitationId: Types.ObjectId | null;
  grantedByUserId: Types.ObjectId;
  updatedByUserId: Types.ObjectId | null;
  suspendedAt: Date | null;
  suspendedByUserId: Types.ObjectId | null;
  suspensionReason: string | null;
  revokedAt: Date | null;
  revokedByUserId: Types.ObjectId | null;
  revokeReason: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export type MembershipDocument = HydratedDocument<Membership>;

function optionalAuditReasonField() {
  return {
    type: String,
    default: null,
    set: normalizeOptionalText,
    maxlength: 256,
    validate: {
      validator: (value: string | null): boolean =>
        value === null || (value.length >= 1 && !containsControlCharacter(value)),
      message: 'Audit reason must not contain control characters',
    },
  };
}

const membershipSchema = new Schema<Membership>(
  {
    vehicleId: {
      type: Schema.Types.ObjectId,
      ref: 'Vehicle',
      required: true,
      immutable: true,
    },
    userId: {
      type: Schema.Types.ObjectId,
      required: true,
      immutable: true,
    },
    role: {
      type: String,
      enum: MEMBERSHIP_ROLES,
      required: true,
      immutable: true,
    },
    permissions: {
      type: [String],
      default: [],
      validate: {
        validator: (permissions: string[]): boolean =>
          validatePermissionSet(permissions, { maxItems: 100, allowPermission: isKnownPermission }),
        message: 'Membership permissions must be unique, known, and non-wildcard',
      },
    },
    status: {
      type: String,
      enum: MEMBERSHIP_STATUSES,
      required: true,
      default: 'ACTIVE',
    },
    sourceInvitationId: {
      type: Schema.Types.ObjectId,
      ref: 'Invitation',
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
    suspendedAt: {
      type: Date,
      default: null,
    },
    suspendedByUserId: {
      type: Schema.Types.ObjectId,
      default: null,
    },
    suspensionReason: optionalAuditReasonField(),
    revokedAt: {
      type: Date,
      default: null,
    },
    revokedByUserId: {
      type: Schema.Types.ObjectId,
      default: null,
    },
    revokeReason: optionalAuditReasonField(),
  },
  { timestamps: true },
);

membershipSchema.pre('validate', function validateMembershipInvariants() {
  if (this.role === 'OWNER') {
    if (
      this.status !== 'ACTIVE' ||
      this.sourceInvitationId !== null ||
      this.suspendedAt !== null ||
      this.suspendedByUserId !== null ||
      this.suspensionReason !== null ||
      this.revokedAt !== null ||
      this.revokedByUserId !== null ||
      this.revokeReason !== null
    ) {
      this.invalidate(
        'role',
        'OWNER membership must remain ACTIVE and cannot be suspended, revoked, or created from an invitation',
      );
    }
    return;
  }

  if (
    !validatePermissionSet(this.permissions, {
      maxItems: 100,
      allowPermission: isDelegableMembershipPermission,
    })
  ) {
    this.invalidate(
      'permissions',
      'MEMBER permissions must be unique, known, non-wildcard, and non-owner-reserved',
    );
  }

  if (this.status === 'ACTIVE') {
    if (
      this.suspendedAt !== null ||
      this.suspendedByUserId !== null ||
      this.suspensionReason !== null ||
      this.revokedAt !== null ||
      this.revokedByUserId !== null ||
      this.revokeReason !== null
    ) {
      this.invalidate(
        'status',
        'ACTIVE membership cannot contain suspension or revocation audit fields',
      );
    }
  } else if (this.status === 'SUSPENDED') {
    if (
      !(this.suspendedAt instanceof Date) ||
      this.suspendedByUserId === null ||
      this.revokedAt !== null ||
      this.revokedByUserId !== null ||
      this.revokeReason !== null
    ) {
      this.invalidate(
        'status',
        'SUSPENDED membership requires suspendedAt and suspendedByUserId without revocation fields',
      );
    }
  } else if (this.status === 'REVOKED') {
    if (!(this.revokedAt instanceof Date) || this.revokedByUserId === null) {
      this.invalidate('status', 'REVOKED membership requires revokedAt and revokedByUserId');
    }
  }
});

// Allows creating a new membership after REVOKED while preventing duplicate non-revoked memberships.
membershipSchema.index(
  { vehicleId: 1, userId: 1 },
  {
    name: 'membership_active_vehicle_user_unique',
    unique: true,
    partialFilterExpression: { revokedAt: null },
  },
);

// Enforces a single active OWNER per vehicle while allowing the same user to own multiple vehicles.
membershipSchema.index(
  { vehicleId: 1 },
  {
    name: 'membership_single_active_owner_unique',
    unique: true,
    partialFilterExpression: { role: 'OWNER', status: 'ACTIVE' },
  },
);

membershipSchema.index(
  { userId: 1, status: 1, vehicleId: 1 },
  { name: 'membership_user_status_vehicle_idx' },
);
membershipSchema.index(
  { vehicleId: 1, status: 1, role: 1 },
  { name: 'membership_vehicle_status_role_idx' },
);

export const MembershipModel: Model<Membership> =
  (mongoose.models.Membership as Model<Membership> | undefined) ??
  model<Membership>('Membership', membershipSchema);
