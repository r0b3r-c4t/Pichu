import mongoose, { type HydratedDocument, type Model, Schema, Types, model } from 'mongoose';
import {
  containsControlCharacter,
  INVITATION_STATUSES,
  INVITATION_TARGET_ROLES,
  isDelegableMembershipPermission,
  normalizeOptionalText,
  validatePermissionSet,
  type InvitationStatus,
  type InvitationTargetRole,
} from './vehicle-constants.js';

export interface Invitation {
  vehicleId: Types.ObjectId;
  inviterUserId: Types.ObjectId;
  inviteeUserId: Types.ObjectId;
  targetRole: InvitationTargetRole;
  permissions: string[];
  status: InvitationStatus;
  expiresAt: Date;
  acceptedAt: Date | null;
  acceptedByUserId: Types.ObjectId | null;
  revokedAt: Date | null;
  revokedByUserId: Types.ObjectId | null;
  revokeReason: string | null;
  expiredAt: Date | null;
  updatedByUserId: Types.ObjectId | null;
  createdAt: Date;
  updatedAt: Date;
}

export type InvitationDocument = HydratedDocument<Invitation>;

const invitationSchema = new Schema<Invitation>(
  {
    vehicleId: {
      type: Schema.Types.ObjectId,
      ref: 'Vehicle',
      required: true,
      immutable: true,
    },
    inviterUserId: {
      type: Schema.Types.ObjectId,
      required: true,
      immutable: true,
    },
    inviteeUserId: {
      type: Schema.Types.ObjectId,
      required: true,
      immutable: true,
    },
    targetRole: {
      type: String,
      enum: INVITATION_TARGET_ROLES,
      required: true,
      default: 'MEMBER',
      immutable: true,
    },
    permissions: {
      type: [String],
      default: [],
      validate: {
        validator: (permissions: string[]): boolean =>
          validatePermissionSet(permissions, {
            maxItems: 100,
            allowPermission: isDelegableMembershipPermission,
          }),
        message:
          'Invitation permissions must be unique, known, non-wildcard, and delegable to MEMBER',
      },
    },
    status: {
      type: String,
      enum: INVITATION_STATUSES,
      required: true,
      default: 'PENDING',
    },
    expiresAt: {
      type: Date,
      required: true,
    },
    acceptedAt: {
      type: Date,
      default: null,
    },
    acceptedByUserId: {
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
    updatedByUserId: {
      type: Schema.Types.ObjectId,
      default: null,
    },
  },
  { timestamps: true },
);

invitationSchema.pre('validate', function validateInvitationInvariants() {
  if (this.inviterUserId && this.inviteeUserId && this.inviterUserId.equals(this.inviteeUserId)) {
    this.invalidate('inviteeUserId', 'Self-invitations are not allowed');
  }

  if (this.targetRole !== 'MEMBER') {
    this.invalidate('targetRole', 'Invitations can only grant MEMBER role');
  }

  if (this.status === 'PENDING') {
    if (
      this.acceptedAt !== null ||
      this.acceptedByUserId !== null ||
      this.revokedAt !== null ||
      this.revokedByUserId !== null ||
      this.revokeReason !== null ||
      this.expiredAt !== null
    ) {
      this.invalidate('status', 'PENDING invitation cannot contain terminal audit fields');
    }
  } else if (this.status === 'ACCEPTED') {
    if (
      !(this.acceptedAt instanceof Date) ||
      this.acceptedByUserId === null ||
      (this.inviteeUserId && !this.acceptedByUserId.equals(this.inviteeUserId)) ||
      this.revokedAt !== null ||
      this.revokedByUserId !== null ||
      this.revokeReason !== null ||
      this.expiredAt !== null
    ) {
      this.invalidate(
        'status',
        'ACCEPTED invitation requires acceptedAt and acceptedByUserId matching inviteeUserId',
      );
    }
  } else if (this.status === 'REVOKED') {
    if (
      !(this.revokedAt instanceof Date) ||
      this.revokedByUserId === null ||
      this.acceptedAt !== null ||
      this.acceptedByUserId !== null ||
      this.expiredAt !== null
    ) {
      this.invalidate('status', 'REVOKED invitation requires revokedAt and revokedByUserId');
    }
  } else if (this.status === 'EXPIRED') {
    if (
      !(this.expiredAt instanceof Date) ||
      this.acceptedAt !== null ||
      this.acceptedByUserId !== null ||
      this.revokedAt !== null ||
      this.revokedByUserId !== null ||
      this.revokeReason !== null
    ) {
      this.invalidate(
        'status',
        'EXPIRED invitation requires expiredAt without other terminal fields',
      );
    }
  }
});

// Prevents concurrent duplicate PENDING invitations while preserving ACCEPTED/REVOKED/EXPIRED history.
invitationSchema.index(
  { vehicleId: 1, inviteeUserId: 1 },
  {
    name: 'invitation_pending_vehicle_invitee_unique',
    unique: true,
    partialFilterExpression: { status: 'PENDING' },
  },
);
invitationSchema.index(
  { vehicleId: 1, status: 1, createdAt: -1 },
  { name: 'invitation_vehicle_status_created_idx' },
);
invitationSchema.index(
  { inviteeUserId: 1, status: 1, expiresAt: 1 },
  { name: 'invitation_invitee_status_expires_idx' },
);
invitationSchema.index({ status: 1, expiresAt: 1 }, { name: 'invitation_status_expires_idx' });

export const InvitationModel: Model<Invitation> =
  (mongoose.models.Invitation as Model<Invitation> | undefined) ??
  model<Invitation>('Invitation', invitationSchema);
