import { z } from 'zod';
import type { Types } from 'mongoose';
import {
  invitationAdminViewSchema,
  memberViewSchema,
  membershipSchema,
  receivedInvitationViewSchema,
  type InvitationAdminView,
  type MemberView,
  type Membership,
  type ReceivedInvitationView,
} from '@pichu/contracts';
import {
  MEMBERSHIP_ROLES,
  type InvitationStatus,
  type MembershipRole,
  type MembershipStatus,
} from '../models/vehicle-constants.js';

const objectIdSchema = z.string().regex(/^[a-f0-9]{24}$/);

/** Intrinsic vehicle properties; never includes the caller's role, status, or audit fields. */
export const vehiclePublicSchema = z.strictObject({
  id: objectIdSchema,
  name: z.string(),
  make: z.string().nullable(),
  model: z.string().nullable(),
  generation: z.string().nullable(),
  trim: z.string().nullable(),
  year: z.number().nullable(),
  bodyStyle: z.string().nullable(),
  engine: z.string().nullable(),
  transmission: z.string().nullable(),
  fuelType: z.string().nullable(),
  ownerUserId: objectIdSchema,
});
export type VehiclePublic = z.infer<typeof vehiclePublicSchema>;

/** Vehicle as seen by the caller; `role` is the caller's active membership role. */
export const vehicleAccessPublicSchema = vehiclePublicSchema.extend({
  role: z.enum(MEMBERSHIP_ROLES),
});
export type VehicleAccessPublic = z.infer<typeof vehicleAccessPublicSchema>;

export const vehicleOwnerPublicSchema = vehiclePublicSchema.extend({
  role: z.literal('OWNER'),
});
export type VehicleOwnerPublic = z.infer<typeof vehicleOwnerPublicSchema>;

export const vehicleArchivePublicSchema = z.strictObject({
  vehicleId: objectIdSchema,
  status: z.literal('ARCHIVED'),
  archivedAt: z.string().datetime(),
});
export type VehicleArchivePublic = z.infer<typeof vehicleArchivePublicSchema>;

interface VehicleProjectionSource {
  _id: Types.ObjectId;
  name: string;
  make?: string | null;
  model?: string | null;
  generation?: string | null;
  trim?: string | null;
  year?: number | null;
  bodyStyle?: string | null;
  engine?: string | null;
  transmission?: string | null;
  fuelType?: string | null;
  ownerUserId: Types.ObjectId;
}

export function vehiclePublicData(vehicle: VehicleProjectionSource): VehiclePublic {
  return vehiclePublicSchema.parse({
    id: String(vehicle._id),
    name: vehicle.name,
    make: vehicle.make ?? null,
    model: vehicle.model ?? null,
    generation: vehicle.generation ?? null,
    trim: vehicle.trim ?? null,
    year: vehicle.year ?? null,
    bodyStyle: vehicle.bodyStyle ?? null,
    engine: vehicle.engine ?? null,
    transmission: vehicle.transmission ?? null,
    fuelType: vehicle.fuelType ?? null,
    ownerUserId: String(vehicle.ownerUserId),
  });
}

export function vehicleAccessPublicData(
  vehicle: VehicleProjectionSource,
  role: MembershipRole | string,
): VehicleAccessPublic {
  return vehicleAccessPublicSchema.parse({ ...vehiclePublicData(vehicle), role });
}

export function vehicleOwnerPublicData(vehicle: VehicleProjectionSource): VehicleOwnerPublic {
  return vehicleOwnerPublicSchema.parse({ ...vehiclePublicData(vehicle), role: 'OWNER' });
}

export function vehicleArchivePublicData(vehicle: {
  _id: Types.ObjectId;
  status: string;
  archivedAt: Date | null;
}): VehicleArchivePublic {
  return vehicleArchivePublicSchema.parse({
    vehicleId: String(vehicle._id),
    status: vehicle.status,
    archivedAt: vehicle.archivedAt?.toISOString(),
  });
}

interface InvitationProjectionSource {
  _id: Types.ObjectId;
  vehicleId: Types.ObjectId;
  inviterUserId: Types.ObjectId;
  inviteeUserId: Types.ObjectId;
  permissions: string[];
  expiresAt: Date;
  createdAt: Date;
  acceptedAt?: Date | null;
  revokedAt?: Date | null;
  revokeReason?: string | null;
}

/** Issuer/owner view; `status` must be the effective status computed by the domain. */
export function invitationAdminViewData(
  invitation: InvitationProjectionSource,
  status: InvitationStatus,
): InvitationAdminView {
  return invitationAdminViewSchema.parse({
    invitationId: String(invitation._id),
    vehicleId: String(invitation.vehicleId),
    inviterUserId: String(invitation.inviterUserId),
    inviteeUserId: String(invitation.inviteeUserId),
    permissions: invitation.permissions,
    status,
    expiresAt: invitation.expiresAt.toISOString(),
    createdAt: invitation.createdAt.toISOString(),
    acceptedAt: invitation.acceptedAt?.toISOString() ?? null,
    revokedAt: invitation.revokedAt?.toISOString() ?? null,
    revokeReason: invitation.revokeReason ?? null,
  });
}

/** Invitee view: never exposes the issuer, the issuing membership, or audit fields. */
export function receivedInvitationViewData(
  invitation: InvitationProjectionSource,
  status: InvitationStatus,
  vehicleName: string | null,
): ReceivedInvitationView {
  return receivedInvitationViewSchema.parse({
    invitationId: String(invitation._id),
    vehicleId: String(invitation.vehicleId),
    vehicleName,
    permissions: invitation.permissions,
    status,
    expiresAt: invitation.expiresAt.toISOString(),
    createdAt: invitation.createdAt.toISOString(),
  });
}

interface MembershipProjectionSource {
  _id: Types.ObjectId;
  vehicleId: Types.ObjectId;
  userId: Types.ObjectId;
  role: MembershipRole | string;
  permissions: string[];
  status: MembershipStatus | string;
}

export function membershipPublicData(membership: MembershipProjectionSource): Membership {
  return membershipSchema.parse({
    membershipId: String(membership._id),
    vehicleId: String(membership.vehicleId),
    userId: String(membership.userId),
    role: membership.role,
    permissions: membership.permissions,
    status: membership.status,
  });
}

/** Owner-only administrative view; audit actors and reasons stay internal. */
export function memberViewData(
  membership: MembershipProjectionSource & {
    createdAt: Date;
    suspendedAt?: Date | null;
    revokedAt?: Date | null;
  },
): MemberView {
  return memberViewSchema.parse({
    ...membershipPublicData(membership),
    createdAt: membership.createdAt.toISOString(),
    suspendedAt: membership.suspendedAt?.toISOString() ?? null,
    revokedAt: membership.revokedAt?.toISOString() ?? null,
  });
}
