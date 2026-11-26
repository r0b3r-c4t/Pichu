import { z } from 'zod';
import type { Types } from 'mongoose';
import {
  INVITATION_STATUSES,
  MEMBERSHIP_ROLES,
  type InvitationStatus,
  type MembershipRole,
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

export const invitationPublicSchema = z.strictObject({
  id: objectIdSchema,
  vehicleId: objectIdSchema,
  inviteeUserId: objectIdSchema,
  permissions: z.array(z.string()),
  status: z.enum(INVITATION_STATUSES),
  expiresAt: z.string().datetime(),
});
export type InvitationPublic = z.infer<typeof invitationPublicSchema>;

export function invitationPublicData(invitation: {
  _id: Types.ObjectId;
  vehicleId: Types.ObjectId;
  inviteeUserId: Types.ObjectId;
  permissions: string[];
  status: InvitationStatus | string;
  expiresAt: Date;
}): InvitationPublic {
  return invitationPublicSchema.parse({
    id: String(invitation._id),
    vehicleId: String(invitation.vehicleId),
    inviteeUserId: String(invitation.inviteeUserId),
    permissions: invitation.permissions,
    status: invitation.status,
    expiresAt: invitation.expiresAt.toISOString(),
  });
}

export const membershipPublicSchema = z.strictObject({
  vehicleId: objectIdSchema,
  userId: objectIdSchema,
  role: z.enum(MEMBERSHIP_ROLES),
  permissions: z.array(z.string()),
});
export type MembershipPublic = z.infer<typeof membershipPublicSchema>;

export function membershipPublicData(membership: {
  vehicleId: Types.ObjectId;
  userId: Types.ObjectId;
  role: MembershipRole | string;
  permissions: string[];
}): MembershipPublic {
  return membershipPublicSchema.parse({
    vehicleId: String(membership.vehicleId),
    userId: String(membership.userId),
    role: membership.role,
    permissions: membership.permissions,
  });
}
