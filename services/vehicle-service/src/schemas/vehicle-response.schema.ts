import { z } from 'zod';
import type { Types } from 'mongoose';
import {
  INVITATION_STATUSES,
  MEMBERSHIP_ROLES,
  type InvitationStatus,
  type MembershipRole,
} from '../models/vehicle-constants.js';

const objectIdSchema = z.string().regex(/^[a-f0-9]{24}$/);

export const vehiclePublicSchema = z.strictObject({
  id: objectIdSchema,
  name: z.string(),
  make: z.string().nullable(),
  model: z.string().nullable(),
  year: z.number().nullable(),
  engine: z.string().nullable(),
  ownerUserId: objectIdSchema,
});
export type VehiclePublic = z.infer<typeof vehiclePublicSchema>;

export function vehiclePublicData(vehicle: {
  _id: Types.ObjectId;
  name: string;
  make?: string | null;
  model?: string | null;
  year?: number | null;
  engine?: string | null;
  ownerUserId: Types.ObjectId;
}): VehiclePublic {
  return vehiclePublicSchema.parse({
    id: String(vehicle._id),
    name: vehicle.name,
    make: vehicle.make ?? null,
    model: vehicle.model ?? null,
    year: vehicle.year ?? null,
    engine: vehicle.engine ?? null,
    ownerUserId: String(vehicle.ownerUserId),
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
