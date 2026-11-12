import { z } from 'zod';
import {
  objectIdSchema,
  pageInfoSchema,
  paginationQuerySchema,
  requestIdSchema,
} from './common.js';

export const vehicleNameSchema = z.string().trim().min(1).max(120);
export const membershipRoleSchema = z.enum(['OWNER', 'MEMBER']);
export const membershipPermissionSchema = z.string().trim().min(1).max(64);
export const invitationStatusSchema = z.enum(['PENDING', 'ACCEPTED', 'REVOKED', 'EXPIRED']);

export const vehicleSummarySchema = z.strictObject({
  id: objectIdSchema,
  name: vehicleNameSchema,
  make: z.string().trim().max(80).nullable(),
  model: z.string().trim().max(80).nullable(),
  year: z.number().int().min(1886).max(2100).nullable(),
  engine: z.string().trim().max(40).nullable(),
  ownerUserId: objectIdSchema,
});
export type VehicleSummary = z.infer<typeof vehicleSummarySchema>;

/** Public creation DTO. The authenticated owner is not supplied by the client. */
export const vehicleCreateRequestSchema = z.strictObject({
  name: vehicleNameSchema,
  make: z.string().trim().max(80).nullable().optional(),
  model: z.string().trim().max(80).nullable().optional(),
  year: z.number().int().min(1886).max(2100).nullable().optional(),
  engine: z.string().trim().max(40).nullable().optional(),
});
export type VehicleCreateRequest = z.infer<typeof vehicleCreateRequestSchema>;

export const vehicleCreateResponseSchema = z.strictObject({
  vehicleId: objectIdSchema,
  message: z.string().optional(),
  data: vehicleSummarySchema.optional(),
  requestId: requestIdSchema.optional(),
});
export type VehicleCreateResponse = z.infer<typeof vehicleCreateResponseSchema>;

export const membershipSchema = z.strictObject({
  vehicleId: objectIdSchema,
  userId: objectIdSchema,
  role: membershipRoleSchema,
  permissions: z.array(membershipPermissionSchema).max(100),
});
export type Membership = z.infer<typeof membershipSchema>;

export const vehicleListQuerySchema = paginationQuerySchema;
export type VehicleListQuery = z.infer<typeof vehicleListQuerySchema>;

export const vehicleListResponseSchema = z.strictObject({
  vehicles: z.array(vehicleSummarySchema),
  page: pageInfoSchema.optional(),
  requestId: requestIdSchema.optional(),
});
export type VehicleListResponse = z.infer<typeof vehicleListResponseSchema>;

export const vehicleDetailResponseSchema = vehicleSummarySchema.extend({
  requestId: requestIdSchema.optional(),
});
export type VehicleDetailResponse = z.infer<typeof vehicleDetailResponseSchema>;

export const vehicleParamsSchema = z.strictObject({
  vehicleId: objectIdSchema,
});
export type VehicleParams = z.infer<typeof vehicleParamsSchema>;

export const invitationParamsSchema = z.strictObject({
  invitationId: objectIdSchema,
});
export type InvitationParams = z.infer<typeof invitationParamsSchema>;

/** Public invitation DTO; the authenticated caller supplies the inviter. */
export const publicInvitationCreateRequestSchema = z.strictObject({
  inviteeUserId: objectIdSchema,
  permissions: z.array(membershipPermissionSchema).max(100),
});
export type PublicInvitationCreateRequest = z.infer<typeof publicInvitationCreateRequestSchema>;

/** Internal Vehicle DTO after the caller identity has been derived. */
export const internalInvitationCreateRequestSchema = z.strictObject({
  inviterUserId: objectIdSchema,
  inviteeUserId: objectIdSchema,
  permissions: z.array(membershipPermissionSchema).max(100),
});
export type InternalInvitationCreateRequest = z.infer<typeof internalInvitationCreateRequestSchema>;

export const invitationCreateResponseSchema = z.strictObject({
  invitationId: objectIdSchema,
  status: invitationStatusSchema,
  message: z.string().optional(),
  data: z
    .strictObject({
      id: objectIdSchema,
      vehicleId: objectIdSchema,
      inviteeUserId: objectIdSchema,
      permissions: z.array(membershipPermissionSchema).max(100),
      status: invitationStatusSchema,
      expiresAt: z.string().datetime(),
    })
    .optional(),
  requestId: requestIdSchema.optional(),
});
export type InvitationCreateResponse = z.infer<typeof invitationCreateResponseSchema>;

export const invitationAcceptRequestSchema = z.strictObject({
  userId: objectIdSchema,
});
export type InvitationAcceptRequest = z.infer<typeof invitationAcceptRequestSchema>;

export const invitationAcceptResponseSchema = z.strictObject({
  accepted: z.literal(true),
  vehicleId: objectIdSchema,
  message: z.string().optional(),
  data: membershipSchema.optional(),
  requestId: requestIdSchema.optional(),
});
export type InvitationAcceptResponse = z.infer<typeof invitationAcceptResponseSchema>;

/** Vehicle's public response after Device accepts a registration; activation is still pending. */
export const vehicleDeviceRegistrationResponseSchema = z.strictObject({
  deviceId: objectIdSchema,
  status: z.literal('PENDING'),
  message: z.string(),
  data: z.strictObject({
    deviceId: objectIdSchema,
    vehicleId: objectIdSchema,
    status: z.literal('PENDING'),
  }),
  requestId: requestIdSchema,
});
export type VehicleDeviceRegistrationResponse = z.infer<
  typeof vehicleDeviceRegistrationResponseSchema
>;
