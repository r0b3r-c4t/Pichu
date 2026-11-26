import { z } from 'zod';
import {
  objectIdSchema,
  pageInfoSchema,
  paginationQuerySchema,
  requestIdSchema,
} from './common.js';

function containsControlCharacter(value: string): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 0x1f || codePoint === 0x7f;
  });
}

/**
 * Bounded vehicle text. Control characters are rejected on the raw value, before trimming,
 * so tabs or line breaks cannot be silently removed; empty or whitespace-only values fail.
 */
function vehicleTextSchema(maxLength: number) {
  return z
    .string()
    .refine((value) => !containsControlCharacter(value), {
      message: 'Vehicle text must not contain control characters',
    })
    .trim()
    .min(1)
    .max(maxLength);
}

export const VEHICLE_TEXT_LIMITS = {
  name: 120,
  make: 80,
  model: 80,
  generation: 60,
  trim: 80,
  bodyStyle: 60,
  engine: 80,
  transmission: 60,
  fuelType: 60,
  archiveReason: 256,
} as const;

export const VEHICLE_YEAR_RANGE = { min: 1886, max: 2100 } as const;

/** Closed list of client-editable vehicle properties. */
export const VEHICLE_MUTABLE_FIELDS = [
  'name',
  'make',
  'model',
  'generation',
  'trim',
  'year',
  'bodyStyle',
  'engine',
  'transmission',
  'fuelType',
] as const;
export type VehicleMutableField = (typeof VEHICLE_MUTABLE_FIELDS)[number];

export const vehicleNameSchema = vehicleTextSchema(VEHICLE_TEXT_LIMITS.name);
export const vehicleYearSchema = z
  .number()
  .int()
  .min(VEHICLE_YEAR_RANGE.min)
  .max(VEHICLE_YEAR_RANGE.max);
export const membershipRoleSchema = z.enum(['OWNER', 'MEMBER']);
export const membershipPermissionSchema = z.string().trim().min(1).max(64);
export const invitationStatusSchema = z.enum(['PENDING', 'ACCEPTED', 'REVOKED', 'EXPIRED']);

const vehicleDescriptiveFields = {
  make: vehicleTextSchema(VEHICLE_TEXT_LIMITS.make).nullable(),
  model: vehicleTextSchema(VEHICLE_TEXT_LIMITS.model).nullable(),
  generation: vehicleTextSchema(VEHICLE_TEXT_LIMITS.generation).nullable(),
  trim: vehicleTextSchema(VEHICLE_TEXT_LIMITS.trim).nullable(),
  year: vehicleYearSchema.nullable(),
  bodyStyle: vehicleTextSchema(VEHICLE_TEXT_LIMITS.bodyStyle).nullable(),
  engine: vehicleTextSchema(VEHICLE_TEXT_LIMITS.engine).nullable(),
  transmission: vehicleTextSchema(VEHICLE_TEXT_LIMITS.transmission).nullable(),
  fuelType: vehicleTextSchema(VEHICLE_TEXT_LIMITS.fuelType).nullable(),
};

/** Intrinsic vehicle properties, independent from the caller's relationship to the vehicle. */
export const vehicleSummarySchema = z.strictObject({
  id: objectIdSchema,
  name: vehicleNameSchema,
  ...vehicleDescriptiveFields,
  ownerUserId: objectIdSchema,
});
export type VehicleSummary = z.infer<typeof vehicleSummarySchema>;

/** Vehicle as seen by the authenticated caller: `role` is the caller's active membership role. */
export const vehicleAccessViewSchema = vehicleSummarySchema.extend({
  role: membershipRoleSchema,
});
export type VehicleAccessView = z.infer<typeof vehicleAccessViewSchema>;

/** Vehicle as returned to its canonical owner after a create or update. */
export const vehicleOwnerViewSchema = vehicleSummarySchema.extend({
  role: z.literal('OWNER'),
});
export type VehicleOwnerView = z.infer<typeof vehicleOwnerViewSchema>;

/** Public creation DTO. The authenticated owner is not supplied by the client. */
export const vehicleCreateRequestSchema = z.strictObject({
  name: vehicleNameSchema,
  make: vehicleDescriptiveFields.make.optional(),
  model: vehicleDescriptiveFields.model.optional(),
  generation: vehicleDescriptiveFields.generation.optional(),
  trim: vehicleDescriptiveFields.trim.optional(),
  year: vehicleDescriptiveFields.year.optional(),
  bodyStyle: vehicleDescriptiveFields.bodyStyle.optional(),
  engine: vehicleDescriptiveFields.engine.optional(),
  transmission: vehicleDescriptiveFields.transmission.optional(),
  fuelType: vehicleDescriptiveFields.fuelType.optional(),
});
export type VehicleCreateRequest = z.infer<typeof vehicleCreateRequestSchema>;

/** Internal Vehicle DTO after the owner identity has been derived from the verified JWT. */
export const internalVehicleCreateRequestSchema = vehicleCreateRequestSchema.extend({
  userId: objectIdSchema,
});
export type InternalVehicleCreateRequest = z.infer<typeof internalVehicleCreateRequestSchema>;

export const vehicleCreateResponseSchema = z.strictObject({
  vehicleId: objectIdSchema,
  message: z.string().optional(),
  data: vehicleOwnerViewSchema.optional(),
  requestId: requestIdSchema.optional(),
});
export type VehicleCreateResponse = z.infer<typeof vehicleCreateResponseSchema>;

const vehicleUpdateFields = {
  name: vehicleNameSchema.optional(),
  make: vehicleDescriptiveFields.make.optional(),
  model: vehicleDescriptiveFields.model.optional(),
  generation: vehicleDescriptiveFields.generation.optional(),
  trim: vehicleDescriptiveFields.trim.optional(),
  year: vehicleDescriptiveFields.year.optional(),
  bodyStyle: vehicleDescriptiveFields.bodyStyle.optional(),
  engine: vehicleDescriptiveFields.engine.optional(),
  transmission: vehicleDescriptiveFields.transmission.optional(),
  fuelType: vehicleDescriptiveFields.fuelType.optional(),
};

function hasVehicleMutableField(value: Partial<Record<VehicleMutableField, unknown>>): boolean {
  return VEHICLE_MUTABLE_FIELDS.some((field) => value[field] !== undefined);
}

const atLeastOneVehicleField = {
  message: 'At least one vehicle field must be provided',
};

/**
 * Public partial update. An omitted field keeps its value, `null` clears an optional field,
 * and `name` can never be cleared.
 */
export const vehicleUpdateRequestSchema = z
  .strictObject(vehicleUpdateFields)
  .refine(hasVehicleMutableField, atLeastOneVehicleField);
export type VehicleUpdateRequest = z.infer<typeof vehicleUpdateRequestSchema>;

/** Internal update DTO; the derived `userId` never counts as an update field. */
export const internalVehicleUpdateRequestSchema = z
  .strictObject({ ...vehicleUpdateFields, userId: objectIdSchema })
  .refine(hasVehicleMutableField, atLeastOneVehicleField);
export type InternalVehicleUpdateRequest = z.infer<typeof internalVehicleUpdateRequestSchema>;

export const vehicleUpdateResponseSchema = z.strictObject({
  vehicleId: objectIdSchema,
  message: z.string().optional(),
  data: vehicleOwnerViewSchema,
  requestId: requestIdSchema.optional(),
});
export type VehicleUpdateResponse = z.infer<typeof vehicleUpdateResponseSchema>;

export const vehicleArchiveReasonSchema = vehicleTextSchema(VEHICLE_TEXT_LIMITS.archiveReason);

/** Optional archive body; a request without a body is equivalent to `{}`. */
export const vehicleArchiveRequestSchema = z.strictObject({
  reason: vehicleArchiveReasonSchema.optional(),
});
export type VehicleArchiveRequest = z.infer<typeof vehicleArchiveRequestSchema>;

export const internalVehicleArchiveRequestSchema = vehicleArchiveRequestSchema.extend({
  userId: objectIdSchema,
});
export type InternalVehicleArchiveRequest = z.infer<typeof internalVehicleArchiveRequestSchema>;

export const vehicleArchiveResponseSchema = z.strictObject({
  vehicleId: objectIdSchema,
  status: z.literal('ARCHIVED'),
  archivedAt: z.string().datetime(),
  message: z.string().optional(),
  requestId: requestIdSchema.optional(),
});
export type VehicleArchiveResponse = z.infer<typeof vehicleArchiveResponseSchema>;

export const membershipSchema = z.strictObject({
  vehicleId: objectIdSchema,
  userId: objectIdSchema,
  role: membershipRoleSchema,
  permissions: z.array(membershipPermissionSchema).max(100),
});
export type Membership = z.infer<typeof membershipSchema>;

/**
 * Opaque keyset cursor (base64url). It is neither encrypted nor signed: it only positions the
 * next page and never grants access; authorization is re-evaluated on every page.
 */
export const vehicleListCursorSchema = z
  .string()
  .min(1)
  .max(256)
  .regex(/^[A-Za-z0-9_-]+$/, 'Invalid pagination cursor');

export const vehicleListQuerySchema = paginationQuerySchema.extend({
  cursor: vehicleListCursorSchema.optional(),
  role: membershipRoleSchema.optional(),
});
export type VehicleListQuery = z.infer<typeof vehicleListQuerySchema>;

/** Internal list query after the caller identity has been derived from the verified JWT. */
export const internalVehicleListQuerySchema = vehicleListQuerySchema.extend({
  userId: objectIdSchema,
});
export type InternalVehicleListQuery = z.infer<typeof internalVehicleListQuerySchema>;

export const vehicleListPageSchema = pageInfoSchema.extend({
  nextCursor: vehicleListCursorSchema.nullable(),
});

export const vehicleListResponseSchema = z.strictObject({
  vehicles: z.array(vehicleAccessViewSchema),
  page: vehicleListPageSchema,
  requestId: requestIdSchema.optional(),
});
export type VehicleListResponse = z.infer<typeof vehicleListResponseSchema>;

export const vehicleDetailResponseSchema = vehicleAccessViewSchema.extend({
  requestId: requestIdSchema.optional(),
});
export type VehicleDetailResponse = z.infer<typeof vehicleDetailResponseSchema>;

/** Internal single-vehicle query; only the derived caller identity is accepted. */
export const internalVehicleGetQuerySchema = z.strictObject({
  userId: objectIdSchema,
});
export type InternalVehicleGetQuery = z.infer<typeof internalVehicleGetQuerySchema>;

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
