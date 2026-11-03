import { z } from 'zod';
import { objectIdSchema } from './common.js';

export const deviceStatusSchema = z.enum(['PENDING', 'ACTIVE', 'REVOKED']);
export const deviceIdentifierSchema = z.string().trim().min(1).max(128);
export const devicePublicKeySchema = z.string().trim().min(32).max(4096);

const deviceIdentitySchema = z.strictObject({
  deviceId: objectIdSchema,
  vehicleId: objectIdSchema.nullable(),
  identifier: deviceIdentifierSchema,
  status: deviceStatusSchema,
});

/** Public device representation. It contains no key material. */
export const deviceIdentityResponseSchema = deviceIdentitySchema;
export type DeviceIdentityResponse = z.infer<typeof deviceIdentityResponseSchema>;

export const deviceSummarySchema = deviceIdentitySchema.extend({
  lastSeenAt: z.string().datetime({ offset: true }).nullable(),
});
export type DeviceSummary = z.infer<typeof deviceSummarySchema>;

/**
 * Internal provisioning fields. userId and vehicleId are assertions from an
 * internal caller, not proof of authorization or device identity.
 * Authentication belongs to TKT-009 and linking authorization to Vehicle/Device
 * tickets; an identifier alone is not device identity proof.
 */
export const deviceRegistrationRequestSchema = z.strictObject({
  identifier: deviceIdentifierSchema,
  publicKey: devicePublicKeySchema,
  vehicleId: objectIdSchema,
  userId: objectIdSchema,
});
export type DeviceRegistrationRequest = z.infer<typeof deviceRegistrationRequestSchema>;

export const deviceRegistrationResponseSchema = z.strictObject({
  deviceId: objectIdSchema,
  status: z.literal('PENDING'),
});
export type DeviceRegistrationResponse = z.infer<typeof deviceRegistrationResponseSchema>;

export const deviceReferenceParamsSchema = z.strictObject({
  deviceId: objectIdSchema,
});
export type DeviceReferenceParams = z.infer<typeof deviceReferenceParamsSchema>;

/** Request body for the current internal revocation endpoint. */
export const deviceRevocationRequestSchema = z.strictObject({
  reason: z.string().trim().min(1).max(256).optional(),
});
export type DeviceRevocationRequest = z.infer<typeof deviceRevocationRequestSchema>;

export const deviceRevocationResponseSchema = z.strictObject({
  revoked: z.literal(true),
});
export type DeviceRevocationResponse = z.infer<typeof deviceRevocationResponseSchema>;

/** Event/audit shape reserved for a later revocation implementation. */
export const deviceRevocationSchema = z.strictObject({
  deviceId: objectIdSchema,
  revokedAt: z.string().datetime({ offset: true }),
  reason: z.string().trim().min(1).max(256).optional(),
});
export type DeviceRevocation = z.infer<typeof deviceRevocationSchema>;

/** Provisional linking DTOs; challenge protocol remains subject to TKT-015/TKT-022. */
export const deviceLinkRequestSchema = z.strictObject({
  vehicleId: objectIdSchema,
  deviceIdentifier: deviceIdentifierSchema,
});
export type DeviceLinkRequest = z.infer<typeof deviceLinkRequestSchema>;

export const deviceLinkChallengeSchema = z.strictObject({
  challengeId: objectIdSchema,
  challenge: z.string().min(32).max(512),
  expiresAt: z.string().datetime({ offset: true }),
});
export type DeviceLinkChallenge = z.infer<typeof deviceLinkChallengeSchema>;

export const deviceLinkCompletionSchema = z.strictObject({
  challengeId: objectIdSchema,
  proof: z.string().min(1).max(4096),
});
export type DeviceLinkCompletion = z.infer<typeof deviceLinkCompletionSchema>;

export const deviceLinkResultSchema = z.strictObject({
  deviceId: objectIdSchema,
  vehicleId: objectIdSchema,
  status: z.literal('ACTIVE'),
});
export type DeviceLinkResult = z.infer<typeof deviceLinkResultSchema>;

/** Current route response; the richer result remains a future protocol DTO. */
export const deviceLinkResponseSchema = z.strictObject({
  linked: z.literal(true),
});
export type DeviceLinkResponse = z.infer<typeof deviceLinkResponseSchema>;
