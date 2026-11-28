import {
  DEVICE_METADATA_LIMITS,
  deviceLinkCompletionSchema,
  deviceMetadataUpdateRequestSchema,
  deviceReferenceParamsSchema,
  deviceRevocationRequestSchema,
  invitationParamsSchema,
  invitationRevokeParamsSchema,
  invitationRevokeRequestSchema,
  memberLeaveRequestSchema,
  memberListQuerySchema,
  memberParamsSchema,
  memberPermissionsUpdateRequestSchema,
  memberReactivateRequestSchema,
  memberTransitionRequestSchema,
  publicDeviceChallengeRequestSchema,
  publicDeviceRegistrationRequestSchema,
  publicInvitationCreateRequestSchema,
  receivedInvitationListQuerySchema,
  vehicleDeviceListQuerySchema,
  vehicleDeviceParamsSchema,
  vehicleInvitationListQuerySchema,
  VEHICLE_TEXT_LIMITS,
  vehicleArchiveRequestSchema,
  vehicleCreateRequestSchema,
  vehicleListQuerySchema,
  vehicleParamsSchema,
  vehicleUpdateRequestSchema,
} from '@pichu/contracts';
import { gatewayErrorResponseSchema } from '@pichu/contracts';
import {
  emailVerificationRequestSchema,
  loginRequestSchema,
  passwordResetConfirmSchema,
  passwordResetRequestSchema,
  registerRequestSchema,
  verificationResendRequestSchema,
} from '@pichu/contracts';
import { z } from 'zod';

export const requestIdHeaderSchema = z.strictObject({
  'x-request-id': z
    .string()
    .trim()
    .min(1)
    .max(128)
    .regex(/^[A-Za-z0-9._:-]+$/),
});

export const bearerAuthorizationSchema = z
  .string()
  .regex(/^Bearer\s+[^\s]+$/, 'Invalid authorization header');

export const vehicleCreateBodySchema = vehicleCreateRequestSchema;
export const vehicleUpdateBodySchema = vehicleUpdateRequestSchema;

/**
 * Vehicle text limits apply after trimming, so Ajv must not enforce the generated raw
 * `maxLength` on them; the Zod contract shared with Vehicle remains the authoritative check.
 * `minLength: 1` stays: it never rejects a value Zod accepts, and it keeps Ajv type coercion
 * from turning `null` into `""` through the string branch of nullable fields.
 */
export function vehicleBodyJsonSchema(generated: Record<string, unknown>): Record<string, unknown> {
  const properties = generated.properties;
  if (typeof properties !== 'object' || properties === null) return generated;
  const limits: Readonly<Record<string, number>> = VEHICLE_TEXT_LIMITS;
  return {
    ...generated,
    properties: Object.fromEntries(
      Object.entries(properties).map(([field, property]) => {
        const limit = limits[field];
        return [field, limit === undefined ? property : relaxTrimmedText(property, limit)];
      }),
    ),
  };
}

function relaxTrimmedText(schema: unknown, limit: number): unknown {
  if (typeof schema !== 'object' || schema === null) return schema;
  const relaxed: Record<string, unknown> = { ...(schema as Record<string, unknown>) };
  if (Array.isArray(relaxed.anyOf)) {
    relaxed.anyOf = relaxed.anyOf.map((option: unknown) => relaxTrimmedText(option, limit));
  }
  if (relaxed.type === 'string') {
    delete relaxed.maxLength;
    delete relaxed.pattern;
    relaxed.description =
      `1-${limit} characters after trimming surrounding whitespace; ` +
      'control characters are rejected.';
  }
  return relaxed;
}

const DEVICE_TRIMMED_LIMITS: Readonly<Record<string, number>> = {
  identifier: 128,
  publicKey: 4096,
  ...DEVICE_METADATA_LIMITS,
};

export function deviceBodyJsonSchema(
  generated: Record<string, unknown>,
  options: { requireAtLeastOneProperty?: boolean } = {},
): Record<string, unknown> {
  const properties = generated.properties;
  if (typeof properties !== 'object' || properties === null) return generated;
  return {
    ...generated,
    ...(options.requireAtLeastOneProperty ? { minProperties: 1 } : {}),
    properties: Object.fromEntries(
      Object.entries(properties).map(([field, property]) => {
        if (field === 'metadata' && typeof property === 'object' && property !== null) {
          return [field, deviceBodyJsonSchema(property as Record<string, unknown>)];
        }
        const limit = DEVICE_TRIMMED_LIMITS[field];
        return [field, limit === undefined ? property : relaxTrimmedText(property, limit)];
      }),
    ),
  };
}

/** DELETE may be sent without a body; an optional strict `{ reason }` body is also accepted. */
export const vehicleArchiveBodySchema = z.union([z.undefined(), vehicleArchiveRequestSchema]);
export const vehicleListQueryInputSchema = vehicleListQuerySchema;
export const vehicleIdParamsInputSchema = vehicleParamsSchema;
export const invitationIdParamsInputSchema = invitationParamsSchema;
export const invitationCreateBodySchema = publicInvitationCreateRequestSchema;
export const invitationAcceptBodySchema = z.strictObject({});
export const vehicleInvitationListQueryInputSchema = vehicleInvitationListQuerySchema;
export const receivedInvitationListQueryInputSchema = receivedInvitationListQuerySchema;
export const invitationRevokeParamsInputSchema = invitationRevokeParamsSchema;
/** Bodies of the following transitions are optional; a missing body equals `{}`. */
export const invitationRevokeBodySchema = z.union([z.undefined(), invitationRevokeRequestSchema]);
export const memberListQueryInputSchema = memberListQuerySchema;
export const memberParamsInputSchema = memberParamsSchema;
export const memberPermissionsUpdateBodySchema = memberPermissionsUpdateRequestSchema;
export const memberTransitionBodySchema = z.union([z.undefined(), memberTransitionRequestSchema]);
export const memberReactivateBodySchema = z.union([z.undefined(), memberReactivateRequestSchema]);
export const memberLeaveBodySchema = memberLeaveRequestSchema;

export const deviceIdParamsInputSchema = deviceReferenceParamsSchema;
export const vehicleDeviceParamsInputSchema = vehicleDeviceParamsSchema;
export const deviceRegistrationBodySchema = publicDeviceRegistrationRequestSchema;
export const vehicleDeviceListQueryInputSchema = vehicleDeviceListQuerySchema;
export const deviceMetadataUpdateBodySchema = deviceMetadataUpdateRequestSchema;
export const deviceChallengeBodySchema = z.union([
  z.undefined(),
  publicDeviceChallengeRequestSchema,
]);
export const deviceLinkCompletionBodySchema = deviceLinkCompletionSchema;
export const deviceRevocationBodySchema = deviceRevocationRequestSchema;

export const emptyObjectSchema = z.strictObject({});
export const loginBodySchema = loginRequestSchema;
export const registerBodySchema = registerRequestSchema;
export const emailVerificationBodySchema = emailVerificationRequestSchema;
export const verificationResendBodySchema = verificationResendRequestSchema;
export const passwordResetRequestBodySchema = passwordResetRequestSchema;
export const passwordResetConfirmBodySchema = passwordResetConfirmSchema;
export const refreshRequestBodySchema = z.union([z.undefined(), z.strictObject({})]);
export const vehicleErrorResponseSchema = gatewayErrorResponseSchema;
