import { z } from 'zod';
import {
  objectIdSchema,
  pageInfoSchema,
  paginationQuerySchema,
  requestIdSchema,
} from './common.js';
import { internalBytes32Schema } from './internal.js';

function containsControlCharacter(value: string): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 0x1f || codePoint === 0x7f;
  });
}

function boundedDeviceTextSchema(maxLength: number, pattern?: RegExp, patternMessage?: string) {
  const base = z
    .string()
    .refine((value) => !containsControlCharacter(value), {
      message: 'Device text must not contain control characters',
    })
    .trim()
    .min(1)
    .max(maxLength);
  return pattern ? base.regex(pattern, patternMessage) : base;
}

export const DEVICE_LINK_PROTOCOL_VERSION = 'pichu-device-link-v1' as const;

export const deviceStatusSchema = z.enum(['PENDING', 'ACTIVE', 'REVOKED']);
export type DeviceStatus = z.infer<typeof deviceStatusSchema>;

export const deviceCredentialEffectiveStatusSchema = z.enum(['ACTIVE', 'REVOKED', 'EXPIRED']);
export type DeviceCredentialEffectiveStatus = z.infer<typeof deviceCredentialEffectiveStatusSchema>;

export const DEVICE_REVOCATION_REASONS = [
  'SECURITY_COMPROMISE',
  'LOST',
  'REPLACED',
  'REGISTRATION_CANCELLED',
  'ADMINISTRATIVE',
] as const;
export type DeviceRevocationReason = (typeof DEVICE_REVOCATION_REASONS)[number];
export const deviceRevocationReasonSchema = z.enum(DEVICE_REVOCATION_REASONS);

export const deviceIdentifierSchema = boundedDeviceTextSchema(128);
export const devicePublicKeySchema = z.string().trim().min(32).max(4096);
export const deviceKeyIdSchema = z
  .string()
  .regex(/^dk_[A-Za-z0-9_-]{22}$/, 'Invalid device key identifier');
export const deviceFingerprintSchema = z
  .string()
  .regex(/^sha256:[a-f0-9]{64}$/, 'Invalid public key fingerprint');

/** Canonical 32-byte CSPRNG challenge nonce encoded as unpadded base64url (43 chars). */
export const deviceChallengeNonceSchema = internalBytes32Schema;

/** Canonical 64-byte Ed25519 signature encoded as unpadded base64url (86 chars, zero tail bits). */
export const deviceEd25519SignatureSchema = z
  .string()
  .regex(/^[A-Za-z0-9_-]{85}[AQgw]$/, 'Invalid canonical 64-byte base64url Ed25519 signature');

export const DEVICE_METADATA_LIMITS = {
  name: 80,
  manufacturer: 64,
  hardwareModel: 64,
  hardwareRevision: 32,
  firmwareVersion: 64,
  serialNumber: 64,
} as const;

export const DEVICE_METADATA_PATTERNS = {
  hardwareRevision: /^[A-Za-z0-9._+/ -]{1,32}$/,
  firmwareVersion: /^[A-Za-z0-9._+-]{1,64}$/,
  serialNumber: /^[A-Za-z0-9._:-]{1,64}$/,
} as const;

/** Closed list of descriptive, non-authoritative device metadata fields. */
export const DEVICE_METADATA_FIELDS = [
  'name',
  'manufacturer',
  'hardwareModel',
  'hardwareRevision',
  'firmwareVersion',
  'serialNumber',
] as const;
export type DeviceMetadataField = (typeof DEVICE_METADATA_FIELDS)[number];

const deviceMetadataFieldSchemas = {
  name: boundedDeviceTextSchema(DEVICE_METADATA_LIMITS.name).nullable(),
  manufacturer: boundedDeviceTextSchema(DEVICE_METADATA_LIMITS.manufacturer).nullable(),
  hardwareModel: boundedDeviceTextSchema(DEVICE_METADATA_LIMITS.hardwareModel).nullable(),
  hardwareRevision: boundedDeviceTextSchema(
    DEVICE_METADATA_LIMITS.hardwareRevision,
    DEVICE_METADATA_PATTERNS.hardwareRevision,
    'Invalid hardware revision format',
  ).nullable(),
  firmwareVersion: boundedDeviceTextSchema(
    DEVICE_METADATA_LIMITS.firmwareVersion,
    DEVICE_METADATA_PATTERNS.firmwareVersion,
    'Invalid firmware version format',
  ).nullable(),
  serialNumber: boundedDeviceTextSchema(
    DEVICE_METADATA_LIMITS.serialNumber,
    DEVICE_METADATA_PATTERNS.serialNumber,
    'Invalid serial number format',
  ).nullable(),
};

/** Normalized device metadata persisted and returned in responses. Never used for trust or auth. */
export const deviceMetadataSchema = z.strictObject(deviceMetadataFieldSchemas);
export type DeviceMetadata = z.infer<typeof deviceMetadataSchema>;

const deviceMetadataOptionalFields = {
  name: deviceMetadataFieldSchemas.name.optional(),
  manufacturer: deviceMetadataFieldSchemas.manufacturer.optional(),
  hardwareModel: deviceMetadataFieldSchemas.hardwareModel.optional(),
  hardwareRevision: deviceMetadataFieldSchemas.hardwareRevision.optional(),
  firmwareVersion: deviceMetadataFieldSchemas.firmwareVersion.optional(),
  serialNumber: deviceMetadataFieldSchemas.serialNumber.optional(),
};

/** Optional metadata supplied at registration time; omitted fields default to `null`. */
export const deviceMetadataInputSchema = z.strictObject(deviceMetadataOptionalFields);
export type DeviceMetadataInput = z.infer<typeof deviceMetadataInputSchema>;

function hasDeviceMetadataField(value: Partial<Record<DeviceMetadataField, unknown>>): boolean {
  return DEVICE_METADATA_FIELDS.some((field) => value[field] !== undefined);
}

const atLeastOneDeviceMetadataField = {
  message: 'At least one device metadata field must be provided',
};

/**
 * Public partial metadata update (`PATCH`). `null` clears a field, omitted preserves its value,
 * and an empty object `{}` is rejected.
 */
export const deviceMetadataUpdateRequestSchema = z
  .strictObject(deviceMetadataOptionalFields)
  .refine(hasDeviceMetadataField, atLeastOneDeviceMetadataField);
export type DeviceMetadataUpdateRequest = z.infer<typeof deviceMetadataUpdateRequestSchema>;

/** Gateway -> Vehicle metadata update DTO; `userId` never counts as a metadata field. */
export const internalVehicleDeviceMetadataUpdateRequestSchema = z
  .strictObject({ ...deviceMetadataOptionalFields, userId: objectIdSchema })
  .refine(hasDeviceMetadataField, atLeastOneDeviceMetadataField);
export type InternalVehicleDeviceMetadataUpdateRequest = z.infer<
  typeof internalVehicleDeviceMetadataUpdateRequestSchema
>;

/** Vehicle -> Device metadata update DTO after Vehicle has verified ownership/permissions. */
export const internalDeviceMetadataUpdateRequestSchema = z.strictObject({
  vehicleId: objectIdSchema,
  userId: objectIdSchema,
  metadata: deviceMetadataUpdateRequestSchema,
});
export type InternalDeviceMetadataUpdateRequest = z.infer<
  typeof internalDeviceMetadataUpdateRequestSchema
>;

const deviceIdentitySchema = z.strictObject({
  deviceId: objectIdSchema,
  vehicleId: objectIdSchema.nullable(),
  identifier: deviceIdentifierSchema,
  status: deviceStatusSchema,
});

/** Minimal public device identity shape. It contains no key material. */
export const deviceIdentityResponseSchema = deviceIdentitySchema;
export type DeviceIdentityResponse = z.infer<typeof deviceIdentityResponseSchema>;

export const deviceSummarySchema = deviceIdentitySchema.extend({
  lastSeenAt: z.string().datetime({ offset: true }).nullable(),
});
export type DeviceSummary = z.infer<typeof deviceSummarySchema>;

/** Public representation of the selected credential. Never exposes `publicKey`. */
export const deviceCredentialSummarySchema = z.strictObject({
  credentialId: objectIdSchema,
  keyId: deviceKeyIdSchema,
  algorithm: z.literal('Ed25519'),
  fingerprint: deviceFingerprintSchema,
  status: deviceCredentialEffectiveStatusSchema,
  usable: z.boolean(),
  activatedAt: z.string().datetime({ offset: true }),
  expiresAt: z.string().datetime({ offset: true }).nullable(),
  revokedAt: z.string().datetime({ offset: true }).nullable(),
});
export type DeviceCredentialSummary = z.infer<typeof deviceCredentialSummarySchema>;

/** Observational telemetry only; never inferred from `ACTIVE` or `operational`. */
export const deviceConnectivitySchema = z.strictObject({
  lastSeenAt: z.string().datetime({ offset: true }).nullable(),
});
export type DeviceConnectivity = z.infer<typeof deviceConnectivitySchema>;

/**
 * Public device detail view separating lifecycle status, effective credential state,
 * operational usability, observational connectivity, descriptive metadata, and revocation.
 */
export const deviceDetailSchema = z.strictObject({
  deviceId: objectIdSchema,
  vehicleId: objectIdSchema,
  identifier: deviceIdentifierSchema,
  status: deviceStatusSchema,
  operational: z.boolean(),
  credential: deviceCredentialSummarySchema,
  connectivity: deviceConnectivitySchema,
  metadata: deviceMetadataSchema,
  createdAt: z.string().datetime({ offset: true }),
  updatedAt: z.string().datetime({ offset: true }),
  linkedAt: z.string().datetime({ offset: true }).nullable(),
  revokedAt: z.string().datetime({ offset: true }).nullable(),
  revocationReason: deviceRevocationReasonSchema.nullable(),
});
export type DeviceDetail = z.infer<typeof deviceDetailSchema>;

export const deviceDetailResponseSchema = deviceDetailSchema.extend({
  requestId: requestIdSchema.optional(),
});
export type DeviceDetailResponse = z.infer<typeof deviceDetailResponseSchema>;

/**
 * Internal Device -> Vehicle record. Includes enrollment requester/membership context so Vehicle
 * can enforce membership-bound authorization without Device deciding user permissions.
 * Vehicle MUST strip these internal fields before returning public responses.
 */
export const internalDeviceRecordSchema = deviceDetailSchema.extend({
  requestedByUserId: objectIdSchema.nullable(),
  requestedByMembershipId: objectIdSchema.nullable(),
  revokedByUserId: objectIdSchema.nullable(),
});
export type InternalDeviceRecord = z.infer<typeof internalDeviceRecordSchema>;

export const internalDeviceDetailResponseSchema = z.strictObject({
  data: internalDeviceRecordSchema,
});
export type InternalDeviceDetailResponse = z.infer<typeof internalDeviceDetailResponseSchema>;

/** Public registration payload (`POST /api/vehicles/:vehicleId/devices`). */
export const publicDeviceRegistrationRequestSchema = z.strictObject({
  identifier: deviceIdentifierSchema,
  publicKey: devicePublicKeySchema,
  metadata: deviceMetadataInputSchema.optional(),
});
export type PublicDeviceRegistrationRequest = z.infer<typeof publicDeviceRegistrationRequestSchema>;

/** Gateway -> Vehicle registration payload with derived caller identity. */
export const internalVehicleDeviceRegistrationRequestSchema =
  publicDeviceRegistrationRequestSchema.extend({
    userId: objectIdSchema,
  });
export type InternalVehicleDeviceRegistrationRequest = z.infer<
  typeof internalVehicleDeviceRegistrationRequestSchema
>;

/**
 * Vehicle -> Device provisioning payload (`POST /internal/devices/register`).
 * `userId`, `membershipId`, and `vehicleId` are verified context assertions from `vehicle-service`.
 */
export const deviceRegistrationRequestSchema = z.strictObject({
  identifier: deviceIdentifierSchema,
  publicKey: devicePublicKeySchema,
  metadata: deviceMetadataInputSchema.optional(),
  vehicleId: objectIdSchema,
  userId: objectIdSchema,
  membershipId: objectIdSchema,
});
export type DeviceRegistrationRequest = z.infer<typeof deviceRegistrationRequestSchema>;

export const deviceRegistrationResponseSchema = z.strictObject({
  deviceId: objectIdSchema,
  status: z.literal('PENDING'),
  data: internalDeviceRecordSchema,
});
export type DeviceRegistrationResponse = z.infer<typeof deviceRegistrationResponseSchema>;

export const deviceReferenceParamsSchema = z.strictObject({
  deviceId: objectIdSchema,
});
export type DeviceReferenceParams = z.infer<typeof deviceReferenceParamsSchema>;

export const vehicleDeviceParamsSchema = z.strictObject({
  vehicleId: objectIdSchema,
  deviceId: objectIdSchema,
});
export type VehicleDeviceParams = z.infer<typeof vehicleDeviceParamsSchema>;

/** Public challenge request (`POST /api/vehicles/:vehicleId/devices/:deviceId/challenge`). */
export const publicDeviceChallengeRequestSchema = z.strictObject({});
export type PublicDeviceChallengeRequest = z.infer<typeof publicDeviceChallengeRequestSchema>;

/** Gateway -> Vehicle challenge request. */
export const internalVehicleDeviceChallengeRequestSchema = z.strictObject({
  userId: objectIdSchema,
});
export type InternalVehicleDeviceChallengeRequest = z.infer<
  typeof internalVehicleDeviceChallengeRequestSchema
>;

/** Vehicle -> Device challenge creation request. */
export const internalDeviceChallengeCreateRequestSchema = z.strictObject({
  vehicleId: objectIdSchema,
  userId: objectIdSchema,
  membershipId: objectIdSchema,
});
export type InternalDeviceChallengeCreateRequest = z.infer<
  typeof internalDeviceChallengeCreateRequestSchema
>;

/**
 * Authoritative challenge payload returned to the client so the device can sign the exact
 * canonical `pichu-device-link-v1` message without guessing any field.
 */
export const deviceLinkChallengeSchema = z.strictObject({
  protocol: z.literal(DEVICE_LINK_PROTOCOL_VERSION),
  challengeId: objectIdSchema,
  deviceId: objectIdSchema,
  vehicleId: objectIdSchema,
  credentialId: objectIdSchema,
  requestedByUserId: objectIdSchema,
  challenge: deviceChallengeNonceSchema,
  expiresAt: z.string().datetime({ offset: true }),
});
export type DeviceLinkChallenge = z.infer<typeof deviceLinkChallengeSchema>;

export const internalDeviceChallengeResponseSchema = z.strictObject({
  data: deviceLinkChallengeSchema,
});
export type InternalDeviceChallengeResponse = z.infer<typeof internalDeviceChallengeResponseSchema>;

/** Public link completion payload (`POST /api/vehicles/:vehicleId/devices/:deviceId/link`). */
export const deviceLinkCompletionSchema = z.strictObject({
  challengeId: objectIdSchema,
  challenge: deviceChallengeNonceSchema,
  signature: deviceEd25519SignatureSchema,
});
export type DeviceLinkCompletion = z.infer<typeof deviceLinkCompletionSchema>;

/** Gateway -> Vehicle link completion payload. */
export const internalVehicleDeviceLinkCompletionRequestSchema = deviceLinkCompletionSchema.extend({
  userId: objectIdSchema,
});
export type InternalVehicleDeviceLinkCompletionRequest = z.infer<
  typeof internalVehicleDeviceLinkCompletionRequestSchema
>;

/** Vehicle -> Device link completion payload. */
export const internalDeviceLinkCompleteRequestSchema = deviceLinkCompletionSchema.extend({
  vehicleId: objectIdSchema,
  userId: objectIdSchema,
  membershipId: objectIdSchema,
});
export type InternalDeviceLinkCompleteRequest = z.infer<
  typeof internalDeviceLinkCompleteRequestSchema
>;

export const deviceLinkResultSchema = z.strictObject({
  deviceId: objectIdSchema,
  vehicleId: objectIdSchema,
  status: z.literal('ACTIVE'),
});
export type DeviceLinkResult = z.infer<typeof deviceLinkResultSchema>;

/** Public revocation payload (`POST /api/vehicles/:vehicleId/devices/:deviceId/revoke`). */
export const deviceRevocationRequestSchema = z.strictObject({
  reason: deviceRevocationReasonSchema,
});
export type DeviceRevocationRequest = z.infer<typeof deviceRevocationRequestSchema>;

/** Gateway -> Vehicle revocation payload. */
export const internalVehicleDeviceRevokeRequestSchema = deviceRevocationRequestSchema.extend({
  userId: objectIdSchema,
});
export type InternalVehicleDeviceRevokeRequest = z.infer<
  typeof internalVehicleDeviceRevokeRequestSchema
>;

/** Vehicle -> Device revocation payload. */
export const internalDeviceRevokeRequestSchema = deviceRevocationRequestSchema.extend({
  vehicleId: objectIdSchema,
  userId: objectIdSchema,
});
export type InternalDeviceRevokeRequest = z.infer<typeof internalDeviceRevokeRequestSchema>;

export const deviceRevocationResponseSchema = z.strictObject({
  revoked: z.literal(true),
});
export type DeviceRevocationResponse = z.infer<typeof deviceRevocationResponseSchema>;

export const deviceRevocationSchema = z.strictObject({
  deviceId: objectIdSchema,
  revokedAt: z.string().datetime({ offset: true }),
  reason: deviceRevocationReasonSchema,
});
export type DeviceRevocation = z.infer<typeof deviceRevocationSchema>;

export const deviceListCursorSchema = z
  .string()
  .min(1)
  .max(256)
  .regex(/^[A-Za-z0-9_-]+$/, 'Invalid pagination cursor');

export const vehicleDeviceListQuerySchema = paginationQuerySchema.extend({
  cursor: deviceListCursorSchema.optional(),
  status: deviceStatusSchema.optional(),
});
export type VehicleDeviceListQuery = z.infer<typeof vehicleDeviceListQuerySchema>;

export const internalVehicleDeviceListQuerySchema = vehicleDeviceListQuerySchema.extend({
  userId: objectIdSchema,
});
export type InternalVehicleDeviceListQuery = z.infer<typeof internalVehicleDeviceListQuerySchema>;

export const vehicleDeviceListPageSchema = pageInfoSchema.extend({
  nextCursor: deviceListCursorSchema.nullable(),
});

export const vehicleDeviceListResponseSchema = z.strictObject({
  devices: z.array(deviceDetailSchema),
  page: vehicleDeviceListPageSchema,
  requestId: requestIdSchema.optional(),
});
export type VehicleDeviceListResponse = z.infer<typeof vehicleDeviceListResponseSchema>;

/** Vehicle -> Device keyset batch query (`GET /internal/vehicles/:vehicleId/devices`). */
export const internalDeviceCollectionQuerySchema = z
  .strictObject({
    limit: z.coerce.number().int().min(1).max(100).default(20),
    status: deviceStatusSchema.optional(),
    afterCreatedAt: z.string().datetime({ offset: true }).optional(),
    afterId: objectIdSchema.optional(),
  })
  .refine((query) => (query.afterCreatedAt === undefined) === (query.afterId === undefined), {
    message: 'afterCreatedAt and afterId must be provided together',
  });
export type InternalDeviceCollectionQuery = z.infer<typeof internalDeviceCollectionQuerySchema>;

export const internalDeviceCollectionResponseSchema = z.strictObject({
  devices: z.array(internalDeviceRecordSchema),
  hasMore: z.boolean(),
});
export type InternalDeviceCollectionResponse = z.infer<
  typeof internalDeviceCollectionResponseSchema
>;
