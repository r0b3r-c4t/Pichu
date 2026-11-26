import { z } from 'zod';
import { CONTRACTS_VERSION, requestIdSchema } from './common.js';

export const domainServiceNameSchema = z.enum([
  'identity-service',
  'vehicle-service',
  'device-service',
  'automation-service',
]);
export type DomainServiceName = z.infer<typeof domainServiceNameSchema>;

/** Services and the Gateway that may appear as an internal caller. */
export const internalCallerNameSchema = z.enum(['api-gateway', ...domainServiceNameSchema.options]);
export type InternalCallerName = z.infer<typeof internalCallerNameSchema>;

/** Backward-compatible name for the complete internal caller set. */
export const serviceNameSchema = internalCallerNameSchema;
export type ServiceName = z.infer<typeof serviceNameSchema>;

/** Decimal timestamp format; freshness is intentionally not checked here. */
export const internalTimestampSchema = z
  .string()
  .regex(/^\d+$/, 'Invalid internal timestamp')
  .refine((value) => Number.isSafeInteger(Number(value)), {
    message: 'Internal timestamp must be a safe integer',
  });
export type InternalTimestamp = z.infer<typeof internalTimestampSchema>;

/** Base64url signature format only; cryptographic verification belongs to TKT-009. */
export const internalSignatureSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9_-]+$/, 'Invalid internal signature format');
export type InternalSignature = z.infer<typeof internalSignatureSchema>;

/**
 * Normalized metadata and authentication-header format for internal calls.
 * This schema does not authenticate, validate freshness or prevent replay.
 */
export const internalRequestHeadersSchema = z.strictObject({
  'x-request-id': requestIdSchema,
  'x-service-name': internalCallerNameSchema,
  'x-contract-version': z.literal(CONTRACTS_VERSION),
  'x-timestamp': internalTimestampSchema,
  'x-signature': internalSignatureSchema,
});
export type InternalRequestHeaders = z.infer<typeof internalRequestHeadersSchema>;

export const internalResponseMetadataSchema = z.strictObject({
  requestId: requestIdSchema.optional(),
  contractVersion: z.literal(CONTRACTS_VERSION),
});
export type InternalResponseMetadata = z.infer<typeof internalResponseMetadataSchema>;

/** v2 transport formats only. These schemas do not authenticate a request. */
export const INTERNAL_AUTH_VERSION = '2' as const;
export const INTERNAL_AUTH_PROTOCOL = 'pichu-s2s-v2' as const;
export const internalEnvironmentSchema = z.enum(['development', 'test', 'staging', 'production']);
export type InternalEnvironment = z.infer<typeof internalEnvironmentSchema>;
export const internalKeyIdSchema = z.string().regex(/^[A-Za-z0-9_-]{1,64}(?![\s\S])/);
export const internalIdentifierV2Schema = z.string().regex(/^[A-Za-z0-9_-]{1,128}(?![\s\S])/);
export const internalTimestampV2Schema = z
  .string()
  .regex(/^[1-9][0-9]{0,15}(?![\s\S])/)
  .refine((value) => Number.isSafeInteger(Number(value)));
// The last character encodes four significant bits and two zero padding bits.
// Runtime crypto validation additionally decodes and re-encodes the value.
export const internalBytes32Schema = z
  .string()
  .regex(/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048](?![\s\S])/);
export const internalAuthorizationV2Schema = z
  .string()
  .max(8192)
  .regex(/^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?![\s\S])/);
export const internalUnsignedHeadersV2Schema = z.strictObject({
  'x-internal-auth-version': z.literal(INTERNAL_AUTH_VERSION),
  'x-service-name': internalCallerNameSchema,
  'x-service-audience': internalCallerNameSchema,
  'x-service-key-id': internalKeyIdSchema,
  'x-contract-version': z.literal(CONTRACTS_VERSION),
  'x-timestamp': internalTimestampV2Schema,
  'x-nonce': internalBytes32Schema,
  'x-request-id': internalIdentifierV2Schema,
  'x-internal-deadline': internalTimestampV2Schema,
  'content-type': z.literal('application/json').optional(),
  authorization: internalAuthorizationV2Schema.optional(),
  'idempotency-key': internalIdentifierV2Schema.optional(),
});
export type InternalUnsignedHeadersV2 = z.infer<typeof internalUnsignedHeadersV2Schema>;
export const internalRequestHeadersV2Schema = internalUnsignedHeadersV2Schema.extend({
  'x-signature': internalBytes32Schema,
});
export type InternalRequestHeadersV2 = z.infer<typeof internalRequestHeadersV2Schema>;
