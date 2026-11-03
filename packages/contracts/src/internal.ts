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
