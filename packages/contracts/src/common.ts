import { z } from 'zod';

/** Protocol version, independent from the npm package SemVer. */
export const CONTRACTS_VERSION = 'v1' as const;

/** Canonical MongoDB ObjectId representation used on the HTTP wire. */
export const objectIdSchema = z.string().regex(/^[a-f0-9]{24}$/, 'Invalid object identifier');
export type ObjectId = z.infer<typeof objectIdSchema>;

function containsControlCharacter(value: string): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 0x1f || codePoint === 0x7f;
  });
}

/** Correlation identifier: trimmed, bounded and free of control characters. */
export const requestIdSchema = z
  .string()
  .trim()
  .min(1)
  .max(128)
  .refine((value) => !containsControlCharacter(value), {
    message: 'Request identifier must not contain control characters',
  });
export type RequestId = z.infer<typeof requestIdSchema>;

export const errorCodeSchema = z.enum([
  'VALIDATION_ERROR',
  'AUTHENTICATION_REQUIRED',
  'FORBIDDEN',
  'NOT_FOUND',
  'CONFLICT',
  'RATE_LIMITED',
  'INVALID_TOKEN',
  'OPERATION_FAILED',
]);
export type ErrorCode = z.infer<typeof errorCodeSchema>;

export const errorDetailsSchema = z.strictObject({
  code: errorCodeSchema,
  message: z.string().trim().min(1).max(200),
});
export type ErrorDetails = z.infer<typeof errorDetailsSchema>;

export const errorResponseSchema = z.strictObject({
  error: errorDetailsSchema,
  requestId: requestIdSchema.optional(),
});
export type ErrorResponse = z.infer<typeof errorResponseSchema>;

export const gatewayErrorResponseSchema = z.strictObject({
  error: z.string().trim().min(1).max(64),
  message: z.string().trim().min(1).max(500),
  details: z
    .array(
      z.strictObject({
        field: z.string().trim().min(1).max(128),
        message: z.string().trim().min(1).max(200),
      }),
    )
    .max(50)
    .optional(),
  requestId: requestIdSchema.optional(),
});
export type GatewayErrorResponse = z.infer<typeof gatewayErrorResponseSchema>;

export const healthResponseSchema = z.strictObject({
  status: z.enum(['ok', 'degraded', 'error']),
  service: z.string().trim().min(1).max(80),
  requestId: requestIdSchema.optional(),
});
export type HealthResponse = z.infer<typeof healthResponseSchema>;

export const paginationQuerySchema = z.strictObject({
  limit: z.coerce.number().int().min(1).max(100).default(20),
  cursor: z.string().trim().min(1).max(256).optional(),
});
export type PaginationQuery = z.infer<typeof paginationQuerySchema>;

export const pageInfoSchema = z.strictObject({
  nextCursor: z.string().trim().min(1).max(256).nullable(),
});
export type PageInfo = z.infer<typeof pageInfoSchema>;
