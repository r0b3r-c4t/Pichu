import { z } from 'zod';

export const apiErrorCodeSchema = z.enum([
  'VALIDATION_ERROR',
  'INVALID_CREDENTIALS',
  'INVALID_TOKEN',
  'UNAUTHORIZED',
  'FORBIDDEN',
  'EMAIL_NOT_VERIFIED',
  'RESOURCE_NOT_FOUND',
  'CONFLICT',
  'USER_ALREADY_EXISTS',
  'USERNAME_ALREADY_EXISTS',
  'RATE_LIMIT_EXCEEDED',
  'PAYLOAD_TOO_LARGE',
  'UNSUPPORTED_MEDIA_TYPE',
  'EMAIL_SERVICE_UNAVAILABLE',
  'SERVICE_UNAVAILABLE',
  'INTERNAL_SERVER_ERROR',
]);

export const apiErrorResponseSchema = z.strictObject({
  error: apiErrorCodeSchema.meta({ description: 'Stable application error code' }),
  message: z.string().min(1).meta({ description: 'Safe, user-facing error message' }),
  details: z
    .array(z.strictObject({ field: z.string(), message: z.string() }))
    .optional()
    .meta({ description: 'Invalid fields; present only for input validation errors' }),
  requestId: z.string().optional().meta({ description: 'Matches the x-request-id header' }),
});

export type ApiErrorResponse = z.infer<typeof apiErrorResponseSchema>;
