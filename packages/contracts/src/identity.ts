import { z } from 'zod';
import { objectIdSchema } from './common.js';

export const identityEmailSchema = z.string().trim().email().max(320);
export const loginPasswordSchema = z.string().min(1).max(256);
export const newPasswordSchema = z.string().min(12).max(256);
export const opaqueTokenSchema = z.string().regex(/^[a-f\d]{64}$/, 'Invalid token format');
export const refreshTokenTransportSchema = z.enum(['cookie', 'body']);

/**
 * Closed request DTOs reject unknown properties. Header schemas validate only
 * the projected contract headers, not the complete Node.js request headers.
 */
export const loginRequestSchema = z.strictObject({
  email: identityEmailSchema,
  password: loginPasswordSchema,
});
export type LoginRequest = z.infer<typeof loginRequestSchema>;

export const loginTransportHeadersSchema = z.strictObject({
  'x-refresh-token-transport': refreshTokenTransportSchema.default('cookie'),
});
export type LoginTransportHeaders = z.infer<typeof loginTransportHeadersSchema>;

export const loginCookieResponseSchema = z.strictObject({ accessToken: z.string().min(1) });
export type LoginCookieResponse = z.infer<typeof loginCookieResponseSchema>;

export const loginBodyResponseSchema = z.strictObject({
  accessToken: z.string().min(1),
  refreshToken: opaqueTokenSchema,
  sessionId: objectIdSchema,
});
export type LoginBodyResponse = z.infer<typeof loginBodyResponseSchema>;

export const loginResponseSchema = z.union([loginCookieResponseSchema, loginBodyResponseSchema]);
export type LoginResponse = z.infer<typeof loginResponseSchema>;

export const refreshCookieRequestBodySchema = z.union([z.undefined(), z.strictObject({})]);
export type RefreshCookieRequestBody = z.infer<typeof refreshCookieRequestBodySchema>;

export const refreshBodyRequestBodySchema = z.strictObject({ refreshToken: opaqueTokenSchema });
export type RefreshBodyRequestBody = z.infer<typeof refreshBodyRequestBodySchema>;

export const refreshCookieTransportHeadersSchema = z.strictObject({
  'x-refresh-token-transport': z.literal('cookie').default('cookie'),
});
export type RefreshCookieTransportHeaders = z.infer<typeof refreshCookieTransportHeadersSchema>;

export const refreshBodyTransportHeadersSchema = z.strictObject({
  'x-refresh-token-transport': z.literal('body'),
});
export type RefreshBodyTransportHeaders = z.infer<typeof refreshBodyTransportHeadersSchema>;

/**
 * HTTP-level refresh contract. Keeping headers and body as separate fields
 * makes the transport/body relationship explicit and rejects mixed transport.
 */
export const refreshRequestSchema = z.union([
  z.strictObject({
    headers: refreshCookieTransportHeadersSchema,
    body: refreshCookieRequestBodySchema.optional(),
  }),
  z.strictObject({
    headers: refreshBodyTransportHeadersSchema,
    body: refreshBodyRequestBodySchema,
  }),
]);
export type RefreshRequest = z.infer<typeof refreshRequestSchema>;

export const refreshCookieResponseSchema = loginCookieResponseSchema;
export type RefreshCookieResponse = z.infer<typeof refreshCookieResponseSchema>;

export const refreshBodyResponseSchema = loginBodyResponseSchema;
export type RefreshBodyResponse = z.infer<typeof refreshBodyResponseSchema>;

export const refreshResponseSchema = loginResponseSchema;
export type RefreshResponse = z.infer<typeof refreshResponseSchema>;

export const registerRequestSchema = z.strictObject({
  name: z.string().trim().min(1).max(120),
  email: identityEmailSchema,
  password: newPasswordSchema,
});
export type RegisterRequest = z.infer<typeof registerRequestSchema>;

export const acceptedResponseSchema = z.strictObject({ accepted: z.literal(true) });
export type AcceptedResponse = z.infer<typeof acceptedResponseSchema>;

export const registerResponseSchema = acceptedResponseSchema;
export type RegisterResponse = z.infer<typeof registerResponseSchema>;

export const emailVerificationRequestSchema = z.strictObject({ token: opaqueTokenSchema });
export type EmailVerificationRequest = z.infer<typeof emailVerificationRequestSchema>;

export const emailVerificationResponseSchema = z.strictObject({ verified: z.literal(true) });
export type EmailVerificationResponse = z.infer<typeof emailVerificationResponseSchema>;

export const verificationResendRequestSchema = z.strictObject({ email: identityEmailSchema });
export type VerificationResendRequest = z.infer<typeof verificationResendRequestSchema>;

export const verificationResendResponseSchema = acceptedResponseSchema;
export type VerificationResendResponse = z.infer<typeof verificationResendResponseSchema>;

export const passwordResetRequestSchema = z.strictObject({ email: identityEmailSchema });
export type PasswordResetRequest = z.infer<typeof passwordResetRequestSchema>;

export const passwordResetConfirmSchema = z.strictObject({
  token: opaqueTokenSchema,
  password: newPasswordSchema,
});
export type PasswordResetConfirm = z.infer<typeof passwordResetConfirmSchema>;

export const resetResponseSchema = z.strictObject({ reset: z.literal(true) });
export type ResetResponse = z.infer<typeof resetResponseSchema>;

export const noIdentityRequestBodySchema = z.undefined();
export type NoIdentityRequestBody = z.infer<typeof noIdentityRequestBodySchema>;

export const logoutRequestSchema = noIdentityRequestBodySchema;
export type LogoutRequest = z.infer<typeof logoutRequestSchema>;

export const logoutAllRequestSchema = noIdentityRequestBodySchema;
export type LogoutAllRequest = z.infer<typeof logoutAllRequestSchema>;

export const revokedResponseSchema = z.strictObject({ revoked: z.literal(true) });
export type RevokedResponse = z.infer<typeof revokedResponseSchema>;

export const logoutResponseSchema = revokedResponseSchema;
export type LogoutResponse = z.infer<typeof logoutResponseSchema>;

export const logoutAllResponseSchema = revokedResponseSchema;
export type LogoutAllResponse = z.infer<typeof logoutAllResponseSchema>;

export const sessionSummarySchema = z.strictObject({
  sessionId: objectIdSchema,
  createdAt: z.string().datetime(),
  lastActivityAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
  userAgent: z.string().max(512).nullable(),
  revokedAt: z.null(),
  current: z.boolean(),
});
export type SessionSummary = z.infer<typeof sessionSummarySchema>;

export const sessionsResponseSchema = z.strictObject({ sessions: z.array(sessionSummarySchema) });
export type SessionsResponse = z.infer<typeof sessionsResponseSchema>;

export const sessionDeletionParamsSchema = z.strictObject({ sessionId: objectIdSchema });
export type SessionDeletionParams = z.infer<typeof sessionDeletionParamsSchema>;

export const sessionDeletionRequestSchema = noIdentityRequestBodySchema;
export type SessionDeletionRequest = z.infer<typeof sessionDeletionRequestSchema>;

export const sessionDeletionResponseSchema = revokedResponseSchema;
export type SessionDeletionResponse = z.infer<typeof sessionDeletionResponseSchema>;

export const internalUserExistenceParamsSchema = z.strictObject({ userId: objectIdSchema });
export type InternalUserExistenceParams = z.infer<typeof internalUserExistenceParamsSchema>;

export const internalUserExistenceResponseSchema = z.strictObject({ exists: z.boolean() });
export type InternalUserExistenceResponse = z.infer<typeof internalUserExistenceResponseSchema>;

export const identityServiceName = 'identity-service' as const;
