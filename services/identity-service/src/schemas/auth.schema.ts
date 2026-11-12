import { z } from 'zod';
import { newPasswordSchema, usernameSchema } from '@pichu/contracts';

export const registerSchema = z.object({
  name: z.string().trim().min(1).max(120),
  username: usernameSchema,
  email: z.string().trim().email().max(320),
  password: newPasswordSchema,
});

export const verifyEmailSchema = z.object({
  token: z.string().regex(/^[a-f0-9]{64}$/),
});

export const resendVerificationSchema = z.object({
  email: z.string().trim().email().max(320),
});

export const passwordRecoveryRequestSchema = z.object({
  email: z.string().trim().email().max(320),
});

export const passwordRecoveryConfirmSchema = z.object({
  token: z.string().regex(/^[a-f0-9]{64}$/),
  password: newPasswordSchema,
});

export const loginSchema = z.object({
  email: z.string().trim().email().max(320),
  password: z.string().min(1).max(256),
});

export const refreshSchema = z.union([z.undefined(), z.strictObject({})]);

export type RegisterInput = z.infer<typeof registerSchema>;
export type VerifyEmailInput = z.infer<typeof verifyEmailSchema>;
export type ResendVerificationInput = z.infer<typeof resendVerificationSchema>;
export type PasswordRecoveryRequestInput = z.infer<typeof passwordRecoveryRequestSchema>;
export type PasswordRecoveryConfirmInput = z.infer<typeof passwordRecoveryConfirmSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type RefreshInput = z.infer<typeof refreshSchema>;
