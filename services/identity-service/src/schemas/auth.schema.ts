import { z } from 'zod';

export const registerSchema = z.object({
  name: z.string().trim().min(1).max(120),
  email: z.string().trim().email().max(320),
  password: z.string().min(12).max(256),
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
  password: z.string().min(12).max(256),
});

export const loginSchema = z.object({
  email: z.string().trim().email().max(320),
  password: z.string().min(1).max(256),
});

export const refreshSchema = z.object({
  refreshToken: z
    .string()
    .regex(/^[a-f0-9]{64}$/)
    .optional(),
});

export type RegisterInput = z.infer<typeof registerSchema>;
export type VerifyEmailInput = z.infer<typeof verifyEmailSchema>;
export type ResendVerificationInput = z.infer<typeof resendVerificationSchema>;
export type PasswordRecoveryRequestInput = z.infer<typeof passwordRecoveryRequestSchema>;
export type PasswordRecoveryConfirmInput = z.infer<typeof passwordRecoveryConfirmSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type RefreshInput = z.infer<typeof refreshSchema>;
