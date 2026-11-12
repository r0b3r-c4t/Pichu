import {
  invitationParamsSchema,
  publicInvitationCreateRequestSchema,
  vehicleCreateRequestSchema,
  vehicleListQuerySchema,
  vehicleParamsSchema,
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
export const vehicleListQueryInputSchema = vehicleListQuerySchema;
export const vehicleIdParamsInputSchema = vehicleParamsSchema;
export const invitationIdParamsInputSchema = invitationParamsSchema;
export const invitationCreateBodySchema = publicInvitationCreateRequestSchema;
export const invitationAcceptBodySchema = z.strictObject({});
export const deviceLinkBodySchema = z.strictObject({
  deviceIdentifier: z.string().trim().min(1).max(128),
  publicKey: z.string().trim().min(32).max(4096),
});

export const emptyObjectSchema = z.strictObject({});
export const loginBodySchema = loginRequestSchema;
export const registerBodySchema = registerRequestSchema;
export const emailVerificationBodySchema = emailVerificationRequestSchema;
export const verificationResendBodySchema = verificationResendRequestSchema;
export const passwordResetRequestBodySchema = passwordResetRequestSchema;
export const passwordResetConfirmBodySchema = passwordResetConfirmSchema;
export const refreshRequestBodySchema = z.union([z.undefined(), z.strictObject({})]);
export const vehicleErrorResponseSchema = gatewayErrorResponseSchema;
