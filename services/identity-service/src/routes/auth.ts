import type { FastifyPluginAsync } from 'fastify';
import {
  registerSchema,
  resendVerificationSchema,
  verifyEmailSchema,
  type RegisterInput,
} from '../schemas/auth.schema.js';
import {
  EmailVerificationService,
  EmailVerificationServiceError,
} from '../services/email-verification.service.js';
import { RegistrationService, RegistrationServiceError } from '../services/registration.service.js';

export interface AuthRoutesDependencies {
  registrationService?: RegistrationService;
  emailVerificationService?: EmailVerificationService;
}

const RESEND_LIMIT = 5;
const RESEND_WINDOW_MS = 15 * 60 * 1000;
const REGISTER_LIMIT = 5;
const REGISTER_WINDOW_MS = 15 * 60 * 1000;
const MAX_TRACKED_CLIENTS = 10_000;

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

export function createIpRateLimiter(
  limit: number,
  windowMs: number,
  maxTrackedClients = MAX_TRACKED_CLIENTS,
): (ip: string, now: number) => number | undefined {
  const requestsByIp = new Map<string, RateLimitEntry>();

  return (ip, now) => {
    for (const [trackedIp, entry] of requestsByIp) {
      if (entry.resetAt <= now) {
        requestsByIp.delete(trackedIp);
      }
    }

    const entry = requestsByIp.get(ip);
    if (entry) {
      if (entry.count >= limit) {
        return Math.max(1, Math.ceil((entry.resetAt - now) / 1000));
      }

      entry.count += 1;
      return undefined;
    }

    if (requestsByIp.size >= maxTrackedClients) {
      let earliestResetAt = Number.POSITIVE_INFINITY;
      for (const trackedEntry of requestsByIp.values()) {
        earliestResetAt = Math.min(earliestResetAt, trackedEntry.resetAt);
      }
      return Math.max(1, Math.ceil((earliestResetAt - now) / 1000));
    }

    requestsByIp.set(ip, { count: 1, resetAt: now + windowMs });
    return undefined;
  };
}

export const createAuthRoutes =
  ({ registrationService, emailVerificationService }: AuthRoutesDependencies): FastifyPluginAsync =>
  async (fastify) => {
    const registerRateLimiter = createIpRateLimiter(REGISTER_LIMIT, REGISTER_WINDOW_MS);

    if (registrationService) {
      fastify.post(
        '/auth/register',
        {
          preHandler: async (request, reply) => {
            const retryAfter = registerRateLimiter(request.ip, Date.now());
            if (retryAfter !== undefined) {
              reply.header('retry-after', retryAfter);
              return reply.code(429).send({ message: 'Too many requests' });
            }
          },
        },
        async (request, reply) => {
          const parsed = registerSchema.safeParse(request.body);
          if (!parsed.success) {
            return reply.code(400).send({ message: 'Invalid registration data' });
          }

          const input: RegisterInput = parsed.data;

          try {
            return await registrationService.register(input);
          } catch (error) {
            if (error instanceof RegistrationServiceError) {
              request.log.error({ code: error.code }, 'Registration failed');
              return reply.code(503).send({ message: 'Registration could not be completed' });
            }
            throw error;
          }
        },
      );
    }

    if (emailVerificationService) {
      const resendRateLimiter = createIpRateLimiter(RESEND_LIMIT, RESEND_WINDOW_MS);

      fastify.post('/auth/verify-email', async (request, reply) => {
        const parsed = verifyEmailSchema.safeParse(request.body);
        if (!parsed.success) {
          return reply.code(400).send({ message: 'Invalid or expired verification token' });
        }

        try {
          const verified = await emailVerificationService.verifyEmail(parsed.data.token);
          if (!verified) {
            return reply.code(400).send({ message: 'Invalid or expired verification token' });
          }

          return { verified: true };
        } catch (error) {
          if (error instanceof EmailVerificationServiceError) {
            request.log.error({ code: error.code }, 'Email verification failed');
            return reply.code(503).send({ message: 'Request could not be completed' });
          }
          throw error;
        }
      });

      fastify.post(
        '/auth/verification/resend',
        {
          preHandler: async (request, reply) => {
            const retryAfter = resendRateLimiter(request.ip, Date.now());
            if (retryAfter !== undefined) {
              reply.header('retry-after', retryAfter);
              return reply.code(429).send({ message: 'Too many requests' });
            }
          },
        },
        async (request, reply) => {
          const parsed = resendVerificationSchema.safeParse(request.body);
          if (!parsed.success) {
            return reply.code(400).send({ message: 'Invalid email address' });
          }

          try {
            await emailVerificationService.resendVerification(parsed.data.email);
            return reply.code(202).send({ accepted: true });
          } catch (error) {
            if (error instanceof EmailVerificationServiceError) {
              request.log.error({ code: error.code }, 'Verification email resend failed');
              return reply.code(503).send({ message: 'Request could not be completed' });
            }
            throw error;
          }
        },
      );
    }
  };
