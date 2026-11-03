import type { FastifyPluginAsync, FastifyReply } from 'fastify';
import { Types } from 'mongoose';
import {
  registerSchema,
  resendVerificationSchema,
  verifyEmailSchema,
  type RegisterInput,
  loginSchema,
  refreshSchema,
  passwordRecoveryRequestSchema,
  passwordRecoveryConfirmSchema,
} from '../schemas/auth.schema.js';
import {
  EmailVerificationService,
  EmailVerificationServiceError,
} from '../services/email-verification.service.js';
import { RegistrationService, RegistrationServiceError } from '../services/registration.service.js';
import {
  LoginService,
  LoginServiceError,
  LoginServiceOperationalError,
} from '../services/login.service.js';
import {
  RefreshTokenInvalidError,
  RefreshTokenReuseError,
  SessionService,
  SessionServiceError,
} from '../services/session.service.js';
import { createAuthenticationGuard } from '../security/authentication.js';
import { JwtService } from '../security/jwt.js';
import {
  PasswordRecoveryService,
  PasswordRecoveryServiceError,
} from '../services/password-recovery.service.js';

export interface AuthRoutesDependencies {
  registrationService?: RegistrationService;
  emailVerificationService?: EmailVerificationService;
  loginService?: LoginService;
  sessionService?: SessionService;
  jwtService?: JwtService;
  cookieSecure?: boolean;
  cookieOrigin?: string;
  passwordRecoveryService?: PasswordRecoveryService;
}

const RESEND_LIMIT = 5;
const RESEND_WINDOW_MS = 15 * 60 * 1000;
const REGISTER_LIMIT = 5;
const REGISTER_WINDOW_MS = 15 * 60 * 1000;
const MAX_TRACKED_CLIENTS = 10_000;
const REFRESH_COOKIE = 'pichu_refresh_token';
const COOKIE_TRANSPORT = 'cookie';
const BODY_TRANSPORT = 'body';
const PASSWORD_RESET_REQUEST_LIMIT = 5;
const PASSWORD_RESET_REQUEST_WINDOW_MS = 15 * 60 * 1000;

function sessionOperationFailed(reply: FastifyReply) {
  return reply.code(503).send({ message: 'Session operation could not be completed' });
}

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
  ({
    registrationService,
    emailVerificationService,
    loginService,
    sessionService,
    jwtService,
    cookieSecure = false,
    cookieOrigin,
    passwordRecoveryService,
  }: AuthRoutesDependencies): FastifyPluginAsync =>
  async (fastify) => {
    const registerRateLimiter = createIpRateLimiter(REGISTER_LIMIT, REGISTER_WINDOW_MS);

    if (passwordRecoveryService) {
      const passwordResetRequestRateLimiter = createIpRateLimiter(
        PASSWORD_RESET_REQUEST_LIMIT,
        PASSWORD_RESET_REQUEST_WINDOW_MS,
      );

      fastify.post('/auth/password-reset/request', async (request, reply) => {
        const retryAfter = passwordResetRequestRateLimiter(request.ip, Date.now());
        if (retryAfter !== undefined) {
          reply.header('retry-after', retryAfter);
          return reply.code(429).send({ message: 'Too many requests' });
        }

        const parsed = passwordRecoveryRequestSchema.safeParse(request.body);
        if (!parsed.success) {
          return reply.code(400).send({ message: 'Invalid email address' });
        }

        try {
          await passwordRecoveryService.requestRecovery(parsed.data.email);
          return reply.code(202).send({ accepted: true });
        } catch (error) {
          if (error instanceof PasswordRecoveryServiceError) {
            request.log.error({ code: error.code }, 'Password recovery request failed');
            return reply.code(503).send({ message: 'Request could not be completed' });
          }
          throw error;
        }
      });

      fastify.post('/auth/password-reset/confirm', async (request, reply) => {
        const parsed = passwordRecoveryConfirmSchema.safeParse(request.body);
        if (!parsed.success) {
          return reply.code(400).send({ message: 'Invalid or expired password reset token' });
        }

        try {
          const reset = await passwordRecoveryService.confirmRecovery(
            parsed.data.token,
            parsed.data.password,
          );
          if (!reset) {
            return reply.code(400).send({ message: 'Invalid or expired password reset token' });
          }
          return { reset: true };
        } catch (error) {
          if (error instanceof PasswordRecoveryServiceError) {
            request.log.error({ code: error.code }, 'Password recovery confirmation failed');
            return reply.code(503).send({ message: 'Request could not be completed' });
          }
          throw error;
        }
      });
    }

    if (loginService && sessionService && jwtService && cookieOrigin) {
      const loginRateLimiter = createIpRateLimiter(REGISTER_LIMIT, REGISTER_WINDOW_MS);
      const refreshRateLimiter = createIpRateLimiter(REGISTER_LIMIT, REGISTER_WINDOW_MS);
      const authenticate = createAuthenticationGuard(jwtService, sessionService);
      const cookieOptions = {
        httpOnly: true,
        secure: cookieSecure,
        sameSite: 'lax' as const,
        path: '/auth',
        maxAge: sessionService.refreshTokenTtlSeconds,
      };

      fastify.post('/auth/login', async (request, reply) => {
        const retryAfter = loginRateLimiter(request.ip, Date.now());
        if (retryAfter !== undefined) {
          reply.header('retry-after', retryAfter);
          return reply.code(429).send({ message: 'Too many requests' });
        }
        const parsed = loginSchema.safeParse(request.body);
        if (!parsed.success) {
          return reply.code(401).send({ message: 'Invalid credentials' });
        }
        const transportHeader = request.headers['x-refresh-token-transport'];
        const transport = transportHeader ?? COOKIE_TRANSPORT;
        if (transport !== COOKIE_TRANSPORT && transport !== BODY_TRANSPORT) {
          return reply.code(400).send({ message: 'Invalid token transport' });
        }
        const useCookie = transport === COOKIE_TRANSPORT;
        if (useCookie && request.headers.origin !== cookieOrigin) {
          return reply.code(403).send({ message: 'Invalid request origin' });
        }
        try {
          const result = await loginService.login(parsed.data, request.headers['user-agent']);
          if (useCookie) {
            reply.setCookie(REFRESH_COOKIE, result.refreshToken, cookieOptions);
            return { accessToken: result.accessToken };
          }
          return result;
        } catch (error) {
          if (error instanceof LoginServiceError) {
            return reply.code(401).send({ message: 'Invalid credentials' });
          }
          if (error instanceof LoginServiceOperationalError) {
            return reply.code(503).send({ message: 'Login could not be completed' });
          }
          throw error;
        }
      });

      fastify.post('/auth/refresh', async (request, reply) => {
        const retryAfter = refreshRateLimiter(request.ip, Date.now());
        if (retryAfter !== undefined) {
          reply.header('retry-after', retryAfter);
          return reply.code(429).send({ message: 'Too many requests' });
        }
        const parsed = refreshSchema.safeParse(request.body ?? {});
        if (!parsed.success) {
          return reply.code(401).send({ message: 'Invalid refresh token' });
        }
        const transportHeader = request.headers['x-refresh-token-transport'];
        const transport = transportHeader ?? COOKIE_TRANSPORT;
        if (transport !== COOKIE_TRANSPORT && transport !== BODY_TRANSPORT) {
          return reply.code(400).send({ message: 'Invalid token transport' });
        }
        const bodyToken = parsed.data.refreshToken;
        const cookieToken = request.cookies[REFRESH_COOKIE];
        if (
          transport === BODY_TRANSPORT &&
          (bodyToken === undefined || cookieToken !== undefined)
        ) {
          return reply.code(400).send({ message: 'Invalid refresh token transport' });
        }
        if (
          transport === COOKIE_TRANSPORT &&
          (bodyToken !== undefined || cookieToken === undefined)
        ) {
          return reply.code(400).send({ message: 'Invalid refresh token transport' });
        }
        const usingCookie = transport === COOKIE_TRANSPORT;
        if (usingCookie && request.headers.origin !== cookieOrigin) {
          return reply.code(403).send({ message: 'Invalid request origin' });
        }
        try {
          const result = await sessionService.rotateRefreshToken(bodyToken ?? cookieToken!);
          let accessToken: string;
          try {
            accessToken = await jwtService.createAccessToken(
              result.session.userId,
              result.session._id,
            );
          } catch {
            if (usingCookie) {
              reply.clearCookie(REFRESH_COOKIE, cookieOptions);
            }
            try {
              await sessionService.revokeSession(
                result.session._id,
                'access-token-issuance-failed',
              );
            } catch {
              request.log.error('Failed to revoke session after access-token issuance failure');
            }
            return reply.code(503).send({ message: 'Request could not be completed' });
          }
          if (usingCookie) {
            const remainingTtlSeconds = Math.max(
              0,
              Math.floor((result.session.expiresAt.getTime() - Date.now()) / 1000),
            );

            reply.setCookie(REFRESH_COOKIE, result.refreshToken, {
              ...cookieOptions,
              maxAge: remainingTtlSeconds,
            });

            return { accessToken };
          }
          return {
            accessToken,
            refreshToken: result.refreshToken,
            sessionId: String(result.session._id),
          };
        } catch (error) {
          if (
            error instanceof RefreshTokenReuseError ||
            error instanceof RefreshTokenInvalidError
          ) {
            reply.clearCookie(REFRESH_COOKIE, cookieOptions);
            return reply.code(401).send({ message: 'Invalid refresh token' });
          }
          if (error instanceof SessionServiceError) {
            return reply.code(503).send({ message: 'Request could not be completed' });
          }
          throw error;
        }
      });

      fastify.post('/auth/logout', { preHandler: authenticate }, async (request, reply) => {
        try {
          await sessionService.revokeSession(new Types.ObjectId(request.auth!.sessionId));
          reply.clearCookie(REFRESH_COOKIE, cookieOptions);
          return { revoked: true };
        } catch (error) {
          if (error instanceof SessionServiceError) {
            return sessionOperationFailed(reply);
          }
          throw error;
        }
      });

      fastify.post('/auth/logout-all', { preHandler: authenticate }, async (request, reply) => {
        try {
          await sessionService.revokeAllSessions(new Types.ObjectId(request.auth!.userId));
          reply.clearCookie(REFRESH_COOKIE, cookieOptions);
          return { revoked: true };
        } catch (error) {
          if (error instanceof SessionServiceError) {
            return sessionOperationFailed(reply);
          }
          throw error;
        }
      });

      fastify.get('/sessions', { preHandler: authenticate }, async (request, reply) => {
        try {
          const sessions = await sessionService.listSessions(
            new Types.ObjectId(request.auth!.userId),
          );
          return {
            sessions: sessions.map((session) => ({
              sessionId: String(session._id),
              createdAt: session.createdAt,
              lastActivityAt: session.lastActivityAt,
              expiresAt: session.expiresAt,
              userAgent: session.userAgent,
              revokedAt: session.revokedAt,
              current: String(session._id) === request.auth!.sessionId,
            })),
          };
        } catch (error) {
          if (error instanceof SessionServiceError) {
            return sessionOperationFailed(reply);
          }
          throw error;
        }
      });

      fastify.delete<{ Params: { sessionId: string } }>(
        '/sessions/:sessionId',
        { preHandler: authenticate },
        async (request, reply) => {
          if (!Types.ObjectId.isValid(request.params.sessionId)) {
            return reply.code(404).send({ message: 'Session not found' });
          }
          const sessionId = new Types.ObjectId(request.params.sessionId);
          try {
            const revoked = await sessionService.revokeOwnedSession(
              sessionId,
              new Types.ObjectId(request.auth!.userId),
            );
            if (!revoked) {
              return reply.code(404).send({ message: 'Session not found' });
            }
            return { revoked: true };
          } catch (error) {
            if (error instanceof SessionServiceError) {
              return sessionOperationFailed(reply);
            }
            throw error;
          }
        },
      );
    }

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
