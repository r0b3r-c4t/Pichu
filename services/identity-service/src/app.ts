import Fastify, { LogController, type FastifyInstance } from 'fastify';
import { Types } from 'mongoose';
import cookie from '@fastify/cookie';
import { healthRoutes } from './routes/health.js';
import { createAuthRoutes } from './routes/auth.js';
import type { EmailProvider } from './email/email-provider.js';
import {
  createMongooseEmailVerificationRepository,
  EmailVerificationService,
} from './services/email-verification.service.js';
import {
  createMongooseRegistrationRepository,
  RegistrationService,
} from './services/registration.service.js';
import { LoginService } from './services/login.service.js';
import { SessionService } from './services/session.service.js';
import { JwtService } from './security/jwt.js';
import { PasswordRecoveryService } from './services/password-recovery.service.js';
import { UserModel } from './models/user.model.js';
import {
  getInternalPrincipal,
  getInternalSignal,
  internalAuthPlugin,
} from '@pichu/internal-auth-adapters/fastify';
import type { Keyring } from '@pichu/internal-auth';
import type { NonceStore } from '@pichu/internal-auth-adapters/types';
import type { ServerOptions } from 'node:https';
import { docsRoutes } from './routes/docs.js';
import { identityRequestId, installIdentityErrorResponses } from './routes/errors.js';
import { UserProfileService, UserProfileServiceError } from './services/user-profile.service.js';

export interface AppDependencies {
  https?: ServerOptions;
  emailProvider?: EmailProvider;
  verificationUrl?: string;
  tokenTtlMs?: number;
  registrationService?: RegistrationService;
  emailVerificationService?: EmailVerificationService;
  loginService?: LoginService;
  sessionService?: SessionService;
  jwtService?: JwtService;
  cookieSecure?: boolean;
  cookieOrigin?: string;
  passwordRecoveryService?: PasswordRecoveryService;
  userProfileService?: UserProfileService;
  internalAuth?: {
    environment: 'development' | 'test' | 'staging' | 'production';
    keyring: Keyring;
    nonces: NonceStore;
    bodyLimit?: number;
  };
}

export function createApp(dependencies: AppDependencies = {}): FastifyInstance {
  const app = Fastify({
    logger: true,
    ...(dependencies.https ? { https: dependencies.https } : {}),
    logController: new LogController({ disableRequestLogging: true }),
    genReqId: identityRequestId,
  });
  installIdentityErrorResponses(app);
  app.addHook('onRequest', async (request) => {
    request.log.info(
      { method: request.method, path: request.url.split('?')[0] },
      'Incoming request',
    );
  });
  app.addHook('onResponse', async (request, reply) => {
    request.log.info(
      { method: request.method, path: request.url.split('?')[0], statusCode: reply.statusCode },
      'Request completed',
    );
  });
  app.setErrorHandler((error, request, reply) => {
    const statusCodeValue =
      error instanceof Error && 'statusCode' in error && typeof error.statusCode === 'number'
        ? error.statusCode
        : undefined;
    const errorCode =
      error instanceof Error && 'code' in error && typeof error.code === 'string'
        ? error.code
        : undefined;
    const statusCode =
      statusCodeValue !== undefined && statusCodeValue >= 400 && statusCodeValue < 500
        ? statusCodeValue
        : 500;

    if (statusCode >= 500) {
      request.log.error(
        {
          code: errorCode,
          errorType: error instanceof Error ? error.name : 'UnknownError',
          causeType:
            error instanceof Error && error.cause instanceof Error ? error.cause.name : undefined,
          requestId: request.id,
        },
        'Unhandled request error',
      );
    }

    reply.status(statusCode).send({
      statusCode,
      error: statusCode >= 500 ? 'Internal Server Error' : 'Bad Request',
      message: statusCode >= 500 ? 'Internal Server Error' : 'Invalid request',
    });
  });
  void app.register(cookie);
  void app.register(healthRoutes);
  void app.register(docsRoutes);
  const userProfileService = dependencies.userProfileService ?? new UserProfileService();
  if (dependencies.internalAuth) {
    const internalAuth = dependencies.internalAuth;
    void app.register(internalAuthPlugin, {
      environment: internalAuth.environment,
      audience: 'identity-service',
      keyring: () => internalAuth.keyring,
      nonces: internalAuth.nonces,
      bodyLimit: internalAuth.bodyLimit,
      policies: {
        identityUserExists: {
          method: 'GET',
          route: '/internal/users/:userId/exists',
          senders: ['vehicle-service'],
        },
        identityUserVerified: {
          method: 'GET',
          route: '/internal/users/:userId/verified',
          senders: ['vehicle-service', 'device-service'],
        },
      },
      routes: async (scope) => {
        scope.get<{ Params: { userId: string } }>(
          '/internal/users/:userId/exists',
          { config: { internalOperation: 'identityUserExists' } },
          async (request, reply) => {
            const claims = await verifyInternalUser(
              request,
              dependencies.jwtService,
              dependencies.sessionService,
            );
            if (!claims) return reply.code(401).send({ message: 'Internal request failed' });
            if (!/^[a-f0-9]{24}$/.test(request.params.userId))
              return reply.code(400).send({ message: 'Internal request failed' });
            try {
              request.log.debug(
                { requestId: getInternalPrincipal(request).requestId },
                'Internal identity lookup',
              );
              const exists = await UserModel.exists({ _id: request.params.userId });
              return { exists: Boolean(exists) };
            } catch {
              getInternalSignal(request).throwIfAborted();
              return reply.code(503).send({ message: 'Internal request failed' });
            }
          },
        );
        scope.get<{ Params: { userId: string } }>(
          '/internal/users/:userId/verified',
          { config: { internalOperation: 'identityUserVerified' } },
          async (request, reply) => {
            const sender = getInternalPrincipal(request).sender;
            if (sender !== 'vehicle-service' && sender !== 'device-service')
              return reply.code(403).send({ message: 'Internal request failed' });
            const claims = await verifyInternalUser(
              request,
              dependencies.jwtService,
              dependencies.sessionService,
            );
            if (!claims || claims.userId !== request.params.userId)
              return reply.code(403).send({ message: 'Internal request failed' });
            if (!/^[a-f0-9]{24}$/.test(request.params.userId))
              return reply.code(400).send({ message: 'Internal request failed' });
            try {
              const verified = await userProfileService.isEmailVerified(request.params.userId);
              getInternalSignal(request).throwIfAborted();
              return { verified };
            } catch (error) {
              if (error instanceof UserProfileServiceError)
                return reply.code(503).send({ message: 'Internal request failed' });
              throw error;
            }
          },
        );
      },
    });
  }
  const registrationService =
    dependencies.registrationService ??
    (dependencies.emailProvider && dependencies.verificationUrl
      ? new RegistrationService({
          repository: createMongooseRegistrationRepository(),
          emailProvider: dependencies.emailProvider,
          verificationUrl: dependencies.verificationUrl,
          tokenTtlMs: dependencies.tokenTtlMs,
        })
      : undefined);

  const emailVerificationService =
    dependencies.emailVerificationService ??
    (dependencies.emailProvider && dependencies.verificationUrl
      ? new EmailVerificationService({
          repository: createMongooseEmailVerificationRepository(),
          emailProvider: dependencies.emailProvider,
          verificationUrl: dependencies.verificationUrl,
          tokenTtlMs: dependencies.tokenTtlMs,
        })
      : undefined);

  if (
    registrationService ||
    emailVerificationService ||
    dependencies.loginService ||
    dependencies.passwordRecoveryService
  ) {
    void app.register(
      createAuthRoutes({
        registrationService,
        emailVerificationService,
        loginService: dependencies.loginService,
        sessionService: dependencies.sessionService,
        jwtService: dependencies.jwtService,
        cookieSecure: dependencies.cookieSecure,
        cookieOrigin: dependencies.cookieOrigin,
        passwordRecoveryService: dependencies.passwordRecoveryService,
        userProfileService,
      }),
    );
  }
  return app;
}

async function verifyInternalUser(
  request: import('fastify').FastifyRequest,
  jwtService: JwtService | undefined,
  sessionService: SessionService | undefined,
) {
  const authorization = request.headers.authorization;
  if (!jwtService || !sessionService || typeof authorization !== 'string') return undefined;
  if (!authorization.startsWith('Bearer ') || authorization.length <= 'Bearer '.length)
    return undefined;
  try {
    const claims = await jwtService.verifyAccessToken(authorization.slice('Bearer '.length));
    if (!Types.ObjectId.isValid(claims.sessionId) || !Types.ObjectId.isValid(claims.userId))
      return undefined;
    const active = await sessionService.isSessionActive(
      new Types.ObjectId(claims.sessionId),
      new Types.ObjectId(claims.userId),
    );
    return active ? claims : undefined;
  } catch {
    return undefined;
  }
}
