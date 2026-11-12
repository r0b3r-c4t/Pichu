import Fastify, { LogController, type FastifyInstance } from 'fastify';
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

import { docsRoutes } from './routes/docs.js';
import { identityRequestId, installIdentityErrorResponses } from './routes/errors.js';
import { UserProfileService } from './services/user-profile.service.js';

export interface AppDependencies {
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
}

export function createApp(dependencies: AppDependencies = {}): FastifyInstance {
  const app = Fastify({
    logger: true,
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
