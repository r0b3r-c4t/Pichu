import Fastify, { type FastifyInstance } from 'fastify';
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

export interface AppDependencies {
  emailProvider?: EmailProvider;
  verificationUrl?: string;
  tokenTtlMs?: number;
  registrationService?: RegistrationService;
  emailVerificationService?: EmailVerificationService;
}

export function createApp(dependencies: AppDependencies = {}): FastifyInstance {
  const app = Fastify({ logger: true });
  app.setErrorHandler((error, request, reply) => {
    const statusCodeValue =
      error instanceof Error && 'statusCode' in error && typeof error.statusCode === 'number'
        ? error.statusCode
        : undefined;
    const errorCode =
      error instanceof Error && 'code' in error && typeof error.code === 'string' ? error.code : undefined;
    const statusCode =
      statusCodeValue !== undefined && statusCodeValue >= 400 && statusCodeValue < 500
        ? statusCodeValue
        : 500;

    if (statusCode >= 500) {
      request.log.error({ code: errorCode }, 'Unhandled request error');
    }

    reply.status(statusCode).send({
      statusCode,
      error: statusCode >= 500 ? 'Internal Server Error' : 'Bad Request',
      message: statusCode >= 500 ? 'Internal Server Error' : 'Invalid request',
    });
  });
  void app.register(healthRoutes);
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

  if (registrationService || emailVerificationService) {
    void app.register(createAuthRoutes({ registrationService, emailVerificationService }));
  }
  return app;
}
