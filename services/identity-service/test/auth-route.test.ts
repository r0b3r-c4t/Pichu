import assert from 'node:assert/strict';
import test from 'node:test';
import { Types } from 'mongoose';
import { createApp } from '../src/app.js';
import { EmailTokenModel } from '../src/models/email-token.model.js';
import { UserModel } from '../src/models/user.model.js';
import { createIpRateLimiter } from '../src/routes/auth.js';
import { hashToken } from '../src/security/crypto.js';
import {
  EmailVerificationService,
  type EmailVerificationRepository,
} from '../src/services/email-verification.service.js';
import { RegistrationService } from '../src/services/registration.service.js';

test('rate limiter rejects a new IP at capacity without evicting an active IP', () => {
  const rateLimit = createIpRateLimiter(2, 60_000, 1);

  assert.equal(rateLimit('192.0.2.1', 0), undefined);
  assert.ok((rateLimit('192.0.2.2', 10) ?? 0) > 0);
  assert.equal(rateLimit('192.0.2.1', 20), undefined);
  assert.ok((rateLimit('192.0.2.1', 30) ?? 0) > 0);
});

test('rate limiter clears expired entries before admitting a new IP', () => {
  const rateLimit = createIpRateLimiter(1, 1_000, 1);

  assert.equal(rateLimit('192.0.2.1', 0), undefined);
  assert.equal(rateLimit('192.0.2.2', 1_000), undefined);
  assert.ok((rateLimit('192.0.2.2', 1_001) ?? 0) > 0);
});

test('rate limiter preserves an existing IP counter at capacity', () => {
  const rateLimit = createIpRateLimiter(2, 60_000, 2);

  assert.equal(rateLimit('192.0.2.1', 0), undefined);
  assert.equal(rateLimit('192.0.2.2', 0), undefined);
  assert.equal(rateLimit('192.0.2.1', 1), undefined);
  assert.equal(rateLimit('192.0.2.2', 1), undefined);
  assert.ok((rateLimit('192.0.2.1', 2) ?? 0) > 0);
  assert.ok((rateLimit('192.0.2.2', 2) ?? 0) > 0);
});

function createEmailVerificationService(options: { verified?: boolean } = {}) {
  const user = new UserModel({
    name: 'Ada',
    email: 'ada@example.com',
    normalizedEmail: 'ada@example.com',
    passwordHash: 'test-hash',
    emailVerifiedAt: options.verified ? new Date() : null,
  });
  let tokenHash: string | undefined = hashToken('a'.repeat(64));
  let tokenUsed = false;
  let resendCalls = 0;
  const repository: EmailVerificationRepository = {
    verifyEmailTokenAndUser: async (hash) => {
      if (!tokenHash || hash !== tokenHash || tokenUsed) {
        return false;
      }
      if (user.emailVerifiedAt) {
        return false;
      }
      tokenUsed = true;
      user.emailVerifiedAt = new Date();
      return true;
    },
    findUnverifiedUserByNormalizedEmail: async (normalizedEmail) => {
      resendCalls += 1;
      return normalizedEmail === user.email && !user.emailVerifiedAt ? user : null;
    },
    acquireVerificationResendLock: async () => 'acquired',
    renewVerificationResendLock: async () => true,
    releaseVerificationResendLock: async () => undefined,
    createEmailVerificationToken: async (input) => {
      tokenHash = input.tokenHash;
      tokenUsed = false;
      return { _id: new Types.ObjectId() };
    },
    invalidatePreviousEmailVerificationTokens: async () => undefined,
    deleteEmailVerificationToken: async () => undefined,
  };
  const service = new EmailVerificationService({
    repository,
    emailProvider: { send: async () => ({ id: 'email-id' }) },
    verificationUrl: 'http://localhost:3000/verify-email',
  });

  return { service, user, getResendCalls: () => resendCalls };
}

test('register route rejects invalid input without sensitive response fields', async (context) => {
  const service = new RegistrationService({
    repository: {
      findUserByNormalizedEmail: async () => null,
      createUser: async () => {
        throw new Error('not expected');
      },
      createEmailToken: async () => {
        throw new Error('not expected');
      },
      deleteEmailToken: async () => undefined,
    },
    emailProvider: { send: async () => ({ id: 'unused' }) },
    verificationUrl: 'http://localhost:3000/verify-email',
  });
  const app = createApp({ registrationService: service });
  context.after(async () => app.close());

  const response = await app.inject({
    method: 'POST',
    url: '/auth/register',
    payload: { name: '', email: 'invalid', password: 'short' },
  });

  assert.equal(response.statusCode, 400);
  assert.deepEqual(response.json(), { message: 'Invalid registration data' });
});

test('register route returns a generic accepted response for valid input', async (context) => {
  const service = new RegistrationService({
    repository: {
      findUserByNormalizedEmail: async () => null,
      createUser: async () =>
        new UserModel({
          _id: new Types.ObjectId(),
          name: 'Ada',
          email: 'ada@example.com',
          normalizedEmail: 'ada@example.com',
          passwordHash: 'hash',
          emailVerifiedAt: null,
        }),
      createEmailToken: async (input) => new EmailTokenModel(input),
      deleteEmailToken: async () => undefined,
    },
    emailProvider: { send: async () => ({ id: 'email-id' }) },
    verificationUrl: 'http://localhost:3000/verify-email',
  });
  const app = createApp({
    emailProvider: { send: async () => ({ id: 'email-id' }) },
    registrationService: service,
  });
  context.after(async () => app.close());

  const response = await app.inject({
    method: 'POST',
    url: '/auth/register',
    payload: { name: 'Ada', email: 'ada@example.com', password: 'correct horse battery staple' },
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json(), { accepted: true });
});

test('register route limits each IP to five requests and returns Retry-After', async (context) => {
  let registrationCalls = 0;
  const service = {
    register: async () => {
      registrationCalls += 1;
      return { accepted: true };
    },
  } as unknown as RegistrationService;
  const app = createApp({ registrationService: service });
  context.after(async () => app.close());

  const responses = [];
  for (let index = 0; index < 6; index += 1) {
    responses.push(
      await app.inject({
        method: 'POST',
        url: '/auth/register',
        remoteAddress: '192.0.2.1',
        payload: {
          name: 'Ada',
          email: 'ada@example.com',
          password: 'correct horse battery staple',
        },
      }),
    );
  }
  const otherIpResponse = await app.inject({
    method: 'POST',
    url: '/auth/register',
    remoteAddress: '192.0.2.2',
    payload: {
      name: 'Ada',
      email: 'ada@example.com',
      password: 'correct horse battery staple',
    },
  });

  assert.deepEqual(
    responses.map((response) => response.statusCode),
    [200, 200, 200, 200, 200, 429],
  );
  assert.deepEqual(responses[4].json(), { accepted: true });
  assert.deepEqual(responses[5].json(), { message: 'Too many requests' });
  assert.ok(Number(responses[5].headers['retry-after']) > 0);
  assert.equal(otherIpResponse.statusCode, 200);
  assert.equal(registrationCalls, 6);
});

test('register route does not expose internal database or provider errors', async (context) => {
  const sensitiveDetails = 'MongoServerError passwordHash tokenHash re_sensitive_api_key';
  const service = new RegistrationService({
    repository: {
      findUserByNormalizedEmail: async () => {
        throw new Error(sensitiveDetails);
      },
      createUser: async () => {
        throw new Error('not expected');
      },
      createEmailToken: async () => {
        throw new Error('not expected');
      },
      deleteEmailToken: async () => undefined,
    },
    emailProvider: { send: async () => ({ id: 'unused' }) },
    verificationUrl: 'http://localhost:3000/verify-email',
  });
  const app = createApp({ registrationService: service });
  context.after(async () => app.close());

  const response = await app.inject({
    method: 'POST',
    url: '/auth/register',
    payload: { name: 'Ada', email: 'ada@example.com', password: 'correct horse battery staple' },
  });

  assert.equal(response.statusCode, 503);
  assert.deepEqual(response.json(), { message: 'Registration could not be completed' });
  assert.equal(response.body.includes(sensitiveDetails), false);
  assert.equal(response.body.includes('passwordHash'), false);
  assert.equal(response.body.includes('tokenHash'), false);
  assert.equal(response.body.includes('re_sensitive_api_key'), false);
});

test('register route uses Fastify generic handling for unexpected errors', async (context) => {
  const sensitiveDetails = 'argon2 internal failure token secret';
  const unexpectedService = {
    register: async () => {
      throw new Error(sensitiveDetails);
    },
  } as unknown as RegistrationService;
  const app = createApp({ registrationService: unexpectedService });
  context.after(async () => app.close());

  const response = await app.inject({
    method: 'POST',
    url: '/auth/register',
    payload: { name: 'Ada', email: 'ada@example.com', password: 'correct horse battery staple' },
  });

  assert.equal(response.statusCode, 500);
  assert.equal(response.body.includes(sensitiveDetails), false);
  assert.equal(response.body.includes('stack'), false);
  assert.equal(response.body.includes('token'), false);
});

test('verification route returns a generic invalid-token response without exposing token data', async (context) => {
  const { service } = createEmailVerificationService();
  const app = createApp({ emailVerificationService: service });
  context.after(async () => app.close());

  const invalidToken = 'b'.repeat(64);
  const response = await app.inject({
    method: 'POST',
    url: '/auth/verify-email',
    payload: { token: invalidToken },
  });

  assert.equal(response.statusCode, 400);
  assert.deepEqual(response.json(), { message: 'Invalid or expired verification token' });
  assert.equal(response.body.includes(invalidToken), false);
  assert.equal(response.body.includes('tokenHash'), false);
});

test('verification route returns success without exposing the token or its hash', async (context) => {
  const { service } = createEmailVerificationService();
  const app = createApp({ emailVerificationService: service });
  context.after(async () => app.close());

  const response = await app.inject({
    method: 'POST',
    url: '/auth/verify-email',
    payload: { token: 'a'.repeat(64) },
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json(), { verified: true });
  assert.equal(response.body.includes('a'.repeat(64)), false);
  assert.equal(response.body.includes(hashToken('a'.repeat(64))), false);
  assert.equal(response.body.includes('tokenHash'), false);
});

test('resend route gives the same accepted response for missing and verified accounts', async (context) => {
  const { service, getResendCalls } = createEmailVerificationService({ verified: true });
  const app = createApp({ emailVerificationService: service });
  context.after(async () => app.close());

  const responses = await Promise.all(
    ['unknown@example.com', 'ada@example.com'].map((email) =>
      app.inject({
        method: 'POST',
        url: '/auth/verification/resend',
        payload: { email },
      }),
    ),
  );

  assert.deepEqual(
    responses.map(({ statusCode, body }) => [statusCode, body]),
    [
      [202, '{"accepted":true}'],
      [202, '{"accepted":true}'],
    ],
  );
  assert.equal(getResendCalls(), 2);
  assert.equal(
    responses.some(({ body }) => body.includes('ada@example.com')),
    false,
  );
});

test('resend route limits requests per client IP', async (context) => {
  const { service, getResendCalls } = createEmailVerificationService();
  const app = createApp({ emailVerificationService: service });
  context.after(async () => app.close());

  const responses = [];
  for (let index = 0; index < 6; index += 1) {
    responses.push(
      await app.inject({
        method: 'POST',
        url: '/auth/verification/resend',
        payload: { email: 'unknown@example.com' },
      }),
    );
  }

  assert.deepEqual(
    responses.map((response) => response.statusCode),
    [202, 202, 202, 202, 202, 429],
  );
  assert.ok(Number(responses[5].headers['retry-after']) > 0);
  assert.equal(getResendCalls(), 5);
  assert.deepEqual(responses[5].json(), { message: 'Too many requests' });
});
