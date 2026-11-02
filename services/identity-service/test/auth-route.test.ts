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
import { SessionServiceError } from '../src/services/session.service.js';
import { LoginServiceOperationalError } from '../src/services/login.service.js';
import { SessionModel } from '../src/models/session.model.js';
import Fastify from 'fastify';
import { createAuthenticationGuard } from '../src/security/authentication.js';
import { DEFAULT_REFRESH_TOKEN_TTL_MS } from '../src/services/session.service.js';

function getSetCookieHeader(value: string | string[] | undefined): string {
  return Array.isArray(value) ? value.join('\n') : (value ?? '');
}

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

function createLoginRouteApp(
  overrides: { login?: (input: unknown, userAgent?: string) => Promise<unknown> } = {},
) {
  let loginCalls = 0;
  const loginService = {
    login: async (input: unknown, userAgent?: string) => {
      loginCalls += 1;
      return (
        overrides.login?.(input, userAgent) ?? {
          accessToken: 'access-token',
          refreshToken: 'a'.repeat(64),
          sessionId: new Types.ObjectId().toHexString(),
        }
      );
    },
  };
  const sessionService = {
    refreshTokenTtlSeconds: 900,
    isSessionActive: async () => true,
    rotateRefreshToken: async () => {
      throw new Error('not expected');
    },
  };
  const jwtService = {
    verifyAccessToken: async () => ({
      userId: new Types.ObjectId().toHexString(),
      sessionId: new Types.ObjectId().toHexString(),
      issuedAt: 1,
      expiresAt: 2,
    }),
  };
  const app = createApp({
    loginService: loginService as never,
    sessionService: sessionService as never,
    jwtService: jwtService as never,
    cookieOrigin: 'https://app.example.test',
    cookieSecure: true,
  });
  return { app, getLoginCalls: () => loginCalls };
}

test('cookie login requires the allowed Origin and does not expose refresh token', async (context) => {
  const { app, getLoginCalls } = createLoginRouteApp();
  context.after(async () => app.close());

  const allowed = await app.inject({
    method: 'POST',
    url: '/auth/login',
    headers: { origin: 'https://app.example.test' },
    payload: { email: 'ada@example.com', password: 'correct password' },
  });
  assert.equal(allowed.statusCode, 200);
  assert.deepEqual(allowed.json(), { accessToken: 'access-token' });
  const loginCookie = getSetCookieHeader(allowed.headers['set-cookie']);
  assert.match(loginCookie, /HttpOnly/);
  assert.match(loginCookie, /Max-Age=900/);

  const different = await app.inject({
    method: 'POST',
    url: '/auth/login',
    headers: { origin: 'https://evil.example.test' },
    payload: { email: 'ada@example.com', password: 'correct password' },
  });
  const missing = await app.inject({
    method: 'POST',
    url: '/auth/login',
    payload: { email: 'ada@example.com', password: 'correct password' },
  });
  assert.equal(different.statusCode, 403);
  assert.equal(missing.statusCode, 403);
  assert.equal(getLoginCalls(), 1);
});

function createRefreshFailureApp() {
  const sessionId = new Types.ObjectId();
  const userId = new Types.ObjectId();
  const revocations: Array<{ sessionId: Types.ObjectId; reason?: string }> = [];
  const sessionService = {
    refreshTokenTtlSeconds: DEFAULT_REFRESH_TOKEN_TTL_MS / 1000,
    isSessionActive: async () => true,
    rotateRefreshToken: async () => ({
      session: { _id: sessionId, userId },
      refreshToken: 'new-refresh-token',
    }),
    revokeSession: async (revokedSessionId: Types.ObjectId, reason?: string) => {
      revocations.push({ sessionId: revokedSessionId, reason });
    },
  };
  const jwtService = {
    verifyAccessToken: async () => ({
      userId: userId.toHexString(),
      sessionId: sessionId.toHexString(),
      issuedAt: 1,
      expiresAt: 2,
    }),
    createAccessToken: async () => {
      throw new Error('sensitive signing failure');
    },
  };
  const app = createApp({
    loginService: { login: async () => ({}) } as never,
    sessionService: sessionService as never,
    jwtService: jwtService as never,
    cookieOrigin: 'https://app.example.test',
    cookieSecure: true,
  });

  return { app, sessionId, revocations };
}

test('refresh revokes the rotated session and clears cookie if access token creation fails', async (context) => {
  const { app, sessionId, revocations } = createRefreshFailureApp();
  context.after(async () => app.close());

  const response = await app.inject({
    method: 'POST',
    url: '/auth/refresh',
    headers: {
      origin: 'https://app.example.test',
      cookie: 'pichu_refresh_token=old-refresh-token',
    },
  });

  assert.equal(response.statusCode, 503);
  assert.deepEqual(response.json(), { message: 'Request could not be completed' });
  assert.equal(response.body.includes('sensitive signing failure'), false);
  const clearedCookie = getSetCookieHeader(response.headers['set-cookie']);
  assert.match(clearedCookie, /pichu_refresh_token=;/);
  assert.match(clearedCookie, /Max-Age=0/);
  assert.equal(revocations.length, 1);
  assert.equal(revocations[0].sessionId.equals(sessionId), true);
  assert.equal(revocations[0].reason, 'access-token-issuance-failed');
});

test('refresh revokes the rotated session after access token failure using body transport', async (context) => {
  const { app, sessionId, revocations } = createRefreshFailureApp();
  context.after(async () => app.close());

  const response = await app.inject({
    method: 'POST',
    url: '/auth/refresh',
    headers: { 'x-refresh-token-transport': 'body' },
    payload: { refreshToken: 'a'.repeat(64) },
  });

  assert.equal(response.statusCode, 503);
  assert.deepEqual(response.json(), { message: 'Request could not be completed' });
  assert.equal(response.body.includes('sensitive signing failure'), false);
  assert.equal(response.headers['set-cookie'], undefined);
  assert.equal(revocations.length, 1);
  assert.equal(revocations[0].sessionId.equals(sessionId), true);
  assert.equal(revocations[0].reason, 'access-token-issuance-failed');
});

test('native body login is explicit and unknown transport is rejected', async (context) => {
  const { app, getLoginCalls } = createLoginRouteApp();
  context.after(async () => app.close());

  const native = await app.inject({
    method: 'POST',
    url: '/auth/login',
    headers: { 'x-refresh-token-transport': 'body' },
    payload: { email: 'ada@example.com', password: 'correct password' },
  });
  assert.equal(native.statusCode, 200);
  assert.equal(native.json().refreshToken, 'a'.repeat(64));

  const unknown = await app.inject({
    method: 'POST',
    url: '/auth/login',
    headers: { 'x-refresh-token-transport': 'header', origin: 'https://app.example.test' },
    payload: { email: 'ada@example.com', password: 'correct password' },
  });
  assert.equal(unknown.statusCode, 400);
  assert.equal(getLoginCalls(), 1);
});

test('login route maps operational login failures to generic 503', async (context) => {
  const { app } = createLoginRouteApp({
    login: async () => {
      throw new LoginServiceOperationalError();
    },
  });
  context.after(async () => app.close());
  const response = await app.inject({
    method: 'POST',
    url: '/auth/login',
    headers: { 'x-refresh-token-transport': 'body' },
    payload: { email: 'ada@example.com', password: 'correct password' },
  });
  assert.equal(response.statusCode, 503);
  assert.deepEqual(response.json(), { message: 'Login could not be completed' });
});

test('authentication guard rejects a JWT whose user does not own its session', async (context) => {
  const claimedUserId = new Types.ObjectId();
  const sessionOwnerId = new Types.ObjectId();
  const sessionId = new Types.ObjectId();
  let receivedUserId: Types.ObjectId | undefined;
  let receivedSessionId: Types.ObjectId | undefined;
  const app = Fastify();
  const jwtService = {
    verifyAccessToken: async () => ({
      userId: claimedUserId.toHexString(),
      sessionId: sessionId.toHexString(),
      issuedAt: 1,
      expiresAt: 2,
    }),
  };
  const sessionService = {
    isSessionActive: async (receivedId: Types.ObjectId, receivedOwnerId: Types.ObjectId) => {
      receivedSessionId = receivedId;
      receivedUserId = receivedOwnerId;
      return receivedId.equals(sessionId) && receivedOwnerId.equals(sessionOwnerId);
    },
  };

  await app.register(async (instance) => {
    instance.get(
      '/protected',
      { preHandler: createAuthenticationGuard(jwtService as never, sessionService as never) },
      async () => ({ ok: true }),
    );
  });
  context.after(async () => app.close());

  const response = await app.inject({
    method: 'GET',
    url: '/protected',
    headers: { authorization: 'Bearer valid-access-token' },
  });

  assert.equal(response.statusCode, 401);
  assert.deepEqual(response.json(), { message: 'Authentication required' });
  assert.equal(receivedSessionId?.equals(sessionId), true);
  assert.equal(receivedUserId?.equals(claimedUserId), true);
});

test('authentication guard distinguishes invalid identity from session storage failure', async (context) => {
  const app = Fastify();
  const jwtService = {
    verifyAccessToken: async () => {
      throw new Error('invalid');
    },
  };
  const sessionService = { isSessionActive: async () => true };
  await app.register(async (instance) => {
    instance.get(
      '/invalid',
      { preHandler: createAuthenticationGuard(jwtService as never, sessionService as never) },
      async () => ({ ok: true }),
    );
  });
  context.after(async () => app.close());
  assert.equal(
    (
      await app.inject({
        method: 'GET',
        url: '/invalid',
        headers: { authorization: 'Bearer token' },
      })
    ).statusCode,
    401,
  );

  const unavailable = Fastify();
  const unavailableJwt = {
    verifyAccessToken: async () => ({
      userId: new Types.ObjectId().toHexString(),
      sessionId: new Types.ObjectId().toHexString(),
      issuedAt: 1,
      expiresAt: 2,
    }),
  };
  const unavailableSessions = {
    isSessionActive: async () => {
      throw new Error('database unavailable');
    },
  };
  await unavailable.register(async (instance) => {
    instance.get(
      '/unavailable',
      {
        preHandler: createAuthenticationGuard(
          unavailableJwt as never,
          unavailableSessions as never,
        ),
      },
      async () => ({ ok: true }),
    );
  });
  context.after(async () => unavailable.close());
  assert.equal(
    (
      await unavailable.inject({
        method: 'GET',
        url: '/unavailable',
        headers: { authorization: 'Bearer token' },
      })
    ).statusCode,
    503,
  );
});

test('session routes return generic 503 responses for persistence failures', async (context) => {
  const userId = new Types.ObjectId();
  const sessionId = new Types.ObjectId();
  const fail = async () => {
    throw new SessionServiceError();
  };
  const app = createApp({
    loginService: {
      login: async () => ({ accessToken: 'a', refreshToken: 'b', sessionId: 'c' }),
    } as never,
    sessionService: {
      isSessionActive: async () => true,
      revokeSession: fail,
      revokeAllSessions: fail,
      listSessions: fail,
      revokeOwnedSession: fail,
    } as never,
    jwtService: {
      verifyAccessToken: async () => ({
        userId: userId.toHexString(),
        sessionId: sessionId.toHexString(),
        issuedAt: 1,
        expiresAt: 2,
      }),
    } as never,
    cookieOrigin: 'https://app.example.test',
  });
  context.after(async () => app.close());
  const headers = { authorization: 'Bearer access-token' };

  for (const request of [
    { method: 'POST' as const, url: '/auth/logout' },
    { method: 'POST' as const, url: '/auth/logout-all' },
    { method: 'GET' as const, url: '/sessions' },
    { method: 'DELETE' as const, url: `/sessions/${sessionId.toHexString()}` },
  ]) {
    const response = await app.inject({ ...request, headers });
    assert.equal(response.statusCode, 503);
    assert.deepEqual(response.json(), { message: 'Session operation could not be completed' });
  }
});

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
