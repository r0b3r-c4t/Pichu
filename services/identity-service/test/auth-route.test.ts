import assert from 'node:assert/strict';
import { assertApiError } from './error-assertion.js';
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
  assert.match(loginCookie, /Secure/);
  assert.match(loginCookie, /SameSite=Lax/);
  assert.match(loginCookie, /Path=\/auth(?:;|$)/);
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
  assertApiError(response, 'SERVICE_UNAVAILABLE', 'Request could not be completed');
  assert.equal(response.body.includes('sensitive signing failure'), false);
  const clearedCookie = getSetCookieHeader(response.headers['set-cookie']);
  assert.match(clearedCookie, /pichu_refresh_token=;/);
  assert.match(clearedCookie, /Max-Age=0/);
  assert.equal(revocations.length, 1);
  assert.equal(revocations[0].sessionId.equals(sessionId), true);
  assert.equal(revocations[0].reason, 'access-token-issuance-failed');
});

test('login ignores the former transport selector and never exposes refresh tokens', async (context) => {
  const { app, getLoginCalls } = createLoginRouteApp();
  context.after(async () => app.close());

  const response = await app.inject({
    method: 'POST',
    url: '/auth/login',
    headers: { 'x-refresh-token-transport': 'body', origin: 'https://app.example.test' },
    payload: { email: 'ada@example.com', password: 'correct password' },
  });
  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json(), { accessToken: 'access-token' });
  assert.match(getSetCookieHeader(response.headers['set-cookie']), /HttpOnly/);
  assert.equal(getLoginCalls(), 1);
});

test('logout and logout-all reject missing Origin before revoking a session', async (context) => {
  let revocations = 0;
  const app = createApp({
    loginService: { login: async () => ({}) } as never,
    sessionService: {
      refreshTokenTtlSeconds: 900,
      isSessionActive: async () => true,
      revokeSession: async () => {
        revocations += 1;
      },
      revokeAllSessions: async () => {
        revocations += 1;
      },
    } as never,
    jwtService: {
      verifyAccessToken: async () => ({
        userId: new Types.ObjectId().toHexString(),
        sessionId: new Types.ObjectId().toHexString(),
        issuedAt: 1,
        expiresAt: 2,
      }),
    } as never,
    cookieOrigin: 'https://app.example.test',
  });
  context.after(async () => app.close());
  for (const url of ['/auth/logout', '/auth/logout-all']) {
    const response = await app.inject({
      method: 'POST',
      url,
      headers: { authorization: 'Bearer access-token' },
    });
    assert.equal(response.statusCode, 403);
    assertApiError(response, 'FORBIDDEN', 'Invalid request origin');
  }
  assert.equal(revocations, 0);
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
    headers: { origin: 'https://app.example.test' },
    payload: { email: 'ada@example.com', password: 'correct password' },
  });
  assert.equal(response.statusCode, 503);
  assertApiError(response, 'SERVICE_UNAVAILABLE', 'Login could not be completed');
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
  const headers = { authorization: 'Bearer access-token', origin: 'https://app.example.test' };

  for (const request of [
    { method: 'POST' as const, url: '/auth/logout' },
    { method: 'POST' as const, url: '/auth/logout-all' },
    { method: 'GET' as const, url: '/sessions' },
    { method: 'DELETE' as const, url: `/sessions/${sessionId.toHexString()}` },
  ]) {
    const response = await app.inject({ ...request, headers });
    assert.equal(response.statusCode, 503);
    assertApiError(response, 'SERVICE_UNAVAILABLE', 'Session operation could not be completed');
  }
});

test('register route rejects invalid input without sensitive response fields', async (context) => {
  const service = new RegistrationService({
    repository: {
      findUserByNormalizedEmail: async () => null,
      findUserByNormalizedUsername: async () => null,
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
    payload: { name: '', username: 'ada_01', email: 'invalid', password: 'short' },
  });

  assert.equal(response.statusCode, 400);
  const invalid = assertApiError(response, 'VALIDATION_ERROR', 'Invalid registration data');
  assert.deepEqual(
    invalid.details?.map(({ field }) => field),
    ['name', 'email', 'password'],
  );
});

test('register route returns a generic accepted response for valid input', async (context) => {
  const service = new RegistrationService({
    repository: {
      findUserByNormalizedEmail: async () => null,
      findUserByNormalizedUsername: async () => null,
      createUser: async () =>
        new UserModel({
          _id: new Types.ObjectId(),
          name: 'Ada',
          username: 'ada_01',
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
    payload: {
      name: 'Ada',
      username: 'ada_01',
      email: 'ada@example.com',
      password: 'correct horse battery staple',
    },
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json(), { accepted: true });
});

test('register route exposes explicit conflict codes with the request ID', async (context) => {
  for (const [field, code] of [
    ['email', 'USER_ALREADY_EXISTS'],
    ['username', 'USERNAME_ALREADY_EXISTS'],
  ] as const) {
    const service = new RegistrationService({
      repository: {
        findUserByNormalizedEmail: async () => (field === 'email' ? new UserModel({}) : null),
        findUserByNormalizedUsername: async () => (field === 'username' ? new UserModel({}) : null),
        createUser: async () => {
          throw new Error('unexpected user');
        },
        createEmailToken: async () => {
          throw new Error('unexpected token');
        },
        deleteEmailToken: async () => undefined,
      },
      emailProvider: {
        send: async () => {
          throw new Error('unexpected email');
        },
      },
      verificationUrl: 'http://localhost:3000/verify-email',
    });
    const app = createApp({ registrationService: service });
    context.after(async () => app.close());
    const response = await app.inject({
      method: 'POST',
      url: '/auth/register',
      headers: { 'x-request-id': 'register-123' },
      payload: {
        name: 'Ada',
        username: 'ada_01',
        email: 'ada@example.com',
        password: 'password123',
      },
    });
    assert.equal(response.statusCode, 409);
    assert.equal(response.json().error, code);
    assert.equal(response.json().requestId, 'register-123');
    assert.equal(response.headers['x-request-id'], 'register-123');
  }
});

test('Identity Swagger requires username and documents both registration conflicts', async (context) => {
  const app = createApp();
  context.after(async () => app.close());
  const document = (await app.inject('/docs/json')).json();
  const register = document.paths['/auth/register'].post;
  const request = register.requestBody.content['application/json'].schema;
  assert.ok(request.required.includes('username'));
  assert.equal(request.properties.username.minLength, 3);
  assert.equal(request.properties.username.maxLength, 30);
  assert.equal(register.responses['409'].description, 'Email or username already in use');
  assert.equal(
    register.responses['409'].content['application/json'].examples.email.value.error,
    'USER_ALREADY_EXISTS',
  );
  assert.equal(
    register.responses['409'].content['application/json'].examples.username.value.error,
    'USERNAME_ALREADY_EXISTS',
  );
});

test('register route uses the shared password policy and returns password validation details', async (context) => {
  const registeredPasswords: string[] = [];
  const app = createApp({
    registrationService: {
      register: async (input: { password: string }) => {
        registeredPasswords.push(input.password);
        return { accepted: true };
      },
    } as never,
  });
  context.after(async () => app.close());

  for (const password of ['x'.repeat(8), 'x'.repeat(12), 'x'.repeat(256)]) {
    const response = await app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: { name: 'Driver', username: 'ada_01', email: 'driver@example.com', password },
    });
    assert.equal(response.statusCode, 200);
  }

  for (const [password, expectedMessage] of [
    ['x'.repeat(7), 'Password must contain 8 to 256 characters'],
    ['x'.repeat(257), 'Password must contain 8 to 256 characters'],
  ]) {
    const response = await app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: { name: 'Driver', username: 'ada_01', email: 'driver@example.com', password },
    });
    assert.equal(response.statusCode, 400);
    const error = assertApiError(response, 'VALIDATION_ERROR', 'Invalid registration data');
    assert.deepEqual(
      error.details?.map(({ field }) => field),
      ['password'],
    );
    assert.equal(error.details?.[0]?.message, expectedMessage);
  }

  assert.deepEqual(
    registeredPasswords.map((password) => password.length),
    [8, 12, 256],
  );
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
          username: 'ada_01',
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
      username: 'ada_01',
      email: 'ada@example.com',
      password: 'correct horse battery staple',
    },
  });

  assert.deepEqual(
    responses.map((response) => response.statusCode),
    [200, 200, 200, 200, 200, 429],
  );
  assert.deepEqual(responses[4].json(), { accepted: true });
  assertApiError(responses[5], 'RATE_LIMIT_EXCEEDED', 'Too many requests');
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
      findUserByNormalizedUsername: async () => null,
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
    payload: {
      name: 'Ada',
      username: 'ada_01',
      email: 'ada@example.com',
      password: 'correct horse battery staple',
    },
  });

  assert.equal(response.statusCode, 503);
  assertApiError(response, 'SERVICE_UNAVAILABLE', 'Registration could not be completed');
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
    payload: {
      name: 'Ada',
      username: 'ada_01',
      email: 'ada@example.com',
      password: 'correct horse battery staple',
    },
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
  assertApiError(response, 'INVALID_TOKEN', 'Invalid or expired verification token');
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
  assertApiError(responses[5], 'RATE_LIMIT_EXCEEDED', 'Too many requests');
});
