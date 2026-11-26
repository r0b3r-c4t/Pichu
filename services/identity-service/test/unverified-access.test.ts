import assert from 'node:assert/strict';
import test from 'node:test';
import { Types } from 'mongoose';
import { createApp } from '../src/app.js';
import { LoginService } from '../src/services/login.service.js';
import { JwtService } from '../src/security/jwt.js';
import { hashPassword } from '../src/security/password.js';
import { UserProfileService } from '../src/services/user-profile.service.js';
import { generateNonce, signRequest, type KeyEntry } from '@pichu/internal-auth';
import type { NonceStore } from '@pichu/internal-auth-adapters/types';

function jwtService(): JwtService {
  return new JwtService({
    secret: 'test-secret-with-at-least-32-bytes-long',
    issuer: 'pichu-test',
    audience: 'pichu-api',
    accessTokenTtlSeconds: 900,
  });
}

test('profile service projects only persisted public fields and never passwordHash', async () => {
  const userId = new Types.ObjectId();
  const profile = new UserProfileService({
    findById: () => ({
      select: () => ({
        lean: () => ({
          exec: async () => ({
            _id: userId,
            name: 'Ada',
            email: 'ada@example.com',
            emailVerifiedAt: null,
            passwordHash: 'private-hash',
            __v: 3,
          }),
        }),
      }),
    }),
  } as never);
  assert.deepEqual(await profile.findById(String(userId)), {
    id: String(userId),
    name: 'Ada',
    username: null,
    email: 'ada@example.com',
    emailVerified: false,
    emailVerifiedAt: null,
  });
});

test('internal verification lookup checks the current database state without loading profile data', async () => {
  const userId = String(new Types.ObjectId());
  let verified = false;
  const service = new UserProfileService({
    exists: async (filter: { _id: string; emailVerifiedAt: unknown }) => {
      assert.equal(filter._id, userId);
      assert.deepEqual(filter.emailVerifiedAt, { $type: 'date' });
      return verified ? { _id: userId } : null;
    },
  } as never);
  assert.equal(await service.isEmailVerified(userId), false);
  verified = true;
  assert.equal(await service.isEmailVerified(userId), true);
});

test('v2 internal verification requires service auth, JWT actor binding and latest state', async (context) => {
  let verified = false;
  const userId = new Types.ObjectId().toHexString();
  const key: KeyEntry = {
    environment: 'test',
    sender: 'vehicle-service',
    audience: 'identity-service',
    keyId: 'test-key',
    secret: Buffer.alloc(32, 7),
    notBefore: 1,
    notAfter: 9_000_000_000_000,
    state: 'active',
  };
  const nonces: NonceStore = {
    assertReady: async () => undefined,
    reserve: async () => 'reserved',
  };
  const jwt = jwtService();
  const session = { isSessionActive: async () => true } as never;
  const sessionId = new Types.ObjectId().toHexString();
  const app = createApp({
    userProfileService: { isEmailVerified: async () => verified } as never,
    jwtService: jwt,
    sessionService: session,
    internalAuth: { environment: 'test', keyring: [key], nonces },
  });
  context.after(async () => app.close());
  const path = `/internal/users/${userId}/verified`;
  const unsigned = await app.inject({ method: 'GET', url: path });
  assert.equal(unsigned.statusCode, 401);
  const signed = async () => {
    const timestamp = Date.now();
    const headers = {
      'x-internal-auth-version': '2' as const,
      'x-service-name': 'vehicle-service' as const,
      'x-service-audience': 'identity-service' as const,
      'x-service-key-id': key.keyId,
      'x-contract-version': 'v1' as const,
      'x-timestamp': String(timestamp),
      'x-nonce': generateNonce(),
      'x-request-id': 'vehicle-request-1',
      'x-internal-deadline': String(timestamp + 2000),
      authorization: `Bearer ${await jwt.createAccessToken(userId, sessionId)}`,
    };
    const signature = signRequest(
      {
        environment: 'test',
        sender: key.sender,
        audience: key.audience,
        keyring: [key],
        now: timestamp,
      },
      headers,
      { method: 'GET', target: path, body: Buffer.alloc(0) },
    );
    return app.inject({
      method: 'GET',
      url: path,
      headers: {
        ...headers,
        'x-signature': signature,
      },
    });
  };
  const before = await signed();
  assert.equal(before.statusCode, 200);
  assert.deepEqual(before.json(), { verified: false });
  verified = true;
  const after = await signed();
  assert.equal(after.statusCode, 200);
  assert.deepEqual(after.json(), { verified: true });
});

test('unverified users receive valid access and refresh tokens without changing verification', async () => {
  const userId = new Types.ObjectId();
  const sessionId = new Types.ObjectId();
  const user = {
    _id: userId,
    passwordHash: await hashPassword('correct horse battery staple'),
    emailVerifiedAt: null,
  };
  const jwt = jwtService();
  const service = new LoginService({
    userModel: {
      findOne: () => ({ select: () => ({ exec: async () => user }) }),
    } as never,
    sessionService: {
      createSession: async () => ({ session: { _id: sessionId }, refreshToken: 'opaque-refresh' }),
    } as never,
    jwtService: jwt,
  });
  const result = await service.login({
    email: 'ada@example.com',
    password: 'correct horse battery staple',
  });
  assert.equal(result.refreshToken, 'opaque-refresh');
  assert.equal(result.sessionId, String(sessionId));
  assert.equal((await jwt.verifyAccessToken(result.accessToken)).userId, String(userId));
  assert.equal(user.emailVerifiedAt, null);
});

test('profile and authenticated resend work before verification; the same token sees verification later', async (context) => {
  const userId = new Types.ObjectId();
  const sessionId = new Types.ObjectId();
  const jwt = jwtService();
  const token = await jwt.createAccessToken(userId, sessionId);
  let verifiedAt: string | null = null;
  const sentTo: string[] = [];
  const app = createApp({
    loginService: { login: async () => ({}) } as never,
    sessionService: { refreshTokenTtlSeconds: 900, isSessionActive: async () => true } as never,
    jwtService: jwt,
    cookieOrigin: 'http://localhost:3000',
    userProfileService: {
      findById: async () => ({
        id: String(userId),
        name: 'Ada',
        username: 'ada_01',
        email: 'ada@example.com',
        emailVerified: verifiedAt !== null,
        emailVerifiedAt: verifiedAt,
      }),
    } as never,
    emailVerificationService: {
      verifyEmail: async () => {
        verifiedAt = new Date().toISOString();
        return true;
      },
      resendVerification: async (email: string) => {
        sentTo.push(email);
      },
    } as never,
  });
  context.after(async () => app.close());
  const headers = { authorization: `Bearer ${token}` };
  const before = await app.inject({ method: 'GET', url: '/auth/me', headers });
  assert.equal(before.statusCode, 200);
  assert.equal(before.json().emailVerified, false);
  assert.equal(before.json().emailVerifiedAt, null);
  assert.equal(before.body.includes('passwordHash'), false);

  const resend = await app.inject({ method: 'POST', url: '/auth/verification/resend/me', headers });
  assert.equal(resend.statusCode, 202);
  assert.deepEqual(resend.json(), { accepted: true });
  assert.deepEqual(sentTo, ['ada@example.com']);

  const verify = await app.inject({
    method: 'POST',
    url: '/auth/verify-email',
    payload: { token: 'a'.repeat(64) },
  });
  assert.equal(verify.statusCode, 200);
  const after = await app.inject({ method: 'GET', url: '/auth/me', headers });
  assert.equal(after.statusCode, 200);
  assert.equal(after.json().emailVerified, true);
  assert.ok(after.json().emailVerifiedAt);

  const invalid = await app.inject({
    method: 'GET',
    url: '/auth/me',
    headers: { authorization: 'Bearer invalid' },
  });
  assert.equal(invalid.statusCode, 401);
  const docs = await app.inject({ method: 'GET', url: '/docs/json' });
  const document = docs.json() as {
    paths: Record<
      string,
      Record<string, { responses: Record<string, unknown>; security?: unknown }>
    >;
  };
  assert.ok(document.paths['/auth/me'].get.responses['200']);
  assert.ok(document.paths['/auth/me'].get.responses['401']);
  assert.ok(document.paths['/auth/me'].get.security);
  assert.ok(document.paths['/auth/verification/resend/me'].post.responses['202']);
});
