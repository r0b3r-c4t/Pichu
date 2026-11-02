import assert from 'node:assert/strict';
import test from 'node:test';
import { Types } from 'mongoose';
import { createApp } from '../src/app.js';
import { UserModel } from '../src/models/user.model.js';
import { hashPassword } from '../src/security/password.js';
import {
  LoginService,
  LoginServiceError,
  LoginServiceOperationalError,
} from '../src/services/login.service.js';

test('login revokes the newly created session when access-token issuance fails', async () => {
  const user = new UserModel({
    _id: new Types.ObjectId(),
    name: 'Ada',
    email: 'ada@example.com',
    normalizedEmail: 'ada@example.com',
    passwordHash: await hashPassword('correct password'),
    emailVerifiedAt: new Date(),
  });
  const query = {
    select: () => query,
    exec: async () => user,
  };
  const session = {
    _id: new Types.ObjectId(),
    userId: user._id,
    familyId: 'family',
    createdAt: new Date(),
    lastActivityAt: new Date(),
    expiresAt: new Date(Date.now() + 60_000),
    revokedAt: null,
    revokeReason: null,
    userAgent: null,
  };
  let revoked = 0;
  const service = new LoginService({
    userModel: { findOne: () => query } as never,
    sessionService: {
      createSession: async () => ({ session, refreshToken: 'a'.repeat(64) }),
      revokeSession: async () => {
        revoked += 1;
      },
    } as never,
    jwtService: {
      createAccessToken: async () => {
        throw new Error('signing failed');
      },
    } as never,
  });

  await assert.rejects(
    service.login({ email: 'ADA@example.com', password: 'correct password' }),
    LoginServiceOperationalError,
  );
  assert.equal(revoked, 1);
});

test('login distinguishes persistence failures from invalid credentials', async () => {
  const operationalUserModel = {
    findOne: () => {
      throw new Error('database unavailable');
    },
  };
  const operationalLookup = new LoginService({
    userModel: operationalUserModel as never,
    sessionService: {} as never,
    jwtService: {} as never,
  });
  await assert.rejects(
    operationalLookup.login({ email: 'ada@example.com', password: 'wrong' }),
    LoginServiceOperationalError,
  );

  const user = new UserModel({
    _id: new Types.ObjectId(),
    name: 'Ada',
    email: 'ada@example.com',
    normalizedEmail: 'ada@example.com',
    passwordHash: await hashPassword('correct password'),
    emailVerifiedAt: new Date(),
  });
  const query = { select: () => query, exec: async () => user };
  const operationalSession = new LoginService({
    userModel: { findOne: () => query } as never,
    sessionService: {
      createSession: async () => {
        throw new Error('session unavailable');
      },
    } as never,
    jwtService: {} as never,
  });
  await assert.rejects(
    operationalSession.login({ email: 'ada@example.com', password: 'correct password' }),
    LoginServiceOperationalError,
  );
  assert.notEqual(LoginServiceError, LoginServiceOperationalError);
});

test('session deletion is scoped to the authenticated owner in persistence operation', async (context) => {
  const ownerId = new Types.ObjectId();
  const otherSessionId = new Types.ObjectId();
  let receivedUserId: Types.ObjectId | undefined;
  let receivedSessionId: Types.ObjectId | undefined;
  const sessionService = {
    isSessionActive: async () => true,
    listSessions: async () => [
      {
        _id: otherSessionId,
        createdAt: new Date(),
        lastActivityAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000),
        revokedAt: null,
        userAgent: null,
      },
    ],
    revokeOwnedSession: async (sessionId: Types.ObjectId, userId: Types.ObjectId) => {
      receivedSessionId = sessionId;
      receivedUserId = userId;
      return false;
    },
  };
  const app = createApp({
    loginService: {
      login: async () => ({ accessToken: 'a', refreshToken: 'b', sessionId: 'c' }),
    } as never,
    sessionService: sessionService as never,
    jwtService: {
      verifyAccessToken: async () => ({
        userId: ownerId.toHexString(),
        sessionId: new Types.ObjectId().toHexString(),
        issuedAt: 1,
        expiresAt: 2,
      }),
    } as never,
    cookieOrigin: 'https://app.example.test',
  });
  context.after(async () => app.close());

  const response = await app.inject({
    method: 'DELETE',
    url: `/sessions/${otherSessionId.toHexString()}`,
    headers: { authorization: 'Bearer access-token' },
  });
  assert.equal(response.statusCode, 404);
  assert.equal(receivedSessionId?.equals(otherSessionId), true);
  assert.equal(receivedUserId?.equals(ownerId), true);
});
