import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import mongoose, { Types } from 'mongoose';
import { EmailTokenModel } from '../src/models/email-token.model.js';
import { RefreshTokenModel } from '../src/models/refresh-token.model.js';
import { SessionModel } from '../src/models/session.model.js';
import { UserModel } from '../src/models/user.model.js';
import { generateOpaqueToken, hashToken } from '../src/security/crypto.js';
import { hashPassword, verifyPassword } from '../src/security/password.js';
import {
  createMongoosePasswordRecoveryRepository,
  PasswordRecoveryService,
} from '../src/services/password-recovery.service.js';
import { SessionService } from '../src/services/session.service.js';

const databaseUrl = process.env.IDENTITY_TEST_DATABASE_URL;
const expectedDatabaseName = 'identity_test_db';
let connectionInitialization: Promise<void> | undefined;

async function connectToTestReplicaSet(): Promise<void> {
  assert.ok(databaseUrl, 'IDENTITY_TEST_DATABASE_URL is required');
  const databaseName = decodeURIComponent(new URL(databaseUrl).pathname.replace(/^\/+/, ''));
  assert.equal(databaseName, expectedDatabaseName);
  if (!connectionInitialization) {
    connectionInitialization = mongoose
      .connect(databaseUrl, { serverSelectionTimeoutMS: 5_000 })
      .then(async () => {
        const hello = await mongoose.connection.db?.admin().command({ hello: 1 });
        assert.equal(hello?.setName, 'pichu-rs');
        assert.equal(hello?.isWritablePrimary, true);
        await Promise.all([
          UserModel.createIndexes(),
          EmailTokenModel.createIndexes(),
          SessionModel.createIndexes(),
          RefreshTokenModel.createIndexes(),
        ]);
      });
  }
  await connectionInitialization;
}

after(async () => mongoose.disconnect());

test('concurrent confirmations consume a recovery token once', { skip: !databaseUrl }, async () => {
  await connectToTestReplicaSet();
  const fixture = await createFixture();
  try {
    const { service } = createRecoveryService();
    const results = await Promise.all([
      service.confirmRecovery(fixture.rawToken, 'first new password'),
      service.confirmRecovery(fixture.rawToken, 'second new password'),
    ]);
    assert.deepEqual(results.sort(), [false, true]);
    assert.equal(await service.confirmRecovery(fixture.rawToken, 'third new password'), false);
  } finally {
    await fixture.cleanup();
  }
});

test(
  'expired and email verification tokens cannot reset a password',
  { skip: !databaseUrl },
  async () => {
    await connectToTestReplicaSet();
    const fixture = await createFixture();
    try {
      const { service } = createRecoveryService();
      await EmailTokenModel.updateOne(
        { _id: fixture.emailToken._id },
        { $set: { expiresAt: new Date(Date.now() - 1000) } },
      );
      assert.equal(await service.confirmRecovery(fixture.rawToken, 'new password value'), false);
      await EmailTokenModel.updateOne(
        { _id: fixture.emailToken._id },
        { $set: { expiresAt: new Date(Date.now() + 60_000), type: 'EMAIL_VERIFICATION' } },
      );
      assert.equal(await service.confirmRecovery(fixture.rawToken, 'new password value'), false);
      const user = await UserModel.findById(fixture.userId).select('+passwordHash').lean().exec();
      assert.equal(user?.passwordHash, fixture.oldPasswordHash);
    } finally {
      await fixture.cleanup();
    }
  },
);

async function createFixture() {
  const userId = new Types.ObjectId();
  const oldPasswordHash = await hashPassword('old password value');
  await UserModel.create({
    _id: userId,
    name: 'Ada',
    username: `u_${userId.toHexString()}`,
    email: `${userId.toHexString()}@example.com`,
    normalizedEmail: `${userId.toHexString()}@example.com`,
    passwordHash: oldPasswordHash,
    passwordRecoverySequence: 1,
    passwordRecoveryGeneration: 1,
    emailVerifiedAt: new Date(),
  });
  const sessionService = new SessionService();
  const createdSession = await sessionService.createSession(userId, 'recovery integration');
  const rawToken = generateOpaqueToken();
  const emailToken = await EmailTokenModel.create({
    userId,
    type: 'PASSWORD_RESET',
    tokenHash: hashToken(rawToken),
    generation: 1,
    status: 'ACTIVE',
    expiresAt: new Date(Date.now() + 60_000),
    usedAt: null,
  });

  return {
    userId,
    oldPasswordHash,
    rawToken,
    emailToken,
    createdSession,
    sessionService,
    async cleanup() {
      await Promise.all([
        EmailTokenModel.deleteMany({ userId }).exec(),
        RefreshTokenModel.deleteMany({ sessionId: createdSession.session._id }).exec(),
        SessionModel.deleteMany({ userId }).exec(),
        UserModel.deleteOne({ _id: userId }).exec(),
      ]);
    },
  };
}

async function createRecoveryUserFixture() {
  const userId = new Types.ObjectId();
  await UserModel.create({
    _id: userId,
    name: 'Ada',
    username: `u_${userId.toHexString()}`,
    email: `${userId.toHexString()}@example.com`,
    normalizedEmail: `${userId.toHexString()}@example.com`,
    passwordHash: await hashPassword('old password value'),
    emailVerifiedAt: new Date(),
  });
  return {
    userId,
    email: `${userId.toHexString()}@example.com`,
    async cleanup() {
      await Promise.all([
        EmailTokenModel.deleteMany({ userId }).exec(),
        UserModel.deleteOne({ _id: userId }).exec(),
      ]);
    },
  };
}

function createRecoveryService() {
  const sessionService = new SessionService();
  const repository = createMongoosePasswordRecoveryRepository({ sessionService });
  return {
    repository,
    service: new PasswordRecoveryService({
      repository,
      resetUrl: 'https://app.example.test/reset-password',
      emailProvider: { send: async () => ({ id: 'accepted' }) },
    }),
  };
}

test(
  'password recovery creates and activates a generated token',
  { skip: !databaseUrl },
  async () => {
    await connectToTestReplicaSet();
    const fixture = await createRecoveryUserFixture();
    try {
      const { service } = createRecoveryService();
      assert.deepEqual(await service.requestRecovery(fixture.email), { accepted: true });
      const [user, token] = await Promise.all([
        UserModel.findById(fixture.userId).lean().exec(),
        EmailTokenModel.findOne({ userId: fixture.userId }).lean().exec(),
      ]);
      assert.ok(user && token);
      assert.equal(user.passwordRecoverySequence, 1);
      assert.equal(user.passwordRecoveryGeneration, 1);
      assert.equal(token.generation, 1);
      assert.equal(token.status, 'ACTIVE');
    } finally {
      await fixture.cleanup();
    }
  },
);

test(
  'delivery failure invalidates only the pending token and preserves the active token',
  { skip: !databaseUrl },
  async () => {
    await connectToTestReplicaSet();
    const fixture = await createRecoveryUserFixture();
    await UserModel.updateOne(
      { _id: fixture.userId },
      { $set: { passwordRecoverySequence: 1, passwordRecoveryGeneration: 1 } },
    ).exec();
    const previousToken = await EmailTokenModel.create({
      userId: fixture.userId,
      type: 'PASSWORD_RESET',
      tokenHash: hashToken(generateOpaqueToken()),
      generation: 1,
      status: 'ACTIVE',
      expiresAt: new Date(Date.now() + 60_000),
    });
    try {
      const sessionService = new SessionService();
      const repository = createMongoosePasswordRecoveryRepository({ sessionService });
      const service = new PasswordRecoveryService({
        repository,
        resetUrl: 'https://app.example.test/reset-password',
        emailProvider: {
          send: async () => {
            throw new Error('provider failure');
          },
        },
      });
      await assert.rejects(service.requestRecovery(fixture.email));
      const tokens = await EmailTokenModel.find({ userId: fixture.userId })
        .sort({ generation: 1 })
        .lean()
        .exec();
      assert.equal(tokens.find((token) => token._id.equals(previousToken._id))?.status, 'ACTIVE');
      assert.equal(tokens.find((token) => token.generation === 2)?.status, 'INVALIDATED');
    } finally {
      await fixture.cleanup();
    }
  },
);

test(
  'concurrent recovery requests leave only the latest generation active',
  { skip: !databaseUrl },
  async () => {
    await connectToTestReplicaSet();
    const fixture = await createRecoveryUserFixture();
    try {
      const first = createRecoveryService().service;
      const second = createRecoveryService().service;
      await Promise.all([
        first.requestRecovery(fixture.email),
        second.requestRecovery(fixture.email),
      ]);
      const [user, tokens] = await Promise.all([
        UserModel.findById(fixture.userId).lean().exec(),
        EmailTokenModel.find({ userId: fixture.userId }).lean().exec(),
      ]);
      assert.ok(user);
      assert.equal(user.passwordRecoverySequence, 2);
      assert.equal(user.passwordRecoveryGeneration, 2);
      assert.equal(tokens.filter((token) => token.status === 'ACTIVE').length, 1);
      assert.equal(tokens.find((token) => token.status === 'ACTIVE')?.generation, 2);
    } finally {
      await fixture.cleanup();
    }
  },
);

test(
  'activation rejects an obsolete generation without activating its token',
  { skip: !databaseUrl },
  async () => {
    await connectToTestReplicaSet();
    const fixture = await createRecoveryUserFixture();
    try {
      const { repository } = createRecoveryService();
      const first = await repository.createPendingToken({
        userId: fixture.userId,
        tokenHash: hashToken(generateOpaqueToken()),
        expiresAt: new Date(Date.now() + 60_000),
      });
      const second = await repository.createPendingToken({
        userId: fixture.userId,
        tokenHash: hashToken(generateOpaqueToken()),
        expiresAt: new Date(Date.now() + 60_000),
      });
      assert.equal(first.generation, 1);
      assert.equal(second.generation, 2);
      assert.equal(
        await repository.activatePendingToken({
          tokenId: second._id,
          userId: fixture.userId,
          generation: second.generation,
          now: new Date(),
        }),
        true,
      );
      assert.equal(
        await repository.activatePendingToken({
          tokenId: first._id,
          userId: fixture.userId,
          generation: first.generation,
          now: new Date(),
        }),
        false,
      );
      const firstToken = await EmailTokenModel.findById(first._id).lean().exec();
      assert.equal(firstToken?.status, 'PENDING');
    } finally {
      await fixture.cleanup();
    }
  },
);

test(
  'password recovery commits password, token consumption and session revocation together',
  { skip: !databaseUrl },
  async () => {
    await connectToTestReplicaSet();
    const fixture = await createFixture();
    try {
      const repository = createMongoosePasswordRecoveryRepository({
        sessionService: fixture.sessionService,
      });
      const service = new PasswordRecoveryService({
        repository,
        resetUrl: 'https://app.example.test/reset-password',
        emailProvider: { send: async () => ({ id: 'unused' }) },
      });

      assert.equal(await service.confirmRecovery(fixture.rawToken, 'new password value'), true);
      const [user, token, session, refreshToken] = await Promise.all([
        UserModel.findById(fixture.userId).select('+passwordHash').lean().exec(),
        EmailTokenModel.findById(fixture.emailToken._id).lean().exec(),
        SessionModel.findById(fixture.createdSession.session._id).lean().exec(),
        RefreshTokenModel.findOne({ sessionId: fixture.createdSession.session._id }).lean().exec(),
      ]);
      assert.ok(user && token && session && refreshToken);
      assert.notEqual(user.passwordHash, fixture.oldPasswordHash);
      assert.equal(token.usedAt instanceof Date, true);
      assert.equal(token.status, 'USED');
      assert.equal(user.passwordRecoveryGeneration, null);
      assert.equal(user.passwordRecoverySequence, 2);
      assert.equal(session.revokedAt instanceof Date, true);
      assert.equal(refreshToken.revokedAt instanceof Date, true);
      assert.equal(await verifyPassword(user.passwordHash, 'new password value'), true);
    } finally {
      await fixture.cleanup();
    }
  },
);

test(
  'password recovery rolls all changes back when session revocation fails after updating',
  { skip: !databaseUrl },
  async () => {
    await connectToTestReplicaSet();
    const fixture = await createFixture();
    try {
      const failingSessionService = {
        assertPersistenceConnection: (connection: typeof mongoose.connection) => {
          if (connection !== mongoose.connection) {
            throw new Error('unexpected connection');
          }
        },
        revokeAllSessions: async (
          userId: Types.ObjectId,
          reason: string,
          transaction: Parameters<SessionService['revokeAllSessions']>[2],
        ) => {
          await fixture.sessionService.revokeAllSessions(userId, reason, transaction);
          throw new Error('forced rollback');
        },
      };
      const repository = createMongoosePasswordRecoveryRepository({
        sessionService: failingSessionService as never,
      });
      const service = new PasswordRecoveryService({
        repository,
        resetUrl: 'https://app.example.test/reset-password',
        emailProvider: { send: async () => ({ id: 'unused' }) },
      });

      await assert.rejects(service.confirmRecovery(fixture.rawToken, 'new password value'));
      const [user, token, session, refreshToken] = await Promise.all([
        UserModel.findById(fixture.userId).select('+passwordHash').lean().exec(),
        EmailTokenModel.findById(fixture.emailToken._id).lean().exec(),
        SessionModel.findById(fixture.createdSession.session._id).lean().exec(),
        RefreshTokenModel.findOne({ sessionId: fixture.createdSession.session._id }).lean().exec(),
      ]);
      assert.ok(user && token && session && refreshToken);
      assert.equal(user.passwordHash, fixture.oldPasswordHash);
      assert.equal(token.usedAt, null);
      assert.equal(token.status, 'ACTIVE');
      assert.equal(user.passwordRecoveryGeneration, 1);
      assert.equal(user.passwordRecoverySequence, 1);
      assert.equal(session.revokedAt, null);
      assert.equal(refreshToken.revokedAt, null);
    } finally {
      await fixture.cleanup();
    }
  },
);
