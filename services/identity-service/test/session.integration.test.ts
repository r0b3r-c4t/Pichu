import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import mongoose, { Types } from 'mongoose';
import { RefreshTokenModel } from '../src/models/refresh-token.model.js';
import { SessionModel } from '../src/models/session.model.js';
import { hashToken } from '../src/security/crypto.js';
import {
  RefreshTokenInvalidError,
  RefreshTokenReuseError,
  SessionService,
} from '../src/services/session.service.js';

const databaseUrl = process.env.IDENTITY_TEST_DATABASE_URL;
const expectedDatabaseName = 'identity_test_db';
const expectedReplicaSetName = 'pichu-rs';
let connectionInitialization: Promise<void> | undefined;

function assertTestDatabaseUrl(connectionString: string): void {
  let databaseName: string;
  try {
    databaseName = decodeURIComponent(new URL(connectionString).pathname.replace(/^\/+/, ''));
  } catch {
    assert.fail('IDENTITY_TEST_DATABASE_URL must be a valid MongoDB URI');
  }
  assert.equal(
    databaseName,
    expectedDatabaseName,
    `Session integration tests require the ${expectedDatabaseName} database`,
  );
}

async function connectToTestReplicaSet(): Promise<void> {
  assert.ok(databaseUrl, 'IDENTITY_TEST_DATABASE_URL is required');
  assertTestDatabaseUrl(databaseUrl);

  if (!connectionInitialization) {
    connectionInitialization = mongoose
      .connect(databaseUrl, { serverSelectionTimeoutMS: 5000 })
      .then(async () => {
        assert.equal(mongoose.connection.name, expectedDatabaseName);
        const hello = await mongoose.connection.db?.admin().command({ hello: 1 });
        assert.equal(hello?.setName, expectedReplicaSetName);
        assert.equal(hello?.isWritablePrimary, true);
        await Promise.all([SessionModel.createIndexes(), RefreshTokenModel.createIndexes()]);
      })
      .catch((error: unknown) => {
        connectionInitialization = undefined;
        throw error;
      });
  }

  await connectionInitialization;
}

after(async () => mongoose.disconnect());

function createFixture() {
  const userIds = new Map<string, Types.ObjectId>();
  const userId = new Types.ObjectId();
  userIds.set(userId.toHexString(), userId);
  const service = new SessionService();

  return {
    userId,
    service,
    addUserId(): Types.ObjectId {
      const id = new Types.ObjectId();
      userIds.set(id.toHexString(), id);
      return id;
    },
    async createSession(ownerId = userId, userAgent?: string) {
      const result = await service.createSession(ownerId, userAgent);
      return result;
    },
    async cleanup(): Promise<void> {
      const sessions = await SessionModel.find({ userId: { $in: [...userIds.values()] } })
        .select({ _id: 1 })
        .lean()
        .exec();
      const sessionIds = sessions.map((session) => session._id);
      await Promise.all([
        RefreshTokenModel.deleteMany({ sessionId: { $in: sessionIds } }).exec(),
        SessionModel.deleteMany({ userId: { $in: [...userIds.values()] } }).exec(),
      ]);
    },
  };
}

test(
  'persists a session and only the hash of its associated refresh token',
  { skip: !databaseUrl },
  async () => {
    await connectToTestReplicaSet();
    const fixture = createFixture();

    try {
      const created = await fixture.createSession(fixture.userId, 'PICHU integration test');
      const [storedSession, storedToken, tokenWithPlaintext] = await Promise.all([
        SessionModel.findById(created.session._id).lean().exec(),
        RefreshTokenModel.findOne({ sessionId: created.session._id }).lean().exec(),
        RefreshTokenModel.findOne({ tokenHash: created.refreshToken }).lean().exec(),
      ]);

      assert.ok(storedSession);
      assert.ok(storedToken);
      assert.equal(storedSession.userId.equals(fixture.userId), true);
      assert.equal(storedSession.familyId, storedToken.familyId);
      assert.equal(storedToken.sessionId.equals(storedSession._id), true);
      assert.equal(storedToken.tokenHash, hashToken(created.refreshToken));
      assert.notEqual(storedToken.tokenHash, created.refreshToken);
      assert.equal(tokenWithPlaintext, null);
    } finally {
      await fixture.cleanup();
    }
  },
);

test('rotates a refresh token and keeps the session active', { skip: !databaseUrl }, async () => {
  await connectToTestReplicaSet();
  const fixture = createFixture();

  try {
    const created = await fixture.createSession();
    const originalToken = await RefreshTokenModel.findOne({
      sessionId: created.session._id,
      tokenHash: hashToken(created.refreshToken),
    })
      .lean()
      .exec();
    assert.ok(originalToken);

    const rotated = await fixture.service.rotateRefreshToken(created.refreshToken);
    const [storedOriginal, storedReplacement, storedSession] = await Promise.all([
      RefreshTokenModel.findById(originalToken._id).lean().exec(),
      RefreshTokenModel.findOne({ tokenHash: hashToken(rotated.refreshToken) })
        .lean()
        .exec(),
      SessionModel.findById(created.session._id).lean().exec(),
    ]);

    assert.ok(storedOriginal?.usedAt instanceof Date);
    assert.ok(storedReplacement);
    assert.equal(storedOriginal?.replacedBy?.equals(storedReplacement._id), true);
    assert.equal(storedReplacement.sessionId.equals(created.session._id), true);
    assert.equal(storedReplacement.familyId, created.session.familyId);
    assert.equal(storedReplacement.tokenHash, hashToken(rotated.refreshToken));
    assert.notEqual(storedReplacement.tokenHash, rotated.refreshToken);
    assert.equal(storedSession?.revokedAt, null);
    assert.equal(await fixture.service.isSessionActive(created.session._id, fixture.userId), true);
  } finally {
    await fixture.cleanup();
  }
});

test(
  'revokes the full session and token family after refresh token reuse',
  { skip: !databaseUrl },
  async () => {
    await connectToTestReplicaSet();
    const fixture = createFixture();

    try {
      const created = await fixture.createSession();
      const rotated = await fixture.service.rotateRefreshToken(created.refreshToken);

      await assert.rejects(
        fixture.service.rotateRefreshToken(created.refreshToken),
        RefreshTokenReuseError,
      );

      const [storedSession, storedTokens] = await Promise.all([
        SessionModel.findById(created.session._id).lean().exec(),
        RefreshTokenModel.find({ sessionId: created.session._id }).lean().exec(),
      ]);
      assert.ok(storedSession?.revokedAt instanceof Date);
      assert.equal(storedSession?.revokeReason, 'refresh-token-reuse');
      assert.equal(storedTokens.length, 2);
      assert.ok(storedTokens.every((token) => token.revokedAt instanceof Date));
      await assert.rejects(
        fixture.service.rotateRefreshToken(rotated.refreshToken),
        RefreshTokenInvalidError,
      );
    } finally {
      await fixture.cleanup();
    }
  },
);

test(
  'concurrent rotations allow one consumption and revoke the session on reuse',
  { skip: !databaseUrl },
  async () => {
    await connectToTestReplicaSet();
    const fixture = createFixture();

    try {
      const created = await fixture.createSession();
      const outcomes = await Promise.allSettled([
        fixture.service.rotateRefreshToken(created.refreshToken),
        fixture.service.rotateRefreshToken(created.refreshToken),
      ]);

      const fulfilled = outcomes.filter(
        (
          outcome,
        ): outcome is PromiseFulfilledResult<
          Awaited<ReturnType<SessionService['rotateRefreshToken']>>
        > => outcome.status === 'fulfilled',
      );
      const rejected = outcomes.filter(
        (outcome): outcome is PromiseRejectedResult => outcome.status === 'rejected',
      );
      assert.equal(fulfilled.length, 1);
      assert.equal(rejected.length, 1);
      assert.ok(rejected[0].reason instanceof RefreshTokenReuseError);

      const [storedSession, storedTokens] = await Promise.all([
        SessionModel.findById(created.session._id).lean().exec(),
        RefreshTokenModel.find({ sessionId: created.session._id }).lean().exec(),
      ]);
      assert.ok(storedSession?.revokedAt instanceof Date);
      assert.equal(storedTokens.length, 2);
      assert.ok(storedTokens.every((token) => token.revokedAt instanceof Date));
      assert.equal(storedTokens.filter((token) => token.usedAt instanceof Date).length, 1);
      assert.equal(storedTokens.filter((token) => token.replacedBy !== null).length, 1);
    } finally {
      await fixture.cleanup();
    }
  },
);

test(
  'revokes a session and all its refresh tokens, preventing further use',
  { skip: !databaseUrl },
  async () => {
    await connectToTestReplicaSet();
    const fixture = createFixture();

    try {
      const created = await fixture.createSession();
      const rotated = await fixture.service.rotateRefreshToken(created.refreshToken);

      await fixture.service.revokeSession(created.session._id);

      const [storedSession, storedTokens] = await Promise.all([
        SessionModel.findById(created.session._id).lean().exec(),
        RefreshTokenModel.find({ sessionId: created.session._id }).lean().exec(),
      ]);
      assert.ok(storedSession?.revokedAt instanceof Date);
      assert.ok(storedTokens.every((token) => token.revokedAt instanceof Date));
      assert.equal(
        await fixture.service.isSessionActive(created.session._id, fixture.userId),
        false,
      );
      await assert.rejects(
        fixture.service.rotateRefreshToken(rotated.refreshToken),
        RefreshTokenInvalidError,
      );
    } finally {
      await fixture.cleanup();
    }
  },
);

test('does not revoke a session owned by another user', { skip: !databaseUrl }, async () => {
  await connectToTestReplicaSet();
  const fixture = createFixture();

  try {
    const otherUserId = fixture.addUserId();
    const otherSession = await fixture.createSession(otherUserId);

    const revoked = await fixture.service.revokeOwnedSession(
      otherSession.session._id,
      fixture.userId,
    );

    const [storedSession, storedToken] = await Promise.all([
      SessionModel.findById(otherSession.session._id).lean().exec(),
      RefreshTokenModel.findOne({ sessionId: otherSession.session._id }).lean().exec(),
    ]);
    assert.equal(revoked, false);
    assert.equal(storedSession?.revokedAt, null);
    assert.equal(storedToken?.revokedAt, null);
    assert.equal(
      await fixture.service.isSessionActive(otherSession.session._id, otherUserId),
      true,
    );
  } finally {
    await fixture.cleanup();
  }
});

test(
  'does not consider an active session to belong to another user',
  { skip: !databaseUrl },
  async () => {
    await connectToTestReplicaSet();
    const fixture = createFixture();

    try {
      const ownerId = fixture.addUserId();
      const session = await fixture.createSession(ownerId);

      assert.equal(
        await fixture.service.isSessionActive(session.session._id, fixture.userId),
        false,
      );
      assert.equal(await fixture.service.isSessionActive(session.session._id, ownerId), true);
    } finally {
      await fixture.cleanup();
    }
  },
);

test(
  'revokes all sessions and refresh tokens only for the requested user',
  { skip: !databaseUrl },
  async () => {
    await connectToTestReplicaSet();
    const fixture = createFixture();

    try {
      const otherUserId = fixture.addUserId();
      const ownSessions = await Promise.all([fixture.createSession(), fixture.createSession()]);
      const otherSession = await fixture.createSession(otherUserId);

      await fixture.service.revokeAllSessions(fixture.userId);

      const [ownStoredSessions, otherStoredSession, ownTokens, otherToken] = await Promise.all([
        SessionModel.find({ userId: fixture.userId }).lean().exec(),
        SessionModel.findById(otherSession.session._id).lean().exec(),
        RefreshTokenModel.find({
          sessionId: { $in: ownSessions.map(({ session }) => session._id) },
        })
          .lean()
          .exec(),
        RefreshTokenModel.findOne({ sessionId: otherSession.session._id }).lean().exec(),
      ]);
      assert.equal(ownStoredSessions.length, 2);
      assert.ok(ownStoredSessions.every((session) => session.revokedAt instanceof Date));
      assert.ok(ownTokens.every((token) => token.revokedAt instanceof Date));
      assert.equal(otherStoredSession?.revokedAt, null);
      assert.equal(otherToken?.revokedAt, null);
    } finally {
      await fixture.cleanup();
    }
  },
);

test(
  'lists only active, unexpired owned sessions ordered by latest activity',
  { skip: !databaseUrl },
  async () => {
    await connectToTestReplicaSet();
    const fixture = createFixture();

    try {
      const older = await fixture.createSession(fixture.userId, 'older user agent');
      const newer = await fixture.createSession(fixture.userId, 'newer user agent');
      const expired = await fixture.createSession();
      const revoked = await fixture.createSession();
      const otherUserId = fixture.addUserId();
      const otherUserSession = await fixture.createSession(otherUserId);
      const now = Date.now();

      await Promise.all([
        SessionModel.updateOne(
          { _id: older.session._id },
          { $set: { lastActivityAt: new Date(now - 2_000) } },
        ).exec(),
        SessionModel.updateOne(
          { _id: newer.session._id },
          { $set: { lastActivityAt: new Date(now - 1_000) } },
        ).exec(),
        SessionModel.updateOne(
          { _id: expired.session._id },
          { $set: { expiresAt: new Date(now - 1) } },
        ).exec(),
      ]);
      await fixture.service.revokeSession(revoked.session._id);

      const sessions = await fixture.service.listSessions(fixture.userId);

      assert.deepEqual(
        sessions.map((session) => session._id.toHexString()),
        [newer.session._id.toHexString(), older.session._id.toHexString()],
      );
      assert.equal(
        sessions.some((session) => session._id.equals(otherUserSession.session._id)),
        false,
      );
      for (const session of sessions) {
        assert.equal(Object.hasOwn(session, 'userId'), false);
        assert.equal(Object.hasOwn(session, 'familyId'), false);
        assert.equal(Object.hasOwn(session, 'revokeReason'), false);
      }
    } finally {
      await fixture.cleanup();
    }
  },
);
