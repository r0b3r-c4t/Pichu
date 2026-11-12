import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import mongoose, { Types } from 'mongoose';
import type { EmailProvider } from '../src/email/email-provider.js';
import { EmailTokenModel } from '../src/models/email-token.model.js';
import { UserModel, type User } from '../src/models/user.model.js';
import { generateOpaqueToken, hashToken } from '../src/security/crypto.js';
import {
  createMongooseEmailVerificationRepository,
  EmailVerificationService,
  EmailVerificationServiceError,
} from '../src/services/email-verification.service.js';

const databaseUrl = process.env.IDENTITY_TEST_DATABASE_URL;
const replicaSetName = 'pichu-rs';
let replicaSetConnection: Promise<void> | undefined;

async function connectToReplicaSet(): Promise<void> {
  assert.ok(databaseUrl, 'IDENTITY_TEST_DATABASE_URL is required');
  assert.equal(decodeURIComponent(new URL(databaseUrl).pathname), '/identity_test_db');
  if (!replicaSetConnection) {
    replicaSetConnection = mongoose
      .connect(databaseUrl, { serverSelectionTimeoutMS: 5000 })
      .then(async () => {
        assert.equal(mongoose.connection.name, 'identity_test_db');
        const hello = await mongoose.connection.db?.admin().command({ hello: 1 });
        assert.equal(hello?.setName, replicaSetName);
        assert.equal(hello?.isWritablePrimary, true);
      })
      .catch((error: unknown) => {
        replicaSetConnection = undefined;
        throw error;
      });
  }
  await replicaSetConnection;
}

after(async () => mongoose.disconnect());

async function createVerificationFixture() {
  const user = await UserModel.create({
    name: 'Email Verification Integration Test',
    username: `u_${new Types.ObjectId().toHexString()}`,
    email: `verification-${new Types.ObjectId().toHexString()}@example.com`,
    passwordHash: 'integration-test-hash',
    emailVerifiedAt: null,
  });
  const rawToken = generateOpaqueToken();
  const token = await EmailTokenModel.create({
    userId: user._id,
    type: 'EMAIL_VERIFICATION',
    tokenHash: hashToken(rawToken),
    expiresAt: new Date(Date.now() + 60_000),
    usedAt: null,
  });
  const emailProvider: EmailProvider = { send: async () => ({ id: 'unused' }) };
  const service = new EmailVerificationService({
    repository: createMongooseEmailVerificationRepository(),
    emailProvider,
    verificationUrl: 'http://localhost:3000/verify-email',
  });

  return { user, token, rawToken, service };
}

async function createUnverifiedUser(name: string) {
  return UserModel.create({
    name,
    username: `u_${new Types.ObjectId().toHexString()}`,
    email: `resend-${new Types.ObjectId().toHexString()}@example.com`,
    passwordHash: 'integration-test-hash',
    emailVerifiedAt: null,
  });
}

async function createStoredVerificationTokens(userId: Types.ObjectId, count: number) {
  return Promise.all(
    Array.from({ length: count }, () =>
      EmailTokenModel.create({
        userId,
        type: 'EMAIL_VERIFICATION',
        tokenHash: hashToken(generateOpaqueToken()),
        expiresAt: new Date(Date.now() + 60_000),
        usedAt: null,
      }),
    ),
  );
}

async function acquireExpiredLease(
  repository: ReturnType<typeof createMongooseEmailVerificationRepository>,
  userId: Types.ObjectId,
  lockId: string,
): Promise<void> {
  const now = new Date();
  const acquired = await repository.acquireVerificationResendLock(
    userId,
    lockId,
    now,
    new Date(now.getTime() - 1),
  );
  assert.equal(acquired, 'acquired');
}

async function removeUserAndTokens(userId: Types.ObjectId): Promise<void> {
  await Promise.all([
    EmailTokenModel.deleteMany({ userId }).exec(),
    UserModel.deleteOne({ _id: userId }).exec(),
  ]);
}

function createResendService(emailProvider: EmailProvider): EmailVerificationService {
  return new EmailVerificationService({
    repository: createMongooseEmailVerificationRepository(),
    emailProvider,
    verificationUrl: 'http://localhost:3000/verify-email',
  });
}

async function waitFor(condition: () => boolean, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition() && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.equal(condition(), true, 'timed out waiting for concurrent email sends');
}

async function removeFixture(userId: Types.ObjectId, tokenId: Types.ObjectId): Promise<void> {
  await Promise.all([
    EmailTokenModel.deleteOne({ _id: tokenId }).exec(),
    UserModel.deleteOne({ _id: userId }).exec(),
  ]);
}

test(
  'MongoDB transaction verifies the token and user together',
  { skip: !databaseUrl },
  async () => {
    await connectToReplicaSet();
    const fixture = await createVerificationFixture();

    try {
      assert.equal(await fixture.service.verifyEmail(fixture.rawToken), true);
      const [storedToken, storedUser] = await Promise.all([
        EmailTokenModel.findById(fixture.token._id).lean().exec(),
        UserModel.findById(fixture.user._id).lean().exec(),
      ]);
      assert.ok(storedToken?.usedAt instanceof Date);
      assert.ok(storedUser?.emailVerifiedAt instanceof Date);
    } finally {
      await removeFixture(fixture.user._id, fixture.token._id);
    }
  },
);

test(
  'MongoDB serializes concurrent verification resends for the same user',
  { skip: !databaseUrl },
  async () => {
    await connectToReplicaSet();
    const user = await createUnverifiedUser('Concurrent Resend Test');
    let activeSends = 0;
    let maximumActiveSends = 0;
    let notifyFirstSend!: () => void;
    let releaseSends!: () => void;
    const firstSend = new Promise<void>((resolve) => {
      notifyFirstSend = resolve;
    });
    const sendGate = new Promise<void>((resolve) => {
      releaseSends = resolve;
    });
    const emailProvider: EmailProvider = {
      send: async () => {
        activeSends += 1;
        maximumActiveSends = Math.max(maximumActiveSends, activeSends);
        notifyFirstSend();
        await sendGate;
        activeSends -= 1;
        return { id: 'unused' };
      },
    };
    const service = createResendService(emailProvider);

    try {
      const firstResend = service.resendVerification(user.email);
      await firstSend;
      const secondResend = service.resendVerification(user.email);
      await new Promise((resolve) => setTimeout(resolve, 250));
      assert.equal(activeSends, 1);
      releaseSends();
      await Promise.all([firstResend, secondResend]);

      assert.equal(maximumActiveSends, 1);
      const tokens = await EmailTokenModel.find({
        userId: user._id,
        type: 'EMAIL_VERIFICATION',
      })
        .lean()
        .exec();
      assert.equal(tokens.length, 2);
      assert.equal(tokens.filter((token) => token.usedAt === null).length, 1);
    } finally {
      releaseSends();
      await Promise.all([
        EmailTokenModel.deleteMany({ userId: user._id }).exec(),
        UserModel.deleteOne({ _id: user._id }).exec(),
      ]);
    }
  },
);

test(
  'MongoDB allows concurrent verification resends for different users',
  { skip: !databaseUrl },
  async () => {
    await connectToReplicaSet();
    const users = await Promise.all([
      createUnverifiedUser('First Independent Resend Test'),
      createUnverifiedUser('Second Independent Resend Test'),
    ]);
    let activeSends = 0;
    let maximumActiveSends = 0;
    let notifyBothSends!: () => void;
    let releaseSends!: () => void;
    const bothSends = new Promise<void>((resolve) => {
      notifyBothSends = resolve;
    });
    const sendGate = new Promise<void>((resolve) => {
      releaseSends = resolve;
    });
    const emailProvider: EmailProvider = {
      send: async () => {
        activeSends += 1;
        maximumActiveSends = Math.max(maximumActiveSends, activeSends);
        if (activeSends === 2) {
          notifyBothSends();
        }
        await sendGate;
        activeSends -= 1;
        return { id: 'unused' };
      },
    };
    const service = createResendService(emailProvider);

    try {
      const resends = users.map((user) => service.resendVerification(user.email));
      await waitFor(() => activeSends === 2);
      assert.equal(maximumActiveSends, 2);
      releaseSends();
      await Promise.all(resends);
      const counts = await Promise.all(
        users.map((user) =>
          EmailTokenModel.countDocuments({
            userId: user._id,
            type: 'EMAIL_VERIFICATION',
            usedAt: null,
          }).exec(),
        ),
      );
      assert.deepEqual(counts, [1, 1]);
    } finally {
      releaseSends();
      await Promise.all([
        EmailTokenModel.deleteMany({ userId: { $in: users.map((user) => user._id) } }).exec(),
        UserModel.deleteMany({ _id: { $in: users.map((user) => user._id) } }).exec(),
      ]);
    }
  },
);

test(
  'MongoDB transaction permits only one concurrent request to consume a token',
  { skip: !databaseUrl },
  async () => {
    await connectToReplicaSet();
    const fixture = await createVerificationFixture();

    try {
      const results = await Promise.all([
        fixture.service.verifyEmail(fixture.rawToken),
        fixture.service.verifyEmail(fixture.rawToken),
      ]);

      assert.equal(results.filter(Boolean).length, 1);
      const [storedToken, storedUser] = await Promise.all([
        EmailTokenModel.findById(fixture.token._id).lean().exec(),
        UserModel.findById(fixture.user._id).lean().exec(),
      ]);
      assert.ok(storedToken?.usedAt instanceof Date);
      assert.ok(storedUser?.emailVerifiedAt instanceof Date);
    } finally {
      await removeFixture(fixture.user._id, fixture.token._id);
    }
  },
);

test(
  'MongoDB transaction rolls token consumption back if the user update fails',
  { skip: !databaseUrl },
  async () => {
    await connectToReplicaSet();
    const fixture = await createVerificationFixture();
    const failingSchema = UserModel.schema.clone();
    failingSchema.pre('updateOne', function failInjectedUserUpdate() {
      throw new Error('injected user update failure');
    });
    const failingUserModel = mongoose.model<User>(
      `FailingVerificationUser_${new Types.ObjectId().toHexString()}`,
      failingSchema,
      UserModel.collection.name,
    );
    const service = new EmailVerificationService({
      repository: createMongooseEmailVerificationRepository(failingUserModel),
      emailProvider: { send: async () => ({ id: 'unused' }) },
      verificationUrl: 'http://localhost:3000/verify-email',
    });

    try {
      await assert.rejects(
        service.verifyEmail(fixture.rawToken),
        (error: unknown) => error instanceof EmailVerificationServiceError,
      );
      const [storedToken, storedUser] = await Promise.all([
        EmailTokenModel.findById(fixture.token._id).lean().exec(),
        UserModel.findById(fixture.user._id).lean().exec(),
      ]);
      assert.equal(storedToken?.usedAt, null);
      assert.equal(storedUser?.emailVerifiedAt, null);
    } finally {
      mongoose.deleteModel(failingUserModel.modelName);
      await removeFixture(fixture.user._id, fixture.token._id);
    }
  },
);

test(
  'MongoDB permits another request to acquire an expired resend lease',
  { skip: !databaseUrl },
  async () => {
    await connectToReplicaSet();
    const user = await createUnverifiedUser('Expired Lease Acquisition Test');
    const repository = createMongooseEmailVerificationRepository();
    const previousOwnerId = new Types.ObjectId().toHexString();
    const nextOwnerId = new Types.ObjectId().toHexString();

    try {
      await acquireExpiredLease(repository, user._id, previousOwnerId);
      const now = new Date();
      const acquisition = await repository.acquireVerificationResendLock(
        user._id,
        nextOwnerId,
        now,
        new Date(now.getTime() + 30_000),
      );

      assert.equal(acquisition, 'acquired');
      const storedUser = await UserModel.findById(user._id)
        .select('+verificationResendLockId +verificationResendLockExpiresAt')
        .lean()
        .exec();
      assert.equal(storedUser?.verificationResendLockId, nextOwnerId);
    } finally {
      await removeUserAndTokens(user._id);
    }
  },
);

test(
  'MongoDB rejects renewal by the previous owner after its lease expires',
  { skip: !databaseUrl },
  async () => {
    await connectToReplicaSet();
    const user = await createUnverifiedUser('Expired Lease Renewal Test');
    const repository = createMongooseEmailVerificationRepository();
    const previousOwnerId = new Types.ObjectId().toHexString();
    const nextOwnerId = new Types.ObjectId().toHexString();

    try {
      await acquireExpiredLease(repository, user._id, previousOwnerId);
      const now = new Date();
      assert.equal(
        await repository.acquireVerificationResendLock(
          user._id,
          nextOwnerId,
          now,
          new Date(now.getTime() + 30_000),
        ),
        'acquired',
      );
      assert.equal(
        await repository.renewVerificationResendLock(
          user._id,
          previousOwnerId,
          now,
          new Date(now.getTime() + 30_000),
        ),
        false,
      );
    } finally {
      await removeUserAndTokens(user._id);
    }
  },
);

test(
  'MongoDB prevents the previous owner from releasing a replacement lease',
  { skip: !databaseUrl },
  async () => {
    await connectToReplicaSet();
    const user = await createUnverifiedUser('Expired Lease Release Test');
    const repository = createMongooseEmailVerificationRepository();
    const previousOwnerId = new Types.ObjectId().toHexString();
    const nextOwnerId = new Types.ObjectId().toHexString();

    try {
      await acquireExpiredLease(repository, user._id, previousOwnerId);
      const now = new Date();
      assert.equal(
        await repository.acquireVerificationResendLock(
          user._id,
          nextOwnerId,
          now,
          new Date(now.getTime() + 30_000),
        ),
        'acquired',
      );
      await repository.releaseVerificationResendLock(user._id, previousOwnerId);

      const storedUser = await UserModel.findById(user._id)
        .select('+verificationResendLockId +verificationResendLockExpiresAt')
        .lean()
        .exec();
      assert.equal(storedUser?.verificationResendLockId, nextOwnerId);
    } finally {
      await removeUserAndTokens(user._id);
    }
  },
);

test(
  'MongoDB prevents a previous lease owner from invalidating tokens',
  { skip: !databaseUrl },
  async () => {
    await connectToReplicaSet();
    const user = await createUnverifiedUser('Expired Lease Invalidation Test');
    const repository = createMongooseEmailVerificationRepository();
    const previousOwnerId = new Types.ObjectId().toHexString();
    const nextOwnerId = new Types.ObjectId().toHexString();

    try {
      const [firstToken] = await createStoredVerificationTokens(user._id, 2);
      await acquireExpiredLease(repository, user._id, previousOwnerId);
      const now = new Date();
      assert.equal(
        await repository.acquireVerificationResendLock(
          user._id,
          nextOwnerId,
          now,
          new Date(now.getTime() + 30_000),
        ),
        'acquired',
      );

      await assert.rejects(
        repository.invalidatePreviousEmailVerificationTokens(
          user._id,
          firstToken._id,
          previousOwnerId,
          now,
        ),
        (error: unknown) => error instanceof EmailVerificationServiceError,
      );

      const [storedTokens, storedUser] = await Promise.all([
        EmailTokenModel.find({ userId: user._id }).lean().exec(),
        UserModel.findById(user._id)
          .select('+verificationResendLockId +verificationResendLockExpiresAt')
          .lean()
          .exec(),
      ]);
      assert.equal(storedTokens.length, 2);
      assert.ok(storedTokens.every((token) => token.usedAt === null));
      assert.equal(storedUser?.verificationResendLockId, nextOwnerId);
      assert.ok(storedUser?.verificationResendLockExpiresAt instanceof Date);
    } finally {
      await removeUserAndTokens(user._id);
    }
  },
);

test(
  'MongoDB rolls back token invalidation when lease ownership validation fails',
  { skip: !databaseUrl },
  async () => {
    await connectToReplicaSet();
    const user = await createUnverifiedUser('Lease Ownership Transaction Rollback Test');
    const repository = createMongooseEmailVerificationRepository();
    const ownerId = new Types.ObjectId().toHexString();
    const wrongOwnerId = new Types.ObjectId().toHexString();
    const now = new Date();

    try {
      const [firstToken] = await createStoredVerificationTokens(user._id, 2);
      assert.equal(
        await repository.acquireVerificationResendLock(
          user._id,
          ownerId,
          now,
          new Date(now.getTime() + 30_000),
        ),
        'acquired',
      );
      await assert.rejects(
        repository.invalidatePreviousEmailVerificationTokens(
          user._id,
          firstToken._id,
          wrongOwnerId,
          now,
        ),
        (error: unknown) => error instanceof EmailVerificationServiceError,
      );

      const [storedTokens, storedUser] = await Promise.all([
        EmailTokenModel.find({ userId: user._id }).lean().exec(),
        UserModel.findById(user._id)
          .select('+verificationResendLockId +verificationResendLockExpiresAt')
          .lean()
          .exec(),
      ]);
      assert.equal(storedTokens.length, 2);
      assert.ok(storedTokens.every((token) => token.usedAt === null));
      assert.equal(storedUser?.verificationResendLockId, ownerId);
      assert.ok(storedUser?.verificationResendLockExpiresAt instanceof Date);
    } finally {
      await removeUserAndTokens(user._id);
    }
  },
);
