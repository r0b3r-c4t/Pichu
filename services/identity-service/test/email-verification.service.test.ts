import assert from 'node:assert/strict';
import test from 'node:test';
import mongoose, { Types } from 'mongoose';
import type { EmailMessage, EmailProvider } from '../src/email/email-provider.js';
import { UserModel, type User } from '../src/models/user.model.js';
import { generateOpaqueToken, hashToken } from '../src/security/crypto.js';
import {
  EmailVerificationService,
  EmailVerificationServiceError,
  createMongooseEmailVerificationRepository,
  type EmailVerificationRepository,
  type VerificationToken,
  type VerificationUser,
} from '../src/services/email-verification.service.js';

interface StoredToken extends VerificationToken {
  userId: Types.ObjectId;
  tokenHash: string;
  expiresAt: Date;
  usedAt: Date | null;
}

function createContext() {
  const user = new UserModel({
    name: 'Ada Lovelace',
    email: 'ada@example.com',
    normalizedEmail: 'ada@example.com',
    passwordHash: 'not-used-by-this-service',
    emailVerifiedAt: null,
  });
  const users = new Map<string, VerificationUser>([[String(user._id), user]]);
  const tokens: StoredToken[] = [];
  const sentMessages: EmailMessage[] = [];
  let sendFailure = false;
  let deleteFailure = false;
  let invalidationFailure = false;
  let lockFailure = false;
  let activeLockId: string | null = null;

  const repository: EmailVerificationRepository = {
    verifyEmailTokenAndUser: async (tokenHash, now) => {
      const token = tokens.find(
        (candidate) =>
          candidate.tokenHash === tokenHash &&
          candidate.usedAt === null &&
          candidate.expiresAt > now,
      );
      if (!token) {
        return false;
      }

      const storedUser = users.get(String(token.userId));
      if (!storedUser || storedUser.emailVerifiedAt !== null) {
        return false;
      }

      token.usedAt = now;
      storedUser.emailVerifiedAt = now;
      return true;
    },
    findUnverifiedUserByNormalizedEmail: async (normalizedEmail) =>
      [...users.values()].find(
        (candidate) =>
          candidate.email.toLowerCase() === normalizedEmail && candidate.emailVerifiedAt === null,
      ) ?? null,
    acquireVerificationResendLock: async (userId, lockId) => {
      if (lockFailure) {
        throw new Error('injected lock failure');
      }
      if (!users.has(String(userId))) {
        return 'unavailable';
      }
      if (activeLockId) {
        return 'busy';
      }
      activeLockId = lockId;
      return 'acquired';
    },
    renewVerificationResendLock: async (_userId, lockId) => activeLockId === lockId,
    releaseVerificationResendLock: async (_userId, lockId) => {
      if (activeLockId === lockId) {
        activeLockId = null;
      }
    },
    createEmailVerificationToken: async (input) => {
      const token: StoredToken = {
        _id: new Types.ObjectId(),
        ...input,
        usedAt: null,
      };
      tokens.push(token);
      return token;
    },
    invalidatePreviousEmailVerificationTokens: async (userId, exceptTokenId, lockId, usedAt) => {
      if (invalidationFailure) {
        throw new Error('injected invalidation failure');
      }
      if (activeLockId !== lockId) {
        throw new Error('injected lock ownership failure');
      }

      for (const token of tokens) {
        if (
          token.userId.equals(userId) &&
          !token._id.equals(exceptTokenId) &&
          token.usedAt === null
        ) {
          token.usedAt = usedAt;
        }
      }
      activeLockId = null;
    },
    deleteEmailVerificationToken: async (tokenId) => {
      if (deleteFailure) {
        throw new Error('injected deletion failure');
      }

      const tokenIndex = tokens.findIndex((candidate) => candidate._id.equals(tokenId));
      if (tokenIndex >= 0) {
        tokens.splice(tokenIndex, 1);
      }
    },
  };

  const emailProvider: EmailProvider = {
    send: async (message) => {
      sentMessages.push(message);
      if (sendFailure) {
        throw new Error('sensitive provider response');
      }
      return { id: 'email_test_id' };
    },
  };

  const service = new EmailVerificationService({
    repository,
    emailProvider,
    verificationUrl: 'http://localhost:3000/verify-email',
    tokenTtlMs: 60_000,
  });

  return {
    user,
    users,
    tokens,
    sentMessages,
    service,
    setSendFailure: (value: boolean) => {
      sendFailure = value;
    },
    setDeleteFailure: (value: boolean) => {
      deleteFailure = value;
    },
    setInvalidationFailure: (value: boolean) => {
      invalidationFailure = value;
    },
    setLockFailure: (value: boolean) => {
      lockFailure = value;
    },
  };
}

function addToken(
  context: ReturnType<typeof createContext>,
  options: {
    token?: string;
    expiresAt?: Date;
    usedAt?: Date | null;
    userId?: Types.ObjectId;
  } = {},
) {
  const token = options.token ?? generateOpaqueToken();
  context.tokens.push({
    _id: new Types.ObjectId(),
    userId: options.userId ?? context.user._id,
    tokenHash: hashToken(token),
    expiresAt: options.expiresAt ?? new Date(Date.now() + 60_000),
    usedAt: options.usedAt ?? null,
  });
  return token;
}

test('verifies an unused, unexpired email token', async () => {
  const context = createContext();
  const token = addToken(context);

  assert.equal(await context.service.verifyEmail(token), true);
  assert.ok(context.user.emailVerifiedAt instanceof Date);
  assert.ok(context.tokens[0].usedAt instanceof Date);
  assert.equal(await context.service.verifyEmail(token), false);
});

test('rejects a nonexistent token', async () => {
  const context = createContext();

  assert.equal(await context.service.verifyEmail(generateOpaqueToken()), false);
  assert.equal(context.user.emailVerifiedAt, null);
});

test('rejects an expired token explicitly', async () => {
  const context = createContext();
  const token = addToken(context, { expiresAt: new Date(Date.now() - 1) });

  assert.equal(await context.service.verifyEmail(token), false);
  assert.equal(context.user.emailVerifiedAt, null);
});

test('rejects a token that was already used', async () => {
  const context = createContext();
  const token = addToken(context, { usedAt: new Date() });

  assert.equal(await context.service.verifyEmail(token), false);
});

test('rejects a token whose user no longer exists', async () => {
  const context = createContext();
  const token = addToken(context, { userId: new Types.ObjectId() });

  assert.equal(await context.service.verifyEmail(token), false);
});

test('does not re-verify a user who is already verified', async () => {
  const context = createContext();
  context.user.emailVerifiedAt = new Date(Date.now() - 1000);
  const token = addToken(context);

  assert.equal(await context.service.verifyEmail(token), false);
  assert.equal(context.tokens[0].usedAt, null);
});

test('resends a verification email and invalidates earlier verification tokens', async () => {
  const context = createContext();
  const previousToken = addToken(context);

  await context.service.resendVerification(' ADA@Example.COM ');

  assert.equal(context.sentMessages.length, 1);
  assert.equal(context.sentMessages[0].to, 'ada@example.com');
  const rawToken = new URL(
    context.sentMessages[0].html.match(/href="([^"]+)"/)?.[1] ?? '',
  ).searchParams.get('token');
  assert.ok(rawToken);
  assert.match(rawToken, /^[a-f0-9]{64}$/);

  const newStoredToken = context.tokens.find((token) => token.tokenHash === hashToken(rawToken));
  assert.ok(newStoredToken);
  assert.equal(newStoredToken.usedAt, null);
  assert.notEqual(newStoredToken.tokenHash, rawToken);

  const invalidatedToken = context.tokens.find(
    (token) => token.tokenHash === hashToken(previousToken),
  );
  assert.ok(invalidatedToken?.usedAt instanceof Date);
});

test('does not send verification email for an unknown or already verified account', async () => {
  const context = createContext();

  await context.service.resendVerification('unknown@example.com');
  context.user.emailVerifiedAt = new Date();
  await context.service.resendVerification(context.user.email);

  assert.equal(context.sentMessages.length, 0);
  assert.equal(context.tokens.length, 0);
});

test('does not send email when MongoDB resend coordination fails', async () => {
  const context = createContext();
  context.setLockFailure(true);

  await assert.rejects(
    context.service.resendVerification(context.user.email),
    (error: unknown) => error instanceof EmailVerificationServiceError,
  );

  assert.equal(context.sentMessages.length, 0);
  assert.equal(context.tokens.length, 0);
  context.setLockFailure(false);
  await context.service.resendVerification(context.user.email);
  assert.equal(context.sentMessages.length, 1);
});

test('keeps the user and removes the new token when email delivery fails', async () => {
  const context = createContext();
  const previousToken = addToken(context);
  context.setSendFailure(true);

  await assert.rejects(
    context.service.resendVerification(context.user.email),
    (error: unknown) => error instanceof EmailVerificationServiceError,
  );

  assert.equal(context.users.size, 1);
  assert.equal(context.tokens.length, 1);
  assert.equal(context.tokens[0].tokenHash, hashToken(previousToken));
  assert.equal(context.tokens[0].usedAt, null);
});

test('preserves previous tokens if deleting a new token after send failure fails', async () => {
  const context = createContext();
  const previousToken = addToken(context);
  context.setSendFailure(true);
  context.setDeleteFailure(true);

  await assert.rejects(
    context.service.resendVerification(context.user.email),
    (error: unknown) => error instanceof EmailVerificationServiceError,
  );

  assert.equal(context.sentMessages.length, 1);
  assert.equal(context.tokens.length, 2);
  assert.equal(
    context.tokens.find((token) => token.tokenHash === hashToken(previousToken))?.usedAt,
    null,
  );
  assert.equal(context.tokens.filter((token) => token.usedAt === null).length, 2);
});

test('keeps new and previous tokens if invalidation fails after email delivery', async () => {
  const context = createContext();
  const previousToken = addToken(context);
  context.setInvalidationFailure(true);

  await assert.rejects(
    context.service.resendVerification(context.user.email),
    (error: unknown) => error instanceof EmailVerificationServiceError,
  );

  assert.equal(context.sentMessages.length, 1);
  assert.equal(context.tokens.length, 2);
  assert.equal(
    context.tokens.find((token) => token.tokenHash === hashToken(previousToken))?.usedAt,
    null,
  );
  assert.equal(context.tokens.filter((token) => token.usedAt === null).length, 2);

  context.setInvalidationFailure(false);
  await context.service.resendVerification(context.user.email);
  assert.equal(context.tokens.filter((token) => token.usedAt === null).length, 1);
});

test('returns a generic service error without exposing provider details', async () => {
  const context = createContext();
  context.setSendFailure(true);

  await assert.rejects(context.service.resendVerification(context.user.email), (error: unknown) => {
    assert.ok(error instanceof EmailVerificationServiceError);
    assert.equal(error.message.includes('sensitive provider response'), false);
    return true;
  });
});

test('rejects repository models that belong to different Mongoose connections', async () => {
  const otherConnection = mongoose.createConnection();
  const otherUserModel = otherConnection.model<User>(
    'EmailVerificationDifferentConnectionUser',
    UserModel.schema,
  );

  try {
    assert.throws(
      () => createMongooseEmailVerificationRepository(otherUserModel),
      (error: unknown) => {
        assert.equal(
          error instanceof Error ? error.message : undefined,
          'Email verification models must use the same Mongoose connection',
        );
        return true;
      },
    );
  } finally {
    await otherConnection.close();
  }
});
