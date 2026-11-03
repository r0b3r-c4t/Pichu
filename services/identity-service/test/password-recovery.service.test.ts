import assert from 'node:assert/strict';
import test from 'node:test';
import mongoose, { Types } from 'mongoose';
import { EmailTokenModel } from '../src/models/email-token.model.js';
import { RefreshTokenModel } from '../src/models/refresh-token.model.js';
import { SessionModel } from '../src/models/session.model.js';
import { UserModel } from '../src/models/user.model.js';
import { hashToken } from '../src/security/crypto.js';
import {
  PasswordRecoveryService,
  PasswordRecoveryServiceError,
  createMongoosePasswordRecoveryRepository,
  type PasswordRecoveryRepository,
} from '../src/services/password-recovery.service.js';
import { SessionService } from '../src/services/session.service.js';

function createRepository(overrides: Partial<PasswordRecoveryRepository> = {}) {
  const userId = new Types.ObjectId();
  const repository: PasswordRecoveryRepository = {
    findUserByNormalizedEmail: async () => ({
      _id: userId,
      name: 'Ada',
      email: 'ada@example.com',
    }),
    createPendingToken: async () => ({ _id: new Types.ObjectId(), generation: 1 }),
    invalidatePendingToken: async () => undefined,
    activatePendingToken: async () => true,
    resetPasswordAndRevokeSessions: async () => true,
    ...overrides,
  };
  return { repository, userId };
}

test('recovery stores only the token hash and sends a generic accepted result', async () => {
  let storedHash = '';
  let sentText = '';
  const { repository } = createRepository({
    createPendingToken: async (input) => {
      storedHash = input.tokenHash;
      return { _id: new Types.ObjectId(), generation: 1 };
    },
  });
  const service = new PasswordRecoveryService({
    repository,
    resetUrl: 'https://app.example.test/reset-password',
    emailProvider: {
      send: async (message) => {
        sentText = message.text ?? '';
        return { id: 'email-id' };
      },
    },
  });

  assert.deepEqual(await service.requestRecovery(' ADA@Example.COM '), { accepted: true });
  const token = new URL(sentText.split(': ').at(-1) ?? '').searchParams.get('token');
  assert.ok(token);
  assert.equal(storedHash, hashToken(token));
  assert.notEqual(sentText.includes(storedHash), true);
});

test('unknown emails do not send mail and return the same accepted result', async () => {
  let sends = 0;
  const { repository } = createRepository({ findUserByNormalizedEmail: async () => null });
  const service = new PasswordRecoveryService({
    repository,
    resetUrl: 'https://app.example.test/reset-password',
    emailProvider: {
      send: async () => {
        sends += 1;
        return { id: 'email-id' };
      },
    },
  });

  assert.deepEqual(await service.requestRecovery('unknown@example.com'), { accepted: true });
  assert.equal(sends, 0);
});

test('delivery failures invalidate only the pending token and stay generic', async () => {
  let invalidated: { tokenId: Types.ObjectId; generation: number } | undefined;
  const tokenId = new Types.ObjectId();
  const { repository } = createRepository({
    createPendingToken: async () => ({ _id: tokenId, generation: 2 }),
    invalidatePendingToken: async (input) => {
      invalidated = input;
    },
  });
  const service = new PasswordRecoveryService({
    repository,
    resetUrl: 'https://app.example.test/reset-password',
    emailProvider: {
      send: async () => {
        throw new Error('provider secret');
      },
    },
  });

  await assert.rejects(service.requestRecovery('ada@example.com'), PasswordRecoveryServiceError);
  assert.equal(invalidated?.tokenId.equals(tokenId), true);
  assert.equal(invalidated?.generation, 2);
});

test('does not activate an obsolete generation after delivery', async () => {
  let invalidated = false;
  const { repository } = createRepository({
    createPendingToken: async () => ({ _id: new Types.ObjectId(), generation: 4 }),
    activatePendingToken: async () => false,
    invalidatePendingToken: async () => {
      invalidated = true;
    },
  });
  const service = new PasswordRecoveryService({
    repository,
    resetUrl: 'https://app.example.test/reset-password',
    emailProvider: { send: async () => ({ id: 'email-id' }) },
  });

  assert.deepEqual(await service.requestRecovery('ada@example.com'), { accepted: true });
  assert.equal(invalidated, true);
});

test('returns a generic error when activation persistence fails', async () => {
  const { repository } = createRepository({
    activatePendingToken: async () => {
      throw new Error('database details');
    },
  });
  const service = new PasswordRecoveryService({
    repository,
    resetUrl: 'https://app.example.test/reset-password',
    emailProvider: { send: async () => ({ id: 'email-id' }) },
  });

  await assert.rejects(service.requestRecovery('ada@example.com'), PasswordRecoveryServiceError);
});

test('confirmation hashes the token, updates the password through the repository and supports one-use results', async () => {
  let receivedHash = '';
  let receivedPasswordHash = '';
  const { repository } = createRepository({
    resetPasswordAndRevokeSessions: async (tokenHash, passwordHash) => {
      receivedHash = tokenHash;
      receivedPasswordHash = passwordHash;
      return true;
    },
  });
  const service = new PasswordRecoveryService({
    repository,
    resetUrl: 'https://app.example.test/reset-password',
    emailProvider: { send: async () => ({ id: 'unused' }) },
  });
  const rawToken = 'a'.repeat(64);

  assert.equal(await service.confirmRecovery(rawToken, 'new secure password'), true);
  assert.equal(receivedHash, hashToken(rawToken));
  assert.match(receivedPasswordHash, /^\$argon2id\$/);

  const invalidRepository = createRepository({
    resetPasswordAndRevokeSessions: async () => false,
  });
  const invalidService = new PasswordRecoveryService({
    repository: invalidRepository.repository,
    resetUrl: 'https://app.example.test/reset-password',
    emailProvider: { send: async () => ({ id: 'unused' }) },
  });
  assert.equal(await invalidService.confirmRecovery(rawToken, 'new secure password'), false);
});

test('persistence failures are not reported as valid recovery operations', async () => {
  const { repository } = createRepository({
    findUserByNormalizedEmail: async () => {
      throw new Error('database unavailable');
    },
  });
  const service = new PasswordRecoveryService({
    repository,
    resetUrl: 'https://app.example.test/reset-password',
    emailProvider: { send: async () => ({ id: 'unused' }) },
  });
  await assert.rejects(service.requestRecovery('ada@example.com'), PasswordRecoveryServiceError);
});

test('rejects recovery models when SessionService uses another Mongoose connection', async () => {
  const otherConnection = mongoose.createConnection();
  const otherSessionModel = otherConnection.model('RecoveryConnectionSession', SessionModel.schema);
  const otherRefreshTokenModel = otherConnection.model(
    'RecoveryConnectionRefreshToken',
    RefreshTokenModel.schema,
  );

  try {
    const sessionService = new SessionService({
      sessionModel: otherSessionModel,
      refreshTokenModel: otherRefreshTokenModel,
    });

    assert.throws(
      () =>
        createMongoosePasswordRecoveryRepository({
          userModel: UserModel,
          emailTokenModel: EmailTokenModel,
          sessionService,
        }),
      /Session and refresh token models must use the same Mongoose connection/,
    );
  } finally {
    await otherConnection.close();
  }
});
