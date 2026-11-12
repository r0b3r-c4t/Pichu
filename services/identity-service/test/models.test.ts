import assert from 'node:assert/strict';
import test from 'node:test';
import { Types } from 'mongoose';
import { EmailTokenModel } from '../src/models/email-token.model.js';
import { RefreshTokenModel } from '../src/models/refresh-token.model.js';
import { SessionModel, MAX_USER_AGENT_LENGTH } from '../src/models/session.model.js';
import { UserModel } from '../src/models/user.model.js';

test('User normalizes email and validates required fields', async () => {
  const user = new UserModel({
    name: '  Ada Lovelace  ',
    username: '  Ada_01  ',
    email: '  ADA@Example.COM ',
    passwordHash: 'hash',
  });

  await user.validate();
  assert.equal(user.name, 'Ada Lovelace');
  assert.equal(user.username, 'Ada_01');
  assert.equal(user.normalizedUsername, 'ada_01');
  assert.equal(user.normalizedEmail, 'ada@example.com');
  assert.equal(user.emailVerifiedAt, null);
  assert.equal(user.passwordRecoverySequence, 0);
  assert.equal(user.passwordRecoveryGeneration, null);
  assert.equal(user.toJSON().passwordHash, undefined);
  assert.equal(user.toObject().passwordHash, undefined);
});

test('User rejects an empty name and does not select passwordHash', async () => {
  const user = new UserModel({
    name: '   ',
    email: 'user@example.com',
    passwordHash: 'hash',
  });

  await assert.rejects(user.validate());
  assert.equal(UserModel.schema.path('passwordHash').options.select, false);
});

test('User reports missing required credentials through validation', async () => {
  const user = new UserModel({ name: 'Ada Lovelace' });

  await assert.rejects(user.validate());
});

test('User and EmailToken expose the required indexes', () => {
  const userIndexes = UserModel.schema.indexes();
  const tokenIndexes = EmailTokenModel.schema.indexes();

  assert.ok(
    userIndexes.some(([fields, options]) => fields.normalizedEmail === 1 && options?.unique),
  );
  assert.ok(
    userIndexes.some(
      ([fields, options]) =>
        fields.normalizedUsername === 1 &&
        options?.unique &&
        JSON.stringify(options.partialFilterExpression) ===
          JSON.stringify({ normalizedUsername: { $type: 'string' } }),
    ),
  );
  assert.ok(tokenIndexes.some(([fields, options]) => fields.tokenHash === 1 && options?.unique));
  assert.ok(tokenIndexes.some(([fields]) => fields.userId === 1 && fields.type === 1));
  assert.ok(
    tokenIndexes.some(
      ([fields]) =>
        fields.userId === 1 && fields.type === 1 && fields.status === 1 && fields.generation === 1,
    ),
  );
  assert.ok(
    tokenIndexes.some(
      ([fields, options]) => fields.expiresAt === 1 && options?.expireAfterSeconds === 0,
    ),
  );
});

test('EmailToken validates its type and required fields', async () => {
  const token = new EmailTokenModel({
    userId: new Types.ObjectId(),
    type: 'EMAIL_VERIFICATION',
    tokenHash: 'hash',
    expiresAt: new Date(Date.now() + 60_000),
  });

  await token.validate();
  assert.equal(token.usedAt, null);
  assert.equal(token.status, 'ACTIVE');
  assert.equal(token.generation, null);

  const pendingResetToken = new EmailTokenModel({
    userId: new Types.ObjectId(),
    type: 'PASSWORD_RESET',
    tokenHash: 'reset-hash',
    generation: 1,
    expiresAt: new Date(Date.now() + 60_000),
  });
  await pendingResetToken.validate();
  assert.equal(pendingResetToken.status, 'PENDING');

  const invalidGenerationToken = new EmailTokenModel({
    userId: new Types.ObjectId(),
    type: 'PASSWORD_RESET',
    tokenHash: 'reset-hash-2',
    generation: 0,
    expiresAt: new Date(Date.now() + 60_000),
  });
  await assert.rejects(invalidGenerationToken.validate());

  const invalidToken = new EmailTokenModel({
    userId: new Types.ObjectId(),
    type: 'INVALID',
    tokenHash: 'hash-2',
    expiresAt: new Date(),
  });
  await assert.rejects(invalidToken.validate());
});

test('Session and RefreshToken expose bounded fields and cleanup indexes', async () => {
  const session = new SessionModel({
    userId: new Types.ObjectId(),
    familyId: 'family-1',
    expiresAt: new Date(Date.now() + 60_000),
    userAgent: 'a'.repeat(MAX_USER_AGENT_LENGTH),
  });
  await session.validate();
  assert.equal(session.revokedAt, null);
  assert.equal(session.userAgent?.length, MAX_USER_AGENT_LENGTH);

  const tooLongUserAgent = new SessionModel({
    userId: new Types.ObjectId(),
    familyId: 'family-2',
    expiresAt: new Date(Date.now() + 60_000),
    userAgent: 'a'.repeat(MAX_USER_AGENT_LENGTH + 1),
  });
  await assert.rejects(tooLongUserAgent.validate());

  const indexes = RefreshTokenModel.schema.indexes();
  assert.ok(indexes.some(([fields, options]) => fields.tokenHash === 1 && options?.unique));
  assert.ok(
    indexes.some(
      ([fields, options]) => fields.expiresAt === 1 && options?.expireAfterSeconds === 0,
    ),
  );
});
