import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import argon2 from 'argon2';
import test from 'node:test';
import { Types } from 'mongoose';
import { EmailProviderError, type EmailMessage } from '../src/email/email-provider.js';
import { EmailTokenModel } from '../src/models/email-token.model.js';
import { UserModel, type UserDocument } from '../src/models/user.model.js';
import {
  RegistrationService,
  RegistrationServiceError,
  RegistrationConflictError,
  type RegistrationRepository,
} from '../src/services/registration.service.js';

interface TestContext {
  repository: RegistrationRepository;
  sentMessages: EmailMessage[];
  createdUsers: UserDocument[];
  deletedTokenIds: Types.ObjectId[];
  createdTokenHashes: string[];
}

function createContext(): TestContext {
  const sentMessages: EmailMessage[] = [];
  const createdUsers: UserDocument[] = [];
  const deletedTokenIds: Types.ObjectId[] = [];
  const createdTokenHashes: string[] = [];
  const repository: RegistrationRepository = {
    findUserByNormalizedEmail: async () => null,
    findUserByNormalizedUsername: async () => null,
    createUser: async (input) => {
      const user = new UserModel(input);
      createdUsers.push(user);
      return user;
    },
    createEmailToken: async (input) => {
      createdTokenHashes.push(input.tokenHash);
      return new EmailTokenModel(input);
    },
    deleteEmailToken: async (tokenId) => {
      deletedTokenIds.push(tokenId);
    },
  };

  return { repository, sentMessages, createdUsers, deletedTokenIds, createdTokenHashes };
}

test('registers a user with an Argon2id password hash and hashed verification token', async () => {
  const context = createContext();
  const service = new RegistrationService({
    repository: context.repository,
    emailProvider: {
      send: async (message) => {
        context.sentMessages.push(message);
        return { id: 'email_test_id' };
      },
    },
    verificationUrl: 'http://localhost:3000/verify-email',
    tokenTtlMs: 60_000,
  });

  const result = await service.register({
    name: 'Ada Lovelace',
    username: 'ada_01',
    email: ' ADA@Example.COM ',
    password: 'correct horse battery staple',
  });

  assert.deepEqual(result, { accepted: true });
  assert.equal(context.createdUsers.length, 1);
  const user = context.createdUsers[0];
  assert.equal(user.emailVerifiedAt, null);
  assert.equal(user.normalizedEmail, 'ada@example.com');
  assert.equal(user.username, 'ada_01');
  assert.equal(user.normalizedUsername, 'ada_01');
  assert.equal(user.passwordHash.startsWith('$argon2id$'), true);
  assert.equal(await argon2.verify(user.passwordHash, 'correct horse battery staple'), true);

  assert.equal(context.sentMessages.length, 1);
  const sentMessage = context.sentMessages[0];
  const rawToken = new URL(sentMessage.html.match(/href="([^"]+)"/)?.[1] ?? '').searchParams.get(
    'token',
  );
  assert.ok(rawToken);
  assert.notEqual(rawToken, '');
  assert.equal(context.createdTokenHashes.length, 1);
  assert.equal(context.createdTokenHashes[0], createHash('sha256').update(rawToken).digest('hex'));
  assert.notEqual(context.createdTokenHashes[0], rawToken);
  assert.match(context.createdTokenHashes[0], /^[a-f0-9]{64}$/);
  assert.equal(rawToken.length, 64);
});

test('wraps password hashing failures without exposing internal details', async () => {
  const context = createContext();
  const service = new RegistrationService({
    repository: context.repository,
    emailProvider: { send: async () => ({ id: 'unused' }) },
    verificationUrl: 'http://localhost:3000/verify-email',
  });

  await assert.rejects(
    service.register({
      name: 'Ada',
      username: 'ada_01',
      email: 'ada@example.com',
      password: null as unknown as string,
    }),
    (error: unknown) => {
      assert.ok(error instanceof RegistrationServiceError);
      assert.equal(error.message, 'Registration could not be completed');
      assert.equal(error.message.includes('password'), false);
      return true;
    },
  );
  assert.equal(context.createdUsers.length, 0);
  assert.equal(context.sentMessages.length, 0);
});

test('rejects duplicate email registration without creating a token or sending email', async () => {
  const context = createContext();
  context.repository.findUserByNormalizedEmail = async () =>
    new UserModel({
      name: 'Existing',
      email: 'user@example.com',
      normalizedEmail: 'user@example.com',
      passwordHash: 'hash',
    });
  const service = new RegistrationService({
    repository: context.repository,
    emailProvider: { send: async () => ({ id: 'unused' }) },
    verificationUrl: 'http://localhost:3000/verify-email',
  });

  await assert.rejects(
    service.register({
      name: 'Other',
      username: 'ada_01',
      email: 'USER@example.com',
      password: 'correct horse battery staple',
    }),
    (error: unknown) =>
      error instanceof RegistrationConflictError && error.code === 'USER_ALREADY_EXISTS',
  );
  assert.equal(context.sentMessages.length, 0);
  assert.equal(context.createdUsers.length, 0);
  assert.equal(context.createdTokenHashes.length, 0);
});

test('rejects a case-insensitive duplicate username before creating credentials', async () => {
  const context = createContext();
  let lookup = '';
  context.repository.findUserByNormalizedUsername = async (normalizedUsername) => {
    lookup = normalizedUsername;
    return new UserModel({
      name: 'Existing',
      username: 'Ada_01',
      email: 'existing@example.com',
      passwordHash: 'hash',
    });
  };
  const service = new RegistrationService({
    repository: context.repository,
    emailProvider: { send: async () => ({ id: 'unused' }) },
    verificationUrl: 'http://localhost:3000/verify-email',
  });
  await assert.rejects(
    service.register({
      name: 'Another Ada',
      username: ' ADA_01 ',
      email: 'another@example.com',
      password: 'correct horse battery staple',
    }),
    (error: unknown) =>
      error instanceof RegistrationConflictError && error.code === 'USERNAME_ALREADY_EXISTS',
  );
  assert.equal(lookup, 'ada_01');
  assert.equal(context.createdUsers.length, 0);
  assert.equal(context.createdTokenHashes.length, 0);
  assert.equal(context.sentMessages.length, 0);
});

test('keeps the user and removes the token when email delivery fails', async () => {
  const context = createContext();
  const service = new RegistrationService({
    repository: context.repository,
    emailProvider: {
      send: async () => {
        throw new EmailProviderError();
      },
    },
    verificationUrl: 'http://localhost:3000/verify-email',
  });

  await assert.rejects(
    service.register({
      name: 'Ada',
      username: 'ada_01',
      email: 'ada@example.com',
      password: 'correct horse battery staple',
    }),
  );
  assert.equal(context.createdUsers.length, 1);
  assert.equal(context.deletedTokenIds.length, 1);
});

test('wraps failures while checking for an existing user', async () => {
  const context = createContext();
  context.repository.findUserByNormalizedEmail = async () => {
    throw new Error('MongoServerError: internal details');
  };
  const service = new RegistrationService({
    repository: context.repository,
    emailProvider: { send: async () => ({ id: 'unused' }) },
    verificationUrl: 'http://localhost:3000/verify-email',
  });

  await assert.rejects(
    service.register({
      name: 'Ada',
      username: 'ada_01',
      email: 'ada@example.com',
      password: 'correct horse battery staple',
    }),
    (error: unknown) => error instanceof RegistrationServiceError,
  );
});

test('treats a non-duplicate user creation error as internal', async () => {
  const context = createContext();
  context.repository.createUser = async () => {
    throw new Error('MongoServerError: validation failure');
  };
  const service = new RegistrationService({
    repository: context.repository,
    emailProvider: { send: async () => ({ id: 'unused' }) },
    verificationUrl: 'http://localhost:3000/verify-email',
  });

  await assert.rejects(
    service.register({
      name: 'Ada',
      username: 'ada_01',
      email: 'ada@example.com',
      password: 'correct horse battery staple',
    }),
    (error: unknown) => error instanceof RegistrationServiceError,
  );
});

test('maps duplicate email and username index errors to their public conflicts', async () => {
  const duplicateErrors = [
    [{ code: 11000, keyPattern: { normalizedEmail: 1 } }, 'USER_ALREADY_EXISTS'],
    [{ code: 11000, keyValue: { normalizedEmail: 'ada@example.com' } }, 'USER_ALREADY_EXISTS'],
    [{ code: 11000, index: 'normalizedEmail_1' }, 'USER_ALREADY_EXISTS'],
    [{ code: 11000, keyPattern: { normalizedUsername: 1 } }, 'USERNAME_ALREADY_EXISTS'],
    [{ code: 11000, keyValue: { normalizedUsername: 'ada_01' } }, 'USERNAME_ALREADY_EXISTS'],
    [{ code: 11000, index: 'normalizedUsername_1' }, 'USERNAME_ALREADY_EXISTS'],
  ] as const;

  for (const [duplicateError, code] of duplicateErrors) {
    const context = createContext();
    context.repository.createUser = async () => {
      throw duplicateError;
    };
    const service = new RegistrationService({
      repository: context.repository,
      emailProvider: { send: async () => ({ id: 'unused' }) },
      verificationUrl: 'http://localhost:3000/verify-email',
    });

    await assert.rejects(
      service.register({
        name: 'Ada',
        username: 'ada_01',
        email: 'ada@example.com',
        password: 'correct horse battery staple',
      }),
      (error: unknown) => error instanceof RegistrationConflictError && error.code === code,
    );
    assert.equal(context.createdTokenHashes.length, 0);
    assert.equal(context.sentMessages.length, 0);
  }
});

test('treats a duplicate error from another index as internal', async () => {
  const context = createContext();
  context.repository.createUser = async () => {
    throw { code: 11000, keyPattern: { email: 1 }, index: 'email_1' };
  };
  const service = new RegistrationService({
    repository: context.repository,
    emailProvider: { send: async () => ({ id: 'unused' }) },
    verificationUrl: 'http://localhost:3000/verify-email',
  });

  await assert.rejects(
    service.register({
      name: 'Ada',
      username: 'ada_01',
      email: 'ada@example.com',
      password: 'correct horse battery staple',
    }),
    (error: unknown) => error instanceof RegistrationServiceError,
  );
});

test('handles two concurrent registrations when one loses the unique index race', async () => {
  const context = createContext();
  let createUserCalls = 0;
  context.repository.createUser = async (input) => {
    createUserCalls += 1;
    if (createUserCalls === 2) {
      throw { code: 11000, keyPattern: { normalizedEmail: 1 } };
    }
    return new UserModel(input);
  };
  const sentMessages: EmailMessage[] = [];
  const service = new RegistrationService({
    repository: context.repository,
    emailProvider: {
      send: async (message) => {
        sentMessages.push(message);
        return { id: 'email-id' };
      },
    },
    verificationUrl: 'http://localhost:3000/verify-email',
  });

  const results = await Promise.allSettled([
    service.register({
      name: 'Ada',
      username: 'ada_01',
      email: 'ada@example.com',
      password: 'correct horse battery staple',
    }),
    service.register({
      name: 'Ada',
      username: 'ada_01',
      email: 'ADA@example.com',
      password: 'correct horse battery staple',
    }),
  ]);

  assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
  assert.equal(
    results.filter(
      (result) =>
        result.status === 'rejected' &&
        result.reason instanceof RegistrationConflictError &&
        result.reason.code === 'USER_ALREADY_EXISTS',
    ).length,
    1,
  );
  assert.equal(sentMessages.length, 1);
});

test('keeps the user when token creation fails', async () => {
  const context = createContext();
  context.repository.createEmailToken = async () => {
    throw new Error('MongoServerError: token storage failed');
  };
  const service = new RegistrationService({
    repository: context.repository,
    emailProvider: { send: async () => ({ id: 'unused' }) },
    verificationUrl: 'http://localhost:3000/verify-email',
  });

  await assert.rejects(
    service.register({
      name: 'Ada',
      username: 'ada_01',
      email: 'ada@example.com',
      password: 'correct horse battery staple',
    }),
    (error: unknown) => error instanceof RegistrationServiceError,
  );
  assert.equal(context.createdUsers.length, 1);
  assert.equal(context.sentMessages.length, 0);
});

test('keeps the user when token cleanup also fails after delivery failure', async () => {
  const context = createContext();
  context.repository.deleteEmailToken = async () => {
    throw new Error('MongoServerError: cleanup failed');
  };
  const service = new RegistrationService({
    repository: context.repository,
    emailProvider: {
      send: async () => {
        throw new Error('Resend error with secret details');
      },
    },
    verificationUrl: 'http://localhost:3000/verify-email',
  });

  await assert.rejects(
    service.register({
      name: 'Ada',
      username: 'ada_01',
      email: 'ada@example.com',
      password: 'correct horse battery staple',
    }),
    (error: unknown) => error instanceof RegistrationServiceError,
  );
  assert.equal(context.createdUsers.length, 1);
});
