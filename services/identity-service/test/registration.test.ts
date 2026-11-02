import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import argon2 from 'argon2';
import test from 'node:test';
import { Types } from 'mongoose';
import {
  EmailProviderError,
  type EmailMessage,
  type EmailProvider,
} from '../src/email/email-provider.js';
import { EmailTokenModel } from '../src/models/email-token.model.js';
import { UserModel, type UserDocument } from '../src/models/user.model.js';
import {
  RegistrationService,
  RegistrationServiceError,
  type RegistrationRepository,
} from '../src/services/registration.service.js';

interface TestContext {
  repository: RegistrationRepository;
  sentMessages: EmailMessage[];
  createdUsers: UserDocument[];
  deletedTokenIds: Types.ObjectId[];
  createdTokenHashes: string[];
}

function createContext(
  send: (message: EmailMessage) => Promise<void> = async () => undefined,
): TestContext {
  const sentMessages: EmailMessage[] = [];
  const createdUsers: UserDocument[] = [];
  const deletedTokenIds: Types.ObjectId[] = [];
  const createdTokenHashes: string[] = [];
  const repository: RegistrationRepository = {
    findUserByNormalizedEmail: async () => null,
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

  const provider: EmailProvider = {
    send: async (message) => {
      sentMessages.push(message);
      await send(message);
      return { id: 'email_test_id' };
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
    email: ' ADA@Example.COM ',
    password: 'correct horse battery staple',
  });

  assert.deepEqual(result, { accepted: true });
  assert.equal(context.createdUsers.length, 1);
  const user = context.createdUsers[0];
  assert.equal(user.emailVerifiedAt, null);
  assert.equal(user.normalizedEmail, 'ada@example.com');
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

test('accepts duplicate email registration without sending another email', async () => {
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

  assert.deepEqual(
    await service.register({
      name: 'Other',
      email: 'USER@example.com',
      password: 'correct horse battery staple',
    }),
    { accepted: true },
  );
  assert.equal(context.sentMessages.length, 0);
  assert.equal(context.createdUsers.length, 0);
});

test('keeps the user and removes the token when email delivery fails', async () => {
  const context = createContext(async () => {
    throw new EmailProviderError();
  });
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
      email: 'ada@example.com',
      password: 'correct horse battery staple',
    }),
    (error: unknown) => error instanceof RegistrationServiceError,
  );
});

test('accepts only duplicate errors for the normalizedEmail index', async () => {
  const duplicateErrors = [
    { code: 11000, keyPattern: { normalizedEmail: 1 } },
    { code: 11000, keyValue: { normalizedEmail: 'ada@example.com' } },
    { code: 11000, index: 'normalizedEmail_1' },
  ];

  for (const duplicateError of duplicateErrors) {
    const context = createContext();
    context.repository.createUser = async () => {
      throw duplicateError;
    };
    const service = new RegistrationService({
      repository: context.repository,
      emailProvider: { send: async () => ({ id: 'unused' }) },
      verificationUrl: 'http://localhost:3000/verify-email',
    });

    assert.deepEqual(
      await service.register({
        name: 'Ada',
        email: 'ada@example.com',
        password: 'correct horse battery staple',
      }),
      { accepted: true },
    );
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

  const results = await Promise.all([
    service.register({
      name: 'Ada',
      email: 'ada@example.com',
      password: 'correct horse battery staple',
    }),
    service.register({
      name: 'Ada',
      email: 'ADA@example.com',
      password: 'correct horse battery staple',
    }),
  ]);

  assert.deepEqual(results, [{ accepted: true }, { accepted: true }]);
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
      email: 'ada@example.com',
      password: 'correct horse battery staple',
    }),
    (error: unknown) => error instanceof RegistrationServiceError,
  );
  assert.equal(context.createdUsers.length, 1);
});
