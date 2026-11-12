import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import mongoose, { Types } from 'mongoose';
import { EmailTokenModel } from '../src/models/email-token.model.js';
import { UserModel } from '../src/models/user.model.js';
import {
  createMongooseRegistrationRepository,
  RegistrationConflictError,
  RegistrationService,
} from '../src/services/registration.service.js';

const databaseUrl = process.env.IDENTITY_TEST_DATABASE_URL;

after(async () => mongoose.disconnect());

test(
  'concurrent registrations enforce unique usernames and emails before token delivery',
  { skip: !databaseUrl },
  async () => {
    assert.ok(databaseUrl);
    assert.equal(decodeURIComponent(new URL(databaseUrl).pathname), '/identity_test_db');
    await mongoose.connect(databaseUrl, { autoIndex: false, serverSelectionTimeoutMS: 5000 });
    assert.equal(mongoose.connection.name, 'identity_test_db');
    const hello = await mongoose.connection.db?.admin().command({ hello: 1 });
    assert.equal(hello?.setName, 'pichu-rs');
    assert.equal(hello?.isWritablePrimary, true);
    await UserModel.createIndexes();
    await EmailTokenModel.createIndexes();

    const marker = new Types.ObjectId().toHexString();
    const sent: string[] = [];
    const service = new RegistrationService({
      repository: createMongooseRegistrationRepository(),
      emailProvider: {
        send: async (message) => {
          sent.push(message.to);
          return { id: 'test-id' };
        },
      },
      verificationUrl: 'http://localhost:3000/verify-email',
    });
    const password = 'correct horse battery staple';
    const emailA = `username-a-${marker}@example.com`;
    const emailB = `username-b-${marker}@example.com`;
    const emailC = `email-${marker}@example.com`;
    const username = `u_${marker}`;
    const candidateEmails = [emailA, emailB, emailC];

    try {
      const usernameResults = await Promise.allSettled([
        service.register({ name: 'Same Name', username, email: emailA, password }),
        service.register({
          name: 'Same Name',
          username: username.toUpperCase(),
          email: emailB,
          password,
        }),
      ]);
      assert.equal(usernameResults.filter((result) => result.status === 'fulfilled').length, 1);
      assert.equal(
        usernameResults.filter(
          (result) =>
            result.status === 'rejected' &&
            result.reason instanceof RegistrationConflictError &&
            result.reason.code === 'USERNAME_ALREADY_EXISTS',
        ).length,
        1,
      );
      assert.equal(sent.length, 1);
      assert.equal(await UserModel.countDocuments({ email: { $in: [emailA, emailB] } }), 1);

      const emailResults = await Promise.allSettled([
        service.register({ name: 'Same Name', username: `e_${marker}`, email: emailC, password }),
        service.register({
          name: 'Same Name',
          username: `f_${marker}`,
          email: emailC.toUpperCase(),
          password,
        }),
      ]);
      assert.equal(emailResults.filter((result) => result.status === 'fulfilled').length, 1);
      assert.equal(
        emailResults.filter(
          (result) =>
            result.status === 'rejected' &&
            result.reason instanceof RegistrationConflictError &&
            result.reason.code === 'USER_ALREADY_EXISTS',
        ).length,
        1,
      );
      assert.equal(sent.length, 2);
      const users = await UserModel.find({ normalizedEmail: { $in: candidateEmails } }).select(
        '_id',
      );
      assert.equal(users.length, 2);
      assert.equal(
        await EmailTokenModel.countDocuments({ userId: { $in: users.map((user) => user._id) } }),
        2,
      );
    } finally {
      const users = await UserModel.find({ normalizedEmail: { $in: candidateEmails } }).select(
        '_id',
      );
      await EmailTokenModel.deleteMany({ userId: { $in: users.map((user) => user._id) } });
      await UserModel.deleteMany({ _id: { $in: users.map((user) => user._id) } });
    }
  },
);
