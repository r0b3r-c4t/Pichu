import { Types, type Model } from 'mongoose';
import type { EmailProvider } from '../email/email-provider.js';
import { createPasswordRecoveryEmail } from '../email/password-recovery-email.js';
import { EmailTokenModel, type EmailToken } from '../models/email-token.model.js';
import { normalizeEmail, UserModel, type User } from '../models/user.model.js';
import { generateOpaqueToken, hashToken } from '../security/crypto.js';
import { hashPassword } from '../security/password.js';
import { SessionService } from './session.service.js';

export interface PasswordRecoveryUser {
  _id: Types.ObjectId;
  name: string;
  email: string;
}

export interface PasswordRecoveryToken {
  _id: Types.ObjectId;
  generation: number;
}

export interface PasswordRecoveryRepository {
  findUserByNormalizedEmail(normalizedEmail: string): Promise<PasswordRecoveryUser | null>;
  createPendingToken(input: {
    userId: Types.ObjectId;
    tokenHash: string;
    expiresAt: Date;
  }): Promise<PasswordRecoveryToken>;
  invalidatePendingToken(input: { tokenId: Types.ObjectId; generation: number }): Promise<void>;
  activatePendingToken(input: {
    tokenId: Types.ObjectId;
    userId: Types.ObjectId;
    generation: number;
    now: Date;
  }): Promise<boolean>;
  resetPasswordAndRevokeSessions(
    tokenHash: string,
    passwordHash: string,
    now: Date,
  ): Promise<boolean>;
}

export interface PasswordRecoveryServiceDependencies {
  repository: PasswordRecoveryRepository;
  emailProvider: EmailProvider;
  resetUrl: string;
  tokenTtlMs?: number;
}

export class PasswordRecoveryServiceError extends Error {
  readonly code = 'PASSWORD_RECOVERY_FAILED';

  constructor(message = 'Password recovery could not be completed') {
    super(message);
    this.name = 'PasswordRecoveryServiceError';
  }
}

export class PasswordRecoveryService {
  private readonly tokenTtlMs: number;

  constructor(private readonly dependencies: PasswordRecoveryServiceDependencies) {
    this.tokenTtlMs = dependencies.tokenTtlMs ?? 60 * 60 * 1000;
  }

  async requestRecovery(email: string): Promise<{ accepted: true }> {
    const normalizedEmail = normalizeEmail(email);
    let user: PasswordRecoveryUser | null;
    try {
      user = await this.dependencies.repository.findUserByNormalizedEmail(normalizedEmail);
    } catch {
      throw new PasswordRecoveryServiceError();
    }

    if (!user) {
      return { accepted: true };
    }

    const rawToken = generateOpaqueToken();
    let token: PasswordRecoveryToken;
    try {
      token = await this.dependencies.repository.createPendingToken({
        userId: user._id,
        tokenHash: hashToken(rawToken),
        expiresAt: new Date(Date.now() + this.tokenTtlMs),
      });
    } catch {
      throw new PasswordRecoveryServiceError();
    }

    const emailContent = createPasswordRecoveryEmail({
      name: user.name,
      resetUrl: this.dependencies.resetUrl,
      token: rawToken,
    });
    try {
      await this.dependencies.emailProvider.send({
        to: user.email,
        subject: emailContent.subject,
        html: emailContent.html,
        text: emailContent.text,
      });
    } catch {
      try {
        await this.dependencies.repository.invalidatePendingToken({
          tokenId: token._id,
          generation: token.generation,
        });
      } catch {
        // Preserve a generic delivery error and do not expose persistence details.
      }
      throw new PasswordRecoveryServiceError();
    }

    try {
      const activated = await this.dependencies.repository.activatePendingToken({
        tokenId: token._id,
        userId: user._id,
        generation: token.generation,
        now: new Date(),
      });
      if (!activated) {
        await this.dependencies.repository.invalidatePendingToken({
          tokenId: token._id,
          generation: token.generation,
        });
      }
    } catch {
      throw new PasswordRecoveryServiceError();
    }

    return { accepted: true };
  }

  async confirmRecovery(token: string, password: string): Promise<boolean> {
    let passwordHash: string;
    try {
      passwordHash = await hashPassword(password);
    } catch {
      throw new PasswordRecoveryServiceError();
    }

    try {
      return await this.dependencies.repository.resetPasswordAndRevokeSessions(
        hashToken(token),
        passwordHash,
        new Date(),
      );
    } catch {
      throw new PasswordRecoveryServiceError();
    }
  }
}

class PasswordResetRejectedError extends Error {}

export interface PasswordRecoveryMongooseRepositoryDependencies {
  userModel?: Model<User>;
  emailTokenModel?: Model<EmailToken>;
  sessionService: SessionService;
}

export function createMongoosePasswordRecoveryRepository(
  dependencies: PasswordRecoveryMongooseRepositoryDependencies,
): PasswordRecoveryRepository {
  const userModel = dependencies.userModel ?? UserModel;
  const emailTokenModel = dependencies.emailTokenModel ?? EmailTokenModel;

  if (userModel.db !== emailTokenModel.db) {
    throw new Error('Password recovery models must use the same Mongoose connection');
  }
  dependencies.sessionService.assertPersistenceConnection(userModel.db);

  return {
    findUserByNormalizedEmail: (normalizedEmail) =>
      userModel
        .findOne({ normalizedEmail })
        .select({ name: 1, email: 1 })
        .lean<PasswordRecoveryUser>()
        .exec(),

    createPendingToken: async (input) => {
      const session = await emailTokenModel.db.startSession();
      try {
        return await session.withTransaction(
          async (transaction) => {
            const user = await userModel
              .findOneAndUpdate(
                { _id: input.userId },
                { $inc: { passwordRecoverySequence: 1 } },
                {
                  returnDocument: 'after',
                  projection: { passwordRecoverySequence: 1 },
                  session: transaction,
                },
              )
              .lean<{ passwordRecoverySequence: number }>()
              .exec();
            if (!user || !Number.isInteger(user.passwordRecoverySequence)) {
              throw new PasswordResetRejectedError();
            }

            const token = new emailTokenModel({
              userId: input.userId,
              type: 'PASSWORD_RESET',
              tokenHash: input.tokenHash,
              generation: user.passwordRecoverySequence,
              status: 'PENDING',
              expiresAt: input.expiresAt,
              usedAt: null,
            });
            await token.save({ session: transaction });
            return { _id: token._id, generation: user.passwordRecoverySequence };
          },
          {
            readPreference: 'primary',
            readConcern: { level: 'snapshot' },
            writeConcern: { w: 'majority' },
          },
        );
      } finally {
        await session.endSession();
      }
    },

    invalidatePendingToken: async ({ tokenId, generation }) => {
      await emailTokenModel
        .updateOne(
          {
            _id: tokenId,
            type: 'PASSWORD_RESET',
            generation,
            status: 'PENDING',
          },
          { $set: { status: 'INVALIDATED' } },
        )
        .exec();
    },

    activatePendingToken: async ({ tokenId, userId, generation, now }) => {
      const session = await emailTokenModel.db.startSession();
      try {
        return await session.withTransaction(
          async (transaction) => {
            const userUpdate = await userModel
              .updateOne(
                { _id: userId, passwordRecoverySequence: generation },
                { $set: { passwordRecoveryGeneration: generation } },
                { session: transaction },
              )
              .exec();
            if (userUpdate.matchedCount !== 1) {
              return false;
            }

            const tokenUpdate = await emailTokenModel
              .updateOne(
                {
                  _id: tokenId,
                  userId,
                  type: 'PASSWORD_RESET',
                  generation,
                  status: 'PENDING',
                  expiresAt: { $gt: now },
                },
                { $set: { status: 'ACTIVE' } },
                { session: transaction },
              )
              .exec();
            if (tokenUpdate.matchedCount !== 1) {
              throw new PasswordResetRejectedError();
            }

            await emailTokenModel
              .updateMany(
                {
                  userId,
                  type: 'PASSWORD_RESET',
                  status: 'ACTIVE',
                  generation: { $ne: generation },
                },
                { $set: { status: 'INVALIDATED' } },
                { session: transaction },
              )
              .exec();
            return true;
          },
          {
            readPreference: 'primary',
            readConcern: { level: 'snapshot' },
            writeConcern: { w: 'majority' },
          },
        );
      } catch (error) {
        if (error instanceof PasswordResetRejectedError) {
          return false;
        }
        throw error;
      } finally {
        await session.endSession();
      }
    },

    resetPasswordAndRevokeSessions: async (tokenHash, passwordHash, now) => {
      const session = await emailTokenModel.db.startSession();
      try {
        return await session.withTransaction(
          async (transaction) => {
            const token = await emailTokenModel
              .findOne({
                tokenHash,
                type: 'PASSWORD_RESET',
                status: 'ACTIVE',
                generation: { $gte: 1 },
                usedAt: null,
                expiresAt: { $gt: now },
              })
              .session(transaction)
              .select({ userId: 1, generation: 1 })
              .lean<{ _id: Types.ObjectId; userId: Types.ObjectId; generation: number }>()
              .exec();

            if (!token) {
              return false;
            }
            if (!Number.isInteger(token.generation) || token.generation < 1) {
              return false;
            }

            const user = await userModel
              .findOne({
                _id: token.userId,
                passwordRecoveryGeneration: token.generation,
              })
              .session(transaction)
              .select({ _id: 1, passwordRecoveryGeneration: 1 })
              .lean<{ _id: Types.ObjectId; passwordRecoveryGeneration: number }>()
              .exec();
            if (!user) {
              return false;
            }
            if (!Number.isInteger(user.passwordRecoveryGeneration)) {
              return false;
            }

            const consumed = await emailTokenModel
              .updateOne(
                {
                  _id: token._id,
                  tokenHash,
                  type: 'PASSWORD_RESET',
                  generation: token.generation,
                  status: 'ACTIVE',
                  usedAt: null,
                  expiresAt: { $gt: now },
                },
                { $set: { status: 'USED', usedAt: now } },
                { session: transaction },
              )
              .exec();
            if (consumed.matchedCount !== 1) {
              throw new PasswordResetRejectedError();
            }

            const userUpdate = await userModel
              .updateOne(
                {
                  _id: token.userId,
                  passwordRecoveryGeneration: token.generation,
                },
                {
                  $set: {
                    passwordHash,
                    passwordRecoveryGeneration: null,
                  },
                  $inc: { passwordRecoverySequence: 1 },
                },
                { session: transaction },
              )
              .exec();
            if (userUpdate.matchedCount !== 1) {
              throw new PasswordResetRejectedError();
            }

            await emailTokenModel
              .updateMany(
                {
                  userId: token.userId,
                  type: 'PASSWORD_RESET',
                  status: { $in: ['ACTIVE', 'PENDING'] },
                  _id: { $ne: token._id },
                },
                { $set: { status: 'INVALIDATED' } },
                { session: transaction },
              )
              .exec();

            await dependencies.sessionService.revokeAllSessions(
              token.userId,
              'password-reset',
              transaction,
            );
            return true;
          },
          {
            readPreference: 'primary',
            readConcern: { level: 'snapshot' },
            writeConcern: { w: 'majority' },
          },
        );
      } catch (error) {
        if (error instanceof PasswordResetRejectedError) {
          return false;
        }
        throw error;
      } finally {
        await session.endSession();
      }
    },
  };
}
