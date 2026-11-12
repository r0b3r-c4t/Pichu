import { Types, type Model } from 'mongoose';
import { EmailProviderError, type EmailProvider } from '../email/email-provider.js';
import { createVerificationEmail } from '../email/verification-email.js';
import { EmailTokenModel, type EmailToken } from '../models/email-token.model.js';
import { normalizeEmail, UserModel, type User } from '../models/user.model.js';
import { generateOpaqueToken, hashToken } from '../security/crypto.js';

export interface VerificationUser {
  _id: Types.ObjectId;
  name: string;
  email: string;
  emailVerifiedAt: Date | null;
}

export interface VerificationToken {
  _id: Types.ObjectId;
}

export interface EmailVerificationRepository {
  verifyEmailTokenAndUser(tokenHash: string, now: Date): Promise<boolean>;
  findUnverifiedUserByNormalizedEmail(normalizedEmail: string): Promise<VerificationUser | null>;
  acquireVerificationResendLock(
    userId: Types.ObjectId,
    lockId: string,
    now: Date,
    expiresAt: Date,
  ): Promise<'acquired' | 'busy' | 'unavailable'>;
  renewVerificationResendLock(
    userId: Types.ObjectId,
    lockId: string,
    now: Date,
    expiresAt: Date,
  ): Promise<boolean>;
  releaseVerificationResendLock(userId: Types.ObjectId, lockId: string): Promise<void>;
  createEmailVerificationToken(input: {
    userId: Types.ObjectId;
    tokenHash: string;
    expiresAt: Date;
  }): Promise<VerificationToken>;
  invalidatePreviousEmailVerificationTokens(
    userId: Types.ObjectId,
    exceptTokenId: Types.ObjectId,
    lockId: string,
    usedAt: Date,
  ): Promise<void>;
  deleteEmailVerificationToken(tokenId: Types.ObjectId): Promise<void>;
}

const RESEND_LOCK_LEASE_MS = 30_000;
const RESEND_LOCK_RENEW_INTERVAL_MS = 10_000;
const RESEND_LOCK_WAIT_MS = 120_000;
const RESEND_LOCK_POLL_INTERVAL_MS = 100;

function wait(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export interface EmailVerificationServiceDependencies {
  repository: EmailVerificationRepository;
  emailProvider: EmailProvider;
  verificationUrl: string;
  tokenTtlMs?: number;
}

export class EmailVerificationServiceError extends Error {
  readonly code = 'EMAIL_VERIFICATION_FAILED';
  readonly stage: string;
  readonly providerCode?: string;

  constructor(options: { cause?: unknown; stage?: string; providerCode?: string } = {}) {
    super('Email verification could not be completed', { cause: options.cause });
    this.stage = options.stage ?? 'unknown';
    this.providerCode = options.providerCode;
    this.name = 'EmailVerificationServiceError';
  }
}

export class EmailVerificationService {
  private readonly tokenTtlMs: number;

  constructor(private readonly dependencies: EmailVerificationServiceDependencies) {
    this.tokenTtlMs = dependencies.tokenTtlMs ?? 24 * 60 * 60 * 1000;
  }

  async verifyEmail(token: string): Promise<boolean> {
    const now = new Date();

    try {
      return await this.dependencies.repository.verifyEmailTokenAndUser(hashToken(token), now);
    } catch (error) {
      throw new EmailVerificationServiceError({ cause: error, stage: 'token.verify' });
    }
  }

  async resendVerification(email: string): Promise<void> {
    const normalizedEmail = normalizeEmail(email);
    let user: VerificationUser | null;

    try {
      user =
        await this.dependencies.repository.findUnverifiedUserByNormalizedEmail(normalizedEmail);
    } catch {
      throw new EmailVerificationServiceError();
    }

    if (!user) {
      return;
    }

    const userId = user._id;
    const lockId = new Types.ObjectId().toHexString();
    const lockDeadline = Date.now() + RESEND_LOCK_WAIT_MS;
    let lockAcquired = false;
    let lockReleased = false;
    let heartbeatFailed = false;
    let heartbeatTimer: ReturnType<typeof setInterval> | undefined;
    let heartbeat = Promise.resolve();
    let accountUnavailable = false;
    let failed = false;
    let failure: EmailVerificationServiceError | undefined;
    let currentStage = 'resend.lock.acquire';
    const stopHeartbeat = async (): Promise<void> => {
      if (heartbeatTimer) {
        clearInterval(heartbeatTimer);
        heartbeatTimer = undefined;
      }
      await heartbeat;
    };

    try {
      while (!lockAcquired) {
        const now = new Date();
        currentStage = 'resend.lock.acquire';
        const acquisition = await this.dependencies.repository.acquireVerificationResendLock(
          userId,
          lockId,
          now,
          new Date(now.getTime() + RESEND_LOCK_LEASE_MS),
        );
        if (acquisition === 'unavailable') {
          accountUnavailable = true;
          break;
        }
        lockAcquired = acquisition === 'acquired';
        if (!lockAcquired) {
          if (Date.now() >= lockDeadline) {
            throw new EmailVerificationServiceError();
          }
          await wait(RESEND_LOCK_POLL_INTERVAL_MS);
        }
      }

      if (!accountUnavailable) {
        heartbeatTimer = setInterval(() => {
          heartbeat = heartbeat
            .then(async () => {
              const now = new Date();
              const renewed = await this.dependencies.repository.renewVerificationResendLock(
                userId,
                lockId,
                now,
                new Date(now.getTime() + RESEND_LOCK_LEASE_MS),
              );
              if (!renewed) {
                heartbeatFailed = true;
              }
            })
            .catch(() => {
              heartbeatFailed = true;
            });
        }, RESEND_LOCK_RENEW_INTERVAL_MS);

        const rawToken = generateOpaqueToken();
        const emailContent = createVerificationEmail({
          name: user.name,
          verificationUrl: this.dependencies.verificationUrl,
          token: rawToken,
        });
        currentStage = 'token.create';
        const token = await this.dependencies.repository.createEmailVerificationToken({
          userId: user._id,
          tokenHash: hashToken(rawToken),
          expiresAt: new Date(Date.now() + this.tokenTtlMs),
        });

        try {
          currentStage = 'email.send';
          await this.dependencies.emailProvider.send({
            to: user.email,
            subject: emailContent.subject,
            html: emailContent.html,
            text: emailContent.text,
          });
        } catch (error) {
          try {
            await this.dependencies.repository.deleteEmailVerificationToken(token._id);
          } catch {
            // Keep the delivery failure generic and preserve previously valid tokens.
          }
          throw new EmailVerificationServiceError({
            cause: error,
            stage: 'email.send',
            providerCode: error instanceof EmailProviderError ? error.providerCode : undefined,
          });
        }

        await stopHeartbeat();
        if (heartbeatFailed) {
          throw new EmailVerificationServiceError();
        }
        currentStage = 'token.invalidate';
        await this.dependencies.repository.invalidatePreviousEmailVerificationTokens(
          user._id,
          token._id,
          lockId,
          new Date(),
        );
        lockReleased = true;
      }
    } catch (error) {
      failed = true;
      failure =
        error instanceof EmailVerificationServiceError
          ? error
          : new EmailVerificationServiceError({ cause: error, stage: currentStage });
    }

    try {
      await stopHeartbeat();
    } catch (error) {
      failed = true;
      failure ??= new EmailVerificationServiceError({ cause: error, stage: 'resend.heartbeat' });
    }

    if (lockAcquired && !lockReleased) {
      try {
        await this.dependencies.repository.releaseVerificationResendLock(userId, lockId);
      } catch (error) {
        failed = true;
        failure ??= new EmailVerificationServiceError({
          cause: error,
          stage: 'resend.lock.release',
        });
      }
    }

    if (failed) {
      throw failure ?? new EmailVerificationServiceError({ stage: currentStage });
    }
  }
}

class VerificationRejectedError extends Error {}
class ResendLockOwnershipError extends Error {}

export function createMongooseEmailVerificationRepository(
  userModel: Model<User> = UserModel,
  emailTokenModel: Model<EmailToken> = EmailTokenModel,
): EmailVerificationRepository {
  if (userModel.db !== emailTokenModel.db) {
    throw new Error('Email verification models must use the same Mongoose connection');
  }

  return {
    verifyEmailTokenAndUser: async (tokenHash, now) => {
      const session = await emailTokenModel.db.startSession();
      let verified = false;

      try {
        await session.withTransaction(
          async () => {
            verified = false;
            const token = await emailTokenModel
              .findOneAndUpdate(
                {
                  tokenHash,
                  type: 'EMAIL_VERIFICATION',
                  usedAt: null,
                  expiresAt: { $gt: now },
                },
                { $set: { usedAt: now } },
                { returnDocument: 'after', projection: { userId: 1 }, session },
              )
              .lean()
              .exec();

            if (!token) {
              return;
            }

            const result = await userModel
              .updateOne(
                { _id: token.userId, emailVerifiedAt: null },
                { $set: { emailVerifiedAt: now } },
                { session },
              )
              .exec();

            if (result.matchedCount !== 1) {
              throw new VerificationRejectedError();
            }

            verified = true;
          },
          {
            readPreference: 'primary',
            readConcern: { level: 'snapshot' },
            writeConcern: { w: 'majority' },
          },
        );

        return verified;
      } catch (error) {
        if (error instanceof VerificationRejectedError) {
          return false;
        }
        throw error;
      } finally {
        await session.endSession();
      }
    },
    findUnverifiedUserByNormalizedEmail: (normalizedEmail) =>
      userModel
        .findOne({ normalizedEmail, emailVerifiedAt: null })
        .select({ name: 1, email: 1, emailVerifiedAt: 1 })
        .lean<VerificationUser>()
        .exec(),
    acquireVerificationResendLock: async (userId, lockId, now, expiresAt) => {
      const acquired = await userModel
        .findOneAndUpdate(
          {
            _id: userId,
            emailVerifiedAt: null,
            $or: [
              { verificationResendLockId: null },
              { verificationResendLockExpiresAt: { $lte: now } },
            ],
          },
          {
            $set: {
              verificationResendLockId: lockId,
              verificationResendLockExpiresAt: expiresAt,
            },
          },
          { returnDocument: 'after' },
        )
        .select({ _id: 1 })
        .lean()
        .exec();
      if (acquired) {
        return 'acquired';
      }

      const userExists = await userModel.exists({ _id: userId, emailVerifiedAt: null }).exec();
      return userExists ? 'busy' : 'unavailable';
    },
    renewVerificationResendLock: async (userId, lockId, now, expiresAt) => {
      const result = await userModel
        .updateOne(
          {
            _id: userId,
            emailVerifiedAt: null,
            verificationResendLockId: lockId,
            verificationResendLockExpiresAt: { $gt: now },
          },
          { $set: { verificationResendLockExpiresAt: expiresAt } },
        )
        .exec();
      return result.matchedCount === 1;
    },
    releaseVerificationResendLock: async (userId, lockId) => {
      await userModel
        .updateOne(
          { _id: userId, verificationResendLockId: lockId },
          {
            $set: {
              verificationResendLockId: null,
              verificationResendLockExpiresAt: null,
            },
          },
        )
        .exec();
    },
    createEmailVerificationToken: async (input) => {
      const token = await emailTokenModel.create({
        ...input,
        type: 'EMAIL_VERIFICATION',
        usedAt: null,
      });

      return { _id: token._id };
    },
    invalidatePreviousEmailVerificationTokens: async (userId, exceptTokenId, lockId, usedAt) => {
      const session = await emailTokenModel.db.startSession();
      try {
        await session.withTransaction(
          async () => {
            const lockResult = await userModel
              .updateOne(
                {
                  _id: userId,
                  emailVerifiedAt: null,
                  verificationResendLockId: lockId,
                  verificationResendLockExpiresAt: { $gt: usedAt },
                },
                {
                  $set: {
                    verificationResendLockId: null,
                    verificationResendLockExpiresAt: null,
                  },
                },
                { session },
              )
              .exec();
            if (lockResult.matchedCount !== 1) {
              throw new ResendLockOwnershipError();
            }

            await emailTokenModel
              .updateMany(
                {
                  userId,
                  type: 'EMAIL_VERIFICATION',
                  usedAt: null,
                  _id: { $ne: exceptTokenId },
                },
                { $set: { usedAt } },
                { session },
              )
              .exec();
          },
          {
            readPreference: 'primary',
            readConcern: { level: 'snapshot' },
            writeConcern: { w: 'majority' },
          },
        );
      } catch (error) {
        if (error instanceof ResendLockOwnershipError) {
          throw new EmailVerificationServiceError();
        }
        throw error;
      } finally {
        await session.endSession();
      }
    },
    deleteEmailVerificationToken: async (tokenId) => {
      await emailTokenModel.deleteOne({ _id: tokenId }).exec();
    },
  };
}
