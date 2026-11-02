import { randomUUID } from 'node:crypto';
import type { ClientSession, Model, Types } from 'mongoose';
import { RefreshTokenModel, type RefreshToken } from '../models/refresh-token.model.js';
import { SessionModel, type Session, type SessionDocument } from '../models/session.model.js';
import { generateOpaqueToken, hashToken } from '../security/crypto.js';

export const DEFAULT_REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;

export class SessionServiceError extends Error {
  readonly code: string = 'SESSION_OPERATION_FAILED';

  constructor(message = 'Session operation could not be completed') {
    super(message);
    this.name = 'SessionServiceError';
  }
}

export class RefreshTokenInvalidError extends SessionServiceError {
  override readonly code = 'REFRESH_TOKEN_INVALID';

  constructor() {
    super('Refresh token is invalid');
    this.name = 'RefreshTokenInvalidError';
  }
}

export class RefreshTokenReuseError extends SessionServiceError {
  override readonly code = 'REFRESH_TOKEN_REUSED';

  constructor() {
    super('Refresh token was reused');
    this.name = 'RefreshTokenReuseError';
  }
}

export interface SessionCreationResult {
  session: SessionDocument;
  refreshToken: string;
}

export interface RotationResult {
  session: SessionDocument;
  refreshToken: string;
}

export interface SessionServiceDependencies {
  sessionModel?: Model<Session>;
  refreshTokenModel?: Model<RefreshToken>;
  refreshTokenTtlMs?: number;
}

export class SessionService {
  private readonly sessionModel: Model<Session>;
  private readonly refreshTokenModel: Model<RefreshToken>;
  private readonly refreshTokenTtlMs: number;

  constructor(dependencies: SessionServiceDependencies = {}) {
    this.sessionModel = dependencies.sessionModel ?? SessionModel;
    this.refreshTokenModel = dependencies.refreshTokenModel ?? RefreshTokenModel;
    this.refreshTokenTtlMs = dependencies.refreshTokenTtlMs ?? DEFAULT_REFRESH_TOKEN_TTL_MS;
  }

  get refreshTokenTtlSeconds(): number {
    return this.refreshTokenTtlMs / 1000;
  }

  async createSession(userId: Types.ObjectId, userAgent?: string): Promise<SessionCreationResult> {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + this.refreshTokenTtlMs);
    const familyId = randomUUID();
    const rawRefreshToken = generateOpaqueToken();

    try {
      const result = await this.withTransaction(async (transaction) => {
        const session = new this.sessionModel({
          userId,
          familyId,
          createdAt: now,
          lastActivityAt: now,
          expiresAt,
          revokedAt: null,
          revokeReason: null,
          userAgent: userAgent?.slice(0, 512) ?? null,
        });
        await session.save({ session: transaction });

        const refreshToken = new this.refreshTokenModel({
          sessionId: session._id,
          familyId,
          tokenHash: hashToken(rawRefreshToken),
          issuedAt: now,
          expiresAt,
          usedAt: null,
          revokedAt: null,
          replacedBy: null,
          createdAt: now,
        });
        await refreshToken.save({ session: transaction });
        return session;
      });

      return { session: result, refreshToken: rawRefreshToken };
    } catch {
      throw new SessionServiceError();
    }
  }

  async rotateRefreshToken(rawRefreshToken: string): Promise<RotationResult> {
    const tokenHash = hashToken(rawRefreshToken);
    const now = new Date();
    let reuseDetected = false;
    let sessionId: Types.ObjectId | undefined;

    try {
      const result = await this.withTransaction(async (transaction) => {
        reuseDetected = false;
        const token = await this.refreshTokenModel
          .findOne({ tokenHash })
          .session(transaction)
          .exec();

        if (!token) {
          return undefined;
        }

        sessionId = token.sessionId;
        const session = await this.sessionModel
          .findById(token.sessionId)
          .session(transaction)
          .exec();
        if (
          !session ||
          session.revokedAt ||
          session.expiresAt <= now ||
          token.expiresAt <= now ||
          token.revokedAt
        ) {
          return undefined;
        }

        const consumed = await this.refreshTokenModel.updateOne(
          { _id: token._id, usedAt: null, revokedAt: null, expiresAt: { $gt: now } },
          { $set: { usedAt: now } },
          { session: transaction },
        );
        if (consumed.matchedCount !== 1) {
          reuseDetected = true;
          return undefined;
        }

        const nextRawToken = generateOpaqueToken();
        const nextToken = new this.refreshTokenModel({
          sessionId: session._id,
          familyId: session.familyId,
          tokenHash: hashToken(nextRawToken),
          issuedAt: now,
          expiresAt: session.expiresAt,
          usedAt: null,
          revokedAt: null,
          replacedBy: null,
          createdAt: now,
        });
        await nextToken.save({ session: transaction });
        await this.refreshTokenModel.updateOne(
          { _id: token._id },
          { $set: { replacedBy: nextToken._id } },
          { session: transaction },
        );
        session.lastActivityAt = now;
        await session.save({ session: transaction });

        return { session, refreshToken: nextRawToken };
      });

      if (reuseDetected && sessionId) {
        await this.revokeSession(sessionId, 'refresh-token-reuse');
        throw new RefreshTokenReuseError();
      }
      if (!result) {
        throw new RefreshTokenInvalidError();
      }
      return result;
    } catch (error) {
      if (error instanceof SessionServiceError) {
        throw error;
      }
      throw new SessionServiceError();
    }
  }

  async isSessionActive(sessionId: Types.ObjectId, userId: Types.ObjectId): Promise<boolean> {
    try {
      const session = await this.sessionModel
        .findOne({
          _id: sessionId,
          userId,
          revokedAt: null,
          expiresAt: { $gt: new Date() },
        })
        .select({ revokedAt: 1, expiresAt: 1 })
        .lean()
        .exec();
      return Boolean(session);
    } catch {
      throw new SessionServiceError();
    }
  }

  async revokeSession(sessionId: Types.ObjectId, reason = 'logout'): Promise<void> {
    try {
      await this.withTransaction(async (transaction) => {
        const now = new Date();
        await this.sessionModel.updateOne(
          { _id: sessionId, revokedAt: null },
          { $set: { revokedAt: now, revokeReason: reason } },
          { session: transaction },
        );
        await this.refreshTokenModel.updateMany(
          { sessionId, revokedAt: null },
          { $set: { revokedAt: now } },
          { session: transaction },
        );
      });
    } catch {
      throw new SessionServiceError();
    }
  }

  async revokeOwnedSession(
    sessionId: Types.ObjectId,
    userId: Types.ObjectId,
    reason = 'logout',
  ): Promise<boolean> {
    try {
      return await this.withTransaction(async (transaction) => {
        const now = new Date();
        const update = await this.sessionModel.updateOne(
          { _id: sessionId, userId, revokedAt: null },
          { $set: { revokedAt: now, revokeReason: reason } },
          { session: transaction },
        );
        if (update.matchedCount !== 1) {
          return false;
        }
        await this.refreshTokenModel.updateMany(
          { sessionId, revokedAt: null },
          { $set: { revokedAt: now } },
          { session: transaction },
        );
        return true;
      });
    } catch {
      throw new SessionServiceError();
    }
  }

  async revokeAllSessions(userId: Types.ObjectId, reason = 'logout-all'): Promise<void> {
    try {
      await this.withTransaction(async (transaction) => {
        const now = new Date();
        const sessions = await this.sessionModel
          .find({ userId, revokedAt: null })
          .session(transaction)
          .select({ _id: 1 })
          .lean()
          .exec();
        const sessionIds = sessions.map((session) => session._id);
        await this.sessionModel.updateMany(
          { userId, revokedAt: null },
          { $set: { revokedAt: now, revokeReason: reason } },
          { session: transaction },
        );
        if (sessionIds.length > 0) {
          await this.refreshTokenModel.updateMany(
            { sessionId: { $in: sessionIds }, revokedAt: null },
            { $set: { revokedAt: now } },
            { session: transaction },
          );
        }
      });
    } catch {
      throw new SessionServiceError();
    }
  }

  async listSessions(userId: Types.ObjectId): Promise<Array<Session & { _id: Types.ObjectId }>> {
    try {
      return (await this.sessionModel
        .find({ userId, revokedAt: null, expiresAt: { $gt: new Date() } })
        .select({ userId: 0, familyId: 0, revokeReason: 0 })
        .sort({ lastActivityAt: -1 })
        .lean()
        .exec()) as Array<Session & { _id: Types.ObjectId }>;
    } catch {
      throw new SessionServiceError();
    }
  }

  private async withTransaction<T>(
    operation: (transaction: ClientSession) => Promise<T>,
  ): Promise<T> {
    const transaction = await this.sessionModel.db.startSession();
    try {
      return await transaction.withTransaction(() => operation(transaction));
    } finally {
      await transaction.endSession();
    }
  }
}
