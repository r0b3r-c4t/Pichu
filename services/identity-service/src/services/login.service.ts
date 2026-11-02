import type { HydratedDocument, Model } from 'mongoose';
import { normalizeEmail, UserModel, type User } from '../models/user.model.js';
import { verifyPassword } from '../security/password.js';
import { JwtService } from '../security/jwt.js';
import { SessionService } from './session.service.js';

// A fixed valid Argon2id hash equalizes the password verification path when no user exists.
const DUMMY_PASSWORD_HASH =
  '$argon2id$v=19$m=65536,p=4,t=3$FqKQwT2na+Dnij5lVOgxtQ$dn+32p19DUvJ6vpIFGWb/UuUXDm//Kksp2POOeNnHYQ';

export interface LoginInput {
  email: string;
  password: string;
}

export interface LoginResult {
  accessToken: string;
  refreshToken: string;
  sessionId: string;
}

export class LoginServiceError extends Error {
  readonly code = 'LOGIN_FAILED';

  constructor() {
    super('Invalid credentials');
    this.name = 'LoginServiceError';
  }
}

export class LoginServiceOperationalError extends Error {
  readonly code = 'LOGIN_OPERATION_FAILED';

  constructor() {
    super('Login could not be completed');
    this.name = 'LoginServiceOperationalError';
  }
}

export interface LoginServiceDependencies {
  userModel?: Model<User>;
  sessionService: SessionService;
  jwtService: JwtService;
  logger?: {
    error(details: { code?: string | number }, message: string): void;
  };
}

export class LoginService {
  private readonly userModel: Model<User>;

  constructor(private readonly dependencies: LoginServiceDependencies) {
    this.userModel = dependencies.userModel ?? UserModel;
  }

  async login(input: LoginInput, userAgent?: string): Promise<LoginResult> {
    const normalizedEmail = normalizeEmail(input.email);
    let user: (HydratedDocument<User> & { passwordHash: string }) | null;
    try {
      user = (await this.userModel
        .findOne({ normalizedEmail })
        .select('+passwordHash')
        .exec()) as typeof user;
    } catch {
      throw new LoginServiceOperationalError();
    }

    let passwordMatches: boolean;
    try {
      passwordMatches = await verifyPassword(
        user?.passwordHash ?? DUMMY_PASSWORD_HASH,
        input.password,
      );
    } catch {
      throw new LoginServiceOperationalError();
    }
    if (!user || !passwordMatches || !user.emailVerifiedAt) {
      throw new LoginServiceError();
    }

    let session: Awaited<ReturnType<SessionService['createSession']>>;
    try {
      session = await this.dependencies.sessionService.createSession(user._id, userAgent);
    } catch {
      throw new LoginServiceOperationalError();
    }

    let accessToken: string;
    try {
      accessToken = await this.dependencies.jwtService.createAccessToken(
        user._id,
        session.session._id,
      );
    } catch {
      try {
        await this.dependencies.sessionService.revokeSession(
          session.session._id,
          'access-token-issuance-failed',
        );
      } catch (revokeError) {
        const code =
          typeof revokeError === 'object' && revokeError !== null && 'code' in revokeError
            ? (revokeError as { code: unknown }).code
            : undefined;
        (
          this.dependencies.logger ?? {
            error: (details, message) => console.error(details, message),
          }
        ).error(
          { code: typeof code === 'string' || typeof code === 'number' ? code : undefined },
          'Failed to compensate login session',
        );
      }
      throw new LoginServiceOperationalError();
    }

    return {
      accessToken,
      refreshToken: session.refreshToken,
      sessionId: String(session.session._id),
    };
  }
}
