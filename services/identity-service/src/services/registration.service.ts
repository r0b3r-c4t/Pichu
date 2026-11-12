import { Types } from 'mongoose';
import { EmailProviderError, type EmailProvider } from '../email/email-provider.js';
import { createVerificationEmail } from '../email/verification-email.js';
import { EmailTokenModel, type EmailTokenDocument } from '../models/email-token.model.js';
import {
  normalizeEmail,
  normalizeUsername,
  UserModel,
  type UserDocument,
} from '../models/user.model.js';
import { generateOpaqueToken, hashToken } from '../security/crypto.js';
import { hashPassword } from '../security/password.js';

export interface RegistrationInput {
  name: string;
  username: string;
  email: string;
  password: string;
}

export interface RegistrationResult {
  accepted: true;
}

export interface RegistrationRepository {
  findUserByNormalizedEmail(normalizedEmail: string): Promise<UserDocument | null>;
  findUserByNormalizedUsername(normalizedUsername: string): Promise<UserDocument | null>;
  createUser(input: {
    name: string;
    username: string;
    normalizedUsername: string;
    email: string;
    normalizedEmail: string;
    passwordHash: string;
    emailVerifiedAt: null;
  }): Promise<UserDocument>;
  createEmailToken(input: {
    userId: Types.ObjectId;
    type: 'EMAIL_VERIFICATION';
    tokenHash: string;
    expiresAt: Date;
    usedAt: null;
  }): Promise<EmailTokenDocument>;
  deleteEmailToken(tokenId: Types.ObjectId): Promise<void>;
}

export interface RegistrationServiceDependencies {
  repository: RegistrationRepository;
  emailProvider: EmailProvider;
  verificationUrl: string;
  tokenTtlMs?: number;
}

export class RegistrationServiceError extends Error {
  readonly code = 'REGISTRATION_FAILED';
  readonly stage: string;
  readonly providerCode?: string;
  readonly cleanupFailed: boolean;

  constructor(
    message = 'Registration could not be completed',
    options: {
      cause?: unknown;
      stage?: string;
      providerCode?: string;
      cleanupFailed?: boolean;
    } = {},
  ) {
    super(message, { cause: options.cause });
    this.stage = options.stage ?? 'unknown';
    this.providerCode = options.providerCode;
    this.cleanupFailed = options.cleanupFailed ?? false;
    this.name = 'RegistrationServiceError';
  }
}

export class RegistrationConflictError extends Error {
  constructor(readonly code: 'USER_ALREADY_EXISTS' | 'USERNAME_ALREADY_EXISTS') {
    super(code === 'USER_ALREADY_EXISTS' ? 'Email already in use' : 'Username already in use');
    this.name = 'RegistrationConflictError';
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function duplicateField(error: unknown): 'normalizedEmail' | 'normalizedUsername' | undefined {
  if (!isRecord(error) || error.code !== 11000) {
    return undefined;
  }
  for (const field of ['normalizedEmail', 'normalizedUsername'] as const) {
    for (const key of ['keyPattern', 'keyValue'] as const) {
      const value = error[key];
      if (
        isRecord(value) &&
        Object.keys(value).length === 1 &&
        Object.prototype.hasOwnProperty.call(value, field)
      )
        return field;
    }
    if (error.index === `${field}_1`) return field;
  }
  return undefined;
}

export class RegistrationService {
  private readonly tokenTtlMs: number;

  constructor(private readonly dependencies: RegistrationServiceDependencies) {
    this.tokenTtlMs = dependencies.tokenTtlMs ?? 24 * 60 * 60 * 1000;
  }

  async register(input: RegistrationInput): Promise<RegistrationResult> {
    const normalizedEmail = normalizeEmail(input.email);
    const normalizedUsername = normalizeUsername(input.username);
    let existingUser: UserDocument | null;
    try {
      existingUser = await this.dependencies.repository.findUserByNormalizedEmail(normalizedEmail);
    } catch (error) {
      throw new RegistrationServiceError('Registration could not be completed', {
        cause: error,
        stage: 'user.lookup',
      });
    }
    if (existingUser) {
      throw new RegistrationConflictError('USER_ALREADY_EXISTS');
    }
    try {
      existingUser =
        await this.dependencies.repository.findUserByNormalizedUsername(normalizedUsername);
    } catch (error) {
      throw new RegistrationServiceError('Registration could not be completed', {
        cause: error,
        stage: 'username.lookup',
      });
    }
    if (existingUser) {
      throw new RegistrationConflictError('USERNAME_ALREADY_EXISTS');
    }

    let passwordHash: string;
    try {
      passwordHash = await hashPassword(input.password);
    } catch (error) {
      throw new RegistrationServiceError('Registration could not be completed', {
        cause: error,
        stage: 'password.hash',
      });
    }
    let user: UserDocument;
    try {
      user = await this.dependencies.repository.createUser({
        name: input.name.trim(),
        username: input.username.trim(),
        normalizedUsername,
        email: input.email.trim(),
        normalizedEmail,
        passwordHash,
        emailVerifiedAt: null,
      });
    } catch (error) {
      const duplicate = duplicateField(error);
      if (duplicate === 'normalizedEmail')
        throw new RegistrationConflictError('USER_ALREADY_EXISTS');
      if (duplicate === 'normalizedUsername')
        throw new RegistrationConflictError('USERNAME_ALREADY_EXISTS');
      throw new RegistrationServiceError('Registration could not be completed', {
        cause: error,
        stage: 'user.create',
      });
    }

    const rawToken = generateOpaqueToken();
    const tokenHash = hashToken(rawToken);
    const expiresAt = new Date(Date.now() + this.tokenTtlMs);
    let token: EmailTokenDocument;
    try {
      token = await this.dependencies.repository.createEmailToken({
        userId: user._id,
        type: 'EMAIL_VERIFICATION',
        tokenHash,
        expiresAt,
        usedAt: null,
      });
    } catch (error) {
      throw new RegistrationServiceError('Registration could not be completed', {
        cause: error,
        stage: 'token.create',
      });
    }

    const email = createVerificationEmail({
      name: user.name,
      verificationUrl: this.dependencies.verificationUrl,
      token: rawToken,
    });

    try {
      await this.dependencies.emailProvider.send({
        to: user.email,
        subject: email.subject,
        html: email.html,
        text: email.text,
      });
    } catch (error) {
      let cleanupFailed = false;
      try {
        await this.dependencies.repository.deleteEmailToken(token._id);
      } catch {
        cleanupFailed = true;
      }
      throw new RegistrationServiceError('Registration could not be completed', {
        cause: error,
        stage: 'email.send',
        providerCode: error instanceof EmailProviderError ? error.providerCode : undefined,
        cleanupFailed,
      });
    }

    return { accepted: true };
  }
}

export function createMongooseRegistrationRepository(): RegistrationRepository {
  return {
    findUserByNormalizedEmail: (normalizedEmail) => UserModel.findOne({ normalizedEmail }).exec(),
    findUserByNormalizedUsername: (normalizedUsername) =>
      UserModel.findOne({ normalizedUsername }).exec(),
    createUser: (input) => UserModel.create(input),
    createEmailToken: (input) => EmailTokenModel.create(input),
    deleteEmailToken: async (tokenId) => {
      await EmailTokenModel.deleteOne({ _id: tokenId }).exec();
    },
  };
}
