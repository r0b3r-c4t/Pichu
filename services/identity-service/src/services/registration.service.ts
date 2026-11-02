import { Types } from 'mongoose';
import { type EmailProvider } from '../email/email-provider.js';
import { createVerificationEmail } from '../email/verification-email.js';
import { EmailTokenModel, type EmailTokenDocument } from '../models/email-token.model.js';
import { normalizeEmail, UserModel, type UserDocument } from '../models/user.model.js';
import { generateOpaqueToken, hashToken } from '../security/crypto.js';
import { hashPassword } from '../security/password.js';

export interface RegistrationInput {
  name: string;
  email: string;
  password: string;
}

export interface RegistrationResult {
  accepted: true;
}

export interface RegistrationRepository {
  findUserByNormalizedEmail(normalizedEmail: string): Promise<UserDocument | null>;
  createUser(input: {
    name: string;
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

  constructor(message = 'Registration could not be completed') {
    super(message);
    this.name = 'RegistrationServiceError';
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function isNormalizedEmailDuplicateError(error: unknown): boolean {
  if (!isRecord(error) || error.code !== 11000) {
    return false;
  }

  const keyPattern = error.keyPattern;
  if (
    isRecord(keyPattern) &&
    Object.keys(keyPattern).length === 1 &&
    Object.prototype.hasOwnProperty.call(keyPattern, 'normalizedEmail')
  ) {
    return true;
  }

  const keyValue = error.keyValue;
  if (
    isRecord(keyValue) &&
    Object.keys(keyValue).length === 1 &&
    Object.prototype.hasOwnProperty.call(keyValue, 'normalizedEmail')
  ) {
    return true;
  }

  return error.index === 'normalizedEmail_1';
}

export class RegistrationService {
  private readonly tokenTtlMs: number;

  constructor(private readonly dependencies: RegistrationServiceDependencies) {
    this.tokenTtlMs = dependencies.tokenTtlMs ?? 24 * 60 * 60 * 1000;
  }

  async register(input: RegistrationInput): Promise<RegistrationResult> {
    const normalizedEmail = normalizeEmail(input.email);
    let existingUser: UserDocument | null;
    try {
      existingUser = await this.dependencies.repository.findUserByNormalizedEmail(normalizedEmail);
    } catch {
      throw new RegistrationServiceError();
    }
    if (existingUser) {
      return { accepted: true };
    }

    let passwordHash: string;
    try {
      passwordHash = await hashPassword(input.password);
    } catch {
      throw new RegistrationServiceError();
    }
    let user: UserDocument;
    try {
      user = await this.dependencies.repository.createUser({
        name: input.name.trim(),
        email: input.email.trim(),
        normalizedEmail,
        passwordHash,
        emailVerifiedAt: null,
      });
    } catch (error) {
      if (isNormalizedEmailDuplicateError(error)) {
        return { accepted: true };
      }
      throw new RegistrationServiceError();
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
    } catch {
      throw new RegistrationServiceError();
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
    } catch {
      try {
        await this.dependencies.repository.deleteEmailToken(token._id);
      } catch {
        // Preserve the generic delivery failure and avoid exposing persistence details.
      }
      throw new RegistrationServiceError();
    }

    return { accepted: true };
  }
}

export function createMongooseRegistrationRepository(): RegistrationRepository {
  return {
    findUserByNormalizedEmail: (normalizedEmail) => UserModel.findOne({ normalizedEmail }).exec(),
    createUser: (input) => UserModel.create(input),
    createEmailToken: (input) => EmailTokenModel.create(input),
    deleteEmailToken: async (tokenId) => {
      await EmailTokenModel.deleteOne({ _id: tokenId }).exec();
    },
  };
}
