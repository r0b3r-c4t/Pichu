import mongoose, { type HydratedDocument, type Model, Schema, model } from 'mongoose';

const MIN_NAME_LENGTH = 1;
const MAX_NAME_LENGTH = 120;

export interface User {
  name: string;
  email: string;
  normalizedEmail: string;
  passwordHash: string;
  emailVerifiedAt: Date | null;
  verificationResendLockId?: string | null;
  verificationResendLockExpiresAt?: Date | null;
  passwordRecoverySequence: number;
  passwordRecoveryGeneration: number | null;
  createdAt: Date;
  updatedAt: Date;
}

export type UserDocument = HydratedDocument<User>;

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

const userSchema = new Schema<User>(
  {
    name: {
      type: String,
      required: true,
      trim: true,
      minlength: MIN_NAME_LENGTH,
      maxlength: MAX_NAME_LENGTH,
    },
    email: {
      type: String,
      required: true,
      trim: true,
    },
    normalizedEmail: {
      type: String,
      required: true,
      trim: true,
      set: normalizeEmail,
    },
    passwordHash: {
      type: String,
      required: true,
      select: false,
    },
    emailVerifiedAt: {
      type: Date,
      default: null,
    },
    verificationResendLockId: {
      type: String,
      default: null,
      select: false,
    },
    verificationResendLockExpiresAt: {
      type: Date,
      default: null,
      select: false,
    },
    passwordRecoverySequence: {
      type: Number,
      required: true,
      default: 0,
      min: 0,
      validate: {
        validator: Number.isInteger,
        message: 'passwordRecoverySequence must be an integer',
      },
    },
    passwordRecoveryGeneration: {
      type: Number,
      default: null,
      min: 1,
      validate: {
        validator: (value: number | null): boolean => value === null || Number.isInteger(value),
        message: 'passwordRecoveryGeneration must be a positive integer or null',
      },
    },
  },
  { timestamps: true },
);

userSchema.pre('validate', function setNormalizedEmail() {
  if (typeof this.email === 'string') {
    this.normalizedEmail = normalizeEmail(this.email);
  }
});

userSchema.index({ normalizedEmail: 1 }, { unique: true });

function removePasswordHash(_document: unknown, value: unknown): unknown {
  delete (value as Record<string, unknown>).passwordHash;
  return value;
}

userSchema.set('toJSON', { transform: removePasswordHash });
userSchema.set('toObject', { transform: removePasswordHash });

export const UserModel: Model<User> =
  (mongoose.models.User as Model<User> | undefined) ?? model<User>('User', userSchema);
