import mongoose, { type HydratedDocument, type Model, Schema, Types, model } from 'mongoose';

export const EMAIL_TOKEN_TYPES = ['EMAIL_VERIFICATION', 'PASSWORD_RESET'] as const;
export type EmailTokenType = (typeof EMAIL_TOKEN_TYPES)[number];

export const EMAIL_TOKEN_STATUSES = ['PENDING', 'ACTIVE', 'USED', 'INVALIDATED'] as const;
export type EmailTokenStatus = (typeof EMAIL_TOKEN_STATUSES)[number];

export interface EmailToken {
  userId: Types.ObjectId;
  type: EmailTokenType;
  tokenHash: string;
  generation: number | null;
  status: EmailTokenStatus;
  expiresAt: Date;
  usedAt: Date | null;
  createdAt: Date;
}

export type EmailTokenDocument = HydratedDocument<EmailToken>;

const emailTokenSchema = new Schema<EmailToken>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    type: {
      type: String,
      enum: EMAIL_TOKEN_TYPES,
      required: true,
    },
    tokenHash: {
      type: String,
      required: true,
    },
    generation: {
      type: Number,
      default: null,
      min: 1,
      validate: {
        validator: (value: number | null): boolean => value === null || Number.isInteger(value),
        message: 'generation must be a positive integer or null',
      },
    },
    status: {
      type: String,
      enum: EMAIL_TOKEN_STATUSES,
      default: function (this: EmailTokenDocument): EmailTokenStatus {
        return this.type === 'PASSWORD_RESET' ? 'PENDING' : 'ACTIVE';
      },
    },
    expiresAt: {
      type: Date,
      required: true,
    },
    usedAt: {
      type: Date,
      default: null,
    },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);

emailTokenSchema.pre('validate', function validateRecoveryGeneration() {
  if (this.type !== 'PASSWORD_RESET' && this.generation !== null) {
    this.invalidate('generation', 'Only PASSWORD_RESET tokens may have a generation');
  }
  // Existing password-reset documents may predate generation tracking. The
  // recovery flow will require a generation when it starts creating tokens.
});

emailTokenSchema.index({ tokenHash: 1 }, { unique: true });
emailTokenSchema.index({ userId: 1, type: 1 });
emailTokenSchema.index({ userId: 1, type: 1, status: 1, generation: 1 });
emailTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const EmailTokenModel: Model<EmailToken> =
  (mongoose.models.EmailToken as Model<EmailToken> | undefined) ??
  model<EmailToken>('EmailToken', emailTokenSchema);
