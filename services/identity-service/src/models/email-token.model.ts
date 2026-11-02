import mongoose, { type HydratedDocument, type Model, Schema, Types, model } from 'mongoose';

export const EMAIL_TOKEN_TYPES = ['EMAIL_VERIFICATION', 'PASSWORD_RESET'] as const;
export type EmailTokenType = (typeof EMAIL_TOKEN_TYPES)[number];

export interface EmailToken {
  userId: Types.ObjectId;
  type: EmailTokenType;
  tokenHash: string;
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

emailTokenSchema.index({ tokenHash: 1 }, { unique: true });
emailTokenSchema.index({ userId: 1, type: 1 });
emailTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const EmailTokenModel: Model<EmailToken> =
  (mongoose.models.EmailToken as Model<EmailToken> | undefined) ?? model<EmailToken>('EmailToken', emailTokenSchema);

