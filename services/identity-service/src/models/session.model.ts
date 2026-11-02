import mongoose, { type HydratedDocument, type Model, Schema, Types, model } from 'mongoose';

export const MAX_USER_AGENT_LENGTH = 512;

export interface Session {
  userId: Types.ObjectId;
  familyId: string;
  createdAt: Date;
  lastActivityAt: Date;
  expiresAt: Date;
  revokedAt: Date | null;
  revokeReason: string | null;
  userAgent: string | null;
}

export type SessionDocument = HydratedDocument<Session>;

const sessionSchema = new Schema<Session>(
  {
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    familyId: { type: String, required: true, index: true },
    createdAt: { type: Date, required: true, default: Date.now },
    lastActivityAt: { type: Date, required: true, default: Date.now },
    expiresAt: { type: Date, required: true },
    revokedAt: { type: Date, default: null },
    revokeReason: { type: String, default: null },
    userAgent: { type: String, default: null, maxlength: MAX_USER_AGENT_LENGTH },
  },
  { timestamps: false },
);

sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
sessionSchema.index({ userId: 1, revokedAt: 1, lastActivityAt: -1 });

export const SessionModel: Model<Session> =
  (mongoose.models.Session as Model<Session> | undefined) ??
  model<Session>('Session', sessionSchema);
