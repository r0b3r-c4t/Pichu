import mongoose, { type HydratedDocument, type Model, Schema, Types, model } from 'mongoose';

export interface RefreshToken {
  sessionId: Types.ObjectId;
  familyId: string;
  tokenHash: string;
  issuedAt: Date;
  expiresAt: Date;
  usedAt: Date | null;
  revokedAt: Date | null;
  replacedBy: Types.ObjectId | null;
  createdAt: Date;
}

export type RefreshTokenDocument = HydratedDocument<RefreshToken>;

const refreshTokenSchema = new Schema<RefreshToken>(
  {
    sessionId: { type: Schema.Types.ObjectId, ref: 'Session', required: true },
    familyId: { type: String, required: true },
    tokenHash: { type: String, required: true, unique: true },
    issuedAt: { type: Date, required: true, default: Date.now },
    expiresAt: { type: Date, required: true },
    usedAt: { type: Date, default: null },
    revokedAt: { type: Date, default: null },
    replacedBy: { type: Schema.Types.ObjectId, ref: 'RefreshToken', default: null },
    createdAt: { type: Date, required: true, default: Date.now },
  },
  { timestamps: false },
);

refreshTokenSchema.index({ sessionId: 1, createdAt: -1 });
refreshTokenSchema.index({ familyId: 1 });
// Used and revoked tokens remain queryable until their natural expiry so reuse can be detected.
// TTL is cleanup only; authorization always checks expiresAt, usedAt and revokedAt explicitly.
refreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const RefreshTokenModel: Model<RefreshToken> =
  (mongoose.models.RefreshToken as Model<RefreshToken> | undefined) ??
  model<RefreshToken>('RefreshToken', refreshTokenSchema);
