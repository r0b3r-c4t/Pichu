import mongoose, { type HydratedDocument, type Model, Schema, Types, model } from 'mongoose';

/**
 * Ephemeral proof-of-possession challenge. Only the SHA-256 of the random challenge is stored.
 * The TTL index removes expired challenges; durable audit lives on Device and DeviceRevocation.
 */
export interface DeviceLinkChallenge {
  challengeHash: string;
  deviceId: Types.ObjectId;
  credentialId: Types.ObjectId;
  vehicleId: Types.ObjectId;
  requestedByUserId: Types.ObjectId;
  /** Vehicle membership ID under which enrollment was requested and challenge issued. */
  requestedByMembershipId: Types.ObjectId;
  expiresAt: Date;
  usedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export type DeviceLinkChallengeDocument = HydratedDocument<DeviceLinkChallenge>;

const challengeSchema = new Schema<DeviceLinkChallenge>(
  {
    challengeHash: { type: String, required: true, immutable: true, select: false },
    deviceId: { type: Schema.Types.ObjectId, required: true, immutable: true },
    credentialId: { type: Schema.Types.ObjectId, required: true, immutable: true },
    vehicleId: { type: Schema.Types.ObjectId, required: true, immutable: true },
    requestedByUserId: { type: Schema.Types.ObjectId, required: true, immutable: true },
    requestedByMembershipId: { type: Schema.Types.ObjectId, required: true, immutable: true },
    expiresAt: { type: Date, required: true, immutable: true },
    usedAt: { type: Date, default: null },
  },
  { timestamps: true },
);
/** Names preserved from the pre-TKT-014 path options. */
challengeSchema.index({ challengeHash: 1 }, { name: 'challengeHash_1', unique: true });
challengeSchema.index({ deviceId: 1 }, { name: 'deviceId_1' });
challengeSchema.index({ expiresAt: 1 }, { name: 'expiresAt_1', expireAfterSeconds: 0 });

export const DeviceLinkChallengeModel: Model<DeviceLinkChallenge> =
  (mongoose.models.DeviceLinkChallenge as Model<DeviceLinkChallenge> | undefined) ??
  model<DeviceLinkChallenge>('DeviceLinkChallenge', challengeSchema);
