import mongoose, { Schema, model, type InferSchemaType } from 'mongoose';

const challengeSchema = new Schema(
  {
    challengeHash: { type: String, required: true, unique: true, select: false },
    deviceId: { type: Schema.Types.ObjectId, required: true, index: true },
    vehicleId: { type: Schema.Types.ObjectId, required: true },
    userId: { type: Schema.Types.ObjectId, required: true },
    expiresAt: { type: Date, required: true },
    usedAt: { type: Date, default: null },
  },
  { timestamps: true },
);
challengeSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
export type DeviceLinkChallenge = InferSchemaType<typeof challengeSchema>;
export const DeviceLinkChallengeModel =
  mongoose.models.DeviceLinkChallenge ?? model('DeviceLinkChallenge', challengeSchema);
