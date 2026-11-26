import mongoose, { Schema, model, type InferSchemaType } from 'mongoose';

export const DEVICE_STATUSES = ['PENDING', 'ACTIVE', 'REVOKED'] as const;
const deviceSchema = new Schema(
  {
    identifier: { type: String, required: true, unique: true, trim: true, maxlength: 128 },
    publicKey: { type: String, required: true, select: false },
    algorithm: { type: String, enum: ['Ed25519'], required: true, default: 'Ed25519' },
    vehicleId: { type: Schema.Types.ObjectId, default: null },
    linkedByUserId: { type: Schema.Types.ObjectId, default: null },
    status: { type: String, enum: DEVICE_STATUSES, required: true, default: 'PENDING' },
    lastSeenAt: { type: Date, default: null },
  },
  { timestamps: true },
);

export type Device = InferSchemaType<typeof deviceSchema>;
export const DeviceModel = mongoose.models.Device ?? model('Device', deviceSchema);
