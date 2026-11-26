import mongoose, { Schema, model, type InferSchemaType } from 'mongoose';

const invitationSchema = new Schema(
  {
    vehicleId: { type: Schema.Types.ObjectId, required: true, index: true },
    inviterUserId: { type: Schema.Types.ObjectId, required: true },
    inviteeUserId: { type: Schema.Types.ObjectId, required: true },
    permissions: { type: [String], default: [] },
    status: {
      type: String,
      enum: ['PENDING', 'ACCEPTED', 'REVOKED', 'EXPIRED'],
      default: 'PENDING',
    },
    expiresAt: { type: Date, required: true },
    acceptedAt: { type: Date, default: null },
  },
  { timestamps: true },
);
invitationSchema.index({ vehicleId: 1, inviteeUserId: 1, status: 1 });
invitationSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
export type Invitation = InferSchemaType<typeof invitationSchema>;
export const InvitationModel = mongoose.models.Invitation ?? model('Invitation', invitationSchema);
