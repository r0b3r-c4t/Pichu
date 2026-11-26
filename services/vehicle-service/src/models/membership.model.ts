import mongoose, { Schema, model, type InferSchemaType } from 'mongoose';
const membershipSchema = new Schema(
  {
    vehicleId: { type: Schema.Types.ObjectId, required: true },
    userId: { type: Schema.Types.ObjectId, required: true },
    role: { type: String, enum: ['OWNER', 'MEMBER'], required: true },
    permissions: { type: [String], default: [] },
  },
  { timestamps: true },
);
membershipSchema.index({ vehicleId: 1, userId: 1 }, { unique: true });
export type Membership = InferSchemaType<typeof membershipSchema>;
export const MembershipModel = mongoose.models.Membership ?? model('Membership', membershipSchema);
