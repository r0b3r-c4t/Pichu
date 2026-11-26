import mongoose from 'mongoose';

const schema = new mongoose.Schema(
  { key: { type: String, required: true, unique: true }, expiresAt: { type: Date, required: true } },
  { collection: 'internal_requests' },
);

export const InternalRequestModel =
  mongoose.models.InternalRequest ?? mongoose.model('InternalRequest', schema);
