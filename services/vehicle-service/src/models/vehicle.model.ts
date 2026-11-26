import mongoose, { Schema, model, type InferSchemaType } from 'mongoose';
const vehicleSchema = new Schema(
  {
    name: { type: String, required: true, trim: true, minlength: 1, maxlength: 120 },
    make: { type: String, trim: true, maxlength: 80, default: null },
    model: { type: String, trim: true, maxlength: 80, default: null },
    year: { type: Number, min: 1886, max: 2100, default: null },
    engine: { type: String, trim: true, maxlength: 40, default: null },
    ownerUserId: { type: Schema.Types.ObjectId, required: true, index: true },
  },
  { timestamps: true },
);
export type Vehicle = InferSchemaType<typeof vehicleSchema>;
export const VehicleModel = mongoose.models.Vehicle ?? model('Vehicle', vehicleSchema);
