import mongoose, { type HydratedDocument, type Model, Schema, Types, model } from 'mongoose';
import {
  containsControlCharacter,
  normalizeOptionalText,
  VEHICLE_STATUSES,
  type VehicleStatus,
} from './vehicle-constants.js';

export interface Vehicle {
  name: string;
  make: string | null;
  model: string | null;
  generation: string | null;
  trim: string | null;
  year: number | null;
  bodyStyle: string | null;
  engine: string | null;
  transmission: string | null;
  fuelType: string | null;
  ownerUserId: Types.ObjectId;
  status: VehicleStatus;
  createdByUserId: Types.ObjectId;
  updatedByUserId: Types.ObjectId | null;
  archivedAt: Date | null;
  archivedByUserId: Types.ObjectId | null;
  archiveReason: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export type VehicleDocument = HydratedDocument<Vehicle>;

function optionalCleanTextField(maxlength: number) {
  return {
    type: String,
    default: null,
    set: normalizeOptionalText,
    maxlength,
    validate: {
      validator: (value: string | null): boolean =>
        value === null || (value.length >= 1 && !containsControlCharacter(value)),
      message: 'Field must not contain control characters',
    },
  };
}

const vehicleSchema = new Schema<Vehicle>(
  {
    name: {
      type: String,
      required: true,
      trim: true,
      minlength: 1,
      maxlength: 120,
      validate: {
        validator: (value: string): boolean =>
          value.length >= 1 && !containsControlCharacter(value),
        message: 'Vehicle name must not contain control characters',
      },
    },
    make: optionalCleanTextField(80),
    model: optionalCleanTextField(80),
    generation: optionalCleanTextField(60),
    trim: optionalCleanTextField(80),
    year: {
      type: Number,
      min: 1886,
      max: 2100,
      default: null,
      validate: {
        validator: (value: number | null): boolean => value === null || Number.isInteger(value),
        message: 'year must be an integer or null',
      },
    },
    bodyStyle: optionalCleanTextField(60),
    engine: optionalCleanTextField(80),
    transmission: optionalCleanTextField(60),
    fuelType: optionalCleanTextField(60),
    ownerUserId: {
      type: Schema.Types.ObjectId,
      required: true,
      immutable: true,
    },
    status: {
      type: String,
      enum: VEHICLE_STATUSES,
      required: true,
      default: 'ACTIVE',
    },
    createdByUserId: {
      type: Schema.Types.ObjectId,
      required: true,
      immutable: true,
    },
    updatedByUserId: {
      type: Schema.Types.ObjectId,
      default: null,
    },
    archivedAt: {
      type: Date,
      default: null,
    },
    archivedByUserId: {
      type: Schema.Types.ObjectId,
      default: null,
    },
    archiveReason: optionalCleanTextField(256),
  },
  { timestamps: true },
);

vehicleSchema.pre('validate', function validateLifecycleState() {
  if (this.status === 'ACTIVE') {
    if (this.archivedAt !== null || this.archivedByUserId !== null || this.archiveReason !== null) {
      this.invalidate('status', 'ACTIVE vehicles cannot retain archive metadata');
    }
  } else if (this.status === 'ARCHIVED') {
    if (!(this.archivedAt instanceof Date) || this.archivedByUserId === null) {
      this.invalidate(
        'status',
        'ARCHIVED vehicles require archivedAt and archivedByUserId audit fields',
      );
    }
  }
});

// Non-unique owner index: a single account may own multiple vehicles across brands.
vehicleSchema.index(
  { ownerUserId: 1, status: 1, createdAt: 1, _id: 1 },
  { name: 'vehicle_owner_status_created_idx' },
);
vehicleSchema.index({ status: 1, _id: 1 }, { name: 'vehicle_status_id_idx' });

export const VehicleModel: Model<Vehicle> =
  (mongoose.models.Vehicle as Model<Vehicle> | undefined) ??
  model<Vehicle>('Vehicle', vehicleSchema);
