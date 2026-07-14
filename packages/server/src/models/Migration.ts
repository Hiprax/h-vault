import mongoose, { Schema, type Model, type Types } from 'mongoose';

export interface IMigration {
  _id: Types.ObjectId;
  version: number;
  name: string;
  appliedAt: Date;
}

const migrationSchema = new Schema<IMigration>(
  {
    version: { type: Number, required: true, unique: true },
    name: { type: String, required: true, maxlength: 200 },
    appliedAt: { type: Date, required: true, default: Date.now },
  },
  {
    collection: 'migrations',
  },
);

export const Migration: Model<IMigration> = mongoose.model<IMigration>(
  'Migration',
  migrationSchema,
);
