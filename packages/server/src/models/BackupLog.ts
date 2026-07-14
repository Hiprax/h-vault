import mongoose, { Schema, type Model, type HydratedDocument, type Types } from 'mongoose';
import { BACKUP_STATUSES } from '@hvault/shared';
import type { BackupStatus } from '@hvault/shared';
import { config } from '../config/index.js';

// ----- Interface -----

export interface IBackupLog {
  _id: Types.ObjectId;
  userId: Types.ObjectId;
  status: BackupStatus;
  fileSizeBytes?: number | undefined;
  itemCount?: number | undefined;
  errorMessage?: string | undefined;
  sentTo: string[];
  timestamp: Date;
}

export type BackupLogDocument = HydratedDocument<IBackupLog>;

// ----- Schema -----

const backupLogSchema = new Schema<IBackupLog>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    status: {
      type: String,
      required: true,
      enum: BACKUP_STATUSES,
    },
    fileSizeBytes: { type: Number },
    itemCount: { type: Number },
    errorMessage: { type: String },
    sentTo: { type: [String], required: true },
    timestamp: { type: Date, required: true, default: Date.now },
  },
  {
    collection: 'backup_logs',
    timestamps: false,
    toJSON: {
      transform(_doc, ret) {
        // Strip server-only fields that have no client purpose. `userId` is
        // implied by the authenticated session that requested the history.
        const { __v: _v, userId: _userId, ...rest } = ret;
        return rest;
      },
    },
  },
);

// ----- Indexes -----

backupLogSchema.index({ userId: 1, timestamp: -1 });
backupLogSchema.index({ userId: 1, status: 1 });
// TTL index: auto-deletes backup logs after the configured backup retention period
backupLogSchema.index(
  { timestamp: 1 },
  { expireAfterSeconds: config.BACKUP_RETENTION_DAYS * 24 * 60 * 60 },
);

// ----- Model -----

export const BackupLog: Model<IBackupLog> = mongoose.model<IBackupLog>(
  'BackupLog',
  backupLogSchema,
);
