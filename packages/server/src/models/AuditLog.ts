import mongoose, { Schema, type Model, type HydratedDocument, type Types } from 'mongoose';
import { AUDIT_ACTIONS } from '@hvault/shared';
import type { AuditAction } from '@hvault/shared';
import { config } from '../config/index.js';

// ----- Interface -----

export interface IAuditLog {
  _id: Types.ObjectId;
  userId: Types.ObjectId | null;
  action: AuditAction;
  metadata?: Record<string, unknown> | undefined;
  ipAddress: string;
  userAgent: string;
  timestamp: Date;
}

export type AuditLogDocument = HydratedDocument<IAuditLog>;

// ----- Schema -----

const auditLogSchema = new Schema<IAuditLog>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      default: null,
    },
    action: {
      type: String,
      required: true,
      enum: AUDIT_ACTIONS,
    },
    metadata: {
      type: Schema.Types.Mixed,
      default: undefined,
    },
    ipAddress: { type: String, required: true, default: '', maxlength: 45 },
    userAgent: { type: String, required: true, default: '', maxlength: 512 },
    timestamp: { type: Date, required: true, default: Date.now },
  },
  {
    collection: 'audit_logs',
    timestamps: false,
    toJSON: {
      transform(_doc, ret) {
        // Strip server-only fields that have no client purpose. `userId` is
        // implied by the authenticated session that requested the log.
        const { __v: _v, userId: _userId, ...rest } = ret;
        return rest;
      },
    },
  },
);

// ----- Indexes -----

auditLogSchema.index({ userId: 1, timestamp: -1 });
auditLogSchema.index({ userId: 1, action: 1, timestamp: -1 });
auditLogSchema.index(
  { timestamp: 1 },
  { expireAfterSeconds: config.AUDIT_LOG_RETENTION_DAYS * 24 * 60 * 60 },
);

// ----- Model -----

export const AuditLog: Model<IAuditLog> = mongoose.model<IAuditLog>('AuditLog', auditLogSchema);
