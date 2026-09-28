import mongoose, { Schema, type Model, type Types } from 'mongoose';
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
  /**
   * How many attempts this row stands for. 1 for an ordinary row; a coalesced
   * row (`auditService.recordLockedAttempt`) counts every locked sign-in attempt
   * of one minute, so a stranger hammering a locked account costs one row a
   * minute rather than one per request. Rows written before the field existed
   * read as 1.
   */
  count: number;
  /**
   * The bucket a coalesced row is counted into (`<user>|<action>|<reason>|<minute>`),
   * unique among the rows that carry one. Server bookkeeping: `select: false`, and
   * stripped from JSON, so no reader of the audit log ever sees it.
   */
  coalesceKey?: string | undefined;
}

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
    count: { type: Number, default: 1, min: 1 },
    coalesceKey: { type: String, select: false, default: undefined },
  },
  {
    collection: 'audit_logs',
    timestamps: false,
    toJSON: {
      transform(_doc, ret) {
        // Strip server-only fields that have no client purpose. `userId` is
        // implied by the authenticated session that requested the log.
        const { __v: _v, userId: _userId, coalesceKey: _coalesceKey, ...rest } = ret;
        return rest;
      },
    },
  },
);

// ----- Indexes -----

auditLogSchema.index({ userId: 1, timestamp: -1 });
auditLogSchema.index({ userId: 1, action: 1, timestamp: -1 });
/**
 * One row per coalescing bucket. Partial, so the index holds only the coalesced
 * rows (every other row has no key and costs it nothing), and unique, so two
 * concurrent first attempts of the same minute cannot write two rows: the loser
 * gets a duplicate-key error and is retried as an update of the winner's row.
 */
auditLogSchema.index(
  { coalesceKey: 1 },
  { unique: true, partialFilterExpression: { coalesceKey: { $type: 'string' } } },
);
auditLogSchema.index(
  { timestamp: 1 },
  { expireAfterSeconds: config.AUDIT_LOG_RETENTION_DAYS * 24 * 60 * 60 },
);

// ----- Model -----

export const AuditLog: Model<IAuditLog> = mongoose.model<IAuditLog>('AuditLog', auditLogSchema);
