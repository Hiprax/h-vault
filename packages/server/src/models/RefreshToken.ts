import mongoose, { Schema, type Model, type HydratedDocument, type Types } from 'mongoose';

// ----- Sub-interface -----

export interface IDeviceInfo {
  userAgent: string;
  ip: string;
  fingerprint: string;
}

// ----- Main Interface -----

export interface IRefreshToken {
  _id: Types.ObjectId;
  userId: Types.ObjectId;
  tokenHash: string;
  familyId: string;
  deviceInfo: IDeviceInfo;
  expiresAt: Date;
  usedAt?: Date | undefined;
  createdAt: Date;
  updatedAt: Date;
}

export type RefreshTokenDocument = HydratedDocument<IRefreshToken>;

// ----- Sub-Schema -----

const deviceInfoSchema = new Schema<IDeviceInfo>(
  {
    userAgent: { type: String, default: '', maxlength: 512 },
    ip: { type: String, default: '', maxlength: 45 },
    fingerprint: { type: String, default: '', maxlength: 128 },
  },
  { _id: false },
);

// ----- Main Schema -----

const refreshTokenSchema = new Schema<IRefreshToken>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    tokenHash: { type: String, required: true, index: true },
    familyId: { type: String, required: true },
    deviceInfo: { type: deviceInfoSchema, required: true },
    expiresAt: { type: Date, required: true },
    usedAt: { type: Date, default: undefined },
  },
  {
    timestamps: true,
    collection: 'refresh_tokens',
    toJSON: {
      transform(_doc, ret) {
        const { __v, tokenHash: _tokenHash, ...rest } = ret;
        return rest;
      },
    },
  },
);

// ----- Indexes -----

refreshTokenSchema.index({ userId: 1, familyId: 1 });
/**
 * Reuse-detection window: how long a *consumed* refresh token must linger
 * after rotation so the auth controller can detect replay of a stolen token.
 * Mirrors the value used by the safety-net cleanup cron in tokenCleanup.ts.
 */
export const REUSE_DETECTION_WINDOW_SECONDS = 7 * 24 * 60 * 60;
/**
 * Plain (non-TTL) range index on expiresAt for the cleanup cron to
 * efficiently sweep unused-and-expired tokens. We deliberately do NOT use
 * `expireAfterSeconds: 0` here: doing so would let MongoDB delete a refresh
 * token the moment it expires, even if it was consumed seconds earlier —
 * which collapses the reuse-detection window to ~zero for tokens consumed
 * near the end of their 7-day lifetime. The cleanup cron handles eviction.
 */
refreshTokenSchema.index({ expiresAt: 1 });
/**
 * TTL on `usedAt`: consumed tokens linger exactly REUSE_DETECTION_WINDOW
 * after rotation, then auto-evict. Tokens that are still active have
 * `usedAt` undefined and are unaffected by this index (MongoDB skips TTL
 * deletion when the indexed field is missing/non-date).
 */
refreshTokenSchema.index({ usedAt: 1 }, { expireAfterSeconds: REUSE_DETECTION_WINDOW_SECONDS });

// ----- Model -----

export const RefreshToken: Model<IRefreshToken> = mongoose.model<IRefreshToken>(
  'RefreshToken',
  refreshTokenSchema,
);
