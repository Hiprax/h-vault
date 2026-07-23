import mongoose, { Schema, type Model, type HydratedDocument, type Types } from 'mongoose';
import { deviceInfoSchema, type IDeviceInfo } from './deviceInfo.js';

// ----- Main Interface -----

/**
 * A server-side record that a specific device may skip the 2FA step at login.
 *
 * Trust is never a client claim: the browser holds only a random opaque token,
 * and this collection stores its SHA-256 (`tokenHash`) so the server — and only
 * the server — can recognise or revoke it. The raw token is never persisted,
 * logged, or returned in a response body; it lives solely in the `Set-Cookie`
 * header. The 2FA-skip check that consumes this record runs strictly AFTER the
 * password comparison, so a cookie can never become an authentication bypass.
 */
export interface ITrustedDevice {
  _id: Types.ObjectId;
  userId: Types.ObjectId;
  tokenHash: string;
  deviceInfo: IDeviceInfo;
  /**
   * Absolute expiry of the trust grant. The TTL index below evicts the record
   * the instant this passes, and rotation-on-use copies it forward unchanged so
   * consuming and re-minting the record never extends the window.
   */
  expiresAt: Date;
  lastUsedAt?: Date | undefined;
  createdAt: Date;
  updatedAt: Date;
}

export type TrustedDeviceDocument = HydratedDocument<ITrustedDevice>;

// ----- Main Schema -----

const trustedDeviceSchema = new Schema<ITrustedDevice>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    tokenHash: { type: String, required: true },
    deviceInfo: { type: deviceInfoSchema, required: true },
    expiresAt: { type: Date, required: true },
    lastUsedAt: { type: Date, default: undefined },
  },
  {
    timestamps: true,
    collection: 'trusted_devices',
    toJSON: {
      transform(_doc, ret) {
        // The SHA-256 of the trust token is a server-only secret: exposing it
        // would let a listing endpoint hand back the exact value a stolen cookie
        // must hash to. Strip it, along with the version key.
        const { __v, tokenHash: _tokenHash, ...rest } = ret;
        return rest;
      },
    },
  },
);

// ----- Indexes -----

/**
 * Unique on `tokenHash`: the lookup key at login is the hash of the presented
 * cookie, and two records must never share one. Declared here (not inline on
 * the field) so it appears once in `schema.indexes()` for the production
 * `create-indexes` pass and never as a duplicate definition.
 */
trustedDeviceSchema.index({ tokenHash: 1 }, { unique: true });
/**
 * Per-user, newest-first: backs the trusted-device listing endpoint and the
 * `MAX_TRUSTED_DEVICES` eviction that drops a user's oldest records.
 */
trustedDeviceSchema.index({ userId: 1, createdAt: -1 });
/**
 * TTL on `expiresAt` (`expireAfterSeconds: 0`): MongoDB deletes each record the
 * moment its absolute expiry passes, so a lapsed trust grant can never be
 * consumed even if the cookie survives. Unlike `RefreshToken`, there is no
 * reuse-detection window to preserve here — an expired trusted device simply
 * falls through to the normal 2FA prompt — so a hard TTL is correct.
 */
trustedDeviceSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// ----- Model -----

export const TrustedDevice: Model<ITrustedDevice> = mongoose.model<ITrustedDevice>(
  'TrustedDevice',
  trustedDeviceSchema,
);
