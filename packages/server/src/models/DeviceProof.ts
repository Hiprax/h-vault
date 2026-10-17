import mongoose, { Schema, type Model, type Types } from 'mongoose';

// ----- Main Interface -----

/**
 * Proof that a browser completed an authentication for ONE account: the
 * `__hv_device` cookie's server side.
 *
 * A lockout brakes guessing, and a browser that has already signed in to the
 * account is not guessing, so a login that presents a valid proof for the
 * account it names is not braked by that account's password lockout. The owner's
 * own browsers therefore keep working while a stranger holds the account locked
 * (the OWASP device-cookie protocol). The browser holds only a random opaque
 * token; this collection stores its SHA-256, scoped to the account, so the
 * server and only the server can recognise or revoke it.
 *
 * Minted at every completed authentication and rotated on use (30 days), or
 * minted SINGLE-USE for ten minutes by the emailed unlock link, so the browser
 * that follows the link is proven even if a stranger re-locks the account a
 * second later. A proof has its own failure budget: a wrong password presented
 * with it counts HERE, not on the account, and at the budget the proof is
 * deleted (revoked) and audited, so one typo never burns a device and five
 * always do.
 */
export interface IDeviceProof {
  _id: Types.ObjectId;
  userId: Types.ObjectId;
  tokenHash: string;
  /** Absolute expiry; the TTL index below removes the row the moment it passes. */
  expiresAt: Date;
  /** Minted by the unlock link: consumed by the next successful sign-in, never rotated. */
  singleUse: boolean;
  /** Wrong passwords presented with this proof inside the current window. */
  failures: number;
  /** When the current failure window opened; absent until the first failure. */
  failuresSince?: Date | undefined;
  createdAt: Date;
  updatedAt: Date;
}

// ----- Main Schema -----

const deviceProofSchema = new Schema<IDeviceProof>(
  {
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    tokenHash: { type: String, required: true },
    expiresAt: { type: Date, required: true },
    singleUse: { type: Boolean, default: false },
    failures: { type: Number, default: 0 },
    failuresSince: { type: Date, default: undefined },
  },
  {
    timestamps: true,
    collection: 'device_proofs',
    toJSON: {
      transform(_doc, ret) {
        // The hash is what a stolen cookie must hash to; no response carries it.
        const { __v, tokenHash: _tokenHash, ...rest } = ret;
        return rest;
      },
    },
  },
);

// ----- Indexes -----

/** The lookup key at login is the hash of the presented cookie; two rows never share one. */
deviceProofSchema.index({ tokenHash: 1 }, { unique: true });
/**
 * Per account, newest first: backs every revocation (`deleteMany({ userId })` at
 * reset, change-password, log-out-everywhere, reuse detection and account
 * deletion) and the per-account cap that evicts the oldest proofs.
 */
deviceProofSchema.index({ userId: 1, createdAt: -1 });
/** TTL: a lapsed proof is removed, and a lapsed one is never honoured before that either. */
deviceProofSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// ----- Model -----

export const DeviceProof: Model<IDeviceProof> = mongoose.model<IDeviceProof>(
  'DeviceProof',
  deviceProofSchema,
);
