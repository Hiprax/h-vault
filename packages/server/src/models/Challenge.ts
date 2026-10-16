import mongoose, { Schema, type Model, type Types } from 'mongoose';

// ----- Main Interface -----

/**
 * One second-factor challenge: the server side of the `tempToken` that `login`
 * hands a 2FA account once its master password is proven.
 *
 * The token is a signed JWT and carries this row's `jti`. A signature alone would
 * let the token be exchanged for a session as many times as its five minutes
 * allow (each exchange still needs a fresh second-factor code, so it was never a
 * bypass, but one proof of the password bought any number of sessions). The row
 * is what makes it single-use: `login2fa` consumes it with ONE compare-and-set
 * (`consumedAt: null` → now) at the first exchange that presents a correct code,
 * so every later presentation of the same token, and every concurrent one that
 * lost the race, is refused. One row per token rather than a "last consumed id"
 * on the user, because the latter blocks only the newest token while an older,
 * unexpired one still passes.
 *
 * A wrong code does not consume it: a typo must not cost the user their sign-in.
 */
export interface IChallenge {
  _id: Types.ObjectId;
  /** The `jti` claim of the token this row backs. */
  jti: string;
  /** The account whose password was proven; the token's own `userId` must match. */
  userId: Types.ObjectId;
  /** The token's own `exp`, to the second. The TTL index removes the row once it passes. */
  expiresAt: Date;
  /** Set by the one exchange that completed the sign-in; `null` until then. */
  consumedAt: Date | null;
}

// ----- Main Schema -----

const challengeSchema = new Schema<IChallenge>(
  {
    jti: { type: String, required: true },
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    expiresAt: { type: Date, required: true },
    consumedAt: { type: Date, default: null },
  },
  { collection: 'challenges' },
);

// ----- Indexes -----

/** The token names its row by `jti`; two tokens never share one. */
challengeSchema.index({ jti: 1 }, { unique: true });
/** Backs the account erasure, which removes an account's rows by `userId`. */
challengeSchema.index({ userId: 1 });
/** TTL: a row is useless once its token has expired, consumed or not. */
challengeSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// ----- Model -----

export const Challenge: Model<IChallenge> = mongoose.model<IChallenge>(
  'Challenge',
  challengeSchema,
);
