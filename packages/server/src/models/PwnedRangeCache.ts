import mongoose, { Schema, type Model, type Types } from 'mongoose';

/**
 * Provenance of a cached range.
 * - `hibp`: fetched on demand from the HIBP range API; subject to the runtime
 *   staleness TTL (`BREACH_CACHE_TTL_DAYS`).
 * - `seed`: imported in bulk by the opt-in seed command; TTL-exempt at runtime
 *   (freshness is owned by the operator re-running the seed, not by per-request
 *   refresh, which would defeat the point of seeding the full corpus).
 */
export type PwnedRangeSource = 'hibp' | 'seed';

export interface IPwnedRangeCache {
  _id: Types.ObjectId;
  /** 5 uppercase hex chars — the HIBP k-anonymity prefix and the canonical cache key. */
  prefix: string;
  /**
   * The `SUFFIX:COUNT` range body with `Add-Padding` rows (COUNT === 0) stripped.
   * An empty string is legitimate: a prefix with zero real breached suffixes.
   */
  range: string;
  source: PwnedRangeSource;
  fetchedAt: Date;
}

/**
 * Persistent, cross-account cache of HIBP Pwned Passwords range responses.
 *
 * ZERO-KNOWLEDGE NOTE: every value stored here is PUBLIC HIBP data, identical
 * for everyone and fetchable by anyone from the range API. The server only ever
 * receives the 5-char prefix (the client computes the full SHA-1 and sends the
 * prefix), so there is no per-user linkage and no suffix-match recorded — the
 * cache is a shared, global keyed store. It is therefore stored in plaintext:
 * encrypting public data adds no confidentiality and only hurts lookups.
 *
 * Growth is hard-bounded to 16^5 = 1,048,576 documents by the unique `prefix`
 * index (one row per possible prefix). There is deliberately NO TTL index —
 * staleness is decided in application code (`toolsController.getRange`) so that
 * `source: 'seed'` entries can be exempt from the on-demand refresh window.
 */
const pwnedRangeCacheSchema = new Schema<IPwnedRangeCache>(
  {
    prefix: {
      type: String,
      required: true,
      unique: true,
      uppercase: true,
      minlength: 5,
      maxlength: 5,
      match: /^[0-9A-F]{5}$/,
    },
    range: { type: String, required: true, default: '' },
    source: { type: String, required: true, enum: ['hibp', 'seed'] },
    fetchedAt: { type: Date, required: true, default: Date.now },
  },
  { collection: 'pwned_range_cache' },
);

export const PwnedRangeCache: Model<IPwnedRangeCache> = mongoose.model<IPwnedRangeCache>(
  'PwnedRangeCache',
  pwnedRangeCacheSchema,
);
