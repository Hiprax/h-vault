import mongoose, { Schema, type Model, type Types } from 'mongoose';
import { HIBP_MAX_RANGE_RESPONSE_BYTES } from '../constants/index.js';
import { indexConfig } from '../config/indexConfig.js';

/**
 * Provenance of a cached range.
 * - `hibp`: fetched on demand from the HIBP range API; subject to the runtime
 *   staleness window (`BREACH_CACHE_TTL_DAYS`), to the TTL index below and to the
 *   `HIBP_ONDEMAND_MAX_ROWS` cap (`utils/breachRangeCap.ts`).
 * - `seed`: imported in bulk by the opt-in seed command; exempt from all three
 *   (freshness is owned by the operator re-running the seed, not by per-request
 *   refresh, which would defeat the point of seeding the full corpus).
 */
type PwnedRangeSource = 'hibp' | 'seed';

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
 * The unique `prefix` index bounds the collection only at the whole corpus
 * (16^5 = 1,048,576 rows, ~37 GB), and every account's breach check writes to it,
 * so the rows fetched ON DEMAND are bounded twice more:
 *
 * - by AGE: the partial TTL index below deletes an on-demand row
 *   {@link ON_DEMAND_RANGE_RETENTION_WINDOWS} freshness windows after it was
 *   fetched. Freshness itself is still decided in application code
 *   (`toolsController.getRange`), and a row past its window is not dead: when
 *   HIBP is unreachable, `getRange` serves it as the fallback. A TTL equal to the
 *   window would delete every row the moment it became that fallback, which is
 *   why the retention is a multiple of the window and never the window itself;
 * - by COUNT: `HIBP_ONDEMAND_MAX_ROWS`, enforced off the lookup path by the hourly
 *   maintenance job and after every 500th inserted range (`utils/breachRangeCap.ts`),
 *   which finds the oldest rows through the `{source, fetchedAt, _id}` index.
 *
 * Both are partial to `source: 'hibp'`: seeded rows are never expired or evicted.
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
    // Bounded to the same ceiling the outbound fetch enforces
    // (`HIBP_MAX_RANGE_RESPONSE_BYTES`), so an oversized body cannot be stored
    // even if it somehow reaches the model. Read what this is worth precisely:
    // BOTH production write sites (`toolsController.getRange`'s upsert and
    // `breachSeed`'s `bulkWrite`) deliberately omit `runValidators`, for the
    // reason recorded at each — `required` rejects '', and an EMPTY range is a
    // legitimate value. So the BINDING bound is `maxContentLength` on the fetch;
    // this one runs on `save()`/`create()` and on any update that opts into
    // validators, and exists to catch a future write site that forgets.
    range: {
      type: String,
      required: true,
      default: '',
      maxlength: HIBP_MAX_RANGE_RESPONSE_BYTES,
    },
    source: { type: String, required: true, enum: ['hibp', 'seed'] },
    fetchedAt: { type: Date, required: true, default: Date.now },
  },
  { collection: 'pwned_range_cache' },
);

/**
 * How many freshness windows (`BREACH_CACHE_TTL_DAYS`) an on-demand row outlives
 * its fetch before the TTL monitor deletes it: three windows of stale fallback
 * after the first of freshness. Never 1 (see the model docblock).
 *
 * The retention is read from the configuration when this module loads, so it is
 * fixed in the index at `create-indexes` time; `create-indexes` re-creates the
 * index when the configured value changes.
 */
export const ON_DEMAND_RANGE_RETENTION_WINDOWS = 4;

pwnedRangeCacheSchema.index(
  { fetchedAt: 1 },
  {
    expireAfterSeconds:
      indexConfig.BREACH_CACHE_TTL_DAYS * ON_DEMAND_RANGE_RETENTION_WINDOWS * 86_400,
    partialFilterExpression: { source: 'hibp' },
  },
);

// Serves the cap: the count of on-demand rows and the walk from the oldest one.
// `_id` is the last key so the walk, which reads only `_id` and `fetchedAt`, is
// answered from the index without loading a single ~36 KB range.
pwnedRangeCacheSchema.index({ source: 1, fetchedAt: 1, _id: 1 });

export const PwnedRangeCache: Model<IPwnedRangeCache> = mongoose.model<IPwnedRangeCache>(
  'PwnedRangeCache',
  pwnedRangeCacheSchema,
);
