import mongoose from 'mongoose';
import type { Store, Options, ClientRateLimitInfo } from 'express-rate-limit';
import { createLogger } from '@hiprax/logger';

const logger = createLogger({ moduleName: 'rate-limit-store' });

/**
 * The single collection every keyed rate-limit counter lives in. Limiters
 * disambiguate themselves with a key prefix (`auth:`, `account:`, `refresh:`,
 * `unlock:`, `breach:`, `general:`, `pwverify:`, `heavy:`, `health:`, `metrics:`,
 * `csrf:`), so one collection with one TTL index serves all of them.
 */
export const RATE_LIMIT_COLLECTION = 'rateLimits';

/**
 * How many times a failing TTL-index creation is retried before the store stops
 * asking. See {@link MongoRateLimitStore.ttlIndexReady} — without a ceiling, a
 * permanently failing `createIndex` would fire on every request forever.
 */
const MAX_TTL_INDEX_ATTEMPTS = 3;

interface RateLimitRecord {
  _id: string;
  counter: number;
  expirationDate: Date;
}

/**
 * An `express-rate-limit` store backed by the connection Mongoose already owns.
 *
 * It replaces `rate-limit-mongo`, which could not work here at all. That package
 * is callback-based and bundles its own mongodb 3.6 driver; the MongoDB driver
 * dropped callbacks in v5, so handing it a Collection from the modern driver the
 * app actually uses left its internal `Steppy` chain waiting on a callback that
 * would never fire — every rate-limited request hung until the client gave up.
 * Its only working mode is to connect a driver-3 MongoClient of its own from a
 * URI, which would mean an end-of-life driver and a separate connection pool for
 * each of the dozen limiters in this file.
 *
 * This store instead issues its counters over `mongoose.connection`, so it adds
 * no connection, no pool and no dependency, and it is closed by the same
 * `mongoose.connection.close()` the graceful shutdown already performs.
 *
 * Counting is a SINGLE atomic upsert built as an aggregation-pipeline update, so
 * concurrent requests for the same key cannot lose an increment between a read
 * and a write — which for a limiter is the difference between enforcing a limit
 * and merely suggesting one. The pipeline decides, server-side and against the
 * server's own `$$NOW`:
 *
 *   * window still open  -> counter + 1, keep the existing expiry
 *   * window expired, or no record at all -> counter = 1, start a fresh window
 *
 * Expired records are also reaped by a TTL index, but correctness never depends
 * on the reaper having run: an expired record is treated as absent by the
 * comparison above, whether or not MongoDB has collected it yet.
 */
export class MongoRateLimitStore implements Store {
  /**
   * Window length. Seeded from the constructor and then authoritatively set by
   * `init`, which express-rate-limit calls with the limiter's resolved options.
   */
  private windowMs: number;

  /**
   * Memoised TTL-index creation. In production Mongoose runs with
   * `autoIndex: false`, and this is a raw collection rather than a model, so the
   * `create-indexes` bootstrap does not cover it — the index is ensured here, on
   * first use, exactly once per process.
   *
   * A failure clears the memo so a later request can retry — but only up to
   * {@link MAX_TTL_INDEX_ATTEMPTS} times. Retrying forever would mean a permanent
   * failure (say, a collection whose index the operator pinned differently) turns
   * every single request into another failed `createIndex` round trip, which is a
   * hot loop against the database on the app's hottest path. Giving up is safe:
   * the index only drives MongoDB's background reaper, and correctness never
   * depends on it — an expired record is treated as absent by the `$$NOW`
   * comparison whether or not it has been collected.
   */
  private ttlIndexReady: Promise<void> | null = null;

  /** Failed `createIndex` attempts so far; see {@link ttlIndexReady}. */
  private ttlIndexAttempts = 0;

  constructor(windowMs: number) {
    this.windowMs = windowMs;
  }

  init(options: Options): void {
    this.windowMs = options.windowMs;
  }

  private collection() {
    const db = mongoose.connection.db;
    if (!db) {
      // The limiters run inside request handlers, which only exist after the
      // server started listening — and it only listens after connectDatabase()
      // resolves. Reaching this would mean the connection dropped mid-request.
      throw new Error('Rate limit store: MongoDB connection is not established');
    }
    return db.collection<RateLimitRecord>(RATE_LIMIT_COLLECTION);
  }

  private async ensureTtlIndex(): Promise<void> {
    if (this.ttlIndexAttempts >= MAX_TTL_INDEX_ATTEMPTS) return;

    this.ttlIndexReady ??= this.collection()
      .createIndex({ expirationDate: 1 }, { expireAfterSeconds: 0 })
      .then(() => undefined)
      .catch((error: unknown) => {
        this.ttlIndexAttempts += 1;
        // Allow a retry on the next request — unless we have now given up, in
        // which case leaving the resolved promise in place is what stops the retry
        // loop (the guard above short-circuits before we ever get here again).
        if (this.ttlIndexAttempts < MAX_TTL_INDEX_ATTEMPTS) this.ttlIndexReady = null;
        logger.error('Rate limit store: failed to create the TTL index', {
          error,
          attempt: this.ttlIndexAttempts,
          givingUp: this.ttlIndexAttempts >= MAX_TTL_INDEX_ATTEMPTS,
        });
      });

    return this.ttlIndexReady;
  }

  async increment(key: string): Promise<ClientRateLimitInfo> {
    await this.ensureTtlIndex();

    const record = await this.collection().findOneAndUpdate(
      { _id: key },
      [
        {
          $set: {
            counter: {
              $cond: [
                { $gt: ['$expirationDate', '$$NOW'] },
                { $add: [{ $ifNull: ['$counter', 0] }, 1] },
                1,
              ],
            },
            expirationDate: {
              $cond: [
                { $gt: ['$expirationDate', '$$NOW'] },
                '$expirationDate',
                { $add: ['$$NOW', this.windowMs] },
              ],
            },
          },
        },
      ],
      { upsert: true, returnDocument: 'after' },
    );

    if (!record) {
      // Unreachable with `upsert: true` + `returnDocument: 'after'`. Fail CLOSED
      // rather than returning a zero count, which express-rate-limit would read
      // as "this client has used none of its quota".
      throw new Error('Rate limit store: upsert returned no record');
    }

    return { totalHits: record.counter, resetTime: record.expirationDate };
  }

  async decrement(key: string): Promise<void> {
    // Only within the live window: decrementing an expired record would resurrect a
    // stale counter that the next increment is about to reset anyway.
    //
    // Expressed as a pipeline so the liveness test uses the DATABASE's clock
    // ($$NOW), exactly as increment() does. A filter written against `new Date()`
    // would compare the app container's clock to timestamps the database wrote —
    // correct only while the two agree, and silently wrong when they drift.
    await this.collection().updateOne({ _id: key }, [
      {
        $set: {
          counter: {
            $cond: [
              { $gt: ['$expirationDate', '$$NOW'] },
              { $add: [{ $ifNull: ['$counter', 0] }, -1] },
              '$counter',
            ],
          },
        },
      },
    ]);
  }

  async get(key: string): Promise<ClientRateLimitInfo | undefined> {
    const record = await this.collection().findOne({
      _id: key,
      expirationDate: { $gt: new Date() },
    });

    if (!record) return undefined;

    return { totalHits: record.counter, resetTime: record.expirationDate };
  }

  async resetKey(key: string): Promise<void> {
    await this.collection().deleteOne({ _id: key });
  }

  async resetAll(): Promise<void> {
    await this.collection().deleteMany({});
  }
}
