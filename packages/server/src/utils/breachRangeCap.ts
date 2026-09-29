import { HIBP_ONDEMAND_MAX_ROWS } from '@hvault/shared';
import { PwnedRangeCache } from '../models/PwnedRangeCache.js';
import { createModuleLogger, errorMessage } from './logger.js';

/**
 * The row cap on the shared breach-range cache (`HIBP_ONDEMAND_MAX_ROWS`).
 *
 * Only rows fetched ON DEMAND (`source: 'hibp'`) count and only they are
 * evicted, oldest-fetched first; rows the seed command imported are never
 * touched. The cap is enforced in two places, and neither is a lookup:
 *
 * - {@link capOnDemandRanges}, a step of the hourly maintenance job, which brings
 *   the collection back inside the cap whatever happened in the hour;
 * - {@link noteOnDemandRangeInsert}, which `getRange` calls after each range it
 *   INSERTS, and which removes one batch after every
 *   {@link ON_DEMAND_EVICTION_EVERY}th, so an hour of heavy traffic cannot run
 *   far past the cap before the job comes round.
 *
 * Counting the collection on every miss would put a count on the hot path; once
 * per 500 inserts, through the `{source, fetchedAt, _id}` index, is all the bound
 * needs.
 *
 * Two evictions running at once (the job on one process, a sampled batch on
 * another) can each remove the same excess, so the cache can end up to one batch
 * BELOW the cap. For a cache that is harmless: an evicted range is fetched again
 * the next time someone needs it.
 */

const logger = createModuleLogger('breach-range-cap');

/** Rows one eviction batch removes at most. */
const ON_DEMAND_EVICTION_BATCH = 1_000;

/** Every how many inserted ranges a process runs one eviction batch. */
const ON_DEMAND_EVICTION_EVERY = 500;

/**
 * How long one maintenance run may spend evicting before it leaves the rest for
 * the next hour. The maintenance lock lasts 15 minutes and is never renewed, and
 * the audit trim ahead of this step may take 10 of them, so this keeps the whole
 * run inside the lock. A run always removes at least one batch.
 */
const CAP_STEP_BUDGET_MS = 3 * 60 * 1000;

/** The index both queries below are served by (declared on the model). */
const CAP_INDEX = { source: 1, fetchedAt: 1, _id: 1 } as const;

/**
 * Removes the oldest-fetched on-demand rows until at most `HIBP_ONDEMAND_MAX_ROWS`
 * remain, `ON_DEMAND_EVICTION_BATCH` at a time. Counts once (again only after a
 * batch that lost a victim to a concurrent change), then stops after
 * `maxBatches` batches or at `deadline` (epoch ms), whichever comes first, having
 * always run at least one batch. Returns how many rows it removed.
 *
 * The delete names the rows it selected AND re-states what made them victims
 * (`source: 'hibp'`, fetched no later than the newest of them), so a row the seed
 * command converted, or a lookup refreshed, between the read and the delete stays.
 * A batch that removes nothing ends the run: every victim was refreshed meanwhile,
 * and the next run looks again.
 */
async function evictOnDemandRanges(maxBatches: number, deadline: number): Promise<number> {
  let excess = await countExcess();
  let removed = 0;
  for (let batch = 0; excess > 0 && batch < maxBatches; batch += 1) {
    if (batch > 0 && Date.now() >= deadline) break;

    const victims = await PwnedRangeCache.find({ source: 'hibp' })
      .sort({ fetchedAt: 1 })
      .limit(Math.min(excess, ON_DEMAND_EVICTION_BATCH))
      .hint(CAP_INDEX)
      .select('_id fetchedAt')
      .lean();
    const newest = victims.at(-1);
    if (newest === undefined) break;

    const { deletedCount } = await PwnedRangeCache.deleteMany({
      _id: { $in: victims.map((victim) => victim._id) },
      source: 'hibp',
      fetchedAt: { $lte: newest.fetchedAt },
    });
    if (deletedCount === 0) break;
    removed += deletedCount;
    // A victim that stayed changed under us, so the running figure is no longer
    // the collection's: count again rather than evict a row too many.
    excess = deletedCount < victims.length ? await countExcess() : excess - deletedCount;
  }
  return removed;
}

/** How many on-demand rows there are above the cap (negative when below it). */
async function countExcess(): Promise<number> {
  const total = await PwnedRangeCache.countDocuments({ source: 'hibp' }, { hint: CAP_INDEX });
  return total - HIBP_ONDEMAND_MAX_ROWS;
}

/**
 * The maintenance step: brings the on-demand rows back inside the cap, or as far
 * as `budgetMs` allows (the next run carries on). A failure propagates, so the
 * maintenance run logs it under this step's name.
 *
 * @param budgetMs How long this run may evict. Tests pass it.
 */
export async function capOnDemandRanges(budgetMs: number = CAP_STEP_BUDGET_MS): Promise<void> {
  const removed = await evictOnDemandRanges(Number.POSITIVE_INFINITY, Date.now() + budgetMs);
  logger.info('Breach-range cache cap enforced', { removed, cap: HIBP_ONDEMAND_MAX_ROWS });
}

/**
 * Ranges this process has inserted since its last sampled eviction. Per process
 * and forgotten on restart: the hourly step is what makes the cap a bound, this
 * only keeps the overshoot small in between.
 */
let insertsSinceEviction = 0;

/**
 * Counts one range `getRange` inserted; on every
 * {@link ON_DEMAND_EVICTION_EVERY}th, removes at most ONE batch of the oldest
 * on-demand rows, inside the request that tripped it. Never rejects: an eviction
 * that fails is logged, and the lookup that tripped it still answers.
 */
export async function noteOnDemandRangeInsert(): Promise<void> {
  insertsSinceEviction += 1;
  if (insertsSinceEviction < ON_DEMAND_EVICTION_EVERY) return;
  insertsSinceEviction = 0;
  try {
    await evictOnDemandRanges(1, Number.POSITIVE_INFINITY);
  } catch (err: unknown) {
    logger.error('Could not evict the oldest breach ranges', { error: errorMessage(err) });
  }
}

/** Forgets how many ranges this process has inserted since its last eviction. For tests. */
export function resetOnDemandRangeSampler(): void {
  insertsSinceEviction = 0;
}
