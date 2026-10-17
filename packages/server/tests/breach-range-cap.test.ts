/**
 * F-06: the shared breach-range cache is bounded.
 *
 * `pwned_range_cache` is written by every account's breach check (one row per
 * prefix a lookup misses), and until this phase nothing ever removed a row that
 * a lookup had fetched: the unique `prefix` index bounded it only at the whole
 * corpus (16^5 rows, ~37 GB). Two controls now bound the rows fetched ON DEMAND
 * (`source: 'hibp'`), and neither touches the rows the seed command imported
 * (`source: 'seed'`):
 *
 *   - a partial TTL index expires an on-demand row FOUR freshness windows after
 *     it was fetched. Never one window: `getRange` serves a stale row when HIBP is
 *     unreachable, and a TTL equal to the window would delete each row the moment
 *     it became that fallback;
 *   - a row cap, `HIBP_ONDEMAND_MAX_ROWS`, enforced by a step of the hourly
 *     maintenance job and after every 500th range the server fetches — never by a
 *     count on every lookup.
 *
 * HIBP itself is the one external boundary here, so `fetchRangeFromHibp` is
 * stubbed; the datastore is the real in-memory mongod.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import mongoose from 'mongoose';
import { HIBP_ONDEMAND_MAX_ROWS } from '@hvault/shared';
import { config } from '../src/config/index.js';
import { getRange, hibpCache, rangeInFlight } from '../src/controllers/toolsController.js';
import { PwnedRangeCache } from '../src/models/PwnedRangeCache.js';
import { runMaintenance } from '../src/jobs/maintenance.js';
import { fetchRangeFromHibp } from '../src/utils/hibp.js';
import { capOnDemandRanges, resetOnDemandRangeSampler } from '../src/utils/breachRangeCap.js';
import { breachMissBudgetFor, type BreachMissBudget } from '../src/utils/breachMissBudget.js';

/** A fresh account's fetch budget: these tests are about the cache, not the budget. */
function anyBudget(): BreachMissBudget {
  return breachMissBudgetFor(new mongoose.Types.ObjectId().toString());
}

vi.mock('../src/utils/hibp.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/utils/hibp.js')>();
  return { ...actual, fetchRangeFromHibp: vi.fn() };
});

const fetchMock = vi.mocked(fetchRangeFromHibp);

const DAY_MS = 86_400_000;
const CAP = HIBP_ONDEMAND_MAX_ROWS;

/** The 5-hex prefix for `n`, upper-case like every stored key. */
function prefixOf(n: number): string {
  return n.toString(16).toUpperCase().padStart(5, '0');
}

/** Prefixes the cold misses use: disjoint from every seeded row's. */
const MISS_BASE = 0x80000;

/**
 * Seeds `count` rows of `source`, the first at `oldest` and each later one a
 * second newer, with prefixes starting at `firstPrefix`. Bulk-inserted without
 * hydration: the test is about how many rows exist, not about the model's
 * validators.
 */
async function seedRows(
  source: 'hibp' | 'seed',
  count: number,
  firstPrefix: number,
  oldest: Date,
): Promise<void> {
  const docs = Array.from({ length: count }, (_, i) => ({
    prefix: prefixOf(firstPrefix + i),
    range: `${source.toUpperCase()}${String(i)}:1`,
    source,
    fetchedAt: new Date(oldest.getTime() + i * 1000),
  }));
  await PwnedRangeCache.collection.insertMany(docs, { ordered: false });
}

async function countBySource(source: 'hibp' | 'seed'): Promise<number> {
  return PwnedRangeCache.countDocuments({ source });
}

/** Resolves `count` distinct cold prefixes through the real lookup, one by one. */
async function missThroughGetRange(count: number, from = MISS_BASE): Promise<void> {
  for (let i = 0; i < count; i += 1) {
    await getRange(prefixOf(from + i), anyBudget());
  }
}

interface ProfileEntry {
  op?: string;
  ns?: string;
  command?: Record<string, unknown>;
  hasSortStage?: boolean;
  planSummary?: string;
  docsExamined?: number;
}

/** Every operation on `pwned_range_cache` while `run` executes (mongod profiler). */
async function profiled(run: () => Promise<void>): Promise<ProfileEntry[]> {
  const db = mongoose.connection.db!;
  await db.command({ profile: 0 });
  await db
    .collection('system.profile')
    .drop()
    .catch(() => undefined);
  await db.command({ profile: 2 });
  try {
    await run();
  } finally {
    await db.command({ profile: 0 });
  }
  const entries = (await db
    .collection('system.profile')
    .find({ ns: `${db.databaseName}.pwned_range_cache` })
    .toArray()) as ProfileEntry[];
  await db
    .collection('system.profile')
    .drop()
    .catch(() => undefined);
  return entries;
}

/** A command that COUNTS the collection, in any of the spellings a driver sends. */
function isCount(entry: ProfileEntry): boolean {
  const command = entry.command ?? {};
  if ('count' in command) return true;
  if ('aggregate' in command) {
    const pipeline = command['pipeline'];
    return (
      Array.isArray(pipeline) &&
      pipeline.some(
        (stage: unknown) =>
          typeof stage === 'object' && stage !== null && ('$group' in stage || '$count' in stage),
      )
    );
  }
  return false;
}

beforeEach(() => {
  hibpCache.clear();
  rangeInFlight.clear();
  resetOnDemandRangeSampler();
  fetchMock.mockReset();
  fetchMock.mockImplementation((prefix: string) => Promise.resolve(`FRESH${prefix}:7`));
});

afterEach(() => {
  hibpCache.clear();
  rangeInFlight.clear();
  vi.restoreAllMocks();
});

describe('the on-demand rows expire, four freshness windows after they were fetched', () => {
  it('has a TTL index on fetchedAt, partial to source "hibp", at 4x BREACH_CACHE_TTL_DAYS', async () => {
    await PwnedRangeCache.createIndexes();
    const indexes = (await PwnedRangeCache.collection.indexes()) as {
      key: Record<string, number>;
      expireAfterSeconds?: number;
      partialFilterExpression?: Record<string, unknown>;
    }[];

    const ttl = indexes.filter((idx) => typeof idx.expireAfterSeconds === 'number');
    expect(ttl).toHaveLength(1);
    expect(ttl[0]!.key).toEqual({ fetchedAt: 1 });
    expect(ttl[0]!.expireAfterSeconds).toBe(config.BREACH_CACHE_TTL_DAYS * 4 * 86_400);
    // Never the freshness window itself: that would delete the stale fallback.
    expect(ttl[0]!.expireAfterSeconds).toBeGreaterThan(config.BREACH_CACHE_TTL_DAYS * 86_400);
    // Seeded rows are outside the index, so the TTL monitor never sees them.
    expect(ttl[0]!.partialFilterExpression).toEqual({ source: 'hibp' });
  });

  it('serves a stale on-demand row when HIBP is unreachable, and the cap leaves it alone', async () => {
    const stalePrefix = 'ABCDE';
    await PwnedRangeCache.create({
      prefix: stalePrefix,
      range: 'STALE:3',
      source: 'hibp',
      // Past the freshness window, well inside the TTL.
      fetchedAt: new Date(Date.now() - 2 * config.BREACH_CACHE_TTL_DAYS * DAY_MS),
    });
    fetchMock.mockRejectedValue(new Error('upstream down'));

    expect(await getRange(stalePrefix, anyBudget())).toBe('STALE:3');
    expect(fetchMock).toHaveBeenCalledTimes(1);

    await runMaintenance();

    const row = await PwnedRangeCache.findOne({ prefix: stalePrefix }).lean();
    expect(row?.range).toBe('STALE:3');
    expect(row?.source).toBe('hibp');
  });
});

describe('the on-demand rows are capped at HIBP_ONDEMAND_MAX_ROWS', () => {
  it('(a) cap + 100 distinct misses, then the maintenance run, leave exactly the newest cap rows', async () => {
    const oldest = new Date(Date.now() - 10 * DAY_MS);
    await seedRows('hibp', CAP, 0, oldest);

    await missThroughGetRange(100);
    expect(fetchMock).toHaveBeenCalledTimes(100);
    expect(await countBySource('hibp')).toBe(CAP + 100);

    await runMaintenance();

    expect(await countBySource('hibp')).toBe(CAP);
    // The evicted rows are the OLDEST fetched: the first hundred seeded ...
    expect(await PwnedRangeCache.countDocuments({ prefix: { $lt: prefixOf(100) } })).toBe(0);
    // ... and never a row a lookup has just fetched.
    const fresh = await PwnedRangeCache.countDocuments({ prefix: { $gte: prefixOf(MISS_BASE) } });
    expect(fresh).toBe(100);
  });

  it('(b) never evicts a seeded row, however old, and never counts one against the cap', async () => {
    const ancient = new Date(Date.now() - 400 * DAY_MS);
    await seedRows('seed', 300, 0x40000, ancient);
    await seedRows('hibp', CAP + 50, 0, new Date(Date.now() - 10 * DAY_MS));

    await runMaintenance();

    expect(await countBySource('seed')).toBe(300);
    expect(await countBySource('hibp')).toBe(CAP);
  });

  it('leaves a cache below the cap untouched', async () => {
    await seedRows('hibp', 1_000, 0, new Date(Date.now() - 10 * DAY_MS));

    await runMaintenance();

    expect(await countBySource('hibp')).toBe(1_000);
  });

  it('evicts after every 500th fetched range, and 499 misses issue no count at all', async () => {
    await seedRows('hibp', CAP, 0, new Date(Date.now() - 10 * DAY_MS));

    const hotPath = await profiled(() => missThroughGetRange(499));
    expect(fetchMock).toHaveBeenCalledTimes(499);
    // The profiler did see the lookups themselves ...
    expect(hotPath.some((entry) => entry.op === 'update')).toBe(true);
    // ... and not one count of the collection among them.
    expect(hotPath.filter(isCount)).toEqual([]);
    expect(await countBySource('hibp')).toBe(CAP + 499);

    await missThroughGetRange(1, MISS_BASE + 499);

    expect(await countBySource('hibp')).toBe(CAP);
    expect(await PwnedRangeCache.countDocuments({ prefix: { $lt: prefixOf(500) } })).toBe(0);
    expect(await PwnedRangeCache.countDocuments({ prefix: { $gte: prefixOf(MISS_BASE) } })).toBe(
      500,
    );
  });

  it('removes exactly one batch of 1,000 in the request, and the job drains the rest', async () => {
    await seedRows('hibp', CAP + 2_500, 0, new Date(Date.now() - 10 * DAY_MS));

    await missThroughGetRange(500);

    // Excess 3,000 at the 500th insert: the request removes ONE batch, no more.
    expect(await countBySource('hibp')).toBe(CAP + 2_000);
    expect(await PwnedRangeCache.countDocuments({ prefix: { $lt: prefixOf(1_000) } })).toBe(0);
    expect(await PwnedRangeCache.findOne({ prefix: prefixOf(1_000) }).lean()).not.toBeNull();

    // The job needs two more batches for the remaining 2,000.
    await runMaintenance();

    expect(await countBySource('hibp')).toBe(CAP);
    expect(await PwnedRangeCache.countDocuments({ prefix: { $lt: prefixOf(3_000) } })).toBe(0);
    expect(await PwnedRangeCache.countDocuments({ prefix: { $gte: prefixOf(MISS_BASE) } })).toBe(
      500,
    );
  });

  it('stops at its time budget having removed one batch, and the next run carries on', async () => {
    await seedRows('hibp', CAP + 2_500, 0, new Date(Date.now() - 10 * DAY_MS));

    await capOnDemandRanges(0);

    expect(await countBySource('hibp')).toBe(CAP + 1_500);

    await capOnDemandRanges();

    expect(await countBySource('hibp')).toBe(CAP);
  });

  it('finds the oldest on-demand rows from the {source, fetchedAt, _id} index alone, never a sort', async () => {
    await seedRows('hibp', CAP + 10, 0, new Date(Date.now() - 10 * DAY_MS));
    await seedRows('seed', 10, 0x40000, new Date(Date.now() - 400 * DAY_MS));

    const entries = await profiled(() => runMaintenance());

    const finds = entries.filter((entry) => entry.op === 'query');
    expect(finds.length).toBeGreaterThan(0);
    for (const find of finds) {
      expect(find.hasSortStage ?? false).toBe(false);
      expect(find.planSummary).toContain('IXSCAN { source: 1, fetchedAt: 1, _id: 1 }');
      // Covered: the walk never loads a range document to find its victims.
      expect(find.docsExamined).toBe(0);
    }
    expect(await countBySource('hibp')).toBe(CAP);
    expect(await countBySource('seed')).toBe(10);
  });
});

describe('an eviction never removes a row that stopped being a victim', () => {
  /**
   * Runs `between` once, after the eviction has READ its victims and before it
   * deletes them: the interleaving a concurrent seed run or lookup produces.
   * The delete itself is the real one.
   */
  function interleaveBeforeTheDelete(between: () => Promise<unknown>): void {
    const realDeleteMany = PwnedRangeCache.deleteMany.bind(PwnedRangeCache);
    let done = false;
    vi.spyOn(PwnedRangeCache, 'deleteMany').mockImplementation(((
      ...args: Parameters<typeof realDeleteMany>
    ) => {
      if (done) return realDeleteMany(...args);
      done = true;
      return (async () => {
        await between();
        return realDeleteMany(...args);
      })();
    }) as typeof PwnedRangeCache.deleteMany);
  }

  it('keeps a victim the seed command imported meanwhile, and still reaches the cap', async () => {
    await seedRows('hibp', CAP + 5, 0, new Date(Date.now() - 10 * DAY_MS));
    interleaveBeforeTheDelete(() =>
      PwnedRangeCache.collection.updateOne({ prefix: prefixOf(0) }, { $set: { source: 'seed' } }),
    );

    await runMaintenance();

    const converted = await PwnedRangeCache.findOne({ prefix: prefixOf(0) }).lean();
    expect(converted?.source).toBe('seed');
    expect(await countBySource('hibp')).toBe(CAP);
    expect(await countBySource('seed')).toBe(1);
  });

  it('keeps a victim a lookup refreshed meanwhile, and evicts the next oldest instead', async () => {
    await seedRows('hibp', CAP + 5, 0, new Date(Date.now() - 10 * DAY_MS));
    interleaveBeforeTheDelete(() =>
      PwnedRangeCache.collection.updateOne(
        { prefix: prefixOf(0) },
        { $set: { fetchedAt: new Date() } },
      ),
    );

    await runMaintenance();

    expect(await PwnedRangeCache.findOne({ prefix: prefixOf(0) }).lean()).not.toBeNull();
    expect(await PwnedRangeCache.findOne({ prefix: prefixOf(5) }).lean()).toBeNull();
    expect(await countBySource('hibp')).toBe(CAP);
  });
});

describe('a range the seed command writes during a lookup stays seeded', () => {
  it('does not turn a seeded row back into an on-demand one that could expire', async () => {
    const prefix = 'ABCDF';
    fetchMock.mockImplementation(async (p: string) => {
      // The seed command imports this prefix while the lookup is fetching it.
      await PwnedRangeCache.collection.insertOne({
        prefix: p,
        range: 'SEEDED:4',
        source: 'seed',
        fetchedAt: new Date(),
      });
      return `FRESH${p}:7`;
    });

    expect(await getRange(prefix, anyBudget())).toBe(`FRESH${prefix}:7`);

    const row = await PwnedRangeCache.findOne({ prefix }).lean();
    expect(row?.source).toBe('seed');
    expect(row?.range).toBe('SEEDED:4');
    expect(await countBySource('hibp')).toBe(0);
  });
});

describe('a range that cannot be stored', () => {
  it('fails the lookup when there is no cached fallback, rather than treating it as stored', async () => {
    vi.spyOn(PwnedRangeCache, 'updateOne').mockRejectedValueOnce(
      Object.assign(new Error('not writable'), { code: 10107 }),
    );

    await expect(getRange('ABCE0', anyBudget())).rejects.toThrow('not writable');

    expect(await PwnedRangeCache.findOne({ prefix: 'ABCE0' }).lean()).toBeNull();
    expect(hibpCache.has('ABCE0')).toBe(false);
  });
});

describe('the sampled eviction counts inserted ranges only, and never fails a lookup', () => {
  it('does not count a refreshed stale row toward the 500', async () => {
    const stalePrefix = prefixOf(0x7ffff);
    await seedRows('hibp', CAP - 1, 0, new Date(Date.now() - 10 * DAY_MS));
    await PwnedRangeCache.create({
      prefix: stalePrefix,
      range: 'STALE:1',
      source: 'hibp',
      fetchedAt: new Date(Date.now() - 2 * config.BREACH_CACHE_TTL_DAYS * DAY_MS),
    });

    await missThroughGetRange(499);
    // A refresh rewrites the stale row in place: an outbound fetch, no new row.
    expect(await getRange(stalePrefix, anyBudget())).toBe(`FRESH${stalePrefix}:7`);
    expect(fetchMock).toHaveBeenCalledTimes(500);
    expect(await countBySource('hibp')).toBe(CAP + 499);

    await missThroughGetRange(1, MISS_BASE + 499);

    expect(await countBySource('hibp')).toBe(CAP);
    // The refreshed row is now among the newest, so it survived the eviction.
    const refreshed = await PwnedRangeCache.findOne({ prefix: stalePrefix }).lean();
    expect(refreshed?.range).toBe(`FRESH${stalePrefix}:7`);
  });

  it('answers the lookup that trips a failing eviction, and leaves every row in place', async () => {
    await seedRows('hibp', CAP, 0, new Date(Date.now() - 10 * DAY_MS));
    // The eviction reads through the {source, fetchedAt} index by name: without
    // it (a deployment that has not run create-indexes yet) the eviction fails.
    await PwnedRangeCache.collection.dropIndex('source_1_fetchedAt_1__id_1');
    try {
      await missThroughGetRange(499);
      const tripping = prefixOf(MISS_BASE + 499);

      await expect(getRange(tripping, anyBudget())).resolves.toBe(`FRESH${tripping}:7`);

      expect(await countBySource('hibp')).toBe(CAP + 500);
      expect(await PwnedRangeCache.findOne({ prefix: tripping }).lean()).not.toBeNull();
    } finally {
      await PwnedRangeCache.createIndexes();
    }
  });
});
