/**
 * F-06: an account's outbound breach lookups are budgeted.
 *
 * Both breach endpoints answer from the shared range cache when they can, and
 * fetch from HIBP when they cannot. Until this phase the only bound on those
 * fetches was the request limiters (30 single + 300 batch requests of up to 100
 * prefixes per 15 minutes, so up to 30,000 fetches an account could cause per
 * window, round the clock). Now every fetch an account CAUSES is charged to two
 * per-account budgets, `HIBP_MAX_MISSES_PER_USER_PER_WINDOW` per
 * `HIBP_MISS_BUDGET_WINDOW_MINUTES` and `HIBP_MAX_MISSES_PER_USER_PER_DAY` per
 * day. A cache hit is free; past a budget the endpoints answer 429 with
 * `Retry-After`, never a range they did not check.
 *
 * The budgets are counters in the rate-limit collection, and they are enforced
 * in every environment (they bound a sink, like the upload admission budgets,
 * rather than throttle requests), so these tests reach a boundary by SEEDING the
 * counter document, as the limiter suites do, never by sending 10,000 lookups.
 * HIBP is the external boundary: `fetchRangeFromHibp` is stubbed.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import {
  HIBP_BATCH_MAX_PREFIXES,
  HIBP_MAX_MISSES_PER_USER_PER_DAY,
  HIBP_MAX_MISSES_PER_USER_PER_WINDOW,
  HIBP_MISS_BUDGET_WINDOW_MINUTES,
  HIBP_ONDEMAND_MAX_ROWS,
  MAX_ITEMS_PER_USER,
} from '@hvault/shared';
import app from '../src/app.js';
import { config } from '../src/config/index.js';
import { getRange, hibpCache, rangeInFlight } from '../src/controllers/toolsController.js';
import { PwnedRangeCache } from '../src/models/PwnedRangeCache.js';
import { RATE_LIMIT_COLLECTION } from '../src/middleware/rateLimitStore.js';
import {
  BREACH_BATCH_RATE_LIMIT_MAX,
  BREACH_BATCH_RATE_LIMIT_WINDOW_MS,
} from '../src/middleware/rateLimiter.js';
import { fetchRangeFromHibp } from '../src/utils/hibp.js';
import { BreachMissBudgetError, breachMissBudgetFor } from '../src/utils/breachMissBudget.js';
import { createTestUser, authHeader, getCsrf } from './helpers.js';
import type { TestUser } from './helpers.js';

vi.mock('../src/utils/hibp.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/utils/hibp.js')>();
  return { ...actual, fetchRangeFromHibp: vi.fn() };
});

const fetchMock = vi.mocked(fetchRangeFromHibp);

const API = '/api/v1';
const DAY_MS = 86_400_000;
const WINDOW_S = HIBP_MISS_BUDGET_WINDOW_MINUTES * 60;

function prefixOf(n: number): string {
  return n.toString(16).toUpperCase().padStart(5, '0');
}

/** Distinct cold prefixes, starting at `from`. */
function coldPrefixes(count: number, from = 0x10000): string[] {
  return Array.from({ length: count }, (_, i) => prefixOf(from + i));
}

/**
 * Seeds one of `userId`'s budget counters as if `used` fetches had already been
 * charged in a window ending `expiresInMs` from now.
 */
async function seedCounter(
  counter: 'window' | 'day',
  userId: string,
  used: number,
  expiresInMs: number,
): Promise<void> {
  const key = counter === 'window' ? `breachMiss:${userId}` : `breachMissDay:${userId}`;
  await mongoose.connection
    .collection(RATE_LIMIT_COLLECTION)
    .updateOne(
      { _id: key as unknown as mongoose.Types.ObjectId },
      { $set: { counter: used, expirationDate: new Date(Date.now() + expiresInMs) } },
      { upsert: true },
    );
}

async function counterValue(counter: 'window' | 'day', userId: string): Promise<number | null> {
  const key = counter === 'window' ? `breachMiss:${userId}` : `breachMissDay:${userId}`;
  const doc = await mongoose.connection
    .collection<{ _id: string; counter: number }>(RATE_LIMIT_COLLECTION)
    .findOne({ _id: key });
  return doc?.counter ?? null;
}

async function seedFreshRange(prefix: string, range: string): Promise<void> {
  await PwnedRangeCache.create({ prefix, range, source: 'hibp', fetchedAt: new Date() });
}

async function postBatch(user: TestUser, hashPrefixes: string[]): Promise<request.Response> {
  const agent = request.agent(app);
  const { token, cookie } = await getCsrf(agent);
  return agent
    .post(`${API}/tools/check-password-breach/batch`)
    .set('Authorization', authHeader(user.accessToken))
    .set('x-csrf-token', token)
    .set('Cookie', cookie)
    .send({ hashPrefixes });
}

async function postSingle(user: TestUser, hashPrefix: string): Promise<request.Response> {
  const agent = request.agent(app);
  const { token, cookie } = await getCsrf(agent);
  return agent
    .post(`${API}/tools/check-password-breach`)
    .set('Authorization', authHeader(user.accessToken))
    .set('x-csrf-token', token)
    .set('Cookie', cookie)
    .send({ hashPrefix });
}

function retryAfterOf(res: request.Response): number {
  return Number(res.headers['retry-after']);
}

beforeEach(() => {
  hibpCache.clear();
  rangeInFlight.clear();
  fetchMock.mockReset();
  fetchMock.mockImplementation((prefix: string) => Promise.resolve(`FRESH${prefix}:9`));
});

afterEach(() => {
  hibpCache.clear();
  rangeInFlight.clear();
  vi.restoreAllMocks();
});

describe('the window budget on the batch endpoint', () => {
  it('fetches up to the budget exactly, then answers the batch that needs one more with 429', async () => {
    const user = await createTestUser();
    // 150 fetches left in this window.
    await seedCounter('window', user.id, HIBP_MAX_MISSES_PER_USER_PER_WINDOW - 150, 10 * 60_000);

    const first = await postBatch(user, coldPrefixes(100));
    expect(first.status).toBe(200);
    expect(Object.keys(first.body.data)).toHaveLength(100);
    expect(first.body.errors).toEqual([]);

    const second = await postBatch(user, coldPrefixes(100, 0x20000));
    expect(second.status).toBe(429);
    expect(second.body.success).toBe(false);
    // No range at all in a refused answer: never a partial list read as checked.
    expect(second.body.data).toBeUndefined();
    const retryAfter = retryAfterOf(second);
    expect(retryAfter).toBeGreaterThanOrEqual(1);
    expect(retryAfter).toBeLessThanOrEqual(10 * 60);

    // Exactly the budget left was spent on HIBP, not one fetch more.
    expect(fetchMock).toHaveBeenCalledTimes(150);
  });

  it('keeps what it fetched before refusing, so the retry after the reset gets those free', async () => {
    const user = await createTestUser();
    await seedCounter('window', user.id, HIBP_MAX_MISSES_PER_USER_PER_WINDOW - 30, 10 * 60_000);
    const prefixes = coldPrefixes(60);

    expect((await postBatch(user, prefixes)).status).toBe(429);
    expect(fetchMock).toHaveBeenCalledTimes(30);
    expect(await PwnedRangeCache.countDocuments({ prefix: { $in: prefixes } })).toBe(30);

    // The window resets.
    await seedCounter('window', user.id, 0, -1_000);
    hibpCache.clear();
    const retry = await postBatch(user, prefixes);

    expect(retry.status).toBe(200);
    expect(Object.keys(retry.body.data)).toHaveLength(60);
    // Only the 30 it never fetched cost anything the second time.
    expect(fetchMock).toHaveBeenCalledTimes(60);
    expect(await counterValue('window', user.id)).toBe(30);
  });

  it('still answers a batch of cache hits after the budget is spent', async () => {
    const user = await createTestUser();
    await seedCounter('window', user.id, HIBP_MAX_MISSES_PER_USER_PER_WINDOW, 10 * 60_000);
    await seedFreshRange('AAAA1', 'HIT1:1');
    await seedFreshRange('AAAA2', 'HIT2:2');

    const res = await postBatch(user, ['AAAA1', 'AAAA2']);

    expect(res.status).toBe(200);
    expect(res.body.data).toEqual({ AAAA1: 'HIT1:1', AAAA2: 'HIT2:2' });
    expect(fetchMock).not.toHaveBeenCalled();
    // A hit is free: the counter did not move.
    expect(await counterValue('window', user.id)).toBe(HIBP_MAX_MISSES_PER_USER_PER_WINDOW);
  });

  it("never spends one account's budget for another", async () => {
    const spent = await createTestUser();
    const other = await createTestUser();
    await seedCounter('window', spent.id, HIBP_MAX_MISSES_PER_USER_PER_WINDOW, 10 * 60_000);

    expect((await postBatch(spent, coldPrefixes(1))).status).toBe(429);
    const res = await postBatch(other, coldPrefixes(1, 0x30000));

    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(await counterValue('window', other.id)).toBe(1);
  });

  it('serves a stale cached range instead of refusing, exactly as when HIBP is down', async () => {
    const user = await createTestUser();
    await seedCounter('window', user.id, HIBP_MAX_MISSES_PER_USER_PER_WINDOW, 10 * 60_000);
    await PwnedRangeCache.create({
      prefix: 'BBBB1',
      range: 'STALE:5',
      source: 'hibp',
      fetchedAt: new Date(Date.now() - 2 * config.BREACH_CACHE_TTL_DAYS * DAY_MS),
    });

    const res = await postBatch(user, ['BBBB1']);

    expect(res.status).toBe(200);
    expect(res.body.data).toEqual({ BBBB1: 'STALE:5' });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe('the window budget on the single endpoint', () => {
  it('admits the last fetch of the budget and refuses the next with 429 and Retry-After', async () => {
    const user = await createTestUser();
    await seedCounter('window', user.id, HIBP_MAX_MISSES_PER_USER_PER_WINDOW - 1, 5 * 60_000);

    const last = await postSingle(user, 'CCCC1');
    expect(last.status).toBe(200);
    expect(last.body.data).toBe('FRESHCCCC1:9');

    const refused = await postSingle(user, 'CCCC2');
    expect(refused.status).toBe(429);
    expect(refused.body.data).toBeUndefined();
    const retryAfter = retryAfterOf(refused);
    expect(retryAfter).toBeGreaterThanOrEqual(1);
    expect(retryAfter).toBeLessThanOrEqual(5 * 60);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(await PwnedRangeCache.findOne({ prefix: 'CCCC2' }).lean()).toBeNull();
  });

  it('never asks for longer than the budget window, whatever the stored reset says', async () => {
    const user = await createTestUser();
    // A counter whose window claims to end in two hours (a clock that moved).
    await seedCounter('window', user.id, HIBP_MAX_MISSES_PER_USER_PER_WINDOW, 2 * 60 * 60_000);

    const refused = await postSingle(user, 'CCCC3');

    expect(refused.status).toBe(429);
    expect(retryAfterOf(refused)).toBe(WINDOW_S);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('counts a fetch only for a miss, and a fetch that fails still counts', async () => {
    const user = await createTestUser();
    await seedFreshRange('DDDD1', 'HIT:1');
    fetchMock.mockRejectedValueOnce(new Error('upstream down'));

    expect((await postSingle(user, 'DDDD1')).status).toBe(200);
    expect(await counterValue('window', user.id)).toBeNull();

    expect((await postSingle(user, 'DDDD2')).status).toBeGreaterThanOrEqual(500);
    expect(await counterValue('window', user.id)).toBe(1);
    expect(await counterValue('day', user.id)).toBe(1);
  });
});

describe('a refused request stops spending', () => {
  it('a refused budget refuses again at once, without counting again', async () => {
    const userId = new mongoose.Types.ObjectId().toString();
    await seedCounter('window', userId, HIBP_MAX_MISSES_PER_USER_PER_WINDOW, 10 * 60_000);
    const budget = breachMissBudgetFor(userId);

    const first = await budget.charge().catch((err: unknown) => err);
    const second = await budget.charge().catch((err: unknown) => err);

    expect(first).toBeInstanceOf(BreachMissBudgetError);
    expect(second).toBe(first);
    expect(await counterValue('window', userId)).toBe(HIBP_MAX_MISSES_PER_USER_PER_WINDOW + 1);
    expect(await counterValue('day', userId)).toBeNull();
  });

  it('asks for at least a second when the application clock runs ahead of the database', async () => {
    const userId = new mongoose.Types.ObjectId().toString();
    await seedCounter('window', userId, HIBP_MAX_MISSES_PER_USER_PER_WINDOW, 60_000);
    // The database says the window ends in a minute; this process thinks that
    // minute is long gone.
    const realNow = Date.now.bind(Date);
    vi.spyOn(Date, 'now').mockImplementation(() => realNow() + 60 * 60_000);

    const refusal = await breachMissBudgetFor(userId)
      .charge()
      .catch((err: unknown) => err);

    expect(refusal).toBeInstanceOf(BreachMissBudgetError);
    expect((refusal as BreachMissBudgetError).retryAfterSeconds).toBe(1);
  });

  it('a refused batch starts no lookup beyond those already under way', async () => {
    const user = await createTestUser();
    await seedCounter('window', user.id, HIBP_MAX_MISSES_PER_USER_PER_WINDOW, 10 * 60_000);
    const findOne = vi.spyOn(PwnedRangeCache, 'findOne');

    const res = await postBatch(user, coldPrefixes(100));

    expect(res.status).toBe(429);
    // At most one round of the fan-out (8 at once), never all 100.
    expect(findOne.mock.calls.length).toBeLessThanOrEqual(8);
    expect(fetchMock).not.toHaveBeenCalled();
    const used = await counterValue('window', user.id);
    expect(used).toBeLessThanOrEqual(HIBP_MAX_MISSES_PER_USER_PER_WINDOW + 8);
  });
});

describe('the daily budget', () => {
  it('refuses once the day is spent although the window is not, with the day in Retry-After', async () => {
    const user = await createTestUser();
    await seedCounter('day', user.id, HIBP_MAX_MISSES_PER_USER_PER_DAY, 20 * 60 * 60_000);

    const res = await postBatch(user, coldPrefixes(3));

    expect(res.status).toBe(429);
    expect(retryAfterOf(res)).toBeGreaterThan(WINDOW_S);
    expect(retryAfterOf(res)).toBeLessThanOrEqual(20 * 60 * 60);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('admits the last fetch of the day and refuses the next', async () => {
    const user = await createTestUser();
    await seedCounter('day', user.id, HIBP_MAX_MISSES_PER_USER_PER_DAY - 1, 60 * 60_000);

    expect((await postSingle(user, 'EEEE1')).status).toBe(200);
    expect((await postSingle(user, 'EEEE2')).status).toBe(429);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe('a refusal belongs to the request whose budget refused it', () => {
  it('a caller that joins a spent caller, for the same cold prefix, still gets its own fetch', async () => {
    const spentId = new mongoose.Types.ObjectId().toString();
    const freshId = new mongoose.Types.ObjectId().toString();
    await seedCounter('window', spentId, HIBP_MAX_MISSES_PER_USER_PER_WINDOW, 10 * 60_000);

    const [spent, fresh] = await Promise.allSettled([
      getRange('FFFF1', breachMissBudgetFor(spentId)),
      getRange('FFFF1', breachMissBudgetFor(freshId)),
    ]);

    expect(spent.status).toBe('rejected');
    expect((spent as PromiseRejectedResult).reason).toBeInstanceOf(BreachMissBudgetError);
    expect(fresh).toEqual({ status: 'fulfilled', value: 'FRESHFFFF1:9' });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(rangeInFlight.size).toBe(0);
  });

  it('three callers for one cold prefix make one fetch, charged to one of them', async () => {
    const ids = Array.from({ length: 3 }, () => new mongoose.Types.ObjectId().toString());
    let release: (range: string) => void = () => undefined;
    fetchMock.mockImplementation(
      () =>
        new Promise<string>((resolve) => {
          release = resolve;
        }),
    );

    const lookups = ids.map((id) => getRange('FFFF2', breachMissBudgetFor(id)));
    await vi.waitFor(() => {
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });
    release('ONE:1');

    expect(await Promise.all(lookups)).toEqual(['ONE:1', 'ONE:1', 'ONE:1']);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(rangeInFlight.size).toBe(0);
    const charged = await Promise.all(ids.map((id) => counterValue('window', id)));
    expect(charged.filter((value) => value === 1)).toHaveLength(1);
  });
});

describe('the budgets are derived, and each one binds', () => {
  it('fits one full cold scan of the largest all-distinct vault in one window', () => {
    // Below this a legitimate scan is refused part-way.
    expect(HIBP_MAX_MISSES_PER_USER_PER_WINDOW).toBeGreaterThanOrEqual(MAX_ITEMS_PER_USER);
  });

  it('binds below what the batch limiter already lets through in the same window', () => {
    // At or above it the request limiter always refuses first and the budget is
    // decoration. The two windows must be the same length for that to hold.
    expect(HIBP_MISS_BUDGET_WINDOW_MINUTES * 60_000).toBe(BREACH_BATCH_RATE_LIMIT_WINDOW_MS);
    expect(HIBP_MAX_MISSES_PER_USER_PER_WINDOW).toBeLessThan(
      BREACH_BATCH_RATE_LIMIT_MAX * HIBP_BATCH_MAX_PREFIXES,
    );
  });

  it('leaves one account unable to replace the whole row cap in one window', () => {
    expect(HIBP_MAX_MISSES_PER_USER_PER_WINDOW).toBeLessThan(HIBP_ONDEMAND_MAX_ROWS);
  });

  it('bounds the day below a window budget spent round the clock, and above one window', () => {
    const windowsPerDay = (24 * 60) / HIBP_MISS_BUDGET_WINDOW_MINUTES;
    expect(HIBP_MAX_MISSES_PER_USER_PER_DAY).toBeGreaterThanOrEqual(
      HIBP_MAX_MISSES_PER_USER_PER_WINDOW,
    );
    expect(HIBP_MAX_MISSES_PER_USER_PER_DAY).toBeLessThan(
      windowsPerDay * HIBP_MAX_MISSES_PER_USER_PER_WINDOW,
    );
  });
});
