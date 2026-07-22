import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import axios from 'axios';
import { seedBreachCorpus, toPrefixHex } from '../src/utils/breachSeed.js';
import { PwnedRangeCache } from '../src/models/PwnedRangeCache.js';

/** Resolve every prefix to a canned body unless a per-url override is given. */
function mockHibp(bodyFor: (prefix: string) => string | Promise<never>) {
  return vi.spyOn(axios, 'get').mockImplementation((url: string) => {
    const prefix = url.split('/range/')[1] ?? '';
    const body = bodyFor(prefix);
    return body instanceof Promise ? body : Promise.resolve({ data: body });
  });
}

describe('seedBreachCorpus', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('imports a range of prefixes as source:"seed" with padding stripped', async () => {
    mockHibp(() => 'GOOD:3\r\nPAD:0');
    const res = await seedBreachCorpus({
      fromPrefix: 0,
      toPrefix: 3,
      concurrency: 1,
      retries: 0,
    });

    expect(res.fetched).toBe(4);
    expect(res.skipped).toBe(0);
    expect(res.failed).toEqual([]);

    const doc = await PwnedRangeCache.findOne({ prefix: '00000' }).lean();
    expect(doc?.range).toBe('GOOD:3');
    expect(doc?.source).toBe('seed');
    expect(await PwnedRangeCache.estimatedDocumentCount()).toBe(4);
  });

  it('is idempotent: a second run skips everything already present', async () => {
    mockHibp(() => 'S:1');
    const first = await seedBreachCorpus({
      fromPrefix: 0,
      toPrefix: 3,
      concurrency: 1,
      retries: 0,
    });
    expect(first.fetched).toBe(4);

    const second = await seedBreachCorpus({
      fromPrefix: 0,
      toPrefix: 3,
      concurrency: 1,
      retries: 0,
    });
    expect(second.fetched).toBe(0);
    expect(second.skipped).toBe(4);
  });

  it('resumes: only missing prefixes are fetched', async () => {
    await PwnedRangeCache.create([
      { prefix: '00000', range: 'A:1', source: 'seed', fetchedAt: new Date() },
      { prefix: '00002', range: 'C:1', source: 'seed', fetchedAt: new Date() },
    ]);
    const getSpy = mockHibp(() => 'NEW:1');

    const res = await seedBreachCorpus({ fromPrefix: 0, toPrefix: 3, concurrency: 1, retries: 0 });

    expect(res.fetched).toBe(2); // 00001 and 00003
    expect(res.skipped).toBe(2);
    expect(getSpy).toHaveBeenCalledTimes(2);
  });

  it('--force re-fetches even fresh entries', async () => {
    await PwnedRangeCache.create(
      Array.from({ length: 4 }, (_v, i) => ({
        prefix: toPrefixHex(i),
        range: 'OLD:1',
        source: 'seed' as const,
        fetchedAt: new Date(),
      })),
    );
    mockHibp(() => 'FRESH:2');

    const res = await seedBreachCorpus({
      fromPrefix: 0,
      toPrefix: 3,
      concurrency: 1,
      retries: 0,
      force: true,
    });

    expect(res.fetched).toBe(4);
    expect(res.skipped).toBe(0);
    const doc = await PwnedRangeCache.findOne({ prefix: '00001' }).lean();
    expect(doc?.range).toBe('FRESH:2');
  });

  it('records a persistently failing prefix in failed[] without aborting the run', async () => {
    mockHibp((prefix) => (prefix === '00002' ? Promise.reject(new Error('upstream 500')) : 'OK:1'));

    const res = await seedBreachCorpus({ fromPrefix: 0, toPrefix: 3, concurrency: 1, retries: 0 });

    expect(res.fetched).toBe(3);
    expect(res.failed).toEqual(['00002']);
    expect(await PwnedRangeCache.findOne({ prefix: '00002' }).lean()).toBeNull();
  });

  it('flushes upserts in batches of the configured size', async () => {
    const bulkSpy = vi.spyOn(PwnedRangeCache, 'bulkWrite');
    mockHibp(() => 'S:1');

    await seedBreachCorpus({
      fromPrefix: 0,
      toPrefix: 4, // 5 prefixes
      concurrency: 1,
      retries: 0,
      batchSize: 2,
    });

    // 5 items, batch size 2 → flushes at 2 and 4, plus a final flush for the 5th.
    expect(bulkSpy.mock.calls.length).toBeGreaterThanOrEqual(2);
    expect(await PwnedRangeCache.estimatedDocumentCount()).toBe(5);
  });

  it('reports progress periodically over a large range', async () => {
    mockHibp(() => 'S:1');
    const onProgress = vi.fn();

    const res = await seedBreachCorpus({
      fromPrefix: 0,
      toPrefix: 999, // 1000 prefixes → crosses the periodic-progress threshold
      concurrency: 16,
      retries: 0,
      onProgress,
    });

    expect(res.fetched).toBe(1000);
    expect(onProgress).toHaveBeenCalled();
    expect(onProgress).toHaveBeenCalledWith(1000, 1000, 0);
  });

  it('stops early when already aborted, fetching nothing', async () => {
    const getSpy = mockHibp(() => 'S:1');
    const res = await seedBreachCorpus({
      fromPrefix: 0,
      toPrefix: 3,
      concurrency: 1,
      retries: 0,
      signal: { aborted: true },
    });

    expect(res.aborted).toBe(true);
    expect(res.fetched).toBe(0);
    expect(getSpy).not.toHaveBeenCalled();
  });

  it('aborts mid-flight during a retry backoff', async () => {
    const signal = { aborted: false };
    // Reject and flip the abort flag on the first call so the retry loop observes
    // the abort on its next attempt and returns null → the worker records the abort.
    vi.spyOn(axios, 'get').mockImplementation(() => {
      signal.aborted = true;
      return Promise.reject(new Error('boom'));
    });

    const res = await seedBreachCorpus({
      fromPrefix: 0,
      toPrefix: 3,
      concurrency: 1,
      retries: 1,
      retryDelayMs: 0,
      signal,
    });

    expect(res.aborted).toBe(true);
    expect(res.failed).toEqual([]);
  });
});
