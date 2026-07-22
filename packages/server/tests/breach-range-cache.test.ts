import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import axios from 'axios';
import { getRange, rangeInFlight, hibpCache } from '../src/controllers/toolsController.js';
import { PwnedRangeCache } from '../src/models/PwnedRangeCache.js';

const DAY = 86_400_000;

describe('getRange — layered breach range cache (L1 → L2 → L3)', () => {
  beforeEach(() => {
    hibpCache.clear();
    rangeInFlight.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    hibpCache.clear();
    rangeInFlight.clear();
  });

  it('serves a fresh L2 (hibp) entry without any outbound call', async () => {
    await PwnedRangeCache.create({
      prefix: 'AAAAA',
      range: 'X:1',
      source: 'hibp',
      fetchedAt: new Date(),
    });
    const getSpy = vi.spyOn(axios, 'get');

    expect(await getRange('AAAAA')).toBe('X:1');
    expect(getSpy).not.toHaveBeenCalled();

    // Now warm in L1: a second call also avoids DB + network.
    expect(await getRange('AAAAA')).toBe('X:1');
    expect(getSpy).not.toHaveBeenCalled();
  });

  it('canonicalizes a lowercase prefix to the uppercase cache key', async () => {
    await PwnedRangeCache.create({
      prefix: 'ABCDE',
      range: 'Y:2',
      source: 'hibp',
      fetchedAt: new Date(),
    });
    const getSpy = vi.spyOn(axios, 'get');

    expect(await getRange('abcde')).toBe('Y:2');
    expect(getSpy).not.toHaveBeenCalled();
  });

  it('re-fetches a STALE hibp entry and updates the stored range + fetchedAt', async () => {
    await PwnedRangeCache.create({
      prefix: 'BBBBB',
      range: 'OLD:1',
      source: 'hibp',
      fetchedAt: new Date(Date.now() - 40 * DAY),
    });
    const getSpy = vi.spyOn(axios, 'get').mockResolvedValue({ data: 'NEW:2\r\nPAD:0' });

    expect(await getRange('BBBBB')).toBe('NEW:2');
    expect(getSpy).toHaveBeenCalledTimes(1);

    const doc = await PwnedRangeCache.findOne({ prefix: 'BBBBB' }).lean();
    expect(doc?.range).toBe('NEW:2');
    expect(doc?.source).toBe('hibp');
    expect(Date.now() - new Date(doc!.fetchedAt).getTime()).toBeLessThan(5 * DAY);
  });

  it('treats a seed entry as fresh regardless of age (TTL-exempt)', async () => {
    await PwnedRangeCache.create({
      prefix: 'CCCCC',
      range: 'SEED:1',
      source: 'seed',
      fetchedAt: new Date(Date.now() - 400 * DAY),
    });
    const getSpy = vi.spyOn(axios, 'get');

    expect(await getRange('CCCCC')).toBe('SEED:1');
    expect(getSpy).not.toHaveBeenCalled();
  });

  it('fetches from HIBP on a cold miss, stripping padding and persisting the entry', async () => {
    const getSpy = vi.spyOn(axios, 'get').mockResolvedValue({ data: 'HIT:5\r\nPAD:0' });

    expect(await getRange('DDDDD')).toBe('HIT:5');
    expect(getSpy).toHaveBeenCalledTimes(1);

    const doc = await PwnedRangeCache.findOne({ prefix: 'DDDDD' }).lean();
    expect(doc?.range).toBe('HIT:5');
    expect(doc?.source).toBe('hibp');
  });

  it('serves a STALE entry as a fallback when the HIBP fetch fails', async () => {
    await PwnedRangeCache.create({
      prefix: 'EEEEE',
      range: 'STALE:1',
      source: 'hibp',
      fetchedAt: new Date(Date.now() - 40 * DAY),
    });
    vi.spyOn(axios, 'get').mockRejectedValue(new Error('upstream down'));

    // No throw — the monotonic corpus makes a stale positive still valid.
    expect(await getRange('EEEEE')).toBe('STALE:1');
  });

  it('throws when HIBP fails and there is no cached fallback (never a false "safe")', async () => {
    vi.spyOn(axios, 'get').mockRejectedValue(new Error('upstream down'));
    await expect(getRange('FFFFF')).rejects.toThrow('upstream down');
  });

  it('coalesces concurrent duplicate fetches into a single outbound call', async () => {
    const getSpy = vi.spyOn(axios, 'get').mockResolvedValue({ data: 'ONCE:1' });

    const [a, b] = await Promise.all([getRange('12345'), getRange('12345')]);

    expect(a).toBe('ONCE:1');
    expect(b).toBe('ONCE:1');
    expect(getSpy).toHaveBeenCalledTimes(1);
    expect(rangeInFlight.size).toBe(0);
  });
});
