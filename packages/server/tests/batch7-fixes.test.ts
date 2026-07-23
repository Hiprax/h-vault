/**
 * Tests for Batch 7 fixes:
 *
 * - MEDIUM-4: HIBP breach check rate limiter, SSRF hardening (maxRedirects: 0), in-memory cache
 * - MEDIUM-5: SMTP transporter verification on first sendEmail call
 * - MEDIUM-6: MAX_RESTORE_ITEMS aligned with MAX_IMPORT_ITEMS shared constant
 * - MEDIUM-11: Differentiated email error messages (transporter_not_configured vs smtp_send_failed)
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import request from 'supertest';
import axios from 'axios';
import app from '../src/app.js';
import {
  HIBP_CACHE_MAX_ENTRIES,
  hibpCache,
  pruneHibpCache,
  resetCacheAccessCount,
  setHibpCacheEntry,
  getHibpCacheBytes,
  getHibpCacheMaxBytes,
  __setHibpCacheMaxBytes,
} from '../src/controllers/toolsController.js';
import { MAX_IMPORT_ITEMS } from '@hvault/shared';
import { createTestUser, authHeader, getCsrf as getCsrfBase } from './helpers.js';

async function getCsrf(
  agent: request.SuperTest<request.Test>,
): Promise<{ csrfToken: string; csrfCookie: string }> {
  const { token, cookie } = await getCsrfBase(agent);
  return { csrfToken: token, csrfCookie: cookie };
}

// ---------------------------------------------------------------------------
// MEDIUM-4: HIBP cache unit tests
// ---------------------------------------------------------------------------
describe('MEDIUM-4: HIBP in-memory cache', () => {
  beforeEach(() => {
    hibpCache.clear();
  });

  it('should export hibpCache as a Map', () => {
    expect(hibpCache).toBeInstanceOf(Map);
  });

  it('should store and retrieve cache entries', () => {
    hibpCache.set('5BAA6', {
      data: 'cached-response-data',
      expires: Date.now() + 60 * 60 * 1000,
    });

    const cached = hibpCache.get('5BAA6');
    expect(cached).toBeDefined();
    expect(cached!.data).toBe('cached-response-data');
    expect(cached!.expires).toBeGreaterThan(Date.now());
  });

  it('treats an expired cache entry as a miss: the controller does NOT serve stale data', async () => {
    const agent = request(app) as unknown as request.SuperTest<request.Test>;
    const user = await createTestUser();

    // Seed an already-expired entry for the prefix the request will use.
    // Uses a valid SUFFIX:COUNT range line (the only shape HIBP ever returns).
    hibpCache.set('5BAA6', {
      data: 'STALESUFFIXAAAAAAAAAAAAAAAAAAAAAAA:1',
      expires: Date.now() - 1000,
    });

    // The controller must fall through to HIBP on an expired hit; stub the
    // upstream fetch so no real network call happens and its value is distinct.
    const getSpy = vi
      .spyOn(axios, 'get')
      .mockResolvedValue({ data: 'FRESHSUFFIXBBBBBBBBBBBBBBBBBBBBBBB:5' } as never);

    try {
      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/tools/check-password-breach')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ hashPrefix: '5BAA6' });

      expect(res.status).toBe(200);
      // The stale value must NOT be returned — the freshly fetched one is.
      expect(res.body.data).toBe('FRESHSUFFIXBBBBBBBBBBBBBBBBBBBBBBB:5');
      expect(res.body.data).not.toBe('STALESUFFIXAAAAAAAAAAAAAAAAAAAAAAA:1');
      // The upstream was actually consulted (proving the expired entry was a miss).
      expect(getSpy).toHaveBeenCalledTimes(1);
      // The cache was refreshed with the new value.
      expect(hibpCache.get('5BAA6')?.data).toBe('FRESHSUFFIXBBBBBBBBBBBBBBBBBBBBBBB:5');
    } finally {
      getSpy.mockRestore();
    }
  });

  it('should return cached data on breach check when cache is warm', async () => {
    const agent = request(app) as unknown as request.SuperTest<request.Test>;
    const user = await createTestUser();

    // Seed the cache with a known value
    hibpCache.set('AAAAA', {
      data: 'cached-breach-data-from-hibp',
      expires: Date.now() + 60 * 60 * 1000,
    });

    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const res = await agent
      .post('/api/v1/tools/check-password-breach')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrfToken)
      .set('Cookie', csrfCookie)
      .send({ hashPrefix: 'AAAAA' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data).toBe('cached-breach-data-from-hibp');
  });

  afterEach(() => {
    hibpCache.clear();
  });
});

// ---------------------------------------------------------------------------
// MEDIUM-4: breachCheckLimiter export
// ---------------------------------------------------------------------------
describe('MEDIUM-4: breachCheckLimiter export', () => {
  it('should export breachCheckLimiter from rateLimiter', async () => {
    const { breachCheckLimiter } = await import('../src/middleware/rateLimiter.js');
    expect(breachCheckLimiter).toBeDefined();
    expect(typeof breachCheckLimiter).toBe('function');
  });
});

// ---------------------------------------------------------------------------
// MEDIUM-6: MAX_RESTORE_ITEMS aligned with MAX_IMPORT_ITEMS
// ---------------------------------------------------------------------------
describe('MEDIUM-6: restore uses MAX_IMPORT_ITEMS from shared', () => {
  it('MAX_IMPORT_ITEMS should be 10,000', () => {
    expect(MAX_IMPORT_ITEMS).toBe(10_000);
  });

  // NOTE: a former source-text test here (`source.not.toContain('const
  // MAX_RESTORE_ITEMS')`) was removed — it coupled to an implementation detail
  // (a renamed local variable would defeat it while an innocuous comment would
  // fail it) and merely duplicated the behavioural 400-on-overflow assertion
  // below, which exercises the real restore cap end to end.

  it('should reject restore when total entries exceed MAX_IMPORT_ITEMS', async () => {
    const agent = request(app) as unknown as request.SuperTest<request.Test>;
    const user = await createTestUser();
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    // Build a massive items array that exceeds 10,000
    const items = Array.from({ length: 10_001 }, (_, i) => ({
      itemType: 'login',
      encryptedData: `data-${String(i)}`,
      dataIv: 'iv',
      dataTag: 'tag',
      encryptedName: `name-${String(i)}`,
      nameIv: 'niv',
      nameTag: 'ntag',
    }));

    const res = await agent
      .post('/api/v1/backup/restore')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrfToken)
      .set('Cookie', csrfCookie)
      .send({
        conflictStrategy: 'skip',
        data: JSON.stringify({ items, folders: [] }),
      });

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.message).toContain(String(MAX_IMPORT_ITEMS));
  });
});

// NOTE: The former "MEDIUM-5 & MEDIUM-11: email error differentiation
// integration" block was removed. Despite its name it asserted only 201 +
// success and never observed the differentiated error strings — the actual
// 'transporter_not_configured' vs 'smtp_send_failed' contract is covered by
// email.test.ts, and the anti-enumeration register-on-existing-email behaviour
// it duplicated is covered by auth.test.ts.

// ---------------------------------------------------------------------------
// HIBP cache pruning
// ---------------------------------------------------------------------------
describe('HIBP cache pruning', () => {
  beforeEach(() => {
    hibpCache.clear();
    resetCacheAccessCount();
  });

  afterEach(() => {
    hibpCache.clear();
    resetCacheAccessCount();
  });

  it('should not prune before 100 accesses', () => {
    hibpCache.set('AAAAA', { data: 'stale', expires: Date.now() - 1000 });

    // Call 99 times — pruning should NOT trigger
    for (let i = 0; i < 99; i++) {
      pruneHibpCache();
    }

    expect(hibpCache.has('AAAAA')).toBe(true);
  });

  it('should prune expired entries on the 100th access', () => {
    hibpCache.set('AAAAA', { data: 'stale', expires: Date.now() - 1000 });
    hibpCache.set('BBBBB', { data: 'fresh', expires: Date.now() + 60_000 });

    // Call 100 times — pruning triggers on the 100th
    for (let i = 0; i < 100; i++) {
      pruneHibpCache();
    }

    expect(hibpCache.has('AAAAA')).toBe(false);
    expect(hibpCache.has('BBBBB')).toBe(true);
  });

  it('should keep all entries when none are expired', () => {
    hibpCache.set('AAAAA', { data: 'a', expires: Date.now() + 60_000 });
    hibpCache.set('BBBBB', { data: 'b', expires: Date.now() + 60_000 });

    for (let i = 0; i < 100; i++) {
      pruneHibpCache();
    }

    expect(hibpCache.size).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// Task 2.2: HIBP cache hard cap (memory exhaustion guard)
// ---------------------------------------------------------------------------
describe('Task 2.2: HIBP cache LRU bound', () => {
  beforeEach(() => {
    hibpCache.clear();
    resetCacheAccessCount();
  });

  afterEach(() => {
    hibpCache.clear();
    resetCacheAccessCount();
  });

  it('exposes HIBP_CACHE_MAX_ENTRIES at 10,000', () => {
    expect(HIBP_CACHE_MAX_ENTRIES).toBe(10_000);
  });

  it('caps cache size at HIBP_CACHE_MAX_ENTRIES under sustained insert pressure', () => {
    const future = Date.now() + 60 * 60 * 1000;
    // Insert significantly more entries than the cap so eviction must kick in.
    const overshoot = HIBP_CACHE_MAX_ENTRIES + 5_000;
    for (let i = 0; i < overshoot; i++) {
      // Pad to 5 hex chars so each prefix is unique. Using i.toString(16) keeps
      // the data shape realistic without requiring real HIBP responses.
      const prefix = i.toString(16).padStart(5, '0').slice(0, 5);
      // Append a uniqueness suffix when prefixes collide at the 5-char window.
      // Prefixes need not match HIBP's exact format — the cache treats them as
      // opaque keys.
      const key = `${prefix}-${String(i)}`;
      setHibpCacheEntry(key, { data: `data-${String(i)}`, expires: future });
    }
    expect(hibpCache.size).toBeLessThanOrEqual(HIBP_CACHE_MAX_ENTRIES);
  });

  it('prefers evicting expired entries over fresh ones when full', () => {
    const past = Date.now() - 1_000;
    const future = Date.now() + 60 * 60 * 1000;

    // Fill the cache: first half expired, second half fresh.
    const halfCap = Math.floor(HIBP_CACHE_MAX_ENTRIES / 2);
    for (let i = 0; i < halfCap; i++) {
      hibpCache.set(`expired-${String(i)}`, { data: 'x', expires: past });
    }
    for (let i = 0; i < HIBP_CACHE_MAX_ENTRIES - halfCap; i++) {
      hibpCache.set(`fresh-${String(i)}`, { data: 'y', expires: future });
    }
    expect(hibpCache.size).toBe(HIBP_CACHE_MAX_ENTRIES);

    // Insert one more — an expired entry should be sacrificed first.
    setHibpCacheEntry('newcomer', { data: 'z', expires: future });
    expect(hibpCache.size).toBe(HIBP_CACHE_MAX_ENTRIES);
    expect(hibpCache.get('newcomer')?.data).toBe('z');

    // The fresh entries should all still be present.
    for (let i = 0; i < HIBP_CACHE_MAX_ENTRIES - halfCap; i++) {
      expect(hibpCache.has(`fresh-${String(i)}`)).toBe(true);
    }
    // At least one expired entry should have been dropped to make room.
    let remainingExpired = 0;
    for (let i = 0; i < halfCap; i++) {
      if (hibpCache.has(`expired-${String(i)}`)) remainingExpired++;
    }
    expect(remainingExpired).toBeLessThan(halfCap);
  });

  it('falls back to oldest-insertion eviction when no expired entries are available', () => {
    const future = Date.now() + 60 * 60 * 1000;

    // Fill the cache entirely with fresh entries in known insertion order.
    for (let i = 0; i < HIBP_CACHE_MAX_ENTRIES; i++) {
      hibpCache.set(`fresh-${String(i)}`, { data: 'y', expires: future });
    }
    expect(hibpCache.size).toBe(HIBP_CACHE_MAX_ENTRIES);

    setHibpCacheEntry('newcomer', { data: 'z', expires: future });

    expect(hibpCache.size).toBe(HIBP_CACHE_MAX_ENTRIES);
    expect(hibpCache.has('newcomer')).toBe(true);
    // The oldest-inserted entry should have been the one to make way.
    expect(hibpCache.has('fresh-0')).toBe(false);
    expect(hibpCache.has(`fresh-${String(HIBP_CACHE_MAX_ENTRIES - 1)}`)).toBe(true);
  });

  it('updates an existing entry without triggering eviction', () => {
    const future = Date.now() + 60 * 60 * 1000;

    // Fill the cache.
    for (let i = 0; i < HIBP_CACHE_MAX_ENTRIES; i++) {
      hibpCache.set(`k-${String(i)}`, { data: 'x', expires: future });
    }
    expect(hibpCache.size).toBe(HIBP_CACHE_MAX_ENTRIES);

    // Re-set an existing key with a new value — no entry should be evicted.
    setHibpCacheEntry('k-5', { data: 'updated', expires: future });
    expect(hibpCache.size).toBe(HIBP_CACHE_MAX_ENTRIES);
    expect(hibpCache.get('k-5')?.data).toBe('updated');
    // None of the other keys should have been evicted.
    expect(hibpCache.has('k-0')).toBe(true);
    expect(hibpCache.has(`k-${String(HIBP_CACHE_MAX_ENTRIES - 1)}`)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Task 1.1 (0.5.0): HIBP cache BYTE budget (HIBP_CACHE_MAX_BYTES)
// ---------------------------------------------------------------------------
describe('Task 1.1: HIBP cache byte budget', () => {
  const originalMaxBytes = getHibpCacheMaxBytes();

  beforeEach(() => {
    hibpCache.clear();
    resetCacheAccessCount();
  });

  afterEach(() => {
    hibpCache.clear();
    resetCacheAccessCount();
    __setHibpCacheMaxBytes(originalMaxBytes);
  });

  it('exposes a positive default byte budget from config', () => {
    // The default is 64 MiB; the exact number lives in config, but it must be a
    // meaningful multi-MiB ceiling, not zero or unset.
    expect(getHibpCacheMaxBytes()).toBeGreaterThanOrEqual(1_048_576);
  });

  it('tracks the byte total as measured UTF-8 bytes, not entry count', () => {
    const future = Date.now() + 60_000;
    setHibpCacheEntry('AAAAA', { data: 'hello', expires: future });
    expect(getHibpCacheBytes()).toBe(Buffer.byteLength('hello', 'utf8'));
    // A multi-byte character is counted by bytes, not code units (€ is 3 UTF-8 bytes).
    setHibpCacheEntry('BBBBB', { data: '€', expires: future });
    expect(getHibpCacheBytes()).toBe(5 + Buffer.byteLength('€', 'utf8'));
  });

  it('adjusts the total by the DELTA on update-in-place (never double-counts)', () => {
    const future = Date.now() + 60_000;
    setHibpCacheEntry('AAAAA', { data: 'short', expires: future });
    expect(getHibpCacheBytes()).toBe(5);
    setHibpCacheEntry('AAAAA', { data: 'a much longer value', expires: future });
    expect(hibpCache.size).toBe(1);
    expect(getHibpCacheBytes()).toBe(Buffer.byteLength('a much longer value', 'utf8'));
  });

  it('evicts by byte budget so the total stays at or below HIBP_CACHE_MAX_BYTES', () => {
    // Shrink the budget so a handful of ~36 KB ranges crosses it cheaply. All
    // inserts share one backing string, so this allocates ~36 KB, not ~100 MB.
    __setHibpCacheMaxBytes(100 * 1024); // 100 KiB
    const range = 'x'.repeat(36 * 1024); // a realistic ~36 KB range
    const future = Date.now() + 60_000;
    for (let i = 0; i < 3_000; i++) {
      setHibpCacheEntry(`k${String(i)}`, { data: range, expires: future });
    }
    expect(getHibpCacheBytes()).toBeLessThanOrEqual(100 * 1024);
    // Byte pressure — not the 10,000 entry cap — is what bounded the Map here.
    expect(hibpCache.size).toBeLessThan(3_000);
    expect(hibpCache.size).toBeLessThanOrEqual(HIBP_CACHE_MAX_ENTRIES);
  });

  it('keeps a single entry that alone exceeds the budget (over by exactly it)', () => {
    __setHibpCacheMaxBytes(1024); // 1 KiB budget
    const big = 'y'.repeat(4096); // 4 KiB — larger than the whole budget
    setHibpCacheEntry('BIG', { data: big, expires: Date.now() + 60_000 });
    // Never evicts below one entry: it is stored, leaving the total over budget.
    expect(hibpCache.size).toBe(1);
    expect(hibpCache.get('BIG')?.data).toBe(big);
    expect(getHibpCacheBytes()).toBe(4096);
    expect(getHibpCacheBytes()).toBeGreaterThan(getHibpCacheMaxBytes());
  });

  it('keeps the byte total consistent after pruneHibpCache reaps expired entries', () => {
    setHibpCacheEntry('EXPIRED', { data: 'z'.repeat(1000), expires: Date.now() - 1 });
    setHibpCacheEntry('LIVE', { data: 'z'.repeat(500), expires: Date.now() + 60_000 });
    expect(getHibpCacheBytes()).toBe(1500);
    // The 100th access triggers the sweep, which must subtract the expired bytes.
    for (let i = 0; i < 100; i++) pruneHibpCache();
    expect(hibpCache.has('EXPIRED')).toBe(false);
    expect(getHibpCacheBytes()).toBe(500);
  });

  it('resetCacheAccessCount zeroes the byte total', () => {
    setHibpCacheEntry('AAAAA', { data: 'data', expires: Date.now() + 60_000 });
    expect(getHibpCacheBytes()).toBeGreaterThan(0);
    resetCacheAccessCount();
    expect(getHibpCacheBytes()).toBe(0);
  });

  it('self-heals the byte total to zero after an external hibpCache.clear()', () => {
    setHibpCacheEntry('AAAAA', { data: 'x'.repeat(1000), expires: Date.now() + 60_000 });
    // A direct clear bypasses this module and desyncs the running total...
    hibpCache.clear();
    // ...but the next insert observes the empty Map and resets it, so the total
    // reflects only the new entry rather than 1000 + 2.
    setHibpCacheEntry('BBBBB', { data: 'yy', expires: Date.now() + 60_000 });
    expect(getHibpCacheBytes()).toBe(2);
  });

  it('keeps HIBP_CACHE_MAX_ENTRIES at 10,000 as the secondary guard', () => {
    expect(HIBP_CACHE_MAX_ENTRIES).toBe(10_000);
  });
});
