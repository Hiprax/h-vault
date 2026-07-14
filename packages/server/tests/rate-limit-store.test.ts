/**
 * MongoRateLimitStore — the express-rate-limit store that backs every limiter in
 * production.
 *
 * These tests exist because of a bug that shipped precisely for want of them. The
 * limiters are pass-through no-ops unless `isProduction`, so the store was NEVER
 * constructed in development or in any test — the whole ~4,000-test suite was
 * green while the production store was misconfigured, and the first thing that
 * ever exercised it was a real production boot, where it hung every rate-limited
 * request. The store is now driven directly here, against a real MongoDB, so its
 * behaviour is covered independently of NODE_ENV.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import mongoose from 'mongoose';
import { MongoRateLimitStore, RATE_LIMIT_COLLECTION } from '../src/middleware/rateLimitStore.js';
import type { Options } from 'express-rate-limit';

/** express-rate-limit calls `init` with its fully-resolved options object. */
function initOptions(windowMs: number): Options {
  return { windowMs } as Options;
}

function collection() {
  return mongoose.connection.db!.collection(RATE_LIMIT_COLLECTION);
}

describe('MongoRateLimitStore', () => {
  let store: MongoRateLimitStore;

  beforeEach(() => {
    store = new MongoRateLimitStore(60_000);
    store.init(initOptions(60_000));
  });

  describe('increment', () => {
    it('starts a new key at 1 and returns a reset time in the future', async () => {
      const before = Date.now();
      const info = await store.increment('auth:1.2.3.4');

      expect(info.totalHits).toBe(1);
      expect(info.resetTime).toBeInstanceOf(Date);
      expect(info.resetTime!.getTime()).toBeGreaterThan(before);
    });

    it('counts up across calls for the same key', async () => {
      expect((await store.increment('auth:1.2.3.4')).totalHits).toBe(1);
      expect((await store.increment('auth:1.2.3.4')).totalHits).toBe(2);
      expect((await store.increment('auth:1.2.3.4')).totalHits).toBe(3);
    });

    it('keeps the ORIGINAL reset time as the window fills', async () => {
      // The window must be fixed at its start. If each hit pushed the expiry out,
      // a client hammering the endpoint would extend its own lockout forever and
      // never be released — and the Retry-After it is handed would be a lie.
      const first = await store.increment('auth:1.2.3.4');
      const third = await (async () => {
        await store.increment('auth:1.2.3.4');
        return store.increment('auth:1.2.3.4');
      })();

      expect(third.resetTime!.getTime()).toBe(first.resetTime!.getTime());
    });

    it('keeps different keys on entirely separate counters', async () => {
      await store.increment('auth:1.1.1.1');
      await store.increment('auth:1.1.1.1');
      const other = await store.increment('auth:2.2.2.2');

      // Every limiter shares one collection and is isolated only by its key
      // prefix, so a collision here would silently merge two limiters' budgets.
      expect(other.totalHits).toBe(1);
      expect((await store.get('auth:1.1.1.1'))!.totalHits).toBe(2);
    });

    it('isolates limiters that share a client but differ by prefix', async () => {
      await store.increment('auth:1.1.1.1');
      await store.increment('csrf:1.1.1.1');
      await store.increment('csrf:1.1.1.1');

      expect((await store.get('auth:1.1.1.1'))!.totalHits).toBe(1);
      expect((await store.get('csrf:1.1.1.1'))!.totalHits).toBe(2);
    });

    it('does not lose increments when requests race on the same key', async () => {
      // The whole point of doing this as one atomic pipeline update: a
      // read-then-write store would drop hits here, and a limiter that
      // undercounts under load is a limiter that fails open exactly when it
      // matters most.
      const results = await Promise.all(
        Array.from({ length: 25 }, () => store.increment('auth:burst')),
      );

      const seen = results.map((r) => r.totalHits).sort((a, b) => a - b);
      expect(seen).toEqual(Array.from({ length: 25 }, (_, i) => i + 1));
      expect((await store.get('auth:burst'))!.totalHits).toBe(25);
    });

    it('starts a fresh window once the old one has expired', async () => {
      // Expiry is decided by comparing against the server's own $$NOW, so it does
      // not wait on MongoDB's TTL reaper (which only sweeps once a minute). An
      // already-expired record must therefore read as absent immediately.
      //
      // A comfortable window keeps the two in-window increments off a wall-clock
      // deadline (a slow mongodb-memory-server round-trip could exceed a tight
      // 20 ms window and spuriously start a fresh window mid-test), and expiry is
      // then forced DETERMINISTICALLY by backdating expirationDate rather than
      // sleeping — so the test is not timing-dependent at all.
      const expiring = new MongoRateLimitStore(60_000);
      expiring.init(initOptions(60_000));

      expect((await expiring.increment('auth:short')).totalHits).toBe(1);
      expect((await expiring.increment('auth:short')).totalHits).toBe(2);

      // Backdate the stored window so it is already expired against $$NOW. The
      // store compares `$expirationDate > $$NOW`, so a past expirationDate makes
      // the next increment reset the counter to 1 (a fresh window).
      await collection().updateOne(
        { _id: 'auth:short' as unknown as never },
        { $set: { expirationDate: new Date(Date.now() - 60_000) } },
      );

      const afterExpiry = await expiring.increment('auth:short');
      expect(afterExpiry.totalHits).toBe(1);
      expect(afterExpiry.resetTime!.getTime()).toBeGreaterThan(Date.now() - 1);
    });
  });

  describe('get', () => {
    it('returns undefined for a key that was never seen', async () => {
      expect(await store.get('auth:unknown')).toBeUndefined();
    });

    it('treats an expired record as absent even before the TTL reaper runs', async () => {
      await collection().insertOne({
        _id: 'auth:stale' as unknown as never,
        counter: 99,
        expirationDate: new Date(Date.now() - 60_000),
      });

      expect(await store.get('auth:stale')).toBeUndefined();
    });
  });

  describe('decrement', () => {
    it('reduces the counter within the live window', async () => {
      await store.increment('auth:1.2.3.4');
      await store.increment('auth:1.2.3.4');
      await store.decrement('auth:1.2.3.4');

      expect((await store.get('auth:1.2.3.4'))!.totalHits).toBe(1);
    });

    it('leaves an expired record alone rather than resurrecting it', async () => {
      await collection().insertOne({
        _id: 'auth:stale' as unknown as never,
        counter: 5,
        expirationDate: new Date(Date.now() - 60_000),
      });

      await store.decrement('auth:stale');

      const raw = await collection().findOne({ _id: 'auth:stale' as unknown as never });
      expect(raw?.['counter']).toBe(5);
      // ...and the next hit still opens a clean window rather than continuing it.
      expect((await store.increment('auth:stale')).totalHits).toBe(1);
    });

    it('is a no-op for a key that does not exist', async () => {
      await expect(store.decrement('auth:nobody')).resolves.toBeUndefined();
      expect(await store.get('auth:nobody')).toBeUndefined();
    });
  });

  describe('resetKey / resetAll', () => {
    it('resetKey clears one key and leaves the others intact', async () => {
      await store.increment('auth:a');
      await store.increment('auth:b');

      await store.resetKey('auth:a');

      expect(await store.get('auth:a')).toBeUndefined();
      expect((await store.get('auth:b'))!.totalHits).toBe(1);
    });

    it('resetAll clears every counter', async () => {
      await store.increment('auth:a');
      await store.increment('csrf:b');

      await store.resetAll();

      expect(await store.get('auth:a')).toBeUndefined();
      expect(await store.get('csrf:b')).toBeUndefined();
    });
  });

  describe('TTL index', () => {
    it('creates the expiry index on first use, so records are reaped', async () => {
      // Production runs Mongoose with autoIndex disabled and this is a raw
      // collection, not a model, so the create-indexes bootstrap does not cover
      // it. Nothing else will build this index if the store does not.
      await store.increment('auth:1.2.3.4');

      const indexes = await collection().indexes();
      const ttl = indexes.find((index) => index.key['expirationDate'] === 1);

      expect(ttl).toBeDefined();
      expect(ttl?.expireAfterSeconds).toBe(0);
    });
  });

  describe('window length', () => {
    it('honours the windowMs express-rate-limit supplies via init()', async () => {
      const store15m = new MongoRateLimitStore(1_000);
      store15m.init(initOptions(15 * 60 * 1000));

      const info = await store15m.increment('auth:1.2.3.4');
      const windowMs = info.resetTime!.getTime() - Date.now();

      // init() must win over the constructor seed, or every limiter would silently
      // run on whatever window the first one happened to be built with — so the
      // window must read ~15 min, never the 1 s seed. resetTime is `$$NOW + windowMs`
      // computed on MongoDB's clock (see MongoRateLimitStore.increment), which can
      // sit a few ms ahead of the Node clock this line subtracts; the upper bound
      // therefore carries a margin rather than an exact 15-min ceiling. The 1 s seed
      // would land ~1000 ms — far below 14 min regardless — so the pair still fails
      // if init() were ignored.
      expect(windowMs).toBeGreaterThan(14 * 60 * 1000);
      expect(windowMs).toBeLessThan(16 * 60 * 1000);
    });
  });
});
