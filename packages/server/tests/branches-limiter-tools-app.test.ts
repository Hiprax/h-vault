/**
 * Error/edge branches of `middleware/rateLimiter.ts`, `controllers/toolsController.ts`
 * and `app.ts` that the rest of the suite never reaches.
 *
 * Three production behaviours only exist when the module graph is in PRODUCTION
 * mode or when optional config is present, so this file forces both, once, at
 * the top of its (file-scoped) module graph:
 *
 *  • `isProduction: true` — every limiter in `rateLimiter.ts` is a pass-through
 *    no-op otherwise, so the real key generators (including the userId-keyed
 *    limiters' fallback to the client IP for an UNAUTHENTICATED request, and
 *    `buildRefreshKey`'s missing-User-Agent path) are never executed. The real
 *    limiters here run on the real {@link MongoRateLimitStore} over the
 *    in-memory MongoDB the harness already owns; `setup.ts` wipes every
 *    collection after each test, so the counters reset between tests.
 *  • `TRUST_PROXY` — `app.ts` only calls `app.set('trust proxy', …)` when it is
 *    configured, and that switch is what makes `req.ip` (audit logs, IP-keyed
 *    rate limits) follow `X-Forwarded-For` behind Nginx.
 *  • `METRICS_TOKEN` — `/api/v1/metrics` is only mounted when it is set.
 *
 * `vi.mock` (hoisted, evaluated once) rather than `vi.resetModules()` +
 * `vi.doMock`: resetting the registry re-evaluates `models/*.ts` against the
 * mongoose singleton — which is externalised and NOT reset — and mongoose throws
 * `OverwriteModelError` on the second `mongoose.model('User')`.
 *
 * Everything asserted below is observable behaviour: HTTP status, response body,
 * the persisted VaultItem rows, the audit-log row, and the rate-limit counter
 * documents the limiters actually wrote.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import express from 'express';
import type { Request, Response, NextFunction, RequestHandler } from 'express';
import cookieParser from 'cookie-parser';
import request from 'supertest';
import mongoose from 'mongoose';

const { TEST_METRICS_TOKEN } = vi.hoisted(() => ({
  TEST_METRICS_TOKEN: 'metrics-token-for-branch-tests-0123456789',
}));

vi.mock('../src/config/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/config/index.js')>();
  return {
    ...actual,
    isProduction: true,
    config: { ...actual.config, TRUST_PROXY: 1, METRICS_TOKEN: TEST_METRICS_TOKEN },
  };
});

// Static imports: the `vi.mock` above is hoisted, so these already resolve
// against the production-mode config. (They must be static rather than a
// top-level dynamic `await import()` — a dynamically-imported module inside a
// mocked graph is attributed to a separate V8 coverage entry and the merge then
// drops the file from the package report entirely.)
import app from '../src/app.js';
import {
  breachCheckLimiter,
  generalAuthLimiter,
  passwordVerifyLimiter,
  refreshLimiter,
} from '../src/middleware/rateLimiter.js';
import { RATE_LIMIT_COLLECTION } from '../src/middleware/rateLimitStore.js';
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
import { AuditLog } from '../src/models/AuditLog.js';
import { VaultItem } from '../src/models/VaultItem.js';
import {
  authHeader,
  createTestUser,
  getCsrf,
  sampleVaultItem,
  seedItem,
  type TestUser,
} from './helpers.js';

type Agent = request.SuperTest<request.Test>;

async function post(
  agent: Agent,
  url: string,
  token: string,
  body: unknown,
  headers: Record<string, string> = {},
): Promise<request.Response> {
  const { token: csrfToken, cookie } = await getCsrf(agent);
  const req = agent
    .post(url)
    .set('Authorization', authHeader(token))
    .set('x-csrf-token', csrfToken)
    .set('Cookie', cookie);
  for (const [key, value] of Object.entries(headers)) {
    req.set(key, value);
  }
  return req.send(body as object);
}

async function put(
  agent: Agent,
  url: string,
  token: string,
  body: unknown,
): Promise<request.Response> {
  const { token: csrfToken, cookie } = await getCsrf(agent);
  return agent
    .put(url)
    .set('Authorization', authHeader(token))
    .set('x-csrf-token', csrfToken)
    .set('Cookie', cookie)
    .send(body as object);
}

/** Every rate-limit counter document the limiters actually persisted. */
async function rateLimitDocs(): Promise<{ key: string; counter: number }[]> {
  const docs = await mongoose.connection.db!.collection(RATE_LIMIT_COLLECTION).find({}).toArray();
  return docs
    .map((doc) => ({ key: String(doc._id), counter: doc['counter'] as number }))
    .sort((a, b) => a.key.localeCompare(b.key));
}

/** A minimal app mounting the REAL exported limiter with NO authenticated user. */
function anonymousLimiterApp(limiter: RequestHandler): express.Express {
  const app = express();
  app.set('trust proxy', 1);
  app.use(cookieParser());
  app.use(limiter);
  app.get('/t', (_req: Request, res: Response) => {
    res.json({ ok: true });
  });
  app.post('/t', (_req: Request, res: Response) => {
    res.json({ ok: true });
  });
  app.use(
    (
      err: { statusCode?: number; status?: number; message?: string },
      _req: Request,
      res: Response,
      _next: NextFunction,
    ) => {
      res.status(err.statusCode ?? err.status ?? 500).json({ message: err.message });
    },
  );
  return app;
}

describe('branches: rateLimiter / toolsController / app.ts', () => {
  let agent: Agent;
  let user: TestUser;

  beforeEach(async () => {
    agent = request(app) as unknown as Agent;
    user = await createTestUser();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ── rateLimiter.ts ────────────────────────────────────────────────────

  describe('userId-keyed limiters: an UNAUTHENTICATED request falls back to the client IP', () => {
    // `keyGenerator: req.user?._id ?? resolveClientKey(req) ?? ''`. These
    // limiters sit behind `authenticate` on their routes, but express-rate-limit
    // evaluates the key generator for whatever reaches it. Without the
    // `resolveClientKey` fallback every anonymous request keys on the bare
    // prefix (`pwverify:`), so ONE client could drain the 5-request budget for
    // every other anonymous caller. Two distinct source IPs must therefore
    // produce two distinct counters.
    const cases: { name: string; limiter: RequestHandler; prefix: string }[] = [
      {
        name: 'passwordVerifyLimiter',
        limiter: passwordVerifyLimiter as RequestHandler,
        prefix: 'pwverify:',
      },
      {
        name: 'breachCheckLimiter',
        limiter: breachCheckLimiter as RequestHandler,
        prefix: 'breach:',
      },
      {
        name: 'generalAuthLimiter',
        limiter: generalAuthLimiter as RequestHandler,
        prefix: 'general:',
      },
    ];

    for (const testCase of cases) {
      it(`${testCase.name}: two anonymous clients get two separate "${testCase.prefix}<ip>" buckets`, async () => {
        const limiterApp = anonymousLimiterApp(testCase.limiter);

        expect(
          (await request(limiterApp).get('/t').set('x-forwarded-for', '203.0.113.11')).status,
        ).toBe(200);
        expect(
          (await request(limiterApp).get('/t').set('x-forwarded-for', '203.0.113.11')).status,
        ).toBe(200);
        expect(
          (await request(limiterApp).get('/t').set('x-forwarded-for', '203.0.113.12')).status,
        ).toBe(200);

        // Collapsing to a single shared bucket (the regression) would show up
        // here as ONE document with counter 3.
        expect(await rateLimitDocs()).toEqual([
          { key: `${testCase.prefix}203.0.113.11`, counter: 2 },
          { key: `${testCase.prefix}203.0.113.12`, counter: 1 },
        ]);
      });
    }

    it('passwordVerifyLimiter still 429s the anonymous IP at its 5-request budget', async () => {
      const limiterApp = anonymousLimiterApp(passwordVerifyLimiter as RequestHandler);

      for (let i = 0; i < 5; i++) {
        expect(
          (await request(limiterApp).get('/t').set('x-forwarded-for', '203.0.113.13')).status,
        ).toBe(200);
      }
      const blocked = await request(limiterApp).get('/t').set('x-forwarded-for', '203.0.113.13');

      expect(blocked.status).toBe(429);
      expect((blocked.body as { message: string }).message).toBe(
        'Too many password verification attempts, please try again later',
      );
    });
  });

  describe('refreshLimiter: a client that sends NO User-Agent header', () => {
    it('is still bucketed by IP and limited at 5 — it does not error out', async () => {
      // `buildRefreshKey` reads `req.headers['user-agent'] ?? ''` before hashing
      // it. Drop the `?? ''` and a UA-less client (a raw HTTP client, curl with
      // an unset UA) crashes the limiter with a TypeError on `ua.length` — a 500
      // on the refresh endpoint, i.e. no limit and no refresh.
      const limiterApp = anonymousLimiterApp(refreshLimiter as RequestHandler);

      const send = (ip: string) =>
        request(limiterApp).post('/t').unset('User-Agent').set('x-forwarded-for', ip);

      for (let i = 0; i < 5; i++) {
        expect((await send('203.0.113.21')).status).toBe(200);
      }
      const blocked = await send('203.0.113.21');
      expect(blocked.status).toBe(429);
      expect((blocked.body as { message: string }).message).toBe(
        'Too many token refresh attempts, please try again later',
      );

      // A second UA-less client on a different IP keeps its own budget.
      expect((await send('203.0.113.22')).status).toBe(200);

      const docs = await rateLimitDocs();
      expect(docs).toHaveLength(2);
      // IP + UA-hash only (no refresh cookie was sent) — and the IP segment is
      // the real client, not a shared bucket.
      expect(docs[0]!.key.startsWith('refresh:203.0.113.21:')).toBe(true);
      expect(docs[0]!.key.split(':')).toHaveLength(3);
      expect(docs[0]!.counter).toBe(6);
      expect(docs[1]!.key.startsWith('refresh:203.0.113.22:')).toBe(true);
      expect(docs[1]!.counter).toBe(1);
    });
  });

  // ── toolsController.ts: the bounded HIBP response cache ───────────────

  describe('HIBP cache: bounded LRU with TTL (setHibpCacheEntry / pruneHibpCache)', () => {
    const future = () => Date.now() + 60_000;
    const past = () => Date.now() - 1;

    beforeEach(() => {
      hibpCache.clear();
      resetCacheAccessCount();
    });

    afterEach(() => {
      hibpCache.clear();
      resetCacheAccessCount();
    });

    /** Fill the cache to exactly the cap. Key `i` is inserted in order. */
    function fillToCap(expiresFor: (index: number) => number): void {
      for (let i = 0; i < HIBP_CACHE_MAX_ENTRIES; i++) {
        setHibpCacheEntry(`k${String(i)}`, { data: `d${String(i)}`, expires: expiresFor(i) });
      }
      expect(hibpCache.size).toBe(HIBP_CACHE_MAX_ENTRIES);
    }

    it('updates an existing key in place: no eviction, no growth', () => {
      fillToCap(future);

      setHibpCacheEntry('k0', { data: 'refreshed', expires: future() });

      // The cap is already reached, but a re-set of a live key must NOT evict
      // anything — the entry is replaced, not added.
      expect(hibpCache.size).toBe(HIBP_CACHE_MAX_ENTRIES);
      expect(hibpCache.get('k0')?.data).toBe('refreshed');
      expect(hibpCache.get('k1')?.data).toBe('d1');
      expect(hibpCache.get(`k${String(HIBP_CACHE_MAX_ENTRIES - 1)}`)).toBeDefined();
    });

    it('at the cap, harvests an EXPIRED entry in preference to the oldest live one', () => {
      // k0 (oldest) is live; k5000 is expired. Insertion-order eviction alone
      // would drop k0 — the expired-first sweep must drop k5000 instead, so a
      // still-useful response is not thrown away to make room.
      fillToCap((i) => (i === 5000 ? past() : future()));

      setHibpCacheEntry('fresh', { data: 'new', expires: future() });

      expect(hibpCache.size).toBe(HIBP_CACHE_MAX_ENTRIES);
      expect(hibpCache.has('k5000')).toBe(false);
      expect(hibpCache.get('k0')?.data).toBe('d0');
      expect(hibpCache.get('fresh')?.data).toBe('new');
    });

    it('at the cap with nothing expired, evicts the OLDEST-inserted entry', () => {
      fillToCap(future);

      setHibpCacheEntry('fresh', { data: 'new', expires: future() });

      // Hard cap holds — the entry count alone bounds worst-case memory at ~360 MB
      // (~36 KB/range × 10,000); the byte budget is the tighter, binding bound.
      expect(hibpCache.size).toBe(HIBP_CACHE_MAX_ENTRIES);
      expect(hibpCache.has('k0')).toBe(false);
      expect(hibpCache.get('k1')?.data).toBe('d1');
      expect(hibpCache.get(`k${String(HIBP_CACHE_MAX_ENTRIES - 1)}`)?.data).toBe(
        `d${String(HIBP_CACHE_MAX_ENTRIES - 1)}`,
      );
      expect(hibpCache.get('fresh')?.data).toBe('new');
    });

    it('pruneHibpCache sweeps expired entries only on every 100th access, and keeps live ones', () => {
      hibpCache.set('expired', { data: 'stale', expires: past() });
      hibpCache.set('live', { data: 'fresh', expires: future() });

      // Sweeping on every request would walk the whole map on the hottest path;
      // the counter is what keeps that to 1-in-100.
      for (let i = 0; i < 99; i++) {
        pruneHibpCache();
      }
      expect(hibpCache.has('expired')).toBe(true);

      pruneHibpCache(); // 100th access — the sweep runs.

      expect(hibpCache.has('expired')).toBe(false);
      expect(hibpCache.get('live')?.data).toBe('fresh');
    });

    // ── Byte budget (HIBP_CACHE_MAX_BYTES) eviction branches ────────────
    describe('byte budget: HIBP_CACHE_MAX_BYTES', () => {
      const originalMaxBytes = getHibpCacheMaxBytes();

      afterEach(() => {
        __setHibpCacheMaxBytes(originalMaxBytes);
      });

      it('evicts down to the byte budget, harvesting an EXPIRED entry first', () => {
        __setHibpCacheMaxBytes(4096);
        const now = Date.now();
        setHibpCacheEntry('live1', { data: 'a'.repeat(1024), expires: now + 60_000 });
        setHibpCacheEntry('expired', { data: 'b'.repeat(1024), expires: now - 1 });
        setHibpCacheEntry('live2', { data: 'c'.repeat(1024), expires: now + 60_000 });
        expect(getHibpCacheBytes()).toBe(3072);
        // A 2 KB insert pushes the total to 5 KB > 4 KB — the expired entry is
        // dropped first, leaving both live entries and the newcomer intact.
        setHibpCacheEntry('live3', { data: 'd'.repeat(2048), expires: now + 60_000 });
        expect(hibpCache.has('expired')).toBe(false);
        expect(hibpCache.has('live1')).toBe(true);
        expect(hibpCache.has('live2')).toBe(true);
        expect(hibpCache.has('live3')).toBe(true);
        expect(getHibpCacheBytes()).toBeLessThanOrEqual(4096);
      });

      it('falls back to oldest-insertion byte eviction when nothing is expired', () => {
        __setHibpCacheMaxBytes(3072);
        const future = Date.now() + 60_000;
        setHibpCacheEntry('oldest', { data: 'a'.repeat(1024), expires: future });
        setHibpCacheEntry('middle', { data: 'b'.repeat(1024), expires: future });
        setHibpCacheEntry('newest', { data: 'c'.repeat(1024), expires: future });
        expect(getHibpCacheBytes()).toBe(3072);
        setHibpCacheEntry('newer', { data: 'd'.repeat(1024), expires: future });
        expect(hibpCache.has('oldest')).toBe(false);
        expect(hibpCache.has('newer')).toBe(true);
        expect(getHibpCacheBytes()).toBeLessThanOrEqual(3072);
      });

      it('an update-in-place that grows past the budget evicts an older entry', () => {
        __setHibpCacheMaxBytes(3072);
        const future = Date.now() + 60_000;
        setHibpCacheEntry('a', { data: 'a'.repeat(1024), expires: future });
        setHibpCacheEntry('b', { data: 'b'.repeat(1024), expires: future });
        setHibpCacheEntry('c', { data: 'c'.repeat(1024), expires: future });
        // Grow 'c' in place to 2 KB → total 4 KB > 3 KB. Re-setting an existing key
        // does not change its insertion order, so 'a' is the oldest and is dropped.
        setHibpCacheEntry('c', { data: 'C'.repeat(2048), expires: future });
        expect(hibpCache.get('c')?.data).toBe('C'.repeat(2048));
        expect(hibpCache.has('a')).toBe(false);
        expect(getHibpCacheBytes()).toBeLessThanOrEqual(3072);
      });

      it('keeps a lone entry larger than the whole budget', () => {
        __setHibpCacheMaxBytes(512);
        setHibpCacheEntry('solo', { data: 'x'.repeat(4096), expires: Date.now() + 60_000 });
        expect(hibpCache.size).toBe(1);
        expect(getHibpCacheBytes()).toBe(4096);
      });

      it('clamps the total to zero when a direct-set entry desyncs the counter (prune)', () => {
        // A test/legacy entry inserted directly with an inflated `bytes` value that the
        // running total never accrued. When prune reaps it, the subtraction would drive
        // the total negative — the clamp keeps it at zero rather than disabling the
        // byte budget until it recovers.
        resetCacheAccessCount(); // total = 0
        hibpCache.set('ghost', { data: 'g', expires: Date.now() - 1, bytes: 5000 });
        for (let i = 0; i < 100; i++) pruneHibpCache();
        expect(hibpCache.has('ghost')).toBe(false);
        expect(getHibpCacheBytes()).toBe(0);
      });

      it('clamps the total to zero when eviction subtracts more than was tracked', () => {
        resetCacheAccessCount(); // total = 0
        // A direct-set entry carrying an inflated byte count the total never accrued.
        hibpCache.set('ghost', { data: 'g', expires: Date.now() + 60_000, bytes: 5000 });
        __setHibpCacheMaxBytes(1);
        // Inserting a real entry pushes size to 2 and the (tiny) real total over the
        // 1-byte budget, forcing eviction of the oldest — 'ghost' — whose inflated
        // 5000 bytes would drive the total negative; the clamp holds it at zero.
        setHibpCacheEntry('real', { data: 'rr', expires: Date.now() + 60_000 });
        expect(hibpCache.has('ghost')).toBe(false);
        expect(hibpCache.has('real')).toBe(true);
        expect(getHibpCacheBytes()).toBe(0);
      });
    });
  });

  // ── toolsController.ts: import validation, audit trail and budget ─────

  describe('POST /api/v1/tools/import — rejected payloads', () => {
    /** One `operations.inserts` row with every required field populated. */
    function insertRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
      return { ...sampleVaultItem(overrides), searchHash: 'a'.repeat(64) };
    }

    it('rejects a bitwarden payload whose rows carry NO ciphertext (400, nothing written)', async () => {
      // A source parser that emitted plaintext rows: the six ciphertext fields
      // are required, so the request never reaches the database and leaves no
      // audit trail of an import that did not happen.
      const res = await post(agent, '/api/v1/tools/import', user.accessToken, {
        format: 'bitwarden',
        operations: {
          inserts: [{ itemType: 'login' }, { itemType: 'note', favorite: true }],
        },
      });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
      expect(await AuditLog.countDocuments({ userId: user.id, action: 'import' })).toBe(0);
    });

    it('rejects a non-string ciphertext field rather than coercing it', async () => {
      // A tampered or legacy export can carry a numeric field. It must fail
      // validation up front: coercing it would silently store a value the
      // client's vault key never produced.
      const res = await post(agent, '/api/v1/tools/import', user.accessToken, {
        format: 'json',
        operations: {
          inserts: [{ ...insertRow({ encryptedName: 'numeric-tag' }), nameTag: 12345 }],
        },
      });

      expect(res.status).toBe(400);
      expect(res.body.message).toContain('nameTag');
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
    });

    it('rejects a row missing a single ciphertext field, keeping the batch atomic', async () => {
      const partial = insertRow({ encryptedName: 'partial' });
      delete partial.nameTag;

      const res = await post(agent, '/api/v1/tools/import', user.accessToken, {
        format: 'keepass',
        operations: { inserts: [insertRow({ encryptedName: 'complete' }), partial] },
      });

      expect(res.status).toBe(400);
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
    });
  });

  describe('POST /api/v1/tools/import — audit trail and rate-limit budget', () => {
    it('records the source format, the default strategy and both counts', async () => {
      const existing = await seedItem(user.id, { encryptedName: 'to-update' });

      const res = await post(agent, '/api/v1/tools/import', user.accessToken, {
        format: 'keepass',
        operations: {
          inserts: [{ ...sampleVaultItem({ encryptedName: 'fresh' }), searchHash: 'b'.repeat(64) }],
          updates: [
            {
              ...sampleVaultItem({ encryptedName: 'rewritten' }),
              id: String(existing._id),
              searchHash: 'c'.repeat(64),
            },
          ],
        },
      });

      expect(res.status).toBe(201);
      expect(res.body.data).toEqual({ insertedCount: 1, updatedCount: 1 });

      const log = await AuditLog.findOne({ userId: user.id, action: 'import' }).lean();
      expect(log).not.toBeNull();
      // `conflictStrategy` was omitted: the schema default is what gets recorded.
      expect(log!.metadata).toMatchObject({
        format: 'keepass',
        conflictStrategy: 'skip',
        insertedCount: 1,
        updatedCount: 1,
      });
    });

    it('counts the request against the per-user import budget, not the shared heavy-op one', async () => {
      // A migration arrives as several sequential batches. Sharing
      // `heavyOpLimiter`'s 10-per-IP budget would stall it (or a prior export
      // would burn a slot), so `/tools/import` owns a userId-keyed counter.
      const res = await post(agent, '/api/v1/tools/import', user.accessToken, {
        format: 'json',
        operations: {
          inserts: [
            { ...sampleVaultItem({ encryptedName: 'budgeted' }), searchHash: 'd'.repeat(64) },
          ],
        },
      });
      expect(res.status).toBe(201);

      const docs = await rateLimitDocs();
      expect(docs.filter((doc) => doc.key.startsWith('heavy:'))).toEqual([]);
      expect(docs.filter((doc) => doc.key.startsWith('import:'))).toEqual([
        { key: `import:${user.id}`, counter: 1 },
      ]);
    });
  });

  // ── app.ts: MongoDB operator stripping walks ARRAYS, not just objects ──

  describe('app.ts — request-body sanitization', () => {
    it('passes an explicit null through untouched, so a null-valued field keeps its meaning', async () => {
      // `folderId: null` is the API's "move this item out of every folder"
      // signal. The sanitizer must return null verbatim: coerce it (e.g. into
      // `{}` by falling through to the object arm) and the update either fails
      // to cast or silently stops clearing the folder.
      const item = await seedItem(user.id, { encryptedName: 'null-folder' });
      const folder = await post(agent, '/api/v1/folders', user.accessToken, {
        encryptedName: 'holding-folder',
        nameIv: 'folder-name-iv',
        nameTag: 'folder-name-tag',
      });
      expect(folder.status).toBe(201);

      const moved = await put(agent, `/api/v1/vault/items/${String(item._id)}`, user.accessToken, {
        folderId: folder.body.data._id as string,
      });
      expect(moved.status).toBe(200);
      expect(String((await VaultItem.findById(String(item._id)).lean())!.folderId)).toBe(
        String(folder.body.data._id),
      );

      const cleared = await put(
        agent,
        `/api/v1/vault/items/${String(item._id)}`,
        user.accessToken,
        {
          folderId: null,
        },
      );

      expect(cleared.status).toBe(200);
      const saved = await VaultItem.findById(String(item._id)).lean();
      expect(saved!.folderId).toBeUndefined();
    });

    it('preserves a legitimate array field through sanitization (arrays are mapped, not objectified)', async () => {
      const res = await post(agent, '/api/v1/vault/items', user.accessToken, {
        ...sampleVaultItem({ encryptedName: 'array-survives' }),
        tags: ['alpha', 'beta'],
      });

      expect(res.status).toBe(201);

      // Without the Array.isArray arm, sanitizeValue would rebuild ['alpha','beta']
      // as { '0': 'alpha', '1': 'beta' } and the write would fail to cast.
      const saved = await VaultItem.findOne({
        userId: user.id,
        encryptedName: 'array-survives',
      }).lean();
      expect(saved).not.toBeNull();
      expect(saved!.tags).toEqual(['alpha', 'beta']);
    });

    it('strips MongoDB operator keys nested INSIDE an array element, so no item is deleted', async () => {
      const item = await seedItem(user.id, { encryptedName: 'must-survive' });

      const res = await post(agent, '/api/v1/vault/items/bulk-delete', user.accessToken, {
        ids: [{ $ne: null }],
      });

      // The `$ne` object is emptied by the sanitizer, so Zod sees `[{}]` and
      // rejects it — the operator never reaches Mongo as a query.
      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);

      const survivor = await VaultItem.findById(String(item._id)).lean();
      expect(survivor).not.toBeNull();
      expect(survivor!.deletedAt).toBeUndefined();
    });
  });

  // ── app.ts: trust proxy ───────────────────────────────────────────────

  describe('app.ts — TRUST_PROXY', () => {
    it('records the X-Forwarded-For client IP (not the proxy socket) in the audit log', async () => {
      // With `app.set('trust proxy', …)` unwired, every request behind the
      // stack's Nginx would be audited (and rate-limited) as 127.0.0.1 —
      // the audit trail would name the proxy instead of the attacker.
      const res = await post(
        agent,
        '/api/v1/tools/export',
        user.accessToken,
        { authHash: 'wrong-password' },
        { 'x-forwarded-for': '198.51.100.77' },
      );

      expect(res.status).toBe(401);

      const entry = await AuditLog.findOne({
        userId: user.id,
        action: 'password_verification_failed',
      }).lean();
      expect(entry).not.toBeNull();
      expect(entry!.ipAddress).toBe('198.51.100.77');
    });
  });

  // ── app.ts: the METRICS_TOKEN-gated /metrics mount ────────────────────

  describe('app.ts — /api/v1/metrics is mounted only when METRICS_TOKEN is configured', () => {
    it('serves the metrics payload for the correct token', async () => {
      const res = await agent.get('/api/v1/metrics').set('x-metrics-token', TEST_METRICS_TOKEN);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(typeof res.body.data.uptime).toBe('number');
      expect(res.body.data.database.state).toBe('connected');
    });

    it('rejects a wrong token with 403 and leaks no metrics', async () => {
      const wrong = await agent
        .get('/api/v1/metrics')
        .set('x-metrics-token', `${TEST_METRICS_TOKEN}x`);

      expect(wrong.status).toBe(403);
      expect(wrong.body.success).toBe(false);
      expect(wrong.body.data).toBeUndefined();
    });

    it('rejects a request with no token at all with 403', async () => {
      const res = await agent.get('/api/v1/metrics');

      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
      expect(res.body.data).toBeUndefined();
    });
  });
});
