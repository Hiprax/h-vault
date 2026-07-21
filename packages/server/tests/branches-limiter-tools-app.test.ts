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

      // Hard cap holds — this is what bounds steady-state memory at ~250 MB.
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
  });

  // ── toolsController.ts: import parsing edge cases ─────────────────────

  describe('POST /api/v1/tools/import — non-JSON formats with incomplete rows', () => {
    it('rejects a bitwarden payload whose items carry NO encryption fields (400, nothing written)', async () => {
      // The bitwarden/lastpass/keepass branch defaults every absent encrypted
      // field to '' rather than letting `undefined` reach Mongoose (which would
      // surface as a required-path ValidationError → 500). Every row is then
      // dropped by the missing-encryption-fields filter.
      const data = JSON.stringify({
        items: [{ itemType: 'login' }, { itemType: 'note', favorite: true }],
      });

      const res = await post(agent, '/api/v1/tools/import', user.accessToken, {
        format: 'bitwarden',
        data,
      });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toMatch(/no valid items/i);
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
      expect(await AuditLog.countDocuments({ userId: user.id, action: 'import' })).toBe(0);
    });

    it('imports the complete rows of a keepass payload and skips the partial one', async () => {
      const complete = sampleVaultItem({ encryptedName: 'keepass-complete' });
      const partial = { ...sampleVaultItem({ encryptedName: 'keepass-partial' }) };
      delete partial.nameTag; // one missing encrypted field is enough to drop the row

      const res = await post(agent, '/api/v1/tools/import', user.accessToken, {
        format: 'keepass',
        data: JSON.stringify({ items: [complete, partial] }),
      });

      expect(res.status).toBe(201);
      expect(res.body.data).toMatchObject({ importedCount: 1, skippedCount: 1 });

      const rows = await VaultItem.find({ userId: user.id }).lean();
      expect(rows).toHaveLength(1);
      expect(rows[0]!.encryptedName).toBe('keepass-complete');
    });

    it('does not blow up on a non-string encrypted field (it is coerced, not .trim()-ed)', async () => {
      // The validity filter guards every field with `typeof x === 'string' ?
      // x.trim() : x`. Drop the guard and a numeric field from a tampered/legacy
      // export throws `x.trim is not a function` → 500 for the whole import.
      const item = { ...sampleVaultItem({ encryptedName: 'numeric-tag' }), nameTag: 12345 };

      const res = await post(agent, '/api/v1/tools/import', user.accessToken, {
        format: 'json',
        data: JSON.stringify({ items: [item] }),
      });

      expect(res.status).toBe(201);
      expect(res.body.data.importedCount).toBe(1);

      const saved = await VaultItem.findOne({
        userId: user.id,
        encryptedName: 'numeric-tag',
      }).lean();
      expect(saved).not.toBeNull();
      expect(saved!.nameTag).toBe('12345');
    });
  });

  // ── toolsController.ts: dedup falls back to encryptedName ─────────────

  describe('POST /api/v1/tools/import — dedup when a searchHash is absent', () => {
    it('deduplicates an existing hash-less item against a hash-less import by encryptedName', async () => {
      // The post-vault-key-rotation case. A searchHash is an HMAC of the item
      // name under the vault key, so after a rotation an old export's hashes no
      // longer match — and an item may carry no hash at all. The dedup builds
      // its lookup maps by skipping hash-less existing rows, and `findExisting`
      // falls through to the encryptedName map for a hash-less import row.
      // Without either arm the row is treated as brand new and the user's vault
      // silently doubles on every re-import.
      await seedItem(user.id, { encryptedName: 'no-hash-name' });
      const before = await VaultItem.countDocuments({ userId: user.id });
      expect(before).toBe(1);

      const incoming = sampleVaultItem({ encryptedName: 'no-hash-name' });
      delete incoming.searchHash;

      const res = await post(agent, '/api/v1/tools/import', user.accessToken, {
        format: 'json',
        conflictStrategy: 'skip',
        data: JSON.stringify({ items: [incoming] }),
      });

      expect(res.status).toBe(201);
      expect(res.body.data).toMatchObject({ duplicateCount: 1, importedCount: 0 });
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(1);
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
