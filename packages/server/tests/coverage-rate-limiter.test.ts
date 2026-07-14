/**
 * The PRODUCTION bodies of every rate limiter.
 *
 * `rateLimiter.ts` returns a pass-through no-op for every limiter unless
 * `isProduction`, so the real limiter bodies — the thresholds, the key prefixes,
 * the `withClientKeyGuard` rejection, the `handler` that converts an exhausted
 * bucket into a 429 — are NEVER executed by the normal suite. That is precisely
 * how a broken store shipped once already (see rate-limit-store.test.ts).
 *
 * Here the module is re-imported with `isProduction` forced true, so the real
 * limiters are constructed on the real {@link MongoRateLimitStore}, backed by the
 * in-memory MongoDB the harness already owns, and driven over HTTP with supertest.
 * Every assertion is on OBSERVABLE behaviour: the HTTP status, the production
 * error message, and the counter documents the limiter actually wrote.
 *
 * Deliberately NOT duplicated here (already covered elsewhere, as pure helpers):
 * `resolveClientKey`/`buildAccountKey`/`buildRefreshKey` unit semantics
 * (rate-limit-client-key, account-limiter-key, refresh-limiter-key) and the store
 * internals (rate-limit-store). What is new is that those helpers are exercised
 * THROUGH the real, production-configured limiters end to end.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import express from 'express';
import type { Request, Response, NextFunction, RequestHandler } from 'express';
import cookieParser from 'cookie-parser';
import request from 'supertest';
import mongoose from 'mongoose';

/**
 * Force `isProduction` true for THIS test file's module graph only, so the
 * limiters below are the real ones (`noopIfNonProduction()` returns undefined and
 * the `??` falls through to the guarded `rateLimit(...)` middleware) and
 * `createStore()` builds a real {@link MongoRateLimitStore} over the connection
 * the harness already opened.
 *
 * `vi.mock` (hoisted, evaluated once) rather than `vi.resetModules()` +
 * `vi.doMock`: resetting the registry re-evaluates `models/User.ts` against the
 * mongoose singleton — which is externalised and therefore NOT reset — and
 * mongoose throws `OverwriteModelError` on the second `mongoose.model('User')`.
 */
vi.mock('../src/config/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/config/index.js')>();
  return { ...actual, isProduction: true };
});

// Static imports: `vi.mock` above is hoisted, so these already resolve against the
// production-mode config. (They must be static rather than a top-level dynamic
// `await import()` — a dynamically-imported module inside a mocked graph is
// attributed to a separate V8 coverage entry, and the merge then DROPS the file
// from the package report entirely.)
import * as limiters from '../src/middleware/rateLimiter.js';
import { RATE_LIMIT_COLLECTION, MongoRateLimitStore } from '../src/middleware/rateLimitStore.js';

type RateLimiterModule = typeof limiters;

interface TestAppOptions {
  /** Read `x-test-user` and expose it as `req.user._id` (for the userId-keyed limiters). */
  injectUser?: boolean;
  /** Drop `req.ip` and `req.socket.remoteAddress` when `x-test-strip-identity: 1` is sent. */
  allowIdentityStrip?: boolean;
}

function createApp(limiter: RequestHandler, options: TestAppOptions = {}) {
  const app = express();
  app.set('trust proxy', 1);
  app.use(express.json());
  app.use(cookieParser());

  if (options.allowIdentityStrip) {
    app.use((req, _res, next) => {
      if (req.header('x-test-strip-identity') === '1') {
        Object.defineProperty(req, 'ip', { value: undefined, configurable: true });
        Object.defineProperty(req.socket, 'remoteAddress', {
          value: undefined,
          configurable: true,
        });
      }
      next();
    });
  }

  if (options.injectUser) {
    app.use((req, _res, next) => {
      const id = req.header('x-test-user');
      if (id !== undefined) {
        (req as Request & { user?: { _id: string } }).user = { _id: id };
      }
      next();
    });
  }

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

function collection() {
  return mongoose.connection.db!.collection(RATE_LIMIT_COLLECTION);
}

/** Every rate-limit counter key the limiters actually persisted, as written. */
async function storedKeys(): Promise<string[]> {
  const docs = await collection().find({}).toArray();
  return docs.map((doc) => String(doc._id));
}

async function counterFor(key: string): Promise<number | undefined> {
  const doc = await collection().findOne({ _id: key as unknown as never });
  return doc?.['counter'] as number | undefined;
}

/** Fire `count` GETs from a fixed forwarded IP, returning every status code. */
async function hitFromIp(
  app: express.Express,
  ip: string,
  count: number,
): Promise<{ statuses: number[]; lastBody: unknown }> {
  const statuses: number[] = [];
  let lastBody: unknown;
  for (let i = 0; i < count; i++) {
    const res = await request(app).get('/t').set('x-forwarded-for', ip);
    statuses.push(res.status);
    lastBody = res.body;
  }
  return { statuses, lastBody };
}

describe('production rate limiters (real limiter bodies + real Mongo store)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('the module under test really is in production mode (not a pass-through no-op)', async () => {
    // Guard for the whole file: if the config mock ever stopped taking effect,
    // every limiter below would be a no-op and each 429 expectation would fail —
    // but this states the precondition explicitly rather than leaving it implied.
    const { isProduction } = await import('../src/config/index.js');
    expect(isProduction).toBe(true);

    const app = createApp(limiters.authLimiter as RequestHandler);
    await request(app).get('/t').set('x-forwarded-for', '192.0.2.1');
    // A no-op limiter writes nothing; the real one persists a counter.
    expect(await storedKeys()).toEqual(['auth:192.0.2.1']);
  });

  describe('IP-keyed limiters enforce their documented threshold', () => {
    // Table drives the REAL exported limiter — a changed limit, a changed prefix
    // or a changed 429 message makes the matching row go red.
    const cases: {
      name: keyof RateLimiterModule;
      limit: number;
      prefix: string;
      message: string;
    }[] = [
      {
        name: 'authLimiter',
        limit: 10,
        prefix: 'auth:',
        message: 'Too many authentication attempts, please try again later',
      },
      {
        name: 'tokenVerifyLimiter',
        limit: 20,
        prefix: 'token:',
        message: 'Too many verification attempts, please try again later',
      },
      {
        name: 'csrfLimiter',
        limit: 30,
        prefix: 'csrf:',
        message: 'Too many requests, please try again later',
      },
      {
        name: 'heavyOpLimiter',
        limit: 10,
        prefix: 'heavy:',
        message: 'Too many requests, please try again later',
      },
      {
        name: 'healthLimiter',
        limit: 60,
        prefix: 'health:',
        message: 'Too many requests, please try again later',
      },
      {
        name: 'metricsLimiter',
        limit: 60,
        prefix: 'metrics:',
        message: 'Too many requests, please try again later',
      },
    ];

    for (const testCase of cases) {
      it(`${testCase.name}: allows ${String(testCase.limit)} then 429s, under the "${testCase.prefix}" key`, async () => {
        const app = createApp(limiters[testCase.name] as RequestHandler);
        const ip = '203.0.113.44';

        const { statuses } = await hitFromIp(app, ip, testCase.limit);
        expect(statuses.every((status) => status === 200)).toBe(true);

        const blocked = await request(app).get('/t').set('x-forwarded-for', ip);
        expect(blocked.status).toBe(429);
        expect((blocked.body as { message: string }).message).toBe(testCase.message);

        // The counter must live under this limiter's OWN prefix, or two limiters
        // would silently share (and drain) a single budget.
        expect(await storedKeys()).toEqual([`${testCase.prefix}${ip}`]);
        expect(await counterFor(`${testCase.prefix}${ip}`)).toBe(testCase.limit + 1);
      });
    }

    it('a second IP still gets its full budget after the first IP is exhausted', async () => {
      const app = createApp(limiters.authLimiter as RequestHandler);

      const { statuses } = await hitFromIp(app, '203.0.113.1', 11);
      expect(statuses[10]).toBe(429);

      const other = await request(app).get('/t').set('x-forwarded-for', '203.0.113.2');
      expect(other.status).toBe(200);
      expect(await counterFor('auth:203.0.113.2')).toBe(1);
    });
  });

  describe('key-prefix isolation across limiters', () => {
    it('exhausting authLimiter does not consume heavyOpLimiter budget for the same IP', async () => {
      const ip = '198.51.100.30';
      const authApp = createApp(limiters.authLimiter as RequestHandler);
      const heavyApp = createApp(limiters.heavyOpLimiter as RequestHandler);

      const { statuses } = await hitFromIp(authApp, ip, 11);
      expect(statuses[10]).toBe(429);

      // Same client, different limiter: an unprefixed (shared) key would have
      // this land on an already-exhausted counter and 429 immediately.
      const heavy = await hitFromIp(heavyApp, ip, 10);
      expect(heavy.statuses.every((status) => status === 200)).toBe(true);

      expect((await storedKeys()).sort()).toEqual([`auth:${ip}`, `heavy:${ip}`]);
      expect(await counterFor(`auth:${ip}`)).toBe(11);
      expect(await counterFor(`heavy:${ip}`)).toBe(10);
    });
  });

  describe('IPv6 source rotation cannot bypass an IP-keyed limiter', () => {
    it('collapses an entire /64 into ONE bucket, so 11 distinct /128s still trip authLimiter', async () => {
      // The documented bypass: a routed /64 hands an attacker 2^64 source
      // addresses. Keyed on the raw /128 each request lands in its own bucket and
      // the limiter never fires.
      const app = createApp(limiters.authLimiter as RequestHandler);
      const statuses: number[] = [];
      for (let i = 0; i < 11; i++) {
        const res = await request(app)
          .get('/t')
          .set('x-forwarded-for', `2001:db8:1:2:aaaa:bbbb:cccc:${(i + 1).toString(16)}`);
        statuses.push(res.status);
      }

      expect(statuses.slice(0, 10).every((status) => status === 200)).toBe(true);
      expect(statuses[10]).toBe(429);
      expect(await storedKeys()).toEqual(['auth:2001:db8:1:2::/64']);
      expect(await counterFor('auth:2001:db8:1:2::/64')).toBe(11);
    });

    it('keeps a genuinely different /64 on its own budget', async () => {
      const app = createApp(limiters.authLimiter as RequestHandler);

      for (let i = 0; i < 10; i++) {
        await request(app).get('/t').set('x-forwarded-for', '2001:db8:1:2::5');
      }
      const exhausted = await request(app).get('/t').set('x-forwarded-for', '2001:db8:1:2::9');
      expect(exhausted.status).toBe(429);

      const neighbour = await request(app).get('/t').set('x-forwarded-for', '2001:db8:1:3::5');
      expect(neighbour.status).toBe(200);
      expect(await counterFor('auth:2001:db8:1:3::/64')).toBe(1);
    });

    it('folds a v4-mapped IPv6 onto its plain IPv4 bucket rather than a second one', async () => {
      const app = createApp(limiters.authLimiter as RequestHandler);

      await request(app).get('/t').set('x-forwarded-for', '203.0.113.77');
      await request(app).get('/t').set('x-forwarded-for', '::ffff:203.0.113.77');

      expect(await storedKeys()).toEqual(['auth:203.0.113.77']);
      expect(await counterFor('auth:203.0.113.77')).toBe(2);
    });

    it('clamps an arbitrary-length spoofed X-Forwarded-For to 45 chars so rotation collides', async () => {
      // TRUST_PROXY=true + a 500-char X-Forwarded-For: without the clamp every
      // rotated value is a distinct Mongo bucket and the limiter degrades to "no
      // rate limit" for the attacker.
      const app = createApp(limiters.authLimiter as RequestHandler);
      const prefix = 'F'.repeat(45);

      const statuses: number[] = [];
      for (let i = 0; i < 11; i++) {
        const res = await request(app)
          .get('/t')
          .set('x-forwarded-for', `${prefix}rotating-suffix-${String(i)}`);
        statuses.push(res.status);
      }

      expect(statuses[10]).toBe(429);
      expect(await storedKeys()).toEqual([`auth:${prefix}`]);
    });
  });

  describe('withClientKeyGuard: no client identity is a hard failure, never a shared bucket', () => {
    it('rejects with 500 RATE_LIMIT_FAILED and writes no counter at all', async () => {
      const app = createApp(limiters.authLimiter as RequestHandler, { allowIdentityStrip: true });

      const res = await request(app).get('/t').set('x-test-strip-identity', '1');

      expect(res.status).toBe(500);
      const message = (res.body as { message: string }).message;
      expect(message).toContain('RATE_LIMIT_FAILED');
      expect(message).toContain('TRUST_PROXY');
      // Nothing was counted: an unidentified request must not be silently merged
      // into a shared `auth:` bucket that one attacker could exhaust for everyone.
      expect(await storedKeys()).toEqual([]);
    });

    it('still serves an identifiable request on the same app', async () => {
      const app = createApp(limiters.healthLimiter as RequestHandler, { allowIdentityStrip: true });

      expect((await request(app).get('/t').set('x-test-strip-identity', '1')).status).toBe(500);
      const ok = await request(app).get('/t').set('x-forwarded-for', '203.0.113.5');
      expect(ok.status).toBe(200);
      expect(await storedKeys()).toEqual(['health:203.0.113.5']);
    });
  });

  describe('accountLimiter (email-keyed)', () => {
    it('a bodyless POST does not throw — it is skipped and counts nothing', async () => {
      // Express 5 / body-parser 2.x leave `req.body === undefined` here, and
      // accountLimiter is the first middleware on POST /login to touch the body.
      // An unguarded read would surface as a 500 instead of Zod's clean 400.
      const app = createApp(limiters.accountLimiter as RequestHandler);

      const res = await request(app).post('/t').set('x-forwarded-for', '203.0.113.60');

      expect(res.status).toBe(200);
      expect(await storedKeys()).toEqual([]);
    });

    it('a text/plain body (not JSON) is likewise skipped without a 500', async () => {
      const app = createApp(limiters.accountLimiter as RequestHandler);

      const res = await request(app)
        .post('/t')
        .set('Content-Type', 'text/plain')
        .set('x-forwarded-for', '203.0.113.61')
        .send('email=someone@example.com');

      expect(res.status).toBe(200);
      expect(await storedKeys()).toEqual([]);
    });

    it('counts 20 attempts per email then 429s, case-insensitively, on one bucket', async () => {
      const app = createApp(limiters.accountLimiter as RequestHandler);
      // Alternate casing AND rotate the source IP: the bucket is the account, so
      // neither dodge buys the attacker an extra attempt.
      for (let i = 0; i < 20; i++) {
        const res = await request(app)
          .post('/t')
          .set('x-forwarded-for', `203.0.113.${String(i + 1)}`)
          .send({ email: i % 2 === 0 ? 'Victim@Example.COM' : 'victim@example.com' });
        expect(res.status).toBe(200);
      }

      const blocked = await request(app)
        .post('/t')
        .set('x-forwarded-for', '198.51.100.99')
        .send({ email: 'VICTIM@example.com' });

      expect(blocked.status).toBe(429);
      expect((blocked.body as { message: string }).message).toBe(
        'Too many login attempts for this account, please try again later',
      );
      expect(await storedKeys()).toEqual(['account:email:victim@example.com']);
      expect(await counterFor('account:email:victim@example.com')).toBe(21);
    });

    it('a different email keeps its own budget once another account is exhausted', async () => {
      const app = createApp(limiters.accountLimiter as RequestHandler);
      for (let i = 0; i < 21; i++) {
        await request(app)
          .post('/t')
          .set('x-forwarded-for', '203.0.113.70')
          .send({ email: 'burned@example.com' });
      }

      const other = await request(app)
        .post('/t')
        .set('x-forwarded-for', '203.0.113.70')
        .send({ email: 'innocent@example.com' });

      expect(other.status).toBe(200);
      expect(await counterFor('account:email:innocent@example.com')).toBe(1);
    });
  });

  describe('userId-keyed limiters cannot be bypassed by rotating the source IP', () => {
    const cases: {
      name: keyof RateLimiterModule;
      limit: number;
      prefix: string;
      message: string;
    }[] = [
      {
        name: 'unlockLimiter',
        limit: 5,
        prefix: 'unlock:',
        message: 'Too many unlock attempts, please try again later',
      },
      {
        name: 'passwordVerifyLimiter',
        limit: 5,
        prefix: 'pwverify:',
        message: 'Too many password verification attempts, please try again later',
      },
      {
        name: 'breachCheckLimiter',
        limit: 30,
        prefix: 'breach:',
        message: 'Too many breach check requests, please try again later',
      },
      {
        name: 'generalAuthLimiter',
        limit: 60,
        prefix: 'general:',
        message: 'Too many requests, please try again later',
      },
    ];

    for (const testCase of cases) {
      it(`${testCase.name}: ${String(testCase.limit)} per user, from ANY IP, then 429`, async () => {
        const app = createApp(limiters[testCase.name] as RequestHandler, { injectUser: true });
        const userId = 'aaaaaaaaaaaaaaaaaaaaaaaa';

        for (let i = 0; i < testCase.limit; i++) {
          const res = await request(app)
            .get('/t')
            .set('x-test-user', userId)
            // A fresh source IP every time — an IP-keyed limiter would never fire.
            .set('x-forwarded-for', `203.0.113.${String((i % 200) + 1)}`);
          expect(res.status).toBe(200);
        }

        const blocked = await request(app)
          .get('/t')
          .set('x-test-user', userId)
          .set('x-forwarded-for', '198.51.100.250');
        expect(blocked.status).toBe(429);
        expect((blocked.body as { message: string }).message).toBe(testCase.message);

        expect(await storedKeys()).toEqual([`${testCase.prefix}${userId}`]);
        expect(await counterFor(`${testCase.prefix}${userId}`)).toBe(testCase.limit + 1);

        // A DIFFERENT user is untouched by the exhausted account's counter.
        const otherUser = await request(app)
          .get('/t')
          .set('x-test-user', 'bbbbbbbbbbbbbbbbbbbbbbbb')
          .set('x-forwarded-for', '198.51.100.250');
        expect(otherUser.status).toBe(200);
      });
    }

    it('falls back to the client IP when no authenticated user is attached', async () => {
      const app = createApp(limiters.unlockLimiter as RequestHandler, { injectUser: true });

      await request(app).get('/t').set('x-forwarded-for', '203.0.113.90');

      expect(await storedKeys()).toEqual(['unlock:203.0.113.90']);
    });
  });

  describe('refreshLimiter (IP + UA + refresh-token session)', () => {
    it('5 refreshes per session then 429 — and a second session on the same IP+UA is unaffected', async () => {
      const app = createApp(limiters.refreshLimiter as RequestHandler);
      const ua = 'Mozilla/5.0 PinnedCorporateBrowser';

      const sessionA = () =>
        request(app)
          .post('/t')
          .set('x-forwarded-for', '203.0.113.100')
          .set('user-agent', ua)
          .set('Cookie', ['refreshToken=session-a-token']);

      for (let i = 0; i < 5; i++) {
        expect((await sessionA()).status).toBe(200);
      }

      const blocked = await sessionA();
      expect(blocked.status).toBe(429);
      expect((blocked.body as { message: string }).message).toBe(
        'Too many token refresh attempts, please try again later',
      );

      // Same NAT, same pinned browser, different refresh session: must NOT share
      // the exhausted bucket (the household / corporate-VPN case).
      const sessionB = await request(app)
        .post('/t')
        .set('x-forwarded-for', '203.0.113.100')
        .set('user-agent', ua)
        .set('Cookie', ['refreshToken=session-b-token']);
      expect(sessionB.status).toBe(200);

      const keys = await storedKeys();
      expect(keys).toHaveLength(2);
      expect(keys.every((key) => key.startsWith('refresh:203.0.113.100:'))).toBe(true);
      // The raw refresh token is never persisted into the rate-limit store.
      expect(keys.some((key) => key.includes('session-a-token'))).toBe(false);
    });

    it('a cookieless refresh still gets an IP+UA bucket and is limited at 5', async () => {
      const app = createApp(limiters.refreshLimiter as RequestHandler);

      const send = () =>
        request(app)
          .post('/t')
          .set('x-forwarded-for', '203.0.113.101')
          .set('user-agent', 'CookielessClient/1.0');

      for (let i = 0; i < 5; i++) {
        expect((await send()).status).toBe(200);
      }
      expect((await send()).status).toBe(429);

      const keys = await storedKeys();
      expect(keys).toHaveLength(1);
      // IP + UA hash only — no fourth (token-hash) segment.
      expect(keys[0]!.split(':')).toHaveLength(3);
    });
  });

  describe('store failure is FAIL CLOSED', () => {
    it('a store error yields 500, never an unlimited pass-through', async () => {
      // express-rate-limit defaults `passOnStoreError: false`, so a store outage
      // must block the request. A limiter that fails OPEN on a database blip is
      // exactly the moment an attacker is most likely to find it.
      const increment = vi
        .spyOn(MongoRateLimitStore.prototype, 'increment')
        .mockRejectedValue(new Error('rate limit store unavailable'));

      const app = createApp(limiters.authLimiter as RequestHandler);
      const res = await request(app).get('/t').set('x-forwarded-for', '203.0.113.120');

      expect(increment).toHaveBeenCalledTimes(1);
      expect(res.status).toBe(500);
      expect(res.status).not.toBe(200);
      expect(res.body).not.toEqual({ ok: true });
    });
  });

  describe('closeRateLimitStore', () => {
    it('resolves without throwing (the shutdown sequence awaits it)', async () => {
      await expect(limiters.closeRateLimitStore()).resolves.toBeUndefined();
    });
  });
});

/**
 * The store's own failure paths. These are what decide whether a database blip
 * degrades the limiters to "no limit" — the one moment an attacker is most likely
 * to be probing them.
 */
describe('MongoRateLimitStore failure paths', () => {
  /** The MongoDB driver Collection prototype shared by every `db.collection()` handle. */
  function driverCollectionPrototype(): {
    createIndex: (...args: never[]) => Promise<string>;
    findOneAndUpdate: (...args: never[]) => Promise<unknown>;
  } {
    const handle = mongoose.connection.db!.collection(RATE_LIMIT_COLLECTION);
    return Object.getPrototypeOf(handle) as ReturnType<typeof driverCollectionPrototype>;
  }

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('a lost MongoDB connection makes the limiter FAIL CLOSED (500), never pass the request', async () => {
    const app = createApp(limiters.authLimiter as RequestHandler);
    const connection = mongoose.connection as unknown as { db: unknown };
    const realDb = connection.db;

    try {
      Object.defineProperty(connection, 'db', {
        value: undefined,
        configurable: true,
        writable: true,
      });

      const res = await request(app).get('/t').set('x-forwarded-for', '203.0.113.130');

      // The store throws "connection is not established"; express-rate-limit does
      // not swallow it (passOnStoreError defaults false), so the request is
      // refused rather than served with no limit applied.
      expect(res.status).toBe(500);
      expect(res.body).not.toEqual({ ok: true });
    } finally {
      Object.defineProperty(connection, 'db', {
        value: realDb,
        configurable: true,
        writable: true,
      });
    }
  });

  it('keeps counting when the TTL index cannot be created, and stops retrying after 3 attempts', async () => {
    // The TTL index only drives MongoDB's background reaper — expiry itself is
    // decided against `$$NOW`. So an un-creatable index must NOT break rate
    // limiting, and it must NOT turn every request into another failed createIndex
    // round-trip on the app's hottest path.
    const createIndex = vi
      .spyOn(driverCollectionPrototype(), 'createIndex')
      .mockRejectedValue(new Error('not authorized to create index'));

    const store = new MongoRateLimitStore(60_000);
    const hits: number[] = [];
    for (let i = 0; i < 6; i++) {
      hits.push((await store.increment('auth:ttl-broken')).totalHits);
    }

    // Counting is unaffected by the index failure.
    expect(hits).toEqual([1, 2, 3, 4, 5, 6]);
    // ...and the store gave up after MAX_TTL_INDEX_ATTEMPTS rather than retrying
    // on every single request forever.
    expect(createIndex).toHaveBeenCalledTimes(3);

    // Expiry still works without the index: an already-expired record reads as
    // absent and the next hit opens a clean window.
    const shortStore = new MongoRateLimitStore(20);
    expect((await shortStore.increment('auth:ttl-broken-window')).totalHits).toBe(1);
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect((await shortStore.increment('auth:ttl-broken-window')).totalHits).toBe(1);
  });

  it('throws rather than reporting zero hits if the upsert returns no record', async () => {
    // Defensive branch: with `upsert: true` + `returnDocument: 'after'` this
    // cannot happen, but if it ever did, returning `totalHits: 0` would tell
    // express-rate-limit the client has used NONE of its quota — a silent
    // fail-open. It must throw instead.
    vi.spyOn(driverCollectionPrototype(), 'findOneAndUpdate').mockResolvedValue(null);

    const store = new MongoRateLimitStore(60_000);
    await expect(store.increment('auth:no-record')).rejects.toThrow(
      'Rate limit store: upsert returned no record',
    );
  });
});
