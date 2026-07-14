/**
 * F3.2 — Rate limiter client key resolution.
 *
 * Verifies that the rate limiter cannot silently collapse every anonymous
 * request into a single shared counter when `req.ip` is undefined. The fix
 * introduces:
 *
 *   1. `resolveClientKey(req)` — falls back from `req.ip` → `socket.remoteAddress`
 *   2. `withClientKeyGuard` — a wrapper that rejects with 500 `RATE_LIMIT_FAILED`
 *      when neither is available, rather than merging the request into a
 *      `'127.0.0.1'` bucket.
 *
 * These tests exercise the key resolution directly via a synthetic Request
 * shape and via a minimal Express app that feeds stripped sockets into a
 * wrapped limiter.
 */
import { describe, it, expect } from 'vitest';
import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import request from 'supertest';
import { rateLimit } from 'express-rate-limit';
import { resolveClientKey } from '../src/middleware/rateLimiter.js';

interface RawRequest {
  ip?: string;
  socket: { remoteAddress?: string };
}

describe('resolveClientKey (F3.2)', () => {
  it('returns req.ip when Express populated it', () => {
    const req: RawRequest = { ip: '203.0.113.7', socket: { remoteAddress: '10.0.0.5' } };
    expect(resolveClientKey(req as unknown as Request)).toBe('203.0.113.7');
  });

  it('falls back to socket.remoteAddress when req.ip is undefined', () => {
    const req: RawRequest = { socket: { remoteAddress: '10.0.0.5' } };
    expect(resolveClientKey(req as unknown as Request)).toBe('10.0.0.5');
  });

  it('falls back to socket.remoteAddress when req.ip is an empty string', () => {
    const req: RawRequest = { ip: '', socket: { remoteAddress: '10.0.0.5' } };
    expect(resolveClientKey(req as unknown as Request)).toBe('10.0.0.5');
  });

  it('returns null when neither req.ip nor socket.remoteAddress is available', () => {
    const req: RawRequest = { socket: {} };
    expect(resolveClientKey(req as unknown as Request)).toBeNull();
  });

  it('returns null when req.ip is undefined and socket.remoteAddress is empty', () => {
    const req: RawRequest = { socket: { remoteAddress: '' } };
    expect(resolveClientKey(req as unknown as Request)).toBeNull();
  });

  it('does not fall back to the literal string "127.0.0.1"', () => {
    // Regression guard: the previous implementation used `req.ip ?? '127.0.0.1'`
    // as a hardcoded fallback, which collapsed every unidentified request
    // into a single shared counter. This test pins that behavior as removed.
    const req: RawRequest = { socket: {} };
    const key = resolveClientKey(req as unknown as Request);
    expect(key).not.toBe('127.0.0.1');
    expect(key).toBeNull();
  });
});

describe('withClientKeyGuard integration (F3.2)', () => {
  /**
   * Build a minimal Express app with a synthetic middleware that lets a test
   * mutate `req.ip` and `req.socket` before the rate limiter runs. This lets
   * us simulate the "no identifiable client" state without having to mock
   * Node's TCP stack.
   */
  function createSyntheticApp(limiter: express.RequestHandler) {
    const app = express();
    app.use(express.json());
    // First middleware: allow the test to strip identifiers via a header.
    app.use((req, _res, next) => {
      if (req.header('x-test-strip-ip') === '1') {
        Object.defineProperty(req, 'ip', { value: undefined, configurable: true });
      }
      if (req.header('x-test-strip-socket') === '1') {
        Object.defineProperty(req.socket, 'remoteAddress', {
          value: undefined,
          configurable: true,
        });
      }
      next();
    });
    app.use(limiter);
    app.get('/test', (_req: Request, res: Response) => {
      res.json({ success: true });
    });
    app.use(
      (
        err: { statusCode?: number; status?: number; message?: string },
        _req: Request,
        res: Response,
        _next: NextFunction,
      ) => {
        const status = err.statusCode ?? err.status ?? 500;
        res.status(status).json({ error: err.message });
      },
    );
    return app;
  }

  it('normal requests with a valid IP pass through the guard', async () => {
    // Rebuild a limiter with a keyGenerator that uses resolveClientKey so we
    // exercise the real fallback path in the tests.
    const limiter = rateLimit({
      windowMs: 60_000,
      limit: 3,
      standardHeaders: true,
      legacyHeaders: false,
      validate: { trustProxy: false, xForwardedForHeader: false, keyGeneratorIpFallback: false },
      keyGenerator: (req: Request) => {
        const key = resolveClientKey(req);
        return `test:${key ?? ''}`;
      },
      handler: (_req, res) => {
        res.status(429).json({ error: 'rate limited' });
      },
    });
    const app = createSyntheticApp(limiter);

    const res = await request(app).get('/test');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ success: true });
  });

  it('requests with stripped IP but valid socket still get a real key (no 127.0.0.1 collapse)', async () => {
    const keys: string[] = [];
    const limiter = rateLimit({
      windowMs: 60_000,
      limit: 100,
      standardHeaders: true,
      legacyHeaders: false,
      validate: { trustProxy: false, xForwardedForHeader: false, keyGeneratorIpFallback: false },
      keyGenerator: (req: Request) => {
        const key = `test:${resolveClientKey(req) ?? 'NULL'}`;
        keys.push(key);
        return key;
      },
      handler: (_req, res) => {
        res.status(429).json({ error: 'rate limited' });
      },
    });
    const app = createSyntheticApp(limiter);

    // Supertest connects over loopback, so req.socket.remoteAddress is ::ffff:127.0.0.1
    // Strip req.ip and verify the limiter falls back to socket.remoteAddress,
    // NOT the literal '127.0.0.1' default.
    const res = await request(app).get('/test').set('x-test-strip-ip', '1');
    expect(res.status).toBe(200);
    expect(keys).toHaveLength(1);
    expect(keys[0]).not.toBe('test:NULL');
    // The real socket loopback address is normalized by ipKeyGenerator:
    // ::ffff:127.0.0.1 → 127.0.0.1, ::1 → ::/64 (network form). Any of these is
    // the genuine per-client socket key — NOT the removed `req.ip ?? '127.0.0.1'`
    // hardcoded collapse (that regression is pinned by the null-key tests above).
    expect(keys[0]).toMatch(/^test:(127\.0\.0\.1|::\/64)$/);
  });

  // NOTE: two tests that hand-rolled their OWN copy of the production
  // `withClientKeyGuard` wrapper ("requests with no IP AND no socket address
  // are rejected with 500" and "logs a rate-limiter identification failure")
  // were removed. They asserted against the guard the test itself wrote, so
  // breaking the real `withClientKeyGuard` (e.g. falling through to a shared
  // bucket) would never have turned them red. The real guard is now driven
  // end-to-end against the production `authLimiter`/`healthLimiter`
  // (isProduction forced true) in `coverage-rate-limiter.test.ts`, which
  // asserts a socket-less request gets a 500 `RATE_LIMIT_FAILED` and writes no
  // counter. The genuine `resolveClientKey` behavioural tests below are kept.

  it('a burst of requests from different IPs is not collapsed into a single counter', async () => {
    // Prior to F3.2, requests with undefined req.ip AND undefined socket would
    // fall back to the string '127.0.0.1', causing 3 different "anonymous"
    // clients to share one counter. With the fix, they either (a) fall back
    // to a real socket address (rare but acceptable), or (b) get rejected
    // individually with 500. Either way, one attacker cannot exhaust the
    // bucket for another client.
    const observedKeys = new Set<string>();
    const limiter = rateLimit({
      windowMs: 60_000,
      limit: 1,
      standardHeaders: true,
      legacyHeaders: false,
      validate: { trustProxy: false, xForwardedForHeader: false, keyGeneratorIpFallback: false },
      keyGenerator: (req: Request) => {
        const key = `test:${resolveClientKey(req) ?? ''}`;
        observedKeys.add(key);
        return key;
      },
      handler: (_req, res) => {
        res.status(429).json({ error: 'rate limited' });
      },
    });

    const app = express();
    app.set('trust proxy', 1);
    app.use(limiter);
    app.get('/test', (_req: Request, res: Response) => {
      res.json({ ok: true });
    });

    // Three distinct forwarded IPs — each should get a unique key.
    const res1 = await request(app).get('/test').set('x-forwarded-for', '203.0.113.1');
    const res2 = await request(app).get('/test').set('x-forwarded-for', '203.0.113.2');
    const res3 = await request(app).get('/test').set('x-forwarded-for', '203.0.113.3');

    expect(res1.status).toBe(200);
    expect(res2.status).toBe(200);
    expect(res3.status).toBe(200);

    // All three produced distinct keys — confirming the absence of a shared
    // '127.0.0.1' fallback.
    expect(observedKeys.size).toBe(3);
    for (const key of observedKeys) {
      expect(key).not.toBe('test:127.0.0.1');
    }
  });
});

// NOTE: a former `withClientKeyGuard wraps exported limiters (F3.2)` describe
// only asserted `typeof limiter === 'function'` and that a request returned
// 200 — which holds precisely BECAUSE every limiter is a pass-through no-op in
// test mode, so `withClientKeyGuard` is never even constructed. Removing the
// guard from every production limiter would have left those assertions green.
// The real guarded limiters are constructed and driven (isProduction forced
// true) in `coverage-rate-limiter.test.ts`, so the tautological block was
// removed.

describe('TRUST_PROXY misconfiguration does not silently collapse counters (F3.2)', () => {
  // Sanity check: when `trust proxy` is enabled, req.ip honors X-Forwarded-For.
  // When it is NOT enabled, req.ip is always the socket's remote address. In
  // neither case should we ever see the literal `'127.0.0.1'` fallback.
  it('req.ip follows socket when trust proxy is disabled', async () => {
    const observedKeys: string[] = [];
    const limiter = rateLimit({
      windowMs: 60_000,
      limit: 100,
      standardHeaders: true,
      legacyHeaders: false,
      validate: { trustProxy: false, xForwardedForHeader: false, keyGeneratorIpFallback: false },
      keyGenerator: (req: Request) => {
        const k = `t:${resolveClientKey(req) ?? 'NULL'}`;
        observedKeys.push(k);
        return k;
      },
      handler: (_req, res) => {
        res.status(429).json({ error: 'limited' });
      },
    });

    const app = express();
    // NOTE: no `trust proxy` — so X-Forwarded-For is ignored and req.ip = socket IP.
    app.use(limiter);
    app.get('/test', (_req: Request, res: Response) => {
      res.json({ ok: true });
    });

    const res = await request(app).get('/test').set('x-forwarded-for', '1.2.3.4');
    expect(res.status).toBe(200);
    expect(observedKeys[0]).not.toBe('t:NULL');
    // Real socket loopback, normalized by ipKeyGenerator (::ffff:127.0.0.1 →
    // 127.0.0.1, ::1 → ::/64). This is the genuine per-client key, not a hardcoded
    // collapse — the forwarded 1.2.3.4 is (correctly) ignored without trust proxy.
    expect(observedKeys[0]).toMatch(/^t:(127\.0\.0\.1|::\/64)$/);
  });

  it('resolveClientKey returns identical strings for repeated calls on the same request', () => {
    // Deterministic: two back-to-back calls on the same req object must yield
    // the same key. (If we had used crypto.randomBytes as a fallback, the
    // key would change per call and defeat rate limiting entirely.)
    const req: RawRequest = { socket: { remoteAddress: '198.51.100.9' } };
    const a = resolveClientKey(req as unknown as Request);
    const b = resolveClientKey(req as unknown as Request);
    expect(a).toBe(b);
    expect(a).toBe('198.51.100.9');
  });

  it('does not mutate the request object', () => {
    const req: RawRequest = { ip: '203.0.113.1', socket: { remoteAddress: '10.0.0.5' } };
    const snapshot = JSON.stringify(req);
    resolveClientKey(req as unknown as Request);
    expect(JSON.stringify(req)).toBe(snapshot);
  });
});

describe('resolveClientKey IP-length truncation (F2)', () => {
  it('clamps an oversized req.ip to MAX_IP_ADDRESS_LENGTH (45) characters', () => {
    const req: RawRequest = { ip: 'A'.repeat(500), socket: { remoteAddress: '10.0.0.5' } };
    const key = resolveClientKey(req as unknown as Request);
    expect(key).not.toBeNull();
    expect(key!.length).toBe(45);
    expect(key).toBe('A'.repeat(45));
  });

  it('clamps an oversized socket.remoteAddress fallback to 45 characters', () => {
    const req: RawRequest = { socket: { remoteAddress: 'C'.repeat(500) } };
    const key = resolveClientKey(req as unknown as Request);
    expect(key).not.toBeNull();
    expect(key!.length).toBe(45);
    expect(key).toBe('C'.repeat(45));
  });

  it('preserves IPs already at or below the cap unchanged', () => {
    // A plain IPv4 address is returned unchanged (ipKeyGenerator only masks IPv6).
    const ipv4 = '192.168.1.1';
    const req1: RawRequest = { ip: ipv4, socket: {} };
    expect(resolveClientKey(req1 as unknown as Request)).toBe(ipv4);

    // A v4-mapped IPv6 is normalized to its plain IPv4 form (well under 45 chars).
    const req2: RawRequest = { ip: '::ffff:192.168.1.1', socket: {} };
    expect(resolveClientKey(req2 as unknown as Request)).toBe('192.168.1.1');

    // An exactly-45-char non-IP value passes through unchanged (not a valid IP,
    // so ipKeyGenerator leaves it be, and it is already at the length cap).
    const exactly45 = 'D'.repeat(45);
    const req3: RawRequest = { ip: exactly45, socket: {} };
    expect(resolveClientKey(req3 as unknown as Request)).toBe(exactly45);
  });

  it('IP-rotation attacks collide into a single bucket once truncated', async () => {
    // Bypass via long-IP rotation (F2): when `TRUST_PROXY=true`, an attacker
    // can send `X-Forwarded-For: <500-char unique suffix>` per request. Before
    // the fix, each unique value produced a distinct rate-limit key, so
    // IP-keyed limiters degraded to "no rate limit". After the fix, every
    // rotated value is sliced to 45 chars — if an attacker reuses the same
    // 45-char prefix, all variants collapse onto one bucket.
    const observedKeys = new Set<string>();
    const limiter = rateLimit({
      windowMs: 60_000,
      limit: 100,
      standardHeaders: true,
      legacyHeaders: false,
      validate: { trustProxy: false, xForwardedForHeader: false, keyGeneratorIpFallback: false },
      keyGenerator: (req: Request) => {
        const key = `attack:${resolveClientKey(req) ?? ''}`;
        observedKeys.add(key);
        return key;
      },
      handler: (_req, res) => {
        res.status(429).json({ error: 'rate limited' });
      },
    });

    const app = express();
    app.set('trust proxy', 1);
    app.use(limiter);
    app.get('/test', (_req: Request, res: Response) => {
      res.json({ ok: true });
    });

    // Three rotated long IPs sharing the same first-45-char prefix. All three
    // must collapse into the same observed key after the slice.
    const prefix = 'F'.repeat(45);
    const r1 = await request(app).get('/test').set('x-forwarded-for', `${prefix}suffix-alpha`);
    const r2 = await request(app).get('/test').set('x-forwarded-for', `${prefix}suffix-beta`);
    const r3 = await request(app).get('/test').set('x-forwarded-for', `${prefix}suffix-gamma`);

    expect(r1.status).toBe(200);
    expect(r2.status).toBe(200);
    expect(r3.status).toBe(200);

    // Without the fix this set would have size 3 (one per spoofed suffix);
    // with the fix it has size 1 because the slice collapses all three.
    expect(observedKeys.size).toBe(1);
    expect(observedKeys.has(`attack:${prefix}`)).toBe(true);
  });

  it('two distinct oversized IPs that diverge before char 45 still produce distinct buckets', async () => {
    // The truncation is purely a length cap, NOT a coalescing of unrelated
    // IPs. Real distinct prefixes must remain distinct buckets so two
    // legitimate clients are not punished by a shared counter.
    const observedKeys = new Set<string>();
    const limiter = rateLimit({
      windowMs: 60_000,
      limit: 100,
      standardHeaders: true,
      legacyHeaders: false,
      validate: { trustProxy: false, xForwardedForHeader: false, keyGeneratorIpFallback: false },
      keyGenerator: (req: Request) => {
        const key = `legit:${resolveClientKey(req) ?? ''}`;
        observedKeys.add(key);
        return key;
      },
      handler: (_req, res) => {
        res.status(429).json({ error: 'rate limited' });
      },
    });

    const app = express();
    app.set('trust proxy', 1);
    app.use(limiter);
    app.get('/test', (_req: Request, res: Response) => {
      res.json({ ok: true });
    });

    // Two oversized IPs that diverge in the first character — distinct
    // truncated buckets expected.
    const a = `A${'X'.repeat(99)}`;
    const b = `B${'X'.repeat(99)}`;
    await request(app).get('/test').set('x-forwarded-for', a);
    await request(app).get('/test').set('x-forwarded-for', b);

    expect(observedKeys.size).toBe(2);
  });
});

describe('resolveClientKey IPv6 /64 subnet aggregation (Finding Q)', () => {
  // The IP-keyed limiters (auth/token/csrf/heavy/health/metrics) key on
  // resolveClientKey. Routing the IP through express-rate-limit's ipKeyGenerator
  // collapses an entire IPv6 /64 into one bucket, so an attacker on a routed
  // allocation cannot rotate the host bits to fragment the limiter into many
  // distinct /128 buckets and bypass it.
  it('maps two distinct /128 addresses in the same /64 to the same key', () => {
    const a: RawRequest = { ip: '2001:db8:abcd:1234::1', socket: {} };
    const b: RawRequest = { ip: '2001:db8:abcd:1234:ffff:ffff:ffff:ffff', socket: {} };
    const keyA = resolveClientKey(a as unknown as Request);
    const keyB = resolveClientKey(b as unknown as Request);
    expect(keyA).toBe(keyB);
    expect(keyA).toBe('2001:db8:abcd:1234::/64');
  });

  it('maps addresses in different /64s to different keys', () => {
    const a: RawRequest = { ip: '2001:db8:abcd:1234::1', socket: {} };
    const b: RawRequest = { ip: '2001:db8:abcd:5678::1', socket: {} };
    const keyA = resolveClientKey(a as unknown as Request);
    const keyB = resolveClientKey(b as unknown as Request);
    expect(keyA).not.toBe(keyB);
    expect(keyA).toBe('2001:db8:abcd:1234::/64');
    expect(keyB).toBe('2001:db8:abcd:5678::/64');
  });

  it('leaves an IPv4 address unchanged (only IPv6 is subnet-masked)', () => {
    const req: RawRequest = { ip: '203.0.113.42', socket: {} };
    expect(resolveClientKey(req as unknown as Request)).toBe('203.0.113.42');
  });

  it('normalizes a v4-mapped IPv6 to its plain IPv4 form', () => {
    const req: RawRequest = { ip: '::ffff:198.51.100.7', socket: {} };
    expect(resolveClientKey(req as unknown as Request)).toBe('198.51.100.7');
  });

  it('normalizes an IPv6 address arriving via the socket fallback too', () => {
    const req: RawRequest = { socket: { remoteAddress: '2001:db8:abcd:1234:aaaa::9' } };
    expect(resolveClientKey(req as unknown as Request)).toBe('2001:db8:abcd:1234::/64');
  });

  it('collapses IPv6 /64 source rotation into a single rate-limit bucket', async () => {
    const observedKeys = new Set<string>();
    const limiter = rateLimit({
      windowMs: 60_000,
      limit: 100,
      standardHeaders: true,
      legacyHeaders: false,
      validate: { trustProxy: false, xForwardedForHeader: false, keyGeneratorIpFallback: false },
      keyGenerator: (req: Request) => {
        const key = `ip6:${resolveClientKey(req) ?? ''}`;
        observedKeys.add(key);
        return key;
      },
      handler: (_req, res) => {
        res.status(429).json({ error: 'rate limited' });
      },
    });

    const app = express();
    app.set('trust proxy', 1);
    app.use(limiter);
    app.get('/test', (_req: Request, res: Response) => {
      res.json({ ok: true });
    });

    // Three different /128 hosts inside the same /64 — an attacker rotating the
    // SLAAC interface identifier. Without the fix each lands in its own bucket;
    // with it all three collapse onto one.
    await request(app).get('/test').set('x-forwarded-for', '2001:db8:1:2::1');
    await request(app).get('/test').set('x-forwarded-for', '2001:db8:1:2::dead');
    await request(app).get('/test').set('x-forwarded-for', '2001:db8:1:2:aaaa:bbbb:cccc:dddd');

    expect(observedKeys.size).toBe(1);
    expect(observedKeys.has('ip6:2001:db8:1:2::/64')).toBe(true);
  });

  it('keeps two different IPv6 /64s in separate buckets', async () => {
    const observedKeys = new Set<string>();
    const limiter = rateLimit({
      windowMs: 60_000,
      limit: 100,
      standardHeaders: true,
      legacyHeaders: false,
      validate: { trustProxy: false, xForwardedForHeader: false, keyGeneratorIpFallback: false },
      keyGenerator: (req: Request) => {
        const key = `ip6:${resolveClientKey(req) ?? ''}`;
        observedKeys.add(key);
        return key;
      },
      handler: (_req, res) => {
        res.status(429).json({ error: 'rate limited' });
      },
    });

    const app = express();
    app.set('trust proxy', 1);
    app.use(limiter);
    app.get('/test', (_req: Request, res: Response) => {
      res.json({ ok: true });
    });

    await request(app).get('/test').set('x-forwarded-for', '2001:db8:1:2::1');
    await request(app).get('/test').set('x-forwarded-for', '2001:db8:1:3::1');

    expect(observedKeys.size).toBe(2);
  });
});
