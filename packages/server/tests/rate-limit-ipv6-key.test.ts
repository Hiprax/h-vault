/**
 * The IPv6 bucketing contract of the rate-limit key path.
 *
 * `resolveClientKey` routes every IP-keyed limiter's key through
 * express-rate-limit's `ipKeyGenerator(ip, IPV6_RATE_LIMIT_SUBNET)`, which is
 * implemented on top of the `ip-address` package. That makes `ip-address` a
 * security dependency rather than a transitive detail: it decides which bucket a
 * request counts against, and therefore whether an attacker can obtain a fresh
 * budget by changing something they control.
 *
 * These tests pin the bucketing behaviour of that path across a dependency bump,
 * where `rate-limit-client-key.test.ts` pins the *resolution* behaviour of
 * `resolveClientKey` itself (req.ip → socket fallback → null, and the length
 * clamp). The two invariants asserted here are:
 *
 *   1. One address is one bucket. Re-spelling an address — case, zero
 *      compression, an expanded prefix — must not move it, or the spelling is a
 *      free bucket.
 *   2. One /64 is one bucket, and two /64s are two. The low 64 bits of a routed
 *      IPv6 allocation are the interface identifier and are fully host-chosen,
 *      so a per-/128 key is not a limit at all.
 *
 * Both are asserted through the counter the limiter actually enforces (a 429),
 * not only through the key string, so a change that leaves the key looking right
 * while splitting the budget still fails.
 */
import { describe, it, expect } from 'vitest';
import express from 'express';
import type { Request, Response } from 'express';
import request from 'supertest';
import { rateLimit } from 'express-rate-limit';
import { resolveClientKey } from '../src/middleware/rateLimiter.js';

const keyFor = (ip: string): string | null =>
  resolveClientKey({ ip, socket: {} } as unknown as Request);

/**
 * A limiter keyed exactly as production keys, with a budget of 2, plus the set
 * of keys it observed. `limit` is deliberately small: the assertions below are
 * on the enforced 429, so the test fails if two addresses that must share a
 * budget silently get one each.
 */
function limiterApp(limit: number) {
  const observedKeys = new Set<string>();
  const limiter = rateLimit({
    windowMs: 60_000,
    limit,
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
  // `trust proxy` is how the shipped stack runs (TRUST_PROXY_HOPS defaults to 2
  // in docker-compose.yml), and it is what makes the address a *request-supplied*
  // string rather than a socket fact — which is precisely why the bucketing rule
  // has to hold for spellings a client can choose, not just for the canonical
  // form Node produces.
  app.set('trust proxy', 1);
  app.use(limiter);
  app.get('/test', (_req: Request, res: Response) => {
    res.json({ ok: true });
  });
  return { app, observedKeys };
}

describe('IPv4-mapped addresses key to the address they actually reach', () => {
  it('puts an IPv4-mapped address in the same bucket as the native IPv4 client', () => {
    // ::ffff:192.0.2.1 IS 192.0.2.1 reached over a v6 socket. Keying it
    // separately would hand every dual-stack client two budgets.
    expect(keyFor('::ffff:192.0.2.1')).toBe(keyFor('192.0.2.1'));
    expect(keyFor('::ffff:192.0.2.1')).toBe('192.0.2.1');
    // The negative that matters: it must NOT fall into the ::/64 network bucket,
    // which every unrouted v6 form shares — that would merge unrelated clients
    // into one counter and let any of them exhaust it for the rest.
    expect(keyFor('::ffff:192.0.2.1')).not.toBe('::/64');
  });

  it('does not give a second budget to an uppercase or expanded spelling of one address', () => {
    // Same 128 bits, three spellings. Express hands req.ip to the key generator
    // verbatim, so a client behind the trusted proxy chain chooses the spelling.
    const canonical = keyFor('::ffff:192.0.2.1');
    expect(keyFor('::FFFF:192.0.2.1')).toBe(canonical);
    expect(keyFor('0:0:0:0:0:ffff:192.0.2.1')).toBe(canonical);
  });

  it('keeps two different IPv4-mapped addresses in two buckets', () => {
    expect(keyFor('::ffff:192.0.2.1')).not.toBe(keyFor('::ffff:192.0.2.2'));
  });
});

describe('IPv6 /64 aggregation survives the NAT64 well-known prefix', () => {
  it('collapses NAT64 (64:ff9b::/96) traffic to its /64 network bucket', () => {
    // RFC 6052's well-known prefix. Two synthesised addresses differing only in
    // the embedded IPv4 sit in one /64 and must count against one budget.
    expect(keyFor('64:ff9b::c000:201')).toBe('64:ff9b::/64');
    expect(keyFor('64:ff9b::c633:6401')).toBe('64:ff9b::/64');
  });

  it('keeps NAT64 traffic out of the buckets of ordinary global unicast /64s', () => {
    expect(keyFor('64:ff9b::c000:201')).not.toBe(keyFor('2001:db8:1:2::c000:201'));
    expect(keyFor('2001:db8:1:2::c000:201')).toBe('2001:db8:1:2::/64');
    expect(keyFor('2001:db8:1:3::c000:201')).toBe('2001:db8:1:3::/64');
  });
});

describe('the enforced counter, not just the key string', () => {
  it('spends one budget for an attacker rotating the interface identifier inside one /64', async () => {
    const { app, observedKeys } = limiterApp(2);

    // Three requests, three distinct /128s, one routed /64 — an attacker
    // rotating SLAAC host bits. The third must be refused: that is the whole
    // point of masking, and it is what a per-/128 key would silently lose.
    const first = await request(app).get('/test').set('x-forwarded-for', '2001:db8:1:2::1');
    const second = await request(app).get('/test').set('x-forwarded-for', '2001:db8:1:2::dead');
    const third = await request(app)
      .get('/test')
      .set('x-forwarded-for', '2001:db8:1:2:aaaa:bbbb:cccc:dddd');

    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(third.status).toBe(429);
    expect(observedKeys).toEqual(new Set(['ip6:2001:db8:1:2::/64']));
  });

  it('does not spend one client’s budget on another /64', async () => {
    const { app, observedKeys } = limiterApp(2);

    // The neighbour /64 has burned its whole budget; this client is a different
    // network and must still be served.
    await request(app).get('/test').set('x-forwarded-for', '2001:db8:1:2::1');
    await request(app).get('/test').set('x-forwarded-for', '2001:db8:1:2::2');
    const exhausted = await request(app).get('/test').set('x-forwarded-for', '2001:db8:1:2::3');
    const neighbour = await request(app).get('/test').set('x-forwarded-for', '2001:db8:1:3::1');

    expect(exhausted.status).toBe(429);
    expect(neighbour.status).toBe(200);
    expect(observedKeys).toEqual(new Set(['ip6:2001:db8:1:2::/64', 'ip6:2001:db8:1:3::/64']));
  });
});
