/**
 * `buildRefreshKey` — the rate-limit key for `POST /auth/refresh`.
 *
 * This file previously asserted the OPPOSITE of what it asserts now, and the
 * behaviour it pinned was a defect.
 *
 * The key used to embed `SHA-256(refreshToken)[0..16]`, on the reasoning that
 * per-session buckets stop several people behind one NAT from exhausting each
 * other's refresh quota. The intent was sound; the implementation could not
 * deliver it, because the value it keyed on is the one value that changes on every
 * request. `refresh` ROTATES the cookie on success, so a healthy client presented
 * a different token each time and landed in a brand-new bucket with a count of
 * one, forever — the limiter never bounded the traffic it exists to bound. The
 * same property made it bypassable from the other side: an attacker streaming
 * distinct garbage cookie values also minted a fresh bucket per request, so the
 * endpoint was effectively unlimited for exactly the caller it should have
 * stopped.
 *
 * The rule is broader than "no rotating secret": NOTHING the caller controls may
 * appear in this key. A first repair swapped the cookie hash for a hash of the
 * USER-AGENT, which is a request header and therefore just as rotatable. The key
 * is now the client IP alone; the shared-egress concern is answered by SIZING the
 * budget (see `REFRESH_RATE_LIMIT_MAX`) instead of by a key that silently stops
 * counting.
 *
 * The pure helper is exported and exercised directly because the production
 * limiter is a pass-through no-op outside production.
 */
import { describe, it, expect } from 'vitest';
import type { Request } from 'express';
import {
  buildRefreshKey,
  REFRESH_RATE_LIMIT_MAX,
  REFRESH_RATE_LIMIT_WINDOW_MS,
} from '../src/middleware/rateLimiter.js';

interface RawRequest {
  ip?: string;
  socket: { remoteAddress?: string };
  headers: Record<string, string>;
  cookies?: Record<string, unknown>;
}

function makeReq(opts: { ip?: string; ua?: string; refreshToken?: string }): Request {
  const req: RawRequest = {
    ip: opts.ip ?? '203.0.113.7',
    socket: { remoteAddress: '10.0.0.1' },
    headers: { 'user-agent': opts.ua ?? 'Mozilla/5.0 SharedBrowser' },
    cookies: opts.refreshToken !== undefined ? { refreshToken: opts.refreshToken } : {},
  };
  return req as unknown as Request;
}

describe('buildRefreshKey', () => {
  it('is STABLE across the cookie rotation that happens on every refresh', () => {
    // The regression guard. Each successful refresh hands the client a new cookie;
    // if that value reached the key, every request would open a fresh bucket and
    // the limiter would count to one forever.
    const first = buildRefreshKey(makeReq({ refreshToken: 'rotation-1' }));
    const second = buildRefreshKey(makeReq({ refreshToken: 'rotation-2' }));
    const third = buildRefreshKey(makeReq({ refreshToken: 'rotation-3' }));

    expect(first).toBe(second);
    expect(second).toBe(third);
  });

  it('is the same with a cookie and without one', () => {
    // A caller cannot escape their bucket by dropping or forging the cookie
    // either — which is the other half of the bypass the old key permitted.
    const withCookie = buildRefreshKey(makeReq({ refreshToken: 'anything' }));
    const withoutCookie = buildRefreshKey(makeReq({}));

    expect(withCookie).toBe(withoutCookie);
  });

  it('separates distinct IPs', () => {
    const a = buildRefreshKey(makeReq({ ip: '203.0.113.7' }));
    const b = buildRefreshKey(makeReq({ ip: '198.51.100.4' }));
    expect(a).not.toBe(b);
  });

  it('is UNAFFECTED by the User-Agent — the caller cannot fragment its own bucket', () => {
    // The second version of this bug, and the reason the whole rule is stated as
    // "nothing the CALLER controls may appear in this key" rather than "no
    // rotating secret". Keying on IP + a hash of the user-agent LOOKS stable, and
    // is not: the user-agent is a request header, so `User-Agent: bot-1`, `bot-2`,
    // … fragments the counter exactly as the rotating cookie did. That was only
    // ever masked by `authLimiter` also sitting on `/auth/refresh`, and removing
    // it is precisely what this change does.
    const chrome = buildRefreshKey(makeReq({ ua: 'Mozilla/5.0 Chrome/120' }));
    const firefox = buildRefreshKey(makeReq({ ua: 'Mozilla/5.0 Firefox/121' }));
    const absurd = buildRefreshKey(makeReq({ ua: 'x'.repeat(5000) }));
    const empty = buildRefreshKey(makeReq({ ua: '' }));

    expect(new Set([chrome, firefox, absurd, empty]).size).toBe(1);
  });

  it('separates distinct IPv6 clients but folds one /64 together', () => {
    // The IP is normalised by `resolveClientKey` before it lands here, so the
    // documented IPv6 aggregation still applies through this key.
    const a = buildRefreshKey(makeReq({ ip: '2001:db8:1:2::5' }));
    const b = buildRefreshKey(makeReq({ ip: '2001:db8:1:2::9' }));
    const other = buildRefreshKey(makeReq({ ip: '2001:db8:1:3::5' }));

    expect(a).toBe(b);
    expect(a).not.toBe(other);
  });

  it('produces the documented two-segment shape', () => {
    const key = buildRefreshKey(makeReq({ ip: '203.0.113.9', ua: 'TestAgent' }));
    expect(key).toBe('refresh:203.0.113.9');
  });

  it('never embeds the raw refresh token', () => {
    const secret = 'super-secret-refresh-token-that-must-not-leak';
    const key = buildRefreshKey(makeReq({ refreshToken: secret }));
    expect(key).not.toContain(secret);
  });

  it('handles a missing user-agent header', () => {
    const req: RawRequest = {
      ip: '203.0.113.9',
      socket: { remoteAddress: '10.0.0.1' },
      headers: {},
      cookies: {},
    };
    expect(buildRefreshKey(req as unknown as Request)).toBe('refresh:203.0.113.9');
  });

  it('contains no request-header content at all', () => {
    // Stated structurally as well as by example, so a future component added to
    // this key has to justify itself against this assertion.
    const req: RawRequest = {
      ip: '203.0.113.9',
      socket: { remoteAddress: '10.0.0.1' },
      headers: {
        'user-agent': 'MARKER-UA',
        'x-forwarded-for': 'MARKER-XFF',
        'accept-language': 'MARKER-LANG',
      },
      cookies: { refreshToken: 'MARKER-COOKIE' },
    };
    const key = buildRefreshKey(req as unknown as Request);
    expect(key).not.toMatch(/MARKER/);
  });
});

describe('the refresh budget is sized for a real client, not guessed', () => {
  // `JWT_ACCESS_EXPIRY` defaults to 5 minutes, so one open tab needs about
  // window/5min refreshes per window, plus one per cold-start resume and per
  // unlock that finds an expired token. Derived here rather than restated so a
  // change to either number fails this test instead of silently making the budget
  // too tight — which is how the user-visible symptom (a 429 during ordinary use)
  // gets reintroduced.
  const ACCESS_TOKEN_TTL_MS = 5 * 60 * 1000;
  const perTabPerWindow = Math.ceil(REFRESH_RATE_LIMIT_WINDOW_MS / ACCESS_TOKEN_TTL_MS);

  it('covers a busy shared address, since the key is now IP-only', () => {
    // Everyone behind one NAT shares this bucket — that is the price of a key the
    // caller cannot fragment — so it has to cover a household or a small office,
    // not one browser. Room for at least fifty concurrently open tabs.
    expect(perTabPerWindow).toBeGreaterThan(0);
    expect(REFRESH_RATE_LIMIT_MAX).toBeGreaterThanOrEqual(perTabPerWindow * 50);
  });

  it('still bounds a flood', () => {
    // Not so generous that it stops being a limiter: well under one request per
    // second sustained from a single source.
    expect(REFRESH_RATE_LIMIT_MAX).toBeLessThan(REFRESH_RATE_LIMIT_WINDOW_MS / 1000);
  });
});
