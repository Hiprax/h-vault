/**
 * T14 — `accountLimiter` key/skip helpers must tolerate a missing request body.
 *
 * In Express 5 (body-parser 2.x) a request with a non-JSON `Content-Type`
 * (e.g. `text/plain`) or no body leaves `req.body === undefined`. `accountLimiter`
 * is the first middleware on `POST /login` to touch the body (it runs before
 * `validate`), so an unguarded `(req.body as …).email` would throw a `TypeError`
 * and surface as an HTTP 500 in production — the limiter is a pass-through no-op
 * in test/dev mode, so this path is only reachable in production.
 *
 * The pure helpers `buildAccountKey` and `skipAccountLimiter` are exported and
 * exercised here directly because the production limiter cannot be driven from
 * test mode. Each helper reads the email through an optional chain so an
 * undefined body never throws.
 */
import { describe, it, expect } from 'vitest';
import type { Request } from 'express';
import { buildAccountKey, skipAccountLimiter } from '../src/middleware/rateLimiter.js';

interface RawRequest {
  ip?: string;
  body?: unknown;
  socket: { remoteAddress?: string };
}

function makeReq(opts: { ip?: string; body?: unknown; remoteAddress?: string }): Request {
  const req: RawRequest = {
    socket: { remoteAddress: opts.remoteAddress ?? '10.0.0.1' },
    body: opts.body,
    ...(opts.ip !== undefined ? { ip: opts.ip } : {}),
  };
  return req as unknown as Request;
}

describe('buildAccountKey (T14)', () => {
  it('does NOT throw when req.body is undefined (non-JSON / bodyless request)', () => {
    const req = makeReq({ ip: '203.0.113.7', body: undefined });
    expect(() => buildAccountKey(req)).not.toThrow();
    // Falls back to the IP-keyed no-email bucket.
    expect(buildAccountKey(req)).toBe('account:no-email:203.0.113.7');
  });

  it('keys on lowercased email when present', () => {
    const req = makeReq({ ip: '203.0.113.7', body: { email: 'USER@Test.Com' } });
    expect(buildAccountKey(req)).toBe('account:email:user@test.com');
  });

  it('falls back to the no-email IP key when email is an empty string', () => {
    const req = makeReq({ ip: '203.0.113.9', body: { email: '' } });
    expect(buildAccountKey(req)).toBe('account:no-email:203.0.113.9');
  });

  it('falls back to the no-email IP key when email is a non-string', () => {
    expect(buildAccountKey(makeReq({ ip: '198.51.100.1', body: { email: 12345 } }))).toBe(
      'account:no-email:198.51.100.1',
    );
    expect(buildAccountKey(makeReq({ ip: '198.51.100.1', body: { email: null } }))).toBe(
      'account:no-email:198.51.100.1',
    );
  });

  it('uses resolveClientKey (socket fallback) when req.ip is absent', () => {
    const req = makeReq({ body: undefined, remoteAddress: '172.16.0.4' });
    expect(buildAccountKey(req)).toBe('account:no-email:172.16.0.4');
  });

  it('does not embed the raw email casing in the email key', () => {
    const key = buildAccountKey(makeReq({ ip: '203.0.113.7', body: { email: 'Mixed@CASE.io' } }));
    expect(key).toBe('account:email:mixed@case.io');
  });

  it('does NOT throw for non-object primitive bodies (text/plain string, number, boolean, array)', () => {
    const bodies: unknown[] = ['plaintext-body', 42, true, ['x'], null];
    for (const body of bodies) {
      const req = makeReq({ ip: '203.0.113.7', body });
      expect(() => buildAccountKey(req)).not.toThrow();
      expect(buildAccountKey(req)).toBe('account:no-email:203.0.113.7');
    }
  });
});

describe('skipAccountLimiter (T14)', () => {
  it('does NOT throw and returns true when req.body is undefined', () => {
    const req = makeReq({ body: undefined });
    expect(() => skipAccountLimiter(req)).not.toThrow();
    expect(skipAccountLimiter(req)).toBe(true);
  });

  it('returns true when the email field is missing entirely', () => {
    expect(skipAccountLimiter(makeReq({ body: { password: 'x' } }))).toBe(true);
  });

  it('returns true when email is an empty string', () => {
    expect(skipAccountLimiter(makeReq({ body: { email: '' } }))).toBe(true);
  });

  it('returns true when email is a non-string type', () => {
    expect(skipAccountLimiter(makeReq({ body: { email: 42 } }))).toBe(true);
    expect(skipAccountLimiter(makeReq({ body: { email: true } }))).toBe(true);
    expect(skipAccountLimiter(makeReq({ body: { email: null } }))).toBe(true);
  });

  it('returns false (counts the request) when a valid email is present', () => {
    expect(skipAccountLimiter(makeReq({ body: { email: 'user@test.com' } }))).toBe(false);
  });

  it('returns true (no throw) for non-object primitive bodies', () => {
    const bodies: unknown[] = ['plaintext-body', 42, true, ['x'], null];
    for (const body of bodies) {
      const req = makeReq({ body });
      expect(() => skipAccountLimiter(req)).not.toThrow();
      expect(skipAccountLimiter(req)).toBe(true);
    }
  });
});
