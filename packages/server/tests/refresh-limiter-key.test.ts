/**
 * Task 3.7 — Refresh rate limiter is keyed by IP + UA + refresh-token hash
 * so two devices behind the same NAT (sharing IP and UA) do not collide on
 * a single 5-req/5-min bucket. The pure-key helper `buildRefreshKey` is
 * exported and exercised here directly because the production limiter is a
 * pass-through no-op in test mode.
 */
import { describe, it, expect } from 'vitest';
import type { Request } from 'express';
import { buildRefreshKey } from '../src/middleware/rateLimiter.js';

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

describe('buildRefreshKey (Task 3.7)', () => {
  it('two distinct refresh tokens from the same IP+UA produce distinct keys', () => {
    const reqA = makeReq({ refreshToken: 'token-aaaaaaaaaaaaa' });
    const reqB = makeReq({ refreshToken: 'token-bbbbbbbbbbbbb' });
    const keyA = buildRefreshKey(reqA);
    const keyB = buildRefreshKey(reqB);
    expect(keyA).not.toBe(keyB);
    // Both still share the IP+UA prefix
    expect(keyA.split(':').slice(0, 3).join(':')).toBe(keyB.split(':').slice(0, 3).join(':'));
    // Both contain the trailing 16-hex token-hash segment
    expect(keyA.split(':')).toHaveLength(4);
    expect(keyB.split(':')).toHaveLength(4);
  });

  it('the same refresh token from the same IP+UA hashes to the same key', () => {
    const reqA = makeReq({ refreshToken: 'token-stable' });
    const reqB = makeReq({ refreshToken: 'token-stable' });
    expect(buildRefreshKey(reqA)).toBe(buildRefreshKey(reqB));
  });

  it('falls back to IP+UA-only key when the refresh cookie is missing', () => {
    const noCookieReq: RawRequest = {
      ip: '203.0.113.9',
      socket: { remoteAddress: '10.0.0.1' },
      headers: { 'user-agent': 'TestAgent' },
      cookies: {},
    };
    const key = buildRefreshKey(noCookieReq as unknown as Request);
    expect(key.startsWith('refresh:203.0.113.9:')).toBe(true);
    // No fourth segment — fallback path
    expect(key.split(':')).toHaveLength(3);
  });

  it('does not embed the raw refresh token in the rate-limit key', () => {
    const secret = 'super-secret-refresh-token-that-must-not-leak';
    const key = buildRefreshKey(makeReq({ refreshToken: secret }));
    expect(key).not.toContain(secret);
    // The trailing segment is exactly 16 hex chars (SHA-256 truncation)
    const segments = key.split(':');
    expect(segments[3]).toMatch(/^[0-9a-f]{16}$/);
  });

  it('two devices with same IP+UA but different sessions do not share a bucket key', () => {
    // The motivating scenario from FIX.md Task 3.7: corporate VPN, household
    // — five users sharing identical IP and pinned UA with five distinct
    // refresh tokens. Each must produce a unique key.
    const tokens = ['t1', 't2', 't3', 't4', 't5'];
    const keys = new Set(tokens.map((t) => buildRefreshKey(makeReq({ refreshToken: t }))));
    expect(keys.size).toBe(tokens.length);
  });
});
