/**
 * Phase 8 — Task 8.2: CSRF Token Edge Case Tests
 *
 * Tests token expiration, safe method bypass, state-changing method enforcement,
 * missing/malformed tokens, and constant-time comparison.
 */
import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import crypto from 'node:crypto';
import request from 'supertest';
import app from '../src/app.js';
import { createTestUser, authHeader, getCsrf as getCsrfBase } from './helpers.js';

const API = '/api/v1';

async function getCsrf(
  agent: request.SuperTest<request.Test>,
): Promise<{ csrfToken: string; csrfCookie: string }> {
  const { token, cookie } = await getCsrfBase(agent);
  return { csrfToken: token, csrfCookie: cookie };
}

// ─────────────────────────────────────────────────────────────────────────────
// Safe methods bypass CSRF
// ─────────────────────────────────────────────────────────────────────────────

describe('CSRF — safe methods bypass validation', () => {
  let agent: request.SuperTest<request.Test>;

  beforeEach(() => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
  });

  it('GET requests should succeed without CSRF token', async () => {
    const res = await agent.get(`${API}/health`);
    expect(res.status).toBe(200);
  });

  it('GET /csrf-token should succeed without existing CSRF token', async () => {
    const res = await agent.get(`${API}/csrf-token`);
    expect(res.status).toBe(200);
    expect(res.body.data.csrfToken).toBeDefined();
    expect(typeof res.body.data.csrfToken).toBe('string');
  });

  it('HEAD requests should succeed without CSRF token', async () => {
    const res = await agent.head(`${API}/health`);
    expect(res.status).toBe(200);
  });

  it('OPTIONS requests should succeed without CSRF token', async () => {
    const res = await agent.options(`${API}/health`);
    // OPTIONS may return 200 or 204 depending on CORS config
    expect(res.status).toBeLessThan(400);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// State-changing methods require CSRF
// ─────────────────────────────────────────────────────────────────────────────

describe('CSRF — state-changing methods require valid token', () => {
  let agent: request.SuperTest<request.Test>;

  beforeEach(() => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
  });

  it('POST without CSRF token should return 403', async () => {
    const res = await agent.post(`${API}/auth/login`).send({ email: 'a@b.com', authHash: 'x' });
    expect(res.status).toBe(403);
  });

  it('PUT without CSRF token should return 403', async () => {
    const user = await createTestUser();
    const res = await agent
      .put(`${API}/user/settings`)
      .set('Authorization', authHeader(user.accessToken))
      .send({ theme: 'dark' });
    expect(res.status).toBe(403);
  });

  it('DELETE without CSRF token should return 403', async () => {
    const user = await createTestUser();
    const res = await agent
      .delete(`${API}/user`)
      .set('Authorization', authHeader(user.accessToken))
      .send({ password: 'x' });
    expect(res.status).toBe(403);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Token expiration
// ─────────────────────────────────────────────────────────────────────────────

describe('CSRF — token expiration after 24 hours', () => {
  let agent: request.SuperTest<request.Test>;

  beforeEach(() => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should accept a token that is less than 24 hours old', async () => {
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    // Use the token immediately — should be valid
    const res = await agent
      .post(`${API}/auth/login`)
      .set('x-csrf-token', csrfToken)
      .set('Cookie', csrfCookie)
      .send({ email: 'test@example.com', authHash: 'hash' });

    // Should not be 403 (CSRF). Might be 401 or other — that's fine.
    expect(res.status).not.toBe(403);
  });

  it('should reject a token older than 24 hours', async () => {
    // Fetch token at real time
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    // Advance time by 24h + 1 minute
    const now = Date.now();
    vi.useFakeTimers({ now: now + 24 * 60 * 60 * 1000 + 60_000 });

    const res = await agent
      .post(`${API}/auth/login`)
      .set('x-csrf-token', csrfToken)
      .set('Cookie', csrfCookie)
      .send({ email: 'test@example.com', authHash: 'hash' });

    expect(res.status).toBe(403);
  });

  it('expired token should return 403, not 500', async () => {
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const now = Date.now();
    vi.useFakeTimers({ now: now + 25 * 60 * 60 * 1000 });

    const res = await agent
      .post(`${API}/auth/login`)
      .set('x-csrf-token', csrfToken)
      .set('Cookie', csrfCookie)
      .send({ email: 'test@example.com', authHash: 'hash' });

    expect(res.status).toBe(403);
    expect(res.status).not.toBe(500);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Malformed and fabricated tokens
// ─────────────────────────────────────────────────────────────────────────────

describe('CSRF — malformed token handling', () => {
  let agent: request.SuperTest<request.Test>;

  beforeEach(() => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
  });

  it('should reject empty string token', async () => {
    const res = await agent
      .post(`${API}/auth/login`)
      .set('x-csrf-token', '')
      .send({ email: 'a@b.com', authHash: 'x' });
    expect(res.status).toBe(403);
  });

  it('should reject token without dot separator', async () => {
    const res = await agent
      .post(`${API}/auth/login`)
      .set('x-csrf-token', 'nodottoken')
      .send({ email: 'a@b.com', authHash: 'x' });
    expect(res.status).toBe(403);
  });

  it('should reject token with empty HMAC portion', async () => {
    const res = await agent
      .post(`${API}/auth/login`)
      .set('x-csrf-token', '.somepayload')
      .send({ email: 'a@b.com', authHash: 'x' });
    expect(res.status).toBe(403);
  });

  it('should reject token with empty payload', async () => {
    const res = await agent
      .post(`${API}/auth/login`)
      .set('x-csrf-token', 'somehmac.')
      .send({ email: 'a@b.com', authHash: 'x' });
    expect(res.status).toBe(403);
  });

  it('should reject a token signed with a different secret', async () => {
    const timestamp = Date.now().toString(36);
    const randomValue = crypto.randomBytes(32).toString('hex');
    const payload = `${timestamp}:${randomValue}`;
    const hmac = crypto
      .createHmac('sha256', 'wrong-secret-key-that-is-definitely-not-right')
      .update(payload)
      .digest('hex');
    const fakeToken = `${hmac}.${payload}`;

    const res = await agent
      .post(`${API}/auth/login`)
      .set('x-csrf-token', fakeToken)
      .send({ email: 'a@b.com', authHash: 'x' });
    expect(res.status).toBe(403);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Constant-time comparison (verifies timingSafeEqual is used)
// ─────────────────────────────────────────────────────────────────────────────

describe('CSRF — constant-time comparison', () => {
  let agent: request.SuperTest<request.Test>;

  beforeEach(() => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
  });

  it('routes CSRF HMAC verification through crypto.timingSafeEqual (not a fast === )', async () => {
    // A wall-clock timing assertion is unreliable (and meaningless with the fast
    // test HMAC), so assert the security property STRUCTURALLY: the CSRF
    // verification of a bad token must go through crypto.timingSafeEqual — the
    // same node:crypto default export csrf.ts imports. Replacing timingSafeEqual
    // with `expectedHmac === receivedHmac` (a length-leaking / short-circuiting
    // compare) makes the spy uninvoked and turns this red. A rejected CSRF token
    // is dropped at the CSRF middleware before any auth logic runs, so the only
    // timingSafeEqual call in this flow is the CSRF comparison itself.
    const { csrfToken } = await getCsrf(agent);

    const timingSafeSpy = vi.spyOn(crypto, 'timingSafeEqual');
    // Only the 64-byte HMAC hex comparison uses 64-byte buffers (the session-id
    // comparison uses shorter, session-length buffers), so a 64-byte call is a
    // precise fingerprint of the HMAC compare specifically.
    const has64ByteCompare = (): boolean =>
      timingSafeSpy.mock.calls.some(([a]) => (a as Buffer).length === 64);
    try {
      // Fully wrong HMAC.
      const fullyWrong = '0'.repeat(64) + csrfToken.slice(64);
      // HMAC that differs only in the last character (near-miss).
      const hmac = csrfToken.slice(0, 64);
      const lastChar = hmac[63]!;
      const altChar = lastChar === 'a' ? 'b' : 'a';
      const nearlyRight = hmac.slice(0, 63) + altChar + csrfToken.slice(64);

      const res1 = await agent
        .post(`${API}/auth/login`)
        .set('x-csrf-token', fullyWrong)
        .send({ email: 'a@b.com', authHash: 'x' });
      expect(res1.status).toBe(403);
      // The HMAC of the wrong token was compared via crypto.timingSafeEqual over
      // 64-byte buffers. Swapping that compare for `expectedHmac === receivedHmac`
      // removes the only 64-byte call and turns this red.
      expect(has64ByteCompare()).toBe(true);

      timingSafeSpy.mockClear();

      const res2 = await agent
        .post(`${API}/auth/login`)
        .set('x-csrf-token', nearlyRight)
        .send({ email: 'a@b.com', authHash: 'x' });
      expect(res2.status).toBe(403);
      // A near-miss token takes the identical constant-time path (no early-out on
      // the first differing character): the 64-byte HMAC compare runs again.
      expect(has64ByteCompare()).toBe(true);
    } finally {
      timingSafeSpy.mockRestore();
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CSRF cookie behavior
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// Session binding: token must be tied to the refresh-token family
// ─────────────────────────────────────────────────────────────────────────────

describe('CSRF — session binding to refresh-token family', () => {
  it('rejects an anon CSRF token once a refresh cookie is presented', async () => {
    const agent = request(app) as unknown as request.SuperTest<request.Test>;

    const { csrfToken, csrfCookie } = await getCsrf(agent);
    const userA = await createTestUser();

    // Smuggling an authenticated request through with an anon-bound CSRF
    // token must fail — the middleware sees the refresh cookie and computes
    // the expected session id from it, which cannot match the anon id.
    const res = await agent
      .put(`${API}/user/settings`)
      .set('Authorization', authHeader(userA.accessToken))
      .set('x-csrf-token', csrfToken)
      .set('Cookie', `${csrfCookie}; refreshToken=${userA.refreshToken}`)
      .send({ theme: 'dark' });

    expect(res.status).toBe(403);
  });

  it('rejects a CSRF token bound to a different refresh-token family', async () => {
    const agent = request(app) as unknown as request.SuperTest<request.Test>;

    const userA = await createTestUser();
    const userB = await createTestUser();

    // Token issued while user A's refresh cookie is active
    const { token: tokenA, cookie: csrfCookieA } = await getCsrfBase(
      agent,
      `refreshToken=${userA.refreshToken}`,
    );

    // Replaying user A's CSRF token alongside user B's refresh cookie must fail
    const res = await agent
      .put(`${API}/user/settings`)
      .set('Authorization', authHeader(userB.accessToken))
      .set('x-csrf-token', tokenA)
      .set('Cookie', `${csrfCookieA}; refreshToken=${userB.refreshToken}`)
      .send({ theme: 'dark' });

    expect(res.status).toBe(403);
  });

  it('accepts a CSRF token reissued with the active refresh cookie', async () => {
    const agent = request(app) as unknown as request.SuperTest<request.Test>;
    const user = await createTestUser();

    const { token, cookie } = await getCsrfBase(agent, `refreshToken=${user.refreshToken}`);

    const res = await agent
      .put(`${API}/user/settings`)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', token)
      .set('Cookie', `${cookie}; refreshToken=${user.refreshToken}`)
      .send({ theme: 'dark' });

    expect(res.status).toBe(200);
  });
});

describe('CSRF — token endpoint response', () => {
  let agent: request.SuperTest<request.Test>;

  beforeEach(() => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
  });

  it('should return a token in the response body and set __csrf cookie', async () => {
    const res = await agent.get(`${API}/csrf-token`);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.csrfToken).toBeDefined();
    expect(typeof res.body.data.csrfToken).toBe('string');
    expect(res.body.data.csrfToken.length).toBeGreaterThan(10);

    // Check __csrf cookie is set
    const cookies = res.headers['set-cookie'] as string | string[];
    const cookieArr = Array.isArray(cookies) ? cookies : [cookies];
    const csrfCookie = cookieArr.find((c: string) => c.startsWith('__csrf='));
    expect(csrfCookie).toBeDefined();
    expect(csrfCookie).toContain('HttpOnly');
  });

  it('should set the __csrf cookie with Max-Age matching the 24h token TTL', async () => {
    const res = await agent.get(`${API}/csrf-token`);

    const cookies = res.headers['set-cookie'] as string | string[];
    const cookieArr = Array.isArray(cookies) ? cookies : [cookies];
    const csrfCookie = cookieArr.find((c: string) => c.startsWith('__csrf='));
    expect(csrfCookie).toBeDefined();

    // Express serializes `maxAge` into both `Max-Age` (seconds) and `Expires` (HTTP date).
    // 24h = 86400 seconds; allow a small tolerance window to account for rounding.
    const maxAgeMatch = /Max-Age=(\d+)/i.exec(csrfCookie!);
    expect(maxAgeMatch).not.toBeNull();
    const maxAgeSeconds = Number(maxAgeMatch![1]);
    expect(maxAgeSeconds).toBeGreaterThanOrEqual(86_399);
    expect(maxAgeSeconds).toBeLessThanOrEqual(86_400);

    // Expires should also be present and land roughly 24h in the future.
    expect(csrfCookie).toMatch(/Expires=/i);
  });

  it('should generate unique tokens on each request', async () => {
    const res1 = await agent.get(`${API}/csrf-token`);
    const res2 = await agent.get(`${API}/csrf-token`);

    expect(res1.body.data.csrfToken).not.toBe(res2.body.data.csrfToken);
  });
});
