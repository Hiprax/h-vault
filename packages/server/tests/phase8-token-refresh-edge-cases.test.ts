/**
 * Phase 8 — Task 8.3: Token Refresh Edge Case Tests
 *
 * Tests refresh token rotation preserving familyId, entire family revocation
 * on reuse, expired token handling, deleted user, and concurrent refresh.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import crypto from 'node:crypto';
import request from 'supertest';
import app from '../src/app.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { User } from '../src/models/User.js';
import { hashToken } from '../src/utils/token.js';
import { createTestUser, getCsrf as getCsrfBase } from './helpers.js';
import type { TestUser, CsrfPair } from './helpers.js';

const API = '/api/v1';

function withCsrf(
  req: request.Test,
  csrf: CsrfPair,
  accessToken?: string,
  extraCookies?: string,
): request.Test {
  const cookies = extraCookies ? `${csrf.cookie}; ${extraCookies}` : csrf.cookie;
  let r = req.set('x-csrf-token', csrf.token).set('Cookie', cookies);
  if (accessToken) {
    r = r.set('Authorization', `Bearer ${accessToken}`);
  }
  return r;
}

/**
 * Extracts the raw refresh token from a Set-Cookie header array.
 */
function extractRefreshToken(setCookieHeaders: string | string[] | undefined): string | null {
  const cookies = Array.isArray(setCookieHeaders)
    ? setCookieHeaders
    : setCookieHeaders
      ? [setCookieHeaders]
      : [];
  const refreshCookie = cookies.find((c: string) => c.startsWith('refreshToken='));
  if (!refreshCookie) return null;
  const value = refreshCookie.split(';')[0]!.replace('refreshToken=', '');
  // Ignore cookie-clear directives (empty or expired)
  return value || null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Rotation preserves familyId
// ─────────────────────────────────────────────────────────────────────────────

describe('Token refresh — rotation preserves familyId', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  it('new refresh token should have the same familyId as the original', async () => {
    // Get the familyId of the original token
    const originalToken = await RefreshToken.findOne({
      tokenHash: hashToken(user.refreshToken),
    }).lean();
    expect(originalToken).toBeDefined();
    const originalFamilyId = originalToken!.familyId;

    // Perform a refresh
    const agent = request.agent(app);
    const csrf = await getCsrfBase(agent, `refreshToken=${user.refreshToken}`);

    const res = await withCsrf(
      agent.post(`${API}/auth/refresh`),
      csrf,
      undefined,
      `refreshToken=${user.refreshToken}`,
    );

    expect(res.status).toBe(200);
    expect(res.body.data.accessToken).toBeDefined();

    // Extract the new refresh token
    const newRawToken = extractRefreshToken(res.headers['set-cookie']);
    expect(newRawToken).not.toBeNull();

    // The new token should share the same familyId
    const newToken = await RefreshToken.findOne({
      tokenHash: hashToken(newRawToken!),
    }).lean();
    expect(newToken).toBeDefined();
    expect(newToken!.familyId).toBe(originalFamilyId);
  });

  it('original token should be marked as used after rotation', async () => {
    const agent = request.agent(app);
    const csrf = await getCsrfBase(agent, `refreshToken=${user.refreshToken}`);

    await withCsrf(
      agent.post(`${API}/auth/refresh`),
      csrf,
      undefined,
      `refreshToken=${user.refreshToken}`,
    ).expect(200);

    const original = await RefreshToken.findOne({
      tokenHash: hashToken(user.refreshToken),
    }).lean();
    expect(original).toBeDefined();
    expect(original!.usedAt).toBeDefined();
    expect(original!.usedAt).toBeInstanceOf(Date);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Reuse detection: entire family revocation
// ─────────────────────────────────────────────────────────────────────────────

describe('Token refresh — reuse detection revokes entire family', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  it('reusing old token should revoke entire family so new token also fails', async () => {
    // Capture the family id BEFORE any rotation. After the family is revoked
    // every token row is deleted, so looking the family up AFTERWARDS (as the
    // old code did) always yields undefined and the "no tokens remain" check
    // silently never runs. Reading it up front lets us assert unconditionally.
    const rt1Doc = await RefreshToken.findOne({
      tokenHash: hashToken(user.refreshToken),
    }).lean();
    expect(rt1Doc).not.toBeNull();
    const familyId = rt1Doc!.familyId;
    expect(familyId).toBeTruthy();

    // Step 1: Rotate RT1 → RT2
    const agent1 = request(app) as unknown as request.SuperTest<request.Test>;
    const csrf1 = await getCsrfBase(agent1, `refreshToken=${user.refreshToken}`);

    const rotateRes = await withCsrf(
      agent1.post(`${API}/auth/refresh`),
      csrf1,
      undefined,
      `refreshToken=${user.refreshToken}`,
    );
    expect(rotateRes.status).toBe(200);

    const rt2 = extractRefreshToken(rotateRes.headers['set-cookie']);
    expect(rt2).not.toBeNull();

    // Step 2: Reuse RT1 (the old, already-used token)
    const agent2 = request(app) as unknown as request.SuperTest<request.Test>;
    const csrf2 = await getCsrfBase(agent2, `refreshToken=${user.refreshToken}`);

    const reuseRes = await withCsrf(
      agent2.post(`${API}/auth/refresh`),
      csrf2,
      undefined,
      `refreshToken=${user.refreshToken}`,
    );
    expect(reuseRes.status).toBe(401);

    // Step 3: Try RT2 — should also fail because the family was revoked
    const agent3 = request(app) as unknown as request.SuperTest<request.Test>;
    const csrf3 = await getCsrfBase(agent3, `refreshToken=${rt2!}`);

    const rt2Res = await withCsrf(
      agent3.post(`${API}/auth/refresh`),
      csrf3,
      undefined,
      `refreshToken=${rt2!}`,
    );
    expect(rt2Res.status).toBe(401);

    // Reuse detection revokes the ENTIRE family (deleteMany by userId+familyId),
    // so no token row from this family may remain — including RT2. Asserted
    // unconditionally against the family id captured before rotation.
    const remaining = await RefreshToken.countDocuments({ familyId });
    expect(remaining).toBe(0);
    // And specifically neither the reused RT1 nor the rotated RT2 survives.
    expect(await RefreshToken.countDocuments({ tokenHash: hashToken(user.refreshToken) })).toBe(0);
    expect(await RefreshToken.countDocuments({ tokenHash: hashToken(rt2!) })).toBe(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Expired tokens
// ─────────────────────────────────────────────────────────────────────────────

describe('Token refresh — expired tokens', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  it('should return 401 for expired refresh token', async () => {
    // Manually expire the token in the database
    await RefreshToken.updateOne(
      { tokenHash: hashToken(user.refreshToken) },
      { $set: { expiresAt: new Date(Date.now() - 1000) } },
    );

    const agent = request(app) as unknown as request.SuperTest<request.Test>;
    const csrf = await getCsrfBase(agent, `refreshToken=${user.refreshToken}`);

    const res = await withCsrf(
      agent.post(`${API}/auth/refresh`),
      csrf,
      undefined,
      `refreshToken=${user.refreshToken}`,
    );

    expect(res.status).toBe(401);
  });

  it('expired token should not trigger family revocation', async () => {
    // Get the familyId
    const tokenDoc = await RefreshToken.findOne({
      tokenHash: hashToken(user.refreshToken),
    }).lean();
    const familyId = tokenDoc!.familyId;

    // Create a second valid token in the same family
    const secondRaw = crypto.randomBytes(64).toString('hex');
    await RefreshToken.create({
      userId: user.id,
      tokenHash: hashToken(secondRaw),
      familyId,
      deviceInfo: { userAgent: 'test', ip: '127.0.0.1', fingerprint: 'fp' },
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    // Expire the first token
    await RefreshToken.updateOne(
      { tokenHash: hashToken(user.refreshToken) },
      { $set: { expiresAt: new Date(Date.now() - 1000) } },
    );

    // Try to use the expired token
    const agent = request(app) as unknown as request.SuperTest<request.Test>;
    const csrf = await getCsrfBase(agent, `refreshToken=${user.refreshToken}`);

    await withCsrf(
      agent.post(`${API}/auth/refresh`),
      csrf,
      undefined,
      `refreshToken=${user.refreshToken}`,
    ).expect(401);

    // The second token should NOT be revoked (family not deleted)
    const secondStillExists = await RefreshToken.findOne({
      tokenHash: hashToken(secondRaw),
    }).lean();
    expect(secondStillExists).toBeDefined();
    expect(secondStillExists!.usedAt).toBeFalsy();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Deleted / missing user
// ─────────────────────────────────────────────────────────────────────────────

describe('Token refresh — deleted user', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  it('should fail when user is deleted after token was issued', async () => {
    // Delete the user while keeping the refresh token in DB
    await User.deleteOne({ _id: user.id });

    const agent = request(app) as unknown as request.SuperTest<request.Test>;
    const csrf = await getCsrfBase(agent, `refreshToken=${user.refreshToken}`);

    const res = await withCsrf(
      agent.post(`${API}/auth/refresh`),
      csrf,
      undefined,
      `refreshToken=${user.refreshToken}`,
    );

    expect(res.status).toBe(401);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Concurrent refresh with same token
// ─────────────────────────────────────────────────────────────────────────────

describe('Token refresh — concurrent requests with same token', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  it('concurrent refreshes: at most one should succeed, the other should fail safely', async () => {
    // Fire two refresh requests simultaneously using the same token
    const agent1 = request(app) as unknown as request.SuperTest<request.Test>;
    const agent2 = request(app) as unknown as request.SuperTest<request.Test>;

    const csrf1 = await getCsrfBase(agent1, `refreshToken=${user.refreshToken}`);
    const csrf2 = await getCsrfBase(agent2, `refreshToken=${user.refreshToken}`);

    const [res1, res2] = await Promise.all([
      withCsrf(
        agent1.post(`${API}/auth/refresh`),
        csrf1,
        undefined,
        `refreshToken=${user.refreshToken}`,
      ),
      withCsrf(
        agent2.post(`${API}/auth/refresh`),
        csrf2,
        undefined,
        `refreshToken=${user.refreshToken}`,
      ),
    ]);

    const statuses = [res1.status, res2.status].sort();

    // At most one succeeds (200), the other fails (401)
    // Both could also fail (401, 401) in a race condition — both are safe outcomes
    if (statuses[0] === 200) {
      expect(statuses[1]).toBe(401);
    } else {
      // Both failed — also acceptable (means atomic claim rejected both)
      expect(statuses[0]).toBe(401);
      expect(statuses[1]).toBe(401);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Missing / invalid token
// ─────────────────────────────────────────────────────────────────────────────

describe('Token refresh — missing and invalid tokens', () => {
  beforeEach(async () => {
    await createTestUser();
  });

  it('should return 401 when no refresh cookie is provided', async () => {
    const agent = request(app) as unknown as request.SuperTest<request.Test>;
    const csrf = await getCsrfBase(agent);

    const res = await withCsrf(agent.post(`${API}/auth/refresh`), csrf);

    expect(res.status).toBe(401);
  });

  it('should return 401 for a completely fabricated refresh token', async () => {
    const fakeToken = crypto.randomBytes(64).toString('hex');

    const agent = request(app) as unknown as request.SuperTest<request.Test>;
    const csrf = await getCsrfBase(agent, `refreshToken=${fakeToken}`);

    const res = await withCsrf(
      agent.post(`${API}/auth/refresh`),
      csrf,
      undefined,
      `refreshToken=${fakeToken}`,
    );

    expect(res.status).toBe(401);
  });
});
