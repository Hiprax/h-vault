/**
 * Task 6.1: Password Reset Flow Tests
 *
 * Covers: token expiration, reuse prevention (stateHash), session invalidation
 * after reset (refresh tokens + passwordChangedAt), timing equalization.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { AuditLog } from '../src/models/AuditLog.js';
import {
  createTestUser,
  generateStateHash,
  deriveTestPurposeKey,
  getCsrf as getCsrfBase,
} from './helpers.js';

async function getCsrf(
  agent: request.SuperTest<request.Test>,
): Promise<{ csrfToken: string; csrfCookie: string }> {
  const { token, cookie } = await getCsrfBase(agent);
  return { csrfToken: token, csrfCookie: cookie };
}

const API = '/api/v1';

function resetPayload(overrides: Record<string, unknown> = {}) {
  return {
    newAuthHash: 'brand-new-auth-hash',
    newEncryptedVaultKey: 'new-enc-vault-key',
    newVaultKeyIv: 'new-vault-iv',
    newVaultKeyTag: 'new-vault-tag',
    ...overrides,
  };
}

describe('Password Reset Flow', () => {
  let agent: request.SuperTest<request.Test>;

  beforeEach(() => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
  });

  // ── Token Expiration ──────────────────────────────────────────────────

  describe('expired token rejection', () => {
    it('should reject an expired reset token', async () => {
      const user = await createTestUser();
      const dbUser = await User.findById(user.id).select('+authHash');

      // Sign a token that expires immediately
      const expiredToken = jwt.sign(
        {
          userId: user.id,
          purpose: 'password_reset',
          stateHash: generateStateHash(dbUser!.authHash),
        },
        deriveTestPurposeKey('password_reset'),
        { algorithm: 'HS256', expiresIn: '0s' },
      );

      // Small delay to ensure the token is expired
      await new Promise((r) => setTimeout(r, 50));

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post(`${API}/auth/reset-password`)
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          token: expiredToken,
          email: user.email,
          ...resetPayload(),
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });
  });

  // ── Token Reuse Prevention ────────────────────────────────────────────

  describe('token reuse prevention', () => {
    it('should reject a reset token after the password has already been changed', async () => {
      const user = await createTestUser();
      const dbUser = await User.findById(user.id).select('+authHash');

      const resetToken = jwt.sign(
        {
          userId: user.id,
          purpose: 'password_reset',
          stateHash: generateStateHash(dbUser!.authHash),
        },
        deriveTestPurposeKey('password_reset'),
        { algorithm: 'HS256', expiresIn: '1h' },
      );

      // First use — should succeed
      const { csrfToken: csrf1, csrfCookie: cookie1 } = await getCsrf(agent);
      const res1 = await agent
        .post(`${API}/auth/reset-password`)
        .set('x-csrf-token', csrf1)
        .set('Cookie', cookie1)
        .send({
          token: resetToken,
          email: user.email,
          ...resetPayload(),
        });
      expect(res1.status).toBe(200);

      // Second use of the same token — should fail because authHash changed
      const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);
      const res2 = await agent
        .post(`${API}/auth/reset-password`)
        .set('x-csrf-token', csrf2)
        .set('Cookie', cookie2)
        .send({
          token: resetToken,
          email: user.email,
          ...resetPayload({ newAuthHash: 'yet-another-hash' }),
        });

      expect(res2.status).toBe(400);
      expect(res2.body.success).toBe(false);
    });
  });

  // ── Session Invalidation ──────────────────────────────────────────────

  describe('session invalidation after reset', () => {
    it('should delete all refresh tokens for the user after a successful reset', async () => {
      const user = await createTestUser();
      const dbUser = await User.findById(user.id).select('+authHash');

      // Verify there is at least one refresh token before reset
      const tokensBefore = await RefreshToken.countDocuments({ userId: user.id });
      expect(tokensBefore).toBeGreaterThan(0);

      const resetToken = jwt.sign(
        {
          userId: user.id,
          purpose: 'password_reset',
          stateHash: generateStateHash(dbUser!.authHash),
        },
        deriveTestPurposeKey('password_reset'),
        { algorithm: 'HS256', expiresIn: '1h' },
      );

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post(`${API}/auth/reset-password`)
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          token: resetToken,
          email: user.email,
          ...resetPayload(),
        });

      expect(res.status).toBe(200);

      const tokensAfter = await RefreshToken.countDocuments({ userId: user.id });
      expect(tokensAfter).toBe(0);
    });

    it('should update passwordChangedAt so old JWTs become invalid', async () => {
      const user = await createTestUser();
      const dbUser = await User.findById(user.id).select('+authHash');

      const passwordChangedBefore = dbUser!.passwordChangedAt;

      const resetToken = jwt.sign(
        {
          userId: user.id,
          purpose: 'password_reset',
          stateHash: generateStateHash(dbUser!.authHash),
        },
        deriveTestPurposeKey('password_reset'),
        { algorithm: 'HS256', expiresIn: '1h' },
      );

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      await agent
        .post(`${API}/auth/reset-password`)
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          token: resetToken,
          email: user.email,
          ...resetPayload(),
        });

      const updatedUser = await User.findById(user.id);
      expect(updatedUser!.passwordChangedAt).toBeDefined();
      expect(updatedUser!.passwordChangedAt.getTime()).toBeGreaterThan(
        passwordChangedBefore?.getTime() ?? 0,
      );

      // The new passwordChangedAt should be very recent (within last few seconds)
      expect(Date.now() - updatedUser!.passwordChangedAt.getTime()).toBeLessThan(5000);
    });

    it('should clear failed login attempts and lockout after reset', async () => {
      const user = await createTestUser();

      // Simulate a locked-out user
      await User.findByIdAndUpdate(user.id, {
        $set: {
          failedLoginAttempts: 10,
          lockoutUntil: new Date(Date.now() + 30 * 60 * 1000),
        },
      });

      const dbUser = await User.findById(user.id).select('+authHash');

      const resetToken = jwt.sign(
        {
          userId: user.id,
          purpose: 'password_reset',
          stateHash: generateStateHash(dbUser!.authHash),
        },
        deriveTestPurposeKey('password_reset'),
        { algorithm: 'HS256', expiresIn: '1h' },
      );

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post(`${API}/auth/reset-password`)
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          token: resetToken,
          email: user.email,
          ...resetPayload(),
        });
      expect(res.status).toBe(200);

      const updatedUser = await User.findById(user.id);
      expect(updatedUser!.failedLoginAttempts).toBe(0);
      expect(updatedUser!.lockoutUntil).toBeUndefined();
    });
  });

  // ── Timing Equalization ───────────────────────────────────────────────

  describe('timing equalization', () => {
    it('runs the dummy bcrypt.compare on BOTH the existing- and non-existing-email paths', async () => {
      // The security property is STRUCTURAL, not wall-clock: `forgotPassword`
      // must perform an equal-cost bcrypt.compare regardless of whether the
      // account exists, so response time can't be used to enumerate emails.
      // With BCRYPT_ROUNDS=4 in tests, a millisecond wall-clock budget can never
      // fail (it passes even with the dummy compare deleted). Spying on
      // bcrypt.compare and asserting an identical per-request call count on both
      // branches is what actually catches the enumeration regression.
      const bcrypt = (await import('bcryptjs')).default;
      const user = await createTestUser();

      const compareSpy = vi.spyOn(bcrypt, 'compare');

      const before1 = compareSpy.mock.calls.length;
      const { csrfToken: csrf1, csrfCookie: cookie1 } = await getCsrf(agent);
      await agent
        .post(`${API}/auth/forgot-password`)
        .set('x-csrf-token', csrf1)
        .set('Cookie', cookie1)
        .send({ email: user.email })
        .expect(200);
      const existingCalls = compareSpy.mock.calls.length - before1;

      const before2 = compareSpy.mock.calls.length;
      const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);
      await agent
        .post(`${API}/auth/forgot-password`)
        .set('x-csrf-token', csrf2)
        .set('Cookie', cookie2)
        .send({ email: 'definitely-not-a-user@example.com' })
        .expect(200);
      const nonExistingCalls = compareSpy.mock.calls.length - before2;

      // Exactly one bcrypt.compare per request on BOTH paths. Deleting the dummy
      // compare on the non-existent branch drops nonExistingCalls to 0 → red.
      expect(existingCalls).toBe(1);
      expect(nonExistingCalls).toBe(1);
      expect(existingCalls).toBe(nonExistingCalls);

      compareSpy.mockRestore();
    });
  });

  // ── Edge Cases ────────────────────────────────────────────────────────

  describe('edge cases', () => {
    it('should reject a token with wrong purpose', async () => {
      const user = await createTestUser();

      // Sign a token with a different purpose
      const wrongPurposeToken = jwt.sign(
        {
          userId: user.id,
          purpose: 'email_verification',
          stateHash: 'irrelevant',
        },
        deriveTestPurposeKey('password_reset'),
        { algorithm: 'HS256', expiresIn: '1h' },
      );

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post(`${API}/auth/reset-password`)
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          token: wrongPurposeToken,
          email: user.email,
          ...resetPayload(),
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should reject a token signed with the wrong secret', async () => {
      const user = await createTestUser();

      const badToken = jwt.sign(
        { userId: user.id, purpose: 'password_reset', stateHash: 'x' },
        'completely-wrong-secret-key-for-testing',
        { algorithm: 'HS256', expiresIn: '1h' },
      );

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post(`${API}/auth/reset-password`)
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          token: badToken,
          email: user.email,
          ...resetPayload(),
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should reject when the user associated with the token no longer exists', async () => {
      const user = await createTestUser();
      const dbUser = await User.findById(user.id).select('+authHash');

      const resetToken = jwt.sign(
        {
          userId: user.id,
          purpose: 'password_reset',
          stateHash: generateStateHash(dbUser!.authHash),
        },
        deriveTestPurposeKey('password_reset'),
        { algorithm: 'HS256', expiresIn: '1h' },
      );

      // Delete the user
      await User.findByIdAndDelete(user.id);

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post(`${API}/auth/reset-password`)
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          token: resetToken,
          email: user.email,
          ...resetPayload(),
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should create a password_change audit log on successful reset', async () => {
      const user = await createTestUser();
      const dbUser = await User.findById(user.id).select('+authHash');

      const resetToken = jwt.sign(
        {
          userId: user.id,
          purpose: 'password_reset',
          stateHash: generateStateHash(dbUser!.authHash),
        },
        deriveTestPurposeKey('password_reset'),
        { algorithm: 'HS256', expiresIn: '1h' },
      );

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post(`${API}/auth/reset-password`)
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .set('User-Agent', 'test-agent')
        .send({
          token: resetToken,
          email: user.email,
          ...resetPayload(),
        });
      expect(res.status).toBe(200);

      const auditEntry = await AuditLog.findOne({
        userId: user.id,
        action: 'password_change',
      }).lean();
      expect(auditEntry).not.toBeNull();
      expect(auditEntry!.metadata).toEqual(expect.objectContaining({ method: 'reset' }));
    });
  });
});
