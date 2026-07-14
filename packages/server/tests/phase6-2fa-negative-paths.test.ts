/**
 * Phase 6 — Task 6.2: 2FA Negative Path Tests
 *
 * Covers scenarios not already exercised by auth.test.ts, user.test.ts,
 * security-fixes.test.ts, or backup-code-consumption.test.ts:
 *   • Device hash mismatch on login/2fa.
 *   • Disable 2FA with a backup code (TOTP required).
 *   • verify2fa with a TOTP code from a different (stale) secret.
 *   • Brute-force attempts against backup codes (all wrong).
 *   • 2FA completion blocked by account lockout (defense-in-depth).
 *   • Login 2FA when user has 2FA disabled (no twoFactorEnabled flag).
 *   • Disable 2FA when 2FA is not enabled.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { TOTP, Secret } from 'otpauth';
import { CryptoManager } from '@hiprax/crypto';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import {
  createTestUser,
  authHeader,
  deriveTestPurposeKey,
  getCsrf,
  type TestUser,
} from './helpers.js';

const API = '/api/v1';
const BCRYPT_ROUNDS = 4;
const cm = new CryptoManager();
const encKey = process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345';

/** Creates a 2FA-enabled user with the provided raw backup codes. */
async function create2faUser(rawCodes: string[] = []): Promise<{
  user: TestUser;
  secretObj: Secret;
}> {
  const secretObj = new Secret();
  const encryptedSecret = cm.encryptTextSync(secretObj.base32, encKey);
  const user = await createTestUser({ emailVerified: true });

  const hashedCodes = await Promise.all(rawCodes.map((c) => bcrypt.hash(c, BCRYPT_ROUNDS)));

  await User.findByIdAndUpdate(user.id, {
    $set: {
      twoFactorEnabled: true,
      twoFactorSecret: encryptedSecret,
      backupCodes: hashedCodes,
      lastTotpTimestamp: 1, // Old timestamp so fresh codes are accepted
    },
  });

  return { user, secretObj };
}

function makeTempToken(userId: string, options: { deviceHash?: string } = {}): string {
  const payload: Record<string, unknown> = { userId, purpose: '2fa_temp' };
  if (options.deviceHash !== undefined) payload['deviceHash'] = options.deviceHash;
  return jwt.sign(payload, deriveTestPurposeKey('2fa_temp'), { expiresIn: '5m' });
}

describe('Phase 6 — 2FA Negative Paths', () => {
  let agent: request.SuperTest<request.Test>;

  beforeEach(() => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
  });

  // ── Device hash mismatch ─────────────────────────────────────────────

  describe('login/2fa device hash mismatch', () => {
    /**
     * Obtains a REAL, server-bound temp token by logging in with a specific
     * User-Agent. The server itself computes deviceHash = sha256(req.ip|UA), so
     * the token is bound to the actual request device — unlike a hand-fabricated
     * hash from a fake IP, which mismatches on the IP component alone and never
     * exercises the User-Agent half of the binding.
     */
    async function loginForTempToken(user: TestUser, userAgent: string): Promise<string> {
      const { token: csrfToken, cookie: csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post(`${API}/auth/login`)
        .set('User-Agent', userAgent)
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ email: user.email, authHash: user.rawPassword });
      expect(res.status).toBe(200);
      expect(res.body.data.twoFactorRequired).toBe(true);
      return res.body.data.tempToken as string;
    }

    it('should reject when the 2FA request comes from a different User-Agent than the temp token', async () => {
      const { user, secretObj } = await create2faUser([]);

      // Bind the temp token to Device A (same loopback IP the whole agent uses).
      const tempToken = await loginForTempToken(user, 'DeviceA/1.0');

      const totp = new TOTP({ algorithm: 'SHA1', digits: 6, period: 30, secret: secretObj });
      const validCode = totp.generate();

      // Submit from Device B — SAME IP, DIFFERENT User-Agent. The only thing that
      // differs is the UA, so this exercises the User-Agent half of the binding:
      // if generateDeviceHash dropped the UA, the same-IP request would MATCH and
      // succeed, and this expectation would fail.
      const { token: csrfToken, cookie: csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post(`${API}/auth/login/2fa`)
        .set('User-Agent', 'DeviceB/2.0')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ tempToken, code: validCode });

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);

      // No successful login audit for this user.
      const loginSuccess = await (
        await import('../src/models/AuditLog.js')
      ).AuditLog.findOne({
        userId: user.id,
        action: 'login',
      });
      expect(loginSuccess).toBeNull();
    });

    it('should ACCEPT the 2FA request from the SAME User-Agent the temp token was bound to (positive control)', async () => {
      const { user, secretObj } = await create2faUser([]);

      const tempToken = await loginForTempToken(user, 'DeviceA/1.0');

      const totp = new TOTP({ algorithm: 'SHA1', digits: 6, period: 30, secret: secretObj });
      const validCode = totp.generate();

      // Same IP AND same User-Agent → device hash matches → login completes. This
      // control ensures the negative test above fails for the RIGHT reason (UA
      // mismatch), not because the request is broken for some unrelated cause.
      const { token: csrfToken, cookie: csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post(`${API}/auth/login/2fa`)
        .set('User-Agent', 'DeviceA/1.0')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ tempToken, code: validCode });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.accessToken).toBeDefined();
    });
  });

  // ── Disable 2FA with backup code ─────────────────────────────────────

  describe('disable 2FA with backup code', () => {
    it('should reject a backup code (TOTP is required for disable)', async () => {
      const rawCode = 'abcdef1234567890';
      const { user } = await create2faUser([rawCode]);

      const { token: csrfToken, cookie: csrfCookie } = await getCsrf(agent);
      const res = await agent
        .delete(`${API}/user/2fa`)
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: user.rawPassword, code: rawCode });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);

      // 2FA must still be enabled
      const refreshed = await User.findById(user.id);
      expect(refreshed!.twoFactorEnabled).toBe(true);
    });
  });

  // ── verify2fa with a code from a different (stale) secret ────────────

  describe('verify2fa with code from wrong secret', () => {
    it('should reject a TOTP generated from a secret unrelated to the pending one', async () => {
      const user = await createTestUser({ emailVerified: true });

      // Start setup — this stores a pending secret on the user record
      const { token: csrfToken1, cookie: csrfCookie1 } = await getCsrf(agent);
      const setupRes = await agent
        .post(`${API}/user/2fa/setup`)
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken1)
        .set('Cookie', csrfCookie1)
        .send({ password: user.rawPassword });
      expect(setupRes.status).toBe(200);

      // Generate a TOTP from an UNRELATED secret — attacker does not know the
      // pending one stashed on the user record.
      const unrelatedSecret = new Secret();
      const unrelatedTotp = new TOTP({
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: unrelatedSecret,
      });
      const attackerCode = unrelatedTotp.generate();

      const { token: csrfToken2, cookie: csrfCookie2 } = await getCsrf(agent);
      const verifyRes = await agent
        .post(`${API}/user/2fa/verify`)
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken2)
        .set('Cookie', csrfCookie2)
        .send({ code: attackerCode });

      expect(verifyRes.status).toBe(400);
      expect(verifyRes.body.success).toBe(false);

      // 2FA must not have been enabled
      const refreshed = await User.findById(user.id);
      expect(refreshed!.twoFactorEnabled).toBe(false);
    });
  });

  // ── Brute-force wrong backup codes ───────────────────────────────────

  describe('brute-force wrong backup codes', () => {
    it('should reject all 8 wrong attempts and keep backup codes intact', async () => {
      const rawCodes = ['codeaaaa11111111', 'codebbbb22222222', 'codecccc33333333'];
      const { user } = await create2faUser(rawCodes);

      // 8 guesses, none matching any stored hash
      const wrongGuesses = [
        'wrong00000000001',
        'wrong00000000002',
        'wrong00000000003',
        'wrong00000000004',
        'wrong00000000005',
        'wrong00000000006',
        'wrong00000000007',
        'wrong00000000008',
      ];

      for (const guess of wrongGuesses) {
        const tempToken = makeTempToken(user.id);
        const { token: csrfToken, cookie: csrfCookie } = await getCsrf(agent);
        const res = await agent
          .post(`${API}/auth/login/2fa`)
          .set('x-csrf-token', csrfToken)
          .set('Cookie', csrfCookie)
          .send({ tempToken, code: guess });
        expect(res.status).toBe(401);
      }

      // All backup codes must remain intact
      const refreshed = await User.findById(user.id).select('+backupCodes');
      expect(refreshed!.backupCodes).toHaveLength(rawCodes.length);
    });
  });

  // ── Login 2FA after account lockout ──────────────────────────────────

  describe('2FA operations after account lockout', () => {
    it('should reject login/2fa when the user is locked out', async () => {
      const { user, secretObj } = await create2faUser([]);

      // Lock the account (e.g. brute-force on another session triggered the lockout)
      const lockoutUntil = new Date(Date.now() + 30 * 60 * 1000);
      await User.findByIdAndUpdate(user.id, {
        $set: { failedLoginAttempts: 10, lockoutUntil },
      });

      const totp = new TOTP({ algorithm: 'SHA1', digits: 6, period: 30, secret: secretObj });
      const validCode = totp.generate();

      const tempToken = makeTempToken(user.id);
      const { token: csrfToken, cookie: csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post(`${API}/auth/login/2fa`)
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ tempToken, code: validCode });

      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe('ACCOUNT_LOCKED');

      // No refresh token issued
      const { RefreshToken } = await import('../src/models/RefreshToken.js');
      const tokens = await RefreshToken.find({ userId: user.id });
      // Only the one created by createTestUser() helper exists (no new issuance)
      expect(tokens.length).toBeLessThanOrEqual(1);
    });
  });

  // ── Login 2FA when 2FA is not enabled ────────────────────────────────

  describe('login/2fa when 2FA is not enabled', () => {
    it('should reject with TWO_FA_NOT_ENABLED when user has no 2FA configured', async () => {
      const user = await createTestUser({ emailVerified: true });
      // 2FA is NOT enabled for this user

      const tempToken = makeTempToken(user.id);
      const { token: csrfToken, cookie: csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post(`${API}/auth/login/2fa`)
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ tempToken, code: '123456' });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe('TWO_FA_NOT_ENABLED');
    });
  });

  // ── Disable 2FA when not enabled ────────────────────────────────────

  describe('disable 2FA when 2FA is not enabled', () => {
    it('should reject with bad request when 2FA is not configured', async () => {
      const user = await createTestUser({ emailVerified: true });

      const { token: csrfToken, cookie: csrfCookie } = await getCsrf(agent);
      const res = await agent
        .delete(`${API}/user/2fa`)
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: user.rawPassword, code: '123456' });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });
  });

  // ── verify2fa without any pending setup ──────────────────────────────

  describe('verify2fa without pending setup', () => {
    it('should reject when there is no pending secret on the user record', async () => {
      const user = await createTestUser({ emailVerified: true });

      const { token: csrfToken, cookie: csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post(`${API}/user/2fa/verify`)
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ code: '123456' });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toMatch(/no pending 2FA setup/i);
    });
  });
});
