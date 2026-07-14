/**
 * Task 6.3: 2FA Backup Code Consumption Tests
 *
 * Covers: single-use consumption, exhaustion, regeneration replaces all codes,
 * concurrent use atomicity, code format, constant-time comparison, TOTP vs
 * backup code path differentiation.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { TOTP, Secret } from 'otpauth';
import { CryptoManager } from '@hiprax/crypto';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { findMatchingBackupCodeIndex } from '../src/controllers/authController.js';
import {
  createTestUser,
  authHeader,
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
const BCRYPT_ROUNDS = 4;
const cm = new CryptoManager();
const encKey = process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345';

/**
 * Creates a 2FA-enabled user with the given raw backup codes hashed and stored.
 * Returns { user, tempToken, rawCodes, secretObj }.
 */
async function create2faUser(rawCodes: string[]) {
  const secretObj = new Secret();
  const encryptedSecret = cm.encryptTextSync(secretObj.base32, encKey);
  const user = await createTestUser({ emailVerified: true });

  const hashedCodes = await Promise.all(rawCodes.map((c) => bcrypt.hash(c, BCRYPT_ROUNDS)));

  await User.findByIdAndUpdate(user.id, {
    $set: {
      twoFactorEnabled: true,
      twoFactorSecret: encryptedSecret,
      backupCodes: hashedCodes,
      lastTotpTimestamp: 1000, // Old timestamp so TOTP doesn't conflict
    },
  });

  const tempToken = jwt.sign(
    { userId: user.id, purpose: '2fa_temp' },
    deriveTestPurposeKey('2fa_temp'),
    { expiresIn: '5m' },
  );

  return { user, tempToken, rawCodes, secretObj };
}

describe('2FA Backup Code Consumption', () => {
  let agent: request.SuperTest<request.Test>;

  beforeEach(() => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
  });

  // ── Single-Use Consumption ────────────────────────────────────────────

  describe('single-use consumption', () => {
    it('should consume a backup code after successful use', async () => {
      const rawCodes = ['abcdef1234567890', 'fedcba0987654321'];
      const { user, tempToken } = await create2faUser(rawCodes);

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post(`${API}/auth/login/2fa`)
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ tempToken, code: rawCodes[0] });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      // Only 1 code should remain
      const updatedUser = await User.findById(user.id).select('+backupCodes');
      expect(updatedUser!.backupCodes).toHaveLength(1);
    });

    it('should not consume a backup code on failed attempt', async () => {
      const rawCodes = ['abcdef1234567890'];
      const { user, tempToken } = await create2faUser(rawCodes);

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post(`${API}/auth/login/2fa`)
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ tempToken, code: 'wrongcode1234567' });

      expect(res.status).toBe(401);

      // Code should still be there
      const updatedUser = await User.findById(user.id).select('+backupCodes');
      expect(updatedUser!.backupCodes).toHaveLength(1);
    });

    it('should prevent reuse of a previously consumed backup code', async () => {
      const rawCodes = ['abcdef1234567890', 'fedcba0987654321'];
      const { user, tempToken } = await create2faUser(rawCodes);

      // First use — succeeds
      const { csrfToken: csrf1, csrfCookie: cookie1 } = await getCsrf(agent);
      const res1 = await agent
        .post(`${API}/auth/login/2fa`)
        .set('x-csrf-token', csrf1)
        .set('Cookie', cookie1)
        .send({ tempToken, code: rawCodes[0] });
      expect(res1.status).toBe(200);

      // Create a new temp token for second attempt
      const tempToken2 = jwt.sign(
        { userId: user.id, purpose: '2fa_temp' },
        deriveTestPurposeKey('2fa_temp'),
        { expiresIn: '5m' },
      );

      // Second use of the same code — fails
      const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);
      const res2 = await agent
        .post(`${API}/auth/login/2fa`)
        .set('x-csrf-token', csrf2)
        .set('Cookie', cookie2)
        .send({ tempToken: tempToken2, code: rawCodes[0] });
      expect(res2.status).toBe(401);
    });
  });

  // ── Exhaustion ────────────────────────────────────────────────────────

  describe('backup code exhaustion', () => {
    it('should leave zero backup codes after all are consumed', async () => {
      const rawCodes = ['code000000000001', 'code000000000002'];
      const { user } = await create2faUser(rawCodes);

      // Use each code in sequence
      for (const code of rawCodes) {
        const tempToken = jwt.sign(
          { userId: user.id, purpose: '2fa_temp' },
          deriveTestPurposeKey('2fa_temp'),
          { expiresIn: '5m' },
        );

        const { csrfToken, csrfCookie } = await getCsrf(agent);
        const res = await agent
          .post(`${API}/auth/login/2fa`)
          .set('x-csrf-token', csrfToken)
          .set('Cookie', csrfCookie)
          .send({ tempToken, code });
        expect(res.status).toBe(200);
      }

      const updatedUser = await User.findById(user.id).select('+backupCodes');
      expect(updatedUser!.backupCodes).toHaveLength(0);
    });

    it('should reject login when all backup codes are exhausted and TOTP is invalid', async () => {
      // User with no backup codes
      const { user } = await create2faUser([]);

      const tempToken = jwt.sign(
        { userId: user.id, purpose: '2fa_temp' },
        deriveTestPurposeKey('2fa_temp'),
        { expiresIn: '5m' },
      );

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post(`${API}/auth/login/2fa`)
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ tempToken, code: 'anybackupcode00' });

      expect(res.status).toBe(401);
    });
  });

  // ── Regeneration ──────────────────────────────────────────────────────

  describe('regeneration replaces all old codes', () => {
    it('should invalidate old backup codes after regeneration', async () => {
      const rawCodes = ['oldcode123456789'];
      const { user, secretObj } = await create2faUser(rawCodes);

      // Regenerate backup codes
      const totp = new TOTP({
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: secretObj,
      });
      const totpCode = totp.generate();

      const { csrfToken: csrf1, csrfCookie: cookie1 } = await getCsrf(agent);
      const regenRes = await agent
        .post(`${API}/user/2fa/regenerate-backup-codes`)
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf1)
        .set('Cookie', cookie1)
        .send({ password: user.rawPassword, code: totpCode });

      expect(regenRes.status).toBe(200);
      const newCodes: string[] = regenRes.body.data.backupCodes;
      expect(newCodes).toBeDefined();
      expect(newCodes.length).toBeGreaterThan(0);

      // Old code should no longer work
      const tempToken = jwt.sign(
        { userId: user.id, purpose: '2fa_temp' },
        deriveTestPurposeKey('2fa_temp'),
        { expiresIn: '5m' },
      );

      const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);
      const loginRes = await agent
        .post(`${API}/auth/login/2fa`)
        .set('x-csrf-token', csrf2)
        .set('Cookie', cookie2)
        .send({ tempToken, code: rawCodes[0] });

      expect(loginRes.status).toBe(401);
    });

    it('should allow login with a newly regenerated backup code', async () => {
      const { user, secretObj } = await create2faUser(['initialcode12345']);

      const totp = new TOTP({
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: secretObj,
      });
      const totpCode = totp.generate();

      const { csrfToken: csrf1, csrfCookie: cookie1 } = await getCsrf(agent);
      const regenRes = await agent
        .post(`${API}/user/2fa/regenerate-backup-codes`)
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf1)
        .set('Cookie', cookie1)
        .send({ password: user.rawPassword, code: totpCode });

      expect(regenRes.status).toBe(200);
      const newCodes: string[] = regenRes.body.data.backupCodes;

      // Login with first new backup code
      const tempToken = jwt.sign(
        { userId: user.id, purpose: '2fa_temp' },
        deriveTestPurposeKey('2fa_temp'),
        { expiresIn: '5m' },
      );

      const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);
      const loginRes = await agent
        .post(`${API}/auth/login/2fa`)
        .set('x-csrf-token', csrf2)
        .set('Cookie', cookie2)
        .send({ tempToken, code: newCodes[0] });

      expect(loginRes.status).toBe(200);
      expect(loginRes.body.success).toBe(true);
    });
  });

  // ── Concurrent Use Atomicity ──────────────────────────────────────────

  describe('concurrent backup code use', () => {
    it('should only allow one concurrent use of the same backup code to succeed', async () => {
      const rawCodes = ['concurrentcode01'];
      const { user } = await create2faUser(rawCodes);

      // Create two temp tokens
      const tempToken1 = jwt.sign(
        { userId: user.id, purpose: '2fa_temp' },
        deriveTestPurposeKey('2fa_temp'),
        { expiresIn: '5m' },
      );
      const tempToken2 = jwt.sign(
        { userId: user.id, purpose: '2fa_temp' },
        deriveTestPurposeKey('2fa_temp'),
        { expiresIn: '5m' },
      );

      const { csrfToken: csrf1, csrfCookie: cookie1 } = await getCsrf(agent);
      const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);

      // Fire both requests concurrently
      const [res1, res2] = await Promise.all([
        agent
          .post(`${API}/auth/login/2fa`)
          .set('x-csrf-token', csrf1)
          .set('Cookie', cookie1)
          .send({ tempToken: tempToken1, code: rawCodes[0] }),
        agent
          .post(`${API}/auth/login/2fa`)
          .set('x-csrf-token', csrf2)
          .set('Cookie', cookie2)
          .send({ tempToken: tempToken2, code: rawCodes[0] }),
      ]);

      // Exactly one should succeed and one should fail
      const statuses = [res1.status, res2.status].sort();
      expect(statuses).toEqual([200, 401]);

      // No backup codes should remain
      const updatedUser = await User.findById(user.id).select('+backupCodes');
      expect(updatedUser!.backupCodes).toHaveLength(0);
    });
  });

  // ── Code Format ───────────────────────────────────────────────────────

  describe('backup code format', () => {
    it('should return codes in 16-character hex format after regeneration', async () => {
      const { user, secretObj } = await create2faUser([]);

      const totp = new TOTP({
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: secretObj,
      });
      const totpCode = totp.generate();

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post(`${API}/user/2fa/regenerate-backup-codes`)
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: user.rawPassword, code: totpCode });

      expect(res.status).toBe(200);
      const codes: string[] = res.body.data.backupCodes;

      // Each code should be 16 hex characters (8 random bytes)
      for (const code of codes) {
        expect(code).toMatch(/^[0-9a-f]{16}$/);
      }

      // Should generate the expected count (BACKUP_CODES_COUNT = 8)
      expect(codes).toHaveLength(8);
    });
  });

  // ── Constant-Time Comparison ──────────────────────────────────────────

  describe('findMatchingBackupCodeIndex constant-time behavior', () => {
    it('should always iterate all codes regardless of match position', async () => {
      const rawCodes = ['code_a_123456789', 'code_b_123456789', 'code_c_123456789'];
      const hashedCodes = await Promise.all(rawCodes.map((c) => bcrypt.hash(c, BCRYPT_ROUNDS)));

      const compareSpy = vi.spyOn(bcrypt, 'compare');
      try {
        // Match at the FIRST position. The constant-time contract requires EVERY
        // stored hash to be bcrypt.compare'd even after a match is found — a `break`
        // on first match would reveal the matched index via response timing. The
        // returned index (0) is identical whether or not the loop short-circuits,
        // so the call COUNT is the only assertion that catches a reintroduced
        // `break`.
        compareSpy.mockClear();
        const idx0 = await findMatchingBackupCodeIndex(rawCodes[0]!, hashedCodes);
        expect(idx0).toBe(0);
        expect(compareSpy).toHaveBeenCalledTimes(hashedCodes.length);

        // Match at the LAST position.
        compareSpy.mockClear();
        const idx2 = await findMatchingBackupCodeIndex(rawCodes[2]!, hashedCodes);
        expect(idx2).toBe(2);
        expect(compareSpy).toHaveBeenCalledTimes(hashedCodes.length);

        // No match — still iterates every code.
        compareSpy.mockClear();
        const noMatch = await findMatchingBackupCodeIndex('nonexistent000000', hashedCodes);
        expect(noMatch).toBe(-1);
        expect(compareSpy).toHaveBeenCalledTimes(hashedCodes.length);
      } finally {
        compareSpy.mockRestore();
      }
    });

    it('should return -1 for an empty backup codes array', async () => {
      const result = await findMatchingBackupCodeIndex('anycode123456789', []);
      expect(result).toBe(-1);
    });
  });

  // ── TOTP vs Backup Code Path Differentiation ─────────────────────────

  describe('TOTP vs backup code path differentiation', () => {
    it('should not update lastTotpTimestamp when using a backup code', async () => {
      const rawCodes = ['backuponly000001'];
      const { user, tempToken } = await create2faUser(rawCodes);

      const beforeUser = await User.findById(user.id).lean();
      const timestampBefore = beforeUser!.lastTotpTimestamp;

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post(`${API}/auth/login/2fa`)
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ tempToken, code: rawCodes[0] });

      expect(res.status).toBe(200);

      // lastTotpTimestamp should remain unchanged (backup codes skip timestamp update)
      const afterUser = await User.findById(user.id).lean();
      expect(afterUser!.lastTotpTimestamp).toBe(timestampBefore);
    });

    it('should update lastTotpTimestamp when using a valid TOTP code', async () => {
      const { user, secretObj } = await create2faUser([]);

      const totp = new TOTP({
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: secretObj,
      });
      const totpCode = totp.generate();

      const tempToken = jwt.sign(
        { userId: user.id, purpose: '2fa_temp' },
        deriveTestPurposeKey('2fa_temp'),
        { expiresIn: '5m' },
      );

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post(`${API}/auth/login/2fa`)
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ tempToken, code: totpCode });

      expect(res.status).toBe(200);

      const afterUser = await User.findById(user.id).lean();
      // Should be updated to a recent time step (not the old 1000)
      expect(afterUser!.lastTotpTimestamp).toBeDefined();
      expect(afterUser!.lastTotpTimestamp).toBeGreaterThan(1000);
    });

    it('should try backup codes only AFTER TOTP validation fails (a valid TOTP never touches them)', async () => {
      // A user with BOTH a TOTP secret and backup codes. Submitting a VALID TOTP
      // must be accepted via the TOTP path WITHOUT the backup-code branch running
      // at all. The previous version of this test submitted a backup code (never a
      // valid TOTP), so it could not distinguish the ordering it names — it
      // succeeded identically whether backup codes were tried before or after
      // TOTP. Here we assert bcrypt.compare (used ONLY to match backup codes) is
      // never invoked, which fails if the `!isValid` guard on the backup branch is
      // removed and backup matching runs unconditionally.
      const backupCodes = ['abc123def4567890', 'fed321cba0987654'];
      const { user, secretObj } = await create2faUser(backupCodes);

      const totp = new TOTP({ algorithm: 'SHA1', digits: 6, period: 30, secret: secretObj });
      const totpCode = totp.generate();

      const tempToken = jwt.sign(
        { userId: user.id, purpose: '2fa_temp' },
        deriveTestPurposeKey('2fa_temp'),
        { expiresIn: '5m' },
      );

      const compareSpy = vi.spyOn(bcrypt, 'compare');
      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post(`${API}/auth/login/2fa`)
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ tempToken, code: totpCode });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      // The backup-code branch (the only bcrypt.compare caller on this path) must
      // NOT have run for a valid TOTP.
      expect(compareSpy).not.toHaveBeenCalled();
      compareSpy.mockRestore();

      // No backup code consumed, and the TOTP time step advanced (TOTP path taken).
      const updatedUser = await User.findById(user.id).select('+backupCodes');
      expect(updatedUser!.backupCodes).toHaveLength(backupCodes.length);
      const after = await User.findById(user.id).lean();
      expect(after!.lastTotpTimestamp).toBeGreaterThan(1000);
    });
  });
});
