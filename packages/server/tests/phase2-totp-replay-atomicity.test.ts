/**
 * Phase 2 — Tasks 2.2 / 2.3: Atomic TOTP replay guard
 *
 * The replay guard used to be a non-atomic read-then-write: each handler read
 * `lastTotpTimestamp`, compared it, and later wrote the new time step
 * unconditionally. Two concurrent requests presenting the SAME valid TOTP in the
 * SAME 30-second time step could both pass the read-check before either wrote,
 * so both proceeded — minting two token sets (login2fa) or publishing two
 * distinct backup-code sets (regenerateBackupCodes). These tests pin the
 * corrected behavior: the write is a compare-and-set that only advances the
 * stored time step, and a no-op update is treated as a replay → reject.
 *
 * Covered:
 *   • authController.login2fa       — concurrent same-timestep TOTP: one wins.
 *   • userController.verify2fa      — concurrent same-timestep TOTP: one wins.
 *   • userController.regenerate...  — concurrent same-timestep TOTP: one wins.
 *   • Sequential reuse of a code still rejected (existing behavior preserved).
 */
import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { TOTP, Secret } from 'otpauth';
import { CryptoManager } from '@hiprax/crypto';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import {
  createTestUser,
  authHeader,
  deriveTestPurposeKey,
  getCsrf,
  type TestUser,
} from './helpers.js';

const API = '/api/v1';
const cm = new CryptoManager();
// Mirrors the controller's twoFactorEncryptionKey resolution: in the test env
// TWO_FACTOR_ENCRYPTION_KEY is unset, so it falls back to SESSION_SECRET.
const encKey = process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345';

/** Enables 2FA on an existing user with a fresh secret; returns the Secret. */
async function enable2faForUser(userId: string): Promise<Secret> {
  const secretObj = new Secret();
  const encryptedSecret = cm.encryptTextSync(secretObj.base32, encKey);
  await User.findByIdAndUpdate(userId, {
    $set: {
      twoFactorEnabled: true,
      twoFactorSecret: encryptedSecret,
      // Old timestamp so a freshly generated code is accepted the first time.
      lastTotpTimestamp: 1,
    },
  });
  return secretObj;
}

/** Mints a 2fa_temp token (no device binding) for login/2fa. */
function makeTempToken(userId: string): string {
  return jwt.sign({ userId, purpose: '2fa_temp' }, deriveTestPurposeKey('2fa_temp'), {
    expiresIn: '5m',
  });
}

/** Generates the current valid TOTP for a secret. */
function currentCode(secret: Secret): string {
  const totp = new TOTP({ algorithm: 'SHA1', digits: 6, period: 30, secret });
  return totp.generate();
}

/**
 * Asserts the plaintext backup codes handed to the client are EXACTLY the set
 * whose bcrypt hashes were persisted — i.e. every returned code authenticates
 * against a stored hash. Comparing only array lengths (both fixed at
 * BACKUP_CODES_COUNT) would pass even if the handler returned one batch of
 * plaintexts while persisting the hashes of a different batch, leaving the user
 * with codes that verify against nothing.
 */
async function assertReturnedCodesMatchPersisted(
  returned: string[],
  persistedHashes: string[],
): Promise<void> {
  expect(returned.length).toBeGreaterThan(0);
  expect(returned.length).toBe(persistedHashes.length);
  for (const raw of returned) {
    const matches = await Promise.all(persistedHashes.map((h) => bcrypt.compare(raw, h)));
    expect(matches.some(Boolean)).toBe(true);
  }
}

describe('Phase 2 — Atomic TOTP replay guard', () => {
  // ── login2fa (Task 2.2) ────────────────────────────────────────────────
  describe('POST /auth/login/2fa concurrent same-timestep replay', () => {
    it('should mint exactly one token set when two requests race the same TOTP', async () => {
      const user = await createTestUser({ emailVerified: true });
      const secret = await enable2faForUser(user.id);
      const code = currentCode(secret);

      const tokensBefore = await RefreshToken.countDocuments({ userId: user.id });

      const fire = async () => {
        const agent = request.agent(app);
        const csrf = await getCsrf(agent);
        return agent
          .post(`${API}/auth/login/2fa`)
          .set('x-csrf-token', csrf.token)
          .set('Cookie', csrf.cookie)
          .send({ tempToken: makeTempToken(user.id), code });
      };

      const [first, second] = await Promise.all([fire(), fire()]);

      // No server error on either request.
      expect(first.status).toBeLessThan(500);
      expect(second.status).toBeLessThan(500);

      const results = [first, second];
      const successes = results.filter((r) => r.status === 200);
      const failures = results.filter((r) => r.status === 401);
      expect(successes.length).toBe(1);
      expect(failures.length).toBe(1);

      // The winner returned an access token; the loser did not.
      expect(successes[0]!.body.data.accessToken).toBeTruthy();
      expect(failures[0]!.body.success).toBe(false);

      // Exactly one NEW refresh token was issued (baseline + winner only).
      const tokensAfter = await RefreshToken.countDocuments({ userId: user.id });
      expect(tokensAfter).toBe(tokensBefore + 1);

      // The consumed time step was persisted.
      const persisted = await User.findById(user.id);
      expect(persisted!.lastTotpTimestamp).toBeGreaterThan(1);
    });

    it('should reject sequential reuse of the same TOTP code', async () => {
      const user = await createTestUser({ emailVerified: true });
      const secret = await enable2faForUser(user.id);
      const code = currentCode(secret);

      const login = async () => {
        const agent = request.agent(app);
        const csrf = await getCsrf(agent);
        return agent
          .post(`${API}/auth/login/2fa`)
          .set('x-csrf-token', csrf.token)
          .set('Cookie', csrf.cookie)
          .send({ tempToken: makeTempToken(user.id), code });
      };

      const first = await login();
      expect(first.status).toBe(200);

      const second = await login();
      expect(second.status).toBe(401);
      expect(second.body.success).toBe(false);
    });
  });

  // ── verify2fa (Task 2.3) ───────────────────────────────────────────────
  describe('POST /user/2fa/verify concurrent same-timestep replay', () => {
    let user: TestUser;

    beforeEach(async () => {
      user = await createTestUser({ emailVerified: true });
    });

    it('should enable 2FA once and publish a single backup-code set under a race', async () => {
      // Setup stashes the pending secret and returns it in the response.
      const setupAgent = request.agent(app);
      const setupCsrf = await getCsrf(setupAgent);
      const setupRes = await setupAgent
        .post(`${API}/user/2fa/setup`)
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', setupCsrf.token)
        .set('Cookie', setupCsrf.cookie)
        .send({ password: user.rawPassword });
      expect(setupRes.status).toBe(200);
      const code = currentCode(Secret.fromBase32(setupRes.body.data.secret as string));

      const fireVerify = async () => {
        const agent = request.agent(app);
        const csrf = await getCsrf(agent);
        return agent
          .post(`${API}/user/2fa/verify`)
          .set('Authorization', authHeader(user.accessToken))
          .set('x-csrf-token', csrf.token)
          .set('Cookie', csrf.cookie)
          .send({ code });
      };

      const [first, second] = await Promise.all([fireVerify(), fireVerify()]);
      expect(first.status).toBeLessThan(500);
      expect(second.status).toBeLessThan(500);

      const results = [first, second];
      const successes = results.filter((r) => r.status === 200);
      const failures = results.filter((r) => r.status !== 200);
      expect(successes.length).toBe(1);
      expect(failures.length).toBe(1);
      // The loser is rejected as either already-enabled (409) or replay (400).
      expect([400, 409]).toContain(failures[0]!.status);

      const persisted = await User.findById(user.id).select('+backupCodes');
      expect(persisted!.twoFactorEnabled).toBe(true);
      const codes = (persisted!.backupCodes ?? []) as string[];
      // The winner's returned plaintext codes must be exactly the ones whose
      // hashes were persisted (verify by bcrypt.compare), not merely equal in
      // count — otherwise the user holds codes that authenticate against nothing.
      const returned = successes[0]!.body.data.backupCodes as string[];
      await assertReturnedCodesMatchPersisted(returned, codes);
    });
  });

  // ── regenerateBackupCodes (Task 2.3) ───────────────────────────────────
  describe('POST /user/2fa/regenerate-backup-codes concurrent same-timestep replay', () => {
    it('should publish exactly one backup-code set when two requests race the same TOTP', async () => {
      const user = await createTestUser({ emailVerified: true });
      const secret = await enable2faForUser(user.id);
      const code = currentCode(secret);

      const fire = async () => {
        const agent = request.agent(app);
        const csrf = await getCsrf(agent);
        return agent
          .post(`${API}/user/2fa/regenerate-backup-codes`)
          .set('Authorization', authHeader(user.accessToken))
          .set('x-csrf-token', csrf.token)
          .set('Cookie', csrf.cookie)
          .send({ password: user.rawPassword, code });
      };

      const [first, second] = await Promise.all([fire(), fire()]);
      expect(first.status).toBeLessThan(500);
      expect(second.status).toBeLessThan(500);

      const results = [first, second];
      const successes = results.filter((r) => r.status === 200);
      const failures = results.filter((r) => r.status === 400);
      expect(successes.length).toBe(1);
      expect(failures.length).toBe(1);
      expect(failures[0]!.body.success).toBe(false);

      // The single persisted backup-code set must match the winner's response:
      // every returned plaintext must verify against a persisted hash (not just
      // equal counts), so the winner never receives codes for a set that was
      // not the one actually stored.
      const persisted = await User.findById(user.id).select('+backupCodes');
      const codes = (persisted!.backupCodes ?? []) as string[];
      const returned = successes[0]!.body.data.backupCodes as string[];
      await assertReturnedCodesMatchPersisted(returned, codes);
    });

    it('should reject sequential reuse of the same regenerate TOTP code', async () => {
      const user = await createTestUser({ emailVerified: true });
      const secret = await enable2faForUser(user.id);
      const code = currentCode(secret);

      const regenerate = async () => {
        const agent = request.agent(app);
        const csrf = await getCsrf(agent);
        return agent
          .post(`${API}/user/2fa/regenerate-backup-codes`)
          .set('Authorization', authHeader(user.accessToken))
          .set('x-csrf-token', csrf.token)
          .set('Cookie', csrf.cookie)
          .send({ password: user.rawPassword, code });
      };

      const first = await regenerate();
      expect(first.status).toBe(200);

      const second = await regenerate();
      expect(second.status).toBe(400);
      expect(second.body.success).toBe(false);
    });
  });
});
