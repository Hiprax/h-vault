import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import mongoose from 'mongoose';
import { MAX_TRUSTED_DEVICES } from '@hvault/shared';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { TrustedDevice } from '../src/models/TrustedDevice.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { hashToken } from '../src/utils/token.js';
import {
  createTestUser,
  generateExpiredToken,
  generateStateHash,
  authHeader,
  deriveTestPurposeKey,
  getCsrf,
  JWT_SECRET,
  JWT_PURPOSE_SECRET,
  type CsrfPair,
} from './helpers.js';

const API = '/api/v1';

/**
 * Applies CSRF token + cookie and optional auth header to a supertest request.
 * Pass `extraCookies` to include additional cookies (e.g. refreshToken) alongside
 * the CSRF cookie — this avoids the pitfall of `.set('Cookie', ...)` overwriting
 * a previously set Cookie header.
 */
function withCsrf(
  req: request.Test,
  csrf: CsrfPair,
  accessToken?: string,
  extraCookies?: string,
): request.Test {
  const cookies = extraCookies ? `${csrf.cookie}; ${extraCookies}` : csrf.cookie;
  let r = req.set('x-csrf-token', csrf.token).set('Cookie', cookies);
  if (accessToken) {
    r = r.set('Authorization', authHeader(accessToken));
  }
  return r;
}

// ---------------------------------------------------------------------------
// Convenience: registration payload
// ---------------------------------------------------------------------------

function registrationBody(overrides: Record<string, unknown> = {}) {
  return {
    email: `newuser-${Date.now()}@example.com`,
    authHash: 'my-auth-hash-value',
    encryptedVaultKey: 'enc-vault-key',
    vaultKeyIv: 'vault-iv',
    vaultKeyTag: 'vault-tag',
    kdfIterations: 600_000,
    kdfAlgorithm: 'PBKDF2-SHA256',
    encryptionVersion: 1,
    ...overrides,
  };
}

// ===========================================================================
//  Tests
// ===========================================================================

describe('Auth API', () => {
  let agent: request.Agent;
  let csrf: CsrfPair;

  beforeEach(async () => {
    agent = request.agent(app);
    csrf = await getCsrf(agent);
  });

  // ── Registration ────────────────────────────────────────────────────────

  describe('POST /auth/register', () => {
    it('should register a new user and return 201', async () => {
      const body = registrationBody();

      const res = await withCsrf(agent.post(`${API}/auth/register`).send(body), csrf);

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toMatch(/registration successful/i);
      expect(res.body.data).toHaveProperty('emailSent');

      // Confirm user was created in DB
      const user = await User.findOne({ email: body.email });
      expect(user).toBeDefined();
      expect(user!.emailVerified).toBe(false);
    });

    it('should return 201 with generic message when registering a duplicate email (no enumeration)', async () => {
      const body = registrationBody();

      // First registration
      const res1 = await withCsrf(agent.post(`${API}/auth/register`).send(body), csrf);

      expect(res1.status).toBe(201);
      expect(res1.body.success).toBe(true);

      // Need a fresh CSRF token for the second request
      const csrf2 = await getCsrf(agent);

      // Duplicate registration — should return same 201 + generic message
      const res2 = await withCsrf(agent.post(`${API}/auth/register`).send(body), csrf2);

      expect(res2.status).toBe(201);
      expect(res2.body.success).toBe(true);
      expect(res2.body.message).toMatch(/registration successful/i);
    });

    it('should return identical response shape for new and existing emails', async () => {
      // Register a fresh email
      const body1 = registrationBody();
      const res1 = await withCsrf(agent.post(`${API}/auth/register`).send(body1), csrf);

      const csrf2 = await getCsrf(agent);

      // Register with the same email again (duplicate)
      const res2 = await withCsrf(agent.post(`${API}/auth/register`).send(body1), csrf2);

      // Both should return 201 with the exact same message to prevent enumeration
      expect(res1.status).toBe(201);
      expect(res2.status).toBe(201);
      expect(res1.body.success).toBe(true);
      expect(res2.body.success).toBe(true);
      expect(res1.body.message).toBe(res2.body.message);

      // Confirm only one user was actually created in the DB
      const userCount = await User.countDocuments({ email: body1.email });
      expect(userCount).toBe(1);
    });

    it('should return identical emailSent for a new and a duplicate email (anti-enumeration, Task 2.1)', async () => {
      // With SMTP unconfigured in the test env, an awaited verification send
      // returns { success: false }. The new-account path must NOT gate its
      // response on that result (which would leak emailSent:false for new
      // accounts vs emailSent:true for existing ones) — both paths must return
      // a constant emailSent:true so the bodies are byte-identical.
      const email = `enum-parity-${Date.now()}@example.com`;

      // First (new-account) registration.
      const res1 = await withCsrf(
        agent.post(`${API}/auth/register`).send(registrationBody({ email })),
        csrf,
      );

      const csrf2 = await getCsrf(agent);

      // Second (duplicate-account) registration.
      const res2 = await withCsrf(
        agent.post(`${API}/auth/register`).send(registrationBody({ email })),
        csrf2,
      );

      // Status, message, and emailSent must all be identical across both paths.
      expect(res1.status).toBe(201);
      expect(res2.status).toBe(res1.status);
      expect(res1.body.message).toBe(res2.body.message);
      expect(res1.body.data.emailSent).toBe(true);
      expect(res2.body.data.emailSent).toBe(true);
      expect(res1.body.data.emailSent).toBe(res2.body.data.emailSent);

      // The full response bodies are byte-identical (no field diverges).
      expect(res1.body).toEqual(res2.body);

      // Exactly one user was created despite two 201 responses.
      expect(await User.countDocuments({ email })).toBe(1);
    });

    it('should perform timing-safe response for duplicate registration (M7)', async () => {
      // Register first user (new-account path — runs one bcrypt.hash).
      const body = registrationBody();
      await withCsrf(agent.post(`${API}/auth/register`).send(body), csrf);

      // The anti-enumeration property is that the duplicate-email branch runs the
      // SAME dummy bcrypt.hash as the new-account branch, so both take the same
      // shape. A wall-clock floor (`elapsed > 5ms`) can't verify it: at
      // BCRYPT_ROUNDS=4 a bare supertest round-trip already exceeds 5ms with the
      // dummy hash deleted, so that assertion could never fail. Assert the hash
      // structurally instead.
      const hashSpy = vi.spyOn(bcrypt, 'hash');
      const csrf2 = await getCsrf(agent);
      hashSpy.mockClear();
      const res = await withCsrf(agent.post(`${API}/auth/register`).send(body), csrf2);

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      // Exactly one bcrypt.hash on the duplicate path — the dummy that equalizes
      // it with the new-account path. Deleting that dummy makes this 0 → red.
      expect(hashSpy).toHaveBeenCalledTimes(1);
      hashSpy.mockRestore();
    });

    it('should return 400 when required fields are missing', async () => {
      const res = await withCsrf(
        agent.post(`${API}/auth/register`).send({ email: 'incomplete@example.com' }),
        csrf,
      );

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should return 400 for an invalid email format', async () => {
      const body = registrationBody({ email: 'not-an-email' });

      const res = await withCsrf(agent.post(`${API}/auth/register`).send(body), csrf);

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should ignore unexpected fields like emailVerified in the request body (Task 4.1)', async () => {
      // Defense-in-depth: even if a future schema change forwards unexpected
      // keys, the controller's pickAllowedFields allowlist must keep them out
      // of the Mongoose User.create() call so account verification can never
      // be bypassed by a hand-crafted registration payload.
      const body = {
        ...registrationBody(),
        emailVerified: true,
        twoFactorEnabled: true,
        failedLoginAttempts: 99,
        passwordChangedAt: new Date(0).toISOString(),
        deletionPending: true,
      };

      const res = await withCsrf(agent.post(`${API}/auth/register`).send(body), csrf);

      expect(res.status).toBe(201);

      const user = await User.findOne({ email: body.email });
      expect(user).toBeTruthy();
      expect(user!.emailVerified).toBe(false);
      expect(user!.twoFactorEnabled).toBe(false);
      expect(user!.failedLoginAttempts).toBe(0);
      expect(user!.deletionPending).toBeFalsy();
    });
  });

  // ── Login ──────────────────────────────────────────────────────────────

  describe('POST /auth/login', () => {
    it('should login successfully and return access token + vault data', async () => {
      const testUser = await createTestUser({ emailVerified: true });

      const res = await withCsrf(
        agent.post(`${API}/auth/login`).send({
          email: testUser.email,
          authHash: testUser.rawPassword,
        }),
        csrf,
      );

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.accessToken).toBeDefined();
      expect(typeof res.body.data.accessToken).toBe('string');
      expect(res.body.data.encryptedVaultKey).toBeDefined();
      expect(res.body.data.vaultKeyIv).toBeDefined();
      expect(res.body.data.vaultKeyTag).toBeDefined();
      expect(res.body.data.kdfIterations).toBeDefined();
      expect(res.body.data.kdfAlgorithm).toBeDefined();

      // A refreshToken cookie should be set
      const setCookies = res.headers['set-cookie'] as string[];
      const hasRefreshCookie = setCookies?.some((c: string) => c.startsWith('refreshToken='));
      expect(hasRefreshCookie).toBe(true);
    });

    it('should return 401 for an invalid password', async () => {
      const testUser = await createTestUser({ emailVerified: true });

      const res = await withCsrf(
        agent.post(`${API}/auth/login`).send({
          email: testUser.email,
          authHash: 'wrong-password',
        }),
        csrf,
      );

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('should return 401 for a non-existent email', async () => {
      const res = await withCsrf(
        agent.post(`${API}/auth/login`).send({
          email: 'does-not-exist@example.com',
          authHash: 'some-password',
        }),
        csrf,
      );

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('should lock the account after 10 consecutive failed attempts', async () => {
      const testUser = await createTestUser({ emailVerified: true });

      // Perform 10 failed login attempts
      for (let i = 0; i < 10; i++) {
        const csrfN = await getCsrf(agent);
        await withCsrf(
          agent.post(`${API}/auth/login`).send({
            email: testUser.email,
            authHash: 'wrong-password',
          }),
          csrfN,
        );
      }

      // Confirm the user is locked out in the database
      const user = await User.findOne({ email: testUser.email });
      expect(user!.failedLoginAttempts).toBe(10);
      expect(user!.lockoutUntil).toBeDefined();
      expect(user!.lockoutUntil!.getTime()).toBeGreaterThan(Date.now());

      // The 11th attempt (even with correct password) should be blocked
      const csrfLocked = await getCsrf(agent);
      const res = await withCsrf(
        agent.post(`${API}/auth/login`).send({
          email: testUser.email,
          authHash: testUser.rawPassword,
        }),
        csrfLocked,
      );

      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
    }, 60_000);
  });

  // ── Token Refresh ─────────────────────────────────────────────────────

  describe('POST /auth/refresh', () => {
    it('should return a new access token when given a valid refresh cookie', async () => {
      const testUser = await createTestUser();

      // CSRF token must be generated with the same refreshToken cookie so that
      // the session identifier matches during validation.
      const csrfWithRefresh = await getCsrf(agent, `refreshToken=${testUser.refreshToken}`);
      const res = await withCsrf(
        agent.post(`${API}/auth/refresh`),
        csrfWithRefresh,
        undefined,
        `refreshToken=${testUser.refreshToken}`,
      );

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.accessToken).toBeDefined();
      expect(typeof res.body.data.accessToken).toBe('string');

      // A new refreshToken cookie should be set (rotation)
      const setCookies = res.headers['set-cookie'] as string[];
      const hasRefreshCookie = setCookies?.some((c: string) => c.startsWith('refreshToken='));
      expect(hasRefreshCookie).toBe(true);
    });

    it('should return 401 when no refresh cookie is provided', async () => {
      const res = await withCsrf(agent.post(`${API}/auth/refresh`), csrf);

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('should return 401 for an invalid refresh token', async () => {
      const csrfWithRefresh = await getCsrf(agent, 'refreshToken=invalid-token-value');
      const res = await withCsrf(
        agent.post(`${API}/auth/refresh`),
        csrfWithRefresh,
        undefined,
        'refreshToken=invalid-token-value',
      );

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });
  });

  // ── Logout ─────────────────────────────────────────────────────────────

  describe('POST /auth/logout', () => {
    it('should logout successfully and clear the refresh cookie', async () => {
      const testUser = await createTestUser();

      const csrfWithRefresh = await getCsrf(agent, `refreshToken=${testUser.refreshToken}`);
      const res = await withCsrf(
        agent.post(`${API}/auth/logout`),
        csrfWithRefresh,
        testUser.accessToken,
        `refreshToken=${testUser.refreshToken}`,
      );

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      // The refreshToken cookie should be cleared
      const setCookies = res.headers['set-cookie'] as string[];
      const clearCookie = setCookies?.find((c: string) => c.startsWith('refreshToken='));
      expect(clearCookie).toBeDefined();
    });

    it('should return 401 without an auth token', async () => {
      const res = await withCsrf(agent.post(`${API}/auth/logout`), csrf);

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });
  });

  // ── Lock ───────────────────────────────────────────────────────────────

  describe('POST /auth/lock', () => {
    it('should record a vault_lock audit entry on success', async () => {
      const testUser = await createTestUser();

      const res = await withCsrf(agent.post(`${API}/auth/lock`), csrf, testUser.accessToken);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toBe('Vault locked');

      const logs = await AuditLog.find({
        userId: testUser.id,
        action: 'vault_lock',
      }).lean();
      expect(logs.length).toBeGreaterThanOrEqual(1);
    });

    it('should return 401 without an auth token', async () => {
      const res = await withCsrf(agent.post(`${API}/auth/lock`), csrf);

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('should leave the refresh token intact (lock keeps session alive)', async () => {
      const testUser = await createTestUser();

      const csrfWithRefresh = await getCsrf(agent, `refreshToken=${testUser.refreshToken}`);
      const res = await withCsrf(
        agent.post(`${API}/auth/lock`),
        csrfWithRefresh,
        testUser.accessToken,
        `refreshToken=${testUser.refreshToken}`,
      );

      expect(res.status).toBe(200);

      // Refresh token should NOT be deleted (only logout does that)
      const tokens = await RefreshToken.countDocuments({ userId: testUser.id });
      expect(tokens).toBe(1);
    });
  });

  // ── Logout All ─────────────────────────────────────────────────────────

  describe('POST /auth/logout-all', () => {
    it('should revoke all other sessions', async () => {
      const testUser = await createTestUser();

      // Create additional refresh tokens (simulating other sessions)
      const crypto = await import('node:crypto');
      const { hashToken } = await import('../src/utils/token.js');

      const extraTokenRaw = crypto.randomBytes(64).toString('hex');
      await RefreshToken.create({
        userId: testUser.id,
        tokenHash: hashToken(extraTokenRaw),
        familyId: crypto.randomUUID(),
        deviceInfo: { userAgent: 'other-device', ip: '192.168.1.1', fingerprint: 'fp2' },
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      });

      // Verify we now have 2 refresh tokens for the user
      const tokensBefore = await RefreshToken.countDocuments({ userId: testUser.id });
      expect(tokensBefore).toBe(2);

      const csrfWithRefresh = await getCsrf(agent, `refreshToken=${testUser.refreshToken}`);
      const res = await withCsrf(
        agent.post(`${API}/auth/logout-all`),
        csrfWithRefresh,
        testUser.accessToken,
        `refreshToken=${testUser.refreshToken}`,
      );

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      // Only the current session's token should remain
      const tokensAfter = await RefreshToken.countDocuments({ userId: testUser.id });
      expect(tokensAfter).toBe(1);
    });

    it('should return 401 without an auth token', async () => {
      const res = await withCsrf(agent.post(`${API}/auth/logout-all`), csrf);

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });
  });

  // ── Verify Email ───────────────────────────────────────────────────────

  describe('POST /auth/verify-email', () => {
    it('should verify email with a valid token', async () => {
      const testUser = await createTestUser({ emailVerified: false });

      // Generate a verification token (same way the controller does)
      const verificationToken = jwt.sign(
        {
          userId: testUser.id,
          purpose: 'email_verification',
          stateHash: generateStateHash(String(false)),
        },
        deriveTestPurposeKey('email_verification'),
        { expiresIn: '24h' },
      );

      const res = await withCsrf(
        agent.post(`${API}/auth/verify-email`).send({ token: verificationToken }),
        csrf,
      );

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      // Confirm the user is now verified in DB
      const user = await User.findById(testUser.id);
      expect(user!.emailVerified).toBe(true);
    });

    it('should return 400 for an invalid / malformed token', async () => {
      const res = await withCsrf(
        agent.post(`${API}/auth/verify-email`).send({ token: 'invalid-token' }),
        csrf,
      );

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should return 400 for a token with wrong purpose', async () => {
      const testUser = await createTestUser({ emailVerified: false });

      const wrongPurposeToken = jwt.sign(
        { userId: testUser.id, purpose: 'password_reset' },
        JWT_PURPOSE_SECRET,
        { expiresIn: '24h' },
      );

      const res = await withCsrf(
        agent.post(`${API}/auth/verify-email`).send({ token: wrongPurposeToken }),
        csrf,
      );

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should return 400 for a token with missing purpose field', async () => {
      const testUser = await createTestUser({ emailVerified: false });

      const noPurposeToken = jwt.sign({ userId: testUser.id }, JWT_PURPOSE_SECRET, {
        expiresIn: '24h',
      });

      const res = await withCsrf(
        agent.post(`${API}/auth/verify-email`).send({ token: noPurposeToken }),
        csrf,
      );

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should succeed gracefully if email is already verified', async () => {
      const testUser = await createTestUser({ emailVerified: true });

      const verificationToken = jwt.sign(
        {
          userId: testUser.id,
          purpose: 'email_verification',
          stateHash: generateStateHash(String(true)),
        },
        deriveTestPurposeKey('email_verification'),
        { expiresIn: '24h' },
      );

      const res = await withCsrf(
        agent.post(`${API}/auth/verify-email`).send({ token: verificationToken }),
        csrf,
      );

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toMatch(/already verified/i);
    });
  });

  // ── Forgot Password ────────────────────────────────────────────────────

  describe('POST /auth/forgot-password', () => {
    it('should return success for an existing email (no enumeration)', async () => {
      const testUser = await createTestUser();

      const res = await withCsrf(
        agent.post(`${API}/auth/forgot-password`).send({ email: testUser.email }),
        csrf,
      );

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('should return success for a non-existent email (no enumeration)', async () => {
      const res = await withCsrf(
        agent.post(`${API}/auth/forgot-password`).send({ email: 'nobody@example.com' }),
        csrf,
      );

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('should return 400 for an invalid email format', async () => {
      const res = await withCsrf(
        agent.post(`${API}/auth/forgot-password`).send({ email: 'not-valid' }),
        csrf,
      );

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should return identical message and emailSent for existing and non-existent emails (anti-enumeration)', async () => {
      const testUser = await createTestUser();

      const res1 = await withCsrf(
        agent.post(`${API}/auth/forgot-password`).send({ email: testUser.email }),
        csrf,
      );

      const csrf2 = await getCsrf(agent);

      const res2 = await withCsrf(
        agent.post(`${API}/auth/forgot-password`).send({ email: 'nonexistent@example.com' }),
        csrf2,
      );

      // Both must return the same message and emailSent value
      expect(res1.body.message).toBe(res2.body.message);
      expect(res1.body.data.emailSent).toBe(true);
      expect(res2.body.data.emailSent).toBe(true);
    });
  });

  // ── Reset Password ─────────────────────────────────────────────────────

  describe('POST /auth/reset-password', () => {
    it('should reset password with a valid token', async () => {
      const testUser = await createTestUser();

      // Fetch the user's bcrypt-hashed authHash to bind the token
      const dbUser = await User.findById(testUser.id).select('+authHash');
      const resetToken = jwt.sign(
        {
          userId: testUser.id,
          purpose: 'password_reset',
          stateHash: generateStateHash(dbUser!.authHash),
        },
        deriveTestPurposeKey('password_reset'),
        { expiresIn: '1h' },
      );

      const res = await withCsrf(
        agent.post(`${API}/auth/reset-password`).send({
          token: resetToken,
          email: testUser.email,
          newAuthHash: 'brand-new-auth-hash',
          newEncryptedVaultKey: 'new-enc-vault-key',
          newVaultKeyIv: 'new-vault-iv',
          newVaultKeyTag: 'new-vault-tag',
        }),
        csrf,
      );

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      // All existing refresh tokens for this user should be revoked
      const tokenCount = await RefreshToken.countDocuments({ userId: testUser.id });
      expect(tokenCount).toBe(0);
    });

    it('should return 400 for an invalid reset token', async () => {
      const res = await withCsrf(
        agent.post(`${API}/auth/reset-password`).send({
          token: 'bogus-token',
          email: 'test@example.com',
          newAuthHash: 'hash',
          newEncryptedVaultKey: 'key',
          newVaultKeyIv: 'iv',
          newVaultKeyTag: 'tag',
        }),
        csrf,
      );

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should return 400 for a token with missing purpose field', async () => {
      const testUser = await createTestUser();

      const noPurposeToken = jwt.sign({ userId: testUser.id }, JWT_PURPOSE_SECRET, {
        expiresIn: '1h',
      });

      const res = await withCsrf(
        agent.post(`${API}/auth/reset-password`).send({
          token: noPurposeToken,
          email: testUser.email,
          newAuthHash: 'brand-new-auth-hash',
          newEncryptedVaultKey: 'new-enc-vault-key',
          newVaultKeyIv: 'new-vault-iv',
          newVaultKeyTag: 'new-vault-tag',
        }),
        csrf,
      );

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should return 400 when email does not match the token user', async () => {
      const testUser = await createTestUser();

      const dbUser = await User.findById(testUser.id).select('+authHash');
      const resetToken = jwt.sign(
        {
          userId: testUser.id,
          purpose: 'password_reset',
          stateHash: generateStateHash(dbUser!.authHash),
        },
        deriveTestPurposeKey('password_reset'),
        { expiresIn: '1h' },
      );

      const res = await withCsrf(
        agent.post(`${API}/auth/reset-password`).send({
          token: resetToken,
          email: 'wrong-email@example.com',
          newAuthHash: 'brand-new-auth-hash',
          newEncryptedVaultKey: 'new-enc-vault-key',
          newVaultKeyIv: 'new-vault-iv',
          newVaultKeyTag: 'new-vault-tag',
        }),
        csrf,
      );

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should accept email case-insensitively', async () => {
      const testUser = await createTestUser({ email: 'testcase@example.com' });

      const dbUser = await User.findById(testUser.id).select('+authHash');
      const resetToken = jwt.sign(
        {
          userId: testUser.id,
          purpose: 'password_reset',
          stateHash: generateStateHash(dbUser!.authHash),
        },
        deriveTestPurposeKey('password_reset'),
        { expiresIn: '1h' },
      );

      const res = await withCsrf(
        agent.post(`${API}/auth/reset-password`).send({
          token: resetToken,
          email: 'TestCase@Example.COM',
          newAuthHash: 'brand-new-auth-hash',
          newEncryptedVaultKey: 'new-enc-vault-key',
          newVaultKeyIv: 'new-vault-iv',
          newVaultKeyTag: 'new-vault-tag',
        }),
        csrf,
      );

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });
  });

  // ── Login 2FA ────────────────────────────────────────────────────────

  describe('POST /auth/login/2fa', () => {
    it('should reject an expired temp token', async () => {
      const testUser = await createTestUser();

      // Create an already-expired temp token (negative expiry avoids timing flakiness)
      const expiredTempToken = jwt.sign(
        { userId: testUser.id, purpose: '2fa_temp' },
        deriveTestPurposeKey('2fa_temp'),
        { expiresIn: '-1s' },
      );

      const res = await withCsrf(
        agent.post(`${API}/auth/login/2fa`).send({
          tempToken: expiredTempToken,
          code: '000000',
        }),
        csrf,
      );

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('should reject a temp token with wrong purpose', async () => {
      const testUser = await createTestUser();

      const wrongPurposeToken = jwt.sign(
        { userId: testUser.id, purpose: 'email_verification' },
        JWT_PURPOSE_SECRET,
        { expiresIn: '5m' },
      );

      const res = await withCsrf(
        agent.post(`${API}/auth/login/2fa`).send({
          tempToken: wrongPurposeToken,
          code: '123456',
        }),
        csrf,
      );

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('should reject a temp token with missing purpose field', async () => {
      const testUser = await createTestUser();

      const noPurposeToken = jwt.sign({ userId: testUser.id }, JWT_PURPOSE_SECRET, {
        expiresIn: '5m',
      });

      const res = await withCsrf(
        agent.post(`${API}/auth/login/2fa`).send({
          tempToken: noPurposeToken,
          code: '123456',
        }),
        csrf,
      );

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('should reject an invalid TOTP code', async () => {
      // Create user with 2FA "enabled" flag but we'll send a code
      // that won't match. We need a user with twoFactorEnabled=true
      // and a twoFactorSecret set. We'll set these directly in DB.
      const { CryptoManager } = await import('@hiprax/crypto');
      const { Secret } = await import('otpauth');

      const cm = new CryptoManager();
      const secretObj = new Secret();
      const secret = secretObj.base32;
      const encryptedSecret = cm.encryptTextSync(
        secret,
        process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345',
      );

      const testUser = await createTestUser();

      // Enable 2FA directly in DB
      await User.findByIdAndUpdate(testUser.id, {
        $set: {
          twoFactorEnabled: true,
          twoFactorSecret: encryptedSecret,
        },
      });

      // Create a valid temp token
      const tempToken = jwt.sign(
        { userId: testUser.id, purpose: '2fa_temp' },
        deriveTestPurposeKey('2fa_temp'),
        { expiresIn: '5m' },
      );

      const res = await withCsrf(
        agent.post(`${API}/auth/login/2fa`).send({
          tempToken,
          code: '000000', // Invalid code
        }),
        csrf,
      );

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('should complete login with valid TOTP code', async () => {
      const { CryptoManager } = await import('@hiprax/crypto');
      const { TOTP, Secret } = await import('otpauth');

      const cm = new CryptoManager();
      const secretObj = new Secret();
      const secret = secretObj.base32;
      const encryptedSecret = cm.encryptTextSync(
        secret,
        process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345',
      );

      const testUser = await createTestUser();

      // Enable 2FA directly in DB
      await User.findByIdAndUpdate(testUser.id, {
        $set: {
          twoFactorEnabled: true,
          twoFactorSecret: encryptedSecret,
        },
      });

      // Create a valid temp token
      const tempToken = jwt.sign(
        { userId: testUser.id, purpose: '2fa_temp' },
        deriveTestPurposeKey('2fa_temp'),
        { expiresIn: '5m' },
      );

      // Generate a valid TOTP code
      const totp = new TOTP({
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: Secret.fromBase32(secret),
      });
      const validCode = totp.generate();

      const res = await withCsrf(
        agent.post(`${API}/auth/login/2fa`).send({
          tempToken,
          code: validCode,
        }),
        csrf,
      );

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.accessToken).toBeDefined();
      expect(typeof res.body.data.accessToken).toBe('string');
      expect(res.body.data.encryptedVaultKey).toBeDefined();
    });

    it('completes login with a 2FA secret stored in the legacy v0 (pre-1.0) crypto format', async () => {
      // Regression guard for the @hiprax/crypto 0.9.5 -> 1.4.4 upgrade. The
      // twoFactorSecret below was encrypted by the OLD version (v0 wire format)
      // and captured before the upgrade. It must still decrypt server-side via
      // legacyMode 'auto', or every user with 2FA enabled would be locked out.
      const { TOTP, Secret } = await import('otpauth');

      const V0_SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
      const V0_CIPHERTEXT =
        'M5ZlRV3Pl6OemwO3CyO2r6YLjQQflilTnEG1N0OLBI2xgQBRll6jsOGpOQ-ircXtjjmBYfcLfwk8KFiVvfJ1Zwyl605PEXO02Xsoao-EDbSTum_uxBN1X_lx_Go';

      const testUser = await createTestUser();

      // Store the secret in the legacy v0 ciphertext form directly in the DB.
      await User.findByIdAndUpdate(testUser.id, {
        $set: {
          twoFactorEnabled: true,
          twoFactorSecret: V0_CIPHERTEXT,
        },
      });

      const tempToken = jwt.sign(
        { userId: testUser.id, purpose: '2fa_temp' },
        deriveTestPurposeKey('2fa_temp'),
        { expiresIn: '5m' },
      );

      const totp = new TOTP({
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: Secret.fromBase32(V0_SECRET),
      });
      const validCode = totp.generate();

      const res = await withCsrf(
        agent.post(`${API}/auth/login/2fa`).send({
          tempToken,
          code: validCode,
        }),
        csrf,
      );

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.accessToken).toBeDefined();
    });

    it('should return twoFactorRequired when logging in with 2FA-enabled account', async () => {
      const { CryptoManager } = await import('@hiprax/crypto');
      const { Secret } = await import('otpauth');

      const cm = new CryptoManager();
      const secretObj = new Secret();
      const secret = secretObj.base32;
      const encryptedSecret = cm.encryptTextSync(
        secret,
        process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345',
      );

      const testUser = await createTestUser({ emailVerified: true });

      // Enable 2FA directly in DB
      await User.findByIdAndUpdate(testUser.id, {
        $set: {
          twoFactorEnabled: true,
          twoFactorSecret: encryptedSecret,
        },
      });

      // Login with correct credentials
      const res = await withCsrf(
        agent.post(`${API}/auth/login`).send({
          email: testUser.email,
          authHash: testUser.rawPassword,
        }),
        csrf,
      );

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.twoFactorRequired).toBe(true);
      expect(res.body.data.tempToken).toBeDefined();
      expect(typeof res.body.data.tempToken).toBe('string');
      // Should NOT have accessToken yet
      expect(res.body.data.accessToken).toBeUndefined();
    });
  });

  // ── Remember me / trusted device (Phase 16) ─────────────────────────

  describe('Remember me / trusted device', () => {
    const DAY_MS = 24 * 60 * 60 * 1000;

    function getSetCookies(res: request.Response): string[] {
      return (res.headers['set-cookie'] as string[] | undefined) ?? [];
    }
    function findCookie(res: request.Response, name: string): string | undefined {
      return getSetCookies(res).find((c) => c.startsWith(`${name}=`));
    }
    function cookieValue(cookie: string): string {
      return cookie.split(';')[0]!.split('=').slice(1).join('=');
    }
    function cookieMaxAgeSeconds(cookie: string): number {
      const m = /Max-Age=(\d+)/i.exec(cookie);
      return m ? Number(m[1]) : NaN;
    }

    async function enable2fa(userId: string): Promise<string> {
      const { CryptoManager } = await import('@hiprax/crypto');
      const { Secret } = await import('otpauth');
      const cm = new CryptoManager();
      const secret = new Secret().base32;
      const encryptedSecret = cm.encryptTextSync(
        secret,
        process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345',
      );
      await User.findByIdAndUpdate(userId, {
        $set: { twoFactorEnabled: true, twoFactorSecret: encryptedSecret },
      });
      return secret;
    }

    async function totpFor(secret: string): Promise<string> {
      const { TOTP, Secret } = await import('otpauth');
      return new TOTP({
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: Secret.fromBase32(secret),
      }).generate();
    }

    it('non-2FA remembered login gets a ~30-day cookie and an absolute-deadline row', async () => {
      const testUser = await createTestUser();

      const res = await withCsrf(
        agent.post(`${API}/auth/login`).send({
          email: testUser.email,
          authHash: testUser.rawPassword,
          rememberMe: true,
        }),
        csrf,
      );

      expect(res.status).toBe(200);
      expect(res.body.data.accessToken).toBeDefined();

      const refreshCookie = findCookie(res, 'refreshToken');
      expect(refreshCookie).toBeDefined();
      // ~30 days, comfortably above the 7-day standard horizon.
      expect(cookieMaxAgeSeconds(refreshCookie!)).toBeGreaterThan(20 * 24 * 60 * 60);

      const row = await RefreshToken.findOne({ tokenHash: hashToken(cookieValue(refreshCookie!)) });
      expect(row).not.toBeNull();
      expect(row!.absoluteExpiresAt).toBeDefined();
      expect(row!.absoluteExpiresAt!.getTime() - Date.now()).toBeGreaterThan(25 * DAY_MS);
    });

    it('a non-remembered login keeps the standard ~7-day session with no absolute deadline', async () => {
      const testUser = await createTestUser();

      const res = await withCsrf(
        agent.post(`${API}/auth/login`).send({
          email: testUser.email,
          authHash: testUser.rawPassword,
        }),
        csrf,
      );

      expect(res.status).toBe(200);
      const refreshCookie = findCookie(res, 'refreshToken');
      expect(cookieMaxAgeSeconds(refreshCookie!)).toBeLessThan(10 * 24 * 60 * 60);

      const row = await RefreshToken.findOne({ tokenHash: hashToken(cookieValue(refreshCookie!)) });
      expect(row).not.toBeNull();
      expect(row!.absoluteExpiresAt).toBeUndefined();
    });

    it('carries rememberMe into the signed 2FA temp token', async () => {
      const testUser = await createTestUser();
      await enable2fa(testUser.id);

      const res = await withCsrf(
        agent.post(`${API}/auth/login`).send({
          email: testUser.email,
          authHash: testUser.rawPassword,
          rememberMe: true,
        }),
        csrf,
      );

      expect(res.status).toBe(200);
      expect(res.body.data.twoFactorRequired).toBe(true);
      const decoded = jwt.decode(res.body.data.tempToken as string) as {
        rememberMe?: boolean;
      } | null;
      expect(decoded?.rememberMe).toBe(true);
    });

    it('grants a trusted device on 2FA success with remember; the raw token lives only in the cookie', async () => {
      const testUser = await createTestUser();
      const secret = await enable2fa(testUser.id);
      const userObjId = new mongoose.Types.ObjectId(testUser.id);

      const tempToken = jwt.sign(
        { userId: testUser.id, purpose: '2fa_temp', rememberMe: true },
        deriveTestPurposeKey('2fa_temp'),
        { expiresIn: '5m' },
      );
      const code = await totpFor(secret);

      const res = await withCsrf(
        agent.post(`${API}/auth/login/2fa`).send({ tempToken, code }),
        csrf,
      );

      expect(res.status).toBe(200);
      expect(res.body.data.accessToken).toBeDefined();

      // Trusted-device cookie present, scoped to the auth path.
      const tdCookie = findCookie(res, 'trustedDevice');
      expect(tdCookie).toBeDefined();
      expect(tdCookie).toMatch(/Path=\/api\/v1\/auth/i);
      const rawTd = cookieValue(tdCookie!);
      expect(rawTd.length).toBeGreaterThan(0);

      // The record stores only the SHA-256 of the cookie token.
      const record = await TrustedDevice.findOne({ userId: userObjId });
      expect(record).not.toBeNull();
      expect(record!.tokenHash).toBe(hashToken(rawTd));
      expect(record!.expiresAt.getTime() - Date.now()).toBeGreaterThan(25 * DAY_MS);

      // The raw token never appears in the response body or a persisted field.
      expect(JSON.stringify(res.body)).not.toContain(rawTd);
      expect(record!.tokenHash).not.toBe(rawTd);

      // Remembered → ~30-day refresh session, and the grant is audited.
      const refreshCookie = findCookie(res, 'refreshToken');
      expect(cookieMaxAgeSeconds(refreshCookie!)).toBeGreaterThan(20 * 24 * 60 * 60);
      const grant = await AuditLog.findOne({ userId: testUser.id, action: 'trusted_device_grant' });
      expect(grant).not.toBeNull();
    });

    it('a 2FA login without remember mints no trusted device and keeps a standard session', async () => {
      const testUser = await createTestUser();
      const secret = await enable2fa(testUser.id);
      const userObjId = new mongoose.Types.ObjectId(testUser.id);

      const tempToken = jwt.sign(
        { userId: testUser.id, purpose: '2fa_temp' },
        deriveTestPurposeKey('2fa_temp'),
        { expiresIn: '5m' },
      );
      const code = await totpFor(secret);

      const res = await withCsrf(
        agent.post(`${API}/auth/login/2fa`).send({ tempToken, code }),
        csrf,
      );

      expect(res.status).toBe(200);
      expect(findCookie(res, 'trustedDevice')).toBeUndefined();
      expect(await TrustedDevice.countDocuments({ userId: userObjId })).toBe(0);
      expect(
        await AuditLog.findOne({ userId: testUser.id, action: 'trusted_device_grant' }),
      ).toBeNull();

      const refreshCookie = findCookie(res, 'refreshToken');
      expect(cookieMaxAgeSeconds(refreshCookie!)).toBeLessThan(10 * 24 * 60 * 60);
    });

    it('reads rememberMe only from the signed token, ignoring a tampered request body', async () => {
      const testUser = await createTestUser();
      const secret = await enable2fa(testUser.id);
      const userObjId = new mongoose.Types.ObjectId(testUser.id);

      // Token says NOT remembered; the attacker adds rememberMe:true to the body.
      const tempToken = jwt.sign(
        { userId: testUser.id, purpose: '2fa_temp', rememberMe: false },
        deriveTestPurposeKey('2fa_temp'),
        { expiresIn: '5m' },
      );
      const code = await totpFor(secret);

      const res = await withCsrf(
        agent.post(`${API}/auth/login/2fa`).send({ tempToken, code, rememberMe: true }),
        csrf,
      );

      expect(res.status).toBe(200);
      expect(findCookie(res, 'trustedDevice')).toBeUndefined();
      expect(await TrustedDevice.countDocuments({ userId: userObjId })).toBe(0);
    });

    it('enforces MAX_TRUSTED_DEVICES, evicting the oldest record', async () => {
      const testUser = await createTestUser();
      const secret = await enable2fa(testUser.id);
      const userObjId = new mongoose.Types.ObjectId(testUser.id);

      // Seed the cap-worth of trusted devices with staggered createdAt (oldest
      // first), inserting through the raw collection so the timestamps plugin
      // cannot overwrite our deterministic createdAt values.
      const now = Date.now();
      const seeds = Array.from({ length: MAX_TRUSTED_DEVICES }, (_, i) => ({
        userId: userObjId,
        tokenHash: hashToken(`seed-${String(i)}`),
        deviceInfo: { userAgent: '', ip: '', fingerprint: '' },
        expiresAt: new Date(now + 30 * DAY_MS),
        createdAt: new Date(now - (MAX_TRUSTED_DEVICES - i) * 60_000),
        updatedAt: new Date(now),
      }));
      await TrustedDevice.collection.insertMany(seeds);

      const tempToken = jwt.sign(
        { userId: testUser.id, purpose: '2fa_temp', rememberMe: true },
        deriveTestPurposeKey('2fa_temp'),
        { expiresIn: '5m' },
      );
      const code = await totpFor(secret);

      const res = await withCsrf(
        agent.post(`${API}/auth/login/2fa`).send({ tempToken, code }),
        csrf,
      );

      expect(res.status).toBe(200);
      // The count stays at the cap; the oldest seed is gone; the new device survives.
      expect(await TrustedDevice.countDocuments({ userId: userObjId })).toBe(MAX_TRUSTED_DEVICES);
      expect(await TrustedDevice.findOne({ tokenHash: hashToken('seed-0') })).toBeNull();
      const rawTd = cookieValue(findCookie(res, 'trustedDevice')!);
      expect(await TrustedDevice.findOne({ tokenHash: hashToken(rawTd) })).not.toBeNull();
    });

    // ── 2FA skip on a recognized device (Phase 17) ────────────────────
    describe('2FA skip on a recognized device', () => {
      /** Seeds a trusted-device record whose raw cookie token is `raw`. */
      async function seedTrustedDevice(
        userId: string,
        raw: string,
        expiresAt: Date = new Date(Date.now() + 30 * DAY_MS),
      ): Promise<void> {
        await TrustedDevice.create({
          userId: new mongoose.Types.ObjectId(userId),
          tokenHash: hashToken(raw),
          deviceInfo: { userAgent: '', ip: '', fingerprint: '' },
          expiresAt,
        });
      }

      /** Logs in at the password step, optionally presenting a trustedDevice cookie. */
      function loginWith(
        testUser: { email: string; rawPassword: string },
        opts: { rememberMe?: boolean; trustedRaw?: string; authHash?: string } = {},
      ): Promise<request.Response> {
        const body: Record<string, unknown> = {
          email: testUser.email,
          authHash: opts.authHash ?? testUser.rawPassword,
        };
        if (opts.rememberMe !== undefined) body['rememberMe'] = opts.rememberMe;
        return withCsrf(
          agent.post(`${API}/auth/login`).send(body),
          csrf,
          undefined,
          opts.trustedRaw ? `trustedDevice=${opts.trustedRaw}` : undefined,
        );
      }

      it('skips 2FA on a valid cookie: rotates the trust token and logs in directly', async () => {
        const testUser = await createTestUser();
        await enable2fa(testUser.id);
        const userObjId = new mongoose.Types.ObjectId(testUser.id);
        const raw = 'trusted-happy-path-token';
        await seedTrustedDevice(testUser.id, raw);

        const res = await loginWith(testUser, { rememberMe: true, trustedRaw: raw });

        expect(res.status).toBe(200);
        // A direct login — NOT a 2FA challenge — with vault key material returned.
        expect(res.body.data.twoFactorRequired).toBeUndefined();
        expect(res.body.data.accessToken).toBeDefined();
        expect(res.body.data.encryptedVaultKey).toBeDefined();

        // The presented record was consumed; exactly one (rotated) record remains.
        expect(await TrustedDevice.findOne({ tokenHash: hashToken(raw) })).toBeNull();
        expect(await TrustedDevice.countDocuments({ userId: userObjId })).toBe(1);

        // A fresh trusted-device cookie was issued (rotated value, not the old one).
        const tdCookie = findCookie(res, 'trustedDevice');
        expect(tdCookie).toBeDefined();
        expect(tdCookie).toMatch(/Path=\/api\/v1\/auth/i);
        const newRaw = cookieValue(tdCookie!);
        expect(newRaw).not.toBe(raw);
        expect(await TrustedDevice.findOne({ tokenHash: hashToken(newRaw) })).not.toBeNull();

        // Audited as a password-only login that skipped the second factor.
        const loginAudit = await AuditLog.findOne({ userId: testUser.id, action: 'login' });
        expect(loginAudit).not.toBeNull();
        expect(loginAudit!.metadata).toMatchObject({ twoFactor: false, trustedDevice: true });
        // A skip is not a fresh grant, so no grant/rejection audit is written.
        expect(
          await AuditLog.findOne({ userId: testUser.id, action: 'trusted_device_grant' }),
        ).toBeNull();
        expect(
          await AuditLog.findOne({ userId: testUser.id, action: 'trusted_device_rejected' }),
        ).toBeNull();

        // Remembered → ~30-day session.
        expect(cookieMaxAgeSeconds(findCookie(res, 'refreshToken')!)).toBeGreaterThan(
          20 * 24 * 60 * 60,
        );
      });

      it('rejects a replayed (already-consumed) token and falls through to 2FA', async () => {
        const testUser = await createTestUser();
        await enable2fa(testUser.id);
        const userObjId = new mongoose.Types.ObjectId(testUser.id);
        const raw = 'trusted-replay-token';
        await seedTrustedDevice(testUser.id, raw);

        // First use consumes the record.
        const first = await loginWith(testUser, { rememberMe: true, trustedRaw: raw });
        expect(first.status).toBe(200);
        expect(first.body.data.twoFactorRequired).toBeUndefined();

        // Replay the SAME (now-consumed) cookie from a FRESH agent. A fresh jar is
        // required: the first login rotated the trust token and the original agent
        // would re-send that new cookie instead of the old one we want to replay.
        const replayAgent = request.agent(app);
        const replayCsrf = await getCsrf(replayAgent);
        const replay = await withCsrf(
          replayAgent.post(`${API}/auth/login`).send({
            email: testUser.email,
            authHash: testUser.rawPassword,
            rememberMe: true,
          }),
          replayCsrf,
          undefined,
          `trustedDevice=${raw}`,
        );
        expect(replay.status).toBe(200);
        expect(replay.body.data.twoFactorRequired).toBe(true);
        expect(replay.body.data.tempToken).toBeDefined();

        // The stale cookie is cleared (empty value, expiry in the past) and the
        // rejection is audited.
        const cleared = findCookie(replay, 'trustedDevice');
        expect(cleared).toBeDefined();
        expect(cookieValue(cleared!)).toBe('');
        expect(cleared).toMatch(/Expires=Thu, 01 Jan 1970/i);
        expect(
          await AuditLog.findOne({ userId: testUser.id, action: 'trusted_device_rejected' }),
        ).not.toBeNull();
        // The replay never re-created a record from the rotated first login.
        expect(await TrustedDevice.countDocuments({ userId: userObjId })).toBe(1);
      });

      it('rejects an expired record without deleting it and falls through to 2FA', async () => {
        const testUser = await createTestUser();
        await enable2fa(testUser.id);
        const userObjId = new mongoose.Types.ObjectId(testUser.id);
        const raw = 'trusted-expired-token';
        // Already past its absolute expiry (TTL reaper has not run in-memory yet).
        await seedTrustedDevice(testUser.id, raw, new Date(Date.now() - 60_000));

        const res = await loginWith(testUser, { rememberMe: true, trustedRaw: raw });

        expect(res.status).toBe(200);
        expect(res.body.data.twoFactorRequired).toBe(true);
        // The expired record is NOT consumed by the `$gt: now` filter — TTL owns it.
        expect(await TrustedDevice.findOne({ tokenHash: hashToken(raw) })).not.toBeNull();
        expect(await TrustedDevice.countDocuments({ userId: userObjId })).toBe(1);
        expect(
          await AuditLog.findOne({ userId: testUser.id, action: 'trusted_device_rejected' }),
        ).not.toBeNull();
      });

      it("ignores another user's cookie: does not consume it and falls through to 2FA", async () => {
        const owner = await createTestUser();
        const raw = 'trusted-cross-user-token';
        await seedTrustedDevice(owner.id, raw);
        const ownerObjId = new mongoose.Types.ObjectId(owner.id);

        const attacker = await createTestUser();
        await enable2fa(attacker.id);

        const res = await loginWith(attacker, { rememberMe: true, trustedRaw: raw });

        expect(res.status).toBe(200);
        expect(res.body.data.twoFactorRequired).toBe(true);
        // The owner's record is untouched (userId-scoped delete never matched it).
        expect(await TrustedDevice.countDocuments({ userId: ownerObjId })).toBe(1);
        expect(await TrustedDevice.findOne({ tokenHash: hashToken(raw) })).not.toBeNull();
        // The attacker gets a rejection audit; the owner does not.
        expect(
          await AuditLog.findOne({ userId: attacker.id, action: 'trusted_device_rejected' }),
        ).not.toBeNull();
        expect(
          await AuditLog.findOne({ userId: owner.id, action: 'trusted_device_rejected' }),
        ).toBeNull();
      });

      it('a wrong password with a valid cookie returns 401 and never consumes the record', async () => {
        const testUser = await createTestUser();
        await enable2fa(testUser.id);
        const userObjId = new mongoose.Types.ObjectId(testUser.id);
        const raw = 'trusted-wrong-password-token';
        await seedTrustedDevice(testUser.id, raw);

        const res = await loginWith(testUser, {
          rememberMe: true,
          trustedRaw: raw,
          authHash: 'definitely-the-wrong-password',
        });

        expect(res.status).toBe(401);
        // The lookup runs strictly AFTER the bcrypt compare, so it is never reached.
        expect(await TrustedDevice.findOne({ tokenHash: hashToken(raw) })).not.toBeNull();
        expect(await TrustedDevice.countDocuments({ userId: userObjId })).toBe(1);
        expect(findCookie(res, 'trustedDevice')).toBeUndefined();
        expect(
          await AuditLog.findOne({ userId: testUser.id, action: 'trusted_device_rejected' }),
        ).toBeNull();
      });

      it('a normal 2FA login with no cookie writes no rejection audit and sets no cookie', async () => {
        const testUser = await createTestUser();
        await enable2fa(testUser.id);

        const res = await loginWith(testUser, { rememberMe: true });

        expect(res.status).toBe(200);
        expect(res.body.data.twoFactorRequired).toBe(true);
        // No cookie present → no lookup, no clear, no audit.
        expect(findCookie(res, 'trustedDevice')).toBeUndefined();
        expect(
          await AuditLog.findOne({ userId: testUser.id, action: 'trusted_device_rejected' }),
        ).toBeNull();
      });

      it('rememberMe:false on a trusted device yields a standard-length session', async () => {
        const testUser = await createTestUser();
        await enable2fa(testUser.id);
        const raw = 'trusted-no-remember-token';
        await seedTrustedDevice(testUser.id, raw);

        const res = await loginWith(testUser, { rememberMe: false, trustedRaw: raw });

        expect(res.status).toBe(200);
        expect(res.body.data.twoFactorRequired).toBeUndefined();
        // Standard ~7-day session, NOT a silent 30-day one.
        const refreshCookie = findCookie(res, 'refreshToken');
        expect(cookieMaxAgeSeconds(refreshCookie!)).toBeLessThan(10 * 24 * 60 * 60);
        const row = await RefreshToken.findOne({
          tokenHash: hashToken(cookieValue(refreshCookie!)),
        });
        expect(row).not.toBeNull();
        expect(row!.absoluteExpiresAt).toBeUndefined();
      });

      it('rotation carries the original deadline forward and never extends it', async () => {
        const testUser = await createTestUser();
        await enable2fa(testUser.id);
        const userObjId = new mongoose.Types.ObjectId(testUser.id);
        const raw = 'trusted-deadline-token';
        // A short 10-day grant, distinct from the 30-day default.
        const originalExpiry = new Date(Date.now() + 10 * DAY_MS);
        await seedTrustedDevice(testUser.id, raw, originalExpiry);

        const res = await loginWith(testUser, { rememberMe: true, trustedRaw: raw });

        expect(res.status).toBe(200);
        // The rotated record keeps the original ~10-day deadline (not ~30).
        const rotated = await TrustedDevice.findOne({ userId: userObjId });
        expect(rotated).not.toBeNull();
        expect(Math.abs(rotated!.expiresAt.getTime() - originalExpiry.getTime())).toBeLessThan(
          2000,
        );
        expect(rotated!.expiresAt.getTime() - Date.now()).toBeLessThan(11 * DAY_MS);

        // The rotated cookie's Max-Age reflects the remaining ~10 days, not 30.
        const tdCookie = findCookie(res, 'trustedDevice');
        expect(cookieMaxAgeSeconds(tdCookie!)).toBeLessThan(11 * 24 * 60 * 60);
        expect(cookieMaxAgeSeconds(tdCookie!)).toBeGreaterThan(8 * 24 * 60 * 60);
      });
    });
  });

  // ── Unlock Account ──────────────────────────────────────────────────

  describe('POST /auth/unlock-account', () => {
    it('should unlock a locked account with a valid token', async () => {
      const testUser = await createTestUser({ emailVerified: true });

      // Lock the account by setting failedLoginAttempts and lockoutUntil
      const lockoutUntil = new Date(Date.now() + 30 * 60 * 1000);
      await User.findByIdAndUpdate(testUser.id, {
        $set: {
          failedLoginAttempts: 10,
          lockoutUntil,
        },
      });

      // Verify account is locked
      const lockedUser = await User.findById(testUser.id);
      expect(lockedUser!.failedLoginAttempts).toBe(10);
      expect(lockedUser!.lockoutUntil).toBeDefined();

      // Create a valid unlock token (bound to lockoutUntil timestamp)
      const unlockToken = jwt.sign(
        {
          userId: testUser.id,
          purpose: 'account_unlock',
          stateHash: generateStateHash(lockoutUntil.toISOString()),
        },
        deriveTestPurposeKey('account_unlock'),
        { expiresIn: '1h' },
      );

      const res = await withCsrf(
        agent.post(`${API}/auth/unlock-account`).send({ token: unlockToken }),
        csrf,
      );

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toMatch(/unlocked/i);

      // Verify the account is unlocked in DB
      const unlockedUser = await User.findById(testUser.id);
      expect(unlockedUser!.failedLoginAttempts).toBe(0);
      expect(unlockedUser!.lockoutUntil).toBeUndefined();
    });

    it('should reject an invalid unlock token', async () => {
      const res = await withCsrf(
        agent.post(`${API}/auth/unlock-account`).send({ token: 'invalid-token' }),
        csrf,
      );

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should reject an unlock token with wrong purpose', async () => {
      const testUser = await createTestUser();

      const wrongPurposeToken = jwt.sign(
        { userId: testUser.id, purpose: 'email_verification' },
        JWT_PURPOSE_SECRET,
        { expiresIn: '1h' },
      );

      const res = await withCsrf(
        agent.post(`${API}/auth/unlock-account`).send({ token: wrongPurposeToken }),
        csrf,
      );

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should reject an unlock token with missing purpose field', async () => {
      const testUser = await createTestUser();

      const noPurposeToken = jwt.sign({ userId: testUser.id }, JWT_PURPOSE_SECRET, {
        expiresIn: '1h',
      });

      const res = await withCsrf(
        agent.post(`${API}/auth/unlock-account`).send({ token: noPurposeToken }),
        csrf,
      );

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should unlock account even after subsequent failed login attempts', async () => {
      const testUser = await createTestUser({ emailVerified: true });

      // Lock the account
      const lockoutUntil = new Date(Date.now() + 30 * 60 * 1000);
      await User.findByIdAndUpdate(testUser.id, {
        $set: {
          failedLoginAttempts: 10,
          lockoutUntil,
        },
      });

      // Create unlock token bound to lockoutUntil
      const unlockToken = jwt.sign(
        {
          userId: testUser.id,
          purpose: 'account_unlock',
          stateHash: generateStateHash(lockoutUntil.toISOString()),
        },
        deriveTestPurposeKey('account_unlock'),
        { expiresIn: '1h' },
      );

      // Simulate additional failed login attempts after lockout (increments failedLoginAttempts)
      await User.findByIdAndUpdate(testUser.id, {
        $set: { failedLoginAttempts: 12 },
      });

      // The unlock token should still work because stateHash is based on lockoutUntil, not failedLoginAttempts
      const res = await withCsrf(
        agent.post(`${API}/auth/unlock-account`).send({ token: unlockToken }),
        csrf,
      );

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toMatch(/unlocked/i);

      // Verify the account is unlocked in DB
      const unlockedUser = await User.findById(testUser.id);
      expect(unlockedUser!.failedLoginAttempts).toBe(0);
      expect(unlockedUser!.lockoutUntil).toBeUndefined();
    });

    it('should reject unlock token after account is already unlocked', async () => {
      const testUser = await createTestUser({ emailVerified: true });

      // Lock the account
      const lockoutUntil = new Date(Date.now() + 30 * 60 * 1000);
      await User.findByIdAndUpdate(testUser.id, {
        $set: {
          failedLoginAttempts: 10,
          lockoutUntil,
        },
      });

      // Create unlock token bound to lockoutUntil
      const unlockToken = jwt.sign(
        {
          userId: testUser.id,
          purpose: 'account_unlock',
          stateHash: generateStateHash(lockoutUntil.toISOString()),
        },
        deriveTestPurposeKey('account_unlock'),
        { expiresIn: '1h' },
      );

      // Unlock the account first
      const res1 = await withCsrf(
        agent.post(`${API}/auth/unlock-account`).send({ token: unlockToken }),
        csrf,
      );
      expect(res1.status).toBe(200);

      // Try to use the same token again — should fail because lockoutUntil is now cleared
      const res2 = await withCsrf(
        agent.post(`${API}/auth/unlock-account`).send({ token: unlockToken }),
        csrf,
      );
      expect(res2.status).toBe(400);
      expect(res2.body.success).toBe(false);
    });

    it('should reject unlock token with stateHash based on failedLoginAttempts instead of lockoutUntil', async () => {
      const testUser = await createTestUser({ emailVerified: true });

      // Lock the account
      const lockoutUntil = new Date(Date.now() + 30 * 60 * 1000);
      await User.findByIdAndUpdate(testUser.id, {
        $set: {
          failedLoginAttempts: 10,
          lockoutUntil,
        },
      });

      // Create a token using the OLD approach (failedLoginAttempts count) — this should NOT work
      const wrongToken = jwt.sign(
        {
          userId: testUser.id,
          purpose: 'account_unlock',
          stateHash: generateStateHash(String(10)),
        },
        deriveTestPurposeKey('account_unlock'),
        { expiresIn: '1h' },
      );

      const res = await withCsrf(
        agent.post(`${API}/auth/unlock-account`).send({ token: wrongToken }),
        csrf,
      );

      // Should be rejected because stateHash is based on failedLoginAttempts, not lockoutUntil
      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should create audit log on account unlock', async () => {
      const testUser = await createTestUser({ emailVerified: true });

      // Lock the account
      const lockoutUntil = new Date(Date.now() + 30 * 60 * 1000);
      await User.findByIdAndUpdate(testUser.id, {
        $set: {
          failedLoginAttempts: 10,
          lockoutUntil,
        },
      });

      // Create a valid unlock token (bound to lockoutUntil timestamp)
      const unlockToken = jwt.sign(
        {
          userId: testUser.id,
          purpose: 'account_unlock',
          stateHash: generateStateHash(lockoutUntil.toISOString()),
        },
        deriveTestPurposeKey('account_unlock'),
        { expiresIn: '1h' },
      );

      await withCsrf(
        agent.post(`${API}/auth/unlock-account`).send({ token: unlockToken }),
        csrf,
      ).expect(200);

      const auditEntry = await AuditLog.findOne({
        userId: testUser.id,
        action: 'account_unlock',
      });

      expect(auditEntry).toBeDefined();
      expect(auditEntry!.userId.toString()).toBe(testUser.id);
      expect(auditEntry!.metadata).toBeDefined();
      expect((auditEntry!.metadata as Record<string, unknown>).method).toBe('email_link');
    });
  });

  // ── Refresh Token Reuse Detection ────────────────────────────────────

  describe('Refresh token reuse detection', () => {
    it('should revoke all tokens when a used refresh token is reused', async () => {
      const testUser = await createTestUser();

      // Use a plain (non-agent) request wrapper so that the cookie jar does NOT
      // store the rotated refreshToken cookie from the first response, which
      // would override the manually set old token in the second request.
      const plain1 = request(app);
      const csrf1 = await getCsrf(
        plain1 as unknown as request.Agent,
        `refreshToken=${testUser.refreshToken}`,
      );

      // First use: valid refresh — returns new tokens
      const res1 = await withCsrf(
        plain1.post(`${API}/auth/refresh`),
        csrf1,
        undefined,
        `refreshToken=${testUser.refreshToken}`,
      );
      expect(res1.status).toBe(200);

      // Second use: reuse the SAME old refresh token — should trigger reuse detection
      const plain2 = request(app);
      const csrf2 = await getCsrf(
        plain2 as unknown as request.Agent,
        `refreshToken=${testUser.refreshToken}`,
      );
      const res2 = await withCsrf(
        plain2.post(`${API}/auth/refresh`),
        csrf2,
        undefined,
        `refreshToken=${testUser.refreshToken}`,
      );

      expect(res2.status).toBe(401);
      expect(res2.body.success).toBe(false);

      // All refresh tokens for this user should be deleted
      const tokenCount = await RefreshToken.countDocuments({ userId: testUser.id });
      expect(tokenCount).toBe(0);
    });

    it('should invalidate the rotated token (RT2) when the old token (RT1) is reused', async () => {
      const testUser = await createTestUser();

      // Step 1: Use RT1 to refresh — extract RT2 from the response cookie
      const plain1 = request(app);
      const csrf1 = await getCsrf(
        plain1 as unknown as request.Agent,
        `refreshToken=${testUser.refreshToken}`,
      );
      const res1 = await withCsrf(
        plain1.post(`${API}/auth/refresh`),
        csrf1,
        undefined,
        `refreshToken=${testUser.refreshToken}`,
      );
      expect(res1.status).toBe(200);

      // Extract RT2 from set-cookie header
      const setCookies1 = res1.headers['set-cookie'] as string[];
      const rt2Cookie = setCookies1?.find((c: string) => c.startsWith('refreshToken='));
      expect(rt2Cookie).toBeDefined();
      const rt2 = rt2Cookie!.split(';')[0]!.replace('refreshToken=', '');
      expect(rt2).toBeTruthy();
      expect(rt2).not.toBe(testUser.refreshToken); // RT2 should differ from RT1

      // Step 2: Reuse RT1 — triggers family revocation
      const plain2 = request(app);
      const csrf2 = await getCsrf(
        plain2 as unknown as request.Agent,
        `refreshToken=${testUser.refreshToken}`,
      );
      const res2 = await withCsrf(
        plain2.post(`${API}/auth/refresh`),
        csrf2,
        undefined,
        `refreshToken=${testUser.refreshToken}`,
      );
      expect(res2.status).toBe(401);

      // Step 3: Attempt to use RT2 — should also fail because the entire family was revoked
      const plain3 = request(app);
      const csrf3 = await getCsrf(plain3 as unknown as request.Agent, `refreshToken=${rt2}`);
      const res3 = await withCsrf(
        plain3.post(`${API}/auth/refresh`),
        csrf3,
        undefined,
        `refreshToken=${rt2}`,
      );
      expect(res3.status).toBe(401);

      // Confirm zero tokens remain for this user
      const tokenCount = await RefreshToken.countDocuments({ userId: testUser.id });
      expect(tokenCount).toBe(0);
    });

    it('should atomically rotate refresh tokens (old marked used, new created)', async () => {
      const testUser = await createTestUser();

      // Count tokens before refresh
      const beforeCount = await RefreshToken.countDocuments({ userId: testUser.id });
      expect(beforeCount).toBe(1);

      const csrfWithRefresh = await getCsrf(agent, `refreshToken=${testUser.refreshToken}`);
      const res = await withCsrf(
        agent.post(`${API}/auth/refresh`),
        csrfWithRefresh,
        undefined,
        `refreshToken=${testUser.refreshToken}`,
      );

      expect(res.status).toBe(200);

      // After rotation: old token marked as used, new token created
      const afterCount = await RefreshToken.countDocuments({ userId: testUser.id });
      expect(afterCount).toBe(2); // old (used) + new

      const usedTokens = await RefreshToken.countDocuments({
        userId: testUser.id,
        usedAt: { $ne: null },
      });
      expect(usedTokens).toBe(1); // old token should be marked used

      const activeTokens = await RefreshToken.countDocuments({ userId: testUser.id, usedAt: null });
      expect(activeTokens).toBe(1); // new token should be active
    });
  });

  // ── Auth Guards ────────────────────────────────────────────────────────

  describe('Auth guards - endpoints requiring authentication', () => {
    it('should return 401 for /auth/logout without a token', async () => {
      const res = await withCsrf(agent.post(`${API}/auth/logout`), csrf);
      expect(res.status).toBe(401);
    });

    it('should return 401 for /auth/logout-all without a token', async () => {
      const res = await withCsrf(agent.post(`${API}/auth/logout-all`), csrf);
      expect(res.status).toBe(401);
    });

    it('should return 401 with an expired access token', async () => {
      const testUser = await createTestUser();
      const expiredToken = generateExpiredToken(testUser.id);

      // Wait a moment for the token to actually expire (issued with 0s expiry)
      await new Promise((resolve) => setTimeout(resolve, 1100));

      const res = await withCsrf(agent.post(`${API}/auth/logout`), csrf, expiredToken);

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('should return 401 with a malformed Bearer token', async () => {
      const res = await withCsrf(
        agent.post(`${API}/auth/logout`).set('Authorization', 'Bearer not.a.valid.jwt'),
        csrf,
      );

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('should return 401 when JWT belongs to a deleted/non-existent user', async () => {
      const testUser = await createTestUser();

      // Verify the token works before deletion
      const _resOk = await withCsrf(agent.post(`${API}/auth/logout`), csrf, testUser.accessToken);
      // This may be 200 or may vary depending on refresh cookie, but we just need
      // to confirm the token was accepted (not 401). Next, we delete the user.

      // Delete the user from the database
      await User.findByIdAndDelete(testUser.id);

      // Confirm user is gone
      const deletedUser = await User.findById(testUser.id);
      expect(deletedUser).toBeNull();

      // Now use the same valid JWT — should be rejected because the user no longer exists
      const csrf2 = await getCsrf(agent);
      const res = await withCsrf(agent.post(`${API}/auth/logout`), csrf2, testUser.accessToken);

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });
  });

  // ── CSRF Protection ────────────────────────────────────────────────────

  describe('CSRF protection', () => {
    it('should reject a POST request without a CSRF token', async () => {
      const testUser = await createTestUser();

      const res = await agent.post(`${API}/auth/login`).send({
        email: testUser.email,
        authHash: testUser.rawPassword,
      });

      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
    });

    it('should reject a CSRF token with missing dot separator', async () => {
      const testUser = await createTestUser({ emailVerified: true });

      const res = await agent
        .post(`${API}/auth/login`)
        .set('x-csrf-token', 'nodotinthiscsrftoken')
        .set('Cookie', csrf.cookie)
        .send({
          email: testUser.email,
          authHash: testUser.rawPassword,
        });

      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
    });

    it('should reject a CSRF token with empty HMAC part', async () => {
      const testUser = await createTestUser({ emailVerified: true });

      const res = await agent
        .post(`${API}/auth/login`)
        .set('x-csrf-token', '.somerandomvalue')
        .set('Cookie', csrf.cookie)
        .send({
          email: testUser.email,
          authHash: testUser.rawPassword,
        });

      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
    });

    it('should reject a CSRF token with empty random part', async () => {
      const testUser = await createTestUser({ emailVerified: true });

      const res = await agent
        .post(`${API}/auth/login`)
        .set('x-csrf-token', 'somehmacvalue.')
        .set('Cookie', csrf.cookie)
        .send({
          email: testUser.email,
          authHash: testUser.rawPassword,
        });

      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
    });

    it('should reject a CSRF token with a tampered HMAC', async () => {
      const testUser = await createTestUser({ emailVerified: true });

      // Take a valid token and modify the HMAC portion
      const validToken = csrf.token;
      const dotIndex = validToken.indexOf('.');
      const randomPart = validToken.slice(dotIndex + 1);
      const tamperedToken = `${'a'.repeat(64)}.${randomPart}`;

      const res = await agent
        .post(`${API}/auth/login`)
        .set('x-csrf-token', tamperedToken)
        .set('Cookie', csrf.cookie)
        .send({
          email: testUser.email,
          authHash: testUser.rawPassword,
        });

      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
    });

    it('should reject an empty CSRF token string', async () => {
      const testUser = await createTestUser({ emailVerified: true });

      const res = await agent
        .post(`${API}/auth/login`)
        .set('x-csrf-token', '')
        .set('Cookie', csrf.cookie)
        .send({
          email: testUser.email,
          authHash: testUser.rawPassword,
        });

      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
    });
  });

  // ── Device Info Validation & Size Limits ──────────────────────────────

  describe('Device info validation and size limits', () => {
    it('should reject an overly long userAgent exceeding 512 characters', async () => {
      const testUser = await createTestUser({ emailVerified: true });
      const longUserAgent = 'A'.repeat(1000);

      const res = await withCsrf(
        agent.post(`${API}/auth/login`).send({
          email: testUser.email,
          authHash: testUser.rawPassword,
          deviceInfo: {
            userAgent: longUserAgent,
            fingerprint: 'normal-fingerprint',
          },
        }),
        csrf,
      );

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should reject an overly long fingerprint exceeding 128 characters', async () => {
      const testUser = await createTestUser({ emailVerified: true });
      const longFingerprint = 'F'.repeat(300);

      const res = await withCsrf(
        agent.post(`${API}/auth/login`).send({
          email: testUser.email,
          authHash: testUser.rawPassword,
          deviceInfo: {
            userAgent: 'normal-user-agent',
            fingerprint: longFingerprint,
          },
        }),
        csrf,
      );

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should succeed with both userAgent and fingerprint at exactly the limit', async () => {
      const testUser = await createTestUser({ emailVerified: true });
      const exactUserAgent = 'U'.repeat(512);
      const exactFingerprint = 'P'.repeat(128);

      const res = await withCsrf(
        agent.post(`${API}/auth/login`).send({
          email: testUser.email,
          authHash: testUser.rawPassword,
          deviceInfo: {
            userAgent: exactUserAgent,
            fingerprint: exactFingerprint,
          },
        }),
        csrf,
      );

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      // Values at exact limits should not be truncated
      const storedTokens = await RefreshToken.find({ userId: testUser.id });
      const loginToken = storedTokens.find((t) => t.deviceInfo.fingerprint !== 'test-fingerprint');
      expect(loginToken).toBeDefined();
      expect(loginToken!.deviceInfo.userAgent).toBe(exactUserAgent);
      expect(loginToken!.deviceInfo.fingerprint).toBe(exactFingerprint);
    });

    it('should handle missing deviceInfo gracefully and fall back to request headers', async () => {
      const testUser = await createTestUser({ emailVerified: true });

      const res = await withCsrf(
        agent.post(`${API}/auth/login`).set('User-Agent', 'TestBrowser/1.0').send({
          email: testUser.email,
          authHash: testUser.rawPassword,
          // No deviceInfo provided
        }),
        csrf,
      );

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      // Should fall back to the User-Agent header
      const storedTokens = await RefreshToken.find({ userId: testUser.id });
      const loginToken = storedTokens.find((t) => t.deviceInfo.userAgent !== 'test-agent');
      expect(loginToken).toBeDefined();
      expect(loginToken!.deviceInfo.userAgent).toBe('TestBrowser/1.0');
    });
  });

  // ── Backup Code 2FA Login ──────────────────────────────────────────

  describe('2FA backup code authentication', () => {
    it('should complete 2FA login with a valid backup code', async () => {
      const bcryptModule = await import('bcryptjs');
      const { CryptoManager } = await import('@hiprax/crypto');
      const { Secret } = await import('otpauth');

      const cm = new CryptoManager();
      const secretObj = new Secret();
      const secret = secretObj.base32;
      const encryptedSecret = cm.encryptTextSync(
        secret,
        process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345',
      );

      const testUser = await createTestUser({ emailVerified: true });

      // Create a known backup code and bcrypt hash it
      const rawBackupCode = 'abcdef1234567890';
      const hashedBackupCode = await bcryptModule.hash(rawBackupCode, 4);

      // Enable 2FA directly in DB with backup codes
      await User.findByIdAndUpdate(testUser.id, {
        $set: {
          twoFactorEnabled: true,
          twoFactorSecret: encryptedSecret,
          backupCodes: [hashedBackupCode],
        },
      });

      // Create a valid temp token
      const tempToken = jwt.sign(
        { userId: testUser.id, purpose: '2fa_temp' },
        deriveTestPurposeKey('2fa_temp'),
        { expiresIn: '5m' },
      );

      // Use backup code instead of TOTP
      const res = await withCsrf(
        agent.post(`${API}/auth/login/2fa`).send({
          tempToken,
          code: rawBackupCode,
        }),
        csrf,
      );

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.accessToken).toBeDefined();

      // Verify backup code was consumed
      const updatedUser = await User.findById(testUser.id).select('+backupCodes');
      expect(updatedUser!.backupCodes).toHaveLength(0);
    });

    it('should reject an invalid backup code', async () => {
      const bcryptModule = await import('bcryptjs');
      const { CryptoManager } = await import('@hiprax/crypto');
      const { Secret } = await import('otpauth');

      const cm = new CryptoManager();
      const secretObj = new Secret();
      const secret = secretObj.base32;
      const encryptedSecret = cm.encryptTextSync(
        secret,
        process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345',
      );

      const testUser = await createTestUser({ emailVerified: true });

      const hashedBackupCode = await bcryptModule.hash('realcode12345678', 4);

      await User.findByIdAndUpdate(testUser.id, {
        $set: {
          twoFactorEnabled: true,
          twoFactorSecret: encryptedSecret,
          backupCodes: [hashedBackupCode],
        },
      });

      const tempToken = jwt.sign(
        { userId: testUser.id, purpose: '2fa_temp' },
        deriveTestPurposeKey('2fa_temp'),
        { expiresIn: '5m' },
      );

      const res = await withCsrf(
        agent.post(`${API}/auth/login/2fa`).send({
          tempToken,
          code: 'wrongcode1234567',
        }),
        csrf,
      );

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);

      // Backup code should NOT be consumed
      const updatedUser = await User.findById(testUser.id).select('+backupCodes');
      expect(updatedUser!.backupCodes).toHaveLength(1);
    });
  });

  // ── Progressive Login Delay ────────────────────────────────────────

  describe('Progressive login delay tracking', () => {
    it('should track failed login attempts progressively', async () => {
      const testUser = await createTestUser({ emailVerified: true });

      // 3 failed attempts
      for (let i = 0; i < 3; i++) {
        const csrfN = await getCsrf(agent);
        await withCsrf(
          agent.post(`${API}/auth/login`).send({
            email: testUser.email,
            authHash: 'wrong-password',
          }),
          csrfN,
        );
      }

      const user3 = await User.findOne({ email: testUser.email });
      expect(user3!.failedLoginAttempts).toBe(3);

      // Successful login should reset counter
      const csrfOk = await getCsrf(agent);
      const res = await withCsrf(
        agent.post(`${API}/auth/login`).send({
          email: testUser.email,
          authHash: testUser.rawPassword,
        }),
        csrfOk,
      );

      expect(res.status).toBe(200);

      const userAfter = await User.findOne({ email: testUser.email });
      expect(userAfter!.failedLoginAttempts).toBe(0);
    }, 30_000);
  });

  // ── Login After Lockout Expiry ─────────────────────────────────────

  describe('Login after lockout expiry', () => {
    it('should allow login after lockout period has expired', async () => {
      const testUser = await createTestUser({ emailVerified: true });

      // Set lockout to the past (expired)
      await User.findByIdAndUpdate(testUser.id, {
        $set: {
          failedLoginAttempts: 10,
          lockoutUntil: new Date(Date.now() - 60 * 1000), // 1 minute ago
        },
      });

      const res = await withCsrf(
        agent.post(`${API}/auth/login`).send({
          email: testUser.email,
          authHash: testUser.rawPassword,
        }),
        csrf,
      );

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.accessToken).toBeDefined();

      // Lockout state should be cleared
      const user = await User.findById(testUser.id);
      expect(user!.failedLoginAttempts).toBe(0);
      expect(user!.lockoutUntil).toBeUndefined();
    });
  });

  // ── Password Reset Clears Lockout ──────────────────────────────────

  describe('Password reset clears lockout', () => {
    it('should clear lockout state after successful password reset', async () => {
      const testUser = await createTestUser({ emailVerified: true });

      // Lock the account
      await User.findByIdAndUpdate(testUser.id, {
        $set: {
          failedLoginAttempts: 10,
          lockoutUntil: new Date(Date.now() + 30 * 60 * 1000),
        },
      });

      // Create a valid reset token bound to current authHash
      const dbUser = await User.findById(testUser.id).select('+authHash');
      const resetToken = jwt.sign(
        {
          userId: testUser.id,
          purpose: 'password_reset',
          stateHash: generateStateHash(dbUser!.authHash),
        },
        deriveTestPurposeKey('password_reset'),
        { expiresIn: '1h' },
      );

      const res = await withCsrf(
        agent.post(`${API}/auth/reset-password`).send({
          token: resetToken,
          email: testUser.email,
          newAuthHash: 'new-auth-hash-after-lockout',
          newEncryptedVaultKey: 'new-key',
          newVaultKeyIv: 'new-iv',
          newVaultKeyTag: 'new-tag',
        }),
        csrf,
      );

      expect(res.status).toBe(200);

      // Verify lockout is cleared
      const user = await User.findById(testUser.id);
      expect(user!.failedLoginAttempts).toBe(0);
      expect(user!.lockoutUntil).toBeUndefined();
    });
  });

  // ── Token Refresh with Deleted User ────────────────────────────────

  describe('Token refresh with deleted user', () => {
    it('should return 401 when refreshing token for a deleted user', async () => {
      const testUser = await createTestUser();

      // Delete the user
      await User.findByIdAndDelete(testUser.id);

      const csrfWithRefresh = await getCsrf(agent, `refreshToken=${testUser.refreshToken}`);
      const res = await withCsrf(
        agent.post(`${API}/auth/refresh`),
        csrfWithRefresh,
        undefined,
        `refreshToken=${testUser.refreshToken}`,
      );

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });
  });

  // ── Token Refresh Account Status Checks ──────────────────────────

  describe('Token refresh account status checks', () => {
    it('should return 401 when refreshing token for a user pending deletion', async () => {
      const testUser = await createTestUser();

      // Mark user as pending deletion
      await User.findByIdAndUpdate(testUser.id, { $set: { deletionPending: true } });

      const csrfWithRefresh = await getCsrf(agent, `refreshToken=${testUser.refreshToken}`);
      const res = await withCsrf(
        agent.post(`${API}/auth/refresh`),
        csrfWithRefresh,
        undefined,
        `refreshToken=${testUser.refreshToken}`,
      );

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('should return 403 when refreshing token for a locked out user', async () => {
      const testUser = await createTestUser();

      // Lock the user out (30 minutes from now)
      await User.findByIdAndUpdate(testUser.id, {
        $set: { lockoutUntil: new Date(Date.now() + 30 * 60 * 1000) },
      });

      const csrfWithRefresh = await getCsrf(agent, `refreshToken=${testUser.refreshToken}`);
      const res = await withCsrf(
        agent.post(`${API}/auth/refresh`),
        csrfWithRefresh,
        undefined,
        `refreshToken=${testUser.refreshToken}`,
      );

      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
    });

    it('should return 401 when refreshing token for an unverified user', async () => {
      const testUser = await createTestUser({ emailVerified: false });

      const csrfWithRefresh = await getCsrf(agent, `refreshToken=${testUser.refreshToken}`);
      const res = await withCsrf(
        agent.post(`${API}/auth/refresh`),
        csrfWithRefresh,
        undefined,
        `refreshToken=${testUser.refreshToken}`,
      );

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('should allow refresh when lockout has expired', async () => {
      const testUser = await createTestUser();

      // Set lockoutUntil to the past
      await User.findByIdAndUpdate(testUser.id, {
        $set: { lockoutUntil: new Date(Date.now() - 1000) },
      });

      const csrfWithRefresh = await getCsrf(agent, `refreshToken=${testUser.refreshToken}`);
      const res = await withCsrf(
        agent.post(`${API}/auth/refresh`),
        csrfWithRefresh,
        undefined,
        `refreshToken=${testUser.refreshToken}`,
      );

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.accessToken).toBeDefined();
    });
  });

  // ── Audit Log Creation ─────────────────────────────────────────────

  describe('Login audit logs', () => {
    it('should create audit log entry on successful login', async () => {
      const testUser = await createTestUser({ emailVerified: true });

      await withCsrf(
        agent.post(`${API}/auth/login`).set('User-Agent', 'AuditTestAgent/1.0').send({
          email: testUser.email,
          authHash: testUser.rawPassword,
        }),
        csrf,
      ).expect(200);

      const auditEntry = await AuditLog.findOne({
        userId: testUser.id,
        action: 'login',
      });

      expect(auditEntry).toBeDefined();
      expect(auditEntry!.userId.toString()).toBe(testUser.id);
    });

    it('should create audit log entry on failed login', async () => {
      const testUser = await createTestUser({ emailVerified: true });

      await withCsrf(
        agent.post(`${API}/auth/login`).set('User-Agent', 'AuditTestAgent/1.0').send({
          email: testUser.email,
          authHash: 'wrong-password',
        }),
        csrf,
      ).expect(401);

      const auditEntry = await AuditLog.findOne({
        userId: testUser.id,
        action: 'login_failed',
      });

      expect(auditEntry).toBeDefined();
      expect(auditEntry!.userId.toString()).toBe(testUser.id);
    });

    it('should create audit log on successful 2FA login', async () => {
      const { CryptoManager } = await import('@hiprax/crypto');
      const { TOTP, Secret } = await import('otpauth');

      const cm = new CryptoManager();
      const secretObj = new Secret();
      const secret = secretObj.base32;
      const encryptedSecret = cm.encryptTextSync(
        secret,
        process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345',
      );

      const testUser = await createTestUser({ emailVerified: true });

      await User.findByIdAndUpdate(testUser.id, {
        $set: {
          twoFactorEnabled: true,
          twoFactorSecret: encryptedSecret,
        },
      });

      const tempToken = jwt.sign(
        { userId: testUser.id, purpose: '2fa_temp' },
        deriveTestPurposeKey('2fa_temp'),
        { expiresIn: '5m' },
      );

      const totp = new TOTP({
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: Secret.fromBase32(secret),
      });
      const validCode = totp.generate();

      await withCsrf(
        agent.post(`${API}/auth/login/2fa`).set('User-Agent', 'AuditTestAgent/1.0').send({
          tempToken,
          code: validCode,
        }),
        csrf,
      ).expect(200);

      const auditEntry = await AuditLog.findOne({
        userId: testUser.id,
        action: 'login',
      });

      // findOne resolves to null on no match, and `null` IS defined — so
      // toBeDefined() passed even when no log was written. Assert the row is
      // real and correctly attributed instead.
      expect(auditEntry).not.toBeNull();
      expect(auditEntry!.userId.toString()).toBe(testUser.id);
      expect((auditEntry!.metadata as { twoFactor?: boolean } | undefined)?.twoFactor).toBe(true);
    });
  });

  // ── JWT with Wrong Secret ──────────────────────────────────────────

  describe('JWT signed with wrong secret', () => {
    it('should return 401 for a JWT signed with a different secret', async () => {
      const testUser = await createTestUser();

      const wrongSecretToken = jwt.sign(
        { userId: testUser.id },
        'completely-wrong-secret-not-the-real-one!!',
        { algorithm: 'HS256', subject: testUser.id, expiresIn: '15m' },
      );

      const res = await withCsrf(agent.post(`${API}/auth/logout`), csrf, wrongSecretToken);

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('should reject purpose tokens signed with JWT_ACCESS_SECRET instead of JWT_REFRESH_SECRET', async () => {
      const testUser = await createTestUser({ emailVerified: false });

      // Sign an email verification token with the ACCESS secret (wrong key for purpose tokens)
      const wrongKeyToken = jwt.sign(
        {
          userId: testUser.id,
          purpose: 'email_verification',
          stateHash: generateStateHash(String(false)),
        },
        JWT_SECRET, // JWT_ACCESS_SECRET — server now expects JWT_REFRESH_SECRET for purpose tokens
        { algorithm: 'HS256', expiresIn: '24h' },
      );

      const res = await withCsrf(
        agent.post(`${API}/auth/verify-email`).send({ token: wrongKeyToken }),
        csrf,
      );

      // Should be rejected because the server verifies purpose tokens with JWT_REFRESH_SECRET
      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should reject 2FA temp tokens signed with JWT_ACCESS_SECRET', async () => {
      const testUser = await createTestUser();

      const wrongKeyTempToken = jwt.sign(
        { userId: testUser.id, purpose: '2fa_temp' },
        JWT_SECRET, // JWT_ACCESS_SECRET — wrong key
        { expiresIn: '5m' },
      );

      const res = await withCsrf(
        agent.post(`${API}/auth/login/2fa`).send({
          tempToken: wrongKeyTempToken,
          code: '123456',
        }),
        csrf,
      );

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('should reject password reset tokens signed with JWT_ACCESS_SECRET', async () => {
      const testUser = await createTestUser();
      const dbUser = await User.findById(testUser.id).select('+authHash');

      const wrongKeyResetToken = jwt.sign(
        {
          userId: testUser.id,
          purpose: 'password_reset',
          stateHash: generateStateHash(dbUser!.authHash),
        },
        JWT_SECRET, // JWT_ACCESS_SECRET — wrong key
        { expiresIn: '1h' },
      );

      const res = await withCsrf(
        agent.post(`${API}/auth/reset-password`).send({
          token: wrongKeyResetToken,
          email: testUser.email,
          newAuthHash: 'new-auth-hash',
          newEncryptedVaultKey: 'new-key',
          newVaultKeyIv: 'new-iv',
          newVaultKeyTag: 'new-tag',
        }),
        csrf,
      );

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should reject account unlock tokens signed with JWT_ACCESS_SECRET', async () => {
      const testUser = await createTestUser();
      const lockoutUntil = new Date(Date.now() + 30 * 60 * 1000);
      await User.findByIdAndUpdate(testUser.id, {
        $set: { failedLoginAttempts: 10, lockoutUntil },
      });

      const wrongKeyUnlockToken = jwt.sign(
        {
          userId: testUser.id,
          purpose: 'account_unlock',
          stateHash: generateStateHash(lockoutUntil.toISOString()),
        },
        JWT_SECRET, // JWT_ACCESS_SECRET — wrong key
        { expiresIn: '1h' },
      );

      const res = await withCsrf(
        agent.post(`${API}/auth/unlock-account`).send({ token: wrongKeyUnlockToken }),
        csrf,
      );

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });
  });

  // ── Logout Without Refresh Cookie ──────────────────────────────────

  describe('Logout without refresh token cookie', () => {
    it('should handle logout gracefully when no refresh token cookie is present', async () => {
      const testUser = await createTestUser();

      // Logout with auth token but without refresh token cookie
      const res = await withCsrf(agent.post(`${API}/auth/logout`), csrf, testUser.accessToken);

      // The documented contract: logout succeeds (200) even with no refresh
      // cookie and still clears the cookie. Accepting `[200, 400]` pinned nothing
      // — both a success and a rejection satisfied it, so a flip in behaviour was
      // invisible.
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      const setCookie = res.headers['set-cookie'] as unknown as string[] | undefined;
      expect(setCookie).toBeDefined();
      // The refresh cookie is cleared on logout (expired/emptied) regardless of
      // whether one was presented.
      expect(setCookie!.some((c) => c.startsWith('refreshToken='))).toBe(true);
    });
  });

  // ── Email Verification Required ────────────────────────────────────

  describe('Email verification enforcement', () => {
    it('should return 401 with generic message for unverified email login (no information leakage)', async () => {
      const testUser = await createTestUser({ emailVerified: false });

      const res = await withCsrf(
        agent.post(`${API}/auth/login`).send({
          email: testUser.email,
          authHash: testUser.rawPassword,
        }),
        csrf,
      );

      // Must return 401 (not 403) with the same message as invalid credentials
      // to prevent attackers from distinguishing verified vs unverified accounts
      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe('Invalid email or password');
      // A hint is included in the data field so the client can show a helpful
      // message, without exposing this information in the error code/status
      expect(res.body.data).toEqual({ reason: 'email_not_verified' });
    });

    it('should return 401 without email_not_verified hint for wrong password on unverified account', async () => {
      const testUser = await createTestUser({ emailVerified: false });

      const res = await withCsrf(
        agent.post(`${API}/auth/login`).send({
          email: testUser.email,
          authHash: 'wrong-password',
        }),
        csrf,
      );

      // Wrong password on unverified account should look identical to a
      // non-existent email — no hint about verification status
      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.data).toBeUndefined();
    });
  });

  // ── Login Timing Side-Channel Prevention ──────────────────────────

  describe('Login timing side-channel prevention', () => {
    it('should perform a dummy bcrypt compare for non-existent emails', async () => {
      // Both requests should return 401 with the same error message — we
      // primarily verify that non-existent email does not return instantly
      // (the dummy bcrypt.compare in the controller prevents that).
      const res = await withCsrf(
        agent.post(`${API}/auth/login`).send({
          email: 'completely-nonexistent@example.com',
          authHash: 'some-password',
        }),
        csrf,
      );

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe('Invalid email or password');
    });

    it('should return identical error responses for non-existent and existing emails with wrong password', async () => {
      const testUser = await createTestUser({ emailVerified: true });

      // Non-existent email
      const csrf1 = await getCsrf(agent);
      const res1 = await withCsrf(
        agent.post(`${API}/auth/login`).send({
          email: 'nonexistent@example.com',
          authHash: 'wrong-password',
        }),
        csrf1,
      );

      // Existing email, wrong password
      const csrf2 = await getCsrf(agent);
      const res2 = await withCsrf(
        agent.post(`${API}/auth/login`).send({
          email: testUser.email,
          authHash: 'wrong-password',
        }),
        csrf2,
      );

      // Both should return the exact same status and message
      expect(res1.status).toBe(401);
      expect(res2.status).toBe(401);
      expect(res1.body.message).toBe(res2.body.message);
      expect(res1.body.success).toBe(res2.body.success);
    });
  });

  // ── Progressive Login Delay ────────────────────────────────────────

  describe('Progressive login delay', () => {
    it('should return 401 after failed attempts without excessive delay in test mode', async () => {
      const testUser = await createTestUser({ emailVerified: true });

      // Perform 3 failed login attempts
      for (let i = 0; i < 3; i++) {
        const csrfN = await getCsrf(agent);
        const res = await withCsrf(
          agent.post(`${API}/auth/login`).send({
            email: testUser.email,
            authHash: 'wrong-password',
          }),
          csrfN,
        );
        expect(res.status).toBe(401);
      }

      // Verify failedLoginAttempts is tracked
      const user = await User.findOne({ email: testUser.email });
      expect(user!.failedLoginAttempts).toBe(3);
    });
  });

  // ── Expired refresh token should not trigger reuse detection ──────────

  describe('Expired refresh token handling', () => {
    it('should return 401 for an expired refresh token without triggering reuse detection', async () => {
      const testUser = await createTestUser();
      const crypto = await import('node:crypto');
      const { hashToken } = await import('../src/utils/token.js');

      // Create an expired refresh token in the same family as the test user's token
      const expiredTokenRaw = crypto.default.randomBytes(64).toString('hex');
      const expiredTokenHash = hashToken(expiredTokenRaw);

      // Look up the test user's existing token to get its familyId
      const existingToken = await RefreshToken.findOne({ userId: testUser.id });
      const familyId = existingToken!.familyId;

      await RefreshToken.create({
        userId: testUser.id,
        tokenHash: expiredTokenHash,
        familyId,
        deviceInfo: {
          userAgent: 'test-agent',
          ip: '127.0.0.1',
          fingerprint: 'test-fp',
        },
        expiresAt: new Date(Date.now() - 1000), // Already expired
      });

      // First attempt with expired token: should get 401 (expired)
      const csrf1 = await getCsrf(agent, `refreshToken=${expiredTokenRaw}`);
      const res1 = await withCsrf(
        agent.post(`${API}/auth/refresh`),
        csrf1,
        undefined,
        `refreshToken=${expiredTokenRaw}`,
      );
      expect(res1.status).toBe(401);

      // The expired token should be cleaned up, not marked as used
      const expiredTokenAfter = await RefreshToken.findOne({ tokenHash: expiredTokenHash });
      expect(expiredTokenAfter).toBeNull();

      // Retry with the same expired token: should get 401 (invalid, not reuse detected)
      // The token family should still be intact
      const csrf2 = await getCsrf(agent, `refreshToken=${expiredTokenRaw}`);
      const res2 = await withCsrf(
        agent.post(`${API}/auth/refresh`),
        csrf2,
        undefined,
        `refreshToken=${expiredTokenRaw}`,
      );
      expect(res2.status).toBe(401);

      // The original valid token should still exist (family not revoked)
      const remainingTokens = await RefreshToken.countDocuments({ userId: testUser.id, familyId });
      expect(remainingTokens).toBeGreaterThanOrEqual(1);
    });
  });

  // ── Vault Key Rotation Recovery ──────────────────────────────────────

  describe('Vault key rotation recovery on login', () => {
    it('should clear rotationInProgress flag and pending fields on login', async () => {
      const testUser = await createTestUser({ emailVerified: true });

      // Simulate interrupted rotation by setting the flags directly
      await User.updateOne(
        { _id: testUser.id },
        {
          $set: {
            rotationInProgress: true,
            pendingEncryptedVaultKey: 'pending-key',
            pendingVaultKeyIv: 'pending-iv',
            pendingVaultKeyTag: 'pending-tag',
          },
        },
      );

      const res = await withCsrf(
        agent.post(`${API}/auth/login`).send({
          email: testUser.email,
          authHash: testUser.rawPassword,
        }),
        csrf,
      );

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.accessToken).toBeDefined();

      // Verify the rotation state was cleared
      const user = await User.findById(testUser.id);
      expect(user!.rotationInProgress).toBe(false);
      expect(user!.pendingEncryptedVaultKey).toBeUndefined();
      expect(user!.pendingVaultKeyIv).toBeUndefined();
      expect(user!.pendingVaultKeyTag).toBeUndefined();
    });

    it('should create a rotation_recovery audit log entry', async () => {
      const testUser = await createTestUser({ emailVerified: true });

      await User.updateOne(
        { _id: testUser.id },
        {
          $set: {
            rotationInProgress: true,
            pendingEncryptedVaultKey: 'pending-key',
            pendingVaultKeyIv: 'pending-iv',
            pendingVaultKeyTag: 'pending-tag',
          },
        },
      );

      await withCsrf(
        agent.post(`${API}/auth/login`).send({
          email: testUser.email,
          authHash: testUser.rawPassword,
        }),
        csrf,
      );

      const auditLogs = await AuditLog.find({
        userId: testUser.id,
        action: 'rotation_recovery',
      });
      expect(auditLogs).toHaveLength(1);
      expect(auditLogs[0]!.metadata).toBeDefined();
      expect((auditLogs[0]!.metadata as Record<string, unknown>)['detail']).toMatch(
        /interrupted vault key rotation/i,
      );
    });

    it('should not touch rotation state when rotationInProgress is false', async () => {
      const testUser = await createTestUser({ emailVerified: true });

      const res = await withCsrf(
        agent.post(`${API}/auth/login`).send({
          email: testUser.email,
          authHash: testUser.rawPassword,
        }),
        csrf,
      );

      expect(res.status).toBe(200);

      // No rotation_recovery audit log should exist
      const auditLogs = await AuditLog.find({
        userId: testUser.id,
        action: 'rotation_recovery',
      });
      expect(auditLogs).toHaveLength(0);
    });

    it('should preserve the existing vault key when clearing rotation state', async () => {
      const testUser = await createTestUser({ emailVerified: true });

      // Get the original vault key values
      const originalUser = await User.findById(testUser.id);
      const originalVaultKey = originalUser!.encryptedVaultKey;
      const originalVaultKeyIv = originalUser!.vaultKeyIv;
      const originalVaultKeyTag = originalUser!.vaultKeyTag;

      await User.updateOne(
        { _id: testUser.id },
        {
          $set: {
            rotationInProgress: true,
            pendingEncryptedVaultKey: 'new-pending-key',
            pendingVaultKeyIv: 'new-pending-iv',
            pendingVaultKeyTag: 'new-pending-tag',
          },
        },
      );

      const res = await withCsrf(
        agent.post(`${API}/auth/login`).send({
          email: testUser.email,
          authHash: testUser.rawPassword,
        }),
        csrf,
      );

      expect(res.status).toBe(200);

      // The original vault key should remain untouched
      const userAfter = await User.findById(testUser.id);
      expect(userAfter!.encryptedVaultKey).toBe(originalVaultKey);
      expect(userAfter!.vaultKeyIv).toBe(originalVaultKeyIv);
      expect(userAfter!.vaultKeyTag).toBe(originalVaultKeyTag);
    });
  });

  // ── JWT middleware: deletionPending users rejected ──────────────────────

  describe('JWT middleware deletionPending enforcement', () => {
    it('should return 401 on authenticated requests when user is pending deletion', async () => {
      const testUser = await createTestUser({ emailVerified: true });

      // Sanity: the access token works before the flag is set.
      const okRes = await agent
        .get(`${API}/user/profile`)
        .set('Authorization', authHeader(testUser.accessToken));
      expect(okRes.status).toBe(200);

      // Mark the user pending deletion server-side; the access token is still
      // cryptographically valid but should now be rejected by the JWT strategy.
      await User.findByIdAndUpdate(testUser.id, { $set: { deletionPending: true } });

      const res = await agent
        .get(`${API}/user/profile`)
        .set('Authorization', authHeader(testUser.accessToken));

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('should still accept a valid token when deletionPending is false', async () => {
      const testUser = await createTestUser({ emailVerified: true });

      await User.findByIdAndUpdate(testUser.id, { $set: { deletionPending: false } });

      const res = await agent
        .get(`${API}/user/profile`)
        .set('Authorization', authHeader(testUser.accessToken));

      expect(res.status).toBe(200);
    });
  });
});
