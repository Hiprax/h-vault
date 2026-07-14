import { describe, it, expect, vi, afterEach } from 'vitest';
import bcrypt from 'bcryptjs';
import request from 'supertest';
import app from '../src/app.js';
import { createTestUser, getCsrf } from './helpers.js';

function registrationBody(email: string, overrides: Record<string, unknown> = {}) {
  return {
    email,
    authHash: 'test-auth-hash-value',
    encryptedVaultKey: 'enc-vault-key',
    vaultKeyIv: 'vault-iv',
    vaultKeyTag: 'vault-tag',
    kdfIterations: 600_000,
    kdfAlgorithm: 'PBKDF2-SHA256',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Test Suite: Error Message Leakage / Anti-Enumeration
// ---------------------------------------------------------------------------

describe('Error Message Leakage Prevention', () => {
  // ── Registration: Identical Responses ──────────────────────────────

  describe('Registration anti-enumeration', () => {
    it('should return identical status code for new and existing email', async () => {
      const existingUser = await createTestUser({ email: 'existing@example.com' });

      const agent = request.agent(app);
      const csrf = await getCsrf(agent);

      // Register a new email
      const newRes = await agent
        .post('/api/v1/auth/register')
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send(registrationBody('brand-new@example.com'));

      // Register the existing email
      const csrf2 = await getCsrf(agent);
      const existingRes = await agent
        .post('/api/v1/auth/register')
        .set('Cookie', csrf2.cookie)
        .set('x-csrf-token', csrf2.token)
        .send(registrationBody(existingUser.email));

      // Status codes must be identical
      expect(newRes.status).toBe(existingRes.status);
      expect(newRes.status).toBe(201);
    });

    it('should return identical success field for new and existing email', async () => {
      const existingUser = await createTestUser({ email: 'existing2@example.com' });

      const agent = request.agent(app);
      const csrf1 = await getCsrf(agent);

      const newRes = await agent
        .post('/api/v1/auth/register')
        .set('Cookie', csrf1.cookie)
        .set('x-csrf-token', csrf1.token)
        .send(registrationBody('brand-new2@example.com'));

      const csrf2 = await getCsrf(agent);
      const existingRes = await agent
        .post('/api/v1/auth/register')
        .set('Cookie', csrf2.cookie)
        .set('x-csrf-token', csrf2.token)
        .send(registrationBody(existingUser.email));

      expect(newRes.body.success).toBe(true);
      expect(existingRes.body.success).toBe(true);
    });

    it('should return identical message for new and existing email', async () => {
      const existingUser = await createTestUser({ email: 'existing3@example.com' });

      const agent = request.agent(app);
      const csrf1 = await getCsrf(agent);

      const newRes = await agent
        .post('/api/v1/auth/register')
        .set('Cookie', csrf1.cookie)
        .set('x-csrf-token', csrf1.token)
        .send(registrationBody('brand-new3@example.com'));

      const csrf2 = await getCsrf(agent);
      const existingRes = await agent
        .post('/api/v1/auth/register')
        .set('Cookie', csrf2.cookie)
        .set('x-csrf-token', csrf2.token)
        .send(registrationBody(existingUser.email));

      expect(newRes.body.message).toBe(existingRes.body.message);
    });

    it('should return identical response shape for new and existing email', async () => {
      const existingUser = await createTestUser({ email: 'existing4@example.com' });

      const agent = request.agent(app);
      const csrf1 = await getCsrf(agent);

      const newRes = await agent
        .post('/api/v1/auth/register')
        .set('Cookie', csrf1.cookie)
        .set('x-csrf-token', csrf1.token)
        .send(registrationBody('brand-new4@example.com'));

      const csrf2 = await getCsrf(agent);
      const existingRes = await agent
        .post('/api/v1/auth/register')
        .set('Cookie', csrf2.cookie)
        .set('x-csrf-token', csrf2.token)
        .send(registrationBody(existingUser.email));

      // Response shape keys should be identical
      const newKeys = Object.keys(newRes.body as Record<string, unknown>).sort();
      const existingKeys = Object.keys(existingRes.body as Record<string, unknown>).sort();
      expect(newKeys).toEqual(existingKeys);
    });
  });

  // ── Login: Same Error for Invalid Email vs Invalid Password ────────

  describe('Login anti-enumeration', () => {
    it('should return identical error for non-existent email and wrong password', async () => {
      const existingUser = await createTestUser({ email: 'login-user@example.com' });

      const agent = request.agent(app);

      // Login with non-existent email
      const csrf1 = await getCsrf(agent);
      const noUserRes = await agent
        .post('/api/v1/auth/login')
        .set('Cookie', csrf1.cookie)
        .set('x-csrf-token', csrf1.token)
        .send({ email: 'does-not-exist@example.com', authHash: 'any-hash' });

      // Login with existing email but wrong password
      const csrf2 = await getCsrf(agent);
      const wrongPwRes = await agent
        .post('/api/v1/auth/login')
        .set('Cookie', csrf2.cookie)
        .set('x-csrf-token', csrf2.token)
        .send({ email: existingUser.email, authHash: 'wrong-password-hash' });

      // Both should return 401
      expect(noUserRes.status).toBe(401);
      expect(wrongPwRes.status).toBe(401);

      // Error messages should be identical
      expect(noUserRes.body.message).toBe(wrongPwRes.body.message);
    });

    it('should not reveal whether email exists in error message', async () => {
      await createTestUser({ email: 'secret-user@example.com' });

      const agent = request.agent(app);
      const csrf = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/auth/login')
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ email: 'secret-user@example.com', authHash: 'wrong-hash' });

      expect(res.status).toBe(401);
      const message = (res.body.message as string).toLowerCase();

      // Should not contain email-specific hints
      expect(message).not.toContain('email not found');
      expect(message).not.toContain('user not found');
      expect(message).not.toContain('no account');
      expect(message).not.toContain('email does not exist');
      // Should use generic "invalid email or password"
      expect(message).toContain('invalid');
    });

    it('should not reveal whether email exists for non-existent user', async () => {
      const agent = request.agent(app);
      const csrf = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/auth/login')
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ email: 'ghost@example.com', authHash: 'any-hash' });

      expect(res.status).toBe(401);
      const message = (res.body.message as string).toLowerCase();

      // Should NOT say "email not found" or similar
      expect(message).not.toContain('not found');
      expect(message).not.toContain('does not exist');
      expect(message).not.toContain('no user');
      // Should use a generic message
      expect(message).toContain('invalid');
    });

    it('should return identical error code for non-existent and wrong password', async () => {
      const existingUser = await createTestUser({ email: 'codechk@example.com' });

      const agent = request.agent(app);

      const csrf1 = await getCsrf(agent);
      const noUserRes = await agent
        .post('/api/v1/auth/login')
        .set('Cookie', csrf1.cookie)
        .set('x-csrf-token', csrf1.token)
        .send({ email: 'nope@example.com', authHash: 'any' });

      const csrf2 = await getCsrf(agent);
      const wrongPwRes = await agent
        .post('/api/v1/auth/login')
        .set('Cookie', csrf2.cookie)
        .set('x-csrf-token', csrf2.token)
        .send({ email: existingUser.email, authHash: 'wrong' });

      // Error code should be identical
      expect(noUserRes.body.statusCode).toBe(wrongPwRes.body.statusCode);
    });
  });

  // ── Forgot Password: Generic Response ─────────────────────────────

  describe('Forgot password anti-enumeration', () => {
    it('should return identical response for existing and non-existent email', async () => {
      await createTestUser({ email: 'forgot-user@example.com' });

      const agent = request.agent(app);

      // Forgot password for existing email
      const csrf1 = await getCsrf(agent);
      const existingRes = await agent
        .post('/api/v1/auth/forgot-password')
        .set('Cookie', csrf1.cookie)
        .set('x-csrf-token', csrf1.token)
        .send({ email: 'forgot-user@example.com' });

      // Forgot password for non-existent email
      const csrf2 = await getCsrf(agent);
      const nonExistentRes = await agent
        .post('/api/v1/auth/forgot-password')
        .set('Cookie', csrf2.cookie)
        .set('x-csrf-token', csrf2.token)
        .send({ email: 'nobody@example.com' });

      // Status codes should be identical
      expect(existingRes.status).toBe(200);
      expect(nonExistentRes.status).toBe(200);

      // Both should indicate success
      expect(existingRes.body.success).toBe(true);
      expect(nonExistentRes.body.success).toBe(true);
    });

    it('should not reveal account existence in forgot password response', async () => {
      const agent = request.agent(app);
      const csrf = await getCsrf(agent);

      // Non-existent email should always use generic "if an account exists" message
      const res = await agent
        .post('/api/v1/auth/forgot-password')
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ email: 'nobody-here@example.com' });

      expect(res.status).toBe(200);
      const message = (res.body.message as string).toLowerCase();

      // Message should use conditional language ("if an account exists")
      expect(message).toContain('if');
      expect(message).not.toContain('nobody-here@example.com');
      expect(message).not.toContain('account found');
    });
  });

  // ── Resend Verification: Generic Response ──────────────────────────

  describe('Resend verification anti-enumeration', () => {
    it('should return identical status for existing and non-existent email', async () => {
      await createTestUser({ email: 'resend-user@example.com', emailVerified: false });

      const agent = request.agent(app);

      const csrf1 = await getCsrf(agent);
      const existingRes = await agent
        .post('/api/v1/auth/resend-verification')
        .set('Cookie', csrf1.cookie)
        .set('x-csrf-token', csrf1.token)
        .send({ email: 'resend-user@example.com' });

      const csrf2 = await getCsrf(agent);
      const nonExistentRes = await agent
        .post('/api/v1/auth/resend-verification')
        .set('Cookie', csrf2.cookie)
        .set('x-csrf-token', csrf2.token)
        .send({ email: 'nobody-here@example.com' });

      // Both should return success (anti-enumeration)
      expect(existingRes.status).toBe(nonExistentRes.status);
      expect(existingRes.body.success).toBe(nonExistentRes.body.success);
    });
  });

  // ── Error Response Structure Consistency ──────────────────────────

  describe('Error response structure', () => {
    it('should use consistent error structure for 401 responses', async () => {
      const agent = request.agent(app);
      const csrf = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/auth/login')
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ email: 'any@example.com', authHash: 'any' });

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBeDefined();
      expect(typeof res.body.message).toBe('string');
      expect(res.body.statusCode).toBe(401);
    });

    it('should not leak stack traces in error message content', async () => {
      const agent = request.agent(app);
      const csrf = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/auth/login')
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ email: 'any@example.com', authHash: 'any' });

      // The message field should not contain stack trace patterns
      const message = res.body.message as string;
      expect(message).not.toMatch(/at \w+\s*\(/);
      expect(message).not.toContain('node_modules');
    });

    it('should not leak internal server details in validation error messages', async () => {
      const agent = request.agent(app);
      const csrf = await getCsrf(agent);

      // Send invalid body to trigger validation error
      const res = await agent
        .post('/api/v1/auth/register')
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ email: 'bad' }); // Missing required fields

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);

      // The message should not contain internal file paths
      const message = res.body.message as string;
      expect(message).not.toContain('node_modules');
      expect(message).not.toContain('.ts:');
    });

    it('should not leak database details in error responses', async () => {
      const agent = request.agent(app);
      const csrf = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/auth/login')
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ email: 'test@example.com', authHash: 'wrong' });

      const body = JSON.stringify(res.body);
      expect(body).not.toContain('MongoDB');
      expect(body).not.toContain('mongoose');
      expect(body).not.toContain('collection');
      expect(body).not.toContain('ObjectId');
    });
  });

  // ── Timing Consistency ────────────────────────────────────────────
  //
  // The anti-enumeration property is that both login branches perform the SAME
  // bcrypt work, so the wall-clock times cannot diverge. A wall-clock ratio
  // assertion cannot verify this: test env `BCRYPT_ROUNDS=4` makes every compare
  // a few ms, so a ratio<100 bound passes even if the dummy compare is removed
  // (and it is flake-prone under load). Assert the property STRUCTURALLY instead:
  // spy on `bcrypt.compare` and require the non-existent-email path and the
  // existing-email-wrong-password path to invoke it the SAME number of times.
  // Removing the dummy compare drops the non-existent path to 0 calls and fails.

  describe('Timing consistency', () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    async function loginCompareCount(
      agent: request.Agent,
      email: string,
      authHash: string,
    ): Promise<number> {
      const compareSpy = vi.spyOn(bcrypt, 'compare');
      const csrf = await getCsrf(agent);
      await agent
        .post('/api/v1/auth/login')
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ email, authHash });
      const count = compareSpy.mock.calls.length;
      compareSpy.mockRestore();
      return count;
    }

    it('runs the same number of bcrypt compares for existing vs non-existent email login', async () => {
      const existingUser = await createTestUser({ email: 'timing-user@example.com' });
      const agent = request.agent(app);

      // Non-existent email → dummy bcrypt.compare against DUMMY_BCRYPT_HASH.
      const nonExistentCompares = await loginCompareCount(
        agent,
        'non-existent-timing@example.com',
        'any',
      );

      // Existing email, wrong password → real bcrypt.compare against the stored hash.
      const existingCompares = await loginCompareCount(agent, existingUser.email, 'wrong-password');

      // Both branches MUST perform exactly one compare — the equalization the
      // dummy-hash path exists to provide. Any asymmetry is a timing oracle.
      expect(nonExistentCompares).toBe(1);
      expect(existingCompares).toBe(1);
      expect(nonExistentCompares).toBe(existingCompares);
    });
  });
});
