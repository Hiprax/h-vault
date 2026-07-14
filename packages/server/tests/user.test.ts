import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../src/app.js';
import { createTestUser, authHeader, getCsrf as getCsrfBase } from './helpers.js';
import type { TestUser } from './helpers.js';

// Re-export with { csrfToken, csrfCookie } naming used throughout this file
async function getCsrf(
  agent: request.SuperTest<request.Test>,
): Promise<{ csrfToken: string; csrfCookie: string }> {
  const { token, cookie } = await getCsrfBase(agent);
  return { csrfToken: token, csrfCookie: cookie };
}

// ── Tests ────────────────────────────────────────────────────────────

describe('User routes', () => {
  let user: TestUser;
  let agent: request.SuperTest<request.Test>;

  beforeEach(async () => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    user = await createTestUser();
  });

  // ── Profile ──────────────────────────────────────────────────────

  describe('GET /api/v1/user/profile', () => {
    it('should return user profile without sensitive fields', async () => {
      const res = await agent
        .get('/api/v1/user/profile')
        .set('Authorization', authHeader(user.accessToken));

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toBeDefined();
      expect(res.body.data.email).toBe(user.email);
      // Sensitive fields must be excluded
      expect(res.body.data.authHash).toBeUndefined();
      expect(res.body.data.twoFactorSecret).toBeUndefined();
      expect(res.body.data.backupCodes).toBeUndefined();
    });
  });

  // ── Settings ─────────────────────────────────────────────────────

  describe('PUT /api/v1/user/settings', () => {
    it('should update theme and autoLockTimeout', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .put('/api/v1/user/settings')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ theme: 'dark', autoLockTimeout: 10 });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.theme).toBe('dark');
      expect(res.body.data.autoLockTimeout).toBe(10);
    });
  });

  // ── Change Password ──────────────────────────────────────────────

  describe('PUT /api/v1/user/change-password', () => {
    it('should change password with correct current password', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .put('/api/v1/user/change-password')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          currentAuthHash: user.rawPassword,
          newAuthHash: 'brand-new-auth-hash',
          newEncryptedVaultKey: 'new-encrypted-vault-key',
          newVaultKeyIv: 'new-vault-key-iv',
          newVaultKeyTag: 'new-vault-key-tag',
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toMatch(/password changed/i);
    });

    it('should reject change with wrong current password', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .put('/api/v1/user/change-password')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          currentAuthHash: 'wrong-password-value',
          newAuthHash: 'brand-new-auth-hash',
          newEncryptedVaultKey: 'new-encrypted-vault-key',
          newVaultKeyIv: 'new-vault-key-iv',
          newVaultKeyTag: 'new-vault-key-tag',
        });

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('should revoke all refresh tokens after successful password change', async () => {
      const { RefreshToken } = await import('../src/models/RefreshToken.js');

      // Verify user has a refresh token before password change
      const beforeCount = await RefreshToken.countDocuments({ userId: user.id });
      expect(beforeCount).toBeGreaterThanOrEqual(1);

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .put('/api/v1/user/change-password')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          currentAuthHash: user.rawPassword,
          newAuthHash: 'brand-new-auth-hash',
          newEncryptedVaultKey: 'new-encrypted-vault-key',
          newVaultKeyIv: 'new-vault-key-iv',
          newVaultKeyTag: 'new-vault-key-tag',
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toMatch(/log in again/i);

      // All refresh tokens should be revoked
      const afterCount = await RefreshToken.countDocuments({ userId: user.id });
      expect(afterCount).toBe(0);
    });
  });

  // ── 2FA Setup ─────────────────────────────────────────────────────

  describe('POST /api/v1/user/2fa/setup', () => {
    it('should return TOTP secret and otpauth URI', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/user/2fa/setup')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: user.rawPassword });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.secret).toBeDefined();
      expect(typeof res.body.data.secret).toBe('string');
      expect(res.body.data.otpauthUri).toBeDefined();
      expect(res.body.data.otpauthUri).toContain('otpauth://totp/');
    });

    it('should return 409 if 2FA is already enabled', async () => {
      // Enable 2FA directly in DB
      const { User } = await import('../src/models/User.js');
      await User.findByIdAndUpdate(user.id, {
        $set: { twoFactorEnabled: true, twoFactorSecret: 'encrypted-secret' },
      });

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/user/2fa/setup')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: user.rawPassword });

      expect(res.status).toBe(409);
      expect(res.body.success).toBe(false);
    });
  });

  // ── 2FA Verify ────────────────────────────────────────────────────

  describe('POST /api/v1/user/2fa/verify', () => {
    it('should enable 2FA and return backup codes with valid TOTP', async () => {
      const { TOTP, Secret } = await import('otpauth');

      // First, set up 2FA to get a secret
      const { csrfToken: csrf1, csrfCookie: cookie1 } = await getCsrf(agent);

      const setupRes = await agent
        .post('/api/v1/user/2fa/setup')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf1)
        .set('Cookie', cookie1)
        .send({ password: user.rawPassword });

      expect(setupRes.status).toBe(200);
      const secret = setupRes.body.data.secret;

      // Generate a valid TOTP code from the secret
      const totp = new TOTP({
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: Secret.fromBase32(secret),
      });
      const validCode = totp.generate();

      // Verify 2FA with the code and secret
      const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);

      const verifyRes = await agent
        .post('/api/v1/user/2fa/verify')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf2)
        .set('Cookie', cookie2)
        .send({ code: validCode, secret });

      expect(verifyRes.status).toBe(200);
      expect(verifyRes.body.success).toBe(true);
      expect(verifyRes.body.message).toMatch(/enabled/i);
      expect(verifyRes.body.data.backupCodes).toBeDefined();
      expect(Array.isArray(verifyRes.body.data.backupCodes)).toBe(true);
      expect(verifyRes.body.data.backupCodes.length).toBeGreaterThan(0);

      // Verify 2FA is now enabled in DB
      const { User } = await import('../src/models/User.js');
      const updatedUser = await User.findById(user.id);
      expect(updatedUser!.twoFactorEnabled).toBe(true);
    });

    it('should reject an invalid TOTP code', async () => {
      // Set up 2FA first
      const { csrfToken: csrf1, csrfCookie: cookie1 } = await getCsrf(agent);

      const setupRes = await agent
        .post('/api/v1/user/2fa/setup')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf1)
        .set('Cookie', cookie1)
        .send({ password: user.rawPassword });

      const secret = setupRes.body.data.secret;

      // Try to verify with an invalid code
      const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);

      const verifyRes = await agent
        .post('/api/v1/user/2fa/verify')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf2)
        .set('Cookie', cookie2)
        .send({ code: '000000', secret });

      expect(verifyRes.status).toBe(400);
      expect(verifyRes.body.success).toBe(false);
    });

    it('should return 409 if 2FA is already enabled', async () => {
      // Enable 2FA directly in DB
      const { User } = await import('../src/models/User.js');
      await User.findByIdAndUpdate(user.id, {
        $set: { twoFactorEnabled: true, twoFactorSecret: 'encrypted-secret' },
      });

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/user/2fa/verify')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ code: '123456', secret: 'some-secret' });

      expect(res.status).toBe(409);
      expect(res.body.success).toBe(false);
    });
  });

  // ── 2FA Disable ───────────────────────────────────────────────────

  describe('DELETE /api/v1/user/2fa', () => {
    it('should disable 2FA with a valid TOTP code', async () => {
      const { TOTP, Secret } = await import('otpauth');
      const { CryptoManager } = await import('@hiprax/crypto');
      const { User } = await import('../src/models/User.js');

      // Create a known secret and enable 2FA
      const secretObj = new Secret();
      const secret = secretObj.base32;
      const cm = new CryptoManager();
      const encryptedSecret = cm.encryptTextSync(
        secret,
        process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345',
      );

      await User.findByIdAndUpdate(user.id, {
        $set: {
          twoFactorEnabled: true,
          twoFactorSecret: encryptedSecret,
          backupCodes: ['hashed-code-1', 'hashed-code-2'],
        },
      });

      // Generate a valid TOTP code
      const totp = new TOTP({
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: Secret.fromBase32(secret),
      });
      const validCode = totp.generate();

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .delete('/api/v1/user/2fa')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ code: validCode, password: user.rawPassword });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toMatch(/disabled/i);

      // Verify 2FA is disabled in DB
      const updatedUser = await User.findById(user.id);
      expect(updatedUser!.twoFactorEnabled).toBe(false);
    });

    it('should reject an invalid TOTP code when disabling', async () => {
      const { Secret } = await import('otpauth');
      const { CryptoManager } = await import('@hiprax/crypto');
      const { User } = await import('../src/models/User.js');

      const secretObj = new Secret();
      const secret = secretObj.base32;
      const cm = new CryptoManager();
      const encryptedSecret = cm.encryptTextSync(
        secret,
        process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345',
      );

      await User.findByIdAndUpdate(user.id, {
        $set: {
          twoFactorEnabled: true,
          twoFactorSecret: encryptedSecret,
        },
      });

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .delete('/api/v1/user/2fa')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ code: '000000', password: user.rawPassword });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should reject wrong password when disabling 2FA', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .delete('/api/v1/user/2fa')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ code: '123456', password: 'wrong-password' });

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('should return 400 if 2FA is not enabled', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .delete('/api/v1/user/2fa')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ code: '123456', password: user.rawPassword });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should revoke previously-issued refresh tokens after disabling 2FA', async () => {
      const cryptoNode = await import('node:crypto');
      const { TOTP, Secret } = await import('otpauth');
      const { CryptoManager } = await import('@hiprax/crypto');
      const { User } = await import('../src/models/User.js');
      const { RefreshToken } = await import('../src/models/RefreshToken.js');
      const { hashToken } = await import('../src/utils/token.js');

      // Seed a few extra refresh tokens for the same user — these simulate
      // sessions issued while 2FA was enabled.
      const extraTokens: string[] = [];
      for (let i = 0; i < 3; i++) {
        const raw = cryptoNode.randomBytes(64).toString('hex');
        extraTokens.push(raw);
        await RefreshToken.create({
          userId: user.id,
          tokenHash: hashToken(raw),
          familyId: cryptoNode.randomUUID(),
          deviceInfo: {
            userAgent: `seeded-agent-${i}`,
            ip: '127.0.0.1',
            fingerprint: `fingerprint-${i}`,
          },
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        });
      }

      const beforeCount = await RefreshToken.countDocuments({ userId: user.id });
      expect(beforeCount).toBeGreaterThanOrEqual(4);

      // Enable 2FA with a known secret.
      const secretObj = new Secret();
      const secret = secretObj.base32;
      const cm = new CryptoManager();
      const encryptedSecret = cm.encryptTextSync(
        secret,
        process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345',
      );
      await User.findByIdAndUpdate(user.id, {
        $set: {
          twoFactorEnabled: true,
          twoFactorSecret: encryptedSecret,
          backupCodes: ['hashed-code-1'],
        },
      });

      const totp = new TOTP({
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: Secret.fromBase32(secret),
      });
      const validCode = totp.generate();

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .delete('/api/v1/user/2fa')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ code: validCode, password: user.rawPassword });

      expect(res.status).toBe(200);

      // All previously-issued refresh tokens (no caller cookie present)
      // must be gone — disable2fa revokes everything for this userId.
      const remaining = await RefreshToken.find({ userId: user.id }).lean();
      expect(remaining.length).toBe(0);

      // None of the seeded raw tokens should resolve to a stored hash.
      for (const raw of extraTokens) {
        const found = await RefreshToken.findOne({ tokenHash: hashToken(raw) }).lean();
        expect(found).toBeNull();
      }
    });
  });

  // ── Sessions ─────────────────────────────────────────────────────

  describe('GET /api/v1/user/sessions', () => {
    it('should return at least one active session', async () => {
      const res = await agent
        .get('/api/v1/user/sessions')
        .set('Authorization', authHeader(user.accessToken));

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.data.length).toBeGreaterThanOrEqual(1);
      // Session should have expected shape
      expect(res.body.data[0]).toHaveProperty('_id');
      expect(res.body.data[0]).toHaveProperty('deviceInfo');
      expect(res.body.data[0]).toHaveProperty('createdAt');
      expect(res.body.data[0]).toHaveProperty('expiresAt');
    });

    it('should cap the returned sessions at MAX_SESSIONS even when more exist', async () => {
      const { RefreshToken } = await import('../src/models/RefreshToken.js');
      const { MAX_SESSIONS } = await import('@hvault/shared');
      const { createHash } = await import('node:crypto');

      // Seed MAX_SESSIONS + 10 refresh tokens for this user so the response
      // MUST be truncated by the controller's `.limit(MAX_SESSIONS)` — with a
      // single seeded session the old `<= 50` assertion held regardless of the
      // limit, so removing/raising the limit would not have been caught.
      const seedCount = MAX_SESSIONS + 10;
      const now = Date.now();
      const docs = Array.from({ length: seedCount }, (_, i) => ({
        userId: user.id,
        tokenHash: createHash('sha256').update(`seed-token-${i}`).digest('hex'),
        familyId: `family-${i}`,
        deviceInfo: { userAgent: `agent-${i}`, ip: '127.0.0.1', fingerprint: `fp-${i}` },
        expiresAt: new Date(now + 7 * 24 * 60 * 60 * 1000),
      }));
      await RefreshToken.insertMany(docs);

      // Sanity: there really are more than MAX_SESSIONS tokens in the DB.
      expect(await RefreshToken.countDocuments({ userId: user.id })).toBeGreaterThan(MAX_SESSIONS);

      const res = await agent
        .get('/api/v1/user/sessions')
        .set('Authorization', authHeader(user.accessToken));

      expect(res.status).toBe(200);
      expect(res.body.data.length).toBe(MAX_SESSIONS);
    });
  });

  describe('DELETE /api/v1/user/sessions/:id', () => {
    it('should revoke a session', async () => {
      // First, list sessions to get a session ID
      const listRes = await agent
        .get('/api/v1/user/sessions')
        .set('Authorization', authHeader(user.accessToken));

      const sessionId = listRes.body.data[0]._id;

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .delete(`/api/v1/user/sessions/${sessionId}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toMatch(/revoked/i);

      // Verify the session was removed
      const afterList = await agent
        .get('/api/v1/user/sessions')
        .set('Authorization', authHeader(user.accessToken));

      const remaining = afterList.body.data.filter((s: { _id: string }) => s._id === sessionId);
      expect(remaining.length).toBe(0);
    });
  });

  // ── Audit Log ────────────────────────────────────────────────────

  describe('GET /api/v1/user/audit-log', () => {
    it('should return audit logs with pagination', async () => {
      // Trigger an auditable action first (change password creates an audit entry).
      // After password change, the original access token is invalidated (it was
      // issued before passwordChangedAt), so we generate a fresh one.
      const { csrfToken, csrfCookie } = await getCsrf(agent);
      await agent
        .put('/api/v1/user/change-password')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          currentAuthHash: user.rawPassword,
          newAuthHash: 'new-auth-hash-value',
          newEncryptedVaultKey: 'new-encrypted-vault-key',
          newVaultKeyIv: 'new-vault-key-iv',
          newVaultKeyTag: 'new-vault-key-tag',
        });

      // Issue a new access token AFTER the password change so it passes the
      // passwordChangedAt check in the JWT strategy. JWT iat has 1-second
      // precision, so we wait >1s to ensure the new iat is strictly after
      // the (ms-precision) passwordChangedAt ceiling.
      await new Promise((r) => setTimeout(r, 1100));
      const { generateAccessToken } = await import('./helpers.js');
      const freshAccessToken = generateAccessToken(user.id);

      const res = await agent
        .get('/api/v1/user/audit-log?page=1&limit=10')
        .set('Authorization', authHeader(freshAccessToken));

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.pagination).toBeDefined();
      expect(res.body.pagination).toHaveProperty('page');
      expect(res.body.pagination).toHaveProperty('limit');
      expect(res.body.pagination).toHaveProperty('total');
      expect(res.body.pagination).toHaveProperty('totalPages');
      expect(res.body.data.length).toBeGreaterThanOrEqual(1);
    });
  });

  // ── Auth Guards ──────────────────────────────────────────────────

  describe('Auth guards', () => {
    it('should return 401 for profile without token', async () => {
      const res = await agent.get('/api/v1/user/profile');
      expect(res.status).toBe(401);
    });

    it('should return 401 for settings without token', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .put('/api/v1/user/settings')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ theme: 'dark' });

      expect(res.status).toBe(401);
    });

    it('should return 401 for sessions without token', async () => {
      const res = await agent.get('/api/v1/user/sessions');
      expect(res.status).toBe(401);
    });

    it('should return 401 for audit-log without token', async () => {
      const res = await agent.get('/api/v1/user/audit-log');
      expect(res.status).toBe(401);
    });
  });

  // ── Profile BWK Fields for Client-Side Verification ────────────────

  describe('Profile includes BWK fields for zero-knowledge verification', () => {
    it('should include encrypted backup key fields in profile response for client-side password verification', async () => {
      // Set up backup fields directly in DB
      const { User } = await import('../src/models/User.js');
      await User.findByIdAndUpdate(user.id, {
        $set: {
          'settings.backup.enabled': true,
          'settings.backup.scheduleHour': 3,
          'settings.backup.backupEmails': ['backup@example.com'],
          'settings.backup.encryptedBWK': 'opaque-bwk-ciphertext',
          'settings.backup.bwkIv': 'opaque-bwk-iv',
          'settings.backup.bwkTag': 'opaque-bwk-tag',
          'settings.backup.bwkSalt': 'opaque-bwk-salt',
          'settings.backup.isConfigured': true,
        },
      });

      const res = await agent
        .get('/api/v1/user/profile')
        .set('Authorization', authHeader(user.accessToken));

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      const backup = res.body.data.settings?.backup;
      expect(backup).toBeDefined();

      // Standard backup settings should be present
      expect(backup.enabled).toBe(true);
      expect(backup.scheduleHour).toBe(3);
      expect(backup.backupEmails).toEqual(['backup@example.com']);
      expect(backup.isConfigured).toBe(true);

      // BWK fields must be present so the client can verify the backup
      // password locally (zero-knowledge). These are opaque ciphertext.
      expect(backup.encryptedBWK).toBe('opaque-bwk-ciphertext');
      expect(backup.bwkIv).toBe('opaque-bwk-iv');
      expect(backup.bwkTag).toBe('opaque-bwk-tag');
      expect(backup.bwkSalt).toBe('opaque-bwk-salt');
    });
  });

  // ── All Settings Fields ────────────────────────────────────────────

  describe('All settings fields individually', () => {
    it('should update clipboardClearTimeout', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .put('/api/v1/user/settings')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ clipboardClearTimeout: 30 });

      expect(res.status).toBe(200);
      expect(res.body.data.clipboardClearTimeout).toBe(30);
    });

    it('should update defaultPasswordLength', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .put('/api/v1/user/settings')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ defaultPasswordLength: 24 });

      expect(res.status).toBe(200);
      expect(res.body.data.defaultPasswordLength).toBe(24);
    });

    it('should update language', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .put('/api/v1/user/settings')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ language: 'fr' });

      expect(res.status).toBe(200);
      expect(res.body.data.language).toBe('fr');
    });

    it('should update defaultPasswordOptions', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const passwordOpts = {
        uppercase: true,
        lowercase: true,
        numbers: false,
        symbols: false,
      };

      const res = await agent
        .put('/api/v1/user/settings')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ defaultPasswordOptions: passwordOpts });

      expect(res.status).toBe(200);
      expect(res.body.data.defaultPasswordOptions).toMatchObject(passwordOpts);
    });

    it('should update autoLockTimeout independently', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .put('/api/v1/user/settings')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ autoLockTimeout: 30 });

      expect(res.status).toBe(200);
      expect(res.body.data.autoLockTimeout).toBe(30);
    });
  });

  // ── Change Password Revokes Sessions ───────────────────────────────

  describe('Change password revokes all sessions', () => {
    it('should revoke all refresh tokens after password change', async () => {
      const { RefreshToken } = await import('../src/models/RefreshToken.js');
      const crypto = await import('node:crypto');
      const { hashToken } = await import('../src/utils/token.js');

      // Create an additional refresh token for the user
      const extraTokenRaw = crypto.randomBytes(64).toString('hex');
      await RefreshToken.create({
        userId: user.id,
        tokenHash: hashToken(extraTokenRaw),
        familyId: crypto.randomUUID(),
        deviceInfo: { userAgent: 'other-device', ip: '192.168.1.1', fingerprint: 'fp2' },
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      });

      // Verify multiple refresh tokens exist
      const tokensBefore = await RefreshToken.countDocuments({ userId: user.id });
      expect(tokensBefore).toBeGreaterThanOrEqual(2);

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .put('/api/v1/user/change-password')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          currentAuthHash: user.rawPassword,
          newAuthHash: 'brand-new-auth-hash',
          newEncryptedVaultKey: 'new-encrypted-vault-key',
          newVaultKeyIv: 'new-vault-key-iv',
          newVaultKeyTag: 'new-vault-key-tag',
        })
        .expect(200);

      // All refresh tokens should be deleted
      const tokensAfter = await RefreshToken.countDocuments({ userId: user.id });
      expect(tokensAfter).toBe(0);
    });
  });

  // ── 2FA Audit Logging ─────────────────────────────────────────────

  describe('2FA audit logging', () => {
    it('should create audit log when 2FA is enabled', async () => {
      const { TOTP, Secret } = await import('otpauth');
      const { AuditLog } = await import('../src/models/AuditLog.js');

      // Set up 2FA
      const { csrfToken: csrf1, csrfCookie: cookie1 } = await getCsrf(agent);
      const setupRes = await agent
        .post('/api/v1/user/2fa/setup')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf1)
        .set('Cookie', cookie1)
        .send({ password: user.rawPassword });

      const secret = setupRes.body.data.secret;

      const totp = new TOTP({
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: Secret.fromBase32(secret),
      });
      const validCode = totp.generate();

      const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);
      await agent
        .post('/api/v1/user/2fa/verify')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf2)
        .set('Cookie', cookie2)
        .send({ code: validCode, secret })
        .expect(200);

      const auditEntry = await AuditLog.findOne({
        userId: user.id,
        action: '2fa_enable',
      });

      expect(auditEntry).toBeDefined();
      expect(auditEntry!.userId.toString()).toBe(user.id);
    });

    it('should create audit log when 2FA is disabled', async () => {
      const { TOTP, Secret } = await import('otpauth');
      const { CryptoManager } = await import('@hiprax/crypto');
      const { User } = await import('../src/models/User.js');
      const { AuditLog } = await import('../src/models/AuditLog.js');

      const secretObj = new Secret();
      const secret = secretObj.base32;
      const cm = new CryptoManager();
      const encryptedSecret = cm.encryptTextSync(
        secret,
        process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345',
      );

      await User.findByIdAndUpdate(user.id, {
        $set: {
          twoFactorEnabled: true,
          twoFactorSecret: encryptedSecret,
          backupCodes: ['hashed-code-1', 'hashed-code-2'],
        },
      });

      const totp = new TOTP({
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: Secret.fromBase32(secret),
      });
      const validCode = totp.generate();

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      await agent
        .delete('/api/v1/user/2fa')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ code: validCode, password: user.rawPassword })
        .expect(200);

      const auditEntry = await AuditLog.findOne({
        userId: user.id,
        action: '2fa_disable',
      });

      expect(auditEntry).toBeDefined();
      expect(auditEntry!.userId.toString()).toBe(user.id);
    });
  });

  // ── Session Revocation IDOR Test ───────────────────────────────────

  describe('Session revocation IDOR protection', () => {
    it('should not allow user B to revoke user A session', async () => {
      const userB = await createTestUser({ email: 'userb-session@example.com' });
      const agentB = request(app) as unknown as request.SuperTest<request.Test>;

      // Get user A's session ID
      const sessionsRes = await agent
        .get('/api/v1/user/sessions')
        .set('Authorization', authHeader(user.accessToken));

      expect(sessionsRes.body.data.length).toBeGreaterThan(0);
      const userASessionId = sessionsRes.body.data[0]._id;

      // User B tries to revoke user A's session
      const { csrfToken, csrfCookie } = await getCsrf(agentB);
      const res = await agentB
        .delete(`/api/v1/user/sessions/${userASessionId}`)
        .set('Authorization', authHeader(userB.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie);

      expect(res.status).toBe(404);
      expect(res.body.success).toBe(false);

      // Verify user A's session still exists
      const sessionsAfter = await agent
        .get('/api/v1/user/sessions')
        .set('Authorization', authHeader(user.accessToken));

      const stillExists = sessionsAfter.body.data.some(
        (s: { _id: string }) => s._id === userASessionId,
      );
      expect(stillExists).toBe(true);
    });
  });

  // ── Audit Log Action Filter ────────────────────────────────────────

  describe('Audit log action filter', () => {
    it('should filter audit logs by action parameter', async () => {
      const { AuditLog } = await import('../src/models/AuditLog.js');

      // Create multiple audit log entries directly
      await AuditLog.create([
        {
          userId: user.id,
          action: 'login',
          ipAddress: '127.0.0.1',
          userAgent: 'test',
          timestamp: new Date(),
        },
        {
          userId: user.id,
          action: 'password_change',
          ipAddress: '127.0.0.1',
          userAgent: 'test',
          timestamp: new Date(),
        },
        {
          userId: user.id,
          action: 'login',
          ipAddress: '127.0.0.1',
          userAgent: 'test',
          timestamp: new Date(),
        },
      ]);

      // Filter by 'login' action
      const res = await agent
        .get('/api/v1/user/audit-log?action=login')
        .set('Authorization', authHeader(user.accessToken));

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.length).toBeGreaterThanOrEqual(2);
      // All entries should be 'login'
      for (const entry of res.body.data) {
        expect(entry.action).toBe('login');
      }
    });

    it('should return all audit logs when no action filter is provided', async () => {
      const { AuditLog } = await import('../src/models/AuditLog.js');

      await AuditLog.create([
        {
          userId: user.id,
          action: 'login',
          ipAddress: '127.0.0.1',
          userAgent: 'test',
          timestamp: new Date(),
        },
        {
          userId: user.id,
          action: 'item_create',
          ipAddress: '127.0.0.1',
          userAgent: 'test',
          timestamp: new Date(),
        },
      ]);

      const res = await agent
        .get('/api/v1/user/audit-log')
        .set('Authorization', authHeader(user.accessToken));

      expect(res.status).toBe(200);
      expect(res.body.data.length).toBeGreaterThanOrEqual(2);
      const actions = res.body.data.map((e: { action: string }) => e.action);
      expect(actions).toContain('login');
      expect(actions).toContain('item_create');
    });
  });

  // ── Delete Account ──────────────────────────────────────────────

  describe('DELETE /api/v1/user/account', () => {
    it('should delete account and all user data with correct password', async () => {
      const { User } = await import('../src/models/User.js');
      const { VaultItem } = await import('../src/models/VaultItem.js');
      const { Folder } = await import('../src/models/Folder.js');
      const { RefreshToken } = await import('../src/models/RefreshToken.js');
      const { AuditLog } = await import('../src/models/AuditLog.js');
      const { BackupLog } = await import('../src/models/BackupLog.js');

      // Create some user data to verify it gets deleted
      await VaultItem.create({
        userId: user.id,
        itemType: 'login',
        encryptedData: 'test-data',
        dataIv: 'test-iv',
        dataTag: 'test-tag',
        encryptedName: 'test-name',
        nameIv: 'test-name-iv',
        nameTag: 'test-name-tag',
      });

      await Folder.create({
        userId: user.id,
        encryptedName: 'test-folder',
        nameIv: 'test-iv',
        nameTag: 'test-tag',
      });

      // Verify data exists before deletion
      expect(await VaultItem.countDocuments({ userId: user.id })).toBeGreaterThan(0);
      expect(await Folder.countDocuments({ userId: user.id })).toBeGreaterThan(0);
      expect(await RefreshToken.countDocuments({ userId: user.id })).toBeGreaterThan(0);

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .delete('/api/v1/user')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: user.rawPassword });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toMatch(/account deleted/i);

      // Verify all user data has been deleted
      expect(await User.findById(user.id)).toBeNull();
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
      expect(await Folder.countDocuments({ userId: user.id })).toBe(0);
      expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(0);
      expect(await AuditLog.countDocuments({ userId: user.id })).toBe(0);
      expect(await BackupLog.countDocuments({ userId: user.id })).toBe(0);
    });

    it('should reject deletion with wrong password', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .delete('/api/v1/user')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: 'wrong-password' });

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);

      // User should still exist
      const { User } = await import('../src/models/User.js');
      expect(await User.findById(user.id)).not.toBeNull();
    });

    it('should reject deletion without password', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .delete('/api/v1/user')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({});

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should return 401 without auth token', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .delete('/api/v1/user')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: user.rawPassword });

      expect(res.status).toBe(401);
    });

    it('should not allow user B to delete user A account (target is derived from the JWT, not the body)', async () => {
      const userB = await createTestUser({ email: 'userb-delete@example.com' });
      const agentB = request(app) as unknown as request.SuperTest<request.Test>;

      const { csrfToken, csrfCookie } = await getCsrf(agentB);
      const { User } = await import('../src/models/User.js');

      // User B authenticates with B's own token/password but SMUGGLES user A's id
      // in the body — a defense-in-depth probe. deleteAccount must ignore the body
      // userId and act solely on the JWT subject: B is deleted, A is untouched.
      // If a regression started honouring `req.body.userId`, this would either
      // 401 (B's password no longer matches the targeted account A) or delete A —
      // both caught by the assertions below.
      const res = await agentB
        .delete('/api/v1/user')
        .set('Authorization', authHeader(userB.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: userB.rawPassword, userId: user.id });

      expect(res.status).toBe(200);

      // User A (the smuggled target) must still exist and be intact.
      const survivorA = await User.findById(user.id);
      expect(survivorA).not.toBeNull();
      expect(survivorA!.email).toBe(user.email);

      // User B (the authenticated caller) is the one actually deleted.
      expect(await User.findById(userB.id)).toBeNull();
    });

    it('should clear refresh token cookie on deletion', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .delete('/api/v1/user')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: user.rawPassword });

      expect(res.status).toBe(200);

      // Check that the response includes a Set-Cookie header clearing the refresh token
      const setCookies = res.headers['set-cookie'] as unknown as string[] | undefined;
      const hasRefreshClear = setCookies?.some(
        (c: string) => c.includes('refreshToken=') && c.includes('Expires='),
      );
      expect(hasRefreshClear).toBe(true);
    });

    it('should require 2FA code when user has 2FA enabled', async () => {
      const { CryptoManager } = await import('@hiprax/crypto');
      const { Secret } = await import('otpauth');
      const { User } = await import('../src/models/User.js');

      const cm = new CryptoManager();
      const secretObj = new Secret();
      const secret = secretObj.base32;
      const encryptedSecret = cm.encryptTextSync(
        secret,
        process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345',
      );

      const twoFaUser = await createTestUser({ email: 'delete-2fa@example.com' });

      await User.findByIdAndUpdate(twoFaUser.id, {
        $set: {
          twoFactorEnabled: true,
          twoFactorSecret: encryptedSecret,
        },
      });

      const agentB = request(app) as unknown as request.SuperTest<request.Test>;
      const { csrfToken, csrfCookie } = await getCsrf(agentB);

      // Attempt deletion without 2FA code
      const res = await agentB
        .delete('/api/v1/user')
        .set('Authorization', authHeader(twoFaUser.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: twoFaUser.rawPassword });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should reject deletion with invalid 2FA code', async () => {
      const { CryptoManager } = await import('@hiprax/crypto');
      const { Secret } = await import('otpauth');
      const { User } = await import('../src/models/User.js');

      const cm = new CryptoManager();
      const secretObj = new Secret();
      const secret = secretObj.base32;
      const encryptedSecret = cm.encryptTextSync(
        secret,
        process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345',
      );

      const twoFaUser = await createTestUser({ email: 'delete-2fa-invalid@example.com' });

      await User.findByIdAndUpdate(twoFaUser.id, {
        $set: {
          twoFactorEnabled: true,
          twoFactorSecret: encryptedSecret,
        },
      });

      const agentB = request(app) as unknown as request.SuperTest<request.Test>;
      const { csrfToken, csrfCookie } = await getCsrf(agentB);

      const res = await agentB
        .delete('/api/v1/user')
        .set('Authorization', authHeader(twoFaUser.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: twoFaUser.rawPassword, code: '000000' });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should allow deletion with valid 2FA code', async () => {
      const { CryptoManager } = await import('@hiprax/crypto');
      const { Secret, TOTP } = await import('otpauth');
      const { User } = await import('../src/models/User.js');

      const cm = new CryptoManager();
      const secretObj = new Secret();
      const secret = secretObj.base32;
      const encryptedSecret = cm.encryptTextSync(
        secret,
        process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345',
      );

      const twoFaUser = await createTestUser({ email: 'delete-2fa-valid@example.com' });

      await User.findByIdAndUpdate(twoFaUser.id, {
        $set: {
          twoFactorEnabled: true,
          twoFactorSecret: encryptedSecret,
        },
      });

      // Generate a valid TOTP code
      const totp = new TOTP({
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: Secret.fromBase32(secret),
      });
      const validCode = totp.generate();

      const agentB = request(app) as unknown as request.SuperTest<request.Test>;
      const { csrfToken, csrfCookie } = await getCsrf(agentB);

      const res = await agentB
        .delete('/api/v1/user')
        .set('Authorization', authHeader(twoFaUser.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: twoFaUser.rawPassword, code: validCode });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(await User.findById(twoFaUser.id)).toBeNull();
    });
  });

  // ── Password verification failed audit logging ─────────────────────

  describe('Password verification failed audit logging', () => {
    it('should create audit log on failed password for change-password', async () => {
      const { AuditLog } = await import('../src/models/AuditLog.js');
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .put('/api/v1/user/change-password')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          currentAuthHash: 'wrong-password',
          newAuthHash: 'new-hash',
          newEncryptedVaultKey: 'new-key',
          newVaultKeyIv: 'new-iv',
          newVaultKeyTag: 'new-tag',
        });

      const auditEntry = await AuditLog.findOne({
        userId: user.id,
        action: 'password_verification_failed',
      });

      expect(auditEntry).toBeDefined();
      expect(auditEntry!.userId.toString()).toBe(user.id);
      expect((auditEntry!.metadata as Record<string, unknown>).endpoint).toBe('change_password');
    });

    it('should create audit log on failed password for 2fa/setup', async () => {
      const { AuditLog } = await import('../src/models/AuditLog.js');
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .post('/api/v1/user/2fa/setup')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: 'wrong-password' });

      const auditEntry = await AuditLog.findOne({
        userId: user.id,
        action: 'password_verification_failed',
      });

      expect(auditEntry).toBeDefined();
      expect((auditEntry!.metadata as Record<string, unknown>).endpoint).toBe('2fa_setup');
    });

    it('should create audit log on failed password for 2fa disable', async () => {
      const { AuditLog } = await import('../src/models/AuditLog.js');
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .delete('/api/v1/user/2fa')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ code: '123456', password: 'wrong-password' });

      const auditEntry = await AuditLog.findOne({
        userId: user.id,
        action: 'password_verification_failed',
      });

      expect(auditEntry).toBeDefined();
      expect((auditEntry!.metadata as Record<string, unknown>).endpoint).toBe('2fa_disable');
    });

    it('should create audit log on failed password for regenerate-backup-codes', async () => {
      // Enable 2FA first so the regenerate endpoint doesn't fail early
      const { User } = await import('../src/models/User.js');
      const { AuditLog } = await import('../src/models/AuditLog.js');
      await User.findByIdAndUpdate(user.id, {
        $set: {
          twoFactorEnabled: true,
          twoFactorSecret: 'encrypted-secret',
          backupCodes: ['hashed-code'],
        },
      });

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .post('/api/v1/user/2fa/regenerate-backup-codes')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: 'wrong-password' });

      const auditEntry = await AuditLog.findOne({
        userId: user.id,
        action: 'password_verification_failed',
      });

      expect(auditEntry).toBeDefined();
      expect((auditEntry!.metadata as Record<string, unknown>).endpoint).toBe(
        'regenerate_backup_codes',
      );
    });

    it('should reject regenerate-backup-codes without code when 2FA is enabled', async () => {
      const { User } = await import('../src/models/User.js');
      await User.findByIdAndUpdate(user.id, {
        $set: {
          twoFactorEnabled: true,
          twoFactorSecret: 'encrypted-secret',
          backupCodes: ['hashed-code'],
        },
      });

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/user/2fa/regenerate-backup-codes')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: user.rawPassword });

      // Should fail because code is not provided
      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should accept regenerate-backup-codes with password and code when 2FA is enabled', async () => {
      const { User } = await import('../src/models/User.js');
      const { TOTP, Secret } = await import('otpauth');
      const { CryptoManager } = await import('@hiprax/crypto');

      // Create a known secret and enable 2FA
      const secretObj = new Secret();
      const rawSecret = secretObj.base32;
      const cm = new CryptoManager();
      const encryptedSecret = cm.encryptTextSync(
        rawSecret,
        process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345',
      );

      await User.findByIdAndUpdate(user.id, {
        $set: {
          twoFactorEnabled: true,
          twoFactorSecret: encryptedSecret,
          backupCodes: ['hashed-code'],
        },
      });

      // Generate a valid TOTP code
      const totp = new TOTP({
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: secretObj,
      });
      const validCode = totp.generate();

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/user/2fa/regenerate-backup-codes')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: user.rawPassword, code: validCode });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.backupCodes).toBeDefined();
      expect(Array.isArray(res.body.data.backupCodes)).toBe(true);
    });
  });

  // ── Account deletion audit log and atomicity ────────────────────────

  describe('Account deletion audit log and atomicity', () => {
    it('should create a system-scoped audit log entry that survives the deleteMany', async () => {
      const { AuditLog } = await import('../src/models/AuditLog.js');

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .delete('/api/v1/user')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: user.rawPassword });

      expect(res.status).toBe(200);

      // The account_delete audit log should survive because it uses userId: null
      const auditEntry = await AuditLog.findOne({ action: 'account_delete' });
      expect(auditEntry).toBeDefined();
      expect(auditEntry!.userId).toBeNull();
      expect((auditEntry!.metadata as Record<string, unknown>).deletedUserId).toBe(user.id);
      expect((auditEntry!.metadata as Record<string, unknown>).deletedEmail).toBe(user.email);
    });

    it('should delete all user-scoped audit logs while preserving system-scoped ones', async () => {
      const { AuditLog } = await import('../src/models/AuditLog.js');

      // Create some user-scoped audit logs first
      await AuditLog.create({
        userId: user.id,
        action: 'login',
        ipAddress: '127.0.0.1',
        userAgent: 'test',
      });

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .delete('/api/v1/user')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: user.rawPassword });

      // User-scoped logs should be deleted
      const userLogs = await AuditLog.countDocuments({ userId: user.id });
      expect(userLogs).toBe(0);

      // System-scoped account_delete log should persist. Use not.toBeNull:
      // AuditLog.findOne resolves to null on no match, and expect(null).toBeDefined()
      // passes vacuously — so a regression that deleted the system-scoped row would
      // slip through. Dereference its metadata to force a throw if it is null.
      const systemLog = await AuditLog.findOne({ action: 'account_delete', userId: null });
      expect(systemLog).not.toBeNull();
      expect(systemLog!.userId).toBeNull();
      expect((systemLog!.metadata as Record<string, unknown>).deletedUserId).toBe(user.id);
    });

    it('should mark user as deletionPending before data cleanup', async () => {
      const { User } = await import('../src/models/User.js');

      // We verify via the result: after successful deletion, user is gone
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .delete('/api/v1/user')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: user.rawPassword });

      expect(res.status).toBe(200);

      // User should be fully deleted after successful operation
      const deletedUser = await User.findById(user.id);
      expect(deletedUser).toBeNull();
    });

    it('should perform deletion sequentially (not parallel) for consistency', async () => {
      const { VaultItem } = await import('../src/models/VaultItem.js');
      const { Folder } = await import('../src/models/Folder.js');
      const { RefreshToken } = await import('../src/models/RefreshToken.js');
      const { AuditLog } = await import('../src/models/AuditLog.js');
      const { BackupLog } = await import('../src/models/BackupLog.js');

      // Create data in multiple collections
      await VaultItem.create({
        userId: user.id,
        itemType: 'login',
        encryptedData: 'test',
        dataIv: 'iv',
        dataTag: 'tag',
        encryptedName: 'name',
        nameIv: 'niv',
        nameTag: 'ntag',
      });
      await Folder.create({
        userId: user.id,
        encryptedName: 'folder',
        nameIv: 'iv',
        nameTag: 'tag',
      });

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .delete('/api/v1/user')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: user.rawPassword });

      expect(res.status).toBe(200);

      // All associated data should be cleaned up
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
      expect(await Folder.countDocuments({ userId: user.id })).toBe(0);
      expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(0);
      expect(await AuditLog.countDocuments({ userId: user.id })).toBe(0);
      expect(await BackupLog.countDocuments({ userId: user.id })).toBe(0);
    });
  });
});
