/**
 * Task 6.2: Account Deletion Cascade Tests
 *
 * API-level tests that verify the DELETE /user endpoint cleans up all
 * associated data: VaultItems, Folders, RefreshTokens, AuditLogs, BackupLogs.
 * Also covers: re-registration, password/2FA requirements, cross-user isolation.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import { TOTP, Secret } from 'otpauth';
import { CryptoManager } from '@hiprax/crypto';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { BackupLog } from '../src/models/BackupLog.js';
import {
  createTestUser,
  authHeader,
  sampleVaultItem,
  sampleFolder,
  getCsrf as getCsrfBase,
} from './helpers.js';
import type { TestUser } from './helpers.js';

async function getCsrf(
  agent: request.SuperTest<request.Test>,
): Promise<{ csrfToken: string; csrfCookie: string }> {
  const { token, cookie } = await getCsrfBase(agent);
  return { csrfToken: token, csrfCookie: cookie };
}

const cm = new CryptoManager();
const encKey = process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345';

/**
 * Seeds full data set for a user across all collections.
 */
async function seedUserData(userId: string) {
  // VaultItems
  await VaultItem.create([
    { userId, ...sampleVaultItem() },
    { userId, ...sampleVaultItem({ encryptedName: 'item-2' }) },
  ]);

  // Folders
  await Folder.create([
    { userId, ...sampleFolder() },
    { userId, ...sampleFolder({ encryptedName: 'folder-2' }) },
  ]);

  // AuditLogs (userId-scoped)
  await AuditLog.create([
    { userId, action: 'login', ipAddress: '127.0.0.1', userAgent: 'test' },
    { userId, action: 'item_create', ipAddress: '127.0.0.1', userAgent: 'test' },
  ]);

  // BackupLogs
  await BackupLog.create([
    { userId, status: 'success', fileSize: 1024, itemCount: 5 },
    { userId, status: 'failed', fileSize: 0, itemCount: 0, error: 'test error' },
  ]);
}

describe('Account Deletion Cascade (API-level)', () => {
  let user: TestUser;
  let agent: request.SuperTest<request.Test>;

  beforeEach(async () => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    user = await createTestUser();
  });

  // ── Individual Collection Cleanup ─────────────────────────────────────

  describe('collection cleanup verification', () => {
    it('should remove all VaultItems for the deleted user', async () => {
      await VaultItem.create({ userId: user.id, ...sampleVaultItem() });
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(1);

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .delete('/api/v1/user')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: user.rawPassword });

      expect(res.status).toBe(200);
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
    });

    it('should remove all Folders for the deleted user', async () => {
      await Folder.create({ userId: user.id, ...sampleFolder() });
      expect(await Folder.countDocuments({ userId: user.id })).toBe(1);

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .delete('/api/v1/user')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: user.rawPassword });

      expect(res.status).toBe(200);
      expect(await Folder.countDocuments({ userId: user.id })).toBe(0);
    });

    it('should remove all RefreshTokens for the deleted user', async () => {
      expect(await RefreshToken.countDocuments({ userId: user.id })).toBeGreaterThan(0);

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .delete('/api/v1/user')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: user.rawPassword });

      expect(res.status).toBe(200);
      expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(0);
    });

    it('should remove all user-scoped AuditLogs for the deleted user', async () => {
      await AuditLog.create({
        userId: user.id,
        action: 'login',
        ipAddress: '127.0.0.1',
        userAgent: 'test',
      });
      expect(await AuditLog.countDocuments({ userId: user.id })).toBeGreaterThan(0);

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .delete('/api/v1/user')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: user.rawPassword });

      expect(res.status).toBe(200);
      expect(await AuditLog.countDocuments({ userId: user.id })).toBe(0);
    });

    it('should remove all BackupLogs for the deleted user', async () => {
      await BackupLog.create({ userId: user.id, status: 'success', fileSize: 1024, itemCount: 5 });
      expect(await BackupLog.countDocuments({ userId: user.id })).toBeGreaterThan(0);

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .delete('/api/v1/user')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: user.rawPassword });

      expect(res.status).toBe(200);
      expect(await BackupLog.countDocuments({ userId: user.id })).toBe(0);
    });

    it('should delete the user document itself', async () => {
      expect(await User.findById(user.id)).not.toBeNull();

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .delete('/api/v1/user')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: user.rawPassword });

      expect(res.status).toBe(200);
      expect(await User.findById(user.id)).toBeNull();
    });

    it('should clean up ALL collections in a single deletion with seeded data', async () => {
      await seedUserData(user.id);

      // Verify data exists
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(2);
      expect(await Folder.countDocuments({ userId: user.id })).toBe(2);
      expect(await RefreshToken.countDocuments({ userId: user.id })).toBeGreaterThan(0);
      expect(await AuditLog.countDocuments({ userId: user.id })).toBe(2);
      expect(await BackupLog.countDocuments({ userId: user.id })).toBe(2);

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .delete('/api/v1/user')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: user.rawPassword });

      expect(res.status).toBe(200);

      expect(await User.findById(user.id)).toBeNull();
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
      expect(await Folder.countDocuments({ userId: user.id })).toBe(0);
      expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(0);
      expect(await AuditLog.countDocuments({ userId: user.id })).toBe(0);
      expect(await BackupLog.countDocuments({ userId: user.id })).toBe(0);
    });
  });

  // ── System Audit Log ──────────────────────────────────────────────────

  describe('system-scoped audit log', () => {
    it('should create an account_delete audit log with null userId that survives deletion', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);
      await agent
        .delete('/api/v1/user')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: user.rawPassword });

      // System-scoped audit log (userId: null) should exist
      const systemLog = await AuditLog.findOne({
        userId: null,
        action: 'account_delete',
      }).lean();
      expect(systemLog).not.toBeNull();
      expect(systemLog!.metadata).toEqual(
        expect.objectContaining({
          deletedUserId: user.id,
          deletedEmail: user.email,
        }),
      );
    });
  });

  // ── Re-registration ───────────────────────────────────────────────────

  describe('re-registration after deletion', () => {
    it('should allow the deleted user email to be used for a new account', async () => {
      const email = user.email;

      const { csrfToken: csrf1, csrfCookie: cookie1 } = await getCsrf(agent);
      const delRes = await agent
        .delete('/api/v1/user')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf1)
        .set('Cookie', cookie1)
        .send({ password: user.rawPassword });
      expect(delRes.status).toBe(200);

      // Register a new account with the same email
      const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);
      const regRes = await agent
        .post('/api/v1/auth/register')
        .set('x-csrf-token', csrf2)
        .set('Cookie', cookie2)
        .send({
          email,
          authHash: 'new-user-auth-hash',
          encryptedVaultKey: 'new-vault-key',
          vaultKeyIv: 'new-iv',
          vaultKeyTag: 'new-tag',
          kdfIterations: 600_000,
          kdfAlgorithm: 'PBKDF2-SHA256',
          encryptionVersion: 1,
        });

      expect(regRes.status).toBe(201);
      expect(regRes.body.success).toBe(true);
    });
  });

  // ── Password Requirement ──────────────────────────────────────────────

  describe('password requirement', () => {
    it('should require password confirmation for deletion', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .delete('/api/v1/user')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({});

      expect(res.status).toBe(400);

      // User should still exist
      expect(await User.findById(user.id)).not.toBeNull();
    });

    it('should reject deletion with an incorrect password', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .delete('/api/v1/user')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: 'completely-wrong-password' });

      expect(res.status).toBe(401);
      expect(await User.findById(user.id)).not.toBeNull();
    });

    it('should create password_verification_failed audit log on wrong password', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);
      await agent
        .delete('/api/v1/user')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: 'wrong-password' });

      const auditEntry = await AuditLog.findOne({
        userId: user.id,
        action: 'password_verification_failed',
      }).lean();
      expect(auditEntry).not.toBeNull();
      expect(auditEntry!.metadata).toEqual(expect.objectContaining({ endpoint: 'delete_account' }));
    });
  });

  // ── 2FA Requirement ───────────────────────────────────────────────────

  describe('2FA requirement', () => {
    it('should require 2FA code when user has 2FA enabled', async () => {
      const secretObj = new Secret();
      const encryptedSecret = cm.encryptTextSync(secretObj.base32, encKey);

      await User.findByIdAndUpdate(user.id, {
        $set: {
          twoFactorEnabled: true,
          twoFactorSecret: encryptedSecret,
          backupCodes: [],
        },
      });

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .delete('/api/v1/user')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: user.rawPassword });

      // Missing 2FA code → 400
      expect(res.status).toBe(400);
      expect(await User.findById(user.id)).not.toBeNull();
    });

    it('should succeed with correct password and valid 2FA code', async () => {
      const secretObj = new Secret();
      const encryptedSecret = cm.encryptTextSync(secretObj.base32, encKey);

      await User.findByIdAndUpdate(user.id, {
        $set: {
          twoFactorEnabled: true,
          twoFactorSecret: encryptedSecret,
          backupCodes: [],
          lastTotpTimestamp: 1000, // Old timestamp
        },
      });

      const totp = new TOTP({
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: secretObj,
      });
      const code = totp.generate();

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .delete('/api/v1/user')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: user.rawPassword, code });

      expect(res.status).toBe(200);
      expect(await User.findById(user.id)).toBeNull();
    });

    it('should reject deletion with an invalid 2FA code', async () => {
      const secretObj = new Secret();
      const encryptedSecret = cm.encryptTextSync(secretObj.base32, encKey);

      await User.findByIdAndUpdate(user.id, {
        $set: {
          twoFactorEnabled: true,
          twoFactorSecret: encryptedSecret,
          backupCodes: [],
        },
      });

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .delete('/api/v1/user')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: user.rawPassword, code: '000000' });

      expect(res.status).toBe(400);
      expect(await User.findById(user.id)).not.toBeNull();
    });
  });

  // ── Cross-User Isolation ──────────────────────────────────────────────

  describe('cross-user isolation', () => {
    it('should not delete User B data when User A is deleted', async () => {
      const userB = await createTestUser();
      await seedUserData(userB.id);

      // Delete User A
      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .delete('/api/v1/user')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ password: user.rawPassword });
      expect(res.status).toBe(200);

      // User A is gone
      expect(await User.findById(user.id)).toBeNull();

      // User B's data is intact
      expect(await User.findById(userB.id)).not.toBeNull();
      expect(await VaultItem.countDocuments({ userId: userB.id })).toBe(2);
      expect(await Folder.countDocuments({ userId: userB.id })).toBe(2);
      expect(await RefreshToken.countDocuments({ userId: userB.id })).toBeGreaterThan(0);
      expect(await AuditLog.countDocuments({ userId: userB.id })).toBe(2);
      expect(await BackupLog.countDocuments({ userId: userB.id })).toBe(2);
    });
  });
});
