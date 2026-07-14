import { describe, it, expect, beforeEach } from 'vitest';
import { Types } from 'mongoose';
import request from 'supertest';
import app from '../src/app.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { User } from '../src/models/User.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { JobLock } from '../src/models/JobLock.js';
import {
  createTestUser,
  authHeader,
  sampleVaultItem,
  sampleFolder,
  getCsrf as getCsrfBase,
} from './helpers.js';
import type { TestUser } from './helpers.js';

// Re-export with { csrfToken, csrfCookie } naming used throughout this file
async function getCsrf(
  agent: request.SuperTest<request.Test>,
): Promise<{ csrfToken: string; csrfCookie: string }> {
  const { token, cookie } = await getCsrfBase(agent);
  return { csrfToken: token, csrfCookie: cookie };
}

// ── Shared BWK test data ─────────────────────────────────────────────

const bwkSetupData = {
  encryptedBWK: 'test-encrypted-bwk-data',
  bwkIv: 'test-bwk-iv-value',
  bwkTag: 'test-bwk-tag-value',
  bwkSalt: 'test-bwk-salt-value',
};

// ── Helper: set up backup for a user ─────────────────────────────────

async function setupBackupForUser(
  agent: request.SuperTest<request.Test>,
  token: string,
  rawAuthHash = 'test-auth-hash-value',
) {
  const { csrfToken, csrfCookie } = await getCsrf(agent);
  const res = await agent
    .post('/api/v1/backup/setup')
    .set('Authorization', authHeader(token))
    .set('x-csrf-token', csrfToken)
    .set('Cookie', csrfCookie)
    .send({ ...bwkSetupData, authHash: rawAuthHash });
  return res;
}

// ── Tests ────────────────────────────────────────────────────────────

describe('Backup routes', () => {
  let user: TestUser;
  let agent: request.SuperTest<request.Test>;

  beforeEach(async () => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    user = await createTestUser();
  });

  // ── Setup Backup ─────────────────────────────────────────────────

  describe('POST /api/v1/backup/setup', () => {
    it('should configure backup with BWK', async () => {
      const res = await setupBackupForUser(agent, user.accessToken);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toMatch(/configured/i);
    });

    it('should return 401 with incorrect password', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/backup/setup')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ ...bwkSetupData, authHash: 'wrong-password' });

      expect(res.status).toBe(401);
    });

    it('should create audit log on failed password verification for backup setup', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);
      await agent
        .post('/api/v1/backup/setup')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ ...bwkSetupData, authHash: 'wrong-password' });

      const auditEntry = await AuditLog.findOne({
        userId: user.id,
        action: 'password_verification_failed',
      });
      expect(auditEntry).not.toBeNull();
      expect((auditEntry!.metadata as Record<string, unknown>).endpoint).toBe('backup_setup');
    });

    it('should reject setup without authHash in body', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/backup/setup')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send(bwkSetupData);

      expect(res.status).toBe(400);
    });

    it('should store bwkEncryptedVaultKey when provided', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/backup/setup')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          ...bwkSetupData,
          authHash: user.rawPassword,
          bwkEncryptedVaultKey: 'enc-vault-key',
          bwkVaultKeyIv: 'vk-iv-value',
          bwkVaultKeyTag: 'vk-tag-value',
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      const updatedUser = await User.findById(user.id).lean();
      expect(updatedUser!.settings.backup.bwkEncryptedVaultKey).toBe('enc-vault-key');
      expect(updatedUser!.settings.backup.bwkVaultKeyIv).toBe('vk-iv-value');
      expect(updatedUser!.settings.backup.bwkVaultKeyTag).toBe('vk-tag-value');
    });

    it('should clear bwkEncryptedVaultKey when not provided', async () => {
      // First set up with bwkEncryptedVaultKey
      const { csrfToken: csrf1, csrfCookie: cookie1 } = await getCsrf(agent);
      await agent
        .post('/api/v1/backup/setup')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf1)
        .set('Cookie', cookie1)
        .send({
          ...bwkSetupData,
          authHash: user.rawPassword,
          bwkEncryptedVaultKey: 'enc-vault-key',
          bwkVaultKeyIv: 'vk-iv-value',
          bwkVaultKeyTag: 'vk-tag-value',
        });

      // Verify it was stored
      let dbUser = await User.findById(user.id).lean();
      expect(dbUser!.settings.backup.bwkEncryptedVaultKey).toBe('enc-vault-key');

      // Now call setup WITHOUT bwkEncryptedVaultKey — should clear it
      const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/backup/setup')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf2)
        .set('Cookie', cookie2)
        .send({
          ...bwkSetupData,
          authHash: user.rawPassword,
        });

      expect(res.status).toBe(200);

      dbUser = await User.findById(user.id).lean();
      expect(dbUser!.settings.backup.bwkEncryptedVaultKey).toBeUndefined();
      expect(dbUser!.settings.backup.bwkVaultKeyIv).toBeUndefined();
      expect(dbUser!.settings.backup.bwkVaultKeyTag).toBeUndefined();
    });
  });

  // ── Update Settings ──────────────────────────────────────────────

  describe('PUT /api/v1/backup/settings', () => {
    it('should enable backup and set schedule', async () => {
      // Setup backup encryption first (isConfigured required for enabling)
      await setupBackupForUser(agent, user.accessToken);

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .put('/api/v1/backup/settings')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ enabled: true, scheduleHour: 6 });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.enabled).toBe(true);
      expect(res.body.data.scheduleHour).toBe(6);
    });

    it('should update backup emails', async () => {
      await setupBackupForUser(agent, user.accessToken);

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .put('/api/v1/backup/settings')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ backupEmails: ['backup@example.com'] });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.backupEmails).toEqual(['backup@example.com']);
    });

    it('should allow updating backup emails without encryption setup', async () => {
      // No setupBackupForUser — encryption is NOT configured
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .put('/api/v1/backup/settings')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ backupEmails: ['user@example.com', 'other@example.com'] });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.backupEmails).toEqual(['user@example.com', 'other@example.com']);
    });

    it('should reject enabling backup without encryption setup', async () => {
      // No setupBackupForUser — encryption is NOT configured
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .put('/api/v1/backup/settings')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ enabled: true });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should disable backup', async () => {
      // Enable first
      const { csrfToken: csrf1, csrfCookie: cookie1 } = await getCsrf(agent);
      await agent
        .put('/api/v1/backup/settings')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf1)
        .set('Cookie', cookie1)
        .send({ enabled: true });

      // Now disable
      const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);
      const res = await agent
        .put('/api/v1/backup/settings')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf2)
        .set('Cookie', cookie2)
        .send({ enabled: false });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.enabled).toBe(false);
    });
  });

  // ── Trigger Backup ───────────────────────────────────────────────

  describe('POST /api/v1/backup/trigger', () => {
    it('should create a backup successfully after setup', async () => {
      // Setup BWK first so encryption path is exercised
      await setupBackupForUser(agent, user.accessToken);

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/backup/trigger')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send();

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toMatch(/backup created/i);
      expect(res.body.data).toBeDefined();
      expect(typeof res.body.data.itemCount).toBe('number');
      expect(typeof res.body.data.fileSizeBytes).toBe('number');
    });
  });

  // ── Download Backup ──────────────────────────────────────────────

  describe('GET /api/v1/backup/download', () => {
    it('should return a JSON attachment', async () => {
      await setupBackupForUser(agent, user.accessToken);

      const res = await agent
        .get('/api/v1/backup/download')
        .set('Authorization', authHeader(user.accessToken));

      expect(res.status).toBe(200);
      // Should have Content-Disposition attachment header
      const contentDisposition = res.headers['content-disposition'];
      expect(contentDisposition).toBeDefined();
      expect(contentDisposition).toMatch(/attachment/);
      expect(contentDisposition).toMatch(/hvault-backup/);
      // Content-Type should be JSON
      expect(res.headers['content-type']).toMatch(/json/);
    });

    it('should return downloadable backup with items', async () => {
      await setupBackupForUser(agent, user.accessToken);

      // Import some data first so there are items to download
      const { csrfToken: csrf1, csrfCookie: cookie1 } = await getCsrf(agent);
      const importData = JSON.stringify({
        items: [sampleVaultItem({ encryptedName: 'backup-test-item' })],
      });
      await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf1)
        .set('Cookie', cookie1)
        .send({ format: 'json', data: importData });

      const res = await agent
        .get('/api/v1/backup/download')
        .set('Authorization', authHeader(user.accessToken));

      expect(res.status).toBe(200);
      // The body should be parseable JSON containing items
      const backup = JSON.parse(res.text);
      expect(backup.items).toBeDefined();
      expect(backup.items.length).toBe(1);
      expect(backup.metadata.itemCount).toBe(1);
    });

    it('should return 400 when downloading without encryption setup', async () => {
      const res = await agent
        .get('/api/v1/backup/download')
        .set('Authorization', authHeader(user.accessToken));

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should include backupEncryption metadata in downloaded backup', async () => {
      await setupBackupForUser(agent, user.accessToken);

      const res = await agent
        .get('/api/v1/backup/download')
        .set('Authorization', authHeader(user.accessToken));

      expect(res.status).toBe(200);
      const backup = JSON.parse(res.text);
      expect(backup.backupEncryption).toBeDefined();
      expect(backup.backupEncryption.encryptedBWK).toBeDefined();
      expect(backup.backupEncryption.bwkIv).toBeDefined();
      expect(backup.backupEncryption.bwkTag).toBeDefined();
      expect(backup.backupEncryption.bwkSalt).toBeDefined();
    });

    it('should reject backup download when item data exceeds max size during streaming', async () => {
      await setupBackupForUser(agent, user.accessToken);

      // Override BACKUP_MAX_SIZE_MB to a very small value to trigger the streaming size check
      const { config } = await import('../src/config/index.js');
      const originalMax = config.BACKUP_MAX_SIZE_MB;
      (config as Record<string, unknown>).BACKUP_MAX_SIZE_MB = 0;

      try {
        // Create an item so there's data to collect
        const { csrfToken, csrfCookie } = await getCsrf(agent);
        await agent
          .post('/api/v1/vault/items')
          .set('Authorization', authHeader(user.accessToken))
          .set('x-csrf-token', csrfToken)
          .set('Cookie', csrfCookie)
          .send(sampleVaultItem());

        const res = await agent
          .get('/api/v1/backup/download')
          .set('Authorization', authHeader(user.accessToken));

        expect(res.status).toBe(413);
        expect(res.body.success).toBe(false);
        // The abort must come from the in-cursor streaming guard, not the
        // post-collection final size check. Only the streaming guard emits the
        // "during collection" message, so pinning it proves the memory-safety
        // guard fired mid-stream (removing it would surface the final-check
        // "(0 MB)" message and fail this assertion).
        expect(String(res.body.message)).toMatch(/during collection/i);
      } finally {
        (config as Record<string, unknown>).BACKUP_MAX_SIZE_MB = originalMax;
      }
    });

    it('should download empty backup when vault has 0 items', async () => {
      await setupBackupForUser(agent, user.accessToken);

      const res = await agent
        .get('/api/v1/backup/download')
        .set('Authorization', authHeader(user.accessToken));

      expect(res.status).toBe(200);
      const backup = JSON.parse(res.text);
      expect(backup.items).toEqual([]);
      expect(backup.metadata.itemCount).toBe(0);
    });

    it('should reject backup download when folder data exceeds max size during streaming', async () => {
      // Task 4.9: folders are streamed via cursor with the same size guard as
      // items. With BACKUP_MAX_SIZE_MB=0 a single folder must cause the
      // streaming size check to fail before any items are read.
      await setupBackupForUser(agent, user.accessToken);

      const { Folder } = await import('../src/models/Folder.js');
      await Folder.create({
        userId: user.id,
        encryptedName: 'oversized-folder',
        nameIv: 'iv',
        nameTag: 'tag',
      });

      const { config } = await import('../src/config/index.js');
      const originalMax = config.BACKUP_MAX_SIZE_MB;
      (config as Record<string, unknown>).BACKUP_MAX_SIZE_MB = 0;

      try {
        const res = await agent
          .get('/api/v1/backup/download')
          .set('Authorization', authHeader(user.accessToken));

        expect(res.status).toBe(413);
        expect(res.body.success).toBe(false);
        // As with the item variant: assert the streaming-guard message so the
        // folder-cursor in-loop abort is what is exercised, not the final check.
        expect(String(res.body.message)).toMatch(/during collection/i);
      } finally {
        (config as Record<string, unknown>).BACKUP_MAX_SIZE_MB = originalMax;
      }
    });
  });

  // ── Backup History ───────────────────────────────────────────────

  describe('GET /api/v1/backup/history', () => {
    it('should return empty history initially', async () => {
      const res = await agent
        .get('/api/v1/backup/history')
        .set('Authorization', authHeader(user.accessToken));

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data)).toBe(true);
      expect(res.body.data.length).toBe(0);
      expect(res.body.pagination).toBeDefined();
      expect(res.body.pagination.total).toBe(0);
    });

    it('should return history after triggering a backup', async () => {
      // Setup and trigger a backup
      await setupBackupForUser(agent, user.accessToken);

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      await agent
        .post('/api/v1/backup/trigger')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send();

      const res = await agent
        .get('/api/v1/backup/history?page=1&limit=10')
        .set('Authorization', authHeader(user.accessToken));

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.length).toBeGreaterThanOrEqual(1);
      expect(res.body.data[0]).toHaveProperty('status');
      expect(res.body.data[0].status).toBe('success');
      expect(res.body.pagination.total).toBeGreaterThanOrEqual(1);
    });
  });

  // ── Change Backup Password ────────────────────────────────────────

  describe('PUT /api/v1/backup/change-password', () => {
    it('should change backup password successfully', async () => {
      // Setup backup first
      await setupBackupForUser(agent, user.accessToken);

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .put('/api/v1/backup/change-password')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          password: user.rawPassword,
          newEncryptedBWK: 'new-encrypted-bwk-data',
          newBwkIv: 'new-bwk-iv-value',
          newBwkTag: 'new-bwk-tag-value',
          newBwkSalt: 'new-bwk-salt-value',
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toMatch(/changed/i);
    });

    it('should return 401 with incorrect password', async () => {
      await setupBackupForUser(agent, user.accessToken);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .put('/api/v1/backup/change-password')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          password: 'wrong-password',
          newEncryptedBWK: 'new-encrypted-bwk-data',
          newBwkIv: 'new-bwk-iv-value',
          newBwkTag: 'new-bwk-tag-value',
          newBwkSalt: 'new-bwk-salt-value',
        });

      expect(res.status).toBe(401);
    });

    it('should create audit log on failed password for change-backup-password', async () => {
      await setupBackupForUser(agent, user.accessToken);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .put('/api/v1/backup/change-password')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          password: 'wrong-password',
          newEncryptedBWK: 'new-encrypted-bwk-data',
          newBwkIv: 'new-bwk-iv-value',
          newBwkTag: 'new-bwk-tag-value',
          newBwkSalt: 'new-bwk-salt-value',
        });

      const auditEntry = await AuditLog.findOne({
        userId: user.id,
        action: 'password_verification_failed',
      });

      expect(auditEntry).toBeDefined();
      expect(auditEntry!.userId.toString()).toBe(user.id);
      expect((auditEntry!.metadata as Record<string, unknown>).endpoint).toBe(
        'change_backup_password',
      );
    });

    it('should return 401 without auth token', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .put('/api/v1/backup/change-password')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          password: 'some-password',
          newEncryptedBWK: 'new-encrypted-bwk-data',
          newBwkIv: 'new-bwk-iv-value',
          newBwkTag: 'new-bwk-tag-value',
          newBwkSalt: 'new-bwk-salt-value',
        });

      expect(res.status).toBe(401);
    });
  });

  // ── Restore Backup ───────────────────────────────────────────────

  describe('POST /api/v1/backup/restore', () => {
    it('should restore backup data with skip conflict strategy', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      // Provide valid ObjectIds so the restore controller can use them
      const itemId1 = new Types.ObjectId().toString();
      const itemId2 = new Types.ObjectId().toString();
      const folderId = new Types.ObjectId().toString();

      const backupData = JSON.stringify({
        items: [
          { _id: itemId1, ...sampleVaultItem({ encryptedName: 'restored-item-1' }) },
          { _id: itemId2, ...sampleVaultItem({ encryptedName: 'restored-item-2' }) },
        ],
        folders: [{ _id: folderId, ...sampleFolder({ encryptedName: 'restored-folder-1' }) }],
      });

      const res = await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ conflictStrategy: 'skip', data: backupData });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toMatch(/restored/i);
      expect(res.body.data).toBeDefined();
      expect(res.body.data.itemsRestored).toBe(2);
      expect(res.body.data.foldersRestored).toBe(1);
      expect(res.body.data.itemsSkipped).toBe(0);
      expect(res.body.data.foldersSkipped).toBe(0);
    });

    it('should reject malformed backup JSON', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ conflictStrategy: 'skip', data: 'not-valid-json{{{' });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should restore with overwrite conflict strategy', async () => {
      const { csrfToken: csrf1, csrfCookie: cookie1 } = await getCsrf(agent);

      const itemId = new Types.ObjectId().toString();
      const folderId = new Types.ObjectId().toString();

      // First, restore initial data
      const initialData = JSON.stringify({
        items: [{ _id: itemId, ...sampleVaultItem({ encryptedName: 'original-item' }) }],
        folders: [{ _id: folderId, ...sampleFolder({ encryptedName: 'original-folder' }) }],
      });

      await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf1)
        .set('Cookie', cookie1)
        .send({ conflictStrategy: 'skip', data: initialData });

      // Now restore with overwrite using the same IDs
      const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);

      const overwriteData = JSON.stringify({
        items: [{ _id: itemId, ...sampleVaultItem({ encryptedName: 'overwritten-item' }) }],
        folders: [{ _id: folderId, ...sampleFolder({ encryptedName: 'overwritten-folder' }) }],
      });

      const res = await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf2)
        .set('Cookie', cookie2)
        .send({ conflictStrategy: 'overwrite', data: overwriteData });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.itemsRestored).toBe(1);
      expect(res.body.data.foldersRestored).toBe(1);
      expect(res.body.data.itemsSkipped).toBe(0);
      expect(res.body.data.foldersSkipped).toBe(0);
    });

    it('should restore with keep_both conflict strategy', async () => {
      const { csrfToken: csrf1, csrfCookie: cookie1 } = await getCsrf(agent);

      const itemId = new Types.ObjectId().toString();

      // First, create an existing item
      const initialData = JSON.stringify({
        items: [{ _id: itemId, ...sampleVaultItem({ encryptedName: 'existing-item' }) }],
        folders: [],
      });

      await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf1)
        .set('Cookie', cookie1)
        .send({ conflictStrategy: 'skip', data: initialData });

      // Now restore with keep_both using the same ID - should create a new item
      const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);

      const keepBothData = JSON.stringify({
        items: [{ _id: itemId, ...sampleVaultItem({ encryptedName: 'duplicate-item' }) }],
        folders: [],
      });

      const res = await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf2)
        .set('Cookie', cookie2)
        .send({ conflictStrategy: 'keep_both', data: keepBothData });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.itemsRestored).toBe(1);

      // The whole point of keep_both is that it DUPLICATES the row rather than
      // updating the matched one in place. If it regressed to the overwrite
      // branch, itemsRestored would still be 1 while the user silently lost
      // their original item — so assert the DB actually holds both rows with
      // distinct _ids and both encryptedName values present.
      const restoredItems = await VaultItem.find({ userId: user.id })
        .select('_id encryptedName')
        .lean();
      expect(restoredItems).toHaveLength(2);
      const names = restoredItems.map((i) => i.encryptedName).sort();
      expect(names).toEqual(['duplicate-item', 'existing-item']);
      const ids = new Set(restoredItems.map((i) => String(i._id)));
      expect(ids.size).toBe(2);
    });
  });

  // ── Restore never replaces the vault key ────────────────────────
  // The server-side adoptVaultKey path was removed: a restore is a plain,
  // unprivileged add of rows the client already re-encrypted to the account's
  // current key. These are regression guards that no restore path can mutate
  // encryptedVaultKey/vaultKeyIv/vaultKeyTag.

  describe('POST /api/v1/backup/restore - vault key is never replaced', () => {
    it('leaves the vault key unchanged and ignores a legacy adoptVaultKey/authHash body', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const originalUser = await User.findById(user.id).lean();
      const originalVK = originalUser!.encryptedVaultKey;
      const originalIv = originalUser!.vaultKeyIv;
      const originalTag = originalUser!.vaultKeyTag;

      const itemId = new Types.ObjectId().toString();
      const backupData = JSON.stringify({
        items: [{ _id: itemId, ...sampleVaultItem({ encryptedName: 'restored-item' }) }],
      });

      // A legacy caller may still send adoptVaultKey/authHash; Zod strips them and
      // the restore proceeds normally without touching the vault key.
      const res = await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          data: backupData,
          authHash: user.rawPassword,
          adoptVaultKey: {
            encryptedVaultKey: 'attacker-supplied-vk',
            vaultKeyIv: 'attacker-iv',
            vaultKeyTag: 'attacker-tag',
          },
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.itemsRestored).toBe(1);

      const updatedUser = await User.findById(user.id).lean();
      expect(updatedUser!.encryptedVaultKey).toBe(originalVK);
      expect(updatedUser!.vaultKeyIv).toBe(originalIv);
      expect(updatedUser!.vaultKeyTag).toBe(originalTag);
    });

    it('does not emit a vaultKeyAdopted flag in the backup_restored audit metadata', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const backupData = JSON.stringify({ items: [], folders: [] });

      await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ data: backupData });

      const audit = await AuditLog.findOne({
        userId: user.id,
        action: 'backup_restored',
      })
        .sort({ timestamp: -1 })
        .lean();

      expect(audit).toBeDefined();
      const meta = audit!.metadata as Record<string, unknown>;
      expect(meta).not.toHaveProperty('vaultKeyAdopted');
    });
  });

  // ── Restore with invalid _id values ─────────────────────────────

  describe('POST /api/v1/backup/restore - _id validation', () => {
    it('should restore items with invalid _id by generating new ObjectIds', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const backupData = JSON.stringify({
        items: [
          { _id: 'not-a-valid-objectid', ...sampleVaultItem({ encryptedName: 'invalid-id-item' }) },
          { _id: '!!!invalid!!!', ...sampleVaultItem({ encryptedName: 'invalid-id-item-2' }) },
        ],
        folders: [
          { _id: 'bad-folder-id', ...sampleFolder({ encryptedName: 'invalid-id-folder' }) },
        ],
      });

      const res = await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ conflictStrategy: 'skip', data: backupData });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.itemsRestored).toBe(2);
      expect(res.body.data.foldersRestored).toBe(1);
    });

    it('should restore items without _id field by generating new ObjectIds', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const backupData = JSON.stringify({
        items: [{ ...sampleVaultItem({ encryptedName: 'no-id-item' }) }],
        folders: [{ ...sampleFolder({ encryptedName: 'no-id-folder' }) }],
      });

      const res = await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ conflictStrategy: 'skip', data: backupData });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.itemsRestored).toBe(1);
      expect(res.body.data.foldersRestored).toBe(1);
    });
  });

  // ── Auth Guards ──────────────────────────────────────────────────

  describe('Auth guards', () => {
    it('should return 401 for setup without token', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/backup/setup')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send(bwkSetupData);

      expect(res.status).toBe(401);
    });

    it('should return 401 for trigger without token', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/backup/trigger')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send();

      expect(res.status).toBe(401);
    });

    it('should return 401 for download without token', async () => {
      const res = await agent.get('/api/v1/backup/download');
      expect(res.status).toBe(401);
    });

    it('should return 401 for history without token', async () => {
      const res = await agent.get('/api/v1/backup/history');
      expect(res.status).toBe(401);
    });

    it('should return 401 for restore without token', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/backup/restore')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ conflictStrategy: 'skip', data: '{}' });

      expect(res.status).toBe(401);
    });
  });

  // ── Audit Logging ─────────────────────────────────────────────────

  describe('Audit logging', () => {
    it('should create audit log on backup setup', async () => {
      await setupBackupForUser(agent, user.accessToken);

      const auditEntry = await AuditLog.findOne({
        userId: user.id,
        action: 'backup_setup',
      });

      expect(auditEntry).toBeDefined();
      expect(auditEntry!.userId.toString()).toBe(user.id);
    });

    it('should create audit log on backup settings update', async () => {
      // Setup backup encryption first (isConfigured required for enabling)
      await setupBackupForUser(agent, user.accessToken);

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .put('/api/v1/backup/settings')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ enabled: true, scheduleHour: 8 })
        .expect(200);

      const auditEntry = await AuditLog.findOne({
        userId: user.id,
        action: 'backup_settings_update',
      });

      expect(auditEntry).toBeDefined();
      expect(auditEntry!.userId.toString()).toBe(user.id);
      expect(auditEntry!.metadata).toBeDefined();
      expect((auditEntry!.metadata as Record<string, unknown>).updatedFields).toBeDefined();
    });

    it('should create audit log on backup download', async () => {
      await setupBackupForUser(agent, user.accessToken);

      await agent
        .get('/api/v1/backup/download')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      const auditEntry = await AuditLog.findOne({
        userId: user.id,
        action: 'backup_download',
      });

      expect(auditEntry).toBeDefined();
      expect(auditEntry!.userId.toString()).toBe(user.id);
      expect(auditEntry!.metadata).toBeDefined();
      expect((auditEntry!.metadata as Record<string, unknown>).fileSizeBytes).toBeDefined();
    });

    it('should create audit log on backup trigger', async () => {
      await setupBackupForUser(agent, user.accessToken);

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      await agent
        .post('/api/v1/backup/trigger')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send()
        .expect(200);

      const auditEntry = await AuditLog.findOne({
        userId: user.id,
        action: 'backup_triggered',
      });

      expect(auditEntry).toBeDefined();
      expect(auditEntry!.userId.toString()).toBe(user.id);
      expect(auditEntry!.metadata).toBeDefined();
      expect(typeof (auditEntry!.metadata as Record<string, unknown>).itemCount).toBe('number');
      expect(typeof (auditEntry!.metadata as Record<string, unknown>).fileSizeBytes).toBe('number');
    });

    it('should create audit log on backup restore', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const backupData = JSON.stringify({
        items: [
          {
            _id: new Types.ObjectId().toString(),
            ...sampleVaultItem({ encryptedName: 'audit-restore-item' }),
          },
        ],
        folders: [],
      });

      await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ conflictStrategy: 'skip', data: backupData })
        .expect(200);

      const auditEntry = await AuditLog.findOne({
        userId: user.id,
        action: 'backup_restored',
      });

      expect(auditEntry).toBeDefined();
      expect(auditEntry!.userId.toString()).toBe(user.id);
      expect(auditEntry!.metadata).toBeDefined();
      const meta = auditEntry!.metadata as Record<string, unknown>;
      expect(meta.itemsRestored).toBe(1);
      expect(meta.foldersRestored).toBe(0);
      expect(meta.conflictStrategy).toBe('skip');
    });

    it('should create audit log on backup password change', async () => {
      await setupBackupForUser(agent, user.accessToken);

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .put('/api/v1/backup/change-password')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          password: user.rawPassword,
          newEncryptedBWK: 'audit-new-encrypted-bwk',
          newBwkIv: 'audit-new-bwk-iv',
          newBwkTag: 'audit-new-bwk-tag',
          newBwkSalt: 'audit-new-bwk-salt',
        })
        .expect(200);

      const auditEntry = await AuditLog.findOne({
        userId: user.id,
        action: 'backup_password_changed',
      });

      expect(auditEntry).toBeDefined();
      expect(auditEntry!.userId.toString()).toBe(user.id);
    });
  });

  // ── Backup Max Size ────────────────────────────────────────────────

  describe('Backup max size enforcement', () => {
    it('should reject trigger when backup exceeds max size', async () => {
      await setupBackupForUser(agent, user.accessToken);

      // Create many items to exceed the max backup size.
      // The config default is 25 MB; we'll create items with large encrypted data.
      const largeData = 'x'.repeat(100_000);
      const itemPromises: Promise<unknown>[] = [];
      for (let i = 0; i < 300; i++) {
        itemPromises.push(
          VaultItem.create({
            userId: user.id,
            itemType: 'note',
            encryptedData: largeData,
            dataIv: 'test-iv',
            dataTag: 'test-tag',
            encryptedName: 'large-item',
            nameIv: 'test-iv',
            nameTag: 'test-tag',
            tags: [],
            favorite: false,
          }),
        );
      }
      await Promise.all(itemPromises);

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/backup/trigger')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send();

      expect(res.status).toBe(413);
      expect(res.body.success).toBe(false);
    });

    it('should reject download when backup exceeds max size', async () => {
      await setupBackupForUser(agent, user.accessToken);

      // Items should still be there from a previous test — create them directly
      const largeData = 'x'.repeat(100_000);
      const itemPromises: Promise<unknown>[] = [];
      for (let i = 0; i < 300; i++) {
        itemPromises.push(
          VaultItem.create({
            userId: user.id,
            itemType: 'note',
            encryptedData: largeData,
            dataIv: 'test-iv',
            dataTag: 'test-tag',
            encryptedName: 'large-download-item',
            nameIv: 'test-iv',
            nameTag: 'test-tag',
            tags: [],
            favorite: false,
          }),
        );
      }
      await Promise.all(itemPromises);

      const res = await agent
        .get('/api/v1/backup/download')
        .set('Authorization', authHeader(user.accessToken));

      expect(res.status).toBe(413);
      expect(res.body.success).toBe(false);
    });
  });

  // ── Restore Item Count Limit ───────────────────────────────────────

  describe('Restore item count limit', () => {
    it('should reject restore when total entries exceed 10,000', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      // Create a payload with 10,001 minimal items (empty objects).
      // The controller checks array length before processing individual items,
      // so empty objects suffice to trigger the count limit.
      const items: Record<string, unknown>[] = Array.from({ length: 10_001 }, () => ({}));

      const backupData = JSON.stringify({ items, folders: [] });

      const res = await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ conflictStrategy: 'skip', data: backupData });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      // Pin the ENTRIES guard specifically: without this message assertion the
      // per-user item cap (also a 400) would satisfy the test even if the
      // MAX_IMPORT_ITEMS entries guard were deleted.
      expect(String(res.body.message)).toMatch(/maximum allowed item count/i);
    });

    it('should reject restore when combined items + folders exceed 10,000', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const items: Record<string, unknown>[] = Array.from({ length: 5_001 }, () => ({}));
      const folders: Record<string, unknown>[] = Array.from({ length: 5_000 }, () => ({}));

      const backupData = JSON.stringify({ items, folders });

      const res = await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ conflictStrategy: 'skip', data: backupData });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      // Same as above: the combined 10,001 entries must trip the entries guard,
      // not the per-user folder cap (5,000 folders would also 400 on its own).
      expect(String(res.body.message)).toMatch(/maximum allowed item count/i);
    });
  });

  // ── User Isolation ─────────────────────────────────────────────────

  describe('User isolation', () => {
    it('should not return another user backup data in download', async () => {
      // Create a second user
      const user2 = await createTestUser();
      await setupBackupForUser(agent, user2.accessToken);

      // Create an item for user1
      await VaultItem.create({
        userId: user.id,
        itemType: 'login',
        encryptedData: 'user1-encrypted-data',
        dataIv: 'user1-data-iv',
        dataTag: 'user1-data-tag',
        encryptedName: 'user1-item',
        nameIv: 'user1-name-iv',
        nameTag: 'user1-name-tag',
        tags: [],
        favorite: false,
      });

      // Create an item for user2
      await VaultItem.create({
        userId: user2.id,
        itemType: 'login',
        encryptedData: 'user2-encrypted-data',
        dataIv: 'user2-data-iv',
        dataTag: 'user2-data-tag',
        encryptedName: 'user2-item',
        nameIv: 'user2-name-iv',
        nameTag: 'user2-name-tag',
        tags: [],
        favorite: false,
      });

      // Download backup as user2
      const res = await agent
        .get('/api/v1/backup/download')
        .set('Authorization', authHeader(user2.accessToken));

      expect(res.status).toBe(200);
      const backup = JSON.parse(res.text) as {
        items: { encryptedData: string; userId: string }[];
      };

      // Should only contain user2's items
      expect(backup.items.length).toBe(1);
      expect(backup.items[0]!.encryptedData).toBe('user2-encrypted-data');
      // None of user1's items should be present
      for (const item of backup.items) {
        expect(item.userId.toString()).toBe(user2.id);
      }
    });

    it('should restore items only to the authenticated user', async () => {
      const user2 = await createTestUser();
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const itemId = new Types.ObjectId().toString();
      const backupData = JSON.stringify({
        items: [{ _id: itemId, ...sampleVaultItem({ encryptedName: 'isolation-restore-item' }) }],
        folders: [],
      });

      // Restore as user2
      await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user2.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ conflictStrategy: 'skip', data: backupData })
        .expect(200);

      // The restored item should belong to user2, not user1 (restored with a
      // fresh server-minted _id, so look it up by content).
      const restoredItem = await VaultItem.findOne({
        userId: user2.id,
        encryptedName: 'isolation-restore-item',
      });
      expect(restoredItem).not.toBeNull();
      expect(restoredItem!.userId.toString()).toBe(user2.id);

      // user1 should not have this item
      const user1Item = await VaultItem.findOne({
        userId: user.id,
        encryptedName: 'isolation-restore-item',
      });
      expect(user1Item).toBeNull();
    });

    it('should not include deleted items in backup download', async () => {
      await setupBackupForUser(agent, user.accessToken);

      // Create a normal item
      await VaultItem.create({
        userId: user.id,
        itemType: 'login',
        encryptedData: 'active-data',
        dataIv: 'iv',
        dataTag: 'tag',
        encryptedName: 'active-item',
        nameIv: 'iv',
        nameTag: 'tag',
        tags: [],
        favorite: false,
      });

      // Create a soft-deleted item
      await VaultItem.create({
        userId: user.id,
        itemType: 'login',
        encryptedData: 'deleted-data',
        dataIv: 'iv',
        dataTag: 'tag',
        encryptedName: 'deleted-item',
        nameIv: 'iv',
        nameTag: 'tag',
        tags: [],
        favorite: false,
        deletedAt: new Date(),
      });

      const res = await agent
        .get('/api/v1/backup/download')
        .set('Authorization', authHeader(user.accessToken));

      expect(res.status).toBe(200);
      const backup = JSON.parse(res.text) as {
        items: { encryptedData: string }[];
      };

      // Only active item should be included
      const dataValues = backup.items.map((i) => i.encryptedData);
      expect(dataValues).toContain('active-data');
      expect(dataValues).not.toContain('deleted-data');
    });

    it('should isolate backup history between users', async () => {
      const user2 = await createTestUser();

      // Setup and trigger backup for user1
      await setupBackupForUser(agent, user.accessToken);
      const { csrfToken: csrf1, csrfCookie: cookie1 } = await getCsrf(agent);
      await agent
        .post('/api/v1/backup/trigger')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf1)
        .set('Cookie', cookie1)
        .send()
        .expect(200);

      // user2 should not see user1's backup history
      const res = await agent
        .get('/api/v1/backup/history')
        .set('Authorization', authHeader(user2.accessToken));

      expect(res.status).toBe(200);
      expect(res.body.data.length).toBe(0);
      expect(res.body.pagination.total).toBe(0);
    });
  });

  // ── Backup with Empty Vault ────────────────────────────────────────

  describe('Backup with empty vault', () => {
    it('should trigger backup successfully with zero items', async () => {
      await setupBackupForUser(agent, user.accessToken);

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/backup/trigger')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send();

      expect(res.status).toBe(200);
      expect(res.body.data.itemCount).toBe(0);
      expect(res.body.data.fileSizeBytes).toBeGreaterThan(0);
    });

    it('should download empty vault backup', async () => {
      await setupBackupForUser(agent, user.accessToken);

      const res = await agent
        .get('/api/v1/backup/download')
        .set('Authorization', authHeader(user.accessToken));

      expect(res.status).toBe(200);
      const backup = JSON.parse(res.text) as {
        items: unknown[];
        folders: unknown[];
      };
      expect(backup.items.length).toBe(0);
      expect(backup.folders.length).toBe(0);
    });
  });

  // ── Backup Trigger Email Feedback ─────────────────────────────────

  describe('Backup trigger email feedback', () => {
    it('should include emailSent field in trigger response', async () => {
      await setupBackupForUser(agent, user.accessToken);

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/backup/trigger')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send();

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('emailSent');
      expect(typeof res.body.data.emailSent).toBe('boolean');
    });

    it('should return emailSent false when email is not configured', async () => {
      await setupBackupForUser(agent, user.accessToken);

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/backup/trigger')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send();

      expect(res.status).toBe(200);
      expect(res.body.data.emailSent).toBe(false);
      expect(res.body.message).toMatch(/email not configured/i);
    });

    it('should log backup as success when email is not configured', async () => {
      await setupBackupForUser(agent, user.accessToken);

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .post('/api/v1/backup/trigger')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send();

      const historyRes = await agent
        .get('/api/v1/backup/history?page=1&limit=10')
        .set('Authorization', authHeader(user.accessToken));

      expect(historyRes.body.data[0].status).toBe('success');
    });
  });

  // ── Restore with Empty Data ────────────────────────────────────────

  describe('Restore edge cases', () => {
    it('should handle restore with empty items and folders', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const backupData = JSON.stringify({ items: [], folders: [] });

      const res = await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ conflictStrategy: 'skip', data: backupData });

      expect(res.status).toBe(200);
      expect(res.body.data.itemsRestored).toBe(0);
      expect(res.body.data.foldersRestored).toBe(0);
    });

    it('should handle restore with missing items and folders arrays', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const backupData = JSON.stringify({});

      const res = await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ conflictStrategy: 'skip', data: backupData });

      expect(res.status).toBe(200);
      expect(res.body.data.itemsRestored).toBe(0);
      expect(res.body.data.foldersRestored).toBe(0);
    });

    it('should restore items that exist in trash without duplicate error', async () => {
      const itemId = new Types.ObjectId().toString();

      // Create a soft-deleted (trashed) item directly in DB
      await VaultItem.create({
        _id: itemId,
        userId: user.id,
        itemType: 'login',
        encryptedData: 'trashed-data',
        dataIv: 'test-iv',
        dataTag: 'test-tag',
        encryptedName: 'trashed-item',
        nameIv: 'test-iv',
        nameTag: 'test-tag',
        tags: [],
        favorite: false,
        deletedAt: new Date(),
      });

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const backupData = JSON.stringify({
        items: [{ _id: itemId, ...sampleVaultItem({ encryptedName: 'restored-from-backup' }) }],
        folders: [],
      });

      const res = await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ conflictStrategy: 'skip', data: backupData });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.itemsRestored).toBe(1);
      expect(res.body.data.itemsSkipped).toBe(0);

      // The item should no longer be in trash (deletedAt cleared)
      const item = await VaultItem.findById(itemId);
      expect(item).toBeDefined();
      expect(item!.deletedAt).toBeUndefined();
      // Data should be updated from the backup
      expect(item!.encryptedName).toBe('restored-from-backup');
    });

    it('should skip existing items with skip conflict strategy and report skip reason', async () => {
      const itemId = new Types.ObjectId().toString();

      // Create existing item directly in DB
      await VaultItem.create({
        _id: itemId,
        userId: user.id,
        itemType: 'login',
        encryptedData: 'original-data',
        dataIv: 'test-iv',
        dataTag: 'test-tag',
        encryptedName: 'original',
        nameIv: 'test-iv',
        nameTag: 'test-tag',
        tags: [],
        favorite: false,
      });

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const backupData = JSON.stringify({
        items: [{ _id: itemId, ...sampleVaultItem({ encryptedName: 'should-be-skipped' }) }],
        folders: [],
      });

      const res = await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ conflictStrategy: 'skip', data: backupData });

      expect(res.status).toBe(200);
      expect(res.body.data.itemsSkipped).toBe(1);
      expect(res.body.data.itemsRestored).toBe(0);
      expect(res.body.data.itemSkipReasons).toEqual([{ itemId, reason: 'conflict_skipped' }]);

      // Original data should be preserved
      const item = await VaultItem.findById(itemId);
      expect(item!.encryptedData).toBe('original-data');
    });

    it('should report invalid_item_type skip reason for unrecognized item types', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const badItemId = new Types.ObjectId().toString();
      const backupData = JSON.stringify({
        items: [{ _id: badItemId, ...sampleVaultItem({ itemType: 'unknown_type' }) }],
        folders: [],
      });

      const res = await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ conflictStrategy: 'skip', data: backupData });

      expect(res.status).toBe(200);
      expect(res.body.data.itemsSkipped).toBe(1);
      expect(res.body.data.itemsRestored).toBe(0);
      expect(res.body.data.itemSkipReasons).toEqual([
        { itemId: badItemId, reason: 'invalid_item_type' },
      ]);
    });

    it('should report missing_encryption_fields skip reason for items without encryption data', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const badItemId = new Types.ObjectId().toString();
      const backupData = JSON.stringify({
        items: [
          {
            _id: badItemId,
            itemType: 'login',
            encryptedData: '',
            dataIv: '',
            dataTag: '',
            encryptedName: '',
            nameIv: '',
            nameTag: '',
          },
        ],
        folders: [],
      });

      const res = await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ conflictStrategy: 'skip', data: backupData });

      expect(res.status).toBe(200);
      expect(res.body.data.itemsSkipped).toBe(1);
      expect(res.body.data.itemsRestored).toBe(0);
      expect(res.body.data.itemSkipReasons).toEqual([
        { itemId: badItemId, reason: 'missing_encryption_fields' },
      ]);
    });

    it('should report folder conflict_skipped skip reason', async () => {
      const folderId = new Types.ObjectId().toString();

      // Create existing folder directly in DB
      const { Folder } = await import('../src/models/Folder.js');
      await Folder.create({
        _id: folderId,
        userId: user.id,
        encryptedName: 'existing-folder',
        nameIv: 'test-iv',
        nameTag: 'test-tag',
      });

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const backupData = JSON.stringify({
        items: [],
        folders: [
          { _id: folderId, ...sampleFolder({ encryptedName: 'should-be-skipped-folder' }) },
        ],
      });

      const res = await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ conflictStrategy: 'skip', data: backupData });

      expect(res.status).toBe(200);
      expect(res.body.data.foldersSkipped).toBe(1);
      expect(res.body.data.foldersRestored).toBe(0);
      expect(res.body.data.folderSkipReasons).toEqual([{ folderId, reason: 'conflict_skipped' }]);
    });

    it('should report multiple skip reasons for mixed valid and invalid items', async () => {
      const existingItemId = new Types.ObjectId().toString();
      const badTypeId = new Types.ObjectId().toString();
      const missingFieldsId = new Types.ObjectId().toString();
      const validItemId = new Types.ObjectId().toString();

      // Create an existing item for the conflict skip
      await VaultItem.create({
        _id: existingItemId,
        userId: user.id,
        itemType: 'login',
        encryptedData: 'original',
        dataIv: 'iv',
        dataTag: 'tag',
        encryptedName: 'original',
        nameIv: 'iv',
        nameTag: 'tag',
        tags: [],
        favorite: false,
      });

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const backupData = JSON.stringify({
        items: [
          { _id: existingItemId, ...sampleVaultItem() },
          { _id: badTypeId, ...sampleVaultItem({ itemType: 'invalid' }) },
          {
            _id: missingFieldsId,
            itemType: 'login',
            encryptedData: '',
            dataIv: '',
            dataTag: '',
            encryptedName: '',
            nameIv: '',
            nameTag: '',
          },
          { _id: validItemId, ...sampleVaultItem({ encryptedName: 'valid-item' }) },
        ],
        folders: [],
      });

      const res = await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ conflictStrategy: 'skip', data: backupData });

      expect(res.status).toBe(200);
      expect(res.body.data.itemsRestored).toBe(1);
      expect(res.body.data.itemsSkipped).toBe(3);
      expect(res.body.data.itemSkipReasons).toHaveLength(3);
      expect(res.body.data.itemSkipReasons).toEqual(
        expect.arrayContaining([
          { itemId: existingItemId, reason: 'conflict_skipped' },
          { itemId: badTypeId, reason: 'invalid_item_type' },
          { itemId: missingFieldsId, reason: 'missing_encryption_fields' },
        ]),
      );
    });

    it('should return empty skip reasons when no items are skipped', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const itemId = new Types.ObjectId().toString();
      const backupData = JSON.stringify({
        items: [{ _id: itemId, ...sampleVaultItem() }],
        folders: [],
      });

      const res = await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ conflictStrategy: 'skip', data: backupData });

      expect(res.status).toBe(200);
      expect(res.body.data.itemsRestored).toBe(1);
      expect(res.body.data.itemsSkipped).toBe(0);
      expect(res.body.data.itemSkipReasons).toEqual([]);
      expect(res.body.data.folderSkipReasons).toEqual([]);
    });

    it('should include skip reasons in audit log', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const badItemId = new Types.ObjectId().toString();
      const backupData = JSON.stringify({
        items: [{ _id: badItemId, ...sampleVaultItem({ itemType: 'nonexistent' }) }],
        folders: [],
      });

      const res = await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ conflictStrategy: 'skip', data: backupData });

      expect(res.status).toBe(200);

      const auditLog = await AuditLog.findOne({
        userId: user.id,
        action: 'backup_restored',
      })
        .sort({ timestamp: -1 })
        .lean();

      expect(auditLog).toBeDefined();
      expect(auditLog!.metadata).toBeDefined();

      const metadata = auditLog!.metadata as Record<string, unknown>;
      expect(metadata.itemsSkipped).toBe(1);

      const itemSkipReasons = metadata.itemSkipReasons as Record<string, string>[];
      expect(itemSkipReasons).toEqual([{ itemId: badItemId, reason: 'invalid_item_type' }]);
    });

    it('should not include skip reasons in audit log when no items are skipped', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const itemId = new Types.ObjectId().toString();
      const backupData = JSON.stringify({
        items: [{ _id: itemId, ...sampleVaultItem() }],
        folders: [],
      });

      const res = await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ conflictStrategy: 'skip', data: backupData });

      expect(res.status).toBe(200);

      const auditLog = await AuditLog.findOne({
        userId: user.id,
        action: 'backup_restored',
      })
        .sort({ timestamp: -1 })
        .lean();

      expect(auditLog).toBeDefined();

      const metadata = auditLog!.metadata as Record<string, unknown>;
      expect(metadata.itemSkipReasons).toBeUndefined();
      expect(metadata.folderSkipReasons).toBeUndefined();
    });
  });

  // ── Restore conflict strategy audit logging ─────────────────────

  describe('POST /api/v1/backup/restore - conflict strategy in audit log', () => {
    it('should record the selected conflict strategy in the audit log', async () => {
      const strategies = ['skip', 'overwrite', 'keep_both'] as const;

      for (const strategy of strategies) {
        const { csrfToken, csrfCookie } = await getCsrf(agent);
        const itemId = new Types.ObjectId().toString();
        const backupData = JSON.stringify({
          items: [
            { _id: itemId, ...sampleVaultItem({ encryptedName: `audit-strategy-${strategy}` }) },
          ],
          folders: [],
        });

        await agent
          .post('/api/v1/backup/restore')
          .set('Authorization', authHeader(user.accessToken))
          .set('x-csrf-token', csrfToken)
          .set('Cookie', csrfCookie)
          .send({ conflictStrategy: strategy, data: backupData });

        const auditEntry = await AuditLog.findOne({
          userId: user.id,
          action: 'backup_restored',
        }).sort({ timestamp: -1 });

        expect(auditEntry).toBeDefined();
        const metadata = auditEntry!.metadata as Record<string, unknown>;
        expect(metadata.conflictStrategy).toBe(strategy);
      }
    });

    it('should default to skip conflict strategy when none specified', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const itemId = new Types.ObjectId().toString();
      const backupData = JSON.stringify({
        items: [{ _id: itemId, ...sampleVaultItem({ encryptedName: 'default-strategy' }) }],
        folders: [],
      });

      await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ data: backupData });

      const auditEntry = await AuditLog.findOne({
        userId: user.id,
        action: 'backup_restored',
      }).sort({ timestamp: -1 });

      expect(auditEntry).toBeDefined();
      const metadata = auditEntry!.metadata as Record<string, unknown>;
      expect(metadata.conflictStrategy).toBe('skip');
    });
  });

  // ── Restore data size limit (aligned with BACKUP_MAX_SIZE_MB) ───

  describe('POST /api/v1/backup/restore - data size limits', () => {
    it('should accept restore data larger than 1MB (up to 25MB limit)', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      // Create a few items with large encryptedData (under model maxlength of 500k)
      // to push the total data string over 1MB.
      const items = [];
      for (let i = 0; i < 3; i++) {
        items.push({
          _id: new Types.ObjectId().toString(),
          ...sampleVaultItem({ encryptedData: 'x'.repeat(400_000) }),
        });
      }
      const backupData = JSON.stringify({ items, folders: [] });

      // Verify the payload is actually over 1MB
      expect(backupData.length).toBeGreaterThan(1_048_576);

      const res = await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ data: backupData });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.itemsRestored).toBe(3);
    });

    it('should accept restore data larger than 2MB (exceeding global body parser limit)', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      // Create items with large encryptedData to push total payload over 2MB
      // (the global body parser limit). This verifies the route-level 30MB parser
      // handles the request instead of the global 2MB parser rejecting it with 413.
      const items = [];
      for (let i = 0; i < 6; i++) {
        items.push({
          _id: new Types.ObjectId().toString(),
          ...sampleVaultItem({ encryptedData: 'x'.repeat(400_000) }),
        });
      }
      const backupData = JSON.stringify({ items, folders: [] });

      // Verify the payload is actually over 2MB
      expect(backupData.length).toBeGreaterThan(2_097_152);

      const res = await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ data: backupData });

      // Should succeed (not 413) because the route-specific 30MB parser handles it
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.itemsRestored).toBe(6);
    });
  });

  // ── Concurrent trigger deduplication ──────────────────────────────

  describe('POST /api/v1/backup/trigger - concurrent deduplication', () => {
    it('should reject a second concurrent trigger for the same user', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await setupBackupForUser(agent, user.accessToken);

      // Simulate an in-progress backup by acquiring the distributed lock
      const lockJobName = `backup:trigger:${user.id}`;
      await JobLock.create({
        jobName: lockJobName,
        lockedBy: 'simulated-worker',
        lockedAt: new Date(),
        expiresAt: new Date(Date.now() + 5 * 60 * 1000),
      });

      const res = await agent
        .post('/api/v1/backup/trigger')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie);

      expect(res.status).toBe(409);
      expect(res.body.success).toBe(false);
    });

    it('should release the lock after successful trigger', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await setupBackupForUser(agent, user.accessToken);

      const res = await agent
        .post('/api/v1/backup/trigger')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie);

      expect(res.status).toBe(200);

      // Lock should be released after successful completion
      const lockJobName = `backup:trigger:${user.id}`;
      const lock = await JobLock.findOne({ jobName: lockJobName });
      expect(lock).toBeNull();
    });
  });
});
