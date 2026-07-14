/**
 * Phase 6 — Task 6.3: Backup Integrity and Edge Case Tests
 *
 * Covers scenarios not already exercised by backup.test.ts,
 * phase2-security-hardening.test.ts, or phase8-backup-restore-atomicity.test.ts:
 *   • JSON that parses but has the wrong structure (items not an array).
 *   • Restore with items referencing a non-existent folder.
 *   • Restore when the user has reached the per-user item limit.
 *   • Restore with items at the maximum allowed encrypted data length.
 *   • Restore with items that have extra fields beyond the allowlist.
 *   • Backup trigger with items at maximum encrypted data length.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import { Types } from 'mongoose';
import app from '../src/app.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import {
  createTestUser,
  authHeader,
  sampleVaultItem,
  sampleFolder,
  getCsrf,
  type TestUser,
} from './helpers.js';

const API = '/api/v1';

const BWK_SETUP = {
  encryptedBWK: 'test-encrypted-bwk-data',
  bwkIv: 'test-bwk-iv-value',
  bwkTag: 'test-bwk-tag-value',
  bwkSalt: 'test-bwk-salt-value',
};

async function setupBackup(token: string, rawPassword: string): Promise<void> {
  const agent = request.agent(app);
  const csrf = await getCsrf(agent);
  const res = await agent
    .post(`${API}/backup/setup`)
    .set('Authorization', authHeader(token))
    .set('x-csrf-token', csrf.token)
    .set('Cookie', csrf.cookie)
    .send({ ...BWK_SETUP, authHash: rawPassword });
  expect(res.status).toBe(200);
}

async function postRestore(
  token: string,
  payload: Record<string, unknown>,
): Promise<request.Response> {
  const agent = request.agent(app);
  const csrf = await getCsrf(agent);
  return agent
    .post(`${API}/backup/restore`)
    .set('Authorization', authHeader(token))
    .set('x-csrf-token', csrf.token)
    .set('Cookie', csrf.cookie)
    .send(payload);
}

describe('Phase 6 — Backup Integrity and Edge Cases', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  // ── Corrupted/tampered JSON structure ──────────────────────────────

  describe('malformed backup payload', () => {
    it('should reject JSON where items is not an array', async () => {
      const data = JSON.stringify({ items: 'not-an-array', folders: [] });
      const res = await postRestore(user.accessToken, {
        conflictStrategy: 'skip',
        data,
      });
      // The controller coerces a non-array `items` via `?? []`-style handling
      // and iterates it defensively, so a malformed structure yields a clean 200
      // with nothing restored (never a 5xx crash, and — pinning the real
      // contract — not an auth/CSRF rejection that would make the DB assertion
      // vacuously true).
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.itemsRestored).toBe(0);
      const count = await VaultItem.countDocuments({ userId: user.id });
      expect(count).toBe(0);
    });

    it('should handle an item missing all encryption fields by skipping it', async () => {
      const itemId = new Types.ObjectId().toString();
      const data = JSON.stringify({
        items: [{ _id: itemId, itemType: 'login' }], // no encryptedData/IV/tag/name fields
        folders: [],
      });
      const res = await postRestore(user.accessToken, {
        conflictStrategy: 'skip',
        data,
      });

      expect(res.status).toBe(200);
      expect(res.body.data.itemsRestored).toBe(0);
      expect(res.body.data.itemsSkipped).toBe(1);
      expect(res.body.data.itemSkipReasons).toEqual([
        { itemId, reason: 'missing_encryption_fields' },
      ]);

      // Nothing persisted
      const count = await VaultItem.countDocuments({ userId: user.id });
      expect(count).toBe(0);
    });

    it('should skip items with invalid itemType', async () => {
      const itemId = new Types.ObjectId().toString();
      const data = JSON.stringify({
        items: [
          {
            _id: itemId,
            itemType: 'bogus-type',
            ...sampleVaultItem({ encryptedName: 'bogus' }),
            itemType_again: 'bogus', // noise
          },
        ],
        folders: [],
      });
      // Override itemType manually (sampleVaultItem sets itemType: 'login')
      const parsed = JSON.parse(data) as { items: Record<string, unknown>[]; folders: unknown[] };
      parsed.items[0]!['itemType'] = 'bogus-type';
      const payload = JSON.stringify(parsed);

      const res = await postRestore(user.accessToken, {
        conflictStrategy: 'skip',
        data: payload,
      });

      expect(res.status).toBe(200);
      expect(res.body.data.itemsRestored).toBe(0);
      expect(res.body.data.itemsSkipped).toBe(1);
      expect(res.body.data.itemSkipReasons[0].reason).toBe('invalid_item_type');
    });
  });

  // ── Restore with items referencing non-existent folder ──────────────

  describe('restore items referencing a non-existent folder', () => {
    it('still restores the item but strips the dangling folderId', async () => {
      const itemId = new Types.ObjectId().toString();
      const danglingFolderId = new Types.ObjectId().toString();

      const data = JSON.stringify({
        items: [
          {
            _id: itemId,
            ...sampleVaultItem({ encryptedName: 'dangling-folder-item' }),
            folderId: danglingFolderId,
          },
        ],
        folders: [], // folder not included in backup
      });

      const res = await postRestore(user.accessToken, {
        conflictStrategy: 'skip',
        data,
      });

      expect(res.status).toBe(200);
      expect(res.body.data.itemsRestored).toBe(1);

      const item = await VaultItem.findOne({
        userId: user.id,
        encryptedName: 'dangling-folder-item',
      }).lean();
      expect(item).not.toBeNull();
      // folderId is stripped because it doesn't belong to any user folder —
      // defense-in-depth against tampered backups planting dangling references.
      // Mirrors the importVault pattern.
      expect(item!.folderId).toBeUndefined();
    });
  });

  // ── Restore when user at item limit ─────────────────────────────────

  describe('restore when user has reached per-user item limit', () => {
    it('should reject restore that would exceed MAX_ITEMS_PER_USER', async () => {
      const { MAX_ITEMS_PER_USER } = await import('@hvault/shared');

      // Simulate the user already having exactly the maximum allowed items
      const spy = vi
        .spyOn(VaultItem, 'countDocuments')
        .mockResolvedValueOnce(MAX_ITEMS_PER_USER as never);

      const data = JSON.stringify({
        items: [
          {
            _id: new Types.ObjectId().toString(),
            ...sampleVaultItem({ encryptedName: 'one-too-many' }),
          },
        ],
        folders: [],
      });

      const res = await postRestore(user.accessToken, {
        conflictStrategy: 'skip',
        data,
      });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(String(res.body.message)).toMatch(/per-user item limit/i);

      spy.mockRestore();
    });
  });

  // ── Restore with items at max encrypted data length ─────────────────

  describe('restore with items at maximum encrypted data length', () => {
    it('should accept an item with encryptedData at MAX_ENCRYPTED_DATA_LENGTH', async () => {
      const { MAX_ENCRYPTED_DATA_LENGTH } = await import('@hvault/shared');

      const hugePayload = 'a'.repeat(MAX_ENCRYPTED_DATA_LENGTH);
      const itemId = new Types.ObjectId().toString();

      const data = JSON.stringify({
        items: [
          {
            _id: itemId,
            ...sampleVaultItem({ encryptedName: 'max-size-item' }),
            encryptedData: hugePayload,
          },
        ],
        folders: [],
      });

      const res = await postRestore(user.accessToken, {
        conflictStrategy: 'skip',
        data,
      });

      expect(res.status).toBe(200);
      expect(res.body.data.itemsRestored).toBe(1);

      const item = await VaultItem.findOne({
        userId: user.id,
        encryptedName: 'max-size-item',
      }).lean();
      expect(item).not.toBeNull();
      expect(item!.encryptedData).toBe(hugePayload);
      expect(item!.encryptedData.length).toBe(MAX_ENCRYPTED_DATA_LENGTH);
    });
  });

  // ── Restore strips fields beyond the allowlist ─────────────────────

  describe('restore strips disallowed fields (defense-in-depth)', () => {
    it('should ignore extra fields on restored items that are not on the allowlist', async () => {
      const itemId = new Types.ObjectId().toString();

      const data = JSON.stringify({
        items: [
          {
            _id: itemId,
            ...sampleVaultItem({ encryptedName: 'with-extras' }),
            // Non-allowlisted fields an attacker might inject
            userId: new Types.ObjectId().toString(), // attempt cross-user
            __proto__: { polluted: true },
            createdAt: '1970-01-01T00:00:00.000Z',
            deletedAt: '2099-01-01T00:00:00.000Z', // attempt to mark as trashed
            searchHash: 'a'.repeat(64), // must be 64 hex if present — this is valid format
          },
        ],
        folders: [],
      });

      const res = await postRestore(user.accessToken, {
        conflictStrategy: 'skip',
        data,
      });

      expect(res.status).toBe(200);
      expect(res.body.data.itemsRestored).toBe(1);

      const item = await VaultItem.findOne({
        userId: user.id,
        encryptedName: 'with-extras',
      }).lean();
      expect(item).not.toBeNull();
      // userId must be the authenticated user, NOT the spoofed one
      expect(String(item!.userId)).toBe(user.id);
      // deletedAt must not be set from the injected value
      expect(item!.deletedAt).toBeUndefined();
    });
  });

  // ── Restore with folders referencing a non-existent parent ─────────

  describe('restore with folders referencing non-existent parent', () => {
    it('should clear parentId references that do not exist post-restore', async () => {
      const parentId = new Types.ObjectId().toString();
      const childId = new Types.ObjectId().toString();

      const data = JSON.stringify({
        items: [],
        folders: [
          // Only the child is in the backup; its parentId dangles.
          {
            _id: childId,
            ...sampleFolder({ encryptedName: 'orphan-child' }),
            parentId,
          },
        ],
      });

      const res = await postRestore(user.accessToken, {
        conflictStrategy: 'skip',
        data,
      });

      expect(res.status).toBe(200);
      expect(res.body.data.foldersRestored).toBe(1);

      const child = await Folder.findOne({ userId: user.id, encryptedName: 'orphan-child' }).lean();
      expect(child).not.toBeNull();
      // parentId should have been stripped by the post-restore cleanup
      expect(child!.parentId).toBeUndefined();
    });
  });

  // ── Backup trigger with configured recipients but no email provider ─

  describe('backup trigger with email disabled', () => {
    it('should create a successful backup log even when email is not configured', async () => {
      await setupBackup(user.accessToken, user.rawPassword);

      const agent = request.agent(app);
      const csrf = await getCsrf(agent);
      const res = await agent
        .post(`${API}/backup/trigger`)
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf.token)
        .set('Cookie', csrf.cookie);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.emailsSent).toBe(0); // no email provider in tests
      expect(res.body.data.emailsFailed).toBe(0);
      expect(res.body.data.failedEmails).toEqual([]);

      // History includes the triggered backup
      const histRes = await agent
        .get(`${API}/backup/history`)
        .set('Authorization', authHeader(user.accessToken));
      expect(histRes.status).toBe(200);
      expect(histRes.body.data.length).toBeGreaterThanOrEqual(1);
    });
  });

  // ── Backup trigger with partial email failure (mocked) ──────────────

  describe('backup trigger with partial email delivery failure', () => {
    it('should report partial failure when some recipient emails fail', async () => {
      await setupBackup(user.accessToken, user.rawPassword);

      // Configure multiple backup emails
      const agent = request.agent(app);
      const csrf1 = await getCsrf(agent);
      const settingsRes = await agent
        .put(`${API}/backup/settings`)
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf1.token)
        .set('Cookie', csrf1.cookie)
        .send({
          backupEmails: ['ok@example.com', 'fails@example.com', 'ok2@example.com'],
        });
      expect(settingsRes.status).toBe(200);

      // Stub sendEmail: success for "ok*" addresses, failure for "fails@" address.
      // Use the emailConfigured module re-export so the controller thinks email
      // is enabled for this test.
      const emailModule = await import('../src/utils/email.js');
      const sendEmailSpy = vi
        .spyOn(emailModule, 'sendEmail')
        .mockImplementation(async (to: string) => {
          if (to.startsWith('fails@')) {
            return { success: false, message: 'smtp_send_failed: simulated' };
          }
          return { success: true, message: 'sent' };
        });

      const configModule = await import('../src/config/index.js');
      const emailConfiguredDescriptor = Object.getOwnPropertyDescriptor(
        configModule,
        'emailConfigured',
      );
      Object.defineProperty(configModule, 'emailConfigured', {
        value: true,
        configurable: true,
        writable: true,
      });

      try {
        const csrf2 = await getCsrf(agent);
        const res = await agent
          .post(`${API}/backup/trigger`)
          .set('Authorization', authHeader(user.accessToken))
          .set('x-csrf-token', csrf2.token)
          .set('Cookie', csrf2.cookie);

        // The controller may read emailConfigured at module load time, which
        // limits what we can verify. In that case the spy never runs and we
        // fall back to checking that the endpoint still returns a valid shape.
        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
        // Assert UNCONDITIONALLY (the former `if (spy.calls > 0)` guard let the
        // whole partial-failure contract silently go unasserted if the email
        // branch were ever skipped). The controller must attempt all three
        // recipients and report the one failure precisely.
        expect(sendEmailSpy).toHaveBeenCalledTimes(3);
        expect(res.body.data.failedEmails).toEqual(['fails@example.com']);
        expect(res.body.data.emailsFailed).toBe(1);
        expect(res.body.data.emailsSent).toBe(2);
      } finally {
        sendEmailSpy.mockRestore();
        if (emailConfiguredDescriptor) {
          Object.defineProperty(configModule, 'emailConfigured', emailConfiguredDescriptor);
        }
      }
    });
  });
});
