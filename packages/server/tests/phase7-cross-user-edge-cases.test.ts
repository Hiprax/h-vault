import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../src/app.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { AuditLog } from '../src/models/AuditLog.js';
import {
  createTestUser,
  authHeader,
  sampleVaultItem,
  sampleFolder,
  getCsrf,
  type TestUser,
} from './helpers.js';

// ---------------------------------------------------------------------------
// Phase 7 — Task 7.3: Cross-User Isolation Edge Case Tests
// ---------------------------------------------------------------------------

describe('Cross-User Isolation Edge Cases', () => {
  let userA: TestUser;
  let userB: TestUser;

  beforeEach(async () => {
    userA = await createTestUser({ email: 'edge-a@example.com' });
    userB = await createTestUser({ email: 'edge-b@example.com' });
  });

  // ── Helpers ─────────────────────────────────────────────────────────

  async function createItemFor(token: string, overrides: Record<string, unknown> = {}) {
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);
    const res = await agent
      .post('/api/v1/vault/items')
      .set('Authorization', authHeader(token))
      .set('Cookie', csrf.cookie)
      .set('x-csrf-token', csrf.token)
      .send(sampleVaultItem(overrides))
      .expect(201);
    return res.body.data._id as string;
  }

  async function createFolderFor(token: string, overrides: Record<string, unknown> = {}) {
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);
    const res = await agent
      .post('/api/v1/folders')
      .set('Authorization', authHeader(token))
      .set('Cookie', csrf.cookie)
      .set('x-csrf-token', csrf.token)
      .send(sampleFolder(overrides))
      .expect(201);
    return res.body.data._id as string;
  }

  // ── Bulk-delete with other user's item IDs ─────────────────────────

  describe('Bulk-delete with mixed-user item IDs', () => {
    it('should only delete own items when IDs include another user items', async () => {
      const itemA = await createItemFor(userA.accessToken, { encryptedName: 'a-item' });
      const itemB = await createItemFor(userB.accessToken, { encryptedName: 'b-item' });
      const itemB2 = await createItemFor(userB.accessToken, { encryptedName: 'b-item-2' });

      // User B tries to bulk-delete their own item + User A's item
      const agent = request.agent(app);
      const csrf = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/vault/items/bulk-delete')
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ ids: [itemA, itemB] });

      expect(res.status).toBe(200);
      // Only User B's item should be soft-deleted (modifiedCount = 1, not 2)
      expect(res.body.data.modifiedCount).toBe(1);

      // Verify User A's item is untouched
      const aItem = await VaultItem.findById(itemA).lean();
      expect(aItem).not.toBeNull();
      expect(aItem?.deletedAt).toBeUndefined();

      // Verify User B's item is soft-deleted
      const bItem = await VaultItem.findById(itemB).lean();
      expect(bItem?.deletedAt).toBeDefined();

      // Verify User B's other item is untouched
      const bItem2 = await VaultItem.findById(itemB2).lean();
      expect(bItem2?.deletedAt).toBeUndefined();
    });
  });

  // ── Bulk-move with folder belonging to another user ────────────────

  describe('Bulk-move to another user folder', () => {
    it('should reject bulk-move when target folder belongs to another user', async () => {
      const itemB = await createItemFor(userB.accessToken);
      const folderA = await createFolderFor(userA.accessToken);

      // User B tries to bulk-move their item into User A's folder
      const agent = request.agent(app);
      const csrf = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/vault/items/bulk-move')
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ ids: [itemB], folderId: folderA });

      // Server should reject — folder doesn't belong to User B
      expect(res.status).toBe(404);

      // Verify item was NOT moved
      const item = await VaultItem.findById(itemB).lean();
      expect(item?.folderId).toBeUndefined();
    });
  });

  // ── Folder creation with another user's parentId ───────────────────

  describe('Folder creation with cross-user parentId', () => {
    it('should reject folder creation with parentId belonging to another user', async () => {
      const folderA = await createFolderFor(userA.accessToken, { encryptedName: 'parent-a' });

      // User B tries to create a folder under User A's folder
      const agent = request.agent(app);
      const csrf = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/folders')
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send(sampleFolder({ parentId: folderA }));

      // Server should reject — parent folder doesn't belong to User B
      expect(res.status).toBe(404);

      // Verify no new folder was created for User B
      const userBFolders = await Folder.find({ userId: userB.id }).lean();
      expect(userBFolders).toHaveLength(0);
    });
  });

  // ── Folder update changing parentId to another user's folder ───────

  describe('Folder update with cross-user parentId', () => {
    it('should reject folder update changing parentId to another user folder', async () => {
      const folderA = await createFolderFor(userA.accessToken, { encryptedName: 'parent-a' });
      const folderB = await createFolderFor(userB.accessToken, { encryptedName: 'child-b' });

      // User B tries to move their folder under User A's folder
      const agent = request.agent(app);
      const csrf = await getCsrf(agent);
      const res = await agent
        .put(`/api/v1/folders/${folderB}`)
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({
          parentId: folderA,
          encryptedName: 'child-b',
          nameIv: 'test-iv',
          nameTag: 'test-tag',
        });

      // Server should reject
      expect(res.status).toBe(404);

      // Verify folder's parentId was NOT changed
      const folder = await Folder.findById(folderB).lean();
      expect(folder?.parentId).toBeUndefined();
    });
  });

  // ── Query parameter userId injection ───────────────────────────────

  describe('UserId query parameter injection', () => {
    it('should ignore userId query parameter and use auth token userId', async () => {
      await createItemFor(userA.accessToken, { encryptedName: 'a-secret' });
      await createItemFor(userB.accessToken, { encryptedName: 'b-secret' });

      // User B tries to list items with User A's userId as query param
      const res = await request(app)
        .get(`/api/v1/vault/items?userId=${userA.id}`)
        .set('Authorization', authHeader(userB.accessToken));

      expect(res.status).toBe(200);
      // Should only return User B's items, not User A's
      expect(res.body.data).toHaveLength(1);
      expect(res.body.data[0].encryptedName).toBe('b-secret');
      // userId is intentionally absent from API responses; the
      // `encryptedName` discriminator above is sufficient to confirm
      // ownership without exposing the field to clients.
      expect(res.body.data[0].userId).toBeUndefined();
      const persisted = await VaultItem.findById(res.body.data[0]._id as string);
      expect(persisted?.userId.toString()).toBe(userB.id);
    });

    it('should ignore userId query parameter for folders', async () => {
      await createFolderFor(userA.accessToken, { encryptedName: 'a-folder' });
      await createFolderFor(userB.accessToken, { encryptedName: 'b-folder' });

      // User B tries to list folders with User A's userId
      const res = await request(app)
        .get(`/api/v1/folders?userId=${userA.id}`)
        .set('Authorization', authHeader(userB.accessToken));

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(1);
      expect(res.body.data[0].encryptedName).toBe('b-folder');
    });

    it('should ignore userId query parameter for audit logs', async () => {
      // Generate some audit log entries for both users
      await createItemFor(userA.accessToken);
      await createItemFor(userB.accessToken);

      // User B tries to access audit logs with User A's userId
      const res = await request(app)
        .get(`/api/v1/user/audit-log?userId=${userA.id}&page=1&limit=100`)
        .set('Authorization', authHeader(userB.accessToken));

      expect(res.status).toBe(200);
      // userId is intentionally absent from API responses; ownership is
      // verified at the persistence layer below.
      for (const log of res.body.data) {
        expect(log.userId).toBeUndefined();
      }
      const persistedB = await AuditLog.find({ userId: userB.id }).lean();
      expect(persistedB.length).toBeGreaterThan(0);
      // None of the returned audit-log _ids should belong to user A.
      const userAIds = new Set(
        (await AuditLog.find({ userId: userA.id }).select('_id').lean()).map((d) => String(d._id)),
      );
      for (const log of res.body.data) {
        expect(userAIds.has(String(log._id))).toBe(false);
      }
    });
  });

  // ── Searching with another user's searchHash ───────────────────────

  describe('SearchHash cross-user isolation', () => {
    it('should not return results when searching with another user searchHash', async () => {
      const sharedHash = 'b'.repeat(64);

      // User A creates an item with a specific searchHash
      await createItemFor(userA.accessToken, {
        encryptedName: 'a-secret-item',
        searchHash: sharedHash,
      });

      // User B lists items — should not see User A's item even with matching hash in DB
      const res = await request(app)
        .get('/api/v1/vault/items')
        .set('Authorization', authHeader(userB.accessToken));

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(0);
    });

    it('same searchHash should be independent per user', async () => {
      const sharedHash = 'c'.repeat(64);

      // Both users create items with the same searchHash
      await createItemFor(userA.accessToken, {
        encryptedName: 'a-item',
        searchHash: sharedHash,
      });
      await createItemFor(userB.accessToken, {
        encryptedName: 'b-item',
        searchHash: sharedHash,
      });

      // User A should only see their item
      const resA = await request(app)
        .get('/api/v1/vault/items')
        .set('Authorization', authHeader(userA.accessToken));
      expect(resA.body.data).toHaveLength(1);
      expect(resA.body.data[0].encryptedName).toBe('a-item');

      // User B should only see their item
      const resB = await request(app)
        .get('/api/v1/vault/items')
        .set('Authorization', authHeader(userB.accessToken));
      expect(resB.body.data).toHaveLength(1);
      expect(resB.body.data[0].encryptedName).toBe('b-item');
    });
  });

  // ── Item creation with another user's folderId ─────────────────────

  describe('Item creation with cross-user folderId', () => {
    it('should reject item creation with folderId belonging to another user', async () => {
      const folderA = await createFolderFor(userA.accessToken);

      // User B tries to create an item in User A's folder
      const agent = request.agent(app);
      const csrf = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/vault/items')
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send(sampleVaultItem({ folderId: folderA }));

      // Should fail — folder doesn't belong to User B
      expect(res.status).toBe(404);

      // Verify no item was created for User B
      const userBItems = await VaultItem.find({ userId: userB.id }).lean();
      expect(userBItems).toHaveLength(0);
    });
  });

  // ── Vault key rotation with items from another user ────────────────

  describe('Vault key rotation cross-user isolation', () => {
    it('should not allow rotating items belonging to another user', async () => {
      const itemA = await createItemFor(userA.accessToken);

      // User B tries to re-encrypt User A's item
      const agent = request.agent(app);
      const csrf = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/vault/items/bulk-reencrypt')
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({
          authHash: userB.rawPassword,
          items: [
            {
              id: itemA,
              encryptedName: 'hacked-name',
              nameIv: 'hacked-iv',
              nameTag: 'hacked-tag',
              encryptedData: 'hacked-data',
              dataIv: 'hacked-data-iv',
              dataTag: 'hacked-data-tag',
            },
          ],
          folders: [],
          newEncryptedVaultKey: 'hacked-vault-key',
          newVaultKeyIv: 'hacked-vk-iv',
          newVaultKeyTag: 'hacked-vk-tag',
        });

      // The rotation should either fail or not modify User A's item
      if (res.status === 200) {
        // If it succeeded, User A's item should NOT have been modified
        const item = await VaultItem.findById(itemA).lean();
        expect(item?.encryptedName).not.toBe('hacked-name');
        expect(item?.userId.toString()).toBe(userA.id);
      } else {
        // Expected: 404 (item not found for User B) or 400/409
        expect(res.status).toBeLessThan(500);
      }
    });
  });

  // ── Folder sort order cross-user isolation ─────────────────────────

  describe('Folder sort order cross-user isolation', () => {
    it('should not allow updating sort order of another user folder', async () => {
      const folderA = await createFolderFor(userA.accessToken, { sortOrder: 0 });

      // User B tries to update User A's folder sort order
      const agent = request.agent(app);
      const csrf = await getCsrf(agent);
      const res = await agent
        .put(`/api/v1/folders/${folderA}/sort`)
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ sortOrder: 999 });

      expect(res.status).toBe(404);

      // Verify sort order was NOT changed
      const folder = await Folder.findById(folderA).lean();
      expect(folder?.sortOrder).toBe(0);
    });
  });
});
