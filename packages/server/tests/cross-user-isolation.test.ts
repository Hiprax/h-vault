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
// Test Suite: Cross-User Data Isolation
// ---------------------------------------------------------------------------

describe('Cross-User Data Isolation', () => {
  let userA: TestUser;
  let userB: TestUser;

  beforeEach(async () => {
    userA = await createTestUser({ email: 'user-a@example.com' });
    userB = await createTestUser({ email: 'user-b@example.com' });
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

  // ── Vault Item Isolation ────────────────────────────────────────────

  describe('Vault Item Isolation', () => {
    it('should not return items belonging to another user in list', async () => {
      // User A creates an item
      await createItemFor(userA.accessToken, { encryptedName: 'user-a-item' });

      // User B creates an item
      await createItemFor(userB.accessToken, { encryptedName: 'user-b-item' });

      // User A lists items — should only see their own
      const resA = await request(app)
        .get('/api/v1/vault/items')
        .set('Authorization', authHeader(userA.accessToken));

      expect(resA.status).toBe(200);
      expect(resA.body.data).toHaveLength(1);
      expect(resA.body.data[0].encryptedName).toBe('user-a-item');
      // userId is intentionally absent from API responses; ownership is
      // implicit in the authenticated session and asserted at the DB layer
      // via the `encryptedName` discriminator above.
      expect(resA.body.data[0].userId).toBeUndefined();
      const persistedA = await VaultItem.findById(resA.body.data[0]._id as string);
      expect(persistedA?.userId.toString()).toBe(userA.id);

      // User B lists items — should only see their own
      const resB = await request(app)
        .get('/api/v1/vault/items')
        .set('Authorization', authHeader(userB.accessToken));

      expect(resB.status).toBe(200);
      expect(resB.body.data).toHaveLength(1);
      expect(resB.body.data[0].encryptedName).toBe('user-b-item');
      expect(resB.body.data[0].userId).toBeUndefined();
      const persistedB = await VaultItem.findById(resB.body.data[0]._id as string);
      expect(persistedB?.userId.toString()).toBe(userB.id);
    });

    it('should return 404 when accessing another user vault item by ID', async () => {
      const itemId = await createItemFor(userA.accessToken);

      // User B tries to access User A's item
      const res = await request(app)
        .get(`/api/v1/vault/items/${itemId}`)
        .set('Authorization', authHeader(userB.accessToken));

      expect(res.status).toBe(404);
    });

    it('should return 404 when trying to update another user vault item', async () => {
      const itemId = await createItemFor(userA.accessToken);

      const agent = request.agent(app);
      const csrf = await getCsrf(agent);

      const res = await agent
        .put(`/api/v1/vault/items/${itemId}`)
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send(sampleVaultItem({ encryptedName: 'hacked' }));

      expect(res.status).toBe(404);

      // Verify the item was NOT modified
      const original = await VaultItem.findById(itemId).lean();
      expect(original?.encryptedName).not.toBe('hacked');
    });

    it('should return 404 when trying to delete another user vault item', async () => {
      const itemId = await createItemFor(userA.accessToken);

      const agent = request.agent(app);
      const csrf = await getCsrf(agent);

      const res = await agent
        .delete(`/api/v1/vault/items/${itemId}`)
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token);

      expect(res.status).toBe(404);

      // Verify the item still exists
      const item = await VaultItem.findById(itemId).lean();
      expect(item).not.toBeNull();
      expect(item?.deletedAt).toBeUndefined();
    });

    it('should return 404 when trying to permanently delete another user vault item', async () => {
      const itemId = await createItemFor(userA.accessToken);

      // First soft-delete as User A
      const agentA = request.agent(app);
      const csrfA = await getCsrf(agentA);
      await agentA
        .delete(`/api/v1/vault/items/${itemId}`)
        .set('Authorization', authHeader(userA.accessToken))
        .set('Cookie', csrfA.cookie)
        .set('x-csrf-token', csrfA.token)
        .expect(200);

      // User B tries to permanently delete User A's trashed item
      const agentB = request.agent(app);
      const csrfB = await getCsrf(agentB);

      const res = await agentB
        .delete(`/api/v1/vault/items/${itemId}/permanent`)
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrfB.cookie)
        .set('x-csrf-token', csrfB.token);

      expect(res.status).toBe(404);

      // Verify the item still exists in trash
      const item = await VaultItem.findById(itemId).lean();
      expect(item).not.toBeNull();
    });

    it('should not return another user trash items', async () => {
      const itemId = await createItemFor(userA.accessToken);

      // Soft-delete as User A
      const agentA = request.agent(app);
      const csrfA = await getCsrf(agentA);
      await agentA
        .delete(`/api/v1/vault/items/${itemId}`)
        .set('Authorization', authHeader(userA.accessToken))
        .set('Cookie', csrfA.cookie)
        .set('x-csrf-token', csrfA.token)
        .expect(200);

      // User B lists trash — should be empty
      const res = await request(app)
        .get('/api/v1/vault/items/trash')
        .set('Authorization', authHeader(userB.accessToken));

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(0);
    });

    it('should return 404 when trying to restore another user trashed item', async () => {
      const itemId = await createItemFor(userA.accessToken);

      // Soft-delete as User A
      const agentA = request.agent(app);
      const csrfA = await getCsrf(agentA);
      await agentA
        .delete(`/api/v1/vault/items/${itemId}`)
        .set('Authorization', authHeader(userA.accessToken))
        .set('Cookie', csrfA.cookie)
        .set('x-csrf-token', csrfA.token)
        .expect(200);

      // User B tries to restore User A's trashed item
      const agentB = request.agent(app);
      const csrfB = await getCsrf(agentB);

      const res = await agentB
        .post(`/api/v1/vault/items/restore/${itemId}`)
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrfB.cookie)
        .set('x-csrf-token', csrfB.token);

      expect(res.status).toBe(404);
    });
  });

  // ── Folder Isolation ────────────────────────────────────────────────

  describe('Folder Isolation', () => {
    it('should not return folders belonging to another user', async () => {
      await createFolderFor(userA.accessToken, { encryptedName: 'folder-a' });
      await createFolderFor(userB.accessToken, { encryptedName: 'folder-b' });

      const resA = await request(app)
        .get('/api/v1/folders')
        .set('Authorization', authHeader(userA.accessToken));

      expect(resA.status).toBe(200);
      expect(resA.body.data).toHaveLength(1);
      expect(resA.body.data[0].encryptedName).toBe('folder-a');

      const resB = await request(app)
        .get('/api/v1/folders')
        .set('Authorization', authHeader(userB.accessToken));

      expect(resB.status).toBe(200);
      expect(resB.body.data).toHaveLength(1);
      expect(resB.body.data[0].encryptedName).toBe('folder-b');
    });

    it('should return 404 when updating another user folder', async () => {
      const folderId = await createFolderFor(userA.accessToken);

      const agent = request.agent(app);
      const csrf = await getCsrf(agent);

      const res = await agent
        .put(`/api/v1/folders/${folderId}`)
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send(sampleFolder({ encryptedName: 'hacked-folder' }));

      expect(res.status).toBe(404);

      // Verify folder was NOT modified
      const folder = await Folder.findById(folderId).lean();
      expect(folder?.encryptedName).not.toBe('hacked-folder');
    });

    it('should return 404 when deleting another user folder', async () => {
      const folderId = await createFolderFor(userA.accessToken);

      const agent = request.agent(app);
      const csrf = await getCsrf(agent);

      const res = await agent
        .delete(`/api/v1/folders/${folderId}?action=delete`)
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token);

      expect(res.status).toBe(404);

      // Verify folder still exists
      const folder = await Folder.findById(folderId).lean();
      expect(folder).not.toBeNull();
    });

    it('should not allow moving items to another user folder', async () => {
      const folderA = await createFolderFor(userA.accessToken);
      const itemB = await createItemFor(userB.accessToken);

      // User B tries to move their item into User A's folder
      const agent = request.agent(app);
      const csrf = await getCsrf(agent);

      const res = await agent
        .put(`/api/v1/vault/items/${itemB}`)
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send(sampleVaultItem({ folderId: folderA }));

      // Should fail — the folder doesn't belong to User B
      // The server should either reject with 400/404 or silently ignore the folderId
      if (res.status === 200) {
        // If the update succeeded, the folderId should NOT be set to User A's folder
        const item = await VaultItem.findById(itemB).lean();
        expect(item?.folderId?.toString()).not.toBe(folderA);
      } else {
        expect([400, 404]).toContain(res.status);
      }
    });
  });

  // ── Audit Log Isolation ─────────────────────────────────────────────

  describe('Audit Log Isolation', () => {
    it('should not show another user audit logs', async () => {
      // User A creates an item (generates an audit log)
      await createItemFor(userA.accessToken, { encryptedName: 'auditable-item' });

      // User B creates an item too
      await createItemFor(userB.accessToken, { encryptedName: 'user-b-auditable' });

      // Persisted ownership sets. `userId` is intentionally stripped from the
      // API response, so we match returned rows to their owner by `_id`.
      const allLogs = await AuditLog.find({}).select('_id userId').lean();
      const userALogs = allLogs.filter((l) => l.userId?.toString() === userA.id);
      const userBLogs = allLogs.filter((l) => l.userId?.toString() === userB.id);
      expect(userALogs.length).toBeGreaterThan(0);
      expect(userBLogs.length).toBeGreaterThan(0);
      const userALogIds = new Set(userALogs.map((l) => String(l._id)));
      const userBLogIds = new Set(userBLogs.map((l) => String(l._id)));

      // User A requests audit logs — must see ONLY their own.
      const resA = await request(app)
        .get('/api/v1/user/audit-log?page=1&limit=100')
        .set('Authorization', authHeader(userA.accessToken));

      expect(resA.status).toBe(200);
      for (const log of resA.body.data) {
        expect(log.userId).toBeUndefined();
      }
      // Cross-user isolation: every returned row belongs to A by _id, and NONE
      // belongs to B. Dropping the `userId` filter from getAuditLog (returning
      // every user's rows) turns these red even though the response has no
      // `userId` field.
      const returnedAIds = resA.body.data.map((l: { _id: string }) => l._id);
      for (const id of returnedAIds) {
        expect(userALogIds.has(String(id))).toBe(true);
        expect(userBLogIds.has(String(id))).toBe(false);
      }
      // The paginated total must equal A's own persisted count, not the union.
      expect(resA.body.pagination.total).toBe(userALogs.length);

      // User B requests audit logs — must see ONLY their own.
      const resB = await request(app)
        .get('/api/v1/user/audit-log?page=1&limit=100')
        .set('Authorization', authHeader(userB.accessToken));

      expect(resB.status).toBe(200);
      for (const log of resB.body.data) {
        expect(log.userId).toBeUndefined();
      }
      const returnedBIds = resB.body.data.map((l: { _id: string }) => l._id);
      for (const id of returnedBIds) {
        expect(userBLogIds.has(String(id))).toBe(true);
        expect(userALogIds.has(String(id))).toBe(false);
      }
      expect(resB.body.pagination.total).toBe(userBLogs.length);
    });
  });

  // ── Bulk Operation Isolation ────────────────────────────────────────

  describe('Bulk Operation Isolation', () => {
    it('should not bulk-delete items belonging to another user', async () => {
      const itemA = await createItemFor(userA.accessToken);

      const agent = request.agent(app);
      const csrf = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/vault/items/bulk-delete')
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ ids: [itemA] });

      // The operation should complete but affect 0 items
      expect(res.status).toBe(200);
      expect(res.body.data.modifiedCount).toBe(0);

      // Verify item still exists and is not soft-deleted
      const item = await VaultItem.findById(itemA).lean();
      expect(item).not.toBeNull();
      expect(item?.deletedAt).toBeUndefined();
    });

    it('should not bulk-move items belonging to another user', async () => {
      const itemA = await createItemFor(userA.accessToken);
      const folderB = await createFolderFor(userB.accessToken);

      const agent = request.agent(app);
      const csrf = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/vault/items/bulk-move')
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ ids: [itemA], folderId: folderB });

      // The operation should complete but affect 0 items
      expect(res.status).toBe(200);
      expect(res.body.data.modifiedCount).toBe(0);

      // Verify item is still in its original folder (none)
      const item = await VaultItem.findById(itemA).lean();
      expect(item?.folderId).toBeUndefined();
    });
  });

  // ── Session Isolation ───────────────────────────────────────────────

  describe('Session Isolation', () => {
    it('should not list sessions of another user', async () => {
      // Each user should only see their own session (1 refresh token each from createTestUser)
      const resA = await request(app)
        .get('/api/v1/user/sessions')
        .set('Authorization', authHeader(userA.accessToken));

      expect(resA.status).toBe(200);
      const sessionsA = resA.body.data as { _id: string }[];
      expect(sessionsA.length).toBe(1);

      const resB = await request(app)
        .get('/api/v1/user/sessions')
        .set('Authorization', authHeader(userB.accessToken));

      expect(resB.status).toBe(200);
      const sessionsB = resB.body.data as { _id: string }[];
      expect(sessionsB.length).toBe(1);

      // Session IDs should be different (proving they are isolated)
      expect(sessionsA[0]!._id).not.toBe(sessionsB[0]!._id);
    });

    it('should not allow revoking another user session', async () => {
      // Get User A's session ID
      const resA = await request(app)
        .get('/api/v1/user/sessions')
        .set('Authorization', authHeader(userA.accessToken));

      const sessionIdA = (resA.body.data as { _id: string }[])[0]!._id;

      // User B tries to revoke User A's session
      const agent = request.agent(app);
      const csrf = await getCsrf(agent);

      const res = await agent
        .delete(`/api/v1/user/sessions/${sessionIdA}`)
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token);

      expect(res.status).toBe(404);

      // Verify User A's session still exists
      const verifyA = await request(app)
        .get('/api/v1/user/sessions')
        .set('Authorization', authHeader(userA.accessToken));

      expect(verifyA.body.data).toHaveLength(1);
    });
  });

  // ── M10: Import userId isolation ───────────────────────────────────

  describe('Import userId isolation', () => {
    /** Posts an import for `token`, on its own agent so the CSRF pair matches. */
    async function postImport(
      token: string,
      operations: Record<string, unknown>,
    ): Promise<request.Response> {
      const agent = request.agent(app);
      const csrf = await getCsrf(agent);
      return agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(token))
        .set('x-csrf-token', csrf.token)
        .set('Cookie', csrf.cookie)
        .send({ format: 'json', operations });
    }

    it('an import insert never touches another user row that shares its searchHash', async () => {
      const searchHash = 'a'.repeat(64);

      const resA = await postImport(userA.accessToken, {
        inserts: [sampleVaultItem({ encryptedName: 'userA-item', searchHash })],
      });
      expect(resA.status).toBe(201);

      const resB = await postImport(userB.accessToken, {
        inserts: [sampleVaultItem({ encryptedName: 'userB-item', searchHash })],
      });
      expect(resB.status).toBe(201);

      // Each user owns exactly one row, with their own ciphertext.
      const userAItems = await VaultItem.find({ userId: userA.id }).lean();
      const userBItems = await VaultItem.find({ userId: userB.id }).lean();
      expect(userAItems).toHaveLength(1);
      expect(userBItems).toHaveLength(1);
      expect(userAItems[0]!.encryptedName).toBe('userA-item');
      expect(userBItems[0]!.encryptedName).toBe('userB-item');
    });

    it("rejects an import update that names another user's item and leaves it untouched", async () => {
      const resA = await postImport(userA.accessToken, {
        inserts: [sampleVaultItem({ encryptedName: 'userA-item', searchHash: 'a'.repeat(64) })],
      });
      expect(resA.status).toBe(201);

      const targetId = String((await VaultItem.findOne({ userId: userA.id }).lean())!._id);

      const res = await postImport(userB.accessToken, {
        updates: [
          {
            id: targetId,
            encryptedName: 'userB-overwrite',
            nameIv: 'b-name-iv',
            nameTag: 'b-name-tag',
            encryptedData: 'b-data',
            dataIv: 'b-data-iv',
            dataTag: 'b-data-tag',
            searchHash: 'b'.repeat(64),
          },
        ],
      });

      // A foreign target is a 400 for the whole request, never a silent skip.
      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);

      const target = await VaultItem.findById(targetId).lean();
      expect(target).not.toBeNull();
      expect(target!.encryptedName).toBe('userA-item');
      expect(String(target!.userId)).toBe(userA.id);
      expect(await VaultItem.countDocuments({ userId: userB.id })).toBe(0);
    });
  });
});
