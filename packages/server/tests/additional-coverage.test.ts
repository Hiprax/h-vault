import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import app from '../src/app.js';
import { Folder } from '../src/models/Folder.js';
import { startTrashCleanupJob } from '../src/jobs/trashCleanup.js';
import { startTokenCleanupJob } from '../src/jobs/tokenCleanup.js';
import { startBackupScheduler } from '../src/jobs/backupScheduler.js';
import {
  createTestUser,
  authHeader,
  sampleVaultItem,
  sampleFolder,
  seedItem,
  seedFolder,
  getCsrf as getCsrfBase,
} from './helpers.js';
import type { TestUser } from './helpers.js';

// Re-export with { csrfToken, csrfCookie } naming used throughout this file
async function getCsrf(agent: request.Agent): Promise<{ csrfToken: string; csrfCookie: string }> {
  const { token, cookie } = await getCsrfBase(agent);
  return { csrfToken: token, csrfCookie: cookie };
}

// ---------------------------------------------------------------------------
// Helper to create an item via the API
// ---------------------------------------------------------------------------

async function createItemViaApi(
  token: string,
  overrides: Record<string, unknown> = {},
): Promise<{ id: string; body: Record<string, unknown> }> {
  const agent = request.agent(app);
  const { csrfToken, csrfCookie } = await getCsrf(agent);

  const res = await agent
    .post('/api/v1/vault/items')
    .set('Authorization', authHeader(token))
    .set('Cookie', csrfCookie)
    .set('x-csrf-token', csrfToken)
    .send(sampleVaultItem(overrides))
    .expect(201);

  return { id: res.body.data._id as string, body: res.body as Record<string, unknown> };
}

// ---------------------------------------------------------------------------
// Helper to create a folder via the API
// ---------------------------------------------------------------------------

async function createFolderViaApi(
  token: string,
  overrides: Record<string, unknown> = {},
): Promise<{ id: string; body: Record<string, unknown> }> {
  const agent = request.agent(app);
  const { csrfToken, csrfCookie } = await getCsrf(agent);

  const res = await agent
    .post('/api/v1/folders')
    .set('Authorization', authHeader(token))
    .set('Cookie', csrfCookie)
    .set('x-csrf-token', csrfToken)
    .send(sampleFolder(overrides))
    .expect(201);

  return { id: res.body.data._id as string, body: res.body as Record<string, unknown> };
}

// ---------------------------------------------------------------------------
// Helper: set up backup for a user
// ---------------------------------------------------------------------------

const bwkSetupData = {
  authHash: 'test-auth-hash-value',
  encryptedBWK: 'test-encrypted-bwk-data',
  bwkIv: 'test-bwk-iv-value',
  bwkTag: 'test-bwk-tag-value',
  bwkSalt: 'test-bwk-salt-value',
};

async function _setupBackupForUser(
  agent: request.Agent | request.SuperTest<request.Test>,
  token: string,
) {
  const csrf = await getCsrf(agent as request.Agent);
  const res = await (agent as request.Agent)
    .post('/api/v1/backup/setup')
    .set('Authorization', authHeader(token))
    .set('x-csrf-token', csrf.csrfToken)
    .set('Cookie', csrf.csrfCookie)
    .send(bwkSetupData);
  return res;
}

// ===========================================================================
// Test suites
// ===========================================================================

describe('Additional Coverage', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  // ========================================================================
  // 1. Vault Item Types
  // ========================================================================

  describe('Vault item types', () => {
    it('should create a card item', async () => {
      const { id, body } = await createItemViaApi(user.accessToken, { itemType: 'card' });

      expect(body).toMatchObject({ success: true });
      expect(id).toBeDefined();
      expect((body as Record<string, Record<string, unknown>>).data.itemType).toBe('card');
      // userId is intentionally absent from API responses (server-only field).
      expect((body as Record<string, Record<string, unknown>>).data.userId).toBeUndefined();
    });

    it('should create an identity item', async () => {
      const { id, body } = await createItemViaApi(user.accessToken, { itemType: 'identity' });

      expect(body).toMatchObject({ success: true });
      expect(id).toBeDefined();
      expect((body as Record<string, Record<string, unknown>>).data.itemType).toBe('identity');
      // userId is intentionally absent from API responses (server-only field).
      expect((body as Record<string, Record<string, unknown>>).data.userId).toBeUndefined();
    });

    it('should create a secret item', async () => {
      const { id, body } = await createItemViaApi(user.accessToken, { itemType: 'secret' });

      expect(body).toMatchObject({ success: true });
      expect(id).toBeDefined();
      expect((body as Record<string, Record<string, unknown>>).data.itemType).toBe('secret');
      // userId is intentionally absent from API responses (server-only field).
      expect((body as Record<string, Record<string, unknown>>).data.userId).toBeUndefined();
    });

    it('should create a note item', async () => {
      const { id, body } = await createItemViaApi(user.accessToken, { itemType: 'note' });

      expect(body).toMatchObject({ success: true });
      expect(id).toBeDefined();
      expect((body as Record<string, Record<string, unknown>>).data.itemType).toBe('note');
      // userId is intentionally absent from API responses (server-only field).
      expect((body as Record<string, Record<string, unknown>>).data.userId).toBeUndefined();
    });

    it('should reject an invalid item type', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/vault/items')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send(sampleVaultItem({ itemType: 'invalid-type' }));

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should persist all item types and retrieve them correctly', async () => {
      await createItemViaApi(user.accessToken, { itemType: 'login' });
      await createItemViaApi(user.accessToken, { itemType: 'card' });
      await createItemViaApi(user.accessToken, { itemType: 'identity' });
      await createItemViaApi(user.accessToken, { itemType: 'secret' });
      await createItemViaApi(user.accessToken, { itemType: 'note' });

      const res = await request(app)
        .get('/api/v1/vault/items')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(res.body.data).toHaveLength(5);

      const types = (res.body.data as { itemType: string }[]).map((item) => item.itemType);
      expect(types).toContain('login');
      expect(types).toContain('card');
      expect(types).toContain('identity');
      expect(types).toContain('secret');
      expect(types).toContain('note');
    });

    it('should filter items by card type', async () => {
      await createItemViaApi(user.accessToken, { itemType: 'login' });
      await createItemViaApi(user.accessToken, { itemType: 'card' });
      await createItemViaApi(user.accessToken, { itemType: 'card' });

      const res = await request(app)
        .get('/api/v1/vault/items?itemType=card')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(res.body.data).toHaveLength(2);
      for (const item of res.body.data) {
        expect(item.itemType).toBe('card');
      }
    });
  });

  // ========================================================================
  // 2. Folder Ownership Validation (IDOR Prevention)
  // ========================================================================

  describe('Folder ownership / IDOR prevention', () => {
    let userB: TestUser;

    beforeEach(async () => {
      userB = await createTestUser({ email: 'idor-userb@example.com' });
    });

    it('should not allow user B to update user A folder', async () => {
      const { id: folderAId } = await createFolderViaApi(user.accessToken, {
        encryptedName: 'user-a-private-folder',
      });

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .put(`/api/v1/folders/${folderAId}`)
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({
          encryptedName: 'hacked-name',
          nameIv: 'hacked-iv',
          nameTag: 'hacked-tag',
        });

      expect(res.status).toBe(404);

      // Verify the original folder is unchanged
      const original = await Folder.findById(folderAId).lean();
      expect(original).toBeDefined();
      expect(original!.encryptedName).toBe('user-a-private-folder');
    });

    it('should not allow user B to delete user A folder', async () => {
      const { id: folderAId } = await createFolderViaApi(user.accessToken, {
        encryptedName: 'user-a-protected-folder',
      });

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .delete(`/api/v1/folders/${folderAId}`)
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken);

      expect(res.status).toBe(404);

      // Verify the folder still exists AND is unchanged. findById resolves to
      // null when the doc is gone, and expect(null).toBeDefined() passes — so the
      // IDOR persistence check must use not.toBeNull and assert the real field.
      const folder = await Folder.findById(folderAId);
      expect(folder).not.toBeNull();
      expect(folder!.encryptedName).toBe('user-a-protected-folder');
    });

    it('should not allow moving item to another user folder', async () => {
      // Create a folder owned by user A
      const { id: folderAId } = await createFolderViaApi(user.accessToken, {
        encryptedName: 'user-a-folder',
      });

      // Create an item owned by user B
      const { id: itemBId } = await createItemViaApi(userB.accessToken);

      // User B tries to bulk-move their item to user A's folder
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/vault/items/bulk-move')
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({ ids: [itemBId], folderId: folderAId });

      // The server should reject because user B does not own the target folder
      expect(res.status).toBe(404);
    });

    it('should not allow user B to reorder user A folder', async () => {
      const { id: folderAId } = await createFolderViaApi(user.accessToken, {
        encryptedName: 'user-a-ordered-folder',
      });

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .put(`/api/v1/folders/${folderAId}/sort`)
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({ sortOrder: 99 });

      expect(res.status).toBe(404);

      // Verify sort order is unchanged
      const folder = await Folder.findById(folderAId).lean();
      expect(folder!.sortOrder).toBe(0);
    });
  });

  // ========================================================================
  // 3. Invalid ObjectId Handling
  // ========================================================================

  describe('Invalid ObjectId handling', () => {
    // The documented contract of the `validateObjectId` middleware is a CLEAN 400
    // with an "Invalid ... format" body — never a leaked Mongoose CastError 500.
    // Asserting strict 400 (not the `[400, 500]` set) makes removing the middleware
    // — which would surface a 500 — actually turn these red.
    it('should return 400 for malformed vault item id on GET', async () => {
      const res = await request(app)
        .get('/api/v1/vault/items/not-a-valid-id')
        .set('Authorization', authHeader(user.accessToken));

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toContain('Invalid');
    });

    it('should return 400 for malformed vault item id on PUT', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .put('/api/v1/vault/items/not-a-valid-id')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({ favorite: true });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toContain('Invalid');
    });

    it('should return 400 for malformed vault item id on DELETE', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .delete('/api/v1/vault/items/not-a-valid-id')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken);

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toContain('Invalid');
    });

    it('should return 400 for malformed folder id on PUT', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .put('/api/v1/folders/not-a-valid-id')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({
          encryptedName: 'test',
          nameIv: 'test-iv',
          nameTag: 'test-tag',
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toContain('Invalid');
    });

    it('should return 400 for malformed folder id on DELETE', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .delete('/api/v1/folders/not-a-valid-id')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken);

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toContain('Invalid');
    });

    it('should return 400 for malformed ids in bulk-delete', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/vault/items/bulk-delete')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({ ids: ['not-a-valid-id'] });

      // Zod validates objectIdSchema (24-char hex) so this should be 400
      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should return 400 for malformed folderId in bulk-move', async () => {
      const validId = new mongoose.Types.ObjectId().toString();

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/vault/items/bulk-move')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({ ids: [validId], folderId: 'not-a-valid-id' });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });
  });

  // ========================================================================
  // 4. Bulk Operations Edge Cases
  // ========================================================================

  describe('Bulk operations edge cases', () => {
    it('should reject bulk-delete with empty array', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/vault/items/bulk-delete')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({ ids: [] });

      // bulkDeleteSchema requires min(1), so empty array should be rejected
      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should reject bulk-move with empty array', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/vault/items/bulk-move')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({ ids: [], folderId: null });

      // bulkMoveSchema requires min(1)
      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should reject bulk-move to non-existent folder', async () => {
      const { id: itemId } = await createItemViaApi(user.accessToken);
      const nonExistentFolderId = new mongoose.Types.ObjectId().toString();

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/vault/items/bulk-move')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({ ids: [itemId], folderId: nonExistentFolderId });

      // Controller checks folder ownership and should return 404
      expect(res.status).toBe(404);
    });

    it('should reject bulk-delete exceeding max items (101 ids)', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      // Generate 101 valid ObjectIds
      const ids = Array.from({ length: 101 }, () => new mongoose.Types.ObjectId().toString());

      const res = await agent
        .post('/api/v1/vault/items/bulk-delete')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({ ids });

      // bulkDeleteSchema has max(100), so 101 should fail
      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should reject bulk-move exceeding max items (101 ids)', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const ids = Array.from({ length: 101 }, () => new mongoose.Types.ObjectId().toString());

      const res = await agent
        .post('/api/v1/vault/items/bulk-move')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({ ids, folderId: null });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should handle bulk-delete with non-existent ids gracefully', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const nonExistentIds = [
        new mongoose.Types.ObjectId().toString(),
        new mongoose.Types.ObjectId().toString(),
      ];

      const res = await agent
        .post('/api/v1/vault/items/bulk-delete')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({ ids: nonExistentIds });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.modifiedCount).toBe(0);
    });
  });

  // ========================================================================
  // 5. Import Validation
  // ========================================================================

  describe('Import validation', () => {
    it('should skip items with missing encryption fields', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const importData = JSON.stringify({
        items: [
          sampleVaultItem({ encryptedName: 'valid-item' }),
          {
            itemType: 'login',
            encryptedData: '',
            dataIv: '',
            dataTag: '',
            encryptedName: '',
            nameIv: '',
            nameTag: '',
          },
        ],
      });

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'json', data: importData });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.importedCount).toBe(1);
      expect(res.body.data.skippedCount).toBe(1);
    });

    it('should handle empty items array', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const importData = JSON.stringify({
        items: [],
      });

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'json', data: importData });

      // Empty items array - could be 400 (no items to import) or 201 with 0 imported
      expect([200, 201, 400]).toContain(res.status);
    });

    it('should reject invalid format', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'invalid-format', data: '{}' });

      // importSchema uses z.enum for format, so invalid format should be 400
      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should reject import with missing data field', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'json' });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should reject import with empty data string', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'json', data: '' });

      // importSchema requires data.min(1)
      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });
  });

  // ========================================================================
  // 6. Backup Restore Edge Cases
  // ========================================================================

  describe('Backup restore edge cases', () => {
    it('should handle items with invalid _id in restore', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const backupData = JSON.stringify({
        items: [
          {
            _id: 'not-valid-objectid',
            ...sampleVaultItem({ encryptedName: 'invalid-id-item' }),
          },
          {
            _id: '!!!bad-id!!!',
            ...sampleVaultItem({ encryptedName: 'invalid-id-item-2' }),
          },
        ],
        folders: [
          {
            _id: 'bad-folder-id',
            ...sampleFolder({ encryptedName: 'invalid-id-folder' }),
          },
        ],
      });

      const res = await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ conflictStrategy: 'skip', data: backupData });

      // The restore controller should generate new ObjectIds for invalid ones
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.itemsRestored).toBe(2);
      expect(res.body.data.foldersRestored).toBe(1);
    });

    it('should handle restore with empty items', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const backupData = JSON.stringify({
        items: [],
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
      expect(res.body.data.itemsRestored).toBe(0);
      expect(res.body.data.foldersRestored).toBe(0);
    });

    it('should handle restore with items missing _id field', async () => {
      const agent = request.agent(app);
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

    it('should skip duplicate items with skip conflict strategy', async () => {
      const agent = request.agent(app);

      // Seed an existing (owned) item + folder — the live vault the restore
      // will conflict with. Restore keys the conflict off the user's own _id, so
      // the backup rows reuse these ids to hit the skip path.
      const item = await seedItem(user.id, { encryptedName: 'original' });
      const folder = await seedFolder(user.id, { encryptedName: 'original-folder' });
      const itemId = String(item._id);
      const folderId = String(folder._id);

      // Restore with the same IDs and a divergent name - should skip.
      const csrf2 = await getCsrf(agent);
      const secondData = JSON.stringify({
        items: [{ _id: itemId, ...sampleVaultItem({ encryptedName: 'duplicate' }) }],
        folders: [{ _id: folderId, ...sampleFolder({ encryptedName: 'duplicate-folder' }) }],
      });

      const res = await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf2.csrfToken)
        .set('Cookie', csrf2.csrfCookie)
        .send({ conflictStrategy: 'skip', data: secondData });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.itemsSkipped).toBe(1);
      expect(res.body.data.foldersSkipped).toBe(1);
    });

    it('should reject restore with malformed JSON data', async () => {
      const agent = request.agent(app);
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

    it('should reject restore with invalid conflict strategy', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const backupData = JSON.stringify({
        items: [],
        folders: [],
      });

      const res = await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ conflictStrategy: 'invalid-strategy', data: backupData });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });
  });

  // ========================================================================
  // Cron job return types (Task 4.12)
  // ========================================================================

  describe('Cron job start functions return ScheduledTask', () => {
    it('startTrashCleanupJob should return a task with a stop method', () => {
      const task = startTrashCleanupJob();
      expect(task).toBeDefined();
      expect(typeof task.stop).toBe('function');
      void task.stop();
    });

    it('startTokenCleanupJob should return a task with a stop method', () => {
      const task = startTokenCleanupJob();
      expect(task).toBeDefined();
      expect(typeof task.stop).toBe('function');
      void task.stop();
    });

    it('startBackupScheduler should return a task with a stop method', () => {
      const task = startBackupScheduler();
      expect(task).toBeDefined();
      expect(typeof task.stop).toBe('function');
      void task.stop();
    });
  });

  // ========================================================================
  // CSRF token endpoint rate limiting (Task 4.13)
  // ========================================================================

  describe('CSRF token endpoint', () => {
    it('should return a CSRF token without explicit rate limiter', async () => {
      const res = await request(app).get('/api/v1/csrf-token').expect(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.csrfToken).toBeDefined();
    });
  });
});
