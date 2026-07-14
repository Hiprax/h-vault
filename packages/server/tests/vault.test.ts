import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import app from '../src/app.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { AuditLog } from '../src/models/AuditLog.js';
import {
  createTestUser,
  authHeader,
  sampleVaultItem,
  seedItem,
  getCsrf as getCsrfBase,
} from './helpers.js';
import type { TestUser } from './helpers.js';

// Re-export with { csrfToken, csrfCookie } naming used throughout this file
async function getCsrf(agent: request.Agent): Promise<{ csrfToken: string; csrfCookie: string }> {
  const { token, cookie } = await getCsrfBase(agent);
  return { csrfToken: token, csrfCookie: cookie };
}

// ---------------------------------------------------------------------------
// Helper to create an item via the API (reused across many test groups)
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

// Soft-delete (move to trash) an item via the API.
async function softDeleteItemViaApi(token: string, id: string): Promise<void> {
  const agent = request.agent(app);
  const { csrfToken, csrfCookie } = await getCsrf(agent);

  await agent
    .delete(`/api/v1/vault/items/${id}`)
    .set('Authorization', authHeader(token))
    .set('Cookie', csrfCookie)
    .set('x-csrf-token', csrfToken)
    .expect(200);
}

// ---------------------------------------------------------------------------
// Test suites
// ---------------------------------------------------------------------------

describe('Vault API', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  // ========================================================================
  // 1. CRUD
  // ========================================================================

  describe('CRUD operations', () => {
    // ── Create ────────────────────────────────────────────────────────

    it('should create a vault item', async () => {
      const { id, body } = await createItemViaApi(user.accessToken);

      expect(body).toMatchObject({ success: true });
      expect(id).toBeDefined();
      expect((body as Record<string, Record<string, unknown>>).data.itemType).toBe('login');
      // userId is intentionally absent from API responses (server-only field).
      expect((body as Record<string, Record<string, unknown>>).data.userId).toBeUndefined();
      // Confirm ownership at the persistence layer instead.
      const persisted = await VaultItem.findById(id);
      expect(persisted?.userId.toString()).toBe(user.id);
    });

    it('should reject creation with missing required fields', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .post('/api/v1/vault/items')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({ itemType: 'login' }) // missing encrypted fields
        .expect(400);
    });

    it('should reject creation when per-user item limit is reached', async () => {
      const { MAX_ITEMS_PER_USER } = await import('@hvault/shared');

      // Stub countDocuments to simulate the limit being reached
      const spy = vi
        .spyOn(VaultItem, 'countDocuments')
        .mockResolvedValueOnce(MAX_ITEMS_PER_USER as never);

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/vault/items')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send(sampleVaultItem())
        .expect(400);

      expect(res.body.success).toBe(false);
      expect(JSON.stringify(res.body)).toContain('Item limit reached');
      // The cap must count only THIS user's items — assert the real query is
      // scoped to the authenticated userId. Without this, the stub would hide a
      // regression that counts every user's items (`countDocuments({})`) or an
      // unscoped/wrong filter, and the test would still pass on the stubbed value.
      expect(spy).toHaveBeenCalledWith({ userId: user.id });
      spy.mockRestore();
    });

    it('counts only the authenticated user’s items toward the cap (real state, scoping)', async () => {
      const { MAX_ITEMS_PER_USER } = await import('@hvault/shared');

      // Seed real items for a DIFFERENT user; they must not count toward this
      // user's cap. This exercises the real countDocuments query against real
      // persisted state (no stub) and proves cross-user isolation of the cap.
      const otherUser = await createTestUser();
      await seedItem(otherUser.id);
      await seedItem(otherUser.id);
      await seedItem(user.id);

      const spy = vi.spyOn(VaultItem, 'countDocuments');

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .post('/api/v1/vault/items')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send(sampleVaultItem())
        .expect(201);

      // The real count query ran and saw only this user's single pre-seeded
      // item (1), far below the cap — the other user's 2 items were excluded.
      expect(spy).toHaveBeenCalledWith({ userId: user.id });
      const realCount = await VaultItem.countDocuments({ userId: user.id });
      expect(realCount).toBe(2); // the seeded one + the just-created one
      expect(realCount).toBeLessThan(MAX_ITEMS_PER_USER);
      const otherCount = await VaultItem.countDocuments({ userId: otherUser.id });
      expect(otherCount).toBe(2);
      spy.mockRestore();
    });

    // ── Get single item ───────────────────────────────────────────────

    it('should get a single vault item by id', async () => {
      const { id } = await createItemViaApi(user.accessToken);

      const res = await request(app)
        .get(`/api/v1/vault/items/${id}`)
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.data._id).toBe(id);
      expect(res.body.data.itemType).toBe('login');
    });

    // ── List items with pagination ────────────────────────────────────

    it('should list items with pagination', async () => {
      // Create 3 items
      await createItemViaApi(user.accessToken, { encryptedName: 'item-1' });
      await createItemViaApi(user.accessToken, { encryptedName: 'item-2' });
      await createItemViaApi(user.accessToken, { encryptedName: 'item-3' });

      const res = await request(app)
        .get('/api/v1/vault/items?page=1&limit=2')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveLength(2);
      expect(res.body.pagination.total).toBe(3);
      expect(res.body.pagination.totalPages).toBe(2);
      expect(res.body.pagination.page).toBe(1);
      expect(res.body.pagination.limit).toBe(2);

      // Page 2
      const res2 = await request(app)
        .get('/api/v1/vault/items?page=2&limit=2')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(res2.body.data).toHaveLength(1);
    });

    it('should filter items by itemType', async () => {
      await createItemViaApi(user.accessToken, { itemType: 'login' });
      await createItemViaApi(user.accessToken, { itemType: 'note' });

      const res = await request(app)
        .get('/api/v1/vault/items?itemType=note')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(res.body.data).toHaveLength(1);
      expect(res.body.data[0].itemType).toBe('note');
    });

    it('should filter items by favorite', async () => {
      await createItemViaApi(user.accessToken, { favorite: true });
      await createItemViaApi(user.accessToken, { favorite: false });

      const res = await request(app)
        .get('/api/v1/vault/items?favorite=true')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(res.body.data).toHaveLength(1);
      expect(res.body.data[0].favorite).toBe(true);
    });

    // ── Boolean query filters: trash / favorite ───────────────────────
    // Regression guard for the z.coerce.boolean() → z.stringbool() fix. The old
    // coercion treated any non-empty string as true, so ?trash=false returned
    // TRASHED items and ?favorite=false returned favorites (the inverse of what
    // the caller asked for). Every query stays userId-scoped by the controller.

    it('should return active items (not trashed) for ?trash=false', async () => {
      const { id: activeId } = await createItemViaApi(user.accessToken, {
        encryptedName: 'active-item',
      });
      const { id: trashedId } = await createItemViaApi(user.accessToken, {
        encryptedName: 'trashed-item',
      });
      await softDeleteItemViaApi(user.accessToken, trashedId);

      const res = await request(app)
        .get('/api/v1/vault/items?trash=false')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(res.body.data).toHaveLength(1);
      expect(res.body.data[0]._id).toBe(activeId);
    });

    it('should return trashed items for ?trash=true', async () => {
      await createItemViaApi(user.accessToken, { encryptedName: 'active-item' });
      const { id: trashedId } = await createItemViaApi(user.accessToken, {
        encryptedName: 'trashed-item',
      });
      await softDeleteItemViaApi(user.accessToken, trashedId);

      const res = await request(app)
        .get('/api/v1/vault/items?trash=true')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(res.body.data).toHaveLength(1);
      expect(res.body.data[0]._id).toBe(trashedId);
    });

    it('should return non-favorite items for ?favorite=false', async () => {
      const { id: plainId } = await createItemViaApi(user.accessToken, {
        favorite: false,
        encryptedName: 'plain-item',
      });
      await createItemViaApi(user.accessToken, { favorite: true, encryptedName: 'fav-item' });

      const res = await request(app)
        .get('/api/v1/vault/items?favorite=false')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(res.body.data).toHaveLength(1);
      expect(res.body.data[0]._id).toBe(plainId);
      expect(res.body.data[0].favorite).toBe(false);
    });

    it('should return favorite items for ?favorite=true', async () => {
      await createItemViaApi(user.accessToken, { favorite: false, encryptedName: 'plain-item' });
      const { id: favId } = await createItemViaApi(user.accessToken, {
        favorite: true,
        encryptedName: 'fav-item',
      });

      const res = await request(app)
        .get('/api/v1/vault/items?favorite=true')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(res.body.data).toHaveLength(1);
      expect(res.body.data[0]._id).toBe(favId);
      expect(res.body.data[0].favorite).toBe(true);
    });

    it('should reject a non-canonical boolean query value (?trash=maybe)', async () => {
      await request(app)
        .get('/api/v1/vault/items?trash=maybe')
        .set('Authorization', authHeader(user.accessToken))
        .expect(400);
    });

    it('should reject invalid sortBy fields via schema validation', async () => {
      await createItemViaApi(user.accessToken, { encryptedName: 'sort-test' });

      // Using an invalid sortBy field should be rejected by Zod validation
      const res = await request(app)
        .get('/api/v1/vault/items?sortBy=encryptedData')
        .set('Authorization', authHeader(user.accessToken));

      expect(res.status).toBe(400);
    });

    it('should accept valid sortBy fields', async () => {
      await createItemViaApi(user.accessToken, { encryptedName: 'sort-valid' });

      const res = await request(app)
        .get('/api/v1/vault/items?sortBy=createdAt&sortOrder=asc')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveLength(1);
    });

    it('should sort items by itemType', async () => {
      await createItemViaApi(user.accessToken, { itemType: 'note', encryptedName: 'note-item' });
      await createItemViaApi(user.accessToken, { itemType: 'login', encryptedName: 'login-item' });

      const res = await request(app)
        .get('/api/v1/vault/items?sortBy=itemType&sortOrder=asc')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveLength(2);
      // 'login' comes before 'note' alphabetically
      expect(res.body.data[0].itemType).toBe('login');
      expect(res.body.data[1].itemType).toBe('note');
    });

    // ── Update ────────────────────────────────────────────────────────

    it('should update a vault item', async () => {
      const { id } = await createItemViaApi(user.accessToken);

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .put(`/api/v1/vault/items/${id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({ favorite: true, tags: ['updated'] })
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.data.favorite).toBe(true);
      expect(res.body.data.tags).toEqual(['updated']);
    });

    it('should $unset folderId when updated to null (not store as null)', async () => {
      // First place an item inside a real folder so folderId is populated.
      const folder = await Folder.create({
        userId: user.id,
        encryptedName: 'enc-folder',
        nameIv: 'iv',
        nameTag: 'tag',
      });
      const folderId = String(folder._id);
      const { id } = await createItemViaApi(user.accessToken, { folderId });

      // Sanity-check: folderId is currently persisted on the item.
      const before = await VaultItem.findById(id).lean();
      expect(before?.folderId?.toString()).toBe(folderId);

      // Now update with folderId: null.
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .put(`/api/v1/vault/items/${id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({ folderId: null })
        .expect(200);

      expect(res.body.success).toBe(true);

      // The field must be absent on the raw BSON document, not stored as `null`.
      // This matches the behaviour of bulkMove and deleteFolder's orphan cleanup.
      const rawDoc = await mongoose.connection
        .db!.collection('vault_items')
        .findOne({ _id: new mongoose.Types.ObjectId(id) });
      expect(rawDoc).toBeTruthy();
      expect('folderId' in rawDoc!).toBe(false);
    });

    // ── Soft delete ───────────────────────────────────────────────────

    it('should soft-delete a vault item', async () => {
      const { id } = await createItemViaApi(user.accessToken);

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .delete(`/api/v1/vault/items/${id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.message).toBe('Item moved to trash');

      // Item should no longer appear in the normal listing
      const listRes = await request(app)
        .get('/api/v1/vault/items')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(listRes.body.data).toHaveLength(0);
    });

    // ── Permanent delete ──────────────────────────────────────────────

    it('should permanently delete a vault item from trash', async () => {
      const { id } = await createItemViaApi(user.accessToken);

      // Soft-delete first (move to trash)
      const softDeleteAgent = request.agent(app);
      const softDeleteCsrf = await getCsrf(softDeleteAgent);

      await softDeleteAgent
        .delete(`/api/v1/vault/items/${id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', softDeleteCsrf.csrfCookie)
        .set('x-csrf-token', softDeleteCsrf.csrfToken)
        .expect(200);

      // Permanently delete from trash
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .delete(`/api/v1/vault/items/${id}/permanent`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.message).toBe('Item permanently deleted');

      // Should not be fetchable anymore
      await request(app)
        .get(`/api/v1/vault/items/${id}`)
        .set('Authorization', authHeader(user.accessToken))
        .expect(404);
    });

    it('should reject permanent delete of active (non-trashed) item', async () => {
      const { id } = await createItemViaApi(user.accessToken);

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .delete(`/api/v1/vault/items/${id}/permanent`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .expect(404);
    });
  });

  // ========================================================================
  // 2. Trash
  // ========================================================================

  describe('Trash operations', () => {
    it('should move item to trash on soft delete', async () => {
      const { id } = await createItemViaApi(user.accessToken);

      // Soft delete
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .delete(`/api/v1/vault/items/${id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .expect(200);

      // Should appear in trash listing
      const trashRes = await request(app)
        .get('/api/v1/vault/items/trash')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(trashRes.body.success).toBe(true);
      expect(trashRes.body.data).toHaveLength(1);
      expect(trashRes.body.data[0]._id).toBe(id);
    });

    it('should restore an item from trash', async () => {
      const { id } = await createItemViaApi(user.accessToken);

      // Soft delete first
      const agent1 = request.agent(app);
      const csrf1 = await getCsrf(agent1);

      await agent1
        .delete(`/api/v1/vault/items/${id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf1.csrfCookie)
        .set('x-csrf-token', csrf1.csrfToken)
        .expect(200);

      // Restore
      const agent2 = request.agent(app);
      const csrf2 = await getCsrf(agent2);

      const restoreRes = await agent2
        .post(`/api/v1/vault/items/restore/${id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf2.csrfCookie)
        .set('x-csrf-token', csrf2.csrfToken)
        .expect(200);

      expect(restoreRes.body.success).toBe(true);
      expect(restoreRes.body.message).toBe('Item restored from trash');

      // Should now appear in normal listing again
      const listRes = await request(app)
        .get('/api/v1/vault/items')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(listRes.body.data).toHaveLength(1);
      expect(listRes.body.data[0]._id).toBe(id);

      // Should no longer be in trash
      const trashRes = await request(app)
        .get('/api/v1/vault/items/trash')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(trashRes.body.data).toHaveLength(0);
    });

    it('should empty trash and permanently delete all trashed items', async () => {
      // Create 3 items, soft-delete 2
      const { id: id1 } = await createItemViaApi(user.accessToken);
      const { id: id2 } = await createItemViaApi(user.accessToken);
      await createItemViaApi(user.accessToken); // id3 stays active

      // Soft delete id1
      const agent1 = request.agent(app);
      const csrf1 = await getCsrf(agent1);
      await agent1
        .delete(`/api/v1/vault/items/${id1}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf1.csrfCookie)
        .set('x-csrf-token', csrf1.csrfToken)
        .expect(200);

      // Soft delete id2
      const agent2 = request.agent(app);
      const csrf2 = await getCsrf(agent2);
      await agent2
        .delete(`/api/v1/vault/items/${id2}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf2.csrfCookie)
        .set('x-csrf-token', csrf2.csrfToken)
        .expect(200);

      // Empty trash
      const agent3 = request.agent(app);
      const csrf3 = await getCsrf(agent3);
      const emptyRes = await agent3
        .delete('/api/v1/vault/items/trash/empty')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf3.csrfCookie)
        .set('x-csrf-token', csrf3.csrfToken)
        .expect(200);

      expect(emptyRes.body.success).toBe(true);
      expect(emptyRes.body.data.deletedCount).toBe(2);

      // Trash should be empty
      const trashRes = await request(app)
        .get('/api/v1/vault/items/trash')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(trashRes.body.data).toHaveLength(0);

      // The non-deleted item should still exist
      const listRes = await request(app)
        .get('/api/v1/vault/items')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(listRes.body.data).toHaveLength(1);
    });

    it('should list only trashed items in the trash endpoint', async () => {
      await createItemViaApi(user.accessToken);
      const { id: trashedId } = await createItemViaApi(user.accessToken);

      // Soft delete one
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);
      await agent
        .delete(`/api/v1/vault/items/${trashedId}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .expect(200);

      const trashRes = await request(app)
        .get('/api/v1/vault/items/trash')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(trashRes.body.data).toHaveLength(1);
      expect(trashRes.body.data[0]._id).toBe(trashedId);
    });
  });

  // ========================================================================
  // 3. Bulk operations
  // ========================================================================

  describe('Bulk operations', () => {
    it('should bulk soft-delete multiple items', async () => {
      const { id: id1 } = await createItemViaApi(user.accessToken);
      const { id: id2 } = await createItemViaApi(user.accessToken);
      await createItemViaApi(user.accessToken); // id3 stays

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/vault/items/bulk-delete')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({ ids: [id1, id2] })
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.data.modifiedCount).toBe(2);

      // Normal listing should only have 1
      const listRes = await request(app)
        .get('/api/v1/vault/items')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(listRes.body.data).toHaveLength(1);

      // Trash should have 2
      const trashRes = await request(app)
        .get('/api/v1/vault/items/trash')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(trashRes.body.data).toHaveLength(2);
    });

    it('should bulk move items to a folder', async () => {
      const { id: id1 } = await createItemViaApi(user.accessToken);
      const { id: id2 } = await createItemViaApi(user.accessToken);

      // Create a real folder belonging to the user for the IDOR check
      const folder = await Folder.create({
        userId: user.id,
        encryptedName: 'enc-name',
        nameIv: 'iv',
        nameTag: 'tag',
      });
      const folderId = String(folder._id);

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/vault/items/bulk-move')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({ ids: [id1, id2], folderId })
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.data.modifiedCount).toBe(2);

      // Verify both items have the new folderId
      const item1Res = await request(app)
        .get(`/api/v1/vault/items/${id1}`)
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(item1Res.body.data.folderId).toBe(folderId);

      const item2Res = await request(app)
        .get(`/api/v1/vault/items/${id2}`)
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(item2Res.body.data.folderId).toBe(folderId);
    });

    it('should bulk move items out of a folder (folderId: null)', async () => {
      const folder = await Folder.create({
        userId: user.id,
        encryptedName: 'enc-folder',
        nameIv: 'iv',
        nameTag: 'tag',
      });
      const folderId = String(folder._id);
      const { id: id1 } = await createItemViaApi(user.accessToken, { folderId });

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/vault/items/bulk-move')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({ ids: [id1], folderId: null })
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.data.modifiedCount).toBe(1);

      // Verify folderId is removed
      const itemRes = await request(app)
        .get(`/api/v1/vault/items/${id1}`)
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(itemRes.body.data.folderId).toBeUndefined();
    });
  });

  // ========================================================================
  // 4. Auth guards
  // ========================================================================

  describe('Auth guards - all endpoints return 401 without token', () => {
    const fakeId = new mongoose.Types.ObjectId().toString();

    it('GET /api/v1/vault/items returns 401', async () => {
      await request(app).get('/api/v1/vault/items').expect(401);
    });

    it('GET /api/v1/vault/items/:id returns 401', async () => {
      await request(app).get(`/api/v1/vault/items/${fakeId}`).expect(401);
    });

    it('POST /api/v1/vault/items returns 401', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .post('/api/v1/vault/items')
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send(sampleVaultItem())
        .expect(401);
    });

    it('PUT /api/v1/vault/items/:id returns 401', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .put(`/api/v1/vault/items/${fakeId}`)
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({ favorite: true })
        .expect(401);
    });

    it('DELETE /api/v1/vault/items/:id returns 401', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .delete(`/api/v1/vault/items/${fakeId}`)
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .expect(401);
    });

    it('DELETE /api/v1/vault/items/:id/permanent returns 401', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .delete(`/api/v1/vault/items/${fakeId}/permanent`)
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .expect(401);
    });

    it('POST /api/v1/vault/items/restore/:id returns 401', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .post(`/api/v1/vault/items/restore/${fakeId}`)
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .expect(401);
    });

    it('POST /api/v1/vault/items/bulk-delete returns 401', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .post('/api/v1/vault/items/bulk-delete')
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({ ids: [fakeId] })
        .expect(401);
    });

    it('POST /api/v1/vault/items/bulk-move returns 401', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .post('/api/v1/vault/items/bulk-move')
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({ ids: [fakeId], folderId: null })
        .expect(401);
    });

    it('GET /api/v1/vault/items/trash returns 401', async () => {
      await request(app).get('/api/v1/vault/items/trash').expect(401);
    });

    it('DELETE /api/v1/vault/items/trash/empty returns 401', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .delete('/api/v1/vault/items/trash/empty')
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .expect(401);
    });
  });

  // ========================================================================
  // 5. Not Found
  // ========================================================================

  describe('Not Found - non-existent items return 404', () => {
    const nonExistentId = new mongoose.Types.ObjectId().toString();

    it('GET /api/v1/vault/items/:id returns 404 for non-existent item', async () => {
      await request(app)
        .get(`/api/v1/vault/items/${nonExistentId}`)
        .set('Authorization', authHeader(user.accessToken))
        .expect(404);
    });

    it('PUT /api/v1/vault/items/:id returns 404 for non-existent item', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .put(`/api/v1/vault/items/${nonExistentId}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({ favorite: true })
        .expect(404);
    });

    it('DELETE /api/v1/vault/items/:id returns 404 for non-existent item', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .delete(`/api/v1/vault/items/${nonExistentId}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .expect(404);
    });

    it('DELETE /api/v1/vault/items/:id/permanent returns 404 for non-existent item', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .delete(`/api/v1/vault/items/${nonExistentId}/permanent`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .expect(404);
    });

    it('POST /api/v1/vault/items/restore/:id returns 404 for non-existent item', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .post(`/api/v1/vault/items/restore/${nonExistentId}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .expect(404);
    });
  });

  // ========================================================================
  // 6. User isolation
  // ========================================================================

  describe('User isolation - user A cannot access user B items', () => {
    let userB: TestUser;

    beforeEach(async () => {
      userB = await createTestUser({ email: 'userb@example.com' });
    });

    it('user B cannot GET user A item', async () => {
      const { id } = await createItemViaApi(user.accessToken);

      await request(app)
        .get(`/api/v1/vault/items/${id}`)
        .set('Authorization', authHeader(userB.accessToken))
        .expect(404);
    });

    it('user B cannot UPDATE user A item', async () => {
      const { id } = await createItemViaApi(user.accessToken);

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .put(`/api/v1/vault/items/${id}`)
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({ favorite: true })
        .expect(404);
    });

    it('user B cannot soft-DELETE user A item', async () => {
      const { id } = await createItemViaApi(user.accessToken);

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .delete(`/api/v1/vault/items/${id}`)
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .expect(404);
    });

    it('user B cannot permanently DELETE user A item', async () => {
      const { id } = await createItemViaApi(user.accessToken);

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .delete(`/api/v1/vault/items/${id}/permanent`)
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .expect(404);
    });

    it('user B cannot restore user A trashed item', async () => {
      const { id } = await createItemViaApi(user.accessToken);

      // Soft delete as user A
      const agent1 = request.agent(app);
      const csrf1 = await getCsrf(agent1);
      await agent1
        .delete(`/api/v1/vault/items/${id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf1.csrfCookie)
        .set('x-csrf-token', csrf1.csrfToken)
        .expect(200);

      // User B tries to restore
      const agent2 = request.agent(app);
      const csrf2 = await getCsrf(agent2);
      await agent2
        .post(`/api/v1/vault/items/restore/${id}`)
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrf2.csrfCookie)
        .set('x-csrf-token', csrf2.csrfToken)
        .expect(404);
    });

    it('user A items do not appear in user B listing', async () => {
      await createItemViaApi(user.accessToken);
      await createItemViaApi(user.accessToken);

      const res = await request(app)
        .get('/api/v1/vault/items')
        .set('Authorization', authHeader(userB.accessToken))
        .expect(200);

      expect(res.body.data).toHaveLength(0);
      expect(res.body.pagination.total).toBe(0);
    });

    it('user A trashed items do not appear in user B trash listing', async () => {
      const { id } = await createItemViaApi(user.accessToken);

      // Soft delete as user A
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);
      await agent
        .delete(`/api/v1/vault/items/${id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .expect(200);

      // User B trash should be empty
      const trashRes = await request(app)
        .get('/api/v1/vault/items/trash')
        .set('Authorization', authHeader(userB.accessToken))
        .expect(200);

      expect(trashRes.body.data).toHaveLength(0);
    });

    it('bulk-delete only affects own items, not other user items', async () => {
      const { id: userAItem } = await createItemViaApi(user.accessToken);
      const { id: userBItem } = await createItemViaApi(userB.accessToken);

      // User B tries to bulk-delete both
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/vault/items/bulk-delete')
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({ ids: [userAItem, userBItem] })
        .expect(200);

      // Only user B's item should have been soft-deleted
      expect(res.body.data.modifiedCount).toBe(1);

      // User A's item should still be accessible
      await request(app)
        .get(`/api/v1/vault/items/${userAItem}`)
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);
    });

    it('bulk-move only affects own items, not other user items', async () => {
      const { id: userAItem } = await createItemViaApi(user.accessToken);
      const { id: userBItem } = await createItemViaApi(userB.accessToken);

      // Create a real folder belonging to userB for the IDOR check
      const folder = await Folder.create({
        userId: userB.id,
        encryptedName: 'enc-name',
        nameIv: 'iv',
        nameTag: 'tag',
      });
      const folderId = String(folder._id);

      // User B tries to bulk-move both
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/vault/items/bulk-move')
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({ ids: [userAItem, userBItem], folderId })
        .expect(200);

      // Only user B's item should have been moved
      expect(res.body.data.modifiedCount).toBe(1);

      // User A's item should not have the folderId
      const itemRes = await request(app)
        .get(`/api/v1/vault/items/${userAItem}`)
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(itemRes.body.data.folderId).toBeUndefined();
    });

    it('empty trash only deletes own trashed items', async () => {
      const { id: userAItem } = await createItemViaApi(user.accessToken);
      const { id: userBItem } = await createItemViaApi(userB.accessToken);

      // Soft delete both items by their respective owners
      const agent1 = request.agent(app);
      const csrf1 = await getCsrf(agent1);
      await agent1
        .delete(`/api/v1/vault/items/${userAItem}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf1.csrfCookie)
        .set('x-csrf-token', csrf1.csrfToken)
        .expect(200);

      const agent2 = request.agent(app);
      const csrf2 = await getCsrf(agent2);
      await agent2
        .delete(`/api/v1/vault/items/${userBItem}`)
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrf2.csrfCookie)
        .set('x-csrf-token', csrf2.csrfToken)
        .expect(200);

      // User B empties trash
      const agent3 = request.agent(app);
      const csrf3 = await getCsrf(agent3);
      const emptyRes = await agent3
        .delete('/api/v1/vault/items/trash/empty')
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrf3.csrfCookie)
        .set('x-csrf-token', csrf3.csrfToken)
        .expect(200);

      expect(emptyRes.body.data.deletedCount).toBe(1);

      // User A's trashed item should still exist
      const trashResA = await request(app)
        .get('/api/v1/vault/items/trash')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(trashResA.body.data).toHaveLength(1);
      expect(trashResA.body.data[0]._id).toBe(userAItem);
    });
  });

  // ========================================================================
  // 7. Audit logging
  // ========================================================================

  describe('Audit logging', () => {
    it('should create audit log on permanent delete', async () => {
      const { id } = await createItemViaApi(user.accessToken);

      // Soft-delete first (move to trash)
      const softDeleteAgent = request.agent(app);
      const softDeleteCsrf = await getCsrf(softDeleteAgent);

      await softDeleteAgent
        .delete(`/api/v1/vault/items/${id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', softDeleteCsrf.csrfCookie)
        .set('x-csrf-token', softDeleteCsrf.csrfToken)
        .expect(200);

      // Permanently delete from trash
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .delete(`/api/v1/vault/items/${id}/permanent`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .expect(200);

      const auditEntry = await AuditLog.findOne({
        userId: user.id,
        action: 'item_delete',
        'metadata.permanent': true,
      });

      expect(auditEntry).toBeDefined();
      expect(auditEntry!.userId.toString()).toBe(user.id);
      expect(auditEntry!.metadata).toBeDefined();
      expect((auditEntry!.metadata as Record<string, unknown>).itemId).toBe(id);
      expect((auditEntry!.metadata as Record<string, unknown>).permanent).toBe(true);
    });

    it('should create audit log on empty trash', async () => {
      // Create 2 items, soft-delete both
      const { id: id1 } = await createItemViaApi(user.accessToken);
      const { id: id2 } = await createItemViaApi(user.accessToken);

      // Soft delete id1
      const agent1 = request.agent(app);
      const csrf1 = await getCsrf(agent1);
      await agent1
        .delete(`/api/v1/vault/items/${id1}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf1.csrfCookie)
        .set('x-csrf-token', csrf1.csrfToken)
        .expect(200);

      // Soft delete id2
      const agent2 = request.agent(app);
      const csrf2 = await getCsrf(agent2);
      await agent2
        .delete(`/api/v1/vault/items/${id2}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf2.csrfCookie)
        .set('x-csrf-token', csrf2.csrfToken)
        .expect(200);

      // Empty trash
      const agent3 = request.agent(app);
      const csrf3 = await getCsrf(agent3);
      await agent3
        .delete('/api/v1/vault/items/trash/empty')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf3.csrfCookie)
        .set('x-csrf-token', csrf3.csrfToken)
        .expect(200);

      const auditEntry = await AuditLog.findOne({
        userId: user.id,
        action: 'item_delete',
        'metadata.action': 'empty_trash',
      });

      expect(auditEntry).toBeDefined();
      expect(auditEntry!.userId.toString()).toBe(user.id);
      expect(auditEntry!.metadata).toBeDefined();
      expect((auditEntry!.metadata as Record<string, unknown>).action).toBe('empty_trash');
      expect((auditEntry!.metadata as Record<string, unknown>).count).toBe(2);
    });

    it('should handle batched deletion for large trash volumes', async () => {
      // Create 600 trashed items directly in DB (exceeds BATCH_SIZE of 500)
      const items = Array.from({ length: 600 }, (_, i) => ({
        userId: new mongoose.Types.ObjectId(user.id),
        itemType: 'login' as const,
        encryptedData: `data-${String(i)}`,
        dataIv: 'iv',
        dataTag: 'tag',
        encryptedName: `name-${String(i)}`,
        nameIv: 'iv',
        nameTag: 'tag',
        deletedAt: new Date(),
      }));
      await VaultItem.insertMany(items);

      // Empty trash via API
      const agent = request.agent(app);
      const csrf = await getCsrf(agent);
      const emptyRes = await agent
        .delete('/api/v1/vault/items/trash/empty')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.csrfCookie)
        .set('x-csrf-token', csrf.csrfToken)
        .expect(200);

      expect(emptyRes.body.success).toBe(true);
      expect(emptyRes.body.data.deletedCount).toBe(600);

      // Verify trash is empty
      const trashRes = await request(app)
        .get('/api/v1/vault/items/trash')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(trashRes.body.data).toHaveLength(0);
    });

    it('should return zero when emptying already empty trash', async () => {
      const agent = request.agent(app);
      const csrf = await getCsrf(agent);
      const emptyRes = await agent
        .delete('/api/v1/vault/items/trash/empty')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.csrfCookie)
        .set('x-csrf-token', csrf.csrfToken)
        .expect(200);

      expect(emptyRes.body.success).toBe(true);
      expect(emptyRes.body.data.deletedCount).toBe(0);
    });
  });

  // ========================================================================
  // 8. Filter by folderId and searchHash
  // ========================================================================

  describe('Filtering by folderId and searchHash', () => {
    it('should filter items by folderId', async () => {
      // Create a folder for the user
      const folder = await Folder.create({
        userId: user.id,
        encryptedName: 'enc-folder',
        nameIv: 'iv',
        nameTag: 'tag',
      });
      const folderId = String(folder._id);

      // Create items: one in folder, one without
      await createItemViaApi(user.accessToken, { folderId });
      await createItemViaApi(user.accessToken);

      const res = await request(app)
        .get(`/api/v1/vault/items?folderId=${folderId}`)
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(res.body.data).toHaveLength(1);
      expect(res.body.data[0].folderId).toBe(folderId);
    });

    it('should store and return searchHash on a created item', async () => {
      // searchHash must be a valid 64-char hex string (SHA-256 format)
      const searchHash = 'a'.repeat(64);

      const { id } = await createItemViaApi(user.accessToken, { searchHash });

      const res = await request(app)
        .get(`/api/v1/vault/items/${id}`)
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(res.body.data.searchHash).toBe(searchHash);
    });
  });

  // ========================================================================
  // 9. Update encrypted data fields
  // ========================================================================

  describe('Update encrypted data fields', () => {
    it('should update encryptedData, dataIv, and dataTag together', async () => {
      const { id } = await createItemViaApi(user.accessToken);

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .put(`/api/v1/vault/items/${id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({
          encryptedData: 'new-encrypted-data',
          dataIv: 'new-data-iv',
          dataTag: 'new-data-tag',
        })
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.data.encryptedData).toBe('new-encrypted-data');
      expect(res.body.data.dataIv).toBe('new-data-iv');
      expect(res.body.data.dataTag).toBe('new-data-tag');
    });

    it('should update encryptedName, nameIv, and nameTag together', async () => {
      const { id } = await createItemViaApi(user.accessToken);

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .put(`/api/v1/vault/items/${id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({
          encryptedName: 'new-encrypted-name',
          nameIv: 'new-name-iv',
          nameTag: 'new-name-tag',
        })
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.data.encryptedName).toBe('new-encrypted-name');
      expect(res.body.data.nameIv).toBe('new-name-iv');
      expect(res.body.data.nameTag).toBe('new-name-tag');
    });
  });

  // ========================================================================
  // 10. Password history
  // ========================================================================

  describe('Password history', () => {
    it('should add passwordHistory via update', async () => {
      const { id } = await createItemViaApi(user.accessToken);

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const passwordHistory = [
        {
          encryptedPassword: 'old-pass-1',
          iv: 'iv-1',
          tag: 'tag-1',
          changedAt: new Date().toISOString(),
        },
        {
          encryptedPassword: 'old-pass-2',
          iv: 'iv-2',
          tag: 'tag-2',
          changedAt: new Date().toISOString(),
        },
      ];

      const res = await agent
        .put(`/api/v1/vault/items/${id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({ passwordHistory })
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.data.passwordHistory).toHaveLength(2);
      expect(res.body.data.passwordHistory[0].encryptedPassword).toBe('old-pass-1');
    });

    it('should update item and grow passwordHistory', async () => {
      const { id } = await createItemViaApi(user.accessToken);

      // First update: add initial history entry
      const agent1 = request.agent(app);
      const csrf1 = await getCsrf(agent1);

      const initialHistory = [
        {
          encryptedPassword: 'initial-pass',
          iv: 'iv-1',
          tag: 'tag-1',
          changedAt: new Date().toISOString(),
        },
      ];

      await agent1
        .put(`/api/v1/vault/items/${id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf1.csrfCookie)
        .set('x-csrf-token', csrf1.csrfToken)
        .send({ passwordHistory: initialHistory })
        .expect(200);

      // Second update: add another history entry
      const agent2 = request.agent(app);
      const csrf2 = await getCsrf(agent2);

      const updatedHistory = [
        ...initialHistory,
        {
          encryptedPassword: 'second-pass',
          iv: 'iv-2',
          tag: 'tag-2',
          changedAt: new Date().toISOString(),
        },
      ];

      const res = await agent2
        .put(`/api/v1/vault/items/${id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf2.csrfCookie)
        .set('x-csrf-token', csrf2.csrfToken)
        .send({ passwordHistory: updatedHistory })
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.data.passwordHistory).toHaveLength(2);
    });
  });

  // ========================================================================
  // 11. Restore non-trashed item and double soft-delete
  // ========================================================================

  describe('Restore and double soft-delete edge cases', () => {
    it('should fail to restore a non-trashed (active) item', async () => {
      const { id } = await createItemViaApi(user.accessToken);

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post(`/api/v1/vault/items/restore/${id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .expect(404);

      expect(res.body.success).toBe(false);
    });

    it('should handle double soft-delete gracefully (re-sets deletedAt)', async () => {
      const { id } = await createItemViaApi(user.accessToken);

      // First soft delete
      const agent1 = request.agent(app);
      const csrf1 = await getCsrf(agent1);
      await agent1
        .delete(`/api/v1/vault/items/${id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf1.csrfCookie)
        .set('x-csrf-token', csrf1.csrfToken)
        .expect(200);

      // Second soft delete — the controller does not filter by deletedAt: null,
      // so it still finds the item and re-sets deletedAt (idempotent behavior)
      const agent2 = request.agent(app);
      const csrf2 = await getCsrf(agent2);
      const res = await agent2
        .delete(`/api/v1/vault/items/${id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf2.csrfCookie)
        .set('x-csrf-token', csrf2.csrfToken);

      // Returns 200 because the item is found and deletedAt is re-set
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });
  });

  // ========================================================================
  // 12. Audit logs for create, update, soft-delete
  // ========================================================================

  describe('Audit logs for create, update, soft-delete', () => {
    it('should create audit log on item creation', async () => {
      const { id } = await createItemViaApi(user.accessToken);

      const auditEntry = await AuditLog.findOne({
        userId: user.id,
        action: 'item_create',
        'metadata.itemId': id,
      });

      expect(auditEntry).toBeDefined();
      expect(auditEntry!.userId.toString()).toBe(user.id);
      expect((auditEntry!.metadata as Record<string, unknown>).itemType).toBe('login');
    });

    it('should create audit log on item update', async () => {
      const { id } = await createItemViaApi(user.accessToken);

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .put(`/api/v1/vault/items/${id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({ favorite: true })
        .expect(200);

      const auditEntry = await AuditLog.findOne({
        userId: user.id,
        action: 'item_update',
        'metadata.itemId': id,
      });

      expect(auditEntry).toBeDefined();
      expect(auditEntry!.userId.toString()).toBe(user.id);
    });

    it('should create audit log on soft delete', async () => {
      const { id } = await createItemViaApi(user.accessToken);

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .delete(`/api/v1/vault/items/${id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .expect(200);

      const auditEntry = await AuditLog.findOne({
        userId: user.id,
        action: 'item_delete',
        'metadata.itemId': id,
      });

      expect(auditEntry).toBeDefined();
      expect(auditEntry!.userId.toString()).toBe(user.id);
      // Soft delete should NOT have the permanent flag
      expect((auditEntry!.metadata as Record<string, unknown>).permanent).toBeUndefined();
    });
  });

  // ========================================================================
  // Bulk re-encrypt (vault key rotation)
  // ========================================================================

  describe('Bulk re-encrypt (vault key rotation)', () => {
    it('should re-encrypt items and update vault key (transaction fallback)', async () => {
      // Create two vault items
      const { id: id1 } = await createItemViaApi(user.accessToken);
      const { id: id2 } = await createItemViaApi(user.accessToken);

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/vault/items/bulk-reencrypt')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({
          authHash: user.rawPassword,
          items: [
            {
              id: id1,
              encryptedName: 'new-enc-name-1',
              nameIv: 'new-name-iv-1',
              nameTag: 'new-name-tag-1',
              encryptedData: 'new-enc-data-1',
              dataIv: 'new-data-iv-1',
              dataTag: 'new-data-tag-1',
            },
            {
              id: id2,
              encryptedName: 'new-enc-name-2',
              nameIv: 'new-name-iv-2',
              nameTag: 'new-name-tag-2',
              encryptedData: 'new-enc-data-2',
              dataIv: 'new-data-iv-2',
              dataTag: 'new-data-tag-2',
            },
          ],
          newEncryptedVaultKey: 'new-encrypted-vault-key',
          newVaultKeyIv: 'new-vault-key-iv',
          newVaultKeyTag: 'new-vault-key-tag',
        })
        .expect(200);

      expect(res.body.success).toBe(true);

      // Verify items were updated
      const item1 = await VaultItem.findById(id1);
      expect(item1!.encryptedName).toBe('new-enc-name-1');
      expect(item1!.nameIv).toBe('new-name-iv-1');
      expect(item1!.encryptedData).toBe('new-enc-data-1');

      const item2 = await VaultItem.findById(id2);
      expect(item2!.encryptedName).toBe('new-enc-name-2');
      expect(item2!.encryptedData).toBe('new-enc-data-2');

      // Verify user vault key was updated
      const updatedUser = await mongoose.model('User').findById(user.id);
      expect(updatedUser!.encryptedVaultKey).toBe('new-encrypted-vault-key');
      expect(updatedUser!.vaultKeyIv).toBe('new-vault-key-iv');
      expect(updatedUser!.vaultKeyTag).toBe('new-vault-key-tag');
    });

    it('should reject with wrong password', async () => {
      const { id } = await createItemViaApi(user.accessToken);

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .post('/api/v1/vault/items/bulk-reencrypt')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({
          authHash: 'wrong-password',
          items: [
            {
              id,
              encryptedName: 'new-enc-name',
              nameIv: 'new-name-iv',
              nameTag: 'new-name-tag',
              encryptedData: 'new-enc-data',
              dataIv: 'new-data-iv',
              dataTag: 'new-data-tag',
            },
          ],
          newEncryptedVaultKey: 'new-evk',
          newVaultKeyIv: 'new-iv',
          newVaultKeyTag: 'new-tag',
        })
        .expect(401);
    });

    it('should handle empty items array (key rotation with no items)', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/vault/items/bulk-reencrypt')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({
          authHash: user.rawPassword,
          items: [],
          newEncryptedVaultKey: 'rotated-vault-key',
          newVaultKeyIv: 'rotated-iv',
          newVaultKeyTag: 'rotated-tag',
        })
        .expect(200);

      expect(res.body.success).toBe(true);

      // Verify vault key was still updated
      const updatedUser = await mongoose.model('User').findById(user.id);
      expect(updatedUser!.encryptedVaultKey).toBe('rotated-vault-key');
    });

    it('should abort rotation and preserve vault key when a non-existent item id is included', async () => {
      const fakeId = new mongoose.Types.ObjectId().toString();

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/vault/items/bulk-reencrypt')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({
          authHash: user.rawPassword,
          items: [
            {
              id: fakeId,
              encryptedName: 'x',
              nameIv: 'x',
              nameTag: 'x',
              encryptedData: 'x',
              dataIv: 'x',
              dataTag: 'x',
            },
          ],
          newEncryptedVaultKey: 'new-evk',
          newVaultKeyIv: 'new-iv',
          newVaultKeyTag: 'new-tag',
        })
        .expect(409);

      expect(res.body.success).toBe(false);

      // Vault key should NOT be updated when items fail
      const updatedUser = await mongoose.model('User').findById(user.id);
      expect(updatedUser!.encryptedVaultKey).toBe('test-encrypted-vault-key');
    });

    it('should abort rotation when one item fails — vault key preserved, no partial writes', async () => {
      const { id: validId1 } = await createItemViaApi(user.accessToken);
      const fakeId = new mongoose.Types.ObjectId().toString();
      const { id: validId2 } = await createItemViaApi(user.accessToken);

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/vault/items/bulk-reencrypt')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({
          authHash: user.rawPassword,
          items: [
            {
              id: validId1,
              encryptedName: 'rotated-1',
              nameIv: 'riv-1',
              nameTag: 'rtag-1',
              encryptedData: 'rdata-1',
              dataIv: 'rdiv-1',
              dataTag: 'rdtag-1',
            },
            {
              id: fakeId,
              encryptedName: 'x',
              nameIv: 'x',
              nameTag: 'x',
              encryptedData: 'x',
              dataIv: 'x',
              dataTag: 'x',
            },
            {
              id: validId2,
              encryptedName: 'rotated-2',
              nameIv: 'riv-2',
              nameTag: 'rtag-2',
              encryptedData: 'rdata-2',
              dataIv: 'rdiv-2',
              dataTag: 'rdtag-2',
            },
          ],
          newEncryptedVaultKey: 'partial-vk',
          newVaultKeyIv: 'partial-iv',
          newVaultKeyTag: 'partial-tag',
        })
        .expect(409);

      expect(res.body.success).toBe(false);

      // Vault key should NOT be updated on partial failure
      const updatedUser = await mongoose.model('User').findById(user.id);
      expect(updatedUser!.encryptedVaultKey).toBe('test-encrypted-vault-key');

      // "No partial writes" is the real contract: neither valid item may carry
      // the NEW-key ciphertext while the vault key stays OLD (that is the exact
      // undecryptable-row data loss). Read both requested items back and assert
      // their ciphertext is still the ORIGINAL sample value, not 'rotated-*'.
      // This is what would go red if the pre-write missing-id abort AND the
      // rollback were both broken — asserting only the User document would not.
      const item1 = await VaultItem.findById(validId1);
      const item2 = await VaultItem.findById(validId2);
      expect(item1).not.toBeNull();
      expect(item2).not.toBeNull();
      expect(item1!.encryptedName).toBe('test-encrypted-name');
      expect(item1!.encryptedData).toBe('test-encrypted-data-base64');
      expect(item2!.encryptedName).toBe('test-encrypted-name');
      expect(item2!.encryptedData).toBe('test-encrypted-data-base64');

      // The sequential path snapshots every requested id and aborts BEFORE any
      // write when one is missing (the fakeId here), so no valid item is
      // modified and the vault key is never swapped. The user's existing key
      // still decrypts everything; the client can retry the full rotation.
    });

    it('should abort rotation when a folder fails — vault key preserved', async () => {
      const { id: itemId } = await createItemViaApi(user.accessToken);
      const fakeFolderId = new mongoose.Types.ObjectId().toString();

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      // Create a real folder
      const folderRes = await agent
        .post('/api/v1/folders')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({
          encryptedName: 'old-folder',
          nameIv: 'old-fiv',
          nameTag: 'old-ftag',
        })
        .expect(201);

      const realFolderId = (folderRes.body as { data: { _id: string } }).data._id;

      const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/vault/items/bulk-reencrypt')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', cookie2)
        .set('x-csrf-token', csrf2)
        .send({
          authHash: user.rawPassword,
          items: [
            {
              id: itemId,
              encryptedName: 'rotated-item',
              nameIv: 'riv',
              nameTag: 'rtag',
              encryptedData: 'rdata',
              dataIv: 'rdiv',
              dataTag: 'rdtag',
            },
          ],
          folders: [
            {
              id: realFolderId,
              encryptedName: 'rotated-folder',
              nameIv: 'rfiv',
              nameTag: 'rftag',
            },
            {
              id: fakeFolderId,
              encryptedName: 'ghost-folder',
              nameIv: 'gfiv',
              nameTag: 'gftag',
            },
          ],
          newEncryptedVaultKey: 'folder-err-vk',
          newVaultKeyIv: 'folder-err-iv',
          newVaultKeyTag: 'folder-err-tag',
        })
        .expect(409);

      expect(res.body.success).toBe(false);

      // Vault key should NOT be updated on partial failure
      const updatedUser = await mongoose.model('User').findById(user.id);
      expect(updatedUser!.encryptedVaultKey).toBe('test-encrypted-vault-key');
    });

    it('should update searchHash when provided', async () => {
      const { id } = await createItemViaApi(user.accessToken);
      const newSearchHash = 'a'.repeat(64);

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/vault/items/bulk-reencrypt')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({
          authHash: user.rawPassword,
          items: [
            {
              id,
              encryptedName: 'rotated-name',
              nameIv: 'rotated-niv',
              nameTag: 'rotated-ntag',
              encryptedData: 'rotated-data',
              dataIv: 'rotated-div',
              dataTag: 'rotated-dtag',
              searchHash: newSearchHash,
            },
          ],
          newEncryptedVaultKey: 'rotated-vk',
          newVaultKeyIv: 'rotated-viv',
          newVaultKeyTag: 'rotated-vtag',
        })
        .expect(200);

      expect(res.body.success).toBe(true);

      const item = await VaultItem.findById(id);
      expect(item!.searchHash).toBe(newSearchHash);
    });

    it('should re-encrypt folders during vault key rotation', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      // Create a folder
      const folderRes = await agent
        .post('/api/v1/folders')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({
          encryptedName: 'old-folder-name',
          nameIv: 'old-fiv',
          nameTag: 'old-ftag',
        })
        .expect(201);

      const folderId = (folderRes.body as { data: { _id: string } }).data._id;

      // Re-encrypt with folders included
      const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/vault/items/bulk-reencrypt')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', cookie2)
        .set('x-csrf-token', csrf2)
        .send({
          authHash: user.rawPassword,
          items: [],
          folders: [
            {
              id: folderId,
              encryptedName: 'rotated-folder-name',
              nameIv: 'rotated-fiv',
              nameTag: 'rotated-ftag',
            },
          ],
          newEncryptedVaultKey: 'rotated-vk',
          newVaultKeyIv: 'rotated-viv',
          newVaultKeyTag: 'rotated-vtag',
        })
        .expect(200);

      expect(res.body.success).toBe(true);

      // Verify folder was updated
      const folder = await Folder.findById(folderId);
      expect(folder!.encryptedName).toBe('rotated-folder-name');
      expect(folder!.nameIv).toBe('rotated-fiv');
      expect(folder!.nameTag).toBe('rotated-ftag');
    });

    it('should re-encrypt soft-deleted (trash) items during vault key rotation', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      // Create an item
      const createRes = await agent
        .post('/api/v1/vault/items')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({
          itemType: 'login',
          encryptedData: 'trash-data',
          dataIv: 'trash-div',
          dataTag: 'trash-dtag',
          encryptedName: 'trash-name',
          nameIv: 'trash-niv',
          nameTag: 'trash-ntag',
        })
        .expect(201);

      const itemId = (createRes.body as { data: { _id: string } }).data._id;

      // Soft-delete the item (move to trash)
      const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);
      await agent
        .delete(`/api/v1/vault/items/${itemId}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', cookie2)
        .set('x-csrf-token', csrf2)
        .expect(200);

      // Verify item is in trash
      const trashed = await VaultItem.findById(itemId);
      expect(trashed!.deletedAt).toBeDefined();

      // Re-encrypt including the trashed item
      const { csrfToken: csrf3, csrfCookie: cookie3 } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/vault/items/bulk-reencrypt')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', cookie3)
        .set('x-csrf-token', csrf3)
        .send({
          authHash: user.rawPassword,
          items: [
            {
              id: itemId,
              encryptedName: 'rotated-trash-name',
              nameIv: 'rotated-tniv',
              nameTag: 'rotated-tntag',
              encryptedData: 'rotated-trash-data',
              dataIv: 'rotated-tdiv',
              dataTag: 'rotated-tdtag',
            },
          ],
          newEncryptedVaultKey: 'rotated-vk',
          newVaultKeyIv: 'rotated-viv',
          newVaultKeyTag: 'rotated-vtag',
        })
        .expect(200);

      expect(res.body.success).toBe(true);

      // Verify trashed item was updated but still in trash
      const updated = await VaultItem.findById(itemId);
      expect(updated!.encryptedName).toBe('rotated-trash-name');
      expect(updated!.encryptedData).toBe('rotated-trash-data');
      expect(updated!.deletedAt).toBeDefined(); // Still in trash
    });

    it('should store lastRotationKey when idempotencyKey is provided', async () => {
      const { id } = await createItemViaApi(user.accessToken);
      const idempotencyKey = crypto.randomUUID();

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/vault/items/bulk-reencrypt')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({
          authHash: user.rawPassword,
          idempotencyKey,
          items: [
            {
              id,
              encryptedName: 'idemp-name',
              nameIv: 'idemp-niv',
              nameTag: 'idemp-ntag',
              encryptedData: 'idemp-data',
              dataIv: 'idemp-div',
              dataTag: 'idemp-dtag',
            },
          ],
          newEncryptedVaultKey: 'idemp-vk',
          newVaultKeyIv: 'idemp-viv',
          newVaultKeyTag: 'idemp-vtag',
        })
        .expect(200);

      expect(res.body.success).toBe(true);

      // Verify lastRotationKey was stored
      const updatedUser = await mongoose.model('User').findById(user.id);
      expect(updatedUser!.lastRotationKey).toBe(idempotencyKey);
      expect(updatedUser!.lastRotationAt).toBeDefined();
    });

    it('should return success without re-processing for duplicate idempotencyKey', async () => {
      const { id } = await createItemViaApi(user.accessToken);
      const idempotencyKey = crypto.randomUUID();

      // First request — performs the rotation
      const agent1 = request.agent(app);
      const { csrfToken: csrf1, csrfCookie: cookie1 } = await getCsrf(agent1);

      await agent1
        .post('/api/v1/vault/items/bulk-reencrypt')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', cookie1)
        .set('x-csrf-token', csrf1)
        .send({
          authHash: user.rawPassword,
          idempotencyKey,
          items: [
            {
              id,
              encryptedName: 'first-name',
              nameIv: 'first-niv',
              nameTag: 'first-ntag',
              encryptedData: 'first-data',
              dataIv: 'first-div',
              dataTag: 'first-dtag',
            },
          ],
          newEncryptedVaultKey: 'first-vk',
          newVaultKeyIv: 'first-viv',
          newVaultKeyTag: 'first-vtag',
        })
        .expect(200);

      // Second request — same idempotencyKey, different data
      const agent2 = request.agent(app);
      const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent2);

      const res = await agent2
        .post('/api/v1/vault/items/bulk-reencrypt')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', cookie2)
        .set('x-csrf-token', csrf2)
        .send({
          authHash: user.rawPassword,
          idempotencyKey,
          items: [
            {
              id,
              encryptedName: 'second-name',
              nameIv: 'second-niv',
              nameTag: 'second-ntag',
              encryptedData: 'second-data',
              dataIv: 'second-div',
              dataTag: 'second-dtag',
            },
          ],
          newEncryptedVaultKey: 'second-vk',
          newVaultKeyIv: 'second-viv',
          newVaultKeyTag: 'second-vtag',
        })
        .expect(200);

      expect(res.body.success).toBe(true);

      // Verify the item still has the FIRST rotation's data (not re-processed)
      const item = await VaultItem.findById(id);
      expect(item!.encryptedName).toBe('first-name');
      expect(item!.encryptedData).toBe('first-data');

      // Verify vault key still has the first rotation's value
      const updatedUser = await mongoose.model('User').findById(user.id);
      expect(updatedUser!.encryptedVaultKey).toBe('first-vk');
    });

    it('should process normally without idempotencyKey (backward compatible)', async () => {
      const { id } = await createItemViaApi(user.accessToken);

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/vault/items/bulk-reencrypt')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({
          authHash: user.rawPassword,
          items: [
            {
              id,
              encryptedName: 'no-key-name',
              nameIv: 'no-key-niv',
              nameTag: 'no-key-ntag',
              encryptedData: 'no-key-data',
              dataIv: 'no-key-div',
              dataTag: 'no-key-dtag',
            },
          ],
          newEncryptedVaultKey: 'no-key-vk',
          newVaultKeyIv: 'no-key-viv',
          newVaultKeyTag: 'no-key-vtag',
        })
        .expect(200);

      expect(res.body.success).toBe(true);

      // Verify items were updated
      const item = await VaultItem.findById(id);
      expect(item!.encryptedName).toBe('no-key-name');

      // Verify lastRotationKey was NOT set
      const updatedUser = await mongoose.model('User').findById(user.id);
      expect(updatedUser!.lastRotationKey).toBeUndefined();
    });

    it('should re-encrypt passwordHistory entries during vault key rotation', async () => {
      // Create an item with passwordHistory
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const createRes = await agent
        .post('/api/v1/vault/items')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send(sampleVaultItem())
        .expect(201);

      const itemId = (createRes.body as { data: { _id: string } }).data._id;

      // Manually add passwordHistory via direct DB update
      await VaultItem.updateOne(
        { _id: itemId },
        {
          $set: {
            passwordHistory: [
              {
                encryptedPassword: 'old-enc-pw-1',
                iv: 'old-pw-iv-1',
                tag: 'old-pw-tag-1',
                changedAt: new Date(),
              },
              {
                encryptedPassword: 'old-enc-pw-2',
                iv: 'old-pw-iv-2',
                tag: 'old-pw-tag-2',
                changedAt: new Date(),
              },
            ],
          },
        },
      );

      // Now rotate vault key, including re-encrypted passwordHistory
      const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/vault/items/bulk-reencrypt')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', cookie2)
        .set('x-csrf-token', csrf2)
        .send({
          authHash: user.rawPassword,
          items: [
            {
              id: itemId,
              encryptedName: 'rotated-name',
              nameIv: 'rotated-niv',
              nameTag: 'rotated-ntag',
              encryptedData: 'rotated-data',
              dataIv: 'rotated-div',
              dataTag: 'rotated-dtag',
              passwordHistory: [
                {
                  encryptedPassword: 'new-enc-pw-1',
                  iv: 'new-pw-iv-1',
                  tag: 'new-pw-tag-1',
                  changedAt: new Date().toISOString(),
                },
                {
                  encryptedPassword: 'new-enc-pw-2',
                  iv: 'new-pw-iv-2',
                  tag: 'new-pw-tag-2',
                  changedAt: new Date().toISOString(),
                },
              ],
            },
          ],
          newEncryptedVaultKey: 'rotated-vk',
          newVaultKeyIv: 'rotated-viv',
          newVaultKeyTag: 'rotated-vtag',
        })
        .expect(200);

      expect(res.body.success).toBe(true);

      // Verify passwordHistory was updated with new encrypted values
      const updatedItem = await VaultItem.findById(itemId);
      expect(updatedItem!.passwordHistory).toHaveLength(2);
      expect(updatedItem!.passwordHistory![0]!.encryptedPassword).toBe('new-enc-pw-1');
      expect(updatedItem!.passwordHistory![0]!.iv).toBe('new-pw-iv-1');
      expect(updatedItem!.passwordHistory![0]!.tag).toBe('new-pw-tag-1');
      expect(updatedItem!.passwordHistory![1]!.encryptedPassword).toBe('new-enc-pw-2');
    });

    it('should not modify passwordHistory when not provided in bulk-reencrypt item', async () => {
      const { id } = await createItemViaApi(user.accessToken);

      // Manually add passwordHistory
      await VaultItem.updateOne(
        { _id: id },
        {
          $set: {
            passwordHistory: [
              {
                encryptedPassword: 'existing-enc-pw',
                iv: 'existing-iv',
                tag: 'existing-tag',
                changedAt: new Date(),
              },
            ],
          },
        },
      );

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      // Rotate without providing passwordHistory (backward compatible)
      await agent
        .post('/api/v1/vault/items/bulk-reencrypt')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({
          authHash: user.rawPassword,
          items: [
            {
              id,
              encryptedName: 'new-name',
              nameIv: 'new-niv',
              nameTag: 'new-ntag',
              encryptedData: 'new-data',
              dataIv: 'new-div',
              dataTag: 'new-dtag',
            },
          ],
          newEncryptedVaultKey: 'new-vk',
          newVaultKeyIv: 'new-viv',
          newVaultKeyTag: 'new-vtag',
        })
        .expect(200);

      // passwordHistory should remain unchanged (not overwritten with undefined)
      const item = await VaultItem.findById(id);
      expect(item!.passwordHistory).toHaveLength(1);
      expect(item!.passwordHistory![0]!.encryptedPassword).toBe('existing-enc-pw');
    });

    it('should set and clear rotationInProgress during sequential fallback', async () => {
      // In the test environment, mongodb-memory-server is standalone (no replica set),
      // so vault key rotation always falls back to sequential updates.
      const { id } = await createItemViaApi(user.accessToken);

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/vault/items/bulk-reencrypt')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({
          authHash: user.rawPassword,
          items: [
            {
              id,
              encryptedName: 'seq-name',
              nameIv: 'seq-niv',
              nameTag: 'seq-ntag',
              encryptedData: 'seq-data',
              dataIv: 'seq-div',
              dataTag: 'seq-dtag',
            },
          ],
          newEncryptedVaultKey: 'seq-vk',
          newVaultKeyIv: 'seq-viv',
          newVaultKeyTag: 'seq-vtag',
        })
        .expect(200);

      expect(res.body.success).toBe(true);

      // After successful rotation, rotationInProgress should be false
      const updatedUser = await mongoose.model('User').findById(user.id);
      expect(updatedUser!.rotationInProgress).toBe(false);
      // pendingEncryptedVaultKey should be cleared
      expect(updatedUser!.pendingEncryptedVaultKey).toBeUndefined();
      expect(updatedUser!.pendingVaultKeyIv).toBeUndefined();
      expect(updatedUser!.pendingVaultKeyTag).toBeUndefined();
      // Vault key should be updated
      expect(updatedUser!.encryptedVaultKey).toBe('seq-vk');
    });

    it('should create audit log on failed password verification for bulk-reencrypt', async () => {
      const { id } = await createItemViaApi(user.accessToken);

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .post('/api/v1/vault/items/bulk-reencrypt')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({
          authHash: 'wrong-password',
          items: [
            {
              id,
              encryptedName: 'x',
              nameIv: 'x',
              nameTag: 'x',
              encryptedData: 'x',
              dataIv: 'x',
              dataTag: 'x',
            },
          ],
          newEncryptedVaultKey: 'new-evk',
          newVaultKeyIv: 'new-iv',
          newVaultKeyTag: 'new-tag',
        })
        .expect(401);

      const auditEntry = await AuditLog.findOne({
        userId: user.id,
        action: 'password_verification_failed',
      });

      expect(auditEntry).toBeDefined();
      expect(auditEntry!.userId.toString()).toBe(user.id);
      expect((auditEntry!.metadata as Record<string, unknown>).endpoint).toBe('bulk_reencrypt');
    });

    // ── Body-size limit (route-level 30 MB override) ──────────────────

    it('accepts a rotation payload larger than the global 2 MB body limit (no 413)', async () => {
      // Create a handful of real items to rotate. The rotation payload below
      // re-encrypts them with large (but schema-legal) ciphertext so the
      // serialized request exceeds the global 2 MB JSON parser limit. Before the
      // route-level 30 MB parser was added (mirroring POST /backup/restore),
      // this request was rejected with HTTP 413 before validation/auth ran.
      const itemIds: string[] = [];
      for (let i = 0; i < 5; i++) {
        const { id } = await createItemViaApi(user.accessToken);
        itemIds.push(id);
      }

      // ~480 KB per item × 5 ≈ 2.4 MB — comfortably over the 2 MB global limit,
      // well under the 30 MB route limit and the 500 KB per-field schema cap.
      const largeData = 'a'.repeat(480_000);

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/vault/items/bulk-reencrypt')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({
          authHash: user.rawPassword,
          items: itemIds.map((id, i) => ({
            id,
            encryptedName: `rotated-name-${String(i)}`,
            nameIv: 'niv',
            nameTag: 'ntag',
            encryptedData: largeData,
            dataIv: 'div',
            dataTag: 'dtag',
          })),
          newEncryptedVaultKey: 'large-payload-vk',
          newVaultKeyIv: 'large-payload-viv',
          newVaultKeyTag: 'large-payload-vtag',
        });

      // Must be parsed and processed, not rejected with 413 Payload Too Large.
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      // The rotation actually applied (not merely parsed): vault key swapped and
      // the oversized ciphertext persisted.
      const updatedUser = await mongoose.model('User').findById(user.id);
      expect(updatedUser!.encryptedVaultKey).toBe('large-payload-vk');
      const firstItem = await VaultItem.findById(itemIds[0]);
      expect(firstItem!.encryptedData).toBe(largeData);
    });

    it('a realistically-sized maximum rotation payload is accepted by the 30 MB route limit (no 413)', async () => {
      // The schema permits up to 10,000 items and 1,000 folders. Their
      // theoretical field maxima (encryptedData up to MAX_ENCRYPTED_DATA_LENGTH)
      // are unbounded for transport purposes, but a real re-encrypted entry is a
      // few hundred bytes of AES-256-GCM base64 ciphertext. A full vault at the
      // schema's item/folder ceilings, sized like real ciphertext, serializes to
      // several MB — well over the global 2 MB parser limit and under the 30 MB
      // route override (mirroring POST /backup/restore).
      //
      // This test EXERCISES the route: it sends that large payload and asserts
      // the request is parsed (any status except 413), so shrinking or dropping
      // the route-level body-limit override would make it go red. authHash is
      // deliberately bogus, so the request is parsed then rejected at auth — the
      // point is only that Nginx/Express did not reject it at the parser as too
      // large.
      const oid = (): string => new mongoose.Types.ObjectId().toString();

      const items = Array.from({ length: 10_000 }, () => ({
        id: oid(),
        // Representative AES-256-GCM base64 sizes for a typical login record.
        encryptedName: 'n'.repeat(88),
        nameIv: 'i'.repeat(16),
        nameTag: 't'.repeat(24),
        encryptedData: 'd'.repeat(700),
        dataIv: 'i'.repeat(16),
        dataTag: 't'.repeat(24),
        searchHash: 'a'.repeat(64),
      }));
      const folders = Array.from({ length: 1_000 }, () => ({
        id: oid(),
        encryptedName: 'n'.repeat(88),
        nameIv: 'i'.repeat(16),
        nameTag: 't'.repeat(24),
      }));

      const payload = {
        authHash: 'x'.repeat(60),
        idempotencyKey: '00000000-0000-4000-8000-000000000000',
        items,
        folders,
        newEncryptedVaultKey: 'k'.repeat(180),
        newVaultKeyIv: 'i'.repeat(16),
        newVaultKeyTag: 't'.repeat(24),
      };

      // Sanity: the payload is genuinely larger than the old 2 MB global limit
      // (so it would 413 without the route override) and under the 30 MB route
      // limit (so it must be accepted).
      const serializedBytes = Buffer.byteLength(JSON.stringify(payload), 'utf8');
      expect(serializedBytes).toBeGreaterThan(2 * 1024 * 1024);
      expect(serializedBytes).toBeLessThan(30 * 1024 * 1024);

      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/vault/items/bulk-reencrypt')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send(payload);

      // The route's 30 MB parser must accept this body: it may fail later (bogus
      // authHash → 401), but it must NOT be rejected as 413 Payload Too Large.
      expect(res.status).not.toBe(413);
      expect(res.status).toBe(401);
    });
  });

  // ========================================================================
  // Field allowlist defense-in-depth
  // ========================================================================

  describe('Field allowlist defense-in-depth', () => {
    it('should not persist attacker-controlled server-only fields on create', async () => {
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const foreignUserId = new mongoose.Types.ObjectId().toString();
      const forgedId = new mongoose.Types.ObjectId().toString();

      // Smuggle server-controlled fields into the create body. The end-to-end
      // mass-assignment defense (Zod .strip() + the controller field allowlist)
      // must ensure none of these are written from the request: ownership must
      // come from the authenticated user, and provenance/soft-delete/identity
      // fields must never be client-settable.
      const res = await agent
        .post('/api/v1/vault/items')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({
          ...sampleVaultItem(),
          userId: foreignUserId,
          _id: forgedId,
          deletedAt: new Date('2000-01-01T00:00:00.000Z').toISOString(),
          sourceRefId: 'attacker-provenance',
        })
        .expect(201);

      const itemId = res.body.data._id as string;
      // The forged _id must not have been honored.
      expect(itemId).not.toBe(forgedId);

      const item = await VaultItem.findById(itemId).lean();
      expect(item).not.toBeNull();
      expect(item!.itemType).toBe('login');
      expect(item!.encryptedData).toBe('test-encrypted-data-base64');
      // Ownership is bound to the authenticated user, NOT the smuggled userId.
      expect(item!.userId.toString()).toBe(user.id);
      expect(item!.userId.toString()).not.toBe(foreignUserId);
      // Soft-delete and restore-provenance fields were not written from the body.
      expect(item!.deletedAt).toBeUndefined();
      expect(item!.sourceRefId).toBeUndefined();
    });

    it('should not persist attacker-controlled server-only fields on update', async () => {
      const { id } = await createItemViaApi(user.accessToken);
      const agent = request.agent(app);
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const foreignUserId = new mongoose.Types.ObjectId().toString();

      const res = await agent
        .put(`/api/v1/vault/items/${id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrfCookie)
        .set('x-csrf-token', csrfToken)
        .send({
          encryptedData: 'updated-data',
          dataIv: 'updated-iv',
          dataTag: 'updated-tag',
          favorite: true,
          // Smuggled server-only fields that must never be written from the body.
          userId: foreignUserId,
          deletedAt: new Date('2000-01-01T00:00:00.000Z').toISOString(),
          sourceRefId: 'attacker-provenance',
        })
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.data.encryptedData).toBe('updated-data');
      expect(res.body.data.favorite).toBe(true);
      // userId is intentionally absent from API responses (server-only field).
      expect(res.body.data.userId).toBeUndefined();

      const persisted = await VaultItem.findById(id);
      expect(persisted).not.toBeNull();
      // Ownership unchanged; the item was not re-assigned to the foreign user
      // and was not soft-deleted / re-stamped with provenance via the body.
      expect(persisted!.userId.toString()).toBe(user.id);
      expect(persisted!.userId.toString()).not.toBe(foreignUserId);
      expect(persisted!.deletedAt).toBeUndefined();
      expect(persisted!.sourceRefId).toBeUndefined();
    });
  });
});
