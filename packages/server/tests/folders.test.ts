import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import app from '../src/app.js';
import { Folder } from '../src/models/Folder.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { AuditLog } from '../src/models/AuditLog.js';
import {
  createTestUser,
  authHeader,
  sampleFolder,
  sampleVaultItem,
  getCsrf,
  type TestUser,
} from './helpers.js';

// ── Constants ──────────────────────────────────────────────────────────

const BASE = '/api/v1/folders';

// ── Test Suite ─────────────────────────────────────────────────────────

describe('Folder Routes', () => {
  let user: TestUser;
  let agent: request.Agent;
  let csrf: { cookie: string; token: string };

  beforeEach(async () => {
    user = await createTestUser();
    agent = request.agent(app);
    csrf = await getCsrf(agent);
  });

  // ── Helpers ────────────────────────────────────────────────────────

  /** Create a folder via the API and return the response body data. */
  async function apiCreateFolder(overrides: Record<string, unknown> = {}) {
    const res = await agent
      .post(BASE)
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', csrf.cookie)
      .set('x-csrf-token', csrf.token)
      .send(sampleFolder(overrides));
    expect(res.status).toBe(201);
    return res.body.data;
  }

  // ── 1. CRUD ────────────────────────────────────────────────────────

  describe('CRUD Operations', () => {
    it('should create a folder and return 201', async () => {
      const body = sampleFolder({ icon: 'lock', color: '#ff0000' });

      const res = await agent
        .post(BASE)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send(body);

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toMatchObject({
        encryptedName: body.encryptedName,
        nameIv: body.nameIv,
        nameTag: body.nameTag,
        icon: 'lock',
        color: '#ff0000',
        sortOrder: 0,
      });
      expect(res.body.data._id).toBeDefined();
      // userId is intentionally absent from API responses (server-only field).
      expect(res.body.data.userId).toBeUndefined();
      const persisted = await Folder.findById(res.body.data._id as string);
      expect(persisted?.userId.toString()).toBe(user.id);
    });

    it('should create a folder with a parentId', async () => {
      const parent = await apiCreateFolder({ encryptedName: 'parent-enc' });

      const child = await apiCreateFolder({
        encryptedName: 'child-enc',
        parentId: parent._id,
      });

      expect(child.parentId).toBe(parent._id);
    });

    it('should list all folders for the authenticated user', async () => {
      await apiCreateFolder({ encryptedName: 'folder-a' });
      await apiCreateFolder({ encryptedName: 'folder-b' });

      const res = await agent.get(BASE).set('Authorization', authHeader(user.accessToken));

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveLength(2);
    });

    it('should return an empty array when user has no folders', async () => {
      const res = await agent.get(BASE).set('Authorization', authHeader(user.accessToken));

      expect(res.status).toBe(200);
      expect(res.body.data).toEqual([]);
    });

    it('should update a folder name', async () => {
      const folder = await apiCreateFolder();

      const res = await agent
        .put(`${BASE}/${folder._id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({
          encryptedName: 'updated-encrypted-name',
          nameIv: 'updated-iv',
          nameTag: 'updated-tag',
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.encryptedName).toBe('updated-encrypted-name');
      expect(res.body.data.nameIv).toBe('updated-iv');
      expect(res.body.data.nameTag).toBe('updated-tag');
    });

    it('should update folder icon and color', async () => {
      const folder = await apiCreateFolder();

      const res = await agent
        .put(`${BASE}/${folder._id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ icon: 'star', color: '#00ff00' });

      expect(res.status).toBe(200);
      expect(res.body.data.icon).toBe('star');
      expect(res.body.data.color).toBe('#00ff00');
    });

    it('should $unset parentId when updated to null (not store as null)', async () => {
      // Nest a child under a parent, then promote the child to root by
      // sending parentId: null in the update.
      const parent = await apiCreateFolder({ encryptedName: 'parent-enc' });
      const child = await apiCreateFolder({
        encryptedName: 'child-enc',
        parentId: parent._id,
      });

      // Sanity-check: child has a populated parentId.
      const beforeRaw = await mongoose.connection
        .db!.collection('folders')
        .findOne({ _id: new mongoose.Types.ObjectId(child._id) });
      expect(beforeRaw?.parentId).toBeTruthy();

      const res = await agent
        .put(`${BASE}/${child._id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ parentId: null });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      // The field must be removed from the BSON document, not stored as `null`.
      // Mirrors deleteFolder's $unset behaviour for child folder reassignment.
      const rawDoc = await mongoose.connection
        .db!.collection('folders')
        .findOne({ _id: new mongoose.Types.ObjectId(child._id) });
      expect(rawDoc).toBeTruthy();
      expect('parentId' in rawDoc!).toBe(false);
    });

    it('should delete a folder and return 200', async () => {
      const folder = await apiCreateFolder();

      const res = await agent
        .delete(`${BASE}/${folder._id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.message).toBe('Folder deleted');

      // Verify the folder is gone
      const dbFolder = await Folder.findById(folder._id);
      expect(dbFolder).toBeNull();
    });
  });

  // ── 2. Reorder ─────────────────────────────────────────────────────

  describe('Reorder (PUT /:id/sort)', () => {
    it('should update the sortOrder of a folder', async () => {
      const folder = await apiCreateFolder();
      expect(folder.sortOrder).toBe(0);

      const res = await agent
        .put(`${BASE}/${folder._id}/sort`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ sortOrder: 5 });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.sortOrder).toBe(5);
    });

    it('should persist the new sortOrder in the database', async () => {
      const folder = await apiCreateFolder();

      await agent
        .put(`${BASE}/${folder._id}/sort`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ sortOrder: 10 });

      const dbFolder = await Folder.findById(folder._id).lean();
      expect(dbFolder!.sortOrder).toBe(10);
    });

    it('should list folders sorted by sortOrder', async () => {
      const folderA = await apiCreateFolder({ encryptedName: 'a', sortOrder: 2 });
      const folderB = await apiCreateFolder({ encryptedName: 'b', sortOrder: 0 });
      const folderC = await apiCreateFolder({ encryptedName: 'c', sortOrder: 1 });

      const res = await agent.get(BASE).set('Authorization', authHeader(user.accessToken));

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(3);
      expect(res.body.data[0]._id).toBe(folderB._id);
      expect(res.body.data[1]._id).toBe(folderC._id);
      expect(res.body.data[2]._id).toBe(folderA._id);
    });

    it('should return 404 when reordering a non-existent folder', async () => {
      const fakeId = new mongoose.Types.ObjectId().toString();

      const res = await agent
        .put(`${BASE}/${fakeId}/sort`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ sortOrder: 1 });

      expect(res.status).toBe(404);
    });
  });

  // ── 3. Delete cascade (action=delete) ──────────────────────────────

  describe('Delete with action=delete', () => {
    it('should delete all vault items in the folder', async () => {
      const folder = await apiCreateFolder();

      // Create items inside the folder directly in DB
      await VaultItem.create({
        ...sampleVaultItem({ folderId: folder._id }),
        userId: user.id,
      });
      await VaultItem.create({
        ...sampleVaultItem({ folderId: folder._id }),
        userId: user.id,
      });

      // Verify items exist
      const beforeCount = await VaultItem.countDocuments({ folderId: folder._id });
      expect(beforeCount).toBe(2);

      const res = await agent
        .delete(`${BASE}/${folder._id}?action=delete`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token);

      expect(res.status).toBe(200);

      // Verify items are soft-deleted (moved to trash, not hard-deleted)
      const afterCount = await VaultItem.countDocuments({ folderId: folder._id, deletedAt: null });
      expect(afterCount).toBe(0);

      // Verify the items still exist in DB with deletedAt set
      const trashedCount = await VaultItem.countDocuments({
        folderId: folder._id,
        deletedAt: { $ne: null },
      });
      expect(trashedCount).toBe(2);
    });

    it('should move child folders to the parent when action=delete', async () => {
      const parent = await apiCreateFolder({ encryptedName: 'parent' });
      const target = await apiCreateFolder({ encryptedName: 'target', parentId: parent._id });
      const child = await apiCreateFolder({ encryptedName: 'child', parentId: target._id });

      // Delete the target folder with action=delete
      const res = await agent
        .delete(`${BASE}/${target._id}?action=delete`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token);

      expect(res.status).toBe(200);

      // Child should now be under parent
      const updatedChild = await Folder.findById(child._id).lean();
      expect(updatedChild).toBeDefined();
      expect(updatedChild!.parentId!.toString()).toBe(parent._id);
    });

    it('should move child folders to root when deleted folder has no parent', async () => {
      const target = await apiCreateFolder({ encryptedName: 'root-target' });
      const child = await apiCreateFolder({ encryptedName: 'child', parentId: target._id });

      await agent
        .delete(`${BASE}/${target._id}?action=delete`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token);

      const updatedChild = await Folder.findById(child._id).lean();
      expect(updatedChild).toBeDefined();
      expect(updatedChild!.parentId).toBeUndefined();
    });

    it('should not affect items in other folders', async () => {
      const folderA = await apiCreateFolder({ encryptedName: 'a' });
      const folderB = await apiCreateFolder({ encryptedName: 'b' });

      await VaultItem.create({
        ...sampleVaultItem({ folderId: folderA._id }),
        userId: user.id,
      });
      await VaultItem.create({
        ...sampleVaultItem({ folderId: folderB._id }),
        userId: user.id,
      });

      // Delete folder A with action=delete
      await agent
        .delete(`${BASE}/${folderA._id}?action=delete`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token);

      // Folder B items should be unaffected
      const remainingItems = await VaultItem.countDocuments({ folderId: folderB._id });
      expect(remainingItems).toBe(1);
    });
  });

  // ── 4. Delete with move (action=move, the default) ─────────────────

  describe('Delete with action=move (default)', () => {
    it('should move items to the parent folder', async () => {
      const parent = await apiCreateFolder({ encryptedName: 'parent' });
      const child = await apiCreateFolder({
        encryptedName: 'child',
        parentId: parent._id,
      });

      await VaultItem.create({
        ...sampleVaultItem({ folderId: child._id }),
        userId: user.id,
      });

      // Delete child folder with default action (move)
      const res = await agent
        .delete(`${BASE}/${child._id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token);

      expect(res.status).toBe(200);

      // Item should have moved to parent
      const items = await VaultItem.find({ userId: user.id }).lean();
      expect(items).toHaveLength(1);
      expect(items[0].folderId!.toString()).toBe(parent._id);
    });

    it('should move items to root when folder has no parent', async () => {
      const folder = await apiCreateFolder();

      await VaultItem.create({
        ...sampleVaultItem({ folderId: folder._id }),
        userId: user.id,
      });

      await agent
        .delete(`${BASE}/${folder._id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token);

      // Item should now have no folderId (root)
      const items = await VaultItem.find({ userId: user.id }).lean();
      expect(items).toHaveLength(1);
      expect(items[0].folderId).toBeUndefined();
    });

    it('should move child folders to the parent', async () => {
      const grandparent = await apiCreateFolder({ encryptedName: 'grandparent' });
      const parent = await apiCreateFolder({
        encryptedName: 'parent',
        parentId: grandparent._id,
      });
      const child = await apiCreateFolder({
        encryptedName: 'child',
        parentId: parent._id,
      });

      // Delete parent folder
      await agent
        .delete(`${BASE}/${parent._id}?action=move`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token);

      // Child should now be under grandparent
      const updatedChild = await Folder.findById(child._id).lean();
      expect(updatedChild).toBeDefined();
      expect(updatedChild!.parentId!.toString()).toBe(grandparent._id);
    });

    it('should move child folders to root when deleted folder has no parent', async () => {
      const rootFolder = await apiCreateFolder({ encryptedName: 'root' });
      const child = await apiCreateFolder({
        encryptedName: 'child',
        parentId: rootFolder._id,
      });

      await agent
        .delete(`${BASE}/${rootFolder._id}?action=move`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token);

      const updatedChild = await Folder.findById(child._id).lean();
      expect(updatedChild).toBeDefined();
      expect(updatedChild!.parentId).toBeUndefined();
    });

    it('should not delete items when using default move action', async () => {
      const folder = await apiCreateFolder();

      await VaultItem.create({
        ...sampleVaultItem({ folderId: folder._id }),
        userId: user.id,
      });
      await VaultItem.create({
        ...sampleVaultItem({ folderId: folder._id }),
        userId: user.id,
      });

      await agent
        .delete(`${BASE}/${folder._id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token);

      // Items should still exist, just not in any folder
      const items = await VaultItem.find({ userId: user.id }).lean();
      expect(items).toHaveLength(2);
      items.forEach((item) => {
        expect(item.folderId).toBeUndefined();
      });
    });
  });

  // NOTE: the "Delete with invalid action query param" block previously here held
  // a single weaker "should reject an invalid action value" test (asserting only
  // `status >= 400`) for the same `?action=invalid` request that the stronger
  // "should reject invalid action query parameter with 400" test (`=== 400` plus
  // `body.success === false`, further below) already covers exactly. The weaker
  // duplicate — and its now-empty describe block — were removed.

  // ── 5. Circular Reference Prevention ───────────────────────────────

  describe('Circular Reference Prevention', () => {
    it('should reject updating a folder to be its own parent', async () => {
      const folder = await apiCreateFolder({ encryptedName: 'self-ref' });

      const res = await agent
        .put(`${BASE}/${folder._id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ parentId: folder._id });

      expect(res.status).toBe(400);
    });

    it('should reject parentId === id without running the $graphLookup aggregation', async () => {
      const folder = await apiCreateFolder({ encryptedName: 'self-ref-fast' });
      const aggregateSpy = vi.spyOn(Folder, 'aggregate');
      const existsSpy = vi.spyOn(Folder, 'exists');

      try {
        const res = await agent
          .put(`${BASE}/${folder._id}`)
          .set('Authorization', authHeader(user.accessToken))
          .set('Cookie', csrf.cookie)
          .set('x-csrf-token', csrf.token)
          .send({ parentId: folder._id });

        expect(res.status).toBe(400);
        expect(res.body.success).toBe(false);
        expect(res.body.message).toContain('A folder cannot be its own parent');
        expect(aggregateSpy).not.toHaveBeenCalled();
        expect(existsSpy).not.toHaveBeenCalled();
      } finally {
        aggregateSpy.mockRestore();
        existsSpy.mockRestore();
      }
    });

    it('should reject self-parent when the route :id is UPPER-CASE hex', async () => {
      // `validateObjectId` accepts upper-case hex and passes it through raw,
      // while `objectIdSchema` lowercases `body.parentId`. The self-parent guard
      // must still fire regardless of the :id hex case (case-normalization fix).
      const folder = await apiCreateFolder({ encryptedName: 'self-ref-upper' });

      const res = await agent
        .put(`${BASE}/${(folder._id as string).toUpperCase()}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ parentId: folder._id });

      expect(res.status).toBe(400);
      expect(res.body.message).toContain('A folder cannot be its own parent');

      // The self-parent must NOT have been persisted.
      const persisted = await Folder.findById(folder._id as string).lean();
      expect(persisted?.parentId).toBeUndefined();
    });

    it('should reject a 2-node cycle when the route :id is UPPER-CASE hex', async () => {
      // A -> B (B's parent is A). Attempting to set A's parent to B via an
      // UPPER-CASE :id must still be detected as a cycle after lowercasing.
      const folderA = await apiCreateFolder({ encryptedName: 'a-upper' });
      const folderB = await apiCreateFolder({ encryptedName: 'b-upper', parentId: folderA._id });

      const res = await agent
        .put(`${BASE}/${(folderA._id as string).toUpperCase()}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ parentId: folderB._id });

      expect(res.status).toBe(400);
      expect(res.body.message).toContain('Circular folder reference detected');

      // The cycle must NOT have been persisted.
      const persisted = await Folder.findById(folderA._id as string).lean();
      expect(persisted?.parentId).toBeUndefined();
    });

    it('should reject an indirect circular reference (A -> B -> A)', async () => {
      const folderA = await apiCreateFolder({ encryptedName: 'a' });
      const folderB = await apiCreateFolder({ encryptedName: 'b', parentId: folderA._id });

      // Try to set A's parent to B (creating A -> B -> A)
      const res = await agent
        .put(`${BASE}/${folderA._id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ parentId: folderB._id });

      expect(res.status).toBe(400);
    });

    it('should reject a deep circular reference (A -> B -> C -> A)', async () => {
      const folderA = await apiCreateFolder({ encryptedName: 'a' });
      const folderB = await apiCreateFolder({ encryptedName: 'b', parentId: folderA._id });
      const folderC = await apiCreateFolder({ encryptedName: 'c', parentId: folderB._id });

      // Try to set A's parent to C (creating A -> B -> C -> A)
      const res = await agent
        .put(`${BASE}/${folderA._id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ parentId: folderC._id });

      expect(res.status).toBe(400);
    });

    it('should allow valid parent updates (no circular reference)', async () => {
      const folderA = await apiCreateFolder({ encryptedName: 'a' });
      const folderB = await apiCreateFolder({ encryptedName: 'b' });

      // Setting B's parent to A is fine (no cycle)
      const res = await agent
        .put(`${BASE}/${folderB._id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ parentId: folderA._id });

      expect(res.status).toBe(200);
      expect(res.body.data.parentId).toBe(folderA._id);
    });

    it('should reject a deeply nested folder chain exceeding MAX_FOLDER_DEPTH (50)', async () => {
      // Create a chain of 55 folders directly in DB to exceed the MAX_FOLDER_DEPTH limit
      const folderIds: string[] = [];
      for (let i = 0; i < 55; i++) {
        const folder = await Folder.create({
          userId: user.id,
          encryptedName: `deep-folder-${i}`,
          nameIv: `iv-${i}`,
          nameTag: `tag-${i}`,
          parentId: i > 0 ? folderIds[i - 1] : undefined,
        });
        folderIds.push(folder._id.toString());
      }

      // Create a separate folder to try to move into the deep chain
      const targetFolder = await apiCreateFolder({ encryptedName: 'target' });

      // Try to set the target folder's parent to the last folder in the deep chain.
      // The depth traversal should exceed MAX_FOLDER_DEPTH and be treated as circular.
      const res = await agent
        .put(`${BASE}/${targetFolder._id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ parentId: folderIds[folderIds.length - 1] });

      expect(res.status).toBe(400);
    });

    it('should reject creating a folder under a deeply nested chain exceeding MAX_FOLDER_DEPTH', async () => {
      // Create a chain of 51 folders directly in DB
      const folderIds: string[] = [];
      for (let i = 0; i < 51; i++) {
        const folder = await Folder.create({
          userId: user.id,
          encryptedName: `create-deep-${i}`,
          nameIv: `iv-${i}`,
          nameTag: `tag-${i}`,
          parentId: i > 0 ? folderIds[i - 1] : undefined,
        });
        folderIds.push(folder._id.toString());
      }

      // Try to create a new folder under the deepest folder in the chain
      const res = await agent
        .post(BASE)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({
          encryptedName: 'too-deep',
          nameIv: 'iv',
          nameTag: 'tag',
          parentId: folderIds[folderIds.length - 1],
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should allow creating a folder at a valid depth', async () => {
      const parentFolder = await apiCreateFolder({ encryptedName: 'valid-parent' });

      const res = await agent
        .post(BASE)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({
          encryptedName: 'valid-child',
          nameIv: 'iv',
          nameTag: 'tag',
          parentId: parentFolder._id,
        });

      expect(res.status).toBe(201);
    });

    it('resolves the ancestor chain via a single $graphLookup aggregation, not an N+1 findOne walk', async () => {
      // Create a root folder (no parentId) and a child two levels deep.
      const rootFolder = await apiCreateFolder({ encryptedName: 'root' });
      const childFolder = await apiCreateFolder({
        encryptedName: 'child',
        parentId: rootFolder._id,
      });
      const target = await apiCreateFolder({ encryptedName: 'target' });

      // Spy AFTER the setup creates are done so only the re-parent's queries count.
      const aggregateSpy = vi.spyOn(Folder, 'aggregate');

      try {
        // Move `target` under `childFolder` (resulting depth = 3, within the cap).
        const res = await agent
          .put(`${BASE}/${target._id}`)
          .set('Authorization', authHeader(user.accessToken))
          .set('Cookie', csrf.cookie)
          .set('x-csrf-token', csrf.token)
          .send({ parentId: childFolder._id });

        expect(res.status).toBe(200);
        expect(res.body.data.parentId).toBe(childFolder._id);

        // The move must actually PERSIST — the original test asserted only a 200
        // and never re-read the row, so a handler that returned 200 without
        // writing (or wrote the wrong parent) went undetected.
        const persisted = await Folder.findById(target._id as string).lean();
        expect(persisted).not.toBeNull();
        expect(String(persisted!.parentId)).toBe(childFolder._id);

        // The ancestor chain is resolved by `$graphLookup` (Folder.aggregate) in a
        // single query per traversal — `getAncestorChain` + `getSubtreeHeight` +
        // the post-write `hasCycle` re-check. If `getAncestorChain`/`hasCycle`
        // regressed to a per-level N+1 `findOne` walk, the aggregate count drops
        // below this floor.
        expect(aggregateSpy.mock.calls.length).toBeGreaterThanOrEqual(2);
      } finally {
        aggregateSpy.mockRestore();
      }
    });
  });

  // ── 5b. Standalone MongoDB (no replica set) ─────────────────────────

  describe('Standalone MongoDB (no replica set)', () => {
    it('should delete a folder successfully without transactions on standalone MongoDB', async () => {
      // mongodb-memory-server runs standalone (no replica set), so this test
      // exercises the non-transactional fallback path after the optional chaining fix.
      const folder = await apiCreateFolder({ encryptedName: 'standalone-test' });

      await VaultItem.create({
        ...sampleVaultItem({ folderId: folder._id }),
        userId: user.id,
      });

      const res = await agent
        .delete(`${BASE}/${folder._id}?action=delete`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      // Folder should be deleted
      const dbFolder = await Folder.findById(folder._id);
      expect(dbFolder).toBeNull();

      // Items should be soft-deleted
      const trashedItems = await VaultItem.countDocuments({
        folderId: folder._id,
        deletedAt: { $ne: null },
      });
      expect(trashedItems).toBe(1);
    });

    it('should delete a folder with move action on standalone MongoDB', async () => {
      const parent = await apiCreateFolder({ encryptedName: 'parent-standalone' });
      const child = await apiCreateFolder({
        encryptedName: 'child-standalone',
        parentId: parent._id,
      });

      await VaultItem.create({
        ...sampleVaultItem({ folderId: child._id }),
        userId: user.id,
      });

      const res = await agent
        .delete(`${BASE}/${child._id}?action=move`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token);

      expect(res.status).toBe(200);

      // Items should be moved to parent folder
      const items = await VaultItem.find({ userId: user.id }).lean();
      expect(items).toHaveLength(1);
      expect(items[0].folderId!.toString()).toBe(parent._id);
    });

    it('should delete an empty folder on standalone MongoDB without errors', async () => {
      const folder = await apiCreateFolder({ encryptedName: 'empty-standalone' });

      const res = await agent
        .delete(`${BASE}/${folder._id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      const dbFolder = await Folder.findById(folder._id);
      expect(dbFolder).toBeNull();
    });

    it('should reparent child folders on standalone MongoDB delete', async () => {
      const parent = await apiCreateFolder({ encryptedName: 'grandparent-standalone' });
      const target = await apiCreateFolder({
        encryptedName: 'target-standalone',
        parentId: parent._id,
      });
      const child = await apiCreateFolder({
        encryptedName: 'grandchild-standalone',
        parentId: target._id,
      });

      const res = await agent
        .delete(`${BASE}/${target._id}?action=move`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token);

      expect(res.status).toBe(200);

      // Child should now be under parent (grandparent)
      const updatedChild = await Folder.findById(child._id).lean();
      expect(updatedChild).toBeDefined();
      expect(updatedChild!.parentId!.toString()).toBe(parent._id);

      // Target folder should be deleted
      const deletedTarget = await Folder.findById(target._id);
      expect(deletedTarget).toBeNull();
    });
  });

  // ── 6. Auth Guards ──────────────────────────────────────────────────

  describe('Authentication Guards', () => {
    it('GET /folders returns 401 without token', async () => {
      const res = await request(app).get(BASE);
      expect(res.status).toBe(401);
    });

    it('POST /folders returns 401 without token', async () => {
      const res = await agent
        .post(BASE)
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send(sampleFolder());

      expect(res.status).toBe(401);
    });

    it('PUT /folders/:id returns 401 without token', async () => {
      const fakeId = new mongoose.Types.ObjectId().toString();

      const res = await agent
        .put(`${BASE}/${fakeId}`)
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ encryptedName: 'x', nameIv: 'y', nameTag: 'z' });

      expect(res.status).toBe(401);
    });

    it('DELETE /folders/:id returns 401 without token', async () => {
      const fakeId = new mongoose.Types.ObjectId().toString();

      const res = await agent
        .delete(`${BASE}/${fakeId}`)
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token);

      expect(res.status).toBe(401);
    });

    it('PUT /folders/:id/sort returns 401 without token', async () => {
      const fakeId = new mongoose.Types.ObjectId().toString();

      const res = await agent
        .put(`${BASE}/${fakeId}/sort`)
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ sortOrder: 1 });

      expect(res.status).toBe(401);
    });
  });

  // ── 6. Not Found ───────────────────────────────────────────────────

  describe('Not Found (404)', () => {
    it('should return 404 when updating a non-existent folder', async () => {
      const fakeId = new mongoose.Types.ObjectId().toString();

      const res = await agent
        .put(`${BASE}/${fakeId}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ encryptedName: 'x', nameIv: 'y', nameTag: 'z' });

      expect(res.status).toBe(404);
    });

    it('should return 404 when deleting a non-existent folder', async () => {
      const fakeId = new mongoose.Types.ObjectId().toString();

      const res = await agent
        .delete(`${BASE}/${fakeId}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token);

      expect(res.status).toBe(404);
    });

    // NOTE: a duplicate "should return 404 when reordering a non-existent folder"
    // test was removed here — it was byte-for-byte equivalent to the one in the
    // reorder describe block above (same request, same single 404 assertion),
    // adding runtime and no signal.
  });

  // ── 7. User Isolation ──────────────────────────────────────────────

  describe('User Isolation', () => {
    let userB: TestUser;
    let csrfB: { cookie: string; token: string };
    let agentB: request.Agent;

    beforeEach(async () => {
      userB = await createTestUser({ email: 'userb@example.com' });
      agentB = request.agent(app);
      csrfB = await getCsrf(agentB);
    });

    it('user B should not see user A folders in list', async () => {
      // User A creates a folder
      await apiCreateFolder({ encryptedName: 'user-a-folder' });

      // User B lists folders
      const res = await agentB.get(BASE).set('Authorization', authHeader(userB.accessToken));

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(0);
    });

    it('user B should not be able to update user A folder', async () => {
      const folderA = await apiCreateFolder({ encryptedName: 'private-folder' });

      const res = await agentB
        .put(`${BASE}/${folderA._id}`)
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrfB.cookie)
        .set('x-csrf-token', csrfB.token)
        .send({ encryptedName: 'hacked', nameIv: 'hacked-iv', nameTag: 'hacked-tag' });

      expect(res.status).toBe(404);

      // Verify original folder is unchanged
      const original = await Folder.findById(folderA._id).lean();
      expect(original!.encryptedName).toBe('private-folder');
    });

    it('user B should not be able to delete user A folder', async () => {
      const folderA = await apiCreateFolder({ encryptedName: 'protected-folder' });

      const res = await agentB
        .delete(`${BASE}/${folderA._id}`)
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrfB.cookie)
        .set('x-csrf-token', csrfB.token);

      expect(res.status).toBe(404);

      // Verify folder still exists AND is unchanged. `findById` returns null on a
      // miss, and `expect(null).toBeDefined()` PASSES — so a regression that
      // dropped the `userId` scope (letting user B actually delete user A's
      // folder) would go undetected. Assert the document survived with its
      // content intact, mirroring the sibling update-isolation test above.
      const folder = await Folder.findById(folderA._id).lean();
      expect(folder).not.toBeNull();
      expect(folder!.encryptedName).toBe('protected-folder');
    });

    it('user B should not be able to reorder user A folder', async () => {
      const folderA = await apiCreateFolder({ encryptedName: 'ordered-folder' });

      const res = await agentB
        .put(`${BASE}/${folderA._id}/sort`)
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrfB.cookie)
        .set('x-csrf-token', csrfB.token)
        .send({ sortOrder: 99 });

      expect(res.status).toBe(404);

      // Verify sortOrder is unchanged
      const folder = await Folder.findById(folderA._id).lean();
      expect(folder!.sortOrder).toBe(0);
    });

    it('each user should only see their own folders', async () => {
      // User A creates 2 folders
      await apiCreateFolder({ encryptedName: 'a-1' });
      await apiCreateFolder({ encryptedName: 'a-2' });

      // User B creates 1 folder
      await agentB
        .post(BASE)
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrfB.cookie)
        .set('x-csrf-token', csrfB.token)
        .send(sampleFolder({ encryptedName: 'b-1' }));

      // User A sees 2
      const resA = await agent.get(BASE).set('Authorization', authHeader(user.accessToken));
      expect(resA.body.data).toHaveLength(2);

      // User B sees 1
      const resB = await agentB.get(BASE).set('Authorization', authHeader(userB.accessToken));
      expect(resB.body.data).toHaveLength(1);
      expect(resB.body.data[0].encryptedName).toBe('b-1');
    });
  });

  // ── 8. Audit Logging ────────────────────────────────────────────────

  describe('Audit logging', () => {
    it('should create audit log on folder create', async () => {
      const folder = await apiCreateFolder({ encryptedName: 'audit-create' });

      const auditEntry = await AuditLog.findOne({
        userId: user.id,
        action: 'folder_create',
      });

      expect(auditEntry).toBeDefined();
      expect(auditEntry!.userId.toString()).toBe(user.id);
      expect(auditEntry!.metadata).toBeDefined();
      expect((auditEntry!.metadata as Record<string, unknown>).folderId).toBe(folder._id);
    });

    it('should create audit log on folder update', async () => {
      const folder = await apiCreateFolder({ encryptedName: 'audit-update' });

      await agent
        .put(`${BASE}/${folder._id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({
          encryptedName: 'updated-name',
          nameIv: 'updated-iv',
          nameTag: 'updated-tag',
        })
        .expect(200);

      const auditEntry = await AuditLog.findOne({
        userId: user.id,
        action: 'folder_update',
      });

      expect(auditEntry).toBeDefined();
      expect(auditEntry!.userId.toString()).toBe(user.id);
      expect(auditEntry!.metadata).toBeDefined();
      expect((auditEntry!.metadata as Record<string, unknown>).folderId).toBe(folder._id);
    });

    it('should create audit log on folder delete', async () => {
      const folder = await apiCreateFolder({ encryptedName: 'audit-delete' });

      await agent
        .delete(`${BASE}/${folder._id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .expect(200);

      const auditEntry = await AuditLog.findOne({
        userId: user.id,
        action: 'folder_delete',
      });

      expect(auditEntry).toBeDefined();
      expect(auditEntry!.userId.toString()).toBe(user.id);
      expect(auditEntry!.metadata).toBeDefined();
      expect((auditEntry!.metadata as Record<string, unknown>).folderId).toBe(folder._id);
    });

    it('should create audit log on folder reorder', async () => {
      const folder = await apiCreateFolder({ encryptedName: 'audit-reorder' });

      await agent
        .put(`${BASE}/${folder._id}/sort`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ sortOrder: 3 })
        .expect(200);

      const auditEntry = await AuditLog.findOne({
        userId: user.id,
        action: 'folder_reorder',
      });

      expect(auditEntry).toBeDefined();
      expect(auditEntry!.userId.toString()).toBe(user.id);
      expect(auditEntry!.metadata).toBeDefined();
      expect((auditEntry!.metadata as Record<string, unknown>).folderId).toBe(folder._id);
      expect((auditEntry!.metadata as Record<string, unknown>).sortOrder).toBe(3);
    });
  });

  // ── 9. Per-User Folder Count Limit ─────────────────────────────────

  describe('Per-User Folder Count Limit', () => {
    it('should reject folder creation when user has reached MAX_FOLDERS_PER_USER', async () => {
      // Insert 500 folders directly in DB to reach the limit
      const bulkFolders = Array.from({ length: 500 }, (_, i) => ({
        userId: user.id,
        encryptedName: `bulk-folder-${String(i)}`,
        nameIv: `iv-${String(i)}`,
        nameTag: `tag-${String(i)}`,
      }));
      await Folder.insertMany(bulkFolders);

      // Attempt to create one more folder via API
      const res = await agent
        .post(BASE)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send(sampleFolder({ encryptedName: 'one-too-many' }));

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toMatch(/folder limit reached/i);
    });

    it('should allow folder creation when user has fewer than MAX_FOLDERS_PER_USER folders', async () => {
      // Insert 499 folders directly in DB (one below the limit)
      const bulkFolders = Array.from({ length: 499 }, (_, i) => ({
        userId: user.id,
        encryptedName: `bulk-folder-${String(i)}`,
        nameIv: `iv-${String(i)}`,
        nameTag: `tag-${String(i)}`,
      }));
      await Folder.insertMany(bulkFolders);

      // This should succeed (folder #500)
      const res = await agent
        .post(BASE)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send(sampleFolder({ encryptedName: 'just-under-limit' }));

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
    });

    it('should enforce the limit per user (not globally)', async () => {
      // Insert 500 folders for user A (at limit)
      const bulkFolders = Array.from({ length: 500 }, (_, i) => ({
        userId: user.id,
        encryptedName: `user-a-folder-${String(i)}`,
        nameIv: `iv-${String(i)}`,
        nameTag: `tag-${String(i)}`,
      }));
      await Folder.insertMany(bulkFolders);

      // User B should still be able to create a folder
      const userB = await createTestUser({ email: 'userb-limit@example.com' });
      const agentB = request.agent(app);
      const csrfB = await getCsrf(agentB);

      const res = await agentB
        .post(BASE)
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrfB.cookie)
        .set('x-csrf-token', csrfB.token)
        .send(sampleFolder({ encryptedName: 'user-b-folder' }));

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
    });
  });

  // ── 10. Folder searchHash ──────────────────────────────────────────

  describe('Folder searchHash', () => {
    it('should store and return searchHash on a created folder', async () => {
      const searchHash = 'a'.repeat(64);
      const folder = await apiCreateFolder({ searchHash });

      expect(folder.searchHash).toBe(searchHash);
    });

    it('should accept folders without searchHash (legacy compat)', async () => {
      const folder = await apiCreateFolder();

      expect(folder.searchHash).toBeUndefined();
    });

    it('should allow multiple folders without searchHash (sparse index)', async () => {
      await apiCreateFolder({ encryptedName: 'no-hash-1' });
      await apiCreateFolder({ encryptedName: 'no-hash-2' });
      await apiCreateFolder({ encryptedName: 'no-hash-3' });

      const res = await agent.get(BASE).set('Authorization', authHeader(user.accessToken));

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(3);
    });

    it('should reject duplicate searchHash for the same user', async () => {
      const searchHash = 'b'.repeat(64);
      await apiCreateFolder({ encryptedName: 'folder-1', searchHash });

      const res = await agent
        .post(BASE)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send(sampleFolder({ encryptedName: 'folder-2', searchHash }));

      // Duplicate searchHash now surfaces as a clean 409 Conflict instead of
      // bubbling the raw E11000 to the global error handler as a 500.
      expect(res.status).toBe(409);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toMatch(/already exists/i);
    });

    it('should allow same searchHash for different users', async () => {
      const searchHash = 'c'.repeat(64);
      await apiCreateFolder({ encryptedName: 'user-a-folder', searchHash });

      const userB = await createTestUser({ email: 'searchhash-b@example.com' });
      const agentB = request.agent(app);
      const csrfB = await getCsrf(agentB);

      const res = await agentB
        .post(BASE)
        .set('Authorization', authHeader(userB.accessToken))
        .set('Cookie', csrfB.cookie)
        .set('x-csrf-token', csrfB.token)
        .send(sampleFolder({ encryptedName: 'user-b-folder', searchHash }));

      expect(res.status).toBe(201);
      expect(res.body.data.searchHash).toBe(searchHash);
    });

    it('should update searchHash on an existing folder', async () => {
      const searchHash = 'd'.repeat(64);
      const folder = await apiCreateFolder({ searchHash });

      const newHash = 'e'.repeat(64);
      const res = await agent
        .put(`${BASE}/${folder._id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({
          encryptedName: 'updated-name',
          nameIv: 'updated-iv',
          nameTag: 'updated-tag',
          searchHash: newHash,
        });

      expect(res.status).toBe(200);
      expect(res.body.data.searchHash).toBe(newHash);
    });
  });

  // ── 3.9 — Delete folder query validation ──────────────────────────

  describe('Delete folder query validation (3.9)', () => {
    it('should accept action=move query parameter', async () => {
      const folder = await apiCreateFolder();

      const res = await agent
        .delete(`${BASE}/${folder._id}?action=move`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('should accept action=delete query parameter', async () => {
      const folder = await apiCreateFolder();

      const res = await agent
        .delete(`${BASE}/${folder._id}?action=delete`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('should default to action=move when no query parameter provided', async () => {
      const folder = await apiCreateFolder();

      const res = await agent
        .delete(`${BASE}/${folder._id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('should reject invalid action query parameter with 400', async () => {
      const folder = await apiCreateFolder();

      const res = await agent
        .delete(`${BASE}/${folder._id}?action=invalid`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token);

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });
  });
});
