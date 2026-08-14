import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../src/app.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { User } from '../src/models/User.js';
import mongoose from 'mongoose';
import { useReplicaSetConnection } from './mongoHarness.js';
import { supportsTransactions } from '../src/utils/transactionSupport.js';
import {
  createTestUser,
  authHeader,
  sampleVaultItem,
  sampleFolder,
  getCsrf,
  type TestUser,
} from './helpers.js';

// ---------------------------------------------------------------------------
// Cross-User Isolation Edge Cases
//
// Everything here names a foreign id in a place the route table cannot classify
// — in a request BODY (`bulk-delete`'s ids, `bulk-move`'s and `createItem`'s
// `folderId`, a folder's `parentId`, a rotation's `items[].id`) or in a QUERY
// STRING the server must ignore — or asserts a property of a response body
// rather than of a URL.
//
// The one case that WAS expressible, "should not allow updating sort order of
// another user folder", now runs from the table in `authz-matrix.test.ts`
// (PUT /api/v1/folders/:id/sort), together with the byte-identical check it did
// not make.
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
      const itemA = await createItemFor(userA.accessToken, { encryptedName: 'a-item' });
      const before = await VaultItem.findById(itemA).lean();

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

      // On a standalone mongod the sequential path resolves every requested id
      // against `{ _id, userId }` BEFORE its first write, so a foreign id
      // aborts the whole rotation with a 409 naming the counts, and the vault
      // key is not changed. Pinned exactly: the previous assertion accepted any
      // status under 500 on one branch and only checked one field on the other,
      // so it stayed green even if the rotation had partially succeeded.
      expect(res.status).toBe(409);
      expect(String(res.body.message)).toMatch(
        /1 item\(s\) and 0 folder\(s\) could not be updated/,
      );
      expect(String(res.body.message)).toMatch(/vault key was not changed/i);

      // User A's ciphertext is byte-identical…
      const after = await VaultItem.findById(itemA).lean();
      expect(after).toEqual(before);
      expect(after?.encryptedName).toBe('a-item');

      // …and user B's own vault key was not rotated to the one it proposed.
      const intruder = await User.findById(userB.id).lean();
      expect(intruder?.encryptedVaultKey).not.toBe('hacked-vault-key');
      expect(intruder?.rotationInProgress).not.toBe(true);
    });
  });
});

// ---------------------------------------------------------------------------
// The same attack against the branch PRODUCTION actually runs.
//
// `bulkReEncrypt` has two paths, and `supportsTransactions()` picks between
// them. The suite's default mongod is a STANDALONE, so every other test in this
// file exercises the sequential fallback — while the deployed stack is a
// replica set (`rs0`), where the transaction branch is what executes. Its
// ownership filters are `VaultItem.updateOne({ _id: item.id, userId })` and the
// matching one for folders, and until this block existed nothing presented them
// with a FOREIGN-BUT-EXISTING id: the only test on that branch uses an id that
// belongs to nobody, which fails on `_id` alone and would still pass with
// `userId` deleted from the filter.
//
// Its own top-level describe because `useReplicaSetConnection()` swaps the
// process-wide mongoose connection for the block and hands it back afterwards.
// ---------------------------------------------------------------------------
describe('Vault key rotation cross-user isolation (transaction branch)', () => {
  useReplicaSetConnection();

  let owner: TestUser;
  let intruder: TestUser;

  beforeEach(async () => {
    owner = await createTestUser({ email: 'rs-owner@example.com' });
    intruder = await createTestUser({ email: 'rs-intruder@example.com' });
  });

  it('runs against a topology where transactions are actually available', () => {
    // Without this the block could silently fall through to the sequential path
    // and report the fallback's behaviour as the transaction branch's — the
    // exact substitution this whole block exists to stop.
    expect(supportsTransactions(mongoose.connection)).toBe(true);
  });

  it("refuses a rotation naming another user's item and leaves it byte-identical", async () => {
    const target = await VaultItem.create({
      userId: owner.id,
      ...sampleVaultItem({ encryptedName: 'owner-ciphertext' }),
    });
    const targetId = String(target._id);
    const before = await VaultItem.findById(targetId).lean();

    const agent = request.agent(app);
    const csrf = await getCsrf(agent);
    const res = await agent
      .post('/api/v1/vault/items/bulk-reencrypt')
      .set('Authorization', authHeader(intruder.accessToken))
      .set('Cookie', csrf.cookie)
      .set('x-csrf-token', csrf.token)
      .send({
        authHash: intruder.rawPassword,
        items: [
          {
            id: targetId,
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

    // 404 is the transaction branch's discriminator; the sequential fallback
    // answers 409 for the same input. Asserting the status therefore also
    // asserts which branch ran.
    expect(res.status, JSON.stringify(res.body)).toBe(404);
    expect(res.body.success).toBe(false);

    const after = await VaultItem.findById(targetId).lean();
    expect(after).toEqual(before);
    expect(after?.encryptedName).toBe('owner-ciphertext');

    // The intruder's own vault key is untouched and its rotation fence is down,
    // so a refused rotation leaves no state behind that would block the next one.
    const attacker = await User.findById(intruder.id).lean();
    expect(attacker?.encryptedVaultKey).not.toBe('hacked-vault-key');
    expect(attacker?.rotationInProgress).not.toBe(true);
  });

  it("refuses a rotation naming another user's folder and leaves it byte-identical", async () => {
    // The folder loop is a second, separately-filtered write inside the same
    // transaction; deleting `userId` from it alone would leave the item case
    // above green.
    const target = await Folder.create({
      userId: owner.id,
      ...sampleFolder({ encryptedName: 'owner-folder-ciphertext' }),
    });
    const targetId = String(target._id);
    const before = await Folder.findById(targetId).lean();

    const agent = request.agent(app);
    const csrf = await getCsrf(agent);
    const res = await agent
      .post('/api/v1/vault/items/bulk-reencrypt')
      .set('Authorization', authHeader(intruder.accessToken))
      .set('Cookie', csrf.cookie)
      .set('x-csrf-token', csrf.token)
      .send({
        authHash: intruder.rawPassword,
        items: [],
        folders: [
          {
            id: targetId,
            encryptedName: 'hacked-folder',
            nameIv: 'hacked-iv',
            nameTag: 'hacked-tag',
          },
        ],
        newEncryptedVaultKey: 'hacked-vault-key',
        newVaultKeyIv: 'hacked-vk-iv',
        newVaultKeyTag: 'hacked-vk-tag',
      });

    expect(res.status, JSON.stringify(res.body)).toBe(404);

    const after = await Folder.findById(targetId).lean();
    expect(after).toEqual(before);
    expect(after?.encryptedName).toBe('owner-folder-ciphertext');

    const attacker = await User.findById(intruder.id).lean();
    expect(attacker?.encryptedVaultKey).not.toBe('hacked-vault-key');
  });
});
