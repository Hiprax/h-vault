/**
 * Branch-coverage tests for the vault + folder controllers.
 *
 * Every test here drives an ERROR or EDGE path that no existing suite reaches,
 * and asserts the OBSERVABLE contract (HTTP status + body, the resulting DB
 * state, and the audit row where one is written) rather than the fact that a
 * line ran:
 *
 *   * `updateItem`'s HAPPY target-folder path (the existing suites only cover
 *     the IDOR rejection, never a successful move).
 *   * `bulkReEncrypt`'s sequential fallback when the FOLDER rollback itself
 *     fails: the rollback is best-effort, but the two invariants that keep the
 *     account usable — the vault key is never swapped, and the rotation fence is
 *     lowered — must still hold, or the user is permanently wedged.
 *   * `createFolder` / `updateFolder`: a persistence error that is NOT an E11000
 *     duplicate must be re-thrown, never mis-reported to the caller as
 *     "A folder with this name already exists".
 *   * The replica-set (transaction) branches that the standalone harness cannot
 *     reach at all: `bulkReEncrypt`'s in-transaction missing-FOLDER abort and its
 *     in-transaction idempotency-key write, plus `deleteFolder`'s transactional
 *     execute path.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest';
import request from 'supertest';
import crypto from 'node:crypto';
import mongoose from 'mongoose';
import { MongoMemoryReplSet } from 'mongodb-memory-server';
import app from '../src/app.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { User } from '../src/models/User.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { supportsTransactions } from '../src/utils/transactionSupport.js';
import { createTestUser, authHeader, getCsrf, seedFolder, seedItem } from './helpers.js';
import type { TestUser, CsrfPair } from './helpers.js';

const ORIGINAL_VAULT_KEY = 'test-encrypted-vault-key';

function authed(
  method: 'post' | 'put' | 'delete',
  path: string,
  user: TestUser,
  csrf: CsrfPair,
  agent: request.Agent,
) {
  return agent[method](path)
    .set('Authorization', authHeader(user.accessToken))
    .set('Cookie', csrf.cookie)
    .set('x-csrf-token', csrf.token);
}

// =====================================================================
// Standalone MongoDB (the default harness) — sequential / non-transaction
// branches.
// =====================================================================

describe('vault + folder controllers — standalone branches', () => {
  let user: TestUser;
  let agent: request.Agent;
  let csrf: CsrfPair;

  beforeEach(async () => {
    user = await createTestUser();
    agent = request.agent(app);
    csrf = await getCsrf(agent);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('PUT /vault/items/:id — move into an OWNED folder', () => {
    it('persists the new folderId, returns it, and writes an item_update audit row', async () => {
      const target = await seedFolder(user.id, { encryptedName: 'target-folder' });
      const item = await seedItem(user.id, { encryptedName: 'movable' });

      const res = await authed('put', `/api/v1/vault/items/${String(item._id)}`, user, csrf, agent)
        .send({ folderId: String(target._id) })
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.data.folderId).toBe(String(target._id));

      const persisted = await VaultItem.findById(item._id).lean();
      expect(persisted).not.toBeNull();
      expect(String(persisted!.folderId)).toBe(String(target._id));
      // The move must not disturb the ciphertext.
      expect(persisted!.encryptedName).toBe('movable');

      const auditRow = await AuditLog.findOne({
        userId: user.id,
        action: 'item_update',
        'metadata.itemId': String(item._id),
      }).lean();
      expect(auditRow).not.toBeNull();
    });
  });

  describe('POST /vault/items/bulk-reencrypt — the FOLDER rollback itself fails', () => {
    it('still preserves the vault key, lowers the fence, and leaves the account writable', async () => {
      const item = await seedItem(user.id, {
        encryptedName: 'orig-item-name',
        encryptedData: 'orig-item-data',
      });
      const folder1 = await seedFolder(user.id, { encryptedName: 'orig-folder-1' });
      const folder2 = await seedFolder(user.id, { encryptedName: 'orig-folder-2' });

      // The first folder write lands (new-key ciphertext), the second fails —
      // and so does the rollback write that tries to restore the first. The
      // rollback is deliberately best-effort, so folder1 is left carrying
      // new-key ciphertext; what must NOT happen is the vault key being swapped
      // (which would strand every OTHER row) or the fence being left raised
      // (which would 409 every subsequent write until the next login).
      const realFolderUpdateOne = Folder.updateOne.bind(Folder);
      let folderWrites = 0;
      vi.spyOn(Folder, 'updateOne').mockImplementation(((...args: unknown[]) => {
        folderWrites += 1;
        if (folderWrites >= 2) {
          throw new Error('simulated folder write outage');
        }
        return (realFolderUpdateOne as unknown as (...a: unknown[]) => unknown)(...args);
      }) as unknown as typeof Folder.updateOne);

      const res = await authed('post', '/api/v1/vault/items/bulk-reencrypt', user, csrf, agent)
        .send({
          authHash: user.rawPassword,
          items: [
            {
              id: String(item._id),
              encryptedName: 'rotated-item-name',
              nameIv: 'niv',
              nameTag: 'ntag',
              encryptedData: 'rotated-item-data',
              dataIv: 'div',
              dataTag: 'dtag',
            },
          ],
          folders: [
            {
              id: String(folder1._id),
              encryptedName: 'rotated-folder-1',
              nameIv: 'fiv',
              nameTag: 'ftag',
            },
            {
              id: String(folder2._id),
              encryptedName: 'rotated-folder-2',
              nameIv: 'fiv',
              nameTag: 'ftag',
            },
          ],
          newEncryptedVaultKey: 'must-not-be-committed',
          newVaultKeyIv: 'bad-iv',
          newVaultKeyTag: 'bad-tag',
        })
        .expect(409);

      expect(res.body.success).toBe(false);
      expect(JSON.stringify(res.body)).toContain('The vault key was not changed');

      const persistedUser = await User.findById(user.id).lean();
      expect(persistedUser).not.toBeNull();
      expect(persistedUser!.encryptedVaultKey).toBe(ORIGINAL_VAULT_KEY);
      expect(persistedUser!.vaultKeyIv).toBe('test-vault-key-iv');
      expect(persistedUser!.rotationInProgress).toBe(false);
      expect(persistedUser!.pendingEncryptedVaultKey).toBeUndefined();

      // The item rollback (VaultItem writes are healthy) DID succeed.
      const persistedItem = await VaultItem.findById(item._id).lean();
      expect(persistedItem!.encryptedName).toBe('orig-item-name');
      expect(persistedItem!.encryptedData).toBe('orig-item-data');

      // The folder rollback failed — folder1 keeps the new-key ciphertext. This
      // is the documented best-effort outcome, and it is exactly why the vault
      // key must stay OLD only for the rows that were restored... folder2 was
      // never written at all.
      const f1 = await Folder.findById(folder1._id).lean();
      expect(f1!.encryptedName).toBe('rotated-folder-1');
      const f2 = await Folder.findById(folder2._id).lean();
      expect(f2!.encryptedName).toBe('orig-folder-2');

      // The account is not wedged: the fence is down, so a fresh ciphertext
      // write is accepted and the user can retry the rotation.
      vi.restoreAllMocks();
      const agent2 = request.agent(app);
      const csrf2 = await getCsrf(agent2);
      await authed('post', '/api/v1/vault/items', user, csrf2, agent2)
        .send({
          itemType: 'login',
          encryptedData: 'post-failure-data',
          dataIv: 'iv',
          dataTag: 'tag',
          encryptedName: 'post-failure-item',
          nameIv: 'niv',
          nameTag: 'ntag',
        })
        .expect(201);
    });
  });

  describe('folder writes — a non-duplicate persistence error is not masked as a 409', () => {
    it('POST /folders re-throws a generic write failure (500, never "already exists")', async () => {
      vi.spyOn(Folder, 'create').mockRejectedValue(new Error('connection reset by peer'));

      const res = await authed('post', '/api/v1/folders', user, csrf, agent)
        .send({
          encryptedName: 'doomed-folder',
          nameIv: 'iv',
          nameTag: 'tag',
        })
        .expect(500);

      expect(res.body.success).toBe(false);
      // Mis-classifying a transient outage as a duplicate-name conflict would
      // send the user chasing a name collision that does not exist.
      expect(JSON.stringify(res.body)).not.toContain('already exists');

      vi.restoreAllMocks();
      expect(await Folder.countDocuments({ userId: user.id })).toBe(0);
      expect(await AuditLog.countDocuments({ userId: user.id, action: 'folder_create' })).toBe(0);
    });

    it('PUT /folders/:id re-throws a generic write failure (500, never "already exists")', async () => {
      const folder = await seedFolder(user.id, { encryptedName: 'orig-name' });

      vi.spyOn(Folder, 'findOneAndUpdate').mockImplementation((() => {
        throw new Error('connection reset by peer');
      }) as unknown as typeof Folder.findOneAndUpdate);

      const res = await authed('put', `/api/v1/folders/${String(folder._id)}`, user, csrf, agent)
        .send({ encryptedName: 'renamed', nameIv: 'iv2', nameTag: 'tag2' })
        .expect(500);

      expect(res.body.success).toBe(false);
      expect(JSON.stringify(res.body)).not.toContain('already exists');

      vi.restoreAllMocks();
      const persisted = await Folder.findById(folder._id).lean();
      expect(persisted).not.toBeNull();
      expect(persisted!.encryptedName).toBe('orig-name');
      expect(await AuditLog.countDocuments({ userId: user.id, action: 'folder_update' })).toBe(0);
    });
  });
});

// =====================================================================
// Replica set — the transaction branches the standalone harness cannot reach.
//
// This block MUST come last in the file: its beforeAll swaps the shared mongoose
// connection (opened against a standalone server by tests/setup.ts) for one
// pointing at a single-node replica set, which is the only way
// `supportsTransactions(...)` / `options.replicaSet` become true. Same pattern
// as tests/vault-rotation-transaction.test.ts.
// =====================================================================

describe('vault + folder controllers — replica-set (transaction) branches', () => {
  let replSet: MongoMemoryReplSet;
  let user: TestUser;
  let agent: request.Agent;
  let csrf: CsrfPair;

  beforeAll(async () => {
    await mongoose.disconnect();
    replSet = await MongoMemoryReplSet.create({
      replSet: { count: 1, storageEngine: 'wiredTiger' },
    });
    await mongoose.connect(replSet.getUri());

    // If the replica set failed to register, every controller below would take
    // the sequential/no-session path and these tests would silently assert the
    // wrong branch. Fail loudly instead.
    expect(supportsTransactions(mongoose.connection)).toBe(true);
  }, 60_000);

  afterAll(async () => {
    await mongoose.disconnect();
    await replSet.stop();
  });

  beforeEach(async () => {
    user = await createTestUser();
    agent = request.agent(app);
    csrf = await getCsrf(agent);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('POST /vault/items/bulk-reencrypt — in-transaction abort on a missing FOLDER', () => {
    it('returns 404, rolls the already-written item back, and never commits the new vault key', async () => {
      const item = await seedItem(user.id, {
        encryptedName: 'txn-orig-name',
        encryptedData: 'txn-orig-data',
      });
      const ghostFolderId = new mongoose.Types.ObjectId().toString();

      const res = await authed('post', '/api/v1/vault/items/bulk-reencrypt', user, csrf, agent)
        .send({
          authHash: user.rawPassword,
          items: [
            {
              id: String(item._id),
              encryptedName: 'txn-rotated-name',
              nameIv: 'niv',
              nameTag: 'ntag',
              encryptedData: 'txn-rotated-data',
              dataIv: 'div',
              dataTag: 'dtag',
            },
          ],
          folders: [
            {
              id: ghostFolderId,
              encryptedName: 'ghost-folder',
              nameIv: 'fiv',
              nameTag: 'ftag',
            },
          ],
          newEncryptedVaultKey: 'txn-must-not-commit',
          newVaultKeyIv: 'txn-bad-iv',
          newVaultKeyTag: 'txn-bad-tag',
        })
        // 404 is unique to the transaction branch — the sequential fallback
        // reports the same scenario as a 409.
        .expect(404);

      expect(res.body.success).toBe(false);
      expect(JSON.stringify(res.body)).toContain(ghostFolderId);

      // The item write happened INSIDE the transaction and must be rolled back.
      const persistedItem = await VaultItem.findById(item._id).lean();
      expect(persistedItem!.encryptedName).toBe('txn-orig-name');
      expect(persistedItem!.encryptedData).toBe('txn-orig-data');

      const persistedUser = await User.findById(user.id).lean();
      expect(persistedUser!.encryptedVaultKey).toBe(ORIGINAL_VAULT_KEY);
      // The fence is raised OUTSIDE the transaction, so the abort cannot lower
      // it — the `finally` must, or every later write 409s until the next login.
      expect(persistedUser!.rotationInProgress).toBe(false);
    });
  });

  describe('POST /vault/items/bulk-reencrypt — in-transaction idempotency key', () => {
    it('commits lastRotationKey with the rotation, then short-circuits a replay without re-processing', async () => {
      const item = await seedItem(user.id, { encryptedName: 'idem-orig' });
      const idempotencyKey = crypto.randomUUID();

      const first = await authed('post', '/api/v1/vault/items/bulk-reencrypt', user, csrf, agent)
        .send({
          authHash: user.rawPassword,
          idempotencyKey,
          items: [
            {
              id: String(item._id),
              encryptedName: 'idem-rotated',
              nameIv: 'niv',
              nameTag: 'ntag',
              encryptedData: 'idem-rotated-data',
              dataIv: 'div',
              dataTag: 'dtag',
            },
          ],
          folders: [],
          newEncryptedVaultKey: 'idem-new-key',
          newVaultKeyIv: 'idem-new-iv',
          newVaultKeyTag: 'idem-new-tag',
        })
        .expect(200);

      expect(first.body.data.updatedCount).toBe(1);

      const afterFirst = await User.findById(user.id).lean();
      expect(afterFirst!.lastRotationKey).toBe(idempotencyKey);
      expect(afterFirst!.lastRotationAt).toBeInstanceOf(Date);
      expect(afterFirst!.encryptedVaultKey).toBe('idem-new-key');

      // A retry of the SAME logical rotation (e.g. the client never saw the
      // first response) must be a no-op: the replay carries different ciphertext
      // and a different key, and neither may land.
      const agent2 = request.agent(app);
      const csrf2 = await getCsrf(agent2);
      const replay = await authed('post', '/api/v1/vault/items/bulk-reencrypt', user, csrf2, agent2)
        .send({
          authHash: user.rawPassword,
          idempotencyKey,
          items: [
            {
              id: String(item._id),
              encryptedName: 'REPLAY-SHOULD-NOT-LAND',
              nameIv: 'x',
              nameTag: 'x',
              encryptedData: 'REPLAY-SHOULD-NOT-LAND',
              dataIv: 'x',
              dataTag: 'x',
            },
          ],
          folders: [],
          newEncryptedVaultKey: 'replay-key-should-not-land',
          newVaultKeyIv: 'x',
          newVaultKeyTag: 'x',
        })
        .expect(200);

      expect(replay.body.success).toBe(true);

      const persistedItem = await VaultItem.findById(item._id).lean();
      expect(persistedItem!.encryptedName).toBe('idem-rotated');
      const afterReplay = await User.findById(user.id).lean();
      expect(afterReplay!.encryptedVaultKey).toBe('idem-new-key');
      expect(afterReplay!.lastRotationAt!.getTime()).toBe(afterFirst!.lastRotationAt!.getTime());
    });
  });

  describe('DELETE /folders/:id — transactional execute path', () => {
    it('action=delete: trashes the folder items, re-parents children, and drops the folder in one transaction', async () => {
      const root = await seedFolder(user.id, { encryptedName: 'txn-root' });
      const doomed = await seedFolder(user.id, {
        encryptedName: 'txn-doomed',
        parentId: root._id,
      });
      const child = await seedFolder(user.id, {
        encryptedName: 'txn-child',
        parentId: doomed._id,
      });
      const item = await seedItem(user.id, {
        encryptedName: 'txn-item',
        folderId: doomed._id,
      });

      const startSessionSpy = vi.spyOn(mongoose, 'startSession');

      await authed(
        'delete',
        `/api/v1/folders/${String(doomed._id)}?action=delete`,
        user,
        csrf,
        agent,
      ).expect(200);

      // The sequential (standalone) path never opens a session.
      expect(startSessionSpy).toHaveBeenCalled();

      expect(await Folder.findById(doomed._id).lean()).toBeNull();

      const persistedChild = await Folder.findById(child._id).lean();
      expect(persistedChild).not.toBeNull();
      expect(String(persistedChild!.parentId)).toBe(String(root._id));

      const persistedItem = await VaultItem.findById(item._id).lean();
      expect(persistedItem).not.toBeNull();
      expect(persistedItem!.deletedAt).toBeInstanceOf(Date);

      const auditRow = await AuditLog.findOne({
        userId: user.id,
        action: 'folder_delete',
        'metadata.folderId': String(doomed._id),
      }).lean();
      expect(auditRow).not.toBeNull();
      expect((auditRow!.metadata as Record<string, unknown>).action).toBe('delete');
    });

    it('action=move: relocates the folder items to the parent instead of trashing them', async () => {
      const root = await seedFolder(user.id, { encryptedName: 'txn-move-root' });
      const doomed = await seedFolder(user.id, {
        encryptedName: 'txn-move-doomed',
        parentId: root._id,
      });
      const item = await seedItem(user.id, {
        encryptedName: 'txn-move-item',
        folderId: doomed._id,
      });

      await authed(
        'delete',
        `/api/v1/folders/${String(doomed._id)}?action=move`,
        user,
        csrf,
        agent,
      ).expect(200);

      expect(await Folder.findById(doomed._id).lean()).toBeNull();

      const persistedItem = await VaultItem.findById(item._id).lean();
      expect(persistedItem).not.toBeNull();
      expect(persistedItem!.deletedAt).toBeUndefined();
      expect(String(persistedItem!.folderId)).toBe(String(root._id));
    });
  });
});
