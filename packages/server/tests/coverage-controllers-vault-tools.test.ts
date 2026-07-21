/**
 * Coverage-focused behavioral tests for the vault + tools controllers and the
 * folder-graph / size-estimator helpers.
 *
 * Every test here targets an ERROR or EDGE branch that the existing suites do
 * not reach, and asserts the OBSERVABLE contract (HTTP status + body, and the
 * resulting DB state) rather than the fact that a line executed:
 *
 *   * `updateItem`'s target-folder IDOR guard.
 *   * `bulkReEncrypt`'s per-user rotation lock (409 while another rotation runs).
 *   * `bulkReEncrypt`'s sequential-fallback ROLLBACK of partially-written
 *     ciphertext — the single most dangerous path in the app: if a rotation
 *     writes new-key ciphertext and then fails, the vault key must stay OLD and
 *     every written row must be restored byte-for-byte, or the user loses data.
 *   * `emptyTrash`'s `$lte: startTime` bound (a concurrent soft-delete arriving
 *     mid-request must survive).
 *   * `importVault`'s tag/searchHash/folderId sanitization, itemType filtering
 *     and CSV mapping defaults.
 *   * `exportVault`'s folder-loop size guard.
 *   * `getAncestorChain`/`hasCycle` user-scoping.
 *   * `estimateItemJsonSize`/`estimateFolderJsonSize` on malformed rows.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import app from '../src/app.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { User } from '../src/models/User.js';
import { acquireJobLock } from '../src/utils/jobLock.js';
import { vaultRotationLockName } from '../src/utils/controllerHelpers.js';
import { getAncestorChain, hasCycle } from '../src/utils/folderGraph.js';
import { estimateItemJsonSize, estimateFolderJsonSize } from '../src/utils/sizeEstimator.js';
import { createTestUser, authHeader, getCsrf, seedFolder, seedItem } from './helpers.js';
import type { TestUser } from './helpers.js';

interface Csrf {
  token: string;
  cookie: string;
}

async function csrfFor(agent: request.Agent): Promise<Csrf> {
  return getCsrf(agent);
}

/** POST helper that attaches auth + CSRF. */
function post(path: string, user: TestUser, csrf: Csrf, agent: request.Agent) {
  return agent
    .post(path)
    .set('Authorization', authHeader(user.accessToken))
    .set('Cookie', csrf.cookie)
    .set('x-csrf-token', csrf.token);
}

const ORIGINAL_VAULT_KEY = 'test-encrypted-vault-key';

describe('vault + tools controller edge branches', () => {
  let user: TestUser;
  let agent: request.Agent;
  let csrf: Csrf;

  beforeEach(async () => {
    user = await createTestUser();
    agent = request.agent(app);
    csrf = await csrfFor(agent);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ======================================================================
  // updateItem — target folder ownership (IDOR)
  // ======================================================================

  describe('PUT /vault/items/:id — target folder ownership', () => {
    it("rejects a move into ANOTHER user's folder with 404 and leaves the item's folder untouched", async () => {
      const otherUser = await createTestUser();
      const otherFolder = await seedFolder(otherUser.id, { encryptedName: 'other-users-folder' });
      const ownFolder = await seedFolder(user.id, { encryptedName: 'own-folder' });
      const item = await seedItem(user.id, { folderId: ownFolder._id });

      const res = await agent
        .put(`/api/v1/vault/items/${String(item._id)}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ folderId: String(otherFolder._id) })
        .expect(404);

      expect(res.body.success).toBe(false);
      expect(JSON.stringify(res.body)).toContain('Target folder not found');

      // The item must still sit in its ORIGINAL folder — no cross-user write.
      const persisted = await VaultItem.findById(item._id).lean();
      expect(String(persisted!.folderId)).toBe(String(ownFolder._id));
    });
  });

  // ======================================================================
  // emptyTrash — bounded to items trashed BEFORE the request started
  // ======================================================================

  describe('DELETE /vault/items/trash/empty — bounded deleteMany', () => {
    it('deletes items trashed before the request but keeps one trashed after it started', async () => {
      const old = await seedItem(user.id, {
        encryptedName: 'trashed-earlier',
        deletedAt: new Date(Date.now() - 60_000),
      });
      // Simulates a soft-delete that lands WHILE emptyTrash is running: its
      // deletedAt is newer than the operation's start time, so the `$lte`
      // bound must exclude it.
      const concurrent = await seedItem(user.id, {
        encryptedName: 'trashed-concurrently',
        deletedAt: new Date(Date.now() + 60_000),
      });

      const res = await agent
        .delete('/api/v1/vault/items/trash/empty')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .expect(200);

      expect(res.body.data.deletedCount).toBe(1);

      expect(await VaultItem.findById(old._id).lean()).toBeNull();
      const survivor = await VaultItem.findById(concurrent._id).lean();
      expect(survivor).not.toBeNull();
      expect(survivor!.encryptedName).toBe('trashed-concurrently');
    });
  });

  // ======================================================================
  // listTrash — sort permutations
  // ======================================================================

  describe('GET /vault/items/trash — sorting', () => {
    it('honours sortBy=deletedAt&sortOrder=asc (oldest trashed first)', async () => {
      const newer = await seedItem(user.id, {
        encryptedName: 'newer',
        deletedAt: new Date(Date.now() - 1_000),
      });
      const older = await seedItem(user.id, {
        encryptedName: 'older',
        deletedAt: new Date(Date.now() - 60_000),
      });

      const asc = await request(app)
        .get('/api/v1/vault/items/trash?sortBy=deletedAt&sortOrder=asc')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(asc.body.data.map((i: { _id: string }) => i._id)).toEqual([
        String(older._id),
        String(newer._id),
      ]);

      const desc = await request(app)
        .get('/api/v1/vault/items/trash?sortBy=deletedAt&sortOrder=desc')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(desc.body.data.map((i: { _id: string }) => i._id)).toEqual([
        String(newer._id),
        String(older._id),
      ]);
    });
  });

  // ======================================================================
  // Bulk operation caps
  // ======================================================================

  describe('bulk operation caps (MAX_BULK_OPERATIONS = 100)', () => {
    it('rejects a 101-id bulk-delete with 400 and trashes nothing', async () => {
      const item = await seedItem(user.id, { encryptedName: 'survivor' });
      const ids = [
        String(item._id),
        ...Array.from({ length: 100 }, () => new mongoose.Types.ObjectId().toString()),
      ];

      const res = await post('/api/v1/vault/items/bulk-delete', user, csrf, agent)
        .send({ ids })
        .expect(400);
      expect(res.body.success).toBe(false);

      const persisted = await VaultItem.findById(item._id).lean();
      expect(persisted!.deletedAt).toBeUndefined();
    });

    it('rejects a 101-id bulk-move with 400 and moves nothing', async () => {
      const folder = await seedFolder(user.id);
      const item = await seedItem(user.id, { encryptedName: 'stays-put' });
      const ids = [
        String(item._id),
        ...Array.from({ length: 100 }, () => new mongoose.Types.ObjectId().toString()),
      ];

      await post('/api/v1/vault/items/bulk-move', user, csrf, agent)
        .send({ ids, folderId: String(folder._id) })
        .expect(400);

      const persisted = await VaultItem.findById(item._id).lean();
      expect(persisted!.folderId).toBeUndefined();
    });
  });

  // ======================================================================
  // bulkReEncrypt — per-user rotation lock
  // ======================================================================

  describe('POST /vault/items/bulk-reencrypt — concurrent rotation lock', () => {
    it('returns 409 while another rotation holds the lock, without touching the vault key or raising the fence', async () => {
      const lockId = await acquireJobLock(vaultRotationLockName(user.id), 60_000);
      expect(lockId).not.toBeNull();

      const item = await seedItem(user.id, { encryptedName: 'locked-out' });

      const res = await post('/api/v1/vault/items/bulk-reencrypt', user, csrf, agent)
        .send({
          authHash: user.rawPassword,
          items: [
            {
              id: String(item._id),
              encryptedName: 'rotated',
              nameIv: 'riv',
              nameTag: 'rtag',
              encryptedData: 'rdata',
              dataIv: 'rdiv',
              dataTag: 'rdtag',
            },
          ],
          folders: [],
          newEncryptedVaultKey: 'should-never-land',
          newVaultKeyIv: 'nope-iv',
          newVaultKeyTag: 'nope-tag',
        })
        .expect(409);

      expect(res.body.success).toBe(false);
      expect(JSON.stringify(res.body)).toContain('already in progress');

      const persistedUser = await User.findById(user.id).lean();
      expect(persistedUser!.encryptedVaultKey).toBe(ORIGINAL_VAULT_KEY);
      // The fence must NOT have been raised by the rejected request — doing so
      // would 409 every subsequent write for the live rotation's victim.
      expect(persistedUser!.rotationInProgress).not.toBe(true);

      // The item's ciphertext is untouched.
      const persistedItem = await VaultItem.findById(item._id).lean();
      expect(persistedItem!.encryptedName).toBe('locked-out');
    });
  });

  // ======================================================================
  // bulkReEncrypt — sequential fallback rollback of partial writes
  // ======================================================================

  describe('POST /vault/items/bulk-reencrypt — rollback of partially-written ciphertext', () => {
    it('restores every already-written ITEM (including $unset of a searchHash the rotation added) and preserves the vault key when a later item write fails', async () => {
      const originalHistory = [
        {
          encryptedPassword: 'old-history-cipher',
          iv: 'hist-iv',
          tag: 'hist-tag',
          changedAt: new Date('2026-01-01T00:00:00.000Z'),
        },
      ];
      // item1 HAS a searchHash + passwordHistory; item2 has NEITHER (so the
      // rollback must $unset the searchHash the rotation wrote onto it).
      const item1 = await seedItem(user.id, {
        encryptedName: 'orig-name-1',
        encryptedData: 'orig-data-1',
        searchHash: 'a'.repeat(64),
        passwordHistory: originalHistory,
      });
      const item2 = await seedItem(user.id, {
        encryptedName: 'orig-name-2',
        encryptedData: 'orig-data-2',
      });
      const item3 = await seedItem(user.id, {
        encryptedName: 'orig-name-3',
        encryptedData: 'orig-data-3',
      });

      // Simulate a transient persistence failure on the THIRD item write: the
      // first two rows are already carrying NEW-key ciphertext at that point.
      const originalUpdateOne = VaultItem.updateOne.bind(VaultItem);
      let writeCalls = 0;
      vi.spyOn(VaultItem, 'updateOne').mockImplementation(((...args: unknown[]) => {
        writeCalls += 1;
        if (writeCalls === 3) {
          throw new Error('simulated mongo write failure');
        }
        return (originalUpdateOne as unknown as (...a: unknown[]) => unknown)(...args);
      }) as unknown as typeof VaultItem.updateOne);

      const rotationItem = (id: string, n: number) => ({
        id,
        encryptedName: `rotated-name-${String(n)}`,
        nameIv: 'new-niv',
        nameTag: 'new-ntag',
        encryptedData: `rotated-data-${String(n)}`,
        dataIv: 'new-div',
        dataTag: 'new-dtag',
        searchHash: 'b'.repeat(64),
      });

      const res = await post('/api/v1/vault/items/bulk-reencrypt', user, csrf, agent)
        .send({
          authHash: user.rawPassword,
          items: [
            {
              ...rotationItem(String(item1._id), 1),
              passwordHistory: [
                {
                  encryptedPassword: 'rotated-history-cipher',
                  iv: 'new-hiv',
                  tag: 'new-htag',
                  changedAt: new Date().toISOString(),
                },
              ],
            },
            rotationItem(String(item2._id), 2),
            rotationItem(String(item3._id), 3),
          ],
          folders: [],
          newEncryptedVaultKey: 'must-not-be-committed',
          newVaultKeyIv: 'bad-iv',
          newVaultKeyTag: 'bad-tag',
        })
        .expect(409);

      expect(res.body.success).toBe(false);
      expect(JSON.stringify(res.body)).toContain('The vault key was not changed');

      // ── The vault key must be UNCHANGED ────────────────────────────────
      const persistedUser = await User.findById(user.id).lean();
      expect(persistedUser!.encryptedVaultKey).toBe(ORIGINAL_VAULT_KEY);
      expect(persistedUser!.rotationInProgress).toBe(false);
      expect(persistedUser!.pendingEncryptedVaultKey).toBeUndefined();
      expect(persistedUser!.pendingVaultKeyIv).toBeUndefined();
      expect(persistedUser!.pendingVaultKeyTag).toBeUndefined();

      // ── Every partially-written row must be back to its OLD ciphertext ──
      const p1 = await VaultItem.findById(item1._id).lean();
      expect(p1!.encryptedName).toBe('orig-name-1');
      expect(p1!.encryptedData).toBe('orig-data-1');
      expect(p1!.searchHash).toBe('a'.repeat(64));
      expect(p1!.passwordHistory).toHaveLength(1);
      expect(p1!.passwordHistory![0]!.encryptedPassword).toBe('old-history-cipher');

      const p2 = await VaultItem.findById(item2._id).lean();
      expect(p2!.encryptedName).toBe('orig-name-2');
      expect(p2!.encryptedData).toBe('orig-data-2');
      // The rotation ADDED a searchHash to a row that had none — the rollback
      // must remove it again, not leave the new-key hash behind.
      expect(p2!.searchHash).toBeUndefined();

      // item3 never got written at all.
      const p3 = await VaultItem.findById(item3._id).lean();
      expect(p3!.encryptedName).toBe('orig-name-3');
    });

    it('still preserves the vault key and lowers the fence when the ROLLBACK itself fails', async () => {
      const item1 = await seedItem(user.id, { encryptedName: 'rb-fail-1' });
      const item2 = await seedItem(user.id, { encryptedName: 'rb-fail-2' });

      // Every write from the second one onward fails — so the rotation aborts
      // AND the rollback of item1 fails too. The rollback is best-effort, but
      // the two invariants that keep the account usable must still hold: the
      // vault key is never swapped, and the rotation fence is lowered so the
      // user is not locked out of every subsequent write.
      const originalUpdateOne = VaultItem.updateOne.bind(VaultItem);
      let writeCalls = 0;
      vi.spyOn(VaultItem, 'updateOne').mockImplementation(((...args: unknown[]) => {
        writeCalls += 1;
        if (writeCalls >= 2) {
          throw new Error('simulated mongo outage');
        }
        return (originalUpdateOne as unknown as (...a: unknown[]) => unknown)(...args);
      }) as unknown as typeof VaultItem.updateOne);

      await post('/api/v1/vault/items/bulk-reencrypt', user, csrf, agent)
        .send({
          authHash: user.rawPassword,
          items: [
            {
              id: String(item1._id),
              encryptedName: 'rotated-1',
              nameIv: 'niv',
              nameTag: 'ntag',
              encryptedData: 'rotated-data-1',
              dataIv: 'div',
              dataTag: 'dtag',
            },
            {
              id: String(item2._id),
              encryptedName: 'rotated-2',
              nameIv: 'niv',
              nameTag: 'ntag',
              encryptedData: 'rotated-data-2',
              dataIv: 'div',
              dataTag: 'dtag',
            },
          ],
          folders: [],
          newEncryptedVaultKey: 'must-not-be-committed',
          newVaultKeyIv: 'bad-iv',
          newVaultKeyTag: 'bad-tag',
        })
        .expect(409);

      const persistedUser = await User.findById(user.id).lean();
      expect(persistedUser!.encryptedVaultKey).toBe(ORIGINAL_VAULT_KEY);
      expect(persistedUser!.vaultKeyIv).toBe('test-vault-key-iv');
      expect(persistedUser!.rotationInProgress).toBe(false);
      expect(persistedUser!.pendingEncryptedVaultKey).toBeUndefined();
    });

    it('rolls back the already-written FOLDER and item when a later folder write fails', async () => {
      const item = await seedItem(user.id, {
        encryptedName: 'orig-item-name',
        encryptedData: 'orig-item-data',
      });
      const folder1 = await seedFolder(user.id, { encryptedName: 'orig-folder-1' });
      const folder2 = await seedFolder(user.id, { encryptedName: 'orig-folder-2' });

      const originalFolderUpdate = Folder.updateOne.bind(Folder);
      let folderWrites = 0;
      vi.spyOn(Folder, 'updateOne').mockImplementation(((...args: unknown[]) => {
        folderWrites += 1;
        if (folderWrites === 2) {
          throw new Error('simulated folder write failure');
        }
        return (originalFolderUpdate as unknown as (...a: unknown[]) => unknown)(...args);
      }) as unknown as typeof Folder.updateOne);

      const res = await post('/api/v1/vault/items/bulk-reencrypt', user, csrf, agent)
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
      expect(persistedUser!.encryptedVaultKey).toBe(ORIGINAL_VAULT_KEY);
      expect(persistedUser!.rotationInProgress).toBe(false);
      expect(persistedUser!.pendingEncryptedVaultKey).toBeUndefined();

      // The first folder was written with new-key ciphertext, then rolled back.
      const f1 = await Folder.findById(folder1._id).lean();
      expect(f1!.encryptedName).toBe('orig-folder-1');
      const f2 = await Folder.findById(folder2._id).lean();
      expect(f2!.encryptedName).toBe('orig-folder-2');

      // The item write succeeded before the folder loop — it must be rolled back
      // too, or the OLD (still-current) vault key can no longer decrypt it.
      const persistedItem = await VaultItem.findById(item._id).lean();
      expect(persistedItem!.encryptedName).toBe('orig-item-name');
      expect(persistedItem!.encryptedData).toBe('orig-item-data');
    });
  });

  // ======================================================================
  // importVault — sanitization + format branches
  // ======================================================================

  describe('POST /tools/import — field sanitization', () => {
    it('sanitizes tags: drops non-strings and over-long tags, trims, and caps at 20', async () => {
      const tags: unknown[] = [
        123,
        null,
        '  spaced  ',
        'x'.repeat(51), // over MAX_TAG_LENGTH (50)
        ...Array.from({ length: 25 }, (_, i) => `tag-${String(i)}`),
      ];

      const res = await post('/api/v1/tools/import', user, csrf, agent)
        .send({
          format: 'json',
          data: JSON.stringify({
            items: [
              {
                itemType: 'login',
                encryptedData: 'd',
                dataIv: 'iv',
                dataTag: 't',
                encryptedName: 'tag-sanitize',
                nameIv: 'niv',
                nameTag: 'ntag',
                tags,
              },
            ],
          }),
        })
        .expect(201);

      expect(res.body.data.importedCount).toBe(1);

      const persisted = await VaultItem.findOne({
        userId: user.id,
        encryptedName: 'tag-sanitize',
      }).lean();
      expect(persisted!.tags).toHaveLength(20);
      expect(persisted!.tags[0]).toBe('spaced'); // trimmed
      expect(persisted!.tags).not.toContain('x'.repeat(51));
      expect(persisted!.tags.every((t) => typeof t === 'string')).toBe(true);
      // The 20-item cap keeps the first 20 survivors in order.
      expect(persisted!.tags[1]).toBe('tag-0');
      expect(persisted!.tags[19]).toBe('tag-18');
    });

    it('drops a malformed searchHash and a malformed folderId instead of persisting them', async () => {
      const res = await post('/api/v1/tools/import', user, csrf, agent)
        .send({
          format: 'json',
          data: JSON.stringify({
            items: [
              {
                itemType: 'login',
                encryptedData: 'd',
                dataIv: 'iv',
                dataTag: 't',
                encryptedName: 'bad-refs',
                nameIv: 'niv',
                nameTag: 'ntag',
                searchHash: 'NOT-A-HASH',
                folderId: 'not-an-objectid',
              },
            ],
          }),
        })
        .expect(201);

      expect(res.body.data.importedCount).toBe(1);

      const persisted = await VaultItem.findOne({
        userId: user.id,
        encryptedName: 'bad-refs',
      }).lean();
      expect(persisted!.searchHash).toBeUndefined();
      expect(persisted!.folderId).toBeUndefined();
    });
  });

  describe('POST /tools/import — non-JSON format item defaults', () => {
    it('defaults a missing itemType to login and drops an unknown itemType (keepass)', async () => {
      const res = await post('/api/v1/tools/import', user, csrf, agent)
        .send({
          format: 'keepass',
          data: JSON.stringify({
            items: [
              {
                // no itemType → defaults to 'login'
                encryptedData: 'd1',
                dataIv: 'iv',
                dataTag: 't',
                encryptedName: 'defaulted-type',
                nameIv: 'niv',
                nameTag: 'ntag',
                favorite: 'yes', // not === true → stored as false
              },
              {
                itemType: 'bogus-type',
                encryptedData: 'd2',
                dataIv: 'iv',
                dataTag: 't',
                encryptedName: 'unknown-type',
                nameIv: 'niv',
                nameTag: 'ntag',
              },
            ],
          }),
        })
        .expect(201);

      // The unknown-type row is filtered out BEFORE the missing-fields filter,
      // so it counts as neither imported nor "skipped for missing encryption".
      expect(res.body.data.importedCount).toBe(1);

      const persisted = await VaultItem.find({ userId: user.id }).lean();
      expect(persisted).toHaveLength(1);
      expect(persisted[0]!.encryptedName).toBe('defaulted-type');
      expect(persisted[0]!.itemType).toBe('login');
      expect(persisted[0]!.favorite).toBe(false);
    });
  });

  describe('POST /tools/import — items missing encryption fields', () => {
    it('rejects the import when items lack ciphertext, persisting nothing', async () => {
      // A native envelope whose items carry no encrypted fields (e.g. plaintext
      // that never went through client-side encryption). The non-empty filter
      // drops them all and the whole import is rejected before any write.
      const importData = JSON.stringify({
        items: [
          { itemType: 'login', name: 'a', username: 'x' },
          { itemType: 'login', name: 'b', password: 'y' },
        ],
      });

      const res = await post('/api/v1/tools/import', user, csrf, agent)
        .send({ format: 'csv', data: importData })
        .expect(400);

      expect(res.body.success).toBe(false);
      expect(JSON.stringify(res.body)).toContain('No valid items');
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
    });
  });

  // ======================================================================
  // exportVault — folder-loop size guard
  // ======================================================================

  describe('POST /tools/export — size guard on the folder pass', () => {
    it('returns 413 when the FOLDERS (not the items) push the estimate past EXPORT_MAX_SIZE_MB', async () => {
      const { config: serverConfig } = await import('../src/config/index.js');
      const original = serverConfig.EXPORT_MAX_SIZE_MB;
      // ~3 KB budget: the 1 KB response wrapper plus 10 folders at >=400 bytes
      // each blows the limit, while the (zero) items never do.
      (serverConfig as Record<string, unknown>).EXPORT_MAX_SIZE_MB = 0.003;

      try {
        for (let i = 0; i < 10; i++) {
          await seedFolder(user.id, { encryptedName: `folder-${String(i)}` });
        }

        const res = await post('/api/v1/tools/export', user, csrf, agent)
          .send({ authHash: user.rawPassword })
          .expect(413);

        expect(res.body.success).toBe(false);
        expect(JSON.stringify(res.body)).toContain('maximum allowed size');
      } finally {
        (serverConfig as Record<string, unknown>).EXPORT_MAX_SIZE_MB = original;
      }
    });
  });

  // ======================================================================
  // folderGraph — user scoping
  // ======================================================================

  describe('folderGraph helpers', () => {
    it('getAncestorChain walks the chain for the OWNER and returns an empty chain for another user', async () => {
      const root = await seedFolder(user.id, { encryptedName: 'root' });
      const mid = await seedFolder(user.id, { encryptedName: 'mid', parentId: root._id });
      const leaf = await seedFolder(user.id, { encryptedName: 'leaf', parentId: mid._id });

      const owned = await getAncestorChain(String(leaf._id), user.id);
      expect(owned.depth).toBe(3);
      expect(new Set(owned.ancestorIds)).toEqual(
        new Set([String(root._id), String(mid._id)].map(String)),
      );

      // The SAME folder id, queried as a different user, must resolve to nothing:
      // the traversal is scoped by userId, so it can never leak another account's
      // folder graph.
      const otherUser = await createTestUser();
      const foreign = await getAncestorChain(String(leaf._id), otherUser.id);
      expect(foreign.ancestorIds).toEqual([]);
      expect(foreign.depth).toBe(0);

      expect(await hasCycle(String(leaf._id), otherUser.id)).toBe(false);
      expect(await hasCycle(String(leaf._id), user.id)).toBe(false);
    });

    it('hasCycle detects a folder that is its own ancestor', async () => {
      const a = await seedFolder(user.id, { encryptedName: 'cycle-a' });
      const b = await seedFolder(user.id, { encryptedName: 'cycle-b', parentId: a._id });
      // Close the loop directly in the DB (bypassing the controller guards), the
      // way a tampered backup would.
      await Folder.updateOne({ _id: a._id }, { $set: { parentId: b._id } });

      expect(await hasCycle(String(a._id), user.id)).toBe(true);
      expect(await hasCycle(String(b._id), user.id)).toBe(true);
    });
  });

  // ======================================================================
  // sizeEstimator — malformed rows must still over-estimate, never throw
  // ======================================================================

  describe('sizeEstimator on malformed rows', () => {
    it('ignores non-string fields, non-string tags and non-object history entries while staying >= the real JSON size', () => {
      const item: Record<string, unknown> = {
        _id: '507f1f77bcf86cd799439011',
        itemType: 'login',
        encryptedData: 42, // not a string
        dataIv: null,
        dataTag: 'b'.repeat(24),
        encryptedName: 'y'.repeat(100),
        nameIv: 'c'.repeat(16),
        nameTag: 'd'.repeat(24),
        searchHash: undefined,
        tags: ['ok', 7, null, 'also-ok'],
        passwordHistory: [
          null,
          'not-an-object',
          { encryptedPassword: 'p'.repeat(80), iv: 9, tag: 't'.repeat(24) },
        ],
      };

      const estimated = estimateItemJsonSize(item);
      expect(estimated).toBeGreaterThanOrEqual(Buffer.byteLength(JSON.stringify(item), 'utf-8'));
    });

    it('ignores non-string folder fields while staying >= the real JSON size', () => {
      const folder: Record<string, unknown> = {
        _id: '507f1f77bcf86cd799439014',
        encryptedName: 'n'.repeat(120),
        nameIv: 12,
        nameTag: null,
        searchHash: 'h'.repeat(64),
        icon: undefined,
        color: { nope: true },
        sortOrder: 5,
      };

      const estimated = estimateFolderJsonSize(folder);
      expect(estimated).toBeGreaterThanOrEqual(Buffer.byteLength(JSON.stringify(folder), 'utf-8'));
    });
  });
});
