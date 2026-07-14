import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import app from '../src/app.js';
import { MAX_ITEMS_PER_USER, MAX_FOLDERS_PER_USER } from '@hvault/shared';
import { Folder } from '../src/models/Folder.js';
import { VaultItem } from '../src/models/VaultItem.js';
import {
  createTestUser,
  authHeader,
  getCsrf,
  seedFolder,
  seedItem,
  dbBackupPayload,
  rawFolders,
  rawItems,
  idSet,
} from './helpers.js';
import type { TestUser } from './helpers.js';

// ─────────────────────────────────────────────────────────────────────────────
// Cross-account (and repeat) restore: the backup's rows carry _id values that
// are globally unique across the whole `folders`/`vault_items` collections. When
// account B restores a backup whose _ids belong to account A (still live, or
// already restored once), the restore MUST mint a FRESH _id for every non-owned
// row — never reuse the backup's _id (which would collide on the `_id_` primary
// key and, via the per-row guard, silently drop the row). It must also rewire
// parentId / folderId references to the freshly-minted ids.
//
// These tests forward the backup rows with `_id`s INTACT, exactly as the real
// client does (see BackupSettingsPage.handleRestore) — the missing coverage that
// let the E11000 data-loss bug ship.
// ─────────────────────────────────────────────────────────────────────────────

async function restore(
  agent: request.SuperTest<request.Test>,
  token: string,
  body: Record<string, unknown>,
) {
  const { token: csrfToken, cookie: csrfCookie } = await getCsrf(agent);
  return agent
    .post('/api/v1/backup/restore')
    .set('Authorization', authHeader(token))
    .set('x-csrf-token', csrfToken)
    .set('Cookie', csrfCookie)
    .send(body);
}

interface SkipReason {
  reason: string;
}

function hasInvalidSkips(res: request.Response): boolean {
  const itemReasons = (res.body.data.itemSkipReasons ?? []) as SkipReason[];
  const folderReasons = (res.body.data.folderSkipReasons ?? []) as SkipReason[];
  return (
    itemReasons.some((r) => r.reason === 'invalid_item_data') ||
    folderReasons.some((r) => r.reason === 'invalid_folder_data')
  );
}

function byName(docs: Record<string, unknown>[], name: string): Record<string, unknown> {
  const found = docs.find((d) => d.encryptedName === name);
  if (!found) throw new Error(`no doc with encryptedName ${name}`);
  return found;
}

describe('Backup restore — cross-account & repeat (_id collision fix)', () => {
  let userA: TestUser;
  let userB: TestUser;
  let agent: request.SuperTest<request.Test>;

  beforeEach(async () => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    userA = await createTestUser();
    userB = await createTestUser();
  });

  // ── Group 1: the bug ──────────────────────────────────────────────────────

  it('restores every folder and item cross-account with _ids intact (no E11000, none skipped, fresh ids)', async () => {
    await seedFolder(userA.id, { encryptedName: 'fA1' });
    await seedFolder(userA.id, { encryptedName: 'fA2' });
    await seedItem(userA.id, { encryptedName: 'iA1' });
    await seedItem(userA.id, { encryptedName: 'iA2' });
    await seedItem(userA.id, { encryptedName: 'iA3' });

    const payload = await dbBackupPayload(userA.id);
    const backupFolderIds = idSet(payload.folders as { _id: unknown }[]);
    const backupItemIds = idSet(payload.items as { _id: unknown }[]);

    const res = await restore(agent, userB.accessToken, {
      conflictStrategy: 'skip',
      data: JSON.stringify(payload),
    });

    expect(res.status).toBe(200);
    expect(res.body.data.foldersRestored).toBe(2);
    expect(res.body.data.itemsRestored).toBe(3);
    expect(res.body.data.foldersSkipped).toBe(0);
    expect(res.body.data.itemsSkipped).toBe(0);
    expect(hasInvalidSkips(res)).toBe(false);

    // B has all rows, each with a FRESH _id (disjoint from the backup ids).
    const bFolders = await rawFolders(userB.id);
    const bItems = await rawItems(userB.id);
    expect(bFolders).toHaveLength(2);
    expect(bItems).toHaveLength(3);
    for (const id of idSet(bFolders as { _id: unknown }[])) {
      expect(backupFolderIds.has(id)).toBe(false);
    }
    for (const id of idSet(bItems as { _id: unknown }[])) {
      expect(backupItemIds.has(id)).toBe(false);
    }

    // Account A is completely untouched (cross-user isolation).
    const aFolders = await rawFolders(userA.id);
    const aItems = await rawItems(userA.id);
    expect(aFolders).toHaveLength(2);
    expect(aItems).toHaveLength(3);
    expect(idSet(aFolders as { _id: unknown }[])).toEqual(backupFolderIds);
    expect(idSet(aItems as { _id: unknown }[])).toEqual(backupItemIds);
  });

  it('restoring the same cross-account backup twice with skip is idempotent (sourceRefId match, no duplication)', async () => {
    await seedFolder(userA.id, { encryptedName: 'fA1' });
    await seedItem(userA.id, { encryptedName: 'iA1' });
    await seedItem(userA.id, { encryptedName: 'iA2' });
    const payload = await dbBackupPayload(userA.id);

    const res1 = await restore(agent, userB.accessToken, {
      conflictStrategy: 'skip',
      data: JSON.stringify(payload),
    });
    const res2 = await restore(agent, userB.accessToken, {
      conflictStrategy: 'skip',
      data: JSON.stringify(payload),
    });

    expect(res1.status).toBe(200);
    expect(res2.status).toBe(200);
    expect(hasInvalidSkips(res1)).toBe(false);
    expect(hasInvalidSkips(res2)).toBe(false);
    // First restore mints fresh ids stamped with sourceRefId = the backup ref id.
    expect(res1.body.data.foldersRestored).toBe(1);
    expect(res1.body.data.itemsRestored).toBe(2);
    // Second restore matches those rows by (userId, sourceRefId) → skipped, so
    // the foreign content is NOT duplicated on repeat.
    expect(res2.body.data.foldersSkipped).toBe(1);
    expect(res2.body.data.itemsSkipped).toBe(2);
    expect(res2.body.data.foldersRestored).toBe(0);
    expect(res2.body.data.itemsRestored).toBe(0);
    expect(await Folder.countDocuments({ userId: userB.id })).toBe(1);
    expect(await VaultItem.countDocuments({ userId: userB.id })).toBe(2);
    // A untouched.
    expect(await Folder.countDocuments({ userId: userA.id })).toBe(1);
    expect(await VaultItem.countDocuments({ userId: userA.id })).toBe(2);
  });

  // ── Group 2: relationship preservation ────────────────────────────────────

  it('rewires a 3-level folder tree to the new ids cross-account', async () => {
    const root = await seedFolder(userA.id, { encryptedName: 'root' });
    const mid = await seedFolder(userA.id, { encryptedName: 'mid', parentId: root._id });
    await seedFolder(userA.id, { encryptedName: 'leaf', parentId: mid._id });
    const payload = await dbBackupPayload(userA.id);
    const backupFolderIds = idSet(payload.folders as { _id: unknown }[]);

    const res = await restore(agent, userB.accessToken, {
      conflictStrategy: 'skip',
      data: JSON.stringify(payload),
    });

    expect(res.status).toBe(200);
    expect(res.body.data.foldersRestored).toBe(3);
    expect(hasInvalidSkips(res)).toBe(false);

    const bFolders = await rawFolders(userB.id);
    const newRoot = byName(bFolders, 'root');
    const newMid = byName(bFolders, 'mid');
    const newLeaf = byName(bFolders, 'leaf');

    expect(newRoot.parentId).toBeUndefined();
    expect(String(newMid.parentId)).toBe(String(newRoot._id));
    expect(String(newLeaf.parentId)).toBe(String(newMid._id));
    // No new folder references a stale backup id.
    for (const f of bFolders) {
      if (f.parentId != null) {
        expect(backupFolderIds.has(String(f.parentId))).toBe(false);
      }
    }
    // A's tree unchanged.
    const aFolders = await rawFolders(userA.id);
    expect(String(byName(aFolders, 'mid').parentId)).toBe(String(root._id));
    expect(String(byName(aFolders, 'leaf').parentId)).toBe(String(mid._id));
  });

  it('remaps item folderId to the new folder id cross-account (unfiled stays unfiled)', async () => {
    const folder = await seedFolder(userA.id, { encryptedName: 'fA' });
    await seedItem(userA.id, { encryptedName: 'iA1', folderId: folder._id });
    await seedItem(userA.id, { encryptedName: 'iA2', folderId: folder._id });
    await seedItem(userA.id, { encryptedName: 'iA3' });
    const payload = await dbBackupPayload(userA.id);

    const res = await restore(agent, userB.accessToken, {
      conflictStrategy: 'skip',
      data: JSON.stringify(payload),
    });

    expect(res.status).toBe(200);
    expect(res.body.data.foldersRestored).toBe(1);
    expect(res.body.data.itemsRestored).toBe(3);
    expect(hasInvalidSkips(res)).toBe(false);

    const bFolders = await rawFolders(userB.id);
    const bItems = await rawItems(userB.id);
    const newFolder = byName(bFolders, 'fA');
    expect(String(newFolder._id)).not.toBe(String(folder._id));
    expect(String(byName(bItems, 'iA1').folderId)).toBe(String(newFolder._id));
    expect(String(byName(bItems, 'iA2').folderId)).toBe(String(newFolder._id));
    expect(byName(bItems, 'iA3').folderId).toBeUndefined();
  });

  // ── Group 3: same-account idempotency (owned rows keep their id) ───────────

  it('same-account skip restore is idempotent (no duplication, no E11000)', async () => {
    const folder = await seedFolder(userA.id, { encryptedName: 'f' });
    const item = await seedItem(userA.id, { encryptedName: 'i' });
    const payload = await dbBackupPayload(userA.id);

    for (let n = 0; n < 2; n++) {
      const res = await restore(agent, userA.accessToken, {
        conflictStrategy: 'skip',
        data: JSON.stringify(payload),
      });
      expect(res.status).toBe(200);
      expect(res.body.data.foldersSkipped).toBe(1);
      expect(res.body.data.itemsSkipped).toBe(1);
      expect(res.body.data.folderSkipReasons).toContainEqual({
        folderId: String(folder._id),
        reason: 'conflict_skipped',
      });
      expect(res.body.data.itemSkipReasons).toContainEqual({
        itemId: String(item._id),
        reason: 'conflict_skipped',
      });
    }
    expect(await Folder.countDocuments({ userId: userA.id })).toBe(1);
    expect(await VaultItem.countDocuments({ userId: userA.id })).toBe(1);
  });

  it('same-account overwrite restore updates in place twice (no duplication)', async () => {
    const folder = await seedFolder(userA.id, { encryptedName: 'orig' });
    const item = await seedItem(userA.id, { encryptedName: 'orig' });
    const payload = await dbBackupPayload(userA.id);

    // Diverge the live docs so overwrite has something to revert.
    await Folder.updateOne({ _id: folder._id }, { $set: { encryptedName: 'modified' } });
    await VaultItem.updateOne({ _id: item._id }, { $set: { encryptedName: 'modified' } });

    for (let n = 0; n < 2; n++) {
      const res = await restore(agent, userA.accessToken, {
        conflictStrategy: 'overwrite',
        data: JSON.stringify(payload),
      });
      expect(res.status).toBe(200);
      expect(res.body.data.foldersRestored).toBe(1);
      expect(res.body.data.itemsRestored).toBe(1);
      expect(hasInvalidSkips(res)).toBe(false);
    }
    expect(await Folder.countDocuments({ userId: userA.id })).toBe(1);
    expect(await VaultItem.countDocuments({ userId: userA.id })).toBe(1);
    const liveFolder = await Folder.findById(folder._id).lean();
    const liveItem = await VaultItem.findById(item._id).lean();
    expect(liveFolder!.encryptedName).toBe('orig');
    expect(liveItem!.encryptedName).toBe('orig');
  });

  // ── Group 4: owned-vs-foreign boundary ─────────────────────────────────────

  it('owned rows use the conflict path and are never re-minted (keep_both keeps the original)', async () => {
    const item = await seedItem(userA.id, { encryptedName: 'own-orig' });
    const payload = await dbBackupPayload(userA.id);
    // The backup carries a different name for the same _id.
    (payload.items[0] as Record<string, unknown>).encryptedName = 'from-backup';

    const res = await restore(agent, userA.accessToken, {
      conflictStrategy: 'keep_both',
      data: JSON.stringify(payload),
    });

    expect(res.status).toBe(200);
    expect(res.body.data.itemsRestored).toBe(1);
    expect(await VaultItem.countDocuments({ userId: userA.id })).toBe(2);
    // The original still exists with its original _id and name.
    const original = await VaultItem.findById(item._id).lean();
    expect(original!.encryptedName).toBe('own-orig');
    // The duplicate got a fresh id and the backup name.
    const items = await rawItems(userA.id);
    const dup = byName(items, 'from-backup');
    expect(String(dup._id)).not.toBe(String(item._id));
  });

  // ── Group 5: folder processing-order independence ──────────────────────────

  it('nests a child listed BEFORE its parent correctly (cross-account)', async () => {
    const parent = await seedFolder(userA.id, { encryptedName: 'parent' });
    await seedFolder(userA.id, { encryptedName: 'child', parentId: parent._id });
    const payload = await dbBackupPayload(userA.id);
    // Force child-before-parent ordering.
    payload.folders = [byName(payload.folders, 'child'), byName(payload.folders, 'parent')];

    const res = await restore(agent, userB.accessToken, {
      conflictStrategy: 'skip',
      data: JSON.stringify(payload),
    });

    expect(res.status).toBe(200);
    expect(res.body.data.foldersRestored).toBe(2);
    expect(hasInvalidSkips(res)).toBe(false);

    const bFolders = await rawFolders(userB.id);
    const newParent = byName(bFolders, 'parent');
    const newChild = byName(bFolders, 'child');
    expect(newParent.parentId).toBeUndefined();
    expect(String(newChild.parentId)).toBe(String(newParent._id));
    expect(String(newChild.parentId)).not.toBe(String(parent._id));
  });

  // ── Group 6: mixed backup (some rows owned by the restorer, some foreign) ──

  it('mixed overwrite: owned rows update in place, foreign colliding rows mint fresh + remap', async () => {
    // B owns these already.
    const fOwn = await seedFolder(userB.id, { encryptedName: 'fOwn' });
    const iOwn = await seedItem(userB.id, { encryptedName: 'own-orig' });
    // A owns these (foreign to B).
    const fForeign = await seedFolder(userA.id, { encryptedName: 'fForeign' });
    await seedItem(userA.id, { encryptedName: 'iForeign', folderId: fForeign._id });

    const ownPayload = await dbBackupPayload(userB.id);
    const foreignPayload = await dbBackupPayload(userA.id);
    (ownPayload.folders[0] as Record<string, unknown>).encryptedName = 'own-folder-v2';
    (ownPayload.items[0] as Record<string, unknown>).encryptedName = 'own-from-backup';

    const data = JSON.stringify({
      folders: [...ownPayload.folders, ...foreignPayload.folders],
      items: [...ownPayload.items, ...foreignPayload.items],
    });

    const res = await restore(agent, userB.accessToken, { conflictStrategy: 'overwrite', data });

    expect(res.status).toBe(200);
    expect(res.body.data.foldersRestored).toBe(2);
    expect(res.body.data.itemsRestored).toBe(2);
    expect(hasInvalidSkips(res)).toBe(false);

    // Owned rows overwritten in place — no duplication.
    expect(await Folder.countDocuments({ userId: userB.id })).toBe(2);
    expect(await VaultItem.countDocuments({ userId: userB.id })).toBe(2);
    expect((await Folder.findById(fOwn._id).lean())!.encryptedName).toBe('own-folder-v2');
    expect((await VaultItem.findById(iOwn._id).lean())!.encryptedName).toBe('own-from-backup');

    // Foreign rows minted fresh + folderId remapped.
    const bFolders = await rawFolders(userB.id);
    const bItems = await rawItems(userB.id);
    const newForeignFolder = byName(bFolders, 'fForeign');
    expect(String(newForeignFolder._id)).not.toBe(String(fForeign._id));
    expect(String(byName(bItems, 'iForeign').folderId)).toBe(String(newForeignFolder._id));

    // A untouched.
    expect(await Folder.countDocuments({ userId: userA.id })).toBe(1);
    expect(await VaultItem.countDocuments({ userId: userA.id })).toBe(1);
  });

  it('mixed skip: owned rows conflict_skipped, foreign rows restored fresh', async () => {
    const fOwn = await seedFolder(userB.id, { encryptedName: 'fOwn' });
    const iOwn = await seedItem(userB.id, { encryptedName: 'iOwn' });
    const fForeign = await seedFolder(userA.id, { encryptedName: 'fForeign' });
    await seedItem(userA.id, { encryptedName: 'iForeign', folderId: fForeign._id });

    const ownPayload = await dbBackupPayload(userB.id);
    const foreignPayload = await dbBackupPayload(userA.id);
    const data = JSON.stringify({
      folders: [...ownPayload.folders, ...foreignPayload.folders],
      items: [...ownPayload.items, ...foreignPayload.items],
    });

    const res = await restore(agent, userB.accessToken, { conflictStrategy: 'skip', data });

    expect(res.status).toBe(200);
    expect(res.body.data.foldersRestored).toBe(1);
    expect(res.body.data.foldersSkipped).toBe(1);
    expect(res.body.data.itemsRestored).toBe(1);
    expect(res.body.data.itemsSkipped).toBe(1);
    expect(res.body.data.folderSkipReasons).toContainEqual({
      folderId: String(fOwn._id),
      reason: 'conflict_skipped',
    });
    expect(res.body.data.itemSkipReasons).toContainEqual({
      itemId: String(iOwn._id),
      reason: 'conflict_skipped',
    });
    expect(hasInvalidSkips(res)).toBe(false);

    const bFolders = await rawFolders(userB.id);
    const bItems = await rawItems(userB.id);
    expect(String(byName(bItems, 'iForeign').folderId)).toBe(
      String(byName(bFolders, 'fForeign')._id),
    );
  });

  // ── Group 7: self-parent guard (tampered backup) ───────────────────────────

  it('clears a self-referential parentId planted by a tampered backup', async () => {
    const folder = await seedFolder(userA.id, { encryptedName: 'self' });
    const payload = await dbBackupPayload(userA.id);
    // Tamper: make the folder its own parent.
    (payload.folders[0] as Record<string, unknown>).parentId = String(folder._id);

    const res = await restore(agent, userB.accessToken, {
      conflictStrategy: 'skip',
      data: JSON.stringify(payload),
    });

    expect(res.status).toBe(200);
    expect(res.body.data.foldersRestored).toBe(1);
    const bFolders = await rawFolders(userB.id);
    expect(byName(bFolders, 'self').parentId).toBeUndefined();
  });

  // ── Group 8: sourceRefId idempotency (Phase 5) ─────────────────────────────
  //
  // Provenance-based (NOT content-based) idempotency. A first restore of
  // non-owned content mints a fresh `_id` stamped with `sourceRefId = the backup
  // row's original _id`; a REPEAT restore of the same backup matches those rows
  // by `(userId, sourceRefId)` and applies the conflict strategy against them
  // instead of duplicating. `skip`/`overwrite` are fully idempotent; `keep_both`
  // still duplicates by contract; two genuinely-distinct rows that merely share
  // a name are NEVER merged (exact-id provenance cannot false-merge).

  it('restoring the same cross-account backup twice with overwrite updates in place (no duplication)', async () => {
    await seedFolder(userA.id, { encryptedName: 'fOrig' });
    await seedItem(userA.id, { encryptedName: 'iOrig' });
    const payload = await dbBackupPayload(userA.id);

    // First restore mints fresh ids stamped with sourceRefId.
    const res1 = await restore(agent, userB.accessToken, {
      conflictStrategy: 'overwrite',
      data: JSON.stringify(payload),
    });
    expect(res1.status).toBe(200);
    expect(res1.body.data.foldersRestored).toBe(1);
    expect(res1.body.data.itemsRestored).toBe(1);
    expect(hasInvalidSkips(res1)).toBe(false);
    expect(await Folder.countDocuments({ userId: userB.id })).toBe(1);
    expect(await VaultItem.countDocuments({ userId: userB.id })).toBe(1);

    // Diverge the restored copies so the second overwrite has something to revert.
    const restoredFolderId = byName(await rawFolders(userB.id), 'fOrig')._id;
    const restoredItemId = byName(await rawItems(userB.id), 'iOrig')._id;
    await Folder.updateOne({ _id: restoredFolderId }, { $set: { encryptedName: 'divergent' } });
    await VaultItem.updateOne({ _id: restoredItemId }, { $set: { encryptedName: 'divergent' } });

    // Second restore matches the prior rows by (userId, sourceRefId) → overwrites
    // them in place. The backup content wins; no new documents are created.
    const res2 = await restore(agent, userB.accessToken, {
      conflictStrategy: 'overwrite',
      data: JSON.stringify(payload),
    });
    expect(res2.status).toBe(200);
    expect(res2.body.data.foldersRestored).toBe(1);
    expect(res2.body.data.itemsRestored).toBe(1);
    expect(hasInvalidSkips(res2)).toBe(false);

    // No duplication — the same physical rows were updated in place.
    expect(await Folder.countDocuments({ userId: userB.id })).toBe(1);
    expect(await VaultItem.countDocuments({ userId: userB.id })).toBe(1);
    expect((await Folder.findById(restoredFolderId).lean())!.encryptedName).toBe('fOrig');
    expect((await VaultItem.findById(restoredItemId).lean())!.encryptedName).toBe('iOrig');
    // A untouched.
    expect(await Folder.countDocuments({ userId: userA.id })).toBe(1);
    expect(await VaultItem.countDocuments({ userId: userA.id })).toBe(1);
  });

  it('same-account restore after a permanent delete is idempotent on repeat (sourceRefId match)', async () => {
    const folder = await seedFolder(userA.id, { encryptedName: 'f' });
    const item = await seedItem(userA.id, { encryptedName: 'i' });
    const payload = await dbBackupPayload(userA.id);

    // Permanently delete the originals — their globally-unique _ids are now gone,
    // so a restore can no longer match them by `_id` (only by sourceRefId, which
    // does not exist yet → the first restore fresh-inserts).
    await Folder.deleteOne({ _id: folder._id });
    await VaultItem.deleteOne({ _id: item._id });
    expect(await Folder.countDocuments({ userId: userA.id })).toBe(0);
    expect(await VaultItem.countDocuments({ userId: userA.id })).toBe(0);

    const res1 = await restore(agent, userA.accessToken, {
      conflictStrategy: 'skip',
      data: JSON.stringify(payload),
    });
    expect(res1.status).toBe(200);
    expect(res1.body.data.foldersRestored).toBe(1);
    expect(res1.body.data.itemsRestored).toBe(1);
    expect(hasInvalidSkips(res1)).toBe(false);
    expect(await Folder.countDocuments({ userId: userA.id })).toBe(1);
    expect(await VaultItem.countDocuments({ userId: userA.id })).toBe(1);

    // Second restore matches the freshly-inserted rows by (userId, sourceRefId)
    // → skipped, so the deleted-and-restored content is not duplicated.
    const res2 = await restore(agent, userA.accessToken, {
      conflictStrategy: 'skip',
      data: JSON.stringify(payload),
    });
    expect(res2.status).toBe(200);
    expect(res2.body.data.foldersSkipped).toBe(1);
    expect(res2.body.data.itemsSkipped).toBe(1);
    expect(res2.body.data.foldersRestored).toBe(0);
    expect(res2.body.data.itemsRestored).toBe(0);
    expect(await Folder.countDocuments({ userId: userA.id })).toBe(1);
    expect(await VaultItem.countDocuments({ userId: userA.id })).toBe(1);
  });

  it('restores two distinct items that share a name and never merges them (repeat = no dup)', async () => {
    // Two genuinely-distinct rows (different _id and encryptedData) that merely
    // share an encryptedName. Content/searchHash dedup would wrongly collapse
    // them to one; sourceRefId provenance keeps both.
    await seedItem(userA.id, { encryptedName: 'twin', encryptedData: 'd1' });
    await seedItem(userA.id, { encryptedName: 'twin', encryptedData: 'd2' });
    const payload = await dbBackupPayload(userA.id);
    expect(payload.items).toHaveLength(2);
    const backupItemIds = idSet(payload.items as { _id: unknown }[]);
    expect(backupItemIds.size).toBe(2); // two genuinely distinct backup rows

    const res1 = await restore(agent, userB.accessToken, {
      conflictStrategy: 'skip',
      data: JSON.stringify(payload),
    });
    expect(res1.status).toBe(200);
    // BOTH restored — not merged into one.
    expect(res1.body.data.itemsRestored).toBe(2);
    expect(hasInvalidSkips(res1)).toBe(false);
    const bItemsAfter1 = await rawItems(userB.id);
    expect(bItemsAfter1.filter((i) => i.encryptedName === 'twin')).toHaveLength(2);
    expect(new Set(bItemsAfter1.map((i) => i.encryptedData))).toEqual(new Set(['d1', 'd2']));
    // Each restored twin is stamped with a DISTINCT backup-row provenance id (its
    // own source _id) — proving the repeat match keys on per-row id, not on the
    // shared encryptedName. A name-based match would be ambiguous here.
    expect(idSet(bItemsAfter1 as { _id: unknown }[]).size).toBe(2);
    expect(new Set(bItemsAfter1.map((i) => i.sourceRefId))).toEqual(backupItemIds);

    // Repeat restore: each twin matches its OWN row by sourceRefId → both skipped,
    // still exactly two.
    const res2 = await restore(agent, userB.accessToken, {
      conflictStrategy: 'skip',
      data: JSON.stringify(payload),
    });
    expect(res2.status).toBe(200);
    expect(res2.body.data.itemsSkipped).toBe(2);
    expect(res2.body.data.itemsRestored).toBe(0);
    expect(await VaultItem.countDocuments({ userId: userB.id })).toBe(2);
    const bItemsAfter2 = await rawItems(userB.id);
    expect(bItemsAfter2.filter((i) => i.encryptedName === 'twin')).toHaveLength(2);
  });

  it('keep_both still duplicates on a repeat cross-account restore (contract)', async () => {
    await seedFolder(userA.id, { encryptedName: 'kf' });
    await seedItem(userA.id, { encryptedName: 'ki' });
    const payload = await dbBackupPayload(userA.id);

    const res1 = await restore(agent, userB.accessToken, {
      conflictStrategy: 'keep_both',
      data: JSON.stringify(payload),
    });
    expect(res1.status).toBe(200);
    expect(res1.body.data.foldersRestored).toBe(1);
    expect(res1.body.data.itemsRestored).toBe(1);
    expect(await Folder.countDocuments({ userId: userB.id })).toBe(1);
    expect(await VaultItem.countDocuments({ userId: userB.id })).toBe(1);

    // keep_both fires even for a (userId, sourceRefId) match — duplication is its
    // defined contract, so a repeat restore grows the collection.
    const res2 = await restore(agent, userB.accessToken, {
      conflictStrategy: 'keep_both',
      data: JSON.stringify(payload),
    });
    expect(res2.status).toBe(200);
    expect(res2.body.data.foldersRestored).toBe(1);
    expect(res2.body.data.itemsRestored).toBe(1);
    expect(await Folder.countDocuments({ userId: userB.id })).toBe(2);
    expect(await VaultItem.countDocuments({ userId: userB.id })).toBe(2);
  });

  it('never leaks sourceRefId through read endpoints after a real restore stamps it', async () => {
    await seedFolder(userA.id, { encryptedName: 'fLeak' });
    await seedItem(userA.id, { encryptedName: 'iLeak' });
    const payload = await dbBackupPayload(userA.id);

    const res = await restore(agent, userB.accessToken, {
      conflictStrategy: 'skip',
      data: JSON.stringify(payload),
    });
    expect(res.status).toBe(200);
    expect(res.body.data.foldersRestored).toBe(1);
    expect(res.body.data.itemsRestored).toBe(1);

    // The restore stamped sourceRefId at the persistence layer (this is what the
    // idempotency match relies on) …
    const storedItem = byName(await rawItems(userB.id), 'iLeak');
    const storedFolder = byName(await rawFolders(userB.id), 'fLeak');
    expect(typeof storedItem.sourceRefId).toBe('string');
    expect(typeof storedFolder.sourceRefId).toBe('string');

    // … yet it is absent from every client-facing response.
    const itemsRes = await agent
      .get('/api/v1/vault/items')
      .set('Authorization', authHeader(userB.accessToken));
    expect(itemsRes.status).toBe(200);
    for (const item of itemsRes.body.data as Record<string, unknown>[]) {
      expect(item).not.toHaveProperty('sourceRefId');
    }
    expect(itemsRes.text).not.toContain('sourceRefId');

    const foldersRes = await agent
      .get('/api/v1/folders')
      .set('Authorization', authHeader(userB.accessToken));
    expect(foldersRes.status).toBe(200);
    for (const folder of foldersRes.body.data as Record<string, unknown>[]) {
      expect(folder).not.toHaveProperty('sourceRefId');
    }
    expect(foldersRes.text).not.toContain('sourceRefId');
  });

  // ── Group 9: per-user caps count NET-NEW inserts, not raw backup size ──────
  //
  // The sourceRefId idempotency (Group 8) makes a repeat skip/overwrite restore a
  // no-op: every prior row matches by (userId, sourceRefId) and inserts nothing.
  // The per-user item/folder caps must therefore count only the rows a restore
  // will actually INSERT, not the raw backup length — otherwise a repeat restore
  // whose `existing + backup.length` crosses the cap would be falsely rejected
  // with 400, contradicting the "fully idempotent across repeated restores"
  // guarantee. keep_both, which genuinely duplicates, must stay bounded by the cap.
  // (Near-cap conditions are simulated by stubbing countDocuments, mirroring
  // phase6-backup-integrity's item-cap test, to avoid seeding hundreds of rows.)

  it('a repeat skip restore whose folders all match by sourceRefId is not rejected at the folder cap', async () => {
    await seedFolder(userA.id, { encryptedName: 'cf1' });
    await seedFolder(userA.id, { encryptedName: 'cf2' });
    await seedFolder(userA.id, { encryptedName: 'cf3' });
    const payload = await dbBackupPayload(userA.id);

    // First restore mints 3 fresh folders in B, each stamped with sourceRefId.
    const first = await restore(agent, userB.accessToken, {
      conflictStrategy: 'skip',
      data: JSON.stringify(payload),
    });
    expect(first.status).toBe(200);
    expect(first.body.data.foldersRestored).toBe(3);

    // Simulate B sitting one below the folder cap. The OLD blunt sum
    // (499 existing + 3 backup = 502 > 500) would 400; the fix counts net-new,
    // and all 3 rows match by sourceRefId → net-new 0 → the restore proceeds.
    const spy = vi
      .spyOn(Folder, 'countDocuments')
      .mockResolvedValueOnce((MAX_FOLDERS_PER_USER - 1) as never);
    const second = await restore(agent, userB.accessToken, {
      conflictStrategy: 'skip',
      data: JSON.stringify(payload),
    });
    spy.mockRestore();

    expect(second.status).toBe(200);
    expect(second.body.data.foldersSkipped).toBe(3);
    expect(second.body.data.foldersRestored).toBe(0);
    // No duplication — B still has exactly the 3 folders from the first restore.
    expect(await Folder.countDocuments({ userId: userB.id })).toBe(3);
  });

  it('a repeat skip restore whose items all match by sourceRefId is not rejected at the item cap', async () => {
    await seedItem(userA.id, { encryptedName: 'ci1' });
    await seedItem(userA.id, { encryptedName: 'ci2' });
    const payload = await dbBackupPayload(userA.id);

    const first = await restore(agent, userB.accessToken, {
      conflictStrategy: 'skip',
      data: JSON.stringify(payload),
    });
    expect(first.status).toBe(200);
    expect(first.body.data.itemsRestored).toBe(2);

    const spy = vi
      .spyOn(VaultItem, 'countDocuments')
      .mockResolvedValueOnce((MAX_ITEMS_PER_USER - 1) as never);
    const second = await restore(agent, userB.accessToken, {
      conflictStrategy: 'skip',
      data: JSON.stringify(payload),
    });
    spy.mockRestore();

    expect(second.status).toBe(200);
    expect(second.body.data.itemsSkipped).toBe(2);
    expect(second.body.data.itemsRestored).toBe(0);
    expect(await VaultItem.countDocuments({ userId: userB.id })).toBe(2);
  });

  it('keep_both stays bounded by the folder cap even when rows match by sourceRefId', async () => {
    await seedFolder(userA.id, { encryptedName: 'kf1' });
    const payload = await dbBackupPayload(userA.id);
    const first = await restore(agent, userB.accessToken, {
      conflictStrategy: 'skip',
      data: JSON.stringify(payload),
    });
    expect(first.status).toBe(200);
    expect(first.body.data.foldersRestored).toBe(1);

    // At the cap: keep_both would mint a fresh duplicate even for a sourceRefId
    // match, so it must still be rejected — the cap's core purpose.
    const spy = vi
      .spyOn(Folder, 'countDocuments')
      .mockResolvedValueOnce(MAX_FOLDERS_PER_USER as never);
    const res = await restore(agent, userB.accessToken, {
      conflictStrategy: 'keep_both',
      data: JSON.stringify(payload),
    });
    spy.mockRestore();

    expect(res.status).toBe(400);
    expect(String(res.body.message)).toMatch(/folder limit/i);
    // Rejected before any write — no duplicate created.
    expect(await Folder.countDocuments({ userId: userB.id })).toBe(1);
  });
});
