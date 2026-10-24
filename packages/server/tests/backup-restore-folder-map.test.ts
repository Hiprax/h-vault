/**
 * `POST /backup/restore` answers `folderIdMap`: which of this account's folders
 * each backup folder became.
 *
 * A full backup's documents are filed by the browser, after the vault rows, through
 * this map: the browser cannot learn otherwise which folder a keep-both copy, or a
 * folder this account never had, was created as. So every branch of the folder loop
 * is pinned against the row the database really holds, and the one that stores
 * nothing (a new folder refused for room) is pinned to be ABSENT, because a document
 * filed under an id nobody owns would come back in a folder that does not exist.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import mongoose from 'mongoose';
import { Folder } from '../src/models/Folder.js';
import { createTestUser, sampleFolder, type TestUser } from './helpers.js';
import {
  apiCall,
  createQuotaItem,
  expectCounterExact,
  restoreQuota,
  savedQuota,
  setQuotaBytes,
} from './support/vaultQuotaApi.js';

let quota: unknown;

beforeEach(() => {
  quota = savedQuota();
});

afterEach(() => {
  restoreQuota(quota);
});

/** Restore `folders` (and no items) under `conflictStrategy`, asserting the 200. */
async function restoreFolders(
  user: TestUser,
  conflictStrategy: 'skip' | 'overwrite' | 'keep_both',
  folders: Record<string, unknown>[],
): Promise<{ folderIdMap: { backupId: string; folderId: string }[] } & Record<string, unknown>> {
  const res = await apiCall(user, 'post', '/backup/restore', {
    conflictStrategy,
    data: JSON.stringify({ folders, items: [] }),
  });
  expect(res.status).toBe(200);
  return res.body.data as { folderIdMap: { backupId: string; folderId: string }[] };
}

/** The ids of every folder this account holds. */
async function folderIds(user: TestUser): Promise<string[]> {
  return (await Folder.find({ userId: user.id }).select('_id').lean()).map((f) => String(f._id));
}

describe('restore folderIdMap', () => {
  it('is an empty list when the backup has no folders', async () => {
    const user = await createTestUser();
    const data = await restoreFolders(user, 'skip', []);
    expect(data.folderIdMap).toEqual([]);
  });

  it.each(['skip', 'overwrite'] as const)(
    'maps a folder this account owns to itself under %s',
    async (strategy) => {
      const user = await createTestUser();
      const created = await apiCall(user, 'post', '/folders', sampleFolder());
      const ownedId = String(created.body.data._id);

      const data = await restoreFolders(user, strategy, [{ _id: ownedId, ...sampleFolder() }]);

      expect(data.folderIdMap).toEqual([{ backupId: ownedId, folderId: ownedId }]);
      // Nothing new was created to map onto.
      expect(await folderIds(user)).toEqual([ownedId]);
    },
  );

  it('maps a folder this account does not have to the folder the restore created for it', async () => {
    const user = await createTestUser();
    const foreignId = new mongoose.Types.ObjectId().toString();

    const data = await restoreFolders(user, 'skip', [{ _id: foreignId, ...sampleFolder() }]);

    const [created] = await folderIds(user);
    expect(created).toBeDefined();
    // A fresh id, never the backup's: the backup's id may belong to another account.
    expect(created).not.toBe(foreignId);
    expect(data.folderIdMap).toEqual([{ backupId: foreignId, folderId: created }]);
  });

  it('maps a repeat restore of the same backup onto the copy the first one created', async () => {
    const user = await createTestUser();
    const foreignId = new mongoose.Types.ObjectId().toString();
    await restoreFolders(user, 'skip', [{ _id: foreignId, ...sampleFolder() }]);
    const [copy] = await folderIds(user);

    const again = await restoreFolders(user, 'skip', [{ _id: foreignId, ...sampleFolder() }]);

    expect(again.folderIdMap).toEqual([{ backupId: foreignId, folderId: copy }]);
    expect(await folderIds(user)).toEqual([copy]);
  });

  it('maps a keep-both duplicate of an owned folder to the NEW copy, not the original', async () => {
    const user = await createTestUser();
    const created = await apiCall(user, 'post', '/folders', sampleFolder());
    const ownedId = String(created.body.data._id);

    const data = await restoreFolders(user, 'keep_both', [{ _id: ownedId, ...sampleFolder() }]);

    const copies = (await folderIds(user)).filter((id) => id !== ownedId);
    expect(copies).toHaveLength(1);
    expect(data.folderIdMap).toEqual([{ backupId: ownedId, folderId: copies[0] }]);
  });

  it('keeps the mapping of a folder skipped for room when it matched one the account has', async () => {
    const user = await createTestUser();
    const created = await apiCall(user, 'post', '/folders', sampleFolder());
    const ownedId = String(created.body.data._id);
    await createQuotaItem(user, 400);
    const used = await expectCounterExact(user);
    // No room for the overwrite's 3,000-character name.
    setQuotaBytes(used + 900);

    const data = await restoreFolders(user, 'overwrite', [
      { _id: ownedId, ...sampleFolder({ encryptedName: 'f'.repeat(3_000) }) },
    ]);

    expect(data.folderSkipReasons).toEqual([{ folderId: ownedId, reason: 'storage_limit' }]);
    expect(data.folderIdMap).toEqual([{ backupId: ownedId, folderId: ownedId }]);
  });

  it('leaves out a NEW folder refused for room, and maps the rest of the backup', async () => {
    const user = await createTestUser();
    await createQuotaItem(user, 400);
    const used = await expectCounterExact(user);
    setQuotaBytes(used + 900);
    const refusedId = new mongoose.Types.ObjectId().toString();
    const fittingId = new mongoose.Types.ObjectId().toString();

    const data = await restoreFolders(user, 'keep_both', [
      { _id: refusedId, ...sampleFolder({ encryptedName: 'f'.repeat(3_000) }) },
      { _id: fittingId, ...sampleFolder() },
    ]);

    expect(data.folderSkipReasons).toEqual([{ folderId: refusedId, reason: 'storage_limit' }]);
    const stored = await folderIds(user);
    expect(stored).toHaveLength(1);
    // The refused folder maps to nothing: no entry names it, and the one entry
    // there is names a folder the account really holds.
    expect(data.folderIdMap).toEqual([{ backupId: fittingId, folderId: stored[0] }]);
  });
});
