/**
 * `POST /vault/items/purge-unreadable`: the owner permanently deleting the entries
 * no key the account stores can open (what a master password reset leaves behind).
 *
 * The server cannot tell which rows those are, so what is pinned here is the
 * envelope around the client's judgement: the master password, the same-key proof
 * (the wrapper the client judged under must still be the account's), no interrupted
 * rotation, no rotation running, and a row deleted ONLY while its stored IVs are the
 * ones the client named. A row rewritten since the check, another account's row, a
 * row already gone: kept, and counted as skipped. Every refusal deletes nothing and
 * writes no purge audit row. The byte quota and row counters move by exactly what
 * went. Both topologies, because a folder's removal is transactional on a replica
 * set and sequential on a standalone mongod.
 */
import { describe, it, expect, afterEach, beforeAll, vi } from 'vitest';
import mongoose from 'mongoose';
import { DOCUMENT_PLAINTEXT_CHUNK_BYTES } from '@hvault/shared';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { Document } from '../src/models/Document.js';
import { User } from '../src/models/User.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { buildObjectKey } from '../src/utils/documentObjects.js';
import { SESSION_INVALID_MESSAGE } from '../src/constants/index.js';
import { supportsTransactions } from '../src/utils/transactionSupport.js';
import { useReplicaSetConnection } from './mongoHarness.js';
import { createTestUser, sampleFolder, type TestUser } from './helpers.js';
import { apiCall, createQuotaItem, expectCounterExact } from './support/vaultQuotaApi.js';

afterEach(() => {
  vi.restoreAllMocks();
});

/** The stored wrapper, as the client read it when it judged the entries. */
async function wrapperOf(userId: string) {
  const row = await User.findById(userId).select('encryptedVaultKey vaultKeyIv vaultKeyTag').lean();
  return {
    encryptedVaultKey: String(row?.encryptedVaultKey),
    vaultKeyIv: String(row?.vaultKeyIv),
    vaultKeyTag: String(row?.vaultKeyTag),
  };
}

/** One item as the client names it: its id and the IVs it had when it was judged. */
async function judgedItem(id: string) {
  const row = await VaultItem.findById(id).lean();
  return { id, nameIv: String(row?.nameIv), dataIv: String(row?.dataIv) };
}

async function judgedFolder(id: string) {
  const row = await Folder.findById(id).lean();
  return { id, nameIv: String(row?.nameIv) };
}

async function createFolder(user: TestUser, parentId?: string): Promise<string> {
  const res = await apiCall(
    user,
    'post',
    '/folders',
    sampleFolder({ vaultKeyVersion: 0, ...(parentId ? { parentId } : {}) }),
  );
  expect(res.status).toBe(201);
  return String(res.body.data._id);
}

async function seedDocument(user: TestUser, folderId: string): Promise<string> {
  const documentId = new mongoose.Types.ObjectId();
  await Document.create({
    _id: documentId,
    userId: user.id,
    folderId,
    objectKey: buildObjectKey(user.id, documentId.toHexString()),
    encryptedDek: 'dek-ciphertext',
    dekIv: 'dek-iv',
    dekTag: 'dek-tag',
    streamSalt: Buffer.alloc(32, 7).toString('base64'),
    noncePrefix: Buffer.alloc(7, 3).toString('base64'),
    encryptedMeta: 'meta-ciphertext',
    metaIv: 'meta-iv',
    metaTag: 'meta-tag',
    chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    chunkCount: 1,
    ciphertextBytes: 48,
    plaintextBytes: 32,
  });
  return String(documentId);
}

async function purge(
  user: TestUser,
  rows: {
    items?: { id: string; nameIv: string; dataIv: string }[];
    folders?: { id: string; nameIv: string }[];
  },
  overrides: Record<string, unknown> = {},
) {
  return apiCall(user, 'post', '/vault/items/purge-unreadable', {
    authHash: user.rawPassword,
    ...(await wrapperOf(user.id)),
    items: rows.items ?? [],
    folders: rows.folders ?? [],
    ...overrides,
  });
}

async function purgeAudits(userId: string) {
  return AuditLog.find({ userId, action: 'unreadable_entries_purged' }).lean();
}

async function itemIds(userId: string): Promise<string[]> {
  return (await VaultItem.find({ userId }).select('_id').lean())
    .map((row) => String(row._id))
    .sort();
}

function purgeSuite(): void {
  it('deletes exactly the named items, settles the counters by what went, and audits the counts', async () => {
    const user = await createTestUser();
    const unreadableA = await createQuotaItem(user, 300);
    const unreadableB = await createQuotaItem(user, 500);
    const readable = await createQuotaItem(user, 100);
    // A trashed row that is NOT named stays too.
    const trashed = await createQuotaItem(user, 100);
    expect((await apiCall(user, 'delete', `/vault/items/${trashed}`)).status).toBe(200);
    const before = await expectCounterExact(user);

    const res = await purge(user, {
      items: [await judgedItem(unreadableA), await judgedItem(unreadableB)],
    });

    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.data).toEqual({
      deletedItems: 2,
      deletedFolders: 0,
      skippedItems: 0,
      skippedFolders: 0,
    });
    expect(await itemIds(user.id)).toEqual([readable, trashed].sort());
    expect(await expectCounterExact(user)).toBeLessThan(before);
    const audits = await purgeAudits(user.id);
    expect(audits).toHaveLength(1);
    expect(audits[0]?.metadata).toEqual({
      deletedItems: 2,
      deletedFolders: 0,
      skippedItems: 0,
      skippedFolders: 0,
    });
  });

  it('keeps a row rewritten since the check, a row already gone and another account’s row', async () => {
    const user = await createTestUser();
    const stranger = await createTestUser();
    const resealed = await createQuotaItem(user, 100);
    const gone = await createQuotaItem(user, 100);
    const theirs = await createQuotaItem(stranger, 100);
    const judged = [await judgedItem(resealed), await judgedItem(gone), await judgedItem(theirs)];
    // Since the check: the first row was rewritten (fresh IVs), the second deleted.
    const edit = await apiCall(user, 'put', `/vault/items/${resealed}`, {
      encryptedData: 'resealed-since-the-check',
      dataIv: 'fresh-data-iv',
      dataTag: 'fresh-data-tag',
      vaultKeyVersion: 0,
    });
    expect(edit.status).toBe(200);
    expect((await apiCall(user, 'delete', `/vault/items/${gone}`)).status).toBe(200);
    expect((await apiCall(user, 'delete', `/vault/items/${gone}/permanent`)).status).toBe(200);

    const res = await purge(user, { items: judged });

    expect(res.status).toBe(200);
    expect(res.body.data).toEqual({
      deletedItems: 0,
      deletedFolders: 0,
      skippedItems: 3,
      skippedFolders: 0,
    });
    expect(await itemIds(user.id)).toEqual([resealed]);
    expect(await itemIds(stranger.id)).toEqual([theirs]);
    await expectCounterExact(user);
    await expectCounterExact(stranger);
  });

  it('keeps an item renamed since the check, whose name IV alone changed', async () => {
    const user = await createTestUser();
    const renamed = await createQuotaItem(user, 100);
    const judged = await judgedItem(renamed);
    const rename = await apiCall(user, 'put', `/vault/items/${renamed}`, {
      encryptedName: 'renamed-since-the-check',
      nameIv: 'fresh-name-iv',
      nameTag: 'fresh-name-tag',
      vaultKeyVersion: 0,
    });
    expect(rename.status).toBe(200);

    const res = await purge(user, { items: [judged] });

    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({ deletedItems: 0, skippedItems: 1 });
    expect(await itemIds(user.id)).toEqual([renamed]);
    await expectCounterExact(user);
  });

  it('removes a folder and moves its items, documents and child folders up to its parent', async () => {
    const user = await createTestUser();
    const parent = await createFolder(user);
    const unreadable = await createFolder(user, parent);
    const child = await createFolder(user, unreadable);
    const member = await createQuotaItem(user, 100, { folderId: unreadable });
    const document = await seedDocument(user, unreadable);

    const res = await purge(user, { folders: [await judgedFolder(unreadable)] });

    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.data).toEqual({
      deletedItems: 0,
      deletedFolders: 1,
      skippedItems: 0,
      skippedFolders: 0,
    });
    expect(await Folder.findById(unreadable).lean()).toBeNull();
    expect(String((await Folder.findById(child).lean())?.parentId)).toBe(parent);
    expect(String((await VaultItem.findById(member).lean())?.folderId)).toBe(parent);
    expect(String((await Document.findById(document).lean())?.folderId)).toBe(parent);
    await expectCounterExact(user);
  });

  it('moves nothing and keeps a folder renamed since the check', async () => {
    const user = await createTestUser();
    const parent = await createFolder(user);
    const folder = await createFolder(user, parent);
    const child = await createFolder(user, folder);
    const member = await createQuotaItem(user, 100, { folderId: folder });
    const judged = await judgedFolder(folder);
    const rename = await apiCall(user, 'put', `/folders/${folder}`, {
      encryptedName: 'renamed-since-the-check',
      nameIv: 'fresh-folder-iv',
      nameTag: 'fresh-folder-tag',
      vaultKeyVersion: 0,
    });
    expect(rename.status).toBe(200);

    const res = await purge(user, { folders: [judged] });

    expect(res.status).toBe(200);
    expect(res.body.data).toEqual({
      deletedItems: 0,
      deletedFolders: 0,
      skippedItems: 0,
      skippedFolders: 1,
    });
    expect(await Folder.findById(folder).lean()).not.toBeNull();
    expect(String((await Folder.findById(child).lean())?.parentId)).toBe(folder);
    expect(String((await VaultItem.findById(member).lean())?.folderId)).toBe(folder);
    await expectCounterExact(user);
  });

  it('never removes another account’s folder, whatever it is named with', async () => {
    const user = await createTestUser();
    const stranger = await createTestUser();
    const theirs = await createFolder(stranger);
    const theirMember = await createQuotaItem(stranger, 100, { folderId: theirs });

    const res = await purge(user, { folders: [await judgedFolder(theirs)] });

    expect(res.status).toBe(200);
    expect(res.body.data).toEqual({
      deletedItems: 0,
      deletedFolders: 0,
      skippedItems: 0,
      skippedFolders: 1,
    });
    expect(await Folder.findById(theirs).lean()).not.toBeNull();
    expect(String((await VaultItem.findById(theirMember).lean())?.folderId)).toBe(theirs);
    await expectCounterExact(user);
    await expectCounterExact(stranger);
  });

  it('keeps the counters equal to what is stored when moving a removed folder’s contents fails', async () => {
    const user = await createTestUser();
    const parent = await createFolder(user);
    const folder = await createFolder(user, parent);
    const member = await createQuotaItem(user, 100, { folderId: folder });
    await seedDocument(user, folder);
    const judged = await judgedFolder(folder);
    // The folder's claim lands, then moving its documents up fails for good: in a
    // transaction the claim is rolled back with it; without one it is final.
    const real = mongoose.mongo.Collection.prototype.updateMany;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'updateMany').mockImplementation(function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof real>
    ) {
      if (this.collectionName === 'documents') {
        return Promise.reject(new Error('documents unavailable'));
      }
      return real.apply(this, args);
    } as never);

    const res = await purge(user, { folders: [judged] });

    expect(res.status).toBe(500);
    vi.restoreAllMocks();
    const stillThere = (await Folder.findById(folder).lean()) !== null;
    expect(stillThere).toBe(supportsTransactions());
    if (stillThere) {
      // Rolled back whole: the member never moved, and nothing went to record.
      expect(String((await VaultItem.findById(member).lean())?.folderId)).toBe(folder);
      expect(await purgeAudits(user.id)).toHaveLength(0);
    } else {
      // Without a transaction the claim is final: the deletion is on record.
      const audits = await purgeAudits(user.id);
      expect(audits).toHaveLength(1);
      expect(audits[0]?.metadata).toEqual({
        deletedItems: 0,
        deletedFolders: 1,
        skippedItems: 0,
        skippedFolders: 0,
        completed: false,
      });
    }
    // Whatever stands, the counters say exactly that: no row is subtracted that is
    // still stored, and none kept that is gone.
    await expectCounterExact(user);
  });
}

/** Every refusal leaves every row, every counter and the audit log as they were. */
async function expectNothingDeleted(user: TestUser, items: string[], folders: string[]) {
  expect(await itemIds(user.id)).toEqual([...items].sort());
  expect(
    (await Folder.find({ userId: user.id }).lean()).map((row) => String(row._id)).sort(),
  ).toEqual([...folders].sort());
  expect(await purgeAudits(user.id)).toHaveLength(0);
  await expectCounterExact(user);
}

describe('purging unreadable entries, standalone', () => {
  purgeSuite();

  it('refuses a wrong master password with 401, audits it, and deletes nothing', async () => {
    const user = await createTestUser();
    const item = await createQuotaItem(user, 100);
    const folder = await createFolder(user);

    const res = await purge(
      user,
      { items: [await judgedItem(item)], folders: [await judgedFolder(folder)] },
      { authHash: 'not-the-master-password' },
    );

    expect(res.status).toBe(401);
    await expectNothingDeleted(user, [item], [folder]);
    const failed = await AuditLog.findOne({
      userId: user.id,
      action: 'password_verification_failed',
    }).lean();
    expect(failed?.metadata).toEqual({ endpoint: 'purge_unreadable' });
  });

  it('refuses with 409 when the vault key changed since the check, and deletes nothing', async () => {
    const user = await createTestUser();
    const item = await createQuotaItem(user, 100);

    const res = await purge(
      user,
      { items: [await judgedItem(item)] },
      {
        encryptedVaultKey: 'a-wrapper-this-account-no-longer-stores',
      },
    );

    expect(res.status).toBe(409);
    expect(res.body.message).toBe(
      "Check the entries again, then retry: this account's vault key changed since they were checked, so nothing was deleted.",
    );
    expect(res.body.data).toBeUndefined();
    await expectNothingDeleted(user, [item], []);
  });

  it.each([
    ['vaultKeyIv', { vaultKeyIv: 'another-iv' }],
    ['vaultKeyTag', { vaultKeyTag: 'another-tag' }],
  ])('refuses with 409 when only the wrapper %s differs', async (_, override) => {
    const user = await createTestUser();
    const item = await createQuotaItem(user, 100);

    const res = await purge(user, { items: [await judgedItem(item)] }, override);

    expect(res.status).toBe(409);
    await expectNothingDeleted(user, [item], []);
  });

  it('refuses with 409 while an interrupted rotation is outstanding', async () => {
    const user = await createTestUser();
    const item = await createQuotaItem(user, 100);
    await User.updateOne(
      { _id: user.id },
      {
        $set: {
          pendingEncryptedVaultKey: 'pending-wrapper',
          pendingVaultKeyIv: 'pending-iv',
          pendingVaultKeyTag: 'pending-tag',
        },
      },
    );

    const res = await purge(user, { items: [await judgedItem(item)] });

    expect(res.status).toBe(409);
    expect(res.body.message).toBe(
      'Finish the interrupted vault key rotation first: these entries may open under the key it was moving to. Nothing was deleted.',
    );
    await expectNothingDeleted(user, [item], []);
  });

  it('refuses with 409 while a rotation is running', async () => {
    const user = await createTestUser();
    const item = await createQuotaItem(user, 100);
    await User.updateOne({ _id: user.id }, { $set: { rotationInProgress: true } });

    const res = await purge(user, { items: [await judgedItem(item)] });

    expect(res.status).toBe(409);
    expect(res.body.message).toBe('Vault key rotation is in progress. Please wait and retry.');
    await User.updateOne({ _id: user.id }, { $set: { rotationInProgress: false } });
    await expectNothingDeleted(user, [item], []);
  });

  it('answers an account being erased as a dead session, deleting nothing', async () => {
    const user = await createTestUser();
    const item = await createQuotaItem(user, 100);
    const judged = await judgedItem(item);
    const wrapper = await wrapperOf(user.id);
    await User.updateOne({ _id: user.id }, { $set: { deletionPending: true } });

    const res = await apiCall(user, 'post', '/vault/items/purge-unreadable', {
      authHash: user.rawPassword,
      ...wrapper,
      items: [judged],
      folders: [],
    });

    expect(res.status).toBe(401);
    expect(await itemIds(user.id)).toEqual([item]);
  });

  it('answers as a dead session when the account goes between sign-in and the purge’s own read', async () => {
    for (const goes of [
      (id: string) => User.updateOne({ _id: id }, { $set: { deletionPending: true } }),
      (id: string) => User.deleteOne({ _id: id }),
    ]) {
      const user = await createTestUser();
      const item = await createQuotaItem(user, 100);
      const judged = await judgedItem(item);
      const wrapper = await wrapperOf(user.id);
      // The handler's own account read is the one that selects `+authHash`; the
      // request's authentication has already passed by then.
      const realExec = mongoose.Query.prototype.exec;
      let flipped = false;
      vi.spyOn(mongoose.Query.prototype, 'exec').mockImplementation(async function (
        this: mongoose.Query<unknown, unknown>,
        ...args: Parameters<typeof realExec>
      ) {
        const fields = (this as unknown as { _fields?: Record<string, unknown> })._fields ?? {};
        if (!flipped && this.model.modelName === 'User' && '+authHash' in fields) {
          flipped = true;
          await goes(user.id);
        }
        return realExec.apply(this, args);
      } as never);

      const res = await apiCall(user, 'post', '/vault/items/purge-unreadable', {
        authHash: user.rawPassword,
        ...wrapper,
        items: [judged],
        folders: [],
      });
      vi.restoreAllMocks();

      expect(flipped).toBe(true);
      expect(res.status).toBe(401);
      expect(res.body.message).toBe(SESSION_INVALID_MESSAGE);
      expect(await itemIds(user.id)).toEqual([item]);
      expect(await purgeAudits(user.id)).toHaveLength(0);
    }
  });

  it('refuses a request that names nothing, or a row twice, at the door', async () => {
    const user = await createTestUser();
    const item = await createQuotaItem(user, 100);
    const judged = await judgedItem(item);

    expect((await purge(user, {})).status).toBe(400);
    expect((await purge(user, { items: [judged, judged] })).status).toBe(400);
    await expectNothingDeleted(user, [item], []);
  });

  it('settles the counters for the rows it removed, and audits them, even when a later delete fails', async () => {
    const user = await createTestUser();
    const first = await createQuotaItem(user, 100);
    const second = await createQuotaItem(user, 100);
    const judged = [await judgedItem(first), await judgedItem(second)];
    const real = mongoose.mongo.Collection.prototype.findOneAndDelete;
    let deletes = 0;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'findOneAndDelete').mockImplementation(function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof real>
    ) {
      if (this.collectionName === 'vault_items') {
        deletes += 1;
        if (deletes === 2) return Promise.reject(new Error('connection reset'));
      }
      return real.apply(this, args);
    } as never);

    const res = await purge(user, { items: judged });

    expect(res.status).toBe(500);
    vi.restoreAllMocks();
    expect(await itemIds(user.id)).toEqual([second]);
    // A deletion cannot be undone, so the one that happened is on record, marked
    // as a request that did not complete.
    const audits = await purgeAudits(user.id);
    expect(audits).toHaveLength(1);
    expect(audits[0]?.metadata).toEqual({
      deletedItems: 1,
      deletedFolders: 0,
      skippedItems: 0,
      skippedFolders: 0,
      completed: false,
    });
    await expectCounterExact(user);
  });
});

describe('purging unreadable entries, replica set (transactional folder removal)', () => {
  useReplicaSetConnection();

  beforeAll(() => {
    expect(supportsTransactions()).toBe(true);
  });

  purgeSuite();
});
