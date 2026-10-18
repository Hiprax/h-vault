/**
 * A save that races a vault-key rotation never lands sealed under the key the
 * rotation retires.
 *
 * The item and folder writes check the rotation fence and the vault-key
 * generation at the top of the handler, then do work, then write. A rotation that
 * commits inside that gap used to be invisible to them: an update re-measured the
 * row the rotation had just rewritten and put its old-key ciphertext over it, and a
 * create inserted a row after the rotation had counted the account's rows, so the
 * rotation committed without it. Either way the row was left sealed under a key
 * nothing stores any more, behind a 200.
 *
 * Each case below builds that interleaving exactly, with no timing: the rotation
 * (or the fence, or a re-seal) runs inside a hook on the save's OWN database
 * write, then the write proceeds. Both topologies are covered, because the
 * rotation lowers its fence in a different order on each: with its commit on the
 * standalone (sequential) path, after it on a replica set (transactional path).
 */
import { describe, it, expect, afterEach, beforeAll, vi } from 'vitest';
import mongoose from 'mongoose';
import type { AuditAction } from '@hvault/shared';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { User } from '../src/models/User.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { createModuleLogger } from '../src/utils/logger.js';
import { supportsTransactions } from '../src/utils/transactionSupport.js';
import { useReplicaSetConnection } from './mongoHarness.js';
import { createTestUser, sampleFolder, sampleVaultItem, type TestUser } from './helpers.js';
import { apiCall, createQuotaItem, expectCounterExact } from './support/vaultQuotaApi.js';

afterEach(() => {
  vi.restoreAllMocks();
});

const FENCE_MESSAGE = 'Vault key rotation is in progress. Please wait and retry.';

type HookedMethod = 'insertOne' | 'findOneAndUpdate' | 'findOneAndDelete';

/**
 * Runs `during` inside the FIRST call of `method` on `collection` whose arguments
 * `matches` accepts, then lets that call proceed; every other call passes straight
 * through. Resolves the number of matching calls seen so far.
 */
function duringFirst(
  collection: string,
  method: HookedMethod,
  matches: (args: unknown[]) => boolean,
  during: () => Promise<void>,
): () => number {
  const real = mongoose.mongo.Collection.prototype[method] as (...args: unknown[]) => unknown;
  let seen = 0;
  vi.spyOn(mongoose.mongo.Collection.prototype, method).mockImplementation(async function (
    this: mongoose.mongo.Collection,
    ...args: unknown[]
  ) {
    if (this.collectionName === collection && matches(args)) {
      seen += 1;
      if (seen === 1) await during();
    }
    return real.apply(this, args);
  } as never);
  return () => seen;
}

/** The account's stored generation (an account that never rotated stores none). */
async function generationOf(userId: string): Promise<number> {
  const row = await User.findById(userId).select('vaultKeyVersion').lean();
  return row?.vaultKeyVersion ?? 0;
}

/** The ciphertext a rotation or re-seal writes into a named item. */
function rotatedItem(id: string, ivPrefix: string): Record<string, unknown> {
  return {
    id,
    encryptedName: 'rotated-name',
    nameIv: `${ivPrefix}rot-name-iv`,
    nameTag: 'rot-name-tag',
    encryptedData: 'rotated-data',
    dataIv: `${ivPrefix}rot-data-iv`,
    dataTag: 'rot-data-tag',
  };
}

/** The ciphertext a rotation or re-seal writes into a named folder. */
function rotatedFolder(id: string, ivPrefix: string): Record<string, unknown> {
  return {
    id,
    encryptedName: 'rotated-folder-name',
    nameIv: `${ivPrefix}rot-folder-iv`,
    nameTag: 'rot-folder-tag',
  };
}

/**
 * Commits a rotation (or, with `reseal`, a re-seal under the same key) naming
 * exactly `itemIds` and `folderIds`, and asserts it succeeded.
 */
async function commitRotation(
  user: TestUser,
  itemIds: string[],
  folderIds: string[],
  reseal = false,
): Promise<void> {
  const stored = await User.findById(user.id)
    .select('encryptedVaultKey vaultKeyIv vaultKeyTag')
    .lean();
  const ivPrefix = reseal ? 'v2:' : '';
  const res = await apiCall(user, 'post', '/vault/items/bulk-reencrypt', {
    authHash: user.rawPassword,
    items: itemIds.map((id) => rotatedItem(id, ivPrefix)),
    folders: folderIds.map((id) => rotatedFolder(id, ivPrefix)),
    documents: [],
    newEncryptedVaultKey: reseal ? stored?.encryptedVaultKey : 'rotated-wrapper',
    newVaultKeyIv: reseal ? stored?.vaultKeyIv : 'rotated-wrapper-iv',
    newVaultKeyTag: reseal ? stored?.vaultKeyTag : 'rotated-wrapper-tag',
    vaultKeyVersion: await generationOf(user.id),
    vaultFieldFormat: 2,
    ...(reseal ? { reseal: true, idempotencyKey: crypto.randomUUID() } : {}),
  });
  expect(res.status, JSON.stringify(res.body)).toBe(200);
}

/** The number of `action` rows the account's audit log holds. */
async function auditRows(userId: string, action: AuditAction): Promise<number> {
  return AuditLog.countDocuments({ userId, action });
}

async function createFolder(user: TestUser): Promise<string> {
  const res = await apiCall(user, 'post', '/folders', sampleFolder({ vaultKeyVersion: 0 }));
  expect(res.status).toBe(201);
  return String(res.body.data._id);
}

/** A create body's ciphertext marker, so its insert is told apart from every other. */
const NEW_ITEM_DATA = 'new-item-sealed-under-generation-0';
const NEW_FOLDER_NAME = 'new-folder-sealed-under-generation-0';
const EDITED_DATA = 'edited-item-sealed-under-generation-0';
const EDITED_FOLDER_NAME = 'edited-folder-sealed-under-generation-0';

const insertsItem = (args: unknown[]) =>
  (args[0] as { encryptedData?: unknown }).encryptedData === NEW_ITEM_DATA;
const insertsFolder = (args: unknown[]) =>
  (args[0] as { encryptedName?: unknown }).encryptedName === NEW_FOLDER_NAME;
const writesEditedItem = (args: unknown[]) =>
  (args[1] as { $set?: { encryptedData?: unknown } }).$set?.encryptedData === EDITED_DATA;
const writesEditedFolder = (args: unknown[]) =>
  (args[1] as { $set?: { encryptedName?: unknown } }).$set?.encryptedName === EDITED_FOLDER_NAME;

function raceSuite(): void {
  describe('a create the rotation committed around', () => {
    it('withdraws the item and answers the recoverable 409 with the new generation', async () => {
      const user = await createTestUser();
      const existing = await createQuotaItem(user, 100);
      const creates = await auditRows(user.id, 'item_create');
      duringFirst('vault_items', 'insertOne', insertsItem, () =>
        commitRotation(user, [existing], []),
      );

      const res = await apiCall(
        user,
        'post',
        '/vault/items',
        sampleVaultItem({ encryptedData: NEW_ITEM_DATA, vaultKeyVersion: 0 }),
      );

      expect(res.status).toBe(409);
      expect(res.body).toEqual({
        success: false,
        message: expect.stringContaining('rotated elsewhere') as unknown as string,
        data: { vaultKeyVersion: 1 },
      });
      expect(
        await VaultItem.countDocuments({ userId: user.id, encryptedData: NEW_ITEM_DATA }),
      ).toBe(0);
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(1);
      expect(await auditRows(user.id, 'item_create')).toBe(creates);
      expect(await generationOf(user.id)).toBe(1);
      await expectCounterExact(user);
    });

    it('withdraws the folder and answers the recoverable 409 with the new generation', async () => {
      const user = await createTestUser();
      const existing = await createFolder(user);
      const creates = await auditRows(user.id, 'folder_create');
      duringFirst('folders', 'insertOne', insertsFolder, () =>
        commitRotation(user, [], [existing]),
      );

      const res = await apiCall(
        user,
        'post',
        '/folders',
        sampleFolder({ encryptedName: NEW_FOLDER_NAME, vaultKeyVersion: 0 }),
      );

      expect(res.status).toBe(409);
      expect(res.body.data).toEqual({ vaultKeyVersion: 1 });
      expect(await Folder.countDocuments({ userId: user.id, encryptedName: NEW_FOLDER_NAME })).toBe(
        0,
      );
      expect(await Folder.countDocuments({ userId: user.id })).toBe(1);
      expect(await auditRows(user.id, 'folder_create')).toBe(creates);
      await expectCounterExact(user);
    });

    it('withdraws the item while the fence is still raised, with the fence refusal', async () => {
      const user = await createTestUser();
      duringFirst('vault_items', 'insertOne', insertsItem, async () => {
        await User.updateOne({ _id: user.id }, { $set: { rotationInProgress: true } });
      });

      const res = await apiCall(
        user,
        'post',
        '/vault/items',
        sampleVaultItem({ encryptedData: NEW_ITEM_DATA, vaultKeyVersion: 0 }),
      );

      expect(res.status).toBe(409);
      expect(res.body.message).toBe(FENCE_MESSAGE);
      expect(res.body.data).toBeUndefined();
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
      await expectCounterExact(user);
    });

    it('lets a create land when the interleaved operation is a re-seal under the same key', async () => {
      const user = await createTestUser();
      const existing = await createQuotaItem(user, 100);
      duringFirst('vault_items', 'insertOne', insertsItem, () =>
        commitRotation(user, [existing], [], true),
      );

      const res = await apiCall(
        user,
        'post',
        '/vault/items',
        sampleVaultItem({ encryptedData: NEW_ITEM_DATA, vaultKeyVersion: 0 }),
      );

      expect(res.status).toBe(201);
      expect(
        await VaultItem.countDocuments({ userId: user.id, encryptedData: NEW_ITEM_DATA }),
      ).toBe(1);
      expect(await generationOf(user.id)).toBe(0);
      await expectCounterExact(user);
    });
  });

  describe('an update the rotation committed around', () => {
    it('keeps the rotated item and answers the recoverable 409 with the new generation', async () => {
      const user = await createTestUser();
      const id = await createQuotaItem(user, 100);
      const updates = await auditRows(user.id, 'item_update');
      const writes = duringFirst('vault_items', 'findOneAndUpdate', writesEditedItem, () =>
        commitRotation(user, [id], []),
      );

      const res = await apiCall(user, 'put', `/vault/items/${id}`, {
        encryptedData: EDITED_DATA,
        dataIv: 'edited-data-iv',
        dataTag: 'edited-data-tag',
        vaultKeyVersion: 0,
      });

      expect(res.status).toBe(409);
      expect(res.body.data).toEqual({ vaultKeyVersion: 1 });
      // The first pinned write missed (the rotation bumped `__v`); the retry's
      // re-check refused before writing again.
      expect(writes()).toBe(1);
      const row = await VaultItem.findById(id).lean();
      expect(row?.encryptedData).toBe('rotated-data');
      expect(row?.dataIv).toBe('rot-data-iv');
      expect(await auditRows(user.id, 'item_update')).toBe(updates);
      await expectCounterExact(user);
    });

    it('keeps the rotated folder name and answers the recoverable 409', async () => {
      const user = await createTestUser();
      const id = await createFolder(user);
      duringFirst('folders', 'findOneAndUpdate', writesEditedFolder, () =>
        commitRotation(user, [], [id]),
      );

      const res = await apiCall(user, 'put', `/folders/${id}`, {
        encryptedName: EDITED_FOLDER_NAME,
        nameIv: 'edited-folder-iv',
        nameTag: 'edited-folder-tag',
        vaultKeyVersion: 0,
      });

      expect(res.status).toBe(409);
      expect(res.body.data).toEqual({ vaultKeyVersion: 1 });
      expect((await Folder.findById(id).lean())?.encryptedName).toBe('rotated-folder-name');
      await expectCounterExact(user);
    });

    it('refuses with the fence when the row was rewritten while the fence is up', async () => {
      const user = await createTestUser();
      const id = await createQuotaItem(user, 100);
      duringFirst('vault_items', 'findOneAndUpdate', writesEditedItem, async () => {
        await User.updateOne({ _id: user.id }, { $set: { rotationInProgress: true } });
        // What a running rotation's row write does to the pin.
        await VaultItem.collection.updateOne(
          { _id: new mongoose.Types.ObjectId(id) },
          { $inc: { __v: 1 } },
        );
      });

      const res = await apiCall(user, 'put', `/vault/items/${id}`, {
        encryptedData: EDITED_DATA,
        dataIv: 'edited-data-iv',
        dataTag: 'edited-data-tag',
        vaultKeyVersion: 0,
      });

      expect(res.status).toBe(409);
      expect(res.body.message).toBe(FENCE_MESSAGE);
      expect((await VaultItem.findById(id).lean())?.encryptedData).toBe('d'.repeat(100));
      await expectCounterExact(user);
    });

    it('lets an update land after a re-seal under the same key rewrote the row', async () => {
      const user = await createTestUser();
      const id = await createQuotaItem(user, 100);
      const writes = duringFirst('vault_items', 'findOneAndUpdate', writesEditedItem, () =>
        commitRotation(user, [id], [], true),
      );

      const res = await apiCall(user, 'put', `/vault/items/${id}`, {
        encryptedData: EDITED_DATA,
        dataIv: 'edited-data-iv',
        dataTag: 'edited-data-tag',
        vaultKeyVersion: 0,
      });

      expect(res.status).toBe(200);
      expect(writes()).toBe(2);
      expect((await VaultItem.findById(id).lean())?.encryptedData).toBe(EDITED_DATA);
      await expectCounterExact(user);
    });
  });
}

describe('saves racing a rotation, standalone (sequential rotation path)', () => {
  raceSuite();

  it('releases the withdrawal’s reservation when another request already removed the row', async () => {
    const user = await createTestUser();
    const existing = await createQuotaItem(user, 100);
    // Right AFTER the create's insert: another tab trashes and permanently deletes
    // the new row (through the counted path), then a rotation commits, so the
    // create's re-check refuses and its withdrawal finds nothing left to remove.
    const real = mongoose.mongo.Collection.prototype.insertOne;
    let interleaved = false;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'insertOne').mockImplementation(async function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof real>
    ) {
      const inserted = await real.apply(this, args);
      if (!interleaved && this.collectionName === 'vault_items' && insertsItem(args)) {
        interleaved = true;
        const id = String(inserted.insertedId);
        expect((await apiCall(user, 'delete', `/vault/items/${id}`)).status).toBe(200);
        expect((await apiCall(user, 'delete', `/vault/items/${id}/permanent`)).status).toBe(200);
        await commitRotation(user, [existing], []);
      }
      return inserted;
    } as never);

    const res = await apiCall(
      user,
      'post',
      '/vault/items',
      sampleVaultItem({ encryptedData: NEW_ITEM_DATA, vaultKeyVersion: 0 }),
    );

    expect(interleaved).toBe(true);
    expect(res.status).toBe(409);
    expect(res.body.data).toEqual({ vaultKeyVersion: 1 });
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(1);
    // The other request already subtracted the row; the withdrawal subtracts nothing more.
    await expectCounterExact(user);
  });

  it('withdraws a row from an account being erased without touching its counters', async () => {
    const user = await createTestUser();
    duringFirst('vault_items', 'insertOne', insertsItem, async () => {
      await User.updateOne({ _id: user.id }, { $set: { deletionPending: true } });
    });
    const reserve = vi.spyOn(User, 'updateOne');

    const res = await apiCall(
      user,
      'post',
      '/vault/items',
      sampleVaultItem({ encryptedData: NEW_ITEM_DATA, vaultKeyVersion: 0 }),
    );

    expect(res.status).toBe(401);
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
    // The create's own reservation and settle are the only counter writes: the
    // withdrawal of an erasing account takes none (its touch would 404).
    const counterWrites = reserve.mock.calls.filter(
      ([, update]) =>
        (update as { $inc?: Record<string, unknown> }).$inc?.['counters.items'] !== undefined,
    );
    expect(counterWrites).toHaveLength(2);
  });

  it('answers the refusal even when the withdrawal fails, and logs the stranded row', async () => {
    const user = await createTestUser();
    duringFirst('vault_items', 'insertOne', insertsItem, () => commitRotation(user, [], []));
    vi.spyOn(mongoose.mongo.Collection.prototype, 'findOneAndDelete').mockImplementation(function (
      this: mongoose.mongo.Collection,
    ) {
      return Promise.reject(new Error('write concern error: no majority available'));
    } as never);
    const logged = vi.spyOn(createModuleLogger('controller-helpers'), 'error');

    const res = await apiCall(
      user,
      'post',
      '/vault/items',
      sampleVaultItem({ encryptedData: NEW_ITEM_DATA, vaultKeyVersion: 0 }),
    );

    expect(res.status).toBe(409);
    expect(res.body.data).toEqual({ vaultKeyVersion: 1 });
    const stranded = await VaultItem.findOne({ userId: user.id }).lean();
    expect(stranded).not.toBeNull();
    expect(logged).toHaveBeenCalledWith(
      'Could not withdraw a row whose vault-key check refused it after the insert',
      {
        userId: user.id,
        kind: 'item',
        rowId: String(stranded?._id),
        error: 'write concern error: no majority available',
      },
    );
  });

  it('withdraws the row and answers the error when the check after the insert cannot run', async () => {
    const user = await createTestUser();
    let checks = 0;
    const realFindById = User.findById.bind(User);
    vi.spyOn(User, 'findById').mockImplementation(((id: string) => {
      const query = realFindById(id);
      const realSelect = query.select.bind(query);
      query.select = ((fields: string) => {
        if (fields !== 'rotationInProgress vaultKeyVersion deletionPending')
          return realSelect(fields);
        checks += 1;
        return { lean: () => Promise.reject(new Error('datastore unavailable')) };
      }) as never;
      return query;
    }) as never);

    const res = await apiCall(
      user,
      'post',
      '/vault/items',
      sampleVaultItem({ encryptedData: NEW_ITEM_DATA, vaultKeyVersion: 0 }),
    );

    expect(res.status).toBe(500);
    expect(checks).toBe(1);
    vi.restoreAllMocks();
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
    await expectCounterExact(user);
  });
});

describe('saves racing a rotation, replica set (transactional rotation path)', () => {
  useReplicaSetConnection();

  beforeAll(() => {
    // Without this the block would silently test the sequential path again.
    expect(supportsTransactions()).toBe(true);
  });

  raceSuite();
});
