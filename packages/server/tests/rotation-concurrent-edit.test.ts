/**
 * A rotation never overwrites an edit saved after the page that sent it read the
 * vault.
 *
 * The rotating page enumerates every row, decrypts it, re-seals it under the new
 * key and only then sends the whole payload. An edit another device or tab saves in
 * between used to be overwritten by the older content the payload carries, silently,
 * because the rotation's row writes were pinned on what the SERVER read, never on
 * what the CLIENT read. Each row now carries the IVs it had when it was read
 * (`priorNameIv`/`priorDataIv`); every ciphertext write mints fresh IVs, so a row
 * whose stored IVs differ was rewritten, and the rotation is refused with nothing
 * written. Both topologies, because the two rotation paths check it differently: a
 * snapshot compare before the fence plus a pinned write (sequential), and a pinned
 * write inside the transaction (replica set).
 */
import { describe, it, expect, afterEach, beforeAll, vi } from 'vitest';
import mongoose from 'mongoose';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { User } from '../src/models/User.js';
import { supportsTransactions } from '../src/utils/transactionSupport.js';
import { useReplicaSetConnection } from './mongoHarness.js';
import { createTestUser, sampleFolder, type TestUser } from './helpers.js';
import { apiCall, createQuotaItem, expectCounterExact } from './support/vaultQuotaApi.js';

afterEach(() => {
  vi.restoreAllMocks();
});

const CHANGED_MESSAGE =
  'Re-read the vault and retry: an entry changed on another device or tab after this page ' +
  'read it, and continuing would undo that edit. No entry was changed.';

/**
 * The edit a writer that raced the fence lands, written raw: the SAME stored size
 * as the row `createQuotaItem(user, 100)` makes (100 data characters, a 12-character
 * IV), so the byte counter it bypasses stays exact.
 */
const RACED_DATA = 'e'.repeat(100);
const RACED_IV = 'raced-iv-012';

/** What the page read: each row's id and the IVs it carried at that moment. */
interface ReadRow {
  id: string;
  nameIv: string;
  dataIv?: string;
}

async function readItem(id: string): Promise<ReadRow> {
  const row = await VaultItem.findById(id).lean();
  return { id, nameIv: String(row?.nameIv), dataIv: String(row?.dataIv) };
}

async function readFolder(id: string): Promise<ReadRow> {
  const row = await Folder.findById(id).lean();
  return { id, nameIv: String(row?.nameIv) };
}

async function createFolder(user: TestUser): Promise<string> {
  const res = await apiCall(user, 'post', '/folders', sampleFolder({ vaultKeyVersion: 0 }));
  expect(res.status).toBe(201);
  return String(res.body.data._id);
}

/** A rotation payload re-sealing every row the page read, each naming its read IVs. */
function rotationOf(
  user: TestUser,
  items: ReadRow[],
  folders: ReadRow[],
  withPriors = true,
): Record<string, unknown> {
  return {
    authHash: user.rawPassword,
    items: items.map((row) => ({
      id: row.id,
      encryptedName: 'rotated-name',
      nameIv: `rotated-name-iv-${row.id.slice(-4)}`,
      nameTag: 'rotated-name-tag',
      encryptedData: 'rotated-data',
      dataIv: `rotated-data-iv-${row.id.slice(-4)}`,
      dataTag: 'rotated-data-tag',
      ...(withPriors ? { priorNameIv: row.nameIv, priorDataIv: row.dataIv } : {}),
    })),
    folders: folders.map((row) => ({
      id: row.id,
      encryptedName: 'rotated-folder-name',
      nameIv: `rotated-folder-iv-${row.id.slice(-4)}`,
      nameTag: 'rotated-folder-tag',
      ...(withPriors ? { priorNameIv: row.nameIv } : {}),
    })),
    documents: [],
    newEncryptedVaultKey: 'rotated-wrapper',
    newVaultKeyIv: 'rotated-wrapper-iv',
    newVaultKeyTag: 'rotated-wrapper-tag',
    vaultKeyVersion: 0,
    vaultFieldFormat: 2,
  };
}

/** Everything a refused rotation must leave exactly as it found it. */
async function accountState(userId: string) {
  const user = await User.findById(userId)
    .select(
      'encryptedVaultKey vaultKeyVersion rotationInProgress pendingEncryptedVaultKey pendingVaultKeyIv pendingVaultKeyTag',
    )
    .lean();
  return {
    wrapper: user?.encryptedVaultKey,
    generation: user?.vaultKeyVersion ?? 0,
    fence: user?.rotationInProgress ?? false,
    pending: user?.pendingEncryptedVaultKey ?? null,
    items: await VaultItem.find({ userId })
      .select('encryptedName nameIv encryptedData dataIv')
      .sort({ _id: 1 })
      .lean(),
    folders: await Folder.find({ userId }).select('encryptedName nameIv').sort({ _id: 1 }).lean(),
  };
}

function editSuite(): void {
  it('refuses with CHANGED when an item was edited after the page read it, changing nothing', async () => {
    const user = await createTestUser();
    const a = await createQuotaItem(user, 100);
    const b = await createQuotaItem(user, 100);
    const read = [await readItem(a), await readItem(b)];
    // Another device saves an edit to B after the enumeration.
    const edit = await apiCall(user, 'put', `/vault/items/${b}`, {
      encryptedData: 'edited-elsewhere',
      dataIv: 'edited-data-iv',
      dataTag: 'edited-data-tag',
      vaultKeyVersion: 0,
    });
    expect(edit.status).toBe(200);
    const before = await accountState(user.id);

    const res = await apiCall(
      user,
      'post',
      '/vault/items/bulk-reencrypt',
      rotationOf(user, read, []),
    );

    expect(res.status).toBe(409);
    expect(res.body.message).toBe(CHANGED_MESSAGE);
    expect(res.body.data).toBeUndefined();
    expect(await accountState(user.id)).toEqual(before);
    expect((await VaultItem.findById(b).lean())?.encryptedData).toBe('edited-elsewhere');
    await expectCounterExact(user);
  });

  it('refuses with CHANGED when a folder was renamed after the page read it', async () => {
    const user = await createTestUser();
    const folder = await createFolder(user);
    const read = [await readFolder(folder)];
    const rename = await apiCall(user, 'put', `/folders/${folder}`, {
      encryptedName: 'renamed-elsewhere',
      nameIv: 'renamed-iv',
      nameTag: 'renamed-tag',
      vaultKeyVersion: 0,
    });
    expect(rename.status).toBe(200);
    const before = await accountState(user.id);

    const res = await apiCall(
      user,
      'post',
      '/vault/items/bulk-reencrypt',
      rotationOf(user, [], read),
    );

    expect(res.status).toBe(409);
    expect(res.body.message).toBe(CHANGED_MESSAGE);
    expect(await accountState(user.id)).toEqual(before);
    await expectCounterExact(user);
  });

  it('still rotates after a move, a favourite and a folder reorder, none of which touch an IV', async () => {
    const user = await createTestUser();
    const folder = await createFolder(user);
    const a = await createQuotaItem(user, 100);
    const read = [await readItem(a)];
    const readFolders = [await readFolder(folder)];
    expect(
      (await apiCall(user, 'put', `/vault/items/${a}`, { folderId: folder, vaultKeyVersion: 0 }))
        .status,
    ).toBe(200);
    expect(
      (await apiCall(user, 'put', `/vault/items/${a}`, { favorite: true, vaultKeyVersion: 0 }))
        .status,
    ).toBe(200);
    expect((await apiCall(user, 'put', `/folders/${folder}/sort`, { sortOrder: 7 })).status).toBe(
      200,
    );

    const res = await apiCall(
      user,
      'post',
      '/vault/items/bulk-reencrypt',
      rotationOf(user, read, readFolders),
    );

    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const row = await VaultItem.findById(a).lean();
    expect(row?.encryptedData).toBe('rotated-data');
    expect(row?.favorite).toBe(true);
    expect(String(row?.folderId)).toBe(folder);
    expect((await accountState(user.id)).generation).toBe(1);
    await expectCounterExact(user);
  });

  it('rotates an older page that names no priors exactly as before, edit and all', async () => {
    const user = await createTestUser();
    const a = await createQuotaItem(user, 100);
    const read = [await readItem(a)];
    await apiCall(user, 'put', `/vault/items/${a}`, {
      encryptedData: 'edited-elsewhere',
      dataIv: 'edited-data-iv',
      dataTag: 'edited-data-tag',
      vaultKeyVersion: 0,
    });

    const res = await apiCall(
      user,
      'post',
      '/vault/items/bulk-reencrypt',
      rotationOf(user, read, [], false),
    );

    // No precondition was named, so none is enforced: the compatibility the field
    // being optional promises, and the reason every current page sends it.
    expect(res.status).toBe(200);
    expect((await VaultItem.findById(a).lean())?.encryptedData).toBe('rotated-data');
  });

  it('refuses a half pair of item priors at the door', async () => {
    const user = await createTestUser();
    const a = await createQuotaItem(user, 100);
    const body = rotationOf(user, [await readItem(a)], []);
    const [item] = body.items as Record<string, unknown>[];
    delete item?.['priorDataIv'];

    const res = await apiCall(user, 'post', '/vault/items/bulk-reencrypt', body);

    expect(res.status).toBe(400);
    expect((await accountState(user.id)).generation).toBe(0);
  });
}

describe('rotation against a concurrent edit, standalone (sequential path)', () => {
  editSuite();

  it('rolls back and refuses with CHANGED when an edit lands between the snapshot and a write', async () => {
    const user = await createTestUser();
    const a = await createQuotaItem(user, 100);
    const b = await createQuotaItem(user, 100);
    const read = [await readItem(a), await readItem(b)];
    const before = await accountState(user.id);
    // A writer that raced the fence rewrites B just before the rotation's write
    // of B reaches it: the snapshot saw B as the page read it.
    const real = mongoose.mongo.Collection.prototype.updateOne;
    let raced = false;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'updateOne').mockImplementation(async function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof real>
    ) {
      const filter = args[0] as { _id?: unknown };
      const update = args[1] as { $set?: { encryptedName?: unknown } };
      if (
        !raced &&
        this.collectionName === 'vault_items' &&
        update.$set?.encryptedName === 'rotated-name' &&
        String(filter._id) === b
      ) {
        raced = true;
        await real.call(
          this,
          { _id: new mongoose.Types.ObjectId(b) },
          {
            $set: { encryptedData: RACED_DATA, dataIv: RACED_IV },
            $inc: { __v: 1 },
          },
        );
      }
      return real.apply(this, args);
    } as never);

    const res = await apiCall(
      user,
      'post',
      '/vault/items/bulk-reencrypt',
      rotationOf(user, read, []),
    );

    expect(raced).toBe(true);
    expect(res.status).toBe(409);
    expect(res.body.message).toBe(CHANGED_MESSAGE);
    vi.restoreAllMocks();
    const after = await accountState(user.id);
    // A, which the rotation wrote first, is back to what it was; B keeps the edit.
    expect(after.items.find((row) => String(row._id) === a)).toEqual(
      before.items.find((row) => String(row._id) === a),
    );
    expect((await VaultItem.findById(b).lean())?.encryptedData).toBe(RACED_DATA);
    expect(after.generation).toBe(0);
    expect(after.wrapper).toBe(before.wrapper);
    expect(after.fence).toBe(false);
    // Past the fence, the sequential path keeps its pending wrapper on EVERY abort
    // (only a commit drops it: `lowerRotationFence`), so Finish or Discard decides.
    expect(after.pending).toBe('rotated-wrapper');
    await expectCounterExact(user);
  });

  it('rolls back and refuses with CHANGED when a rename lands between the snapshot and a folder write', async () => {
    const user = await createTestUser();
    const a = await createQuotaItem(user, 100);
    const f = await createFolder(user);
    const stored = await Folder.findById(f).lean();
    const read = { items: [await readItem(a)], folders: [await readFolder(f)] };
    const before = await accountState(user.id);
    // The same stored size as the name it replaces, so the counter it bypasses stays exact.
    const racedName = 'r'.repeat(String(stored?.encryptedName).length);
    const racedIv = 'q'.repeat(String(stored?.nameIv).length);
    const real = mongoose.mongo.Collection.prototype.updateOne;
    let raced = false;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'updateOne').mockImplementation(async function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof real>
    ) {
      const filter = args[0] as { _id?: unknown };
      const update = args[1] as { $set?: { encryptedName?: unknown } };
      if (
        !raced &&
        this.collectionName === 'folders' &&
        update.$set?.encryptedName === 'rotated-folder-name' &&
        String(filter._id) === f
      ) {
        raced = true;
        await real.call(
          this,
          { _id: new mongoose.Types.ObjectId(f) },
          { $set: { encryptedName: racedName, nameIv: racedIv }, $inc: { __v: 1 } },
        );
      }
      return real.apply(this, args);
    } as never);

    const res = await apiCall(
      user,
      'post',
      '/vault/items/bulk-reencrypt',
      rotationOf(user, read.items, read.folders),
    );

    expect(raced).toBe(true);
    expect(res.status).toBe(409);
    expect(res.body.message).toBe(CHANGED_MESSAGE);
    vi.restoreAllMocks();
    const after = await accountState(user.id);
    // The item the rotation wrote first is back to what it was; the folder keeps the rename.
    expect(after.items).toEqual(before.items);
    expect((await Folder.findById(f).lean())?.encryptedName).toBe(racedName);
    expect(after.generation).toBe(0);
    expect(after.wrapper).toBe(before.wrapper);
    expect(after.fence).toBe(false);
    expect(after.pending).toBe('rotated-wrapper');
    await expectCounterExact(user);
  });
});

describe('rotation against a concurrent edit, replica set (transactional path)', () => {
  useReplicaSetConnection();

  beforeAll(() => {
    expect(supportsTransactions()).toBe(true);
  });

  editSuite();

  it('refuses with CHANGED when an edit commits during the transaction', async () => {
    const user = await createTestUser();
    const a = await createQuotaItem(user, 100);
    const read = [await readItem(a)];
    const before = await accountState(user.id);
    const real = mongoose.mongo.Collection.prototype.updateOne;
    let raced = false;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'updateOne').mockImplementation(async function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof real>
    ) {
      const update = args[1] as { $set?: { encryptedName?: unknown } };
      if (
        !raced &&
        this.collectionName === 'vault_items' &&
        update.$set?.encryptedName === 'rotated-name'
      ) {
        raced = true;
        // Committed outside the rotation's session, as another request's write is.
        await real.call(
          this,
          { _id: new mongoose.Types.ObjectId(a) },
          {
            $set: { encryptedData: RACED_DATA, dataIv: RACED_IV },
            $inc: { __v: 1 },
          },
        );
      }
      return real.apply(this, args);
    } as never);

    const res = await apiCall(
      user,
      'post',
      '/vault/items/bulk-reencrypt',
      rotationOf(user, read, []),
    );

    expect(raced).toBe(true);
    expect(res.status).toBe(409);
    expect(res.body.message).toBe(CHANGED_MESSAGE);
    vi.restoreAllMocks();
    const after = await accountState(user.id);
    expect(after.generation).toBe(before.generation);
    expect(after.wrapper).toBe(before.wrapper);
    expect(after.fence).toBe(false);
    expect((await VaultItem.findById(a).lean())?.encryptedData).toBe(RACED_DATA);
    await expectCounterExact(user);
  });
});
