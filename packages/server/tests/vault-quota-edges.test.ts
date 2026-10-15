/**
 * F-24: the vault byte quota at its edges.
 *
 * - The boundary itself, in bytes: a growth that lands exactly ON the quota is
 *   admitted, one byte past it is refused, and a same-size rewrite of an account
 *   sitting exactly at the quota is never refused (nor are reads).
 * - A refused folder create, and a restore that runs out of room part-way, which
 *   skips the rows that do not fit as `storage_limit` and restores the rest.
 * - `-0`: JSON can spell it, BSON stores it as a double, and the counter must still
 *   agree with the database.
 * - Which failed writes count as "certainly not applied" (the reservation is
 *   handed back) and which keep the reservation.
 * - Every read the quota makes goes to the primary, and every row cursor of the
 *   heavy responses asks for small batches.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import app from '../src/app.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { ROW_CURSOR_BATCH_SIZE } from '../src/utils/jsonStream.js';
import { User } from '../src/models/User.js';
import {
  addVaultBytes,
  isDefiniteWriteFailure,
  recountVaultQuotas,
  reserveVaultWrite,
  settleVaultWrite,
  VAULT_STORAGE_QUOTA_MESSAGE,
  VaultQuotaExceededError,
} from '../src/utils/vaultQuota.js';
import { authHeader, createTestUser, getCsrf, sampleFolder, type TestUser } from './helpers.js';
import { storedVaultBytes, vaultBytesCounter } from './support/vaultBytes.js';
import {
  apiCall,
  createQuotaItem,
  expectCounterExact,
  quotaItemBody,
  restoreQuota,
  savedQuota,
  setQuotaBytes,
  trashQuotaItem,
} from './support/vaultQuotaApi.js';

let quota: unknown;

beforeEach(() => {
  quota = savedQuota();
});

afterEach(() => {
  restoreQuota(quota);
  vi.restoreAllMocks();
});

/** A PUT of an item's ciphertext, `dataBytes` characters of `fill`. */
function dataUpdate(dataBytes: number, fill = 'x'): Record<string, unknown> {
  return {
    encryptedData: fill.repeat(dataBytes),
    dataIv: 'test-data-iv',
    dataTag: 'test-data-tag',
  };
}

/** A raw JSON request, for a body `JSON.stringify` cannot produce (it writes `-0` as `0`). */
async function rawJson(user: TestUser, method: 'put' | 'post', path: string, json: string) {
  const agent = request.agent(app);
  const csrf = await getCsrf(agent);
  return agent[method](`/api/v1${path}`)
    .set('Authorization', authHeader(user.accessToken))
    .set('Cookie', csrf.cookie)
    .set('x-csrf-token', csrf.token)
    .set('Content-Type', 'application/json')
    .send(json);
}

describe('the boundary, in bytes', () => {
  it('a growth that lands exactly on the quota is admitted; one byte more is refused', async () => {
    const user = await createTestUser();
    const id = await createQuotaItem(user, 1_000);
    const used = await expectCounterExact(user);

    // 600 more characters of ciphertext is 600 more bytes of BSON string.
    setQuotaBytes(used + 599);
    const over = await apiCall(user, 'put', `/vault/items/${id}`, dataUpdate(1_600));
    expect(over.status).toBe(400);
    expect(over.body.message).toBe(VAULT_STORAGE_QUOTA_MESSAGE);
    expect(await vaultBytesCounter(user.id)).toBe(used);

    setQuotaBytes(used + 600);
    const exact = await apiCall(user, 'put', `/vault/items/${id}`, dataUpdate(1_600));
    expect(exact.status).toBe(200);
    expect(await expectCounterExact(user)).toBe(used + 600);
  });

  it('an account sitting exactly at its quota can rewrite a row at the same size, read, and shrink', async () => {
    const user = await createTestUser();
    const id = await createQuotaItem(user, 2_000);
    const used = await expectCounterExact(user);
    setQuotaBytes(used);

    const same = await apiCall(user, 'put', `/vault/items/${id}`, dataUpdate(2_000, 's'));
    expect(same.status).toBe(200);
    expect((await VaultItem.findById(id).lean())?.encryptedData).toBe('s'.repeat(2_000));
    expect(await expectCounterExact(user)).toBe(used);

    for (const path of ['/vault/items', '/folders', '/user/profile', `/vault/items/${id}`]) {
      expect((await apiCall(user, 'get', path)).status).toBe(200);
    }

    // Negative: one byte of growth is refused, a shrink is not.
    expect((await apiCall(user, 'put', `/vault/items/${id}`, dataUpdate(2_001))).status).toBe(400);
    expect((await apiCall(user, 'put', `/vault/items/${id}`, dataUpdate(10))).status).toBe(200);
    await expectCounterExact(user);
  });

  it('a vault key rotation that GROWS the vault is never refused, even at the quota', async () => {
    const user = await createTestUser();
    const id = await createQuotaItem(user, 1_000);
    const used = await expectCounterExact(user);
    setQuotaBytes(used);

    const rotated = await apiCall(user, 'post', '/vault/items/bulk-reencrypt', {
      authHash: user.rawPassword,
      newEncryptedVaultKey: 'rotated-key',
      newVaultKeyIv: 'rotated-iv',
      newVaultKeyTag: 'rotated-tag',
      items: [
        {
          id,
          encryptedName: 'a-rotated-name',
          nameIv: 'rotated-name-iv',
          nameTag: 'rotated-name-tag',
          encryptedData: 'r'.repeat(5_000),
          dataIv: 'rotated-data-iv',
          dataTag: 'rotated-data-tag',
        },
      ],
      folders: [],
      documents: [],
    });

    expect(rotated.status).toBe(200);
    // Past the quota now, by exactly the rotation's own growth, and counted.
    expect(await expectCounterExact(user)).toBeGreaterThan(used + 3_900);
    // Negative: the next growing write (sealed under the new key generation) is refused.
    const owner = await mongoose.connection
      .collection('users')
      .findOne(
        { _id: new mongoose.Types.ObjectId(user.id) },
        { projection: { vaultKeyVersion: 1 } },
      );
    const grow = await apiCall(user, 'put', `/vault/items/${id}`, {
      ...dataUpdate(6_000),
      vaultKeyVersion: owner?.['vaultKeyVersion'] as number,
    });
    expect(grow.status).toBe(400);
    expect(grow.body.message).toBe(VAULT_STORAGE_QUOTA_MESSAGE);
  });

  it('reads keep working however far past the quota an account is', async () => {
    const user = await createTestUser();
    const id = await createQuotaItem(user, 3_000);
    await trashQuotaItem(user, id);
    setQuotaBytes(1);

    for (const path of [
      '/vault/items',
      '/vault/items/trash',
      '/folders',
      '/user/profile',
      '/user/audit-log',
    ]) {
      const res = await apiCall(user, 'get', path);
      expect([path, res.status]).toEqual([path, 200]);
    }
  });

  it('a folder create the quota has no room for is refused with 400 and writes nothing', async () => {
    const user = await createTestUser();
    await createQuotaItem(user, 500);
    const used = await expectCounterExact(user);
    setQuotaBytes(used);

    const refused = await apiCall(user, 'post', '/folders', sampleFolder());

    expect(refused.status).toBe(400);
    expect(refused.body.message).toBe(VAULT_STORAGE_QUOTA_MESSAGE);
    expect(await Folder.countDocuments({ userId: user.id })).toBe(0);
    expect(await vaultBytesCounter(user.id)).toBe(used);
  });
});

describe('a restore that runs out of room', () => {
  it('skips what does not fit as storage_limit, restores the rest, and counts exactly', async () => {
    const user = await createTestUser();
    await createQuotaItem(user, 400);
    const used = await expectCounterExact(user);
    // Room for the small row, not for the two large ones.
    setQuotaBytes(used + 2_000);

    const backup = {
      items: [
        { _id: new mongoose.Types.ObjectId().toString(), ...quotaItemBody(5_000) },
        { _id: new mongoose.Types.ObjectId().toString(), ...quotaItemBody(300) },
        { _id: new mongoose.Types.ObjectId().toString(), ...quotaItemBody(6_000) },
      ],
      folders: [],
    };
    const res = await apiCall(user, 'post', '/backup/restore', {
      conflictStrategy: 'keep_both',
      data: JSON.stringify(backup),
    });

    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({ itemsRestored: 1, itemsSkipped: 2 });
    expect(res.body.data.itemSkipReasons).toEqual([
      { itemId: backup.items[0]!._id, reason: 'storage_limit' },
      { itemId: backup.items[2]!._id, reason: 'storage_limit' },
    ]);
    const lengths = (await VaultItem.find({ userId: user.id }).lean()).map(
      (row) => row.encryptedData.length,
    );
    expect(lengths.sort((a, b) => a - b)).toEqual([300, 400]);
    await expectCounterExact(user);
  });

  it('a keep-both duplicate of a folder the account has, skipped for room, files its items into that folder', async () => {
    const user = await createTestUser();
    // A folder from another account's backup (a foreign id), restored once: the
    // account now has its own copy, which records the foreign id as its source.
    const foreignId = new mongoose.Types.ObjectId().toString();
    const first = await apiCall(user, 'post', '/backup/restore', {
      conflictStrategy: 'keep_both',
      data: JSON.stringify({ folders: [{ _id: foreignId, ...sampleFolder() }], items: [] }),
    });
    expect(first.status).toBe(200);
    const copy = await Folder.findOne({ userId: user.id }).lean();
    expect(copy).not.toBeNull();
    await createQuotaItem(user, 400);
    const used = await expectCounterExact(user);
    // Room for one small item, not for a second copy of the folder with a long name.
    setQuotaBytes(used + 900);

    const res = await apiCall(user, 'post', '/backup/restore', {
      conflictStrategy: 'keep_both',
      data: JSON.stringify({
        folders: [{ _id: foreignId, ...sampleFolder({ encryptedName: 'f'.repeat(3_000) }) }],
        items: [
          {
            _id: new mongoose.Types.ObjectId().toString(),
            ...quotaItemBody(40),
            folderId: foreignId,
          },
        ],
      }),
    });

    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({
      foldersRestored: 0,
      foldersSkipped: 1,
      itemsRestored: 1,
    });
    expect(res.body.data.folderSkipReasons).toEqual([
      { folderId: foreignId, reason: 'storage_limit' },
    ]);
    // Filed into the account's own copy of that folder, not left unfiled.
    const restored = await VaultItem.findOne({
      userId: user.id,
      encryptedData: 'd'.repeat(40),
    }).lean();
    expect(String(restored?.folderId)).toBe(String(copy!._id));
    expect(await Folder.countDocuments({ userId: user.id })).toBe(1);
    await expectCounterExact(user);
  });

  it('an overwrite that would grow a folder past the quota is skipped; its items stay in it', async () => {
    const user = await createTestUser();
    const existing = await apiCall(user, 'post', '/folders', sampleFolder());
    const folderId = String(existing.body.data._id);
    await createQuotaItem(user, 400);
    const used = await expectCounterExact(user);
    setQuotaBytes(used + 900);

    const res = await apiCall(user, 'post', '/backup/restore', {
      conflictStrategy: 'overwrite',
      data: JSON.stringify({
        folders: [{ _id: folderId, ...sampleFolder({ encryptedName: 'f'.repeat(3_000) }) }],
        items: [{ _id: new mongoose.Types.ObjectId().toString(), ...quotaItemBody(40), folderId }],
      }),
    });

    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({ foldersSkipped: 1, itemsRestored: 1 });
    expect(res.body.data.folderSkipReasons).toEqual([{ folderId, reason: 'storage_limit' }]);
    // The folder keeps its name; the restored item is filed in it.
    const folder = await Folder.findById(folderId).lean();
    expect(folder?.encryptedName).toBe('test-encrypted-folder-name');
    const restored = await VaultItem.findOne({
      userId: user.id,
      encryptedData: 'd'.repeat(40),
    }).lean();
    expect(String(restored?.folderId)).toBe(folderId);
    await expectCounterExact(user);
  });

  it('a folder that does not fit is skipped and the items filed in it come back unfiled', async () => {
    const user = await createTestUser();
    await createQuotaItem(user, 400);
    const used = await expectCounterExact(user);
    const folderId = new mongoose.Types.ObjectId().toString();
    // Room for the item (~400 bytes of row), not for the item AND a folder with
    // a 3,000-character name.
    setQuotaBytes(used + 900);

    const res = await apiCall(user, 'post', '/backup/restore', {
      conflictStrategy: 'keep_both',
      data: JSON.stringify({
        folders: [{ _id: folderId, ...sampleFolder({ encryptedName: 'f'.repeat(3_000) }) }],
        items: [{ _id: new mongoose.Types.ObjectId().toString(), ...quotaItemBody(40), folderId }],
      }),
    });

    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({
      foldersRestored: 0,
      foldersSkipped: 1,
      itemsRestored: 1,
    });
    expect(res.body.data.folderSkipReasons).toEqual([{ folderId, reason: 'storage_limit' }]);
    const restored = await VaultItem.findOne({
      userId: user.id,
      encryptedData: 'd'.repeat(40),
    }).lean();
    expect(restored?.folderId ?? null).toBeNull();
    await expectCounterExact(user);
  });
});

describe('a restore whose matched row is deleted while it runs', () => {
  /** Runs `before` once, just before the restore measures a row of `collection` to overwrite it. */
  function beforeOverwriteMeasure(collection: string, before: () => Promise<void>): void {
    const real = mongoose.mongo.Collection.prototype.find;
    let done = false;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'find').mockImplementation(function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof real>
    ) {
      const projection = args[1]?.projection as Record<string, unknown> | undefined;
      if (
        !done &&
        this.collectionName === collection &&
        projection &&
        'hasUpdatedAt' in projection
      ) {
        done = true;
        // `find` is synchronous; the deletion runs before the cursor is read.
        const cursor = real.apply(this, args);
        const toArray = cursor.toArray.bind(cursor);
        cursor.toArray = async () => {
          await before();
          return toArray();
        };
        return cursor;
      }
      return real.apply(this, args);
    } as never);
  }

  for (const [label, trashed] of [
    ['an overwritten item', false],
    ['a trashed item the restore brings back', true],
  ] as const) {
    it(`${label} comes back as a new row, counted once`, async () => {
      const user = await createTestUser();
      const id = await createQuotaItem(user, 800);
      if (trashed) await trashQuotaItem(user, id);
      await expectCounterExact(user);
      beforeOverwriteMeasure('vault_items', async () => {
        if (!trashed) await trashQuotaItem(user, id);
        expect((await apiCall(user, 'delete', `/vault/items/${id}/permanent`)).status).toBe(200);
      });

      const res = await apiCall(user, 'post', '/backup/restore', {
        conflictStrategy: 'overwrite',
        data: JSON.stringify({ items: [{ _id: id, ...quotaItemBody(1_200) }], folders: [] }),
      });

      expect(res.status).toBe(200);
      expect(res.body.data).toMatchObject({ itemsRestored: 1, itemsSkipped: 0 });
      // Not the deleted row (it is gone for good): a new one, recording its source.
      expect(await VaultItem.exists({ _id: id })).toBeNull();
      const rows = await VaultItem.find({ userId: user.id }).lean();
      expect(rows.map((row) => [row.encryptedData.length, String(row.sourceRefId)])).toEqual([
        [1_200, id],
      ]);
      await expectCounterExact(user);
    });
  }

  it('an overwritten folder comes back as a new one, and the items filed in it follow', async () => {
    const user = await createTestUser();
    const folder = await apiCall(user, 'post', '/folders', sampleFolder());
    const folderId = String(folder.body.data._id);
    await expectCounterExact(user);
    beforeOverwriteMeasure('folders', async () => {
      expect((await apiCall(user, 'delete', `/folders/${folderId}`)).status).toBe(200);
    });

    const res = await apiCall(user, 'post', '/backup/restore', {
      conflictStrategy: 'overwrite',
      data: JSON.stringify({
        folders: [{ _id: folderId, ...sampleFolder({ encryptedName: 'restored-folder' }) }],
        items: [{ _id: new mongoose.Types.ObjectId().toString(), ...quotaItemBody(50), folderId }],
      }),
    });

    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({ foldersRestored: 1, itemsRestored: 1 });
    const folders = await Folder.find({ userId: user.id }).lean();
    expect(folders.map((row) => row.encryptedName)).toEqual(['restored-folder']);
    expect(String(folders[0]!._id)).not.toBe(folderId);
    const item = await VaultItem.findOne({ userId: user.id }).lean();
    expect(String(item?.folderId)).toBe(String(folders[0]!._id));
    await expectCounterExact(user);
  });
});

describe('a restore whose matched folder is deleted while it runs and cannot be re-created', () => {
  it('restores the items filed in it unfiled, never under the deleted folder', async () => {
    const user = await createTestUser();
    const folder = await apiCall(user, 'post', '/folders', sampleFolder());
    const folderId = String(folder.body.data._id);
    const used = await expectCounterExact(user);
    // Room for the item, not for a folder with a 3,000-character name, even once
    // the deleted folder's bytes are free again.
    setQuotaBytes(used + 900);
    const real = mongoose.mongo.Collection.prototype.find;
    let deleted = false;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'find').mockImplementation(function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof real>
    ) {
      const projection = args[1]?.projection as Record<string, unknown> | undefined;
      if (
        !deleted &&
        this.collectionName === 'folders' &&
        projection &&
        'hasUpdatedAt' in projection
      ) {
        deleted = true;
        const cursor = real.apply(this, args);
        const toArray = cursor.toArray.bind(cursor);
        cursor.toArray = async () => {
          expect((await apiCall(user, 'delete', `/folders/${folderId}`)).status).toBe(200);
          return toArray();
        };
        return cursor;
      }
      return real.apply(this, args);
    } as never);

    const res = await apiCall(user, 'post', '/backup/restore', {
      conflictStrategy: 'overwrite',
      data: JSON.stringify({
        folders: [{ _id: folderId, ...sampleFolder({ encryptedName: 'f'.repeat(3_000) }) }],
        items: [{ _id: new mongoose.Types.ObjectId().toString(), ...quotaItemBody(50), folderId }],
      }),
    });

    expect(deleted).toBe(true);
    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({
      foldersRestored: 0,
      foldersSkipped: 1,
      itemsRestored: 1,
    });
    expect(res.body.data.folderSkipReasons).toEqual([{ folderId, reason: 'storage_limit' }]);
    expect(await Folder.countDocuments({ userId: user.id })).toBe(0);
    const item = await VaultItem.findOne({ userId: user.id }).lean();
    expect(item?.folderId ?? null).toBeNull();
    await expectCounterExact(user);
  });
});

describe('-0', () => {
  it('a folder sorted to -0, twice: stored as 0 and the counter agrees', async () => {
    const user = await createTestUser();
    const created = await apiCall(user, 'post', '/folders', sampleFolder());
    const id = String(created.body.data._id);
    await expectCounterExact(user);

    for (let i = 0; i < 2; i += 1) {
      const res = await rawJson(user, 'put', `/folders/${id}/sort`, '{"sortOrder":-0}');
      expect(res.status).toBe(200);
      await expectCounterExact(user);
    }
    const row = await mongoose.connection
      .collection('folders')
      .findOne({ _id: new mongoose.Types.ObjectId(id) });
    expect(Object.is(row?.['sortOrder'], 0)).toBe(true);
  });

  it('a folder CREATED at -0 is stored as 0 and counted exactly', async () => {
    const user = await createTestUser();
    const res = await rawJson(
      user,
      'post',
      '/folders',
      JSON.stringify(sampleFolder()).replace(/}$/, ',"sortOrder":-0}'),
    );
    expect(res.status).toBe(201);
    const row = await mongoose.connection
      .collection('folders')
      .findOne({ _id: new mongoose.Types.ObjectId(String(res.body.data._id)) });
    expect(Object.is(row?.['sortOrder'], 0)).toBe(true);
    await expectCounterExact(user);
  });
});

describe('which failed writes certainly did not apply', () => {
  it('validation and casting failures, and a single write the server refused, did not', async () => {
    const validation = await new VaultItem({}).validate().catch((error: unknown) => error);
    const cast = await VaultItem.findById('not-an-id').catch((error: unknown) => error);
    const user = await createTestUser();
    const id = new mongoose.Types.ObjectId();
    await VaultItem.collection.insertOne({ _id: id, userId: new mongoose.Types.ObjectId(user.id) });
    const duplicate = await VaultItem.collection
      .insertOne({ _id: id })
      .catch((error: unknown) => error);

    expect((validation as Error).name).toBe('ValidationError');
    expect(isDefiniteWriteFailure(validation)).toBe(true);
    expect((cast as Error).name).toBe('CastError');
    expect(isDefiniteWriteFailure(cast)).toBe(true);
    expect(duplicate).toBeInstanceOf(mongoose.mongo.MongoServerError);
    expect(isDefiniteWriteFailure(duplicate)).toBe(true);
  });

  it('a bulk write, a labelled error, a network failure and anything unknown may have applied', async () => {
    const user = await createTestUser();
    const id = new mongoose.Types.ObjectId();
    await VaultItem.collection.insertOne({ _id: id, userId: new mongoose.Types.ObjectId(user.id) });
    const bulk = await VaultItem.collection
      .insertMany([{ _id: new mongoose.Types.ObjectId() }, { _id: id }])
      .catch((error: unknown) => error);
    const labelled = new mongoose.mongo.MongoServerError({
      message: 'duplicate, inside a transaction',
      code: 11000,
      errorLabels: ['TransientTransactionError'],
    });
    const unrefused = new mongoose.mongo.MongoServerError({ message: 'write conflict', code: 112 });

    expect(bulk).toBeInstanceOf(mongoose.mongo.MongoBulkWriteError);
    expect(isDefiniteWriteFailure(bulk)).toBe(false);
    expect(isDefiniteWriteFailure(labelled)).toBe(false);
    expect(isDefiniteWriteFailure(unrefused)).toBe(false);
    expect(isDefiniteWriteFailure(new mongoose.mongo.MongoNetworkError('connection reset'))).toBe(
      false,
    );
    expect(isDefiniteWriteFailure(new Error('anything'))).toBe(false);
    expect(isDefiniteWriteFailure('a string')).toBe(false);
  });

  it('a document that failed server-side validation (121) did not apply', () => {
    const refused = new mongoose.mongo.MongoServerError({
      message: 'Document failed validation',
      code: 121,
    });
    expect(isDefiniteWriteFailure(refused)).toBe(true);
  });
});

describe('a reservation that cannot be made', () => {
  it('refuses a byte count that is not a non-negative integer, writing nothing', async () => {
    const user = await createTestUser();
    await createQuotaItem(user, 500);
    const used = await expectCounterExact(user);

    for (const bytes of [-1, 1.5, Number.NaN]) {
      await expect(reserveVaultWrite(user.id, { bytes })).rejects.toThrow(RangeError);
    }
    expect(await vaultBytesCounter(user.id)).toBe(used);
  });

  it('gives up after three missed attempts: a growing one is refused, a zero one fails loudly', async () => {
    const user = await createTestUser();
    await createQuotaItem(user, 500);
    const used = await expectCounterExact(user);
    // A database whose conditional update never matches although the counter
    // has room (it keeps changing under the request).
    const real = User.updateOne.bind(User) as (...args: unknown[]) => unknown;
    let attempts = 0;
    vi.spyOn(User, 'updateOne').mockImplementation(((...args: unknown[]) => {
      const update = args[1] as { $inc?: { vaultBytes?: unknown } };
      if (update.$inc?.vaultBytes !== undefined) {
        attempts += 1;
        return Promise.resolve({ acknowledged: true, matchedCount: 0, modifiedCount: 0 });
      }
      return real(...args);
    }) as never);

    await expect(reserveVaultWrite(user.id, { bytes: 100 })).rejects.toThrow(
      VaultQuotaExceededError,
    );
    expect(attempts).toBe(3);
    await expect(reserveVaultWrite(user.id, { bytes: 0 })).rejects.toThrow(
      `The vault counter of ${user.id} could not be touched`,
    );
    expect(attempts).toBe(6);
    vi.restoreAllMocks();
    expect(await vaultBytesCounter(user.id)).toBe(used);
  });
});

describe('counter arithmetic refuses what it cannot store', () => {
  it('a non-finite delta is refused, and a settle that computes one leaves the counter alone', async () => {
    const user = await createTestUser();
    await createQuotaItem(user, 800);
    const used = await expectCounterExact(user);

    await expect(addVaultBytes(user.id, Number.NaN)).rejects.toThrow(RangeError);
    await expect(addVaultBytes(user.id, Number.POSITIVE_INFINITY)).rejects.toThrow(RangeError);
    // Best effort, as every settle is: logged, never thrown, nothing stored.
    await expect(
      settleVaultWrite({ userId: user.id, bytes: 0, items: 0, folders: 0 }, Number.NaN),
    ).resolves.toBeUndefined();

    expect(await vaultBytesCounter(user.id)).toBe(used);
  });
});

describe('every read the quota makes goes to the primary', () => {
  it('the install, the row measure, the reservation re-read and the delete walk', async () => {
    const user = await createTestUser();
    // A row stored before the counter existed: the first write installs it.
    const legacy = await VaultItem.create({ userId: user.id, ...quotaItemBody(800) });
    await VaultItem.updateOne({ _id: legacy._id }, { $set: { deletedAt: new Date() } });
    const id = await createQuotaItem(user, 600);

    const reads: { kind: string; collection: string; mode: unknown }[] = [];
    const modeOf = (options: unknown): unknown => {
      const preference = (options as { readPreference?: unknown } | undefined)?.readPreference;
      return typeof preference === 'string'
        ? preference
        : (preference as { mode?: unknown } | undefined)?.mode;
    };
    const proto = mongoose.mongo.Collection.prototype;
    const realFind = proto.find;
    const realFindOne = proto.findOne;
    const realAggregate = proto.aggregate;
    vi.spyOn(proto, 'find').mockImplementation(function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof realFind>
    ) {
      const projection = args[1]?.projection as Record<string, unknown> | undefined;
      if (projection && ('counted' in projection || Object.keys(projection).join() === '_id')) {
        reads.push({ kind: 'find', collection: this.collectionName, mode: modeOf(args[1]) });
      }
      if (this.collectionName === 'users' && projection && 'quotaEpoch' in projection) {
        reads.push({ kind: 'find', collection: 'users', mode: modeOf(args[1]) });
      }
      return realFind.apply(this, args);
    } as never);
    vi.spyOn(proto, 'findOne').mockImplementation(function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof realFindOne>
    ) {
      const projection = (args[1] as { projection?: Record<string, unknown> } | undefined)
        ?.projection;
      if (this.collectionName === 'users' && projection && 'vaultBytes' in projection) {
        reads.push({ kind: 'findOne', collection: 'users', mode: modeOf(args[1]) });
      }
      return realFindOne.apply(this, args as never);
    } as never);
    vi.spyOn(proto, 'aggregate').mockImplementation(function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof realAggregate>
    ) {
      if (JSON.stringify(args[0]).includes('$bsonSize')) {
        reads.push({ kind: 'aggregate', collection: this.collectionName, mode: modeOf(args[1]) });
      }
      return realAggregate.apply(this, args);
    } as never);
    // Remove the counter so the next write re-reads it and installs it again.
    await mongoose.connection
      .collection('users')
      .updateOne({ _id: new mongoose.Types.ObjectId(user.id) }, { $unset: { vaultBytes: '' } });

    expect((await apiCall(user, 'put', `/vault/items/${id}`, dataUpdate(900))).status).toBe(200);
    expect((await apiCall(user, 'delete', '/vault/items/trash/empty')).status).toBe(200);
    // The recount's candidate read.
    await recountVaultQuotas();
    // An import whose insert fails naming no row (a dropped connection) measures
    // what landed by id.
    const findsBeforeImport = reads.filter((read) => read.collection === 'vault_items').length;
    vi.spyOn(VaultItem, 'insertMany').mockRejectedValueOnce(
      new mongoose.mongo.MongoNetworkError('connection reset'),
    );
    const failed = await apiCall(user, 'post', '/tools/import', {
      format: 'json',
      operations: { inserts: [quotaItemBody(10, { searchHash: 'e'.repeat(64) })], updates: [] },
    });
    expect(failed.status).toBe(500);
    expect(reads.filter((read) => read.collection === 'vault_items').length).toBeGreaterThan(
      findsBeforeImport,
    );

    const kinds = new Set(reads.map((read) => `${read.kind}:${read.collection}`));
    // Each kind of read happened, and every one of them went to the primary.
    expect(kinds).toEqual(
      new Set([
        'findOne:users',
        'aggregate:vault_items',
        'aggregate:folders',
        'find:vault_items',
        'find:users',
      ]),
    );
    expect(reads.filter((read) => read.mode !== 'primary')).toEqual([]);
    await expectCounterExact(user);
  });
});

describe('the heavy responses read rows sixteen at a time', () => {
  it('the backup download, the export and the item list', async () => {
    const user = await createTestUser();
    await createQuotaItem(user, 100);
    expect((await apiCall(user, 'post', '/folders', sampleFolder())).status).toBe(201);
    const setup = await apiCall(user, 'post', '/backup/setup', {
      encryptedBWK: 'test-encrypted-bwk-data',
      bwkIv: 'test-bwk-iv-value',
      bwkTag: 'test-bwk-tag-value',
      bwkSalt: 'test-bwk-salt-value',
      authHash: user.rawPassword,
    });
    expect(setup.status).toBe(200);

    const real = mongoose.mongo.Collection.prototype.find;
    const seen: { collection: string; batchSize: unknown }[] = [];
    vi.spyOn(mongoose.mongo.Collection.prototype, 'find').mockImplementation(function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof real>
    ) {
      const projection = args[1]?.projection as Record<string, unknown> | undefined;
      const isRowWalk = !projection || 'sourceRefId' in projection || 'userId' in projection;
      if (
        (this.collectionName === 'vault_items' || this.collectionName === 'folders') &&
        isRowWalk
      ) {
        seen.push({ collection: this.collectionName, batchSize: args[1]?.batchSize });
      }
      return real.apply(this, args);
    } as never);

    expect((await apiCall(user, 'get', '/backup/download')).status).toBe(200);
    const download = seen.splice(0);
    expect(
      (await apiCall(user, 'post', '/tools/export', { authHash: user.rawPassword })).status,
    ).toBe(200);
    const exported = seen.splice(0);
    expect((await apiCall(user, 'get', '/vault/items')).status).toBe(200);
    const listed = seen.splice(0);

    // The download and the export each walk both collections twice (the size
    // estimate, then the stream); every walk asks for small batches.
    for (const walk of [download, exported]) {
      expect(new Set(walk.map((read) => read.collection))).toEqual(
        new Set(['folders', 'vault_items']),
      );
      expect(walk.filter((read) => read.batchSize !== ROW_CURSOR_BATCH_SIZE)).toEqual([]);
    }
    expect(download).toHaveLength(4);
    expect(exported).toHaveLength(4);
    expect(listed).toEqual([{ collection: 'vault_items', batchSize: ROW_CURSOR_BATCH_SIZE }]);
    expect(await storedVaultBytes(user.id)).toBeGreaterThan(0);
  });
});
