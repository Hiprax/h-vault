/**
 * F-12: the server stores no keyed hash of an item's or a folder's name.
 *
 * `searchHash` was an HMAC of the decrypted name under a subkey of the vault key.
 * Nothing read it: item restore matches on an owned `_id` and then
 * `(userId, sourceRefId)`, the client searches decrypted names locally, and the
 * folder index it backed was only ever reached by restored folders (ordinary
 * folder creates and renames sent no hash). What it did do was hand the server a
 * stable per-account fingerprint of every name, so two entries with the same name
 * were linkable, and an entry's name could be confirmed against a guess by anyone
 * who also held the vault key's subkey. So it is gone: no model declares it, no
 * index names it, no write path stores it, an older client that still sends it is
 * accepted and the value dropped, migration v5 removes it from the rows and every
 * index over it that a database already has, and no read returns a residual one.
 *
 * Every assertion about what is STORED reads the raw collection, never the model:
 * a model without the path would hide a field that is still in the document.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import app from '../src/app.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { JobLock } from '../src/models/JobLock.js';
import { Migration } from '../src/models/Migration.js';
import { runMigrations } from '../src/utils/migrations.js';
import {
  authHeader,
  createTestUser,
  getCsrf,
  sampleFolder,
  sampleVaultItem,
  seedFolder,
  seedItem,
  type TestUser,
} from './helpers.js';

const API = '/api/v1';

// The driver spies below wrap shared prototypes, so none may outlive its test.
afterEach(() => {
  vi.restoreAllMocks();
});
const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);

function items(): mongoose.mongo.Collection {
  return mongoose.connection.collection('vault_items');
}

function folders(): mongoose.mongo.Collection {
  return mongoose.connection.collection('folders');
}

function oid(id: string): mongoose.Types.ObjectId {
  return new mongoose.Types.ObjectId(id);
}

/** Every stored row of one collection for one account, straight from the driver. */
async function storedRows(
  collection: mongoose.mongo.Collection,
  userId: string,
): Promise<Record<string, unknown>[]> {
  return collection.find({ userId: oid(userId) }).toArray();
}

/** The keys of every index on a collection, as JSON, for set comparisons. */
async function indexKeys(collection: mongoose.mongo.Collection): Promise<string[]> {
  return (await collection.indexes()).map((index) => JSON.stringify(index.key));
}

async function send(
  method: 'post' | 'put',
  path: string,
  user: TestUser,
  body: Record<string, unknown>,
): Promise<request.Response> {
  const agent = request.agent(app);
  const { token, cookie } = await getCsrf(agent);
  return agent[method](`${API}${path}`)
    .set('Authorization', authHeader(user.accessToken))
    .set('Cookie', cookie)
    .set('x-csrf-token', token)
    .send(body);
}

/** One import insert, in the shape the current client sends: no `searchHash`. */
function importInsert(index: number, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return sampleVaultItem({
    encryptedName: `imported-name-${String(index)}`,
    encryptedData: `imported-data-${String(index)}`,
    ...extra,
  });
}

/** One import update, in the shape the current client sends: no `searchHash`. */
function importUpdate(id: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id,
    encryptedName: 'updated-name',
    nameIv: 'updated-name-iv',
    nameTag: 'updated-name-tag',
    encryptedData: 'updated-data',
    dataIv: 'updated-data-iv',
    dataTag: 'updated-data-tag',
    ...extra,
  };
}

describe('F-12: the models declare no name hash', () => {
  it('neither VaultItem nor Folder has a searchHash path', () => {
    expect(VaultItem.schema.path('searchHash')).toBeUndefined();
    expect(Folder.schema.path('searchHash')).toBeUndefined();
    // The paths that carry the name are still there: this is a removal of one
    // field, not of the name.
    expect(VaultItem.schema.path('encryptedName')).toBeDefined();
    expect(Folder.schema.path('encryptedName')).toBeDefined();
  });

  it('no declared index names searchHash', () => {
    for (const model of [VaultItem, Folder]) {
      const declared = model.schema.indexes().map(([keys]) => Object.keys(keys));
      expect(declared.some((keys) => keys.includes('searchHash'))).toBe(false);
      // Negative control: the scan sees the indexes that remain.
      expect(declared.some((keys) => keys.includes('userId'))).toBe(true);
    }
  });
});

describe('F-12: no write path stores a name hash an older client still sends', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  it('creating and updating an item accepts the field and stores nothing of it', async () => {
    const created = await send(
      'post',
      '/vault/items',
      user,
      sampleVaultItem({ searchHash: HASH_A }),
    );
    expect(created.status).toBe(201);
    expect(created.body.data).not.toHaveProperty('searchHash');
    const id = created.body.data._id as string;

    const updated = await send('put', `/vault/items/${id}`, user, {
      encryptedName: 'renamed',
      nameIv: 'renamed-iv',
      nameTag: 'renamed-tag',
      searchHash: HASH_B,
    });
    expect(updated.status).toBe(200);
    expect(updated.body.data).not.toHaveProperty('searchHash');

    const [row] = await storedRows(items(), user.id);
    expect(row).toBeDefined();
    expect(row).not.toHaveProperty('searchHash');
    expect(row?.encryptedName).toBe('renamed');
  });

  it('creating and renaming folders stores no hash, and two folders that sent the same one both exist', async () => {
    const first = await send('post', '/folders', user, sampleFolder({ searchHash: HASH_A }));
    const second = await send(
      'post',
      '/folders',
      user,
      sampleFolder({ encryptedName: 'second', searchHash: HASH_A }),
    );
    expect(first.status).toBe(201);
    expect(second.status).toBe(201);

    const renamed = await send('put', `/folders/${first.body.data._id as string}`, user, {
      encryptedName: 'renamed-folder',
      nameIv: 'renamed-folder-iv',
      nameTag: 'renamed-folder-tag',
      searchHash: HASH_B,
    });
    expect(renamed.status).toBe(200);

    const rows = await storedRows(folders(), user.id);
    expect(rows).toHaveLength(2);
    for (const row of rows) expect(row).not.toHaveProperty('searchHash');
  });

  it('an import without the field is accepted, and one with it stores nothing of it', async () => {
    const existing = await seedItem(user.id, { encryptedName: 'existing' });

    const res = await send('post', '/tools/import', user, {
      format: 'json',
      operations: {
        inserts: [importInsert(0), importInsert(1, { searchHash: HASH_A })],
        updates: [importUpdate(String(existing._id))],
      },
    });

    expect(res.status).toBe(201);
    expect(res.body.data).toMatchObject({ insertedCount: 2, updatedCount: 1 });
    const rows = await storedRows(items(), user.id);
    expect(rows).toHaveLength(3);
    for (const row of rows) expect(row).not.toHaveProperty('searchHash');
    expect(rows.map((row) => row.encryptedName).sort()).toEqual([
      'imported-name-0',
      'imported-name-1',
      'updated-name',
    ]);
  });

  it('a key rotation stores no hash for the items it re-encrypts', async () => {
    const item = await seedItem(user.id);
    const folder = await seedFolder(user.id);

    const res = await send('post', '/vault/items/bulk-reencrypt', user, {
      authHash: user.rawPassword,
      newEncryptedVaultKey: 'rotated-vault-key',
      newVaultKeyIv: 'rotated-vault-key-iv',
      newVaultKeyTag: 'rotated-vault-key-tag',
      items: [
        {
          id: String(item._id),
          encryptedName: 'rotated-name',
          nameIv: 'rotated-name-iv',
          nameTag: 'rotated-name-tag',
          encryptedData: 'rotated-data',
          dataIv: 'rotated-data-iv',
          dataTag: 'rotated-data-tag',
          searchHash: HASH_A,
        },
      ],
      folders: [
        {
          id: String(folder._id),
          encryptedName: 'rotated-folder',
          nameIv: 'rotated-folder-iv',
          nameTag: 'rotated-folder-tag',
          searchHash: HASH_B,
        },
      ],
    });

    expect(res.status).toBe(200);
    const [itemRow] = await storedRows(items(), user.id);
    const [folderRow] = await storedRows(folders(), user.id);
    expect(itemRow?.encryptedName).toBe('rotated-name');
    expect(folderRow?.encryptedName).toBe('rotated-folder');
    expect(itemRow).not.toHaveProperty('searchHash');
    expect(folderRow).not.toHaveProperty('searchHash');
  });

  it('never returns a hash a row still carries: lists, reads, a restore from trash and the export all exclude it', async () => {
    // A residual: a row an earlier release's process wrote with a hash (during a
    // rolling restart, after migration v5 ran), put there with a raw write.
    const item = await seedItem(user.id, { encryptedName: 'residual-item' });
    const trashed = await seedItem(user.id, {
      encryptedName: 'residual-trashed',
      deletedAt: new Date(),
    });
    const folder = await seedFolder(user.id, { encryptedName: 'residual-folder' });
    await items().updateMany({ userId: oid(user.id) }, { $set: { searchHash: HASH_A } });
    await folders().updateOne({ _id: oid(String(folder._id)) }, { $set: { searchHash: HASH_B } });
    const get = (path: string) =>
      request(app).get(`${API}${path}`).set('Authorization', authHeader(user.accessToken));

    const list = await get('/vault/items');
    const one = await get(`/vault/items/${String(item._id)}`);
    const trash = await get('/vault/items/trash');
    const folderList = await get('/folders');
    const restored = await send('post', `/vault/items/restore/${String(trashed._id)}`, user, {});
    const exported = await send('post', '/tools/export', user, { authHash: user.rawPassword });

    for (const res of [list, one, trash, folderList, restored, exported]) {
      expect(res.status).toBeLessThan(300);
      expect(JSON.stringify(res.body)).not.toContain('searchHash');
    }
    // Positive controls: the rows themselves came back, and the hash is still at
    // rest (only the projections hide it).
    expect(JSON.stringify(list.body)).toContain('residual-item');
    expect(JSON.stringify(folderList.body)).toContain('residual-folder');
    expect(JSON.stringify(exported.body)).toContain('residual-folder');
    expect(await items().countDocuments({ searchHash: HASH_A })).toBe(2);
  });

  it('never echoes a residual hash in an update response: item PUT, folder rename and reorder', async () => {
    const item = await seedItem(user.id, { encryptedName: 'residual-item' });
    const folder = await seedFolder(user.id, { encryptedName: 'residual-folder' });
    await items().updateOne({ _id: oid(String(item._id)) }, { $set: { searchHash: HASH_A } });
    await folders().updateOne({ _id: oid(String(folder._id)) }, { $set: { searchHash: HASH_B } });

    const updated = await send('put', `/vault/items/${String(item._id)}`, user, { favorite: true });
    const renamed = await send('put', `/folders/${String(folder._id)}`, user, {
      encryptedName: 'renamed-folder',
      nameIv: 'renamed-iv',
      nameTag: 'renamed-tag',
    });
    const reordered = await send('put', `/folders/${String(folder._id)}/sort`, user, {
      sortOrder: 2,
    });

    for (const res of [updated, renamed, reordered]) {
      expect(res.status).toBe(200);
      expect(res.body.data).not.toHaveProperty('searchHash');
    }
    // Positive controls: each answer is the row it changed.
    expect(updated.body.data.favorite).toBe(true);
    expect(renamed.body.data.encryptedName).toBe('renamed-folder');
    expect(reordered.body.data.sortOrder).toBe(2);
  });

  it('a restore of a backup whose rows carry hashes restores every row and stores none of them', async () => {
    // A backup written by an earlier release: two folders with the SAME hash (the
    // shape the old unique index refused) and items with hashes of their own.
    const backup = {
      items: [
        { ...sampleVaultItem({ encryptedName: 'backup-item-1' }), searchHash: HASH_A },
        { ...sampleVaultItem({ encryptedName: 'backup-item-2' }), searchHash: HASH_A },
      ],
      folders: [
        { ...sampleFolder({ encryptedName: 'backup-folder-1' }), searchHash: HASH_B, sortOrder: 0 },
        { ...sampleFolder({ encryptedName: 'backup-folder-2' }), searchHash: HASH_B, sortOrder: 1 },
      ],
    };

    const res = await send('post', '/backup/restore', user, {
      conflictStrategy: 'keep_both',
      data: JSON.stringify(backup),
    });

    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({
      itemsRestored: 2,
      foldersRestored: 2,
      itemsSkipped: 0,
      foldersSkipped: 0,
    });
    const itemRows = await storedRows(items(), user.id);
    const folderRows = await storedRows(folders(), user.id);
    expect(itemRows).toHaveLength(2);
    expect(folderRows).toHaveLength(2);
    for (const row of [...itemRows, ...folderRows]) expect(row).not.toHaveProperty('searchHash');
  });
});

// ---------------------------------------------------------------------------
// Migration v5
// ---------------------------------------------------------------------------

/**
 * Every index an earlier release built over `searchHash`, exactly as its models
 * declared them: the compound index on each collection, AND the single-field
 * sparse index the folder model's PATH option (`sparse: true`) created on its own.
 */
async function buildLegacyIndexes(): Promise<void> {
  await items().createIndex({ userId: 1, searchHash: 1 }, { sparse: true });
  await folders().createIndex(
    { userId: 1, searchHash: 1 },
    { unique: true, partialFilterExpression: { searchHash: { $type: 'string' } } },
  );
  await folders().createIndex({ searchHash: 1 }, { sparse: true });
}

/** Whether any index on a collection still names `searchHash` in its key. */
async function anyIndexNamesSearchHash(collection: mongoose.mongo.Collection): Promise<boolean> {
  return (await collection.indexes()).some((index) => 'searchHash' in index.key);
}

/** Rows written by an earlier release, hash and all, straight into the collections. */
async function seedLegacyRows(userId: string, count: number): Promise<void> {
  const now = new Date();
  await items().insertMany(
    Array.from({ length: count }, (_, index) => ({
      userId: oid(userId),
      itemType: 'login',
      encryptedData: `data-${String(index)}`,
      dataIv: 'iv',
      dataTag: 'tag',
      encryptedName: `name-${String(index)}`,
      nameIv: 'name-iv',
      nameTag: 'name-tag',
      tags: [],
      favorite: false,
      searchHash: index.toString(16).padStart(64, '0'),
      createdAt: now,
      updatedAt: now,
      __v: 3,
    })),
  );
  await folders().insertMany(
    Array.from({ length: 3 }, (_, index) => ({
      userId: oid(userId),
      encryptedName: `folder-${String(index)}`,
      nameIv: 'folder-iv',
      nameTag: 'folder-tag',
      sortOrder: index,
      searchHash: (index + 1).toString(16).padStart(64, 'f'),
      createdAt: now,
      updatedAt: now,
      __v: 0,
    })),
  );
}

describe('migration v5 (remove-search-hash)', () => {
  beforeEach(async () => {
    await JobLock.ensureIndexes();
    await Migration.ensureIndexes();
  });

  it('unsets the field on every row in batches, drops every index on it and touches nothing else', async () => {
    const a = await createTestUser();
    const b = await createTestUser();
    // More rows than one batch, so the walk has to page.
    await seedLegacyRows(a.id, 2_100);
    await seedLegacyRows(b.id, 5);
    await buildLegacyIndexes();
    const updateMany = vi.spyOn(mongoose.mongo.Collection.prototype, 'updateMany');

    await runMigrations();

    expect((await Migration.findOne({ version: 5 }).lean())?.name).toBe('remove-search-hash');
    expect(await items().countDocuments({ searchHash: { $exists: true } })).toBe(0);
    expect(await folders().countDocuments({ searchHash: { $exists: true } })).toBe(0);
    for (const collection of [items(), folders()]) {
      expect(await anyIndexNamesSearchHash(collection)).toBe(false);
      // Negative control: the indexes the models still declare are untouched.
      expect((await indexKeys(collection)).some((key) => key.startsWith('{"userId":1'))).toBe(true);
    }
    // Every other field is as it was, the version counter included: the unset is
    // not an edit, and a pin taken on `__v` by a concurrent write must still hold.
    const sample = await items().findOne({ userId: oid(a.id), encryptedName: 'name-7' });
    expect(sample).toMatchObject({ encryptedData: 'data-7', nameIv: 'name-iv', __v: 3 });
    expect(await items().countDocuments({})).toBe(2_105);
    expect(await folders().countDocuments({})).toBe(6);
    // Batched: no single write names more than one batch of rows.
    const itemWrites = updateMany.mock.contexts
      .map((context, index) => ({ context, args: updateMany.mock.calls[index] }))
      .filter(
        ({ context }) => (context as mongoose.mongo.Collection).collectionName === 'vault_items',
      );
    expect(itemWrites.length).toBeGreaterThanOrEqual(3);
    for (const { args } of itemWrites) {
      const filter = args?.[0] as { _id?: { $in?: unknown[] } } | undefined;
      expect(filter?._id?.$in?.length ?? Infinity).toBeLessThanOrEqual(1_000);
    }
  });

  it('is idempotent: a second run over a clean database changes nothing and does not fail', async () => {
    const user = await createTestUser();
    await seedLegacyRows(user.id, 4);
    await buildLegacyIndexes();
    await runMigrations();
    // Forget the record, as a crash between the work and the record would.
    await Migration.deleteOne({ version: 5 });

    await expect(runMigrations()).resolves.toBeUndefined();

    expect(await Migration.countDocuments({ version: 5 })).toBe(1);
    expect(await items().countDocuments({ searchHash: { $exists: true } })).toBe(0);
    expect(await items().countDocuments({ userId: oid(user.id) })).toBe(4);
  });

  it('runs on a database that never had the collections, and on an index another process dropped first', async () => {
    const user = await createTestUser();
    await seedLegacyRows(user.id, 2);
    await buildLegacyIndexes();
    // A database with no folders collection at all: listing its indexes answers
    // NamespaceNotFound. Simulated at the driver rather than by dropping the real
    // collection, which would take the indexes the model declares with it and
    // leave every later test in this file (in whatever order they run) without
    // them.
    const realIndexes = mongoose.mongo.Collection.prototype.indexes;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'indexes').mockImplementation(function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof realIndexes>
    ) {
      if (this.collectionName === 'folders') {
        return Promise.reject(
          new mongoose.mongo.MongoServerError({ message: 'ns does not exist', code: 26 }),
        );
      }
      return realIndexes.apply(this, args);
    } as never);
    // And the vault_items compound index is dropped by "another process" between
    // this run's listing and its drop: IndexNotFound.
    const real = mongoose.mongo.Collection.prototype.dropIndex;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'dropIndex').mockImplementation(async function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof real>
    ) {
      await real.apply(this, args);
      throw new mongoose.mongo.MongoServerError({ message: 'index not found', code: 27 });
    } as never);

    await expect(runMigrations()).resolves.toBeUndefined();

    expect(await Migration.countDocuments({ version: 5 })).toBe(1);
    expect(await anyIndexNamesSearchHash(items())).toBe(false);
    expect(await items().countDocuments({ searchHash: { $exists: true } })).toBe(0);
    // Negative: the rows themselves are all still there.
    expect(await items().countDocuments({ userId: oid(user.id) })).toBe(2);
  });

  it('a failure to list the indexes fails the migration and records nothing', async () => {
    const user = await createTestUser();
    await seedLegacyRows(user.id, 2);
    await buildLegacyIndexes();
    const real = mongoose.mongo.Collection.prototype.indexes;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'indexes').mockImplementation(function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof real>
    ) {
      if (this.collectionName === 'vault_items') {
        return Promise.reject(
          new mongoose.mongo.MongoServerError({ message: 'not authorized', code: 13 }),
        );
      }
      return real.apply(this, args);
    } as never);

    await expect(runMigrations()).rejects.toThrow('not authorized');

    expect(await Migration.countDocuments({ version: 5 })).toBe(0);
    // Nothing was cleared either: the field is removed only after the indexes.
    expect(await items().countDocuments({ searchHash: { $exists: true } })).toBe(2);
  });

  it('a failure other than a missing index fails the migration and records nothing', async () => {
    const user = await createTestUser();
    await seedLegacyRows(user.id, 2);
    await buildLegacyIndexes();
    const real = mongoose.mongo.Collection.prototype.dropIndex;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'dropIndex').mockImplementation(function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof real>
    ) {
      if (this.collectionName === 'folders') {
        return Promise.reject(
          new mongoose.mongo.MongoServerError({ message: 'not authorized', code: 13 }),
        );
      }
      return real.apply(this, args);
    } as never);

    await expect(runMigrations()).rejects.toThrow('not authorized');

    expect(await Migration.countDocuments({ version: 5 })).toBe(0);
  });
});
