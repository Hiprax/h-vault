/**
 * F-24: the vault byte counter stays exact when requests overlap.
 *
 * Each case forces ONE interleaving deterministically, by running the competing
 * request from inside a hook on the exact database call the first request is
 * about to make, then lets that call proceed. The assertion is always the same
 * ground truth (`support/vaultBytes.ts`, the database's own `$bsonSize` total),
 * plus what each request answered and which rows are left.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

vi.mock('node-cron', () => ({
  default: { schedule: vi.fn().mockReturnValue({ stop: vi.fn() }) },
}));

import mongoose from 'mongoose';
import cron from 'node-cron';
import { startTrashCleanupJob } from '../src/jobs/trashCleanup.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { User } from '../src/models/User.js';
import {
  installVaultCounters,
  reserveVaultWrite,
  VaultQuotaExceededError,
} from '../src/utils/vaultQuota.js';
import { createTestUser, sampleFolder, type TestUser } from './helpers.js';
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

/**
 * Runs `before(filter, call)` ahead of every native `findOneAndDelete` on
 * `vault_items` (the per-row delete every counted delete makes), then the delete.
 */
function hookItemDeletes(
  before: (filter: Record<string, unknown>, call: number) => Promise<void>,
): void {
  const real = mongoose.mongo.Collection.prototype.findOneAndDelete;
  let calls = 0;
  vi.spyOn(mongoose.mongo.Collection.prototype, 'findOneAndDelete').mockImplementation(
    async function (this: mongoose.mongo.Collection, ...args: Parameters<typeof real>) {
      if (this.collectionName === 'vault_items') {
        calls += 1;
        await before(args[0] as unknown as Record<string, unknown>, calls);
      }
      return real.apply(this, args);
    } as never,
  );
}

/**
 * Runs `before()` ahead of a native `findOneAndUpdate` on `collection` when
 * `matches(update)` holds (the pinned write `updateCountedRow` makes goes through
 * it), then the write itself; every other call passes straight through.
 */
function hookItemUpdates(
  matches: (update: { $set?: Record<string, unknown> }) => boolean,
  before: () => Promise<void>,
  collection = 'vault_items',
): void {
  const real = mongoose.mongo.Collection.prototype.findOneAndUpdate;
  vi.spyOn(mongoose.mongo.Collection.prototype, 'findOneAndUpdate').mockImplementation(
    async function (this: mongoose.mongo.Collection, ...args: Parameters<typeof real>) {
      if (
        this.collectionName === collection &&
        matches(args[1] as { $set?: Record<string, unknown> })
      ) {
        await before();
      }
      return real.apply(this, args);
    } as never,
  );
}

/** The `encryptedData` an update writes, or `''`. */
function writtenData(update: { $set?: Record<string, unknown> }): string {
  const value = update.$set?.['encryptedData'];
  return typeof value === 'string' ? value : '';
}

/** The nightly trash purge's tick, taken from the cron registration it makes. */
function purgeTick(): () => Promise<void> {
  const schedule = vi.mocked(cron.schedule);
  schedule.mockClear();
  startTrashCleanupJob();
  return schedule.mock.calls[0]![1] as () => Promise<void>;
}

/** An account whose rows were stored before the counter existed. */
async function legacyRows(): Promise<TestUser> {
  const user = await createTestUser();
  await VaultItem.create({ userId: user.id, ...quotaItemBody(3_000) });
  await VaultItem.create({ userId: user.id, ...quotaItemBody(5_000) });
  expect(await vaultBytesCounter(user.id)).toBeUndefined();
  return user;
}

/** The raw `users` row's `quotaEpoch`, which every counter write moves. */
async function quotaEpochOf(userId: string): Promise<number | undefined> {
  const row = await mongoose.connection
    .collection('users')
    .findOne({ _id: new mongoose.Types.ObjectId(userId) }, { projection: { quotaEpoch: 1 } });
  return row?.['quotaEpoch'] as number | undefined;
}

describe('many-row deletes subtract each row once, whoever removes it', () => {
  it('a second empty-trash that runs between the first one reading its rows and deleting them', async () => {
    const user = await createTestUser();
    const live = await createQuotaItem(user, 500);
    const trashed: string[] = [];
    for (const size of [1_000, 2_000, 3_000, 4_000]) {
      const id = await createQuotaItem(user, size);
      await trashQuotaItem(user, id);
      trashed.push(id);
    }
    await expectCounterExact(user);

    let second: Awaited<ReturnType<typeof apiCall>> | undefined;
    hookItemDeletes(async (_filter, call) => {
      if (call === 1) second = await apiCall(user, 'delete', '/vault/items/trash/empty');
    });

    const first = await apiCall(user, 'delete', '/vault/items/trash/empty');

    expect(first.status).toBe(200);
    expect(second?.status).toBe(200);
    // Every trashed row went exactly once: the second request removed all four,
    // the first found each already gone and counted none of them.
    expect(second?.body.data.deletedCount).toBe(4);
    expect(first.body.data.deletedCount).toBe(0);
    const left = await VaultItem.find({ userId: user.id }).lean();
    expect(left.map((row) => String(row._id))).toEqual([live]);
    await expectCounterExact(user);
  });

  it('a permanent delete that lands between the empty-trash reading its rows and deleting them', async () => {
    const user = await createTestUser();
    const trashed: string[] = [];
    for (const size of [1_500, 2_500, 3_500]) {
      const id = await createQuotaItem(user, size);
      await trashQuotaItem(user, id);
      trashed.push(id);
    }
    await expectCounterExact(user);
    const victim = trashed[2]!;

    let permanent: Awaited<ReturnType<typeof apiCall>> | undefined;
    hookItemDeletes(async (_filter, call) => {
      if (call === 1) {
        permanent = await apiCall(user, 'delete', `/vault/items/${victim}/permanent`);
      }
    });

    const emptied = await apiCall(user, 'delete', '/vault/items/trash/empty');

    expect(permanent?.status).toBe(200);
    expect(emptied.status).toBe(200);
    expect(emptied.body.data.deletedCount).toBe(2);
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
    expect(await expectCounterExact(user)).toBe(0);
  });

  it('an empty-trash that fails part-way still subtracts exactly the rows it removed', async () => {
    const user = await createTestUser();
    for (const size of [1_000, 2_000, 3_000, 4_000]) {
      await trashQuotaItem(user, await createQuotaItem(user, size));
    }
    await expectCounterExact(user);

    hookItemDeletes(async (_filter, call) => {
      if (call === 3) throw new Error('connection reset by peer');
    });

    const res = await apiCall(user, 'delete', '/vault/items/trash/empty');

    expect(res.status).toBe(500);
    // Two rows went before the failure, two are still in the trash, and the
    // counter subtracted exactly the two that went.
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(2);
    await expectCounterExact(user);
  });
});

describe('the first reservation of an account without a counter', () => {
  it('ten zero reservations at once all succeed, and the counter is installed exactly once', async () => {
    const user = await createTestUser();
    // Rows stored before the counter existed.
    await VaultItem.create({ userId: user.id, ...quotaItemBody(3_000) });
    await VaultItem.create({ userId: user.id, ...quotaItemBody(5_000) });
    expect(await vaultBytesCounter(user.id)).toBeUndefined();

    const reservations = await Promise.all(
      Array.from({ length: 10 }, () => reserveVaultWrite(user.id, { bytes: 0 })),
    );

    expect(reservations).toHaveLength(10);
    for (const reservation of reservations) {
      // F-15: a reservation also names the rows it took (none here).
      expect(reservation).toEqual({ userId: user.id, bytes: 0, items: 0, folders: 0 });
    }
    expect(await vaultBytesCounter(user.id)).toBe(await storedVaultBytes(user.id));
    expect(await storedVaultBytes(user.id)).toBeGreaterThan(8_000);
    // One install (its compare-and-set admits one writer) and one touch per
    // reservation: a second install would have moved the epoch a twelfth time.
    expect(await quotaEpochOf(user.id)).toBe(11);
  });

  /**
   * Runs `install` once, just before the reservation's re-read of the counter: the
   * moment another request installs the counter between this one's first,
   * missed, conditional update and its look at why it missed.
   */
  function installBeforeTheReRead(userId: string): void {
    const real = mongoose.mongo.Collection.prototype.findOne;
    let done = false;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'findOne').mockImplementation(async function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof real>
    ) {
      const projection = (args[1] as { projection?: Record<string, unknown> } | undefined)
        ?.projection;
      if (!done && this.collectionName === 'users' && projection && 'vaultBytes' in projection) {
        done = true;
        await installVaultCounters(userId);
      }
      return real.apply(this, args as never);
    } as never);
  }

  it('a GROWING reservation that lost the install race to another request is admitted when it fits', async () => {
    const user = await legacyRows();
    installBeforeTheReRead(user.id);

    const reservation = await reserveVaultWrite(user.id, { bytes: 1_000 });

    expect(reservation).toEqual({ userId: user.id, bytes: 1_000, items: 0, folders: 0 });
    expect(await vaultBytesCounter(user.id)).toBe((await storedVaultBytes(user.id)) + 1_000);
  });

  it('… and refused, counting nothing, when it does not', async () => {
    const user = await legacyRows();
    const stored = await storedVaultBytes(user.id);
    setQuotaBytes(stored + 500);
    installBeforeTheReRead(user.id);

    await expect(reserveVaultWrite(user.id, { bytes: 1_000 })).rejects.toThrow(
      VaultQuotaExceededError,
    );
    expect(await vaultBytesCounter(user.id)).toBe(stored);
  });
});

describe('a pinned update measures the row it actually replaced', () => {
  it('two updates of one item: the one that loses the pin measures again and the counter stays exact', async () => {
    const user = await createTestUser();
    const id = await createQuotaItem(user, 1_000);
    await expectCounterExact(user);

    let competing: Awaited<ReturnType<typeof apiCall>> | undefined;
    let pinnedWritesOfFirst = 0;
    hookItemUpdates(
      (update) => writtenData(update).startsWith('a'),
      async () => {
        pinnedWritesOfFirst += 1;
        // Between the first request's measure and its write, a second request
        // grows the same row a lot.
        if (pinnedWritesOfFirst === 1) {
          competing = await apiCall(user, 'put', `/vault/items/${id}`, {
            encryptedData: 'b'.repeat(9_000),
            dataIv: 'test-data-iv',
            dataTag: 'test-data-tag',
          });
        }
      },
    );

    const res = await apiCall(user, 'put', `/vault/items/${id}`, {
      encryptedData: 'a'.repeat(3_000),
      dataIv: 'test-data-iv',
      dataTag: 'test-data-tag',
    });

    expect(competing?.status).toBe(200);
    expect(res.status).toBe(200);
    // The first write missed its pin (the second bumped `__v`) and was made again
    // against the row as the second request left it.
    expect(pinnedWritesOfFirst).toBe(2);
    expect((await VaultItem.findById(id).lean())?.encryptedData).toBe('a'.repeat(3_000));
    await expectCounterExact(user);
  });

  it('an update whose row changes before every one of its writes gives up after three attempts with 409', async () => {
    const user = await createTestUser();
    const id = await createQuotaItem(user, 1_000);
    await expectCounterExact(user);

    let attempts = 0;
    hookItemUpdates(
      (update) => writtenData(update).startsWith('a'),
      async () => {
        attempts += 1;
        // Another writer moves `__v` each time (the counter is untouched: same size).
        await VaultItem.collection.updateOne(
          { _id: new mongoose.Types.ObjectId(id) },
          { $inc: { __v: 1 } },
        );
      },
    );

    const res = await apiCall(user, 'put', `/vault/items/${id}`, {
      encryptedData: 'a'.repeat(3_000),
      dataIv: 'test-data-iv',
      dataTag: 'test-data-tag',
    });

    expect(res.status).toBe(409);
    expect(res.body.message).toBe(
      'This entry was changed by another request while this one was saving it. Reload and try again.',
    );
    expect(attempts).toBe(3);
    expect((await VaultItem.findById(id).lean())?.encryptedData).toBe('d'.repeat(1_000));
    await expectCounterExact(user);
  });

  it('an item deleted and created again under its id between the measure and the write is not updated', async () => {
    const user = await createTestUser();
    const nonce = `${'6'.repeat(8)}${'0123456789abcdef'.repeat(2)}`;
    const original = await createQuotaItem(user, 1_000, { idNonce: nonce });
    await expectCounterExact(user);

    let recreated: string | undefined;
    hookItemUpdates(
      (update) => writtenData(update).startsWith('u'),
      async () => {
        if (recreated !== undefined) return;
        // The row goes for good, and a create with the same nonce brings back a
        // DIFFERENT row under the same id, at `__v` 0 again.
        await trashQuotaItem(user, original);
        const purge = await apiCall(user, 'delete', `/vault/items/${original}/permanent`);
        expect(purge.status).toBe(200);
        recreated = await createQuotaItem(user, 6_000, { idNonce: nonce });
      },
    );

    const res = await apiCall(user, 'put', `/vault/items/${original}`, {
      encryptedData: 'u'.repeat(2_000),
      dataIv: 'test-data-iv',
      dataTag: 'test-data-tag',
    });

    expect(recreated).toBe(original);
    // The edit was made to the row that went; its successor keeps its own content.
    expect(res.status).toBe(404);
    expect((await VaultItem.findById(original).lean())?.encryptedData).toBe('d'.repeat(6_000));
    await expectCounterExact(user);
  });

  it('a folder reordered between a rename measuring it and writing it: the rename is made again', async () => {
    const user = await createTestUser();
    const created = await apiCall(user, 'post', '/folders', sampleFolder());
    expect(created.status).toBe(201);
    const id = String(created.body.data._id);
    await expectCounterExact(user);

    // A reorder takes no fence and is counted (`sortOrder` is a counted field), so
    // it bumps `__v` and the rename's pinned write misses once.
    let reorder: Awaited<ReturnType<typeof apiCall>> | undefined;
    let renameWrites = 0;
    hookItemUpdates(
      (update) => update.$set?.['encryptedName'] === 'n'.repeat(400),
      async () => {
        renameWrites += 1;
        if (renameWrites === 1) {
          reorder = await apiCall(user, 'put', `/folders/${id}/sort`, { sortOrder: 7 });
        }
      },
      'folders',
    );

    const renamed = await apiCall(user, 'put', `/folders/${id}`, {
      encryptedName: 'n'.repeat(400),
      nameIv: 'renamed-iv',
      nameTag: 'renamed-tag',
    });

    expect(reorder?.status).toBe(200);
    expect(renamed.status).toBe(200);
    expect(renameWrites).toBe(2);
    const row = await mongoose.connection
      .collection('folders')
      .findOne({ _id: new mongoose.Types.ObjectId(id) });
    expect(row?.['encryptedName']).toBe('n'.repeat(400));
    expect(row?.['sortOrder']).toBe(7);
    await expectCounterExact(user);
  });
});

describe('a sequential rotation and the writers no fence stops', () => {
  it('a folder reordered between the rotation measuring it and writing it is rotated all the same', async () => {
    const user = await createTestUser();
    const item = await createQuotaItem(user, 1_000);
    const created = await apiCall(user, 'post', '/folders', sampleFolder());
    const folderId = String(created.body.data._id);
    await expectCounterExact(user);

    // A reorder takes no fence, so it can land mid-rotation; it bumps `__v`, the
    // rotation's pinned write misses, measures the folder again and retries.
    const real = mongoose.mongo.Collection.prototype.updateOne;
    let reorder: Awaited<ReturnType<typeof apiCall>> | undefined;
    let rotationWrites = 0;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'updateOne').mockImplementation(async function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof real>
    ) {
      const update = args[1] as { $set?: { encryptedName?: unknown } };
      if (this.collectionName === 'folders' && update.$set?.encryptedName === 'rotated-folder') {
        rotationWrites += 1;
        if (rotationWrites === 1) {
          reorder = await apiCall(user, 'put', `/folders/${folderId}/sort`, { sortOrder: 9 });
        }
      }
      return real.apply(this, args);
    } as never);

    const rotated = await apiCall(user, 'post', '/vault/items/bulk-reencrypt', {
      authHash: user.rawPassword,
      newEncryptedVaultKey: 'rotated-key',
      newVaultKeyIv: 'rotated-iv',
      newVaultKeyTag: 'rotated-tag',
      items: [
        {
          id: item,
          encryptedName: 'rotated-item',
          nameIv: 'ri-iv',
          nameTag: 'ri-tag',
          encryptedData: 'r'.repeat(2_500),
          dataIv: 'rd-iv',
          dataTag: 'rd-tag',
        },
      ],
      folders: [
        { id: folderId, encryptedName: 'rotated-folder', nameIv: 'rf-iv', nameTag: 'rf-tag' },
      ],
      documents: [],
    });

    expect(reorder?.status).toBe(200);
    expect(rotated.status).toBe(200);
    expect(rotationWrites).toBe(2);
    const folder = await mongoose.connection
      .collection('folders')
      .findOne({ _id: new mongoose.Types.ObjectId(folderId) });
    expect(folder?.['encryptedName']).toBe('rotated-folder');
    expect(folder?.['sortOrder']).toBe(9);
    await expectCounterExact(user);
  });
});

describe('a sequential rotation that is rolled back after retrying a row', () => {
  it('rolls the retried folder back on the image it actually wrote', async () => {
    const user = await createTestUser();
    const first = await apiCall(
      user,
      'post',
      '/folders',
      sampleFolder({ encryptedName: 'first-folder' }),
    );
    const second = await apiCall(
      user,
      'post',
      '/folders',
      sampleFolder({ encryptedName: 'second-folder' }),
    );
    const firstId = String(first.body.data._id);
    const secondId = String(second.body.data._id);
    await expectCounterExact(user);

    // The first folder's rotation write misses once (a reorder lands just before
    // it) and is made again; the second folder's write then fails, so the
    // rotation rolls the first one back.
    const real = mongoose.mongo.Collection.prototype.updateOne;
    let firstWrites = 0;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'updateOne').mockImplementation(async function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof real>
    ) {
      const update = args[1] as { $set?: { encryptedName?: unknown } };
      if (this.collectionName === 'folders') {
        if (update.$set?.encryptedName === 'rotated-first') {
          firstWrites += 1;
          if (firstWrites === 1) {
            const reorder = await apiCall(user, 'put', `/folders/${firstId}/sort`, {
              sortOrder: 4,
            });
            expect(reorder.status).toBe(200);
          }
        }
        if (update.$set?.encryptedName === 'rotated-second') {
          throw new mongoose.mongo.MongoServerError({
            message: 'the database refused the write',
            code: 121,
          });
        }
      }
      return real.apply(this, args);
    } as never);

    const rotated = await apiCall(user, 'post', '/vault/items/bulk-reencrypt', {
      authHash: user.rawPassword,
      newEncryptedVaultKey: 'rotated-key',
      newVaultKeyIv: 'rotated-iv',
      newVaultKeyTag: 'rotated-tag',
      items: [],
      folders: [
        { id: firstId, encryptedName: 'rotated-first', nameIv: 'r1-iv', nameTag: 'r1-tag' },
        { id: secondId, encryptedName: 'rotated-second', nameIv: 'r2-iv', nameTag: 'r2-tag' },
      ],
      documents: [],
    });

    expect(rotated.status).toBe(409);
    expect(firstWrites).toBe(2);
    const row = await mongoose.connection
      .collection('folders')
      .findOne({ _id: new mongoose.Types.ObjectId(firstId) });
    // Back to the name the unchanged vault key opens; the reorder survives.
    expect(row?.['encryptedName']).toBe('first-folder');
    expect(row?.['sortOrder']).toBe(4);
    await expectCounterExact(user);
  });
});

describe('the rollback of an aborted sequential rotation and the writers around it', () => {
  async function twoFolders(user: TestUser): Promise<[string, string]> {
    const first = await apiCall(
      user,
      'post',
      '/folders',
      sampleFolder({ encryptedName: 'first-folder' }),
    );
    const second = await apiCall(
      user,
      'post',
      '/folders',
      sampleFolder({ encryptedName: 'second-folder' }),
    );
    return [String(first.body.data._id), String(second.body.data._id)];
  }

  function rotateTwoFolders(user: TestUser, firstId: string, secondId: string) {
    return apiCall(user, 'post', '/vault/items/bulk-reencrypt', {
      authHash: user.rawPassword,
      newEncryptedVaultKey: 'rotated-key',
      newVaultKeyIv: 'rotated-iv',
      newVaultKeyTag: 'rotated-tag',
      items: [],
      folders: [
        { id: firstId, encryptedName: 'rotated-first', nameIv: 'r1-iv', nameTag: 'r1-tag' },
        { id: secondId, encryptedName: 'rotated-second', nameIv: 'r2-iv', nameTag: 'r2-tag' },
      ],
      documents: [],
    });
  }

  /**
   * Fails the second folder's rotation write, and runs `beforeRollback` once just
   * before the first folder's rollback write (the write restoring its old name).
   */
  function failSecondAndHookRollback(
    beforeRollback: () => Promise<void>,
    everyAttempt = false,
  ): { rollbackWrites: number } {
    const counts = { rollbackWrites: 0 };
    const real = mongoose.mongo.Collection.prototype.updateOne;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'updateOne').mockImplementation(async function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof real>
    ) {
      const update = args[1] as { $set?: { encryptedName?: unknown } };
      if (this.collectionName === 'folders') {
        if (update.$set?.encryptedName === 'rotated-second') {
          throw new mongoose.mongo.MongoServerError({
            message: 'the database refused the write',
            code: 121,
          });
        }
        if (update.$set?.encryptedName === 'first-folder') {
          counts.rollbackWrites += 1;
          if (everyAttempt || counts.rollbackWrites === 1) await beforeRollback();
        }
      }
      return real.apply(this, args);
    } as never);
    return counts;
  }

  it('a folder reordered just before its rollback is still rolled back to the old name', async () => {
    const user = await createTestUser();
    const [firstId, secondId] = await twoFolders(user);
    await expectCounterExact(user);
    const counts = failSecondAndHookRollback(async () => {
      // A reorder takes no fence: it lands while the rotation is rolling back.
      const reorder = await apiCall(user, 'put', `/folders/${firstId}/sort`, { sortOrder: 6 });
      expect(reorder.status).toBe(200);
    });

    // How often the rollback asks whether the rotation committed before undoing it.
    const realFindOne = mongoose.mongo.Collection.prototype.findOne;
    let committedChecks = 0;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'findOne').mockImplementation(async function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof realFindOne>
    ) {
      const projection = (args[1] as { projection?: Record<string, unknown> } | undefined)
        ?.projection;
      if (this.collectionName === 'users' && projection && 'encryptedVaultKey' in projection) {
        committedChecks += 1;
      }
      return realFindOne.apply(this, args as never);
    } as never);

    const rotated = await rotateTwoFolders(user, firstId, secondId);

    expect(rotated.status).toBe(409);
    // The rollback missed its pin once (the reorder bumped `__v`) and was retried.
    expect(counts.rollbackWrites).toBe(2);
    // One rollback pass: the orderly abort reaches the rollback twice (its own
    // call, then the catch), and the second finds nothing left to undo.
    expect(committedChecks).toBe(1);
    const row = await mongoose.connection
      .collection('folders')
      .findOne({ _id: new mongoose.Types.ObjectId(firstId) });
    expect(row?.['encryptedName']).toBe('first-folder');
    expect(row?.['nameIv']).toBe('test-folder-name-iv');
    expect(row?.['sortOrder']).toBe(6);
    await expectCounterExact(user);
  });

  it('a rollback whose folder is reordered before every attempt gives up after three', async () => {
    const user = await createTestUser();
    const [firstId, secondId] = await twoFolders(user);
    await expectCounterExact(user);
    let order = 10;
    const counts = failSecondAndHookRollback(async () => {
      order += 1;
      const reorder = await apiCall(user, 'put', `/folders/${firstId}/sort`, { sortOrder: order });
      expect(reorder.status).toBe(200);
    }, true);

    const rotated = await rotateTwoFolders(user, firstId, secondId);

    expect(rotated.status).toBe(409);
    expect(counts.rollbackWrites).toBe(3);
    await expectCounterExact(user);
  });

  it("a folder another writer rewrote before the rollback keeps that writer's content", async () => {
    const user = await createTestUser();
    const [firstId, secondId] = await twoFolders(user);
    await expectCounterExact(user);
    const counts = failSecondAndHookRollback(async () => {
      // A write that raced the fence: new ciphertext (same sizes, so the counter
      // needs no help to stay exact) and a new `__v`.
      await mongoose.connection
        .collection('folders')
        .updateOne(
          { _id: new mongoose.Types.ObjectId(firstId) },
          { $set: { encryptedName: 'raced-first-1', nameIv: 'rX-iv' }, $inc: { __v: 1 } },
        );
    });

    const rotated = await rotateTwoFolders(user, firstId, secondId);

    expect(rotated.status).toBe(409);
    const row = await mongoose.connection
      .collection('folders')
      .findOne({ _id: new mongoose.Types.ObjectId(firstId) });
    // Not rolled back over: the snapshot would have destroyed the newer write.
    expect(row?.['encryptedName']).toBe('raced-first-1');
    expect(row?.['nameIv']).toBe('rX-iv');
    // One attempt: the re-measure no longer finds this rotation's IVs, so the
    // rollback gives up rather than retry over the newer write.
    expect(counts.rollbackWrites).toBe(1);
    await expectCounterExact(user);
  });

  it('a rewrite that raced the fence WITHOUT moving `__v` is still not rolled back over', async () => {
    // A writer that changes ciphertext without bumping `__v` (an older server
    // during a rolling deploy): only the IVs in the rollback's own filter tell
    // its write apart from the rotation's.
    const user = await createTestUser();
    const [firstId, secondId] = await twoFolders(user);
    await expectCounterExact(user);
    const counts = failSecondAndHookRollback(async () => {
      await mongoose.connection
        .collection('folders')
        .updateOne(
          { _id: new mongoose.Types.ObjectId(firstId) },
          { $set: { encryptedName: 'raced-first-2', nameIv: 'rY-iv' } },
        );
    });

    const rotated = await rotateTwoFolders(user, firstId, secondId);

    expect(rotated.status).toBe(409);
    const row = await mongoose.connection
      .collection('folders')
      .findOne({ _id: new mongoose.Types.ObjectId(firstId) });
    expect(row?.['encryptedName']).toBe('raced-first-2');
    expect(row?.['nameIv']).toBe('rY-iv');
    expect(counts.rollbackWrites).toBe(1);
    await expectCounterExact(user);
  });
});

/**
 * Replaces the row `id` with ANOTHER incarnation of it: deleted and stored again
 * under the same id at `__v` 0, identical but for a later `createdAt` (a Date is
 * eight bytes either way, so the counter stays exact without help).
 */
async function recreateUnderItsId(
  collection: 'vault_items' | 'folders',
  id: string,
): Promise<void> {
  const raw = mongoose.connection.collection(collection);
  const _id = new mongoose.Types.ObjectId(id);
  const row = await raw.findOne({ _id });
  expect(row).not.toBeNull();
  await raw.deleteOne({ _id });
  await raw.insertOne({ ...row!, __v: 0, createdAt: new Date(Date.now() + 60_000) });
}

describe('the rollback of an aborted sequential rotation and an item rewritten under it', () => {
  it("an item a writer rewrote before its rollback keeps that writer's content", async () => {
    const user = await createTestUser();
    const first = await createQuotaItem(user, 1_000);
    const second = await createQuotaItem(user, 1_000);
    await expectCounterExact(user);

    const real = mongoose.mongo.Collection.prototype.updateOne;
    let raced = false;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'updateOne').mockImplementation(async function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof real>
    ) {
      const update = args[1] as { $set?: { encryptedName?: unknown } };
      if (this.collectionName === 'vault_items') {
        if (update.$set?.encryptedName === 'rotated-second') {
          throw new mongoose.mongo.MongoServerError({
            message: 'the database refused the write',
            code: 121,
          });
        }
        // The first item's rollback is about to run: a write that raced the
        // fence has rewritten it (same sizes, so the counter needs no help).
        if (!raced && update.$set?.encryptedName === 'test-encrypted-name') {
          raced = true;
          await VaultItem.collection.updateOne(
            { _id: new mongoose.Types.ObjectId(first) },
            { $set: { encryptedName: 'raced-first0', nameIv: 'rq0-iv' } },
          );
        }
      }
      return real.apply(this, args);
    } as never);

    const rotated = await apiCall(user, 'post', '/vault/items/bulk-reencrypt', {
      authHash: user.rawPassword,
      newEncryptedVaultKey: 'rotated-key',
      newVaultKeyIv: 'rotated-iv',
      newVaultKeyTag: 'rotated-tag',
      items: [first, second].map((id, index) => ({
        id,
        encryptedName: index === 0 ? 'rotated-firs' : 'rotated-second',
        nameIv: `ri${String(index)}-iv`,
        nameTag: 'ri-tag',
        encryptedData: 'r'.repeat(1_000),
        dataIv: `rd${String(index)}-iv`,
        dataTag: 'rd-tag',
      })),
      folders: [],
      documents: [],
    });

    expect(rotated.status).toBe(409);
    expect(raced).toBe(true);
    const row = await VaultItem.findById(first).lean();
    expect(row?.encryptedName).toBe('raced-first0');
    expect(row?.nameIv).toBe('rq0-iv');
    await expectCounterExact(user);
  });
});

describe('a sequential rotation write whose outcome is unknown', () => {
  function rotation(user: TestUser, rows: { id: string; name: string; data: number }[]) {
    return apiCall(user, 'post', '/vault/items/bulk-reencrypt', {
      authHash: user.rawPassword,
      newEncryptedVaultKey: 'rotated-key',
      newVaultKeyIv: 'rotated-iv',
      newVaultKeyTag: 'rotated-tag',
      items: rows.map((row, index) => ({
        id: row.id,
        encryptedName: row.name,
        nameIv: `rn${String(index)}-iv`,
        nameTag: 'rn-tag',
        encryptedData: 'r'.repeat(row.data),
        dataIv: `rd${String(index)}-iv`,
        dataTag: 'rd-tag',
      })),
      folders: [],
      documents: [],
    });
  }

  /** Lets the matching item write land, then fails it as a dropped connection would. */
  function landThenDrop(matches: (name: unknown) => boolean): void {
    const real = mongoose.mongo.Collection.prototype.updateOne;
    let dropped = false;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'updateOne').mockImplementation(async function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof real>
    ) {
      const update = args[1] as { $set?: { encryptedName?: unknown } };
      if (
        !dropped &&
        this.collectionName === 'vault_items' &&
        matches(update.$set?.encryptedName)
      ) {
        dropped = true;
        await real.apply(this, args);
        throw new mongoose.mongo.MongoNetworkError('connection reset after the write');
      }
      return real.apply(this, args);
    } as never);
  }

  it('a rotation write that landed before its connection dropped keeps its growth counted', async () => {
    const user = await createTestUser();
    const id = await createQuotaItem(user, 1_000);
    await expectCounterExact(user);
    landThenDrop((name) => name === 'rotated-grown');

    const res = await rotation(user, [{ id, name: 'rotated-grown', data: 6_000 }]);

    expect(res.status).toBe(409);
    // The write landed (the row grew), and the counter followed it.
    expect((await VaultItem.findById(id).lean())?.encryptedData).toBe('r'.repeat(6_000));
    await expectCounterExact(user);
  });

  it('a rollback write that landed before its connection dropped keeps its growth counted', async () => {
    const user = await createTestUser();
    const first = await createQuotaItem(user, 6_000);
    const second = await createQuotaItem(user, 6_000);
    await expectCounterExact(user);
    // The second row's (shrinking) write is refused outright; the first row's
    // rollback, which grows it back to its old size, lands and then drops.
    const real = mongoose.mongo.Collection.prototype.updateOne;
    let rolledBack = false;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'updateOne').mockImplementation(async function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof real>
    ) {
      const update = args[1] as { $set?: { encryptedName?: unknown } };
      if (this.collectionName === 'vault_items') {
        if (update.$set?.encryptedName === 'shrunk-second') {
          throw new mongoose.mongo.MongoServerError({
            message: 'the database refused the write',
            code: 121,
          });
        }
        if (!rolledBack && update.$set?.encryptedName === 'test-encrypted-name') {
          rolledBack = true;
          await real.apply(this, args);
          throw new mongoose.mongo.MongoNetworkError('connection reset after the rollback');
        }
      }
      return real.apply(this, args);
    } as never);

    const res = await rotation(user, [
      { id: first, name: 'shrunk-first', data: 100 },
      { id: second, name: 'shrunk-second', data: 100 },
    ]);

    expect(res.status).toBe(409);
    expect(rolledBack).toBe(true);
    expect((await VaultItem.findById(first).lean())?.encryptedData).toBe('d'.repeat(6_000));
    await expectCounterExact(user);
  });
});

describe('another incarnation of a row is never written by a write measured on the first', () => {
  it('a sequential rotation stops at an item deleted and created again under its id', async () => {
    const user = await createTestUser();
    const id = await createQuotaItem(user, 1_000);
    await expectCounterExact(user);

    const real = mongoose.mongo.Collection.prototype.updateOne;
    let replaced = false;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'updateOne').mockImplementation(async function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof real>
    ) {
      const update = args[1] as { $set?: { encryptedName?: unknown } };
      if (
        !replaced &&
        this.collectionName === 'vault_items' &&
        update.$set?.encryptedName === 'rotated-item'
      ) {
        replaced = true;
        await recreateUnderItsId('vault_items', id);
      }
      return real.apply(this, args);
    } as never);

    const rotated = await apiCall(user, 'post', '/vault/items/bulk-reencrypt', {
      authHash: user.rawPassword,
      newEncryptedVaultKey: 'rotated-key',
      newVaultKeyIv: 'rotated-iv',
      newVaultKeyTag: 'rotated-tag',
      items: [
        {
          id,
          encryptedName: 'rotated-item',
          nameIv: 'ri-iv',
          nameTag: 'ri-tag',
          encryptedData: 'r'.repeat(3_000),
          dataIv: 'rd-iv',
          dataTag: 'rd-tag',
        },
      ],
      folders: [],
      documents: [],
    });

    expect(replaced).toBe(true);
    // The rotation's ciphertext belongs to the row it enumerated, which is gone:
    // it aborts rather than seal the new incarnation under a key never adopted.
    expect(rotated.status).toBe(409);
    const row = await VaultItem.findById(id).lean();
    expect(row?.encryptedData).toBe('d'.repeat(1_000));
    await expectCounterExact(user);
  });

  it('an import overwrite stops at a target deleted and created again under its id', async () => {
    const user = await createTestUser();
    const target = await createQuotaItem(user, 900);
    await expectCounterExact(user);

    const real = VaultItem.updateOne.bind(VaultItem) as (...args: unknown[]) => unknown;
    let replaced = false;
    vi.spyOn(VaultItem, 'updateOne').mockImplementation(((...args: unknown[]) => {
      const filter = args[0] as { _id?: unknown; __v?: unknown };
      if (!replaced && String(filter._id) === target && filter.__v !== undefined) {
        replaced = true;
        return (async () => {
          await recreateUnderItsId('vault_items', target);
          return real(...args);
        })();
      }
      return real(...args);
    }) as never);

    const res = await apiCall(user, 'post', '/tools/import', {
      format: 'json',
      operations: {
        inserts: [],
        updates: [
          {
            id: target,
            encryptedName: 'overwritten',
            nameIv: 'o-iv',
            nameTag: 'o-tag',
            encryptedData: 'o'.repeat(4_000),
            dataIv: 'o-data-iv',
            dataTag: 'o-data-tag',
            searchHash: 'c'.repeat(64),
          },
        ],
      },
    });

    expect(replaced).toBe(true);
    expect(res.status).toBe(409);
    expect((await VaultItem.findById(target).lean())?.encryptedData).toBe('d'.repeat(900));
    await expectCounterExact(user);
  });
});

describe('a single-row write hands its reservation back exactly when it certainly did not apply', () => {
  it('a create whose derived id is already stored (409): reserved, then released whole', async () => {
    const user = await createTestUser();
    const nonce = `${'5'.repeat(8)}${'00112233445566778899aabbccddeeff'}`;
    await createQuotaItem(user, 700, { idNonce: nonce });
    await expectCounterExact(user);
    const epoch = await quotaEpochOf(user.id);

    const res = await apiCall(
      user,
      'post',
      '/vault/items',
      quotaItemBody(4_000, { idNonce: nonce }),
    );

    expect(res.status).toBe(409);
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(1);
    expect(await quotaEpochOf(user.id)).toBe((epoch ?? 0) + 2);
    await expectCounterExact(user);
  });

  // This used to reach the refusal through the folder name index (a rename onto a
  // name hash the account already had: E11000, 409). F-12 removed that index, so no
  // rename can conflict any more; the property it pinned — a growing rename the
  // database certainly refused hands its reservation back whole — is reached here
  // through a definite refusal injected at the driver, as the tests above do.
  it('a folder rename the database certainly refused: reserved, then released whole', async () => {
    const user = await createTestUser();
    const created = await apiCall(user, 'post', '/folders', sampleFolder());
    expect(created.status).toBe(201);
    const id = String(created.body.data._id);
    await expectCounterExact(user);
    const epoch = await quotaEpochOf(user.id);
    const grown = 'a-much-longer-name-that-would-grow-the-folder-row';
    const real = mongoose.mongo.Collection.prototype.findOneAndUpdate;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'findOneAndUpdate').mockImplementation(function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof real>
    ) {
      const update = args[1] as { $set?: { encryptedName?: unknown } };
      if (this.collectionName === 'folders' && update.$set?.encryptedName === grown) {
        return Promise.reject(
          new mongoose.mongo.MongoServerError({
            message: 'the database refused the write',
            code: 121,
          }),
        );
      }
      return real.apply(this, args);
    } as never);

    const res = await apiCall(user, 'put', `/folders/${id}`, {
      encryptedName: grown,
      nameIv: 'renamed-iv',
      nameTag: 'renamed-tag',
    });

    expect(res.status).toBe(500);
    expect((await Folder.findById(id).lean())?.encryptedName).not.toBe(grown);
    expect(await quotaEpochOf(user.id)).toBe((epoch ?? 0) + 2);
    await expectCounterExact(user);
  });

  it('a create whose outcome is unknown (the connection dropped after the write) stays counted', async () => {
    const user = await createTestUser();
    await createQuotaItem(user, 500);
    await expectCounterExact(user);

    const real = VaultItem.create.bind(VaultItem) as (...args: unknown[]) => unknown;
    vi.spyOn(VaultItem, 'create').mockImplementation(((...args: unknown[]) =>
      (async () => {
        await (real(...args) as Promise<unknown>);
        throw new mongoose.mongo.MongoNetworkError('connection reset after the write');
      })()) as never);

    const res = await apiCall(user, 'post', '/vault/items', quotaItemBody(6_000));

    expect(res.status).toBe(500);
    // The row landed; the reservation it was made under is kept, and is exact.
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(2);
    await expectCounterExact(user);
  });
});

describe('the nightly purge and a counter it cannot touch', () => {
  it('deletes nothing for an account whose reservation fails for any reason but a missing account', async () => {
    const user = await createTestUser();
    const id = await createQuotaItem(user, 2_000);
    await trashQuotaItem(user, id);
    await VaultItem.updateOne(
      { _id: id },
      { $set: { deletedAt: new Date(Date.now() - 400 * 86_400_000) } },
    );
    const used = await expectCounterExact(user);
    const real = User.updateOne.bind(User) as (...args: unknown[]) => unknown;
    vi.spyOn(User, 'updateOne').mockImplementation(((...args: unknown[]) => {
      const update = args[1] as { $inc?: { vaultBytes?: unknown } };
      if (update.$inc?.vaultBytes !== undefined) {
        return Promise.reject(new Error('the database refused the counter'));
      }
      return real(...args);
    }) as never);

    await purgeTick()();
    vi.restoreAllMocks();

    // Not purged uncounted: the row waits for a run that can count it.
    expect(await VaultItem.exists({ _id: id })).not.toBeNull();
    expect(await vaultBytesCounter(user.id)).toBe(used);
    await expectCounterExact(user);
  });
});

describe('an account without a counter, first touched by a many-row delete', () => {
  it('emptying the trash installs the counter and subtracts what it removed, once', async () => {
    const user = await legacyRows();
    const trashed = await VaultItem.create({
      userId: user.id,
      ...quotaItemBody(4_000),
      deletedAt: new Date(),
    });

    const res = await apiCall(user, 'delete', '/vault/items/trash/empty');

    expect(res.status).toBe(200);
    expect(res.body.data.deletedCount).toBe(1);
    expect(await VaultItem.exists({ _id: trashed._id })).toBeNull();
    await expectCounterExact(user);
  });

  it('the nightly purge installs the counter and subtracts what it removed, once', async () => {
    const user = await legacyRows();
    await VaultItem.create({
      userId: user.id,
      ...quotaItemBody(4_000),
      deletedAt: new Date(Date.now() - 400 * 86_400_000),
    });

    await purgeTick()();

    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(2);
    await expectCounterExact(user);
  });
});

describe('an import refused after its reservation hands the reservation back', () => {
  it('a vault-key generation that moved after the reservation (409)', async () => {
    const user = await createTestUser();
    await createQuotaItem(user, 900);
    await expectCounterExact(user);
    const epochBefore = await quotaEpochOf(user.id);

    const res = await apiCall(user, 'post', '/tools/import', {
      format: 'json',
      vaultKeyVersion: 99,
      operations: {
        inserts: [quotaItemBody(5_000, { searchHash: 'b'.repeat(64) })],
        updates: [],
      },
    });

    expect(res.status).toBe(409);
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(1);
    // The reservation WAS taken (the counter moved twice: reserve, then release)
    // and was handed back whole.
    expect(await quotaEpochOf(user.id)).toBe((epochBefore ?? 0) + 2);
    await expectCounterExact(user);
  });

  it('an update target changed mid-request (409): the inserts that landed stay counted', async () => {
    const user = await createTestUser();
    const target = await createQuotaItem(user, 900);
    await expectCounterExact(user);

    const real = VaultItem.updateOne.bind(VaultItem) as (...args: unknown[]) => unknown;
    vi.spyOn(VaultItem, 'updateOne').mockImplementation(((...args: unknown[]) => {
      const filter = args[0] as { _id?: unknown; __v?: unknown };
      if (String(filter._id) === target && filter.__v !== undefined) {
        return (async () => {
          // Another writer changes the row after the import measured it.
          await VaultItem.collection.updateOne(
            { _id: new mongoose.Types.ObjectId(target) },
            { $inc: { __v: 1 } },
          );
          return real(...args);
        })();
      }
      return real(...args);
    }) as never);

    const res = await apiCall(user, 'post', '/tools/import', {
      format: 'json',
      operations: {
        inserts: [quotaItemBody(2_000, { searchHash: 'c'.repeat(64) })],
        updates: [
          {
            id: target,
            encryptedName: 'overwritten',
            nameIv: 'o-iv',
            nameTag: 'o-tag',
            encryptedData: 'o'.repeat(4_000),
            dataIv: 'o-data-iv',
            dataTag: 'o-data-tag',
            searchHash: 'c'.repeat(64),
          },
        ],
      },
    });

    expect(res.status).toBe(409);
    // Standalone: the insert ahead of the failure landed and is counted; the
    // update did not apply.
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(2);
    expect((await VaultItem.findById(target).lean())?.encryptedData).toBe('d'.repeat(900));
    await expectCounterExact(user);
  });

  it('an insert that applied before its connection dropped, whose rows cannot be measured either, stays counted', async () => {
    const user = await createTestUser();
    await createQuotaItem(user, 900);
    await expectCounterExact(user);

    // The insert lands, then the connection drops; the follow-up read of what
    // landed fails too.
    const realInsert = VaultItem.insertMany.bind(VaultItem) as (...args: unknown[]) => unknown;
    vi.spyOn(VaultItem, 'insertMany').mockImplementationOnce(((...args: unknown[]) =>
      (async () => {
        await (realInsert(...args) as Promise<unknown>);
        throw new mongoose.mongo.MongoNetworkError('connection reset after the insert');
      })()) as never);
    const realFind = mongoose.mongo.Collection.prototype.find;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'find').mockImplementation(function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof realFind>
    ) {
      const projection = args[1]?.projection as Record<string, unknown> | undefined;
      if (this.collectionName === 'vault_items' && projection && 'counted' in projection) {
        throw new mongoose.mongo.MongoNetworkError('still unreachable');
      }
      return realFind.apply(this, args);
    } as never);

    const res = await apiCall(user, 'post', '/tools/import', {
      format: 'json',
      operations: {
        inserts: [
          quotaItemBody(2_000, { searchHash: 'd'.repeat(64) }),
          quotaItemBody(3_000, { searchHash: 'd'.repeat(64) }),
        ],
        updates: [],
      },
    });
    vi.restoreAllMocks();

    expect(res.status).toBe(500);
    // Both rows landed and both are counted: what the insert reserved was kept.
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(3);
    await expectCounterExact(user);
  });

  it('an update whose write failed ambiguously after it applied stays counted (standalone)', async () => {
    const user = await createTestUser();
    const target = await createQuotaItem(user, 900);
    await expectCounterExact(user);

    // The write lands, then the connection drops before the answer arrives.
    const real = VaultItem.updateOne.bind(VaultItem) as (...args: unknown[]) => unknown;
    vi.spyOn(VaultItem, 'updateOne').mockImplementation(((...args: unknown[]) => {
      const filter = args[0] as { _id?: unknown; __v?: unknown };
      if (String(filter._id) === target && filter.__v !== undefined) {
        return (async () => {
          await (real(...args) as Promise<unknown>);
          throw new mongoose.mongo.MongoNetworkError('connection reset after the write');
        })();
      }
      return real(...args);
    }) as never);

    const res = await apiCall(user, 'post', '/tools/import', {
      format: 'json',
      operations: {
        inserts: [],
        updates: [
          {
            id: target,
            encryptedName: 'grown',
            nameIv: 'g-iv',
            nameTag: 'g-tag',
            encryptedData: 'g'.repeat(6_000),
            dataIv: 'g-data-iv',
            dataTag: 'g-data-tag',
            searchHash: 'c'.repeat(64),
          },
        ],
      },
    });

    expect(res.status).toBe(500);
    // The update applied; its growth is counted although the request failed.
    expect((await VaultItem.findById(target).lean())?.encryptedData).toBe('g'.repeat(6_000));
    await expectCounterExact(user);
  });

  it("an insert whose derived id another create took meanwhile (409): only this request's rows are counted", async () => {
    const user = await createTestUser();
    const nonce = `${'7'.repeat(8)}${'fedcba9876543210'.repeat(2)}`;

    const real = VaultItem.insertMany.bind(VaultItem) as (...args: unknown[]) => unknown;
    let raced: string | undefined;
    vi.spyOn(VaultItem, 'insertMany').mockImplementation(((...args: unknown[]) => {
      return (async () => {
        // The id the second insert derives from its nonce is taken, by an
        // ordinary create with the same nonce, after the import checked it.
        raced ??= await createQuotaItem(user, 7_000, { idNonce: nonce });
        return real(...args);
      })();
    }) as never);

    const res = await apiCall(user, 'post', '/tools/import', {
      format: 'json',
      operations: {
        inserts: [
          quotaItemBody(1_000, { searchHash: 'd'.repeat(64) }),
          quotaItemBody(2_000, { searchHash: 'd'.repeat(64), idNonce: nonce }),
          quotaItemBody(3_000, { searchHash: 'd'.repeat(64) }),
        ],
        updates: [],
      },
    });

    expect(res.status).toBe(409);
    // Standalone and ordered: the first insert landed, the second was refused and
    // the third never sent. The raced row is the create's, counted by the create.
    const rows = await VaultItem.find({ userId: user.id }).lean();
    expect(rows.map((row) => row.encryptedData.length).sort((a, b) => a - b)).toEqual([
      1_000, 7_000,
    ]);
    expect(rows.some((row) => String(row._id) === raced)).toBe(true);
    await expectCounterExact(user);
  });
});
