/**
 * F-15: the per-user row caps (`MAX_ITEMS_PER_USER`, `MAX_FOLDERS_PER_USER`) are
 * ONE conditional write on the account, shared by every writer.
 *
 * The caps used to be a read followed by a write (`countDocuments` → `create`),
 * so N requests that each read a count one below the cap all passed it and all
 * inserted. The account row now carries denormalised counters
 * (`counters.items`, `counters.folders`, trashed rows included, since the caps
 * count them) that `reserveVaultWrite` moves in the same conditional update as
 * the byte quota, before any row is written. These cases pin:
 *
 * - the race itself, between requests of one endpoint and across endpoints (an
 *   item create against an import), each forced deterministically: every
 *   competitor is held at the database insert until all of them have either
 *   reached it or been answered, so a check-then-insert lets every one through
 *   and an atomic reservation lets exactly one;
 * - that the counters equal the database's own count after every path that
 *   creates or removes a row, soft deletes and restores included (which must
 *   NOT move them, because the caps count trashed rows);
 * - an account that has no counters yet: the first write installs them from the
 *   rows and is never refused for their absence;
 * - the hourly recount correcting a counter that drifted.
 *
 * The ground truth is always `countDocuments` on the collections themselves,
 * never the implementation's arithmetic.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

vi.mock('node-cron', () => ({
  default: { schedule: vi.fn().mockReturnValue({ stop: vi.fn() }) },
}));

import mongoose from 'mongoose';
import request from 'supertest';
import cron from 'node-cron';
import { MAX_FOLDERS_PER_USER, MAX_ITEMS_PER_USER } from '@hvault/shared';
import app from '../src/app.js';
import { startTrashCleanupJob } from '../src/jobs/trashCleanup.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { User } from '../src/models/User.js';
import {
  addVaultCounts,
  recountVaultQuotas,
  QUOTA_RECOUNT_QUIESCENCE_MS,
  reserveVaultWrite,
  rowLimitMessage,
  settleVaultWrite,
  VaultQuotaExceededError,
  VaultRowLimitError,
} from '../src/utils/vaultQuota.js';
import {
  authHeader,
  createTestUser,
  getCsrf,
  sampleFolder,
  sampleVaultItem,
  type TestUser,
} from './helpers.js';
import { apiCall } from './support/vaultQuotaApi.js';

const API = '/api/v1';

afterEach(() => {
  vi.restoreAllMocks();
});

/** The account's two row counters as stored (`undefined` when absent). */
async function rowCounters(
  userId: string,
): Promise<{ items: number | undefined; folders: number | undefined }> {
  const row = await mongoose.connection
    .collection('users')
    .findOne({ _id: new mongoose.Types.ObjectId(userId) }, { projection: { counters: 1 } });
  const counters = (row as { counters?: { items?: unknown; folders?: unknown } } | null)?.counters;
  return {
    items: typeof counters?.items === 'number' ? counters.items : undefined,
    folders: typeof counters?.folders === 'number' ? counters.folders : undefined,
  };
}

/** The rows the account owns, counted by the database (trash included, as the caps count). */
async function storedRows(userId: string): Promise<{ items: number; folders: number }> {
  return {
    items: await VaultItem.countDocuments({ userId }),
    folders: await Folder.countDocuments({ userId }),
  };
}

/** Asserts both counters equal what the database stores, and returns the counts. */
async function expectCountersExact(
  user: TestUser,
  step: string,
): Promise<{ items: number; folders: number }> {
  const stored = await storedRows(user.id);
  expect(await rowCounters(user.id), step).toEqual(stored);
  return stored;
}

/**
 * Stores `count` item rows for `userId` straight into the collection, as rows an
 * account accumulated over time. Lean on purpose: only their number matters.
 */
async function seedItemRows(userId: string, count: number): Promise<void> {
  const owner = new mongoose.Types.ObjectId(userId);
  const rows = Array.from({ length: count }, () => ({
    userId: owner,
    ...sampleVaultItem({ encryptedData: 'seed' }),
    createdAt: new Date(),
    updatedAt: new Date(),
    __v: 0,
  }));
  await VaultItem.collection.insertMany(rows, { ordered: false });
}

/**
 * Holds every native insert into `vault_items` (`insertOne` and `insertMany`)
 * until `open()` is called, counting the arrivals.
 */
function holdItemInserts(): { arrived: () => number; open: () => void } {
  let arrived = 0;
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  for (const method of ['insertOne', 'insertMany'] as const) {
    const real = mongoose.mongo.Collection.prototype[method] as (
      ...args: unknown[]
    ) => Promise<unknown>;
    vi.spyOn(mongoose.mongo.Collection.prototype, method).mockImplementation(async function (
      this: mongoose.mongo.Collection,
      ...args: unknown[]
    ) {
      if (this.collectionName === 'vault_items') {
        arrived += 1;
        await gate;
      }
      return real.apply(this, args);
    } as never);
  }
  return { arrived: () => arrived, open: () => release() };
}

/**
 * Fires every request at once and holds the inserts until each competitor has
 * either reached its insert or been answered: the interleaving in which a
 * check-then-insert admits them all.
 */
async function race(sends: (() => Promise<request.Response>)[]): Promise<request.Response[]> {
  const inserts = holdItemInserts();
  let answered = 0;
  const check = (): void => {
    if (inserts.arrived() + answered >= sends.length) inserts.open();
  };
  const watcher = setInterval(check, 5);
  try {
    return await Promise.all(
      sends.map((send) =>
        send().finally(() => {
          answered += 1;
          check();
        }),
      ),
    );
  } finally {
    clearInterval(watcher);
    inserts.open();
  }
}

/** A create request whose CSRF handshake is already done, so many can start together. */
async function prepared(
  user: TestUser,
  path: string,
  body: Record<string, unknown>,
): Promise<() => Promise<request.Response>> {
  const agent = request.agent(app);
  const csrf = await getCsrf(agent);
  return () =>
    Promise.resolve(
      agent
        .post(`${API}${path}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf.token)
        .set('Cookie', csrf.cookie)
        .send(body),
    );
}

describe('F-15: the item cap is one atomic reservation', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  it('admits exactly one of 50 concurrent creates at MAX-1, and refuses the rest with the cap message', async () => {
    await seedItemRows(user.id, MAX_ITEMS_PER_USER - 1);
    const sends = await Promise.all(
      Array.from({ length: 50 }, (_, i) =>
        prepared(user, '/vault/items', sampleVaultItem({ encryptedName: `racer-${String(i)}` })),
      ),
    );

    const responses = await race(sends);

    const created = responses.filter((res) => res.status === 201);
    const refused = responses.filter((res) => res.status === 400);
    expect(created).toHaveLength(1);
    expect(refused).toHaveLength(49);
    for (const res of refused) {
      expect(res.body.message).toBe(
        `Item limit reached. You can have a maximum of ${String(MAX_ITEMS_PER_USER)} items.`,
      );
    }
    // Not one row past the cap, and the counter agrees with the rows.
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(MAX_ITEMS_PER_USER);
    expect((await rowCounters(user.id)).items).toBe(MAX_ITEMS_PER_USER);
  });

  it('admits exactly one row when an item create races an import at MAX-1', async () => {
    await seedItemRows(user.id, MAX_ITEMS_PER_USER - 1);
    const create = await prepared(
      user,
      '/vault/items',
      sampleVaultItem({ encryptedName: 'from-create' }),
    );
    const importOne = await prepared(user, '/tools/import', {
      format: 'json',
      operations: { inserts: [sampleVaultItem({ encryptedName: 'from-import' })], updates: [] },
    });

    const [createRes, importRes] = await race([create, importOne]);

    // One writer wins (each answers 201), the other is refused with its own cap
    // message; never both.
    expect([createRes!.status, importRes!.status].sort()).toEqual([201, 400]);
    if (createRes!.status === 400) {
      expect(createRes!.body.message).toMatch(/Item limit reached/);
      expect(importRes!.body.data.insertedCount).toBe(1);
    } else {
      expect(importRes!.body.message).toMatch(/per-user item limit/i);
    }
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(MAX_ITEMS_PER_USER);
    expect((await rowCounters(user.id)).items).toBe(MAX_ITEMS_PER_USER);
  });

  it('leaves sequential creates below the cap unaffected', async () => {
    for (const name of ['a', 'b', 'c']) {
      const res = await apiCall(
        user,
        'post',
        '/vault/items',
        sampleVaultItem({ encryptedName: name }),
      );
      expect(res.status).toBe(201);
    }
    expect(await expectCountersExact(user, 'after three creates')).toEqual({
      items: 3,
      folders: 0,
    });
  });
});

describe('F-15: the folder cap is one atomic reservation', () => {
  it('admits exactly one of 20 concurrent folder creates at MAX-1', async () => {
    const user = await createTestUser();
    await Folder.insertMany(
      Array.from({ length: MAX_FOLDERS_PER_USER - 1 }, (_, i) => ({
        userId: user.id,
        ...sampleFolder({ encryptedName: `seed-${String(i)}` }),
      })),
    );
    const sends = await Promise.all(
      Array.from({ length: 20 }, (_, i) =>
        prepared(user, '/folders', sampleFolder({ encryptedName: `racer-${String(i)}` })),
      ),
    );

    // Folder creates insert through `insertOne` on `folders`, which the item
    // gate does not hold, so these overlap only as the event loop interleaves
    // them; the cap must hold however they do.
    const responses = await Promise.all(sends.map((send) => send()));

    expect(responses.filter((res) => res.status === 201)).toHaveLength(1);
    const refused = responses.filter((res) => res.status === 400);
    expect(refused).toHaveLength(19);
    for (const res of refused) {
      expect(res.body.message).toBe(
        `Folder limit reached. You can have a maximum of ${String(MAX_FOLDERS_PER_USER)} folders.`,
      );
    }
    expect(await Folder.countDocuments({ userId: user.id })).toBe(MAX_FOLDERS_PER_USER);
    expect((await rowCounters(user.id)).folders).toBe(MAX_FOLDERS_PER_USER);
  });
});

/** The nightly trash purge's tick, taken from the cron registration it makes. */
function purgeTick(): () => Promise<void> {
  const schedule = vi.mocked(cron.schedule);
  schedule.mockClear();
  startTrashCleanupJob();
  return schedule.mock.calls[0]![1] as () => Promise<void>;
}

describe('F-15: the counters equal the stored rows after every path', () => {
  it('holds through create, trash, restore, purge, empty-trash, import, backup restore, folder delete and the nightly purge', async () => {
    const user = await createTestUser();
    const itemIds: string[] = [];
    for (const name of ['one', 'two', 'three', 'four', 'five']) {
      const res = await apiCall(
        user,
        'post',
        '/vault/items',
        sampleVaultItem({ encryptedName: name }),
      );
      expect(res.status).toBe(201);
      itemIds.push(String(res.body.data._id));
    }
    expect(await expectCountersExact(user, 'create')).toEqual({ items: 5, folders: 0 });

    const folderIds: string[] = [];
    for (const name of ['f1', 'f2', 'f3']) {
      const res = await apiCall(user, 'post', '/folders', sampleFolder({ encryptedName: name }));
      expect(res.status).toBe(201);
      folderIds.push(String(res.body.data._id));
    }
    expect(await expectCountersExact(user, 'folder create')).toEqual({ items: 5, folders: 3 });

    // Trash and restore are NOT counter sites: the caps count trashed rows.
    expect((await apiCall(user, 'delete', `/vault/items/${itemIds[0]!}`)).status).toBe(200);
    expect(await expectCountersExact(user, 'trash')).toEqual({ items: 5, folders: 3 });
    expect((await apiCall(user, 'post', `/vault/items/restore/${itemIds[0]!}`)).status).toBe(200);
    expect(await expectCountersExact(user, 'restore')).toEqual({ items: 5, folders: 3 });
    expect(
      (await apiCall(user, 'post', '/vault/items/bulk-delete', { ids: itemIds.slice(0, 3) }))
        .status,
    ).toBe(200);
    expect(await expectCountersExact(user, 'bulk trash')).toEqual({ items: 5, folders: 3 });

    // Hard deletes are: one permanent delete, then the rest of the trash.
    expect((await apiCall(user, 'delete', `/vault/items/${itemIds[0]!}/permanent`)).status).toBe(
      200,
    );
    expect(await expectCountersExact(user, 'permanent delete')).toEqual({ items: 4, folders: 3 });
    expect((await apiCall(user, 'delete', '/vault/items/trash/empty')).status).toBe(200);
    expect(await expectCountersExact(user, 'empty trash')).toEqual({ items: 2, folders: 3 });

    const imported = await apiCall(user, 'post', '/tools/import', {
      format: 'json',
      operations: {
        inserts: [
          sampleVaultItem({ encryptedName: 'imp-1' }),
          sampleVaultItem({ encryptedName: 'imp-2' }),
        ],
        updates: [],
      },
    });
    expect(imported.status).toBe(201);
    expect(await expectCountersExact(user, 'import')).toEqual({ items: 4, folders: 3 });

    const restored = await apiCall(user, 'post', '/backup/restore', {
      conflictStrategy: 'keep_both',
      data: JSON.stringify({
        items: [sampleVaultItem({ encryptedName: 'from-backup' })],
        folders: [sampleFolder({ encryptedName: 'folder-from-backup' })],
      }),
    });
    expect(restored.status).toBe(200);
    expect(await expectCountersExact(user, 'backup restore')).toEqual({ items: 5, folders: 4 });

    // A folder delete removes the folder row either way; its items are trashed
    // (`delete`) or moved (`move`), neither of which removes an item row.
    const filed = await apiCall(
      user,
      'post',
      '/vault/items',
      sampleVaultItem({ encryptedName: 'filed', folderId: folderIds[0]! }),
    );
    expect(filed.status).toBe(201);
    expect((await apiCall(user, 'delete', `/folders/${folderIds[0]!}?action=delete`)).status).toBe(
      200,
    );
    expect(await expectCountersExact(user, 'folder delete (delete)')).toEqual({
      items: 6,
      folders: 3,
    });
    expect((await apiCall(user, 'delete', `/folders/${folderIds[1]!}?action=move`)).status).toBe(
      200,
    );
    expect(await expectCountersExact(user, 'folder delete (move)')).toEqual({
      items: 6,
      folders: 2,
    });

    // The nightly purge removes the trash older than the retention window.
    await VaultItem.updateMany(
      { userId: user.id, deletedAt: { $ne: null } },
      { $set: { deletedAt: new Date(Date.now() - 400 * 24 * 60 * 60 * 1000) } },
    );
    await purgeTick()();
    expect(await expectCountersExact(user, 'nightly purge')).toEqual({ items: 5, folders: 2 });
  });
});

describe('F-15: an account with no counters yet', () => {
  it('installs both counters from the rows on its first folder create, and is not refused', async () => {
    const user = await createTestUser();
    await seedItemRows(user.id, 2);
    await Folder.insertMany(
      ['x', 'y', 'z'].map((name) => ({
        userId: user.id,
        ...sampleFolder({ encryptedName: name }),
      })),
    );
    expect(await rowCounters(user.id)).toEqual({ items: undefined, folders: undefined });

    const res = await apiCall(user, 'post', '/folders', sampleFolder({ encryptedName: 'new' }));

    expect(res.status).toBe(201);
    expect(await expectCountersExact(user, 'install')).toEqual({ items: 2, folders: 4 });
  });

  it('installs the counters on a delete too, so the removal is counted once', async () => {
    const user = await createTestUser();
    await seedItemRows(user.id, 3);
    const victim = await VaultItem.findOne({ userId: user.id }).lean();
    await VaultItem.updateOne({ _id: victim!._id }, { $set: { deletedAt: new Date() } });

    const res = await apiCall(user, 'delete', `/vault/items/${String(victim!._id)}/permanent`);

    expect(res.status).toBe(200);
    expect(await expectCountersExact(user, 'install on delete')).toEqual({ items: 2, folders: 0 });
  });
});

describe('F-15: the hourly recount covers the row counters', () => {
  it('corrects a planted drift in both counters on a quiet account', async () => {
    const user = await createTestUser();
    expect((await apiCall(user, 'post', '/vault/items', sampleVaultItem())).status).toBe(201);
    expect((await apiCall(user, 'post', '/folders', sampleFolder())).status).toBe(201);
    await mongoose.connection.collection('users').updateOne(
      { _id: new mongoose.Types.ObjectId(user.id) },
      {
        $set: {
          'counters.items': 77,
          'counters.folders': 9,
          vaultBytesWrittenAt: new Date(Date.now() - 2 * QUOTA_RECOUNT_QUIESCENCE_MS),
        },
      },
    );

    const summary = await recountVaultQuotas();

    expect(summary.failures).toBe(0);
    expect(summary.corrected).toBeGreaterThanOrEqual(1);
    expect(await expectCountersExact(user, 'recount')).toEqual({ items: 1, folders: 1 });
  });

  it('leaves a busy account alone (a write landed within the quiescence window)', async () => {
    const user = await createTestUser();
    expect((await apiCall(user, 'post', '/vault/items', sampleVaultItem())).status).toBe(201);
    await mongoose.connection
      .collection('users')
      .updateOne({ _id: new mongoose.Types.ObjectId(user.id) }, { $set: { 'counters.items': 77 } });

    await recountVaultQuotas();

    expect((await rowCounters(user.id)).items).toBe(77);
  });
});

/** Installs all three counters on `userId` with the given row counts (bytes as stored). */
async function plantCounters(userId: string, items: number, folders: number): Promise<void> {
  await reserveVaultWrite(userId, { bytes: 0 });
  await mongoose.connection
    .collection('users')
    .updateOne(
      { _id: new mongoose.Types.ObjectId(userId) },
      { $set: { 'counters.items': items, 'counters.folders': folders } },
    );
}

describe('F-15: reserveVaultWrite with rows', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  it('refuses rows past the item cap with VaultRowLimitError naming the stored count, and moves nothing', async () => {
    await plantCounters(user.id, MAX_ITEMS_PER_USER - 1, 0);

    const refusal = await reserveVaultWrite(user.id, { bytes: 10, items: 2 }).catch(
      (error: unknown) => error,
    );

    expect(refusal).toBeInstanceOf(VaultRowLimitError);
    expect(refusal).toMatchObject({
      kind: 'item',
      stored: MAX_ITEMS_PER_USER - 1,
      statusCode: 400,
    });
    expect((refusal as Error).message).toBe(rowLimitMessage('item'));
    expect(await rowCounters(user.id)).toEqual({ items: MAX_ITEMS_PER_USER - 1, folders: 0 });
  });

  it('admits the last row exactly at the boundary (MAX-1 plus one)', async () => {
    await plantCounters(user.id, MAX_ITEMS_PER_USER - 1, MAX_FOLDERS_PER_USER - 1);

    await reserveVaultWrite(user.id, { bytes: 0, items: 1 });
    await reserveVaultWrite(user.id, { bytes: 0, folders: 1 });

    expect(await rowCounters(user.id)).toEqual({
      items: MAX_ITEMS_PER_USER,
      folders: MAX_FOLDERS_PER_USER,
    });
    await expect(reserveVaultWrite(user.id, { bytes: 0, folders: 1 })).rejects.toMatchObject({
      kind: 'folder',
      stored: MAX_FOLDERS_PER_USER,
    });
  });

  it('checks the row cap before the byte quota when neither has room', async () => {
    await plantCounters(user.id, MAX_ITEMS_PER_USER, 0);

    await expect(
      reserveVaultWrite(user.id, { bytes: Number.MAX_SAFE_INTEGER, items: 1 }),
    ).rejects.toBeInstanceOf(VaultRowLimitError);
    await expect(
      reserveVaultWrite(user.id, { bytes: Number.MAX_SAFE_INTEGER }),
    ).rejects.toBeInstanceOf(VaultQuotaExceededError);
  });

  it('never refuses a reservation that adds no row, even over the cap', async () => {
    // A drifted (or legacy) account past its cap must still be able to delete.
    await plantCounters(user.id, MAX_ITEMS_PER_USER + 5, MAX_FOLDERS_PER_USER + 5);

    const reservation = await reserveVaultWrite(user.id, { bytes: 0 });

    expect(reservation).toEqual({ userId: user.id, bytes: 0, items: 0, folders: 0 });
  });

  it('refuses a negative, fractional or unsafe row amount before touching the account', async () => {
    for (const bad of [-1, 1.5, Number.NaN, Number.MAX_SAFE_INTEGER + 1]) {
      await expect(reserveVaultWrite(user.id, { bytes: 0, items: bad })).rejects.toThrow(
        RangeError,
      );
      await expect(reserveVaultWrite(user.id, { bytes: 0, folders: bad })).rejects.toThrow(
        RangeError,
      );
    }
    expect(await rowCounters(user.id)).toEqual({ items: undefined, folders: undefined });
  });

  it('settles the rows that landed, handing back the rest of the reservation', async () => {
    await plantCounters(user.id, 10, 3);
    const reservation = await reserveVaultWrite(user.id, { bytes: 0, items: 4, folders: 2 });
    expect(await rowCounters(user.id)).toEqual({ items: 14, folders: 5 });

    await settleVaultWrite(reservation, 0, { items: 1 });

    // One item landed; the three other items and both folders are handed back.
    expect(await rowCounters(user.id)).toEqual({ items: 11, folders: 3 });
  });

  it('refuses a non-finite row delta rather than storing it', async () => {
    await plantCounters(user.id, 1, 1);
    await expect(addVaultCounts(user.id, { items: Number.NaN })).rejects.toThrow(RangeError);
    await expect(addVaultCounts(user.id, { folders: Number.POSITIVE_INFINITY })).rejects.toThrow(
      RangeError,
    );
    expect(await rowCounters(user.id)).toEqual({ items: 1, folders: 1 });
  });

  it('never installs a missing counter as a delta', async () => {
    expect(await addVaultCounts(user.id, { items: -1 })).toBe(false);
    expect(await rowCounters(user.id)).toEqual({ items: undefined, folders: undefined });
  });
});

describe('F-15: refusals each writer gives at the cap', () => {
  it('refuses an import whole with the count it was refused against, writing nothing', async () => {
    const user = await createTestUser();
    await plantCounters(user.id, MAX_ITEMS_PER_USER - 1, 0);

    const res = await apiCall(user, 'post', '/tools/import', {
      format: 'json',
      operations: {
        inserts: [sampleVaultItem({ encryptedName: 'a' }), sampleVaultItem({ encryptedName: 'b' })],
        updates: [],
      },
    });

    expect(res.status).toBe(400);
    expect(res.body.message).toBe(
      `Import would exceed the per-user item limit (${String(MAX_ITEMS_PER_USER)}). You currently have ${String(MAX_ITEMS_PER_USER - 1)} items and this import would add 2.`,
    );
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
    expect((await rowCounters(user.id)).items).toBe(MAX_ITEMS_PER_USER - 1);
  });

  it('skips restore rows a concurrent writer left no room for as storage_limit, and stores none of them', async () => {
    const user = await createTestUser();
    // The rows say there is room, so the restore's whole-request count passes;
    // the counters say another request has just taken the last places.
    await plantCounters(user.id, MAX_ITEMS_PER_USER, MAX_FOLDERS_PER_USER);

    const res = await apiCall(user, 'post', '/backup/restore', {
      conflictStrategy: 'keep_both',
      data: JSON.stringify({
        items: [sampleVaultItem({ encryptedName: 'late' })],
        folders: [sampleFolder({ encryptedName: 'late-folder' })],
      }),
    });

    expect(res.status).toBe(200);
    expect(res.body.data.itemsRestored).toBe(0);
    expect(res.body.data.foldersRestored).toBe(0);
    expect(res.body.data.itemSkipReasons).toEqual([
      expect.objectContaining({ reason: 'storage_limit' }),
    ]);
    expect(res.body.data.folderSkipReasons).toEqual([
      expect.objectContaining({ reason: 'storage_limit' }),
    ]);
    expect(await storedRows(user.id)).toEqual({ items: 0, folders: 0 });
    expect(await rowCounters(user.id)).toEqual({
      items: MAX_ITEMS_PER_USER,
      folders: MAX_FOLDERS_PER_USER,
    });
  });
});

describe('F-15: a failed insert and the row it reserved', () => {
  const NONCE = '66f1c2a000112233445566778899aabbccddeeff';

  it('hands the row back when the insert certainly did not apply (a retried create, 409)', async () => {
    const user = await createTestUser();
    for (const [path, body] of [
      ['/vault/items', sampleVaultItem({ idNonce: NONCE })],
      ['/folders', sampleFolder({ idNonce: NONCE })],
    ] as const) {
      expect((await apiCall(user, 'post', path, body)).status).toBe(201);
      const retry = await apiCall(user, 'post', path, body);
      expect(retry.status).toBe(409);
    }

    // One of each stored, one of each counted: the refused retries took nothing.
    expect(await expectCountersExact(user, 'after two refused retries')).toEqual({
      items: 1,
      folders: 1,
    });
  });

  it('keeps the row when the outcome is unknown (an overcount the recount corrects)', async () => {
    const user = await createTestUser();
    const create = vi
      .spyOn(VaultItem, 'create')
      .mockRejectedValueOnce(new Error('connection reset'));

    const res = await apiCall(user, 'post', '/vault/items', sampleVaultItem());
    create.mockRestore();

    expect(res.status).toBe(500);
    expect(await storedRows(user.id)).toEqual({ items: 0, folders: 0 });
    expect(await rowCounters(user.id)).toEqual({ items: 1, folders: 0 });
  });

  it('refuses rows with the row limit when every attempt misses although there is room', async () => {
    const user = await createTestUser();
    await plantCounters(user.id, 3, 2);
    const real = User.updateOne.bind(User) as (...args: unknown[]) => unknown;
    let attempts = 0;
    vi.spyOn(User, 'updateOne').mockImplementation(((...args: unknown[]) => {
      const update = args[1] as { $inc?: Record<string, unknown> };
      if (update.$inc?.['counters.items'] !== undefined) {
        attempts += 1;
        return Promise.resolve({ acknowledged: true, matchedCount: 0, modifiedCount: 0 });
      }
      return real(...args);
    }) as never);

    await expect(reserveVaultWrite(user.id, { bytes: 0, items: 1 })).rejects.toMatchObject({
      kind: 'item',
      stored: 3,
    });
    await expect(reserveVaultWrite(user.id, { bytes: 0, folders: 1 })).rejects.toMatchObject({
      kind: 'folder',
      stored: 2,
    });
    expect(attempts).toBe(6);
    vi.restoreAllMocks();
    expect(await rowCounters(user.id)).toEqual({ items: 3, folders: 2 });
  });
});
