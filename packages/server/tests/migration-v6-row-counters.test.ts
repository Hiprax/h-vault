/**
 * Migration v6 (`vault-row-counters`, F-15): installs the row counters behind the
 * per-user caps on accounts that predate them, in batches.
 *
 * The accounts here already carry a `vaultBytes` counter, as every account an
 * earlier release touched does, so migration v3 (which installs all three
 * counters on an account WITHOUT `vaultBytes`) leaves them alone and what is
 * measured is v6's own work. The ground truth is the database's own count.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import mongoose from 'mongoose';
import { runMigrations } from '../src/utils/migrations.js';
import { Migration } from '../src/models/Migration.js';
import { JobLock } from '../src/models/JobLock.js';
import { createModuleLogger } from '../src/utils/logger.js';

const users = (): mongoose.mongo.Collection => mongoose.connection.collection('users');

/** Stores `count` bare accounts that have a byte counter and no row counters. */
async function seedAccounts(
  count: number,
  extra: Record<string, unknown> = {},
): Promise<mongoose.Types.ObjectId[]> {
  const ids = Array.from({ length: count }, () => new mongoose.Types.ObjectId());
  await users().insertMany(
    ids.map((_id, index) => ({
      _id,
      email: `v6-${String(index)}-${String(_id)}@example.com`,
      vaultBytes: 0,
      ...extra,
    })),
  );
  return ids;
}

async function seedRows(
  collection: string,
  owner: mongoose.Types.ObjectId,
  count: number,
): Promise<void> {
  if (count === 0) return;
  await mongoose.connection
    .collection(collection)
    .insertMany(Array.from({ length: count }, () => ({ userId: owner, encryptedName: 'n' })));
}

async function countersOf(
  id: mongoose.Types.ObjectId,
): Promise<{ items?: unknown; folders?: unknown } | undefined> {
  const row = await users().findOne({ _id: id }, { projection: { counters: 1 } });
  return (row as { counters?: { items?: unknown; folders?: unknown } } | null)?.counters;
}

describe('migration v6 (vault-row-counters)', () => {
  beforeEach(async () => {
    await JobLock.ensureIndexes();
    await Migration.ensureIndexes();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('installs both counters from the stored rows, in batches, and is recorded', async () => {
    // More accounts than one round, so the walk has to page.
    const ids = await seedAccounts(520);
    await seedRows('vault_items', ids[0]!, 3);
    await seedRows('folders', ids[0]!, 2);
    await seedRows('vault_items', ids[519]!, 1);
    const bulkWrite = vi.spyOn(mongoose.mongo.Collection.prototype, 'bulkWrite');

    await runMigrations();

    expect((await Migration.findOne({ version: 6 }).lean())?.name).toBe('vault-row-counters');
    expect(await countersOf(ids[0]!)).toEqual({ items: 3, folders: 2 });
    expect(await countersOf(ids[519]!)).toEqual({ items: 1, folders: 0 });
    expect(await countersOf(ids[250]!)).toEqual({ items: 0, folders: 0 });
    expect(
      await users().countDocuments({
        _id: { $in: ids },
        'counters.items': { $type: 'number' },
        'counters.folders': { $type: 'number' },
      }),
    ).toBe(520);
    // Batched: at least two rounds over `users`, none naming more than one
    // round's accounts (two writes each).
    const userWrites = bulkWrite.mock.contexts
      .map((context, index) => ({ context, args: bulkWrite.mock.calls[index] }))
      .filter(({ context }) => (context as mongoose.mongo.Collection).collectionName === 'users');
    expect(userWrites.length).toBeGreaterThanOrEqual(2);
    for (const { args } of userWrites) {
      expect((args?.[0] as unknown[]).length).toBeLessThanOrEqual(1_000);
    }
  });

  it('stops at its time budget after the round that crossed it, leaving the rest to their first write', async () => {
    const ids = await seedAccounts(520);
    vi.useFakeTimers({ toFake: ['Date'] });
    // The first grouped count of v6's first round moves the clock past the
    // 30-second budget, so the round finishes and the loop stops before the next.
    const realAggregate = mongoose.mongo.Collection.prototype.aggregate;
    let advanced = false;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'aggregate').mockImplementation(function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof realAggregate>
    ) {
      const pipeline = JSON.stringify(args[0]);
      if (!advanced && this.collectionName === 'vault_items' && pipeline.includes('"$userId"')) {
        advanced = true;
        vi.setSystemTime(Date.now() + 31_000);
      }
      return realAggregate.apply(this, args);
    } as never);
    const info = vi.spyOn(createModuleLogger('migrations'), 'info');

    await runMigrations();

    expect(advanced).toBe(true);
    expect((await Migration.findOne({ version: 6 }).lean())?.name).toBe('vault-row-counters');
    const installed = await users().countDocuments({
      _id: { $in: ids },
      'counters.items': { $type: 'number' },
    });
    // One round (500, the lowest ids), never the 20 past it.
    expect(installed).toBe(500);
    expect(await countersOf(ids[519]!)).toBeUndefined();
    expect(info).toHaveBeenCalledWith(
      expect.stringContaining('until the time budget'),
      expect.objectContaining({ installed: 1_000 }),
    );
  });

  it('stops, logged, when a round fails, and still lets the server boot (the migration is recorded)', async () => {
    const [owner] = await seedAccounts(1);
    const realBulkWrite = mongoose.mongo.Collection.prototype.bulkWrite;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'bulkWrite').mockImplementation(function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof realBulkWrite>
    ) {
      if (this.collectionName === 'users') {
        return Promise.reject(new Error('the database refused the write'));
      }
      return realBulkWrite.apply(this, args);
    } as never);
    const warn = vi.spyOn(createModuleLogger('migrations'), 'warn');

    await expect(runMigrations()).resolves.toBeUndefined();

    expect(await Migration.countDocuments({ version: 6 })).toBe(1);
    expect(await countersOf(owner!)).toBeUndefined();
    expect(warn).toHaveBeenCalledWith('Migration v6: a round failed', {
      error: 'the database refused the write',
    });
  });

  it('never overwrites a counter that is already installed, and fills only the missing one', async () => {
    const [owner] = await seedAccounts(1, { counters: { items: 42 } });
    await seedRows('vault_items', owner!, 5);
    await seedRows('folders', owner!, 4);

    await runMigrations();

    // `items` was installed (42, whatever the rows say: the recount owns drift);
    // `folders` was missing and is now the stored count.
    expect(await countersOf(owner!)).toEqual({ items: 42, folders: 4 });
  });

  it('skips an account being erased', async () => {
    const [owner] = await seedAccounts(1, { deletionPending: true });
    await seedRows('vault_items', owner!, 2);

    await runMigrations();

    expect(await countersOf(owner!)).toBeUndefined();
  });

  it('is idempotent: a second run changes nothing and does not fail', async () => {
    const [owner] = await seedAccounts(1);
    await seedRows('vault_items', owner!, 2);
    await runMigrations();
    await users().updateOne({ _id: owner! }, { $set: { 'counters.items': 9 } });
    // Forget the record, as a crash between the work and the record would.
    await Migration.deleteOne({ version: 6 });

    await expect(runMigrations()).resolves.toBeUndefined();

    expect(await Migration.countDocuments({ version: 6 })).toBe(1);
    expect(await countersOf(owner!)).toEqual({ items: 9, folders: 0 });
  });
});
