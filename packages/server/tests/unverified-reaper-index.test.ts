/**
 * The reaper of never-verified accounts (F-21) pages through them without
 * re-reading the whole population on every page.
 *
 * Its page query asks for unverified accounts past a cursor, in `_id` order. Over
 * the single-field `{emailVerified: 1}` index every page fetched EVERY unverified
 * account, old and young, and sorted them in memory to find the next 500: the
 * cost of one page grew with the population, so under the flood the reaper exists
 * for, a page passed its time limit and every run reaped nothing. Over a partial
 * `{emailVerified: 1, _id: 1}` index holding only unverified accounts, a page is a
 * range scan that starts at the cursor: no sort stage, and a run reads each
 * unverified account at most once (the young ones it passes included, since the age
 * test is `createdAt`; that is the cost left on a run's last page).
 *
 * Migration v7 builds that index on a deployment that predates it (production
 * runs with `autoIndex` off) and drops the single-field one it replaces, found by
 * its key rather than by its name.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import mongoose from 'mongoose';
import { reapUnverifiedAccounts } from '../src/utils/unverifiedAccounts.js';
import { runMigrations } from '../src/utils/migrations.js';
import { Migration } from '../src/models/Migration.js';
import { JobLock } from '../src/models/JobLock.js';
import { User } from '../src/models/User.js';
import { config } from '../src/config/index.js';

const DAY_MS = 24 * 60 * 60 * 1000;
const users = (): mongoose.mongo.Collection => mongoose.connection.collection('users');

interface ProfileEntry {
  op?: string;
  command?: { find?: string; collection?: string; filter?: Record<string, unknown> };
  hasSortStage?: boolean;
  planSummary?: string;
  keysExamined?: number;
}

/** Every `find` and `getMore` on `users` while `run` executes (mongod profiler). */
async function profiledUserFinds(run: () => Promise<void>): Promise<ProfileEntry[]> {
  const db = mongoose.connection.db!;
  await db.command({ profile: 0 });
  await db
    .collection('system.profile')
    .drop()
    .catch(() => undefined);
  // Large enough to keep every page: the default capped size drops the earliest
  // entries once the reaper's per-account reads have filled it.
  await db.createCollection('system.profile', { capped: true, size: 64 * 1024 * 1024 });
  await db.command({ profile: 2 });
  try {
    await run();
  } finally {
    await db.command({ profile: 0 });
  }
  const entries = (await db
    .collection('system.profile')
    .find({ $or: [{ 'command.find': 'users' }, { 'command.collection': 'users' }] })
    .toArray()) as ProfileEntry[];
  await db
    .collection('system.profile')
    .drop()
    .catch(() => undefined);
  return entries;
}

/**
 * `count` raw unverified accounts created `ageDays` ago. Each owns a vault item
 * when `owning`, so the reaper reads it and passes it over without erasing it,
 * which keeps a many-page run cheap.
 */
async function seedUnverified(count: number, ageDays: number, owning: boolean): Promise<void> {
  const createdAt = new Date(Date.now() - ageDays * DAY_MS);
  const ids = Array.from({ length: count }, () => new mongoose.Types.ObjectId());
  await users().insertMany(
    ids.map((_id) => ({
      _id,
      email: `reaper-index-${String(_id)}@example.com`,
      emailVerified: false,
      createdAt,
      updatedAt: createdAt,
    })),
  );
  if (owning) {
    await mongoose.connection
      .collection('vault_items')
      .insertMany(ids.map((userId) => ({ userId, encryptedName: 'n' })));
  }
}

/** The key of every index on `users`, with its partial filter. */
async function userIndexes(): Promise<{ key: Record<string, unknown>; partial?: unknown }[]> {
  const listed = await users().indexes();
  return listed.map((index) => ({
    key: index.key as Record<string, unknown>,
    ...(index.partialFilterExpression === undefined
      ? {}
      : { partial: index.partialFilterExpression }),
  }));
}

/**
 * Every test starts from exactly the indexes the model declares on `emailVerified`,
 * whatever an earlier test built or left behind (the per-test clean-up removes
 * documents, not indexes, and the suite runs in shuffled order).
 */
beforeEach(async () => {
  const listed = await users()
    .indexes()
    .catch(() => []);
  for (const index of listed) {
    if (index.name !== undefined && 'emailVerified' in (index.key as Record<string, unknown>)) {
      await users().dropIndex(index.name);
    }
  }
  await User.createIndexes();
});

describe('F-21: the reaper pages from a partial {emailVerified, _id} index', () => {
  it('reads each page as one range scan from its cursor: no sort stage, each candidate read once', async () => {
    // Three pages of old candidates (each passed over: it owns data), behind
    // enough young unverified accounts that a page which re-read the population
    // would read them again and again.
    const oldOwners = 1_100;
    await seedUnverified(oldOwners, config.UNVERIFIED_ACCOUNT_TTL_DAYS + 3, true);
    await seedUnverified(300, 1, false);

    let reaped = -1;
    const entries = await profiledUserFinds(async () => {
      reaped = await reapUnverifiedAccounts();
    });

    expect(reaped).toBe(0);
    const pages = entries.filter((entry) => entry.command?.filter?.['emailVerified'] === false);
    expect(pages.length).toBe(3);
    for (const page of pages) {
      expect(page.hasSortStage ?? false).toBe(false);
      expect(page.planSummary).toContain('IXSCAN { emailVerified: 1, _id: 1 }');
    }
    // Each page is one reply (no getMore), and every page starts at the cursor:
    // together they examine each unverified account about once (the young ones on
    // the last page), never once per page.
    expect(entries.filter((entry) => entry.op === 'getmore')).toEqual([]);
    const examined = pages.reduce((sum, page) => sum + (page.keysExamined ?? 0), 0);
    expect(examined).toBeLessThanOrEqual(oldOwners + 300 + pages.length);
    // Negative: nothing that owns data was erased.
    expect(await users().countDocuments({ emailVerified: false })).toBe(oldOwners + 300);
  });

  it('declares the partial compound index and no longer the single-field one', async () => {
    const indexes = await userIndexes();
    expect(indexes).toContainEqual({
      key: { emailVerified: 1, _id: 1 },
      partial: { emailVerified: false },
    });
    expect(indexes.some((index) => JSON.stringify(index.key) === '{"emailVerified":1}')).toBe(
      false,
    );
  });
});

describe('migration v7 (unverified-reaper-index)', () => {
  beforeEach(async () => {
    await JobLock.ensureIndexes();
    await Migration.ensureIndexes();
  });

  it('builds the partial index, drops the single-field one by its key, and is recorded', async () => {
    // A deployment from before this release: the old index (under a name other
    // than the default, so only its KEY can find it) and not the new one.
    for (const index of await users().indexes()) {
      const key = JSON.stringify(index.key);
      if (key === '{"emailVerified":1,"_id":1}' || key === '{"emailVerified":1}') {
        await users().dropIndex(index.name!);
      }
    }
    await users().createIndex({ emailVerified: 1 }, { name: 'legacy-email-verified' });

    await runMigrations();

    expect((await Migration.findOne({ version: 7 }).lean())?.name).toBe('unverified-reaper-index');
    const indexes = await userIndexes();
    expect(indexes).toContainEqual({
      key: { emailVerified: 1, _id: 1 },
      partial: { emailVerified: false },
    });
    expect(indexes.some((index) => JSON.stringify(index.key) === '{"emailVerified":1}')).toBe(
      false,
    );
    // Negative: every other index on the collection is left alone.
    expect(indexes.some((index) => JSON.stringify(index.key) === '{"email":1}')).toBe(true);
    // And the index is exactly the one the model declares: `create-indexes`, which
    // fails on an index of the same keys built differently, has nothing to add.
    await expect(User.createIndexes()).resolves.toBeUndefined();
    expect(indexes.some((index) => JSON.stringify(index.key) === '{"lockoutUntil":1}')).toBe(true);
  });

  it('is a no-op on a database that already has the new index and never had the old one', async () => {
    const before = await userIndexes();

    await runMigrations();

    expect((await Migration.findOne({ version: 7 }).lean())?.name).toBe('unverified-reaper-index');
    expect(await userIndexes()).toEqual(before);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  /** Drops whichever indexes on `users` carry exactly `key`. */
  async function dropByKey(key: Record<string, unknown>): Promise<void> {
    for (const index of await users().indexes()) {
      if (JSON.stringify(index.key) === JSON.stringify(key)) await users().dropIndex(index.name!);
    }
  }

  it('tolerates the same index built under another name, and is recorded', async () => {
    await dropByKey({ emailVerified: 1, _id: 1 });
    await users().createIndex(
      { emailVerified: 1, _id: 1 },
      { name: 'operator-built-reaper-index', partialFilterExpression: { emailVerified: false } },
    );

    await runMigrations();

    expect((await Migration.findOne({ version: 7 }).lean())?.name).toBe('unverified-reaper-index');
    const names = (await users().indexes()).map((index) => index.name);
    expect(names).toContain('operator-built-reaper-index');
  });

  it('fails, unrecorded, when the index cannot be built for any other reason', async () => {
    const build = mongoose.mongo.Collection.prototype.createIndex;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'createIndex').mockImplementation(function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof build>
    ) {
      if (JSON.stringify(args[0]) === '{"emailVerified":1,"_id":1}') {
        return Promise.reject(Object.assign(new Error('not primary'), { code: 10107 }));
      }
      return build.apply(this, args);
    });

    await expect(runMigrations()).rejects.toThrow('not primary');

    expect(await Migration.findOne({ version: 7 }).lean()).toBeNull();
    // The run before it is untouched: v6 is recorded.
    expect(await Migration.findOne({ version: 6 }).lean()).not.toBeNull();
  });

  it('treats an old index another process dropped meanwhile as gone', async () => {
    await dropByKey({ emailVerified: 1 });
    await users().createIndex({ emailVerified: 1 }, { name: 'legacy-email-verified' });
    const drop = mongoose.mongo.Collection.prototype.dropIndex;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'dropIndex').mockImplementation(function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof drop>
    ) {
      if (args[0] === 'legacy-email-verified') {
        return Promise.reject(Object.assign(new Error('index not found'), { code: 27 }));
      }
      return drop.apply(this, args);
    });

    await runMigrations();

    expect((await Migration.findOne({ version: 7 }).lean())?.name).toBe('unverified-reaper-index');
  });

  it('fails, unrecorded, when dropping the old index fails for any other reason', async () => {
    await dropByKey({ emailVerified: 1 });
    await users().createIndex({ emailVerified: 1 }, { name: 'legacy-email-verified' });
    const drop = mongoose.mongo.Collection.prototype.dropIndex;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'dropIndex').mockImplementation(function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof drop>
    ) {
      if (args[0] === 'legacy-email-verified') {
        return Promise.reject(Object.assign(new Error('interrupted'), { code: 11601 }));
      }
      return drop.apply(this, args);
    });

    await expect(runMigrations()).rejects.toThrow('interrupted');

    expect(await Migration.findOne({ version: 7 }).lean()).toBeNull();
  });

  it('drops only an index on exactly {emailVerified: 1}, and skips one it cannot name', async () => {
    const list = mongoose.mongo.Collection.prototype.indexes;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'indexes').mockImplementation(async function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof list>
    ) {
      const real = await list.apply(this, args);
      if (this.collectionName !== 'users') return real;
      return [
        ...real,
        { key: { emailVerified: 1 } },
        { name: 'descending', key: { emailVerified: -1 } },
        { name: 'compound', key: { emailVerified: 1, createdAt: 1 } },
      ] as typeof real;
    });
    const dropIndex = vi.spyOn(mongoose.mongo.Collection.prototype, 'dropIndex');

    await runMigrations();

    expect((await Migration.findOne({ version: 7 }).lean())?.name).toBe('unverified-reaper-index');
    const dropped = dropIndex.mock.calls.map((call) => call[0]);
    expect(dropped).not.toContain('descending');
    expect(dropped).not.toContain('compound');
    expect(dropped).not.toContain(undefined);
  });
});
