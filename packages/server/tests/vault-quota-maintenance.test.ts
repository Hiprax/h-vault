/**
 * F-24: what keeps the vault byte counter honest in the background.
 *
 * - The hourly recount (`recountVaultQuotas`, maintenance step
 *   `vault-quota-recount`) corrects a drifted counter on a QUIET account, installs
 *   a missing one, leaves a busy account alone, never writes a total a concurrent
 *   write made stale, and moves an account that fails to the back of the queue.
 * - Migration v3 builds the recount's index and installs counters, passing over
 *   an account whose total fails.
 * - `/metrics` reports a snapshot it never waits for.
 *
 * The ground truth is the database's own total (`support/vaultBytes.ts`).
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import express from 'express';
import request from 'supertest';
import mongoose from 'mongoose';
import { errorMiddleware } from '@hiprax/errors';
import { VaultItem } from '../src/models/VaultItem.js';
import { User } from '../src/models/User.js';
import { JobLock } from '../src/models/JobLock.js';
import { Migration } from '../src/models/Migration.js';
import { getMetrics } from '../src/controllers/metricsController.js';
import { runMaintenance } from '../src/jobs/maintenance.js';
import { runMigrations } from '../src/utils/migrations.js';
import {
  installVaultBytes,
  QUOTA_RECOUNT_QUIESCENCE_MS,
  recountVaultQuotas,
  resetVaultStorageSnapshot,
} from '../src/utils/vaultQuota.js';
import { createTestUser, type TestUser } from './helpers.js';
import { storedVaultBytes, vaultBytesCounter } from './support/vaultBytes.js';
import { createQuotaItem, expectCounterExact, quotaItemBody } from './support/vaultQuotaApi.js';

afterEach(() => {
  vi.restoreAllMocks();
});

const users = () => mongoose.connection.collection('users');
const oid = (id: string) => new mongoose.Types.ObjectId(id);

/** The account's raw quota bookkeeping. */
async function bookkeeping(userId: string): Promise<Record<string, unknown>> {
  const row = await users().findOne(
    { _id: oid(userId) },
    { projection: { vaultBytes: 1, quotaEpoch: 1, quotaRecountedAt: 1, vaultBytesWrittenAt: 1 } },
  );
  return row ?? {};
}

/** Plants a drift of `by` bytes and makes the account quiet (last write long ago). */
async function plantQuietDrift(userId: string, by: number): Promise<void> {
  await users().updateOne(
    { _id: oid(userId) },
    {
      $inc: { vaultBytes: by },
      $set: { vaultBytesWrittenAt: new Date(Date.now() - 2 * QUOTA_RECOUNT_QUIESCENCE_MS) },
    },
  );
}

/** An account with stored rows and NO counter (it predates the quota). */
async function legacyAccount(): Promise<TestUser> {
  const user = await createTestUser();
  await VaultItem.create({ userId: user.id, ...quotaItemBody(2_500) });
  await VaultItem.create({ userId: user.id, ...quotaItemBody(700) });
  expect(await vaultBytesCounter(user.id)).toBeUndefined();
  return user;
}

describe('the recount', () => {
  it('corrects a drifted counter on a quiet account, and says it did', async () => {
    const user = await createTestUser();
    await createQuotaItem(user, 1_500);
    const stored = await expectCounterExact(user);
    await plantQuietDrift(user.id, 4_321);
    const epoch = (await bookkeeping(user.id))['quotaEpoch'] as number;

    const summary = await recountVaultQuotas();

    expect(summary).toEqual({ recounted: 1, corrected: 1, failures: 0 });
    const after = await bookkeeping(user.id);
    expect(after['vaultBytes']).toBe(stored);
    expect(after['quotaEpoch']).toBe(epoch + 1);
    expect(after['quotaRecountedAt']).toBeInstanceOf(Date);
  });

  it('leaves an account that wrote in the last ten minutes alone', async () => {
    const user = await createTestUser();
    await createQuotaItem(user, 1_500);
    const stored = await expectCounterExact(user);
    // Drift, but the account is busy: its last counted write is recent.
    await users().updateOne({ _id: oid(user.id) }, { $inc: { vaultBytes: 99 } });

    const summary = await recountVaultQuotas();

    expect(summary).toEqual({ recounted: 0, corrected: 0, failures: 0 });
    expect(await vaultBytesCounter(user.id)).toBe(stored + 99);
  });

  it('installs a missing counter with the true total', async () => {
    const user = await legacyAccount();

    const summary = await recountVaultQuotas();

    expect(summary).toEqual({ recounted: 1, corrected: 0, failures: 0 });
    expect(await vaultBytesCounter(user.id)).toBe(await storedVaultBytes(user.id));
  });

  it('never recounts an account being erased', async () => {
    const user = await legacyAccount();
    await users().updateOne({ _id: oid(user.id) }, { $set: { deletionPending: true } });

    expect(await recountVaultQuotas()).toEqual({ recounted: 0, corrected: 0, failures: 0 });
    expect(await vaultBytesCounter(user.id)).toBeUndefined();
  });

  it('does not write a total that a write landing while it measured has made stale', async () => {
    const user = await createTestUser();
    await createQuotaItem(user, 1_500);
    await plantQuietDrift(user.id, 1_000);

    // Between the recount's measure and its write, the owner stores another item.
    const real = mongoose.mongo.Collection.prototype.updateOne;
    let landed = false;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'updateOne').mockImplementation(async function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof real>
    ) {
      const update = args[1] as { $set?: { quotaRecountedAt?: unknown } };
      if (this.collectionName === 'users' && update.$set?.quotaRecountedAt && !landed) {
        landed = true;
        await createQuotaItem(user, 3_000);
      }
      return real.apply(this, args);
    } as never);

    const summary = await recountVaultQuotas();

    expect(landed).toBe(true);
    expect(summary).toEqual({ recounted: 0, corrected: 0, failures: 0 });
    // The planted drift is still there (the next quiet run fixes it); what must
    // not happen is the stale total, which would have lost the new item's bytes.
    expect(await vaultBytesCounter(user.id)).toBe((await storedVaultBytes(user.id)) + 1_000);
  });

  it('moves an account it cannot measure to the back of the queue and goes on', async () => {
    const failing = await legacyAccount();
    const healthy = await legacyAccount();

    const real = VaultItem.aggregate.bind(VaultItem) as (...args: unknown[]) => unknown;
    vi.spyOn(VaultItem, 'aggregate').mockImplementation(((...args: unknown[]) => {
      const pipeline = args[0] as { $match?: { userId?: unknown } }[];
      if (String(pipeline[0]?.$match?.userId) === failing.id) {
        throw new Error('simulated aggregate failure');
      }
      return real(...args);
    }) as never);

    const summary = await recountVaultQuotas();

    expect(summary).toEqual({ recounted: 1, corrected: 0, failures: 1 });
    expect(await vaultBytesCounter(failing.id)).toBeUndefined();
    expect((await bookkeeping(failing.id))['quotaRecountedAt']).toBeInstanceOf(Date);
    expect(await vaultBytesCounter(healthy.id)).toBe(await storedVaultBytes(healthy.id));
  });

  it('stops after five accounts in a row fail', async () => {
    for (let i = 0; i < 7; i += 1) await legacyAccount();
    vi.spyOn(VaultItem, 'aggregate').mockImplementation((() => {
      throw new Error('the database refuses');
    }) as never);

    const summary = await recountVaultQuotas();

    expect(summary).toEqual({ recounted: 0, corrected: 0, failures: 5 });
    // Five were moved back; the other two were never reached.
    const touched = await users().countDocuments({ quotaRecountedAt: { $type: 'date' } });
    expect(touched).toBe(5);
  });

  it('goes on when an account can neither be measured nor moved to the back of the queue', async () => {
    const failing = await legacyAccount();
    const healthy = await legacyAccount();
    const realAggregate = VaultItem.aggregate.bind(VaultItem) as (...args: unknown[]) => unknown;
    vi.spyOn(VaultItem, 'aggregate').mockImplementation(((...args: unknown[]) => {
      const pipeline = args[0] as { $match?: { userId?: unknown } }[];
      if (String(pipeline[0]?.$match?.userId) === failing.id) {
        throw new Error('simulated aggregate failure');
      }
      return realAggregate(...args);
    }) as never);
    const realUpdate = User.updateOne.bind(User) as (...args: unknown[]) => unknown;
    vi.spyOn(User, 'updateOne').mockImplementation(((...args: unknown[]) => {
      const update = args[1] as { $set?: Record<string, unknown> };
      const keys = Object.keys(update.$set ?? {});
      if (keys.length === 1 && keys[0] === 'quotaRecountedAt') {
        return Promise.reject(new Error('the bump is refused too'));
      }
      return realUpdate(...args);
    }) as never);

    const summary = await recountVaultQuotas();

    expect(summary).toEqual({ recounted: 1, corrected: 0, failures: 1 });
    expect((await bookkeeping(failing.id))['quotaRecountedAt']).toBeUndefined();
    expect(await vaultBytesCounter(healthy.id)).toBe(await storedVaultBytes(healthy.id));
  });

  it('a zero budget still recounts exactly one account', async () => {
    await legacyAccount();
    await legacyAccount();

    expect(await recountVaultQuotas(0)).toEqual({ recounted: 1, corrected: 0, failures: 0 });
  });

  it('runs as a maintenance step', async () => {
    const user = await createTestUser();
    await createQuotaItem(user, 900);
    await plantQuietDrift(user.id, -400);

    await runMaintenance();

    await expectCounterExact(user);
    expect(await JobLock.countDocuments({ jobName: 'maintenance' })).toBe(0);
  });
});

describe('the time limits on background totals', () => {
  /** `maxTimeMS` of every vault total or snapshot aggregate run while `run` runs. */
  async function aggregateLimits(run: () => Promise<unknown>): Promise<[string, unknown][]> {
    const seen: [string, unknown][] = [];
    const real = mongoose.mongo.Collection.prototype.aggregate;
    const spy = vi
      .spyOn(mongoose.mongo.Collection.prototype, 'aggregate')
      .mockImplementation(function (
        this: mongoose.mongo.Collection,
        ...args: Parameters<typeof real>
      ) {
        if (JSON.stringify(args[0]).includes('$bsonSize') || this.collectionName === 'users') {
          const options = args[1] as { maxTimeMS?: unknown } | undefined;
          seen.push([this.collectionName, options?.maxTimeMS]);
        }
        return real.apply(this, args);
      } as never);
    try {
      await run();
    } finally {
      spy.mockRestore();
    }
    return seen;
  }

  it("the recount caps each of an account's two totals at 5 s", async () => {
    await legacyAccount();
    expect(await aggregateLimits(() => recountVaultQuotas())).toEqual([
      ['vault_items', 5_000],
      ['folders', 5_000],
    ]);
  });

  it('migration v3 caps each at 10 s', async () => {
    await JobLock.ensureIndexes();
    await Migration.ensureIndexes();
    await legacyAccount();
    expect(await aggregateLimits(() => runMigrations())).toEqual([
      ['vault_items', 10_000],
      ['folders', 10_000],
    ]);
  });

  it('the request-path install takes NO time limit (a timed-out install would fail a delete)', async () => {
    const user = await legacyAccount();
    expect(await aggregateLimits(() => installVaultBytes(user.id))).toEqual([
      ['vault_items', undefined],
      ['folders', undefined],
    ]);
  });

  it('the /metrics snapshot reads its total from the primary', async () => {
    resetVaultStorageSnapshot();
    const metricsApp = express();
    metricsApp.get('/metrics', getMetrics);
    metricsApp.use(errorMiddleware);
    const real = mongoose.mongo.Collection.prototype.aggregate;
    const modes: unknown[] = [];
    vi.spyOn(mongoose.mongo.Collection.prototype, 'aggregate').mockImplementation(function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof real>
    ) {
      if (this.collectionName === 'users') {
        const preference = (args[1] as { readPreference?: unknown } | undefined)?.readPreference;
        modes.push(
          typeof preference === 'string'
            ? preference
            : (preference as { mode?: unknown } | undefined)?.mode,
        );
      }
      return real.apply(this, args);
    } as never);
    try {
      await request(metricsApp).get('/metrics');
      await vi.waitFor(async () => {
        const res = await request(metricsApp).get('/metrics');
        expect(res.body.data.vaultStorage).not.toBeNull();
      });
      expect(modes).toEqual(['primary']);
    } finally {
      resetVaultStorageSnapshot();
    }
  });

  it('the /metrics snapshot caps its total at 5 s', async () => {
    resetVaultStorageSnapshot();
    const metricsApp = express();
    metricsApp.get('/metrics', getMetrics);
    metricsApp.use(errorMiddleware);
    try {
      const limits = await aggregateLimits(async () => {
        await request(metricsApp).get('/metrics');
        await vi.waitFor(async () => {
          const res = await request(metricsApp).get('/metrics');
          expect(res.body.data.vaultStorage).not.toBeNull();
        });
      });
      expect(limits).toEqual([['users', 5_000]]);
    } finally {
      resetVaultStorageSnapshot();
    }
  });
});

describe('migration v3 (vault-quota-counter)', () => {
  beforeEach(async () => {
    await JobLock.ensureIndexes();
    await Migration.ensureIndexes();
  });

  it('a failure to build its index that is not a conflict fails the migration, recording nothing', async () => {
    const real = mongoose.mongo.Collection.prototype.createIndex;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'createIndex').mockImplementation(function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof real>
    ) {
      if (this.collectionName === 'users' && JSON.stringify(args[0]) === '{"quotaRecountedAt":1}') {
        return Promise.reject(
          new mongoose.mongo.MongoServerError({ message: 'not authorized', code: 13 }),
        );
      }
      return real.apply(this, args);
    } as never);
    const user = await legacyAccount();

    await expect(runMigrations()).rejects.toThrow('not authorized');

    expect(await Migration.countDocuments({ version: 3 })).toBe(0);
    expect(await vaultBytesCounter(user.id)).toBeUndefined();
  });

  it('stops installing at its time budget and leaves the rest to the first write or the recount', async () => {
    const first = await legacyAccount();
    const second = await legacyAccount();
    // The first account's total takes the whole 30-second budget (the clock is
    // moved on inside it), so the walk stops before the second.
    vi.useFakeTimers({ toFake: ['Date'], now: Date.now() });
    const realAggregate = VaultItem.aggregate.bind(VaultItem) as (...args: unknown[]) => unknown;
    let moved = false;
    vi.spyOn(VaultItem, 'aggregate').mockImplementation(((...args: unknown[]) => {
      if (!moved) {
        moved = true;
        vi.setSystemTime(Date.now() + 31_000);
      }
      return realAggregate(...args);
    }) as never);
    try {
      await runMigrations();
    } finally {
      vi.useRealTimers();
    }

    expect(await Migration.countDocuments({ version: 3 })).toBe(1);
    const installed = [
      await vaultBytesCounter(first.id),
      await vaultBytesCounter(second.id),
    ].filter((value) => value !== undefined);
    expect(installed).toHaveLength(1);
  });

  it('builds the recount index and installs every missing counter', async () => {
    await users()
      .dropIndex('quotaRecountedAt_1')
      .catch(() => undefined);
    const a = await legacyAccount();
    const b = await legacyAccount();
    const erased = await legacyAccount();
    await users().updateOne({ _id: oid(erased.id) }, { $set: { deletionPending: true } });

    await runMigrations();

    expect((await Migration.findOne({ version: 3 }).lean())?.name).toBe('vault-quota-counter');
    const indexes = await users().indexes();
    expect(indexes.some((index) => JSON.stringify(index.key) === '{"quotaRecountedAt":1}')).toBe(
      true,
    );
    expect(await vaultBytesCounter(a.id)).toBe(await storedVaultBytes(a.id));
    expect(await vaultBytesCounter(b.id)).toBe(await storedVaultBytes(b.id));
    // Negative: an account being erased gets no counter.
    expect(await vaultBytesCounter(erased.id)).toBeUndefined();
  });

  it('leaves an installed counter alone, tolerates an index built by hand, and passes over a failing account', async () => {
    await users()
      .dropIndex('quotaRecountedAt_1')
      .catch(() => undefined);
    // The same keys under another name: `createIndex` answers 85, tolerated.
    await users().createIndex({ quotaRecountedAt: 1 }, { name: 'operator_built' });
    const installed = await createTestUser();
    await createQuotaItem(installed, 600);
    await users().updateOne({ _id: oid(installed.id) }, { $inc: { vaultBytes: 7 } });
    const failing = await legacyAccount();
    const healthy = await legacyAccount();

    const real = VaultItem.aggregate.bind(VaultItem) as (...args: unknown[]) => unknown;
    vi.spyOn(VaultItem, 'aggregate').mockImplementation(((...args: unknown[]) => {
      const pipeline = args[0] as { $match?: { userId?: unknown } }[];
      if (String(pipeline[0]?.$match?.userId) === failing.id) {
        throw new Error('simulated aggregate failure');
      }
      return real(...args);
    }) as never);

    try {
      await expect(runMigrations()).resolves.toBeUndefined();

      expect(await Migration.countDocuments({ version: 3 })).toBe(1);
      expect(await vaultBytesCounter(installed.id)).toBe(
        (await storedVaultBytes(installed.id)) + 7,
      );
      expect(await vaultBytesCounter(failing.id)).toBeUndefined();
      expect(await vaultBytesCounter(healthy.id)).toBe(await storedVaultBytes(healthy.id));
    } finally {
      // Put the model's own index back for whatever runs next in this file.
      await users().dropIndex('operator_built');
      await users().createIndex({ quotaRecountedAt: 1 });
    }
  });
});

describe('/metrics reports vault storage from a snapshot it never waits for', () => {
  const metricsApp = express();
  metricsApp.get('/metrics', getMetrics);
  metricsApp.use(errorMiddleware);

  beforeEach(() => {
    resetVaultStorageSnapshot();
  });

  afterEach(() => {
    resetVaultStorageSnapshot();
  });

  it('answers null at once, then the total of every installed counter', async () => {
    const a = await createTestUser();
    await createQuotaItem(a, 1_000);
    const b = await createTestUser();
    await createQuotaItem(b, 2_000);
    await legacyAccount(); // no counter: not counted

    const first = await request(metricsApp).get('/metrics');
    expect(first.status).toBe(200);
    expect(first.body.data.vaultStorage).toBeNull();

    const expected = (await storedVaultBytes(a.id)) + (await storedVaultBytes(b.id));
    await vi.waitFor(async () => {
      const next = await request(metricsApp).get('/metrics');
      expect(next.body.data.vaultStorage).toMatchObject({ accounts: 2, totalBytes: expected });
    });
  });

  it('a refresh that fails leaves the snapshot as it was, and a later request tries again', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: Date.now() });
    const refused = {
      read: () => refused,
      option: () => Promise.reject(new Error('the database refused the total')),
    };
    const aggregate = vi
      .spyOn(mongoose.Model, 'aggregate')
      .mockImplementation((() => refused) as never);
    try {
      const first = await request(metricsApp).get('/metrics');
      expect(first.status).toBe(200);
      expect(first.body.data.vaultStorage).toBeNull();
      // The failure settles (and is logged); within five minutes nothing retries.
      await vi.waitFor(async () => {
        await request(metricsApp).get('/metrics');
        expect(aggregate).toHaveBeenCalledTimes(1);
      });
      // Five minutes on, the next request starts a new refresh: the failed one
      // did not leave the refresh marked as running for ever.
      vi.setSystemTime(Date.now() + 5 * 60 * 1000);
      const later = await request(metricsApp).get('/metrics');
      expect(later.body.data.vaultStorage).toBeNull();
      expect(aggregate).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it('answers while the database never does', async () => {
    const hanging = {
      read: () => hanging,
      option: () => ({ then: () => new Promise(() => undefined) }),
    };
    const aggregate = vi
      .spyOn(mongoose.Model, 'aggregate')
      .mockImplementation((() => hanging) as never);

    const res = await request(metricsApp).get('/metrics');

    expect(res.status).toBe(200);
    expect(res.body.data.vaultStorage).toBeNull();
    expect(aggregate).toHaveBeenCalledTimes(1);
    // A second request while the first refresh hangs starts no second one.
    expect((await request(metricsApp).get('/metrics')).status).toBe(200);
    expect(aggregate).toHaveBeenCalledTimes(1);
  });
});
