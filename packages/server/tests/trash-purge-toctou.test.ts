/**
 * F-29 — the nightly trash purge deletes only what is STILL in the trash when the
 * delete runs.
 *
 * The purge reads a batch of expired trash, then deletes it. Between the two the
 * owner may pull an item back out of the trash (`POST /vault/items/restore/:id`),
 * and a delete keyed on `_id` and `userId` alone would then destroy a live item
 * for good. The delete must re-state the trash predicate so a restore that wins
 * the race keeps its item.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import cron from 'node-cron';
import { TRASH_AUTO_PURGE_DAYS } from '@hvault/shared';
import app from '../src/app.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { startTrashCleanupJob } from '../src/jobs/trashCleanup.js';
import { createTestUser, authHeader, getCsrf, seedItem } from './helpers.js';

vi.mock('node-cron', () => ({
  default: { schedule: vi.fn().mockReturnValue({ stop: vi.fn() }) },
}));

const mockedSchedule = vi.mocked(cron.schedule);

function purgeTick(): () => Promise<void> {
  mockedSchedule.mockClear();
  startTrashCleanupJob();
  return mockedSchedule.mock.calls[0]![1] as () => Promise<void>;
}

function daysAgo(n: number): Date {
  return new Date(Date.now() - n * 24 * 60 * 60 * 1000);
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe('trash purge: an item restored between the select and the delete survives', () => {
  it('keeps the restored item, purges the one still in the trash, and audits only the purge', async () => {
    const owner = await createTestUser();
    const expired = daysAgo(TRASH_AUTO_PURGE_DAYS + 10);
    const restored = await seedItem(owner.id, { deletedAt: expired });
    const stillTrashed = await seedItem(owner.id, { deletedAt: expired });
    const restoredId = String(restored['_id']);

    // The batch boundary: the job has READ both rows; before its delete runs, the
    // owner restores one of them through the real endpoint.
    const originalDeleteMany = VaultItem.deleteMany.bind(VaultItem) as (
      ...args: unknown[]
    ) => unknown;
    let restoredMidBatch = false;
    vi.spyOn(VaultItem, 'deleteMany').mockImplementation((async (...args: unknown[]) => {
      if (!restoredMidBatch) {
        restoredMidBatch = true;
        const agent = request.agent(app);
        const csrf = await getCsrf(agent);
        await agent
          .post(`/api/v1/vault/items/restore/${restoredId}`)
          .set('Authorization', authHeader(owner.accessToken))
          .set('Cookie', csrf.cookie)
          .set('x-csrf-token', csrf.token)
          .expect(200);
      }
      return originalDeleteMany(...args);
    }) as never);

    await purgeTick()();

    expect(restoredMidBatch).toBe(true);
    const survivor = await VaultItem.findById(restoredId).lean();
    expect(survivor).not.toBeNull();
    expect(survivor!.deletedAt ?? null).toBeNull();
    // Negative: the row nobody restored is purged as before.
    expect(await VaultItem.findById(stillTrashed['_id']).lean()).toBeNull();

    // The purge's record counts what it destroyed, not what it read.
    const audit = await AuditLog.find({ userId: owner.id, action: 'trash_auto_purge' }).lean();
    expect(audit).toHaveLength(1);
    expect(audit[0]!.metadata).toMatchObject({ itemCount: 1 });
  });

  it('writes no purge row for an account whose whole batch was restored', async () => {
    const owner = await createTestUser();
    const only = await seedItem(owner.id, { deletedAt: daysAgo(TRASH_AUTO_PURGE_DAYS + 1) });

    const originalDeleteMany = VaultItem.deleteMany.bind(VaultItem) as (
      ...args: unknown[]
    ) => unknown;
    vi.spyOn(VaultItem, 'deleteMany').mockImplementation((async (...args: unknown[]) => {
      await VaultItem.collection.updateOne(
        { _id: only['_id'] as mongoose.Types.ObjectId },
        { $unset: { deletedAt: 1 } },
      );
      return originalDeleteMany(...args);
    }) as never);

    await purgeTick()();

    expect(await VaultItem.countDocuments({ _id: only['_id'] as mongoose.Types.ObjectId })).toBe(1);
    expect(await AuditLog.countDocuments({ userId: owner.id, action: 'trash_auto_purge' })).toBe(0);
  });

  it('a restore in one batch does not end the walk early: every later expired row is still purged', async () => {
    const owner = await createTestUser();
    const expired = daysAgo(TRASH_AUTO_PURGE_DAYS + 3);
    // One more than the job's batch (500), so there IS a second batch.
    const docs = Array.from({ length: 501 }, () => ({
      _id: new mongoose.Types.ObjectId(),
      userId: new mongoose.Types.ObjectId(owner.id),
      itemType: 'login',
      encryptedData: 'd',
      dataIv: 'i',
      dataTag: 't',
      encryptedName: 'n',
      nameIv: 'i',
      nameTag: 't',
      deletedAt: expired,
    }));
    await VaultItem.collection.insertMany(docs);

    const originalDeleteMany = VaultItem.deleteMany.bind(VaultItem) as (
      ...args: unknown[]
    ) => unknown;
    let first = true;
    vi.spyOn(VaultItem, 'deleteMany').mockImplementation((async (...args: unknown[]) => {
      if (first) {
        first = false;
        const filter = args[0] as { _id: { $in: mongoose.Types.ObjectId[] } };
        await VaultItem.collection.updateOne(
          { _id: filter._id.$in[0]! },
          { $unset: { deletedAt: 1 } },
        );
      }
      return originalDeleteMany(...args);
    }) as never);

    await purgeTick()();

    // One restored row survives; the other 500 expired rows are all gone, though
    // the first batch deleted fewer than a full batch.
    expect(await VaultItem.countDocuments({ userId: owner.id })).toBe(1);
    expect(await VaultItem.countDocuments({ userId: owner.id, deletedAt: { $ne: null } })).toBe(0);
  });
});
