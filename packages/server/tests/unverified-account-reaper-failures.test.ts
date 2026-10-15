/**
 * F-21, the reaper when things go wrong: a cascade that fails, a claim that
 * throws, a run that reaches its time budget, a reaper that cannot even read its
 * candidates, and a queue full of accounts it must skip. Each case pins what must
 * happen AND what must not (an account half-erased and forgotten, a skipped account
 * that blocks the rest, a failure that costs the rest of the cleanup job).
 *
 * The cascade is the real one, wrapped in a pass-through spy so one call can be
 * made to fail or observed at the moment it starts.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import mongoose from 'mongoose';

vi.mock('node-cron', () => ({
  default: {
    schedule: vi.fn().mockReturnValue({ stop: vi.fn() }),
  },
}));

vi.mock('../src/utils/cascadeDelete.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/utils/cascadeDelete.js')>();
  return { ...actual, cascadeDeleteUser: vi.fn(actual.cascadeDeleteUser) };
});

import cron from 'node-cron';
import { config } from '../src/config/index.js';
import { startTokenCleanupJob } from '../src/jobs/tokenCleanup.js';
import { reapUnverifiedAccounts } from '../src/utils/unverifiedAccounts.js';
import { cascadeDeleteUser } from '../src/utils/cascadeDelete.js';
import { User } from '../src/models/User.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { VaultItem } from '../src/models/VaultItem.js';

const { cascadeDeleteUser: realCascade } = await vi.importActual<
  typeof import('../src/utils/cascadeDelete.js')
>('../src/utils/cascadeDelete.js');

const DAY_MS = 24 * 60 * 60 * 1000;
const REAPED = 'unverified_account_reaped';
const cascade = vi.mocked(cascadeDeleteUser);

afterEach(() => {
  vi.restoreAllMocks();
  cascade.mockClear();
});

/** Raw unverified accounts, `days` old, in `_id` (creation) order. */
async function oldUnverified(count: number, days = config.UNVERIFIED_ACCOUNT_TTL_DAYS * 2) {
  const createdAt = new Date(Date.now() - days * DAY_MS);
  const docs = Array.from({ length: count }, (_, i) => ({
    _id: new mongoose.Types.ObjectId(),
    email: `reap-${String(i)}-${new mongoose.Types.ObjectId().toString()}@example.com`,
    authHash: 'x',
    emailVerified: false,
    createdAt,
    updatedAt: createdAt,
  }));
  await User.collection.insertMany(docs);
  return docs;
}

const exists = async (id: mongoose.Types.ObjectId) =>
  (await User.collection.findOne({ _id: id })) !== null;

describe('F-21: the reaper under failure', () => {
  it('claims the account BEFORE the cascade starts', async () => {
    const [account] = await oldUnverified(1);
    let pendingAtCascade: unknown;
    cascade.mockImplementationOnce(async (opts) => {
      pendingAtCascade = (await User.collection.findOne({ _id: account!._id }))?.[
        'deletionPending'
      ];
      return realCascade(opts);
    });

    expect(await reapUnverifiedAccounts()).toBe(1);

    expect(pendingAtCascade).toBe(true);
    expect(cascade).toHaveBeenCalledWith(
      expect.objectContaining({ auditAction: REAPED, ip: 'system' }),
    );
    expect(await exists(account!._id)).toBe(false);
  });

  it('a cascade that fails leaves the account claimed for the zombie loop, and counts nothing', async () => {
    const [account] = await oldUnverified(1);
    cascade.mockResolvedValueOnce(false);

    expect(await reapUnverifiedAccounts()).toBe(0);

    const row = await User.collection.findOne({ _id: account!._id });
    expect(row).not.toBeNull();
    expect(row!['deletionPending']).toBe(true);
    expect(await AuditLog.countDocuments({ action: REAPED })).toBe(0);
  });

  it('one account whose claim throws is passed over, and the next is still reaped', async () => {
    const [first, second] = await oldUnverified(2);
    const original = User.findOneAndUpdate.bind(User);
    vi.spyOn(User, 'findOneAndUpdate').mockImplementationOnce((() => {
      throw new Error('claim refused by the database');
    }) as unknown as typeof User.findOneAndUpdate);
    // Later calls go to the real method.
    vi.mocked(User.findOneAndUpdate).mockImplementation(
      original as unknown as typeof User.findOneAndUpdate,
    );

    expect(await reapUnverifiedAccounts()).toBe(1);

    const kept = await User.collection.findOne({ _id: first!._id });
    expect(kept).not.toBeNull();
    expect(kept!['deletionPending']).toBeUndefined();
    expect(await exists(second!._id)).toBe(false);
  });

  it('stops at its time budget and leaves the rest untouched for the next run', async () => {
    const [first, second] = await oldUnverified(2);
    const realNow = Date.now.bind(Date);
    let offset = 0;
    vi.spyOn(Date, 'now').mockImplementation(() => realNow() + offset);
    // The first erasure "takes" six minutes: the clock moves past the five-minute
    // budget only once it has finished.
    cascade.mockImplementationOnce(async (opts) => {
      const erased = await realCascade(opts);
      offset = 6 * 60 * 1000;
      return erased;
    });

    const reaped = await reapUnverifiedAccounts(new Date());

    vi.mocked(Date.now).mockRestore();
    expect(reaped).toBe(1);
    expect(await exists(first!._id)).toBe(false);
    const untouched = await User.collection.findOne({ _id: second!._id });
    expect(untouched).not.toBeNull();
    expect(untouched!['deletionPending']).toBeUndefined();
  });

  it('pages past accounts it must skip, so a full page of them cannot stall it', async () => {
    const owners = await oldUnverified(500);
    await VaultItem.collection.insertMany(owners.map(({ _id }) => ({ userId: _id })));
    const [last] = await oldUnverified(1);

    expect(await reapUnverifiedAccounts()).toBe(1);

    expect(await exists(last!._id)).toBe(false);
    expect(await User.collection.countDocuments({ _id: { $in: owners.map((o) => o._id) } })).toBe(
      500,
    );
  });

  it('a reaper that cannot read its candidates costs the cleanup job nothing else', async () => {
    const [account] = await oldUnverified(1);
    // An expired, unused refresh token the job must still delete.
    await RefreshToken.collection.insertOne({
      userId: new mongoose.Types.ObjectId(),
      tokenHash: 'expired-unused',
      familyId: 'f',
      expiresAt: new Date(Date.now() - 60_000),
    });
    const original = User.find.bind(User);
    vi.spyOn(User, 'find').mockImplementation(((
      filter: Record<string, unknown>,
      ...rest: unknown[]
    ) => {
      if ('emailVerified' in filter) throw new Error('candidate read refused');
      return original(filter, ...(rest as []));
    }) as unknown as typeof User.find);

    startTokenCleanupJob();
    const calls = vi.mocked(cron.schedule).mock.calls;
    const callback = calls[calls.length - 1]![1] as () => Promise<void>;
    await expect(callback()).resolves.toBeUndefined();

    expect(await RefreshToken.collection.countDocuments({ tokenHash: 'expired-unused' })).toBe(0);
    expect(await exists(account!._id)).toBe(true);
  });
});
