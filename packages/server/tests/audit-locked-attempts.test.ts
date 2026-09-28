/**
 * F-03 — the audit service's coalesced locked-attempt rows and the
 * stranger-writable cap, as units against the real datastore.
 *
 * The HTTP behaviour is pinned in `password-lockout-uniform.test.ts`; this file
 * pins the paths a request cannot reach deterministically: two first attempts
 * of one minute racing to insert, a datastore that refuses, and the cap's
 * boundary arithmetic. Like every audit write, none of these may throw into a
 * request.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import mongoose from 'mongoose';
import { MAX_STRANGER_AUDIT_ROWS_PER_USER } from '@hvault/shared';
import { AuditLog } from '../src/models/AuditLog.js';
import {
  createAuditLog,
  noteStrangerWritableInsert,
  recordLockedAttempt,
  recordNothing,
  resetStrangerAuditTracking,
  STRANGER_AUDIT_TRIM_EVERY,
  trimStrangerAuditRows,
} from '../src/services/auditService.js';

afterEach(() => {
  vi.restoreAllMocks();
  resetStrangerAuditTracking();
});

function newUserId(): string {
  return new mongoose.Types.ObjectId().toString();
}

describe('recordLockedAttempt', () => {
  it('coalesces a minute of attempts into one row with a count, and starts a new row next minute', async () => {
    const userId = newUserId();
    const minute = new Date(Date.UTC(2026, 8, 28, 12, 0, 5));

    await recordLockedAttempt(userId, '198.51.100.1', 'ua-one', minute);
    await recordLockedAttempt(
      userId,
      '198.51.100.2',
      'ua-two',
      new Date(minute.getTime() + 30_000),
    );
    await recordLockedAttempt(
      userId,
      '198.51.100.3',
      'ua-three',
      new Date(minute.getTime() + 60_000),
    );

    const rows = await AuditLog.find({ userId }).sort({ timestamp: 1 }).lean();
    expect(rows.map((row) => row.count)).toEqual([2, 1]);
    // The first attempt of the minute names the row; later ones only count.
    expect(rows[0]!.ipAddress).toBe('198.51.100.1');
    expect(rows[0]!.timestamp.getTime()).toBe(minute.getTime());
    expect(rows[0]!.action).toBe('login_failed');
    expect(rows[0]!.metadata).toEqual({ reason: 'locked' });
    // The bucket key is bookkeeping: not selected by default, not in JSON.
    expect(rows[0]).not.toHaveProperty('coalesceKey');
    const hydrated = await AuditLog.findById(rows[0]!._id).select('+coalesceKey');
    expect(hydrated!.coalesceKey).toBe(
      `${userId}|login_failed|locked|${String(Date.UTC(2026, 8, 28, 12, 0, 0))}`,
    );
    expect(JSON.stringify(hydrated!.toJSON())).not.toContain('coalesceKey');
  });

  it('an ordinary audit row carries count 1 by default', async () => {
    const userId = newUserId();
    await createAuditLog(userId, 'login', undefined, '127.0.0.1', 'ua');
    const row = await AuditLog.findOne({ userId }).lean();
    expect(row!.count).toBe(1);
  });

  it('retries a lost insert race as an update of the winning row', async () => {
    const userId = newUserId();
    const at = new Date(Date.UTC(2026, 8, 28, 13, 0, 0));
    await recordLockedAttempt(userId, 'a', 'a', at);

    // The next upsert behaves as if a concurrent request inserted first.
    const original = AuditLog.updateOne.bind(AuditLog) as (...args: unknown[]) => unknown;
    let raced = false;
    vi.spyOn(AuditLog, 'updateOne').mockImplementation(((...args: unknown[]) => {
      const options = args[2] as { upsert?: boolean } | undefined;
      if (!raced && options?.upsert === true) {
        raced = true;
        return Promise.reject(Object.assign(new Error('E11000 duplicate key'), { code: 11000 }));
      }
      return original(...args);
    }) as never);

    await recordLockedAttempt(userId, 'b', 'b', at);

    expect(raced).toBe(true);
    const rows = await AuditLog.find({ userId }).lean();
    expect(rows).toHaveLength(1);
    expect(rows[0]!.count).toBe(2);
  });

  it('never throws when the datastore refuses, and writes nothing', async () => {
    const userId = newUserId();
    vi.spyOn(AuditLog, 'updateOne').mockImplementation((() =>
      Promise.reject(new Error('datastore unavailable'))) as never);

    await expect(recordLockedAttempt(userId, 'a', 'a')).resolves.toBeUndefined();
    vi.restoreAllMocks();
    expect(await AuditLog.countDocuments({ userId })).toBe(0);
  });
});

describe('recordNothing', () => {
  it('writes nothing, and never throws even when the datastore refuses', async () => {
    const before = await AuditLog.countDocuments({});
    await recordNothing();
    expect(await AuditLog.countDocuments({})).toBe(before);

    vi.spyOn(AuditLog, 'updateOne').mockImplementation((() =>
      Promise.reject(new Error('datastore unavailable'))) as never);
    await expect(recordNothing()).resolves.toBeUndefined();
  });
});

describe('the stranger-writable cap', () => {
  it(`trims on every ${String(STRANGER_AUDIT_TRIM_EVERY)}th insert, and not before`, async () => {
    const userId = newUserId();
    const spy = vi.spyOn(AuditLog, 'find');
    for (let i = 0; i < STRANGER_AUDIT_TRIM_EVERY - 1; i++) {
      await noteStrangerWritableInsert(userId);
    }
    expect(spy).not.toHaveBeenCalled();
    await noteStrangerWritableInsert(userId);
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it('keeps exactly the newest rows at a shared timestamp, using _id as the tie-break', async () => {
    const userId = new mongoose.Types.ObjectId();
    const at = new Date(Date.UTC(2026, 8, 1));
    const docs = Array.from({ length: MAX_STRANGER_AUDIT_ROWS_PER_USER + 2 }, () => ({
      _id: new mongoose.Types.ObjectId(),
      userId,
      action: 'login_failed',
      ipAddress: 's',
      userAgent: 's',
      timestamp: at,
    }));
    await AuditLog.insertMany(docs);

    await trimStrangerAuditRows(userId.toString());

    const kept = await AuditLog.find({ userId }).select('_id').lean();
    expect(kept).toHaveLength(MAX_STRANGER_AUDIT_ROWS_PER_USER);
    const sorted = docs.map((d) => d._id.toString()).sort();
    // The two smallest ids at that instant are the ones removed.
    const keptIds = new Set(kept.map((row) => row._id.toString()));
    expect(keptIds.has(sorted[0]!)).toBe(false);
    expect(keptIds.has(sorted[1]!)).toBe(false);
    expect(keptIds.has(sorted[2]!)).toBe(true);
  });

  it('does nothing to an account under the cap', async () => {
    const userId = new mongoose.Types.ObjectId();
    await AuditLog.create({ userId, action: 'login_failed', ipAddress: 's', userAgent: 's' });
    await trimStrangerAuditRows(userId.toString());
    expect(await AuditLog.countDocuments({ userId })).toBe(1);
  });

  it('a failed trim never throws, and the next interval trims again', async () => {
    const userId = new mongoose.Types.ObjectId();
    await AuditLog.insertMany(
      Array.from({ length: MAX_STRANGER_AUDIT_ROWS_PER_USER + 1 }, (_, i) => ({
        userId,
        action: 'login_failed',
        ipAddress: 's',
        userAgent: 's',
        timestamp: new Date(Date.UTC(2026, 8, 1) + i),
      })),
    );
    const find = vi.spyOn(AuditLog, 'find').mockImplementationOnce((() => {
      throw new Error('datastore unavailable');
    }) as never);

    for (let i = 0; i < STRANGER_AUDIT_TRIM_EVERY; i++) {
      await expect(noteStrangerWritableInsert(userId.toString())).resolves.toBeUndefined();
    }
    // The trim was attempted once and failed: nothing was removed.
    expect(find).toHaveBeenCalledTimes(1);
    expect(await AuditLog.countDocuments({ userId })).toBe(MAX_STRANGER_AUDIT_ROWS_PER_USER + 1);

    // The counter started again, so the next interval trims for real.
    for (let i = 0; i < STRANGER_AUDIT_TRIM_EVERY - 1; i++) {
      await noteStrangerWritableInsert(userId.toString());
    }
    expect(find).toHaveBeenCalledTimes(1);
    await noteStrangerWritableInsert(userId.toString());
    expect(find).toHaveBeenCalledTimes(2);
    expect(await AuditLog.countDocuments({ userId })).toBe(MAX_STRANGER_AUDIT_ROWS_PER_USER);
  });
});

describe('what counts toward the stranger-writable cap', () => {
  it('a coalesced attempt is an update, not an insert: a minute of them never trims', async () => {
    const userId = newUserId();
    const at = new Date(Date.UTC(2026, 8, 28, 15, 0, 0));
    const find = vi.spyOn(AuditLog, 'find');

    for (let i = 0; i < STRANGER_AUDIT_TRIM_EVERY + 5; i++) {
      await recordLockedAttempt(userId, 'a', 'a', new Date(at.getTime() + i * 100));
    }

    expect(find).not.toHaveBeenCalled();
    const rows = await AuditLog.find({ userId }).lean();
    expect(rows).toHaveLength(1);
    expect(rows[0]!.count).toBe(STRANGER_AUDIT_TRIM_EVERY + 5);
  });

  it("each minute's first attempt is an insert, and the hundredth such insert trims once", async () => {
    const userId = newUserId();
    const start = Date.UTC(2026, 8, 28, 16, 0, 0);
    const find = vi.spyOn(AuditLog, 'find');

    for (let i = 0; i < STRANGER_AUDIT_TRIM_EVERY - 1; i++) {
      await recordLockedAttempt(userId, 'a', 'a', new Date(start + i * 60_000));
    }
    expect(find).not.toHaveBeenCalled();
    await recordLockedAttempt(
      userId,
      'a',
      'a',
      new Date(start + (STRANGER_AUDIT_TRIM_EVERY - 1) * 60_000),
    );
    expect(find).toHaveBeenCalledTimes(1);
    expect(await AuditLog.countDocuments({ userId })).toBe(STRANGER_AUDIT_TRIM_EVERY);
  });
});

describe('the coalescing key index', () => {
  it('refuses a second row with the same key, and never constrains rows without one', async () => {
    await AuditLog.init();
    const userId = new mongoose.Types.ObjectId();
    const base = { userId, action: 'login_failed' as const, ipAddress: 's', userAgent: 's' };

    await AuditLog.create({ ...base, coalesceKey: 'bucket|1' });
    await expect(AuditLog.create({ ...base, coalesceKey: 'bucket|1' })).rejects.toMatchObject({
      code: 11000,
    });
    // Ordinary rows carry no key and are outside the partial index.
    await AuditLog.create(base);
    await AuditLog.create(base);

    expect(await AuditLog.countDocuments({ userId })).toBe(3);
  });

  it('lets a concurrent burst of first attempts in one minute land on ONE row', async () => {
    const userId = newUserId();
    const at = new Date(Date.UTC(2026, 8, 28, 17, 0, 0));

    await Promise.all(
      Array.from({ length: 8 }, (_, i) => recordLockedAttempt(userId, `ip-${String(i)}`, 'ua', at)),
    );

    const rows = await AuditLog.find({ userId }).lean();
    expect(rows).toHaveLength(1);
    expect(rows[0]!.count).toBe(8);
  });
});
