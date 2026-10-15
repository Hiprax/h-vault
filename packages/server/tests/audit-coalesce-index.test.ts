/**
 * The per-minute coalescing of locked sign-in attempts must be served by its
 * index, on every path that looks a row up by `coalesceKey`.
 *
 * `{coalesceKey: 1}` is a PARTIAL index (`coalesceKey: {$type: 'string'}`), and
 * MongoDB's planner uses a partial index only for a query that contains its
 * filter expression: an equality on a string is not taken to imply `$type`, so a
 * filter of `{coalesceKey}` alone plans as a COLLSCAN over every account's audit
 * log. That lookup runs for every sign-in naming an unknown address, a locked
 * account or one being erased: a scan per anonymous request, and a response time
 * that grows with the log and differs from the wrong-password path, which only
 * inserts. These tests read the plan the server actually chose, from the
 * profiler, for each of the three lookups.
 */
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import mongoose from 'mongoose';
import { AuditLog } from '../src/models/AuditLog.js';
import { recordLockedAttempt, recordNothing } from '../src/services/auditService.js';

interface ProfileEntry {
  op?: string;
  ns?: string;
  command?: { q?: Record<string, unknown> };
  planSummary?: string;
}

/** Runs `run` with the profiler on and returns the updates it saw on `audit_logs`. */
async function profiledUpdates(run: () => Promise<void>): Promise<ProfileEntry[]> {
  const db = mongoose.connection.db!;
  await db.command({ profile: 0 });
  await db
    .collection('system.profile')
    .drop()
    .catch(() => undefined);
  await db.command({ profile: 2 });
  try {
    await run();
  } finally {
    await db.command({ profile: 0 });
  }
  const entries = (await db
    .collection('system.profile')
    .find({ op: 'update', ns: `${db.databaseName}.audit_logs` })
    .toArray()) as ProfileEntry[];
  await db
    .collection('system.profile')
    .drop()
    .catch(() => undefined);
  return entries;
}

function lookupsByKey(entries: ProfileEntry[]): ProfileEntry[] {
  return entries.filter(
    (entry) => entry.command?.q !== undefined && 'coalesceKey' in entry.command.q,
  );
}

beforeAll(async () => {
  await AuditLog.createIndexes();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('the coalesced locked-attempt lookups are served by the coalesceKey index', () => {
  it('records a first and a repeat attempt in one minute through an index scan, never a collection scan', async () => {
    const userId = new mongoose.Types.ObjectId().toString();
    // Other accounts' rows, so a scan would have something to scan.
    await AuditLog.insertMany(
      Array.from({ length: 50 }, () => ({
        userId: new mongoose.Types.ObjectId(),
        action: 'login',
        ipAddress: '127.0.0.1',
        userAgent: 'seed',
        timestamp: new Date(),
      })),
    );
    const now = new Date('2026-10-14T10:00:30.000Z');

    const entries = await profiledUpdates(async () => {
      await recordLockedAttempt(userId, '203.0.113.7', 'agent', now);
      await recordLockedAttempt(userId, '203.0.113.8', 'agent', now);
    });

    const lookups = lookupsByKey(entries);
    expect(lookups).toHaveLength(2);
    for (const lookup of lookups) {
      expect(lookup.planSummary).toContain('IXSCAN { coalesceKey: 1 }');
      expect(lookup.planSummary).not.toContain('COLLSCAN');
    }
    // The behaviour the index serves is unchanged: one row, counting both.
    const rows = await AuditLog.find({ userId, action: 'login_failed' }).lean();
    expect(rows).toHaveLength(1);
    expect(rows[0]?.count).toBe(2);
  });

  it('retries a lost insert race as an indexed update', async () => {
    const userId = new mongoose.Types.ObjectId().toString();
    const now = new Date('2026-10-14T10:05:30.000Z');
    await recordLockedAttempt(userId, '203.0.113.7', 'agent', now);
    const real = AuditLog.updateOne.bind(AuditLog);
    let calls = 0;
    // The first update of the second attempt loses the insert race.
    vi.spyOn(AuditLog, 'updateOne').mockImplementation(((...args: Parameters<typeof real>) => {
      calls += 1;
      if (calls === 1) {
        return Promise.reject(Object.assign(new Error('E11000 duplicate key'), { code: 11000 }));
      }
      return real(...args);
    }) as never);

    const entries = await profiledUpdates(async () => {
      await recordLockedAttempt(userId, '203.0.113.9', 'agent', now);
    });

    expect(calls).toBe(2);
    const lookups = lookupsByKey(entries);
    expect(lookups).toHaveLength(1);
    expect(lookups[0]?.planSummary).toContain('IXSCAN { coalesceKey: 1 }');
    const rows = await AuditLog.find({ userId, action: 'login_failed' }).lean();
    expect(rows.map((row) => row.count)).toEqual([2]);
  });

  it('makes the equalising round trip for an unknown address through the index, and writes nothing', async () => {
    const before = await AuditLog.countDocuments();

    const entries = await profiledUpdates(() => recordNothing());

    const lookups = lookupsByKey(entries);
    expect(lookups).toHaveLength(1);
    expect(lookups[0]?.planSummary).toContain('IXSCAN { coalesceKey: 1 }');
    expect(lookups[0]?.planSummary).not.toContain('COLLSCAN');
    expect(await AuditLog.countDocuments()).toBe(before);
  });
});
