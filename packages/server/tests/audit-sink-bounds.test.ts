/**
 * F-02 — the audit sink is bounded per account, at the one chokepoint every
 * writer passes through (`services/auditService.ts`).
 *
 * Two classes. SECURITY rows (sign-ins, password and 2FA events, exports,
 * sessions, settings) are never coalesced and never trimmed, except the
 * stranger-writable ones Phase 2 already caps. ACTIVITY rows (what an account did
 * to its own items, folders, documents and backups) are capped per account at
 * `MAX_ACTIVITY_AUDIT_ROWS_PER_USER`, trimmed oldest first by the hourly
 * maintenance job and by a sampled trim on every hundredth insert; and a short
 * allowlist of metadata-only edits repeated by the same actor within
 * `AUDIT_COALESCE_WINDOW_MS` is counted into one row instead of one row each.
 *
 * Both page sorts of `GET /user/audit-log` are served by an index (no blocking
 * SORT), and migration v2 drops the two superseded indexes.
 */
import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import cron from 'node-cron';
import {
  AUDIT_ACTIONS,
  AUDIT_COALESCE_WINDOW_MS,
  MAX_ACTIVITY_AUDIT_ROWS_PER_USER,
  STRANGER_WRITABLE_AUDIT_ACTIONS,
  type AuditAction,
} from '@hvault/shared';
import app from '../src/app.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { JobLock } from '../src/models/JobLock.js';
import { Migration } from '../src/models/Migration.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { acquireJobLock, releaseJobLock } from '../src/utils/jobLock.js';
import { runMigrations } from '../src/utils/migrations.js';
import {
  AUDIT_ACTION_CLASS,
  COALESCE_TARGET,
  AUDIT_TRIM_TRACKED_ACCOUNTS,
  createAuditLog,
  noteActivityInsert,
  noteStrangerWritableInsert,
  recordJobAuditEntries,
  resetActivityAuditTracking,
  resetStrangerAuditTracking,
  trimActivityAuditRows,
} from '../src/services/auditService.js';
import {
  resetAuditTrimCursor,
  runMaintenance,
  startMaintenanceJob,
  trimEveryAccountsAuditLog,
} from '../src/jobs/maintenance.js';
import { maskEmail } from '@hvault/shared';
import { createTestUser, authHeader, getCsrf, sampleVaultItem } from './helpers.js';
import { installTestClock, advanceClockBy, uninstallTestClock } from './clock.js';

vi.mock('node-cron', () => ({
  default: { schedule: vi.fn().mockReturnValue({ stop: vi.fn() }) },
}));

/** Sampler state is per process; every test starts from nothing. */
function resetSampling(): void {
  resetStrangerAuditTracking();
  resetActivityAuditTracking();
  resetAuditTrimCursor();
}

beforeEach(() => {
  resetSampling();
});

afterEach(() => {
  vi.restoreAllMocks();
  uninstallTestClock();
  resetSampling();
});

/**
 * An hour-aligned instant a day ago. Every seeded row is placed relative to it,
 * never at a fixed calendar date, so no row ever falls outside the audit log's
 * 365-day TTL (the TTL monitor could reap a stale fixed-date row mid-test).
 */
const RECENT_HOUR = Math.floor(Date.now() / 3_600_000) * 3_600_000 - 24 * 3_600_000;
const HOUR = 3_600_000;

const SEED_UA = 'seed-agent';
const SEED_IP = '203.0.113.200';

/**
 * Inserts `n` rows for `userId` straight into the collection (the service is the
 * unit under test, so seeding must not go through it), one second apart starting
 * at `startMs`, oldest first. Returns their timestamps in the same order.
 */
async function seedRows(
  userId: mongoose.Types.ObjectId,
  n: number,
  startMs: number,
  action: AuditAction = 'item_update',
): Promise<number[]> {
  const stamps: number[] = [];
  const CHUNK = 20_000;
  for (let offset = 0; offset < n; offset += CHUNK) {
    const docs = [];
    for (let i = offset; i < Math.min(n, offset + CHUNK); i++) {
      const at = startMs + i * 1000;
      stamps.push(at);
      docs.push({
        _id: new mongoose.Types.ObjectId(),
        userId,
        action,
        metadata: { itemId: `seed-${String(i)}` },
        ipAddress: SEED_IP,
        userAgent: SEED_UA,
        timestamp: new Date(at),
        count: 1,
      });
    }
    await AuditLog.collection.insertMany(docs, { ordered: false });
  }
  return stamps;
}

const ACTIVITY_SAMPLE = 'item_update' satisfies AuditAction;

async function activityCount(userId: string | mongoose.Types.ObjectId): Promise<number> {
  return AuditLog.countDocuments({ userId, action: ACTIVITY_SAMPLE });
}

/** Two days ago: comfortably inside the 365-day TTL, and before any live row. */
function seedStart(): number {
  return Date.now() - 2 * 24 * 60 * 60 * 1000;
}

// ── Coalescing ───────────────────────────────────────────────────────────────

describe('coalescing: only allowlisted metadata-only activity, only for the same actor', () => {
  async function createItem(token: string): Promise<string> {
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);
    const res = await agent
      .post('/api/v1/vault/items')
      .set('Authorization', authHeader(token))
      .set('Cookie', csrf.cookie)
      .set('x-csrf-token', csrf.token)
      .send(sampleVaultItem())
      .expect(201);
    return res.body.data._id as string;
  }

  async function putItem(
    agent: request.Agent,
    csrf: { token: string; cookie: string },
    token: string,
    id: string,
    body: Record<string, unknown>,
    userAgent = 'editor-agent',
  ): Promise<void> {
    await agent
      .put(`/api/v1/vault/items/${id}`)
      .set('Authorization', authHeader(token))
      .set('Cookie', csrf.cookie)
      .set('x-csrf-token', csrf.token)
      .set('User-Agent', userAgent)
      .send(body)
      .expect(200);
  }

  it('(a) 50 identical metadata-only edits from one address and one agent leave one row counting 50', async () => {
    const user = await createTestUser();
    const id = await createItem(user.accessToken);
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);

    const W = 50;
    for (let i = 0; i < W; i++) {
      await putItem(agent, csrf, user.accessToken, id, { favorite: i % 2 === 0 });
    }

    const rows = await AuditLog.find({ userId: user.id, action: 'item_update' }).lean();
    expect(rows.length).toBeLessThan(W);
    expect(rows).toHaveLength(1);
    expect(rows.reduce((sum, row) => sum + row.count, 0)).toBe(W);
    expect(rows[0]!.metadata).toMatchObject({ itemId: id, contentChanged: false });
    // Negative: the create row is its own row, untouched by the edits after it.
    const create = await AuditLog.find({ userId: user.id, action: 'item_create' }).lean();
    expect(create).toHaveLength(1);
    expect(create[0]!.count).toBe(1);
  });

  it('a ciphertext edit is never coalesced, and never absorbs a metadata-only edit after it', async () => {
    const user = await createTestUser();
    const id = await createItem(user.accessToken);
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);

    for (let i = 0; i < 3; i++) {
      await putItem(agent, csrf, user.accessToken, id, {
        encryptedData: `ciphertext-${String(i)}`,
        dataIv: 'aabbccddeeff00112233aabb',
        dataTag: 'aabbccddeeff00112233aabbccddeeff',
      });
    }
    await putItem(agent, csrf, user.accessToken, id, { favorite: true });

    const rows = await AuditLog.find({ userId: user.id, action: 'item_update' })
      .sort({ timestamp: 1, _id: 1 })
      .lean();
    expect(rows.map((row) => row.count)).toEqual([1, 1, 1, 1]);
    expect(
      rows.map((row) => (row.metadata as { contentChanged?: unknown }).contentChanged),
    ).toEqual([true, true, true, false]);
  });

  it('(b) two addresses editing the same item within the window never share a row', async () => {
    const userId = new mongoose.Types.ObjectId().toString();
    const metadata = { itemId: 'item-1', itemType: 'login', contentChanged: false };

    // Interleaved: each edit's newest row belongs to the OTHER address.
    for (const ip of ['198.51.100.1', '198.51.100.2', '198.51.100.1', '198.51.100.2']) {
      await createAuditLog(userId, 'item_update', { ...metadata }, ip, 'same-agent');
    }
    let rows = await AuditLog.find({ userId }).sort({ timestamp: 1, _id: 1 }).lean();
    expect(rows.map((row) => [row.ipAddress, row.count])).toEqual([
      ['198.51.100.1', 1],
      ['198.51.100.2', 1],
      ['198.51.100.1', 1],
      ['198.51.100.2', 1],
    ]);

    // Consecutive: each address's run is one row, and neither run absorbed the other.
    await AuditLog.deleteMany({ userId });
    for (const ip of ['198.51.100.1', '198.51.100.1', '198.51.100.2', '198.51.100.2']) {
      await createAuditLog(userId, 'item_update', { ...metadata }, ip, 'same-agent');
    }
    rows = await AuditLog.find({ userId }).sort({ timestamp: 1, _id: 1 }).lean();
    expect(rows.map((row) => [row.ipAddress, row.count])).toEqual([
      ['198.51.100.1', 2],
      ['198.51.100.2', 2],
    ]);
  });

  it('a different user agent from the same address is a different actor', async () => {
    const user = await createTestUser();
    const id = await createItem(user.accessToken);
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);

    await putItem(agent, csrf, user.accessToken, id, { favorite: true }, 'agent-one');
    await putItem(agent, csrf, user.accessToken, id, { favorite: false }, 'agent-two');

    const rows = await AuditLog.find({ userId: user.id, action: 'item_update' }).lean();
    expect(rows).toHaveLength(2);
    expect(rows.map((row) => row.userAgent).sort()).toEqual(['agent-one', 'agent-two']);
  });

  it('a different item is a different target, and a row older than the window is left alone', async () => {
    const userId = new mongoose.Types.ObjectId().toString();
    installTestClock({ at: RECENT_HOUR + 10 * HOUR });
    const edit = (itemId: string) =>
      createAuditLog(
        userId,
        'item_update',
        { itemId, itemType: 'login', contentChanged: false },
        '198.51.100.9',
        'agent',
      );

    await edit('item-a');
    await edit('item-b');
    advanceClockBy(AUDIT_COALESCE_WINDOW_MS - 1);
    await edit('item-b'); // inside the window of item-b's row: counted into it
    advanceClockBy(AUDIT_COALESCE_WINDOW_MS + 1);
    await edit('item-b'); // the window has passed: a row of its own

    const rows = await AuditLog.find({ userId }).sort({ timestamp: 1, _id: 1 }).lean();
    expect(rows.map((row) => [(row.metadata as { itemId: string }).itemId, row.count])).toEqual([
      ['item-a', 1],
      ['item-b', 2],
      ['item-b', 1],
    ]);
    // The counted-into row carries the LATEST edit's time: the window slides.
    expect(rows[1]!.timestamp.getTime()).toBe(RECENT_HOUR + 10 * HOUR + 59_999);
  });

  it('the window is inclusive: an edit exactly AUDIT_COALESCE_WINDOW_MS after the row is counted into it', async () => {
    const userId = new mongoose.Types.ObjectId().toString();
    const at = RECENT_HOUR + 11 * HOUR;
    installTestClock({ at });
    const edit = () =>
      createAuditLog(
        userId,
        'folder_reorder',
        { folderId: 'f', sortOrder: 1 },
        '198.51.100.3',
        'agent',
      );
    await edit();
    advanceClockBy(AUDIT_COALESCE_WINDOW_MS);
    await edit();
    advanceClockBy(AUDIT_COALESCE_WINDOW_MS + 1);
    await edit();
    const rows = await AuditLog.find({ userId }).sort({ timestamp: 1 }).lean();
    expect(rows.map((row) => [row.timestamp.getTime() - at, row.count])).toEqual([
      [AUDIT_COALESCE_WINDOW_MS, 2],
      [2 * AUDIT_COALESCE_WINDOW_MS + 1, 1],
    ]);
  });

  it('a coalescing write that fails costs the event nothing: it is recorded as a row of its own', async () => {
    const userId = new mongoose.Types.ObjectId().toString();
    const edit = () =>
      createAuditLog(userId, 'folder_reorder', { folderId: 'f', sortOrder: 1 }, 'ip', 'ua');
    await edit();
    vi.spyOn(AuditLog, 'updateOne').mockImplementation((() => {
      throw new Error('coalesce refused');
    }) as never);
    await edit();
    vi.restoreAllMocks();
    const rows = await AuditLog.find({ userId }).lean();
    expect(rows.map((row) => row.count)).toEqual([1, 1]);
  });

  it('the route id in either case names the same item, so the run still coalesces', async () => {
    const user = await createTestUser();
    const id = await createItem(user.accessToken);
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);
    await putItem(agent, csrf, user.accessToken, id, { favorite: true });
    await putItem(agent, csrf, user.accessToken, id.toUpperCase(), { favorite: false });

    const rows = await AuditLog.find({ userId: user.id, action: 'item_update' }).lean();
    expect(rows).toHaveLength(1);
    expect(rows[0]!.count).toBe(2);
    expect(rows[0]!.metadata).toMatchObject({ itemId: id });
  });

  it('folder_reorder coalesces per folder; actions outside the allowlist never do', async () => {
    const userId = new mongoose.Types.ObjectId().toString();
    for (let i = 0; i < 3; i++) {
      await createAuditLog(userId, 'folder_reorder', { folderId: 'f1', sortOrder: i }, 'ip', 'ua');
    }
    for (let i = 0; i < 3; i++) {
      await createAuditLog(userId, 'item_create', { itemId: 'i1', itemType: 'login' }, 'ip', 'ua');
    }
    for (let i = 0; i < 2; i++) {
      await createAuditLog(userId, 'document_update', { documentId: 'd1' }, 'ip', 'ua');
    }

    const reorder = await AuditLog.find({ userId, action: 'folder_reorder' }).lean();
    expect(reorder).toHaveLength(1);
    expect(reorder[0]!.count).toBe(3);
    // The counted-into row describes the newest reorder.
    expect(reorder[0]!.metadata).toEqual({ folderId: 'f1', sortOrder: 2 });
    expect(await AuditLog.countDocuments({ userId, action: 'item_create' })).toBe(3);
    expect(await AuditLog.countDocuments({ userId, action: 'document_update' })).toBe(2);
  });

  it('an update row with no content marker (written before the marker existed) is never coalesced', async () => {
    const userId = new mongoose.Types.ObjectId().toString();
    await createAuditLog(userId, 'folder_update', { folderId: 'g' }, 'ip', 'ua');
    await createAuditLog(userId, 'folder_update', { folderId: 'g' }, 'ip', 'ua');
    await createAuditLog(userId, 'item_update', { itemId: 'i' }, 'ip', 'ua');
    await createAuditLog(userId, 'item_update', { itemId: 'i' }, 'ip', 'ua');
    expect((await AuditLog.find({ userId }).lean()).map((row) => row.count)).toEqual([1, 1, 1, 1]);
  });

  it('a folder rename (ciphertext) is never coalesced; the metadata-only edits after it are', async () => {
    const userId = new mongoose.Types.ObjectId().toString();
    await createAuditLog(
      userId,
      'folder_update',
      { folderId: 'f', contentChanged: true },
      'ip',
      'ua',
    );
    await createAuditLog(
      userId,
      'folder_update',
      { folderId: 'f', contentChanged: true },
      'ip',
      'ua',
    );
    await createAuditLog(
      userId,
      'folder_update',
      { folderId: 'f', contentChanged: false },
      'ip',
      'ua',
    );
    await createAuditLog(
      userId,
      'folder_update',
      { folderId: 'f', contentChanged: false },
      'ip',
      'ua',
    );
    const rows = await AuditLog.find({ userId }).sort({ timestamp: 1, _id: 1 }).lean();
    expect(
      rows.map((row) => [(row.metadata as { contentChanged: boolean }).contentChanged, row.count]),
    ).toEqual([
      [true, 1],
      [true, 1],
      [false, 2],
    ]);
  });
});

// ── The security class ──────────────────────────────────────────────────────

describe('the security class is never coalesced and never trimmed (bar the stranger cap)', () => {
  it('classifies every action, and every stranger-writable action is security', () => {
    const classes: Record<string, string> = AUDIT_ACTION_CLASS;
    expect(Object.keys(classes).sort()).toEqual([...AUDIT_ACTIONS].sort());
    for (const action of AUDIT_ACTIONS) {
      expect(['security', 'activity']).toContain(classes[action]);
    }
    for (const action of STRANGER_WRITABLE_AUDIT_ACTIONS) {
      expect(classes[action]).toBe('security');
    }
    expect(classes['password_change']).toBe('security');
    expect(classes['login']).toBe('security');
    expect(classes['settings_update']).toBe('security');
    expect(classes['item_update']).toBe('activity');
    expect(classes['trash_auto_purge']).toBe('activity');
    // An irreversible bulk deletion behind the master password: never trimmed.
    expect(classes['unreadable_entries_purged']).toBe('security');
  });

  it('only activity actions are ever coalesced, and exactly the three the allowlist names', () => {
    const coalescible = Object.keys(COALESCE_TARGET).sort();
    expect(coalescible).toEqual(['folder_reorder', 'folder_update', 'item_update']);
    for (const action of coalescible) {
      expect(AUDIT_ACTION_CLASS[action as AuditAction]).toBe('activity');
    }
  });

  it('(c) 50 wrong-password rows of an unlocked account in distinct minutes stay 50 rows of one', async () => {
    const user = await createTestUser();
    installTestClock({ at: RECENT_HOUR + 8 * HOUR });
    for (let i = 0; i < 50; i++) {
      await createAuditLog(
        user.id,
        'login_failed',
        { reason: 'invalid_password' },
        SEED_IP,
        SEED_UA,
      );
      advanceClockBy(60_000);
    }
    uninstallTestClock();

    await runMaintenance();

    const rows = await AuditLog.find({ userId: user.id, action: 'login_failed' }).lean();
    expect(rows).toHaveLength(50);
    expect(rows.every((row) => row.count === 1)).toBe(true);
    expect(new Set(rows.map((row) => row.timestamp.getTime())).size).toBe(50);
  });

  it('(c) password_change rows survive a trim that removes older AND newer activity rows', async () => {
    const user = await createTestUser();
    const start = seedStart();
    // Security rows OLDER than every activity row: the first thing an age-ordered
    // trim that ignored the class would remove.
    await seedRows(
      new mongoose.Types.ObjectId(user.id),
      50,
      start - 60 * 60 * 1000,
      'password_change',
    );
    await seedRows(
      new mongoose.Types.ObjectId(user.id),
      MAX_ACTIVITY_AUDIT_ROWS_PER_USER + 500,
      start,
    );
    // And identical security rows written in the same second never merge either.
    for (let i = 0; i < 5; i++) {
      await createAuditLog(
        user.id,
        'password_change',
        { action: 'vault_key_rotation' },
        'ip',
        'ua',
      );
    }

    await runMaintenance();

    const security = await AuditLog.find({ userId: user.id, action: 'password_change' }).lean();
    expect(security).toHaveLength(55);
    expect(security.every((row) => row.count === 1)).toBe(true);
    expect(await activityCount(user.id)).toBe(MAX_ACTIVITY_AUDIT_ROWS_PER_USER);
  }, 120_000);
});

// ── The activity cap ────────────────────────────────────────────────────────

describe('the activity cap holds', () => {
  it('(d) the maintenance job keeps exactly the newest MAX activity rows and leaves another account alone', async () => {
    const owner = await createTestUser();
    const other = await createTestUser();
    const start = seedStart();
    const stamps = await seedRows(
      new mongoose.Types.ObjectId(owner.id),
      MAX_ACTIVITY_AUDIT_ROWS_PER_USER + 500,
      start,
    );
    await seedRows(new mongoose.Types.ObjectId(other.id), 600, start);

    await runMaintenance();

    expect(await activityCount(owner.id)).toBe(MAX_ACTIVITY_AUDIT_ROWS_PER_USER);
    const oldest = await AuditLog.findOne({ userId: owner.id }).sort({ timestamp: 1 }).lean();
    // Exactly the 500 oldest went: the survivor with the earliest time is the 501st seeded.
    expect(oldest!.timestamp.getTime()).toBe(stamps[500]);
    const newest = await AuditLog.findOne({ userId: owner.id }).sort({ timestamp: -1 }).lean();
    expect(newest!.timestamp.getTime()).toBe(stamps[stamps.length - 1]);
    // Negative: the other account, far under the cap, keeps every row.
    expect(await activityCount(other.id)).toBe(600);
    // And the job let go of its lock.
    expect(await JobLock.countDocuments({ jobName: 'maintenance' })).toBe(0);
  }, 120_000);

  it('(d) between runs, the hundredth activity insert of an account trims it', async () => {
    const userId = new mongoose.Types.ObjectId();
    await seedRows(userId, MAX_ACTIVITY_AUDIT_ROWS_PER_USER, seedStart());

    for (let i = 0; i < 99; i++) {
      await createAuditLog(
        userId.toString(),
        'item_update',
        { itemId: `live-${String(i)}`, itemType: 'login', contentChanged: true },
        'ip',
        'ua',
      );
    }
    // Not yet: sampling, not a trim per insert.
    expect(await activityCount(userId)).toBe(MAX_ACTIVITY_AUDIT_ROWS_PER_USER + 99);

    await createAuditLog(
      userId.toString(),
      'item_update',
      { itemId: 'live-99', itemType: 'login', contentChanged: true },
      'ip',
      'ua',
    );
    expect(await activityCount(userId)).toBe(MAX_ACTIVITY_AUDIT_ROWS_PER_USER);
    // The live rows are the newest, so every one of them survived.
    expect(await AuditLog.countDocuments({ userId, 'metadata.itemId': /^live-/ })).toBe(100);
  }, 120_000);

  it('a trim inside a request removes at most one batch; the hourly job removes the rest', async () => {
    const owner = await createTestUser();
    const userId = new mongoose.Types.ObjectId(owner.id);
    await seedRows(userId, MAX_ACTIVITY_AUDIT_ROWS_PER_USER + 6_000, seedStart());

    for (let i = 0; i < 100; i++) {
      await createAuditLog(
        owner.id,
        'item_update',
        { itemId: `live-${String(i)}`, itemType: 'login', contentChanged: true },
        'ip',
        'ua',
      );
    }
    // 6,100 over the cap; the sampled trim took one batch of 5,000.
    expect(await activityCount(userId)).toBe(MAX_ACTIVITY_AUDIT_ROWS_PER_USER + 1_100);

    await runMaintenance();
    expect(await activityCount(userId)).toBe(MAX_ACTIVITY_AUDIT_ROWS_PER_USER);
  }, 120_000);

  it('a row a JOB writes counts toward the same cap as a row a request writes', async () => {
    const userId = new mongoose.Types.ObjectId();
    await seedRows(userId, MAX_ACTIVITY_AUDIT_ROWS_PER_USER, seedStart());
    for (let i = 0; i < 99; i++) {
      await createAuditLog(
        userId.toString(),
        'item_update',
        { itemId: `live-${String(i)}`, itemType: 'login', contentChanged: true },
        'ip',
        'ua',
      );
    }

    // The trash purge writes this account's hundredth activity row itself.
    await recordJobAuditEntries([
      {
        userId: userId.toString(),
        action: 'trash_auto_purge',
        metadata: { itemCount: 1 },
        ipAddress: 'system',
        userAgent: 'system/trash-cleanup-job',
      },
    ]);

    expect(
      await AuditLog.countDocuments({
        userId,
        action: { $in: ['item_update', 'trash_auto_purge'] },
      }),
    ).toBe(MAX_ACTIVITY_AUDIT_ROWS_PER_USER);
    expect(await AuditLog.countDocuments({ userId, action: 'trash_auto_purge' })).toBe(1);
  }, 120_000);
});

// ── The maintenance job ─────────────────────────────────────────────────────

describe('the maintenance job', () => {
  it('is scheduled hourly at :15 UTC and its tick is tracked', async () => {
    const schedule = vi.mocked(cron.schedule);
    schedule.mockClear();
    const task = startMaintenanceJob();
    expect(schedule).toHaveBeenCalledTimes(1);
    expect(schedule).toHaveBeenCalledWith('15 * * * *', expect.any(Function), {
      timezone: 'UTC',
    });
    expect(task).toBe(schedule.mock.results[0]!.value);

    // The tick runs the job (here: nothing to trim) and resolves.
    const tick = schedule.mock.calls[0]![1] as () => Promise<void>;
    await expect(tick()).resolves.toBeUndefined();
    expect(await JobLock.countDocuments({ jobName: 'maintenance' })).toBe(0);
  });

  it('does nothing while another instance holds its lock', async () => {
    const user = await createTestUser();
    await seedRows(
      new mongoose.Types.ObjectId(user.id),
      MAX_ACTIVITY_AUDIT_ROWS_PER_USER + 5,
      seedStart(),
    );
    const held = await acquireJobLock('maintenance', 60_000);
    expect(held).not.toBeNull();

    await runMaintenance();
    expect(await activityCount(user.id)).toBe(MAX_ACTIVITY_AUDIT_ROWS_PER_USER + 5);

    await releaseJobLock('maintenance', held!);
    await runMaintenance();
    expect(await activityCount(user.id)).toBe(MAX_ACTIVITY_AUDIT_ROWS_PER_USER);
  }, 120_000);

  it('a failing step never stops the steps after it, and the lock is released', async () => {
    const after = vi.fn(() => Promise.resolve());
    await expect(
      runMaintenance([
        { name: 'boom', run: () => Promise.reject(new Error('step failed')) },
        { name: 'after', run: after },
      ]),
    ).resolves.toBeUndefined();
    expect(after).toHaveBeenCalledTimes(1);
    expect(await JobLock.countDocuments({ jobName: 'maintenance' })).toBe(0);
  });

  it('one account whose trim fails does not stop the others from being trimmed', async () => {
    const first = await createTestUser();
    const second = await createTestUser();
    const ids = [first.id, second.id].sort();
    await seedRows(
      new mongoose.Types.ObjectId(ids[0]),
      MAX_ACTIVITY_AUDIT_ROWS_PER_USER + 3,
      seedStart(),
    );
    await seedRows(
      new mongoose.Types.ObjectId(ids[1]),
      MAX_ACTIVITY_AUDIT_ROWS_PER_USER + 3,
      seedStart(),
    );

    const original = AuditLog.deleteMany.bind(AuditLog) as (...args: unknown[]) => unknown;
    let failed = false;
    vi.spyOn(AuditLog, 'deleteMany').mockImplementation(((...args: unknown[]) => {
      if (!failed) {
        failed = true;
        return Promise.reject(new Error('refused'));
      }
      return original(...args);
    }) as never);

    await runMaintenance();

    expect(failed).toBe(true);
    const counts = [await activityCount(ids[0]!), await activityCount(ids[1]!)];
    expect(counts).toContain(MAX_ACTIVITY_AUDIT_ROWS_PER_USER);
    expect(counts).toContain(MAX_ACTIVITY_AUDIT_ROWS_PER_USER + 3);
  }, 180_000);
});

describe('the per-process samplers when full', () => {
  it('the activity sampler forgets its oldest count instead of trimming every untracked account at once', async () => {
    for (let i = 0; i < AUDIT_TRIM_TRACKED_ACCOUNTS; i++) {
      await noteActivityInsert(`tracked-${String(i)}`);
    }
    const find = vi.spyOn(AuditLog, 'find');
    await noteActivityInsert(new mongoose.Types.ObjectId().toString());
    await noteActivityInsert(new mongoose.Types.ObjectId().toString());
    expect(find).not.toHaveBeenCalled();
  });

  it('the stranger sampler, full, still trims an untracked account at once', async () => {
    for (let i = 0; i < AUDIT_TRIM_TRACKED_ACCOUNTS; i++) {
      await noteStrangerWritableInsert(`tracked-${String(i)}`);
    }
    const find = vi.spyOn(AuditLog, 'find');
    await noteStrangerWritableInsert(new mongoose.Types.ObjectId().toString());
    expect(find).toHaveBeenCalledTimes(1);
  });

  it('a backlog far over the cap is removed in several bounded deletes, down to exactly the cap', async () => {
    const userId = new mongoose.Types.ObjectId();
    await seedRows(userId, MAX_ACTIVITY_AUDIT_ROWS_PER_USER + 12_000, seedStart());
    const deletes = vi.spyOn(AuditLog, 'deleteMany');
    expect(await trimActivityAuditRows(userId.toString())).toBe(12_000);
    expect(deletes.mock.calls.length).toBeGreaterThanOrEqual(3);
    expect(await activityCount(userId)).toBe(MAX_ACTIVITY_AUDIT_ROWS_PER_USER);
  }, 120_000);
});

describe('the audit trim walk', () => {
  it('pauses at its time budget and the next run carries on from the account after', async () => {
    const [a, b] = [await createTestUser(), await createTestUser()].sort((x, y) =>
      x.id < y.id ? -1 : 1,
    );
    await seedRows(
      new mongoose.Types.ObjectId(a!.id),
      MAX_ACTIVITY_AUDIT_ROWS_PER_USER + 2,
      seedStart(),
    );
    await seedRows(
      new mongoose.Types.ObjectId(b!.id),
      MAX_ACTIVITY_AUDIT_ROWS_PER_USER + 2,
      seedStart(),
    );

    await trimEveryAccountsAuditLog(0);
    expect(await activityCount(a!.id)).toBe(MAX_ACTIVITY_AUDIT_ROWS_PER_USER);
    expect(await activityCount(b!.id)).toBe(MAX_ACTIVITY_AUDIT_ROWS_PER_USER + 2);

    await trimEveryAccountsAuditLog(0);
    expect(await activityCount(b!.id)).toBe(MAX_ACTIVITY_AUDIT_ROWS_PER_USER);
  }, 180_000);

  it('stops after a run of accounts that all fail, rather than walking every account to log errors', async () => {
    for (let i = 0; i < 7; i++) await createTestUser();
    const find = vi.spyOn(AuditLog, 'find').mockImplementation((() => {
      throw new Error('database refusing');
    }) as never);
    await expect(trimEveryAccountsAuditLog()).resolves.toBeUndefined();
    // Two trims per account, five accounts, then the breaker.
    expect(find).toHaveBeenCalledTimes(10);
  });
});

describe('the job writer', () => {
  it('writes nothing for an empty batch', async () => {
    const insert = vi.spyOn(AuditLog, 'insertMany');
    await expect(recordJobAuditEntries([])).resolves.toBeUndefined();
    expect(insert).not.toHaveBeenCalled();
  });

  it('THROWS when the insert fails, so a purge stops rather than going on unrecorded', async () => {
    vi.spyOn(AuditLog, 'insertMany').mockImplementation((() =>
      Promise.reject(new Error('datastore refused'))) as never);
    await expect(
      recordJobAuditEntries([
        {
          userId: new mongoose.Types.ObjectId().toString(),
          action: 'trash_auto_purge',
          metadata: { itemCount: 1 },
          ipAddress: 'system',
          userAgent: 'system/trash-cleanup-job',
        },
      ]),
    ).rejects.toThrow('datastore refused');
  });

  it('stamps one time on every row of a batch, and a system row (no account) counts toward nothing', async () => {
    const userId = new mongoose.Types.ObjectId();
    await recordJobAuditEntries([
      {
        userId: userId.toString(),
        action: 'document_purge',
        metadata: { documentCount: 2 },
        ipAddress: 'system',
        userAgent: 'system/document-cleanup-job',
      },
      {
        userId: null,
        action: 'deletion_cleanup',
        metadata: { note: 'system' },
        ipAddress: 'system',
        userAgent: 'system/token-cleanup-job',
      },
    ]);
    const rows = await AuditLog.find({}).lean();
    expect(rows).toHaveLength(2);
    expect(rows[0]!.timestamp.getTime()).toBe(rows[1]!.timestamp.getTime());
    expect(rows.map((row) => row.count)).toEqual([1, 1]);
  });
});

describe('the maintenance job survives its own plumbing failing', () => {
  it('resolves, having done nothing, when the lock cannot be read', async () => {
    const user = await createTestUser();
    await seedRows(new mongoose.Types.ObjectId(user.id), 10, seedStart());
    vi.spyOn(JobLock, 'findOneAndUpdate').mockImplementation((() =>
      Promise.reject(new Error('lock store down'))) as never);
    const step = vi.fn(() => Promise.resolve());
    await expect(runMaintenance([{ name: 'never', run: step }])).resolves.toBeUndefined();
    expect(step).not.toHaveBeenCalled();
  });

  it('resolves when releasing the lock fails, after running every step', async () => {
    vi.spyOn(JobLock, 'deleteOne').mockImplementation((() =>
      Promise.reject(new Error('release refused'))) as never);
    const step = vi.fn(() => Promise.resolve());
    await expect(runMaintenance([{ name: 'ran', run: step }])).resolves.toBeUndefined();
    expect(step).toHaveBeenCalledTimes(1);
  });
});

// ── Index-served pages ──────────────────────────────────────────────────────

describe('both audit-log page sorts are served by an index', () => {
  interface ProfileEntry {
    op?: string;
    ns?: string;
    command?: { find?: string; filter?: Record<string, unknown> };
    hasSortStage?: boolean;
    planSummary?: string;
  }

  async function profiledFinds(run: () => Promise<void>): Promise<ProfileEntry[]> {
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
      .find({ 'command.find': 'audit_logs' })
      .toArray()) as ProfileEntry[];
    await db
      .collection('system.profile')
      .drop()
      .catch(() => undefined);
    return entries;
  }

  it('(e) the unfiltered page and the page filtered by action explain with no SORT stage', async () => {
    const user = await createTestUser();
    const userId = new mongoose.Types.ObjectId(user.id);
    const start = seedStart();
    await seedRows(userId, 300, start, 'item_update');
    await seedRows(userId, 300, start, 'login');
    // Ties on timestamp are the normal case (an import stamps many rows at once).
    await seedRows(userId, 50, start, 'folder_create');

    const entries = await profiledFinds(async () => {
      await request(app)
        .get('/api/v1/user/audit-log?page=2&limit=20')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);
      await request(app)
        .get('/api/v1/user/audit-log?page=3&limit=20&action=login')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);
    });

    const unfiltered = entries.find((entry) => entry.command?.filter?.['action'] === undefined);
    const filtered = entries.find((entry) => entry.command?.filter?.['action'] === 'login');
    expect(unfiltered).toBeDefined();
    expect(filtered).toBeDefined();
    expect(unfiltered!.hasSortStage ?? false).toBe(false);
    expect(filtered!.hasSortStage ?? false).toBe(false);
    expect(unfiltered!.planSummary).toContain('IXSCAN { userId: 1, timestamp: -1, _id: -1 }');
    expect(filtered!.planSummary).toContain(
      'IXSCAN { userId: 1, action: 1, timestamp: -1, _id: -1 }',
    );
  });
});

// ── Migration v2 ────────────────────────────────────────────────────────────

describe('migration v2 drops the superseded audit indexes', () => {
  const OLD = ['userId_1_timestamp_-1', 'userId_1_action_1_timestamp_-1'];
  const NEW = ['userId_1_timestamp_-1__id_-1', 'userId_1_action_1_timestamp_-1__id_-1'];

  async function indexNames(): Promise<string[]> {
    const indexes = await AuditLog.collection.indexes();
    return indexes.map((index) => String(index.name));
  }

  async function seedOldIndexes(): Promise<void> {
    await AuditLog.collection.createIndex({ userId: 1, timestamp: -1 }, { name: OLD[0]! });
    await AuditLog.collection.createIndex(
      { userId: 1, action: 1, timestamp: -1 },
      { name: OLD[1]! },
    );
  }

  beforeEach(async () => {
    await JobLock.createIndexes();
    await Migration.createIndexes();
  });

  afterEach(async () => {
    // Put the model's own indexes back for whatever runs next in this file.
    await AuditLog.createIndexes();
  });

  it('(f) drops both old indexes on a populated collection, builds the new ones, and is idempotent', async () => {
    await seedRows(new mongoose.Types.ObjectId(), 100, seedStart());
    await seedOldIndexes();
    expect(await indexNames()).toEqual(expect.arrayContaining(OLD));

    await runMigrations();
    const after = await indexNames();
    for (const name of OLD) expect(after).not.toContain(name);
    expect(after).toEqual(expect.arrayContaining(NEW));
    expect(await Migration.countDocuments({ version: 2 })).toBe(1);
    // Negative: the data and the other indexes are untouched.
    expect(await AuditLog.countDocuments({})).toBe(100);
    expect(after).toContain('timestamp_1');

    // Run again: a recorded migration is skipped...
    await runMigrations();
    expect(await Migration.countDocuments({ version: 2 })).toBe(1);
    // ...and re-applying it (as a crashed boot that never recorded it would) is a no-op.
    await Migration.deleteMany({ version: 2 });
    await runMigrations();
    expect(await indexNames()).toEqual(after);
    expect(await Migration.countDocuments({ version: 2 })).toBe(1);
  });

  it('rewrites every legacy erasure record to a masked address, once', async () => {
    await AuditLog.collection.insertMany([
      {
        userId: null,
        action: 'account_delete',
        metadata: { deletedUserId: 'u1', deletedEmail: 'jane.doe@example.org' },
        ipAddress: 'ip',
        userAgent: 'ua',
        timestamp: new Date(),
        count: 1,
      },
      {
        userId: null,
        action: 'deletion_cleanup',
        metadata: { deletedUserId: 'u2', deletedEmail: 'a@example.org' },
        ipAddress: 'ip',
        userAgent: 'ua',
        timestamp: new Date(),
        count: 1,
      },
      // Negative: not an erasure record; its metadata is not touched.
      {
        userId: new mongoose.Types.ObjectId(),
        action: 'registration',
        metadata: { deletedEmail: 'keep@example.org' },
        ipAddress: 'ip',
        userAgent: 'ua',
        timestamp: new Date(),
        count: 1,
      },
    ]);

    await runMigrations();
    await Migration.deleteMany({ version: 2 });
    await runMigrations(); // again: a one-character local part must not be masked twice

    const records = await AuditLog.find({ userId: null }).sort({ action: 1 }).lean();
    expect(records.map((row) => row.metadata)).toEqual([
      { deletedUserId: 'u1', maskedEmail: maskEmail('jane.doe@example.org') },
      { deletedUserId: 'u2', maskedEmail: maskEmail('a@example.org') },
    ]);
    expect(JSON.stringify(records)).not.toContain('jane.doe');
    const other = await AuditLog.findOne({ action: 'registration' }).lean();
    expect(other!.metadata).toEqual({ deletedEmail: 'keep@example.org' });
  });

  it('accepts a page index an operator already built under another name', async () => {
    await AuditLog.collection.dropIndex('userId_1_timestamp_-1__id_-1').catch(() => undefined);
    await AuditLog.collection.createIndex(
      { userId: 1, timestamp: -1, _id: -1 },
      { name: 'operator_built' },
    );
    await seedOldIndexes();
    await expect(runMigrations()).resolves.toBeUndefined();
    const names = await indexNames();
    expect(names).toContain('operator_built');
    for (const name of OLD) expect(names).not.toContain(name);
    await AuditLog.collection.dropIndex('operator_built');
  });

  it('an unexpected index-build failure aborts v2: nothing dropped, nothing recorded', async () => {
    await seedOldIndexes();
    // Refused for the audit collection only: the lock indexes the runner builds
    // first must succeed, or the failure would come from there instead of v2.
    const collection = mongoose.connection.collection('audit_logs');
    const proto = Object.getPrototypeOf(collection) as {
      createIndex: (this: { collectionName: string }, ...args: unknown[]) => unknown;
    };
    const originalCreateIndex = proto.createIndex;
    let refused = 0;
    vi.spyOn(proto, 'createIndex').mockImplementation(function (
      this: { collectionName: string },
      ...args: unknown[]
    ) {
      if (this.collectionName === 'audit_logs' && refused === 0) {
        refused += 1;
        return Promise.reject(Object.assign(new Error('not authorized'), { code: 13 }));
      }
      return originalCreateIndex.apply(this, args);
    });

    await expect(runMigrations()).rejects.toThrow('not authorized');
    vi.restoreAllMocks();
    expect(refused).toBe(1);
    expect(await Migration.countDocuments({ version: 2 })).toBe(0);
    expect(await indexNames()).toEqual(expect.arrayContaining(OLD));
  });

  it('an unexpected index-drop failure aborts v2 unrecorded, so the next boot retries it', async () => {
    await seedOldIndexes();
    const collection = mongoose.connection.collection('audit_logs');
    vi.spyOn(
      Object.getPrototypeOf(collection) as { dropIndex: () => unknown },
      'dropIndex',
    ).mockRejectedValueOnce(Object.assign(new Error('not authorized'), { code: 13 }));

    await expect(runMigrations()).rejects.toThrow('not authorized');
    vi.restoreAllMocks();
    expect(await Migration.countDocuments({ version: 2 })).toBe(0);

    await runMigrations();
    expect(await Migration.countDocuments({ version: 2 })).toBe(1);
    for (const name of OLD) expect(await indexNames()).not.toContain(name);
  });

  it('(f) tolerates a collection that does not exist yet', async () => {
    await AuditLog.collection.drop().catch(() => undefined);
    await expect(runMigrations()).resolves.toBeUndefined();
    expect(await Migration.countDocuments({ version: 2 })).toBe(1);
    const names = await indexNames();
    for (const name of OLD) expect(names).not.toContain(name);
    expect(names).toEqual(expect.arrayContaining(NEW));
  });
});

// Keeps the model registered for the per-file index build in `setup.ts`.
void VaultItem;
