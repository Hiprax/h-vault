import { describe, it, expect, vi, beforeEach, beforeAll, afterAll } from 'vitest';
import mongoose from 'mongoose';
import crypto from 'node:crypto';
import { MongoMemoryReplSet } from 'mongodb-memory-server';

/**
 * Coverage-driven suite for the cascade-delete util and the three cron jobs.
 *
 * The behaviours exercised here are the ones the existing suites structurally
 * cannot reach:
 *
 *  - `cascadeDelete`'s REAL transactional branch (the standalone in-memory
 *    server always takes the sequential fallback, so `withTransaction`'s body —
 *    including the atomic abort that must leave NO orphan audit row — was never
 *    executed). A `MongoMemoryReplSet` is stood up for it, mirroring
 *    `tests/vault-rotation-transaction.test.ts`.
 *  - `cascadeDelete`'s sequential FAILURE path (returns false, re-asserts
 *    `deletionPending` so the zombie cleanup retries, writes no audit row).
 *  - `backupScheduler.processUserBackup`'s error/edge paths: the folder-cursor
 *    size abort, the final serialized-buffer guard (the backstop for an
 *    under-counting incremental estimate), partial email-failure tolerance, a
 *    thrown send (outer catch) that must not take down the other users in the
 *    batch, a bookkeeping failure after a successful send, and the >5-user
 *    batch flush.
 *  - `tokenCleanup`'s `usedAt: null` deletion rule.
 *  - `trashCleanup`'s multi-batch (BATCH_SIZE = 500) loop.
 */

// ── Mocks (file-scoped, hoisted) ─────────────────────────────────────────────

vi.mock('node-cron', () => ({
  default: {
    schedule: vi.fn().mockReturnValue({ stop: vi.fn() }),
  },
}));

vi.mock('../src/utils/email.js', async (importOriginal) => {
  const original = await importOriginal<typeof import('../src/utils/email.js')>();
  return {
    ...original,
    sendEmail: vi.fn().mockResolvedValue({ success: true, message: 'Email sent successfully.' }),
  };
});

/**
 * The size estimators delegate to the real implementation unless a test opts
 * into an override. One test needs the estimator to UNDER-count so the final
 * serialized-buffer guard (the backstop that catches exactly that case) is the
 * thing that fires.
 */
const { sizeOverride } = vi.hoisted(() => ({
  sizeOverride: { item: null as null | (() => number), folder: null as null | (() => number) },
}));

vi.mock('../src/utils/sizeEstimator.js', async (importOriginal) => {
  const orig = await importOriginal<typeof import('../src/utils/sizeEstimator.js')>();
  return {
    estimateItemJsonSize: (item: Record<string, unknown>): number =>
      sizeOverride.item ? sizeOverride.item() : orig.estimateItemJsonSize(item),
    estimateFolderJsonSize: (folder: Record<string, unknown>): number =>
      sizeOverride.folder ? sizeOverride.folder() : orig.estimateFolderJsonSize(folder),
  };
});

import cron from 'node-cron';
import { User } from '../src/models/User.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { BackupLog } from '../src/models/BackupLog.js';
import { config } from '../src/config/index.js';
import { cascadeDeleteUser, supportsTransactions } from '../src/utils/cascadeDelete.js';
import { startBackupScheduler } from '../src/jobs/backupScheduler.js';
import { startTokenCleanupJob } from '../src/jobs/tokenCleanup.js';
import { startTrashCleanupJob } from '../src/jobs/trashCleanup.js';
import { sendEmail } from '../src/utils/email.js';
import { createTestUser, sampleVaultItem, sampleFolder } from './helpers.js';

const mockedSchedule = vi.mocked(cron.schedule);
const mockedSendEmail = vi.mocked(sendEmail);

function getScheduledCallback(): () => Promise<void> {
  const calls = mockedSchedule.mock.calls;
  return calls[calls.length - 1]![1] as () => Promise<void>;
}

interface SeededBackupUser {
  _id: mongoose.Types.ObjectId;
  email: string;
}

async function createBackupUser(backup: Record<string, unknown> = {}): Promise<SeededBackupUser> {
  const user = await User.create({
    email: `sched-${crypto.randomUUID()}@example.com`,
    authHash: '$2a$04$fakehashfakehashfakehashfakehashfakehashfakehashfake',
    emailVerified: true,
    encryptedVaultKey: 'test-encrypted-vault-key',
    vaultKeyIv: 'test-vault-key-iv',
    vaultKeyTag: 'test-vault-key-tag',
    kdfIterations: 600_000,
    kdfAlgorithm: 'PBKDF2-SHA256',
    encryptionVersion: 1,
    settings: {
      backup: {
        enabled: true,
        scheduleHour: new Date().getUTCHours(),
        encryptedBWK: 'test-encrypted-bwk',
        bwkIv: 'test-bwk-iv',
        bwkTag: 'test-bwk-tag',
        bwkSalt: 'test-bwk-salt',
        isConfigured: true,
        ...backup,
      },
    },
  });
  return { _id: user._id, email: user.email };
}

beforeEach(() => {
  vi.restoreAllMocks();
  mockedSchedule.mockReturnValue({ stop: vi.fn() } as unknown as ReturnType<typeof cron.schedule>);
  mockedSendEmail.mockReset();
  mockedSendEmail.mockResolvedValue({ success: true, message: 'Email sent successfully.' });
  sizeOverride.item = null;
  sizeOverride.folder = null;
});

// ─── cascadeDelete: sequential failure path ──────────────────────────────────

describe('cascadeDeleteUser — sequential failure path (standalone)', () => {
  it('returns false, keeps the user, re-asserts deletionPending and writes NO audit row', async () => {
    const target = await createTestUser();
    const bystander = await createTestUser();
    await VaultItem.create({ ...sampleVaultItem(), userId: bystander.id });

    // The flag is normally already set by the caller; clear it so the re-set in
    // the catch block is load-bearing rather than a no-op.
    await User.updateOne({ _id: target.id }, { $set: { deletionPending: false } });

    // Fail midway through the sequence: items are already gone, folders are not.
    const folderSpy = vi
      .spyOn(Folder, 'deleteMany')
      .mockRejectedValueOnce(new Error('connection reset during cascade'));

    const result = await cascadeDeleteUser({
      userId: target.id,
      userEmail: target.email,
      ip: '127.0.0.1',
      userAgent: 'test-agent',
      auditAction: 'deletion_cleanup',
    });

    folderSpy.mockRestore();

    expect(result).toBe(false);

    // The user survives AND is flagged for retry — the zombie sweep must be
    // able to find it again on the next cycle.
    const userAfter = await User.findById(target.id).lean();
    expect(userAfter).not.toBeNull();
    expect(userAfter!.deletionPending).toBe(true);

    // The cascade aborted before the audit write, so no "erased" event was
    // logged for an erasure that did not happen.
    const logs = await AuditLog.find({ action: 'deletion_cleanup' }).lean();
    expect(logs).toHaveLength(0);

    // Cross-user isolation: the bystander is untouched.
    expect(await User.findById(bystander.id)).not.toBeNull();
    expect(await VaultItem.countDocuments({ userId: bystander.id })).toBe(1);
  });

  it('does not throw when the deletionPending re-set itself fails', async () => {
    const target = await createTestUser();

    const folderSpy = vi
      .spyOn(Folder, 'deleteMany')
      .mockRejectedValueOnce(new Error('cascade blew up'));
    const updateSpy = vi
      .spyOn(User, 'updateOne')
      .mockRejectedValueOnce(new Error('re-set also failed'));

    const result = await cascadeDeleteUser({
      userId: target.id,
      userEmail: target.email,
      ip: '127.0.0.1',
      userAgent: 'test-agent',
      auditAction: 'deletion_cleanup',
    });

    folderSpy.mockRestore();
    updateSpy.mockRestore();

    // The inner failure must be swallowed: the caller only learns the cascade
    // did not complete.
    expect(result).toBe(false);
    expect(await User.findById(target.id)).not.toBeNull();
  });
});

// ─── backupScheduler: processUserBackup edge/error paths ─────────────────────

describe('backupScheduler — processUserBackup edge and error paths', () => {
  it('aborts during FOLDER streaming when the shared size budget is blown', async () => {
    startBackupScheduler();
    const callback = getScheduledCallback();

    const user = await createBackupUser();
    await Folder.create({ ...sampleFolder(), userId: user._id });
    await VaultItem.create({ ...sampleVaultItem(), userId: user._id });

    const original = config.BACKUP_MAX_SIZE_MB;
    try {
      // Any non-empty folder blows a zero budget, so the abort must happen in
      // the folder loop — before a single item is ever streamed.
      (config as { BACKUP_MAX_SIZE_MB: number }).BACKUP_MAX_SIZE_MB = 0;
      await callback();
    } finally {
      (config as { BACKUP_MAX_SIZE_MB: number }).BACKUP_MAX_SIZE_MB = original;
    }

    expect(mockedSendEmail).not.toHaveBeenCalled();

    const logs = await BackupLog.find({ userId: user._id }).lean();
    expect(logs).toHaveLength(1);
    expect(logs[0]!.status).toBe('failed');
    expect(logs[0]!.errorMessage).toMatch(/exceeds maximum size/i);
    expect(logs[0]!.sentTo).toEqual([user.email]);
  });

  it('rejects an oversized backup at the final buffer check when the estimate under-counts', async () => {
    startBackupScheduler();
    const callback = getScheduledCallback();

    const user = await createBackupUser();
    await VaultItem.create({ ...sampleVaultItem(), userId: user._id });

    // Force the incremental estimator to under-count (0 bytes/row) so both
    // streaming guards pass. The serialized payload — envelope + row — is far
    // larger than the 200-byte budget, so ONLY the final buffer-length guard
    // can catch it. Deleting that guard would let an oversized attachment ship.
    sizeOverride.item = () => 0;
    sizeOverride.folder = () => 0;

    const original = config.BACKUP_MAX_SIZE_MB;
    try {
      (config as { BACKUP_MAX_SIZE_MB: number }).BACKUP_MAX_SIZE_MB = 200 / (1024 * 1024);
      await callback();
    } finally {
      (config as { BACKUP_MAX_SIZE_MB: number }).BACKUP_MAX_SIZE_MB = original;
    }

    expect(mockedSendEmail).not.toHaveBeenCalled();

    const logs = await BackupLog.find({ userId: user._id }).lean();
    expect(logs).toHaveLength(1);
    expect(logs[0]!.status).toBe('failed');
    expect(logs[0]!.errorMessage).toMatch(/exceeds maximum size/i);
  });

  it('tolerates a PARTIAL email failure: logs success with the failed recipient recorded', async () => {
    startBackupScheduler();
    const callback = getScheduledCallback();

    const good = 'good-recipient@example.com';
    const bad = 'bad-recipient@example.com';
    const user = await createBackupUser({ backupEmails: [good, bad] });
    await VaultItem.create({ ...sampleVaultItem(), userId: user._id });

    mockedSendEmail.mockImplementation(async (to: string) =>
      to === bad
        ? { success: false, message: 'smtp_send_failed: mailbox unavailable' }
        : { success: true, message: 'Email sent successfully.' },
    );

    await callback();

    expect(mockedSendEmail).toHaveBeenCalledTimes(2);

    // At least one delivery succeeded → the backup itself is a success, but the
    // failed recipient must be recorded rather than silently dropped.
    const logs = await BackupLog.find({ userId: user._id }).lean();
    expect(logs).toHaveLength(1);
    expect(logs[0]!.status).toBe('success');
    expect(logs[0]!.sentTo).toEqual([good, bad]);
    expect(logs[0]!.errorMessage).toContain(bad);
    expect(logs[0]!.errorMessage).not.toContain(good);
    expect(logs[0]!.itemCount).toBe(1);

    const updated = await User.findById(user._id).lean();
    expect(updated!.settings.backup.lastBackupStatus).toBe('success');
  });

  it('contains a THROWN send for one user and still backs up the others in the batch', async () => {
    startBackupScheduler();
    const callback = getScheduledCallback();

    const doomed = await createBackupUser();
    const healthy = await createBackupUser();
    await VaultItem.create({ ...sampleVaultItem(), userId: doomed._id });
    await VaultItem.create({ ...sampleVaultItem(), userId: healthy._id });

    mockedSendEmail.mockImplementation(async (to: string) => {
      if (to === doomed.email) throw new Error('transport exploded');
      return { success: true, message: 'Email sent successfully.' };
    });

    // The job promise must resolve — a rejection escalates to process.exit(1)
    // via the server's unhandledRejection hook.
    await expect(callback()).resolves.toBeUndefined();

    const doomedLogs = await BackupLog.find({ userId: doomed._id }).lean();
    expect(doomedLogs).toHaveLength(1);
    expect(doomedLogs[0]!.status).toBe('failed');
    expect(doomedLogs[0]!.errorMessage).toBe('Backup processing failed');
    const doomedUser = await User.findById(doomed._id).lean();
    expect(doomedUser!.settings.backup.lastBackupStatus).toBe('failed');

    // Promise.allSettled per batch: one user's blow-up must not starve the rest.
    const healthyLogs = await BackupLog.find({ userId: healthy._id }).lean();
    expect(healthyLogs).toHaveLength(1);
    expect(healthyLogs[0]!.status).toBe('success');
    const healthyUser = await User.findById(healthy._id).lean();
    expect(healthyUser!.settings.backup.lastBackupStatus).toBe('success');
  });

  it('marks the user FAILED when the success bookkeeping write fails after a delivered email', async () => {
    startBackupScheduler();
    const callback = getScheduledCallback();

    const user = await createBackupUser();
    await VaultItem.create({ ...sampleVaultItem(), userId: user._id });

    // Reject only the success BackupLog write; the outer catch's failure log
    // (a second create) still has to go through.
    const createSpy = vi
      .spyOn(BackupLog, 'create')
      .mockRejectedValueOnce(new Error('backuplog write failed'));

    await expect(callback()).resolves.toBeUndefined();
    createSpy.mockRestore();

    expect(mockedSendEmail).toHaveBeenCalledTimes(1);

    // The user's status must never read "success" when the run did not fully
    // complete — a stale success would hide a broken backup pipeline.
    const updated = await User.findById(user._id).lean();
    expect(updated!.settings.backup.lastBackupStatus).toBe('failed');

    const logs = await BackupLog.find({ userId: user._id }).lean();
    expect(logs).toHaveLength(1);
    expect(logs[0]!.status).toBe('failed');
    expect(logs[0]!.errorMessage).toBe('Backup processing failed');
  });

  it('does not reject when even the best-effort failure bookkeeping fails', async () => {
    startBackupScheduler();
    const callback = getScheduledCallback();

    const user = await createBackupUser();
    await VaultItem.create({ ...sampleVaultItem(), userId: user._id });

    mockedSendEmail.mockRejectedValue(new Error('transport exploded'));
    const createSpy = vi
      .spyOn(BackupLog, 'create')
      .mockRejectedValue(new Error('backuplog collection unavailable'));
    const updateSpy = vi
      .spyOn(User, 'findByIdAndUpdate')
      .mockRejectedValue(new Error('user update unavailable'));

    // Every recovery write fails; the job still has to resolve cleanly.
    await expect(callback()).resolves.toBeUndefined();

    createSpy.mockRestore();
    updateSpy.mockRestore();

    // And the lock is released so the next hourly tick can run at all.
    const { JobLock } = await import('../src/models/JobLock.js');
    expect(await JobLock.findOne({ jobName: 'backup-scheduler' })).toBeNull();
  });

  it('processes MORE users than the batch size (flushes a full batch, then the remainder)', async () => {
    startBackupScheduler();
    const callback = getScheduledCallback();

    // batchSize is 5: 6 users exercises the mid-loop flush AND the final
    // partial batch. A dropped remainder would silently skip a user's backup.
    const users: SeededBackupUser[] = [];
    for (let i = 0; i < 6; i++) {
      const u = await createBackupUser();
      await VaultItem.create({ ...sampleVaultItem(), userId: u._id });
      users.push(u);
    }

    await callback();

    expect(mockedSendEmail).toHaveBeenCalledTimes(6);
    const recipients = mockedSendEmail.mock.calls.map((c) => c[0]);
    expect(new Set(recipients)).toEqual(new Set(users.map((u) => u.email)));

    const logs = await BackupLog.find({}).lean();
    expect(logs).toHaveLength(6);
    expect(logs.every((l) => l.status === 'success')).toBe(true);
  });
});

// ─── tokenCleanup: usedAt: null rule ─────────────────────────────────────────

describe('tokenCleanup — expired token with an explicit usedAt: null', () => {
  it('deletes an expired token whose usedAt is null (not merely absent)', async () => {
    startTokenCleanupJob();
    const callback = getScheduledCallback();

    const userId = new mongoose.Types.ObjectId();
    const base = {
      userId,
      familyId: crypto.randomUUID(),
      deviceInfo: { userAgent: 'test-agent', ip: '127.0.0.1', fingerprint: 'fp' },
    };

    // `usedAt: null` is what an explicit un-set writes; the cleanup's $or must
    // treat it exactly like an absent field, otherwise these never get reaped.
    const expiredNullUsed = await RefreshToken.create({
      ...base,
      tokenHash: crypto.randomBytes(32).toString('hex'),
      usedAt: null,
      expiresAt: new Date(Date.now() - 60_000),
    });
    const liveNullUsed = await RefreshToken.create({
      ...base,
      tokenHash: crypto.randomBytes(32).toString('hex'),
      usedAt: null,
      expiresAt: new Date(Date.now() + 60 * 60_000),
    });

    await callback();

    const remaining = await RefreshToken.find({}).lean();
    expect(remaining.map((t) => String(t._id))).toEqual([String(liveNullUsed._id)]);
    expect(await RefreshToken.findById(expiredNullUsed._id)).toBeNull();
  });
});

// ─── trashCleanup: multi-batch loop ──────────────────────────────────────────

describe('trashCleanup — multi-batch purge', () => {
  it('loops past the 500-item batch limit and audits EVERY batch', async () => {
    startTrashCleanupJob();
    const callback = getScheduledCallback();

    const heavyUser = new mongoose.Types.ObjectId();
    const lightUser = new mongoose.Types.ObjectId();
    const purgeAt = new Date(Date.now() - 40 * 24 * 60 * 60 * 1000);

    // 505 > BATCH_SIZE (500) forces a second loop iteration. A broken
    // `while (deletedCount === BATCH_SIZE)` condition would leave the overflow
    // rows in the trash forever.
    await VaultItem.insertMany(
      Array.from({ length: 505 }, () => ({
        ...sampleVaultItem(),
        userId: heavyUser,
        deletedAt: purgeAt,
      })),
    );
    await VaultItem.insertMany(
      Array.from({ length: 3 }, () => ({
        ...sampleVaultItem(),
        userId: lightUser,
        deletedAt: purgeAt,
      })),
    );
    // Recently trashed → must survive.
    const keeper = await VaultItem.create({
      ...sampleVaultItem(),
      userId: lightUser,
      deletedAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000),
    });

    await callback();

    expect(await VaultItem.countDocuments({ userId: heavyUser })).toBe(0);
    const lightRemaining = await VaultItem.find({ userId: lightUser }).lean();
    expect(lightRemaining.map((i) => String(i._id))).toEqual([String(keeper._id)]);

    // Audit rows are written per batch, so the heavy user gets one per batch and
    // their itemCounts must add up to everything that was actually purged.
    const heavyLogs = await AuditLog.find({
      userId: heavyUser,
      action: 'trash_auto_purge',
    }).lean();
    expect(heavyLogs.length).toBeGreaterThan(1);
    const heavyTotal = heavyLogs.reduce(
      (sum, l) => sum + (l.metadata as { itemCount: number }).itemCount,
      0,
    );
    expect(heavyTotal).toBe(505);

    const lightLogs = await AuditLog.find({
      userId: lightUser,
      action: 'trash_auto_purge',
    }).lean();
    expect(lightLogs).toHaveLength(1);
    expect((lightLogs[0]!.metadata as { itemCount: number }).itemCount).toBe(3);
  }, 60_000);
});

// ─── cascadeDelete: the REAL transactional branch (replica set) ──────────────
//
// Declared last on purpose: its beforeAll swaps the process-wide mongoose
// connection from the standalone in-memory server (tests/setup.ts) to a
// single-node replica set, which is the only topology where
// `supportsTransactions()` is true and `withTransaction` actually runs.

describe('cascadeDeleteUser — transactional branch (replica set)', () => {
  let replSet: MongoMemoryReplSet;

  beforeAll(async () => {
    await mongoose.disconnect();
    replSet = await MongoMemoryReplSet.create({
      replSet: { count: 1, storageEngine: 'wiredTiger' },
    });
    await mongoose.connect(replSet.getUri());
    await Promise.all(Object.values(mongoose.models).map((m) => m.createIndexes()));

    // Sanity guard: without this the suite would silently assert the sequential
    // fallback and prove nothing about the transactional path.
    expect(supportsTransactions()).toBe(true);
  }, 90_000);

  afterAll(async () => {
    await mongoose.disconnect();
    await replSet.stop();
  });

  it('erases every collection atomically and leaves other users untouched', async () => {
    const target = await createTestUser();
    const bystander = await createTestUser();

    await VaultItem.create({ ...sampleVaultItem(), userId: target.id });
    await Folder.create({ ...sampleFolder(), userId: target.id });
    await AuditLog.create({
      userId: target.id,
      action: 'login',
      ipAddress: '127.0.0.1',
      userAgent: 'test',
    });
    await BackupLog.create({ userId: target.id, status: 'success', sentTo: [target.email] });

    await VaultItem.create({ ...sampleVaultItem(), userId: bystander.id });
    await Folder.create({ ...sampleFolder(), userId: bystander.id });
    await AuditLog.create({
      userId: bystander.id,
      action: 'login',
      ipAddress: '127.0.0.1',
      userAgent: 'test',
    });

    const startSessionSpy = vi.spyOn(mongoose, 'startSession');

    const result = await cascadeDeleteUser({
      userId: target.id,
      userEmail: target.email,
      ip: '127.0.0.1',
      userAgent: 'test-agent',
      auditAction: 'account_delete',
    });

    expect(result).toBe(true);
    expect(startSessionSpy).toHaveBeenCalled();

    expect(await User.findById(target.id)).toBeNull();
    expect(await VaultItem.countDocuments({ userId: target.id })).toBe(0);
    expect(await Folder.countDocuments({ userId: target.id })).toBe(0);
    expect(await RefreshToken.countDocuments({ userId: target.id })).toBe(0);
    expect(await AuditLog.countDocuments({ userId: target.id })).toBe(0);
    expect(await BackupLog.countDocuments({ userId: target.id })).toBe(0);

    // The system-scoped record of the erasure survives the erasure.
    const systemLogs = await AuditLog.find({ userId: null, action: 'account_delete' }).lean();
    expect(systemLogs).toHaveLength(1);
    expect((systemLogs[0]!.metadata as Record<string, unknown>)['deletedUserId']).toBe(target.id);
    expect((systemLogs[0]!.metadata as Record<string, unknown>)['deletedEmail']).toBe(target.email);

    // Cross-user isolation.
    expect(await User.findById(bystander.id)).not.toBeNull();
    expect(await VaultItem.countDocuments({ userId: bystander.id })).toBe(1);
    expect(await Folder.countDocuments({ userId: bystander.id })).toBe(1);
    expect(await RefreshToken.countDocuments({ userId: bystander.id })).toBe(1);
    expect(await AuditLog.countDocuments({ userId: bystander.id })).toBe(1);
  });

  it('rolls back EVERY write and writes no orphan audit row when the transaction aborts', async () => {
    const target = await createTestUser();
    await VaultItem.create({ ...sampleVaultItem(), userId: target.id });
    await Folder.create({ ...sampleFolder(), userId: target.id });
    await BackupLog.create({ userId: target.id, status: 'success', sentTo: [target.email] });

    // Enter with the flag cleared so the abort-time re-set is load-bearing.
    await User.updateOne({ _id: target.id }, { $set: { deletionPending: false } });

    // Blow up on the LAST write in the transaction — every preceding delete
    // (and the audit insert) is already applied inside the session, so only a
    // genuine rollback can restore them.
    const deleteSpy = vi
      .spyOn(User, 'findByIdAndDelete')
      .mockImplementationOnce(
        () =>
          Promise.reject(new Error('forced abort')) as unknown as ReturnType<
            typeof User.findByIdAndDelete
          >,
      );

    const result = await cascadeDeleteUser({
      userId: target.id,
      userEmail: target.email,
      ip: '127.0.0.1',
      userAgent: 'test-agent',
      auditAction: 'deletion_cleanup',
    });

    deleteSpy.mockRestore();

    expect(result).toBe(false);

    // Nothing was erased — the user's data is fully intact for the retry.
    const userAfter = await User.findById(target.id).lean();
    expect(userAfter).not.toBeNull();
    expect(userAfter!.deletionPending).toBe(true);
    expect(await VaultItem.countDocuments({ userId: target.id })).toBe(1);
    expect(await Folder.countDocuments({ userId: target.id })).toBe(1);
    expect(await RefreshToken.countDocuments({ userId: target.id })).toBe(1);
    expect(await BackupLog.countDocuments({ userId: target.id })).toBe(1);

    // The invariant the standalone suite could not assert: the audit row was
    // written INSIDE the session, so an abort must take it with it. A surviving
    // row would claim an erasure that never happened.
    expect(await AuditLog.countDocuments({ action: 'deletion_cleanup' })).toBe(0);
  });
});
