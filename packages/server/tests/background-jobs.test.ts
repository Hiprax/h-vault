import { describe, it, expect, vi, beforeEach } from 'vitest';
import mongoose from 'mongoose';
import crypto from 'node:crypto';
import { User } from '../src/models/User.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { BackupLog } from '../src/models/BackupLog.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { JobLock } from '../src/models/JobLock.js';
import { config } from '../src/config/index.js';

// Mock node-cron BEFORE importing job modules
vi.mock('node-cron', () => ({
  default: {
    schedule: vi.fn().mockReturnValue({ stop: vi.fn() }),
  },
}));

// Mock email
vi.mock('../src/utils/email.js', async (importOriginal) => {
  const original = await importOriginal<typeof import('../src/utils/email.js')>();
  return {
    ...original,
    sendEmail: vi.fn().mockResolvedValue({ success: true, message: 'Email sent successfully.' }),
  };
});

import cron from 'node-cron';
import { startBackupScheduler } from '../src/jobs/backupScheduler.js';
import { startTokenCleanupJob } from '../src/jobs/tokenCleanup.js';
import { startTrashCleanupJob } from '../src/jobs/trashCleanup.js';
import { sendEmail } from '../src/utils/email.js';

const mockedSchedule = vi.mocked(cron.schedule);
const mockedSendEmail = vi.mocked(sendEmail);

/**
 * Helper: extract the cron callback from the most recent `cron.schedule` call.
 */
function getScheduledCallback(): () => Promise<void> {
  const calls = mockedSchedule.mock.calls;
  return calls[calls.length - 1]![1] as () => Promise<void>;
}

/**
 * Helper: create a user with backup enabled at the current UTC hour.
 */
async function createBackupUser(overrides: Record<string, unknown> = {}) {
  const currentHour = new Date().getUTCHours();
  const email =
    (overrides['email'] as string | undefined) ?? `backup-${crypto.randomUUID()}@example.com`;

  const user = await User.create({
    email,
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
        scheduleHour: currentHour,
        encryptedBWK: 'test-encrypted-bwk',
        bwkIv: 'test-bwk-iv',
        bwkTag: 'test-bwk-tag',
        bwkSalt: 'test-bwk-salt',
        bwkEncryptedVaultKey: 'test-bwk-encrypted-vk',
        bwkVaultKeyIv: 'test-bwk-vk-iv',
        bwkVaultKeyTag: 'test-bwk-vk-tag',
        isConfigured: true,
        ...(overrides['backup'] as Record<string, unknown> | undefined),
      },
    },
  });

  return user;
}

/**
 * Helper: create a vault item for a given user.
 */
async function createVaultItem(
  userId: mongoose.Types.ObjectId,
  overrides: Record<string, unknown> = {},
) {
  return VaultItem.create({
    userId,
    itemType: 'login',
    encryptedData: 'test-encrypted-data',
    dataIv: 'test-data-iv',
    dataTag: 'test-data-tag',
    encryptedName: 'test-encrypted-name',
    nameIv: 'test-name-iv',
    nameTag: 'test-name-tag',
    ...overrides,
  });
}

/**
 * Helper: create a folder for a given user.
 */
async function createFolder(
  userId: mongoose.Types.ObjectId,
  overrides: Record<string, unknown> = {},
) {
  return Folder.create({
    userId,
    encryptedName: 'test-encrypted-folder-name',
    nameIv: 'test-folder-iv',
    nameTag: 'test-folder-tag',
    ...overrides,
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  mockedSchedule.mockReturnValue({ stop: vi.fn() } as unknown as ReturnType<typeof cron.schedule>);
});

// ─── Backup Scheduler ────────────────────────────────────────────────────────

describe('backupScheduler', () => {
  it('should register cron job with hourly schedule and UTC timezone', () => {
    startBackupScheduler();

    expect(mockedSchedule).toHaveBeenCalledTimes(1);
    expect(mockedSchedule).toHaveBeenCalledWith('0 * * * *', expect.any(Function), {
      timezone: 'UTC',
    });
  });

  it('should send backup email for eligible users', async () => {
    startBackupScheduler();
    const callback = getScheduledCallback();

    const user = await createBackupUser();
    const item = await createVaultItem(user._id);
    const folder = await createFolder(user._id);

    await callback();

    expect(mockedSendEmail).toHaveBeenCalledTimes(1);
    const [to, subject, html, attachments] = mockedSendEmail.mock.calls[0]!;
    expect(to).toBe(user.email);
    expect(subject).toContain('Encrypted Vault Backup');
    expect(html).toContain(String(1)); // 1 item
    expect(attachments).toHaveLength(1);
    expect(attachments![0]!.filename).toMatch(/hvault-backup-.*\.enc/);
    expect(attachments![0]!.contentType).toBe('application/octet-stream');

    // Verify the attachment content is valid JSON with expected fields
    const backupData = JSON.parse(attachments![0]!.content.toString('utf-8')) as Record<
      string,
      unknown
    >;
    expect(backupData['formatVersion']).toBe(1);
    expect(backupData['encryptionVersion']).toBe(1);
    expect(backupData['itemCount']).toBe(1);
    expect(backupData['items']).toHaveLength(1);
    expect(backupData['folders']).toHaveLength(1);
    expect((backupData['items'] as { _id: string }[])[0]!._id).toBe(item._id.toString());
    expect((backupData['folders'] as { _id: string }[])[0]!._id).toBe(folder._id.toString());
  });

  it('should never emit sourceRefId in the scheduled backup payload', async () => {
    startBackupScheduler();
    const callback = getScheduledCallback();

    const user = await createBackupUser();
    const foreignRef = new mongoose.Types.ObjectId().toString();
    // Seed rows carrying restore-provenance (as Phase 4 will stamp on
    // fresh-inserted, non-owned rows). The emitted backup must NOT leak it.
    await createVaultItem(user._id, { sourceRefId: foreignRef });
    await createFolder(user._id, { sourceRefId: foreignRef });

    await callback();

    expect(mockedSendEmail).toHaveBeenCalledTimes(1);
    const [, , , attachments] = mockedSendEmail.mock.calls[0]!;
    const raw = attachments![0]!.content.toString('utf-8');
    // Sanity: the provenance value was really persisted on the seeded rows.
    const stored = await VaultItem.findOne({ userId: user._id }).lean();
    expect(stored?.sourceRefId).toBe(foreignRef);
    // The emitted attachment carries the encrypted rows but no provenance.
    expect(raw).toContain('items');
    expect(raw).not.toContain('sourceRefId');
    expect(raw).not.toContain(foreignRef);
  });

  it('should include backupEncryption metadata for self-contained restore', async () => {
    startBackupScheduler();
    const callback = getScheduledCallback();

    await createBackupUser();
    await createVaultItem((await User.findOne().lean())!._id);

    await callback();

    expect(mockedSendEmail).toHaveBeenCalledTimes(1);
    const [, , , attachments] = mockedSendEmail.mock.calls[0]!;
    const backupData = JSON.parse(attachments![0]!.content.toString('utf-8')) as Record<
      string,
      unknown
    >;
    const backupEncryption = backupData['backupEncryption'] as Record<string, unknown>;
    expect(backupEncryption).toBeDefined();
    expect(backupEncryption['encryptedBWK']).toBe('test-encrypted-bwk');
    expect(backupEncryption['bwkIv']).toBe('test-bwk-iv');
    expect(backupEncryption['bwkTag']).toBe('test-bwk-tag');
    expect(backupEncryption['bwkSalt']).toBe('test-bwk-salt');
    expect(backupEncryption['bwkEncryptedVaultKey']).toBe('test-bwk-encrypted-vk');
    expect(backupEncryption['bwkVaultKeyIv']).toBe('test-bwk-vk-iv');
    expect(backupEncryption['bwkVaultKeyTag']).toBe('test-bwk-vk-tag');
  });

  it('should create success BackupLog entry after sending', async () => {
    startBackupScheduler();
    const callback = getScheduledCallback();

    const user = await createBackupUser();
    await createVaultItem(user._id);

    await callback();

    const logs = await BackupLog.find({ userId: user._id });
    expect(logs).toHaveLength(1);
    expect(logs[0]!.status).toBe('success');
    expect(logs[0]!.itemCount).toBe(1);
    expect(logs[0]!.sentTo).toEqual([user.email]);
    expect(logs[0]!.fileSizeBytes).toBeGreaterThan(0);
  });

  it('should use backupEmails when specified instead of user email', async () => {
    startBackupScheduler();
    const callback = getScheduledCallback();

    const backupEmails = ['backup-recipient@example.com'];
    const user = await createBackupUser({
      backup: { backupEmails },
    });
    await createVaultItem(user._id);

    await callback();

    expect(mockedSendEmail).toHaveBeenCalledTimes(1);
    const [to] = mockedSendEmail.mock.calls[0]!;
    expect(to).toBe(backupEmails[0]);

    const logs = await BackupLog.find({ userId: user._id });
    expect(logs[0]!.sentTo).toEqual(backupEmails);
  });

  it('should create failed BackupLog when backup exceeds max size', async () => {
    startBackupScheduler();
    const callback = getScheduledCallback();

    const user = await createBackupUser();
    await createVaultItem(user._id);

    // Temporarily set max size to 0 so any backup exceeds it
    const originalMaxSize = config.BACKUP_MAX_SIZE_MB;
    try {
      (config as { BACKUP_MAX_SIZE_MB: number }).BACKUP_MAX_SIZE_MB = 0;

      await callback();

      expect(mockedSendEmail).not.toHaveBeenCalled();

      const logs = await BackupLog.find({ userId: user._id });
      expect(logs).toHaveLength(1);
      expect(logs[0]!.status).toBe('failed');
      expect(logs[0]!.errorMessage).toMatch(/exceeds maximum size/i);
    } finally {
      (config as { BACKUP_MAX_SIZE_MB: number }).BACKUP_MAX_SIZE_MB = originalMaxSize;
    }
  });

  it('should skip processing when another instance holds the lock', async () => {
    startBackupScheduler();
    const callback = getScheduledCallback();

    // Create a non-expired lock held by another instance
    await JobLock.create({
      jobName: 'backup-scheduler',
      lockedBy: 'other-instance-id',
      lockedAt: new Date(),
      expiresAt: new Date(Date.now() + 30 * 60 * 1000),
    });

    const user = await createBackupUser();
    await createVaultItem(user._id);

    await callback();

    expect(mockedSendEmail).not.toHaveBeenCalled();
    const logs = await BackupLog.find({});
    expect(logs).toHaveLength(0);
  });

  it('should release lock after processing', async () => {
    startBackupScheduler();
    const callback = getScheduledCallback();

    // No users needed, just verify lock lifecycle
    await callback();

    const locks = await JobLock.find({ jobName: 'backup-scheduler' });
    expect(locks).toHaveLength(0);
  });

  it('should skip users without backup enabled', async () => {
    startBackupScheduler();
    const callback = getScheduledCallback();

    // Create a user with backup disabled
    await createBackupUser({
      backup: { enabled: false },
    });

    await callback();

    expect(mockedSendEmail).not.toHaveBeenCalled();
    const logs = await BackupLog.find({});
    expect(logs).toHaveLength(0);
  });

  it('should skip users without encryptedBWK', async () => {
    startBackupScheduler();
    const callback = getScheduledCallback();

    await User.create({
      email: `no-bwk-${crypto.randomUUID()}@example.com`,
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
          isConfigured: false,
          // No encryptedBWK set
        },
      },
    });

    await callback();

    expect(mockedSendEmail).not.toHaveBeenCalled();
  });

  it('should handle sendEmail failures gracefully and create failed BackupLog', async () => {
    startBackupScheduler();
    const callback = getScheduledCallback();

    mockedSendEmail.mockResolvedValueOnce({ success: false, message: 'SMTP connection refused' });

    const user = await createBackupUser();
    await createVaultItem(user._id);

    // Should not throw
    await callback();

    const logs = await BackupLog.find({ userId: user._id });
    // The user has a single (default account-email) recipient and the one send
    // fails, so the scheduler must write EXACTLY ONE failed log — not a success
    // log, and not spurious duplicates. Pinning the exact set (rather than
    // >= 1) catches both a stray extra BackupLog and a mis-statused success row.
    expect(logs).toHaveLength(1);
    expect(logs[0]!.status).toBe('failed');
    expect(logs[0]!.errorMessage).toMatch(/email delivery failed/i);

    // Verify user status was updated to failed
    const updatedUser = await User.findById(user._id);
    expect(updatedUser!.settings.backup.lastBackupStatus).toBe('failed');
  });

  it('should update user backup status on success', async () => {
    startBackupScheduler();
    const callback = getScheduledCallback();

    const user = await createBackupUser();
    await createVaultItem(user._id);

    await callback();

    const updatedUser = await User.findById(user._id);
    expect(updatedUser!.settings.backup.lastBackupStatus).toBe('success');
    expect(updatedUser!.settings.backup.lastBackupAt).toBeDefined();
    expect(updatedUser!.settings.backup.lastBackupAt!.getTime()).toBeGreaterThan(
      Date.now() - 10_000,
    );
  });

  it('should exclude soft-deleted vault items from backup', async () => {
    startBackupScheduler();
    const callback = getScheduledCallback();

    const user = await createBackupUser();
    await createVaultItem(user._id); // active item
    await createVaultItem(user._id, { deletedAt: new Date() }); // soft-deleted

    await callback();

    expect(mockedSendEmail).toHaveBeenCalledTimes(1);
    const attachments = mockedSendEmail.mock.calls[0]![3]!;
    const backupData = JSON.parse(attachments[0]!.content.toString('utf-8')) as Record<
      string,
      unknown
    >;
    expect(backupData['itemCount']).toBe(1);
    expect(backupData['items']).toHaveLength(1);
  });

  it('should process multiple eligible users', async () => {
    startBackupScheduler();
    const callback = getScheduledCallback();

    const user1 = await createBackupUser();
    const user2 = await createBackupUser();
    await createVaultItem(user1._id);
    await createVaultItem(user2._id);

    await callback();

    expect(mockedSendEmail).toHaveBeenCalledTimes(2);

    const logs = await BackupLog.find({});
    expect(logs).toHaveLength(2);
    expect(logs.every((l) => l.status === 'success')).toBe(true);
  });
});

// ─── Token Cleanup ───────────────────────────────────────────────────────────

describe('tokenCleanup', () => {
  /**
   * Helper: create a refresh token.
   */
  async function createRefreshToken(overrides: Record<string, unknown> = {}) {
    const userId =
      (overrides['userId'] as mongoose.Types.ObjectId | undefined) ?? new mongoose.Types.ObjectId();
    return RefreshToken.create({
      userId,
      tokenHash: crypto.randomBytes(32).toString('hex'),
      familyId: crypto.randomUUID(),
      deviceInfo: {
        userAgent: 'test-agent',
        ip: '127.0.0.1',
        fingerprint: 'test-fp',
      },
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days from now
      ...overrides,
    });
  }

  it('should register cron job with 6-hour schedule and UTC timezone', () => {
    startTokenCleanupJob();

    expect(mockedSchedule).toHaveBeenCalledTimes(1);
    expect(mockedSchedule).toHaveBeenCalledWith('0 */6 * * *', expect.any(Function), {
      timezone: 'UTC',
    });
  });

  it('should delete expired refresh tokens', async () => {
    startTokenCleanupJob();
    const callback = getScheduledCallback();

    // Create an expired token
    await createRefreshToken({
      expiresAt: new Date(Date.now() - 60_000), // expired 1 minute ago
    });

    // Create a valid token
    const validToken = await createRefreshToken();

    await callback();

    const remaining = await RefreshToken.find({});
    expect(remaining).toHaveLength(1);
    expect(remaining[0]!._id.toString()).toBe(validToken._id.toString());
  });

  it('should delete consumed (usedAt set) refresh tokens older than 7 days', async () => {
    startTokenCleanupJob();
    const callback = getScheduledCallback();

    // Create a consumed token older than 7 days (should be deleted)
    await createRefreshToken({
      usedAt: new Date(Date.now() - 8 * 24 * 60 * 60 * 1000),
    });

    // Create a valid active token
    const activeToken = await createRefreshToken();

    await callback();

    const remaining = await RefreshToken.find({});
    expect(remaining).toHaveLength(1);
    expect(remaining[0]!._id.toString()).toBe(activeToken._id.toString());
  });

  it('should preserve recently consumed tokens for reuse detection', async () => {
    startTokenCleanupJob();
    const callback = getScheduledCallback();

    // Create a consumed token only 1 minute old (should be preserved for reuse detection)
    const recentUsedToken = await createRefreshToken({
      usedAt: new Date(Date.now() - 60_000),
    });

    // Create a valid active token
    const activeToken = await createRefreshToken();

    await callback();

    const remaining = await RefreshToken.find({});
    expect(remaining).toHaveLength(2);
    const remainingIds = remaining.map((t) => t._id.toString());
    expect(remainingIds).toContain(recentUsedToken._id.toString());
    expect(remainingIds).toContain(activeToken._id.toString());
  });

  it('should preserve consumed tokens whose expiresAt has passed but are still inside the reuse-detection window', async () => {
    // This is the regression guard for Task 3.3: under the previous TTL
    // strategy (`expiresAt: 1, expireAfterSeconds: 0`) MongoDB would have
    // deleted this token at `expiresAt`, collapsing the reuse-detection
    // window to near-zero for tokens consumed late in their 7-day life.
    startTokenCleanupJob();
    const callback = getScheduledCallback();

    const recentlyConsumedExpired = await createRefreshToken({
      usedAt: new Date(Date.now() - 60_000), // consumed 1 minute ago
      expiresAt: new Date(Date.now() - 5 * 60_000), // expired 5 minutes ago
    });

    await callback();

    const remaining = await RefreshToken.find({});
    expect(remaining).toHaveLength(1);
    expect(remaining[0]!._id.toString()).toBe(recentlyConsumedExpired._id.toString());
  });

  it('should NOT delete valid active tokens', async () => {
    startTokenCleanupJob();
    const callback = getScheduledCallback();

    // Create 3 valid active tokens
    await createRefreshToken();
    await createRefreshToken();
    await createRefreshToken();

    await callback();

    const remaining = await RefreshToken.find({});
    expect(remaining).toHaveLength(3);
  });

  it('should skip when lock is held by another instance', async () => {
    startTokenCleanupJob();
    const callback = getScheduledCallback();

    await JobLock.create({
      jobName: 'token-cleanup',
      lockedBy: 'other-instance',
      lockedAt: new Date(),
      expiresAt: new Date(Date.now() + 10 * 60 * 1000),
    });

    // Create an expired token that should NOT be cleaned up
    await createRefreshToken({
      expiresAt: new Date(Date.now() - 60_000),
    });

    await callback();

    // Token should still exist because job was skipped
    const remaining = await RefreshToken.find({});
    expect(remaining).toHaveLength(1);
  });

  it('should release lock after processing', async () => {
    startTokenCleanupJob();
    const callback = getScheduledCallback();

    await callback();

    const locks = await JobLock.find({ jobName: 'token-cleanup' });
    expect(locks).toHaveLength(0);
  });

  it('should delete both expired and consumed tokens in one run', async () => {
    startTokenCleanupJob();
    const callback = getScheduledCallback();

    // Expired token
    await createRefreshToken({
      expiresAt: new Date(Date.now() - 60_000),
    });

    // Consumed token older than 7 days
    await createRefreshToken({
      usedAt: new Date(Date.now() - 8 * 24 * 60 * 60 * 1000),
    });

    // Active token
    const activeToken = await createRefreshToken();

    await callback();

    const remaining = await RefreshToken.find({});
    expect(remaining).toHaveLength(1);
    expect(remaining[0]!._id.toString()).toBe(activeToken._id.toString());
  });
});

// ─── Trash Cleanup ───────────────────────────────────────────────────────────

describe('trashCleanup', () => {
  it('should register cron job with daily 2AM schedule and UTC timezone', () => {
    startTrashCleanupJob();

    expect(mockedSchedule).toHaveBeenCalledTimes(1);
    expect(mockedSchedule).toHaveBeenCalledWith('0 2 * * *', expect.any(Function), {
      timezone: 'UTC',
    });
  });

  it('should permanently delete items trashed beyond 30 days', async () => {
    startTrashCleanupJob();
    const callback = getScheduledCallback();

    const userId = new mongoose.Types.ObjectId();

    // Item deleted 31 days ago — should be purged
    await createVaultItem(userId, {
      deletedAt: new Date(Date.now() - 31 * 24 * 60 * 60 * 1000),
    });

    await callback();

    const remaining = await VaultItem.find({ userId });
    expect(remaining).toHaveLength(0);
  });

  it('should NOT delete recently trashed items (10 days ago)', async () => {
    startTrashCleanupJob();
    const callback = getScheduledCallback();

    const userId = new mongoose.Types.ObjectId();

    // Item deleted 10 days ago — should be kept
    await createVaultItem(userId, {
      deletedAt: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000),
    });

    await callback();

    const remaining = await VaultItem.find({ userId });
    expect(remaining).toHaveLength(1);
  });

  it('should NOT delete non-trashed items', async () => {
    startTrashCleanupJob();
    const callback = getScheduledCallback();

    const userId = new mongoose.Types.ObjectId();

    // Active item (no deletedAt)
    await createVaultItem(userId);

    await callback();

    const remaining = await VaultItem.find({ userId });
    expect(remaining).toHaveLength(1);
  });

  it('should create audit log entries per user with action trash_auto_purge and metadata.itemCount', async () => {
    startTrashCleanupJob();
    const callback = getScheduledCallback();

    const userId1 = new mongoose.Types.ObjectId();
    const userId2 = new mongoose.Types.ObjectId();

    // User 1: 2 items past cutoff
    await createVaultItem(userId1, {
      deletedAt: new Date(Date.now() - 35 * 24 * 60 * 60 * 1000),
    });
    await createVaultItem(userId1, {
      deletedAt: new Date(Date.now() - 40 * 24 * 60 * 60 * 1000),
    });

    // User 2: 1 item past cutoff
    await createVaultItem(userId2, {
      deletedAt: new Date(Date.now() - 31 * 24 * 60 * 60 * 1000),
    });

    await callback();

    const auditLogs = await AuditLog.find({ action: 'trash_auto_purge' }).sort({
      userId: 1,
    });
    expect(auditLogs).toHaveLength(2);

    const user1Log = auditLogs.find((l) => l.userId.toString() === userId1.toString());
    const user2Log = auditLogs.find((l) => l.userId.toString() === userId2.toString());

    expect(user1Log).toBeDefined();
    expect(user1Log!.metadata).toBeDefined();
    expect((user1Log!.metadata as { itemCount: number }).itemCount).toBe(2);
    expect((user1Log!.metadata as { cutoffDays: number }).cutoffDays).toBe(30);
    expect(user1Log!.ipAddress).toBe('system');
    expect(user1Log!.userAgent).toBe('system/trash-cleanup-job');

    expect(user2Log).toBeDefined();
    expect((user2Log!.metadata as { itemCount: number }).itemCount).toBe(1);
  });

  it('should skip when lock is held by another instance', async () => {
    startTrashCleanupJob();
    const callback = getScheduledCallback();

    await JobLock.create({
      jobName: 'trash-cleanup',
      lockedBy: 'other-instance',
      lockedAt: new Date(),
      expiresAt: new Date(Date.now() + 15 * 60 * 1000),
    });

    const userId = new mongoose.Types.ObjectId();
    await createVaultItem(userId, {
      deletedAt: new Date(Date.now() - 35 * 24 * 60 * 60 * 1000),
    });

    await callback();

    // Item should still exist because job was skipped
    const remaining = await VaultItem.find({ userId });
    expect(remaining).toHaveLength(1);
  });

  it('should release lock after processing', async () => {
    startTrashCleanupJob();
    const callback = getScheduledCallback();

    await callback();

    const locks = await JobLock.find({ jobName: 'trash-cleanup' });
    expect(locks).toHaveLength(0);
  });

  it('should handle batch deletion of multiple items', async () => {
    startTrashCleanupJob();
    const callback = getScheduledCallback();

    const userId = new mongoose.Types.ObjectId();

    // Create 10 items all past the cutoff date
    const promises = Array.from({ length: 10 }, () =>
      createVaultItem(userId, {
        deletedAt: new Date(Date.now() - 45 * 24 * 60 * 60 * 1000),
      }),
    );
    await Promise.all(promises);

    await callback();

    const remaining = await VaultItem.find({ userId });
    expect(remaining).toHaveLength(0);

    // Verify audit log records the total count
    const auditLogs = await AuditLog.find({
      userId,
      action: 'trash_auto_purge',
    });
    expect(auditLogs).toHaveLength(1);
    expect((auditLogs[0]!.metadata as { itemCount: number }).itemCount).toBe(10);
  });

  it('should not create audit log entries when no items are purged', async () => {
    startTrashCleanupJob();
    const callback = getScheduledCallback();

    // No trashed items in the database
    await callback();

    const auditLogs = await AuditLog.find({ action: 'trash_auto_purge' });
    expect(auditLogs).toHaveLength(0);
  });
});

// ─── Deletion Pending Cleanup ───────────────────────────────────────────────

describe('deletionPending cleanup (in tokenCleanup)', () => {
  /**
   * Helper: create a user with deletionPending: true (simulating a crash
   * during the deleteAccount flow).
   */
  async function createZombieUser(overrides: Record<string, unknown> = {}) {
    return User.create({
      email: `zombie-${crypto.randomUUID()}@example.com`,
      authHash: '$2a$04$fakehashfakehashfakehashfakehashfakehashfakehashfake',
      emailVerified: true,
      encryptedVaultKey: 'test-encrypted-vault-key',
      vaultKeyIv: 'test-vault-key-iv',
      vaultKeyTag: 'test-vault-key-tag',
      kdfIterations: 600_000,
      kdfAlgorithm: 'PBKDF2-SHA256',
      encryptionVersion: 1,
      deletionPending: true,
      ...overrides,
    });
  }

  it('should complete deletion for users with deletionPending: true', async () => {
    startTokenCleanupJob();
    const callback = getScheduledCallback();

    const zombie = await createZombieUser();
    await createVaultItem(zombie._id);
    await createFolder(zombie._id);

    await callback();

    // User should be fully deleted
    const user = await User.findById(zombie._id);
    expect(user).toBeNull();

    // All associated data should also be deleted
    const items = await VaultItem.find({ userId: zombie._id });
    expect(items).toHaveLength(0);

    const folders = await Folder.find({ userId: zombie._id });
    expect(folders).toHaveLength(0);
  });

  it('should create a deletion_cleanup audit log entry', async () => {
    startTokenCleanupJob();
    const callback = getScheduledCallback();

    const zombie = await createZombieUser();

    await callback();

    const auditLogs = await AuditLog.find({ action: 'deletion_cleanup' });
    expect(auditLogs).toHaveLength(1);
    expect(auditLogs[0]!.userId).toBeNull();
    expect(auditLogs[0]!.ipAddress).toBe('system');
    expect(auditLogs[0]!.userAgent).toBe('system/token-cleanup-job');
    expect((auditLogs[0]!.metadata as Record<string, unknown>)['deletedUserId']).toBe(
      zombie._id.toString(),
    );
    expect((auditLogs[0]!.metadata as Record<string, unknown>)['deletedEmail']).toBe(zombie.email);
  });

  it('should delete user-scoped audit logs during cleanup', async () => {
    startTokenCleanupJob();
    const callback = getScheduledCallback();

    const zombie = await createZombieUser();

    // Create a user-scoped audit log
    await AuditLog.create({
      userId: zombie._id,
      action: 'login',
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
    });

    await callback();

    // User-scoped audit logs should be deleted
    const userLogs = await AuditLog.find({ userId: zombie._id });
    expect(userLogs).toHaveLength(0);

    // But the system-scoped deletion_cleanup log should remain
    const systemLogs = await AuditLog.find({ action: 'deletion_cleanup' });
    expect(systemLogs).toHaveLength(1);
  });

  it('should not affect users without deletionPending flag', async () => {
    startTokenCleanupJob();
    const callback = getScheduledCallback();

    // Create a normal user (no deletionPending)
    const normalUser = await User.create({
      email: `normal-${crypto.randomUUID()}@example.com`,
      authHash: '$2a$04$fakehashfakehashfakehashfakehashfakehashfakehashfake',
      emailVerified: true,
      encryptedVaultKey: 'test-encrypted-vault-key',
      vaultKeyIv: 'test-vault-key-iv',
      vaultKeyTag: 'test-vault-key-tag',
      kdfIterations: 600_000,
      kdfAlgorithm: 'PBKDF2-SHA256',
      encryptionVersion: 1,
    });

    await createVaultItem(normalUser._id);

    await callback();

    // Normal user should still exist
    const user = await User.findById(normalUser._id);
    expect(user).not.toBeNull();

    const items = await VaultItem.find({ userId: normalUser._id });
    expect(items).toHaveLength(1);
  });

  it('should handle multiple zombie users in a single run', async () => {
    startTokenCleanupJob();
    const callback = getScheduledCallback();

    const zombie1 = await createZombieUser();
    const zombie2 = await createZombieUser();
    await createVaultItem(zombie1._id);
    await createVaultItem(zombie2._id);

    await callback();

    const user1 = await User.findById(zombie1._id);
    const user2 = await User.findById(zombie2._id);
    expect(user1).toBeNull();
    expect(user2).toBeNull();

    const auditLogs = await AuditLog.find({ action: 'deletion_cleanup' });
    expect(auditLogs).toHaveLength(2);
  });

  it('should also delete refresh tokens and backup logs for zombie users', async () => {
    startTokenCleanupJob();
    const callback = getScheduledCallback();

    const zombie = await createZombieUser();

    // Create associated refresh token
    await RefreshToken.create({
      userId: zombie._id,
      tokenHash: crypto.randomBytes(32).toString('hex'),
      familyId: crypto.randomUUID(),
      deviceInfo: { userAgent: 'test-agent', ip: '127.0.0.1', fingerprint: 'test-fp' },
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    // Create associated backup log
    await BackupLog.create({
      userId: zombie._id,
      status: 'success',
      itemCount: 1,
      fileSizeBytes: 100,
      sentTo: [zombie.email],
    });

    await callback();

    const tokens = await RefreshToken.find({ userId: zombie._id });
    expect(tokens).toHaveLength(0);

    const backupLogs = await BackupLog.find({ userId: zombie._id });
    expect(backupLogs).toHaveLength(0);
  });

  it('should skip users whose deletionPending flag has been cleared', async () => {
    startTokenCleanupJob();
    const callback = getScheduledCallback();

    // Create a zombie user and then clear the flag (e.g. the deletion was
    // aborted). `deletionPending` is the sole selector for the cleanup scan, so
    // the user must fall out of the sweep entirely.
    const zombie = await createZombieUser();
    await createVaultItem(zombie._id);
    await User.findByIdAndUpdate(zombie._id, { deletionPending: false });

    await callback();

    // User should still exist (not deleted) because the scan did not select it
    const user = await User.findById(zombie._id);
    expect(user).not.toBeNull();

    // Data should also remain
    const items = await VaultItem.find({ userId: zombie._id });
    expect(items).toHaveLength(1);

    // No cleanup audit log should have been created
    const auditLogs = await AuditLog.find({ action: 'deletion_cleanup' });
    expect(auditLogs).toHaveLength(0);
  });
});
