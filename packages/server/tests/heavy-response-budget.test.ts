/**
 * The heavy-response budget outside the HTTP path: the bounded wait the scheduled
 * backup takes a slot through, and the scheduler itself, which builds the same
 * whole-vault document as a download and so must queue behind the same two slots.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { installTestClock, uninstallTestClock } from './clock.js';
import crypto from 'node:crypto';

vi.mock('node-cron', () => ({
  default: { schedule: vi.fn().mockReturnValue({ stop: vi.fn() }) },
}));

vi.mock('../src/utils/email.js', async (importOriginal) => {
  const original = await importOriginal<typeof import('../src/utils/email.js')>();
  return {
    ...original,
    sendEmail: vi.fn().mockResolvedValue({ success: true, message: 'Email sent successfully.' }),
  };
});

import cron from 'node-cron';
import {
  MAX_IN_FLIGHT_HEAVY_RESPONSES,
  MIN_SUSTAINED_UPLOAD_BYTES_PER_SECOND,
} from '@hvault/shared';
import mongoose from 'mongoose';
import { config } from '../src/config/index.js';
import { User } from '../src/models/User.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { sampleVaultItem } from './helpers.js';
import { BackupLog } from '../src/models/BackupLog.js';
import { SCHEDULED_BACKUP_SLOT_POLICY, startBackupScheduler } from '../src/jobs/backupScheduler.js';
import { sendEmail } from '../src/utils/email.js';
import { ROW_CURSOR_BATCH_SIZE } from '../src/utils/jsonStream.js';
import { createSemaphore } from '../src/utils/partSemaphore.js';
import {
  SEND_DEADLINE_POLICY,
  acquireWithin,
  heavyResponseSemaphore,
  heavyResponseUserQuota,
  sendDeadlineMs,
} from '../src/utils/heavyResponseBudget.js';

describe('the budget', () => {
  it('is two slots per process and one per account, the share strictly below the budget', () => {
    expect(heavyResponseSemaphore.permits).toBe(MAX_IN_FLIGHT_HEAVY_RESPONSES);
    expect(MAX_IN_FLIGHT_HEAVY_RESPONSES).toBe(2);
    expect(heavyResponseUserQuota.limit).toBe(1);
    expect(heavyResponseUserQuota.limit).toBeLessThan(heavyResponseSemaphore.permits);
  });
});

describe('acquireWithin', () => {
  it('grants a free slot at once and hands it back on release', async () => {
    const semaphore = createSemaphore(1);
    const release = await acquireWithin(semaphore, 1_000);
    expect(release).toBeTypeOf('function');
    expect(semaphore.available).toBe(0);
    release!();
    release!(); // idempotent
    expect(semaphore.available).toBe(1);
  });

  it('gives up after the wait, and hands a slot granted later straight back', async () => {
    const semaphore = createSemaphore(1);
    const held = await acquireWithin(semaphore, 1_000);
    const late = await acquireWithin(semaphore, 20);
    expect(late).toBeNull();
    expect(semaphore.waiting).toBe(1);

    held!();
    // The abandoned waiter was granted the slot and returned it: nobody holds it.
    expect(semaphore.available).toBe(1);
    expect(semaphore.waiting).toBe(0);
  });

  it('waits for a slot freed inside the wait', async () => {
    const semaphore = createSemaphore(1);
    const held = await acquireWithin(semaphore, 1_000);
    const waiting = acquireWithin(semaphore, 5_000);
    setTimeout(() => held!(), 20);
    const release = await waiting;
    expect(release).toBeTypeOf('function');
    expect(semaphore.available).toBe(0);
    release!();
  });
});

describe('the send deadline', () => {
  it('is the transfer time at the slowest sustained rate plus the slack', () => {
    expect(SEND_DEADLINE_POLICY.bytesPerSecond).toBe(MIN_SUSTAINED_UPLOAD_BYTES_PER_SECOND);
    expect(sendDeadlineMs(0)).toBe(SEND_DEADLINE_POLICY.slackMs);
    // 25 MiB at 128 KiB/s is 200 s.
    expect(sendDeadlineMs(25 * 1024 * 1024)).toBe(200_000 + SEND_DEADLINE_POLICY.slackMs);
    expect(sendDeadlineMs(1)).toBe(1 + SEND_DEADLINE_POLICY.slackMs);
  });
});

describe('the scheduled backup takes a heavy-response slot', () => {
  // The scheduler picks the accounts whose `scheduleHour` is the CURRENT UTC hour,
  // read when its tick runs; these tests set that hour when they seed the account.
  // A run straddling an hour boundary would seed one hour and tick in the next, so
  // the wall clock is frozen for the block (the date only: timers stay real).
  beforeEach(() => {
    installTestClock();
  });
  afterEach(() => {
    uninstallTestClock();
  });

  const held: (() => void)[] = [];

  beforeEach(() => {
    vi.mocked(sendEmail).mockClear();
  });

  afterEach(() => {
    for (const release of held.splice(0)) release();
  });

  async function scheduledUser() {
    return User.create({
      email: `scheduled-${crypto.randomUUID()}@example.com`,
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
        },
      },
    });
  }

  /** Cursors the server holds open right now, from its own counters. */
  async function openCursors(): Promise<number> {
    const status = (await mongoose.connection.db!.command({ serverStatus: 1 })) as {
      metrics: { cursor: { open: { total: number } } };
    };
    return Number(status.metrics.cursor.open.total);
  }

  it('closes the database cursor when a backup is refused for size part-way through', async () => {
    // More than one 16 MiB driver batch of rows, so leaving the loop early leaves
    // a cursor with batches still to fetch (a walk that fits one batch is closed by
    // the server itself and would prove nothing).
    const user = await scheduledUser();
    await VaultItem.insertMany(
      Array.from({ length: 150 }, () => ({
        userId: user._id,
        ...sampleVaultItem({ encryptedData: 'e'.repeat(200_000) }),
      })),
    );
    const mutable = config as unknown as Record<string, unknown>;
    const saved = mutable.BACKUP_MAX_SIZE_MB;
    mutable.BACKUP_MAX_SIZE_MB = 1;
    try {
      const baseline = await openCursors();

      await schedulerTick()();

      const log = await BackupLog.findOne({ userId: user._id }).lean();
      expect(log?.status).toBe('failed');
      expect(log?.errorMessage).toMatch(/maximum size/);
      expect(sendEmail).not.toHaveBeenCalled();
      expect(await openCursors()).toBe(baseline);
    } finally {
      mutable.BACKUP_MAX_SIZE_MB = saved;
    }
  }, 60_000);

  it('asks the database for rows sixteen at a time, never the default first batch', async () => {
    // The default first batch is 101 rows: at up to half a megabyte a row, ~50 MB
    // held before the first is used. Every cursor the backup walks is asked for
    // ROW_CURSOR_BATCH_SIZE.
    const user = await scheduledUser();
    await VaultItem.create({ userId: user._id, ...sampleVaultItem() });
    const real = mongoose.mongo.Collection.prototype.find;
    const batchSizes: { collection: string; batchSize: unknown }[] = [];
    vi.spyOn(mongoose.mongo.Collection.prototype, 'find').mockImplementation(function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof real>
    ) {
      if (this.collectionName === 'vault_items' || this.collectionName === 'folders') {
        batchSizes.push({ collection: this.collectionName, batchSize: args[1]?.batchSize });
      }
      return real.apply(this, args);
    } as never);

    await schedulerTick()();

    expect(batchSizes).toEqual([
      { collection: 'folders', batchSize: ROW_CURSOR_BATCH_SIZE },
      { collection: 'vault_items', batchSize: ROW_CURSOR_BATCH_SIZE },
    ]);
    expect(ROW_CURSOR_BATCH_SIZE).toBe(16);
  });

  function schedulerTick(): () => Promise<void> {
    const schedule = vi.mocked(cron.schedule);
    schedule.mockClear();
    startBackupScheduler();
    return schedule.mock.calls[0]![1] as () => Promise<void>;
  }

  it('waits while both slots are taken, then builds and mails the backup, and gives the slot back', async () => {
    const user = await scheduledUser();
    for (let i = 0; i < MAX_IN_FLIGHT_HEAVY_RESPONSES; i += 1) {
      const release = await acquireWithin(heavyResponseSemaphore, 1_000);
      held.push(release!);
    }
    expect(heavyResponseSemaphore.available).toBe(0);

    const run = schedulerTick()();
    // Wait for the tick to queue on the semaphore, not for a guessed time.
    await vi.waitFor(() => {
      expect(heavyResponseSemaphore.waiting).toBe(1);
    });
    // Nothing built, nothing mailed, nothing recorded while it waits.
    expect(sendEmail).not.toHaveBeenCalled();
    expect(await BackupLog.countDocuments({ userId: user._id })).toBe(0);

    held.shift()!();
    await run;

    expect(sendEmail).toHaveBeenCalledTimes(1);
    expect(await BackupLog.countDocuments({ userId: user._id, status: 'success' })).toBe(1);
    // Its own slot came back; one is still held by the test.
    expect(heavyResponseSemaphore.available).toBe(MAX_IN_FLIGHT_HEAVY_RESPONSES - 1);
  });

  it('records a failed backup and moves on when no slot frees within the wait', async () => {
    const user = await scheduledUser();
    for (let i = 0; i < MAX_IN_FLIGHT_HEAVY_RESPONSES; i += 1) {
      held.push((await acquireWithin(heavyResponseSemaphore, 1_000))!);
    }
    const saved = SCHEDULED_BACKUP_SLOT_POLICY.waitMs;
    SCHEDULED_BACKUP_SLOT_POLICY.waitMs = 30;
    try {
      await schedulerTick()();
    } finally {
      SCHEDULED_BACKUP_SLOT_POLICY.waitMs = saved;
    }

    expect(sendEmail).not.toHaveBeenCalled();
    const log = await BackupLog.findOne({ userId: user._id }).lean();
    expect(log?.status).toBe('failed');
    expect(log?.errorMessage).toMatch(/busy/i);
    expect(log?.sentTo).toEqual([]);
    // The test's two slots are still the only ones held.
    expect(heavyResponseSemaphore.available).toBe(0);
  });

  it('gives the slot back even when the backup fails', async () => {
    const user = await scheduledUser();
    vi.mocked(sendEmail).mockResolvedValueOnce({ success: false, message: 'smtp down' });

    await schedulerTick()();

    expect(await BackupLog.countDocuments({ userId: user._id, status: 'failed' })).toBe(1);
    expect(heavyResponseSemaphore.available).toBe(MAX_IN_FLIGHT_HEAVY_RESPONSES);
  });
});
