/**
 * The heavy-response budget outside the HTTP path: the bounded wait the scheduled
 * backup takes a slot through, and the scheduler itself, which builds the same
 * whole-vault document as a download and so must queue behind the same two slots.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
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
import { User } from '../src/models/User.js';
import { BackupLog } from '../src/models/BackupLog.js';
import { SCHEDULED_BACKUP_SLOT_POLICY, startBackupScheduler } from '../src/jobs/backupScheduler.js';
import { sendEmail } from '../src/utils/email.js';
import { createSemaphore } from '../src/utils/partSemaphore.js';
import {
  SEND_DEADLINE_POLICY,
  acquireWithin,
  heavyResponseSemaphore,
  heavyResponseUserQuota,
  sendDeadlineMs,
} from '../src/utils/heavyResponseBudget.js';

const settle = () => new Promise((resolve) => setTimeout(resolve, 50));

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
    await settle();
    // Nothing built, nothing mailed, nothing recorded while it waits.
    expect(sendEmail).not.toHaveBeenCalled();
    expect(await BackupLog.countDocuments({ userId: user._id })).toBe(0);
    expect(heavyResponseSemaphore.waiting).toBe(1);

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
