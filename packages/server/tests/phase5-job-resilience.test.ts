import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

/**
 * Phase 5 / T10 — A transient DB error during job-lock acquire/release must not
 * crash the whole server.
 *
 * Two failure modes are covered:
 *   1. `trackJob` must never let a rejected tracked promise surface as an
 *      unhandled rejection (the bookkeeping `.finally()` chain re-rejects).
 *   2. Each cron job must contain a transient `acquireJobLock`/`releaseJobLock`
 *      failure (log + continue) so its promise resolves instead of rejecting.
 *
 * `server.ts` escalates any unhandled rejection to `process.exit(1)`, so an
 * un-contained transient lock error would take down the entire API server.
 */

// Capture logger output across all job modules. Hoisted so the mock factory
// (also hoisted) can reference them.
const { loggerError, loggerInfo, loggerWarn, loggerDebug } = vi.hoisted(() => ({
  loggerError: vi.fn(),
  loggerInfo: vi.fn(),
  loggerWarn: vi.fn(),
  loggerDebug: vi.fn(),
}));

vi.mock('@hiprax/logger', async (importOriginal) => {
  const original = await importOriginal<typeof import('@hiprax/logger')>();
  return {
    ...original,
    createLogger: () => ({
      error: loggerError,
      info: loggerInfo,
      warn: loggerWarn,
      debug: loggerDebug,
    }),
  };
});

// Control lock acquire/release so we can simulate transient MongoDB failures.
const { mockAcquire, mockRelease } = vi.hoisted(() => ({
  mockAcquire: vi.fn(),
  mockRelease: vi.fn(),
}));

vi.mock('../src/utils/jobLock.js', () => ({
  acquireJobLock: mockAcquire,
  releaseJobLock: mockRelease,
}));

// Mock node-cron so we can capture and invoke the scheduled callback directly.
vi.mock('node-cron', () => ({
  default: {
    schedule: vi.fn().mockReturnValue({ stop: vi.fn() }),
  },
}));

import cron from 'node-cron';
import { startTokenCleanupJob } from '../src/jobs/tokenCleanup.js';
import { startTrashCleanupJob } from '../src/jobs/trashCleanup.js';
import { startBackupScheduler } from '../src/jobs/backupScheduler.js';
import { trackJob, getRunningJobs } from '../src/utils/jobTracker.js';

const mockedSchedule = vi.mocked(cron.schedule);

function getScheduledCallback(): () => Promise<void> {
  const calls = mockedSchedule.mock.calls;
  return calls[calls.length - 1]![1] as () => Promise<void>;
}

/** Allow the microtask queue + an unhandledRejection macrotask to settle. */
const flush = (): Promise<void> => new Promise<void>((resolve) => setTimeout(resolve, 20));

const jobs = [
  { name: 'token-cleanup', start: startTokenCleanupJob },
  { name: 'trash-cleanup', start: startTrashCleanupJob },
  { name: 'backup-scheduler', start: startBackupScheduler },
] as const;

describe('Phase 5 — background job resilience (T10)', () => {
  let unhandled: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.clearAllMocks();
    mockedSchedule.mockReturnValue({ stop: vi.fn() } as unknown as ReturnType<
      typeof cron.schedule
    >);
    unhandled = vi.fn();
    process.on('unhandledRejection', unhandled);
  });

  afterEach(() => {
    process.off('unhandledRejection', unhandled);
  });

  describe('trackJob bookkeeping', () => {
    it('does not surface an unhandled rejection when a tracked promise rejects', async () => {
      trackJob(Promise.reject(new Error('transient db error')));

      await flush();

      expect(unhandled).not.toHaveBeenCalled();
      // The settled promise is still removed from the running set.
      expect(getRunningJobs()).toHaveLength(0);
    });

    it('removes a resolved tracked promise from the running set', async () => {
      trackJob(Promise.resolve());

      await flush();

      expect(getRunningJobs()).toHaveLength(0);
    });
  });

  for (const job of jobs) {
    describe(`${job.name} — transient lock failures are contained`, () => {
      it('does not reject or crash the process when acquireJobLock fails', async () => {
        mockAcquire.mockRejectedValueOnce(new Error('lock acquire failed: primary stepped down'));

        job.start();
        const callback = getScheduledCallback();

        // The cron callback returns the job promise; it must RESOLVE (the
        // transient error is logged and contained), never reject.
        await expect(callback()).resolves.toBeUndefined();
        await flush();

        expect(unhandled).not.toHaveBeenCalled();
        expect(loggerError).toHaveBeenCalled();
        // A lock we never acquired must not be released.
        expect(mockRelease).not.toHaveBeenCalled();
        expect(getRunningJobs()).toHaveLength(0);
      });

      it('does not reject or crash the process when releaseJobLock fails', async () => {
        mockAcquire.mockResolvedValueOnce('test-lock-id');
        mockRelease.mockRejectedValueOnce(new Error('lock release failed: connection closing'));

        job.start();
        const callback = getScheduledCallback();

        await expect(callback()).resolves.toBeUndefined();
        await flush();

        expect(unhandled).not.toHaveBeenCalled();
        expect(loggerError).toHaveBeenCalled();
        expect(mockRelease).toHaveBeenCalledWith(job.name, 'test-lock-id');
        expect(getRunningJobs()).toHaveLength(0);
      });

      it('skips releasing when another instance already holds the lock', async () => {
        mockAcquire.mockResolvedValueOnce(null);

        job.start();
        const callback = getScheduledCallback();

        await expect(callback()).resolves.toBeUndefined();
        await flush();

        expect(unhandled).not.toHaveBeenCalled();
        expect(mockRelease).not.toHaveBeenCalled();
      });
    });
  }
});
