import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// Fully mocked unit test for the release-check SCHEDULE: node-cron, config, the
// check itself, the job tracker, the model and the logger are all stubbed, so
// every branch of `jobs/updateCheck.ts` runs deterministically and nothing leaves
// the process. What the check DOES is `update-check.test.ts`'s subject.
const h = vi.hoisted(() => ({
  cfg: {
    UPDATE_CHECK_ENABLED: true,
    UPDATE_CHECK_REPOSITORY: 'Hiprax/h-vault',
    NODE_ENV: 'production' as string,
  },
  scheduled: {
    expr: '',
    cb: undefined as undefined | (() => unknown),
    opts: undefined as unknown,
  },
  stop: vi.fn(),
  perform: vi.fn(),
  track: vi.fn(),
  findById: vi.fn(),
  log: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

vi.mock('node-cron', () => ({
  default: {
    schedule: (expr: string, cb: () => unknown, opts: unknown) => {
      h.scheduled.expr = expr;
      h.scheduled.cb = cb;
      h.scheduled.opts = opts;
      return { stop: h.stop };
    },
  },
}));
vi.mock('../src/config/index.js', () => ({ config: h.cfg }));
vi.mock('../src/utils/updateCheck.js', () => ({ performUpdateCheck: h.perform }));
vi.mock('../src/utils/jobTracker.js', () => ({ trackJob: h.track }));
vi.mock('../src/models/UpdateCheckState.js', () => ({
  UPDATE_CHECK_STATE_ID: 'github-latest',
  UpdateCheckState: { findById: h.findById },
}));
vi.mock('../src/utils/logger.js', () => ({
  createModuleLogger: () => h.log,
  errorMessage: (error: unknown) => (error instanceof Error ? error.message : String(error)),
}));

import {
  isUpdateCheckDue,
  runBootUpdateCheck,
  startUpdateCheckJob,
} from '../src/jobs/updateCheck.js';
import {
  UPDATE_CHECK_BOOT_DELAY_MS,
  UPDATE_CHECK_BOOT_JITTER_MS,
  UPDATE_CHECK_INTERVAL_HOURS,
} from '../src/constants/index.js';

const INTERVAL_MS = UPDATE_CHECK_INTERVAL_HOURS * 3_600_000;
const NOW = new Date('2026-09-28T12:00:00Z');

/** The stored state `findById(...).lean()` resolves to. */
function storedState(value: unknown): void {
  h.findById.mockReturnValue({ lean: () => Promise.resolve(value) });
}

/** A random source that answers in the order the job asks: minute, then jitter. */
function fixedRandom(minute: number, jitter: number) {
  const answers = [minute, jitter];
  return vi.fn((max: number) => {
    const next = answers.shift()!;
    expect(next).toBeLessThan(max);
    return next;
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  h.cfg.UPDATE_CHECK_ENABLED = true;
  h.cfg.UPDATE_CHECK_REPOSITORY = 'Hiprax/h-vault';
  h.cfg.NODE_ENV = 'production';
  h.scheduled.expr = '';
  h.scheduled.cb = undefined;
  h.scheduled.opts = undefined;
  h.perform.mockResolvedValue(true);
  storedState(null);
});

afterEach(() => {
  vi.useRealTimers();
});

describe('startUpdateCheckJob', () => {
  it('schedules nothing, and starts no boot check, when checks are turned off', () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    h.cfg.UPDATE_CHECK_ENABLED = false;
    expect(startUpdateCheckJob()).toBeNull();
    expect(h.scheduled.cb).toBeUndefined();
    vi.advanceTimersByTime(UPDATE_CHECK_BOOT_DELAY_MS + UPDATE_CHECK_BOOT_JITTER_MS);
    expect(h.track).not.toHaveBeenCalled();
  });

  it('schedules nothing in the test environment, even with checks turned on', () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    h.cfg.NODE_ENV = 'test';
    const random = vi.fn(() => 0);
    expect(startUpdateCheckJob({ random })).toBeNull();
    expect(h.scheduled.cb).toBeUndefined();
    expect(random).not.toHaveBeenCalled();
    vi.advanceTimersByTime(UPDATE_CHECK_BOOT_DELAY_MS + UPDATE_CHECK_BOOT_JITTER_MS);
    expect(h.track).not.toHaveBeenCalled();
  });

  it.each(['development', 'production'])('schedules the check in %s', (environment) => {
    h.cfg.NODE_ENV = environment;
    const job = startUpdateCheckJob({ random: fixedRandom(5, 0) });
    expect(job).not.toBeNull();
    expect(h.scheduled.expr).toBe(`5 */${String(UPDATE_CHECK_INTERVAL_HOURS)} * * *`);
    job?.stop();
  });

  it('runs every interval, in UTC, at the minute it drew', () => {
    const random = fixedRandom(17, 1234);
    const job = startUpdateCheckJob({ random });
    expect(job).not.toBeNull();
    expect(h.scheduled.expr).toBe(`17 */${String(UPDATE_CHECK_INTERVAL_HOURS)} * * *`);
    expect(h.scheduled.opts).toEqual({ timezone: 'UTC' });
    expect(random.mock.calls).toEqual([[60], [UPDATE_CHECK_BOOT_JITTER_MS]]);
    expect(h.log.info).toHaveBeenCalledWith('Release check scheduled', {
      repository: 'Hiprax/h-vault',
      everyHours: UPDATE_CHECK_INTERVAL_HOURS,
      minute: 17,
    });
    void job!.stop();
  });

  it('runs the check through the job tracker on each tick', async () => {
    const options = { random: fixedRandom(3, 0), now: () => NOW };
    const job = startUpdateCheckJob(options);
    h.scheduled.cb!();
    expect(h.perform).toHaveBeenCalledWith(options);
    expect(h.track).toHaveBeenCalledTimes(1);
    await expect(h.track.mock.calls[0]![0]).resolves.toBeUndefined();
    void job!.stop();
  });

  it('checks once after the boot delay plus the drawn jitter, when a check is due', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const job = startUpdateCheckJob({ random: fixedRandom(0, 1234) });
    vi.advanceTimersByTime(UPDATE_CHECK_BOOT_DELAY_MS + 1234 - 1);
    expect(h.track).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(h.track).toHaveBeenCalledTimes(1);
    await h.track.mock.calls[0]![0];
    expect(h.perform).toHaveBeenCalledTimes(1);
    void job!.stop();
  });

  it('stops its cron and cancels a boot check that has not run yet', () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const job = startUpdateCheckJob({ random: fixedRandom(0, 0) });
    void job!.stop();
    expect(h.stop).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(UPDATE_CHECK_BOOT_DELAY_MS + UPDATE_CHECK_BOOT_JITTER_MS);
    expect(h.track).not.toHaveBeenCalled();
  });

  it('draws its minute from the platform random source by default', () => {
    const job = startUpdateCheckJob();
    const minute = Number(h.scheduled.expr.split(' ')[0]);
    expect(Number.isInteger(minute)).toBe(true);
    expect(minute).toBeGreaterThanOrEqual(0);
    expect(minute).toBeLessThan(60);
    void job!.stop();
  });
});

describe('isUpdateCheckDue', () => {
  it('is due before any check', async () => {
    storedState(null);
    expect(await isUpdateCheckDue(NOW)).toBe(true);
  });

  it('is due when the stored check was for another repository', async () => {
    storedState({ repository: 'someone/fork', lastCheckedAt: NOW });
    expect(await isUpdateCheckDue(NOW)).toBe(true);
  });

  it('is due exactly one interval after the last check, and not a millisecond sooner', async () => {
    storedState({
      repository: 'Hiprax/h-vault',
      lastCheckedAt: new Date(NOW.getTime() - INTERVAL_MS),
    });
    expect(await isUpdateCheckDue(NOW)).toBe(true);
    storedState({
      repository: 'Hiprax/h-vault',
      lastCheckedAt: new Date(NOW.getTime() - INTERVAL_MS + 1),
    });
    expect(await isUpdateCheckDue(NOW)).toBe(false);
  });
});

describe('runBootUpdateCheck', () => {
  it('checks when a check is due', async () => {
    storedState(null);
    await runBootUpdateCheck({ now: () => NOW });
    expect(h.perform).toHaveBeenCalledWith({ now: expect.any(Function) });
  });

  it('skips the check when one ran recently, so a restart does not ask again', async () => {
    storedState({ repository: 'Hiprax/h-vault', lastCheckedAt: NOW });
    await runBootUpdateCheck({ now: () => NOW });
    expect(h.perform).not.toHaveBeenCalled();
  });

  it('logs a failure instead of throwing', async () => {
    h.findById.mockImplementation(() => {
      throw new Error('database unavailable');
    });
    await expect(runBootUpdateCheck()).resolves.toBeUndefined();
    expect(h.log.error).toHaveBeenCalledWith('Boot release check failed', {
      error: 'database unavailable',
    });
    expect(h.perform).not.toHaveBeenCalled();
  });
});
