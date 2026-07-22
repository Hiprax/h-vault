import { describe, it, expect, vi, beforeEach } from 'vitest';

// Fully-mocked unit test for the boot-time breach-cache init + optional refresh
// cron. No DB or network: the model, config, seeder, job lock, tracker and
// node-cron are all stubbed so we can drive every branch deterministically.
const h = vi.hoisted(() => ({
  cfg: {
    BREACH_SEED_REFRESH_CRON: undefined as string | undefined,
    BREACH_SEED_AUTO: false,
    BREACH_CACHE_TTL_DAYS: 30,
  },
  cronValid: { value: true },
  scheduledCb: { fn: undefined as undefined | (() => unknown) },
  estimatedCount: vi.fn(),
  seedMock: vi.fn(),
  acquireMock: vi.fn(),
  releaseMock: vi.fn(),
  scheduleMock: vi.fn(),
  validateMock: vi.fn(),
}));

vi.mock('node-cron', () => ({
  default: {
    schedule: (expr: string, cb: () => unknown, opts: unknown) => {
      h.scheduledCb.fn = cb;
      h.scheduleMock(expr, cb, opts);
      return { stop: vi.fn() };
    },
    validate: (expr: string) => {
      h.validateMock(expr);
      return h.cronValid.value;
    },
  },
}));
vi.mock('../src/config/index.js', () => ({ config: h.cfg }));
vi.mock('../src/models/PwnedRangeCache.js', () => ({
  PwnedRangeCache: { estimatedDocumentCount: h.estimatedCount },
}));
vi.mock('../src/utils/breachSeed.js', () => ({ seedBreachCorpus: h.seedMock }));
vi.mock('../src/utils/jobLock.js', () => ({
  acquireJobLock: h.acquireMock,
  releaseJobLock: h.releaseMock,
}));
vi.mock('../src/utils/jobTracker.js', () => ({ trackJob: vi.fn() }));

import { initBreachRangeCache } from '../src/jobs/breachSeed.js';

describe('initBreachRangeCache', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    h.cfg.BREACH_SEED_REFRESH_CRON = undefined;
    h.cfg.BREACH_SEED_AUTO = false;
    h.cfg.BREACH_CACHE_TTL_DAYS = 30;
    h.cronValid.value = true;
    h.scheduledCb.fn = undefined;
    h.estimatedCount.mockResolvedValue(0);
    h.seedMock.mockResolvedValue({ fetched: 1, skipped: 0, failed: [], aborted: false });
    h.acquireMock.mockResolvedValue('lock-1');
    h.releaseMock.mockResolvedValue(undefined);
  });

  it('logs a hint and returns null when the cache is empty and no cron is configured', async () => {
    h.estimatedCount.mockResolvedValue(0);
    const task = await initBreachRangeCache();
    expect(task).toBeNull();
    expect(h.scheduleMock).not.toHaveBeenCalled();
  });

  it('returns null when the cache is populated and no cron is configured', async () => {
    h.estimatedCount.mockResolvedValue(42);
    const task = await initBreachRangeCache();
    expect(task).toBeNull();
  });

  it('tolerates a failure reading the cache size at boot', async () => {
    h.estimatedCount.mockRejectedValue(new Error('db down'));
    const task = await initBreachRangeCache();
    expect(task).toBeNull();
  });

  it('schedules the refresh cron when a valid expression is configured', async () => {
    h.cfg.BREACH_SEED_REFRESH_CRON = '0 3 * * 0';
    const task = await initBreachRangeCache();
    expect(h.validateMock).toHaveBeenCalledWith('0 3 * * 0');
    expect(h.scheduleMock).toHaveBeenCalledWith('0 3 * * 0', expect.any(Function), {
      timezone: 'UTC',
    });
    expect(task).not.toBeNull();
  });

  it('does not schedule when the cron expression is invalid', async () => {
    h.cfg.BREACH_SEED_REFRESH_CRON = 'nonsense';
    h.cronValid.value = false;
    const task = await initBreachRangeCache();
    expect(h.scheduleMock).not.toHaveBeenCalled();
    expect(task).toBeNull();
  });

  it('scheduled tick skips seeding when BREACH_SEED_AUTO is false', async () => {
    h.cfg.BREACH_SEED_REFRESH_CRON = '0 3 * * 0';
    await initBreachRangeCache();
    expect(h.scheduledCb.fn).toBeDefined();
    await h.scheduledCb.fn!();
    expect(h.acquireMock).not.toHaveBeenCalled();
    expect(h.seedMock).not.toHaveBeenCalled();
  });

  it('scheduled tick seeds under the job lock when BREACH_SEED_AUTO is true', async () => {
    h.cfg.BREACH_SEED_REFRESH_CRON = '0 3 * * 0';
    h.cfg.BREACH_SEED_AUTO = true;
    await initBreachRangeCache();
    await h.scheduledCb.fn!();
    expect(h.acquireMock).toHaveBeenCalledWith('breach-seed', expect.any(Number));
    expect(h.seedMock).toHaveBeenCalledWith(expect.objectContaining({ staleAfterDays: 30 }));
    expect(h.releaseMock).toHaveBeenCalledWith('breach-seed', 'lock-1');
  });

  it('scheduled tick skips when another instance holds the lock', async () => {
    h.cfg.BREACH_SEED_REFRESH_CRON = '0 3 * * 0';
    h.cfg.BREACH_SEED_AUTO = true;
    h.acquireMock.mockResolvedValue(null);
    await initBreachRangeCache();
    await h.scheduledCb.fn!();
    expect(h.seedMock).not.toHaveBeenCalled();
    expect(h.releaseMock).not.toHaveBeenCalled();
  });

  it('scheduled tick releases the lock even if seeding throws', async () => {
    h.cfg.BREACH_SEED_REFRESH_CRON = '0 3 * * 0';
    h.cfg.BREACH_SEED_AUTO = true;
    h.seedMock.mockRejectedValue(new Error('seed boom'));
    await initBreachRangeCache();
    await h.scheduledCb.fn!();
    expect(h.releaseMock).toHaveBeenCalledWith('breach-seed', 'lock-1');
  });

  it('scheduled tick swallows a lock-release failure', async () => {
    h.cfg.BREACH_SEED_REFRESH_CRON = '0 3 * * 0';
    h.cfg.BREACH_SEED_AUTO = true;
    h.releaseMock.mockRejectedValue(new Error('release boom'));
    await initBreachRangeCache();
    await h.scheduledCb.fn!();
    expect(h.releaseMock).toHaveBeenCalled();
  });
});
