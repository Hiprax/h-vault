import { describe, it, expect, vi, beforeEach } from 'vitest';

/**
 * Finding G: on a fresh production cluster boot `autoIndex` is off and index
 * creation is a separate manual step, so the `JobLock.jobName` /
 * `Migration.version` unique indexes may not exist yet when `runMigrations`
 * runs — leaving the migration lock without any uniqueness to serialize on and
 * allowing duplicate migration-version rows. `runMigrations` now builds those
 * two tiny indexes BEFORE acquiring the migration lock.
 *
 * In the test env `NODE_ENV=test` so `autoIndex` is ON and mongodb-memory-server
 * builds these unique indexes regardless — a "concurrent runMigrations don't
 * double-insert" assertion would pass with OR without the fix. The load-bearing
 * behavior is instead asserted directly: `createIndexes()` for both models is
 * invoked BEFORE `acquireJobLock`.
 */

// Control the migration lock so acquire/release are observable without touching
// the real JobLock collection — we only assert index-build ORDER relative to it.
const { mockAcquire, mockRelease } = vi.hoisted(() => ({
  mockAcquire: vi.fn(),
  mockRelease: vi.fn(),
}));

vi.mock('../src/utils/jobLock.js', () => ({
  acquireJobLock: mockAcquire,
  releaseJobLock: mockRelease,
}));

import { JobLock } from '../src/models/JobLock.js';
import { Migration } from '../src/models/Migration.js';
import { runMigrations } from '../src/utils/migrations.js';

describe('runMigrations — boot-time index building (Finding G)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockAcquire.mockResolvedValue('lock-id');
    mockRelease.mockResolvedValue(undefined);
  });

  it('builds the JobLock and Migration indexes BEFORE acquiring the migration lock', async () => {
    const jobLockIdx = vi.spyOn(JobLock, 'createIndexes');
    const migrationIdx = vi.spyOn(Migration, 'createIndexes');

    // Empty registry → no migration side effects; we only exercise the boot path.
    await runMigrations([]);

    expect(jobLockIdx).toHaveBeenCalledTimes(1);
    expect(migrationIdx).toHaveBeenCalledTimes(1);
    expect(mockAcquire).toHaveBeenCalledTimes(1);

    // Ordering is the load-bearing invariant: the unique indexes must exist
    // before the lock is acquired, otherwise the lock's mutual exclusion (and
    // the version dedup) is inert on a fresh cluster boot.
    const acquireOrder = mockAcquire.mock.invocationCallOrder[0]!;
    expect(jobLockIdx.mock.invocationCallOrder[0]!).toBeLessThan(acquireOrder);
    expect(migrationIdx.mock.invocationCallOrder[0]!).toBeLessThan(acquireOrder);

    jobLockIdx.mockRestore();
    migrationIdx.mockRestore();
  });

  it('rebuilds the jobName and version unique indexes when they are missing (fresh-boot path)', async () => {
    const hasJobNameUnique = (idxs: { key: unknown; unique?: boolean }[]) =>
      idxs.some(
        (idx) => JSON.stringify(idx.key) === JSON.stringify({ jobName: 1 }) && idx.unique === true,
      );
    const hasVersionUnique = (idxs: { key: unknown; unique?: boolean }[]) =>
      idxs.some(
        (idx) => JSON.stringify(idx.key) === JSON.stringify({ version: 1 }) && idx.unique === true,
      );

    // Simulate a fresh production cluster boot: autoIndex is off and the indexes
    // have NOT been built yet. The test env (autoIndex on + setup.ts's beforeAll
    // createIndexes) builds them regardless, so we must DROP them first —
    // otherwise this assertion would hold with OR without `ensureLockIndexes`,
    // exactly the vacuity this rewrite fixes.
    await JobLock.collection.dropIndexes();
    await Migration.collection.dropIndexes();
    expect(hasJobNameUnique(await JobLock.collection.indexes())).toBe(false);
    expect(hasVersionUnique(await Migration.collection.indexes())).toBe(false);

    // runMigrations must rebuild them via ensureLockIndexes BEFORE the lock is
    // acquired. If that pre-build is removed the indexes stay missing here.
    await runMigrations([]);

    expect(hasJobNameUnique(await JobLock.collection.indexes())).toBe(true);
    expect(hasVersionUnique(await Migration.collection.indexes())).toBe(true);
  });
});
