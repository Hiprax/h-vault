import { describe, it, expect } from 'vitest';
import { JobLock } from '../src/models/JobLock.js';
import { acquireJobLock, releaseJobLock } from '../src/utils/jobLock.js';

describe('JobLock', () => {
  describe('JobLock model', () => {
    it('should create a job lock document', async () => {
      const lock = await JobLock.create({
        jobName: 'test-job',
        lockedBy: 'instance-1',
        lockedAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000),
      });

      expect(lock.jobName).toBe('test-job');
      expect(lock.lockedBy).toBe('instance-1');
      expect(lock.expiresAt).toBeDefined();
    });

    it('should enforce unique jobName', async () => {
      await JobLock.create({
        jobName: 'unique-job',
        lockedBy: 'instance-1',
        lockedAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000),
      });

      await expect(
        JobLock.create({
          jobName: 'unique-job',
          lockedBy: 'instance-2',
          lockedAt: new Date(),
          expiresAt: new Date(Date.now() + 60_000),
        }),
      ).rejects.toThrow();
    });
  });

  describe('acquireJobLock', () => {
    it('should acquire a lock when no lock exists', async () => {
      const lockId = await acquireJobLock('new-job', 60_000);
      expect(lockId).toBeTruthy();
      expect(typeof lockId).toBe('string');
    });

    it('should not acquire a lock when another instance holds it', async () => {
      // Create an existing non-expired lock from a different instance
      await JobLock.create({
        jobName: 'held-job',
        lockedBy: 'other-instance',
        lockedAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000),
      });

      const lockId = await acquireJobLock('held-job', 60_000);
      expect(lockId).toBeNull();
    });

    it('should acquire a lock when existing lock is expired', async () => {
      // Create an expired lock
      await JobLock.create({
        jobName: 'expired-job',
        lockedBy: 'other-instance',
        lockedAt: new Date(Date.now() - 120_000),
        expiresAt: new Date(Date.now() - 60_000),
      });

      const lockId = await acquireJobLock('expired-job', 60_000);
      expect(lockId).toBeTruthy();
    });
  });

  describe('releaseJobLock', () => {
    it('should release a held lock', async () => {
      const lockId = await acquireJobLock('release-job', 60_000);
      expect(lockId).toBeTruthy();

      await releaseJobLock('release-job', lockId!);

      const lock = await JobLock.findOne({ jobName: 'release-job' });
      expect(lock).toBeNull();
    });

    it('should not release a lock held by a different instance', async () => {
      await JobLock.create({
        jobName: 'other-lock',
        lockedBy: 'other-instance',
        lockedAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000),
      });

      await releaseJobLock('other-lock', 'wrong-instance-id');

      // The lock must survive a release attempt carrying the wrong token, and
      // must still be owned by the original holder. `toBeDefined()` was a
      // vacuous check here: `findOne` resolves to `null` (not `undefined`) when
      // the document is gone, and `expect(null).toBeDefined()` passes — so a
      // release that dropped the `lockedBy` scope would not have failed it.
      const lock = await JobLock.findOne({ jobName: 'other-lock' });
      expect(lock).not.toBeNull();
      expect(lock!.lockedBy).toBe('other-instance');
    });
  });

  /**
   * The lock token must identify the ACQUISITION, not the process. A run that
   * overruns its TTL has its lock re-acquired — in a single-instance
   * deployment, by the very same process on the next cron tick. If `lockedBy`
   * were a process-constant id, the stale run's release would match (and
   * delete) the live lock document belonging to the new run, letting a third
   * caller start the job while the second one is still executing.
   */
  describe('per-acquisition lock token', () => {
    it('should mint a distinct token for each acquisition of the same job', async () => {
      const first = await acquireJobLock('token-job', 60_000);
      expect(first).toBeTruthy();
      await releaseJobLock('token-job', first!);

      const second = await acquireJobLock('token-job', 60_000);
      expect(second).toBeTruthy();
      expect(second).not.toBe(first);
    });

    it('should not let a stale run release a lock that was re-acquired', async () => {
      // Run 1 acquires the lock.
      const staleToken = await acquireJobLock('stale-job', 60_000);
      expect(staleToken).toBeTruthy();

      // Run 1 overruns its TTL: force-expire its lock.
      await JobLock.updateOne(
        { jobName: 'stale-job' },
        { $set: { expiresAt: new Date(Date.now() - 1_000) } },
      );

      // Run 2 (same process) re-acquires it.
      const liveToken = await acquireJobLock('stale-job', 60_000);
      expect(liveToken).toBeTruthy();
      expect(liveToken).not.toBe(staleToken);

      // Run 1 finally finishes and releases with its own — now stale — token.
      await releaseJobLock('stale-job', staleToken!);

      // Run 2's lock must survive, still held by run 2.
      const lock = await JobLock.findOne({ jobName: 'stale-job' });
      expect(lock).not.toBeNull();
      expect(lock!.lockedBy).toBe(liveToken);

      // And a third caller must still be locked out while run 2 holds it.
      await expect(acquireJobLock('stale-job', 60_000)).resolves.toBeNull();

      // The live holder can still release its own lock.
      await releaseJobLock('stale-job', liveToken!);
      expect(await JobLock.findOne({ jobName: 'stale-job' })).toBeNull();
    });
  });
});
