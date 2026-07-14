import { randomUUID } from 'node:crypto';
import { JobLock } from '../models/JobLock.js';

/**
 * Acquire a distributed job lock, returning an id that identifies THIS
 * acquisition (or `null` when another holder owns a live lock).
 *
 * The id is minted fresh on every call, never derived from a process-constant
 * instance id. A run that outlives its TTL has its lock treated as expired and
 * re-acquired — possibly by the SAME process (a clustered worker running the
 * next cron tick). With a process-constant `lockedBy`, the stale run's
 * `releaseJobLock` would match the NEW run's lock document and delete it,
 * handing the job to a third caller while the second one is still executing.
 * Releasing by the per-acquisition id makes a stale release a no-op instead.
 */
export async function acquireJobLock(jobName: string, ttlMs: number): Promise<string | null> {
  const now = new Date();
  const expiresAt = new Date(now.getTime() + ttlMs);
  const lockId = randomUUID();

  try {
    const result = await JobLock.findOneAndUpdate(
      {
        jobName,
        $or: [{ expiresAt: { $lte: now } }, { expiresAt: { $exists: false } }],
      },
      {
        $set: {
          lockedBy: lockId,
          lockedAt: now,
          expiresAt,
        },
        $setOnInsert: { jobName },
      },
      { upsert: true, returnDocument: 'after' },
    );

    if (result.lockedBy === lockId) {
      return lockId;
    }
    return null;
  } catch (error: unknown) {
    if (error instanceof Error && 'code' in error && (error as { code: number }).code === 11000) {
      return null;
    }
    throw error;
  }
}

/**
 * Release a lock previously acquired with `acquireJobLock`.
 *
 * Scoped to the acquisition id, so a release issued by a stale (TTL-expired)
 * run cannot free a lock that has since been re-acquired.
 */
export async function releaseJobLock(jobName: string, lockId: string): Promise<void> {
  await JobLock.deleteOne({ jobName, lockedBy: lockId });
}
