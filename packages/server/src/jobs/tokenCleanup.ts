import cron, { type ScheduledTask } from 'node-cron';
import { createLogger } from '@hiprax/logger';
import { RefreshToken } from '../models/RefreshToken.js';
import { User } from '../models/User.js';
import { acquireJobLock, releaseJobLock } from '../utils/jobLock.js';
import { cascadeDeleteUser } from '../utils/cascadeDelete.js';
import { trackJob } from '../utils/jobTracker.js';

const logger = createLogger({ moduleName: 'jobs/tokenCleanup' });

const TOKEN_CLEANUP_LOCK_TTL_MS = 10 * 60 * 1000; // 10 minutes

/**
 * Cleanup for unused-and-expired refresh tokens.
 *
 * NOTE: The RefreshToken model has a TTL index on `usedAt` with
 * `expireAfterSeconds = REUSE_DETECTION_WINDOW_SECONDS` (7 days) — MongoDB
 * auto-evicts consumed tokens 7 days after rotation, regardless of when
 * their original `expiresAt` would have fallen. The TTL on `expiresAt` was
 * intentionally removed because it would have deleted consumed tokens at
 * `expiresAt` and collapsed the reuse-detection window to near-zero for
 * tokens consumed late in their 7-day life.
 *
 * This cron is the primary cleanup for tokens that were never consumed and
 * whose `expiresAt` has passed (the TTL on `usedAt` cannot reach them since
 * `usedAt` is undefined). It also acts as a safety net for the TTL on
 * `usedAt` if the monitor falls behind.
 */
export function startTokenCleanupJob(): ScheduledTask {
  // Run every 6 hours
  const task = cron.schedule(
    '0 */6 * * *',
    () => {
      const jobPromise = (async () => {
        let lockId: string | null = null;
        try {
          lockId = await acquireJobLock('token-cleanup', TOKEN_CLEANUP_LOCK_TTL_MS);
          if (!lockId) {
            logger.info('Token cleanup skipped: another instance holds the lock');
            return;
          }

          // Delete UNUSED tokens whose expiresAt has passed. Consumed tokens
          // are excluded so the TTL on `usedAt` can preserve them for the
          // full reuse-detection window even if `expiresAt` has elapsed.
          const expiredResult = await RefreshToken.deleteMany({
            expiresAt: { $lte: new Date() },
            $or: [{ usedAt: { $exists: false } }, { usedAt: null }],
          });

          // Safety net: delete consumed tokens older than the reuse-detection
          // window. The TTL index on `usedAt` should already evict these; this
          // catch-up exists in case the TTL monitor lags during heavy load.
          const REUSE_DETECTION_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
          const consumedResult = await RefreshToken.deleteMany({
            usedAt: {
              $exists: true,
              $ne: null,
              $lt: new Date(Date.now() - REUSE_DETECTION_WINDOW_MS),
            },
          });

          const totalDeleted = expiredResult.deletedCount + consumedResult.deletedCount;
          if (totalDeleted > 0) {
            logger.info(
              `Token cleanup: removed ${String(expiredResult.deletedCount)} expired and ${String(consumedResult.deletedCount)} consumed tokens`,
            );
          }

          // Complete deletion for users stuck in deletionPending state.
          // This handles the case where the server crashed mid-deletion in the
          // deleteAccount endpoint — the user was marked deletionPending but the
          // cascading data cleanup didn't finish.
          //
          // The cascade is invoked directly, with NO pre-clearing "claim" write.
          // `deletionPending` is the only durable record that this user's data
          // still needs erasing, so clearing it before the erasure is durable
          // would strand the user's data invisibly (a GDPR erasure failure) if
          // the process died mid-cascade. Instead: on success the cascade
          // deletes the User document (flag and all); on a handled failure the
          // cascade re-sets the flag; on a hard crash the flag was never
          // touched — every outcome leaves the user retryable on the next cycle.
          // Concurrency is bounded by the `token-cleanup` job lock, and the
          // cascade's deletes are idempotent, so a run that races a TTL-expired
          // predecessor re-does the same deletes rather than corrupting state.
          const zombieUsers = await User.find({ deletionPending: true }).lean();
          for (const zombie of zombieUsers) {
            const userId = zombie._id;
            try {
              const deleted = await cascadeDeleteUser({
                userId,
                userEmail: zombie.email,
                ip: 'system',
                userAgent: 'system/token-cleanup-job',
                auditAction: 'deletion_cleanup',
              });

              if (deleted) {
                logger.info(
                  `Deletion cleanup: completed pending deletion for user ${userId.toString()}`,
                );
              } else {
                logger.warn(
                  `Deletion cleanup: cascade failed for user ${userId.toString()}; deletionPending remains set for retry`,
                );
              }
            } catch (cleanupErr: unknown) {
              const msg = cleanupErr instanceof Error ? cleanupErr.message : 'Unknown error';
              logger.error(`Deletion cleanup failed for user ${userId.toString()}: ${msg}`);
            }
          }
        } catch (error: unknown) {
          const message = error instanceof Error ? error.message : 'Unknown error';
          logger.error(`Token cleanup job failed: ${message}`);
        } finally {
          // Only release a lock we actually acquired, and never let a transient
          // release failure escape the job promise (it would surface as an
          // unhandled rejection via the tracker bookkeeping chain).
          if (lockId) {
            try {
              await releaseJobLock('token-cleanup', lockId);
            } catch (releaseErr: unknown) {
              const msg = releaseErr instanceof Error ? releaseErr.message : 'Unknown error';
              logger.error(`Failed to release token-cleanup lock: ${msg}`);
            }
          }
        }
      })();
      trackJob(jobPromise);
      return jobPromise;
    },
    { timezone: 'UTC' },
  );

  logger.info('Token cleanup job scheduled (every 6 hours, safety net for TTL index)');
  return task;
}
