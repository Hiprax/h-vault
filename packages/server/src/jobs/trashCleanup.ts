import cron, { type ScheduledTask } from 'node-cron';
import { createLogger } from '@hiprax/logger';
import { VaultItem } from '../models/VaultItem.js';
import { AuditLog } from '../models/AuditLog.js';
import { TRASH_AUTO_PURGE_DAYS } from '@hvault/shared';
import { acquireJobLock, releaseJobLock } from '../utils/jobLock.js';
import { trackJob } from '../utils/jobTracker.js';

const logger = createLogger({ moduleName: 'jobs/trashCleanup' });

const TRASH_CLEANUP_LOCK_TTL_MS = 15 * 60 * 1000; // 15 minutes

export function startTrashCleanupJob(): ScheduledTask {
  // Run daily at 2:00 AM UTC
  const task = cron.schedule(
    '0 2 * * *',
    () => {
      const jobPromise = (async () => {
        let lockId: string | null = null;
        try {
          lockId = await acquireJobLock('trash-cleanup', TRASH_CLEANUP_LOCK_TTL_MS);
          if (!lockId) {
            logger.info('Trash cleanup skipped: another instance holds the lock');
            return;
          }

          const cutoffDate = new Date();
          cutoffDate.setDate(cutoffDate.getDate() - TRASH_AUTO_PURGE_DAYS);

          const BATCH_SIZE = 500;
          let totalDeleted = 0;
          let deletedCount: number;
          do {
            const items = await VaultItem.find({ deletedAt: { $lte: cutoffDate } })
              .select('_id userId')
              .limit(BATCH_SIZE)
              .lean();
            if (items.length === 0) break;

            // Group items by userId for defense-in-depth delete filtering
            const itemsByUser = new Map<string, typeof items>();
            for (const item of items) {
              const uid = String(item.userId);
              const userItems = itemsByUser.get(uid);
              if (userItems) {
                userItems.push(item);
              } else {
                itemsByUser.set(uid, [item]);
              }
            }

            // Delete per-user with userId in filter for defense-in-depth
            deletedCount = 0;
            for (const [userId, userItems] of itemsByUser) {
              const result = await VaultItem.deleteMany({
                _id: { $in: userItems.map((i) => i._id) },
                userId,
              });
              deletedCount += result.deletedCount;
            }
            totalDeleted += deletedCount;

            // Create audit log entries immediately after each batch
            // so deleted items are always audited even if a later batch fails
            const auditEntries = Array.from(itemsByUser.entries()).map(([userId, userItems]) => ({
              userId,
              action: 'trash_auto_purge' as const,
              metadata: {
                itemCount: userItems.length,
                cutoffDays: TRASH_AUTO_PURGE_DAYS,
                batchSize: deletedCount,
              },
              ipAddress: 'system',
              userAgent: 'system/trash-cleanup-job',
              timestamp: new Date(),
            }));

            await AuditLog.insertMany(auditEntries);

            logger.info(
              `Trash cleanup batch: deleted ${String(deletedCount)} items for ${String(itemsByUser.size)} user(s)`,
            );
          } while (deletedCount === BATCH_SIZE);

          if (totalDeleted > 0) {
            logger.info(
              `Trash cleanup complete: permanently deleted ${String(totalDeleted)} total items`,
            );
          }
        } catch (error: unknown) {
          const message = error instanceof Error ? error.message : 'Unknown error';
          logger.error(`Trash cleanup job failed: ${message}`);
        } finally {
          // Only release a lock we actually acquired, and never let a transient
          // release failure escape the job promise (it would surface as an
          // unhandled rejection via the tracker bookkeeping chain).
          if (lockId) {
            try {
              await releaseJobLock('trash-cleanup', lockId);
            } catch (releaseErr: unknown) {
              const msg = releaseErr instanceof Error ? releaseErr.message : 'Unknown error';
              logger.error(`Failed to release trash-cleanup lock: ${msg}`);
            }
          }
        }
      })();
      trackJob(jobPromise);
      return jobPromise;
    },
    { timezone: 'UTC' },
  );

  logger.info('Trash cleanup job scheduled (daily at 2:00 AM UTC)');
  return task;
}
