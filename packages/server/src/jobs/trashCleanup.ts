import cron, { type ScheduledTask } from 'node-cron';
import type mongoose from 'mongoose';
import { createModuleLogger } from '../utils/logger.js';
import { storageConfigured } from '../config/index.js';
import { VaultItem } from '../models/VaultItem.js';
import { AuditLog } from '../models/AuditLog.js';
import { Document } from '../models/Document.js';
import { TRASH_AUTO_PURGE_DAYS } from '@hvault/shared';
import { acquireJobLock, releaseJobLock } from '../utils/jobLock.js';
import { trackJob } from '../utils/jobTracker.js';
import { getStorage } from '../services/storage/index.js';

const logger = createModuleLogger('jobs/trashCleanup');

const TRASH_CLEANUP_LOCK_TTL_MS = 15 * 60 * 1000; // 15 minutes

/**
 * Purge every document trashed before `cutoffDate`, oldest id first.
 *
 * ## A document is a row beside an object, so this is not the item loop
 *
 * The item loop above is one `deleteMany` per user per batch. A document also owns
 * a stored object, and the row holds the only wrapped copy of the key that
 * decrypts it, so each row is the same three ordered steps `purgeDocument`
 * performs for a user-initiated purge: mark `purgePending`, delete the OBJECT,
 * then delete the ROW. A crash or a failure AFTER the marker is written leaves a
 * marker the hourly garbage collector finishes; a failure writing the marker
 * itself leaves the row exactly as it was, for the next nightly run. The reverse
 * order would leave an object charged to nobody with nothing left to name it.
 *
 * ## Why it pages on `_id` and the item loop does not
 *
 * A row whose object delete fails is deliberately LEFT for the collector, so it
 * stays inside `deletedAt <= cutoff`. The item loop's `do … while (deleted ===
 * BATCH_SIZE)` re-reads the same predicate, which is safe only because every row
 * it reads is then deleted; here it would return the same failing page for ever.
 * Paging on `_id > lastId` ascending advances past a row whether it was purged or
 * skipped, so the walk is monotonic and terminates.
 *
 * ## Why it does not run at all without storage
 *
 * Deleting these rows while the objects are unreachable would destroy the only
 * wrapped DEK and leave ciphertext nobody can ever open, charged to a bucket the
 * server is not currently talking to. On a deployment that never enabled the
 * feature there is nothing here at all — the routes that create these rows sit
 * behind `requireStorage` — and on one whose `S3_*` variables were REMOVED after
 * documents existed, leaving the rows alone is the only answer that keeps them
 * recoverable if storage is configured again.
 *
 * Audit rows are written per BATCH, not once at the end, for the reason the item
 * loop states: a purge that happened must stay audited even if a later batch does
 * not finish. They reuse `trash_auto_purge` — this is the same scheduled operation
 * reaching a second collection, not a sixth document action.
 *
 * Returns the totals, for the job's own log line.
 */
async function purgeTrashedDocuments(
  cutoffDate: Date,
  batchSize: number,
): Promise<{ purged: number; failed: number }> {
  let purged = 0;
  let failed = 0;

  const storage = getStorage();
  let lastId: mongoose.Types.ObjectId | undefined;

  for (;;) {
    const expired = { deletedAt: { $lte: cutoffDate } };
    const page = await Document.find(
      lastId === undefined ? expired : { ...expired, _id: { $gt: lastId } },
    )
      .select('_id userId objectKey')
      .sort({ _id: 1 })
      .limit(batchSize)
      .lean();

    if (page.length === 0) break;

    const purgedByUser = new Map<string, number>();
    for (const row of page) {
      // The cursor advances BEFORE the work, so a row that fails is passed over
      // rather than read again on the next page.
      lastId = row._id;
      let marked = false;
      try {
        // THE CLAIM, and it is a compare-and-set rather than a bare write.
        //
        // The page was read at most one batch of network round trips ago, and in
        // that gap the owner may have pulled this very document back out of the
        // trash. `restoreDocument` requires `purgePending: null`, so once this
        // single-document atomic update lands, a restore can no longer win — but
        // only because the filter re-states `deletedAt <= cutoff`, which a
        // restored row no longer satisfies. Without it, the marker would be set
        // unconditionally, this loop would delete the OBJECT of a document the
        // user had just recovered, and the wrapped key would go with the row.
        const claim = await Document.updateOne(
          { _id: row._id, userId: row.userId, deletedAt: { $lte: cutoffDate } },
          { $set: { purgePending: true } },
        );
        if (claim.matchedCount === 0) {
          // Restored, purged by its owner, or otherwise no longer expired. Not a
          // failure and not a purge: there is simply nothing here to destroy.
          continue;
        }
        marked = true;
        await storage.deleteObject(row.objectKey);
        // `userId` in the delete filter as well as `_id`, the same
        // defense-in-depth the item loop applies to its own `deleteMany`. No
        // `deletedAt` here: the claim above already won the row, and re-testing a
        // predicate that this loop is now the sole owner of would only add a way
        // to leave a marked row behind.
        const { deletedCount } = await Document.deleteOne({ _id: row._id, userId: row.userId });
        if (deletedCount > 0) {
          const userId = String(row.userId);
          purgedByUser.set(userId, (purgedByUser.get(userId) ?? 0) + deletedCount);
          purged += deletedCount;
        }
      } catch (error: unknown) {
        failed += 1;
        const message = error instanceof Error ? error.message : 'Unknown error';
        logger.error(
          `Trash cleanup could not purge document ${String(row._id)}; ` +
            (marked
              ? `it keeps purgePending for the collector: ${message}`
              : `it was never marked, so the next run retries it: ${message}`),
        );
      }
    }

    if (purgedByUser.size > 0) {
      await AuditLog.insertMany(
        Array.from(purgedByUser.entries()).map(([userId, documentCount]) => ({
          userId,
          action: 'trash_auto_purge' as const,
          metadata: { documentCount, cutoffDays: TRASH_AUTO_PURGE_DAYS },
          ipAddress: 'system',
          userAgent: 'system/trash-cleanup-job',
          timestamp: new Date(),
        })),
      );
    }
  }

  return { purged, failed };
}

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

          // Documents are a second collection with a second kind of deletion —
          // see `purgeTrashedDocuments`. Skipped entirely when the operator has
          // not configured object storage, because deleting these rows without
          // reaching their objects would destroy the only wrapped copy of the key
          // that opens them.
          if (storageConfigured) {
            const documents = await purgeTrashedDocuments(cutoffDate, BATCH_SIZE);
            if (documents.purged > 0 || documents.failed > 0) {
              logger.info(
                `Trash cleanup complete: permanently deleted ${String(documents.purged)} document(s), ` +
                  `${String(documents.failed)} left for the collector`,
              );
            }
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
