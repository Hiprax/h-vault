import cron, { type ScheduledTask } from 'node-cron';
import { createLogger } from '@hiprax/logger';
import { config } from '../config/index.js';
import { PwnedRangeCache } from '../models/PwnedRangeCache.js';
import { acquireJobLock, releaseJobLock } from '../utils/jobLock.js';
import { trackJob } from '../utils/jobTracker.js';
import { seedBreachCorpus } from '../utils/breachSeed.js';

const logger = createLogger({ moduleName: 'jobs/breach-seed' });

/** Shared job-lock name for BOTH the CLI seed and the optional refresh cron. */
export const BREACH_SEED_LOCK_NAME = 'breach-seed';
/** Generous TTL: a full-corpus pass at modest concurrency stays well within a day. */
export const BREACH_SEED_LOCK_TTL_MS = 24 * 60 * 60 * 1000;

/**
 * Boot-time initialisation for the persistent breach range cache.
 *
 * NEVER downloads the corpus on boot. It only:
 *  1. logs a hint when the cache is empty (lookups will fall back to on-demand
 *     HIBP fetches until an operator runs `npm run seed-breaches`), and
 *  2. optionally schedules a refresh cron when `BREACH_SEED_REFRESH_CRON` is set.
 *     The scheduled job fetches missing/stale ranges only when `BREACH_SEED_AUTO`
 *     is true — otherwise it logs that auto-seed is disabled and does nothing.
 *
 * Returns the scheduled task (for graceful-shutdown registration) or null.
 * Intended to run on the primary worker only.
 */
export async function initBreachRangeCache(): Promise<ScheduledTask | null> {
  try {
    const count = await PwnedRangeCache.estimatedDocumentCount();
    if (count === 0) {
      logger.warn(
        'Breach range cache is empty; password-breach lookups fall back to on-demand HIBP fetches. ' +
          'To pre-seed the full corpus for offline/zero-dependency operation (tens of GB, several hours), run ' +
          '`npm run seed-breaches -w packages/server`.',
      );
    } else {
      logger.info(`Breach range cache holds ${String(count)} cached prefix range(s).`);
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    logger.warn(`Could not read breach range cache size at boot: ${message}`);
  }

  const cronExpr = config.BREACH_SEED_REFRESH_CRON;
  if (!cronExpr) return null;

  if (!cron.validate(cronExpr)) {
    logger.warn(
      `BREACH_SEED_REFRESH_CRON is not a valid cron expression: "${cronExpr}". Refresh disabled.`,
    );
    return null;
  }

  const task = cron.schedule(
    cronExpr,
    () => {
      const jobPromise = (async () => {
        if (!config.BREACH_SEED_AUTO) {
          logger.info('Breach seed refresh tick skipped: BREACH_SEED_AUTO is disabled.');
          return;
        }
        let lockId: string | null = null;
        try {
          lockId = await acquireJobLock(BREACH_SEED_LOCK_NAME, BREACH_SEED_LOCK_TTL_MS);
          if (!lockId) {
            logger.info('Breach seed refresh skipped: another instance holds the lock');
            return;
          }
          logger.info('Breach seed refresh started (fetching missing/stale ranges)');
          const res = await seedBreachCorpus({
            staleAfterDays: config.BREACH_CACHE_TTL_DAYS,
            onProgress: (done, total, failed) => {
              logger.info(
                `Breach seed refresh progress: ${String(done)}/${String(total)} (failed ${String(failed)})`,
              );
            },
          });
          logger.info(
            `Breach seed refresh complete: fetched ${String(res.fetched)}, skipped ${String(res.skipped)}, failed ${String(res.failed.length)}`,
          );
        } catch (error: unknown) {
          const message = error instanceof Error ? error.message : 'Unknown error';
          logger.error(`Breach seed refresh failed: ${message}`);
        } finally {
          if (lockId) {
            try {
              await releaseJobLock(BREACH_SEED_LOCK_NAME, lockId);
            } catch (releaseErr: unknown) {
              const msg = releaseErr instanceof Error ? releaseErr.message : 'Unknown error';
              logger.error(`Failed to release breach-seed lock: ${msg}`);
            }
          }
        }
      })();
      trackJob(jobPromise);
      return jobPromise;
    },
    { timezone: 'UTC' },
  );

  logger.info(
    `Breach seed refresh scheduled (${cronExpr} UTC, auto=${String(config.BREACH_SEED_AUTO)})`,
  );
  return task;
}
