import cron, { type ScheduledTask } from 'node-cron';
import type mongoose from 'mongoose';
import { createModuleLogger, errorMessage } from '../utils/logger.js';
import { User } from '../models/User.js';
import { trimActivityAuditRows, trimStrangerAuditRows } from '../services/auditService.js';
import { acquireJobLock, releaseJobLock } from '../utils/jobLock.js';
import { trackJob } from '../utils/jobTracker.js';
import { capOnDemandRanges } from '../utils/breachRangeCap.js';
import { sendOwedRecipientConfirmations } from '../utils/backupRecipients.js';
import { recountVaultQuotas } from '../utils/vaultQuota.js';

const logger = createModuleLogger('jobs/maintenance');

const MAINTENANCE_LOCK_NAME = 'maintenance';
const MAINTENANCE_LOCK_TTL_MS = 15 * 60 * 1000;

/** How many accounts the audit trim reads per page of the `users` collection. */
const ACCOUNT_PAGE_SIZE = 500;

/**
 * One named piece of hourly housekeeping. Steps run in order, each on its own:
 * a step that throws is logged and the next one still runs.
 */
export interface MaintenanceStep {
  name: string;
  run: () => Promise<void>;
}

/**
 * How long one run of the audit trim may walk before it stops and leaves the rest
 * for the next hour: well inside the 15-minute lock, which is never renewed, so a
 * slow walk can never overlap a second instance's.
 */
const AUDIT_TRIM_BUDGET_MS = 10 * 60 * 1000;

/**
 * How many accounts in a row may fail before the walk stops. One account that
 * fails is logged and passed over; a run of them is a database that is refusing,
 * and walking every account to log two errors each would only bury the cause.
 */
const AUDIT_TRIM_MAX_CONSECUTIVE_FAILURES = 5;

/**
 * Where the last run stopped when its budget ran out, so the next one carries on
 * from there instead of starting again at the first account. Per process: a
 * restart begins at the top, which costs one pass and loses nothing.
 */
let auditTrimResumeAfter: mongoose.Types.ObjectId | undefined;

/** Forgets where the audit trim stopped. For tests. */
export function resetAuditTrimCursor(): void {
  auditTrimResumeAfter = undefined;
}

/**
 * Brings every account's audit log back inside its caps: the activity class to
 * `MAX_ACTIVITY_AUDIT_ROWS_PER_USER` and the stranger-writable actions to
 * `MAX_STRANGER_AUDIT_ROWS_PER_USER`.
 *
 * `auditService` also trims an account on every hundredth insert, but that count
 * is per process and forgotten on restart, so on its own an account could sit
 * above a cap for as long as its writes kept landing on different workers. This
 * pass is what makes the cap a bound rather than a tendency: at most an hour of
 * writes above it, whatever the topology (longer only on an instance so large
 * that one pass takes more than its budget). It walks `users` by `_id` a page at
 * a time, so a deployment of any size is read in bounded memory; one account
 * whose trim fails is logged and passed over; a run of failures stops the walk.
 *
 * @param budgetMs How long this run may walk; it always finishes at least one
 *                 account, so a zero budget still makes progress. Tests pass it.
 */
export async function trimEveryAccountsAuditLog(
  budgetMs: number = AUDIT_TRIM_BUDGET_MS,
): Promise<void> {
  const startedAt = Date.now();
  let lastId = auditTrimResumeAfter;
  let accounts = 0;
  let activityRemoved = 0;
  let strangerRemoved = 0;
  let failures = 0;
  let consecutiveFailures = 0;

  for (;;) {
    const page = await User.find(lastId === undefined ? {} : { _id: { $gt: lastId } })
      .select('_id')
      .sort({ _id: 1 })
      .limit(ACCOUNT_PAGE_SIZE)
      .lean();
    if (page.length === 0) {
      // A whole pass finished: the next run starts at the first account again.
      auditTrimResumeAfter = undefined;
      break;
    }

    for (const { _id } of page) {
      lastId = _id;
      accounts += 1;
      const userId = _id.toString();
      let failed = false;
      try {
        activityRemoved += await trimActivityAuditRows(userId);
      } catch (err: unknown) {
        failed = true;
        logger.error("Could not trim an account's activity audit rows", {
          userId,
          error: errorMessage(err),
        });
      }
      try {
        strangerRemoved += await trimStrangerAuditRows(userId);
      } catch (err: unknown) {
        failed = true;
        logger.error("Could not trim an account's stranger-writable audit rows", {
          userId,
          error: errorMessage(err),
        });
      }
      if (failed) {
        failures += 1;
        consecutiveFailures += 1;
        if (consecutiveFailures >= AUDIT_TRIM_MAX_CONSECUTIVE_FAILURES) {
          // Nothing is carried over: the next run starts again from the top.
          auditTrimResumeAfter = undefined;
          logger.error('Audit trim stopped: several accounts in a row could not be trimmed', {
            accounts,
            failures,
          });
          return;
        }
      } else {
        consecutiveFailures = 0;
      }
      if (Date.now() - startedAt >= budgetMs) {
        auditTrimResumeAfter = _id;
        logger.info('Audit trim paused at its time budget; the next run continues from here', {
          accounts,
          activityRemoved,
          strangerRemoved,
          failures,
        });
        return;
      }
    }
  }

  logger.info('Audit trim complete', { accounts, activityRemoved, strangerRemoved, failures });
}

/**
 * Every hourly step, in order. Later work that must run every hour whatever else
 * the deployment has configured (no object storage, no SMTP) is appended here
 * rather than given a cron of its own: `trashCleanup` runs daily,
 * `documentCleanup` does not exist without storage, and `backupScheduler` holds
 * its lock for half an hour.
 */
const MAINTENANCE_STEPS: readonly MaintenanceStep[] = [
  { name: 'audit-trim', run: () => trimEveryAccountsAuditLog() },
  { name: 'hibp-range-cap', run: () => capOnDemandRanges() },
  // F-24 and F-15: corrects the vault counters that drifted (a crash between a row
  // write and its settle, an ambiguous failure whose reservation was kept): the
  // byte count and the two row counts behind the per-user caps, rewritten together
  // from the same two aggregates, for a bounded batch of quiet accounts. 45
  // seconds, plus at most one account's two 5-second aggregates past it.
  { name: 'vault-quota-recount', run: () => recountVaultQuotas().then(() => undefined) },
  // Phase 6 (F-05): the confirmation mails backup recipients are still owed —
  // only ever for addresses the owner approved with the master password, within
  // each account's daily email budget. Last and short (one minute): the steps
  // above budget just under 14 of the lock's 15 minutes.
  { name: 'backup-recipient-confirmations', run: () => sendOwedRecipientConfirmations() },
];

/**
 * One maintenance run: take the `maintenance` lock (another instance holding it
 * means that instance is doing this run, so this one does nothing), run every
 * step, release the lock. Never rejects.
 *
 * @param steps The steps to run. The default is the production list; tests pass
 *              their own to exercise the isolation between steps.
 */
export async function runMaintenance(
  steps: readonly MaintenanceStep[] = MAINTENANCE_STEPS,
): Promise<void> {
  let lockId: string | null = null;
  try {
    lockId = await acquireJobLock(MAINTENANCE_LOCK_NAME, MAINTENANCE_LOCK_TTL_MS);
    if (!lockId) {
      logger.info('Maintenance skipped: another instance holds the lock');
      return;
    }
    for (const step of steps) {
      try {
        await step.run();
      } catch (err: unknown) {
        logger.error(`Maintenance step "${step.name}" failed`, { error: errorMessage(err) });
      }
    }
  } catch (err: unknown) {
    logger.error('Maintenance run failed', { error: errorMessage(err) });
  } finally {
    // Only a lock this run acquired is released, and a failed release is logged
    // rather than let escape the job promise.
    if (lockId) {
      try {
        await releaseJobLock(MAINTENANCE_LOCK_NAME, lockId);
      } catch (err: unknown) {
        logger.error('Failed to release the maintenance lock', { error: errorMessage(err) });
      }
    }
  }
}

/**
 * Schedules {@link runMaintenance} hourly at :15 UTC — off :00, where the backup
 * scheduler, the token cleanup and the nightly trash purge fire, and off :30, the
 * document collector's minute. Started on the primary worker only, like every other cron,
 * and unconditionally: no step needs object storage, and the one step that sends
 * mail (recipient confirmations) does nothing while email is not configured.
 */
export function startMaintenanceJob(): ScheduledTask {
  const task = cron.schedule(
    '15 * * * *',
    () => {
      const run = runMaintenance();
      trackJob(run);
      return run;
    },
    { timezone: 'UTC' },
  );
  logger.info('Maintenance job scheduled (hourly at :15 UTC)');
  return task;
}
