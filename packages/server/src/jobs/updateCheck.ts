import { randomInt } from 'node:crypto';
import cron from 'node-cron';
import { config } from '../config/index.js';
import {
  UPDATE_CHECK_BOOT_DELAY_MS,
  UPDATE_CHECK_BOOT_JITTER_MS,
  UPDATE_CHECK_INTERVAL_HOURS,
} from '../constants/index.js';
import { UPDATE_CHECK_STATE_ID, UpdateCheckState } from '../models/UpdateCheckState.js';
import { trackJob } from '../utils/jobTracker.js';
import { createModuleLogger, errorMessage } from '../utils/logger.js';
import { performUpdateCheck, type CheckOptions } from '../utils/updateCheck.js';

const logger = createModuleLogger('jobs/updateCheck');

/** What `createGracefulShutdown` needs from a started job. */
interface StartedJob {
  stop(): void | Promise<void>;
}

/** Overrides for tests: the random source, the clock and the check's fetch options. */
export interface UpdateCheckJobOptions extends CheckOptions {
  /** A uniform integer in [0, max). Defaults to the platform's CSPRNG. */
  random?: (max: number) => number;
}

/**
 * Whether the stored state is old enough that a boot should check now rather
 * than wait for the schedule: never checked, checked for another repository, or
 * last checked a full interval ago. Keeps a server that restarts often from
 * asking GitHub on every start.
 */
export async function isUpdateCheckDue(now: Date): Promise<boolean> {
  const state = await UpdateCheckState.findById(UPDATE_CHECK_STATE_ID).lean();
  if (state?.repository !== config.UPDATE_CHECK_REPOSITORY) return true;
  return now.getTime() - state.lastCheckedAt.getTime() >= UPDATE_CHECK_INTERVAL_HOURS * 3_600_000;
}

/** The boot check: waits out the boot delay, then checks only if one is due. */
export async function runBootUpdateCheck(options: CheckOptions = {}): Promise<void> {
  try {
    if (await isUpdateCheckDue(options.now?.() ?? new Date())) {
      await performUpdateCheck(options);
    }
  } catch (error: unknown) {
    logger.error('Boot release check failed', { error: errorMessage(error) });
  }
}

/**
 * Starts the release check on the primary worker: every
 * `UPDATE_CHECK_INTERVAL_HOURS` hours (UTC) at a minute picked at random when the
 * process starts, plus one check shortly after boot when the last one is stale.
 * The random minute and boot jitter spread a fleet of installations across the
 * hour instead of sending them to GitHub in the same second.
 *
 * Returns `null`, scheduling nothing, when the operator turned the check off
 * (`UPDATE_CHECK_ENABLED=false`) and in the test environment, where no request
 * may leave the machine.
 */
export function startUpdateCheckJob(options: UpdateCheckJobOptions = {}): StartedJob | null {
  if (!config.UPDATE_CHECK_ENABLED || config.NODE_ENV === 'test') return null;
  const random = options.random ?? ((max: number) => randomInt(max));
  const minute = random(60);

  const task = cron.schedule(
    `${String(minute)} */${String(UPDATE_CHECK_INTERVAL_HOURS)} * * *`,
    () => {
      trackJob(performUpdateCheck(options).then(() => undefined));
    },
    { timezone: 'UTC' },
  );
  const bootTimer = setTimeout(
    () => {
      trackJob(runBootUpdateCheck(options));
    },
    UPDATE_CHECK_BOOT_DELAY_MS + random(UPDATE_CHECK_BOOT_JITTER_MS),
  );
  // The boot check must never hold a shutting-down process open.
  bootTimer.unref();

  logger.info('Release check scheduled', {
    repository: config.UPDATE_CHECK_REPOSITORY,
    everyHours: UPDATE_CHECK_INTERVAL_HOURS,
    minute,
  });
  return {
    stop: () => {
      clearTimeout(bootTimer);
      return task.stop();
    },
  };
}
