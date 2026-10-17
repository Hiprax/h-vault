import {
  MAX_IN_FLIGHT_HEAVY_RESPONSES,
  MAX_IN_FLIGHT_HEAVY_RESPONSES_PER_USER,
  MIN_SUSTAINED_UPLOAD_BYTES_PER_SECOND,
} from '@hvault/shared';
import { createKeyedQuota, createSemaphore } from './partSemaphore.js';
import type { KeyedQuota, Semaphore } from './partSemaphore.js';

/**
 * The budget every HEAVY RESPONSE is admitted through: a backup download, a
 * backup mailed on demand, a vault export, and the scheduled backup job. Each one
 * reads a whole vault of up to 25 MB, and nothing bounded how many ran at once.
 *
 * Here rather than beside the middleware (`middleware/heavyResponseAdmission.ts`)
 * because the scheduler takes the same slots, and a job has no `res` or `next` to
 * hand `admitWithinBudget`.
 */

/** Heavy responses in progress in this process, across every account. */
export const heavyResponseSemaphore: Semaphore = createSemaphore(MAX_IN_FLIGHT_HEAVY_RESPONSES);

/** One account's share of {@link heavyResponseSemaphore}: a second request is refused. */
export const heavyResponseUserQuota: KeyedQuota = createKeyedQuota(
  MAX_IN_FLIGHT_HEAVY_RESPONSES_PER_USER,
);

/**
 * Takes one slot of `semaphore`, waiting at most `waitMs`. Resolves to the release
 * (idempotent) or to `null` when the wait ran out, in which case the slot, if it is
 * granted later, is handed straight back: nobody is left holding it.
 */
export function acquireWithin(semaphore: Semaphore, waitMs: number): Promise<(() => void) | null> {
  return new Promise((resolve) => {
    let settled = false;
    const timer = setTimeout(() => {
      settled = true;
      resolve(null);
    }, waitMs);
    timer.unref();
    semaphore.acquire((release) => {
      if (settled) {
        release();
        return;
      }
      settled = true;
      clearTimeout(timer);
      resolve(release);
    });
  });
}

/**
 * The inputs of {@link sendDeadlineMs}: the slowest sustained rate a client is
 * assumed to read at (`MIN_SUSTAINED_UPLOAD_BYTES_PER_SECOND`, the one divisor every
 * transfer deadline here is derived from) and a fixed slack. A plain object so a
 * test can shorten it the way the suite adjusts `config`; nothing in production
 * writes to it.
 */
export const SEND_DEADLINE_POLICY = {
  bytesPerSecond: MIN_SUSTAINED_UPLOAD_BYTES_PER_SECOND,
  slackMs: 30_000,
};

/**
 * The absolute deadline for sending `bytes` to a client: the time the body takes at
 * the policy's rate, plus its slack.
 *
 * ABSOLUTE rather than an idle timeout, deliberately. A socket idle timeout
 * (`res.setTimeout`) never fires for a client that reads one byte a second, so a
 * trickle reader could hold one of the process's two slots for hours; this bounds
 * how long ANY reader can hold one.
 */
export function sendDeadlineMs(bytes: number): number {
  return (
    Math.ceil((bytes / SEND_DEADLINE_POLICY.bytesPerSecond) * 1000) + SEND_DEADLINE_POLICY.slackMs
  );
}
