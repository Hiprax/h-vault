/**
 * The circuit breaker every bulk walk over object storage shares.
 *
 * ## Why a walk needs one at all
 *
 * Three places in this system delete stored objects one row at a time and keep
 * going after a failure: the hourly collector's three sweeps, the user-facing
 * empty-trash request, and the nightly auto-purge. Continuing past a failure is
 * deliberate in all three — a row whose object cannot be reached is marked
 * `purgePending` first, so the work is deferred rather than lost, and abandoning
 * the whole walk on one unreachable key would strand every row behind it.
 *
 * That is the right answer for ONE bad key and the wrong answer for a bad ENGINE,
 * because an engine that refuses one delete is almost always refusing all of
 * them, and the arithmetic is unforgiving. The S3 client is pinned to a 5-second
 * connect timeout and three attempts (`services/storage/s3Provider.ts`), so a
 * thousand doomed deletes is over four hours. In a cron that blows the
 * fifteen-minute lock TTL and lets the next tick start a second concurrent run
 * alongside the first; in a request handler it holds a connection open for hours
 * against a client that gave up long ago; and in both it buries the log in a
 * thousand copies of one message.
 *
 * ## What the counter measures, and why it resets
 *
 * CONSECUTIVE failures, reset by any success, so it reads "the engine is down
 * right now" rather than "this walk has had a bad day". A walk over an account
 * with a handful of individually unreachable keys scattered through it finishes
 * and reports each one; a walk against an engine that is simply not answering
 * stops after {@link MAX_CONSECUTIVE_STORAGE_FAILURES} attempts.
 *
 * Nothing is lost by stopping. Every caller marks its row `purgePending` before
 * attempting the delete, so a row it attempted and failed is finished by the
 * hourly collector, and a row it never reached still carries `deletedAt` and is
 * still in the trash — visible to the user, and inside the next run's set. What
 * a caller MUST do is report the counts it actually accumulated rather than the
 * counts it set out to accumulate, because a walk that stopped early and reported
 * success would tell a user their trash is empty while it is not.
 *
 * The total is kept beside the consecutive count because every caller needs both:
 * the consecutive one decides whether to stop, and the total is what goes in the
 * response body or the run's log line.
 */

/**
 * How many storage calls may fail BACK TO BACK before a walk gives up.
 *
 * Deliberately not exported: it is a property of the breaker, and every caller
 * asks {@link StorageBreaker.isRefusing} rather than counting for itself. The
 * tests restate it as a literal for the same reason — a test that imported the
 * number would agree with the code by construction.
 */
const MAX_CONSECUTIVE_STORAGE_FAILURES = 5;

/** One walk's failure bookkeeping. Create one per walk; never share across runs. */
export interface StorageBreaker {
  /** Every failure this walk recorded, for the response body or the log line. */
  readonly failures: number;
  /** Whether the engine has refused often enough in a row to abandon this walk. */
  isRefusing(): boolean;
  /** Clears the consecutive run. Call after every storage call that succeeds. */
  recordSuccess(): void;
  /** Counts one failure against both the total and the consecutive run. */
  recordFailure(): void;
}

/** A breaker for one walk, opened closed with both counters at zero. */
export function createStorageBreaker(): StorageBreaker {
  let failures = 0;
  let consecutiveFailures = 0;

  return {
    get failures(): number {
      return failures;
    },
    isRefusing: (): boolean => consecutiveFailures >= MAX_CONSECUTIVE_STORAGE_FAILURES,
    recordSuccess: (): void => {
      consecutiveFailures = 0;
    },
    recordFailure: (): void => {
      failures += 1;
      consecutiveFailures += 1;
    },
  };
}
