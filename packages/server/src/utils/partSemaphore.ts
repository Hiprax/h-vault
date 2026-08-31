import { MAX_IN_FLIGHT_PART_UPLOADS } from '@hvault/shared';

/**
 * A counting semaphore, and the one instance of it that bounds how many document
 * parts this process buffers at a time.
 *
 * WHY IT EXISTS. One uploaded part is one sealed segment, and a segment is
 * `DOCUMENT_CIPHERTEXT_CHUNK_BYTES` (8 MiB). `express.raw` buffers a part WHOLE
 * before the handler sees it, so the process's peak memory on the upload path is
 * `8 MiB * (parts being parsed or stored at once)` and nothing else bounds that
 * product: the rate limiter bounds requests per window, not requests in flight,
 * and the per-user concurrency cap bounds one user rather than the process. In the
 * Docker deployment the app is ONE node process inside `mem_limit: 1g`, so an
 * unbounded product is an out-of-memory kill under a load a rate limiter happily
 * permits.
 *
 * `MAX_IN_FLIGHT_PART_UPLOADS` is therefore a MEMORY budget before it is a
 * throughput knob, and the number it multiplies is recorded beside the constant.
 *
 * WHY IT IS A QUEUE RATHER THAN A REFUSAL. A part that arrives while the budget is
 * full is made to WAIT, not answered with 429 or 503. It costs a socket and no
 * memory (its body has not been read yet — see the ordering rule below), and
 * refusing it would fail a transfer partway through for a condition that normally
 * clears in milliseconds, which is exactly the failure the part limiter's own
 * budget is derived to avoid. Request volume is bounded upstream by
 * `documentPartLimiter`.
 *
 * The cost of that choice, stated rather than left to be discovered: "normally" is
 * not "always". A slot is held across the storage call, and the S3 client is
 * configured with a socket idle timeout and a retry count, so a wedged storage
 * engine can hold one for minutes rather than milliseconds — and this many wedged
 * parts stall every part upload in the process for that long. That is the
 * deliberate trade, because the alternative caps a healthy transfer to protect
 * against an unhealthy engine; it is not an impossible case.
 *
 * THE ORDERING RULE THIS EXISTS TO ENFORCE, which is easy to get wrong and
 * invisible when wrong: a slot must be taken **before the body parser runs**, and
 * held **across the storage call**. Express runs a route's parser before its
 * handler, so a slot acquired inside the handler is acquired after 8 MiB has
 * already been buffered and bounds nothing at all. The middleware that mounts this
 * therefore sits AHEAD of `express.raw` (see `middleware/documentPartBody.ts`) and
 * releases only when the response closes.
 *
 * The API is CALLBACK-based rather than promise-based on purpose. A promise here
 * would be a promise nobody awaits, resolved from inside an Express middleware; if
 * it ever rejected, the process-wide `unhandledRejection` handler would exit the
 * server, which is the same trap `utils/jobTracker.ts` records. A callback cannot
 * reject, so there is no rejection path to forget.
 */

/** A counting semaphore with FIFO hand-off. */
export interface Semaphore {
  /** How many slots exist in total. Fixed at construction. */
  readonly permits: number;
  /** How many slots are free right now. */
  readonly available: number;
  /** How many callers are queued for a slot. */
  readonly waiting: number;
  /**
   * Runs `task` with a release function, immediately if a slot is free and
   * otherwise when one becomes free.
   *
   * `task` MUST call `release` exactly once. Calling it more than once is safe
   * (the release is idempotent, which is what lets a caller wire it to two events
   * that may both fire); never calling it leaks a slot for the life of the
   * process.
   */
  acquire(task: (release: () => void) => void): void;
}

export function createSemaphore(permits: number): Semaphore {
  if (!Number.isSafeInteger(permits) || permits < 1) {
    throw new RangeError('permits must be a safe integer of at least 1');
  }

  let free = permits;
  const waiters: ((release: () => void) => void)[] = [];
  // Re-entrancy guard. `task` below is invoked SYNCHRONOUSLY from inside the loop,
  // and a task whose request has already closed releases its slot straight away —
  // which calls `drain` again. Without this flag that is recursion one frame deep
  // per queued waiter; with it, the nested call only returns the permit and the
  // loop that is already running picks it up on its next iteration.
  let draining = false;

  function makeRelease(): () => void {
    let released = false;
    return () => {
      if (released) return;
      released = true;
      free += 1;
      drain();
    };
  }

  function drain(): void {
    if (draining) return;
    draining = true;
    try {
      // `shift()` is the loop condition, so the `undefined` case is the empty
      // queue rather than a branch to prove unreachable: `noUncheckedIndexedAccess`
      // would otherwise force a non-null assertion here, and an assertion is a
      // claim while this is a check.
      while (free > 0) {
        const task = waiters.shift();
        if (task === undefined) return;
        free -= 1;
        task(makeRelease());
      }
    } finally {
      draining = false;
    }
  }

  return {
    permits,
    get available() {
      return free;
    },
    get waiting() {
      return waiters.length;
    },
    acquire(task: (release: () => void) => void): void {
      waiters.push(task);
      drain();
    },
  };
}

/**
 * The process-wide budget for parts being buffered or stored.
 *
 * Module-level, so it is genuinely per PROCESS: a pm2 deployment runs two
 * instances and therefore holds twice this many parts across the pair, which is
 * recorded beside `MAX_IN_FLIGHT_PART_UPLOADS` because it is the number that has
 * to fit in memory.
 */
export const partUploadSemaphore: Semaphore = createSemaphore(MAX_IN_FLIGHT_PART_UPLOADS);
