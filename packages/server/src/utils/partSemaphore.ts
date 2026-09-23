import { MAX_IN_FLIGHT_PART_UPLOADS, MAX_IN_FLIGHT_PART_UPLOADS_PER_USER } from '@hvault/shared';

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
 * TWO THINGS BOUND THAT WINDOW, and neither of them is the queue. The first is
 * {@link partUploadUserQuota} below: one identity may hold at most
 * `MAX_IN_FLIGHT_PART_UPLOADS_PER_USER` of these slots, so a single account can
 * never be every waiter's reason for waiting. The second is the part route's own
 * body deadline (`DOCUMENT_PART_BODY_TIMEOUT_MS`, 64 s by default, armed by
 * `middleware/documentPartBody.ts` when a slot is granted), which turns "a client
 * that stops sending" from an indefinite hold into a bounded one; the server-wide
 * receive deadline in `utils/httpTimeouts.ts` is only its ceiling. Before the pair
 * existed, four requests from one account that declared a `Content-Length` and
 * then dribbled held the whole budget for as long as Node's default
 * `requestTimeout` of five minutes, without sending a byte, naming a valid upload
 * id, or spending a unit of quota.
 *
 * THE ORDERING RULE THIS EXISTS TO ENFORCE, which is easy to get wrong and
 * invisible when wrong: a slot must be taken **before the body parser runs**, and
 * held **across the storage call**. Express runs a route's parser before its
 * handler, so a slot acquired inside the handler is acquired after 8 MiB has
 * already been buffered and bounds nothing at all. The middleware that mounts this
 * therefore sits AHEAD of `express.raw` (see `middleware/documentPartBody.ts`) and
 * releases only once the response has closed AND the handler has settled, since a
 * handler whose client went away still holds the part until its storage call returns.
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

// ---------------------------------------------------------------------------
// The per-identity share of that budget
// ---------------------------------------------------------------------------

/**
 * A counting quota held PER KEY, with no queue: a key at its limit is REFUSED
 * rather than made to wait.
 *
 * The difference from the semaphore above is the whole design, not an
 * implementation detail. A caller past the PROCESS budget is queued, because the
 * condition clears in milliseconds and refusing would fail a transfer that was
 * already halfway through. A caller past its OWN share is refused, because the
 * condition clears only when that same caller finishes something — so queueing it
 * would let one identity convert a refusal it has earned into a growing pile of
 * sockets, which is the shape of the problem rather than a fix for it.
 */
export interface KeyedQuota {
  /** How many charges one key may hold at a time. Fixed at construction. */
  readonly limit: number;
  /** How many keys are charged at all. Zero when nothing is in flight. */
  readonly keys: number;
  /** Charges currently held by `key`. */
  heldBy(key: string): number;
  /**
   * Charges one unit to `key` and returns the release, or `null` when `key`
   * already holds {@link limit}.
   *
   * The release is idempotent, exactly as the semaphore's is and for the same
   * reason: the one caller wires it to an event that may fire alongside its own
   * cleanup path.
   */
  charge(key: string): (() => void) | null;
}

export function createKeyedQuota(limit: number): KeyedQuota {
  if (!Number.isSafeInteger(limit) || limit < 1) {
    throw new RangeError('limit must be a safe integer of at least 1');
  }

  // Keyed by user id, and the DELETE at zero is load-bearing rather than tidy:
  // this map would otherwise grow by one entry per account that has ever uploaded
  // a part and never shrink, which is the same unbounded growth the semaphore
  // exists to prevent, moved one layer up.
  const held = new Map<string, number>();

  return {
    limit,
    get keys() {
      return held.size;
    },
    heldBy(key: string): number {
      return held.get(key) ?? 0;
    },
    charge(key: string): (() => void) | null {
      const current = held.get(key) ?? 0;
      if (current >= limit) return null;
      held.set(key, current + 1);

      let released = false;
      return () => {
        if (released) return;
        released = true;
        const remaining = (held.get(key) ?? 1) - 1;
        if (remaining <= 0) held.delete(key);
        else held.set(key, remaining);
      };
    },
  };
}

/**
 * How much of {@link partUploadSemaphore} any ONE identity may hold.
 *
 * Module-level for the same reason the semaphore is: the budget it shares out is
 * per PROCESS, so the share has to be counted in the same process. Under pm2's two
 * instances an account may therefore hold this many parts on each — which is the
 * honest description of a per-process memory budget, not a hole, because the
 * number that has to fit in memory is still `MAX_IN_FLIGHT_PART_UPLOADS` per
 * process.
 */
export const partUploadUserQuota: KeyedQuota = createKeyedQuota(
  MAX_IN_FLIGHT_PART_UPLOADS_PER_USER,
);
