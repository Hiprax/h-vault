/**
 * The suite's clock: frozen by default, moved only on purpose.
 *
 * `tests/harness/determinism.ts` pins the timezone, the locale, the seed and the
 * order. This pins the one remaining ambient input those do not reach: **what
 * time it is**. Until this module existed, every suite that needed to control
 * time reached for `vi.useFakeTimers()` and `vi.setSystemTime()` itself, and
 * every suite that did NOT need to control time simply read the machine's clock
 * — so a test that incidentally crossed a second, a minute or a TOTP step
 * boundary had a verdict that depended on when it happened to run. That is a
 * flake with a very long period, which is the worst kind: it fails once a
 * fortnight, on someone else's machine, and gets re-run.
 *
 * ---------------------------------------------------------------------------
 * WHY IT IS OPT-IN, AND WHY THAT IS NOT A COMPROMISE
 * ---------------------------------------------------------------------------
 *
 * Installing a frozen clock globally, from `tests/setup.ts`, is the obvious
 * design and it is wrong here. The server tier drives a REAL `mongod` in a
 * separate process, and that process keeps its own clock: TTL reaping, `$$NOW`
 * in the rate-limit store's upsert pipeline, and every server-side timestamp
 * comparison would be measured against a clock the test worker had frozen and
 * mongod had not. A global freeze would therefore trade a rare, real flake for a
 * permanent, invisible divergence between the two halves of every integration
 * test.
 *
 * So the seam is opt-in, and its DEFAULT is deliberately "freeze where we
 * already are" (`at` unset) rather than "jump to a fixed instant": a test that
 * only needs the clock to stop, or to move forward by a known amount, then keeps
 * mongod's skew at zero and pays nothing. {@link FROZEN_INSTANT_MS} is there for
 * the tier that has no second process to diverge from.
 *
 * ---------------------------------------------------------------------------
 * WHY `toFake: ['Date']` IS THE DEFAULT
 * ---------------------------------------------------------------------------
 *
 * `vi.useFakeTimers()` with no options fakes `setTimeout`, `setInterval`,
 * `queueMicrotask` and friends as well as `Date`. In a suite that awaits real
 * I/O — an HTTP round trip through supertest, a mongoose query — that is fatal:
 * the driver's own timers stop firing and the await never settles. Faking `Date`
 * ALONE stops the wall clock while leaving every real timer running, which is
 * exactly what "the server must see a later second" needs and nothing more.
 *
 * `timers: 'all'` is available for the suites that genuinely drive timers (a
 * clipboard erase deadline, an auto-lock countdown), because those were already
 * doing it by hand and one definition is better than nine.
 */
import { vi } from 'vitest';

/**
 * The pinned instant for tests that want a fully determined clock rather than a
 * frozen "now".
 *
 * `2026-01-15T12:00:10.000Z`, and the seconds are not arbitrary. It sits ten
 * seconds into a 30-second TOTP step (43,210 mod 30 = 10), so a code generated
 * at this instant is comfortably clear of both step boundaries; it is nowhere
 * near a DST transition in either pinned zone, so a test that opts into
 * {@link DST_TZ} does not accidentally land inside the repeated hour it is
 * trying to reason about deliberately; and it is a whole second, so no
 * `Math.floor(Date.now() / 1000)` rounds differently than the millisecond value
 * suggests.
 */
export const FROZEN_INSTANT_MS = Date.UTC(2026, 0, 15, 12, 0, 10);

/** The same instant, for a message or an assertion that wants to read. */
export const FROZEN_INSTANT_ISO = new Date(FROZEN_INSTANT_MS).toISOString();

export interface TestClockOptions {
  /**
   * The instant to freeze at. Defaults to the real `Date.now()` at the moment of
   * installation, which is what keeps a second process's clock from diverging —
   * see the note above.
   */
  at?: number;
  /**
   * `'date'` (default) fakes the wall clock and nothing else, so real I/O still
   * settles. `'all'` fakes the timer functions too, for a suite that drives a
   * deadline rather than merely reads the clock.
   */
  timers?: 'date' | 'all';
}

/**
 * Freezes the clock. Every later read of `Date.now()`, `new Date()` and
 * `Date.prototype.getTime` in this worker returns the same instant until
 * {@link advanceClockBy} or {@link setClockTo} moves it.
 */
export function installTestClock({ at, timers = 'date' }: TestClockOptions = {}): void {
  vi.useFakeTimers({
    now: at ?? Date.now(),
    ...(timers === 'date' ? { toFake: ['Date'] as const } : {}),
  });
}

/** Moves the frozen clock forward. Negative values are refused: time does not go back. */
export function advanceClockBy(ms: number): void {
  if (!Number.isFinite(ms) || ms < 0) {
    throw new Error(
      `advanceClockBy expects a non-negative finite number of milliseconds; received ${String(ms)}. ` +
        'A test that needs an EARLIER instant should install the clock there instead — ' +
        'winding a clock backwards mid-test is how a token minted "later" ends up dated before its issuer.',
    );
  }
  vi.setSystemTime(Date.now() + ms);
}

/** Moves the frozen clock to an absolute instant. */
export function setClockTo(instant: number | Date): void {
  vi.setSystemTime(instant);
}

/** Hands the clock back to the machine. Safe to call when none was installed. */
export function uninstallTestClock(): void {
  vi.useRealTimers();
}

/**
 * Runs `body` with a frozen clock and restores the real one afterwards, even if
 * `body` throws.
 *
 * The restore is the point. A test that installs a fake clock and fails before
 * its own cleanup leaves the whole worker frozen, and every LATER file in that
 * worker then runs against a clock that stopped somewhere in the middle of a
 * test it has never heard of — an order-dependent failure produced by the very
 * mechanism installed to remove one.
 */
export async function withTestClock<T>(
  options: TestClockOptions,
  body: () => Promise<T> | T,
): Promise<T> {
  installTestClock(options);
  try {
    return await body();
  } finally {
    uninstallTestClock();
  }
}
