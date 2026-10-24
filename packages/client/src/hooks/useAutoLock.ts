import { useEffect, useRef, useCallback } from 'react';
import {
  AUTO_LOCK_TIMEOUT_MINUTES,
  LOCK_ON_HIDDEN_DEFAULT,
  LOCK_ON_HIDDEN_DELAY_MINUTES,
} from '@hvault/shared';
import { useAuthStore } from '../stores/authStore';
import { useUserSettings } from './useUserSettings';

const MINUTE_MS = 60 * 1000;

/**
 * Activity that counts as "the user is still here".
 *
 * `pointerdown` and `wheel` are included alongside the originals because a user
 * can work for minutes with only clicks and a trackpad. `scroll` is bound in the
 * CAPTURE phase (see the listener registration) because scroll events do not
 * bubble from elements — the app's main pane is an `overflow-y-auto` container,
 * so a bubble-phase listener on `document` never saw scrolling inside it and
 * reading a long note counted as idleness.
 */
const ACTIVITY_EVENTS: (keyof DocumentEventMap)[] = [
  'mousemove',
  'keydown',
  'click',
  'pointerdown',
  'wheel',
  'scroll',
  'touchstart',
];

/**
 * How often the wall-clock deadline is re-checked regardless of events.
 *
 * The armed `setTimeout` is the primary trigger; this is the backstop for the
 * cases where a timer cannot be trusted to fire on time — see {@link useAutoLock}.
 * 20 s is far below any usable lock timeout (the minimum is one minute) and costs
 * a single `Date.now()` comparison.
 */
const DEADLINE_POLL_MS = 20_000;

/**
 * Minimum gap between two activity resets. `mousemove` fires at pointer-event
 * rate, and without this every one of them re-armed a timer; a deadline only
 * needs updating a few times a second at most.
 */
const ACTIVITY_THROTTLE_MS = 1_000;

/**
 * The longest gap between two evaluations that still reads as one live, visible
 * page. A visible tab evaluates at least every {@link DEADLINE_POLL_MS}, so a longer
 * gap means the machine slept or the tab was frozen, and progress is not credited.
 */
const PROGRESS_CONTINUITY_MS = 60_000;

/** When a full backup or full restore last made forward progress in a visible tab. */
let autoLockProgressAt = 0;

/**
 * Record that a full backup or full restore the user started just made forward
 * progress: a verified segment, a stored part, a finished document. Only those two
 * jobs call it (the operator's decision, 0.22.0); an ordinary upload is still not
 * activity.
 *
 * It is a timestamp and nothing else, so there is nothing to release: a job that
 * stops calling it (finished, stopped, offline, stuck on a hung request) lets the
 * normal deadline run again one timeout after its last progress. Ignored while the
 * tab is hidden, so work done in a background tab never counts.
 */
export function noteAutoLockProgress(): void {
  if (!document.hidden) autoLockProgressAt = Date.now();
}

/**
 * Locks the vault on a WALL-CLOCK deadline.
 *
 * ## Why a deadline and not a timer
 *
 * This used to be a bare `setTimeout(lock, timeout)` re-armed on activity, with no
 * `Date.now()` anywhere. A `setTimeout` measures elapsed *running* time, not
 * elapsed real time, and browsers do not owe you either one on a schedule: hidden
 * tabs are throttled to ~1 wake/second and, after five minutes hidden, to ~1/minute;
 * a frozen or discarded tab may not run timers at all; and a machine suspend stops
 * the clock entirely. All of those make a timer fire LATE, so the old hook would
 * happily return from an eight-hour laptop sleep with the vault still unlocked and
 * fifteen minutes left on its timer — the exact state auto-lock exists to prevent.
 *
 * The model here is: compute a deadline as an absolute instant, arm a timer to it
 * as an optimisation, and *check the deadline against `Date.now()`* whenever the
 * page could plausibly have missed a wake — on the timer, on becoming visible, on
 * focus, on `pageshow` (bfcache restore), on mount, and on a coarse interval. A
 * late or skipped timer then costs nothing: the check on return locks immediately.
 *
 * ## The two deadlines
 *
 * - **Idle**: `lastActivity + autoLockTimeout`. Runs continuously, including while
 *   the tab is hidden — nothing generates activity events there — so a hidden tab
 *   still locks exactly on schedule.
 * - **Hidden** (opt-in, `lockOnHidden`): `hiddenSince + lockOnHiddenDelay`.
 *
 * The vault locks at whichever comes first, so no clamping is needed.
 *
 * Hidden-tab locking is now a setting, off by default, and this is a deliberate
 * behaviour change. It was previously unconditional and hardcoded to
 * `Math.min(30_000, autoLockTimeout / 2)` — which, because the cap dominates for
 * every timeout above one minute, meant a flat **30 seconds** no matter what the
 * user had configured. Switching tabs to look something up locked the vault. That
 * is not a defensible default for a setting labelled "auto-lock after N minutes",
 * and it interacted badly with everything downstream: each surprise lock forced an
 * unlock, and each unlock spent rate-limit budget the user needed for logging in.
 */
export function useAutoLock() {
  const lock = useAuthStore((s) => s.lock);
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const isLocked = useAuthStore((s) => s.isLocked);
  const { autoLockTimeout, lockOnHidden, lockOnHiddenDelay } = useUserSettings();

  // Settings held in refs so the event listeners and the deadline computation can
  // read the current values without re-subscribing on every settings change.
  const idleTimeoutMsRef = useRef(AUTO_LOCK_TIMEOUT_MINUTES * MINUTE_MS);
  const lockOnHiddenRef = useRef(LOCK_ON_HIDDEN_DEFAULT);
  const hiddenDelayMsRef = useRef(LOCK_ON_HIDDEN_DELAY_MINUTES * MINUTE_MS);

  const lastActivityRef = useRef(Date.now());
  const hiddenSinceRef = useRef<number | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  /**
   * Set once this hook has asked for a lock, and cleared only when the effect
   * re-arms for a fresh unlocked session.
   *
   * `lock()` updates the store synchronously before its first `await`, so the
   * store re-read in {@link evaluate} normally suffices. This does not rely on
   * that: several wake points (the armed timer, the poll interval, a `focus`)
   * can fire in the same tick, and a second `lock()` would emit a second
   * `vault_lock` audit row and a second `POST /auth/lock` for one real event.
   * "At most one lock request per unlocked session" is the invariant; state them
   * both rather than depending on one store's update timing.
   */
  const lockRequestedRef = useRef(false);
  /** When `evaluate` last ran, for the continuity test {@link noteAutoLockProgress} relies on. */
  const lastEvaluateAtRef = useRef(Date.now());

  /**
   * The instant the vault must be locked by, as epoch milliseconds.
   *
   * `Infinity` for the hidden deadline when the feature is off or the tab is
   * visible, so `Math.min` naturally yields the idle deadline alone.
   */
  const deadlineAt = useCallback((): number => {
    const idleDeadline = lastActivityRef.current + idleTimeoutMsRef.current;
    const hiddenSince = hiddenSinceRef.current;
    const hiddenDeadline =
      lockOnHiddenRef.current && hiddenSince !== null
        ? hiddenSince + hiddenDelayMsRef.current
        : Infinity;
    return Math.min(idleDeadline, hiddenDeadline);
  }, []);

  const clearTimer = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  /**
   * Lock if the deadline has passed, otherwise re-arm the timer to it.
   *
   * Re-reads the store rather than trusting the render-time props: this runs from
   * timers and listeners that can outlive a state change by a tick, and locking an
   * already-locked (or logged-out) session would be a spurious `POST /auth/lock`.
   */
  const evaluate = useCallback(() => {
    const state = useAuthStore.getState();
    if (!state.isAuthenticated || state.isLocked || lockRequestedRef.current) {
      clearTimer();
      return;
    }

    // A long job's progress counts as activity (it is only ever recorded while the
    // tab is visible), but only when the previous evaluation was recent: a longer
    // gap is a sleep or a frozen tab, and the deadline must then be judged on the
    // evidence from before it. Progress stamped LATER than now (the clock was set
    // back) is dropped, never merely deferred: kept, it would be merged as fresh
    // activity the moment the clock caught up with it. The gap is measured BEFORE
    // this evaluation is recorded, and the progress is merged BEFORE the deadline
    // is computed.
    const now = Date.now();
    if (autoLockProgressAt > now) autoLockProgressAt = 0;
    if (now - lastEvaluateAtRef.current < PROGRESS_CONTINUITY_MS) {
      lastActivityRef.current = Math.max(lastActivityRef.current, autoLockProgressAt);
    }
    lastEvaluateAtRef.current = now;

    const remaining = deadlineAt() - now;
    if (remaining <= 0) {
      clearTimer();
      lockRequestedRef.current = true;
      void lock();
      return;
    }

    clearTimer();
    // `setTimeout` clamps very large delays inconsistently across engines, so cap
    // the arm at the poll interval's horizon when the deadline is far away; the
    // periodic check below covers the gap either way.
    timerRef.current = setTimeout(evaluate, Math.min(remaining, DEADLINE_POLL_MS));
  }, [clearTimer, deadlineAt, lock]);

  // Keep the refs in step with the user's settings, then re-evaluate so a saved
  // change takes effect immediately (including one that has ALREADY elapsed —
  // shortening the timeout below the current idle age must lock now, not later).
  useEffect(() => {
    idleTimeoutMsRef.current = autoLockTimeout * MINUTE_MS;
    lockOnHiddenRef.current = lockOnHidden;
    hiddenDelayMsRef.current = lockOnHiddenDelay * MINUTE_MS;
    if (!isAuthenticated || isLocked) return;
    evaluate();
  }, [autoLockTimeout, lockOnHidden, lockOnHiddenDelay, isAuthenticated, isLocked, evaluate]);

  useEffect(() => {
    if (!isAuthenticated || isLocked) return;

    // A fresh unlocked session: this effect runs only when `isAuthenticated`
    // becomes true or `isLocked` becomes false (its other two deps are stable
    // callbacks), so it is exactly the right place to re-arm.
    lockRequestedRef.current = false;
    // Entering the effect is itself a wake point: after an unlock, or a remount,
    // the deadline may already have passed with no event pending to notice it.
    lastActivityRef.current = Date.now();
    hiddenSinceRef.current = document.hidden ? Date.now() : null;
    evaluate();

    let lastActivityHandled = 0;
    const handleActivity = () => {
      const now = Date.now();
      if (now - lastActivityHandled < ACTIVITY_THROTTLE_MS) return;
      lastActivityHandled = now;
      lastActivityRef.current = now;
      evaluate();
    };

    const handleVisibilityChange = () => {
      if (document.hidden) {
        // Start the hidden clock. Note this does NOT touch `lastActivityRef`:
        // hiding the tab is not activity, so the idle deadline keeps running.
        hiddenSinceRef.current = Date.now();
        evaluate();
        return;
      }

      // Becoming visible is the single most important wake point — this is where a
      // throttled or suspended timer is caught up with.
      //
      // **Evaluate BEFORE discarding `hiddenSince`, and the order is the whole
      // point.** `deadlineAt()` derives the hidden deadline from that ref and
      // returns `Infinity` once it is null, so clearing first and then evaluating
      // asks about a deadline that no longer exists — and a tab hidden well past
      // `lockOnHiddenDelay` would return unlocked. That is exactly the case the
      // wall-clock model exists to catch: the armed timer cannot be relied on
      // here, because a suspended or throttled tab may not have run it, and on
      // resume whether it is dispatched before this handler is a race. Checking
      // the deadline while the evidence for it still exists removes the race.
      evaluate();
      hiddenSinceRef.current = null;
      // Re-arm against the idle deadline alone now that the hidden one is retired.
      // A no-op when the call above already locked: `evaluate` short-circuits on
      // `lockRequestedRef`.
      evaluate();
    };

    const handleWake = () => {
      evaluate();
    };

    for (const event of ACTIVITY_EVENTS) {
      // `capture: true` so scrolling inside a nested overflow container counts;
      // scroll events do not bubble from elements.
      document.addEventListener(event, handleActivity, { passive: true, capture: true });
    }
    document.addEventListener('visibilitychange', handleVisibilityChange);
    window.addEventListener('focus', handleWake);
    // A bfcache restore replays the page with its timers in an undefined state.
    window.addEventListener('pageshow', handleWake);

    // Backstop for the case no event fires at all: the tab is visible and focused,
    // the machine sleeps past the deadline, and it wakes with nothing to signal it.
    const poll = setInterval(evaluate, DEADLINE_POLL_MS);

    return () => {
      clearInterval(poll);
      clearTimer();
      for (const event of ACTIVITY_EVENTS) {
        document.removeEventListener(event, handleActivity, { capture: true });
      }
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.removeEventListener('focus', handleWake);
      window.removeEventListener('pageshow', handleWake);
    };
  }, [isAuthenticated, isLocked, evaluate, clearTimer]);
}
