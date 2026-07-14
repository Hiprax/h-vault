import { useEffect } from 'react';

/**
 * Module-level flag indicating whether sensitive data is currently on the
 * clipboard.  Shared across all component instances so that any copy
 * operation in the app marks the clipboard as "dirty".
 */
let clipboardDirty = false;

/**
 * The single pending auto-clear timer for the whole app.
 *
 * Every copy control (CopyField, TotpDisplay, PasswordGenerator) schedules its
 * clear through {@link scheduleClipboardClear}, so only the MOST RECENT copy's
 * deadline is ever armed. When each control owned its own timer, copying field
 * A (clear at t+30s) and then field B (clear at t+40s) left A's timer running:
 * it fired at t+30s and wiped B's freshly-copied value ten seconds early.
 */
let clearTimer: ReturnType<typeof setTimeout> | null = null;

function cancelScheduledClear(): void {
  if (clearTimer !== null) {
    clearTimeout(clearTimer);
    clearTimer = null;
  }
}

/** Mark clipboard as containing sensitive data. */
export function markClipboardDirty(): void {
  clipboardDirty = true;
}

/** Mark clipboard as safe (after explicit clear or on clear success). */
export function markClipboardClean(): void {
  clipboardDirty = false;
}

/**
 * Arm the app-wide clipboard auto-clear for `ms` from now, cancelling any clear
 * a previous copy had scheduled. The latest copy always owns the deadline.
 *
 * Deliberately module-level rather than per-component: the timer must outlive
 * the control that armed it, so navigating away from a vault item still wipes
 * the value that item put on the clipboard. Lock and logout cancel it via
 * {@link clearClipboardIfDirty}, which wipes immediately instead.
 */
export function scheduleClipboardClear(ms: number): void {
  cancelScheduledClear();
  clearTimer = setTimeout(() => {
    clearTimer = null;
    clearClipboardIfDirty();
  }, ms);
}

/**
 * Wipe the system clipboard if it currently holds sensitive data ("dirty").
 *
 * Exported so non-event-driven flows — notably vault lock and logout — can
 * clear the clipboard on demand. `useClipboardGuard` only reacts to
 * `visibilitychange`→hidden / `pagehide`, neither of which fires when the
 * lock screen is shown in the still-visible tab (and the layout that mounts
 * the guard is unmounted on lock anyway). Without an imperative wipe, a secret
 * copied just before locking would linger on the OS clipboard behind the lock
 * screen — the copy component's pending auto-clear timer is cancelled on
 * unmount without clearing.
 *
 * Also cancels any pending {@link scheduleClipboardClear} timer: the clipboard
 * is being wiped now, so a later fire could only clobber a value the user
 * copied afterwards.
 *
 * No-op when the clipboard is already clean, so it is safe to call
 * unconditionally on every lock/logout.
 */
export function clearClipboardIfDirty(): void {
  cancelScheduledClear();
  if (!clipboardDirty) return;
  clipboardDirty = false;
  try {
    // Blind-clear: only requires clipboard-write permission (no read).
    // `.catch` swallows a rejected write; the surrounding `try` guards the rare
    // non-secure-context case where `navigator.clipboard` is absent (the DOM
    // type claims it is always present), which throws on property access.
    void navigator.clipboard.writeText('').catch(() => {
      // Clipboard API may be unavailable in certain contexts (e.g. background tab)
    });
  } catch {
    // navigator.clipboard is undefined — nothing to clear
  }
}

/**
 * Registers global event listeners that attempt to clear the system clipboard
 * when the page becomes hidden or is being unloaded.  This covers scenarios
 * that `setTimeout`-based auto-clear cannot handle — e.g. user closing the
 * tab before the timer fires.
 *
 * Mount this hook once in the app layout.  Multiple mounts are safe — the
 * listeners are idempotent and each instance cleans up after itself.
 */
export function useClipboardGuard(): void {
  useEffect(() => {
    function handleVisibilityChange(): void {
      if (document.visibilityState === 'hidden') {
        clearClipboardIfDirty();
      }
    }

    function handlePageHide(): void {
      clearClipboardIfDirty();
    }

    document.addEventListener('visibilitychange', handleVisibilityChange);
    window.addEventListener('pagehide', handlePageHide);

    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.removeEventListener('pagehide', handlePageHide);
    };
  }, []);
}
