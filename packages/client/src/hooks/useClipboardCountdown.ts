import { useEffect } from 'react';
import { useToast } from '../components/ui/Toast';
import {
  getClipboardGuardState,
  subscribeClipboardGuard,
  type ClipboardGuardState,
} from '../services/clipboard/clipboardService';

/** How long the "waiting for this tab" notice stays up. */
const OVERDUE_TOAST_MS = 8_000;

/**
 * Shows a single app-wide toast that counts down to the clipboard erase, driven
 * entirely by the clipboard guard's own state.
 *
 * Mount once, in the app layout. The guard ITSELF lives higher up, in `App`, so
 * its retry listeners survive the lock screen; the two are coupled only through
 * `subscribeClipboardGuard`. This hook used to be mounted per copy control and
 * driven imperatively with `startCountdown(seconds)`, which meant the toast was a
 * second, independent claim about when the clipboard would be cleared: copying
 * two fields left two countdowns running, and neither one was cancelled when the
 * clipboard was actually erased, so the UI kept promising a deadline for a
 * clipboard that was already empty. Deriving it from the guard means the number
 * on screen is the real deadline or there is no toast at all.
 */
export function useClipboardCountdown(): void {
  const { toast, dismiss, update } = useToast();

  // `toast`, `dismiss` and `update` are stable for the lifetime of the provider,
  // so this subscribes once.
  useEffect(() => {
    let toastId: string | null = null;
    let interval: ReturnType<typeof setInterval> | null = null;
    let mode: 'idle' | 'countdown' | 'overdue' = 'idle';
    /** Deadline the visible countdown belongs to, so a re-copy re-renders it. */
    let shownDeadline: number | null = null;

    function stopInterval(): void {
      if (interval !== null) {
        clearInterval(interval);
        interval = null;
      }
    }

    function clearToast(): void {
      if (toastId !== null) {
        dismiss(toastId);
        toastId = null;
      }
    }

    function secondsUntil(deadline: number): number {
      return Math.max(0, Math.ceil((deadline - Date.now()) / 1_000));
    }

    function apply(state: ClipboardGuardState): void {
      // Nothing on the clipboard: the erase is confirmed, so the notice goes away.
      if (!state.pending) {
        stopInterval();
        clearToast();
        mode = 'idle';
        shownDeadline = null;
        return;
      }

      // The browser refused the erase (an unfocused document cannot write). Say
      // so instead of counting down to a deadline that has already passed.
      if (state.overdue) {
        if (mode === 'overdue') return;
        stopInterval();
        clearToast();
        // Deliberately not "will be cleared when you return": on Firefox and Safari
        // every clipboard write needs a user gesture, so the guard cannot promise a
        // moment. It retries on the next interaction, which this wording matches.
        toastId = toast({
          title: 'Clipboard not cleared yet — it will be cleared on your next action here',
          type: 'info',
          duration: OVERDUE_TOAST_MS,
        });
        mode = 'overdue';
        shownDeadline = null;
        return;
      }

      const deadline = state.deadlineAt;
      if (deadline === null) return;
      if (mode === 'countdown' && shownDeadline === deadline) return;

      stopInterval();
      clearToast();
      const total = secondsUntil(deadline);
      toastId = toast({
        title: `Clipboard will clear in ${total}s`,
        type: 'info',
        duration: total * 1_000 + 1_000,
      });
      shownDeadline = deadline;
      mode = 'countdown';
      interval = setInterval(() => {
        const remaining = secondsUntil(deadline);
        if (remaining <= 0) {
          stopInterval();
          return;
        }
        if (toastId !== null) update(toastId, { title: `Clipboard will clear in ${remaining}s` });
      }, 1_000);
    }

    apply(getClipboardGuardState());
    const unsubscribe = subscribeClipboardGuard(apply);

    return () => {
      unsubscribe();
      stopInterval();
      clearToast();
    };
  }, [toast, dismiss, update]);
}
