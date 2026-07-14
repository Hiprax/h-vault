import { useCallback, useEffect, useRef } from 'react';
import { useToast } from '../components/ui/Toast';

/**
 * Provides a `startCountdown` function that shows a persistent countdown
 * toast while the clipboard auto-clear timer is running.
 *
 * The toast updates every second with "Clipboard will clear in Xs" and
 * auto-dismisses when the clipboard is cleared.
 */
export function useClipboardCountdown() {
  const { toast, dismiss, update } = useToast();
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const toastIdRef = useRef<string | null>(null);

  const stopCountdown = useCallback(() => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    if (toastIdRef.current) {
      dismiss(toastIdRef.current);
      toastIdRef.current = null;
    }
  }, [dismiss]);

  const startCountdown = useCallback(
    (durationSeconds: number) => {
      // Clear any existing countdown
      stopCountdown();

      let remaining = durationSeconds;
      const id = toast({
        title: `Clipboard will clear in ${remaining}s`,
        type: 'info',
        duration: (durationSeconds + 1) * 1000,
      });
      toastIdRef.current = id;

      intervalRef.current = setInterval(() => {
        remaining -= 1;
        if (remaining <= 0) {
          stopCountdown();
          return;
        }
        update(id, { title: `Clipboard will clear in ${remaining}s` });
      }, 1000);
    },
    [toast, update, stopCountdown],
  );

  useEffect(() => () => stopCountdown(), [stopCountdown]);

  return { startCountdown, stopCountdown };
}
