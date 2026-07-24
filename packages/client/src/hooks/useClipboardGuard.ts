import { useEffect } from 'react';
import { eraseCopiedSecretNow, flushDueErase } from '../services/clipboard/clipboardService';

/**
 * Wires the browser events that let the clipboard guard finish work the platform
 * would not let it do earlier.
 *
 * **Mount once, at the app root** (`App`), NOT inside `AppLayout`. `ProtectedRoute`
 * swaps `AppLayout` for the unlock screen the instant the vault locks, so a guard
 * mounted below that boundary loses its listeners at exactly the moment an
 * overdue erase is most likely to exist: an auto-lock in a hidden tab both refuses
 * the erase (an unfocused document cannot write) and unmounts the layout.
 *
 * The guard deliberately does NOT erase the clipboard when the page is hidden.
 * Hiding the tab is how the user goes to paste; erasing there is what made a
 * copied password vanish before it could be used. See
 * `services/clipboard/clipboardService.ts` for the full rationale.
 *
 * Retry triggers, in order of how reliably each one is accepted by browsers:
 *
 * - **A user gesture** (`pointerdown`, `keydown`). The only trigger Firefox and
 *   Safari will accept, because they require transient user activation for every
 *   clipboard write; a timer-driven or focus-driven erase can never succeed there.
 *   Both events are low-frequency and `flushDueErase()` returns immediately when
 *   nothing is due, so this is cheap.
 * - **`focus` and `visibilitychange` -> visible.** Enough for Chromium, which gates
 *   writes on document focus rather than on activation. Also the backstop for a
 *   deadline whose timer was throttled while the tab was hidden.
 * - **On mount.** Covers the remount after an unlock, where the document is
 *   already focused and visible so no event would otherwise fire.
 * - **`pagehide` with `persisted === false`.** The document is being discarded, so
 *   no timer will ever fire again; erase best-effort. When `persisted` is true the
 *   page is entering the back/forward cache and may be restored with its timers
 *   intact, so erasing there would be the same premature wipe in a new costume.
 */
export function useClipboardGuard(): void {
  useEffect(() => {
    function handleVisibilityChange(): void {
      if (document.visibilityState === 'visible') {
        flushDueErase();
      }
    }

    function handleRetryTrigger(): void {
      flushDueErase();
    }

    function handlePageHide(event: PageTransitionEvent): void {
      if (event.persisted) return;
      eraseCopiedSecretNow();
    }

    // An erase may already be overdue before any event arrives: the deadline can
    // have lapsed while this hook was unmounted behind the lock screen.
    flushDueErase();

    document.addEventListener('visibilitychange', handleVisibilityChange);
    document.addEventListener('pointerdown', handleRetryTrigger, { passive: true });
    document.addEventListener('keydown', handleRetryTrigger, { passive: true });
    window.addEventListener('focus', handleRetryTrigger);
    window.addEventListener('pagehide', handlePageHide);

    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      document.removeEventListener('pointerdown', handleRetryTrigger);
      document.removeEventListener('keydown', handleRetryTrigger);
      window.removeEventListener('focus', handleRetryTrigger);
      window.removeEventListener('pagehide', handlePageHide);
    };
  }, []);
}
