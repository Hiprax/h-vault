import { useEffect, useRef, useCallback } from 'react';
import { useAuthStore } from '../stores/authStore';
import { useUserSettings } from './useUserSettings';

const DEFAULT_TIMEOUT_MINUTES = 15;

function getVisibilityHiddenDelay(timeoutMs: number): number {
  return Math.min(30_000, timeoutMs / 2);
}
const ACTIVITY_EVENTS: (keyof DocumentEventMap)[] = [
  'mousemove',
  'keydown',
  'click',
  'scroll',
  'touchstart',
];

/**
 * Locks the vault after a period of user inactivity.
 *
 * - Reads `autoLockTimeout` from the shared `useUserSettings` cache (defaults to
 *   15 min until the profile fetch resolves). The cache dedups the GET /profile
 *   this hook used to issue on its own, and it already re-fetches on same-tab and
 *   cross-tab settings invalidation — so a saved timeout change simply arrives
 *   here as a new `autoLockTimeout` value.
 * - Resets on mousemove / keydown / click / scroll / touchstart
 * - Starts a 30-second lock timer on `visibilitychange` (tab hidden / browser minimised)
 * - Calls `authStore.lock()` when the timer expires
 */
export function useAutoLock() {
  const lock = useAuthStore((s) => s.lock);
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const isLocked = useAuthStore((s) => s.isLocked);
  const { autoLockTimeout } = useUserSettings();

  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const visibilityTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const timeoutMsRef = useRef(DEFAULT_TIMEOUT_MINUTES * 60 * 1000);

  const resetTimer = useCallback(() => {
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => {
      const state = useAuthStore.getState();
      if (state.isAuthenticated && !state.isLocked) {
        void lock();
      }
    }, timeoutMsRef.current);
  }, [lock]);

  // Keep the inactivity timeout in sync with the user's configured setting and
  // (re)arm the timer whenever it changes: on mount with the cached/default
  // value, then again when the profile fetch resolves or the setting is saved.
  useEffect(() => {
    if (!isAuthenticated || isLocked) return;

    timeoutMsRef.current = autoLockTimeout * 60 * 1000;
    resetTimer();

    return () => {
      if (timerRef.current) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
    };
  }, [autoLockTimeout, isAuthenticated, isLocked, resetTimer]);

  // Listen for user activity and visibility changes
  useEffect(() => {
    if (!isAuthenticated || isLocked) return;

    const handleActivity = () => {
      // Cancel visibility-hidden timer if user returns and interacts
      if (visibilityTimerRef.current) {
        clearTimeout(visibilityTimerRef.current);
        visibilityTimerRef.current = null;
      }
      resetTimer();
    };
    const handleVisibilityChange = () => {
      if (document.hidden) {
        // Start a delayed lock timer instead of locking immediately
        if (visibilityTimerRef.current) clearTimeout(visibilityTimerRef.current);
        visibilityTimerRef.current = setTimeout(() => {
          const state = useAuthStore.getState();
          if (state.isAuthenticated && !state.isLocked) {
            void lock();
          }
          visibilityTimerRef.current = null;
        }, getVisibilityHiddenDelay(timeoutMsRef.current));
      } else {
        // Tab became visible again — cancel the pending visibility lock
        if (visibilityTimerRef.current) {
          clearTimeout(visibilityTimerRef.current);
          visibilityTimerRef.current = null;
        }
        resetTimer();
      }
    };

    for (const event of ACTIVITY_EVENTS) {
      document.addEventListener(event, handleActivity, { passive: true });
    }
    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
      if (visibilityTimerRef.current) clearTimeout(visibilityTimerRef.current);
      for (const event of ACTIVITY_EVENTS) {
        document.removeEventListener(event, handleActivity);
      }
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [isAuthenticated, isLocked, lock, resetTimer]);
}
