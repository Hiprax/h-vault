import { useCallback, useEffect, useRef, useState } from 'react';

/**
 * Tracks whether the app can actually reach the H-Vault server, not just
 * whether the browser has a network interface up.
 *
 * `navigator.onLine` only reflects link-layer connectivity, so it stays `true`
 * when the browser is connected to a network but the API server is down or
 * unreachable. This hook combines `navigator.onLine` with a lightweight poll of
 * the public `/api/v1/health` endpoint so the UI reflects real server
 * reachability: killing the server flips the indicator to offline within one
 * poll interval, and it recovers automatically once the server responds again.
 */

const HEALTH_ENDPOINT = '/api/v1/health';
/** How often to re-check server reachability while the tab is open. */
const POLL_INTERVAL_MS = 30_000;
/** Abort a health probe that hangs longer than this. */
const HEALTH_TIMEOUT_MS = 5_000;

export interface ConnectionStatus {
  isOnline: boolean;
}

export function useConnectionStatus(): ConnectionStatus {
  const [isOnline, setIsOnline] = useState<boolean>(() =>
    typeof navigator === 'undefined' ? true : navigator.onLine,
  );
  const mountedRef = useRef(true);
  // Monotonic id of the most-recently-started probe. checkServer() can be
  // triggered concurrently (mount, interval, `online` event, visibility), so a
  // probe only applies its result if it is still the latest one — otherwise a
  // slow/out-of-order probe could clobber a fresher result. Also lets us abort
  // the in-flight probe on unmount.
  const latestProbeRef = useRef(0);
  const controllerRef = useRef<AbortController | null>(null);

  const checkServer = useCallback(async (): Promise<void> => {
    const probeId = ++latestProbeRef.current;
    const apply = (value: boolean) => {
      if (mountedRef.current && probeId === latestProbeRef.current) setIsOnline(value);
    };

    // The browser itself reports no connectivity — no point probing the server.
    if (typeof navigator !== 'undefined' && !navigator.onLine) {
      apply(false);
      return;
    }

    const controller = new AbortController();
    controllerRef.current = controller;
    const timer = setTimeout(() => controller.abort(), HEALTH_TIMEOUT_MS);
    try {
      const res = await fetch(HEALTH_ENDPOINT, {
        method: 'GET',
        cache: 'no-store',
        signal: controller.signal,
        headers: { Accept: 'application/json' },
      });
      apply(res.ok);
    } catch {
      // Network error, DNS failure, timeout/abort, or connection refused
      // (server down) all mean the server is currently unreachable.
      apply(false);
    } finally {
      clearTimeout(timer);
    }
  }, []);

  useEffect(() => {
    mountedRef.current = true;

    void checkServer();
    const interval = setInterval(() => void checkServer(), POLL_INTERVAL_MS);

    const handleOnline = () => void checkServer();
    const handleOffline = () => {
      // A newer explicit browser-offline signal supersedes any in-flight probe.
      latestProbeRef.current += 1;
      if (mountedRef.current) setIsOnline(false);
    };
    const handleVisibility = () => {
      if (document.visibilityState === 'visible') void checkServer();
    };

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);
    document.addEventListener('visibilitychange', handleVisibility);

    return () => {
      mountedRef.current = false;
      controllerRef.current?.abort();
      clearInterval(interval);
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
      document.removeEventListener('visibilitychange', handleVisibility);
    };
  }, [checkServer]);

  return { isOnline };
}
