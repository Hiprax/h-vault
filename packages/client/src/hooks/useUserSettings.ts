import { useEffect, useState } from 'react';
import { getProfileApi } from '../services/api/userApi';
import { useAuthStore } from '../stores/authStore';

interface UserSettings {
  autoLockTimeout: number;
  clipboardClearTimeout: number;
  theme: string;
}

const DEFAULT_SETTINGS: UserSettings = {
  autoLockTimeout: 15,
  clipboardClearTimeout: 30,
  theme: 'system',
};

const SETTINGS_INVALIDATION_KEY = '__hv_settings_invalidated';

// Same-tab notification listeners
type SettingsListener = () => void;
const settingsListeners = new Set<SettingsListener>();

export function onSettingsInvalidated(listener: SettingsListener): () => void {
  settingsListeners.add(listener);
  return () => {
    settingsListeners.delete(listener);
  };
}

// User-scoped cache: keyed by user ID to prevent cross-user data leakage
// when switching accounts in the same browser session.
let cachedSettings: UserSettings | null = null;
let cachedForUserId: string | null = null;
// In-flight request dedup: while a fetch is running, all consumers share the
// same promise instead of each firing their own GET /profile. A single vault
// item detail renders many CopyFields (and a TotpDisplay), each calling this
// hook — without this guard they would all hit the API on a cold cache.
let inFlight: Promise<void> | null = null;

/**
 * Returns the user's settings. Fetches from the API on first call
 * and caches the result for the session. Listens for invalidation signals —
 * same-tab (`clearSettingsCache()`, e.g. a SettingsPage save) and cross-tab
 * (the `storage` event) — and re-fetches on either, so every consumer
 * re-renders with the new value.
 *
 * The cache is scoped to the current user ID. When the authenticated
 * user changes (e.g., logout + login as a different user), the stale
 * cache is automatically discarded.
 */
export function useUserSettings(): UserSettings {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const isLocked = useAuthStore((s) => s.isLocked);
  const userId = useAuthStore((s) => s.user?.userId ?? null);

  // Invalidate cache when the user changes (different user or logged out).
  // Also drop any in-flight fetch so the new user does not dedup against — and
  // receive — the previous user's settings.
  if (userId !== cachedForUserId) {
    cachedSettings = null;
    cachedForUserId = userId;
    inFlight = null;
  }

  const [settings, setSettings] = useState(cachedSettings ?? DEFAULT_SETTINGS);

  // Listen for invalidation signals — same-tab and cross-tab.
  useEffect(() => {
    if (typeof window === 'undefined') return;

    let cancelled = false;

    const refetch = () => {
      // Read the auth state live rather than closing over it: `clearSettingsCache()`
      // notifies its listeners synchronously, and `logout()` calls it after it has
      // already nulled the session — a stale closure would fire a doomed GET /profile.
      const { isAuthenticated: authed, isLocked: locked } = useAuthStore.getState();
      if (!authed || locked) return;
      void fetchSettings().then(() => {
        if (!cancelled && cachedSettings) setSettings(cachedSettings);
      });
    };

    // Same-tab invalidation. `clearSettingsCache()` (a SettingsPage save) has already
    // dropped the module cache and the in-flight fetch before notifying us. Without
    // this subscription an ALREADY-MOUNTED consumer would keep rendering the
    // pre-save value: the cold-cache effect below does not re-run for it, and the
    // originating tab never receives its own `storage` event.
    const unsubscribe = onSettingsInvalidated(refetch);

    // Cross-tab invalidation.
    const handleStorage = (event: StorageEvent) => {
      if (event.key !== SETTINGS_INVALIDATION_KEY) return;
      cachedSettings = null;
      // Drop any in-flight fetch so the re-fetch reflects the invalidation
      // rather than deduping against a pre-invalidation request.
      inFlight = null;
      refetch();
    };
    window.addEventListener('storage', handleStorage);

    return () => {
      cancelled = true;
      unsubscribe();
      window.removeEventListener('storage', handleStorage);
    };
  }, []);

  useEffect(() => {
    if (!isAuthenticated || isLocked || cachedSettings) return;

    let cancelled = false;
    void fetchSettings().then(() => {
      if (!cancelled && cachedSettings) setSettings(cachedSettings);
    });
    return () => {
      cancelled = true;
    };
  }, [isAuthenticated, isLocked]);

  return settings;
}

/**
 * Fetch settings from the API and populate the module-level cache.
 *
 * In-flight dedup: if a fetch is already running, the existing promise is
 * returned so concurrent first-mount consumers (e.g. the many CopyFields in a
 * vault item detail) share a single GET /profile instead of each issuing their
 * own. Callers read {@link cachedSettings} once the returned promise resolves.
 */
async function fetchSettings(): Promise<void> {
  if (inFlight) return inFlight;

  const pending = (async () => {
    try {
      const res = await getProfileApi();
      const result = res.data;
      if (result.success) {
        const s: UserSettings = {
          autoLockTimeout: result.data.settings.autoLockTimeout,
          clipboardClearTimeout: result.data.settings.clipboardClearTimeout,
          theme: result.data.settings.theme,
        };
        cachedSettings = s;
      }
    } catch {
      // Keep defaults
    }
  })();

  inFlight = pending;
  try {
    await pending;
  } finally {
    // Only clear the shared pointer if it still refers to this fetch — a
    // concurrent invalidation / user switch may have reset it and started a
    // newer fetch that must not be clobbered.
    if (inFlight === pending) inFlight = null;
  }
}

/**
 * Clear the cached settings and broadcast to other tabs so they
 * re-fetch on their next render cycle (similar to CSRF invalidation).
 */
export function clearSettingsCache() {
  cachedSettings = null;
  // Drop any in-flight fetch so the next consumer starts a fresh request
  // rather than awaiting (and caching) pre-invalidation data.
  inFlight = null;
  try {
    localStorage.setItem(SETTINGS_INVALIDATION_KEY, Date.now().toString());
  } catch {
    // localStorage may be unavailable — ignore
  }
  // Notify same-tab listeners
  for (const listener of settingsListeners) {
    listener();
  }
}
