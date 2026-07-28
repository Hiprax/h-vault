import { useEffect, useState } from 'react';
import {
  AUTO_LOCK_TIMEOUT_MINUTES,
  AUTO_LOCK_MIN_MINUTES,
  AUTO_LOCK_MAX_MINUTES,
  CLIPBOARD_CLEAR_SECONDS,
  LOCK_ON_HIDDEN_DEFAULT,
  LOCK_ON_HIDDEN_DELAY_MINUTES,
} from '@hvault/shared';
import { getProfileApi } from '../services/api/userApi';
import { useAuthStore } from '../stores/authStore';

interface UserSettings {
  autoLockTimeout: number;
  lockOnHidden: boolean;
  lockOnHiddenDelay: number;
  clipboardClearTimeout: number;
  theme: string;
}

// Every default is the SHARED constant, never a literal repeated here. These
// values are also the server-side model defaults, so a divergence would mean the
// UI silently arms a different timer than the account is actually configured for
// until the profile fetch lands — and the fallbacks used to be hardcoded `15` and
// `30` in two client files with nothing asserting they tracked the source.
const DEFAULT_SETTINGS: UserSettings = {
  autoLockTimeout: AUTO_LOCK_TIMEOUT_MINUTES,
  lockOnHidden: LOCK_ON_HIDDEN_DEFAULT,
  lockOnHiddenDelay: LOCK_ON_HIDDEN_DELAY_MINUTES,
  clipboardClearTimeout: CLIPBOARD_CLEAR_SECONDS,
  theme: 'system',
};

/**
 * Keep a minutes value inside the bounds `updateSettingsSchema` enforces on the
 * way in, falling back to `fallback` for anything outside them.
 *
 * The wire is validated on write, so this should never fire — but these numbers
 * are multiplied into `setTimeout` deadlines, and the failure mode of a bad one is
 * silent rather than loud: `NaN` compares false against every deadline test, so an
 * auto-lock the user had configured would simply never fire. Clamping is the same
 * defence `clipboardClearTimeout` already carries, and for the same reason.
 */
function clampMinutes(value: number, fallback: number): number {
  if (!Number.isFinite(value)) return fallback;
  if (value < AUTO_LOCK_MIN_MINUTES || value > AUTO_LOCK_MAX_MINUTES) return fallback;
  return value;
}

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
        const settings = result.data.settings;
        // Clamped, not merely read. These values arm REAL timers — the auto-lock
        // deadline and the clipboard erase — and they arrive over the wire, so a
        // malformed or hostile one must not be armed verbatim. `clampMinutes`
        // rejects NaN and out-of-range values by falling back to the shared
        // default, matching the bounds `updateSettingsSchema` enforces on write.
        // (Absent fields are already filled in server-side, in `getProfile`'s
        // `withSettingsDefaults`, so the declared types are honest here.)
        const s: UserSettings = {
          autoLockTimeout: clampMinutes(settings.autoLockTimeout, DEFAULT_SETTINGS.autoLockTimeout),
          lockOnHidden: settings.lockOnHidden,
          lockOnHiddenDelay: clampMinutes(
            settings.lockOnHiddenDelay,
            DEFAULT_SETTINGS.lockOnHiddenDelay,
          ),
          clipboardClearTimeout: settings.clipboardClearTimeout,
          theme: settings.theme,
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
