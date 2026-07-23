/**
 * Cold-start "remember me" session resume.
 *
 * When a user opted into "remember me" on this device, a bare hint marker is
 * written to `localStorage` at login (see `stores/authStore.ts`). On the next
 * cold boot — crucially, a full browser restart, where the per-session
 * `encryptedStorage` key is gone and nothing rehydrates — this module silently
 * re-establishes the *authenticated-but-locked* session so the user lands on
 * the Unlock screen (master password only) instead of the login screen.
 *
 * What it does and, more importantly, does NOT do:
 *   - It refreshes the access token from the httpOnly refresh-token cookie and
 *     fetches the profile to recover the wrapped-vault-key material.
 *   - It sets `isAuthenticated: true` and `isLocked: true` so `ProtectedRoute`
 *     renders the Unlock screen.
 *   - It NEVER sets `vaultKey` or `mek`. Remember-me changes authentication
 *     only, never cryptography: the vault key is always re-derived from the
 *     master password on the Unlock screen. Persisting or reconstructing key
 *     material here would break the zero-knowledge model.
 *
 * Transient vs authoritative failure (this is an offline-capable PWA):
 *   - A 401/403 from either request means the session is genuinely gone
 *     (expired / revoked). The hint is removed and the user falls back to the
 *     login screen.
 *   - A network error or a 5xx (offline cold boot, a brief server restart) must
 *     NOT destroy a valid 30-day session. The hint is KEPT so the next boot
 *     retries, and this boot simply lands on the login screen.
 */

import { isAxiosError } from 'axios';
import { useAuthStore, REMEMBER_HINT_KEY } from '../../stores/authStore.js';
import { refreshTokenApi } from '../api/authApi.js';
import { getProfileApi } from '../api/userApi.js';

/**
 * Whether the remember-me cold-start resume hint is present. Best-effort:
 * reading `localStorage` can throw (private browsing, storage disabled), in
 * which case there is nothing to resume.
 */
function hasRememberHint(): boolean {
  try {
    return localStorage.getItem(REMEMBER_HINT_KEY) === '1';
  } catch {
    return false;
  }
}

/**
 * Remove the cold-start hint. Called only when the session is authoritatively
 * gone (a 401/403). Best-effort for the same reason as {@link hasRememberHint}.
 */
function clearRememberHint(): void {
  try {
    localStorage.removeItem(REMEMBER_HINT_KEY);
  } catch {
    // localStorage may be unavailable; the hint is only an optimization.
  }
}

/**
 * Classify a caught error as an authoritative session rejection. Only a genuine
 * 401/403 means the remembered session is gone; everything else (a network
 * error whose `response` is undefined, a 5xx, a non-Axios throw) is treated as
 * transient so the hint survives for the next boot.
 */
function isSessionGone(error: unknown): boolean {
  if (isAxiosError(error)) {
    const status = error.response?.status;
    return status === 401 || status === 403;
  }
  return false;
}

/**
 * Whether a cold-start resume should be attempted at all. True only when a
 * remember hint exists AND the store is not already authenticated (e.g. from a
 * synchronous same-tab rehydrate). Exported so the app root can gate its
 * initial render synchronously — showing no loading state when there is nothing
 * to resume — without duplicating the hint-key or the auth check.
 */
export function shouldAttemptResume(): boolean {
  return hasRememberHint() && !useAuthStore.getState().isAuthenticated;
}

/**
 * Attempt to resume a remembered session. Resolves to `true` when the session
 * was re-established (the caller should render the Unlock screen) and `false`
 * otherwise. NEVER throws and NEVER sets vault key material.
 */
export async function resumeSession(): Promise<boolean> {
  if (!shouldAttemptResume()) {
    return false;
  }

  try {
    // Refresh under the cross-tab lock (refreshTokenApi wraps withRefreshLock)
    // so a sibling tab refreshing at the same instant cannot trip reuse
    // detection with the pre-rotation cookie.
    const refreshResponse = await refreshTokenApi();
    if (!refreshResponse.data.success) {
      // A 2xx that is not a success envelope should not happen; treat it as
      // transient and keep the hint rather than destroying a valid session.
      return false;
    }
    useAuthStore.getState().setAccessToken(refreshResponse.data.data.accessToken);

    // The access token is now in the store, so the request interceptor will
    // attach the Bearer header for the profile fetch.
    const profileResponse = await getProfileApi();
    if (!profileResponse.data.success) {
      return false;
    }
    const profile = profileResponse.data.data;

    useAuthStore.setState({
      user: { userId: profile._id, email: profile.email },
      isAuthenticated: true,
      // Locked: crypto material is never set here; the Unlock screen re-derives
      // the vault key from the master password.
      isLocked: true,
      encryptedVaultKeyData: {
        encrypted: profile.encryptedVaultKey,
        iv: profile.vaultKeyIv,
        tag: profile.vaultKeyTag,
      },
      kdfIterations: profile.kdfIterations,
    });
    return true;
  } catch (error) {
    if (isSessionGone(error)) {
      clearRememberHint();
    }
    // Transient failure (network / 5xx): keep the hint for the next boot.
    return false;
  }
}
