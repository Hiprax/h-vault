/**
 * Authentication Zustand store.
 *
 * Manages authentication state, key material, and vault key lifecycle.
 * Sensitive cryptographic material (vaultKey, mek, accessToken) is NEVER
 * persisted to localStorage -- only non-sensitive user metadata is persisted
 * so the app can show the lock screen on reload instead of the login screen.
 */

import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';
import { encryptedStorage } from './encryptedStorage.js';
import { cryptoService } from '../services/crypto/cryptoService.js';
import { registerApi, loginApi, login2faApi, logoutApi, lockApi } from '../services/api/authApi.js';
import { clearCsrfToken } from '../services/api/client.js';
import { offlineCache } from '../services/offlineCache.js';
import { clearHealthResults } from '../services/health/healthResultsStore.js';
import { clearSettingsCache } from '../hooks/useUserSettings.js';
import { clearClipboardIfDirty } from '../hooks/useClipboardGuard.js';
import { logger } from '../lib/logger.js';
import { useVaultStore } from './vaultStore.js';
import { isAxiosError } from 'axios';
import type { SuccessfulLoginResponse } from '@hvault/shared';
import { KDF_ITERATIONS, KDF_ALGORITHM, ENCRYPTION_VERSION, ERROR_CODES } from '@hvault/shared';
import { getDeviceFingerprint } from '../utils/deviceFingerprint.js';

/**
 * Bounded per-call timeout (ms) for the best-effort lock/logout network calls.
 * These requests must never block local session teardown indefinitely on a
 * stalled/black-holed connection. A per-call timeout is used deliberately
 * instead of a global Axios timeout, which would risk aborting the
 * legitimately-long backup-restore / vault-key-rotation requests.
 */
const LOCK_LOGOUT_TIMEOUT_MS = 5000;

/**
 * localStorage key for the cold-start "remember me" hint. It is a bare marker
 * ('1') and holds NO session or key material — only a signal that this browser
 * has an opted-in remembered session worth attempting a silent cold-start
 * resume for (see `services/auth/sessionResume.ts`). It is written at the two
 * points a login can complete (the non-2FA branch of `login` and `verify2fa`),
 * cleared on any non-remembered login, and removed on `logout` but NOT on
 * `lock` (a lock is not a logout).
 */
const REMEMBER_HINT_KEY = '__hv_remember';

/**
 * Persist or clear the remember-me cold-start hint. Best-effort: localStorage
 * can be unavailable (private browsing, storage disabled), and the hint is only
 * an optimization for silent resume, so a failure is swallowed rather than
 * allowed to break login/logout.
 */
function writeRememberHint(remember: boolean): void {
  try {
    if (remember) {
      localStorage.setItem(REMEMBER_HINT_KEY, '1');
    } else {
      localStorage.removeItem(REMEMBER_HINT_KEY);
    }
  } catch {
    // localStorage may be unavailable in some contexts (e.g. private browsing).
  }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface AuthUser {
  userId: string;
  email: string;
}

interface EncryptedVaultKeyData {
  encrypted: string;
  iv: string;
  tag: string;
}

interface AuthState {
  // Session
  accessToken: string | null;
  user: AuthUser | null;
  isAuthenticated: boolean;
  isLocked: boolean;

  // Crypto material (never persisted)
  vaultKey: CryptoKey | null;
  mek: CryptoKey | null;

  // Encrypted vault key data (persisted so we can unlock without re-login)
  encryptedVaultKeyData: EncryptedVaultKeyData | null;
  kdfIterations: number;

  // 2FA flow
  twoFactorRequired: boolean;
  tempToken: string | null;
  _2faTimeoutId: ReturnType<typeof setTimeout> | null;

  // Transient "remember me" flag, stashed across the 2FA step so verify2fa can
  // honor the choice made at the login screen. NEVER persisted (excluded from
  // `partialize`) — it is a per-attempt UI intent, not session state.
  _rememberMe: boolean;

  // Loading guard (prevents concurrent login/2FA attempts)
  isLoading: boolean;

  // Actions
  register: (email: string, masterPassword: string) => Promise<{ emailSent: boolean }>;
  login: (email: string, masterPassword: string, rememberMe?: boolean) => Promise<void>;
  verify2fa: (code: string) => Promise<void>;
  unlock: (masterPassword: string, preDerivedMek?: CryptoKey) => Promise<void>;
  lock: () => Promise<void>;
  logout: () => Promise<void>;
  setAccessToken: (token: string | null) => void;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * After a successful login / 2FA response, decrypt the vault key and return
 * the pieces needed to update the store.
 */
async function processLoginResponse(
  loginData: SuccessfulLoginResponse,
  mek: CryptoKey,
): Promise<{
  vaultKey: CryptoKey;
  encryptedVaultKeyData: EncryptedVaultKeyData;
}> {
  const encryptedVaultKeyData: EncryptedVaultKeyData = {
    encrypted: loginData.encryptedVaultKey,
    iv: loginData.vaultKeyIv,
    tag: loginData.vaultKeyTag,
  };

  const rawVaultKey = await cryptoService.decryptVaultKey(
    encryptedVaultKeyData.encrypted,
    encryptedVaultKeyData.iv,
    encryptedVaultKeyData.tag,
    mek,
  );
  const vaultKey = await cryptoService.importVaultKey(rawVaultKey);
  cryptoService.clearKey(rawVaultKey);

  return { vaultKey, encryptedVaultKeyData };
}

/**
 * Extract userId from a JWT access token payload (without verification --
 * the server has already verified it). Returns the `sub` claim.
 */
function parseAccessTokenUserId(accessToken: string): string {
  const parts = accessToken.split('.');
  const payload = parts[1];
  if (!payload) {
    logger.error('Token parse failed: invalid token format');
    throw new Error('Authentication error');
  }
  const decoded = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
  const parsed: unknown = JSON.parse(decoded);
  if (
    typeof parsed === 'object' &&
    parsed !== null &&
    'sub' in parsed &&
    typeof (parsed as Record<string, unknown>).sub === 'string'
  ) {
    return (parsed as Record<string, unknown>).sub as string;
  }
  logger.error('Token parse failed: missing or invalid sub claim');
  throw new Error('Authentication error');
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      // State
      accessToken: null,
      user: null,
      isAuthenticated: false,
      isLocked: false,
      vaultKey: null,
      mek: null,
      encryptedVaultKeyData: null,
      kdfIterations: KDF_ITERATIONS,
      twoFactorRequired: false,
      tempToken: null,
      _2faTimeoutId: null,
      _rememberMe: false,
      isLoading: false,

      // -------------------------------------------------------------------
      // Register
      // -------------------------------------------------------------------
      register: async (email: string, masterPassword: string): Promise<{ emailSent: boolean }> => {
        const { masterEncryptionKey, authKey } = await cryptoService.deriveKeys(
          masterPassword,
          email,
        );
        const authHash = cryptoService.getAuthHash(authKey);

        const rawVaultKey = cryptoService.generateVaultKey();
        const vaultKeyCK = await cryptoService.importVaultKey(rawVaultKey);
        cryptoService.clearKey(rawVaultKey);
        const encryptedVaultKeyData = await cryptoService.encryptVaultKey(
          vaultKeyCK,
          masterEncryptionKey,
        );

        const response = await registerApi({
          email,
          authHash,
          encryptedVaultKey: encryptedVaultKeyData.encrypted,
          vaultKeyIv: encryptedVaultKeyData.iv,
          vaultKeyTag: encryptedVaultKeyData.tag,
          kdfIterations: KDF_ITERATIONS,
          kdfAlgorithm: KDF_ALGORITHM,
          encryptionVersion: ENCRYPTION_VERSION,
        });

        // Clear sensitive material after registration
        await cryptoService.clearCryptoKey(vaultKeyCK);
        cryptoService.clearKey(authKey);
        await cryptoService.clearCryptoKey(masterEncryptionKey);

        const data = response.data;
        const emailSent = data.success && 'data' in data && data.data.emailSent;
        return { emailSent };
      },

      // -------------------------------------------------------------------
      // Login
      // -------------------------------------------------------------------
      login: async (email: string, masterPassword: string, rememberMe = false): Promise<void> => {
        // Prevent concurrent login attempts to avoid MEK state corruption
        if (get().isLoading) return;
        set({ isLoading: true });

        let masterEncryptionKey: CryptoKey | null = null;
        try {
          const derived = await cryptoService.deriveKeys(masterPassword, email);
          masterEncryptionKey = derived.masterEncryptionKey;
          const authHash = cryptoService.getAuthHash(derived.authKey);

          // Clear auth key as soon as we have the hash
          cryptoService.clearKey(derived.authKey);

          const fingerprint = await getDeviceFingerprint();
          const response = await loginApi({
            email,
            authHash,
            rememberMe,
            deviceInfo: {
              userAgent: navigator.userAgent,
              fingerprint,
            },
          });

          const loginResult = response.data;
          if (!loginResult.success) {
            throw new Error('Login response did not contain expected data');
          }
          const loginData = loginResult.data;

          // 2FA required -- store MEK temporarily so we can decrypt the vault
          // key after the 2FA code is verified. Start a 5-minute auto-cleanup
          // timer in case the user abandons the 2FA dialog. Store the email
          // so it's available for verify2fa and subsequent unlock/disable flows.
          if ('twoFactorRequired' in loginData) {
            set({
              twoFactorRequired: true,
              tempToken: loginData.tempToken,
              mek: masterEncryptionKey,
              user: { userId: '', email },
              // Stash the choice so verify2fa can write the cold-start hint at
              // the ACTUAL completion point (a 2FA login only finishes there).
              // Not persisted — see `partialize`.
              _rememberMe: rememberMe,
              isLoading: false,
            });

            // Auto-clear MEK and 2FA state after 5 minutes if still pending.
            // Store the timeout ID so verify2fa can cancel it on success.
            const mekRef = masterEncryptionKey;
            const timeoutId = setTimeout(
              () => {
                const state = get();
                if (state.twoFactorRequired && state.mek === mekRef) {
                  void cryptoService.clearCryptoKey(mekRef);
                  set({
                    mek: null,
                    twoFactorRequired: false,
                    tempToken: null,
                    _2faTimeoutId: null,
                  });
                }
              },
              5 * 60 * 1000,
            );
            set({ _2faTimeoutId: timeoutId });

            // Ownership transferred to store state; prevent cleanup below
            masterEncryptionKey = null;
            return;
          }

          const { vaultKey, encryptedVaultKeyData } = await processLoginResponse(
            loginData,
            masterEncryptionKey,
          );

          const userId = parseAccessTokenUserId(loginData.accessToken);

          // Scope the offline cache to the new user and clear any stale data
          // to prevent cross-user data leakage in IndexedDB
          try {
            await offlineCache.setUser(userId);
            await offlineCache.clear();
          } catch (err) {
            logger.warn('Failed to clear offline cache during login', err);
          }

          set({
            accessToken: loginData.accessToken,
            user: { userId, email },
            isAuthenticated: true,
            isLocked: false,
            vaultKey,
            mek: masterEncryptionKey,
            encryptedVaultKeyData,
            kdfIterations: loginData.kdfIterations,
            twoFactorRequired: false,
            tempToken: null,
            _rememberMe: false,
            isLoading: false,
          });

          // A non-2FA login completes HERE, so write (or actively clear) the
          // cold-start hint now. A non-remembered login removes any stale hint
          // left by a prior remembered session on this browser.
          writeRememberHint(rememberMe);

          // Ownership transferred to store state; prevent cleanup below
          masterEncryptionKey = null;
        } catch (error) {
          set({ isLoading: false });
          // Clear MEK if it was derived but not transferred to store state
          if (masterEncryptionKey) {
            await cryptoService.clearCryptoKey(masterEncryptionKey);
          }
          throw error;
        }
      },

      // -------------------------------------------------------------------
      // 2FA verification
      // -------------------------------------------------------------------
      verify2fa: async (code: string): Promise<void> => {
        // Prevent concurrent 2FA verification attempts
        if (get().isLoading) return;
        set({ isLoading: true });

        try {
          const { tempToken, mek, user, _2faTimeoutId, _rememberMe } = get();
          if (!tempToken) {
            throw new Error('No pending 2FA session');
          }
          if (!mek) {
            throw new Error('Master encryption key is not available');
          }

          const fingerprint = await getDeviceFingerprint();
          const response = await login2faApi({
            tempToken,
            code,
            deviceInfo: {
              userAgent: navigator.userAgent,
              fingerprint,
            },
          });

          const tfaResult = response.data;
          if (!tfaResult.success) {
            throw new Error('2FA response did not contain expected data');
          }
          const loginData = tfaResult.data;

          const { vaultKey, encryptedVaultKeyData } = await processLoginResponse(loginData, mek);

          const userId = parseAccessTokenUserId(loginData.accessToken);
          const email = user?.email ?? '';

          // Scope the offline cache to the new user and clear any stale data
          // to prevent cross-user data leakage in IndexedDB
          try {
            await offlineCache.setUser(userId);
            await offlineCache.clear();
          } catch (err) {
            logger.warn('Failed to clear offline cache during 2FA login', err);
          }

          // 2FA finalization succeeded — cancel the 5-minute MEK abandon-cleanup
          // timer now. Cancellation is deferred to this point (rather than at the
          // start of the flow) so that a retryable failure mid-flow leaves the
          // reaper running.
          if (_2faTimeoutId) clearTimeout(_2faTimeoutId);

          set({
            accessToken: loginData.accessToken,
            user: { userId, email },
            isAuthenticated: true,
            isLocked: false,
            vaultKey,
            mek,
            encryptedVaultKeyData,
            kdfIterations: loginData.kdfIterations,
            twoFactorRequired: false,
            tempToken: null,
            _2faTimeoutId: null,
            _rememberMe: false,
            isLoading: false,
          });

          // A 2FA login only completes HERE (login() returned early). Write (or
          // clear) the cold-start hint using the choice stashed at the login
          // screen, so a remembered 2FA session resumes just like a non-2FA one.
          writeRememberHint(_rememberMe);
        } catch (error) {
          // Decide whether the same temp token can be retried:
          //   Retryable     → a wrong-but-correctable 2FA code or a transient
          //     network error (an Axios error whose code is NOT in
          //     NON_RETRYABLE_CODES). Keep the MEK and the abandon-cleanup
          //     timer so the user can resubmit and the 5-minute reaper still
          //     fires if they walk away.
          //   Non-retryable → the temp token / session is dead (expired,
          //     invalid, locked) OR a post-verification crypto/parse failure
          //     (corrupt or rotated vault key, malformed JWT) that surfaced as
          //     a plain, non-Axios Error. A resubmit cannot fix any of these,
          //     and the abandon timer was the only reaper, so clear the MEK
          //     immediately instead of leaving it resident with no cleanup.
          const NON_RETRYABLE_CODES: string[] = [
            ERROR_CODES.TOKEN_EXPIRED,
            ERROR_CODES.TOKEN_INVALID,
            ERROR_CODES.ACCOUNT_LOCKED,
          ];
          let retryable = false;
          if (isAxiosError(error)) {
            const errorCode = (error.response?.data as Record<string, unknown> | undefined)?.error;
            const code =
              typeof errorCode === 'object' && errorCode !== null
                ? (errorCode as Record<string, unknown>).code
                : undefined;
            retryable = !(typeof code === 'string' && NON_RETRYABLE_CODES.includes(code));
          }
          if (!retryable) {
            const { mek: currentMek, _2faTimeoutId: tid } = get();
            if (tid) clearTimeout(tid);
            if (currentMek) {
              void cryptoService.clearCryptoKey(currentMek);
            }
            set({
              mek: null,
              twoFactorRequired: false,
              tempToken: null,
              _2faTimeoutId: null,
              isLoading: false,
            });
            throw error;
          }
          set({ isLoading: false });
          throw error;
        }
      },

      // -------------------------------------------------------------------
      // Unlock (re-derive keys from stored email + master password)
      //
      // When the caller has already run PBKDF2 (e.g. for the server-side
      // rate-limited verify-unlock check), the pre-derived MEK can be passed
      // in to avoid a second PBKDF2 round.
      // -------------------------------------------------------------------
      unlock: async (masterPassword: string, preDerivedMek?: CryptoKey): Promise<void> => {
        const { user, encryptedVaultKeyData } = get();
        if (!user?.email) {
          throw new Error('Cannot unlock: user email is not available');
        }
        if (!encryptedVaultKeyData) {
          throw new Error('Cannot unlock: encrypted vault key data is not available');
        }

        let masterEncryptionKey: CryptoKey;
        if (preDerivedMek) {
          masterEncryptionKey = preDerivedMek;
        } else {
          const derived = await cryptoService.deriveKeys(masterPassword, user.email);
          masterEncryptionKey = derived.masterEncryptionKey;
          cryptoService.clearKey(derived.authKey);
        }

        let vaultKey: CryptoKey;
        try {
          const rawVaultKey = await cryptoService.decryptVaultKey(
            encryptedVaultKeyData.encrypted,
            encryptedVaultKeyData.iv,
            encryptedVaultKeyData.tag,
            masterEncryptionKey,
          );
          vaultKey = await cryptoService.importVaultKey(rawVaultKey);
          cryptoService.clearKey(rawVaultKey);
        } catch (error) {
          await cryptoService.clearCryptoKey(masterEncryptionKey);
          throw error;
        }

        // Only set crypto material here; isLocked stays true until
        // ProtectedRoute has refreshed the access token. This prevents
        // child components from firing API calls before a token is available,
        // which would cause concurrent refresh calls and trigger reuse detection.
        set({
          vaultKey,
          mek: masterEncryptionKey,
        });
      },

      // -------------------------------------------------------------------
      // Lock (clear crypto material, keep session alive)
      // -------------------------------------------------------------------
      lock: async (): Promise<void> => {
        const { vaultKey, mek, accessToken } = get();

        // Secure local state FIRST — before ANY network I/O — so a stalled or
        // black-holed connection can never leave the vault unlocked with
        // resident key material (the exact state auto-lock exists to
        // eliminate). Set state before zeroing keys to prevent concurrent
        // readers from seeing zeroed-but-non-null keys (which would cause
        // silent decryption failures).
        set({ vaultKey: null, mek: null, isLocked: true });
        // Wipe any sensitive value still on the OS clipboard. The per-component
        // auto-clear timer is cancelled (without clearing) when ProtectedRoute
        // unmounts the copy component on lock, and useClipboardGuard only fires
        // on hidden/pagehide — so without this the secret would linger behind
        // the still-visible lock screen.
        clearClipboardIfDirty();
        // Clear decrypted vault data from the vault store
        useVaultStore.getState().clearStore();

        // Record the vault_lock audit entry best-effort, AFTER local state is
        // already secured. Fire-and-forget with a bounded per-call timeout so a
        // stalled connection cannot delay or block the lock. lock() does not
        // clear accessToken (the session stays alive), so the request
        // interceptor can still attach the Bearer header.
        if (accessToken) {
          void lockApi(LOCK_LOGOUT_TIMEOUT_MS).catch((err: unknown) => {
            logger.warn('Failed to record vault_lock audit entry', err);
          });
        }

        // Then zero the actual key material
        if (vaultKey) await cryptoService.clearCryptoKey(vaultKey);
        if (mek) await cryptoService.clearCryptoKey(mek);
        // Clear offline cache to prevent cross-user data leakage
        try {
          await offlineCache.clear();
        } catch (err) {
          logger.warn('Failed to clear offline cache during lock', err);
        }
      },

      // -------------------------------------------------------------------
      // Logout (full cleanup)
      // -------------------------------------------------------------------
      logout: async (): Promise<void> => {
        const { vaultKey, mek, accessToken, user } = get();

        // Call server logout BEFORE clearing state so the Axios interceptor
        // can still read the access token from the store and send a valid
        // Bearer header. This ensures the refresh token is revoked server-side.
        // A bounded per-call timeout keeps a stalled/black-holed connection
        // from blocking local state teardown indefinitely (the failure is
        // caught and the teardown proceeds regardless).
        if (accessToken) {
          try {
            await logoutApi(LOCK_LOGOUT_TIMEOUT_MS);
          } catch (err) {
            logger.warn('Failed to call logout API', err);
          }
        }

        // Clear all state FIRST to prevent concurrent readers from seeing
        // zeroed-but-non-null keys (same pattern as lock()). This ensures
        // any in-flight vault operations see vaultKey === null and bail out
        // cleanly, rather than attempting decryption with a zeroed buffer.
        // Cancel any pending 2FA cleanup timer
        const { _2faTimeoutId } = get();
        if (_2faTimeoutId) clearTimeout(_2faTimeoutId);

        set({
          accessToken: null,
          user: null,
          isAuthenticated: false,
          isLocked: false,
          vaultKey: null,
          mek: null,
          encryptedVaultKeyData: null,
          kdfIterations: KDF_ITERATIONS,
          twoFactorRequired: false,
          tempToken: null,
          _2faTimeoutId: null,
          _rememberMe: false,
          isLoading: false,
        });

        // Remove the cold-start remember hint: a full logout ends the remembered
        // session, so the next boot must land on the login screen. lock() must
        // NOT do this — a lock keeps the session and its remembered status.
        writeRememberHint(false);

        // Wipe any sensitive value still on the OS clipboard (same rationale as
        // lock(): the copy component's pending auto-clear timer is cancelled on
        // unmount and the visibility-based guard never fires on logout).
        clearClipboardIfDirty();

        // Clear decrypted vault data from the vault store
        useVaultStore.getState().clearStore();

        // Then zero the actual key material using the captured references
        if (vaultKey) {
          await cryptoService.clearCryptoKey(vaultKey);
        }
        if (mek) {
          await cryptoService.clearCryptoKey(mek);
        }

        // Clear offline IndexedDB cache so no encrypted data persists
        // across different user sessions on the same browser, then
        // reset user scope so the next login starts fresh.
        try {
          await offlineCache.clear();
          await offlineCache.setUser(null);
        } catch (err) {
          logger.warn('Failed to clear offline cache during logout', err);
        }

        // Clear the per-user encrypted Vault Health snapshot (breach + strength).
        // Logout ONLY — NOT lock: the snapshot is encrypted at rest under the
        // vault key, so keeping it across a lock is exactly as safe as the
        // already-persisted wrapped vault key, and is required for results to
        // survive a refresh / auto-lock. clearHealthResults never throws; the
        // try/catch is defense-in-depth so logout teardown always completes.
        if (user?.userId) {
          try {
            await clearHealthResults(user.userId);
          } catch (err) {
            logger.warn('Failed to clear health results during logout', err);
          }
        }

        // Clear cached user settings so the next session fetches fresh data.
        clearSettingsCache();

        // The CSRF token is tied to the session (refresh token cookie).
        // Clear it so the next login fetches a fresh one.
        clearCsrfToken();

        // Broadcast logout to other tabs so they also clear sensitive state.
        try {
          localStorage.setItem('__hv_logout_event', Date.now().toString());
        } catch {
          // localStorage may be unavailable in some contexts (e.g., private browsing)
        }
      },

      // -------------------------------------------------------------------
      // Token management (called by the Axios interceptor)
      // -------------------------------------------------------------------
      setAccessToken: (token: string | null): void => {
        set({ accessToken: token });
      },
    }),
    {
      name: 'hvault-auth',
      storage: createJSONStorage(() => encryptedStorage),
      // Only persist non-sensitive data. CryptoKeys, ArrayBuffers, and
      // access tokens must NEVER be written to localStorage.
      //
      // SECURITY NOTE: `encryptedVaultKeyData` is persisted so that the
      // unlock screen can re-derive MEK from the master password and
      // decrypt the vault key without a server round-trip. This ciphertext
      // is AES-256-GCM encrypted under the MEK, which itself is derived
      // from the user's master password via PBKDF2 (600k iterations).
      // An attacker with access to localStorage would still need the
      // master password to derive MEK and decrypt the vault key. The risk
      // is that offline brute-force attacks become possible against the
      // stored ciphertext — this is an accepted trade-off for enabling
      // offline unlock and faster UX.
      partialize: (state) => ({
        user: state.user,
        isAuthenticated: state.isAuthenticated,
        encryptedVaultKeyData: state.encryptedVaultKeyData,
        kdfIterations: state.kdfIterations,
      }),
      onRehydrateStorage: () => (state) => {
        // After rehydration, if the user is authenticated but the vault key
        // is gone (it's never persisted), mark the vault as locked so that
        // ProtectedRoute shows the unlock screen.
        if (state && state.isAuthenticated && !state.vaultKey) {
          state.isLocked = true;
        }
      },
    },
  ),
);

// ---------------------------------------------------------------------------
// Cross-tab logout synchronization
// ---------------------------------------------------------------------------
// When one tab logs out, it writes a timestamp to localStorage. Other tabs
// detect this via the `storage` event and trigger their own logout to ensure
// sensitive state is cleared everywhere.
if (typeof window !== 'undefined') {
  window.addEventListener('storage', (event: StorageEvent) => {
    if (event.key === '__hv_logout_event' && event.newValue) {
      const { isAuthenticated, isLocked } = useAuthStore.getState();
      if (isAuthenticated || isLocked) {
        void useAuthStore.getState().logout();
      }
    }
  });
}
