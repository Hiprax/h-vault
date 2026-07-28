/**
 * Axios HTTP client configured for the H-Vault API.
 *
 * - Base URL: /api/v1
 * - Automatically attaches the Bearer access token from the auth store.
 * - Automatically fetches and attaches CSRF tokens for state-changing requests.
 * - On 401 responses, transparently attempts a token refresh via the
 *   refresh-token cookie and retries the original request.
 * - Sends credentials (cookies) with every request for refresh-token support.
 */

import axios, {
  type AxiosError,
  type AxiosRequestConfig,
  type InternalAxiosRequestConfig,
} from 'axios';
import { useAuthStore } from '../../stores/authStore.js';
import { isSessionGone, isCsrfRejection } from '../auth/sessionFailure.js';

// Augment Axios's request config with a per-request flag that lets specific
// requests opt out of the automatic "401 → token refresh → retry" behaviour
// implemented by the response interceptor below.
declare module 'axios' {
  interface AxiosRequestConfig {
    /**
     * When `true`, a 401 response to this request is surfaced to the caller
     * directly instead of triggering a token refresh + replay. Used for
     * credential re-verification requests (e.g. `/auth/verify-unlock`) where a
     * 401 means "wrong password", not "expired access token" — refreshing and
     * replaying would consume a second server-side rate-limit slot and rotate
     * the refresh token on every wrong attempt.
     */
    _skipAuthRefresh?: boolean;
  }
}

// `useAuthStore` is imported statically above. The API client, auth store, and
// auth API form an import cycle (client -> authStore -> authApi -> client), but
// every cross-module reference is read at call time — inside the interceptors
// and store actions, never during module evaluation — so the live ESM bindings
// are always initialized before they are used (the Axios `api` instance is
// created before any interceptor runs). Do not reintroduce a dynamic import.

// ---------------------------------------------------------------------------
// CSRF token management
// ---------------------------------------------------------------------------

const CSRF_SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS'];
const CSRF_INVALIDATION_KEY = '__hv_csrf_invalidated';

let csrfToken: string | null = null;
let csrfFetchPromise: Promise<string> | null = null;

/**
 * Fetches a CSRF token from the server and caches it.
 * The server also sets the __csrf cookie as a side-effect.
 *
 * Uses promise deduplication so that concurrent callers share a single
 * in-flight fetch instead of triggering multiple parallel requests.
 */
async function ensureCsrfToken(): Promise<string> {
  if (csrfToken) return csrfToken;

  // If a fetch is already in flight, piggy-back on it
  if (csrfFetchPromise) return csrfFetchPromise;

  csrfFetchPromise = axios
    .get<{ data: { csrfToken: string } }>('/api/v1/csrf-token', {
      withCredentials: true,
    })
    .then((res) => {
      csrfToken = res.data.data.csrfToken;
      return csrfToken;
    })
    .finally(() => {
      csrfFetchPromise = null;
    });

  return csrfFetchPromise;
}

/**
 * Invalidates the cached CSRF token so the next state-changing request
 * fetches a fresh one.  Also broadcasts the invalidation to other tabs
 * via a localStorage signal so they don't keep using a stale token.
 */
export function clearCsrfToken(): void {
  csrfToken = null;
  csrfFetchPromise = null;
  try {
    localStorage.setItem(CSRF_INVALIDATION_KEY, Date.now().toString());
  } catch {
    // localStorage may be unavailable — ignore
  }
}

// Listen for CSRF invalidation signals from other tabs
if (typeof window !== 'undefined') {
  window.addEventListener('storage', (event: StorageEvent) => {
    if (event.key === CSRF_INVALIDATION_KEY) {
      csrfToken = null;
      csrfFetchPromise = null;
    }
  });
}

// ---------------------------------------------------------------------------
// Axios instance
// ---------------------------------------------------------------------------

export const api = axios.create({
  baseURL: '/api/v1',
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
});

// ---------------------------------------------------------------------------
// Request interceptor: attach access token + CSRF token
// ---------------------------------------------------------------------------

api.interceptors.request.use(
  async (config: InternalAxiosRequestConfig): Promise<InternalAxiosRequestConfig> => {
    // Attach Bearer access token
    const { accessToken } = useAuthStore.getState();
    if (accessToken) {
      config.headers.Authorization = `Bearer ${accessToken}`;
    }

    // Attach CSRF token for state-changing methods
    const method = (config.method ?? 'GET').toUpperCase();
    if (!CSRF_SAFE_METHODS.includes(method)) {
      const token = await ensureCsrfToken();
      config.headers['x-csrf-token'] = token;
    }

    return config;
  },
);

// ---------------------------------------------------------------------------
// Response interceptor: CSRF retry + silent token refresh on 401
// ---------------------------------------------------------------------------

// Token refresh state.
// When a 401 is received, we attempt to refresh the access token using the
// httpOnly refresh-token cookie.  While the refresh is in-flight, any other
// 401 responses are queued (pendingRequests) and resolved/rejected once the
// single refresh attempt settles.  This prevents a thundering-herd of
// concurrent refresh calls when multiple requests fail at the same time.
let isRefreshing = false;
let pendingRequests: {
  resolve: (token: string) => void;
  reject: (error: unknown) => void;
}[] = [];

// ---------------------------------------------------------------------------
// Cross-tab refresh serialization (Web Locks)
// ---------------------------------------------------------------------------

// `isRefreshing` above is module scope, so it only single-flights refreshes
// within ONE tab. The refresh-token cookie, however, is shared by every tab of
// the origin. If two tabs refresh at the same moment they present the SAME
// token: the server claims it once and treats the second presentation as token
// reuse, revoking the whole token family — logging every session out. Holding a
// same-origin Web Lock around the refresh POST serializes the rotation across
// tabs, so the waiting tab refreshes with the already-rotated cookie and
// succeeds. The server's strict reuse detection is left untouched.
//
// EVERY refresh POST must take this lock — a writer that skips it defeats the
// serialization for everyone — so `withRefreshLock` is exported and used by all
// three call sites: this interceptor, `authApi.refreshTokenApi` (ProtectedRoute)
// and the unlock screen's pre-verify refresh.
const REFRESH_LOCK_NAME = 'hv-token-refresh';

// How long a tab waits for a sibling to finish rotating before giving up and
// refreshing unserialized. The shared Axios instance deliberately has no global
// timeout (it would abort the legitimately-long 30 MB restore / rotation
// requests), so without this bound a single stalled refresh POST would hold the
// lock indefinitely and park every other tab behind it — trading a per-tab hang
// for an origin-wide one. On timeout we simply fall back to the pre-lock
// behaviour rather than failing the refresh.
const REFRESH_LOCK_WAIT_MS = 10_000;

/**
 * Returns the Web Locks manager, or `undefined` where the API is unavailable
 * (older browsers, jsdom, non-browser contexts).
 *
 * The DOM lib types `navigator.locks` as always present, so availability is
 * probed with `'locks' in navigator` inside a `try` around the `navigator`
 * access — the same idiom `getClipboardApi()` in
 * `services/clipboard/clipboardService.ts` uses for `navigator.clipboard`.
 * An optional chain or a `typeof … === 'undefined'` check would be reported as
 * an unnecessary condition by the type-aware lint rules.
 */
function getLockManager(): LockManager | undefined {
  try {
    if ('locks' in navigator) return navigator.locks;
  } catch {
    // `navigator` itself is unavailable — fall back to running unserialized.
  }
  return undefined;
}

/**
 * Bounds how long a tab queues for the lock. Aborting the signal only drops a
 * request that has NOT been granted yet — a lock already held keeps running to
 * completion — so this caps the WAIT, never the refresh itself.
 *
 * `AbortSignal.timeout` is newer than the Web Locks API, so a browser can have
 * locks without it; construct it defensively and wait unbounded if it is
 * missing.
 */
function refreshLockOptions(): LockOptions {
  try {
    return { signal: AbortSignal.timeout(REFRESH_LOCK_WAIT_MS) };
  } catch {
    return {};
  }
}

/**
 * Runs `run` while holding the cross-tab refresh lock, so only one tab of the
 * origin rotates the shared refresh-token cookie at a time.
 *
 * Runs `run` directly — today's behaviour, single-flighted per tab only — when
 * the Web Locks API is unavailable (older browsers, insecure contexts, jsdom)
 * or when the lock could not be acquired (the wait timed out, or the lock
 * manager rejected the request). A lock-layer failure must degrade to an
 * unserialized refresh rather than surface as a failed refresh: callers read a
 * rejection as a dead session and log the user out, so letting a lock hiccup
 * escape would cause the very spurious logout this lock exists to prevent.
 *
 * The two are told apart by their error type — the lock layer always rejects
 * with a `DOMException` (`TimeoutError`, `AbortError`, `SecurityError`,
 * `InvalidStateError`), while a failed refresh rejects with an `AxiosError`,
 * which is propagated unchanged.
 */
export async function withRefreshLock<T>(run: () => Promise<T>): Promise<T> {
  const locks = getLockManager();
  if (!locks) return run();

  try {
    const outcome = await locks.request(REFRESH_LOCK_NAME, refreshLockOptions(), async () => ({
      value: await run(),
    }));
    return outcome.value;
  } catch (error) {
    if (error instanceof DOMException) return run();
    throw error;
  }
}

/**
 * Rotate the access token. **The one and only way to refresh in this client.**
 *
 * There used to be four hand-rolled copies of this — the 401 interceptor,
 * `authApi.refreshTokenApi`, `sessionResume` and the unlock screen — and they had
 * quietly diverged on all three things that matter:
 *
 *  1. **Envelope validation.** Only `ProtectedRoute` checked `success`. The unlock
 *     screen read `res.data.data.accessToken` straight off the response, so a 2xx
 *     with an unexpected body threw a `TypeError` that landed in its catch and was
 *     treated as an expired session.
 *  2. **CSRF invalidation.** A CSRF token is an HMAC bound to
 *     `hashToken(refreshToken)` (`middleware/csrf.ts`), and this POST rotates that
 *     cookie — so after every refresh the cached token is dead in EVERY tab. Only
 *     the interceptor called `clearCsrfToken()`. The others left the stale token
 *     cached, so the caller's very next write 403'd and had to be replayed: a
 *     guaranteed extra round-trip on every single vault unlock.
 *  3. **Storing the result.** Each site set the access token itself, or forgot to.
 *
 * Doing it once removes all three. The POST is held under the cross-tab Web Lock
 * because the refresh cookie is shared by every tab of the origin: two tabs
 * presenting the same pre-rotation token trips the server's reuse detection, which
 * revokes the whole family and signs the user out everywhere.
 *
 * Rejections propagate UNCHANGED so the caller can classify them with
 * `isSessionGone` — this function must never decide on its own that a session is
 * over.
 */
export async function performTokenRefresh(): Promise<string> {
  const accessToken = await withRefreshLock(async () => {
    const response = await api.post<{ success?: boolean; data?: { accessToken?: unknown } }>(
      '/auth/refresh',
    );
    const body = response.data;
    const token = body.data?.accessToken;
    // `success === false` on a 2xx should not happen, and neither should a body
    // without a string token. Both are rejected here rather than allowed to become
    // a `TypeError` at a call site, where the shape of the throw decides whether
    // the user keeps their session.
    if (body.success === false || typeof token !== 'string' || token.length === 0) {
      throw new Error('Token refresh returned an unexpected response');
    }
    return token;
  });

  useAuthStore.getState().setAccessToken(accessToken);
  // The refresh-token cookie just rotated, so every cached CSRF token on this
  // origin is now bound to a session identifier that no longer exists. Clearing
  // here (which also broadcasts to sibling tabs) is what stops the caller's next
  // state-changing request from 403-ing.
  clearCsrfToken();

  return accessToken;
}

function onRefreshSuccess(newToken: string): void {
  // Atomically swap the queue to prevent orphaned requests:
  // any request added between the swap and isRefreshing = false
  // will start its own refresh cycle instead of being queued.
  const queue = pendingRequests;
  pendingRequests = [];
  isRefreshing = false;
  queue.forEach(({ resolve }) => resolve(newToken));
}

function onRefreshFailure(error: unknown): void {
  const queue = pendingRequests;
  pendingRequests = [];
  isRefreshing = false;
  queue.forEach(({ reject }) => reject(error));
}

api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as
      (InternalAxiosRequestConfig & { _retry?: boolean; _csrfRetry?: boolean }) | undefined;

    // --- CSRF 403 retry ---
    // A stale CSRF token (session rotation, server restart, another tab
    // invalidating it) is recoverable: clear the cache, fetch a fresh token and
    // replay once. `_csrfRetry` bounds it to a single replay.
    //
    // The replay is gated on the 403 ACTUALLY being a CSRF rejection. It used to
    // fire on every 403 of a state-changing request, which silently doubled some
    // of the most expensive requests in the app: `POST /auth/login` answers 403
    // `ACCOUNT_LOCKED`, so a locked account was sent twice — two bcrypt compares,
    // two `authLimiter` slots and two `accountLimiter` slots for one visible
    // attempt, halving the user's real budget precisely when they could least
    // afford it. Replaying a request the server has already refused on its merits
    // cannot succeed; it only costs.
    const method = originalRequest?.method?.toUpperCase();
    const isStateChanging = method !== undefined && !CSRF_SAFE_METHODS.includes(method);
    if (
      error.response?.status === 403 &&
      originalRequest &&
      isStateChanging &&
      !originalRequest._csrfRetry &&
      isCsrfRejection(error)
    ) {
      originalRequest._csrfRetry = true;
      clearCsrfToken();
      try {
        const freshToken = await ensureCsrfToken();
        originalRequest.headers['x-csrf-token'] = freshToken;
      } catch {
        // The token fetch itself failed (offline, or the CSRF endpoint is being
        // rate-limited). Surface the ORIGINAL 403 rather than replacing it with a
        // second, less informative error about a request the caller never made.
        return Promise.reject(error);
      }
      return api(originalRequest as AxiosRequestConfig);
    }

    // --- 401 token refresh ---
    // Only attempt refresh on 401 and when this is not already a retry.
    // The _retry flag ensures we don't enter an infinite refresh loop.
    if (error.response?.status !== 401 || !originalRequest || originalRequest._retry) {
      return Promise.reject(error);
    }

    // Guard: never attempt to refresh the refresh endpoint itself or logout,
    // as that would create infinite recursion (refresh → 401 → refresh → …).
    if (originalRequest.url === '/auth/refresh' || originalRequest.url === '/auth/logout') {
      return Promise.reject(error);
    }

    // Guard: requests that opt out of automatic refresh (credential
    // re-verification such as /auth/verify-unlock, where a 401 means
    // "wrong password" rather than "expired access token") must surface the
    // 401 directly. Refreshing + replaying would burn a second server-side
    // rate-limit slot and rotate the refresh token on every wrong attempt.
    if (originalRequest._skipAuthRefresh) {
      return Promise.reject(error);
    }

    // Guard: don't attempt token refresh if already logged out.
    // During logout, the access token is cleared from the store before
    // async cleanup completes. Any in-flight requests that receive a 401
    // should fail immediately rather than triggering a futile refresh cycle.
    if (!useAuthStore.getState().accessToken) {
      return Promise.reject(error);
    }

    if (isRefreshing) {
      // Another request already triggered a token refresh.  Instead of
      // firing a second concurrent refresh, we queue this request and wait.
      // When the in-flight refresh settles, onRefreshSuccess/onRefreshFailure
      // will resolve or reject every queued promise, causing each waiting
      // request to retry with the new token.
      return new Promise<string>((resolve, reject) => {
        pendingRequests.push({ resolve, reject });
      }).then((token) => {
        originalRequest.headers.Authorization = `Bearer ${token}`;
        originalRequest._retry = true;
        return api(originalRequest as AxiosRequestConfig);
      });
    }

    // First 401 — this request will drive the refresh cycle.
    isRefreshing = true;
    originalRequest._retry = true;

    // The token refresh gets its OWN try/catch. ONLY a failed refresh is an
    // unrecoverable session — the retried original request below runs OUTSIDE
    // this catch so its rejection (a benign 4xx, a 5xx, or a transient network
    // error) propagates to the original caller UNCHANGED and never forces a
    // logout. Awaiting both the refresh and the replay under a single catch
    // (the previous shape) logged the user out whenever the replay failed for
    // any reason, even though the session was perfectly valid.
    let newToken: string;
    try {
      // `performTokenRefresh` owns the Web Lock, the envelope check, storing the
      // new access token and invalidating the now-stale CSRF token. Only the POST
      // is serialized across tabs — the per-tab `isRefreshing` guard and the
      // `pendingRequests` queue keep working exactly as before.
      newToken = await performTokenRefresh();
    } catch (refreshError) {
      // Flush the queue with the error so waiting requests fail immediately.
      onRefreshFailure(refreshError);

      // Log out ONLY when the server authoritatively rejected the refresh token
      // (401/403). A 429, a 5xx or an offline blip means the session is fine and
      // we simply could not reach it — and logging out here is not a local
      // teardown, it calls `POST /auth/logout` and deletes a refresh token that
      // still had days left. That turned a momentary rate limit into a permanently
      // destroyed session. Anything transient now propagates to the caller with
      // the session intact, so the next request retries normally.
      if (isSessionGone(refreshError)) {
        await useAuthStore.getState().logout();
      }

      return Promise.reject(
        refreshError instanceof Error ? refreshError : new Error(String(refreshError)),
      );
    }

    originalRequest.headers.Authorization = `Bearer ${newToken}`;

    // Flush the queue — all waiting requests will now retry with newToken.
    onRefreshSuccess(newToken);

    // Replay the original request with the fresh token. Its rejection
    // propagates to the caller unchanged (no logout) — matching the queued
    // path above, which also returns retry errors to the caller.
    return api(originalRequest as AxiosRequestConfig);
  },
);
