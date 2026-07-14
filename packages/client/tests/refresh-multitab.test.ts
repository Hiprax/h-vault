/**
 * Phase 3 — cross-tab refresh serialization.
 *
 * The refresh-token cookie is shared by every tab of the origin, but the Axios
 * interceptor's `isRefreshing` single-flight guard is module scope, i.e. per
 * tab. Two tabs that refresh at the same instant therefore present the SAME
 * refresh token; the server claims it once and treats the second presentation
 * as reuse, revoking the whole token family and logging every session out.
 *
 * The fix holds a same-origin Web Lock (`hv-token-refresh`) around the actual
 * `POST /auth/refresh`, so the waiting tab refreshes with the already-rotated
 * cookie. These tests drive the REAL `api` instance through a custom adapter so
 * the real request/response interceptors run, and stub `navigator.locks` (jsdom
 * has no Web Locks API) to observe the lock boundary.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import axios, { AxiosError, type AxiosAdapter, type AxiosResponse } from 'axios';

const REFRESH_LOCK_NAME = 'hv-token-refresh';

// --- auth store mock (the interceptor only uses getState) -------------------

let currentToken: string | null = 'stale-token';
const mockLogout = vi.fn().mockResolvedValue(undefined);
const mockGetState = vi.fn(() => ({
  accessToken: currentToken,
  setAccessToken: (token: string) => {
    currentToken = token;
  },
  logout: mockLogout,
}));

// --- request routing --------------------------------------------------------

let refreshCount = 0;
let refreshShouldFail = false;
let protectedHits = 0;
let csrfProtectedHits = 0;
/** Authorization header seen by each `/protected` call, in order. */
let protectedAuth: (string | undefined)[] = [];

function ok(data: unknown, config: AxiosResponse['config']): AxiosResponse {
  return { data, status: 200, statusText: 'OK', headers: {}, config } as AxiosResponse;
}

function httpError(status: number, config: AxiosResponse['config']): Promise<never> {
  return Promise.reject(
    new AxiosError(
      `Request failed with status code ${String(status)}`,
      AxiosError.ERR_BAD_REQUEST,
      config,
      undefined,
      {
        status,
        statusText: status === 401 ? 'Unauthorized' : 'Forbidden',
        data: { success: false, error: { code: 'ERR', message: 'nope' } },
        headers: {},
        config,
      },
    ),
  );
}

const mockAdapter: AxiosAdapter = (config) => {
  const url = config.url ?? '';

  if (url.includes('csrf-token')) {
    return Promise.resolve(ok({ data: { csrfToken: 'test-csrf' } }, config));
  }

  if (url === '/auth/refresh') {
    refreshCount++;
    if (refreshShouldFail) return httpError(401, config);
    return Promise.resolve(ok({ data: { accessToken: `tok-${String(refreshCount)}` } }, config));
  }

  if (url === '/protected') {
    protectedHits++;
    const auth = config.headers.Authorization as string | undefined;
    protectedAuth.push(auth);
    // Anything but a freshly minted token looks like an expired access token,
    // so every first attempt 401s and only a post-refresh replay succeeds.
    return auth?.startsWith('Bearer tok-') === true
      ? Promise.resolve(ok({ ok: true }, config))
      : httpError(401, config);
  }

  if (url === '/csrf-protected') {
    csrfProtectedHits++;
    // Stale CSRF token on the first hit; the replay with a fresh token succeeds.
    return csrfProtectedHits === 1
      ? httpError(403, config)
      : Promise.resolve(ok({ ok: true }, config));
  }

  return httpError(401, config);
};

// --- Web Locks stub ---------------------------------------------------------

type LockCallback = () => Promise<unknown>;

/** Names passed to `navigator.locks.request`, in acquisition order. */
let lockRequests: string[] = [];
/** Options passed alongside the most recent lock request. */
let lastLockOptions: LockOptions | undefined;
/** When true, the stub rejects the request WITHOUT running the callback. */
let lockAcquisitionFails = false;
/** `refreshCount` sampled at the moment the lock callback started. */
let refreshCountAtLockEntry: number | null = null;
/** True while a lock callback is executing (i.e. the lock is held). */
let lockHeld = false;
/** Whether the lock was still held while the refresh POST was in flight. */
let lockHeldDuringRefresh = false;

/**
 * Installs a Web Locks stub. `gate`, when provided, is awaited BEFORE the
 * callback runs — modelling a sibling tab that currently holds the lock.
 */
function installLocks(gate?: Promise<void>): void {
  const request = async (
    name: string,
    options: LockOptions,
    callback: LockCallback,
  ): Promise<unknown> => {
    lockRequests.push(name);
    lastLockOptions = options;
    if (lockAcquisitionFails) {
      // Models a lock-layer failure (SecurityError / TimeoutError on the wait):
      // the callback NEVER runs, so nothing was serialized and nothing failed.
      throw new DOMException('lock unavailable', 'TimeoutError');
    }
    if (gate) await gate;
    lockHeld = true;
    try {
      return await callback();
    } finally {
      lockHeld = false;
    }
  };

  Object.defineProperty(globalThis.navigator, 'locks', {
    configurable: true,
    value: { request } as unknown as LockManager,
  });
}

function uninstallLocks(): void {
  Reflect.deleteProperty(globalThis.navigator, 'locks');
}

/** Loads a FRESH copy of the client module (module-scope refresh state reset). */
async function loadClient(): Promise<typeof import('../src/services/api/client')> {
  vi.resetModules();
  vi.doMock('../src/stores/authStore', () => ({
    useAuthStore: { getState: mockGetState },
  }));
  const mod = await import('../src/services/api/client');
  mod.api.defaults.adapter = mockAdapter;
  return mod;
}

const originalAxiosAdapter = axios.defaults.adapter;

beforeEach(() => {
  refreshCount = 0;
  refreshShouldFail = false;
  protectedHits = 0;
  csrfProtectedHits = 0;
  protectedAuth = [];
  lockRequests = [];
  lastLockOptions = undefined;
  lockAcquisitionFails = false;
  refreshCountAtLockEntry = null;
  lockHeld = false;
  lockHeldDuringRefresh = false;
  currentToken = 'stale-token';
  mockLogout.mockClear();
  localStorage.clear();
  uninstallLocks();
  // The CSRF token is fetched through the GLOBAL axios instance.
  axios.defaults.adapter = mockAdapter;
});

afterEach(() => {
  axios.defaults.adapter = originalAxiosAdapter;
  uninstallLocks();
  vi.doUnmock('../src/stores/authStore');
});

describe('cross-tab refresh lock', () => {
  it('runs the refresh POST inside the hv-token-refresh lock', async () => {
    installLocks();
    const { api } = await loadClient();

    // Observe the lock boundary from the adapter's point of view.
    const spied: AxiosAdapter = (config) => {
      if (config.url === '/auth/refresh') {
        refreshCountAtLockEntry ??= refreshCount;
        lockHeldDuringRefresh = lockHeld;
      }
      return mockAdapter(config);
    };
    api.defaults.adapter = spied;

    const res = await api.get('/protected');

    expect(res.status).toBe(200);
    expect(lockRequests).toEqual([REFRESH_LOCK_NAME]);
    // The POST had not fired before the lock callback started …
    expect(refreshCountAtLockEntry).toBe(0);
    // … and the lock was still held while it was in flight.
    expect(lockHeldDuringRefresh).toBe(true);
    expect(refreshCount).toBe(1);
    // The lock is released once the callback settles.
    expect(lockHeld).toBe(false);
    // The retry carried the freshly minted access token.
    expect(protectedAuth).toEqual(['Bearer stale-token', 'Bearer tok-1']);
  });

  it('does not issue the refresh POST until the lock is granted', async () => {
    let openGate!: () => void;
    const gate = new Promise<void>((resolve) => {
      openGate = resolve;
    });
    installLocks(gate);
    const { api } = await loadClient();

    const pending = api.get('/protected');

    // Give the interceptor every chance to run: it must be parked on the lock.
    await Promise.resolve();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(lockRequests).toEqual([REFRESH_LOCK_NAME]);
    expect(refreshCount).toBe(0);
    expect(protectedHits).toBe(1);

    openGate();
    const res = await pending;

    expect(res.status).toBe(200);
    expect(refreshCount).toBe(1);
    expect(protectedHits).toBe(2);
  });

  it('takes the lock only once for concurrent 401s (queue is unchanged)', async () => {
    installLocks();
    const { api } = await loadClient();

    const [a, b] = await Promise.all([api.get('/protected'), api.get('/protected')]);

    // Both requests 401 on their first attempt: one drives the refresh, the
    // other is parked on `pendingRequests` by the per-tab `isRefreshing` guard.
    // Exactly one refresh cycle — and one lock acquisition — must occur, and
    // both requests must be replayed with the new token.
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
    expect(refreshCount).toBe(1);
    expect(lockRequests).toEqual([REFRESH_LOCK_NAME]);
    expect(protectedHits).toBe(4);
    expect(protectedAuth).toEqual([
      'Bearer stale-token',
      'Bearer stale-token',
      'Bearer tok-1',
      'Bearer tok-1',
    ]);
  });

  it('rejects a queued request when the locked refresh fails', async () => {
    refreshShouldFail = true;
    installLocks();
    const { api } = await loadClient();

    // Both 401 → one drives the (failing) refresh, the other waits in the queue;
    // `onRefreshFailure` must flush the queue rather than leave it hanging.
    const results = await Promise.allSettled([api.get('/protected'), api.get('/protected')]);

    expect(results.map((r) => r.status)).toEqual(['rejected', 'rejected']);
    expect(refreshCount).toBe(1);
    expect(lockRequests).toEqual([REFRESH_LOCK_NAME]);
    expect(lockHeld).toBe(false);
  });

  it('logs out when the refresh fails inside the lock, and releases it', async () => {
    refreshShouldFail = true;
    installLocks();
    const { api } = await loadClient();

    await expect(api.get('/protected')).rejects.toBeInstanceOf(AxiosError);

    expect(lockRequests).toEqual([REFRESH_LOCK_NAME]);
    expect(refreshCount).toBe(1);
    expect(mockLogout).toHaveBeenCalledTimes(1);
    expect(lockHeld).toBe(false);
  });

  it('bounds the wait with an abort signal so a stalled sibling cannot park this tab forever', async () => {
    installLocks();
    const { api } = await loadClient();

    await api.get('/protected');

    // Aborting the signal only drops a not-yet-granted request, so this caps
    // the WAIT for a sibling — never the refresh itself.
    expect(lastLockOptions?.signal).toBeInstanceOf(AbortSignal);
    expect(lastLockOptions?.signal?.aborted).toBe(false);
  });

  it('refreshes unserialized (no logout) when the lock cannot be acquired', async () => {
    lockAcquisitionFails = true;
    installLocks();
    const { api } = await loadClient();

    const res = await api.get('/protected');

    // The lock layer failed before the callback ran, so nothing was refreshed
    // under it. That must degrade to today's unserialized refresh — NOT surface
    // as a failed refresh, which the interceptor would read as a dead session.
    expect(lockRequests).toEqual([REFRESH_LOCK_NAME]);
    expect(res.status).toBe(200);
    expect(refreshCount).toBe(1);
    expect(mockLogout).not.toHaveBeenCalled();
  });
});

describe('every refresh call site takes the lock', () => {
  it('refreshTokenApi (ProtectedRoute) refreshes under the lock', async () => {
    installLocks();
    await loadClient();
    const { refreshTokenApi } = await import('../src/services/api/authApi');

    const res = await refreshTokenApi();

    // A refresh POST that skipped the lock would defeat the serialization for
    // every other tab — the reuse race this phase closes would still be live.
    expect(lockRequests).toEqual([REFRESH_LOCK_NAME]);
    expect(refreshCount).toBe(1);
    expect(res.data).toEqual({ data: { accessToken: 'tok-1' } });
  });

  it('propagates a refresh failure from refreshTokenApi through the lock', async () => {
    refreshShouldFail = true;
    installLocks();
    await loadClient();
    const { refreshTokenApi } = await import('../src/services/api/authApi');

    await expect(refreshTokenApi()).rejects.toBeInstanceOf(AxiosError);

    // The callback DID run, so the rejection is the refresh's own — it must not
    // be swallowed by the unserialized-fallback path (which would double-post).
    expect(lockRequests).toEqual([REFRESH_LOCK_NAME]);
    expect(refreshCount).toBe(1);
    expect(lockHeld).toBe(false);
  });
});

describe('fallback when the Web Locks API is unavailable', () => {
  it('refreshes directly and retries when navigator.locks is absent', async () => {
    expect('locks' in navigator).toBe(false);
    const { api } = await loadClient();

    const res = await api.get('/protected');

    expect(res.status).toBe(200);
    expect(lockRequests).toEqual([]);
    expect(refreshCount).toBe(1);
    expect(protectedAuth).toEqual(['Bearer stale-token', 'Bearer tok-1']);
  });

  it('still logs out on a failed refresh without the Web Locks API', async () => {
    refreshShouldFail = true;
    const { api } = await loadClient();

    await expect(api.get('/protected')).rejects.toBeInstanceOf(AxiosError);

    expect(refreshCount).toBe(1);
    expect(mockLogout).toHaveBeenCalledTimes(1);
  });
});

describe('existing 401/403 behaviour is unchanged', () => {
  it('does not refresh (or lock) a 401 flagged _skipAuthRefresh', async () => {
    installLocks();
    const { api } = await loadClient();

    await expect(
      api.post('/auth/verify-unlock', { authHash: 'x' }, { _skipAuthRefresh: true }),
    ).rejects.toBeInstanceOf(AxiosError);

    expect(refreshCount).toBe(0);
    expect(lockRequests).toEqual([]);
    expect(mockLogout).not.toHaveBeenCalled();
  });

  it('does not refresh (or lock) a 401 when already logged out', async () => {
    currentToken = null;
    installLocks();
    const { api } = await loadClient();

    await expect(api.get('/protected')).rejects.toBeInstanceOf(AxiosError);

    expect(refreshCount).toBe(0);
    expect(lockRequests).toEqual([]);
  });

  it('replays a 403 with a fresh CSRF token without taking the refresh lock', async () => {
    installLocks();
    const { api } = await loadClient();

    const res = await api.post('/csrf-protected', {});

    expect(res.status).toBe(200);
    expect(csrfProtectedHits).toBe(2);
    expect(refreshCount).toBe(0);
    expect(lockRequests).toEqual([]);
  });
});
