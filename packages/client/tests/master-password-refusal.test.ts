/**
 * A wrong master password on a route that re-checks it costs ONE request.
 *
 * Every such route shares one small server budget (`passwordVerifyLimiter`). The
 * 401 interceptor used to treat the server's wrong-proof 401 like an expired
 * access token: it refreshed the session and sent the same wrong proof again, so
 * every typo spent two of the budget and rotated the refresh token for nothing.
 * The server answers a wrong proof only after it has accepted the session, with
 * one shared sentence (`MASTER_PASSWORD_PROOF_REFUSED_MESSAGE`), and the
 * interceptor now hands that answer straight back.
 *
 * Driven through the REAL `api` instance and the REAL auth store with a custom
 * adapter, as `unlock-double-refresh.test.tsx` is, so the real interceptors run.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import axios, {
  AxiosError,
  type AxiosAdapter,
  type AxiosRequestConfig,
  type AxiosResponse,
} from 'axios';
import { MASTER_PASSWORD_PROOF_REFUSED_MESSAGE } from '@hvault/shared';

vi.mock('../src/stores/encryptedStorage', () => ({
  encryptedStorage: {
    getItem: vi.fn().mockResolvedValue(null),
    setItem: vi.fn().mockResolvedValue(undefined),
    removeItem: vi.fn(),
  },
}));

vi.mock('../src/services/offlineCache', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../src/services/offlineCache')>()),
  offlineCache: {
    clear: vi.fn().mockResolvedValue(undefined),
    setUser: vi.fn().mockResolvedValue(undefined),
    cacheItems: vi.fn().mockResolvedValue(undefined),
    cacheFolders: vi.fn().mockResolvedValue(undefined),
    getCachedItems: vi.fn().mockResolvedValue([]),
    getCachedFolders: vi.fn().mockResolvedValue([]),
  },
}));

import { useAuthStore } from '../src/stores/authStore';
import { api, clearCsrfToken } from '../src/services/api/client';

/** Every request the adapter saw, by URL, in order. */
let seen: string[] = [];
/** What the next request to `/proof` answers with, per attempt (1-based). */
let proofAnswer: (attempt: number, config: AxiosResponse['config']) => Promise<AxiosResponse>;
/** Lets a test hold the refresh open; `releaseRefresh` always lets it go in `afterEach`. */
let refreshGate: Promise<void> | null = null;
let releaseRefresh: () => void = () => undefined;

function ok(data: unknown, config: AxiosResponse['config']): AxiosResponse {
  return { data, status: 200, statusText: 'OK', headers: {}, config } as AxiosResponse;
}

function refused(
  status: number,
  message: string,
  config: AxiosResponse['config'],
): Promise<AxiosResponse> {
  return Promise.reject(
    new AxiosError(
      `Request failed with status code ${String(status)}`,
      'ERR_BAD_REQUEST',
      config,
      undefined,
      {
        status,
        statusText: '',
        data: { success: false, message, statusCode: status, statusText: '' },
        headers: {},
        config,
      },
    ),
  );
}

const count = (url: string): number => seen.filter((entry) => entry === url).length;

const mockAdapter: AxiosAdapter = async (config) => {
  const url = config.url ?? '';
  if (url.includes('csrf-token')) return ok({ data: { csrfToken: 'test-csrf' } }, config);
  seen.push(url);
  if (url === '/auth/refresh') {
    if (refreshGate !== null) await refreshGate;
    return ok({ data: { accessToken: `fresh-${String(count('/auth/refresh'))}` } }, config);
  }
  if (url === '/proof') return proofAnswer(count('/proof'), config);
  if (url === '/expired-then-fine') {
    return count('/expired-then-fine') === 1
      ? refused(401, 'Invalid or expired token', config)
      : ok({ ok: true }, config);
  }
  return refused(404, 'Not found', config);
};

const originalApiAdapter = api.defaults.adapter;
const originalAxiosAdapter = axios.defaults.adapter;

function restoreAdapter(
  defaults: { adapter?: AxiosRequestConfig['adapter'] },
  adapter: AxiosRequestConfig['adapter'],
): void {
  defaults.adapter = adapter;
}

beforeEach(() => {
  seen = [];
  refreshGate = null;
  clearCsrfToken();
  localStorage.clear();
  api.defaults.adapter = mockAdapter;
  axios.defaults.adapter = mockAdapter;
  useAuthStore.setState({
    accessToken: 'live-token',
    user: { userId: 'user-1', email: 'vault@example.com' },
    isAuthenticated: true,
    isLocked: false,
  });
});

afterEach(() => {
  // A refresh left open would keep the interceptor's module-level `isRefreshing`
  // set and queue every later test's 401 behind it.
  releaseRefresh();
  restoreAdapter(api.defaults, originalApiAdapter);
  restoreAdapter(axios.defaults, originalAxiosAdapter);
  clearCsrfToken();
  vi.restoreAllMocks();
});

describe('a wrong master-password proof', () => {
  it('is sent once and reported as it came: no refresh, no replay, no sign-out', async () => {
    proofAnswer = (_attempt, config) => refused(401, MASTER_PASSWORD_PROOF_REFUSED_MESSAGE, config);
    const logout = vi.spyOn(useAuthStore.getState(), 'logout');

    const rejection: unknown = await api
      .put('/proof', { authHash: 'typo' })
      .catch((e: unknown) => e);

    expect(rejection).toBeInstanceOf(AxiosError);
    expect((rejection as AxiosError).response?.status).toBe(401);
    expect(((rejection as AxiosError).response?.data as { message: string }).message).toBe(
      MASTER_PASSWORD_PROOF_REFUSED_MESSAGE,
    );
    expect(count('/proof')).toBe(1);
    expect(count('/auth/refresh')).toBe(0);
    expect(logout).not.toHaveBeenCalled();
    const state = useAuthStore.getState();
    expect(state.accessToken).toBe('live-token');
    expect(state.isAuthenticated).toBe(true);
    expect(state.isLocked).toBe(false);
  });

  it('is handed back at once even while another request is refreshing the session', async () => {
    // A request whose session expired starts a refresh, held open; the proof's
    // 401 arrives meanwhile. It must not join the refresh queue and be replayed.
    refreshGate = new Promise<void>((resolve) => {
      releaseRefresh = resolve;
    });
    proofAnswer = (_attempt, config) => refused(401, MASTER_PASSWORD_PROOF_REFUSED_MESSAGE, config);

    const expired = api.get('/expired-then-fine');
    await vi.waitFor(() => expect(count('/auth/refresh')).toBe(1));
    let proof: unknown = 'still waiting';
    const settled = api
      .put('/proof', { authHash: 'typo' })
      .catch((e: unknown) => e)
      .then((outcome) => {
        proof = outcome;
      });
    // Settled while the refresh is STILL held: queued behind it, it would not be.
    await vi.waitFor(() => expect(proof).toBeInstanceOf(AxiosError));

    expect((proof as AxiosError).response?.status).toBe(401);
    expect(count('/proof')).toBe(1);
    releaseRefresh();
    await settled;
    expect((await expired).status).toBe(200);
    expect(count('/proof')).toBe(1);
    expect(count('/auth/refresh')).toBe(1);
  });
});

describe('every other 401 still refreshes the session and retries', () => {
  for (const message of [
    `${MASTER_PASSWORD_PROOF_REFUSED_MESSAGE}.`,
    `Unauthorized: ${MASTER_PASSWORD_PROOF_REFUSED_MESSAGE}`,
    'Invalid or expired token',
  ]) {
    it(`a 401 saying "${message}" is refreshed and replayed once`, async () => {
      proofAnswer = (attempt, config) =>
        attempt === 1 ? refused(401, message, config) : Promise.resolve(ok({ ok: true }, config));

      const res = await api.put('/proof', { authHash: 'right' });

      expect(res.status).toBe(200);
      expect(count('/auth/refresh')).toBe(1);
      expect(count('/proof')).toBe(2);
      expect(useAuthStore.getState().accessToken).toBe('fresh-1');
    });
  }

  it('the refusal sentence on another status is not special either', async () => {
    proofAnswer = (_attempt, config) => refused(403, MASTER_PASSWORD_PROOF_REFUSED_MESSAGE, config);

    const rejection: unknown = await api.put('/proof', {}).catch((e: unknown) => e);

    expect((rejection as AxiosError).response?.status).toBe(403);
    // A non-CSRF 403 is not refreshed (only 401 is), and is sent once.
    expect(count('/proof')).toBe(1);
    expect(count('/auth/refresh')).toBe(0);
  });
});
