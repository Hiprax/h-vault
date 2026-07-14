/**
 * Regression tests for T19 — a wrong-password vault unlock must NOT cause the
 * Axios 401 interceptor to fire a second /auth/refresh and replay the
 * verify-unlock request.
 *
 * Unlike `unlock-rate-limit.test.tsx` (which mocks `api.post` directly and so
 * bypasses the interceptors entirely), these tests drive the REAL `api`
 * instance with a custom adapter so the real request/response interceptors run.
 * The bug being guarded against: because Step 1 of `handleUnlock` sets a
 * non-null access token, a 401 from `/auth/verify-unlock` looked like an
 * expired token to the interceptor, which then refreshed + replayed the
 * request — consuming two server-side `unlockLimiter` slots per visible
 * attempt and rotating the refresh token unnecessarily.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import axios, { AxiosError, type AxiosAdapter, type AxiosResponse } from 'axios';

// Mock crypto so we don't run real PBKDF2; the key objects are opaque here.
vi.mock('../src/services/crypto/cryptoService', () => ({
  cryptoService: {
    deriveKeys: vi
      .fn()
      .mockResolvedValue({ masterEncryptionKey: {} as CryptoKey, authKey: new ArrayBuffer(32) }),
    getAuthHash: vi.fn().mockReturnValue('mock-auth-hash'),
    clearKey: vi.fn(),
    clearCryptoKey: vi.fn().mockResolvedValue(undefined),
  },
}));

// Persistence + offline cache touch storage/IndexedDB — stub them out so the
// REAL auth store can be used without side effects.
vi.mock('../src/stores/encryptedStorage', () => ({
  encryptedStorage: {
    getItem: vi.fn().mockResolvedValue(null),
    setItem: vi.fn().mockResolvedValue(undefined),
    removeItem: vi.fn(),
  },
}));

vi.mock('../src/services/offlineCache', () => ({
  offlineCache: {
    clear: vi.fn().mockResolvedValue(undefined),
    setUser: vi.fn().mockResolvedValue(undefined),
    cacheItems: vi.fn().mockResolvedValue(undefined),
    cacheFolders: vi.fn().mockResolvedValue(undefined),
    getCachedItems: vi.fn().mockResolvedValue([]),
    getCachedFolders: vi.fn().mockResolvedValue([]),
  },
}));

// Imports after mocks. The REAL api client (with its interceptors) and the
// REAL auth store are intentionally used.
import { UnlockScreen } from '../src/components/auth/UnlockScreen';
import { useAuthStore } from '../src/stores/authStore';
import { api, clearCsrfToken } from '../src/services/api/client';

let refreshCount = 0;
let verifyUnlockCount = 0;
let protectedHits = 0;
let otherCount = 0;

/** Build a settled AxiosResponse for the custom adapter. */
function ok(data: unknown, config: AxiosResponse['config']): AxiosResponse {
  return { data, status: 200, statusText: 'OK', headers: {}, config } as AxiosResponse;
}

/** Build a rejected 401 AxiosError for the custom adapter. */
function unauthorized(config: AxiosResponse['config']): Promise<never> {
  return Promise.reject(
    new AxiosError(
      'Request failed with status code 401',
      AxiosError.ERR_BAD_REQUEST,
      config,
      undefined,
      {
        status: 401,
        statusText: 'Unauthorized',
        data: { success: false, error: { code: 'UNAUTHORIZED', message: 'Invalid credentials' } },
        headers: {},
        config,
      },
    ),
  );
}

/** Route requests to canned responses while counting refresh/verify calls. */
const mockAdapter: AxiosAdapter = (config) => {
  const url = config.url ?? '';
  if (url.includes('csrf-token')) {
    return Promise.resolve(ok({ data: { csrfToken: 'test-csrf' } }, config));
  }
  if (url === '/auth/refresh') {
    refreshCount++;
    return Promise.resolve(ok({ data: { accessToken: `tok-${String(refreshCount)}` } }, config));
  }
  if (url.includes('verify-unlock')) {
    verifyUnlockCount++;
    // Always 401: simulates a wrong master password.
    return unauthorized(config);
  }
  if (url.includes('protected-resource')) {
    protectedHits++;
    // First hit looks like an expired access token (401); the post-refresh
    // replay succeeds — exercising the normal refresh-and-retry path.
    return protectedHits === 1 ? unauthorized(config) : Promise.resolve(ok({ ok: true }, config));
  }
  otherCount++;
  return unauthorized(config);
};

const originalApiAdapter = api.defaults.adapter;
const originalAxiosAdapter = axios.defaults.adapter;

beforeEach(() => {
  refreshCount = 0;
  verifyUnlockCount = 0;
  protectedHits = 0;
  otherCount = 0;
  clearCsrfToken();
  localStorage.clear();
  // The global axios instance handles the CSRF token fetch; `api` handles the
  // refresh / verify-unlock calls. Both need the mock adapter.
  api.defaults.adapter = mockAdapter;
  axios.defaults.adapter = mockAdapter;
  useAuthStore.setState({
    accessToken: null,
    user: { userId: 'user-1', email: 'vault@example.com' },
    isAuthenticated: true,
    isLocked: true,
    encryptedVaultKeyData: { encrypted: 'e', iv: 'i', tag: 't' },
  });
});

afterEach(() => {
  api.defaults.adapter = originalApiAdapter;
  axios.defaults.adapter = originalAxiosAdapter;
  clearCsrfToken();
});

describe('T19 — wrong-password unlock does not double-refresh', () => {
  it('fires exactly one /auth/verify-unlock and one /auth/refresh on a wrong password', async () => {
    render(
      <MemoryRouter>
        <UnlockScreen />
      </MemoryRouter>,
    );

    fireEvent.change(screen.getByLabelText('Master Password'), {
      target: { value: 'wrong-password' },
    });
    fireEvent.click(screen.getByRole('button', { name: /unlock vault/i }));

    // Wait for the handler to fully settle (error surfaced to the user).
    await screen.findByText('Request failed with status code 401');

    // Step 1 performs the single intentional refresh; verify-unlock then 401s.
    // Without the `_skipAuthRefresh` guard the interceptor would refresh again
    // and replay verify-unlock, yielding 2 and 2.
    expect(refreshCount).toBe(1);
    expect(verifyUnlockCount).toBe(1);
  });
});

describe('T19 — interceptor honours the _skipAuthRefresh flag', () => {
  beforeEach(() => {
    // The interceptor's refresh path only runs when an access token exists.
    useAuthStore.setState({ accessToken: 'existing-token' });
  });

  it('does NOT refresh on a 401 when _skipAuthRefresh is set', async () => {
    await expect(
      api.post('/auth/verify-unlock', { authHash: 'x' }, { _skipAuthRefresh: true }),
    ).rejects.toBeInstanceOf(AxiosError);

    expect(refreshCount).toBe(0);
    expect(verifyUnlockCount).toBe(1);
  });

  it('still refreshes once and retries on a 401 for a normal request (no regression)', async () => {
    const res = await api.post('/protected-resource', {});

    // First 401 → one refresh → replay succeeds. The flag must not break the
    // ordinary expired-token refresh-and-retry flow.
    expect(res.status).toBe(200);
    expect(refreshCount).toBe(1);
    expect(otherCount).toBe(0);
  });
});
