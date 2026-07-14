/**
 * Behavioural coverage for the auth/crypto core:
 *
 *  - authStore: malformed server envelopes, the 5-minute 2FA MEK reaper,
 *    the pre-derived-MEK unlock path, best-effort lock/logout side effects,
 *    cross-tab logout, and rehydrate-into-locked.
 *  - cryptoService: `decryptBWK` (the backup-password verification primitive)
 *    and the `encryptVaultKey` failure path.
 *  - services/api/client: CSRF fetch deduplication and cross-tab CSRF
 *    invalidation.
 *  - useAutoLock: the tab-hidden delayed-lock timer (re-arm + unmount cleanup).
 *  - useConnectionStatus: the `offline` event, the visibility re-probe, the
 *    background poll, and the hung-probe abort.
 *
 * These target branches left uncovered by the existing suites
 * (authStore-functional, crypto, crypto-missing, refresh-multitab,
 * hooks-functional, useConnectionStatus).
 */

import { describe, it, expect, vi, beforeEach, afterEach, beforeAll } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import axios, { type AxiosAdapter, type AxiosResponse } from 'axios';

// ---------------------------------------------------------------------------
// jsdom polyfill (uiStore reads matchMedia at module scope)
// ---------------------------------------------------------------------------

vi.hoisted(() => {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    configurable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }),
  });
});

// ---------------------------------------------------------------------------
// Mocks (declared before the store imports)
//
// NOTE: `services/api/client` is deliberately NOT mocked — the CSRF tests below
// drive the REAL Axios instance through a stub adapter.
// ---------------------------------------------------------------------------

vi.mock('../src/stores/encryptedStorage', () => ({
  encryptedStorage: {
    getItem: vi.fn().mockResolvedValue(null),
    setItem: vi.fn().mockResolvedValue(undefined),
    removeItem: vi.fn(),
  },
}));

vi.mock('../src/services/crypto/cryptoService', () => ({
  cryptoService: {
    deriveKeys: vi.fn(),
    getAuthHash: vi.fn().mockReturnValue('mock-auth-hash'),
    generateVaultKey: vi.fn(),
    importVaultKey: vi.fn(),
    encryptVaultKey: vi.fn(),
    decryptVaultKey: vi.fn(),
    encryptData: vi.fn(),
    decryptData: vi.fn(),
    generateSearchHash: vi.fn(),
    clearKey: vi.fn(),
    clearCryptoKey: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock('../src/services/api/authApi', () => ({
  registerApi: vi.fn(),
  loginApi: vi.fn(),
  login2faApi: vi.fn(),
  logoutApi: vi.fn().mockResolvedValue(undefined),
  lockApi: vi.fn().mockResolvedValue({ data: { success: true } }),
}));

vi.mock('../src/services/api/vaultApi', () => ({
  listItemsApi: vi.fn(),
  createItemApi: vi.fn(),
  updateItemApi: vi.fn(),
  deleteItemApi: vi.fn(),
  permanentDeleteApi: vi.fn(),
  emptyTrashApi: vi.fn(),
  restoreItemApi: vi.fn(),
  listFoldersApi: vi.fn(),
  createFolderApi: vi.fn(),
  updateFolderApi: vi.fn(),
  deleteFolderApi: vi.fn(),
  listTrashApi: vi.fn(),
}));

vi.mock('../src/services/offlineCache', () => ({
  offlineCache: {
    setUser: vi.fn().mockResolvedValue(undefined),
    cacheItems: vi.fn().mockResolvedValue(undefined),
    cacheFolders: vi.fn().mockResolvedValue(undefined),
    getCachedItems: vi.fn().mockResolvedValue([]),
    getCachedFolders: vi.fn().mockResolvedValue([]),
    clear: vi.fn().mockResolvedValue(undefined),
  },
}));

const mockLoggerWarn = vi.fn();
vi.mock('../src/lib/logger', () => ({
  logger: {
    error: vi.fn(),
    warn: (...args: unknown[]) => mockLoggerWarn(...args),
    info: vi.fn(),
    debug: vi.fn(),
  },
}));

// useAutoLock reads its timeout from this hook; pin it so the auto-lock tests
// are deterministic and issue no profile fetch.
vi.mock('../src/hooks/useUserSettings', () => ({
  useUserSettings: () => ({ autoLockTimeout: 15, clipboardClearTimeout: 30, theme: 'system' }),
  clearSettingsCache: vi.fn(),
  onSettingsInvalidated: vi.fn(() => () => {}),
}));

// ---------------------------------------------------------------------------
// Imports (after mocks)
// ---------------------------------------------------------------------------

import { useAuthStore } from '../src/stores/authStore.js';
import { cryptoService } from '../src/services/crypto/cryptoService.js';
import { loginApi, login2faApi, lockApi, logoutApi } from '../src/services/api/authApi.js';
import { offlineCache } from '../src/services/offlineCache.js';
import { api, clearCsrfToken } from '../src/services/api/client.js';
import { useAutoLock } from '../src/hooks/useAutoLock.js';
import { useConnectionStatus } from '../src/hooks/useConnectionStatus.js';
import type { CryptoService as CryptoServiceType } from '../src/services/crypto/cryptoService.js';

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const mockMek = { id: 'mek' } as unknown as CryptoKey;
const mockAuthKey = new ArrayBuffer(32);
const mockVaultKeyCK = { id: 'vk' } as unknown as CryptoKey;

const authInitialState = {
  accessToken: null,
  user: null,
  isAuthenticated: false,
  isLocked: false,
  vaultKey: null,
  mek: null,
  encryptedVaultKeyData: null,
  kdfIterations: 600_000,
  twoFactorRequired: false,
  tempToken: null,
  _2faTimeoutId: null,
  isLoading: false,
};

function buildMockJwt(sub: string): string {
  const header = btoa(JSON.stringify({ alg: 'HS256' }));
  const payload = btoa(JSON.stringify({ sub }));
  return `${header}.${payload}.sig`;
}

const twoFactorLoginResponse = {
  data: { success: true, data: { twoFactorRequired: true, tempToken: 'temp-token-1' } },
};

const successful2faResponse = {
  data: {
    success: true,
    data: {
      accessToken: buildMockJwt('user-2fa'),
      encryptedVaultKey: 'enc-vk',
      vaultKeyIv: 'vk-iv',
      vaultKeyTag: 'vk-tag',
      kdfIterations: 600_000,
      kdfAlgorithm: 'PBKDF2-SHA256',
    },
  },
};

beforeEach(() => {
  vi.clearAllMocks();
  useAuthStore.setState({ ...authInitialState });

  vi.mocked(cryptoService.deriveKeys).mockResolvedValue({
    masterEncryptionKey: mockMek,
    authKey: mockAuthKey,
  });
  vi.mocked(cryptoService.importVaultKey).mockResolvedValue(mockVaultKeyCK);
  vi.mocked(cryptoService.decryptVaultKey).mockResolvedValue(new ArrayBuffer(32));
  vi.mocked(lockApi).mockResolvedValue({ data: { success: true } } as never);
  vi.mocked(logoutApi).mockResolvedValue(undefined as never);
});

// ===========================================================================
// authStore — malformed server envelopes
// ===========================================================================

describe('authStore — malformed server envelopes', () => {
  it('login rejects and zeroes the derived MEK when the server envelope is not a success', async () => {
    vi.mocked(loginApi).mockResolvedValue({
      data: { success: false, error: { code: 'SERVER_ERROR', message: 'boom' } },
    } as never);

    await expect(useAuthStore.getState().login('user@example.com', 'Master123!')).rejects.toThrow(
      'Login response did not contain expected data',
    );

    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(false);
    expect(state.isLoading).toBe(false);
    // The MEK was derived but never transferred to the store — it must be zeroed,
    // not left resident in memory.
    expect(state.mek).toBeNull();
    expect(cryptoService.clearCryptoKey).toHaveBeenCalledWith(mockMek);
  });

  it('verify2fa rejects and clears the MEK when the 2FA envelope is not a success', async () => {
    useAuthStore.setState({
      twoFactorRequired: true,
      tempToken: 'temp-token-1',
      mek: mockMek,
      user: { userId: '', email: 'user@example.com' },
    });
    vi.mocked(login2faApi).mockResolvedValue({ data: { success: false } } as never);

    await expect(useAuthStore.getState().verify2fa('123456')).rejects.toThrow(
      '2FA response did not contain expected data',
    );

    // A plain (non-Axios) failure is non-retryable → the MEK must not linger.
    const state = useAuthStore.getState();
    expect(state.mek).toBeNull();
    expect(state.tempToken).toBeNull();
    expect(state.twoFactorRequired).toBe(false);
    expect(state.isAuthenticated).toBe(false);
    expect(cryptoService.clearCryptoKey).toHaveBeenCalledWith(mockMek);
  });
});

// ===========================================================================
// authStore — the 5-minute abandoned-2FA MEK reaper
// ===========================================================================

describe('authStore — abandoned 2FA session reaper', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('zeroes the MEK and drops the 2FA session when the user abandons the code prompt for 5 minutes', async () => {
    vi.mocked(loginApi).mockResolvedValue(twoFactorLoginResponse as never);

    await useAuthStore.getState().login('user@example.com', 'Master123!');
    expect(useAuthStore.getState().mek).toBe(mockMek);

    // Just before the deadline the session is still usable.
    vi.advanceTimersByTime(5 * 60 * 1000 - 1);
    expect(useAuthStore.getState().mek).toBe(mockMek);

    vi.advanceTimersByTime(1);

    const state = useAuthStore.getState();
    expect(state.mek).toBeNull();
    expect(state.twoFactorRequired).toBe(false);
    expect(state.tempToken).toBeNull();
    expect(state._2faTimeoutId).toBeNull();
    expect(cryptoService.clearCryptoKey).toHaveBeenCalledWith(mockMek);
  });

  it('does not reap a MEK that a newer login has already replaced', async () => {
    vi.mocked(loginApi).mockResolvedValue(twoFactorLoginResponse as never);
    await useAuthStore.getState().login('user@example.com', 'Master123!');

    // A second login (still pending 2FA) installs a DIFFERENT MEK. The first
    // login's reaper must not zero it — that would break the live session.
    const newerMek = { id: 'newer-mek' } as unknown as CryptoKey;
    useAuthStore.setState({ mek: newerMek });
    vi.mocked(cryptoService.clearCryptoKey).mockClear();

    vi.advanceTimersByTime(5 * 60 * 1000);

    expect(useAuthStore.getState().mek).toBe(newerMek);
    expect(useAuthStore.getState().twoFactorRequired).toBe(true);
    expect(cryptoService.clearCryptoKey).not.toHaveBeenCalled();
  });

  it('logout cancels the pending reaper so it cannot fire against the next session', async () => {
    vi.mocked(loginApi).mockResolvedValue(twoFactorLoginResponse as never);
    await useAuthStore.getState().login('user@example.com', 'Master123!');
    const pendingTimeoutId = useAuthStore.getState()._2faTimeoutId;
    expect(pendingTimeoutId).not.toBeNull();

    const clearTimeoutSpy = vi.spyOn(globalThis, 'clearTimeout');

    await useAuthStore.getState().logout();

    expect(clearTimeoutSpy).toHaveBeenCalledWith(pendingTimeoutId);
    expect(useAuthStore.getState()._2faTimeoutId).toBeNull();
    clearTimeoutSpy.mockRestore();
  });
});

// ===========================================================================
// authStore — best-effort side effects on the 2FA / lock / logout paths
// ===========================================================================

describe('authStore — best-effort side effects', () => {
  it('completes the 2FA login even when the offline cache cannot be cleared', async () => {
    useAuthStore.setState({
      twoFactorRequired: true,
      tempToken: 'temp-token-1',
      mek: mockMek,
      user: { userId: '', email: 'user@example.com' },
    });
    const cacheError = new Error('IndexedDB unavailable');
    vi.mocked(offlineCache.clear).mockRejectedValueOnce(cacheError);
    vi.mocked(login2faApi).mockResolvedValue(successful2faResponse as never);

    await useAuthStore.getState().verify2fa('123456');

    expect(mockLoggerWarn).toHaveBeenCalledWith(
      'Failed to clear offline cache during 2FA login',
      cacheError,
    );
    // The failure is non-fatal: the user is signed in with a live vault key.
    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(true);
    expect(state.vaultKey).toBe(mockVaultKeyCK);
  });

  it('lock() still locks the vault when the vault_lock audit call fails', async () => {
    vi.mocked(lockApi).mockRejectedValue(new Error('network down') as never);
    useAuthStore.setState({
      accessToken: 'access-token',
      isAuthenticated: true,
      isLocked: false,
      vaultKey: mockVaultKeyCK,
      mek: mockMek,
    });

    await useAuthStore.getState().lock();

    const state = useAuthStore.getState();
    expect(state.isLocked).toBe(true);
    expect(state.vaultKey).toBeNull();
    expect(state.mek).toBeNull();
    // The rejection of the fire-and-forget audit call is swallowed and logged,
    // never surfaced to the caller.
    await vi.waitFor(() => {
      expect(mockLoggerWarn).toHaveBeenCalledWith(
        'Failed to record vault_lock audit entry',
        expect.any(Error),
      );
    });
  });

  it('logout() tears the session down even when the offline cache cannot be cleared', async () => {
    const cacheError = new Error('IndexedDB unavailable');
    vi.mocked(offlineCache.clear).mockRejectedValueOnce(cacheError);
    useAuthStore.setState({
      accessToken: 'access-token',
      user: { userId: 'u1', email: 'a@b.c' },
      isAuthenticated: true,
      vaultKey: mockVaultKeyCK,
      mek: mockMek,
    });

    await useAuthStore.getState().logout();

    expect(mockLoggerWarn).toHaveBeenCalledWith(
      'Failed to clear offline cache during logout',
      cacheError,
    );
    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(false);
    expect(state.accessToken).toBeNull();
    expect(state.user).toBeNull();
    expect(state.vaultKey).toBeNull();
    expect(state.mek).toBeNull();
  });
});

// ===========================================================================
// authStore — unlock with a pre-derived MEK
// ===========================================================================

describe('authStore.unlock with a pre-derived MEK', () => {
  it('reuses the caller-supplied MEK instead of running PBKDF2 a second time', async () => {
    const preDerived = { id: 'pre-derived' } as unknown as CryptoKey;
    useAuthStore.setState({
      user: { userId: 'u1', email: 'user@example.com' },
      isAuthenticated: true,
      isLocked: true,
      encryptedVaultKeyData: { encrypted: 'enc', iv: 'iv', tag: 'tag' },
    });

    await useAuthStore.getState().unlock('Master123!', preDerived);

    // The 600k-iteration derivation is skipped entirely.
    expect(cryptoService.deriveKeys).not.toHaveBeenCalled();
    expect(cryptoService.decryptVaultKey).toHaveBeenCalledWith('enc', 'iv', 'tag', preDerived);

    const state = useAuthStore.getState();
    expect(state.mek).toBe(preDerived);
    expect(state.vaultKey).toBe(mockVaultKeyCK);
  });

  it('zeroes a caller-supplied MEK when the vault key fails to decrypt', async () => {
    const preDerived = { id: 'pre-derived' } as unknown as CryptoKey;
    vi.mocked(cryptoService.decryptVaultKey).mockRejectedValue(new Error('GCM tag mismatch'));
    useAuthStore.setState({
      user: { userId: 'u1', email: 'user@example.com' },
      isAuthenticated: true,
      isLocked: true,
      encryptedVaultKeyData: { encrypted: 'enc', iv: 'iv', tag: 'tag' },
    });

    await expect(useAuthStore.getState().unlock('Master123!', preDerived)).rejects.toThrow(
      'GCM tag mismatch',
    );

    expect(cryptoService.clearCryptoKey).toHaveBeenCalledWith(preDerived);
    expect(useAuthStore.getState().vaultKey).toBeNull();
  });
});

// ===========================================================================
// authStore — cross-tab logout (`storage` listener registered at module load)
// ===========================================================================

describe('authStore — cross-tab logout', () => {
  function fireLogoutEvent(newValue: string | null): void {
    window.dispatchEvent(new StorageEvent('storage', { key: '__hv_logout_event', newValue }));
  }

  it('logs this tab out when another tab broadcasts a logout', async () => {
    useAuthStore.setState({
      accessToken: 'access-token',
      user: { userId: 'u1', email: 'a@b.c' },
      isAuthenticated: true,
      vaultKey: mockVaultKeyCK,
      mek: mockMek,
    });

    fireLogoutEvent(Date.now().toString());

    await vi.waitFor(() => {
      expect(useAuthStore.getState().isAuthenticated).toBe(false);
    });
    const state = useAuthStore.getState();
    expect(state.vaultKey).toBeNull();
    expect(state.mek).toBeNull();
    expect(state.accessToken).toBeNull();
    expect(logoutApi).toHaveBeenCalled();
  });

  it('also logs out a tab that is merely locked (keys gone, session alive)', async () => {
    useAuthStore.setState({
      accessToken: 'access-token',
      user: { userId: 'u1', email: 'a@b.c' },
      isAuthenticated: false,
      isLocked: true,
    });

    fireLogoutEvent('1');

    await vi.waitFor(() => {
      expect(useAuthStore.getState().accessToken).toBeNull();
    });
    expect(useAuthStore.getState().isLocked).toBe(false);
  });

  it('ignores the broadcast in a tab that was never signed in', async () => {
    useAuthStore.setState({ accessToken: 'orphan-token', isAuthenticated: false, isLocked: false });

    fireLogoutEvent('1');
    await Promise.resolve();

    expect(logoutApi).not.toHaveBeenCalled();
    expect(useAuthStore.getState().accessToken).toBe('orphan-token');
  });

  it('ignores a logout key whose value was removed (newValue === null)', async () => {
    useAuthStore.setState({
      accessToken: 'access-token',
      isAuthenticated: true,
      isLocked: false,
    });

    fireLogoutEvent(null);
    await Promise.resolve();

    expect(logoutApi).not.toHaveBeenCalled();
    expect(useAuthStore.getState().isAuthenticated).toBe(true);
  });
});

// ===========================================================================
// authStore — rehydration
// ===========================================================================

describe('authStore — rehydration from persisted storage', () => {
  it('comes back LOCKED when a persisted session is restored without a vault key', async () => {
    const { encryptedStorage } = await import('../src/stores/encryptedStorage.js');
    vi.mocked(encryptedStorage.getItem).mockResolvedValueOnce(
      JSON.stringify({
        state: {
          user: { userId: 'u1', email: 'a@b.c' },
          isAuthenticated: true,
          encryptedVaultKeyData: { encrypted: 'e', iv: 'i', tag: 't' },
          kdfIterations: 600_000,
        },
        version: 0,
      }),
    );

    await useAuthStore.persist.rehydrate();

    const state = useAuthStore.getState();
    // The vault key is never persisted, so a reload MUST land on the unlock
    // screen rather than an authenticated-but-keyless vault.
    expect(state.isAuthenticated).toBe(true);
    expect(state.vaultKey).toBeNull();
    expect(state.isLocked).toBe(true);

    useAuthStore.setState({ ...authInitialState });
  });
});

// ===========================================================================
// cryptoService — real Web Crypto (the module is mocked above for the store,
// so the real class is loaded via importActual)
// ===========================================================================

describe('cryptoService — BWK decryption and vault-key encryption failure', () => {
  let crypto: CryptoServiceType;

  beforeAll(async () => {
    const actual = await vi.importActual<typeof import('../src/services/crypto/cryptoService.js')>(
      '../src/services/crypto/cryptoService.js',
    );
    crypto = new actual.CryptoService();
  });

  it('decryptBWK round-trips the wrapping key when the backup password is correct', async () => {
    const salt = crypto.generateSalt();
    const bek = await crypto.deriveBEK('correct-backup-password', salt);
    const bwk = crypto.generateBWK();
    const expected = new Uint8Array(new Uint8Array(bwk));

    const { encrypted, iv, tag } = await crypto.encryptBWK(bwk, bek);
    const recovered = await crypto.decryptBWK(encrypted, iv, tag, bek);

    expect(new Uint8Array(recovered)).toEqual(expected);
  });

  it('decryptBWK rejects when the backup password is wrong (BEK mismatch)', async () => {
    const salt = crypto.generateSalt();
    const bek = await crypto.deriveBEK('correct-backup-password', salt);
    const wrongBek = await crypto.deriveBEK('wrong-backup-password', salt);
    const bwk = crypto.generateBWK();

    const { encrypted, iv, tag } = await crypto.encryptBWK(bwk, bek);

    await expect(crypto.decryptBWK(encrypted, iv, tag, wrongBek)).rejects.toThrow();
  });

  it('decryptBWK rejects a tampered auth tag rather than returning garbage key bytes', async () => {
    const salt = crypto.generateSalt();
    const bek = await crypto.deriveBEK('backup-password', salt);
    const bwk = crypto.generateBWK();

    const { encrypted, iv, tag } = await crypto.encryptBWK(bwk, bek);
    const tagBytes = new Uint8Array(crypto.base64ToArrayBuffer(tag));
    tagBytes[0] ^= 0xff;
    const tamperedTag = crypto.arrayBufferToBase64(tagBytes.buffer as ArrayBuffer);

    await expect(crypto.decryptBWK(encrypted, iv, tamperedTag, bek)).rejects.toThrow();
  });

  it('encryptVaultKey surfaces a user-facing error when the vault key cannot be exported', async () => {
    const { masterEncryptionKey: mek } = await crypto.deriveKeys('pw', 'u@e.com');
    // A non-extractable key cannot be exported, so encryptVaultKey's exportKey
    // call throws — the raw WebCrypto error must not leak to the UI.
    const nonExtractable = await globalThis.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );

    await expect(crypto.encryptVaultKey(nonExtractable, mek)).rejects.toThrow(
      'Failed to encrypt vault key. The encryption key may be invalid or the vault key data is corrupted.',
    );
  });
});

// ===========================================================================
// services/api/client — CSRF token lifecycle (real Axios instance + adapter)
// ===========================================================================

describe('api client — CSRF token lifecycle', () => {
  let csrfFetches: number;
  let sentCsrfHeaders: (string | undefined)[];
  let sentAuthHeaders: (string | undefined)[];
  const originalGlobalAdapter = axios.defaults.adapter;
  const originalApiAdapter = api.defaults.adapter;

  function ok(data: unknown, config: AxiosResponse['config']): AxiosResponse {
    return { data, status: 200, statusText: 'OK', headers: {}, config } as AxiosResponse;
  }

  const adapter: AxiosAdapter = (config) => {
    const url = config.url ?? '';
    if (url.includes('csrf-token')) {
      csrfFetches += 1;
      return Promise.resolve(ok({ data: { csrfToken: `csrf-${String(csrfFetches)}` } }, config));
    }
    sentCsrfHeaders.push(config.headers['x-csrf-token'] as string | undefined);
    sentAuthHeaders.push(config.headers.Authorization as string | undefined);
    return Promise.resolve(ok({ success: true }, config));
  };

  beforeEach(() => {
    csrfFetches = 0;
    sentCsrfHeaders = [];
    sentAuthHeaders = [];
    axios.defaults.adapter = adapter;
    api.defaults.adapter = adapter;
    clearCsrfToken();
  });

  afterEach(() => {
    axios.defaults.adapter = originalGlobalAdapter;
    api.defaults.adapter = originalApiAdapter;
  });

  it('fetches the CSRF token once for concurrent state-changing requests', async () => {
    await Promise.all([api.post('/a', {}), api.post('/b', {}), api.put('/c', {})]);

    // Three writes on a cold cache must share ONE /csrf-token round-trip …
    expect(csrfFetches).toBe(1);
    // … and all three must carry that same token.
    expect(sentCsrfHeaders).toEqual(['csrf-1', 'csrf-1', 'csrf-1']);
  });

  it('does not fetch a CSRF token for safe methods', async () => {
    await api.get('/items');

    expect(csrfFetches).toBe(0);
    expect(sentCsrfHeaders).toEqual([undefined]);
  });

  it('re-fetches the token after another tab invalidates it', async () => {
    await api.post('/a', {});
    expect(csrfFetches).toBe(1);

    // Another tab rotated the session and broadcast the invalidation.
    window.dispatchEvent(
      new StorageEvent('storage', { key: '__hv_csrf_invalidated', newValue: '1' }),
    );

    await api.post('/b', {});

    // The stale token must NOT be reused — a fresh one is fetched.
    expect(csrfFetches).toBe(2);
    expect(sentCsrfHeaders).toEqual(['csrf-1', 'csrf-2']);
  });

  it('keeps the cached token when an unrelated storage key changes', async () => {
    await api.post('/a', {});
    window.dispatchEvent(new StorageEvent('storage', { key: 'some-other-key', newValue: 'noise' }));
    await api.post('/b', {});

    expect(csrfFetches).toBe(1);
    expect(sentCsrfHeaders).toEqual(['csrf-1', 'csrf-1']);
  });

  it('attaches the Bearer token that authStore.setAccessToken installed', async () => {
    useAuthStore.getState().setAccessToken('fresh-access-token');

    await api.get('/profile');

    expect(sentAuthHeaders).toEqual(['Bearer fresh-access-token']);

    // …and clearing it stops the header being sent.
    useAuthStore.getState().setAccessToken(null);
    await api.get('/profile');
    expect(sentAuthHeaders[1]).toBeUndefined();
  });
});

// ===========================================================================
// useAutoLock — the tab-hidden delayed lock
// ===========================================================================

describe('useAutoLock — tab-hidden delayed lock', () => {
  const VISIBILITY_DELAY_MS = 30_000;
  let mockLock: ReturnType<typeof vi.fn>;

  function setHidden(hidden: boolean): void {
    Object.defineProperty(document, 'hidden', { value: hidden, configurable: true });
  }

  beforeEach(() => {
    vi.useFakeTimers();
    mockLock = vi.fn().mockResolvedValue(undefined);
    useAuthStore.setState({ isAuthenticated: true, isLocked: false, lock: mockLock });
  });

  afterEach(() => {
    setHidden(false);
    vi.useRealTimers();
    useAuthStore.setState({ ...authInitialState });
  });

  it('restarts the 30s countdown when the tab is re-hidden (timers do not stack)', () => {
    renderHook(() => useAutoLock());

    setHidden(true);
    act(() => {
      document.dispatchEvent(new Event('visibilitychange'));
    });

    vi.advanceTimersByTime(10_000);
    expect(mockLock).not.toHaveBeenCalled();

    // A second hidden signal (e.g. window blur → hide) must cancel and re-arm,
    // not leave two timers racing.
    act(() => {
      document.dispatchEvent(new Event('visibilitychange'));
    });

    // The ORIGINAL deadline (t = 30s) passes with no lock…
    vi.advanceTimersByTime(VISIBILITY_DELAY_MS - 10_000 - 1);
    expect(mockLock).not.toHaveBeenCalled();

    // …and the lock fires exactly once, 30s after the SECOND signal.
    vi.advanceTimersByTime(10_001);
    expect(mockLock).toHaveBeenCalledTimes(1);
  });

  it('cancels the pending hidden-tab lock when the hook unmounts', () => {
    const { unmount } = renderHook(() => useAutoLock());

    setHidden(true);
    act(() => {
      document.dispatchEvent(new Event('visibilitychange'));
    });

    unmount();

    // The vault was already unmounted (e.g. the user navigated away); a leaked
    // timer would call lock() against a dead component.
    vi.advanceTimersByTime(VISIBILITY_DELAY_MS * 2);
    expect(mockLock).not.toHaveBeenCalled();
  });

  it('does not lock a hidden tab whose session was already locked elsewhere', () => {
    renderHook(() => useAutoLock());

    setHidden(true);
    act(() => {
      document.dispatchEvent(new Event('visibilitychange'));
    });

    // Another tab locked the vault while this one was hidden.
    useAuthStore.setState({ isLocked: true });

    vi.advanceTimersByTime(VISIBILITY_DELAY_MS);
    expect(mockLock).not.toHaveBeenCalled();
  });
});

// ===========================================================================
// useConnectionStatus — event-driven transitions and polling
// ===========================================================================

describe('useConnectionStatus — transitions', () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  function setOnLine(value: boolean): void {
    Object.defineProperty(navigator, 'onLine', { configurable: true, value });
  }

  function setVisibility(state: DocumentVisibilityState): void {
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: state });
  }

  beforeEach(() => {
    vi.useFakeTimers();
    setOnLine(true);
    setVisibility('visible');
    fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
    setOnLine(true);
    setVisibility('visible');
  });

  it('flips to offline on the browser `offline` event without probing the server', async () => {
    const { result } = renderHook(() => useConnectionStatus());
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(result.current.isOnline).toBe(true);
    const probesSoFar = fetchMock.mock.calls.length;

    setOnLine(false);
    act(() => {
      window.dispatchEvent(new Event('offline'));
    });

    expect(result.current.isOnline).toBe(false);
    // The browser already told us there is no link — probing would be pointless.
    expect(fetchMock).toHaveBeenCalledTimes(probesSoFar);
  });

  it('re-probes the server when the tab becomes visible again', async () => {
    const { result } = renderHook(() => useConnectionStatus());
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    const probesSoFar = fetchMock.mock.calls.length;

    // While hidden, the server went down.
    fetchMock.mockResolvedValue({ ok: false });
    setVisibility('visible');
    await act(async () => {
      document.dispatchEvent(new Event('visibilitychange'));
      await vi.advanceTimersByTimeAsync(0);
    });

    expect(fetchMock).toHaveBeenCalledTimes(probesSoFar + 1);
    expect(result.current.isOnline).toBe(false);
  });

  it('does not probe on a visibilitychange that hides the tab', async () => {
    renderHook(() => useConnectionStatus());
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    const probesSoFar = fetchMock.mock.calls.length;

    setVisibility('hidden');
    await act(async () => {
      document.dispatchEvent(new Event('visibilitychange'));
      await vi.advanceTimersByTimeAsync(0);
    });

    expect(fetchMock).toHaveBeenCalledTimes(probesSoFar);
  });

  it('keeps polling in the background and reports the server going down', async () => {
    const { result } = renderHook(() => useConnectionStatus());
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(result.current.isOnline).toBe(true);

    // The server dies; the next poll (30s later) must notice.
    fetchMock.mockRejectedValue(new Error('ECONNREFUSED'));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000);
    });

    expect(result.current.isOnline).toBe(false);
  });

  it('reports offline when a health probe hangs past the 5s abort deadline', async () => {
    // A black-holed connection: the fetch only settles when the signal aborts.
    fetchMock.mockImplementation(
      (_url: string, init: { signal: AbortSignal }) =>
        new Promise((_resolve, reject) => {
          init.signal.addEventListener('abort', () => {
            reject(new DOMException('aborted', 'AbortError'));
          });
        }),
    );

    const { result } = renderHook(() => useConnectionStatus());

    await act(async () => {
      await vi.advanceTimersByTimeAsync(4_999);
    });
    // Still hanging — no verdict yet.
    expect(result.current.isOnline).toBe(true);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(2);
    });

    expect(result.current.isOnline).toBe(false);
  });
});
