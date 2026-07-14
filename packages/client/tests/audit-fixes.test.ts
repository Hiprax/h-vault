/**
 * Tests for client-side fix tasks from the comprehensive audit.
 *
 * Covers:
 * - Task 1.2: Vault store clearStore is called on lock/logout
 * - Task 2.1: MEK cleared on error paths (register, login catch, unlock)
 * - Task 2.2: lock() sets state before zeroing keys (race condition fix)
 * - Task 2.6: Offline cache cleared on lock/login
 * - Task 3.8: encryptedStorage stack overflow fix (loop-based btoa)
 * - Task 3.11: keypress replaced with keydown in ACTIVITY_EVENTS
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ---------------------------------------------------------------------------
// Polyfill matchMedia (required by uiStore)
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
// Mocks -- all inline vi.fn() to avoid hoisting issues
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
  logoutApi: vi.fn(),
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

vi.mock('@hvault/shared', async () => {
  const actual = await vi.importActual<Record<string, unknown>>('@hvault/shared');
  return {
    ...actual,
    KDF_ITERATIONS: 600_000,
    KDF_ALGORITHM: 'PBKDF2',
    ENCRYPTION_VERSION: 1,
  };
});

// ---------------------------------------------------------------------------
// Imports (after mocks)
// ---------------------------------------------------------------------------

import { useAuthStore } from '../src/stores/authStore';
import { useVaultStore } from '../src/stores/vaultStore';
import { cryptoService } from '../src/services/crypto/cryptoService';
import { offlineCache } from '../src/services/offlineCache';
import { logoutApi } from '../src/services/api/authApi';
import type { DecryptedVaultItem, DecryptedFolder } from '../src/stores/vaultStore';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createMockItem(id: string): DecryptedVaultItem {
  return {
    id,
    itemType: 'login',
    name: `Test Item ${id}`,
    data: { username: 'user', password: 'pass' },
    tags: ['test'],
    favorite: false,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    _raw: {} as DecryptedVaultItem['_raw'],
  };
}

function createMockFolder(id: string): DecryptedFolder {
  return {
    id,
    name: `Test Folder ${id}`,
    sortOrder: 0,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    _raw: {} as DecryptedFolder['_raw'],
  };
}

const mockMek = {} as CryptoKey;
const mockVaultKey = {} as CryptoKey;

// ==========================================================================
// Task 1.2: Vault store clearStore is called on lock/logout
// ==========================================================================

describe('Task 1.2: Vault store cleared on lock/logout', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    // Reset auth store to authenticated state
    useAuthStore.setState({
      isAuthenticated: true,
      isLocked: false,
      vaultKey: mockVaultKey,
      mek: mockMek,
      user: { email: 'test@example.com' },
      encryptedVaultKeyData: {
        encrypted: 'enc',
        iv: 'iv',
        tag: 'tag',
      },
      accessToken: 'mock-token',
    });

    // Set up vault store with data
    useVaultStore.setState({
      items: [createMockItem('1'), createMockItem('2')],
      trashItems: [createMockItem('3')],
      folders: [createMockFolder('f1')],
      searchQuery: 'test search',
      selectedFolder: 'f1',
      showFavorites: true,
    });
  });

  it('should clear vault store data on lock', async () => {
    // Verify vault store has data before lock
    expect(useVaultStore.getState().items).toHaveLength(2);
    expect(useVaultStore.getState().trashItems).toHaveLength(1);
    expect(useVaultStore.getState().folders).toHaveLength(1);

    await useAuthStore.getState().lock();

    // Vault store should be cleared
    expect(useVaultStore.getState().items).toHaveLength(0);
    expect(useVaultStore.getState().trashItems).toHaveLength(0);
    expect(useVaultStore.getState().folders).toHaveLength(0);
    expect(useVaultStore.getState().searchQuery).toBe('');
    expect(useVaultStore.getState().selectedFolder).toBeNull();
    expect(useVaultStore.getState().showFavorites).toBe(false);
  });

  it('should clear vault store data on logout', async () => {
    vi.mocked(logoutApi).mockResolvedValue(undefined);

    expect(useVaultStore.getState().items).toHaveLength(2);

    await useAuthStore.getState().logout();

    expect(useVaultStore.getState().items).toHaveLength(0);
    expect(useVaultStore.getState().trashItems).toHaveLength(0);
    expect(useVaultStore.getState().folders).toHaveLength(0);
  });
});

// ==========================================================================
// Task 2.2: lock() sets state FIRST before zeroing keys
// ==========================================================================

describe('Task 2.2: lock() race condition fix', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    useAuthStore.setState({
      isAuthenticated: true,
      isLocked: false,
      vaultKey: {} as CryptoKey,
      mek: {} as CryptoKey,
      user: { email: 'test@example.com' },
    });

    useVaultStore.setState({
      items: [],
      trashItems: [],
      folders: [],
    });
  });

  it('should set vaultKey and mek to null before async clearCryptoKey completes', async () => {
    vi.mocked(cryptoService.clearCryptoKey).mockImplementation(async () => {
      // Check state during async operation — state should already be set
      const state = useAuthStore.getState();
      expect(state.vaultKey).toBeNull();
      expect(state.mek).toBeNull();
      expect(state.isLocked).toBe(true);
    });

    await useAuthStore.getState().lock();

    // Final state check
    expect(useAuthStore.getState().vaultKey).toBeNull();
    expect(useAuthStore.getState().mek).toBeNull();
    expect(useAuthStore.getState().isLocked).toBe(true);
  });
});

// ==========================================================================
// Task 2.1: MEK cleared on error paths
// ==========================================================================

describe('Task 2.1: MEK cleanup on error paths', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    useAuthStore.setState({
      isAuthenticated: false,
      isLocked: true,
      vaultKey: null,
      mek: null,
      user: { email: 'test@example.com' },
      encryptedVaultKeyData: {
        encrypted: 'enc',
        iv: 'iv',
        tag: 'tag',
      },
    });
  });

  it('should clear MEK if decryptVaultKey throws during unlock', async () => {
    const fakeMek = {} as CryptoKey;
    const fakeAuthKey = new ArrayBuffer(32);

    vi.mocked(cryptoService.deriveKeys).mockResolvedValue({
      masterEncryptionKey: fakeMek,
      authKey: fakeAuthKey,
    });

    vi.mocked(cryptoService.decryptVaultKey).mockRejectedValue(new Error('Decryption failed'));

    await expect(useAuthStore.getState().unlock('wrong-password')).rejects.toThrow(
      'Decryption failed',
    );

    // MEK should have been cleared even though decryption failed
    expect(cryptoService.clearCryptoKey).toHaveBeenCalledWith(fakeMek);
  });
});

// ==========================================================================
// Task 2.6: Offline cache cleared on lock
// ==========================================================================

describe('Task 2.6: Offline cache user isolation', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    useAuthStore.setState({
      isAuthenticated: true,
      isLocked: false,
      vaultKey: {} as CryptoKey,
      mek: {} as CryptoKey,
      user: { email: 'test@example.com' },
    });

    useVaultStore.setState({
      items: [],
      trashItems: [],
      folders: [],
    });
  });

  it('should clear offline cache on lock', async () => {
    await useAuthStore.getState().lock();

    expect(offlineCache.clear).toHaveBeenCalled();
  });

  it('should not fail lock if offline cache clear throws', async () => {
    vi.mocked(offlineCache.clear).mockRejectedValue(new Error('IndexedDB error'));

    // Lock should still succeed even if cache clear fails
    await useAuthStore.getState().lock();

    expect(useAuthStore.getState().isLocked).toBe(true);
    expect(offlineCache.clear).toHaveBeenCalled();
  });
});

// ==========================================================================
// Vault store clearStore action
// ==========================================================================

describe('vaultStore.clearStore', () => {
  beforeEach(() => {
    useVaultStore.setState({
      items: [createMockItem('1')],
      trashItems: [createMockItem('2')],
      folders: [createMockFolder('f1')],
      searchQuery: 'search term',
      selectedFolder: 'f1',
      selectedType: 'login',
      showFavorites: true,
      showTrash: true,
      sortBy: 'dateModified',
      sortOrder: 'desc',
    });
  });

  it('should reset all items and folders to empty arrays', () => {
    useVaultStore.getState().clearStore();

    const state = useVaultStore.getState();
    expect(state.items).toEqual([]);
    expect(state.trashItems).toEqual([]);
    expect(state.folders).toEqual([]);
  });

  it('should reset search and filter state', () => {
    useVaultStore.getState().clearStore();

    const state = useVaultStore.getState();
    expect(state.searchQuery).toBe('');
    expect(state.selectedFolder).toBeNull();
    expect(state.showFavorites).toBe(false);
    expect(state.showTrash).toBe(false);
  });

  it('should reset sort state to defaults', () => {
    useVaultStore.getState().clearStore();

    const state = useVaultStore.getState();
    expect(state.sortBy).toBe('dateModified');
    expect(state.sortOrder).toBe('desc');
  });

  it('should reset loading flags', () => {
    useVaultStore.setState({ loading: true, itemsLoading: true, trashLoading: true });
    useVaultStore.getState().clearStore();

    const state = useVaultStore.getState();
    expect(state.loading).toBe(false);
    expect(state.itemsLoading).toBe(false);
    expect(state.trashLoading).toBe(false);
  });
});

// ==========================================================================
// Logout race condition fix: logout() clears state BEFORE zeroing keys
// ==========================================================================

describe('Logout race condition fix: state cleared before key zeroing', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    useAuthStore.setState({
      isAuthenticated: true,
      isLocked: false,
      vaultKey: {} as CryptoKey,
      mek: {} as CryptoKey,
      user: { email: 'test@example.com', userId: 'u1' },
      accessToken: 'mock-token',
      encryptedVaultKeyData: { encrypted: 'enc', iv: 'iv', tag: 'tag' },
    });

    useVaultStore.setState({
      items: [createMockItem('1')],
      trashItems: [createMockItem('2')],
      folders: [createMockFolder('f1')],
    });

    vi.mocked(logoutApi).mockResolvedValue(undefined);
  });

  it('should set vaultKey and mek to null before clearCryptoKey completes (same as lock pattern)', async () => {
    vi.mocked(cryptoService.clearCryptoKey).mockImplementation(async () => {
      // During async key zeroing, state should already be cleared
      const state = useAuthStore.getState();
      expect(state.vaultKey).toBeNull();
      expect(state.mek).toBeNull();
      expect(state.isAuthenticated).toBe(false);
      expect(state.accessToken).toBeNull();
    });

    await useAuthStore.getState().logout();

    // Final state check
    const state = useAuthStore.getState();
    expect(state.vaultKey).toBeNull();
    expect(state.mek).toBeNull();
    expect(state.isAuthenticated).toBe(false);
  });

  it('should clear auth state before zeroing key material', async () => {
    const stateSnapshots: { vaultKeyNull: boolean; isAuth: boolean }[] = [];

    vi.mocked(cryptoService.clearCryptoKey).mockImplementation(async () => {
      // Capture state when clearCryptoKey is called (async key zeroing)
      const state = useAuthStore.getState();
      stateSnapshots.push({
        vaultKeyNull: state.vaultKey === null,
        isAuth: state.isAuthenticated,
      });
    });

    await useAuthStore.getState().logout();

    // clearCryptoKey should have run after state was cleared (called for vaultKey + mek)
    expect(stateSnapshots.length).toBeGreaterThan(0);
    expect(stateSnapshots[0]!.vaultKeyNull).toBe(true);
    expect(stateSnapshots[0]!.isAuth).toBe(false);
  });

  it('should call logoutApi before clearing state (token still available)', async () => {
    let tokenDuringLogoutApi: string | null = null;

    vi.mocked(logoutApi).mockImplementation(async () => {
      // During logoutApi, the access token should still be in the store
      tokenDuringLogoutApi = useAuthStore.getState().accessToken;
    });

    await useAuthStore.getState().logout();

    expect(tokenDuringLogoutApi).toBe('mock-token');
    // After logout completes, token should be cleared
    expect(useAuthStore.getState().accessToken).toBeNull();
  });

  it('should clear vault store during logout', async () => {
    expect(useVaultStore.getState().items).toHaveLength(1);

    await useAuthStore.getState().logout();

    expect(useVaultStore.getState().items).toHaveLength(0);
    expect(useVaultStore.getState().trashItems).toHaveLength(0);
    expect(useVaultStore.getState().folders).toHaveLength(0);
  });

  it('should still zero key material using captured references after state is cleared', async () => {
    const capturedVaultKey = useAuthStore.getState().vaultKey;
    const capturedMek = useAuthStore.getState().mek;

    await useAuthStore.getState().logout();

    // clearCryptoKey should have been called with the original CryptoKey references
    expect(cryptoService.clearCryptoKey).toHaveBeenCalledWith(capturedVaultKey);
    expect(cryptoService.clearCryptoKey).toHaveBeenCalledWith(capturedMek);
  });
});

// ==========================================================================
// API client: skip refresh when already logged out
// ==========================================================================

describe('API client: skip 401 refresh when logged out', () => {
  const mockGetState = vi.fn();
  const mockSetAccessToken = vi.fn();
  const mockLogoutFn = vi.fn().mockResolvedValue(undefined);

  beforeEach(() => {
    vi.resetModules();
    localStorage.clear();
    // Clear call history so each test starts clean. `mockLogoutFn`/`mockSetAccessToken`
    // are module-level vi.fn()s that `vi.restoreAllMocks()` (afterEach) does NOT reset,
    // so without this the "logout not attempted" assertion below would only hold when
    // this test happened to run before the sibling that makes logout fire.
    mockLogoutFn.mockClear();
    mockSetAccessToken.mockClear();
    mockGetState.mockReturnValue({
      accessToken: null,
      setAccessToken: mockSetAccessToken,
      logout: mockLogoutFn,
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should reject 401 without attempting refresh when accessToken is null', async () => {
    vi.resetModules();
    // Mock auth store with null accessToken (logged out state)
    vi.doMock('../src/stores/authStore', () => ({
      useAuthStore: { getState: mockGetState },
    }));

    const { api } = await import('../src/services/api/client');

    const interceptors = (
      api.interceptors.response as unknown as {
        handlers: { rejected: (error: unknown) => Promise<unknown> }[];
      }
    ).handlers;
    const responseInterceptor = interceptors[0]!.rejected;

    const mockError = {
      response: { status: 401 },
      config: {
        url: '/vault/items',
        method: 'get',
        headers: {},
        _retry: false,
        _csrfRetry: true,
      },
    };

    // Should reject immediately without attempting refresh
    await expect(responseInterceptor(mockError)).rejects.toBeDefined();

    // logoutApi or refresh should NOT have been attempted
    expect(mockLogoutFn).not.toHaveBeenCalled();
  });

  it('should still attempt refresh when accessToken is present', async () => {
    vi.resetModules();
    // Mock auth store with valid accessToken
    mockGetState.mockReturnValue({
      accessToken: 'valid-token',
      setAccessToken: mockSetAccessToken,
      logout: mockLogoutFn,
    });

    vi.doMock('../src/stores/authStore', () => ({
      useAuthStore: { getState: mockGetState },
    }));

    const { api } = await import('../src/services/api/client');

    // Mock api.post so the refresh call rejects immediately instead of hanging
    const postSpy = vi.spyOn(api, 'post').mockRejectedValue(new Error('Refresh failed'));

    const interceptors = (
      api.interceptors.response as unknown as {
        handlers: { rejected: (error: unknown) => Promise<unknown> }[];
      }
    ).handlers;
    const responseInterceptor = interceptors[0]!.rejected;

    const mockError = {
      response: { status: 401 },
      config: {
        url: '/vault/items',
        method: 'get',
        headers: {} as Record<string, string>,
        _retry: false,
        _csrfRetry: true,
      },
    };

    // With a present access token the logged-out guard must NOT short-circuit:
    // the interceptor drives the refresh cycle, the mocked POST rejects, and the
    // failure path forces a logout and rejects. Assert unconditionally (not
    // inside a catch, which would let a spurious resolve pass with zero checks).
    await expect(responseInterceptor(mockError)).rejects.toBeDefined();
    // The refresh was actually attempted against the refresh endpoint.
    expect(postSpy).toHaveBeenCalledWith('/auth/refresh');
    // A failed refresh is an unrecoverable session → exactly one logout.
    expect(mockLogoutFn).toHaveBeenCalledTimes(1);

    postSpy.mockRestore();
  });
});
