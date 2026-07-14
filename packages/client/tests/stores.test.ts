/**
 * Comprehensive tests for Zustand stores: uiStore, authStore, vaultStore.
 *
 * Each store is tested in its own describe block with proper state reset
 * between tests to avoid pollution.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ---------------------------------------------------------------------------
// Polyfill matchMedia -- jsdom does not implement it but the uiStore module
// references it at the top level when first imported.
// vi.hoisted runs before vi.mock hoisting, ensuring matchMedia exists
// before any module code executes.
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
// Mocks -- must be declared before importing the stores
// ---------------------------------------------------------------------------

// Mock encryptedStorage used by authStore's persist middleware
vi.mock('../src/stores/encryptedStorage', () => ({
  encryptedStorage: {
    getItem: vi.fn().mockResolvedValue(null),
    setItem: vi.fn().mockResolvedValue(undefined),
    removeItem: vi.fn(),
  },
}));

// Mock cryptoService used by authStore and vaultStore
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

// Mock authApi used by authStore
vi.mock('../src/services/api/authApi', () => ({
  registerApi: vi.fn(),
  loginApi: vi.fn(),
  login2faApi: vi.fn(),
  logoutApi: vi.fn(),
  lockApi: vi.fn().mockResolvedValue({ data: { success: true } }),
}));

// Mock vaultApi used by vaultStore
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

// Mock offlineCache used by vaultStore
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

// Mock @hvault/shared constants
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
// Imports (after mocks are declared)
// ---------------------------------------------------------------------------

import { useUIStore } from '../src/stores/uiStore';
import { useAuthStore } from '../src/stores/authStore';
import { useVaultStore } from '../src/stores/vaultStore';
import { logoutApi } from '../src/services/api/authApi';
import { cryptoService } from '../src/services/crypto/cryptoService';
import {
  listItemsApi,
  deleteItemApi,
  permanentDeleteApi,
  emptyTrashApi,
  deleteFolderApi,
  listTrashApi,
} from '../src/services/api/vaultApi';

import type { DecryptedVaultItem, DecryptedFolder } from '../src/stores/vaultStore';

// ==========================================================================
// uiStore
// ==========================================================================

describe('uiStore', () => {
  // Initial state snapshot (without action functions)
  const uiInitialState = {
    theme: 'system' as const,
    sidebarOpen: true,
    commandPaletteOpen: false,
    offlineCacheAvailable: true,
  };

  beforeEach(() => {
    // Reset store to initial values before each test
    useUIStore.setState({
      ...uiInitialState,
    });

    // Clean up document element classes and attributes
    document.documentElement.classList.remove('dark');
    document.documentElement.removeAttribute('data-theme');
  });

  // -----------------------------------------------------------------------
  // Initial state
  // -----------------------------------------------------------------------

  it('should have correct initial state', () => {
    // Assert the store's DECLARED defaults (the initializer snapshot), not the
    // values `beforeEach` seeded via setState — otherwise a changed production
    // default (e.g. sidebarOpen -> false) would slip through because the seed
    // hard-codes the old value. getInitialState() returns the create-time state,
    // unaffected by setState or persist rehydration.
    const initial = useUIStore.getInitialState();
    expect(initial.theme).toBe('system');
    expect(initial.sidebarOpen).toBe(true);
    expect(initial.sidebarCollapsed).toBe(false);
    expect(initial.commandPaletteOpen).toBe(false);
    expect(initial.offlineCacheAvailable).toBe(true);
  });

  // -----------------------------------------------------------------------
  // setTheme
  // -----------------------------------------------------------------------

  describe('setTheme', () => {
    it('should set theme to "dark" and add "dark" class to document element', () => {
      useUIStore.getState().setTheme('dark');

      const state = useUIStore.getState();
      expect(state.theme).toBe('dark');
      expect(document.documentElement.classList.contains('dark')).toBe(true);
      expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
    });

    it('should set theme to "light" and remove "dark" class from document element', () => {
      // First set dark to add the class
      document.documentElement.classList.add('dark');

      useUIStore.getState().setTheme('light');

      const state = useUIStore.getState();
      expect(state.theme).toBe('light');
      expect(document.documentElement.classList.contains('dark')).toBe(false);
      expect(document.documentElement.getAttribute('data-theme')).toBe('light');
    });

    it('should set theme to "system" and resolve based on matchMedia (prefers dark)', () => {
      // Mock matchMedia to prefer dark
      const matchMediaMock = vi.fn().mockImplementation((query: string) => ({
        matches: query === '(prefers-color-scheme: dark)',
        media: query,
        onchange: null,
        addListener: vi.fn(),
        removeListener: vi.fn(),
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        dispatchEvent: vi.fn(),
      }));
      window.matchMedia = matchMediaMock;

      useUIStore.getState().setTheme('system');

      const state = useUIStore.getState();
      expect(state.theme).toBe('system');
      expect(document.documentElement.classList.contains('dark')).toBe(true);
      expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
    });

    it('should set theme to "system" and resolve to light when OS preference is light', () => {
      // Mock matchMedia to prefer light
      const matchMediaMock = vi.fn().mockImplementation((query: string) => ({
        matches: false, // not dark
        media: query,
        onchange: null,
        addListener: vi.fn(),
        removeListener: vi.fn(),
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        dispatchEvent: vi.fn(),
      }));
      window.matchMedia = matchMediaMock;

      useUIStore.getState().setTheme('system');

      const state = useUIStore.getState();
      expect(state.theme).toBe('system');
      expect(document.documentElement.classList.contains('dark')).toBe(false);
      expect(document.documentElement.getAttribute('data-theme')).toBe('light');
    });

    it('should switch from dark to light correctly', () => {
      useUIStore.getState().setTheme('dark');
      expect(document.documentElement.classList.contains('dark')).toBe(true);
      expect(document.documentElement.getAttribute('data-theme')).toBe('dark');

      useUIStore.getState().setTheme('light');
      expect(document.documentElement.classList.contains('dark')).toBe(false);
      expect(document.documentElement.getAttribute('data-theme')).toBe('light');
    });
  });

  // -----------------------------------------------------------------------
  // toggleSidebar
  // -----------------------------------------------------------------------

  describe('toggleSidebar', () => {
    it('should flip sidebarOpen from true to false', () => {
      expect(useUIStore.getState().sidebarOpen).toBe(true);

      useUIStore.getState().toggleSidebar();

      expect(useUIStore.getState().sidebarOpen).toBe(false);
    });

    it('should flip sidebarOpen from false to true', () => {
      useUIStore.setState({ sidebarOpen: false });

      useUIStore.getState().toggleSidebar();

      expect(useUIStore.getState().sidebarOpen).toBe(true);
    });

    it('should toggle twice and return to original value', () => {
      expect(useUIStore.getState().sidebarOpen).toBe(true);

      useUIStore.getState().toggleSidebar();
      useUIStore.getState().toggleSidebar();

      expect(useUIStore.getState().sidebarOpen).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // toggleCommandPalette
  // -----------------------------------------------------------------------

  describe('toggleCommandPalette', () => {
    it('should flip commandPaletteOpen from false to true', () => {
      expect(useUIStore.getState().commandPaletteOpen).toBe(false);

      useUIStore.getState().toggleCommandPalette();

      expect(useUIStore.getState().commandPaletteOpen).toBe(true);
    });

    it('should flip commandPaletteOpen from true to false', () => {
      useUIStore.setState({ commandPaletteOpen: true });

      useUIStore.getState().toggleCommandPalette();

      expect(useUIStore.getState().commandPaletteOpen).toBe(false);
    });

    it('should toggle twice and return to original value', () => {
      expect(useUIStore.getState().commandPaletteOpen).toBe(false);

      useUIStore.getState().toggleCommandPalette();
      useUIStore.getState().toggleCommandPalette();

      expect(useUIStore.getState().commandPaletteOpen).toBe(false);
    });
  });

  // -----------------------------------------------------------------------
  // toggleSidebarCollapsed
  // -----------------------------------------------------------------------

  describe('toggleSidebarCollapsed', () => {
    it('should flip sidebarCollapsed from false to true', () => {
      useUIStore.setState({ sidebarCollapsed: false });
      expect(useUIStore.getState().sidebarCollapsed).toBe(false);

      useUIStore.getState().toggleSidebarCollapsed();

      expect(useUIStore.getState().sidebarCollapsed).toBe(true);
    });

    it('should flip sidebarCollapsed from true to false', () => {
      useUIStore.setState({ sidebarCollapsed: true });

      useUIStore.getState().toggleSidebarCollapsed();

      expect(useUIStore.getState().sidebarCollapsed).toBe(false);
    });

    it('should toggle twice and return to original value', () => {
      useUIStore.setState({ sidebarCollapsed: false });
      expect(useUIStore.getState().sidebarCollapsed).toBe(false);

      useUIStore.getState().toggleSidebarCollapsed();
      useUIStore.getState().toggleSidebarCollapsed();

      expect(useUIStore.getState().sidebarCollapsed).toBe(false);
    });

    it('should have sidebarCollapsed default to false', () => {
      // Assert the DECLARED default from the initializer, not a value the test
      // itself just wrote — flipping the production default to `true` (shipping
      // every user a collapsed sidebar) must turn this red.
      expect(useUIStore.getInitialState().sidebarCollapsed).toBe(false);
    });
  });

  // -----------------------------------------------------------------------
  // sidebarCollapsed persistence
  // -----------------------------------------------------------------------

  describe('sidebarCollapsed persistence', () => {
    it('should be included in the partialize config (persisted to localStorage)', () => {
      // Persistence is the actual contract here, so read the bytes the persist
      // middleware wrote. Removing sidebarCollapsed from `partialize` (so the
      // collapsed state no longer survives a reload) must turn this red — the
      // previous version only re-ran the toggle and never touched localStorage.
      useUIStore.setState({ sidebarCollapsed: true });

      const raw = localStorage.getItem('hvault-ui');
      expect(raw).not.toBeNull();
      const persisted = JSON.parse(raw!) as { state: { sidebarCollapsed?: boolean } };
      expect(persisted.state.sidebarCollapsed).toBe(true);

      // And it flips back to false when persisted again.
      useUIStore.setState({ sidebarCollapsed: false });
      const persistedAfter = JSON.parse(localStorage.getItem('hvault-ui')!) as {
        state: { sidebarCollapsed?: boolean };
      };
      expect(persistedAfter.state.sidebarCollapsed).toBe(false);
    });
  });

  // -----------------------------------------------------------------------
  // setOfflineCacheAvailable
  // -----------------------------------------------------------------------

  describe('setOfflineCacheAvailable', () => {
    it('should set offlineCacheAvailable to false', () => {
      expect(useUIStore.getState().offlineCacheAvailable).toBe(true);

      useUIStore.getState().setOfflineCacheAvailable(false);

      expect(useUIStore.getState().offlineCacheAvailable).toBe(false);
    });

    it('should set offlineCacheAvailable back to true', () => {
      useUIStore.setState({ offlineCacheAvailable: false });

      useUIStore.getState().setOfflineCacheAvailable(true);

      expect(useUIStore.getState().offlineCacheAvailable).toBe(true);
    });
  });
});

// ==========================================================================
// authStore
// ==========================================================================

describe('authStore', () => {
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
  };

  beforeEach(() => {
    vi.clearAllMocks();
    useAuthStore.setState({ ...authInitialState });
  });

  // -----------------------------------------------------------------------
  // Initial state
  // -----------------------------------------------------------------------

  it('should have correct initial state', () => {
    // Assert the initializer's DECLARED defaults, not the values `beforeEach`
    // seeded via setState. kdfIterations reads through to the store's own
    // KDF_ITERATIONS default, so lowering that constant turns this red.
    const initial = useAuthStore.getInitialState();
    expect(initial.accessToken).toBeNull();
    expect(initial.user).toBeNull();
    expect(initial.isAuthenticated).toBe(false);
    expect(initial.isLocked).toBe(false);
    expect(initial.vaultKey).toBeNull();
    expect(initial.mek).toBeNull();
    expect(initial.encryptedVaultKeyData).toBeNull();
    expect(initial.kdfIterations).toBe(600_000);
    expect(initial.twoFactorRequired).toBe(false);
    expect(initial.tempToken).toBeNull();
  });

  // -----------------------------------------------------------------------
  // setAccessToken
  // -----------------------------------------------------------------------

  describe('setAccessToken', () => {
    it('should update accessToken with a string value', () => {
      useAuthStore.getState().setAccessToken('new-token-abc');

      expect(useAuthStore.getState().accessToken).toBe('new-token-abc');
    });

    it('should set accessToken to null', () => {
      useAuthStore.setState({ accessToken: 'existing-token' });

      useAuthStore.getState().setAccessToken(null);

      expect(useAuthStore.getState().accessToken).toBeNull();
    });

    it('should not affect other state fields', () => {
      useAuthStore.setState({
        user: { userId: 'u1', email: 'test@example.com' },
        isAuthenticated: true,
      });

      useAuthStore.getState().setAccessToken('token-xyz');

      const state = useAuthStore.getState();
      expect(state.accessToken).toBe('token-xyz');
      expect(state.user).toEqual({ userId: 'u1', email: 'test@example.com' });
      expect(state.isAuthenticated).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // lock
  // -----------------------------------------------------------------------

  describe('lock', () => {
    it('should clear vaultKey and mek and set isLocked to true', async () => {
      const fakeVaultKey = {} as CryptoKey;
      useAuthStore.setState({
        vaultKey: fakeVaultKey,
        mek: {} as CryptoKey,
        isLocked: false,
        isAuthenticated: true,
        user: { userId: 'u1', email: 'test@example.com' },
      });

      await useAuthStore.getState().lock();

      const state = useAuthStore.getState();
      expect(state.vaultKey).toBeNull();
      expect(state.mek).toBeNull();
      expect(state.isLocked).toBe(true);
    });

    it('should call cryptoService.clearCryptoKey when vaultKey exists', async () => {
      const fakeVaultKey = {} as CryptoKey;
      useAuthStore.setState({ vaultKey: fakeVaultKey });

      await useAuthStore.getState().lock();

      expect(cryptoService.clearCryptoKey).toHaveBeenCalledWith(fakeVaultKey);
    });

    it('should call cryptoService.clearCryptoKey when mek exists', async () => {
      const fakeMek = {} as CryptoKey;
      useAuthStore.setState({ mek: fakeMek });

      await useAuthStore.getState().lock();

      expect(cryptoService.clearCryptoKey).toHaveBeenCalledWith(fakeMek);
    });

    it('should not call cryptoService.clearCryptoKey for vaultKey when vaultKey is null', async () => {
      useAuthStore.setState({ vaultKey: null, mek: null });

      await useAuthStore.getState().lock();

      expect(cryptoService.clearCryptoKey).not.toHaveBeenCalled();
    });

    it('should preserve user and isAuthenticated when locking', async () => {
      useAuthStore.setState({
        user: { userId: 'u1', email: 'test@example.com' },
        isAuthenticated: true,
        vaultKey: new ArrayBuffer(32),
        mek: {} as CryptoKey,
      });

      await useAuthStore.getState().lock();

      const state = useAuthStore.getState();
      expect(state.user).toEqual({ userId: 'u1', email: 'test@example.com' });
      expect(state.isAuthenticated).toBe(true);
      expect(state.isLocked).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // logout
  // -----------------------------------------------------------------------

  describe('logout', () => {
    it('should clear all state to defaults', async () => {
      // Set up a fully authenticated state
      useAuthStore.setState({
        accessToken: 'some-token',
        user: { userId: 'u1', email: 'test@example.com' },
        isAuthenticated: true,
        isLocked: false,
        vaultKey: {} as CryptoKey,
        mek: {} as CryptoKey,
        encryptedVaultKeyData: {
          encrypted: 'enc',
          iv: 'iv',
          tag: 'tag',
        },
        kdfIterations: 700_000,
        twoFactorRequired: true,
        tempToken: 'temp-123',
      });

      vi.mocked(logoutApi).mockResolvedValue({
        data: { success: true, data: null },
      } as unknown as Awaited<ReturnType<typeof logoutApi>>);

      await useAuthStore.getState().logout();

      const state = useAuthStore.getState();
      expect(state.accessToken).toBeNull();
      expect(state.user).toBeNull();
      expect(state.isAuthenticated).toBe(false);
      expect(state.isLocked).toBe(false);
      expect(state.vaultKey).toBeNull();
      expect(state.mek).toBeNull();
      expect(state.encryptedVaultKeyData).toBeNull();
      expect(state.kdfIterations).toBe(600_000);
      expect(state.twoFactorRequired).toBe(false);
      expect(state.tempToken).toBeNull();
    });

    it('should call logoutApi when accessToken exists', async () => {
      useAuthStore.setState({ accessToken: 'valid-token' });
      vi.mocked(logoutApi).mockResolvedValue({
        data: { success: true, data: null },
      } as unknown as Awaited<ReturnType<typeof logoutApi>>);

      await useAuthStore.getState().logout();

      expect(logoutApi).toHaveBeenCalled();
    });

    it('should not call logoutApi when accessToken is null', async () => {
      useAuthStore.setState({ accessToken: null });

      await useAuthStore.getState().logout();

      expect(logoutApi).not.toHaveBeenCalled();
    });

    it('should call cryptoService.clearCryptoKey when vaultKey exists', async () => {
      const fakeVaultKey = {} as CryptoKey;
      useAuthStore.setState({
        vaultKey: fakeVaultKey,
        accessToken: null,
      });

      await useAuthStore.getState().logout();

      expect(cryptoService.clearCryptoKey).toHaveBeenCalledWith(fakeVaultKey);
    });

    it('should call cryptoService.clearCryptoKey when mek exists', async () => {
      const fakeMek = {} as CryptoKey;
      useAuthStore.setState({
        mek: fakeMek,
        accessToken: null,
      });

      await useAuthStore.getState().logout();

      expect(cryptoService.clearCryptoKey).toHaveBeenCalledWith(fakeMek);
    });

    it('should still clear state even if logoutApi throws', async () => {
      useAuthStore.setState({
        accessToken: 'some-token',
        user: { userId: 'u1', email: 'test@example.com' },
        isAuthenticated: true,
      });
      vi.mocked(logoutApi).mockRejectedValue(new Error('Network error'));

      await useAuthStore.getState().logout();

      const state = useAuthStore.getState();
      expect(state.accessToken).toBeNull();
      expect(state.user).toBeNull();
      expect(state.isAuthenticated).toBe(false);
    });

    it('should call logoutApi before clearing state (so the access token is available)', async () => {
      let stateWhenApiCalled: Record<string, unknown> | null = null;
      vi.mocked(logoutApi).mockImplementation(async () => {
        stateWhenApiCalled = { ...useAuthStore.getState() };
        return { data: { success: true, data: null } } as unknown as Awaited<
          ReturnType<typeof logoutApi>
        >;
      });

      useAuthStore.setState({
        accessToken: 'some-token',
        user: { userId: 'u1', email: 'test@example.com' },
        isAuthenticated: true,
      });

      await useAuthStore.getState().logout();

      // State should still have the token when logoutApi was called
      // so the Axios interceptor can attach the Bearer header
      expect(stateWhenApiCalled.accessToken).toBe('some-token');
      expect(stateWhenApiCalled.isAuthenticated).toBe(true);

      // After logout completes, state should be fully cleared
      const finalState = useAuthStore.getState();
      expect(finalState.accessToken).toBeNull();
      expect(finalState.user).toBeNull();
      expect(finalState.isAuthenticated).toBe(false);
    });
  });
});

// ==========================================================================
// vaultStore
// ==========================================================================

describe('vaultStore', () => {
  const vaultInitialState = {
    items: [] as DecryptedVaultItem[],
    trashItems: [] as DecryptedVaultItem[],
    folders: [] as DecryptedFolder[],
    loading: false,
    itemsLoading: false,
    trashLoading: false,
    searchQuery: '',
    selectedFolder: null,
    selectedType: null,
    showFavorites: false,
    showTrash: false,
    sortBy: 'dateModified' as const,
    sortOrder: 'desc' as const,
  };

  /** Factory for creating a minimal DecryptedVaultItem for testing */
  function makeMockItem(overrides: Partial<DecryptedVaultItem> = {}): DecryptedVaultItem {
    return {
      id: 'item-1',
      itemType: 'password',
      tags: [],
      favorite: false,
      name: 'Test Item',
      data: {},
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      _raw: {} as DecryptedVaultItem['_raw'],
      ...overrides,
    };
  }

  beforeEach(() => {
    vi.clearAllMocks();
    useVaultStore.setState({ ...vaultInitialState });
  });

  // -----------------------------------------------------------------------
  // Initial state
  // -----------------------------------------------------------------------

  it('should have correct initial state', () => {
    // Assert the initializer's DECLARED defaults, not the seed `beforeEach`
    // wrote via setState — a changed production default must turn this red.
    const initial = useVaultStore.getInitialState();
    expect(initial.items).toEqual([]);
    expect(initial.trashItems).toEqual([]);
    expect(initial.folders).toEqual([]);
    expect(initial.loading).toBe(false);
    expect(initial.searchQuery).toBe('');
    expect(initial.selectedFolder).toBeNull();
    expect(initial.selectedType).toBeNull();
    expect(initial.showFavorites).toBe(false);
    expect(initial.showTrash).toBe(false);
    expect(initial.sortBy).toBe('dateModified');
    expect(initial.sortOrder).toBe('desc');
  });

  // -----------------------------------------------------------------------
  // setSearchQuery
  // -----------------------------------------------------------------------

  describe('setSearchQuery', () => {
    it('should update searchQuery', () => {
      useVaultStore.getState().setSearchQuery('github');

      expect(useVaultStore.getState().searchQuery).toBe('github');
    });

    it('should set searchQuery to empty string', () => {
      useVaultStore.setState({ searchQuery: 'existing' });

      useVaultStore.getState().setSearchQuery('');

      expect(useVaultStore.getState().searchQuery).toBe('');
    });
  });

  // -----------------------------------------------------------------------
  // setSelectedFolder
  // -----------------------------------------------------------------------

  describe('setSelectedFolder', () => {
    it('should set selectedFolder to a folder id', () => {
      useVaultStore.getState().setSelectedFolder('folder-123');

      expect(useVaultStore.getState().selectedFolder).toBe('folder-123');
    });

    it('should set selectedFolder to null', () => {
      useVaultStore.setState({ selectedFolder: 'folder-123' });

      useVaultStore.getState().setSelectedFolder(null);

      expect(useVaultStore.getState().selectedFolder).toBeNull();
    });
  });

  // -----------------------------------------------------------------------
  // setSelectedType
  // -----------------------------------------------------------------------

  describe('setSelectedType', () => {
    it('should set selectedType to a type value', () => {
      useVaultStore.getState().setSelectedType('password');

      expect(useVaultStore.getState().selectedType).toBe('password');
    });

    it('should set selectedType to null', () => {
      useVaultStore.setState({
        selectedType: 'password' as unknown as DecryptedVaultItem['itemType'],
      });

      useVaultStore.getState().setSelectedType(null);

      expect(useVaultStore.getState().selectedType).toBeNull();
    });

    it('should accept various item types', () => {
      useVaultStore.getState().setSelectedType('note');
      expect(useVaultStore.getState().selectedType).toBe('note');

      useVaultStore.getState().setSelectedType('card');
      expect(useVaultStore.getState().selectedType).toBe('card');
    });
  });

  // -----------------------------------------------------------------------
  // setShowFavorites / setShowTrash
  // -----------------------------------------------------------------------

  describe('setShowFavorites', () => {
    it('should set showFavorites to true', () => {
      useVaultStore.getState().setShowFavorites(true);

      expect(useVaultStore.getState().showFavorites).toBe(true);
    });

    it('should set showFavorites to false', () => {
      useVaultStore.setState({ showFavorites: true });

      useVaultStore.getState().setShowFavorites(false);

      expect(useVaultStore.getState().showFavorites).toBe(false);
    });
  });

  describe('setShowTrash', () => {
    it('should set showTrash to true', () => {
      useVaultStore.getState().setShowTrash(true);

      expect(useVaultStore.getState().showTrash).toBe(true);
    });

    it('should set showTrash to false', () => {
      useVaultStore.setState({ showTrash: true });

      useVaultStore.getState().setShowTrash(false);

      expect(useVaultStore.getState().showTrash).toBe(false);
    });
  });

  // -----------------------------------------------------------------------
  // toggleFavorites
  // -----------------------------------------------------------------------

  describe('toggleFavorites', () => {
    it('should set showFavorites to true and showTrash to false when toggling on', () => {
      useVaultStore.setState({ showFavorites: false, showTrash: true });

      useVaultStore.getState().toggleFavorites();

      const state = useVaultStore.getState();
      expect(state.showFavorites).toBe(true);
      expect(state.showTrash).toBe(false);
    });

    it('should set showFavorites to false when toggling off', () => {
      useVaultStore.setState({ showFavorites: true, showTrash: false });

      useVaultStore.getState().toggleFavorites();

      const state = useVaultStore.getState();
      expect(state.showFavorites).toBe(false);
      expect(state.showTrash).toBe(false);
    });

    it('should always reset showTrash to false when toggling favorites on', () => {
      useVaultStore.setState({ showFavorites: false, showTrash: true });

      useVaultStore.getState().toggleFavorites();

      expect(useVaultStore.getState().showTrash).toBe(false);
      expect(useVaultStore.getState().showFavorites).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // toggleTrash
  // -----------------------------------------------------------------------

  describe('toggleTrash', () => {
    it('should set showTrash to true and showFavorites to false when toggling on', () => {
      useVaultStore.setState({ showTrash: false, showFavorites: true });

      useVaultStore.getState().toggleTrash();

      const state = useVaultStore.getState();
      expect(state.showTrash).toBe(true);
      expect(state.showFavorites).toBe(false);
    });

    it('should set showTrash to false when toggling off', () => {
      useVaultStore.setState({ showTrash: true, showFavorites: false });

      useVaultStore.getState().toggleTrash();

      const state = useVaultStore.getState();
      expect(state.showTrash).toBe(false);
      expect(state.showFavorites).toBe(false);
    });

    it('should always reset showFavorites to false when toggling trash on', () => {
      useVaultStore.setState({ showTrash: false, showFavorites: true });

      useVaultStore.getState().toggleTrash();

      expect(useVaultStore.getState().showFavorites).toBe(false);
      expect(useVaultStore.getState().showTrash).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // setSortBy / setSortOrder
  // -----------------------------------------------------------------------

  describe('setSortBy', () => {
    it('should set sortBy to "name"', () => {
      useVaultStore.getState().setSortBy('name');

      expect(useVaultStore.getState().sortBy).toBe('name');
    });

    it('should set sortBy to "dateCreated"', () => {
      useVaultStore.getState().setSortBy('dateCreated');

      expect(useVaultStore.getState().sortBy).toBe('dateCreated');
    });

    it('should set sortBy to "dateModified"', () => {
      useVaultStore.getState().setSortBy('dateModified');

      expect(useVaultStore.getState().sortBy).toBe('dateModified');
    });

    it('should set sortBy to "type"', () => {
      useVaultStore.getState().setSortBy('type');

      expect(useVaultStore.getState().sortBy).toBe('type');
    });
  });

  describe('setSortOrder', () => {
    it('should set sortOrder to "asc"', () => {
      useVaultStore.setState({ sortOrder: 'desc' });

      useVaultStore.getState().setSortOrder('asc');

      expect(useVaultStore.getState().sortOrder).toBe('asc');
    });

    it('should set sortOrder to "desc"', () => {
      useVaultStore.getState().setSortOrder('desc');

      expect(useVaultStore.getState().sortOrder).toBe('desc');
    });
  });

  // -----------------------------------------------------------------------
  // deleteItem (async -- calls deleteItemApi, removes from items)
  // -----------------------------------------------------------------------

  describe('deleteItem', () => {
    it('should call deleteItemApi and remove item from state', async () => {
      const item1 = makeMockItem({ id: 'item-1', name: 'Item 1' });
      const item2 = makeMockItem({ id: 'item-2', name: 'Item 2' });
      const item3 = makeMockItem({ id: 'item-3', name: 'Item 3' });

      useVaultStore.setState({ items: [item1, item2, item3] });

      vi.mocked(deleteItemApi).mockResolvedValue({
        data: { success: true, data: null },
      } as unknown as Awaited<ReturnType<typeof deleteItemApi>>);

      await useVaultStore.getState().deleteItem('item-2');

      expect(deleteItemApi).toHaveBeenCalledWith('item-2');
      const remaining = useVaultStore.getState().items;
      expect(remaining).toHaveLength(2);
      expect(remaining.map((i) => i.id)).toEqual(['item-1', 'item-3']);
    });

    it('should not remove item if deleteItemApi throws', async () => {
      const item1 = makeMockItem({ id: 'item-1', name: 'Item 1' });
      useVaultStore.setState({ items: [item1] });

      vi.mocked(deleteItemApi).mockRejectedValue(new Error('Server error'));

      await expect(useVaultStore.getState().deleteItem('item-1')).rejects.toThrow('Server error');

      // Item should still be in state since the API call failed before set()
      expect(useVaultStore.getState().items).toHaveLength(1);
    });

    it('should handle deleting a non-existent item gracefully', async () => {
      const item1 = makeMockItem({ id: 'item-1' });
      useVaultStore.setState({ items: [item1] });

      vi.mocked(deleteItemApi).mockResolvedValue({
        data: { success: true, data: null },
      } as unknown as Awaited<ReturnType<typeof deleteItemApi>>);

      await useVaultStore.getState().deleteItem('non-existent');

      // The original item should still be there since filter won't match
      expect(useVaultStore.getState().items).toHaveLength(1);
      expect(useVaultStore.getState().items[0]!.id).toBe('item-1');
    });
  });

  // -----------------------------------------------------------------------
  // permanentDeleteItem (async -- calls permanentDeleteApi, removes from trashItems)
  // -----------------------------------------------------------------------

  describe('permanentDeleteItem', () => {
    it('should call permanentDeleteApi and remove item from trashItems', async () => {
      const trash1 = makeMockItem({ id: 'trash-1', name: 'Trash 1' });
      const trash2 = makeMockItem({ id: 'trash-2', name: 'Trash 2' });

      useVaultStore.setState({ trashItems: [trash1, trash2] });

      vi.mocked(permanentDeleteApi).mockResolvedValue({
        data: { success: true, data: null },
      } as unknown as Awaited<ReturnType<typeof permanentDeleteApi>>);

      await useVaultStore.getState().permanentDeleteItem('trash-1');

      expect(permanentDeleteApi).toHaveBeenCalledWith('trash-1');
      const remaining = useVaultStore.getState().trashItems;
      expect(remaining).toHaveLength(1);
      expect(remaining[0]!.id).toBe('trash-2');
    });

    it('should not remove item from trashItems if permanentDeleteApi throws', async () => {
      const trash1 = makeMockItem({ id: 'trash-1', name: 'Trash 1' });
      useVaultStore.setState({ trashItems: [trash1] });

      vi.mocked(permanentDeleteApi).mockRejectedValue(new Error('Server error'));

      await expect(useVaultStore.getState().permanentDeleteItem('trash-1')).rejects.toThrow(
        'Server error',
      );

      expect(useVaultStore.getState().trashItems).toHaveLength(1);
    });
  });

  // -----------------------------------------------------------------------
  // emptyTrash (async -- calls emptyTrashApi, clears trashItems)
  // -----------------------------------------------------------------------

  describe('emptyTrash', () => {
    it('should call emptyTrashApi and clear all trashItems', async () => {
      const trash1 = makeMockItem({ id: 'trash-1' });
      const trash2 = makeMockItem({ id: 'trash-2' });
      const trash3 = makeMockItem({ id: 'trash-3' });

      useVaultStore.setState({ trashItems: [trash1, trash2, trash3] });

      vi.mocked(emptyTrashApi).mockResolvedValue({
        data: { success: true, data: null },
      } as unknown as Awaited<ReturnType<typeof emptyTrashApi>>);

      await useVaultStore.getState().emptyTrash();

      expect(emptyTrashApi).toHaveBeenCalled();
      expect(useVaultStore.getState().trashItems).toEqual([]);
    });

    it('should not clear trashItems if emptyTrashApi throws', async () => {
      const trash1 = makeMockItem({ id: 'trash-1' });
      useVaultStore.setState({ trashItems: [trash1] });

      vi.mocked(emptyTrashApi).mockRejectedValue(new Error('Server error'));

      await expect(useVaultStore.getState().emptyTrash()).rejects.toThrow('Server error');

      expect(useVaultStore.getState().trashItems).toHaveLength(1);
    });

    it('should work when trashItems is already empty', async () => {
      useVaultStore.setState({ trashItems: [] });

      vi.mocked(emptyTrashApi).mockResolvedValue({
        data: { success: true, data: null },
      } as unknown as Awaited<ReturnType<typeof emptyTrashApi>>);

      await useVaultStore.getState().emptyTrash();

      expect(emptyTrashApi).toHaveBeenCalled();
      expect(useVaultStore.getState().trashItems).toEqual([]);
    });
  });

  // -----------------------------------------------------------------------
  // Interaction: toggleFavorites and toggleTrash are mutually exclusive
  // -----------------------------------------------------------------------

  describe('toggleFavorites and toggleTrash mutual exclusivity', () => {
    it('toggling favorites on then trash on should deactivate favorites', () => {
      useVaultStore.getState().toggleFavorites();
      expect(useVaultStore.getState().showFavorites).toBe(true);
      expect(useVaultStore.getState().showTrash).toBe(false);

      useVaultStore.getState().toggleTrash();
      expect(useVaultStore.getState().showTrash).toBe(true);
      expect(useVaultStore.getState().showFavorites).toBe(false);
    });

    it('toggling trash on then favorites on should deactivate trash', () => {
      useVaultStore.getState().toggleTrash();
      expect(useVaultStore.getState().showTrash).toBe(true);
      expect(useVaultStore.getState().showFavorites).toBe(false);

      useVaultStore.getState().toggleFavorites();
      expect(useVaultStore.getState().showFavorites).toBe(true);
      expect(useVaultStore.getState().showTrash).toBe(false);
    });
  });

  // -----------------------------------------------------------------------
  // Offline cache failure notification
  // -----------------------------------------------------------------------

  describe('offline cache failure notification', () => {
    it('should set offlineCacheAvailable to false when cacheItems fails', async () => {
      // Set up auth state with a vault key
      useAuthStore.setState({ vaultKey: {} as CryptoKey });

      // Mock API to return items successfully
      vi.mocked(listItemsApi).mockResolvedValue({
        data: {
          success: true,
          data: [],
          pagination: { page: 1, limit: 200, total: 0, totalPages: 0 },
        },
      } as unknown as Awaited<ReturnType<typeof listItemsApi>>);

      // Mock cache write to fail
      const { offlineCache: mockCache } = await import('../src/services/offlineCache');
      vi.mocked(mockCache.cacheItems).mockRejectedValue(new Error('QuotaExceededError'));

      // Ensure offlineCacheAvailable starts as true
      useUIStore.setState({ offlineCacheAvailable: true });

      await useVaultStore.getState().fetchItems();

      // Wait for the .catch() handler to execute (async)
      await new Promise((resolve) => setTimeout(resolve, 10));

      expect(useUIStore.getState().offlineCacheAvailable).toBe(false);
    });
  });

  // -----------------------------------------------------------------------
  // itemsLoading / trashLoading (Task 4.7)
  // -----------------------------------------------------------------------

  describe('itemsLoading and trashLoading flags', () => {
    it('should have itemsLoading and trashLoading initially set to false', () => {
      const state = useVaultStore.getState();
      expect(state.itemsLoading).toBe(false);
      expect(state.trashLoading).toBe(false);
      expect(state.loading).toBe(false);
    });

    it('should set itemsLoading to true when fetchItems starts', async () => {
      useAuthStore.setState({ vaultKey: {} as CryptoKey });

      // Create a deferred promise so we can inspect state mid-flight
      let resolveApi!: (value: unknown) => void;
      const apiPromise = new Promise((resolve) => {
        resolveApi = resolve;
      });
      vi.mocked(listItemsApi).mockReturnValue(
        apiPromise as unknown as ReturnType<typeof listItemsApi>,
      );

      const fetchPromise = useVaultStore.getState().fetchItems();

      // While API is in-flight, itemsLoading should be true
      expect(useVaultStore.getState().itemsLoading).toBe(true);
      expect(useVaultStore.getState().loading).toBe(true);

      // Resolve the API call
      resolveApi({
        data: {
          success: true,
          data: [],
          pagination: { page: 1, limit: 200, total: 0, totalPages: 0 },
        },
      });

      await fetchPromise;

      expect(useVaultStore.getState().itemsLoading).toBe(false);
    });

    it('should set trashLoading to true when fetchTrashItems starts', async () => {
      useAuthStore.setState({ vaultKey: {} as CryptoKey });

      let resolveApi!: (value: unknown) => void;
      const apiPromise = new Promise((resolve) => {
        resolveApi = resolve;
      });
      vi.mocked(listTrashApi).mockReturnValue(
        apiPromise as unknown as ReturnType<typeof listTrashApi>,
      );

      const fetchPromise = useVaultStore.getState().fetchTrashItems();

      // While API is in-flight, trashLoading should be true
      expect(useVaultStore.getState().trashLoading).toBe(true);
      expect(useVaultStore.getState().loading).toBe(true);

      resolveApi({
        data: {
          success: true,
          data: [],
          pagination: { page: 1, limit: 200, total: 0, totalPages: 0 },
        },
      });

      await fetchPromise;

      expect(useVaultStore.getState().trashLoading).toBe(false);
    });

    it('loading should remain true if trashLoading is still active when itemsLoading finishes', async () => {
      useAuthStore.setState({ vaultKey: {} as CryptoKey });

      // Start trash loading first with a deferred promise (won't resolve yet)
      let resolveTrashApi!: (value: unknown) => void;
      const trashApiPromise = new Promise((resolve) => {
        resolveTrashApi = resolve;
      });
      vi.mocked(listTrashApi).mockReturnValue(
        trashApiPromise as unknown as ReturnType<typeof listTrashApi>,
      );

      const trashPromise = useVaultStore.getState().fetchTrashItems();

      expect(useVaultStore.getState().trashLoading).toBe(true);
      expect(useVaultStore.getState().loading).toBe(true);

      // Now start items loading and let it finish
      vi.mocked(listItemsApi).mockResolvedValue({
        data: {
          success: true,
          data: [],
          pagination: { page: 1, limit: 200, total: 0, totalPages: 0 },
        },
      } as unknown as Awaited<ReturnType<typeof listItemsApi>>);

      await useVaultStore.getState().fetchItems();

      // itemsLoading should be false, but loading should remain true because trashLoading is still active
      expect(useVaultStore.getState().itemsLoading).toBe(false);
      expect(useVaultStore.getState().trashLoading).toBe(true);
      expect(useVaultStore.getState().loading).toBe(true);

      // Now resolve trash
      resolveTrashApi({
        data: {
          success: true,
          data: [],
          pagination: { page: 1, limit: 200, total: 0, totalPages: 0 },
        },
      });

      await trashPromise;

      // Both done — loading should now be false
      expect(useVaultStore.getState().itemsLoading).toBe(false);
      expect(useVaultStore.getState().trashLoading).toBe(false);
      expect(useVaultStore.getState().loading).toBe(false);
    });

    it('loading should remain true if itemsLoading is still active when trashLoading finishes', async () => {
      useAuthStore.setState({ vaultKey: {} as CryptoKey });

      // Start items loading first with a deferred promise
      let resolveItemsApi!: (value: unknown) => void;
      const itemsApiPromise = new Promise((resolve) => {
        resolveItemsApi = resolve;
      });
      vi.mocked(listItemsApi).mockReturnValue(
        itemsApiPromise as unknown as ReturnType<typeof listItemsApi>,
      );

      const itemsPromise = useVaultStore.getState().fetchItems();

      // Now start trash loading and let it finish
      vi.mocked(listTrashApi).mockResolvedValue({
        data: {
          success: true,
          data: [],
          pagination: { page: 1, limit: 200, total: 0, totalPages: 0 },
        },
      } as unknown as Awaited<ReturnType<typeof listTrashApi>>);

      await useVaultStore.getState().fetchTrashItems();

      // trashLoading should be false, but loading should remain true because itemsLoading is still active
      expect(useVaultStore.getState().trashLoading).toBe(false);
      expect(useVaultStore.getState().itemsLoading).toBe(true);
      expect(useVaultStore.getState().loading).toBe(true);

      // Now resolve items
      resolveItemsApi({
        data: {
          success: true,
          data: [],
          pagination: { page: 1, limit: 200, total: 0, totalPages: 0 },
        },
      });

      await itemsPromise;

      expect(useVaultStore.getState().itemsLoading).toBe(false);
      expect(useVaultStore.getState().trashLoading).toBe(false);
      expect(useVaultStore.getState().loading).toBe(false);
    });
  });

  // -----------------------------------------------------------------------
  // deleteFolder item cleanup (Task 4.9)
  // -----------------------------------------------------------------------

  describe('deleteFolder item cleanup', () => {
    it('should clear folderId on items belonging to the deleted folder', async () => {
      const item1 = makeMockItem({ id: 'item-1', name: 'Item 1', folderId: 'folder-A' });
      const item2 = makeMockItem({ id: 'item-2', name: 'Item 2', folderId: 'folder-B' });
      const item3 = makeMockItem({ id: 'item-3', name: 'Item 3', folderId: 'folder-A' });

      const folderA: DecryptedFolder = {
        id: 'folder-A',
        name: 'Folder A',
        sortOrder: 0,
        createdAt: '2024-01-01T00:00:00Z',
        updatedAt: '2024-01-01T00:00:00Z',
        _raw: {} as DecryptedFolder['_raw'],
      };
      const folderB: DecryptedFolder = {
        id: 'folder-B',
        name: 'Folder B',
        sortOrder: 1,
        createdAt: '2024-01-01T00:00:00Z',
        updatedAt: '2024-01-01T00:00:00Z',
        _raw: {} as DecryptedFolder['_raw'],
      };

      useVaultStore.setState({
        items: [item1, item2, item3],
        folders: [folderA, folderB],
      });

      vi.mocked(deleteFolderApi).mockResolvedValue({
        data: { success: true, data: null },
      } as unknown as Awaited<ReturnType<typeof deleteFolderApi>>);

      await useVaultStore.getState().deleteFolder('folder-A');

      const state = useVaultStore.getState();

      // Folder A should be removed
      expect(state.folders).toHaveLength(1);
      expect(state.folders[0]!.id).toBe('folder-B');

      // Items that belonged to folder-A should have folderId cleared
      const updatedItem1 = state.items.find((i) => i.id === 'item-1');
      const updatedItem3 = state.items.find((i) => i.id === 'item-3');
      expect(updatedItem1!.folderId).toBeUndefined();
      expect(updatedItem3!.folderId).toBeUndefined();

      // Item in folder-B should be unaffected
      const updatedItem2 = state.items.find((i) => i.id === 'item-2');
      expect(updatedItem2!.folderId).toBe('folder-B');
    });

    it('should reset selectedFolder if it matches the deleted folder', async () => {
      const folderA: DecryptedFolder = {
        id: 'folder-A',
        name: 'Folder A',
        sortOrder: 0,
        createdAt: '2024-01-01T00:00:00Z',
        updatedAt: '2024-01-01T00:00:00Z',
        _raw: {} as DecryptedFolder['_raw'],
      };

      useVaultStore.setState({
        folders: [folderA],
        selectedFolder: 'folder-A',
      });

      vi.mocked(deleteFolderApi).mockResolvedValue({
        data: { success: true, data: null },
      } as unknown as Awaited<ReturnType<typeof deleteFolderApi>>);

      await useVaultStore.getState().deleteFolder('folder-A');

      expect(useVaultStore.getState().selectedFolder).toBeNull();
    });

    it('should not reset selectedFolder if it does not match the deleted folder', async () => {
      const folderA: DecryptedFolder = {
        id: 'folder-A',
        name: 'Folder A',
        sortOrder: 0,
        createdAt: '2024-01-01T00:00:00Z',
        updatedAt: '2024-01-01T00:00:00Z',
        _raw: {} as DecryptedFolder['_raw'],
      };
      const folderB: DecryptedFolder = {
        id: 'folder-B',
        name: 'Folder B',
        sortOrder: 1,
        createdAt: '2024-01-01T00:00:00Z',
        updatedAt: '2024-01-01T00:00:00Z',
        _raw: {} as DecryptedFolder['_raw'],
      };

      useVaultStore.setState({
        folders: [folderA, folderB],
        selectedFolder: 'folder-B',
      });

      vi.mocked(deleteFolderApi).mockResolvedValue({
        data: { success: true, data: null },
      } as unknown as Awaited<ReturnType<typeof deleteFolderApi>>);

      await useVaultStore.getState().deleteFolder('folder-A');

      // selectedFolder should remain folder-B since we deleted folder-A
      expect(useVaultStore.getState().selectedFolder).toBe('folder-B');
    });

    it('should not modify items that have no folderId', async () => {
      const itemNoFolder = makeMockItem({ id: 'item-1', name: 'No Folder Item' });
      // itemNoFolder has no folderId set (undefined by default from makeMockItem)

      const folderA: DecryptedFolder = {
        id: 'folder-A',
        name: 'Folder A',
        sortOrder: 0,
        createdAt: '2024-01-01T00:00:00Z',
        updatedAt: '2024-01-01T00:00:00Z',
        _raw: {} as DecryptedFolder['_raw'],
      };

      useVaultStore.setState({
        items: [itemNoFolder],
        folders: [folderA],
      });

      vi.mocked(deleteFolderApi).mockResolvedValue({
        data: { success: true, data: null },
      } as unknown as Awaited<ReturnType<typeof deleteFolderApi>>);

      await useVaultStore.getState().deleteFolder('folder-A');

      const state = useVaultStore.getState();
      expect(state.items).toHaveLength(1);
      expect(state.items[0]!.folderId).toBeUndefined();
    });
  });
});
