/**
 * Additional coverage tests for stores and services with low coverage.
 *
 * Targets:
 * - vaultStore.ts: offline fallback, decryption failures, validation errors,
 *   fetchFolders, fetchTrashItems, updateItem password history
 * - uiStore.ts: system theme detection via matchMedia, persist partialize
 * - client.ts: CSRF management, 401/403 response interceptors, request interceptor,
 *   token refresh flow, cross-tab CSRF invalidation
 * - logger.ts: dev mode log levels, function signatures
 * - offlineCache.ts: OfflineCacheError edge cases
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ---------------------------------------------------------------------------
// matchMedia polyfill — must exist before any module import that references it
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
// Top-level mocks for vaultStore / authStore / uiStore tests (Sections 1-2).
// The API client tests (Section 3) use vi.resetModules + vi.doMock to
// import the real client module with a controlled authStore mock.
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
    cacheItems: vi.fn().mockResolvedValue(undefined),
    cacheFolders: vi.fn().mockResolvedValue(undefined),
    getCachedItems: vi.fn().mockResolvedValue([]),
    getCachedFolders: vi.fn().mockResolvedValue([]),
    clear: vi.fn().mockResolvedValue(undefined),
    getLastSync: vi.fn().mockResolvedValue(null),
  },
}));

vi.mock('../src/services/api/client', () => ({
  clearCsrfToken: vi.fn(),
}));

vi.mock('../src/hooks/useUserSettings', () => ({
  clearSettingsCache: vi.fn(),
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

// Imports (after mocks)
import { useAuthStore } from '../src/stores/authStore';
import { useVaultStore } from '../src/stores/vaultStore';
import { useUIStore } from '../src/stores/uiStore';
import { cryptoService } from '../src/services/crypto/cryptoService';
import { offlineCache } from '../src/services/offlineCache';
import {
  listItemsApi,
  listTrashApi,
  listFoldersApi,
  updateItemApi,
} from '../src/services/api/vaultApi';
import type { DecryptedVaultItem, DecryptedFolder } from '../src/stores/vaultStore';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeMockItem(overrides: Partial<DecryptedVaultItem> = {}): DecryptedVaultItem {
  return {
    id: 'item-1',
    itemType: 'login',
    tags: [],
    favorite: false,
    name: 'Test Item',
    data: {},
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
    _raw: {
      _id: 'item-1',
      userId: 'user-1',
      itemType: 'login',
      encryptedName: 'enc-name',
      nameIv: 'n-iv',
      nameTag: 'n-tag',
      encryptedData: 'enc-data',
      dataIv: 'd-iv',
      dataTag: 'd-tag',
      tags: [],
      favorite: false,
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
    } as DecryptedVaultItem['_raw'],
    ...overrides,
  };
}

function _makeMockFolder(overrides: Partial<DecryptedFolder> = {}): DecryptedFolder {
  return {
    id: 'folder-1',
    name: 'Test Folder',
    sortOrder: 0,
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
    _raw: {} as DecryptedFolder['_raw'],
    ...overrides,
  };
}

function makeRawItemResponse(overrides: Record<string, unknown> = {}) {
  return {
    _id: 'item-1',
    userId: 'user-1',
    itemType: 'login',
    encryptedName: 'enc-name',
    nameIv: 'n-iv',
    nameTag: 'n-tag',
    encryptedData: 'enc-data',
    dataIv: 'd-iv',
    dataTag: 'd-tag',
    tags: [],
    favorite: false,
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
    ...overrides,
  };
}

function makeRawFolderResponse(overrides: Record<string, unknown> = {}) {
  return {
    _id: 'folder-1',
    userId: 'user-1',
    encryptedName: 'enc-folder-name',
    nameIv: 'fn-iv',
    nameTag: 'fn-tag',
    sortOrder: 0,
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
    ...overrides,
  };
}

const mockVaultKey = {} as CryptoKey;

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
  isLoading: false,
};

function setupUnlockedVault(): void {
  useAuthStore.setState({ vaultKey: mockVaultKey });
}

// ===========================================================================
// Section 1: vaultStore additional coverage
// ===========================================================================

describe('vaultStore — additional edge cases', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useVaultStore.setState(vaultInitialState);
    useAuthStore.setState(authInitialState);
  });

  // -------------------------------------------------------------------------
  // fetchItems — offline fallback
  // -------------------------------------------------------------------------

  describe('fetchItems — offline fallback', () => {
    it('should fall back to offline cache when navigator.onLine is false and API fails', async () => {
      setupUnlockedVault();

      vi.mocked(listItemsApi).mockRejectedValue(new Error('Network error'));

      const originalOnLine = navigator.onLine;
      Object.defineProperty(navigator, 'onLine', { value: false, configurable: true });

      const cachedRaw = [makeRawItemResponse({ _id: 'cached-1' })];
      vi.mocked(offlineCache.getCachedItems).mockResolvedValue(cachedRaw);

      vi.mocked(cryptoService.decryptData)
        .mockResolvedValueOnce('Cached Item')
        .mockResolvedValueOnce(JSON.stringify({ username: 'cached-user' }));

      await useVaultStore.getState().fetchItems();

      expect(offlineCache.getCachedItems).toHaveBeenCalled();
      expect(useVaultStore.getState().items).toHaveLength(1);
      expect(useVaultStore.getState().items[0]!.name).toBe('Cached Item');
      expect(useVaultStore.getState().itemsLoading).toBe(false);

      Object.defineProperty(navigator, 'onLine', { value: originalOnLine, configurable: true });
    });

    it('should re-throw error when online and API fails', async () => {
      setupUnlockedVault();

      vi.mocked(listItemsApi).mockRejectedValue(new Error('Server error'));

      const originalOnLine = navigator.onLine;
      Object.defineProperty(navigator, 'onLine', { value: true, configurable: true });

      await expect(useVaultStore.getState().fetchItems()).rejects.toThrow('Server error');
      expect(useVaultStore.getState().itemsLoading).toBe(false);

      Object.defineProperty(navigator, 'onLine', { value: originalOnLine, configurable: true });
    });

    it('should set itemsLoading to false in finally block even on error', async () => {
      setupUnlockedVault();

      vi.mocked(listItemsApi).mockRejectedValue(new Error('Fail'));
      Object.defineProperty(navigator, 'onLine', { value: true, configurable: true });

      try {
        await useVaultStore.getState().fetchItems();
      } catch {
        // expected
      }

      expect(useVaultStore.getState().itemsLoading).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // fetchItems — decryption failure handling (Promise.allSettled)
  // -------------------------------------------------------------------------

  describe('fetchItems — decryption failures', () => {
    it('should include successfully decrypted items and skip failed ones', async () => {
      setupUnlockedVault();

      const rawItems = [
        makeRawItemResponse({ _id: 'good-1' }),
        makeRawItemResponse({ _id: 'bad-1' }),
        makeRawItemResponse({ _id: 'good-2' }),
      ];

      vi.mocked(listItemsApi).mockResolvedValue({
        data: {
          success: true,
          data: rawItems,
          pagination: { page: 1, limit: 200, total: 3, totalPages: 1 },
        },
      } as never);

      // decryptItem calls decryptData twice per item (name then data).
      // Promise.allSettled runs all three decryptItem calls concurrently.
      // The first await in each fires in rapid succession (microtask order),
      // so all three name calls consume mocks first, then data calls follow.
      // Actual order: good-1 name, bad-1 name, good-2 name, good-1 data, good-2 data
      vi.mocked(cryptoService.decryptData)
        .mockResolvedValueOnce('Good Item 1') // good-1 name
        .mockRejectedValueOnce(new Error('Decryption failed')) // bad-1 name
        .mockResolvedValueOnce('Good Item 2') // good-2 name
        .mockResolvedValueOnce(JSON.stringify({ username: 'user1' })) // good-1 data
        .mockResolvedValueOnce(JSON.stringify({ username: 'user2' })); // good-2 data

      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      await useVaultStore.getState().fetchItems();

      const { items } = useVaultStore.getState();
      expect(items).toHaveLength(2);
      expect(items[0]!.id).toBe('good-1');
      expect(items[1]!.id).toBe('good-2');

      consoleSpy.mockRestore();
    });

    it('should handle all items failing decryption', async () => {
      setupUnlockedVault();

      const rawItems = [makeRawItemResponse({ _id: 'bad-1' })];

      vi.mocked(listItemsApi).mockResolvedValue({
        data: {
          success: true,
          data: rawItems,
          pagination: { page: 1, limit: 200, total: 1, totalPages: 1 },
        },
      } as never);

      vi.mocked(cryptoService.decryptData).mockRejectedValue(new Error('Corrupt'));

      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      await useVaultStore.getState().fetchItems();

      expect(useVaultStore.getState().items).toHaveLength(0);

      consoleSpy.mockRestore();
    });
  });

  // -------------------------------------------------------------------------
  // fetchItems — data validation edge cases
  // -------------------------------------------------------------------------

  describe('fetchItems — data validation edge cases', () => {
    it('should wrap non-object parsed data (array) in _raw field', async () => {
      setupUnlockedVault();

      vi.mocked(listItemsApi).mockResolvedValue({
        data: {
          success: true,
          data: [makeRawItemResponse({ _id: 'arr-item' })],
          pagination: { page: 1, limit: 200, total: 1, totalPages: 1 },
        },
      } as never);

      vi.mocked(cryptoService.decryptData)
        .mockResolvedValueOnce('Array Item')
        .mockResolvedValueOnce('[1, 2, 3]');

      await useVaultStore.getState().fetchItems();

      const { items } = useVaultStore.getState();
      expect(items).toHaveLength(1);
      expect(items[0]!.data).toEqual({ _raw: [1, 2, 3] });
    });

    it('should wrap unparseable JSON data in _raw field as string', async () => {
      setupUnlockedVault();

      vi.mocked(listItemsApi).mockResolvedValue({
        data: {
          success: true,
          data: [makeRawItemResponse({ _id: 'bad-json' })],
          pagination: { page: 1, limit: 200, total: 1, totalPages: 1 },
        },
      } as never);

      vi.mocked(cryptoService.decryptData)
        .mockResolvedValueOnce('Bad JSON Item')
        .mockResolvedValueOnce('not-valid-json{{{');

      await useVaultStore.getState().fetchItems();

      const { items } = useVaultStore.getState();
      expect(items).toHaveLength(1);
      expect(items[0]!.data).toEqual({ _raw: 'not-valid-json{{{' });
    });

    it('should handle null parsed data as non-object', async () => {
      setupUnlockedVault();

      vi.mocked(listItemsApi).mockResolvedValue({
        data: {
          success: true,
          data: [makeRawItemResponse({ _id: 'null-item' })],
          pagination: { page: 1, limit: 200, total: 1, totalPages: 1 },
        },
      } as never);

      vi.mocked(cryptoService.decryptData)
        .mockResolvedValueOnce('Null Item')
        .mockResolvedValueOnce('null');

      await useVaultStore.getState().fetchItems();

      const { items } = useVaultStore.getState();
      expect(items).toHaveLength(1);
      expect(items[0]!.data).toEqual({ _raw: null });
    });

    it('should keep data with _validationError flag when Zod schema fails', async () => {
      setupUnlockedVault();

      vi.mocked(listItemsApi).mockResolvedValue({
        data: {
          success: true,
          data: [makeRawItemResponse({ _id: 'invalid-schema', itemType: 'login' })],
          pagination: { page: 1, limit: 200, total: 1, totalPages: 1 },
        },
      } as never);

      // `username` is capped at 500 chars by loginDataSchema, so a 501-char value
      // is genuinely rejected by Zod. (A payload of unknown keys would be silently
      // stripped by `.strip()` and PASS, never exercising the placeholder branch.)
      const tooLongUsername = 'x'.repeat(501);
      vi.mocked(cryptoService.decryptData)
        .mockResolvedValueOnce('Invalid Schema Item')
        .mockResolvedValueOnce(JSON.stringify({ username: tooLongUsername }));

      await useVaultStore.getState().fetchItems();

      const { items } = useVaultStore.getState();
      expect(items).toHaveLength(1);
      expect(items[0]!.name).toBe('Invalid Schema Item');
      // The Zod-failure branch keeps the parsed object as a placeholder flagged
      // with `_validationError: true` (never a clean schema-defaulted object).
      const data = items[0]!.data as Record<string, unknown>;
      expect(data._validationError).toBe(true);
      expect(data.username).toBe(tooLongUsername);
    });
  });

  // -------------------------------------------------------------------------
  // fetchItems — pagination (multiple pages)
  // -------------------------------------------------------------------------

  describe('fetchItems — pagination', () => {
    it('should fetch all pages when totalPages > 1', async () => {
      setupUnlockedVault();

      vi.mocked(listItemsApi)
        .mockResolvedValueOnce({
          data: {
            success: true,
            data: [makeRawItemResponse({ _id: 'page1-item' })],
            pagination: { page: 1, limit: 200, total: 2, totalPages: 2 },
          },
        } as never)
        .mockResolvedValueOnce({
          data: {
            success: true,
            data: [makeRawItemResponse({ _id: 'page2-item' })],
            pagination: { page: 2, limit: 200, total: 2, totalPages: 2 },
          },
        } as never);

      vi.mocked(cryptoService.decryptData)
        .mockResolvedValueOnce('Page 1 Item')
        .mockResolvedValueOnce(JSON.stringify({ username: 'u1' }))
        .mockResolvedValueOnce('Page 2 Item')
        .mockResolvedValueOnce(JSON.stringify({ username: 'u2' }));

      await useVaultStore.getState().fetchItems();

      expect(listItemsApi).toHaveBeenCalledTimes(2);
      expect(useVaultStore.getState().items).toHaveLength(2);
    });

    it('should throw when API returns success: false', async () => {
      setupUnlockedVault();

      vi.mocked(listItemsApi).mockResolvedValue({
        data: {
          success: false,
          error: { code: 'SERVER_ERROR', message: 'Internal error' },
        },
      } as never);

      Object.defineProperty(navigator, 'onLine', { value: true, configurable: true });

      await expect(useVaultStore.getState().fetchItems()).rejects.toThrow(
        'Failed to fetch vault items',
      );
    });
  });

  // -------------------------------------------------------------------------
  // fetchTrashItems — decryption failures and error paths
  // -------------------------------------------------------------------------

  describe('fetchTrashItems — edge cases', () => {
    it('should handle partial decryption failures in trash items', async () => {
      setupUnlockedVault();

      vi.mocked(listTrashApi).mockResolvedValue({
        data: {
          success: true,
          data: [
            makeRawItemResponse({ _id: 'trash-good' }),
            makeRawItemResponse({ _id: 'trash-bad' }),
          ],
          pagination: { page: 1, limit: 200, total: 2, totalPages: 1 },
        },
      } as never);

      // Promise.allSettled runs both decryptItem calls concurrently.
      // Order: trash-good name, trash-bad name, trash-good data
      vi.mocked(cryptoService.decryptData)
        .mockResolvedValueOnce('Trash Good')
        .mockRejectedValueOnce(new Error('Decrypt fail'))
        .mockResolvedValueOnce(JSON.stringify({ username: 'tg' }));

      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      await useVaultStore.getState().fetchTrashItems();

      expect(useVaultStore.getState().trashItems).toHaveLength(1);
      expect(useVaultStore.getState().trashItems[0]!.id).toBe('trash-good');
      expect(useVaultStore.getState().trashLoading).toBe(false);

      consoleSpy.mockRestore();
    });

    it('should throw when trash API returns success: false', async () => {
      setupUnlockedVault();

      vi.mocked(listTrashApi).mockResolvedValue({
        data: {
          success: false,
          error: { code: 'ERROR', message: 'Fail' },
        },
      } as never);

      await expect(useVaultStore.getState().fetchTrashItems()).rejects.toThrow(
        'Failed to fetch trash items',
      );
      expect(useVaultStore.getState().trashLoading).toBe(false);
    });

    it('should set trashLoading to false in finally block on error', async () => {
      setupUnlockedVault();

      vi.mocked(listTrashApi).mockRejectedValue(new Error('Network'));

      try {
        await useVaultStore.getState().fetchTrashItems();
      } catch {
        // expected
      }

      expect(useVaultStore.getState().trashLoading).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // fetchFolders — offline fallback, decryption failures, cache failure
  // -------------------------------------------------------------------------

  describe('fetchFolders — edge cases', () => {
    it('should fetch and decrypt folders successfully', async () => {
      setupUnlockedVault();

      vi.mocked(listFoldersApi).mockResolvedValue({
        data: {
          success: true,
          data: [makeRawFolderResponse({ _id: 'f1' })],
        },
      } as never);

      vi.mocked(cryptoService.decryptData).mockResolvedValueOnce('My Folder');

      await useVaultStore.getState().fetchFolders();

      expect(useVaultStore.getState().folders).toHaveLength(1);
      expect(useVaultStore.getState().folders[0]!.name).toBe('My Folder');
    });

    it('should fall back to offline cache when offline and API fails', async () => {
      setupUnlockedVault();

      vi.mocked(listFoldersApi).mockRejectedValue(new Error('Network'));

      const originalOnLine = navigator.onLine;
      Object.defineProperty(navigator, 'onLine', { value: false, configurable: true });

      vi.mocked(offlineCache.getCachedFolders).mockResolvedValue([
        makeRawFolderResponse({ _id: 'cached-f1' }),
      ]);
      vi.mocked(cryptoService.decryptData).mockResolvedValueOnce('Cached Folder');

      await useVaultStore.getState().fetchFolders();

      expect(offlineCache.getCachedFolders).toHaveBeenCalled();
      expect(useVaultStore.getState().folders).toHaveLength(1);
      expect(useVaultStore.getState().folders[0]!.name).toBe('Cached Folder');

      Object.defineProperty(navigator, 'onLine', { value: originalOnLine, configurable: true });
    });

    it('should re-throw when online and API fails', async () => {
      setupUnlockedVault();

      vi.mocked(listFoldersApi).mockRejectedValue(new Error('Server error'));

      const originalOnLine = navigator.onLine;
      Object.defineProperty(navigator, 'onLine', { value: true, configurable: true });

      await expect(useVaultStore.getState().fetchFolders()).rejects.toThrow('Server error');

      Object.defineProperty(navigator, 'onLine', { value: originalOnLine, configurable: true });
    });

    it('should throw when API returns success: false', async () => {
      setupUnlockedVault();

      vi.mocked(listFoldersApi).mockResolvedValue({
        data: {
          success: false,
          error: { code: 'ERROR', message: 'Fail' },
        },
      } as never);

      const originalOnLine = navigator.onLine;
      Object.defineProperty(navigator, 'onLine', { value: true, configurable: true });

      await expect(useVaultStore.getState().fetchFolders()).rejects.toThrow(
        'Failed to fetch folders',
      );

      Object.defineProperty(navigator, 'onLine', { value: originalOnLine, configurable: true });
    });

    it('should handle partial folder decryption failures', async () => {
      setupUnlockedVault();

      vi.mocked(listFoldersApi).mockResolvedValue({
        data: {
          success: true,
          data: [makeRawFolderResponse({ _id: 'good-f' }), makeRawFolderResponse({ _id: 'bad-f' })],
        },
      } as never);

      vi.mocked(cryptoService.decryptData)
        .mockResolvedValueOnce('Good Folder')
        .mockRejectedValueOnce(new Error('Decrypt fail'));

      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      await useVaultStore.getState().fetchFolders();

      expect(useVaultStore.getState().folders).toHaveLength(1);
      expect(useVaultStore.getState().folders[0]!.name).toBe('Good Folder');

      consoleSpy.mockRestore();
    });

    it('should set offlineCacheAvailable to false when cacheFolders fails', async () => {
      setupUnlockedVault();

      vi.mocked(listFoldersApi).mockResolvedValue({
        data: {
          success: true,
          data: [],
        },
      } as never);

      vi.mocked(offlineCache.cacheFolders).mockRejectedValue(new Error('Cache write error'));
      useUIStore.setState({ offlineCacheAvailable: true });

      await useVaultStore.getState().fetchFolders();

      // Wait for async .catch() handler
      await new Promise((resolve) => setTimeout(resolve, 10));

      expect(useUIStore.getState().offlineCacheAvailable).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // updateItem — password history tracking
  // -------------------------------------------------------------------------

  describe('updateItem — password history', () => {
    it('should build password history when password changes on login item', async () => {
      setupUnlockedVault();

      const existingItem = makeMockItem({
        id: 'login-1',
        itemType: 'login',
        name: 'My Login',
        data: { password: 'old-password', username: 'user1' },
        _raw: {
          _id: 'login-1',
          userId: 'user-1',
          itemType: 'login',
          encryptedName: 'enc',
          nameIv: 'iv',
          nameTag: 'tag',
          encryptedData: 'edata',
          dataIv: 'div',
          dataTag: 'dtag',
          tags: [],
          favorite: false,
          createdAt: '2024-01-01T00:00:00Z',
          updatedAt: '2024-01-01T00:00:00Z',
          passwordHistory: [],
        } as DecryptedVaultItem['_raw'],
      });

      useVaultStore.setState({ items: [existingItem] });

      vi.mocked(cryptoService.encryptData)
        .mockResolvedValueOnce({ encrypted: 'enc-name', iv: 'n-iv', tag: 'n-tag' })
        .mockResolvedValueOnce({ encrypted: 'enc-data', iv: 'd-iv', tag: 'd-tag' })
        .mockResolvedValueOnce({ encrypted: 'enc-old-pass', iv: 'op-iv', tag: 'op-tag' });

      vi.mocked(cryptoService.generateSearchHash).mockResolvedValue('hash');

      vi.mocked(updateItemApi).mockResolvedValue({
        data: {
          success: true,
          data: makeRawItemResponse({ _id: 'login-1' }),
        },
      } as never);

      vi.mocked(cryptoService.decryptData)
        .mockResolvedValueOnce('My Login')
        .mockResolvedValueOnce(JSON.stringify({ password: 'new-password', username: 'user1' }));

      await useVaultStore
        .getState()
        .updateItem('login-1', 'My Login', { password: 'new-password', username: 'user1' });

      expect(updateItemApi).toHaveBeenCalledWith(
        'login-1',
        expect.objectContaining({
          passwordHistory: expect.arrayContaining([
            expect.objectContaining({
              encryptedPassword: 'enc-old-pass',
              iv: 'op-iv',
              tag: 'op-tag',
            }),
          ]) as unknown,
        }),
      );
    });

    it('should not build password history when password has not changed', async () => {
      setupUnlockedVault();

      const existingItem = makeMockItem({
        id: 'login-1',
        itemType: 'login',
        name: 'My Login',
        data: { password: 'same-password', username: 'user1' },
      });

      useVaultStore.setState({ items: [existingItem] });

      vi.mocked(cryptoService.encryptData)
        .mockResolvedValueOnce({ encrypted: 'enc-name', iv: 'n-iv', tag: 'n-tag' })
        .mockResolvedValueOnce({ encrypted: 'enc-data', iv: 'd-iv', tag: 'd-tag' });

      vi.mocked(cryptoService.generateSearchHash).mockResolvedValue('hash');

      vi.mocked(updateItemApi).mockResolvedValue({
        data: {
          success: true,
          data: makeRawItemResponse({ _id: 'login-1' }),
        },
      } as never);

      vi.mocked(cryptoService.decryptData)
        .mockResolvedValueOnce('My Login')
        .mockResolvedValueOnce(JSON.stringify({ password: 'same-password', username: 'user1' }));

      await useVaultStore
        .getState()
        .updateItem('login-1', 'My Login', { password: 'same-password', username: 'user1' });

      const callArgs = vi.mocked(updateItemApi).mock.calls[0]![1] as Record<string, unknown>;
      expect(callArgs.passwordHistory).toBeUndefined();
    });

    it('should not build password history for non-login items', async () => {
      setupUnlockedVault();

      const existingItem = makeMockItem({
        id: 'note-1',
        itemType: 'note',
        name: 'My Note',
        data: { content: 'old content' },
      });

      useVaultStore.setState({ items: [existingItem] });

      vi.mocked(cryptoService.encryptData)
        .mockResolvedValueOnce({ encrypted: 'enc-name', iv: 'n-iv', tag: 'n-tag' })
        .mockResolvedValueOnce({ encrypted: 'enc-data', iv: 'd-iv', tag: 'd-tag' });

      vi.mocked(cryptoService.generateSearchHash).mockResolvedValue('hash');

      vi.mocked(updateItemApi).mockResolvedValue({
        data: {
          success: true,
          data: makeRawItemResponse({ _id: 'note-1', itemType: 'note' }),
        },
      } as never);

      vi.mocked(cryptoService.decryptData)
        .mockResolvedValueOnce('My Note')
        .mockResolvedValueOnce(JSON.stringify({ content: 'new content' }));

      await useVaultStore.getState().updateItem('note-1', 'My Note', { content: 'new content' });

      const callArgs = vi.mocked(updateItemApi).mock.calls[0]![1] as Record<string, unknown>;
      expect(callArgs.passwordHistory).toBeUndefined();
    });

    it('should not build password history when existing password is empty', async () => {
      setupUnlockedVault();

      const existingItem = makeMockItem({
        id: 'login-1',
        itemType: 'login',
        name: 'My Login',
        data: { password: '', username: 'user1' },
      });

      useVaultStore.setState({ items: [existingItem] });

      vi.mocked(cryptoService.encryptData)
        .mockResolvedValueOnce({ encrypted: 'enc-name', iv: 'n-iv', tag: 'n-tag' })
        .mockResolvedValueOnce({ encrypted: 'enc-data', iv: 'd-iv', tag: 'd-tag' });

      vi.mocked(cryptoService.generateSearchHash).mockResolvedValue('hash');

      vi.mocked(updateItemApi).mockResolvedValue({
        data: {
          success: true,
          data: makeRawItemResponse({ _id: 'login-1' }),
        },
      } as never);

      vi.mocked(cryptoService.decryptData)
        .mockResolvedValueOnce('My Login')
        .mockResolvedValueOnce(JSON.stringify({ password: 'new-pass', username: 'user1' }));

      await useVaultStore
        .getState()
        .updateItem('login-1', 'My Login', { password: 'new-pass', username: 'user1' });

      const callArgs = vi.mocked(updateItemApi).mock.calls[0]![1] as Record<string, unknown>;
      expect(callArgs.passwordHistory).toBeUndefined();
    });

    it('should update item in state when API returns success', async () => {
      setupUnlockedVault();

      const existingItem = makeMockItem({ id: 'item-1', name: 'Old Name' });
      useVaultStore.setState({ items: [existingItem] });

      vi.mocked(cryptoService.encryptData)
        .mockResolvedValueOnce({ encrypted: 'enc-name', iv: 'n-iv', tag: 'n-tag' })
        .mockResolvedValueOnce({ encrypted: 'enc-data', iv: 'd-iv', tag: 'd-tag' });
      vi.mocked(cryptoService.generateSearchHash).mockResolvedValue('hash');

      vi.mocked(updateItemApi).mockResolvedValue({
        data: {
          success: true,
          data: makeRawItemResponse({ _id: 'item-1' }),
        },
      } as never);

      vi.mocked(cryptoService.decryptData)
        .mockResolvedValueOnce('New Name')
        .mockResolvedValueOnce(JSON.stringify({ username: 'updated' }));

      await useVaultStore.getState().updateItem('item-1', 'New Name', { username: 'updated' });

      const { items } = useVaultStore.getState();
      expect(items).toHaveLength(1);
      expect(items[0]!.name).toBe('New Name');
    });

    it('should not update state when API returns success: false', async () => {
      setupUnlockedVault();

      const existingItem = makeMockItem({ id: 'item-1', name: 'Original' });
      useVaultStore.setState({ items: [existingItem] });

      vi.mocked(cryptoService.encryptData)
        .mockResolvedValueOnce({ encrypted: 'enc', iv: 'iv', tag: 'tag' })
        .mockResolvedValueOnce({ encrypted: 'enc', iv: 'iv', tag: 'tag' });
      vi.mocked(cryptoService.generateSearchHash).mockResolvedValue('hash');

      vi.mocked(updateItemApi).mockResolvedValue({
        data: {
          success: false,
          error: { code: 'ERROR', message: 'Fail' },
        },
      } as never);

      await useVaultStore.getState().updateItem('item-1', 'Changed', {});

      expect(useVaultStore.getState().items[0]!.name).toBe('Original');
    });
  });
});

// ===========================================================================
// Section 2: uiStore additional coverage
// ===========================================================================

describe('uiStore — additional coverage', () => {
  beforeEach(() => {
    useUIStore.setState({
      theme: 'system',
      sidebarOpen: true,
      commandPaletteOpen: false,
      offlineCacheAvailable: true,
    });
    document.documentElement.classList.remove('dark');
    document.documentElement.removeAttribute('data-theme');
  });

  describe('persist partialize', () => {
    it('persists ONLY { theme, sidebarCollapsed } to localStorage — never transient UI state', () => {
      // Mutate every persistable and non-persistable field.
      useUIStore.getState().setTheme('dark');
      useUIStore.getState().toggleSidebarCollapsed();
      useUIStore.getState().toggleSidebar(); // sidebarOpen — must NOT persist
      useUIStore.getState().toggleCommandPalette(); // commandPaletteOpen — must NOT persist
      useUIStore.getState().setOfflineCacheAvailable(false); // must NOT persist

      // Read what the persist middleware actually wrote to storage.
      const raw = localStorage.getItem('hvault-ui');
      expect(raw).toBeTruthy();
      const persisted = JSON.parse(raw!) as { state: Record<string, unknown> };

      // The partialize allowlist is exactly these two keys — leaking sidebarOpen /
      // commandPaletteOpen / offlineCacheAvailable across sessions would fail here.
      expect(Object.keys(persisted.state).sort()).toEqual(['sidebarCollapsed', 'theme']);
      expect(persisted.state.theme).toBe('dark');
      expect(persisted.state).not.toHaveProperty('sidebarOpen');
      expect(persisted.state).not.toHaveProperty('commandPaletteOpen');
      expect(persisted.state).not.toHaveProperty('offlineCacheAvailable');
    });
  });

  describe('theme interactions', () => {
    it('should correctly cycle through all theme values', () => {
      useUIStore.getState().setTheme('light');
      expect(useUIStore.getState().theme).toBe('light');
      expect(document.documentElement.classList.contains('dark')).toBe(false);

      useUIStore.getState().setTheme('dark');
      expect(useUIStore.getState().theme).toBe('dark');
      expect(document.documentElement.classList.contains('dark')).toBe(true);

      useUIStore.getState().setTheme('system');
      expect(useUIStore.getState().theme).toBe('system');
    });

    it('should resolve system theme to dark when OS prefers dark', () => {
      window.matchMedia = (query: string) =>
        ({
          matches: query === '(prefers-color-scheme: dark)',
          media: query,
          onchange: null,
          addListener: () => {},
          removeListener: () => {},
          addEventListener: () => {},
          removeEventListener: () => {},
          dispatchEvent: () => false,
        }) as MediaQueryList;

      useUIStore.getState().setTheme('system');

      expect(document.documentElement.classList.contains('dark')).toBe(true);
      expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
    });

    it('should resolve system theme to light when OS prefers light', () => {
      window.matchMedia = (query: string) =>
        ({
          matches: false,
          media: query,
          onchange: null,
          addListener: () => {},
          removeListener: () => {},
          addEventListener: () => {},
          removeEventListener: () => {},
          dispatchEvent: () => false,
        }) as MediaQueryList;

      useUIStore.getState().setTheme('system');

      expect(document.documentElement.classList.contains('dark')).toBe(false);
      expect(document.documentElement.getAttribute('data-theme')).toBe('light');
    });
  });

  describe('setOfflineCacheAvailable toggling', () => {
    it('should toggle offlineCacheAvailable from true to false and back', () => {
      expect(useUIStore.getState().offlineCacheAvailable).toBe(true);

      useUIStore.getState().setOfflineCacheAvailable(false);
      expect(useUIStore.getState().offlineCacheAvailable).toBe(false);

      useUIStore.getState().setOfflineCacheAvailable(true);
      expect(useUIStore.getState().offlineCacheAvailable).toBe(true);
    });
  });
});

// ===========================================================================
// Section 3: API Client — CSRF and token refresh (CRITICAL)
//
// These tests use vi.doMock/vi.resetModules to import the REAL client module
// with a mocked authStore. The top-level vi.mock for client.ts does not
// apply here because vi.doUnmock overrides it for the dynamic import.
// ===========================================================================

describe('API Client — comprehensive coverage', () => {
  const mockGetState = vi.fn();
  const mockSetAccessToken = vi.fn();
  const mockLogout = vi.fn().mockResolvedValue(undefined);

  beforeEach(() => {
    vi.resetModules();
    localStorage.clear();
    mockGetState.mockReturnValue({
      accessToken: null,
      setAccessToken: mockSetAccessToken,
      logout: mockLogout,
    });
    mockSetAccessToken.mockReset();
    mockLogout.mockReset().mockResolvedValue(undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  /**
   * Helper: import the real client module with a mocked authStore.
   * Must call vi.resetModules() before each use to get a fresh module.
   */
  async function importRealClient() {
    vi.doUnmock('../src/services/api/client');
    vi.doMock('../src/stores/authStore', () => ({
      useAuthStore: { getState: mockGetState },
    }));
    return import('../src/services/api/client');
  }

  // Helper to get interceptors from the api instance
  function getRequestInterceptor(api: { interceptors: { request: unknown } }) {
    const interceptors = (
      api.interceptors.request as unknown as {
        handlers: {
          fulfilled: (config: Record<string, unknown>) => Promise<Record<string, unknown>>;
        }[];
      }
    ).handlers;
    return interceptors[0]!.fulfilled;
  }

  function getResponseInterceptor(api: { interceptors: { response: unknown } }) {
    const interceptors = (
      api.interceptors.response as unknown as {
        handlers: { rejected: (error: unknown) => Promise<unknown> }[];
      }
    ).handlers;
    return interceptors[0]!.rejected;
  }

  // -------------------------------------------------------------------------
  // clearCsrfToken
  // -------------------------------------------------------------------------

  describe('clearCsrfToken', () => {
    it('should write invalidation timestamp to localStorage', async () => {
      vi.resetModules();
      const { clearCsrfToken } = await importRealClient();

      const before = Date.now();
      clearCsrfToken();
      const after = Date.now();

      const stored = localStorage.getItem('__hv_csrf_invalidated');
      expect(stored).toBeTruthy();
      const ts = Number(stored);
      expect(ts).toBeGreaterThanOrEqual(before);
      expect(ts).toBeLessThanOrEqual(after);
    });

    it('should not throw when localStorage is unavailable', async () => {
      vi.resetModules();
      const { clearCsrfToken } = await importRealClient();

      const originalSetItem = localStorage.setItem;
      localStorage.setItem = () => {
        throw new Error('localStorage disabled');
      };

      expect(() => clearCsrfToken()).not.toThrow();

      localStorage.setItem = originalSetItem;
    });
  });

  // -------------------------------------------------------------------------
  // Request interceptor — Bearer token attachment
  // -------------------------------------------------------------------------

  describe('Request interceptor — Bearer token', () => {
    it('should attach Authorization header when accessToken exists', async () => {
      vi.resetModules();
      mockGetState.mockReturnValue({
        accessToken: 'test-jwt-token',
        setAccessToken: mockSetAccessToken,
        logout: mockLogout,
      });

      const { api } = await importRealClient();
      const interceptor = getRequestInterceptor(api);

      const config = {
        method: 'get',
        headers: {
          set Authorization(val: string) {
            (config.headers as Record<string, string>)._auth = val;
          },
          get Authorization() {
            return (config.headers as Record<string, string>)._auth;
          },
          _auth: undefined as string | undefined,
        },
      };

      const result = await interceptor(config as unknown as Record<string, unknown>);
      expect((result as { headers: { _auth: string } }).headers._auth).toBe(
        'Bearer test-jwt-token',
      );
    });

    it('should not attach Authorization header when accessToken is null', async () => {
      vi.resetModules();
      mockGetState.mockReturnValue({
        accessToken: null,
        setAccessToken: mockSetAccessToken,
        logout: mockLogout,
      });

      const { api } = await importRealClient();
      const interceptor = getRequestInterceptor(api);

      const headers: Record<string, string | undefined> = {};
      const config = {
        method: 'get',
        headers: new Proxy(headers, {
          set(target, prop, value) {
            target[prop as string] = value as string;
            return true;
          },
          get(target, prop) {
            return target[prop as string];
          },
        }),
      };

      const result = await interceptor(config as unknown as Record<string, unknown>);
      expect(
        (result as { headers: Record<string, string | undefined> }).headers['Authorization'],
      ).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // Request interceptor — CSRF token for safe vs state-changing methods
  // -------------------------------------------------------------------------

  describe('Request interceptor — CSRF token handling', () => {
    it('should NOT attach x-csrf-token for safe methods (GET, HEAD, OPTIONS)', async () => {
      vi.resetModules();
      const { api } = await importRealClient();
      const interceptor = getRequestInterceptor(api);

      for (const method of ['get', 'head', 'options']) {
        const headers: Record<string, string | undefined> = {};
        const config = {
          method,
          headers: new Proxy(headers, {
            set(target, prop, value) {
              target[prop as string] = value as string;
              return true;
            },
            get(target, prop) {
              return target[prop as string];
            },
          }),
        };

        const result = await interceptor(config as unknown as Record<string, unknown>);
        expect(
          (result as { headers: Record<string, string | undefined> }).headers['x-csrf-token'],
        ).toBeUndefined();
      }
    });

    it('should default to GET when method is undefined (safe, no CSRF)', async () => {
      vi.resetModules();
      const { api } = await importRealClient();
      const interceptor = getRequestInterceptor(api);

      const headers: Record<string, string | undefined> = {};
      const config = {
        method: undefined,
        headers: new Proxy(headers, {
          set(target, prop, value) {
            target[prop as string] = value as string;
            return true;
          },
          get(target, prop) {
            return target[prop as string];
          },
        }),
      };

      const result = await interceptor(config as unknown as Record<string, unknown>);
      expect(
        (result as { headers: Record<string, string | undefined> }).headers['x-csrf-token'],
      ).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // Response interceptor — 403 CSRF retry
  // -------------------------------------------------------------------------

  describe('Response interceptor — 403 CSRF retry', () => {
    it('should set _csrfRetry flag and attempt retry on first 403', async () => {
      vi.resetModules();
      const { api } = await importRealClient();
      const interceptor = getResponseInterceptor(api);

      const mockError = {
        response: { status: 403 },
        config: {
          url: '/vault/items',
          method: 'post',
          headers: {} as Record<string, string>,
          _csrfRetry: undefined as boolean | undefined,
        },
      };

      // The loop-guard flag is set synchronously BEFORE the interceptor awaits the
      // CSRF refresh, so it must be true regardless of whether the replayed request
      // ultimately resolves or rejects. Asserting unconditionally (not inside a
      // catch) means the test cannot silently pass with zero assertions if the
      // replay resolves — and it fails if production stops setting `_csrfRetry`,
      // reopening the infinite-retry loop the flag exists to prevent.
      await interceptor(mockError).catch(() => {
        // The replay fails (no server); the rejection is expected and irrelevant.
      });

      expect(mockError.config._csrfRetry).toBe(true);
    });

    it('should reject on second 403 (already retried)', async () => {
      vi.resetModules();
      const { api } = await importRealClient();
      const interceptor = getResponseInterceptor(api);

      const mockError = {
        response: { status: 403 },
        config: {
          url: '/vault/items',
          method: 'post',
          headers: {},
          _csrfRetry: true, // Already retried
        },
      };

      await expect(interceptor(mockError)).rejects.toBeDefined();
    });
  });

  // -------------------------------------------------------------------------
  // Response interceptor — 401 token refresh
  // -------------------------------------------------------------------------

  describe('Response interceptor — 401 token refresh', () => {
    it('should reject for /auth/refresh to prevent infinite loop', async () => {
      vi.resetModules();
      const { api } = await importRealClient();
      const interceptor = getResponseInterceptor(api);

      const mockError = {
        response: { status: 401 },
        config: {
          url: '/auth/refresh',
          method: 'post',
          headers: {},
          _retry: false,
          _csrfRetry: true,
        },
      };

      await expect(interceptor(mockError)).rejects.toBeDefined();
    });

    it('should reject for /auth/logout to prevent infinite loop', async () => {
      vi.resetModules();
      const { api } = await importRealClient();
      const interceptor = getResponseInterceptor(api);

      const mockError = {
        response: { status: 401 },
        config: {
          url: '/auth/logout',
          method: 'post',
          headers: {},
          _retry: false,
          _csrfRetry: true,
        },
      };

      await expect(interceptor(mockError)).rejects.toBeDefined();
    });

    it('should reject when _retry flag is already true', async () => {
      vi.resetModules();
      const { api } = await importRealClient();
      const interceptor = getResponseInterceptor(api);

      const mockError = {
        response: { status: 401 },
        config: {
          url: '/vault/items',
          method: 'get',
          headers: {},
          _retry: true,
          _csrfRetry: true,
        },
      };

      await expect(interceptor(mockError)).rejects.toBeDefined();
    });

    it('should reject non-401/non-403 errors without interception', async () => {
      vi.resetModules();
      const { api } = await importRealClient();
      const interceptor = getResponseInterceptor(api);

      for (const status of [400, 404, 500, 502, 503]) {
        const mockError = {
          response: { status },
          config: {
            url: '/vault/items',
            method: 'get',
            headers: {},
            _csrfRetry: true, // Skip 403 path
          },
        };

        await expect(interceptor(mockError)).rejects.toBeDefined();
      }
    });

    it('should reject when error has no config (originalRequest undefined)', async () => {
      vi.resetModules();
      const { api } = await importRealClient();
      const interceptor = getResponseInterceptor(api);

      const mockError = {
        response: { status: 401 },
        config: undefined,
      };

      await expect(interceptor(mockError)).rejects.toBeDefined();
    });

    it('should reject when error has no response', async () => {
      vi.resetModules();
      const { api } = await importRealClient();
      const interceptor = getResponseInterceptor(api);

      const mockError = {
        response: undefined,
        config: {
          url: '/vault/items',
          method: 'get',
          headers: {},
        },
      };

      await expect(interceptor(mockError)).rejects.toBeDefined();
    });
  });

  // -------------------------------------------------------------------------
  // API instance configuration
  // -------------------------------------------------------------------------

  describe('api instance defaults', () => {
    it('should have baseURL /api/v1, withCredentials true, JSON content type', async () => {
      vi.resetModules();
      const { api } = await importRealClient();

      expect(api.defaults.baseURL).toBe('/api/v1');
      expect(api.defaults.withCredentials).toBe(true);
      expect(api.defaults.headers['Content-Type']).toBe('application/json');
    });
  });

  // -------------------------------------------------------------------------
  // Cross-tab CSRF invalidation via storage event
  // -------------------------------------------------------------------------

  describe('cross-tab CSRF invalidation via storage event', () => {
    it('should register a storage event listener on module load', async () => {
      vi.resetModules();
      const addEventSpy = vi.spyOn(window, 'addEventListener');

      await importRealClient();

      const storageCalls = addEventSpy.mock.calls.filter(([event]) => event === 'storage');
      expect(storageCalls.length).toBeGreaterThan(0);

      addEventSpy.mockRestore();
    });
  });
});

// ===========================================================================
// Section 4: Logger — dev mode behavior and log levels
// ===========================================================================

describe('logger', () => {
  describe('development mode (import.meta.env.DEV = true)', () => {
    it('should call console.error in dev mode', async () => {
      vi.resetModules();
      const { logger } = await import('../src/lib/logger');

      const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
      logger.error('test error message', { detail: 'info' });
      expect(spy).toHaveBeenCalledWith('test error message', { detail: 'info' });
      spy.mockRestore();
    });

    it('should call console.warn in dev mode', async () => {
      vi.resetModules();
      const { logger } = await import('../src/lib/logger');

      const spy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      logger.warn('test warning');
      expect(spy).toHaveBeenCalledWith('test warning');
      spy.mockRestore();
    });

    it('should call console.info in dev mode', async () => {
      vi.resetModules();
      const { logger } = await import('../src/lib/logger');

      const spy = vi.spyOn(console, 'info').mockImplementation(() => {});
      logger.info('test info');
      expect(spy).toHaveBeenCalledWith('test info');
      spy.mockRestore();
    });

    it('should call console.debug in dev mode', async () => {
      vi.resetModules();
      const { logger } = await import('../src/lib/logger');

      const spy = vi.spyOn(console, 'debug').mockImplementation(() => {});
      logger.debug('test debug');
      expect(spy).toHaveBeenCalledWith('test debug');
      spy.mockRestore();
    });

    it('should pass multiple arguments to console methods', async () => {
      vi.resetModules();
      const { logger } = await import('../src/lib/logger');

      const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
      logger.error('msg', 1, { key: 'val' }, [1, 2, 3]);
      expect(spy).toHaveBeenCalledWith('msg', 1, { key: 'val' }, [1, 2, 3]);
      spy.mockRestore();
    });
  });

  describe('logger function signatures', () => {
    // NOTE: a `typeof logger.x === 'function'` test was removed here — it was
    // tautological (true by construction of the module's object literal and
    // impossible to fail unless the import itself fails, which every other test
    // in this block already surfaces). The forwarding behaviour of all four
    // methods is covered by the dev-mode tests above and the no-arg test below.

    it('logger methods should not throw when called with no arguments', async () => {
      vi.resetModules();
      const { logger } = await import('../src/lib/logger');

      const spyError = vi.spyOn(console, 'error').mockImplementation(() => {});
      const spyWarn = vi.spyOn(console, 'warn').mockImplementation(() => {});
      const spyInfo = vi.spyOn(console, 'info').mockImplementation(() => {});
      const spyDebug = vi.spyOn(console, 'debug').mockImplementation(() => {});

      expect(() => logger.error()).not.toThrow();
      expect(() => logger.warn()).not.toThrow();
      expect(() => logger.info()).not.toThrow();
      expect(() => logger.debug()).not.toThrow();

      spyError.mockRestore();
      spyWarn.mockRestore();
      spyInfo.mockRestore();
      spyDebug.mockRestore();
    });
  });
});

// ===========================================================================
// Section 5: OfflineCacheError — edge cases
// These tests import the real module (not the mock) via vi.resetModules
// ===========================================================================

describe('offlineCache — OfflineCacheError edge cases', () => {
  describe('OfflineCacheError class', () => {
    it('should be an instance of Error with correct name', async () => {
      vi.resetModules();
      vi.doUnmock('../src/services/offlineCache');
      const { OfflineCacheError } = await import('../src/services/offlineCache');
      const err = new OfflineCacheError('test', 'unknown');

      expect(err).toBeInstanceOf(Error);
      expect(err.name).toBe('OfflineCacheError');
    });

    it('should preserve stack trace', async () => {
      vi.resetModules();
      vi.doUnmock('../src/services/offlineCache');
      const { OfflineCacheError } = await import('../src/services/offlineCache');
      const err = new OfflineCacheError('test', 'unknown');

      expect(err.stack).toBeDefined();
    });

    it('should support all error types', async () => {
      vi.resetModules();
      vi.doUnmock('../src/services/offlineCache');
      const { OfflineCacheError } = await import('../src/services/offlineCache');

      const types = ['unavailable', 'quota_exceeded', 'permission_denied', 'unknown'] as const;
      for (const type of types) {
        const err = new OfflineCacheError(`Error: ${type}`, type);
        expect(err.type).toBe(type);
        expect(err.message).toBe(`Error: ${type}`);
      }
    });

    it('should accept optional cause parameter', async () => {
      vi.resetModules();
      vi.doUnmock('../src/services/offlineCache');
      const { OfflineCacheError } = await import('../src/services/offlineCache');

      const cause = new TypeError('original error');
      const err = new OfflineCacheError('wrapped', 'unknown', cause);
      expect(err.cause).toBe(cause);
    });

    it('should have undefined cause when not provided', async () => {
      vi.resetModules();
      vi.doUnmock('../src/services/offlineCache');
      const { OfflineCacheError } = await import('../src/services/offlineCache');
      const err = new OfflineCacheError('no cause', 'unknown');
      expect(err.cause).toBeUndefined();
    });
  });
});
