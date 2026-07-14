/**
 * Functional tests for vaultStore CRUD actions.
 *
 * Tests cover: createItem, restoreItem, createFolder, updateFolder, deleteFolder.
 * Each test exercises the real store action, verifies state mutations, and asserts
 * that the correct crypto and API calls were made.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ---------------------------------------------------------------------------
// Polyfill matchMedia -- jsdom does not implement it but the uiStore module
// references it at the top level when first imported.
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

// ---------------------------------------------------------------------------
// Imports (after mocks)
// ---------------------------------------------------------------------------

import { useAuthStore } from '../src/stores/authStore';
import { useVaultStore } from '../src/stores/vaultStore';
import { cryptoService } from '../src/services/crypto/cryptoService';
import {
  createItemApi,
  updateItemApi,
  deleteItemApi,
  restoreItemApi,
  createFolderApi,
  updateFolderApi,
  deleteFolderApi,
  listFoldersApi,
  listTrashApi,
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
    _raw: {} as DecryptedVaultItem['_raw'],
    ...overrides,
  };
}

function makeMockFolder(overrides: Partial<DecryptedFolder> = {}): DecryptedFolder {
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

/** Standard raw API item returned by create/restore endpoints. */
function makeRawItemResponse(overrides: Record<string, unknown> = {}) {
  return {
    _id: 'new-item-1',
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

/** Standard raw API folder returned by create/update endpoints. */
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

// ---------------------------------------------------------------------------
// Initial state snapshots for reset
// ---------------------------------------------------------------------------

const vaultInitialState = {
  items: [],
  trashItems: [],
  folders: [],
  loading: false,
  itemsLoading: false,
  trashLoading: false,
  decryptionFailures: 0,
  lastDecryptionError: null,
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

// ---------------------------------------------------------------------------
// Shared setup
// ---------------------------------------------------------------------------

const mockVaultKey = {} as CryptoKey;

function setupUnlockedVault(): void {
  useAuthStore.setState({ vaultKey: mockVaultKey });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('vaultStore – CRUD actions', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useVaultStore.setState(vaultInitialState);
    useAuthStore.setState(authInitialState);
  });

  // =========================================================================
  // createItem
  // =========================================================================

  describe('createItem', () => {
    it('should throw when vault is locked (no vaultKey)', async () => {
      // vaultKey is null by default from authInitialState
      await expect(
        useVaultStore.getState().createItem('login', 'My Login', { username: 'u' }),
      ).rejects.toThrow('Vault is locked');
    });

    it('should encrypt name and data, call createItemApi, decrypt response, and add to items', async () => {
      setupUnlockedVault();

      // Encrypt mocks: first call is for name, second call is for data
      vi.mocked(cryptoService.encryptData)
        .mockResolvedValueOnce({ encrypted: 'enc-name', iv: 'n-iv', tag: 'n-tag' })
        .mockResolvedValueOnce({ encrypted: 'enc-data', iv: 'd-iv', tag: 'd-tag' });

      vi.mocked(cryptoService.generateSearchHash).mockResolvedValue('mock-search-hash');

      // API response
      vi.mocked(createItemApi).mockResolvedValue({
        data: {
          success: true,
          data: makeRawItemResponse(),
        },
      } as unknown as Awaited<ReturnType<typeof createItemApi>>);

      // Decrypt mocks for the returned item
      vi.mocked(cryptoService.decryptData)
        .mockResolvedValueOnce('My Login')
        .mockResolvedValueOnce(JSON.stringify({ username: 'user1' }));

      await useVaultStore.getState().createItem('login', 'My Login', { username: 'user1' });

      // Verify encryption calls
      expect(cryptoService.encryptData).toHaveBeenCalledTimes(2);
      expect(cryptoService.encryptData).toHaveBeenNthCalledWith(1, 'My Login', mockVaultKey);
      expect(cryptoService.encryptData).toHaveBeenNthCalledWith(
        2,
        JSON.stringify({ username: 'user1' }),
        mockVaultKey,
      );

      // Verify search hash generation
      expect(cryptoService.generateSearchHash).toHaveBeenCalledWith('My Login', mockVaultKey);

      // Verify API call
      expect(createItemApi).toHaveBeenCalledWith({
        itemType: 'login',
        encryptedName: 'enc-name',
        nameIv: 'n-iv',
        nameTag: 'n-tag',
        encryptedData: 'enc-data',
        dataIv: 'd-iv',
        dataTag: 'd-tag',
        searchHash: 'mock-search-hash',
        tags: [],
        favorite: false,
      });

      // Verify the item was added to state
      const { items } = useVaultStore.getState();
      expect(items).toHaveLength(1);
      expect(items[0]!.id).toBe('new-item-1');
      expect(items[0]!.itemType).toBe('login');
      expect(items[0]!.name).toBe('My Login');
    });

    it('should pass folderId, tags, and favorite options to createItemApi', async () => {
      setupUnlockedVault();

      vi.mocked(cryptoService.encryptData).mockResolvedValue({
        encrypted: 'enc',
        iv: 'iv',
        tag: 'tag',
      });
      vi.mocked(cryptoService.generateSearchHash).mockResolvedValue('hash');

      vi.mocked(createItemApi).mockResolvedValue({
        data: {
          success: true,
          data: makeRawItemResponse({
            folderId: 'folder-42',
            tags: ['important', 'work'],
            favorite: true,
          }),
        },
      } as unknown as Awaited<ReturnType<typeof createItemApi>>);

      vi.mocked(cryptoService.decryptData)
        .mockResolvedValueOnce('Decrypted Name')
        .mockResolvedValueOnce(JSON.stringify({ username: '' }));

      await useVaultStore.getState().createItem(
        'login',
        'Name',
        { username: '' },
        {
          folderId: 'folder-42',
          tags: ['important', 'work'],
          favorite: true,
        },
      );

      expect(createItemApi).toHaveBeenCalledWith(
        expect.objectContaining({
          folderId: 'folder-42',
          tags: ['important', 'work'],
          favorite: true,
        }),
      );
    });

    it('should prepend the new item to existing items', async () => {
      setupUnlockedVault();

      // Pre-populate items
      const existing = makeMockItem({ id: 'existing-1', name: 'Existing' });
      useVaultStore.setState({ items: [existing] });

      vi.mocked(cryptoService.encryptData).mockResolvedValue({
        encrypted: 'enc',
        iv: 'iv',
        tag: 'tag',
      });
      vi.mocked(cryptoService.generateSearchHash).mockResolvedValue('hash');

      vi.mocked(createItemApi).mockResolvedValue({
        data: {
          success: true,
          data: makeRawItemResponse({ _id: 'new-item-2' }),
        },
      } as unknown as Awaited<ReturnType<typeof createItemApi>>);

      vi.mocked(cryptoService.decryptData)
        .mockResolvedValueOnce('New Item')
        .mockResolvedValueOnce(JSON.stringify({ username: '' }));

      await useVaultStore.getState().createItem('login', 'New Item', { username: '' });

      const { items } = useVaultStore.getState();
      expect(items).toHaveLength(2);
      // New item is prepended
      expect(items[0]!.id).toBe('new-item-2');
      expect(items[1]!.id).toBe('existing-1');
    });

    it('should not add item to state when API returns success: false', async () => {
      setupUnlockedVault();

      vi.mocked(cryptoService.encryptData).mockResolvedValue({
        encrypted: 'enc',
        iv: 'iv',
        tag: 'tag',
      });
      vi.mocked(cryptoService.generateSearchHash).mockResolvedValue('hash');

      vi.mocked(createItemApi).mockResolvedValue({
        data: {
          success: false,
          error: { code: 'VALIDATION_ERROR', message: 'Bad input' },
        },
      } as unknown as Awaited<ReturnType<typeof createItemApi>>);

      await useVaultStore.getState().createItem('login', 'Name', {});

      expect(useVaultStore.getState().items).toHaveLength(0);
    });

    it('should propagate API errors', async () => {
      setupUnlockedVault();

      vi.mocked(cryptoService.encryptData).mockResolvedValue({
        encrypted: 'enc',
        iv: 'iv',
        tag: 'tag',
      });
      vi.mocked(cryptoService.generateSearchHash).mockResolvedValue('hash');

      vi.mocked(createItemApi).mockRejectedValue(new Error('Network error'));

      await expect(useVaultStore.getState().createItem('login', 'Name', {})).rejects.toThrow(
        'Network error',
      );

      expect(useVaultStore.getState().items).toHaveLength(0);
    });
  });

  // =========================================================================
  // restoreItem
  // =========================================================================

  describe('restoreItem', () => {
    it('should throw when vault is locked', async () => {
      await expect(useVaultStore.getState().restoreItem('item-1')).rejects.toThrow(
        'Vault is locked',
      );
    });

    it('should call restoreItemApi, decrypt, remove from trashItems, and add to items', async () => {
      setupUnlockedVault();

      // Pre-populate trash
      const trashItem = makeMockItem({ id: 'trash-1', name: 'Trashed' });
      useVaultStore.setState({ trashItems: [trashItem], items: [] });

      vi.mocked(restoreItemApi).mockResolvedValue({
        data: {
          success: true,
          data: makeRawItemResponse({ _id: 'trash-1' }),
        },
      } as unknown as Awaited<ReturnType<typeof restoreItemApi>>);

      vi.mocked(cryptoService.decryptData)
        .mockResolvedValueOnce('Restored Item')
        .mockResolvedValueOnce(JSON.stringify({ username: 'restored' }));

      await useVaultStore.getState().restoreItem('trash-1');

      // Verify API call
      expect(restoreItemApi).toHaveBeenCalledWith('trash-1');

      // Verify state changes
      const state = useVaultStore.getState();
      expect(state.trashItems).toHaveLength(0);
      expect(state.items).toHaveLength(1);
      expect(state.items[0]!.id).toBe('trash-1');
      expect(state.items[0]!.name).toBe('Restored Item');
    });

    it('should append restored item to existing items', async () => {
      setupUnlockedVault();

      const existing = makeMockItem({ id: 'existing-1' });
      const trashItem = makeMockItem({ id: 'trash-1' });
      useVaultStore.setState({ items: [existing], trashItems: [trashItem] });

      vi.mocked(restoreItemApi).mockResolvedValue({
        data: {
          success: true,
          data: makeRawItemResponse({ _id: 'trash-1' }),
        },
      } as unknown as Awaited<ReturnType<typeof restoreItemApi>>);

      vi.mocked(cryptoService.decryptData)
        .mockResolvedValueOnce('Restored')
        .mockResolvedValueOnce(JSON.stringify({ username: '' }));

      await useVaultStore.getState().restoreItem('trash-1');

      const { items } = useVaultStore.getState();
      expect(items).toHaveLength(2);
      // Restored item is appended
      expect(items[0]!.id).toBe('existing-1');
      expect(items[1]!.id).toBe('trash-1');
    });

    it('should not modify state when API returns success: false', async () => {
      setupUnlockedVault();

      const trashItem = makeMockItem({ id: 'trash-1' });
      useVaultStore.setState({ trashItems: [trashItem], items: [] });

      vi.mocked(restoreItemApi).mockResolvedValue({
        data: {
          success: false,
          error: { code: 'NOT_FOUND', message: 'Item not found' },
        },
      } as unknown as Awaited<ReturnType<typeof restoreItemApi>>);

      await useVaultStore.getState().restoreItem('trash-1');

      const state = useVaultStore.getState();
      // State should be unchanged
      expect(state.trashItems).toHaveLength(1);
      expect(state.items).toHaveLength(0);
    });

    it('should propagate API errors', async () => {
      setupUnlockedVault();

      vi.mocked(restoreItemApi).mockRejectedValue(new Error('Server error'));

      await expect(useVaultStore.getState().restoreItem('item-1')).rejects.toThrow('Server error');
    });
  });

  // =========================================================================
  // createFolder
  // =========================================================================

  describe('createFolder', () => {
    it('should throw when vault is locked', async () => {
      await expect(useVaultStore.getState().createFolder('My Folder')).rejects.toThrow(
        'Vault is locked',
      );
    });

    it('should encrypt name, compute sortOrder, call createFolderApi, decrypt and add to folders', async () => {
      setupUnlockedVault();

      vi.mocked(cryptoService.encryptData).mockResolvedValue({
        encrypted: 'enc-folder-name',
        iv: 'fn-iv',
        tag: 'fn-tag',
      });

      vi.mocked(createFolderApi).mockResolvedValue({
        data: {
          success: true,
          data: makeRawFolderResponse({ _id: 'folder-new', sortOrder: 0 }),
        },
      } as unknown as Awaited<ReturnType<typeof createFolderApi>>);

      vi.mocked(cryptoService.decryptData).mockResolvedValueOnce('My Folder');

      await useVaultStore.getState().createFolder('My Folder');

      // Verify encryption
      expect(cryptoService.encryptData).toHaveBeenCalledWith('My Folder', mockVaultKey);

      // Verify API call - sortOrder is max(-1) + 1 = 0 when no folders exist
      expect(createFolderApi).toHaveBeenCalledWith({
        encryptedName: 'enc-folder-name',
        nameIv: 'fn-iv',
        nameTag: 'fn-tag',
        sortOrder: 0,
      });

      // Verify state
      const { folders } = useVaultStore.getState();
      expect(folders).toHaveLength(1);
      expect(folders[0]!.id).toBe('folder-new');
      expect(folders[0]!.name).toBe('My Folder');
    });

    it('should compute sortOrder as max existing + 1', async () => {
      setupUnlockedVault();

      // Pre-populate folders with various sort orders
      useVaultStore.setState({
        folders: [
          makeMockFolder({ id: 'f1', sortOrder: 3 }),
          makeMockFolder({ id: 'f2', sortOrder: 7 }),
          makeMockFolder({ id: 'f3', sortOrder: 2 }),
        ],
      });

      vi.mocked(cryptoService.encryptData).mockResolvedValue({
        encrypted: 'enc',
        iv: 'iv',
        tag: 'tag',
      });

      vi.mocked(createFolderApi).mockResolvedValue({
        data: {
          success: true,
          data: makeRawFolderResponse({ _id: 'folder-new', sortOrder: 8 }),
        },
      } as unknown as Awaited<ReturnType<typeof createFolderApi>>);

      vi.mocked(cryptoService.decryptData).mockResolvedValueOnce('New Folder');

      await useVaultStore.getState().createFolder('New Folder');

      // Max sortOrder among existing is 7, so new should be 8
      expect(createFolderApi).toHaveBeenCalledWith(expect.objectContaining({ sortOrder: 8 }));
    });

    it('should pass parentId, icon, and color options', async () => {
      setupUnlockedVault();

      vi.mocked(cryptoService.encryptData).mockResolvedValue({
        encrypted: 'enc',
        iv: 'iv',
        tag: 'tag',
      });

      vi.mocked(createFolderApi).mockResolvedValue({
        data: {
          success: true,
          data: makeRawFolderResponse({
            _id: 'folder-new',
            parentId: 'parent-1',
            icon: 'star',
            color: '#ff0000',
          }),
        },
      } as unknown as Awaited<ReturnType<typeof createFolderApi>>);

      vi.mocked(cryptoService.decryptData).mockResolvedValueOnce('Sub Folder');

      await useVaultStore
        .getState()
        .createFolder('Sub Folder', { parentId: 'parent-1', icon: 'star', color: '#ff0000' });

      expect(createFolderApi).toHaveBeenCalledWith(
        expect.objectContaining({
          parentId: 'parent-1',
          icon: 'star',
          color: '#ff0000',
        }),
      );
    });

    it('should append the new folder to existing folders', async () => {
      setupUnlockedVault();

      const existing = makeMockFolder({ id: 'existing-folder' });
      useVaultStore.setState({ folders: [existing] });

      vi.mocked(cryptoService.encryptData).mockResolvedValue({
        encrypted: 'enc',
        iv: 'iv',
        tag: 'tag',
      });

      vi.mocked(createFolderApi).mockResolvedValue({
        data: {
          success: true,
          data: makeRawFolderResponse({ _id: 'new-folder' }),
        },
      } as unknown as Awaited<ReturnType<typeof createFolderApi>>);

      vi.mocked(cryptoService.decryptData).mockResolvedValueOnce('New Folder');

      await useVaultStore.getState().createFolder('New Folder');

      const { folders } = useVaultStore.getState();
      expect(folders).toHaveLength(2);
      expect(folders[0]!.id).toBe('existing-folder');
      expect(folders[1]!.id).toBe('new-folder');
    });

    it('should not add folder when API returns success: false', async () => {
      setupUnlockedVault();

      vi.mocked(cryptoService.encryptData).mockResolvedValue({
        encrypted: 'enc',
        iv: 'iv',
        tag: 'tag',
      });

      vi.mocked(createFolderApi).mockResolvedValue({
        data: {
          success: false,
          error: { code: 'VALIDATION_ERROR', message: 'Bad input' },
        },
      } as unknown as Awaited<ReturnType<typeof createFolderApi>>);

      await useVaultStore.getState().createFolder('Bad Folder');

      expect(useVaultStore.getState().folders).toHaveLength(0);
    });

    it('should propagate API errors', async () => {
      setupUnlockedVault();

      vi.mocked(cryptoService.encryptData).mockResolvedValue({
        encrypted: 'enc',
        iv: 'iv',
        tag: 'tag',
      });

      vi.mocked(createFolderApi).mockRejectedValue(new Error('Network failure'));

      await expect(useVaultStore.getState().createFolder('Folder')).rejects.toThrow(
        'Network failure',
      );
    });
  });

  // =========================================================================
  // updateFolder
  // =========================================================================

  describe('updateFolder', () => {
    it('should throw when vault is locked', async () => {
      await expect(useVaultStore.getState().updateFolder('folder-1', 'Renamed')).rejects.toThrow(
        'Vault is locked',
      );
    });

    it('should encrypt name, call updateFolderApi, decrypt response, and replace folder in state', async () => {
      setupUnlockedVault();

      const existing = makeMockFolder({ id: 'folder-1', name: 'Old Name', sortOrder: 5 });
      useVaultStore.setState({ folders: [existing] });

      vi.mocked(cryptoService.encryptData).mockResolvedValue({
        encrypted: 'enc-new-name',
        iv: 'new-iv',
        tag: 'new-tag',
      });

      vi.mocked(updateFolderApi).mockResolvedValue({
        data: {
          success: true,
          data: makeRawFolderResponse({ _id: 'folder-1', sortOrder: 5 }),
        },
      } as unknown as Awaited<ReturnType<typeof updateFolderApi>>);

      vi.mocked(cryptoService.decryptData).mockResolvedValueOnce('Renamed Folder');

      await useVaultStore.getState().updateFolder('folder-1', 'Renamed Folder');

      // Verify encryption
      expect(cryptoService.encryptData).toHaveBeenCalledWith('Renamed Folder', mockVaultKey);

      // Verify API call
      expect(updateFolderApi).toHaveBeenCalledWith('folder-1', {
        encryptedName: 'enc-new-name',
        nameIv: 'new-iv',
        nameTag: 'new-tag',
      });

      // Verify state replacement
      const { folders } = useVaultStore.getState();
      expect(folders).toHaveLength(1);
      expect(folders[0]!.id).toBe('folder-1');
      expect(folders[0]!.name).toBe('Renamed Folder');
    });

    it('should pass color and sortOrder options to updateFolderApi', async () => {
      setupUnlockedVault();

      useVaultStore.setState({ folders: [makeMockFolder({ id: 'folder-1' })] });

      vi.mocked(cryptoService.encryptData).mockResolvedValue({
        encrypted: 'enc',
        iv: 'iv',
        tag: 'tag',
      });

      vi.mocked(updateFolderApi).mockResolvedValue({
        data: {
          success: true,
          data: makeRawFolderResponse({ _id: 'folder-1', color: '#0000ff', sortOrder: 10 }),
        },
      } as unknown as Awaited<ReturnType<typeof updateFolderApi>>);

      vi.mocked(cryptoService.decryptData).mockResolvedValueOnce('Folder');

      await useVaultStore
        .getState()
        .updateFolder('folder-1', 'Folder', { color: '#0000ff', sortOrder: 10 });

      expect(updateFolderApi).toHaveBeenCalledWith('folder-1', {
        encryptedName: 'enc',
        nameIv: 'iv',
        nameTag: 'tag',
        color: '#0000ff',
        sortOrder: 10,
      });
    });

    it('should only replace the target folder, leaving others unchanged', async () => {
      setupUnlockedVault();

      const folder1 = makeMockFolder({ id: 'folder-1', name: 'Folder A' });
      const folder2 = makeMockFolder({ id: 'folder-2', name: 'Folder B' });
      useVaultStore.setState({ folders: [folder1, folder2] });

      vi.mocked(cryptoService.encryptData).mockResolvedValue({
        encrypted: 'enc',
        iv: 'iv',
        tag: 'tag',
      });

      vi.mocked(updateFolderApi).mockResolvedValue({
        data: {
          success: true,
          data: makeRawFolderResponse({ _id: 'folder-1' }),
        },
      } as unknown as Awaited<ReturnType<typeof updateFolderApi>>);

      vi.mocked(cryptoService.decryptData).mockResolvedValueOnce('Updated A');

      await useVaultStore.getState().updateFolder('folder-1', 'Updated A');

      const { folders } = useVaultStore.getState();
      expect(folders).toHaveLength(2);
      expect(folders[0]!.name).toBe('Updated A');
      expect(folders[1]!.name).toBe('Folder B');
    });

    it('should not modify state when API returns success: false', async () => {
      setupUnlockedVault();

      const folder = makeMockFolder({ id: 'folder-1', name: 'Original' });
      useVaultStore.setState({ folders: [folder] });

      vi.mocked(cryptoService.encryptData).mockResolvedValue({
        encrypted: 'enc',
        iv: 'iv',
        tag: 'tag',
      });

      vi.mocked(updateFolderApi).mockResolvedValue({
        data: {
          success: false,
          error: { code: 'NOT_FOUND', message: 'Folder not found' },
        },
      } as unknown as Awaited<ReturnType<typeof updateFolderApi>>);

      await useVaultStore.getState().updateFolder('folder-1', 'New Name');

      // State unchanged
      expect(useVaultStore.getState().folders[0]!.name).toBe('Original');
    });

    it('should propagate API errors', async () => {
      setupUnlockedVault();

      useVaultStore.setState({ folders: [makeMockFolder({ id: 'folder-1' })] });

      vi.mocked(cryptoService.encryptData).mockResolvedValue({
        encrypted: 'enc',
        iv: 'iv',
        tag: 'tag',
      });

      vi.mocked(updateFolderApi).mockRejectedValue(new Error('Update failed'));

      await expect(useVaultStore.getState().updateFolder('folder-1', 'Name')).rejects.toThrow(
        'Update failed',
      );
    });
  });

  // =========================================================================
  // deleteFolder
  // =========================================================================

  describe('deleteFolder', () => {
    it('should call deleteFolderApi and remove the folder from state', async () => {
      const folder1 = makeMockFolder({ id: 'folder-1', name: 'Folder A' });
      const folder2 = makeMockFolder({ id: 'folder-2', name: 'Folder B' });
      useVaultStore.setState({ folders: [folder1, folder2] });

      vi.mocked(deleteFolderApi).mockResolvedValue({
        data: { success: true, data: null },
      } as unknown as Awaited<ReturnType<typeof deleteFolderApi>>);

      await useVaultStore.getState().deleteFolder('folder-1');

      expect(deleteFolderApi).toHaveBeenCalledWith('folder-1', undefined);

      const { folders } = useVaultStore.getState();
      expect(folders).toHaveLength(1);
      expect(folders[0]!.id).toBe('folder-2');
    });

    it('should clear folderId on items that belonged to the deleted folder', async () => {
      const folder = makeMockFolder({ id: 'folder-1' });
      const item1 = makeMockItem({ id: 'item-1', folderId: 'folder-1' });
      const item2 = makeMockItem({ id: 'item-2', folderId: 'folder-2' });
      const item3 = makeMockItem({ id: 'item-3' }); // no folderId
      useVaultStore.setState({
        folders: [folder],
        items: [item1, item2, item3],
      });

      vi.mocked(deleteFolderApi).mockResolvedValue({
        data: { success: true, data: null },
      } as unknown as Awaited<ReturnType<typeof deleteFolderApi>>);

      await useVaultStore.getState().deleteFolder('folder-1');

      const { items } = useVaultStore.getState();
      // item-1 should have folderId cleared
      expect(items.find((i) => i.id === 'item-1')!.folderId).toBeUndefined();
      // item-2 should be unchanged
      expect(items.find((i) => i.id === 'item-2')!.folderId).toBe('folder-2');
      // item-3 should still have no folderId
      expect(items.find((i) => i.id === 'item-3')!.folderId).toBeUndefined();
    });

    it('should reset selectedFolder when the deleted folder was selected', async () => {
      const folder = makeMockFolder({ id: 'folder-1' });
      useVaultStore.setState({
        folders: [folder],
        selectedFolder: 'folder-1',
      });

      vi.mocked(deleteFolderApi).mockResolvedValue({
        data: { success: true, data: null },
      } as unknown as Awaited<ReturnType<typeof deleteFolderApi>>);

      await useVaultStore.getState().deleteFolder('folder-1');

      expect(useVaultStore.getState().selectedFolder).toBeNull();
    });

    it('should NOT reset selectedFolder when a different folder was selected', async () => {
      const folder = makeMockFolder({ id: 'folder-1' });
      useVaultStore.setState({
        folders: [folder],
        selectedFolder: 'folder-other',
      });

      vi.mocked(deleteFolderApi).mockResolvedValue({
        data: { success: true, data: null },
      } as unknown as Awaited<ReturnType<typeof deleteFolderApi>>);

      await useVaultStore.getState().deleteFolder('folder-1');

      expect(useVaultStore.getState().selectedFolder).toBe('folder-other');
    });

    it('should pass the action parameter to deleteFolderApi', async () => {
      setupUnlockedVault();
      const folder = makeMockFolder({ id: 'folder-1', name: 'Folder A' });
      useVaultStore.setState({ folders: [folder] });

      vi.mocked(deleteFolderApi).mockResolvedValue({
        data: { success: true, data: null },
      } as unknown as Awaited<ReturnType<typeof deleteFolderApi>>);
      vi.mocked(listTrashApi).mockResolvedValue({
        data: {
          success: true,
          data: [],
          pagination: { page: 1, limit: 200, total: 0, totalPages: 0 },
        },
      } as unknown as Awaited<ReturnType<typeof listTrashApi>>);

      await useVaultStore.getState().deleteFolder('folder-1', 'delete');

      expect(deleteFolderApi).toHaveBeenCalledWith('folder-1', 'delete');
    });

    it('should pass move action to deleteFolderApi', async () => {
      const folder = makeMockFolder({ id: 'folder-1', name: 'Folder A' });
      useVaultStore.setState({ folders: [folder] });

      vi.mocked(deleteFolderApi).mockResolvedValue({
        data: { success: true, data: null },
      } as unknown as Awaited<ReturnType<typeof deleteFolderApi>>);

      await useVaultStore.getState().deleteFolder('folder-1', 'move');

      expect(deleteFolderApi).toHaveBeenCalledWith('folder-1', 'move');
    });

    it('should propagate API errors', async () => {
      vi.mocked(deleteFolderApi).mockRejectedValue(new Error('Delete failed'));

      await expect(useVaultStore.getState().deleteFolder('folder-1')).rejects.toThrow(
        'Delete failed',
      );
    });

    it('should handle all three state mutations atomically', async () => {
      const folder = makeMockFolder({ id: 'folder-del' });
      const item = makeMockItem({ id: 'item-in-folder', folderId: 'folder-del' });
      useVaultStore.setState({
        folders: [folder],
        items: [item],
        selectedFolder: 'folder-del',
      });

      vi.mocked(deleteFolderApi).mockResolvedValue({
        data: { success: true, data: null },
      } as unknown as Awaited<ReturnType<typeof deleteFolderApi>>);

      await useVaultStore.getState().deleteFolder('folder-del');

      const state = useVaultStore.getState();
      expect(state.folders).toHaveLength(0);
      expect(state.items[0]!.folderId).toBeUndefined();
      expect(state.selectedFolder).toBeNull();
    });

    it('should remove items from active list when action is delete', async () => {
      setupUnlockedVault();
      const folder = makeMockFolder({ id: 'folder-1' });
      const item1 = makeMockItem({ id: 'item-1', folderId: 'folder-1' });
      const item2 = makeMockItem({ id: 'item-2', folderId: 'folder-2' });
      const item3 = makeMockItem({ id: 'item-3' }); // no folderId
      useVaultStore.setState({
        folders: [folder],
        items: [item1, item2, item3],
      });

      vi.mocked(deleteFolderApi).mockResolvedValue({
        data: { success: true, data: null },
      } as unknown as Awaited<ReturnType<typeof deleteFolderApi>>);
      vi.mocked(listTrashApi).mockResolvedValue({
        data: {
          success: true,
          data: [],
          pagination: { page: 1, limit: 200, total: 0, totalPages: 0 },
        },
      } as unknown as Awaited<ReturnType<typeof listTrashApi>>);

      await useVaultStore.getState().deleteFolder('folder-1', 'delete');

      const { items } = useVaultStore.getState();
      // item-1 should be removed (it belonged to the deleted folder)
      expect(items.find((i) => i.id === 'item-1')).toBeUndefined();
      // item-2 and item-3 should remain unchanged
      expect(items).toHaveLength(2);
      expect(items.find((i) => i.id === 'item-2')!.folderId).toBe('folder-2');
      expect(items.find((i) => i.id === 'item-3')!.folderId).toBeUndefined();
    });

    it('should clear folderId (not remove) when action is move', async () => {
      const folder = makeMockFolder({ id: 'folder-1' });
      const item1 = makeMockItem({ id: 'item-1', folderId: 'folder-1' });
      const item2 = makeMockItem({ id: 'item-2', folderId: 'folder-2' });
      useVaultStore.setState({
        folders: [folder],
        items: [item1, item2],
      });

      vi.mocked(deleteFolderApi).mockResolvedValue({
        data: { success: true, data: null },
      } as unknown as Awaited<ReturnType<typeof deleteFolderApi>>);

      await useVaultStore.getState().deleteFolder('folder-1', 'move');

      const { items } = useVaultStore.getState();
      // Both items should remain in the list
      expect(items).toHaveLength(2);
      // item-1 should have folderId cleared (moved to root)
      expect(items.find((i) => i.id === 'item-1')!.folderId).toBeUndefined();
      // item-2 should be unchanged
      expect(items.find((i) => i.id === 'item-2')!.folderId).toBe('folder-2');
    });

    it('should refresh trash items after action delete', async () => {
      setupUnlockedVault();
      const folder = makeMockFolder({ id: 'folder-1' });
      useVaultStore.setState({ folders: [folder], items: [] });

      vi.mocked(deleteFolderApi).mockResolvedValue({
        data: { success: true, data: null },
      } as unknown as Awaited<ReturnType<typeof deleteFolderApi>>);
      vi.mocked(listTrashApi).mockResolvedValue({
        data: {
          success: true,
          data: [],
          pagination: { page: 1, limit: 200, total: 0, totalPages: 0 },
        },
      } as unknown as Awaited<ReturnType<typeof listTrashApi>>);

      await useVaultStore.getState().deleteFolder('folder-1', 'delete');
      // Wait for fire-and-forget fetchTrashItems to complete
      await new Promise((resolve) => setTimeout(resolve, 0));

      // fetchTrashItems calls listTrashApi internally
      expect(listTrashApi).toHaveBeenCalled();
    });

    it('should NOT refresh trash items when action is move', async () => {
      const folder = makeMockFolder({ id: 'folder-1' });
      useVaultStore.setState({ folders: [folder], items: [] });

      vi.mocked(deleteFolderApi).mockResolvedValue({
        data: { success: true, data: null },
      } as unknown as Awaited<ReturnType<typeof deleteFolderApi>>);

      await useVaultStore.getState().deleteFolder('folder-1', 'move');

      expect(listTrashApi).not.toHaveBeenCalled();
    });
  });

  // =========================================================================
  // deleteItem
  // =========================================================================

  describe('deleteItem', () => {
    it('should remove the item from items after soft-delete', async () => {
      const item1 = makeMockItem({ id: 'item-1', name: 'Login 1' });
      const item2 = makeMockItem({ id: 'item-2', name: 'Login 2' });
      useVaultStore.setState({ items: [item1, item2] });

      vi.mocked(deleteItemApi).mockResolvedValue({
        data: { success: true, message: 'Item moved to trash' },
      } as unknown as Awaited<ReturnType<typeof deleteItemApi>>);

      await useVaultStore.getState().deleteItem('item-1');

      expect(deleteItemApi).toHaveBeenCalledWith('item-1');
      const { items } = useVaultStore.getState();
      expect(items).toHaveLength(1);
      expect(items[0]!.id).toBe('item-2');
    });

    it('should add deleted item to trashItems when trash has been fetched', async () => {
      const item = makeMockItem({ id: 'item-1', name: 'My Login' });
      const existingTrash = makeMockItem({ id: 'trash-old', name: 'Old Trash' });
      useVaultStore.setState({ items: [item], trashItems: [existingTrash] });

      vi.mocked(deleteItemApi).mockResolvedValue({
        data: { success: true, message: 'Item moved to trash' },
      } as unknown as Awaited<ReturnType<typeof deleteItemApi>>);

      await useVaultStore.getState().deleteItem('item-1');

      const state = useVaultStore.getState();
      expect(state.items).toHaveLength(0);
      expect(state.trashItems).toHaveLength(2);
      expect(state.trashItems[0]!.id).toBe('trash-old');
      expect(state.trashItems[1]!.id).toBe('item-1');
      expect(state.trashItems[1]!.deletedAt).toBeDefined();
    });

    it('should NOT add deleted item to trashItems when trash has not been fetched (empty)', async () => {
      const item = makeMockItem({ id: 'item-1', name: 'My Login' });
      useVaultStore.setState({ items: [item], trashItems: [] });

      vi.mocked(deleteItemApi).mockResolvedValue({
        data: { success: true, message: 'Item moved to trash' },
      } as unknown as Awaited<ReturnType<typeof deleteItemApi>>);

      await useVaultStore.getState().deleteItem('item-1');

      const state = useVaultStore.getState();
      expect(state.items).toHaveLength(0);
      expect(state.trashItems).toHaveLength(0);
    });

    it('should propagate API errors without modifying state', async () => {
      const item = makeMockItem({ id: 'item-1', name: 'My Login' });
      useVaultStore.setState({ items: [item], trashItems: [] });

      vi.mocked(deleteItemApi).mockRejectedValue(new Error('Network error'));

      await expect(useVaultStore.getState().deleteItem('item-1')).rejects.toThrow('Network error');

      // State should remain unchanged
      const state = useVaultStore.getState();
      expect(state.items).toHaveLength(1);
      expect(state.items[0]!.id).toBe('item-1');
    });
  });

  // -------------------------------------------------------------------------
  // Sort defaults alignment (client matches server: updatedAt/desc)
  // -------------------------------------------------------------------------
  describe('sort defaults', () => {
    it('should default to dateModified/desc matching server defaults', () => {
      useVaultStore.getState().clearStore();
      const state = useVaultStore.getState();
      expect(state.sortBy).toBe('dateModified');
      expect(state.sortOrder).toBe('desc');
    });
  });

  // -------------------------------------------------------------------------
  // Decryption failures tracking
  // -------------------------------------------------------------------------
  describe('decryptionFailures', () => {
    it('should reset decryptionFailures on clearStore', () => {
      useVaultStore.setState({ decryptionFailures: 5 });
      useVaultStore.getState().clearStore();
      expect(useVaultStore.getState().decryptionFailures).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // Generation gating: a mutation whose network round-trip resolves AFTER a
  // lock/logout (clearStore) must not write decrypted plaintext back into the
  // just-cleared store. clearStore() bumps a mutation generation captured at
  // the start of each mutation; the post-await set() is skipped when it drifts.
  // -------------------------------------------------------------------------
  describe('mutation write gating on lock/logout', () => {
    /** Returns a mock whose returned promise is resolved via the captured fn. */
    function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
      let resolve!: (value: T) => void;
      const promise = new Promise<T>((r) => {
        resolve = r;
      });
      return { promise, resolve };
    }

    it('createItem: does not write the item back after clearStore() mid-flight', async () => {
      setupUnlockedVault();

      vi.mocked(cryptoService.encryptData).mockResolvedValue({
        encrypted: 'enc',
        iv: 'iv',
        tag: 'tag',
      });
      vi.mocked(cryptoService.generateSearchHash).mockResolvedValue('hash');

      const api = deferred<Awaited<ReturnType<typeof createItemApi>>>();
      vi.mocked(createItemApi).mockReturnValue(api.promise);

      vi.mocked(cryptoService.decryptData)
        .mockResolvedValueOnce('My Login')
        .mockResolvedValueOnce(JSON.stringify({ username: 'user1' }));

      const promise = useVaultStore
        .getState()
        .createItem('login', 'My Login', { username: 'user1' });

      // Simulate lock/logout mid-flight: empties the store and bumps the
      // mutation generation captured before the await.
      useVaultStore.getState().clearStore();

      api.resolve({
        data: { success: true, data: makeRawItemResponse() },
      } as unknown as Awaited<ReturnType<typeof createItemApi>>);
      await promise;

      // The decrypted item must NOT have been written back into the store.
      expect(useVaultStore.getState().items).toHaveLength(0);
    });

    it('restoreItem: does not write the item back after clearStore() mid-flight', async () => {
      setupUnlockedVault();
      useVaultStore.setState({ trashItems: [makeMockItem({ id: 'trash-1' })] });

      const api = deferred<Awaited<ReturnType<typeof restoreItemApi>>>();
      vi.mocked(restoreItemApi).mockReturnValue(api.promise);

      vi.mocked(cryptoService.decryptData)
        .mockResolvedValueOnce('Restored')
        .mockResolvedValueOnce(JSON.stringify({ username: 'restored' }));

      const promise = useVaultStore.getState().restoreItem('trash-1');

      useVaultStore.getState().clearStore();

      api.resolve({
        data: { success: true, data: makeRawItemResponse({ _id: 'trash-1' }) },
      } as unknown as Awaited<ReturnType<typeof restoreItemApi>>);
      await promise;

      const state = useVaultStore.getState();
      expect(state.items).toHaveLength(0);
      expect(state.trashItems).toHaveLength(0);
    });

    it('createFolder: does not write the folder back after clearStore() mid-flight', async () => {
      setupUnlockedVault();

      vi.mocked(cryptoService.encryptData).mockResolvedValue({
        encrypted: 'enc',
        iv: 'iv',
        tag: 'tag',
      });

      const api = deferred<Awaited<ReturnType<typeof createFolderApi>>>();
      vi.mocked(createFolderApi).mockReturnValue(api.promise);
      vi.mocked(cryptoService.decryptData).mockResolvedValueOnce('My Folder');

      const promise = useVaultStore.getState().createFolder('My Folder');

      useVaultStore.getState().clearStore();

      api.resolve({
        data: { success: true, data: makeRawFolderResponse({ _id: 'folder-new' }) },
      } as unknown as Awaited<ReturnType<typeof createFolderApi>>);
      await promise;

      expect(useVaultStore.getState().folders).toHaveLength(0);
    });

    it('updateItem: does not overwrite a fresh-session item when superseded by clearStore()', async () => {
      setupUnlockedVault();
      // Pre-existing item the update targets.
      useVaultStore.setState({ items: [makeMockItem({ id: 'item-1', name: 'Original' })] });

      vi.mocked(cryptoService.encryptData).mockResolvedValue({
        encrypted: 'enc',
        iv: 'iv',
        tag: 'tag',
      });
      vi.mocked(cryptoService.generateSearchHash).mockResolvedValue('hash');

      const api = deferred<Awaited<ReturnType<typeof updateItemApi>>>();
      vi.mocked(updateItemApi).mockReturnValue(api.promise);

      vi.mocked(cryptoService.decryptData)
        .mockResolvedValueOnce('Stale Name')
        .mockResolvedValueOnce(JSON.stringify({ username: 'stale' }));

      const promise = useVaultStore
        .getState()
        .updateItem('item-1', 'Stale Name', { username: 'stale' });

      // Lock/logout mid-flight, then a fresh session repopulates the same id.
      useVaultStore.getState().clearStore();
      useVaultStore.setState({ items: [makeMockItem({ id: 'item-1', name: 'Fresh Session' })] });

      api.resolve({
        data: { success: true, data: makeRawItemResponse({ _id: 'item-1' }) },
      } as unknown as Awaited<ReturnType<typeof updateItemApi>>);
      await promise;

      // The stale in-flight update must not clobber the fresh-session item.
      const { items } = useVaultStore.getState();
      expect(items).toHaveLength(1);
      expect(items[0]!.name).toBe('Fresh Session');
    });

    it('updateFolder: does not overwrite a fresh-session folder when superseded by clearStore()', async () => {
      setupUnlockedVault();
      useVaultStore.setState({ folders: [makeMockFolder({ id: 'folder-1', name: 'Original' })] });

      vi.mocked(cryptoService.encryptData).mockResolvedValue({
        encrypted: 'enc',
        iv: 'iv',
        tag: 'tag',
      });

      const api = deferred<Awaited<ReturnType<typeof updateFolderApi>>>();
      vi.mocked(updateFolderApi).mockReturnValue(api.promise);
      vi.mocked(cryptoService.decryptData).mockResolvedValueOnce('Stale Folder');

      const promise = useVaultStore.getState().updateFolder('folder-1', 'Stale Folder');

      useVaultStore.getState().clearStore();
      useVaultStore.setState({
        folders: [makeMockFolder({ id: 'folder-1', name: 'Fresh Session' })],
      });

      api.resolve({
        data: { success: true, data: makeRawFolderResponse({ _id: 'folder-1' }) },
      } as unknown as Awaited<ReturnType<typeof updateFolderApi>>);
      await promise;

      const { folders } = useVaultStore.getState();
      expect(folders).toHaveLength(1);
      expect(folders[0]!.name).toBe('Fresh Session');
    });
  });

  // -------------------------------------------------------------------------
  // Fetch dedup-guard ownership: a stale fetch invocation superseded by
  // clearStore() must not null the newer fetch's in-flight guard (which would
  // permit a duplicate concurrent fetch).
  // -------------------------------------------------------------------------
  describe('fetch dedup-guard ownership on clearStore', () => {
    it('fetchFolders: a superseded fetch does not clobber the newer fetch guard', async () => {
      setupUnlockedVault();

      // Each listFoldersApi call parks on its own deferred promise so we can
      // orchestrate the interleaving precisely.
      const resolvers: ((value: unknown) => void)[] = [];
      vi.mocked(listFoldersApi).mockImplementation(
        () =>
          new Promise((resolve) => {
            resolvers.push(resolve);
          }) as unknown as ReturnType<typeof listFoldersApi>,
      );

      // Fetch A starts and is in flight (owns the guard).
      const fetchA = useVaultStore.getState().fetchFolders();
      expect(listFoldersApi).toHaveBeenCalledTimes(1);

      // Lock/logout mid-flight: nulls the guard and bumps the generation.
      useVaultStore.getState().clearStore();

      // Fetch B starts fresh (guard was null), now owns the guard.
      const fetchB = useVaultStore.getState().fetchFolders();
      expect(listFoldersApi).toHaveBeenCalledTimes(2);

      // Resolve A: it is superseded, so it returns early and its finally must
      // NOT null B's guard.
      resolvers[0]!({ data: { success: true, data: [] } });
      await fetchA;

      // A duplicate fetch now must dedup onto B's still-live guard — no new
      // network call. Without the ownership check, A's finally would have
      // nulled the guard and this call would fire a third request. (Identity
      // can't be asserted: `fetchFolders` is async, so it wraps the in-flight
      // guard in a fresh promise per call — the call count is the real proof.)
      const fetchC = useVaultStore.getState().fetchFolders();
      expect(listFoldersApi).toHaveBeenCalledTimes(2);

      // Clean up: resolve B (and therefore C) so no promise dangles.
      resolvers[1]!({ data: { success: true, data: [] } });
      await fetchB;
      await fetchC;
    });
  });
});
