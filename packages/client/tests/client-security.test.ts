/**
 * Tests for client-side security & crypto fixes (Phase 4, Tasks 4.1–4.4, 4.7–4.9, 4.13–4.14).
 *
 * 4.1 — Warn user when falling back to unencrypted storage
 * 4.2 — Handle single corrupted vault item gracefully (Promise.allSettled)
 * 4.3 — Validate encrypted storage buffer format
 * 4.4 — Add CSRF token cross-tab synchronization
 * 4.7 — Clear authKey in all code paths (register and login)
 * 4.8 — Add error handlers to VaultPage async operations
 * 4.9 — Clear master password from form state during 2FA
 * 4.13 — Sanitize error messages to avoid leaking JWT structure
 * 4.14 — Cache CryptoKey import in encrypted storage
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve as pathResolve } from 'node:path';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const clientSrcDir = pathResolve(__dirname, '../src');

// ---------------------------------------------------------------------------
// Polyfill matchMedia for jsdom
// ---------------------------------------------------------------------------

const { mockDecryptData, mockListItemsApi, mockListTrashApi, mockListFoldersApi } = vi.hoisted(
  () => {
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

    return {
      mockDecryptData: vi.fn(),
      mockListItemsApi: vi.fn(),
      mockListTrashApi: vi.fn(),
      mockListFoldersApi: vi.fn(),
    };
  },
);

// ==========================================================================
// Mocks for stores (must be declared before imports)
// ==========================================================================

vi.mock('../src/stores/encryptedStorage', () => ({
  encryptedStorage: {
    getItem: vi.fn().mockResolvedValue(null),
    setItem: vi.fn().mockResolvedValue(undefined),
    removeItem: vi.fn(),
  },
  isStorageDegraded: vi.fn().mockReturnValue(false),
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
    decryptData: mockDecryptData,
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
  listItemsApi: (...args: unknown[]) => mockListItemsApi(...args),
  createItemApi: vi.fn(),
  updateItemApi: vi.fn(),
  deleteItemApi: vi.fn(),
  permanentDeleteApi: vi.fn(),
  emptyTrashApi: vi.fn(),
  restoreItemApi: vi.fn(),
  listFoldersApi: (...args: unknown[]) => mockListFoldersApi(...args),
  createFolderApi: vi.fn(),
  updateFolderApi: vi.fn(),
  deleteFolderApi: vi.fn(),
  listTrashApi: (...args: unknown[]) => mockListTrashApi(...args),
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

import { useAuthStore } from '../src/stores/authStore';
import { useVaultStore } from '../src/stores/vaultStore';

// NOTE: a former `isStorageDegraded (Task 4.1)` describe imported
// `isStorageDegraded` from `../src/stores/encryptedStorage` — which is MOCKED
// at the top of this file (`vi.fn().mockReturnValue(false)`) — so it only ever
// asserted the mock, never the real degraded-flag read. It was removed; the
// real `isStorageDegraded` (false when unset, true when the flag is set) is
// exercised against the UNMOCKED module in `encryptedStorage.test.ts`.

// ==========================================================================
// 4.2 — vaultStore: Promise.allSettled for graceful decryption
// ==========================================================================

describe('vaultStore - Promise.allSettled (Task 4.2)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useAuthStore.setState({ vaultKey: {} as CryptoKey });
    useVaultStore.setState({
      items: [],
      trashItems: [],
      folders: [],
      loading: false,
    });
  });

  it('should still load successfully decrypted items even when one fails', async () => {
    const rawItems = [
      {
        _id: 'item-1',
        userId: 'user-1',
        itemType: 'login',
        tags: [],
        favorite: false,
        encryptedName: 'enc1',
        nameIv: 'iv1',
        nameTag: 'tag1',
        encryptedData: 'data1',
        dataIv: 'div1',
        dataTag: 'dtag1',
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
      {
        _id: 'item-2',
        userId: 'user-1',
        itemType: 'login',
        tags: [],
        favorite: false,
        encryptedName: 'enc2-corrupt',
        nameIv: 'iv2',
        nameTag: 'tag2',
        encryptedData: 'data2',
        dataIv: 'div2',
        dataTag: 'dtag2',
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
      {
        _id: 'item-3',
        userId: 'user-1',
        itemType: 'login',
        tags: [],
        favorite: false,
        encryptedName: 'enc3',
        nameIv: 'iv3',
        nameTag: 'tag3',
        encryptedData: 'data3',
        dataIv: 'div3',
        dataTag: 'dtag3',
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
    ];

    mockListItemsApi.mockResolvedValue({
      data: {
        success: true,
        data: rawItems,
        pagination: { page: 1, limit: 200, total: rawItems.length, totalPages: 1 },
      },
    });

    // Make the second item's decryption fail
    let callCount = 0;
    mockDecryptData.mockImplementation((encrypted: string) => {
      callCount++;
      if (encrypted === 'enc2-corrupt') {
        throw new Error('Decryption failed: corrupted data');
      }
      // Return valid data for other items
      if (encrypted.startsWith('data')) {
        return JSON.stringify({ username: 'test' });
      }
      return `Decrypted-${String(callCount)}`;
    });

    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await useVaultStore.getState().fetchItems();

    const state = useVaultStore.getState();
    // Should have 2 items (item-1 and item-3), not 3
    expect(state.items).toHaveLength(2);
    expect(state.items[0]!.id).toBe('item-1');
    expect(state.items[1]!.id).toBe('item-3');

    // Should have logged the error (the helper now includes the first
    // failure reason after a colon)
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('Failed to decrypt 1 vault items'),
    );

    consoleSpy.mockRestore();
  });

  it('should load all items when none fail decryption', async () => {
    const rawItems = [
      {
        _id: 'item-1',
        userId: 'user-1',
        itemType: 'login',
        tags: [],
        favorite: false,
        encryptedName: 'enc1',
        nameIv: 'iv1',
        nameTag: 'tag1',
        encryptedData: 'data1',
        dataIv: 'div1',
        dataTag: 'dtag1',
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
    ];

    mockListItemsApi.mockResolvedValue({
      data: {
        success: true,
        data: rawItems,
        pagination: { page: 1, limit: 200, total: rawItems.length, totalPages: 1 },
      },
    });

    mockDecryptData.mockImplementation((encrypted: string) => {
      if (encrypted.startsWith('data')) {
        return JSON.stringify({ username: 'test' });
      }
      return 'Decrypted Name';
    });

    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await useVaultStore.getState().fetchItems();

    expect(useVaultStore.getState().items).toHaveLength(1);
    // Should NOT have logged any error about failed decryption
    expect(consoleSpy).not.toHaveBeenCalledWith(expect.stringContaining('Failed to decrypt'));

    consoleSpy.mockRestore();
  });

  it('should handle all items failing decryption gracefully', async () => {
    const rawItems = [
      {
        _id: 'item-1',
        userId: 'user-1',
        itemType: 'login',
        tags: [],
        favorite: false,
        encryptedName: 'corrupt1',
        nameIv: 'iv1',
        nameTag: 'tag1',
        encryptedData: 'data1',
        dataIv: 'div1',
        dataTag: 'dtag1',
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
    ];

    mockListItemsApi.mockResolvedValue({
      data: {
        success: true,
        data: rawItems,
        pagination: { page: 1, limit: 200, total: rawItems.length, totalPages: 1 },
      },
    });

    mockDecryptData.mockRejectedValue(new Error('All corrupted'));

    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await useVaultStore.getState().fetchItems();

    expect(useVaultStore.getState().items).toHaveLength(0);
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('Failed to decrypt 1 vault items'),
    );

    consoleSpy.mockRestore();
  });
});

// ==========================================================================
// 4.4 — CSRF token cross-tab synchronization
// ==========================================================================

describe('CSRF cross-tab synchronization (Task 4.4)', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  afterEach(() => {
    localStorage.clear();
  });

  it('clearCsrfToken should write to localStorage for cross-tab broadcast', async () => {
    const { clearCsrfToken } = await import('../src/services/api/client');

    clearCsrfToken();

    const value = localStorage.getItem('__hv_csrf_invalidated');
    expect(value).toBeTruthy();
    // Value should be a timestamp string
    expect(Number(value)).toBeGreaterThan(0);
  });

  it('clearCsrfToken should not throw when localStorage is unavailable', async () => {
    const { clearCsrfToken } = await import('../src/services/api/client');

    // Mock localStorage.setItem to throw
    const originalSetItem = localStorage.setItem.bind(localStorage);
    localStorage.setItem = () => {
      throw new Error('localStorage unavailable');
    };

    expect(() => clearCsrfToken()).not.toThrow();

    localStorage.setItem = originalSetItem;
  });
});

// ==========================================================================
// 4.8 — CSRF token fetch deduplication
// ==========================================================================

describe('vaultStore fetchItems/fetchFolders concurrency guard (L15)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useAuthStore.setState({ vaultKey: {} as CryptoKey });
    useVaultStore.setState({ items: [], trashItems: [], folders: [], loading: false });
  });

  it('coalesces two concurrent fetchItems calls into a single API round-trip', async () => {
    // Behavioural dedup check (replaces a grep of vaultStore.ts source text for
    // `let fetchItemsInFlight` / `if (fetchItemsInFlight) return ...`, which
    // stayed green if the guard was moved after the await or renamed). Defer the
    // sole listItems response so the two calls genuinely overlap.
    let resolveFetch!: (value: unknown) => void;
    const deferred = new Promise((resolve) => {
      resolveFetch = resolve;
    });
    mockListItemsApi.mockReturnValue(deferred);

    const store = useVaultStore.getState();
    const p1 = store.fetchItems();
    const p2 = store.fetchItems();

    // The second call must have short-circuited on the in-flight guard — no
    // second network request was issued.
    expect(mockListItemsApi).toHaveBeenCalledTimes(1);

    resolveFetch({
      data: {
        success: true,
        data: [],
        pagination: { page: 1, limit: 200, total: 0, totalPages: 1 },
      },
    });
    await Promise.all([p1, p2]);

    // Still exactly one round-trip after both promises settle.
    expect(mockListItemsApi).toHaveBeenCalledTimes(1);
  });
});

describe('CSRF token fetch deduplication (Task 4.8)', () => {
  it('API client source should deduplicate concurrent CSRF token fetches via csrfFetchPromise', async () => {
    const source = readFileSync(pathResolve(clientSrcDir, 'services/api/client.ts'), 'utf-8');

    // csrfFetchPromise should be declared for deduplication
    expect(source).toContain('let csrfFetchPromise: Promise<string> | null = null');

    // ensureCsrfToken should check for an in-flight promise before starting a new fetch
    expect(source).toContain('if (csrfFetchPromise) return csrfFetchPromise');

    // The promise should be reset in the finally block after fetch completes
    expect(source).toMatch(/\.finally\(\(\)\s*=>\s*\{[\s\S]*?csrfFetchPromise = null/);
  });

  it('clearCsrfToken should also reset csrfFetchPromise', async () => {
    const source = readFileSync(pathResolve(clientSrcDir, 'services/api/client.ts'), 'utf-8');

    // clearCsrfToken should reset both csrfToken and csrfFetchPromise
    expect(source).toMatch(/clearCsrfToken[\s\S]*?csrfToken = null[\s\S]*?csrfFetchPromise = null/);
  });

  it('clearCsrfToken should be callable and reset state without errors', async () => {
    const { clearCsrfToken } = await import('../src/services/api/client');

    // Should be a callable function
    expect(typeof clearCsrfToken).toBe('function');

    // Should not throw when called multiple times
    expect(() => {
      clearCsrfToken();
      clearCsrfToken();
    }).not.toThrow();
  });

  it('cross-tab CSRF invalidation listener should clear both csrfToken and csrfFetchPromise', () => {
    const source = readFileSync(pathResolve(clientSrcDir, 'services/api/client.ts'), 'utf-8');

    // The storage event listener should reset csrfFetchPromise alongside csrfToken
    // to prevent stale in-flight fetches from resolving after cross-tab invalidation
    expect(source).toMatch(
      /addEventListener\('storage'[\s\S]*?CSRF_INVALIDATION_KEY[\s\S]*?csrfToken = null[\s\S]*?csrfFetchPromise = null/,
    );
  });
});

// ==========================================================================
// 4.7 — Clear authKey in all code paths (register and login)
// ==========================================================================

describe('authStore - clearKey for authKey (Task 4.7)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useAuthStore.setState({
      accessToken: null,
      user: null,
      isAuthenticated: false,
      isLocked: false,
      vaultKey: null,
      mek: null,
      encryptedVaultKeyData: null,
      twoFactorRequired: false,
      tempToken: null,
      isLoading: false,
    });
  });

  it('should clear authKey after register', async () => {
    const { cryptoService } = await import('../src/services/crypto/cryptoService');
    const { registerApi } = await import('../src/services/api/authApi');

    const mockAuthKey = new ArrayBuffer(32);
    const mockMek = {} as CryptoKey;
    const mockVaultKey = new ArrayBuffer(32);
    const mockVaultKeyCK = {} as CryptoKey;

    vi.mocked(cryptoService.deriveKeys).mockResolvedValue({
      masterEncryptionKey: mockMek,
      authKey: mockAuthKey,
    });
    vi.mocked(cryptoService.generateVaultKey).mockResolvedValue(mockVaultKey);
    vi.mocked(cryptoService.importVaultKey).mockResolvedValue(mockVaultKeyCK);
    vi.mocked(cryptoService.encryptVaultKey).mockResolvedValue({
      encrypted: 'enc',
      iv: 'iv',
      tag: 'tag',
    });
    vi.mocked(registerApi).mockResolvedValue({ data: { success: true } } as never);

    await useAuthStore.getState().register('test@test.com', 'password123');

    // Raw vault key should be cleared after import
    expect(cryptoService.clearKey).toHaveBeenCalledWith(mockVaultKey);
    // authKey should be cleared after registration
    expect(cryptoService.clearKey).toHaveBeenCalledWith(mockAuthKey);
    // Imported vault CryptoKey should be cleared
    expect(cryptoService.clearCryptoKey).toHaveBeenCalledWith(mockVaultKeyCK);
    // MEK should be cleared after registration (Task 2.1 fix)
    expect(cryptoService.clearCryptoKey).toHaveBeenCalledWith(mockMek);
  });

  it('should clear authKey after login (non-2FA)', async () => {
    const { cryptoService } = await import('../src/services/crypto/cryptoService');
    const { loginApi } = await import('../src/services/api/authApi');

    const mockAuthKey = new ArrayBuffer(32);
    const mockMek = {} as CryptoKey;
    const mockVaultKey = new ArrayBuffer(32);

    vi.mocked(cryptoService.deriveKeys).mockResolvedValue({
      masterEncryptionKey: mockMek,
      authKey: mockAuthKey,
    });
    vi.mocked(cryptoService.decryptVaultKey).mockResolvedValue(mockVaultKey);
    vi.mocked(cryptoService.importVaultKey).mockResolvedValue({} as CryptoKey);
    vi.mocked(loginApi).mockResolvedValue({
      data: {
        success: true,
        data: {
          accessToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEifQ.sig',
          encryptedVaultKey: 'enc',
          vaultKeyIv: 'iv',
          vaultKeyTag: 'tag',
          kdfIterations: 600000,
          kdfAlgorithm: 'PBKDF2-SHA256',
        },
      },
    } as never);

    await useAuthStore.getState().login('test@test.com', 'password123');

    // authKey should be cleared immediately after hash generation
    expect(cryptoService.clearKey).toHaveBeenCalledWith(mockAuthKey);
  });
});

// ==========================================================================
// 4.8 — VaultPage async error handlers (unit-level store tests)
// ==========================================================================

describe('vaultStore - fetchItems error handling (Task 4.8)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useAuthStore.setState({ vaultKey: {} as CryptoKey });
    useVaultStore.setState({
      items: [],
      trashItems: [],
      folders: [],
      loading: false,
    });
  });

  it('should reject when fetchItems API call fails', async () => {
    mockListItemsApi.mockRejectedValue(new Error('Network error'));

    // fetchItems should propagate the rejection so .catch() in VaultPage can handle it
    await expect(useVaultStore.getState().fetchItems()).rejects.toThrow('Network error');
  });

  it('should reject when fetchFolders API call fails', async () => {
    mockListFoldersApi.mockRejectedValue(new Error('Network error'));

    await expect(useVaultStore.getState().fetchFolders()).rejects.toThrow('Network error');
  });

  it('should reject when fetchTrashItems API call fails', async () => {
    mockListTrashApi.mockRejectedValue(new Error('Network error'));

    await expect(useVaultStore.getState().fetchTrashItems()).rejects.toThrow('Network error');
  });
});

// ==========================================================================
// 4.13 — Sanitize error messages to avoid leaking JWT structure
// ==========================================================================

describe('authStore - sanitized error messages (Task 4.13)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useAuthStore.setState({
      accessToken: null,
      user: null,
      isAuthenticated: false,
      isLocked: false,
      vaultKey: null,
      mek: null,
      encryptedVaultKeyData: null,
      twoFactorRequired: false,
      tempToken: null,
      isLoading: false,
    });
  });

  it('should throw generic "Authentication error" for malformed token (no payload)', async () => {
    const { cryptoService } = await import('../src/services/crypto/cryptoService');
    const { loginApi } = await import('../src/services/api/authApi');

    const mockAuthKey = new ArrayBuffer(32);
    const mockMek = {} as CryptoKey;
    const mockVaultKey = new ArrayBuffer(32);

    vi.mocked(cryptoService.deriveKeys).mockResolvedValue({
      masterEncryptionKey: mockMek,
      authKey: mockAuthKey,
    });
    vi.mocked(cryptoService.decryptVaultKey).mockResolvedValue(mockVaultKey);
    vi.mocked(cryptoService.importVaultKey).mockResolvedValue({} as CryptoKey);
    vi.mocked(loginApi).mockResolvedValue({
      data: {
        success: true,
        data: {
          // Token with no payload segment
          accessToken: 'header-only',
          encryptedVaultKey: 'enc',
          vaultKeyIv: 'iv',
          vaultKeyTag: 'tag',
          kdfIterations: 600000,
          kdfAlgorithm: 'PBKDF2-SHA256',
        },
      },
    } as never);

    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await expect(useAuthStore.getState().login('test@test.com', 'password123')).rejects.toThrow(
      'Authentication error',
    );

    // Should NOT contain specific JWT structure details
    try {
      await useAuthStore.getState().login('test@test.com', 'password123');
    } catch (e: unknown) {
      const message = (e as Error).message;
      expect(message).not.toContain('Invalid access token format');
      expect(message).not.toContain('sub');
      expect(message).not.toContain('JWT');
    }

    consoleSpy.mockRestore();
  });

  it('should throw generic "Authentication error" for token missing sub claim', async () => {
    const { cryptoService } = await import('../src/services/crypto/cryptoService');
    const { loginApi } = await import('../src/services/api/authApi');

    const mockAuthKey = new ArrayBuffer(32);
    const mockMek = {} as CryptoKey;
    const mockVaultKey = new ArrayBuffer(32);

    vi.mocked(cryptoService.deriveKeys).mockResolvedValue({
      masterEncryptionKey: mockMek,
      authKey: mockAuthKey,
    });
    vi.mocked(cryptoService.decryptVaultKey).mockResolvedValue(mockVaultKey);
    vi.mocked(cryptoService.importVaultKey).mockResolvedValue({} as CryptoKey);

    // Create a valid JWT structure but with no "sub" claim
    const payloadNoSub = btoa(JSON.stringify({ iat: 1234567890, exp: 9999999999 }));
    vi.mocked(loginApi).mockResolvedValue({
      data: {
        success: true,
        data: {
          accessToken: `eyJhbGciOiJIUzI1NiJ9.${payloadNoSub}.sig`,
          encryptedVaultKey: 'enc',
          vaultKeyIv: 'iv',
          vaultKeyTag: 'tag',
          kdfIterations: 600000,
          kdfAlgorithm: 'PBKDF2-SHA256',
        },
      },
    } as never);

    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await expect(useAuthStore.getState().login('test@test.com', 'password123')).rejects.toThrow(
      'Authentication error',
    );

    // Should NOT reveal JWT structure details
    try {
      await useAuthStore.getState().login('test@test.com', 'password123');
    } catch (e: unknown) {
      const message = (e as Error).message;
      expect(message).not.toContain('sub');
      expect(message).not.toContain('claim');
      expect(message).not.toContain('access token');
    }

    consoleSpy.mockRestore();
  });
});

// NOTE: two describes were removed here:
//   • `encryptedStorage - CryptoKey caching (Task 4.14)` — its surface test
//     dynamically imported `../src/stores/encryptedStorage`, which resolves to
//     the vi.mock at the top of this file, so it only asserted the mock's own
//     `vi.fn()` stubs; its sibling merely grepped the source for cache-variable
//     declarations. The real adapter surface and session-key caching are
//     covered behaviourally in `encryptedStorage.test.ts` (round-trips, "reuses
//     cached key across multiple operations", "generates a new session key").
//   • `encryptedStorage - session key extractability documentation (Task 29)` —
//     `readFileSync` + `toContain` assertions on comment prose and source text,
//     which pass no matter what the code does (and break on a harmless reword).
//     The load-bearing property — the generated session key IS extractable so
//     its raw bytes can be serialised to sessionStorage — is proven
//     behaviourally in `encryptedStorage.test.ts` ("generates a new session
//     key" exports 32 raw bytes to base64, impossible for a non-extractable
//     key). The defence-in-depth re-import-as-non-extractable flag has no
//     observable effect at the public adapter API, so a source-text assertion
//     for it was false coverage and was dropped rather than kept.

// ==========================================================================
// 8.7 — Harden markdown rendering (replace dangerouslySetInnerHTML)
// ==========================================================================

describe('Hardened markdown rendering (Task 8.7)', () => {
  it('VaultItemDetail should not use dangerouslySetInnerHTML', async () => {
    const source = readFileSync(
      pathResolve(clientSrcDir, 'components/vault/VaultItemDetail.tsx'),
      'utf-8',
    );

    expect(source).not.toContain('dangerouslySetInnerHTML');
    expect(source).toContain('ReactMarkdown');
    expect(source).toContain("from 'react-markdown'");
  });

  it('VaultItemForm should not use dangerouslySetInnerHTML', async () => {
    const source = readFileSync(
      pathResolve(clientSrcDir, 'components/vault/VaultItemForm.tsx'),
      'utf-8',
    );

    expect(source).not.toContain('dangerouslySetInnerHTML');
    expect(source).toContain('ReactMarkdown');
    expect(source).toContain("from 'react-markdown'");
  });

  it('PasswordHistorySection should use Promise.allSettled for resilient decryption', () => {
    const source = readFileSync(
      pathResolve(clientSrcDir, 'components/vault/VaultItemDetail.tsx'),
      'utf-8',
    );

    expect(source).toContain('Promise.allSettled');
    expect(source).not.toMatch(/Promise\.all\(\s*\n?\s*entries\.map/);
  });

  it('VaultItemDetail should not import marked or DOMPurify', async () => {
    const source = readFileSync(
      pathResolve(clientSrcDir, 'components/vault/VaultItemDetail.tsx'),
      'utf-8',
    );

    expect(source).not.toMatch(/from ['"]marked['"]/);
    expect(source).not.toMatch(/from ['"]dompurify['"]/);
  });

  it('ReactMarkdown should have skipHtml enabled for defense-in-depth', () => {
    const source = readFileSync(
      pathResolve(clientSrcDir, 'components/vault/VaultItemDetail.tsx'),
      'utf-8',
    );

    expect(source).toContain('skipHtml={true}');
  });

  it('ReactMarkdown should sanitize links with isSafeUrl', () => {
    const source = readFileSync(
      pathResolve(clientSrcDir, 'components/vault/VaultItemDetail.tsx'),
      'utf-8',
    );

    expect(source).toContain('isSafeUrl(href)');
    expect(source).toContain('target="_blank"');
    expect(source).toContain('rel="noopener noreferrer"');
  });

  it('VaultItemForm ReactMarkdown should have skipHtml enabled', () => {
    const source = readFileSync(
      pathResolve(clientSrcDir, 'components/vault/VaultItemForm.tsx'),
      'utf-8',
    );

    expect(source).toContain('skipHtml');
  });

  it('VaultItemForm should not import marked or DOMPurify', async () => {
    const source = readFileSync(
      pathResolve(clientSrcDir, 'components/vault/VaultItemForm.tsx'),
      'utf-8',
    );

    expect(source).not.toMatch(/from ['"]marked['"]/);
    expect(source).not.toMatch(/from ['"]dompurify['"]/);
  });
});

// ==========================================================================
// 8.8 — Password strength validation in change password flow
// ==========================================================================

describe('Password strength validation in change password flow (Task 8.8)', () => {
  it('SettingsPage should import zxcvbn lazily', async () => {
    const source = readFileSync(pathResolve(clientSrcDir, 'pages/SettingsPage.tsx'), 'utf-8');

    expect(source).toMatch(/import.*getZxcvbn.*from.*lazyZxcvbn/);
  });

  it('handleChangePassword should reject passwords with zxcvbn score < 3', async () => {
    const source = readFileSync(pathResolve(clientSrcDir, 'pages/SettingsPage.tsx'), 'utf-8');

    // Verify the strength check exists before the API call
    expect(source).toContain('zxcvbnLoaded(newPassword)');
    expect(source).toContain('strengthResult.score < 3');
    expect(source).toContain('New password is too weak');
  });

  it('SettingsPage should have password strength meter UI', async () => {
    const source = readFileSync(pathResolve(clientSrcDir, 'pages/SettingsPage.tsx'), 'utf-8');

    // Verify strength meter UI elements
    expect(source).toContain('newPasswordStrength');
    expect(source).toContain('strengthLabels');
    expect(source).toContain('strengthColors');
  });

  it('SettingsPage should force logout after successful password change', async () => {
    const source = readFileSync(pathResolve(clientSrcDir, 'pages/SettingsPage.tsx'), 'utf-8');

    // After a successful password change the server revokes all refresh tokens,
    // so the client must force a full logout to prevent stale-MEK issues.
    expect(source).toContain('await logout()');
    expect(source).toContain("navigate('/login'");
  });
});
