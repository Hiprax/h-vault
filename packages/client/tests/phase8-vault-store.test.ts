/**
 * Phase 8 tests: Client-side improvements
 *
 * 8.1 - Decryption error recovery (reportDecryptionFailures helper,
 *       lastDecryptionError diagnostic field, event emission for all fetch
 *       methods)
 * 8.2 - Pre-flight encrypted field size validation
 *       (EncryptedFieldTooLargeError on createItem/updateItem)
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ---------------------------------------------------------------------------
// Polyfill matchMedia (stores reference it at module load)
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
// Mocks (must come before importing the stores)
// ---------------------------------------------------------------------------

vi.mock('../src/stores/encryptedStorage', () => ({
  encryptedStorage: {
    getItem: vi.fn().mockResolvedValue(null),
    setItem: vi.fn().mockResolvedValue(undefined),
    removeItem: vi.fn(),
  },
  isStorageDegraded: () => false,
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

vi.mock('../src/lib/logger', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

// ---------------------------------------------------------------------------
// Imports (after mocks)
// ---------------------------------------------------------------------------

import { useAuthStore } from '../src/stores/authStore';
import {
  useVaultStore,
  reportDecryptionFailures,
  decryptExportResponse,
  EncryptedFieldTooLargeError,
  DECRYPTION_FAILURE_THRESHOLD,
  DECRYPTION_CONCURRENCY,
  mapWithConcurrency,
} from '../src/stores/vaultStore';
import { cryptoService } from '../src/services/crypto/cryptoService';
import { logger } from '../src/lib/logger';
import { isUndecodableData } from '../src/lib/vaultData';
import { offlineCache } from '../src/services/offlineCache';
import {
  listItemsApi,
  listTrashApi,
  listFoldersApi,
  createItemApi,
  updateItemApi,
  deleteItemApi,
  permanentDeleteApi,
  emptyTrashApi,
} from '../src/services/api/vaultApi';
import { MAX_ENCRYPTED_NAME_LENGTH, MAX_ENCRYPTED_DATA_LENGTH } from '@hvault/shared';

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

const mockVaultKey = {} as CryptoKey;

function setupUnlockedVault(): void {
  useAuthStore.setState({ vaultKey: mockVaultKey });
}

function resetVault(): void {
  useVaultStore.setState({
    items: [],
    trashItems: [],
    folders: [],
    loading: false,
    itemsLoading: false,
    trashLoading: false,
    itemsLoaded: 0,
    itemsTotal: null,
    decryptionFailures: 0,
    lastDecryptionError: null,
    searchQuery: '',
    selectedFolder: null,
    selectedType: null,
    showFavorites: false,
    showTrash: false,
    sortBy: 'dateModified' as const,
    sortOrder: 'desc' as const,
    filteredItemCount: null,
  });
  useAuthStore.setState({ vaultKey: null });
}

function makeRawItemResponse(overrides: Record<string, unknown> = {}) {
  return {
    _id: '507f1f77bcf86cd799439011',
    userId: '507f1f77bcf86cd799439012',
    itemType: 'login' as const,
    encryptedName: 'enc-name',
    nameIv: 'n-iv',
    nameTag: 'n-tag',
    encryptedData: 'enc-data',
    dataIv: 'd-iv',
    dataTag: 'd-tag',
    tags: [] as string[],
    favorite: false,
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
    ...overrides,
  };
}

function makeRawFolderResponse(overrides: Record<string, unknown> = {}) {
  return {
    _id: '507f1f77bcf86cd799439011',
    userId: '507f1f77bcf86cd799439012',
    encryptedName: 'enc-folder-name',
    nameIv: 'fn-iv',
    nameTag: 'fn-tag',
    sortOrder: 0,
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
    ...overrides,
  };
}

// =========================================================================
// 8.1 — reportDecryptionFailures helper (pure function)
// =========================================================================

describe('8.1 — reportDecryptionFailures helper', () => {
  let capturedEvents: CustomEvent<{ count: number }>[] = [];
  const eventHandler = (e: Event) => {
    capturedEvents.push(e as CustomEvent<{ count: number }>);
  };

  beforeEach(() => {
    capturedEvents = [];
    window.addEventListener('vault-decryption-failures', eventHandler);
  });

  afterEach(() => {
    window.removeEventListener('vault-decryption-failures', eventHandler);
  });

  it('returns zero count and null message when all promises fulfilled', () => {
    const results: PromiseSettledResult<unknown>[] = [
      { status: 'fulfilled', value: 'a' },
      { status: 'fulfilled', value: 'b' },
    ];

    const report = reportDecryptionFailures(results, 'vault items');

    expect(report.failedCount).toBe(0);
    expect(report.errorMessage).toBeNull();
    expect(capturedEvents).toHaveLength(0);
  });

  it('reports failure count, captures error message, and dispatches event', () => {
    const results: PromiseSettledResult<unknown>[] = [
      { status: 'fulfilled', value: 'ok' },
      { status: 'rejected', reason: new Error('bad tag') },
      { status: 'rejected', reason: new Error('invalid iv') },
    ];

    const report = reportDecryptionFailures(results, 'vault items');

    expect(report.failedCount).toBe(2);
    expect(report.errorMessage).toBe('vault items: bad tag');
    expect(capturedEvents).toHaveLength(1);
    expect(capturedEvents[0]!.detail).toEqual({ count: 2 });
  });

  it('prefixes the error message with the context (folders)', () => {
    const results: PromiseSettledResult<unknown>[] = [
      { status: 'rejected', reason: new Error('key mismatch') },
    ];

    const report = reportDecryptionFailures(results, 'folders');

    expect(report.errorMessage).toBe('folders: key mismatch');
  });

  it('prefixes the error message with the context (trash items)', () => {
    const results: PromiseSettledResult<unknown>[] = [
      { status: 'rejected', reason: new Error('auth tag invalid') },
    ];

    const report = reportDecryptionFailures(results, 'trash items');

    expect(report.errorMessage).toBe('trash items: auth tag invalid');
  });

  it('handles non-Error rejection reasons by stringifying them', () => {
    const results: PromiseSettledResult<unknown>[] = [
      { status: 'rejected', reason: 'raw string reason' },
    ];

    const report = reportDecryptionFailures(results, 'vault items');

    expect(report.failedCount).toBe(1);
    expect(report.errorMessage).toBe('vault items: raw string reason');
  });

  it('does not dispatch an event when failures are below the threshold', () => {
    // Threshold is 1 — zero failures should never emit.
    expect(DECRYPTION_FAILURE_THRESHOLD).toBeGreaterThanOrEqual(1);
    const results: PromiseSettledResult<unknown>[] = [{ status: 'fulfilled', value: 'ok' }];
    reportDecryptionFailures(results, 'vault items');
    expect(capturedEvents).toHaveLength(0);
  });
});

// =========================================================================
// 8.1 — vaultStore fetch methods track lastDecryptionError
// =========================================================================

describe('8.1 — vaultStore fetch methods track lastDecryptionError', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetVault();
  });

  it('initializes lastDecryptionError to null', () => {
    expect(useVaultStore.getState().lastDecryptionError).toBeNull();
  });

  it('clearStore resets lastDecryptionError to null', () => {
    useVaultStore.setState({
      decryptionFailures: 3,
      lastDecryptionError: 'vault items: something went wrong',
    });
    useVaultStore.getState().clearStore();
    expect(useVaultStore.getState().lastDecryptionError).toBeNull();
    expect(useVaultStore.getState().decryptionFailures).toBe(0);
  });

  it('fetchItems captures lastDecryptionError on decrypt failure', async () => {
    setupUnlockedVault();

    vi.mocked(listItemsApi).mockResolvedValue({
      data: {
        success: true,
        data: [makeRawItemResponse({ _id: '507f1f77bcf86cd799439011' })],
        pagination: { page: 1, limit: 200, total: 1, totalPages: 1 },
      },
    } as unknown as Awaited<ReturnType<typeof listItemsApi>>);

    // First call is for name, second for data — make name fail.
    vi.mocked(cryptoService.decryptData).mockRejectedValueOnce(new Error('GCM tag mismatch'));

    const events: number[] = [];
    const handler = (e: Event) => {
      events.push((e as CustomEvent<{ count: number }>).detail.count);
    };
    window.addEventListener('vault-decryption-failures', handler);

    try {
      await useVaultStore.getState().fetchItems();
    } finally {
      window.removeEventListener('vault-decryption-failures', handler);
    }

    const state = useVaultStore.getState();
    expect(state.decryptionFailures).toBe(1);
    expect(state.lastDecryptionError).toContain('vault items');
    expect(state.lastDecryptionError).toContain('GCM tag mismatch');
    expect(events).toEqual([1]);
  });

  it('fetchItems clears decryptionFailures on a clean re-fetch', async () => {
    setupUnlockedVault();
    useVaultStore.setState({
      decryptionFailures: 4,
      lastDecryptionError: 'vault items: previous run',
    });

    vi.mocked(listItemsApi).mockResolvedValue({
      data: {
        success: true,
        data: [makeRawItemResponse()],
        pagination: { page: 1, limit: 200, total: 1, totalPages: 1 },
      },
    } as unknown as Awaited<ReturnType<typeof listItemsApi>>);

    vi.mocked(cryptoService.decryptData)
      .mockResolvedValueOnce('Clean Item Name')
      .mockResolvedValueOnce(JSON.stringify({ username: 'u' }));

    await useVaultStore.getState().fetchItems();

    const state = useVaultStore.getState();
    expect(state.decryptionFailures).toBe(0);
    // lastDecryptionError is preserved across successful fetches to keep
    // the diagnostic trail — it is cleared only by clearStore.
    expect(state.lastDecryptionError).toBe('vault items: previous run');
  });

  it('fetchTrashItems emits event and captures lastDecryptionError on failure', async () => {
    setupUnlockedVault();

    vi.mocked(listTrashApi).mockResolvedValue({
      data: {
        success: true,
        data: [makeRawItemResponse({ _id: '507f1f77bcf86cd799439099' })],
        pagination: { page: 1, limit: 200, total: 1, totalPages: 1 },
      },
    } as unknown as Awaited<ReturnType<typeof listTrashApi>>);

    vi.mocked(cryptoService.decryptData).mockRejectedValueOnce(new Error('trash corruption'));

    const events: number[] = [];
    const handler = (e: Event) => {
      events.push((e as CustomEvent<{ count: number }>).detail.count);
    };
    window.addEventListener('vault-decryption-failures', handler);

    try {
      await useVaultStore.getState().fetchTrashItems();
    } finally {
      window.removeEventListener('vault-decryption-failures', handler);
    }

    expect(events).toEqual([1]);
    expect(useVaultStore.getState().lastDecryptionError).toContain('trash items');
    expect(useVaultStore.getState().lastDecryptionError).toContain('trash corruption');
  });

  it('fetchFolders emits event and captures lastDecryptionError on failure', async () => {
    setupUnlockedVault();

    vi.mocked(listFoldersApi).mockResolvedValue({
      data: {
        success: true,
        data: [makeRawFolderResponse()],
      },
    } as unknown as Awaited<ReturnType<typeof listFoldersApi>>);

    vi.mocked(cryptoService.decryptData).mockRejectedValueOnce(new Error('folder cipher invalid'));

    const events: number[] = [];
    const handler = (e: Event) => {
      events.push((e as CustomEvent<{ count: number }>).detail.count);
    };
    window.addEventListener('vault-decryption-failures', handler);

    try {
      await useVaultStore.getState().fetchFolders();
    } finally {
      window.removeEventListener('vault-decryption-failures', handler);
    }

    expect(events).toEqual([1]);
    expect(useVaultStore.getState().lastDecryptionError).toContain('folders');
    expect(useVaultStore.getState().lastDecryptionError).toContain('folder cipher invalid');
  });

  it('fetchItems no longer changes state on success when all decrypt fine (sanity)', async () => {
    setupUnlockedVault();

    vi.mocked(listItemsApi).mockResolvedValue({
      data: {
        success: true,
        data: [makeRawItemResponse()],
        pagination: { page: 1, limit: 200, total: 1, totalPages: 1 },
      },
    } as unknown as Awaited<ReturnType<typeof listItemsApi>>);

    vi.mocked(cryptoService.decryptData)
      .mockResolvedValueOnce('Name')
      .mockResolvedValueOnce(JSON.stringify({ username: 'u' }));

    await useVaultStore.getState().fetchItems();

    expect(useVaultStore.getState().decryptionFailures).toBe(0);
    expect(useVaultStore.getState().items).toHaveLength(1);
  });
});

// =========================================================================
// 8.2 — EncryptedFieldTooLargeError class
// =========================================================================

describe('8.2 — EncryptedFieldTooLargeError', () => {
  it('surfaces name-specific message for the "name" field', () => {
    const err = new EncryptedFieldTooLargeError('name', 2000, 1000);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('EncryptedFieldTooLargeError');
    expect(err.field).toBe('name');
    expect(err.actualLength).toBe(2000);
    expect(err.maxLength).toBe(1000);
    expect(err.message).toContain('name');
    expect(err.message).toContain('shorten');
  });

  it('surfaces data-specific message for the "data" field', () => {
    const err = new EncryptedFieldTooLargeError('data', 1_000_000, 500_000);
    expect(err.field).toBe('data');
    expect(err.message).toContain('data is too large');
    // Actionable hint in the message
    expect(err.message).toMatch(/notes|custom fields|history/);
  });
});

// =========================================================================
// 8.2 — createItem / updateItem pre-flight size checks
// =========================================================================

describe('8.2 — createItem / updateItem pre-flight size checks', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetVault();
    setupUnlockedVault();
    vi.mocked(cryptoService.generateSearchHash).mockResolvedValue('deadbeef'.repeat(8));
  });

  it('createItem rejects when encrypted name exceeds MAX_ENCRYPTED_NAME_LENGTH', async () => {
    const tooLongName = 'n'.repeat(MAX_ENCRYPTED_NAME_LENGTH + 1);
    // Use mockImplementation so each call returns the same oversized name.
    // The first call in createItem encrypts the name, the second the data.
    let callIndex = 0;
    vi.mocked(cryptoService.encryptData).mockImplementation(() => {
      callIndex += 1;
      // Odd calls → name, even calls → data
      return Promise.resolve(
        callIndex % 2 === 1
          ? { encrypted: tooLongName, iv: 'iv', tag: 'tag' }
          : { encrypted: 'ok-data', iv: 'iv', tag: 'tag' },
      );
    });

    await expect(
      useVaultStore.getState().createItem('login', 'x', { username: 'u' }),
    ).rejects.toThrow(EncryptedFieldTooLargeError);

    // Error.field and lengths are accurate
    try {
      await useVaultStore.getState().createItem('login', 'x', { username: 'u' });
    } catch (err) {
      expect(err).toBeInstanceOf(EncryptedFieldTooLargeError);
      const e = err as EncryptedFieldTooLargeError;
      expect(e.field).toBe('name');
      expect(e.actualLength).toBe(MAX_ENCRYPTED_NAME_LENGTH + 1);
      expect(e.maxLength).toBe(MAX_ENCRYPTED_NAME_LENGTH);
    }

    // API must not be called when pre-flight fails
    expect(createItemApi).not.toHaveBeenCalled();
  });

  it('createItem rejects when encrypted data exceeds MAX_ENCRYPTED_DATA_LENGTH', async () => {
    const tooLongData = 'd'.repeat(MAX_ENCRYPTED_DATA_LENGTH + 1);
    let callIndex = 0;
    vi.mocked(cryptoService.encryptData).mockImplementation(() => {
      callIndex += 1;
      return Promise.resolve(
        callIndex % 2 === 1
          ? { encrypted: 'name-ok', iv: 'iv', tag: 'tag' }
          : { encrypted: tooLongData, iv: 'iv', tag: 'tag' },
      );
    });

    await expect(
      useVaultStore.getState().createItem('note', 'n', { content: 'x' }),
    ).rejects.toThrow(EncryptedFieldTooLargeError);

    try {
      await useVaultStore.getState().createItem('note', 'n', { content: 'x' });
    } catch (err) {
      expect(err).toBeInstanceOf(EncryptedFieldTooLargeError);
      const e = err as EncryptedFieldTooLargeError;
      expect(e.field).toBe('data');
      expect(e.actualLength).toBe(MAX_ENCRYPTED_DATA_LENGTH + 1);
    }

    expect(createItemApi).not.toHaveBeenCalled();
  });

  it('createItem still works when encrypted sizes are within limits', async () => {
    vi.mocked(cryptoService.encryptData)
      .mockResolvedValueOnce({ encrypted: 'ok-name', iv: 'iv', tag: 'tag' })
      .mockResolvedValueOnce({ encrypted: 'ok-data', iv: 'iv', tag: 'tag' });

    vi.mocked(createItemApi).mockResolvedValue({
      data: { success: true, data: makeRawItemResponse() },
    } as unknown as Awaited<ReturnType<typeof createItemApi>>);

    vi.mocked(cryptoService.decryptData)
      .mockResolvedValueOnce('My Login')
      .mockResolvedValueOnce(JSON.stringify({ username: 'u' }));

    await useVaultStore.getState().createItem('login', 'My Login', { username: 'u' });

    expect(createItemApi).toHaveBeenCalledTimes(1);
    expect(useVaultStore.getState().items).toHaveLength(1);
  });

  it('updateItem rejects when encrypted name exceeds MAX_ENCRYPTED_NAME_LENGTH', async () => {
    const tooLongName = 'n'.repeat(MAX_ENCRYPTED_NAME_LENGTH + 1);
    vi.mocked(cryptoService.encryptData)
      .mockResolvedValueOnce({ encrypted: tooLongName, iv: 'iv', tag: 'tag' })
      .mockResolvedValueOnce({ encrypted: 'ok', iv: 'iv', tag: 'tag' });

    await expect(
      useVaultStore.getState().updateItem('item-1', 'x', { username: 'u' }),
    ).rejects.toThrow(EncryptedFieldTooLargeError);

    expect(updateItemApi).not.toHaveBeenCalled();
  });

  it('updateItem rejects when encrypted data exceeds MAX_ENCRYPTED_DATA_LENGTH', async () => {
    const tooLongData = 'd'.repeat(MAX_ENCRYPTED_DATA_LENGTH + 1);
    vi.mocked(cryptoService.encryptData)
      .mockResolvedValueOnce({ encrypted: 'name-ok', iv: 'iv', tag: 'tag' })
      .mockResolvedValueOnce({ encrypted: tooLongData, iv: 'iv', tag: 'tag' });

    await expect(
      useVaultStore.getState().updateItem('item-1', 'n', { content: 'x' }),
    ).rejects.toThrow(/Item data is too large/);

    expect(updateItemApi).not.toHaveBeenCalled();
  });

  it('updateItem succeeds when sizes are within limits', async () => {
    // Pre-populate an existing item so updateItem's password-history lookup
    // does not throw.
    useVaultStore.setState({
      items: [
        {
          id: 'item-1',
          itemType: 'login',
          tags: [],
          favorite: false,
          name: 'Old',
          data: {},
          createdAt: '2024-01-01T00:00:00Z',
          updatedAt: '2024-01-01T00:00:00Z',
          _raw: makeRawItemResponse({ _id: 'item-1' }) as never,
        },
      ],
    });

    vi.mocked(cryptoService.encryptData)
      .mockResolvedValueOnce({ encrypted: 'name', iv: 'iv', tag: 'tag' })
      .mockResolvedValueOnce({ encrypted: 'data', iv: 'iv', tag: 'tag' });

    vi.mocked(updateItemApi).mockResolvedValue({
      data: { success: true, data: makeRawItemResponse({ _id: 'item-1' }) },
    } as unknown as Awaited<ReturnType<typeof updateItemApi>>);

    vi.mocked(cryptoService.decryptData)
      .mockResolvedValueOnce('Updated')
      .mockResolvedValueOnce(JSON.stringify({ username: 'u2' }));

    await useVaultStore.getState().updateItem('item-1', 'Updated', { username: 'u2' });

    expect(updateItemApi).toHaveBeenCalledTimes(1);
  });
});

// =========================================================================
// 3.4 — Bounded-concurrency decryption (mapWithConcurrency)
// =========================================================================

describe('3.4 — mapWithConcurrency helper', () => {
  it('exports DECRYPTION_CONCURRENCY at a reasonable value (>=4, <=64)', () => {
    expect(DECRYPTION_CONCURRENCY).toBeGreaterThanOrEqual(4);
    expect(DECRYPTION_CONCURRENCY).toBeLessThanOrEqual(64);
  });

  it('preserves input order in the result array', async () => {
    const inputs = [10, 20, 30, 40, 50];
    const results = await mapWithConcurrency(inputs, 3, (n) => Promise.resolve(n * 2));
    const values = results.map((r) => (r.status === 'fulfilled' ? r.value : null));
    expect(values).toEqual([20, 40, 60, 80, 100]);
  });

  it('caps in-flight tasks at the requested concurrency', async () => {
    let inFlight = 0;
    let peak = 0;
    const inputs = Array.from({ length: 32 }, (_, i) => i);

    await mapWithConcurrency(inputs, 4, async () => {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 1));
      inFlight -= 1;
    });

    expect(peak).toBeLessThanOrEqual(4);
    expect(peak).toBeGreaterThan(0);
  });

  it('captures failures as rejected results without aborting the batch', async () => {
    const results = await mapWithConcurrency([1, 2, 3], 2, (n) =>
      n === 2 ? Promise.reject(new Error('boom')) : Promise.resolve(n),
    );

    expect(results[0]).toEqual({ status: 'fulfilled', value: 1 });
    expect(results[1]?.status).toBe('rejected');
    expect(results[2]).toEqual({ status: 'fulfilled', value: 3 });
  });

  it('handles empty input arrays without throwing', async () => {
    const results = await mapWithConcurrency([], 8, () => Promise.resolve(1));
    expect(results).toEqual([]);
  });
});

// =========================================================================
// 3.4 — fetchItems progressive streaming
// =========================================================================

describe('3.4 — fetchItems progressive streaming', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetVault();
  });

  it('appends pages incrementally and tracks itemsLoaded / itemsTotal', async () => {
    setupUnlockedVault();

    // Simulate 3 pages of 2 items each — total = 6.
    const page1 = [
      makeRawItemResponse({ _id: '507f1f77bcf86cd799439001' }),
      makeRawItemResponse({ _id: '507f1f77bcf86cd799439002' }),
    ];
    const page2 = [
      makeRawItemResponse({ _id: '507f1f77bcf86cd799439003' }),
      makeRawItemResponse({ _id: '507f1f77bcf86cd799439004' }),
    ];
    const page3 = [
      makeRawItemResponse({ _id: '507f1f77bcf86cd799439005' }),
      makeRawItemResponse({ _id: '507f1f77bcf86cd799439006' }),
    ];

    vi.mocked(listItemsApi)
      .mockResolvedValueOnce({
        data: {
          success: true,
          data: page1,
          pagination: { page: 1, limit: 200, total: 6, totalPages: 3 },
        },
      } as unknown as Awaited<ReturnType<typeof listItemsApi>>)
      .mockResolvedValueOnce({
        data: {
          success: true,
          data: page2,
          pagination: { page: 2, limit: 200, total: 6, totalPages: 3 },
        },
      } as unknown as Awaited<ReturnType<typeof listItemsApi>>)
      .mockResolvedValueOnce({
        data: {
          success: true,
          data: page3,
          pagination: { page: 3, limit: 200, total: 6, totalPages: 3 },
        },
      } as unknown as Awaited<ReturnType<typeof listItemsApi>>);

    // 12 decryptData calls total (2 per item × 6 items).
    vi.mocked(cryptoService.decryptData).mockImplementation((enc) => {
      // Alternate name / data so each item produces a valid login record.
      if (typeof enc === 'string' && enc.includes('name')) {
        return Promise.resolve(`item-name`);
      }
      return Promise.resolve(JSON.stringify({ username: 'u' }));
    });

    await useVaultStore.getState().fetchItems();

    const state = useVaultStore.getState();
    expect(state.items).toHaveLength(6);
    expect(state.itemsLoaded).toBe(6);
    expect(state.itemsTotal).toBe(6);
    expect(state.itemsLoading).toBe(false);

    // The pages must be appended in order — IDs from page1 should come before page2/3.
    expect(state.items[0]?.id).toBe('507f1f77bcf86cd799439001');
    expect(state.items[2]?.id).toBe('507f1f77bcf86cd799439003');
    expect(state.items[5]?.id).toBe('507f1f77bcf86cd799439006');
  });

  it('resets items and itemsLoaded at the start of a fresh fetch', async () => {
    setupUnlockedVault();

    // Pre-populate stale state from a previous session.
    useVaultStore.setState({
      items: [
        {
          id: 'stale',
          itemType: 'login',
          tags: [],
          favorite: false,
          name: 'stale',
          data: {},
          createdAt: '2024-01-01T00:00:00Z',
          updatedAt: '2024-01-01T00:00:00Z',
          _raw: makeRawItemResponse({ _id: 'stale' }) as never,
        },
      ],
      itemsLoaded: 1,
      itemsTotal: 1,
    });

    vi.mocked(listItemsApi).mockResolvedValueOnce({
      data: {
        success: true,
        data: [makeRawItemResponse({ _id: '507f1f77bcf86cd799439111' })],
        pagination: { page: 1, limit: 200, total: 1, totalPages: 1 },
      },
    } as unknown as Awaited<ReturnType<typeof listItemsApi>>);

    vi.mocked(cryptoService.decryptData)
      .mockResolvedValueOnce('Fresh')
      .mockResolvedValueOnce(JSON.stringify({ username: 'u' }));

    await useVaultStore.getState().fetchItems();

    const state = useVaultStore.getState();
    // Stale item replaced; fresh item present.
    expect(state.items).toHaveLength(1);
    expect(state.items[0]?.id).toBe('507f1f77bcf86cd799439111');
    expect(state.itemsLoaded).toBe(1);
    expect(state.itemsTotal).toBe(1);
  });
});

// =========================================================================
// 4.6 — fetchItems / fetchTrashItems pagination cap (MAX_PAGES)
// =========================================================================

describe('4.6 — pagination cap', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetVault();
  });

  it('fetchItems stops at MAX_PAGES (50) when totalPages keeps inflating', async () => {
    setupUnlockedVault();

    // Single item per page; pretend the server reports 1000 totalPages.
    // Without the cap, the loop would request all 1000 pages.
    let pagesRequested = 0;
    vi.mocked(listItemsApi).mockImplementation((params) => {
      pagesRequested += 1;
      const page = params?.page ?? 1;
      return Promise.resolve({
        data: {
          success: true,
          data: [makeRawItemResponse({ _id: `id-${String(page).padStart(20, '0')}` })],
          pagination: { page, limit: 200, total: 1000 * 200, totalPages: 1000 },
        },
      } as unknown as Awaited<ReturnType<typeof listItemsApi>>);
    });

    vi.mocked(cryptoService.decryptData).mockImplementation((enc) =>
      Promise.resolve(
        typeof enc === 'string' && enc.includes('name')
          ? 'name'
          : JSON.stringify({ username: 'u' }),
      ),
    );

    await useVaultStore.getState().fetchItems();

    // Cap is 50; we should never request more than that.
    expect(pagesRequested).toBe(50);

    const state = useVaultStore.getState();
    expect(state.items).toHaveLength(50);
    expect(state.lastDecryptionError).toBe(
      'Vault item count exceeds expected limit; some items may be missing',
    );
  });

  it('fetchTrashItems stops at MAX_PAGES (50) when totalPages keeps inflating', async () => {
    setupUnlockedVault();

    let pagesRequested = 0;
    vi.mocked(listTrashApi).mockImplementation((params) => {
      pagesRequested += 1;
      const page = params?.page ?? 1;
      return Promise.resolve({
        data: {
          success: true,
          data: [
            makeRawItemResponse({
              _id: `trash-${String(page).padStart(15, '0')}`,
              deletedAt: '2024-01-02T00:00:00Z',
            }),
          ],
          pagination: { page, limit: 200, total: 9999, totalPages: 9999 },
        },
      } as unknown as Awaited<ReturnType<typeof listTrashApi>>);
    });

    vi.mocked(cryptoService.decryptData).mockImplementation((enc) =>
      Promise.resolve(
        typeof enc === 'string' && enc.includes('name')
          ? 'name'
          : JSON.stringify({ username: 'u' }),
      ),
    );

    await useVaultStore.getState().fetchTrashItems();

    expect(pagesRequested).toBe(50);

    const state = useVaultStore.getState();
    expect(state.trashItems).toHaveLength(50);
    expect(state.lastDecryptionError).toBe(
      'Trash item count exceeds expected limit; some items may be missing',
    );
  });

  it('fetchItems does not trip the cap when totalPages is below MAX_PAGES', async () => {
    setupUnlockedVault();

    let pagesRequested = 0;
    vi.mocked(listItemsApi).mockImplementation((params) => {
      pagesRequested += 1;
      const page = params?.page ?? 1;
      return Promise.resolve({
        data: {
          success: true,
          data: [makeRawItemResponse({ _id: `id-${String(page)}` })],
          pagination: { page, limit: 200, total: 3, totalPages: 3 },
        },
      } as unknown as Awaited<ReturnType<typeof listItemsApi>>);
    });

    vi.mocked(cryptoService.decryptData).mockImplementation((enc) =>
      Promise.resolve(
        typeof enc === 'string' && enc.includes('name')
          ? 'name'
          : JSON.stringify({ username: 'u' }),
      ),
    );

    await useVaultStore.getState().fetchItems();

    expect(pagesRequested).toBe(3);

    const state = useVaultStore.getState();
    // No cap-triggered diagnostic should be set.
    if (state.lastDecryptionError !== null) {
      expect(state.lastDecryptionError).not.toContain('exceeds expected limit');
    } else {
      expect(state.lastDecryptionError).toBeNull();
    }
  });
});

// =========================================================================
// fetchItems / deleteItem race (progressive append filtering)
// =========================================================================

describe('fetchItems / deleteItem race', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetVault();
    setupUnlockedVault();
  });

  it('does not reintroduce a deleted item when deleteItem races a streaming page', async () => {
    // Two pages with a known _id on page 2 that the user deletes between
    // fetching page 1 and page 2. Without the in-flight delete tracker the
    // append would resurrect the deleted item.
    const racingId = '507f1f77bcf86cd799440099';

    // Use a deferred promise for page 2 so the test can intercept it after
    // page 1 has already appended.
    let resolvePage2: (value: unknown) => void = () => {};
    const page2Promise = new Promise<unknown>((resolve) => {
      resolvePage2 = resolve;
    });

    vi.mocked(listItemsApi).mockImplementation((params) => {
      const page = params?.page ?? 1;
      if (page === 1) {
        return Promise.resolve({
          data: {
            success: true,
            data: [makeRawItemResponse({ _id: '507f1f77bcf86cd799440011' })],
            pagination: { page: 1, limit: 200, total: 2, totalPages: 2 },
          },
        } as unknown as Awaited<ReturnType<typeof listItemsApi>>);
      }
      // page 2 — gated by the test
      return page2Promise as Promise<Awaited<ReturnType<typeof listItemsApi>>>;
    });

    vi.mocked(cryptoService.decryptData).mockImplementation((enc) =>
      Promise.resolve(
        typeof enc === 'string' && enc.includes('name')
          ? 'name'
          : JSON.stringify({ username: 'u' }),
      ),
    );

    vi.mocked(deleteItemApi).mockResolvedValue({
      data: { success: true },
    } as unknown as Awaited<ReturnType<typeof deleteItemApi>>);

    // Kick off the fetch; let page 1 land.
    const fetchPromise = useVaultStore.getState().fetchItems();
    // Yield two full task ticks so the page 1 await chain (api → decrypt → set)
    // settles before the delete fires.
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    await new Promise<void>((resolve) => setTimeout(resolve, 0));

    // Now delete the id that is about to arrive on page 2.
    await useVaultStore.getState().deleteItem(racingId);

    // Resolve page 2 with the racing item.
    resolvePage2({
      data: {
        success: true,
        data: [makeRawItemResponse({ _id: racingId })],
        pagination: { page: 2, limit: 200, total: 2, totalPages: 2 },
      },
    });

    await fetchPromise;

    // The deleted id must not be present in items, despite arriving on page 2.
    const state = useVaultStore.getState();
    expect(state.items.some((i) => i.id === racingId)).toBe(false);
  });

  it('drops stale page results when a newer fetchItems supersedes the old one', async () => {
    // First fetch will hang on page 1; before it resolves, a second fetch
    // starts and completes. The hung first fetch must not trample the
    // freshly-populated state when its page eventually resolves.
    let resolveFirstPage1: (value: unknown) => void = () => {};
    const firstPage1 = new Promise<unknown>((resolve) => {
      resolveFirstPage1 = resolve;
    });

    let listCallIndex = 0;
    vi.mocked(listItemsApi).mockImplementation(() => {
      listCallIndex += 1;
      if (listCallIndex === 1) {
        return firstPage1 as Promise<Awaited<ReturnType<typeof listItemsApi>>>;
      }
      // Subsequent calls (the second fetch) resolve normally.
      return Promise.resolve({
        data: {
          success: true,
          data: [makeRawItemResponse({ _id: '507f1f77bcf86cd799440022' })],
          pagination: { page: 1, limit: 200, total: 1, totalPages: 1 },
        },
      } as unknown as Awaited<ReturnType<typeof listItemsApi>>);
    });

    vi.mocked(cryptoService.decryptData).mockImplementation((enc) =>
      Promise.resolve(
        typeof enc === 'string' && enc.includes('name')
          ? 'name'
          : JSON.stringify({ username: 'u' }),
      ),
    );

    const firstFetch = useVaultStore.getState().fetchItems();
    // Let microtasks settle so the in-flight guard is registered.
    await Promise.resolve();

    // Forcibly clear the in-flight pointer so a second fetch can start
    // (simulating the lock/unlock or clearStore reset path that would
    // happen between two distinct fetches in the wild).
    useVaultStore.getState().clearStore();
    setupUnlockedVault();

    // Second fetch supersedes the first.
    await useVaultStore.getState().fetchItems();

    expect(useVaultStore.getState().items).toHaveLength(1);
    expect(useVaultStore.getState().items[0]!.id).toBe('507f1f77bcf86cd799440022');

    // Now resolve the first fetch's page. The store must NOT regress to the
    // first fetch's data because that fetch was superseded.
    resolveFirstPage1({
      data: {
        success: true,
        data: [makeRawItemResponse({ _id: '507f1f77bcf86cd799440011' })],
        pagination: { page: 1, limit: 200, total: 1, totalPages: 1 },
      },
    });

    await firstFetch;

    const state = useVaultStore.getState();
    expect(state.items).toHaveLength(1);
    expect(state.items[0]!.id).toBe('507f1f77bcf86cd799440022');
    expect(state.items.some((i) => i.id === '507f1f77bcf86cd799440011')).toBe(false);
  });

  it('permanentDeleteItem records the id so a streaming trash page does not reintroduce it', async () => {
    const racingId = '507f1f77bcf86cd799440055';

    let resolvePage2: (value: unknown) => void = () => {};
    const page2Promise = new Promise<unknown>((resolve) => {
      resolvePage2 = resolve;
    });

    vi.mocked(listTrashApi).mockImplementation((params) => {
      const page = params?.page ?? 1;
      if (page === 1) {
        return Promise.resolve({
          data: {
            success: true,
            data: [
              makeRawItemResponse({
                _id: '507f1f77bcf86cd799440044',
                deletedAt: '2024-01-02T00:00:00Z',
              }),
            ],
            pagination: { page: 1, limit: 200, total: 2, totalPages: 2 },
          },
        } as unknown as Awaited<ReturnType<typeof listTrashApi>>);
      }
      return page2Promise as Promise<Awaited<ReturnType<typeof listTrashApi>>>;
    });

    vi.mocked(cryptoService.decryptData).mockImplementation((enc) =>
      Promise.resolve(
        typeof enc === 'string' && enc.includes('name')
          ? 'name'
          : JSON.stringify({ username: 'u' }),
      ),
    );

    vi.mocked(permanentDeleteApi).mockResolvedValue({
      data: { success: true },
    } as unknown as Awaited<ReturnType<typeof permanentDeleteApi>>);

    const fetchPromise = useVaultStore.getState().fetchTrashItems();
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    await new Promise<void>((resolve) => setTimeout(resolve, 0));

    await useVaultStore.getState().permanentDeleteItem(racingId);

    resolvePage2({
      data: {
        success: true,
        data: [makeRawItemResponse({ _id: racingId, deletedAt: '2024-01-02T00:00:00Z' })],
        pagination: { page: 2, limit: 200, total: 2, totalPages: 2 },
      },
    });

    await fetchPromise;

    expect(useVaultStore.getState().trashItems.some((i) => i.id === racingId)).toBe(false);
  });

  it('emptyTrash mid-stream prevents page 2 from resurrecting an already-rendered row', async () => {
    // Multi-page fetchTrashItems: page 1 lands and renders one row, the
    // user clicks "empty trash" — page 2 is still in flight and must NOT
    // re-append the row that was visible when empty was clicked.

    const page1Id = 'trash-page1';

    let resolvePage2: (value: unknown) => void = () => {};
    const page2Promise = new Promise<unknown>((resolve) => {
      resolvePage2 = resolve;
    });

    vi.mocked(listTrashApi).mockImplementation((params) => {
      const page = params?.page ?? 1;
      if (page === 1) {
        return Promise.resolve({
          data: {
            success: true,
            data: [makeRawItemResponse({ _id: page1Id, deletedAt: '2024-01-02T00:00:00Z' })],
            pagination: { page: 1, limit: 200, total: 2, totalPages: 2 },
          },
        } as unknown as Awaited<ReturnType<typeof listTrashApi>>);
      }
      return page2Promise as Promise<Awaited<ReturnType<typeof listTrashApi>>>;
    });

    vi.mocked(cryptoService.decryptData).mockImplementation((enc) =>
      Promise.resolve(
        typeof enc === 'string' && enc.includes('name')
          ? 'name'
          : JSON.stringify({ username: 'u' }),
      ),
    );

    vi.mocked(emptyTrashApi).mockResolvedValue({
      data: { success: true },
    } as unknown as Awaited<ReturnType<typeof emptyTrashApi>>);

    // Start the fetch. Page 1 lands almost immediately because the mock
    // returns synchronously; flush microtasks until the page-1 append has
    // settled (`await new Promise(setTimeout)` yields one full task tick).
    const fetchPromise = useVaultStore.getState().fetchTrashItems();
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    await new Promise<void>((resolve) => setTimeout(resolve, 0));

    // Page 1 is now in state; user clicks empty.
    expect(useVaultStore.getState().trashItems.some((i) => i.id === page1Id)).toBe(true);
    await useVaultStore.getState().emptyTrash();

    // Resolve page 2; it re-includes page1Id (e.g. server pagination
    // hadn't yet observed the empty). The filter must drop it.
    resolvePage2({
      data: {
        success: true,
        data: [makeRawItemResponse({ _id: page1Id, deletedAt: '2024-01-02T00:00:00Z' })],
        pagination: { page: 2, limit: 200, total: 2, totalPages: 2 },
      },
    });

    await fetchPromise;

    expect(useVaultStore.getState().trashItems.some((i) => i.id === page1Id)).toBe(false);
  });
});

// =========================================================================
// T22 — generation guards on offline decryption & cache writes
// (+ a folders generation counter)
// =========================================================================

describe('T22 — generation guards on offline decryption & cache writes', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetVault();
    // Default: decrypt name → 'name', data → valid JSON login record.
    vi.mocked(cryptoService.decryptData).mockImplementation((enc) =>
      Promise.resolve(
        typeof enc === 'string' && enc.includes('name')
          ? 'name'
          : JSON.stringify({ username: 'u' }),
      ),
    );
  });

  const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

  describe('offline paths', () => {
    beforeEach(() => {
      Object.defineProperty(navigator, 'onLine', { configurable: true, value: false });
    });
    afterEach(() => {
      Object.defineProperty(navigator, 'onLine', { configurable: true, value: true });
    });

    it('fetchItems offline: a lock/clearStore before the cached decrypt resolves does NOT repopulate items', async () => {
      setupUnlockedVault();
      vi.mocked(listItemsApi).mockRejectedValue(new Error('offline'));

      // Cached read resolves only when the test allows it, so we can clear the
      // store mid-flight (simulating a lock/logout during a slow offline decrypt).
      let resolveCached: (v: unknown) => void = () => {};
      const cachedPromise = new Promise<unknown>((resolve) => {
        resolveCached = resolve;
      });
      vi.mocked(offlineCache.getCachedItems).mockReturnValue(
        cachedPromise as unknown as ReturnType<typeof offlineCache.getCachedItems>,
      );

      const fetchPromise = useVaultStore.getState().fetchItems();
      await tick(); // let the fetch reach the offline getCachedItems await

      // Lock/logout would call clearStore() — it bumps the generation counter.
      useVaultStore.getState().clearStore();

      resolveCached([makeRawItemResponse()]);
      await fetchPromise;

      // The stale offline decrypt must NOT write plaintext back into the
      // just-cleared store.
      expect(useVaultStore.getState().items).toEqual([]);
    });

    it('fetchItems offline: without supersession, cached items ARE decrypted and shown', async () => {
      setupUnlockedVault();
      vi.mocked(listItemsApi).mockRejectedValue(new Error('offline'));
      vi.mocked(offlineCache.getCachedItems).mockResolvedValue([
        makeRawItemResponse({ _id: '507f1f77bcf86cd799439021' }),
      ] as never);

      await useVaultStore.getState().fetchItems();

      expect(useVaultStore.getState().items).toHaveLength(1);
      expect(useVaultStore.getState().items[0]?.id).toBe('507f1f77bcf86cd799439021');
    });

    it('fetchFolders offline: a clearStore before the cached decrypt resolves does NOT repopulate folders', async () => {
      setupUnlockedVault();
      vi.mocked(listFoldersApi).mockRejectedValue(new Error('offline'));

      let resolveCached: (v: unknown) => void = () => {};
      const cachedPromise = new Promise<unknown>((resolve) => {
        resolveCached = resolve;
      });
      vi.mocked(offlineCache.getCachedFolders).mockReturnValue(
        cachedPromise as unknown as ReturnType<typeof offlineCache.getCachedFolders>,
      );

      const fetchPromise = useVaultStore.getState().fetchFolders();
      await tick();

      useVaultStore.getState().clearStore();

      resolveCached([makeRawFolderResponse()]);
      await fetchPromise;

      expect(useVaultStore.getState().folders).toEqual([]);
    });

    it('fetchFolders offline: without supersession, cached folders ARE decrypted and shown', async () => {
      setupUnlockedVault();
      vi.mocked(listFoldersApi).mockRejectedValue(new Error('offline'));
      vi.mocked(offlineCache.getCachedFolders).mockResolvedValue([
        makeRawFolderResponse({ _id: '507f1f77bcf86cd799439031' }),
      ] as never);

      await useVaultStore.getState().fetchFolders();

      expect(useVaultStore.getState().folders).toHaveLength(1);
      expect(useVaultStore.getState().folders[0]?.id).toBe('507f1f77bcf86cd799439031');
    });
  });

  describe('online paths', () => {
    it('fetchFolders online: a clearStore before the response resolves does NOT repopulate folders or write the cache', async () => {
      setupUnlockedVault();

      let resolveFolders: (v: unknown) => void = () => {};
      const foldersPromise = new Promise<unknown>((resolve) => {
        resolveFolders = resolve;
      });
      vi.mocked(listFoldersApi).mockReturnValue(
        foldersPromise as unknown as ReturnType<typeof listFoldersApi>,
      );

      const fetchPromise = useVaultStore.getState().fetchFolders();
      await tick(); // reach the listFoldersApi await

      useVaultStore.getState().clearStore();

      resolveFolders({
        data: { success: true, data: [makeRawFolderResponse()] },
      });
      await fetchPromise;

      expect(useVaultStore.getState().folders).toEqual([]);
      // F10: the fire-and-forget cache write must not run after clearStore,
      // otherwise ciphertext would be re-persisted after offlineCache.clear().
      expect(vi.mocked(offlineCache.cacheFolders)).not.toHaveBeenCalled();
    });

    it('fetchFolders online: normal flow populates folders and writes the offline cache', async () => {
      setupUnlockedVault();
      vi.mocked(listFoldersApi).mockResolvedValue({
        data: { success: true, data: [makeRawFolderResponse()] },
      } as unknown as Awaited<ReturnType<typeof listFoldersApi>>);

      await useVaultStore.getState().fetchFolders();

      expect(useVaultStore.getState().folders).toHaveLength(1);
      expect(vi.mocked(offlineCache.cacheFolders)).toHaveBeenCalledTimes(1);
    });

    it('fetchItems online: a clearStore before the page resolves does NOT write the items cache', async () => {
      setupUnlockedVault();

      let resolvePage: (v: unknown) => void = () => {};
      const pagePromise = new Promise<unknown>((resolve) => {
        resolvePage = resolve;
      });
      vi.mocked(listItemsApi).mockReturnValue(
        pagePromise as unknown as ReturnType<typeof listItemsApi>,
      );

      const fetchPromise = useVaultStore.getState().fetchItems();
      await tick();

      useVaultStore.getState().clearStore();

      resolvePage({
        data: {
          success: true,
          data: [makeRawItemResponse()],
          pagination: { page: 1, limit: 200, total: 1, totalPages: 1 },
        },
      });
      await fetchPromise;

      expect(useVaultStore.getState().items).toEqual([]);
      expect(vi.mocked(offlineCache.cacheItems)).not.toHaveBeenCalled();
    });
  });
});

// =========================================================================
// decryptExportResponse — the plaintext-export decryption bridge (Phase 10)
// =========================================================================

describe('decryptExportResponse', () => {
  const vaultKey = {} as CryptoKey;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('decrypts items and folders from the authoritative export response', async () => {
    vi.mocked(cryptoService.decryptData)
      // item: name then data
      .mockResolvedValueOnce('My Login')
      .mockResolvedValueOnce(
        JSON.stringify({ username: 'alice', password: 'pw', uris: [], customFields: [] }),
      )
      // folder: name
      .mockResolvedValueOnce('Work');

    const response = {
      items: [makeRawItemResponse()],
      folders: [makeRawFolderResponse()],
      metadata: { exportDate: '2024-01-01T00:00:00Z', version: '0.4.0', itemCount: 1 },
    };

    const { items, folders } = await decryptExportResponse(
      response as unknown as import('@hvault/shared').ExportResponse,
      vaultKey,
    );

    expect(items).toHaveLength(1);
    expect(items[0]!.name).toBe('My Login');
    expect(isUndecodableData(items[0]!.data)).toBe(false);
    expect(folders).toHaveLength(1);
    expect(folders[0]!.name).toBe('Work');
  });

  it('turns an item that cannot be decrypted into an undecodable placeholder (never dropping it)', async () => {
    // The single decryptData call (item name) rejects, so decryptItem throws.
    vi.mocked(cryptoService.decryptData).mockRejectedValueOnce(new Error('GCM tag mismatch'));

    const raw = makeRawItemResponse({ _id: 'aabbccddeeff001122334455' });
    const response = {
      items: [raw],
      folders: [],
      metadata: { exportDate: '2024-01-01T00:00:00Z', version: '0.4.0', itemCount: 1 },
    };

    const { items } = await decryptExportResponse(
      response as unknown as import('@hvault/shared').ExportResponse,
      vaultKey,
    );

    // Reported (present), not silently dropped — and flagged undecodable so
    // toPortableItems reports it in `skipped`.
    expect(items).toHaveLength(1);
    expect(items[0]!.id).toBe('aabbccddeeff001122334455');
    expect(items[0]!.name).toBe('');
    expect(isUndecodableData(items[0]!.data)).toBe(true);
  });

  it('drops an undecryptable folder from the path set and logs it', async () => {
    vi.mocked(cryptoService.decryptData).mockRejectedValueOnce(new Error('folder cipher invalid'));

    const response = {
      items: [],
      folders: [makeRawFolderResponse()],
      metadata: { exportDate: '2024-01-01T00:00:00Z', version: '0.4.0', itemCount: 0 },
    };

    const { items, folders } = await decryptExportResponse(
      response as unknown as import('@hvault/shared').ExportResponse,
      vaultKey,
    );

    expect(items).toHaveLength(0);
    expect(folders).toHaveLength(0);
    expect(vi.mocked(logger.warn)).toHaveBeenCalled();
  });
});
