/**
 * Functional tests for client services (Task 12.5):
 *
 * A - offlineCache: IndexedDB operations, OfflineCacheError, error classification
 * B - API Client: CSRF token management, request/response interceptors
 * C - encryptedStorage: AES-256-GCM encryption round-trip, degraded mode
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ===========================================================================
// A - offlineCache
// ===========================================================================

describe('offlineCache', () => {
  // -------------------------------------------------------------------------
  // OfflineCacheError unit tests (directly importable)
  // -------------------------------------------------------------------------

  describe('OfflineCacheError', () => {
    let OfflineCacheError: typeof import('../src/services/offlineCache').OfflineCacheError;

    beforeEach(async () => {
      const mod = await import('../src/services/offlineCache');
      OfflineCacheError = mod.OfflineCacheError;
    });

    it('should construct with correct name, message, type, and cause', () => {
      const cause = new Error('root cause');
      const err = new OfflineCacheError('Storage full', 'quota_exceeded', cause);

      expect(err).toBeInstanceOf(Error);
      expect(err).toBeInstanceOf(OfflineCacheError);
      expect(err.name).toBe('OfflineCacheError');
      expect(err.message).toBe('Storage full');
      expect(err.type).toBe('quota_exceeded');
      expect(err.cause).toBe(cause);
    });

    it('should set type to "unavailable"', () => {
      const err = new OfflineCacheError('No IDB', 'unavailable');
      expect(err.type).toBe('unavailable');
      expect(err.cause).toBeUndefined();
    });

    it('should set type to "permission_denied"', () => {
      const err = new OfflineCacheError('Denied', 'permission_denied');
      expect(err.type).toBe('permission_denied');
    });

    it('should set type to "unknown"', () => {
      const err = new OfflineCacheError('Something broke', 'unknown', 'string-cause');
      expect(err.type).toBe('unknown');
      expect(err.cause).toBe('string-cause');
    });
  });

  // -------------------------------------------------------------------------
  // IndexedDB mock-based functional tests for cache operations
  // -------------------------------------------------------------------------

  describe('offlineCache operations with mocked IndexedDB', () => {
    // We build a minimal in-memory IndexedDB mock to exercise the real
    // offlineCache code paths (open, transaction, objectStore, put, getAll, etc).

    type StoreRecord = Record<string, unknown>;
    let stores: Record<string, StoreRecord[]>;

    /** Helper: create a minimal IDBRequest-like object */
    function makeRequest<T>(resultValue?: T) {
      const req: {
        result: T | undefined;
        error: DOMException | null;
        onsuccess: (() => void) | null;
        onerror: (() => void) | null;
        onupgradeneeded: (() => void) | null;
      } = {
        result: resultValue,
        error: null,
        onsuccess: null,
        onerror: null,
        onupgradeneeded: null,
      };
      return req;
    }

    function createMockObjectStore(storeName: string) {
      return {
        put: vi.fn((item: StoreRecord) => {
          if (!stores[storeName]) stores[storeName] = [];
          // Upsert by _id or key
          const keyField = storeName === 'meta' ? 'key' : '_id';
          const keyVal = item[keyField];
          const idx = stores[storeName]!.findIndex((r) => r[keyField] === keyVal);
          if (idx >= 0) {
            stores[storeName]![idx] = item;
          } else {
            stores[storeName]!.push(item);
          }
          const req = makeRequest();
          setTimeout(() => req.onsuccess?.(), 0);
          return req;
        }),
        getAll: vi.fn(() => {
          const req = makeRequest(stores[storeName] ?? []);
          setTimeout(() => req.onsuccess?.(), 0);
          return req;
        }),
        get: vi.fn((key: string) => {
          const store = stores[storeName] ?? [];
          const keyField = storeName === 'meta' ? 'key' : '_id';
          const found = store.find((r) => r[keyField] === key);
          const req = makeRequest(found);
          setTimeout(() => req.onsuccess?.(), 0);
          return req;
        }),
        clear: vi.fn(() => {
          stores[storeName] = [];
          const req = makeRequest();
          setTimeout(() => req.onsuccess?.(), 0);
          return req;
        }),
      };
    }

    function createMockTransaction(storeNames: string | string[]) {
      const _names = Array.isArray(storeNames) ? storeNames : [storeNames];
      const tx: {
        objectStore: (name: string) => ReturnType<typeof createMockObjectStore>;
        oncomplete: (() => void) | null;
        onerror: (() => void) | null;
        error: DOMException | null;
      } = {
        objectStore: (name: string) => createMockObjectStore(name),
        oncomplete: null,
        onerror: null,
        error: null,
      };
      // Fire oncomplete asynchronously
      setTimeout(() => tx.oncomplete?.(), 5);
      return tx;
    }

    function createMockDatabase() {
      return {
        objectStoreNames: {
          contains: vi.fn().mockReturnValue(false),
        },
        createObjectStore: vi.fn(),
        transaction: vi.fn((storeNames: string | string[], _mode?: IDBTransactionMode) =>
          createMockTransaction(storeNames),
        ),
        close: vi.fn(),
      };
    }

    let mockDb: ReturnType<typeof createMockDatabase>;

    beforeEach(() => {
      vi.resetModules();
      stores = { items: [], folders: [], meta: [] };
      mockDb = createMockDatabase();

      // Install a global indexedDB mock
      const openMock = vi.fn().mockImplementation(() => {
        const req = makeRequest(mockDb);
        setTimeout(() => {
          req.onupgradeneeded?.();
          req.onsuccess?.();
        }, 0);
        return req;
      });

      Object.defineProperty(globalThis, 'indexedDB', {
        value: { open: openMock },
        writable: true,
        configurable: true,
      });
    });

    afterEach(() => {
      vi.restoreAllMocks();
    });

    it('cacheItems should store items and update lastItemsSync meta', async () => {
      const { offlineCache } = await import('../src/services/offlineCache');
      const items = [
        { _id: '1', encryptedData: 'aaa' },
        { _id: '2', encryptedData: 'bbb' },
      ];

      await offlineCache.cacheItems(items);

      // Verify the database was opened (indexedDB.open was called)
      expect(
        (globalThis as unknown as { indexedDB: { open: ReturnType<typeof vi.fn> } }).indexedDB.open,
      ).toHaveBeenCalled();
      // Verify transaction was created
      expect(mockDb.transaction).toHaveBeenCalled();
      // The items must actually be persisted into the items store...
      expect(stores['items']).toEqual(items);
      // ...and the lastItemsSync meta row written (the second half of the contract).
      expect(stores['meta']).toEqual([{ key: 'lastItemsSync', value: expect.any(Number) }]);
    });

    it('cacheFolders should store folders and update lastFoldersSync meta', async () => {
      const { offlineCache } = await import('../src/services/offlineCache');
      const folders = [{ _id: 'f1', encryptedName: 'folder-data' }];

      await offlineCache.cacheFolders(folders);

      expect(mockDb.transaction).toHaveBeenCalled();
      // The folders must actually be persisted into the folders store...
      expect(stores['folders']).toEqual(folders);
      // ...and the lastFoldersSync meta row written.
      expect(stores['meta']).toEqual([{ key: 'lastFoldersSync', value: expect.any(Number) }]);
    });

    it('getCachedItems should return stored items from the items store', async () => {
      stores['items'] = [
        { _id: '1', data: 'x' },
        { _id: '2', data: 'y' },
      ];
      const { offlineCache } = await import('../src/services/offlineCache');

      const result = await offlineCache.getCachedItems();

      expect(result).toEqual([
        { _id: '1', data: 'x' },
        { _id: '2', data: 'y' },
      ]);
    });

    it('getCachedFolders should return stored folders', async () => {
      stores['folders'] = [{ _id: 'f1', name: 'test' }];
      const { offlineCache } = await import('../src/services/offlineCache');

      const result = await offlineCache.getCachedFolders();

      expect(result).toEqual([{ _id: 'f1', name: 'test' }]);
    });

    it('getLastSync should return null when no sync timestamp exists', async () => {
      stores['meta'] = [];
      const { offlineCache } = await import('../src/services/offlineCache');

      const result = await offlineCache.getLastSync('items');

      // The mock returns undefined for missing keys, which falls to ?? null
      expect(result).toBeNull();
    });

    it('getLastSync should return stored timestamp when present', async () => {
      const now = Date.now();
      stores['meta'] = [{ key: 'lastItemsSync', value: now }];
      const { offlineCache } = await import('../src/services/offlineCache');

      const result = await offlineCache.getLastSync('items');

      expect(result).toBe(now);
    });

    it('getLastSync("folders") should query the correct meta key', async () => {
      const now = Date.now();
      stores['meta'] = [{ key: 'lastFoldersSync', value: now }];
      const { offlineCache } = await import('../src/services/offlineCache');

      const result = await offlineCache.getLastSync('folders');

      expect(result).toBe(now);
    });

    it('clear should clear all three stores', async () => {
      stores['items'] = [{ _id: '1' }];
      stores['folders'] = [{ _id: 'f1' }];
      stores['meta'] = [{ key: 'lastItemsSync', value: 123 }];

      const { offlineCache } = await import('../src/services/offlineCache');
      await offlineCache.clear();

      // transaction was called to clear all stores
      expect(mockDb.transaction).toHaveBeenCalled();
      // All three stores must actually be emptied — encrypted item/folder
      // ciphertext surviving a lock/logout is the cross-user leak clear() prevents.
      expect(stores['items']).toEqual([]);
      expect(stores['folders']).toEqual([]);
      expect(stores['meta']).toEqual([]);
    });
  });

  // -------------------------------------------------------------------------
  // Error classification via failing operations
  // -------------------------------------------------------------------------

  describe('error classification through cache operations', () => {
    afterEach(() => {
      vi.restoreAllMocks();
      vi.resetModules();
    });

    // The classifyError function is not exported, but it is invoked in the
    // catch blocks of cacheItems and cacheFolders.  To trigger the DOMException
    // code paths we throw the DOMException *synchronously* from indexedDB.open()
    // so that the try/catch in cacheItems/cacheFolders catches it directly and
    // feeds it to classifyError.  (Using request.onerror would cause openDatabase
    // to wrap the error in a plain Error, losing the DOMException prototype.)

    it('should throw OfflineCacheError with type "quota_exceeded" on QuotaExceededError', async () => {
      vi.resetModules();

      const quotaError = new DOMException('Quota exceeded', 'QuotaExceededError');

      Object.defineProperty(globalThis, 'indexedDB', {
        value: {
          open: vi.fn().mockImplementation(() => {
            throw quotaError;
          }),
        },
        writable: true,
        configurable: true,
      });

      const { offlineCache, OfflineCacheError } = await import('../src/services/offlineCache');

      let caught: unknown;
      try {
        await offlineCache.cacheItems([]);
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(OfflineCacheError);
      expect((caught as InstanceType<typeof OfflineCacheError>).type).toBe('quota_exceeded');
      expect((caught as InstanceType<typeof OfflineCacheError>).cause).toBe(quotaError);
    });

    it('should throw OfflineCacheError with type "permission_denied" on NotAllowedError', async () => {
      vi.resetModules();

      const notAllowed = new DOMException('Not allowed', 'NotAllowedError');

      Object.defineProperty(globalThis, 'indexedDB', {
        value: {
          open: vi.fn().mockImplementation(() => {
            throw notAllowed;
          }),
        },
        writable: true,
        configurable: true,
      });

      const { offlineCache, OfflineCacheError } = await import('../src/services/offlineCache');

      let caught: unknown;
      try {
        await offlineCache.cacheFolders([]);
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(OfflineCacheError);
      expect((caught as InstanceType<typeof OfflineCacheError>).type).toBe('permission_denied');
    });

    it('should throw OfflineCacheError with type "permission_denied" on SecurityError', async () => {
      vi.resetModules();

      const secError = new DOMException('Security violation', 'SecurityError');

      Object.defineProperty(globalThis, 'indexedDB', {
        value: {
          open: vi.fn().mockImplementation(() => {
            throw secError;
          }),
        },
        writable: true,
        configurable: true,
      });

      const { offlineCache, OfflineCacheError } = await import('../src/services/offlineCache');

      let caught: unknown;
      try {
        // Use cacheItems which has try/catch → classifyError
        await offlineCache.cacheItems([]);
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(OfflineCacheError);
      expect((caught as InstanceType<typeof OfflineCacheError>).type).toBe('permission_denied');
    });

    it('should throw OfflineCacheError with type "unknown" on generic errors', async () => {
      vi.resetModules();

      const genericError = new Error('Unexpected failure');

      Object.defineProperty(globalThis, 'indexedDB', {
        value: {
          open: vi.fn().mockImplementation(() => {
            throw genericError;
          }),
        },
        writable: true,
        configurable: true,
      });

      const { offlineCache, OfflineCacheError } = await import('../src/services/offlineCache');

      let caught: unknown;
      try {
        // Use cacheFolders which has try/catch → classifyError
        await offlineCache.cacheFolders([]);
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(OfflineCacheError);
      expect((caught as InstanceType<typeof OfflineCacheError>).type).toBe('unknown');
      expect((caught as InstanceType<typeof OfflineCacheError>).message).toBe('Unexpected failure');
    });

    it('should pass through an existing OfflineCacheError unchanged', async () => {
      vi.resetModules();

      // Import module once so OfflineCacheError and classifyError share the same class reference
      const { offlineCache, OfflineCacheError } = await import('../src/services/offlineCache');
      const existing = new OfflineCacheError('Already classified', 'quota_exceeded');

      // Now make indexedDB.open throw that same OfflineCacheError instance
      Object.defineProperty(globalThis, 'indexedDB', {
        value: {
          open: vi.fn().mockImplementation(() => {
            throw existing;
          }),
        },
        writable: true,
        configurable: true,
      });

      let caught: unknown;
      try {
        await offlineCache.cacheItems([]);
      } catch (err) {
        caught = err;
      }
      // classifyError returns existing OfflineCacheError as-is (identity check)
      expect(caught).toBe(existing);
      expect((caught as InstanceType<typeof OfflineCacheError>).type).toBe('quota_exceeded');
    });

    it('should throw OfflineCacheError with type "unavailable" when indexedDB is undefined', async () => {
      vi.resetModules();

      // Remove indexedDB entirely
      const original = globalThis.indexedDB;

      delete (globalThis as Record<string, unknown>)['indexedDB'];

      try {
        const { offlineCache, OfflineCacheError } = await import('../src/services/offlineCache');

        let caught: unknown;
        try {
          await offlineCache.cacheItems([]);
        } catch (err) {
          caught = err;
        }
        expect(caught).toBeInstanceOf(OfflineCacheError);
        expect((caught as InstanceType<typeof OfflineCacheError>).type).toBe('unavailable');
      } finally {
        // Restore
        Object.defineProperty(globalThis, 'indexedDB', {
          value: original,
          writable: true,
          configurable: true,
        });
      }
    });

    it('should classify non-Error thrown values as "unknown" with default message', async () => {
      vi.resetModules();

      Object.defineProperty(globalThis, 'indexedDB', {
        value: {
          open: vi.fn().mockImplementation(() => {
            // Throw a non-Error value
            throw 'string-error';
          }),
        },
        writable: true,
        configurable: true,
      });

      const { offlineCache, OfflineCacheError } = await import('../src/services/offlineCache');

      let caught: unknown;
      try {
        await offlineCache.cacheItems([]);
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(OfflineCacheError);
      expect((caught as InstanceType<typeof OfflineCacheError>).type).toBe('unknown');
      expect((caught as InstanceType<typeof OfflineCacheError>).message).toBe(
        'Unknown IndexedDB error',
      );
    });
  });
});

// ===========================================================================
// B - API Client (CSRF, interceptors, 401/403 handling)
// ===========================================================================

describe('API Client', () => {
  // We use vi.mock to control the authStore dynamic import and axios behavior.

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
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('clearCsrfToken', () => {
    it('should write invalidation signal to localStorage', async () => {
      // Import without module mocking to test the exported function
      vi.resetModules();

      // We need to mock the authStore import that fires in the module
      vi.doMock('../src/stores/authStore', () => ({
        useAuthStore: { getState: mockGetState },
      }));

      const { clearCsrfToken } = await import('../src/services/api/client');

      clearCsrfToken();

      const stored = localStorage.getItem('__hv_csrf_invalidated');
      expect(stored).toBeTruthy();
      // The value should be a numeric timestamp string
      expect(Number(stored)).toBeGreaterThan(0);
    });

    it('should not throw when localStorage is unavailable', async () => {
      vi.resetModules();
      vi.doMock('../src/stores/authStore', () => ({
        useAuthStore: { getState: mockGetState },
      }));

      const { clearCsrfToken } = await import('../src/services/api/client');

      // Temporarily break localStorage
      const originalSetItem = localStorage.setItem;
      localStorage.setItem = () => {
        throw new Error('localStorage disabled');
      };

      expect(() => clearCsrfToken()).not.toThrow();

      localStorage.setItem = originalSetItem;
    });
  });

  describe('Request interceptor', () => {
    it('should attach Authorization header when accessToken exists', async () => {
      vi.resetModules();

      mockGetState.mockReturnValue({
        accessToken: 'test-jwt-token',
        setAccessToken: mockSetAccessToken,
        logout: mockLogout,
      });

      vi.doMock('../src/stores/authStore', () => ({
        useAuthStore: { getState: mockGetState },
      }));

      const { api } = await import('../src/services/api/client');

      // Get the request interceptor by inspecting interceptors
      // We'll test by examining what the interceptor does to a config
      const interceptors = (
        api.interceptors.request as unknown as {
          handlers: {
            fulfilled: (config: Record<string, unknown>) => Promise<Record<string, unknown>>;
          }[];
        }
      ).handlers;
      expect(interceptors.length).toBeGreaterThan(0);

      const requestInterceptor = interceptors[0]!.fulfilled;

      // Simulate a GET request config (safe method, no CSRF needed)
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

      const result = await requestInterceptor(config as unknown as Record<string, unknown>);
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

      vi.doMock('../src/stores/authStore', () => ({
        useAuthStore: { getState: mockGetState },
      }));

      const { api } = await import('../src/services/api/client');

      const interceptors = (
        api.interceptors.request as unknown as {
          handlers: {
            fulfilled: (config: Record<string, unknown>) => Promise<Record<string, unknown>>;
          }[];
        }
      ).handlers;
      const requestInterceptor = interceptors[0]!.fulfilled;

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

      const result = await requestInterceptor(config as unknown as Record<string, unknown>);
      expect(
        (result as { headers: Record<string, string | undefined> }).headers['Authorization'],
      ).toBeUndefined();
    });
  });

  describe('CSRF token handling in request interceptor', () => {
    it('should NOT attach x-csrf-token for safe methods (GET, HEAD, OPTIONS)', async () => {
      vi.resetModules();
      vi.doMock('../src/stores/authStore', () => ({
        useAuthStore: { getState: mockGetState },
      }));

      const { api } = await import('../src/services/api/client');

      const interceptors = (
        api.interceptors.request as unknown as {
          handlers: {
            fulfilled: (config: Record<string, unknown>) => Promise<Record<string, unknown>>;
          }[];
        }
      ).handlers;
      const requestInterceptor = interceptors[0]!.fulfilled;

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

        const result = await requestInterceptor(config as unknown as Record<string, unknown>);
        expect(
          (result as { headers: Record<string, string | undefined> }).headers['x-csrf-token'],
        ).toBeUndefined();
      }
    });
  });

  describe('Response interceptor — 403 CSRF retry', () => {
    it('clears the cached CSRF token and replays with a freshly fetched token on 403', async () => {
      vi.resetModules();
      vi.doMock('../src/stores/authStore', () => ({
        useAuthStore: { getState: mockGetState },
      }));

      const axios = (await import('axios')).default;
      const { api } = await import('../src/services/api/client');

      // The /csrf-token endpoint serves an incrementing token; every replayed
      // /vault/items request records the x-csrf-token header it actually carried.
      let csrfCounter = 0;
      const replayedTokens: (string | undefined)[] = [];
      const adapter = async (config: {
        url?: string;
        headers?: Record<string, unknown> & { get?: (name: string) => unknown };
      }) => {
        const url = config.url ?? '';
        const base = { status: 200, statusText: 'OK', headers: {}, config };
        if (url.includes('csrf-token')) {
          csrfCounter += 1;
          return { ...base, data: { data: { csrfToken: `csrf-${String(csrfCounter)}` } } };
        }
        if (url.includes('/vault/items')) {
          const headers = config.headers ?? {};
          const raw =
            typeof headers.get === 'function'
              ? headers.get('x-csrf-token')
              : headers['x-csrf-token'];
          replayedTokens.push(raw === undefined || raw === null ? undefined : String(raw));
        }
        return { ...base, data: { ok: true } };
      };
      axios.defaults.adapter = adapter as never;
      api.defaults.adapter = adapter as never;

      // Prime the CSRF cache with csrf-1 via a first state-changing request.
      await api.post('/vault/items', {});
      expect(replayedTokens).toEqual(['csrf-1']);

      const interceptors = (
        api.interceptors.response as unknown as {
          handlers: { rejected: (error: unknown) => Promise<unknown> }[];
        }
      ).handlers;
      expect(interceptors.length).toBeGreaterThan(0);

      const responseInterceptor = interceptors[0]!.rejected;

      const mockError = {
        response: { status: 403 },
        config: {
          url: '/vault/items',
          method: 'post',
          headers: {} as Record<string, string>,
          _csrfRetry: undefined as boolean | undefined,
        },
      };

      // The interceptor resolves: it clears the stale csrf-1, fetches csrf-2, and
      // replays the request (which now succeeds with 200).
      const result = await responseInterceptor(mockError);
      expect((result as { data: { ok: boolean } }).data.ok).toBe(true);
      expect(mockError.config._csrfRetry).toBe(true);

      // The replayed request must carry the FRESHLY fetched token (csrf-2), which
      // is only possible if the cached csrf-1 was invalidated and re-fetched.
      // Remove clearCsrfToken()/the header assignment from the 403 branch and the
      // replay reuses the stale csrf-1, failing this assertion.
      expect(replayedTokens.at(-1)).toBe('csrf-2');
    });

    it('should not retry 403 if _csrfRetry is already set', async () => {
      vi.resetModules();
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
        response: { status: 403 },
        config: {
          url: '/vault/items',
          method: 'post',
          headers: {},
          _csrfRetry: true, // Already retried
        },
      };

      // Should fall through to 401 check, then reject
      await expect(responseInterceptor(mockError)).rejects.toBeDefined();
    });
  });

  describe('Response interceptor — 401 token refresh', () => {
    it('should not attempt refresh on /auth/refresh endpoint (prevent loop)', async () => {
      vi.resetModules();
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
          url: '/auth/refresh',
          method: 'post',
          headers: {},
          _retry: false,
          _csrfRetry: true, // Skip 403 path
        },
      };

      await expect(responseInterceptor(mockError)).rejects.toBeDefined();
    });

    it('should not attempt refresh on /auth/logout endpoint', async () => {
      vi.resetModules();
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
          url: '/auth/logout',
          method: 'post',
          headers: {},
          _retry: false,
          _csrfRetry: true,
        },
      };

      await expect(responseInterceptor(mockError)).rejects.toBeDefined();
    });

    it('should not attempt refresh if _retry is already true', async () => {
      vi.resetModules();
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
          _retry: true, // Already retried
          _csrfRetry: true,
        },
      };

      await expect(responseInterceptor(mockError)).rejects.toBeDefined();
    });

    it('should reject non-401/non-403 errors without interception', async () => {
      vi.resetModules();
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
        response: { status: 500 },
        config: {
          url: '/vault/items',
          method: 'get',
          headers: {},
          _csrfRetry: true,
        },
      };

      await expect(responseInterceptor(mockError)).rejects.toBeDefined();
    });

    it('should reject when error has no config', async () => {
      vi.resetModules();
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
        config: undefined,
      };

      await expect(responseInterceptor(mockError)).rejects.toBeDefined();
    });

    // -----------------------------------------------------------------------
    // Refresh-succeeds-but-retry-fails: the retried request's rejection must
    // propagate to the caller UNCHANGED and must NOT trigger a logout. Only a
    // failed refresh POST is an unrecoverable session.
    // -----------------------------------------------------------------------

    /**
     * Build a mock Axios adapter that succeeds for the CSRF + refresh calls and
     * fails the retried original request with `retryStatus`.
     */
    function buildRefreshAdapter(retryStatus: number) {
      return async (config: { url?: string }) => {
        const url = config.url ?? '';
        const ok = (data: unknown) => ({
          data,
          status: 200,
          statusText: 'OK',
          headers: {},
          config,
        });
        if (url.includes('csrf-token')) return ok({ data: { csrfToken: 'test-csrf' } });
        if (url.includes('/auth/refresh')) return ok({ data: { accessToken: 'new-access-token' } });
        // The retried original request fails. A custom function adapter does
        // NOT apply validateStatus, so we must reject with an AxiosError-shaped
        // error (carrying `.response.status`) exactly as the real xhr/http
        // adapter's settle() would, to exercise the retry-failure path.
        const response = {
          data: { error: { message: 'boom' } },
          status: retryStatus,
          statusText: 'Error',
          headers: {},
          config,
        };
        return Promise.reject(
          Object.assign(new Error(`Request failed with status code ${retryStatus}`), {
            isAxiosError: true,
            config,
            response,
          }),
        );
      };
    }

    async function setupRefreshFlow(retryStatus: number) {
      vi.resetModules();
      mockLogout.mockClear();
      mockSetAccessToken.mockClear();
      mockGetState.mockReturnValue({
        accessToken: 'expired-token',
        setAccessToken: mockSetAccessToken,
        logout: mockLogout,
      });
      vi.doMock('../src/stores/authStore', () => ({
        useAuthStore: { getState: mockGetState },
      }));

      const axios = (await import('axios')).default;
      const { api } = await import('../src/services/api/client');
      const adapter = buildRefreshAdapter(retryStatus);
      // Both the global axios (used for the CSRF GET) and the api instance
      // (refresh + retry) must resolve through the mock adapter.
      axios.defaults.adapter = adapter as never;
      api.defaults.adapter = adapter as never;

      const responseInterceptor = (
        api.interceptors.response as unknown as {
          handlers: { rejected: (error: unknown) => Promise<unknown> }[];
        }
      ).handlers[0]!.rejected;

      return { responseInterceptor };
    }

    it('should NOT logout when refresh succeeds but the retried request fails (409)', async () => {
      const { responseInterceptor } = await setupRefreshFlow(409);

      const mockError = {
        response: { status: 401 },
        config: {
          url: '/vault/items',
          method: 'get',
          headers: {} as Record<string, string>,
          _csrfRetry: true, // skip the 403 path
        },
      };

      // The caller receives the retry's 409, NOT a logout.
      await expect(responseInterceptor(mockError)).rejects.toMatchObject({
        response: { status: 409 },
      });
      expect(mockSetAccessToken).toHaveBeenCalledWith('new-access-token');
      expect(mockLogout).not.toHaveBeenCalled();
    });

    it('should NOT logout when refresh succeeds but the retried request fails (500)', async () => {
      const { responseInterceptor } = await setupRefreshFlow(500);

      const mockError = {
        response: { status: 401 },
        config: {
          url: '/vault/items',
          method: 'get',
          headers: {} as Record<string, string>,
          _csrfRetry: true,
        },
      };

      await expect(responseInterceptor(mockError)).rejects.toMatchObject({
        response: { status: 500 },
      });
      expect(mockLogout).not.toHaveBeenCalled();
    });

    it('should logout when the refresh POST itself fails', async () => {
      vi.resetModules();
      mockLogout.mockClear();
      mockGetState.mockReturnValue({
        accessToken: 'expired-token',
        setAccessToken: mockSetAccessToken,
        logout: mockLogout,
      });
      vi.doMock('../src/stores/authStore', () => ({
        useAuthStore: { getState: mockGetState },
      }));

      const axios = (await import('axios')).default;
      const { api } = await import('../src/services/api/client');
      // CSRF succeeds; the refresh POST fails → the refresh try/catch runs
      // logout(). (The /auth/refresh URL is guarded from re-entering the refresh
      // cycle, so its rejection surfaces straight to the catch.)
      const adapter = async (config: { url?: string }) => {
        const url = config.url ?? '';
        if (url.includes('csrf-token')) {
          return {
            data: { data: { csrfToken: 'test-csrf' } },
            status: 200,
            statusText: 'OK',
            headers: {},
            config,
          };
        }
        return Promise.reject(
          Object.assign(new Error('Request failed with status code 401'), {
            isAxiosError: true,
            config,
            response: {
              data: { error: { message: 'refresh rejected' } },
              status: 401,
              statusText: 'Unauthorized',
              headers: {},
              config,
            },
          }),
        );
      };
      axios.defaults.adapter = adapter as never;
      api.defaults.adapter = adapter as never;

      const responseInterceptor = (
        api.interceptors.response as unknown as {
          handlers: { rejected: (error: unknown) => Promise<unknown> }[];
        }
      ).handlers[0]!.rejected;

      const mockError = {
        response: { status: 401 },
        config: {
          url: '/vault/items',
          method: 'get',
          headers: {} as Record<string, string>,
          _csrfRetry: true,
        },
      };

      await expect(responseInterceptor(mockError)).rejects.toBeDefined();
      expect(mockLogout).toHaveBeenCalledTimes(1);
    });
  });

  describe('api instance configuration', () => {
    it('should have baseURL set to /api/v1', async () => {
      vi.resetModules();
      vi.doMock('../src/stores/authStore', () => ({
        useAuthStore: { getState: mockGetState },
      }));

      const { api } = await import('../src/services/api/client');

      expect(api.defaults.baseURL).toBe('/api/v1');
    });

    it('should have withCredentials set to true', async () => {
      vi.resetModules();
      vi.doMock('../src/stores/authStore', () => ({
        useAuthStore: { getState: mockGetState },
      }));

      const { api } = await import('../src/services/api/client');

      expect(api.defaults.withCredentials).toBe(true);
    });

    it('should have Content-Type set to application/json', async () => {
      vi.resetModules();
      vi.doMock('../src/stores/authStore', () => ({
        useAuthStore: { getState: mockGetState },
      }));

      const { api } = await import('../src/services/api/client');

      expect(api.defaults.headers['Content-Type']).toBe('application/json');
    });
  });
});

// ===========================================================================
// C - encryptedStorage (AES-256-GCM round-trip, degraded mode)
// ===========================================================================

describe('encryptedStorage', () => {
  beforeEach(() => {
    vi.resetModules();
    localStorage.clear();
    sessionStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('setItem and getItem round-trip', () => {
    it('should encrypt data and store base64 in localStorage', async () => {
      const { encryptedStorage } = await import('../src/stores/encryptedStorage');

      await encryptedStorage.setItem('test-key', 'hello world');

      const stored = localStorage.getItem('test-key');
      expect(stored).toBeTruthy();
      // The stored value should be base64-encoded (not the plaintext)
      expect(stored).not.toBe('hello world');
      // Base64 string should be decodable
      expect(() => atob(stored!)).not.toThrow();
    });

    it('should decrypt stored data back to original value (round-trip)', async () => {
      const { encryptedStorage } = await import('../src/stores/encryptedStorage');

      const original = 'H-Vault test data with special chars: !@#$%^&*()';
      await encryptedStorage.setItem('roundtrip-key', original);

      const result = await encryptedStorage.getItem('roundtrip-key');
      expect(result).toBe(original);
    });

    it('should handle empty string values', async () => {
      const { encryptedStorage } = await import('../src/stores/encryptedStorage');

      await encryptedStorage.setItem('empty-key', '');

      const result = await encryptedStorage.getItem('empty-key');
      expect(result).toBe('');
    });

    it('should handle large JSON payloads', async () => {
      const { encryptedStorage } = await import('../src/stores/encryptedStorage');

      const largePayload = JSON.stringify({
        items: Array.from({ length: 100 }, (_, i) => ({
          id: i,
          name: `Item ${i}`,
          data: 'x'.repeat(100),
        })),
      });

      await encryptedStorage.setItem('large-key', largePayload);

      const result = await encryptedStorage.getItem('large-key');
      expect(result).toBe(largePayload);
    });

    it('should generate a session key in sessionStorage on first use', async () => {
      expect(sessionStorage.getItem('hvault_storage_key')).toBeNull();

      const { encryptedStorage } = await import('../src/stores/encryptedStorage');
      await encryptedStorage.setItem('key', 'value');

      const sessionKey = sessionStorage.getItem('hvault_storage_key');
      expect(sessionKey).toBeTruthy();
      // Should be a base64 string (AES-256 = 32 bytes raw)
      expect(() => atob(sessionKey!)).not.toThrow();
      const raw = atob(sessionKey!);
      expect(raw.length).toBe(32); // 256 bits = 32 bytes
    });

    it('should reuse the same session key across multiple operations', async () => {
      const { encryptedStorage } = await import('../src/stores/encryptedStorage');

      await encryptedStorage.setItem('key1', 'value1');
      const key1 = sessionStorage.getItem('hvault_storage_key');

      await encryptedStorage.setItem('key2', 'value2');
      const key2 = sessionStorage.getItem('hvault_storage_key');

      expect(key1).toBe(key2);
    });

    it('each encryption should produce different ciphertext (random IVs)', async () => {
      const { encryptedStorage } = await import('../src/stores/encryptedStorage');

      await encryptedStorage.setItem('key-a', 'same-value');
      const stored1 = localStorage.getItem('key-a');

      // Clear and re-set with same value
      localStorage.removeItem('key-a');
      await encryptedStorage.setItem('key-a', 'same-value');
      const stored2 = localStorage.getItem('key-a');

      // Due to random IV, ciphertext should differ
      expect(stored1).not.toBe(stored2);
    });
  });

  describe('getItem edge cases', () => {
    it('should return null for missing keys', async () => {
      const { encryptedStorage } = await import('../src/stores/encryptedStorage');

      const result = await encryptedStorage.getItem('nonexistent');
      expect(result).toBeNull();
    });

    it('should remove corrupted data (buffer too short) and return null', async () => {
      const { encryptedStorage } = await import('../src/stores/encryptedStorage');

      // First set an item to create the session key
      await encryptedStorage.setItem('setup', 'setup');

      // Now put a too-short base64 value directly (less than 13 bytes)
      // 8 bytes = "AAAAAAAA" in base64 is "QUFBQUFBQUE="
      const shortBytes = new Uint8Array(8);
      const shortBase64 = btoa(String.fromCharCode(...shortBytes));
      localStorage.setItem('corrupt-key', shortBase64);

      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      const result = await encryptedStorage.getItem('corrupt-key');
      expect(result).toBeNull();
      // The corrupted entry should be removed
      expect(localStorage.getItem('corrupt-key')).toBeNull();

      consoleSpy.mockRestore();
    });

    it('should remove data with invalid ciphertext and return null', async () => {
      const { encryptedStorage } = await import('../src/stores/encryptedStorage');

      // Create session key first
      await encryptedStorage.setItem('setup', 'setup');

      // Put random 20 bytes (valid length but garbage ciphertext)
      const garbage = new Uint8Array(20);
      crypto.getRandomValues(garbage);
      const garbageBase64 = btoa(String.fromCharCode(...garbage));
      localStorage.setItem('garbage-key', garbageBase64);

      const result = await encryptedStorage.getItem('garbage-key');
      expect(result).toBeNull();
      // Corrupted entry should be cleaned up
      expect(localStorage.getItem('garbage-key')).toBeNull();
    });
  });

  describe('removeItem', () => {
    it('should remove item from localStorage', async () => {
      const { encryptedStorage } = await import('../src/stores/encryptedStorage');

      await encryptedStorage.setItem('remove-me', 'data');
      expect(localStorage.getItem('remove-me')).toBeTruthy();

      encryptedStorage.removeItem('remove-me');
      expect(localStorage.getItem('remove-me')).toBeNull();
    });

    it('should not throw when removing nonexistent key', async () => {
      const { encryptedStorage } = await import('../src/stores/encryptedStorage');

      expect(() => encryptedStorage.removeItem('nonexistent')).not.toThrow();
    });
  });

  describe('isStorageDegraded', () => {
    it('should return false when degraded flag is not set', async () => {
      const { isStorageDegraded } = await import('../src/stores/encryptedStorage');

      expect(isStorageDegraded()).toBe(false);
    });

    it('should return true when degraded flag is set to "true"', async () => {
      localStorage.setItem('__hv_storage_degraded', 'true');

      const { isStorageDegraded } = await import('../src/stores/encryptedStorage');

      expect(isStorageDegraded()).toBe(true);
    });

    it('should return false when degraded flag has non-"true" value', async () => {
      localStorage.setItem('__hv_storage_degraded', 'false');

      const { isStorageDegraded } = await import('../src/stores/encryptedStorage');

      expect(isStorageDegraded()).toBe(false);
    });
  });

  describe('degraded mode (crypto.subtle unavailable)', () => {
    it('should fall back to unencrypted storage and set degraded flag', async () => {
      vi.resetModules();

      // Temporarily remove crypto.subtle
      const originalCrypto = globalThis.crypto;
      Object.defineProperty(globalThis, 'crypto', {
        value: {
          getRandomValues: originalCrypto.getRandomValues.bind(originalCrypto),
          // No subtle property
        },
        writable: true,
        configurable: true,
      });

      // Clear any existing session key
      sessionStorage.removeItem('hvault_storage_key');

      try {
        const { encryptedStorage, isStorageDegraded } =
          await import('../src/stores/encryptedStorage');

        await encryptedStorage.setItem('degraded-key', 'plaintext-value');

        // In degraded mode, non-JSON values get wrapped in a safe state structure
        expect(isStorageDegraded()).toBe(true);
        expect(localStorage.getItem('__hv_storage_degraded')).toBe('true');

        // M5: Verify only isAuthenticated is kept in degraded mode (all sensitive fields stripped)
        const sensitiveState = JSON.stringify({
          state: {
            user: { userId: 'u1', email: 'a@b.com' },
            isAuthenticated: true,
            encryptedVaultKeyData: { encrypted: 'secret', iv: 'iv', tag: 'tag' },
            isLocked: false,
          },
          version: 0,
        });
        await encryptedStorage.setItem('degraded-sensitive', sensitiveState);
        const stored = localStorage.getItem('degraded-sensitive');
        expect(stored).toBeTruthy();
        const parsed = JSON.parse(stored!) as Record<string, unknown>;
        const state = (parsed as { state: Record<string, unknown> }).state;
        // All sensitive fields must be stripped
        expect(state.encryptedVaultKeyData).toBeUndefined();
        expect(state.user).toBeUndefined();
        expect(state.isLocked).toBeUndefined();
        // Only isAuthenticated should survive
        expect(state.isAuthenticated).toBe(true);
        // version and other top-level keys should remain
        expect(parsed.version).toBe(0);
      } finally {
        // Restore crypto
        Object.defineProperty(globalThis, 'crypto', {
          value: originalCrypto,
          writable: true,
          configurable: true,
        });
      }
    });

    it('should clear degraded flag when encryption starts working again', async () => {
      // Set the degraded flag manually
      localStorage.setItem('__hv_storage_degraded', 'true');

      const { encryptedStorage, isStorageDegraded } =
        await import('../src/stores/encryptedStorage');

      // Now use it with working crypto — should encrypt and clear degraded flag
      await encryptedStorage.setItem('good-key', 'encrypted-value');

      expect(isStorageDegraded()).toBe(false);
      expect(localStorage.getItem('__hv_storage_degraded')).toBeNull();
      // The stored value should be encrypted (not plaintext)
      expect(localStorage.getItem('good-key')).not.toBe('encrypted-value');
    });
  });
});
