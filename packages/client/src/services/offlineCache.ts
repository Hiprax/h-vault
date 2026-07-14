/**
 * Offline cache service using IndexedDB.
 * Stores encrypted vault items and folders for offline read access.
 */

// ---------------------------------------------------------------------------
// Error types for offline cache failures
// ---------------------------------------------------------------------------

export type OfflineCacheErrorType =
  'unavailable' | 'quota_exceeded' | 'permission_denied' | 'unknown';

export class OfflineCacheError extends Error {
  readonly type: OfflineCacheErrorType;

  constructor(message: string, type: OfflineCacheErrorType, cause?: unknown) {
    super(message);
    this.name = 'OfflineCacheError';
    this.type = type;
    this.cause = cause;
  }
}

function classifyError(error: unknown): OfflineCacheError {
  if (error instanceof OfflineCacheError) return error;

  if (typeof indexedDB === 'undefined') {
    return new OfflineCacheError('IndexedDB is not available', 'unavailable', error);
  }

  if (error instanceof DOMException) {
    if (error.name === 'QuotaExceededError') {
      return new OfflineCacheError('IndexedDB storage quota exceeded', 'quota_exceeded', error);
    }
    if (error.name === 'NotAllowedError' || error.name === 'SecurityError') {
      return new OfflineCacheError('IndexedDB access denied', 'permission_denied', error);
    }
  }

  const message = error instanceof Error ? error.message : 'Unknown IndexedDB error';
  return new OfflineCacheError(message, 'unknown', error);
}

// ---------------------------------------------------------------------------
// IndexedDB setup
// ---------------------------------------------------------------------------

const DB_NAME_PREFIX = 'hvault-offline';
const DB_VERSION = 1;
const ITEMS_STORE = 'items';
const FOLDERS_STORE = 'folders';
const META_STORE = 'meta';

// User-scoped database name: includes a SHA-256 hash of the user ID so that
// each user gets an isolated IndexedDB instance. This prevents cross-user
// data leakage when switching accounts in the same browser.
let currentDbName = DB_NAME_PREFIX;

/**
 * Derive a short hex hash from the user ID for use in the IndexedDB name.
 *
 * Uses SubtleCrypto (SHA-256) when available. Without it (non-secure
 * contexts), falls back to two independent 32-bit hashes concatenated into a
 * 16-hex-char (64-bit) string. The previous single 32-bit FNV-1a fallback hit
 * a 50% birthday-collision probability around ~65k user IDs — a real risk on
 * shared corporate kiosks where a collision would silently route two distinct
 * accounts to the same IndexedDB instance — so the second accumulator widens
 * the output to 64 bits.
 *
 * Both accumulators multiply with `Math.imul`. A plain `*` by these multipliers
 * overflows IEEE-754's 53-bit mantissa and silently drops the low bits *before*
 * `>>> 0`; with the 64-bit FNV prime that collapsed the upper half to a handful
 * of values (its low hex digits were always zero), so the old "2^64 key space"
 * claim was false. `Math.imul` performs a true 32-bit multiply, so each half
 * keeps its full 32-bit range.
 */
export async function deriveUserHash(userId: string): Promise<string> {
  try {
    const encoder = new TextEncoder();
    const data = encoder.encode(userId);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    // 16 bytes / 32 hex chars / 128 bits — comfortable safety margin and
    // still short enough to embed in a database name.
    return hashArray
      .slice(0, 16)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  } catch {
    // Fallback for environments without SubtleCrypto (non-secure contexts).
    // Two independent 32-bit hashes: hashA is FNV-1a; hashB uses a distinct
    // basis, input mix, and odd multiplier so a collision in one half does not
    // imply a collision in the other.
    console.warn(
      'SubtleCrypto unavailable — using FNV hash fallback for the offline cache DB name. HTTPS is recommended.',
    );
    let hashA = 0x811c9dc5; // FNV-1a 32-bit offset basis
    let hashB = 0xcbf29ce4 >>> 0; // distinct basis for the second accumulator
    for (let i = 0; i < userId.length; i++) {
      const c = userId.charCodeAt(i);
      hashA = Math.imul(hashA ^ c, 0x01000193) >>> 0; // FNV-1a 32-bit prime
      hashB = Math.imul(hashB ^ ((c + i) & 0xff), 0x5bd1e995) >>> 0; // distinct odd multiplier
    }
    return hashA.toString(16).padStart(8, '0') + hashB.toString(16).padStart(8, '0');
  }
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(currentDbName, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(ITEMS_STORE)) {
        db.createObjectStore(ITEMS_STORE, { keyPath: '_id' });
      }
      if (!db.objectStoreNames.contains(FOLDERS_STORE)) {
        db.createObjectStore(FOLDERS_STORE, { keyPath: '_id' });
      }
      if (!db.objectStoreNames.contains(META_STORE)) {
        db.createObjectStore(META_STORE, { keyPath: 'key' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () =>
      reject(request.error instanceof Error ? request.error : new Error('IndexedDB open failed'));
  });
}

export const offlineCache = {
  /**
   * Set the current user for database scoping. Must be called after login
   * (before any cache reads/writes) to ensure data isolation between users.
   * When userId is null (logged out), resets to the default unscoped DB name.
   */
  async setUser(userId: string | null): Promise<void> {
    if (userId) {
      const hash = await deriveUserHash(userId);
      currentDbName = `${DB_NAME_PREFIX}-${hash}`;
    } else {
      currentDbName = DB_NAME_PREFIX;
    }
  },

  /** Cache all vault items (replaces existing cache) */
  async cacheItems(items: unknown[]): Promise<void> {
    let db: IDBDatabase | undefined;
    try {
      db = await openDatabase();
      const tx = db.transaction(ITEMS_STORE, 'readwrite');
      const store = tx.objectStore(ITEMS_STORE);
      store.clear();
      for (const item of items) {
        store.put(item);
      }
      await new Promise<void>((resolve, reject) => {
        tx.oncomplete = () => resolve();
        tx.onerror = () =>
          reject(tx.error instanceof Error ? tx.error : new Error('IndexedDB transaction failed'));
      });
      // Update last sync timestamp
      const metaTx = db.transaction(META_STORE, 'readwrite');
      metaTx.objectStore(META_STORE).put({ key: 'lastItemsSync', value: Date.now() });
      await new Promise<void>((resolve, reject) => {
        metaTx.oncomplete = () => resolve();
        metaTx.onerror = () =>
          reject(
            metaTx.error instanceof Error
              ? metaTx.error
              : new Error('IndexedDB transaction failed'),
          );
      });
    } catch (error) {
      throw classifyError(error);
    } finally {
      db?.close();
    }
  },

  /** Cache all folders (replaces existing cache) */
  async cacheFolders(folders: unknown[]): Promise<void> {
    let db: IDBDatabase | undefined;
    try {
      db = await openDatabase();
      const tx = db.transaction(FOLDERS_STORE, 'readwrite');
      const store = tx.objectStore(FOLDERS_STORE);
      store.clear();
      for (const folder of folders) {
        store.put(folder);
      }
      await new Promise<void>((resolve, reject) => {
        tx.oncomplete = () => resolve();
        tx.onerror = () =>
          reject(tx.error instanceof Error ? tx.error : new Error('IndexedDB transaction failed'));
      });
      const metaTx = db.transaction(META_STORE, 'readwrite');
      metaTx.objectStore(META_STORE).put({ key: 'lastFoldersSync', value: Date.now() });
      await new Promise<void>((resolve, reject) => {
        metaTx.oncomplete = () => resolve();
        metaTx.onerror = () =>
          reject(
            metaTx.error instanceof Error
              ? metaTx.error
              : new Error('IndexedDB transaction failed'),
          );
      });
    } catch (error) {
      throw classifyError(error);
    } finally {
      db?.close();
    }
  },

  /** Get cached items */
  async getCachedItems<T>(): Promise<T[]> {
    let db: IDBDatabase | undefined;
    try {
      db = await openDatabase();
      const store = db.transaction(ITEMS_STORE).objectStore(ITEMS_STORE);
      return await new Promise((resolve, reject) => {
        const request = store.getAll();
        request.onsuccess = () => resolve(request.result as T[]);
        request.onerror = () =>
          reject(
            request.error instanceof Error ? request.error : new Error('IndexedDB read failed'),
          );
      });
    } catch (error) {
      throw classifyError(error);
    } finally {
      db?.close();
    }
  },

  /** Get cached folders */
  async getCachedFolders<T>(): Promise<T[]> {
    let db: IDBDatabase | undefined;
    try {
      db = await openDatabase();
      const store = db.transaction(FOLDERS_STORE).objectStore(FOLDERS_STORE);
      return await new Promise((resolve, reject) => {
        const request = store.getAll();
        request.onsuccess = () => resolve(request.result as T[]);
        request.onerror = () =>
          reject(
            request.error instanceof Error ? request.error : new Error('IndexedDB read failed'),
          );
      });
    } catch (error) {
      throw classifyError(error);
    } finally {
      db?.close();
    }
  },

  /** Get last sync timestamp for items */
  async getLastSync(type: 'items' | 'folders'): Promise<number | null> {
    let db: IDBDatabase | undefined;
    try {
      db = await openDatabase();
      const store = db.transaction(META_STORE).objectStore(META_STORE);
      const key = type === 'items' ? 'lastItemsSync' : 'lastFoldersSync';
      return await new Promise((resolve, reject) => {
        const request = store.get(key);
        request.onsuccess = () => {
          const result = request.result as { key: string; value: number } | undefined;
          resolve(result?.value ?? null);
        };
        request.onerror = () =>
          reject(
            request.error instanceof Error ? request.error : new Error('IndexedDB read failed'),
          );
      });
    } catch (error) {
      throw classifyError(error);
    } finally {
      db?.close();
    }
  },

  /** Clear all cached data */
  async clear(): Promise<void> {
    let db: IDBDatabase | undefined;
    try {
      db = await openDatabase();
      const tx = db.transaction([ITEMS_STORE, FOLDERS_STORE, META_STORE], 'readwrite');
      tx.objectStore(ITEMS_STORE).clear();
      tx.objectStore(FOLDERS_STORE).clear();
      tx.objectStore(META_STORE).clear();
      await new Promise<void>((resolve, reject) => {
        tx.oncomplete = () => resolve();
        tx.onerror = () =>
          reject(tx.error instanceof Error ? tx.error : new Error('IndexedDB transaction failed'));
      });
    } catch (error) {
      throw classifyError(error);
    } finally {
      db?.close();
    }
  },
};
