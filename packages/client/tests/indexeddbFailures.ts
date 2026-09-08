/**
 * Shared plumbing for driving REAL IndexedDB failures in the two IndexedDB-backed
 * services (`offlineCache` and `healthResultsStore`).
 *
 * Everything here operates at the storage boundary and returns genuine engine
 * objects — real `IDBRequest`s, real `DOMException`s, real event timing — so the
 * handlers under test run the way they run in a browser rather than against a
 * hand-rolled double. Nothing here substitutes any part of the code under test.
 *
 * Two measured facts about the environment shape these helpers, and both were
 * observed rather than assumed:
 *
 *  1. `IDBTransaction.error` is still `null` while a failing request's `error`
 *     event bubbles; the bubbled event's `target` is the request, and it carries
 *     the real `DOMException`.
 *  2. `DOMException instanceof Error` is TRUE in every browser and in Node, and
 *     FALSE under jsdom, whose `DOMException` inherits from a different realm's
 *     `Error.prototype`. Production code must therefore not use that check to
 *     decide whether an engine error is present, or the suite and the browser
 *     take different arms.
 *
 * The callers require `fake-indexeddb/auto` to be imported by the test file.
 */

export interface RawStoreSpec {
  name: string;
  keyPath: string;
}

/** Open (and if needed create) a database directly, bypassing the module under test. */
export function openRawDatabase(
  name: string,
  version: number,
  stores: readonly RawStoreSpec[] = [],
): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(name, version);
    request.onupgradeneeded = () => {
      for (const store of stores) {
        if (!request.result.objectStoreNames.contains(store.name)) {
          request.result.createObjectStore(store.name, { keyPath: store.keyPath });
        }
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('raw open failed'));
  });
}

/** Write one record directly, bypassing the module under test. */
function putRawRecord(db: IDBDatabase, storeName: string, record: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    tx.objectStore(storeName).put(record);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(new Error(`raw put into ${storeName} failed`));
  });
}

/**
 * A factory for REAL requests that are guaranteed to fail asynchronously with a
 * `ConstraintError`, minted from a scratch database of their own.
 *
 * This exists because a READONLY transaction cannot be made to fail from the
 * outside: `add` on a readonly store throws `ReadOnlyError` synchronously and
 * never reaches `request.onerror`. Handing the code under test a request from a
 * separate readwrite transaction gives it a genuine failing request to attach
 * its handler to, with a genuine `DOMException` in `.error`.
 */
export async function createDoomedRequestFactory(scratchDbName: string): Promise<() => IDBRequest> {
  const db = await openRawDatabase(scratchDbName, 1, [{ name: 'rows', keyPath: '_id' }]);
  await putRawRecord(db, 'rows', { _id: 'dup' });
  return () => db.transaction('rows', 'readwrite').objectStore('rows').add({ _id: 'dup' });
}

/**
 * Run `fn` with `globalThis.indexedDB` replaced, restoring it afterwards even if
 * `fn` throws. Pass `undefined` to model a browser that has no IndexedDB at all.
 */
export async function withIndexedDB<T>(replacement: unknown, fn: () => Promise<T>): Promise<T> {
  const original = Object.getOwnPropertyDescriptor(globalThis, 'indexedDB');
  Object.defineProperty(globalThis, 'indexedDB', { value: replacement, configurable: true });
  try {
    return await fn();
  } finally {
    if (original) {
      Object.defineProperty(globalThis, 'indexedDB', original);
    } else {
      Reflect.deleteProperty(globalThis, 'indexedDB');
    }
  }
}

/**
 * A stand-in `indexedDB` whose `open` throws. Chrome and Firefox both throw
 * synchronously from `indexedDB.open()` when site data is blocked
 * (`SecurityError`) or the origin is over quota (`QuotaExceededError`), so this
 * is the shape of a real refusal rather than an invented one.
 */
export function indexedDBThrowingOnOpen(error: unknown): unknown {
  return {
    open: () => {
      throw error;
    },
  };
}
