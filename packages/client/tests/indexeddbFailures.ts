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

import { vi } from 'vitest';

export interface RawStoreSpec {
  name: string;
  keyPath: string;
}

/**
 * Open (and if needed create) a database directly, bypassing the module under
 * test. `factory` defaults to whatever `indexedDB` is installed; pass the real
 * engine explicitly where a stand-in (see {@link watchBlockedOpens}) is installed
 * that would change the version asked for.
 */
export function openRawDatabase(
  name: string,
  version: number,
  stores: readonly RawStoreSpec[] = [],
  factory: IDBFactory = indexedDB,
): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = factory.open(name, version);
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
 * Replace `globalThis.indexedDB`, returning the function that puts the original
 * back. Pass `undefined` to model a browser that has no IndexedDB at all.
 */
export function replaceIndexedDB(replacement: unknown): () => void {
  const original = Object.getOwnPropertyDescriptor(globalThis, 'indexedDB');
  Object.defineProperty(globalThis, 'indexedDB', { value: replacement, configurable: true });
  return () => {
    if (original) {
      Object.defineProperty(globalThis, 'indexedDB', original);
    } else {
      Reflect.deleteProperty(globalThis, 'indexedDB');
    }
  };
}

/** Run `fn` with `globalThis.indexedDB` replaced, restoring it even if `fn` throws. */
export async function withIndexedDB<T>(replacement: unknown, fn: () => Promise<T>): Promise<T> {
  const restore = replaceIndexedDB(replacement);
  try {
    return await fn();
  } finally {
    restore();
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

/** A stand-in `indexedDB` that reports every `blocked` the real engine fires. */
export interface BlockWatch {
  /** The stand-in to install with {@link withIndexedDB}. */
  readonly factory: unknown;
  /** How many opens made through `factory` the engine has reported `blocked`. */
  blocked: number;
  /** How many of those {@link outlastGracePeriod} has already run out. */
  outlasted: number;
}

/**
 * A stand-in `indexedDB` that forwards every `open` to the REAL engine and
 * counts the `blocked` events the engine fires at those requests. It listens
 * with `addEventListener`, which leaves the `onblocked` property (the code
 * under test's) untouched, and the engine fires `blocked` whether or not anyone
 * listens, so the count is the same before and after a fix.
 *
 * With `versionsAhead: 1` every open asks for one version above the one the
 * caller named: this bundle, as it will behave on the first schema bump. Paired
 * with a connection held open at the current version by
 * {@link openRawDatabase} (which installs no `versionchange` handler, exactly
 * like a tab still running an older bundle), that produces a genuine `blocked`
 * on a genuine request, with the engine's own queueing behind it.
 */
export function watchBlockedOpens(engine: IDBFactory, { versionsAhead = 0 } = {}): BlockWatch {
  const watch: BlockWatch = {
    factory: {
      open: (name: string, version?: number) => {
        const request = engine.open(name, (version ?? 1) + versionsAhead);
        request.addEventListener('blocked', () => {
          watch.blocked += 1;
        });
        return request;
      },
    },
    blocked: 0,
    outlasted: 0,
  };
  return watch;
}

/**
 * Poll `done` until it holds, failing with `failure` after three seconds of REAL
 * time. It yields with `setImmediate`, the one scheduler neither of this file's
 * fake-timer configurations replaces, and deliberately not with `vi.waitFor`,
 * which advances fake timers on every check and would move the very clock a
 * grace-period test is measuring. The ceiling bounds a failure; a passing run
 * returns as soon as `done` holds.
 */
async function pollUntil(done: () => boolean, failure: string): Promise<void> {
  const deadline = performance.now() + 3_000;
  while (!done()) {
    if (performance.now() > deadline) throw new Error(failure);
    await new Promise<void>((resolve) => {
      setImmediate(resolve);
    });
  }
}

/**
 * Wait until `promise` has settled, failing the test by NAMING THE HANG when it
 * does not. Used where the defect under test is a promise that NEVER settles:
 * awaiting it directly would turn a red test into a stalled run.
 */
export async function expectToSettle(promise: Promise<unknown>, what: string): Promise<void> {
  const state = { settled: false };
  promise.then(
    () => {
      state.settled = true;
    },
    () => {
      state.settled = true;
    },
  );
  await pollUntil(() => state.settled, `${what} never settled`);
}

/**
 * Run an open's grace period out, once the engine has reported the next open
 * made through `watch` blocked.
 *
 * For suites running with `vi.useFakeTimers({ toFake: ['setTimeout',
 * 'clearTimeout'] })`, and ONLY those two: `fake-indexeddb` schedules its own
 * work through `setImmediate`, which the default fake-timer set also replaces,
 * and a frozen engine never reports anything. The signal is the engine's own
 * `blocked` event rather than "a timer exists", because the stores arm timers
 * of their own on the same paths (a logout arms three).
 */
export async function outlastGracePeriod(watch: BlockWatch, graceMs: number): Promise<void> {
  await pollUntil(() => watch.blocked > watch.outlasted, 'the open was never reported blocked');
  watch.outlasted += 1;
  await vi.advanceTimersByTimeAsync(graceMs);
}
