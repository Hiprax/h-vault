/**
 * `offlineCache` — the error half of the module: every branch of the private
 * `classifyError`, and every `request.onerror`, `tx.onerror` and `tx.onabort`
 * handler in the six operations.
 *
 * Everything here is driven through the module's public surface, because
 * `classifyError` is private and the handlers are closures: a test that reached
 * in and called them directly would pin the implementation rather than the
 * behaviour. What is substituted is the browser boundary (`indexedDB.open`, or
 * one `IDBObjectStore` method), never the unit under test.
 *
 * Two measured facts about IndexedDB shape most of this file, and neither is
 * guesswork — both were observed against the same `fake-indexeddb` build the
 * suite runs on:
 *
 *  1. `IDBTransaction.error` is still `null` while the failing request's `error`
 *     event is bubbling; the specification only populates it during the abort
 *     that follows. The bubbled event's `target` IS the failing request, and its
 *     `error` is the real `DOMException`. Reading `tx.error` in a `tx.onerror`
 *     handler therefore always yields nothing.
 *  2. `DOMException instanceof Error` is TRUE in every browser and in Node and
 *     FALSE under this suite's jsdom, whose `DOMException` inherits from a
 *     different realm's `Error.prototype`. Production code must therefore never
 *     use that check to decide whether an engine error is present, or the suite
 *     and the browser take different arms and the shipped behaviour becomes
 *     unobservable from here. The `?? new Error(<fallback>)` guards the module
 *     uses instead answer the same way in every realm, and run only when the
 *     error object is genuinely absent.
 *
 * Consequences that these tests pin:
 *  - a failed WRITE must surface the engine's own `DOMException` (name, message
 *    and identity as `cause`), not a generic stand-in — otherwise `classifyError`
 *    sees a plain `Error` and answers `'unknown'`, which makes `'quota_exceeded'`
 *    unreachable on the only path that can produce a quota error;
 *  - a failed READ must do the same.
 */

import 'fake-indexeddb/auto';
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import {
  createDoomedRequestFactory,
  indexedDBThrowingOnOpen,
  openRawDatabase,
  withIndexedDB,
} from './indexeddbFailures.js';

type CacheModule = typeof import('../src/services/offlineCache');
type CacheError = InstanceType<CacheModule['OfflineCacheError']>;

/**
 * The module keeps the active database name in module scope, so each test takes
 * a fresh copy. The `fake-indexeddb` global is installed by the static import
 * above and is deliberately NOT reset: databases persist for the file, which is
 * why every test scopes itself to a unique user id.
 */
async function freshImport(): Promise<CacheModule> {
  vi.resetModules();
  return import('../src/services/offlineCache');
}

let userSeq = 0;
function uniqueUser(): string {
  userSeq += 1;
  return `err-user-${String(userSeq)}`;
}

/** Await a rejection and return it, without asserting anything about it yet. */
async function rejection(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error: unknown) {
    return error;
  }
  throw new Error('expected the operation to reject, but it resolved');
}

function asCacheError(mod: CacheModule, error: unknown): CacheError {
  expect(error).toBeInstanceOf(mod.OfflineCacheError);
  const err = error as CacheError;
  // Every rejection is the module's own error type, never a raw DOMException
  // leaking to the caller — the `name` is what a logger and a `catch` see.
  expect(err.name).toBe('OfflineCacheError');
  return err;
}

// ---------------------------------------------------------------------------
// A scratch database used only to mint REAL, already-doomed IDBRequests.
//
// The read operations (`getCachedItems`, `getCachedFolders`, `getLastSync`) run
// inside READONLY transactions, so the `put`→`add` trick the write tests use is
// not available to them: `add` on a readonly store throws `ReadOnlyError`
// synchronously and never reaches `request.onerror`. A duplicate `add` on this
// separate readwrite store produces a genuine asynchronous `ConstraintError` on
// a genuine `IDBRequest`, so the handler under test runs against real event
// timing and a real `DOMException` rather than a hand-rolled double.
// ---------------------------------------------------------------------------

const SCRATCH_DB = 'offline-cache-error-scratch';
let doomedRequest: () => IDBRequest;

beforeAll(async () => {
  doomedRequest = await createDoomedRequestFactory(SCRATCH_DB);
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// classifyError — one test per branch
// ---------------------------------------------------------------------------

describe('offlineCache — error classification', () => {
  it('classifies a missing IndexedDB as `unavailable`', async () => {
    const mod = await freshImport();
    await withIndexedDB(undefined, async () => {
      const err = asCacheError(mod, await rejection(mod.offlineCache.getCachedItems()));
      expect(err.type).toBe('unavailable');
      expect(err.message).toBe('IndexedDB is not available');
    });
  });

  it('classifies a QuotaExceededError from `open` as `quota_exceeded`', async () => {
    const mod = await freshImport();
    const thrown = new DOMException('The origin is over its storage quota.', 'QuotaExceededError');
    await withIndexedDB(indexedDBThrowingOnOpen(thrown), async () => {
      const err = asCacheError(mod, await rejection(mod.offlineCache.cacheItems([{ _id: 'a' }])));
      expect(err.type).toBe('quota_exceeded');
      expect(err.message).toBe('IndexedDB storage quota exceeded');
      // The engine's own error is kept, not swallowed — a report that only said
      // "quota" would leave nothing to diagnose from.
      expect(err.cause).toBe(thrown);
    });
  });

  it('classifies a NotAllowedError as `permission_denied`', async () => {
    const mod = await freshImport();
    const thrown = new DOMException('Storage access denied.', 'NotAllowedError');
    await withIndexedDB(indexedDBThrowingOnOpen(thrown), async () => {
      const err = asCacheError(mod, await rejection(mod.offlineCache.getCachedFolders()));
      expect(err.type).toBe('permission_denied');
      expect(err.message).toBe('IndexedDB access denied');
      expect(err.cause).toBe(thrown);
    });
  });

  it('classifies a SecurityError as `permission_denied` too', async () => {
    // Chrome and Firefox both throw SecurityError from `indexedDB.open()` when
    // the user has blocked site data, so this arm of the `||` is the common one.
    const mod = await freshImport();
    const thrown = new DOMException('The operation is insecure.', 'SecurityError');
    await withIndexedDB(indexedDBThrowingOnOpen(thrown), async () => {
      const err = asCacheError(mod, await rejection(mod.offlineCache.clear()));
      expect(err.type).toBe('permission_denied');
      expect(err.message).toBe('IndexedDB access denied');
      expect(err.cause).toBe(thrown);
    });
  });

  it('classifies an unrecognised DOMException as `unknown`, keeping its message', async () => {
    const mod = await freshImport();
    const thrown = new DOMException('The database connection is closing.', 'InvalidStateError');
    await withIndexedDB(indexedDBThrowingOnOpen(thrown), async () => {
      const err = asCacheError(mod, await rejection(mod.offlineCache.getLastSync('items')));
      expect(err.type).toBe('unknown');
      expect(err.message).toBe('The database connection is closing.');
      expect(err.cause).toBe(thrown);
    });
  });

  it('classifies a plain Error as `unknown`, keeping its message', async () => {
    const mod = await freshImport();
    const thrown = new Error('the disk fell over');
    await withIndexedDB(indexedDBThrowingOnOpen(thrown), async () => {
      const err = asCacheError(mod, await rejection(mod.offlineCache.cacheFolders([])));
      expect(err.type).toBe('unknown');
      expect(err.message).toBe('the disk fell over');
      expect(err.cause).toBe(thrown);
    });
  });

  it('classifies a non-Error throw as `unknown` with a stand-in message', async () => {
    const mod = await freshImport();
    await withIndexedDB(indexedDBThrowingOnOpen('not an error object'), async () => {
      const err = asCacheError(mod, await rejection(mod.offlineCache.getCachedItems()));
      expect(err.type).toBe('unknown');
      expect(err.message).toBe('Unknown IndexedDB error');
      expect(err.cause).toBe('not an error object');
    });
  });

  it('returns an already-classified error unchanged rather than re-wrapping it', async () => {
    // The guard that makes `classifyError` idempotent. Nothing inside the six
    // operations throws an `OfflineCacheError` today, so this is reachable only
    // from the boundary — but the moment one operation is built on another, a
    // missing guard would restamp a precise `quota_exceeded` as `unknown` and
    // bury the cause one level deeper.
    const mod = await freshImport();
    const already = new mod.OfflineCacheError('storage is full', 'quota_exceeded', 'root cause');
    await withIndexedDB(indexedDBThrowingOnOpen(already), async () => {
      const err = await rejection(mod.offlineCache.cacheItems([]));
      expect(err).toBe(already);
      expect((err as CacheError).type).toBe('quota_exceeded');
      expect((err as CacheError).cause).toBe('root cause');
    });
  });
});

// ---------------------------------------------------------------------------
// openDatabase's request.onerror — reached by all six operations
// ---------------------------------------------------------------------------

/**
 * Every public operation, so the "an open failure is classified" property is
 * asserted for all six rather than for whichever one a single test happened to
 * pick. A new operation that forgot its `catch (error) { throw classifyError(…) }`
 * is added to this table and goes red.
 */
const OPERATIONS: readonly (readonly [
  string,
  (c: CacheModule['offlineCache']) => Promise<unknown>,
])[] = [
  ['cacheItems', (c) => c.cacheItems([{ _id: 'a' }])],
  ['cacheFolders', (c) => c.cacheFolders([{ _id: 'a' }])],
  ['getCachedItems', (c) => c.getCachedItems()],
  ['getCachedFolders', (c) => c.getCachedFolders()],
  ['getLastSync', (c) => c.getLastSync('folders')],
  ['clear', (c) => c.clear()],
];

describe('offlineCache — a failing database open', () => {
  it('surfaces the engine VersionError, with its message and the original as cause', async () => {
    const mod = await freshImport();
    const userId = uniqueUser();
    const dbName = `hvault-offline-${await mod.deriveUserHash(userId)}`;
    // A newer version already exists on disk, so the module's `open(name, 1)`
    // fails asynchronously through `request.onerror` — no mocking at all.
    (await openRawDatabase(dbName, 2)).close();
    await mod.offlineCache.setUser(userId);

    const err = asCacheError(mod, await rejection(mod.offlineCache.getCachedItems()));
    expect(err.type).toBe('unknown');
    expect(err.message).toMatch(/lower version/i);
    expect((err.cause as DOMException).name).toBe('VersionError');
    // NOT the module's stand-in string: the fallback only exists for an absent
    // error object, and a real failed open always carries one.
    expect(err.message).not.toBe('IndexedDB open failed');
  });

  it.each(OPERATIONS)(
    'routes %s through the classifier when the open fails',
    async (_name, run) => {
      const mod = await freshImport();
      const thrown = new DOMException('quota', 'QuotaExceededError');
      await withIndexedDB(indexedDBThrowingOnOpen(thrown), async () => {
        const err = asCacheError(mod, await rejection(run(mod.offlineCache)));
        expect(err.type).toBe('quota_exceeded');
      });
    },
  );
});

// ---------------------------------------------------------------------------
// The write paths' tx.onerror handlers
//
// `put` is redirected to `add` for the duration of each test. That is a single
// substitution at the storage boundary and it produces a REAL asynchronous
// ConstraintError inside the module's OWN transaction, which bubbles through the
// engine's real event machinery to the `tx.onerror` handler under test.
// ---------------------------------------------------------------------------

function putBehavesAsAdd(): void {
  vi.spyOn(IDBObjectStore.prototype, 'put').mockImplementation(function (
    this: IDBObjectStore,
    value: unknown,
  ) {
    return this.add(value);
  });
}

describe('offlineCache — a failing write transaction', () => {
  it('cacheItems surfaces the real transaction error and commits nothing', async () => {
    const mod = await freshImport();
    await mod.offlineCache.setUser(uniqueUser());
    putBehavesAsAdd();

    const err = asCacheError(
      mod,
      await rejection(mod.offlineCache.cacheItems([{ _id: 'dup' }, { _id: 'dup' }])),
    );
    expect((err.cause as DOMException).name).toBe('ConstraintError');
    expect(err.message).toMatch(/constraint/i);
    // The bug this pins: reading `tx.error` inside `tx.onerror` yields null, so
    // the module used to report this generic string and `classifyError` answered
    // `'unknown'` for every write failure — including a quota failure.
    expect(err.message).not.toBe('IndexedDB transaction failed');

    vi.restoreAllMocks();
    expect(await mod.offlineCache.getCachedItems()).toEqual([]);
    expect(await mod.offlineCache.getLastSync('items')).toBeNull();
  });

  it('cacheFolders surfaces the real transaction error and commits nothing', async () => {
    const mod = await freshImport();
    await mod.offlineCache.setUser(uniqueUser());
    putBehavesAsAdd();

    const err = asCacheError(
      mod,
      await rejection(mod.offlineCache.cacheFolders([{ _id: 'dup' }, { _id: 'dup' }])),
    );
    expect((err.cause as DOMException).name).toBe('ConstraintError');
    expect(err.message).not.toBe('IndexedDB transaction failed');

    vi.restoreAllMocks();
    expect(await mod.offlineCache.getCachedFolders()).toEqual([]);
    expect(await mod.offlineCache.getLastSync('folders')).toBeNull();
  });

  it('cacheItems surfaces a failure of the SECOND (timestamp) transaction', async () => {
    const mod = await freshImport();
    await mod.offlineCache.setUser(uniqueUser());
    await mod.offlineCache.cacheItems([{ _id: 'a' }]);
    const firstSync = await mod.offlineCache.getLastSync('items');
    expect(firstSync).not.toBeNull();

    // Items now write cleanly (an empty list issues no `put` at all), so the
    // duplicate key is the meta record itself and only the metadata transaction
    // fails.
    putBehavesAsAdd();
    const err = asCacheError(mod, await rejection(mod.offlineCache.cacheItems([])));
    expect((err.cause as DOMException).name).toBe('ConstraintError');
    expect(err.message).not.toBe('IndexedDB transaction failed');

    vi.restoreAllMocks();
    // The two transactions are not atomic with each other: the first one did
    // commit, so the rows are gone while the stale timestamp survives. Pinning
    // this makes a future "just wrap both in one transaction" a visible change
    // rather than a silent one.
    expect(await mod.offlineCache.getCachedItems()).toEqual([]);
    expect(await mod.offlineCache.getLastSync('items')).toBe(firstSync);
  });

  it('cacheFolders surfaces a failure of the SECOND (timestamp) transaction', async () => {
    const mod = await freshImport();
    await mod.offlineCache.setUser(uniqueUser());
    await mod.offlineCache.cacheFolders([{ _id: 'a' }]);
    const firstSync = await mod.offlineCache.getLastSync('folders');
    expect(firstSync).not.toBeNull();

    putBehavesAsAdd();
    const err = asCacheError(mod, await rejection(mod.offlineCache.cacheFolders([])));
    expect((err.cause as DOMException).name).toBe('ConstraintError');
    expect(err.message).not.toBe('IndexedDB transaction failed');

    vi.restoreAllMocks();
    expect(await mod.offlineCache.getCachedFolders()).toEqual([]);
    expect(await mod.offlineCache.getLastSync('folders')).toBe(firstSync);
  });

  it('clear surfaces the real transaction error and leaves the cache intact', async () => {
    const mod = await freshImport();
    await mod.offlineCache.setUser(uniqueUser());
    await mod.offlineCache.cacheItems([{ _id: 'dup' }]);

    // `clear()` issues no `put`, so the substitution here is on `clear` itself:
    // it becomes a duplicate `add` against the row just seeded.
    vi.spyOn(IDBObjectStore.prototype, 'clear').mockImplementation(function (this: IDBObjectStore) {
      return this.add({ _id: 'dup', key: 'dup' }) as unknown as IDBRequest<undefined>;
    });

    const err = asCacheError(mod, await rejection(mod.offlineCache.clear()));
    expect((err.cause as DOMException).name).toBe('ConstraintError');
    expect(err.message).not.toBe('IndexedDB transaction failed');

    vi.restoreAllMocks();
    // A failed clear must not have half-emptied the cache.
    expect(await mod.offlineCache.getCachedItems()).toEqual([{ _id: 'dup' }]);
  });
});

// ---------------------------------------------------------------------------
// The write paths' tx.onabort handlers
//
// A transaction can end with NEITHER `complete` nor `error`: a commit-time
// failure, or an abort raised while no request is outstanding. Every one of
// these is driven by a REAL `abort()` on the module's OWN transaction, made
// possible by the fact that the module discards what `clear()` and `put()`
// return — so replacing one of them with an abort issues no request at all, and
// there is nothing to fire an `error` event.
//
// Without an `onabort` leg the promise is never settled: the caller awaits for
// ever and the `finally` that closes the connection never runs. These tests fail
// by TIMING OUT, which is exactly the shape of the defect.
// ---------------------------------------------------------------------------

/** Replace `clear` with a real abort of its own transaction, on the nth call. */
function clearAbortsTransaction(onCall = 1): void {
  let calls = 0;
  vi.spyOn(IDBObjectStore.prototype, 'clear').mockImplementation(function (this: IDBObjectStore) {
    calls += 1;
    if (calls === onCall) {
      this.transaction.abort();
    }
    return undefined as unknown as IDBRequest<undefined>;
  });
}

/** Replace `put` with a real abort of its own transaction. */
function putAbortsTransaction(): void {
  vi.spyOn(IDBObjectStore.prototype, 'put').mockImplementation(function (this: IDBObjectStore) {
    this.transaction.abort();
    return undefined as unknown as IDBRequest<IDBValidKey>;
  });
}

describe('offlineCache — a transaction that aborts with nothing to report', () => {
  it('cacheItems settles instead of hanging when the items transaction aborts', async () => {
    const mod = await freshImport();
    await mod.offlineCache.setUser(uniqueUser());
    clearAbortsTransaction();

    const err = asCacheError(mod, await rejection(mod.offlineCache.cacheItems([])));
    expect(err.type).toBe('unknown');
    expect(err.message).toBe('IndexedDB transaction aborted');

    vi.restoreAllMocks();
    // The abort rolled the transaction back, so no timestamp was recorded either.
    expect(await mod.offlineCache.getLastSync('items')).toBeNull();
  });

  it('cacheItems settles when the TIMESTAMP transaction aborts', async () => {
    const mod = await freshImport();
    await mod.offlineCache.setUser(uniqueUser());
    putAbortsTransaction();

    const err = asCacheError(mod, await rejection(mod.offlineCache.cacheItems([])));
    expect(err.message).toBe('IndexedDB transaction aborted');
  });

  it('cacheFolders settles instead of hanging when the folders transaction aborts', async () => {
    const mod = await freshImport();
    await mod.offlineCache.setUser(uniqueUser());
    clearAbortsTransaction();

    const err = asCacheError(mod, await rejection(mod.offlineCache.cacheFolders([])));
    expect(err.message).toBe('IndexedDB transaction aborted');

    vi.restoreAllMocks();
    expect(await mod.offlineCache.getLastSync('folders')).toBeNull();
  });

  it('cacheFolders settles when the TIMESTAMP transaction aborts', async () => {
    const mod = await freshImport();
    await mod.offlineCache.setUser(uniqueUser());
    putAbortsTransaction();

    const err = asCacheError(mod, await rejection(mod.offlineCache.cacheFolders([])));
    expect(err.message).toBe('IndexedDB transaction aborted');
  });

  it('clear settles instead of hanging when its transaction aborts', async () => {
    const mod = await freshImport();
    await mod.offlineCache.setUser(uniqueUser());
    await mod.offlineCache.cacheItems([{ _id: 'kept' }]);

    // The third `clear()` is the last of the three this transaction issues, so the
    // abort lands after the module has finished touching the object stores; an
    // earlier one would make the NEXT `objectStore()` call throw synchronously and
    // exercise a different path entirely.
    clearAbortsTransaction(3);

    const err = asCacheError(mod, await rejection(mod.offlineCache.clear()));
    expect(err.message).toBe('IndexedDB transaction aborted');

    vi.restoreAllMocks();
    // Rolled back whole: an aborted clear must not have emptied anything.
    expect(await mod.offlineCache.getCachedItems()).toEqual([{ _id: 'kept' }]);
  });
});

// ---------------------------------------------------------------------------
// The read paths' request.onerror handlers
// ---------------------------------------------------------------------------

describe('offlineCache — a failing read request', () => {
  it('getCachedItems surfaces the request error', async () => {
    const mod = await freshImport();
    await mod.offlineCache.setUser(uniqueUser());
    vi.spyOn(IDBObjectStore.prototype, 'getAll').mockImplementation(
      () => doomedRequest() as IDBRequest<unknown[]>,
    );

    const err = asCacheError(mod, await rejection(mod.offlineCache.getCachedItems()));
    expect((err.cause as DOMException).name).toBe('ConstraintError');
    expect(err.type).toBe('unknown');
    expect(err.message).not.toBe('IndexedDB read failed');
  });

  it('getCachedFolders surfaces the request error', async () => {
    const mod = await freshImport();
    await mod.offlineCache.setUser(uniqueUser());
    vi.spyOn(IDBObjectStore.prototype, 'getAll').mockImplementation(
      () => doomedRequest() as IDBRequest<unknown[]>,
    );

    const err = asCacheError(mod, await rejection(mod.offlineCache.getCachedFolders()));
    expect((err.cause as DOMException).name).toBe('ConstraintError');
    expect(err.message).not.toBe('IndexedDB read failed');
  });

  it('getLastSync surfaces the request error', async () => {
    const mod = await freshImport();
    await mod.offlineCache.setUser(uniqueUser());
    vi.spyOn(IDBObjectStore.prototype, 'get').mockImplementation(
      () => doomedRequest() as IDBRequest<unknown>,
    );

    const err = asCacheError(mod, await rejection(mod.offlineCache.getLastSync('items')));
    expect((err.cause as DOMException).name).toBe('ConstraintError');
    expect(err.message).not.toBe('IndexedDB read failed');
  });

  it('getLastSync resolves to null for an absent record rather than rejecting', async () => {
    // The success arm's `?? null`: a missing meta row is a legitimate answer, not
    // an error, and must not be confused with the failures above.
    const mod = await freshImport();
    await mod.offlineCache.setUser(uniqueUser());
    await expect(mod.offlineCache.getLastSync('items')).resolves.toBeNull();
  });
});
