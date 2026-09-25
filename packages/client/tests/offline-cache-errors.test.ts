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
import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import {
  createDoomedRequestFactory,
  expectToSettle,
  indexedDBThrowingOnOpen,
  openRawDatabase,
  outlastGracePeriod,
  replaceIndexedDB,
  watchBlockedOpens,
  withIndexedDB,
  type BlockWatch,
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
    // The guard that makes `classifyError` idempotent. The shared open itself
    // rejects with an `OfflineCacheError` (a `version_conflict`, see below), and
    // a missing guard would restamp that, or a precise `quota_exceeded`, as
    // `unknown` and bury the cause one level deeper.
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
  it('classifies the engine VersionError as `version_conflict`, keeping it as cause', async () => {
    // Was `unknown`, i.e. "offline storage is not working in this browser". The
    // specification defines a `VersionError` from `open` as the database on disk
    // being NEWER than the version asked for, which in this app means a newer
    // bundle upgraded it: the same condition `blocked` reports from the other
    // side, with the same remedy (reload onto the newer bundle), and nothing to
    // do with the browser.
    const mod = await freshImport();
    const userId = uniqueUser();
    const dbName = `hvault-offline-${await mod.deriveUserHash(userId)}`;
    // A newer version already exists on disk, so the module's `open(name, 1)`
    // fails asynchronously through `request.onerror` — no mocking at all.
    (await openRawDatabase(dbName, 2)).close();
    await mod.offlineCache.setUser(userId);

    const err = asCacheError(mod, await rejection(mod.offlineCache.getCachedItems()));
    expect(err.type).toBe('version_conflict');
    expect(err.message).toBe('IndexedDB was upgraded by a newer version of this app');
    expect((err.cause as DOMException).name).toBe('VersionError');
    expect((err.cause as DOMException).message).toMatch(/lower version/i);
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

// ---------------------------------------------------------------------------
// An upgrade another connection is holding up
//
// An open that asks for a higher version than a live connection holds fires
// `versionchange` at that connection and `blocked` at the request, and then
// WAITS, with no timeout, for the connection to close. A tab on an older bundle
// holds its connection with no `versionchange` handler, so it never closes on
// request. Every connection here that plays that tab is a genuine one from
// `openRawDatabase`, which installs no handler, and every block is the engine's.
// ---------------------------------------------------------------------------

const BLOCKED_MESSAGE = 'IndexedDB upgrade blocked by a connection another tab holds open';
const NO_ANSWER_MESSAGE = 'IndexedDB did not answer a request to open the database';

/**
 * Another tab's upgrade of `name` to `version`, left BLOCKED by the older-tab
 * connection {@link holdAsOlderTab} holds: it is issued straight to the engine,
 * as another tab's would be, so this tab's bookkeeping never sees it. Resolves
 * once the engine has reported it blocked; its connection is closed whenever it
 * is finally granted.
 */
function otherTabUpgradeBlocked(name: string, version: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = ENGINE.open(name, version);
    request.onblocked = () => resolve();
    request.onsuccess = () => request.result.close();
    request.onerror = () => reject(request.error ?? new Error('other-tab open failed'));
  });
}

/**
 * Like {@link otherTabUpgradeBlocked}, but the other tab KEEPS the connection it
 * is finally granted, with no `versionchange` handler: once its upgrade lands, it
 * is the connection that blocks the next one. Registered for `afterEach` to close.
 */
function otherTabUpgradeHeld(
  name: string,
  version: number,
): { blocked: Promise<void>; granted: Promise<IDBDatabase> } {
  const request = ENGINE.open(name, version);
  const blocked = new Promise<void>((resolve) => {
    request.onblocked = () => resolve();
  });
  const granted = new Promise<IDBDatabase>((resolve, reject) => {
    request.onsuccess = () => {
      olderTabConnections.push(request.result);
      resolve(request.result);
    };
    request.onerror = () => reject(request.error ?? new Error('other-tab open failed'));
  });
  return { blocked, granted };
}

let blockedDbSeq = 0;
function uniqueDbName(): string {
  blockedDbSeq += 1;
  return `blocked-open-${String(blockedDbSeq)}`;
}

/** The real engine, captured before any test installs a stand-in over it. */
const ENGINE = indexedDB;

const olderTabConnections: IDBDatabase[] = [];
async function holdAsOlderTab(
  name: string,
  stores: readonly { name: string; keyPath: string }[] = [{ name: 'rows', keyPath: '_id' }],
): Promise<IDBDatabase> {
  const db = await openRawDatabase(name, 1, stores, ENGINE);
  olderTabConnections.push(db);
  return db;
}

afterEach(() => {
  // Let every upgrade left waiting finish, so nothing outlives its test.
  for (const db of olderTabConnections.splice(0)) db.close();
});

/** A rejection that must arrive, where the defect is that it never does. */
async function settledRejection(promise: Promise<unknown>, what: string): Promise<unknown> {
  await expectToSettle(promise, what);
  return rejection(promise);
}

/** Open `name` at `version` directly and report whether the engine said `blocked` first. */
function rawOpenOutcome(name: string, version: number): Promise<'opened' | 'blocked'> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(name, version);
    request.onblocked = () => resolve('blocked');
    request.onsuccess = () => {
      request.result.close();
      resolve('opened');
    };
    request.onerror = () => reject(request.error ?? new Error('raw open failed'));
  });
}

/** Whether a connection still works, read by asking it for a transaction. */
function connectionState(db: IDBDatabase): 'open' | string {
  try {
    db.transaction(db.objectStoreNames[0] ?? 'rows').abort();
    return 'open';
  } catch (error: unknown) {
    return (error as DOMException).name;
  }
}

/**
 * Fake `setTimeout` (only: the engine runs on `setImmediate`) and route every
 * open through a {@link BlockWatch}, for the duration of each test in a block.
 */
function withBlockWatch(versionsAhead: number): () => BlockWatch {
  let watch: BlockWatch | undefined;
  let restore: (() => void) | undefined;
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    watch = watchBlockedOpens(indexedDB, { versionsAhead });
    restore = replaceIndexedDB(watch.factory);
  });
  afterEach(() => {
    restore?.();
    vi.useRealTimers();
  });
  return () => {
    if (!watch) throw new Error('withBlockWatch used outside a test');
    return watch;
  };
}

describe('openVersionedDatabase — an upgrade another connection is holding up', () => {
  const watch = withBlockWatch(0);

  it('rejects a blocked upgrade as `version_conflict` instead of leaving it pending for ever', async () => {
    const mod = await freshImport();
    const name = uniqueDbName();
    const older = await holdAsOlderTab(name);
    const upgrade = vi.fn();

    const refused = settledRejection(
      mod.openVersionedDatabase(name, 2, upgrade),
      'the blocked open',
    );
    await outlastGracePeriod(watch(), mod.BLOCKED_OPEN_GRACE_MS);
    const err = asCacheError(mod, await refused);
    expect(err.type).toBe('version_conflict');
    expect(err.message).toBe(BLOCKED_MESSAGE);
    expect(mod.offlineCacheErrorType(err)).toBe('version_conflict');

    // Refusing is all it did: the upgrade never ran underneath the older tab, and
    // that tab's connection was asked to step aside, never closed out from under it.
    expect(upgrade).not.toHaveBeenCalled();
    expect(older.version).toBe(1);
    expect(connectionState(older)).toBe('open');
  });

  it('waits the grace period out to the millisecond before refusing', async () => {
    const mod = await freshImport();
    const name = uniqueDbName();
    await holdAsOlderTab(name);
    const open = mod.openVersionedDatabase(name, 2, vi.fn());
    const outcome = { settled: false };
    open
      .catch(() => undefined)
      .finally(() => {
        outcome.settled = true;
      });

    await outlastGracePeriod(watch(), mod.BLOCKED_OPEN_GRACE_MS - 1);
    expect(outcome.settled).toBe(false);

    await vi.advanceTimersByTimeAsync(1);
    expect(outcome.settled).toBe(true);
    expect(asCacheError(mod, await rejection(open)).type).toBe('version_conflict');
  });

  it('opens normally when the other connection lets go inside the grace period', async () => {
    // The common case on a real schema bump: the other tab is mid-transaction,
    // closes the moment it finishes, and the upgrade proceeds. It must not be
    // reported as a failure.
    const mod = await freshImport();
    const name = uniqueDbName();
    const older = await holdAsOlderTab(name);
    const upgrade = vi.fn((db: IDBDatabase) => {
      db.createObjectStore('added', { keyPath: 'k' });
      // An upgrade may outlast what was left of the grace period. The refusal is
      // disarmed the moment the upgrade starts, so running the clock on from
      // inside it must not abandon an open that is already succeeding.
      vi.advanceTimersByTime(mod.BLOCKED_OPEN_GRACE_MS);
    });

    const open = mod.openVersionedDatabase(name, 2, upgrade);
    await outlastGracePeriod(watch(), mod.BLOCKED_OPEN_GRACE_MS - 1);
    older.close();

    const db = await open;
    expect(db.version).toBe(2);
    expect([...db.objectStoreNames]).toEqual(['added', 'rows']);
    expect(upgrade).toHaveBeenCalledTimes(1);
    // The refusal was disarmed, not merely outrun: nothing fires later.
    expect(vi.getTimerCount()).toBe(0);
    db.close();
  });

  it('gives up on an open queued BEHIND the blocked one, which no engine event would reach', async () => {
    // The engine processes one open per database at a time. The second request
    // waits for the first to finish and receives no event of its own while it
    // does, so rejecting only the request that saw `blocked` leaves this one
    // hanging exactly as before.
    const mod = await freshImport();
    const name = uniqueDbName();
    await holdAsOlderTab(name);

    const first = mod.openVersionedDatabase(name, 2, vi.fn());
    const second = mod.openVersionedDatabase(name, 2, vi.fn());
    const both = Promise.all([
      settledRejection(first, 'the blocked open'),
      settledRejection(second, 'the open queued behind it'),
    ]);
    await outlastGracePeriod(watch(), mod.BLOCKED_OPEN_GRACE_MS);

    const [firstErr, secondErr] = (await both).map((error) => asCacheError(mod, error));
    expect(firstErr?.type).toBe('version_conflict');
    expect(secondErr?.type).toBe('version_conflict');
    expect(secondErr?.message).toBe(BLOCKED_MESSAGE);
  });

  it('still refuses as `version_conflict` once the queued open’s own deadline has run out too', async () => {
    // The grace period abandons the blocked open A and the open B queued behind it.
    // B heard nothing from the engine, so its own deadline, armed when it was
    // issued, runs out later as well. That must not relabel A, which the engine DID
    // answer: a later open is refused with the cause of the first abandoned record,
    // and a relabelled A would send the user to the "offline storage is not
    // working" banner instead of the one naming the other tab.
    const mod = await freshImport();
    const name = uniqueDbName();
    await holdAsOlderTab(name);
    const both = Promise.all([
      settledRejection(mod.openVersionedDatabase(name, 2, vi.fn()), 'the blocked open'),
      settledRejection(mod.openVersionedDatabase(name, 2, vi.fn()), 'the open queued behind it'),
    ]);
    await outlastGracePeriod(watch(), mod.BLOCKED_OPEN_GRACE_MS);
    await both;
    await vi.advanceTimersByTimeAsync(mod.OPEN_RESPONSE_DEADLINE_MS);
    expect(vi.getTimerCount()).toBe(0);

    const engineOpen = vi.spyOn(indexedDB, 'open');
    const later = asCacheError(
      mod,
      await settledRejection(mod.openVersionedDatabase(name, 2, vi.fn()), 'the later open'),
    );
    expect(later.type).toBe('version_conflict');
    expect(later.message).toBe(BLOCKED_MESSAGE);
    expect(engineOpen).not.toHaveBeenCalled();
  });

  /**
   * A and B queue silently behind another tab's blocked upgrade, so both arm the
   * no-answer deadline. At 14.5 s that upgrade lands and the other tab KEEPS its
   * connection: A reaches the head, is reported `blocked`, and starts its grace
   * period, which B's deadline, at 15 s, falls inside. Returns once B's deadline
   * has run out, with the engine requests (A first) and the other tab's connection.
   */
  async function lateBlockedPair(mod: Awaited<ReturnType<typeof freshImport>>, name: string) {
    const older = await holdAsOlderTab(name);
    const otherTab = otherTabUpgradeHeld(name, 2);
    await otherTab.blocked;

    const requests: IDBOpenDBRequest[] = [];
    const watched = indexedDB;
    const restore = replaceIndexedDB({
      open: (dbName: string, version?: number) => {
        const request = watched.open(dbName, version);
        requests.push(request);
        return request;
      },
    });
    const settled: string[] = [];
    const track = (label: string, promise: Promise<unknown>): Promise<unknown> =>
      promise.then(
        () => settled.push(`${label}:opened`),
        (error: unknown) => {
          settled.push(`${label}:${asCacheError(mod, error).type}`);
        },
      );
    const both = Promise.all([
      track('A', mod.openVersionedDatabase(name, 3, vi.fn())),
      track('B', mod.openVersionedDatabase(name, 3, vi.fn())),
    ]);
    restore();

    await vi.advanceTimersByTimeAsync(mod.OPEN_RESPONSE_DEADLINE_MS - 500);
    expect(settled).toEqual([]);
    older.close();
    const holder = await otherTab.granted;
    const started = performance.now();
    while (watch().blocked === 0) {
      if (performance.now() - started > 3_000) throw new Error('A was never reported blocked');
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
    await vi.advanceTimersByTimeAsync(500);
    await Promise.resolve();
    return { settled, both, requests, holder };
  }

  it('lets an open the engine has answered finish its grace period, whatever a quieter open’s deadline says', async () => {
    // B heard nothing, so its deadline abandons it; A HAS heard from the engine and
    // is not waiting blind, so it keeps its grace period and is refused for the
    // reason it was actually held up.
    const mod = await freshImport();
    const { settled, both } = await lateBlockedPair(mod, uniqueDbName());
    expect(settled).toEqual(['B:unknown']);

    await vi.advanceTimersByTimeAsync(mod.BLOCKED_OPEN_GRACE_MS);
    await both;
    expect(settled).toEqual(['B:unknown', 'A:version_conflict']);
  });

  it('refuses a later open with the cause the remaining abandoned request’s own caller was given', async () => {
    // A's grace period abandons B a SECOND time, as a version conflict, after B's
    // caller was already told the engine did not answer. Once A leaves the engine,
    // B is the first abandoned record left, and a later open is refused with B's
    // record: that must be what B's caller heard, not the later relabel.
    const mod = await freshImport();
    const name = uniqueDbName();
    const { both, requests, holder } = await lateBlockedPair(mod, name);
    await vi.advanceTimersByTimeAsync(mod.BLOCKED_OPEN_GRACE_MS);
    await both;

    // One microtask after A's `success`, which is after the WHOLE dispatch (the
    // engine calls `addEventListener` listeners before the `onsuccess` property,
    // so a bare listener would run before the module removes A), and before the
    // engine's next turn, where it reaches B: A has left the table, B has not.
    const later = new Promise<unknown>((resolve) => {
      requests[0]!.addEventListener('success', () => {
        queueMicrotask(() => {
          resolve(
            mod.openVersionedDatabase(name, 3, vi.fn()).then(
              () => 'opened',
              (e: unknown) => e,
            ),
          );
        });
      });
    });
    const engineOpen = vi.spyOn(indexedDB, 'open');
    holder.close();

    const err = asCacheError(mod, await later);
    expect(err.type).toBe('unknown');
    expect(err.message).toBe(NO_ANSWER_MESSAGE);
    expect(engineOpen).not.toHaveBeenCalled();
  });

  it('gives up on an open queued behind ANOTHER TAB’S blocked upgrade, which tells this tab nothing', async () => {
    // The engine's queue of opens is per origin and database, shared by every
    // tab, so a request waiting behind another tab's blocked upgrade receives
    // no event at all and this tab's own bookkeeping never learns of the hold.
    // Only a deadline armed when the request is ISSUED can end the wait.
    const mod = await freshImport();
    const name = uniqueDbName();
    await holdAsOlderTab(name);
    await otherTabUpgradeBlocked(name, 2);

    const open = mod.openVersionedDatabase(name, 2, vi.fn());
    const outcome = { settled: false };
    open
      .catch(() => undefined)
      .finally(() => {
        outcome.settled = true;
      });

    // Nothing reached this request: no `blocked`, so no grace period was armed.
    await vi.advanceTimersByTimeAsync(mod.OPEN_RESPONSE_DEADLINE_MS - 1);
    expect(outcome.settled).toBe(false);

    await vi.advanceTimersByTimeAsync(1);
    expect(outcome.settled).toBe(true);
    const err = asCacheError(mod, await rejection(open));
    // NOT `version_conflict`: a silent engine cannot tell another tab from a slow
    // one, and that banner would prescribe a remedy that may not apply.
    expect(err.type).toBe('unknown');
    expect(err.message).toBe(NO_ANSWER_MESSAGE);

    // A later open is refused at once for the SAME reason, never queued behind
    // the request this module has already given up on.
    const engineOpen = vi.spyOn(indexedDB, 'open');
    const later = asCacheError(
      mod,
      await settledRejection(mod.openVersionedDatabase(name, 2, vi.fn()), 'the later open'),
    );
    expect(later.type).toBe('unknown');
    expect(later.message).toBe(NO_ANSWER_MESSAGE);
    expect(engineOpen).not.toHaveBeenCalled();
  });

  it('leaves no deadline behind once an ordinary open has been answered', async () => {
    const mod = await freshImport();
    const db = await mod.openVersionedDatabase(uniqueDbName(), 1, (created) =>
      created.createObjectStore('rows', { keyPath: '_id' }),
    );
    expect(vi.getTimerCount()).toBe(0);
    db.close();
  });

  it('refuses a later open AT ONCE while an abandoned request still waits, never queueing it', async () => {
    const mod = await freshImport();
    const name = uniqueDbName();
    await holdAsOlderTab(name);
    const blocked = settledRejection(
      mod.openVersionedDatabase(name, 2, vi.fn()),
      'the blocked open',
    );
    await outlastGracePeriod(watch(), mod.BLOCKED_OPEN_GRACE_MS);
    await blocked;

    const open = vi.spyOn(indexedDB, 'open');
    const err = asCacheError(
      mod,
      await settledRejection(mod.openVersionedDatabase(name, 2, vi.fn()), 'the later open'),
    );
    expect(err.type).toBe('version_conflict');
    // Nothing was handed to the engine, and no grace period was started: a
    // request placed now would sit silently behind the abandoned one, which is
    // the hang this refusal exists to avoid.
    expect(open).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('closes the connection an abandoned request is finally granted, then opens normally', async () => {
    const mod = await freshImport();
    const name = uniqueDbName();
    const older = await holdAsOlderTab(name);
    const upgrade = vi.fn((db: IDBDatabase) => db.createObjectStore('added', { keyPath: 'k' }));
    const blocked = settledRejection(
      mod.openVersionedDatabase(name, 2, upgrade),
      'the blocked open',
    );
    await outlastGracePeriod(watch(), mod.BLOCKED_OPEN_GRACE_MS);
    await blocked;

    // The older tab goes away; the abandoned request now runs the upgrade and is
    // granted its connection, which nobody is waiting for.
    older.close();
    const db = await vi.waitFor(() => mod.openVersionedDatabase(name, 2, vi.fn()), {
      timeout: 3_000,
      interval: 10,
    });
    expect(db.version).toBe(2);
    expect([...db.objectStoreNames]).toEqual(['added', 'rows']);
    // The abandoned request ran the upgrade; the later open found it done.
    expect(upgrade).toHaveBeenCalledTimes(1);
    db.close();

    // Had that unwanted connection been kept, it would be a connection with no
    // `versionchange` handler, and the NEXT upgrade would be blocked by it.
    expect(await rawOpenOutcome(name, 3)).toBe('opened');
  });

  it('hands out connections that step aside when another tab upgrades', async () => {
    const mod = await freshImport();
    const name = uniqueDbName();
    const db = await mod.openVersionedDatabase(name, 1, (created) =>
      created.createObjectStore('rows', { keyPath: '_id' }),
    );

    // Another tab, on a newer bundle, upgrades while this connection is open.
    expect(await rawOpenOutcome(name, 2)).toBe('opened');
    // This tab's connection closed itself to let it, so it refuses new work
    // rather than silently operating on a schema it no longer matches.
    expect(connectionState(db)).toBe('InvalidStateError');
  });

  it('confines the refusal to the database that is blocked', async () => {
    const mod = await freshImport();
    const blockedName = uniqueDbName();
    const other = uniqueDbName();
    await holdAsOlderTab(blockedName);
    const blocked = settledRejection(
      mod.openVersionedDatabase(blockedName, 2, vi.fn()),
      'the blocked open',
    );
    await outlastGracePeriod(watch(), mod.BLOCKED_OPEN_GRACE_MS);
    await blocked;

    // The offline cache and the health store are separate databases: one of them
    // being held up by another tab must not take the other down with it.
    const db = await mod.openVersionedDatabase(other, 1, (created) =>
      created.createObjectStore('rows', { keyPath: '_id' }),
    );
    expect(db.name).toBe(other);
    db.close();
  });
});

const OFFLINE_STORES = [
  { name: 'items', keyPath: '_id' },
  { name: 'folders', keyPath: '_id' },
  { name: 'meta', keyPath: 'key' },
] as const;

describe('offlineCache — the first schema bump meeting a tab on an older bundle', () => {
  const watch = withBlockWatch(1);

  it.each(OPERATIONS)('%s settles as `version_conflict` instead of hanging', async (_name, run) => {
    const mod = await freshImport();
    const userId = uniqueUser();
    await mod.offlineCache.setUser(userId);
    await holdAsOlderTab(`hvault-offline-${await mod.deriveUserHash(userId)}`, OFFLINE_STORES);

    const refused = settledRejection(run(mod.offlineCache), 'the operation');
    await outlastGracePeriod(watch(), mod.BLOCKED_OPEN_GRACE_MS);
    const err = asCacheError(mod, await refused);
    expect(err.type).toBe('version_conflict');
    expect(err.message).toBe(BLOCKED_MESSAGE);
    expect(watch().blocked).toBe(1);
  });
});

describe('offlineCache — another tab upgrading part-way through an operation', () => {
  it('reports `version_conflict` when the connection stepped aside between two transactions', async () => {
    // `cacheItems` writes the rows, then the sync timestamp in a second
    // transaction. Another tab's upgrade arriving while the first is running
    // closes this connection as soon as it finishes, so the engine refuses the
    // second. That is this tab stepping aside on purpose, not storage failing.
    const mod = await freshImport();
    const userId = uniqueUser();
    await mod.offlineCache.setUser(userId);
    const dbName = `hvault-offline-${await mod.deriveUserHash(userId)}`;

    let newerTab: Promise<IDBDatabase> | undefined;
    const clear = IDBObjectStore.prototype.clear;
    vi.spyOn(IDBObjectStore.prototype, 'clear').mockImplementationOnce(function (
      this: IDBObjectStore,
    ) {
      // The newer tab opens while the items transaction is live.
      newerTab = openRawDatabase(dbName, 2);
      return clear.call(this);
    });

    const err = asCacheError(mod, await rejection(mod.offlineCache.cacheItems([{ _id: 'row' }])));
    expect(err.type).toBe('version_conflict');
    expect(err.message).toBe('IndexedDB connection closed for an upgrade in another tab');
    expect((err.cause as DOMException).name).toBe('InvalidStateError');

    // The newer tab was held up at most until that transaction ended, and got in.
    const upgraded = await (newerTab ?? Promise.reject(new Error('the newer tab never opened')));
    expect(upgraded.version).toBe(2);
    const rows = await new Promise<unknown[]>((resolve, reject) => {
      const request = upgraded.transaction('items').objectStore('items').getAll();
      request.onsuccess = () => resolve(request.result as unknown[]);
      request.onerror = () => reject(request.error ?? new Error('read failed'));
    });
    // The first transaction committed; the timestamp it could not write is absent.
    expect(rows).toEqual([{ _id: 'row' }]);
    const sync = await new Promise<unknown>((resolve, reject) => {
      const request = upgraded.transaction('meta').objectStore('meta').get('lastItemsSync');
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error('read failed'));
    });
    expect(sync).toBeUndefined();
    upgraded.close();

    // And this tab, now the older one, is told the same thing on its next open.
    const next = asCacheError(mod, await rejection(mod.offlineCache.getCachedItems()));
    expect(next.type).toBe('version_conflict');
  });

  it('keeps an InvalidStateError on a connection that did NOT step aside as `unknown`', async () => {
    // The `version_conflict` reading is only for a connection this module closed
    // for another tab's upgrade; any other refusal keeps the engine's wording.
    const mod = await freshImport();
    await mod.offlineCache.setUser(uniqueUser());
    const transaction = IDBDatabase.prototype.transaction;
    let calls = 0;
    vi.spyOn(IDBDatabase.prototype, 'transaction').mockImplementation(function (
      this: IDBDatabase,
      ...args: Parameters<IDBDatabase['transaction']>
    ) {
      calls += 1;
      if (calls === 2) throw new DOMException('The connection is closing.', 'InvalidStateError');
      return transaction.apply(this, args);
    });

    const err = asCacheError(mod, await rejection(mod.offlineCache.cacheItems([])));
    expect(err.type).toBe('unknown');
    expect(err.message).toBe('The connection is closing.');
  });
});
