/**
 * Offline cache service using IndexedDB.
 * Stores encrypted vault items and folders for offline read access.
 */

// ---------------------------------------------------------------------------
// Error types for offline cache failures
// ---------------------------------------------------------------------------

export type OfflineCacheErrorType =
  'unavailable' | 'quota_exceeded' | 'permission_denied' | 'version_conflict' | 'unknown';

export class OfflineCacheError extends Error {
  readonly type: OfflineCacheErrorType;

  constructor(message: string, type: OfflineCacheErrorType, cause?: unknown) {
    super(message);
    this.name = 'OfflineCacheError';
    this.type = type;
    this.cause = cause;
  }
}

/**
 * Classify a rejection from one of the operations below. `db` is the connection
 * the operation was using, when it got that far: it is what tells an
 * `InvalidStateError` caused by this tab stepping aside for another tab's
 * upgrade apart from any other `InvalidStateError`.
 */
function classifyError(error: unknown, db?: IDBDatabase): OfflineCacheError {
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
    // An open at a LOWER version than the database on disk has exactly one cause
    // in this app: a newer bundle, in another tab or an earlier session, upgraded
    // it. That is the same condition `blocked` reports from the other side, so it
    // carries the same cause and the same remedy (reload onto the newer bundle),
    // rather than the "not working in this browser" that `unknown` would claim.
    if (error.name === 'VersionError') {
      return new OfflineCacheError(
        'IndexedDB was upgraded by a newer version of this app',
        'version_conflict',
        error,
      );
    }
    // The connection closed itself for another tab's upgrade part-way through an
    // operation (see `openVersionedDatabase`), so the operation's next
    // `db.transaction(...)` is refused. Only for a connection this module KNOWS it
    // closed for that reason: any other `InvalidStateError` stays `unknown`.
    if (error.name === 'InvalidStateError' && db !== undefined && closedForVersionChange.has(db)) {
      return new OfflineCacheError(
        'IndexedDB connection closed for an upgrade in another tab',
        'version_conflict',
        error,
      );
    }
    // Any other DOMException keeps the engine's own wording. This arm exists
    // because `DOMException instanceof Error` is NOT portable: it is true in
    // every browser and in Node, and false under jsdom, whose DOMException
    // inherits from a different realm's `Error.prototype`. Falling through to
    // the generic branch below therefore kept the message in production and
    // replaced it with a stand-in under test — a divergence that makes the
    // shipped behaviour of this function unobservable from the suite.
    return new OfflineCacheError(error.message, 'unknown', error);
  }

  const message = error instanceof Error ? error.message : 'Unknown IndexedDB error';
  return new OfflineCacheError(message, 'unknown', error);
}

/**
 * The cause behind a rejected `offlineCache` operation, as a plain discriminant.
 *
 * Every method here rejects with an `OfflineCacheError`; anything else arriving
 * is a programming fault rather than a storage condition, so it degrades to
 * `'unknown'` instead of throwing a second time from inside a `.catch`.
 */
export function offlineCacheErrorType(error: unknown): OfflineCacheErrorType {
  return error instanceof OfflineCacheError ? error.type : 'unknown';
}

// ---------------------------------------------------------------------------
// Reading the error off a failed request or transaction
// ---------------------------------------------------------------------------

/**
 * The error behind a failed IndexedDB transaction, read off the event that
 * reported it. Shared with `healthResultsStore`, the other IndexedDB-backed
 * service, so the two cannot drift.
 *
 * `IDBTransaction.error` is still `null` while the failing request's `error`
 * event is bubbling: the specification only populates it during the abort that
 * follows, and the `error` listener on the transaction runs before that. So a
 * handler that read `tx.error` saw nothing every single time, rejected with the
 * bare fallback below, and `classifyError` — handed a plain `Error` — answered
 * `'unknown'`. That made `'quota_exceeded'` unreachable on the write path, which
 * is the only path a quota failure can arrive on.
 *
 * On an `error` event the target is the failing request and carries the real
 * `DOMException`; on an `abort` event the target is the transaction, whose
 * `error` is set for an implicit abort and `null` for an explicit one. Reading
 * `event.target.error` covers both, and falls back for the explicit case.
 *
 * The presence test is deliberately a null check rather than an `instanceof
 * Error` check: `DOMException instanceof Error` is true in every browser and
 * false under jsdom (different realm's `Error.prototype`), so the stricter guard
 * would keep the engine's error in production and discard it under test.
 */
export function transactionFailureError(event: Event, fallbackMessage: string): Error {
  const target: unknown = event.target;
  if (typeof target === 'object' && target !== null && 'error' in target) {
    const { error } = target;
    if (error !== null && error !== undefined) {
      // A `DOMException`, which `lib.dom` declares as an `Error` subtype and
      // every browser implements as one. Asserting rather than testing with
      // `instanceof Error` is the point: that test is the one jsdom answers
      // differently, and this value is only ever handed to `classifyError`,
      // which re-examines it properly.
      return error as Error;
    }
  }
  return new Error(fallbackMessage);
}

// ---------------------------------------------------------------------------
// IndexedDB setup
// ---------------------------------------------------------------------------

const DB_NAME_PREFIX = 'hvault-offline';
/**
 * Bumping this runs an upgrade in every tab that opens the database afterwards.
 * Keep whatever that upgrade does FAR inside {@link OPEN_RESPONSE_DEADLINE_MS}: a
 * tab whose open is queued behind another tab's upgrade hears nothing until it
 * ends, and gives up once that deadline passes.
 */
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

/**
 * How long an open that another tab is holding up waits for it to step aside
 * before giving up.
 *
 * Every connection this app hands out is opened for one operation and closed in
 * that operation's `finally`, and closes itself on `versionchange` (below). A
 * connection only finishes closing once its running transaction does, though,
 * so on the first schema bump a tab that is mid-write when another tab upgrades
 * reports `blocked` for a few milliseconds and then lets go. Refusing on the
 * event itself would turn that normal case into a failed write, or into a
 * logout that skipped clearing the cache; waiting for ever is the defect. A
 * connection still held after this long belongs to a tab that is not going to
 * release it (one on a bundle from before this handler existed, holding a
 * transaction that never ended), so the open is refused. The longest
 * transaction this app runs is `cacheItems` rewriting a full vault
 * (`MAX_ITEMS_PER_USER` rows), measured at about 140 ms on the engine the suite
 * runs on; browser engines differ, which is what the margin is for.
 */
export const BLOCKED_OPEN_GRACE_MS = 1_000;

const BLOCKED_OPEN_MESSAGE = 'IndexedDB upgrade blocked by a connection another tab holds open';

/**
 * How long an open may wait for the engine to say ANYTHING about it before it is
 * given up on: a `blocked`, an `upgradeneeded`, a success or an error.
 *
 * {@link BLOCKED_OPEN_GRACE_MS} cannot cover this, because it is armed by
 * `blocked` and `blocked` reaches only the request at the head of the engine's
 * queue. That queue is per origin and database name, shared by every TAB, and a
 * request waiting behind another tab's blocked upgrade receives no event at all:
 * nothing in this tab ever learns of the hold, and without this deadline the
 * request would wait for as long as that other tab's upgrade does. A logout
 * awaits a clear on each database, and a sign-in awaits one before it lets the
 * user in, so both would hang with nothing on screen.
 *
 * Far longer than the grace period on purpose. An open that has not been reached
 * cannot tell another tab from an engine that is merely slow (a cold start, a busy
 * disk), and every open this app makes is answered in milliseconds when nothing
 * is holding it up; the one upgrade this app runs only creates object stores. A
 * request given up on here is refused as `unknown`, never as `version_conflict`,
 * because the banner for that names a remedy about other tabs that may not apply.
 */
export const OPEN_RESPONSE_DEADLINE_MS = 15_000;

const OPEN_NO_ANSWER_MESSAGE = 'IndexedDB did not answer a request to open the database';

/** One open this module has handed to the engine and the engine has not finished. */
interface PendingOpen {
  /**
   * The refusal this module gave up with, once it has stopped waiting for the
   * request; `null` until then, and never unset. A later open of the same
   * database is refused with the same cause while this one is still inside the
   * engine.
   */
  abandonedWith: OfflineCacheError | null;
  /**
   * Whether the engine has said anything about this request yet. One it has
   * answered is not waiting blind, so another request's no-answer deadline leaves
   * it alone: its own grace period, or the engine, decides how it ends.
   */
  heard: boolean;
  /** Reject the caller now. The engine request carries on and is closed on arrival. */
  abandon: (error: OfflineCacheError) => void;
}

/**
 * Every open still inside the engine, per database name.
 *
 * The engine processes one open per database at a time, and a request waiting
 * its turn receives NO event while it waits (measured: an open issued behind a
 * `blocked` one hears nothing until that one is processed). So once one request
 * is blocked, every request THIS TAB queued behind it is equally stuck and this
 * table is how the grace period reaches them. (A request queued behind ANOTHER
 * tab's blocked upgrade is in no table here at all; see
 * {@link OPEN_RESPONSE_DEADLINE_MS}.) IndexedDB has no way to cancel a request,
 * so giving up ABANDONS it: the caller is rejected, the record stays here until
 * the engine finishes with it, and a connection it is eventually granted is
 * closed at once. A new open of the same name while an abandoned one is still
 * here is refused, with the same cause, without being handed to the engine at
 * all, because it would only queue, silently, behind the request this module
 * has already given up on.
 */
const pendingOpens = new Map<string, Set<PendingOpen>>();

/** Connections that closed themselves so another tab could upgrade; see `classifyError`. */
const closedForVersionChange = new WeakSet<IDBDatabase>();

function versionConflict(): OfflineCacheError {
  return new OfflineCacheError(BLOCKED_OPEN_MESSAGE, 'version_conflict');
}

function noAnswer(): OfflineCacheError {
  return new OfflineCacheError(OPEN_NO_ANSWER_MESSAGE, 'unknown');
}

/**
 * Open (creating or upgrading as needed) one of this app's IndexedDB databases.
 * The ONE place either IndexedDB-backed service opens a connection, shared with
 * `healthResultsStore`, so both get the same guarantees:
 *
 * - **It always settles.** An upgrade another connection is holding up rejects
 *   with a `version_conflict` once {@link BLOCKED_OPEN_GRACE_MS} has passed,
 *   together with every open of the same database this tab queued behind it. An
 *   open the engine says nothing about at all, which is what one queued behind
 *   ANOTHER tab's blocked upgrade gets, rejects as `unknown` once
 *   {@link OPEN_RESPONSE_DEADLINE_MS} has passed. A promise left pending here is
 *   not a lost write: `authStore.logout` awaits a clear on each database and runs
 *   its remaining teardown after them, and `login` awaits one before it lets the
 *   user in, so either would never return.
 * - **It never holds up another tab.** Every connection it hands out closes
 *   itself on `versionchange`, so a newer bundle's upgrade in another tab
 *   proceeds as soon as this tab's running transaction ends. Work this tab then
 *   attempts on that connection is refused by the engine and classified as a
 *   `version_conflict`.
 *
 * An abandoned request still runs `upgrade` if the engine gets that far: closing
 * or aborting inside `upgradeneeded` would roll the version back and leave the
 * next open to be blocked all over again.
 */
export function openVersionedDatabase(
  name: string,
  version: number,
  upgrade: (db: IDBDatabase) => void,
): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const pending = pendingOpens.get(name) ?? new Set<PendingOpen>();
    const givenUp = [...pending].find((open) => open.abandonedWith !== null)?.abandonedWith;
    if (givenUp) {
      reject(new OfflineCacheError(givenUp.message, givenUp.type));
      return;
    }
    const request = indexedDB.open(name, version);
    pendingOpens.set(name, pending);

    // Abandoning twice is harmless: a settled promise ignores a second `reject`.
    // It happens to a request that has heard NOTHING from the engine: a blocked
    // open's grace period abandons it, and later its own deadline does, or the
    // other way round. The record keeps the FIRST cause, the one its own caller
    // was given, because a later open is refused with the cause of the first
    // abandoned record still here, and once the requests ahead of this one have
    // left the engine, that record is this one. (A request that HAS heard from the
    // engine is never abandoned by another's deadline; see `heard`.)
    const record: PendingOpen = {
      abandonedWith: null,
      heard: false,
      abandon: (error) => {
        record.abandonedWith ??= error;
        reject(error);
      },
    };
    pending.add(record);

    let graceTimer: ReturnType<typeof setTimeout> | undefined;
    // Armed now and disarmed by the engine's FIRST word about this request,
    // whatever it is. See `OPEN_RESPONSE_DEADLINE_MS` for why nothing else can
    // end a wait behind another tab's upgrade.
    let answerTimer: ReturnType<typeof setTimeout> | undefined = setTimeout(() => {
      // Every request that is as silent as this one is stuck behind the same
      // thing; one the engine has answered is not, and keeps its own ending.
      for (const open of pending) if (!open.heard) open.abandon(noAnswer());
    }, OPEN_RESPONSE_DEADLINE_MS);
    const answered = (): void => {
      record.heard = true;
      clearTimeout(answerTimer);
      answerTimer = undefined;
    };
    const finish = (): void => {
      answered();
      clearTimeout(graceTimer);
      pending.delete(record);
      if (pending.size === 0) pendingOpens.delete(name);
    };

    request.onblocked = () => {
      answered();
      // Re-armed rather than stacked, should the engine report it again, so no
      // timer is ever left behind that `finish` does not clear.
      clearTimeout(graceTimer);
      graceTimer = setTimeout(() => {
        for (const open of pending) open.abandon(versionConflict());
      }, BLOCKED_OPEN_GRACE_MS);
    };
    request.onupgradeneeded = () => {
      // The other connections let go in time: the upgrade is running.
      answered();
      clearTimeout(graceTimer);
      upgrade(request.result);
    };
    request.onsuccess = () => {
      finish();
      const db = request.result;
      if (record.abandonedWith !== null) {
        db.close();
        return;
      }
      db.onversionchange = () => {
        closedForVersionChange.add(db);
        db.close();
      };
      resolve(db);
    };
    request.onerror = () => {
      finish();
      reject(request.error ?? new Error('IndexedDB open failed'));
    };
  });
}

function openDatabase(): Promise<IDBDatabase> {
  return openVersionedDatabase(currentDbName, DB_VERSION, (db) => {
    if (!db.objectStoreNames.contains(ITEMS_STORE)) {
      db.createObjectStore(ITEMS_STORE, { keyPath: '_id' });
    }
    if (!db.objectStoreNames.contains(FOLDERS_STORE)) {
      db.createObjectStore(FOLDERS_STORE, { keyPath: '_id' });
    }
    if (!db.objectStoreNames.contains(META_STORE)) {
      db.createObjectStore(META_STORE, { keyPath: 'key' });
    }
  });
}

// ---------------------------------------------------------------------------
// Connection, transaction and read helpers
// ---------------------------------------------------------------------------

/**
 * Runs `work` on a fresh connection, classifies whatever it throws, and closes
 * the connection however it ends. `db` is still unset when the open itself was
 * refused, and `classifyError` reads that as "no connection to blame".
 */
async function withDatabase<T>(work: (db: IDBDatabase) => Promise<T>): Promise<T> {
  let db: IDBDatabase | undefined;
  try {
    db = await openDatabase();
    return await work(db);
  } catch (error) {
    throw classifyError(error, db);
  } finally {
    db?.close();
  }
}

/**
 * Resolves when `tx` commits, and rejects when it fails or aborts, with the
 * engine's own error wherever the event carries one (see `transactionFailureError`).
 * Every MUTATING transaction in this module settles through here.
 *
 * A transaction can end WITHOUT any request having reported an error — a
 * commit-time failure, or an abort raised while no request is still
 * outstanding. Only `abort` fires then, so a handler listening for `complete`
 * and `error` alone leaves this promise pending for ever, the caller awaiting it
 * never returns, and the `finally` that closes the connection never runs.
 */
function transactionSettled(tx: IDBTransaction): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = (event) => reject(transactionFailureError(event, 'IndexedDB transaction failed'));
    tx.onabort = (event) => reject(transactionFailureError(event, 'IndexedDB transaction aborted'));
  });
}

/**
 * Replaces every row of `storeName` with `rows`, and only once that has committed,
 * records when under `syncKey`: a sync time is never written for rows that are
 * not there.
 */
async function replaceStoreContents(
  db: IDBDatabase,
  storeName: string,
  rows: unknown[],
  syncKey: string,
): Promise<void> {
  const tx = db.transaction(storeName, 'readwrite');
  const store = tx.objectStore(storeName);
  store.clear();
  for (const row of rows) {
    store.put(row);
  }
  await transactionSettled(tx);
  const metaTx = db.transaction(META_STORE, 'readwrite');
  metaTx.objectStore(META_STORE).put({ key: syncKey, value: Date.now() });
  await transactionSettled(metaTx);
}

/** Every row of `storeName`. */
function readAllRows<T>(db: IDBDatabase, storeName: string): Promise<T[]> {
  const store = db.transaction(storeName).objectStore(storeName);
  return new Promise((resolve, reject) => {
    const request = store.getAll();
    request.onsuccess = () => resolve(request.result as T[]);
    request.onerror = () => reject(request.error ?? new Error('IndexedDB read failed'));
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
  cacheItems(items: unknown[]): Promise<void> {
    return withDatabase((db) => replaceStoreContents(db, ITEMS_STORE, items, 'lastItemsSync'));
  },

  /** Cache all folders (replaces existing cache) */
  cacheFolders(folders: unknown[]): Promise<void> {
    return withDatabase((db) =>
      replaceStoreContents(db, FOLDERS_STORE, folders, 'lastFoldersSync'),
    );
  },

  /** Get cached items */
  getCachedItems<T>(): Promise<T[]> {
    return withDatabase((db) => readAllRows<T>(db, ITEMS_STORE));
  },

  /** Get cached folders */
  getCachedFolders<T>(): Promise<T[]> {
    return withDatabase((db) => readAllRows<T>(db, FOLDERS_STORE));
  },

  /** Get last sync timestamp for items */
  getLastSync(type: 'items' | 'folders'): Promise<number | null> {
    return withDatabase((db) => {
      const store = db.transaction(META_STORE).objectStore(META_STORE);
      const key = type === 'items' ? 'lastItemsSync' : 'lastFoldersSync';
      return new Promise((resolve, reject) => {
        const request = store.get(key);
        request.onsuccess = () => {
          const result = request.result as { key: string; value: number } | undefined;
          resolve(result?.value ?? null);
        };
        request.onerror = () => reject(request.error ?? new Error('IndexedDB read failed'));
      });
    });
  },

  /** Clear all cached data */
  clear(): Promise<void> {
    return withDatabase((db) => {
      const tx = db.transaction([ITEMS_STORE, FOLDERS_STORE, META_STORE], 'readwrite');
      tx.objectStore(ITEMS_STORE).clear();
      tx.objectStore(FOLDERS_STORE).clear();
      tx.objectStore(META_STORE).clear();
      return transactionSettled(tx);
    });
  },
};
