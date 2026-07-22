/**
 * Encrypted, per-user persistence of Vault Health results (breach findings and
 * weak-strength scores) so they survive a page refresh AND a browser close.
 *
 * Design notes:
 * - A DEDICATED IndexedDB database (`hvault-health-<userHash>`), separate from
 *   `offlineCache`, so it is NOT wiped by `offlineCache.clear()` on lock/login.
 *   It is cleared only on explicit logout (see `authStore.logout`). Encrypted at
 *   rest under the vault key, so surviving a lock is exactly as safe as the
 *   already-persisted MEK-wrapped vault key.
 * - STATELESS w.r.t. user scope: every call takes `userId` explicitly and derives
 *   its DB name per call. `offlineCache.setUser()` is not called on unlock, so
 *   relying on module state would read the wrong DB after a refresh.
 * - Every function SWALLOWS errors and degrades gracefully (load → null, writes →
 *   no-op). A locked vault, a rotated key, IndexedDB being unavailable, or a quota
 *   error must never break the page or block logout.
 */
import { cryptoService } from '../crypto/cryptoService';
import { deriveUserHash } from '../offlineCache';

const DB_NAME_PREFIX = 'hvault-health';
const DB_VERSION = 1;
const RESULTS_STORE = 'results';
/** Single-record key: the whole health snapshot lives in one encrypted blob. */
const RECORD_KEY = 'v1';

export interface HealthPerItem {
  /** The item's `updatedAt` at compute time — the cache-busting version. */
  v: string;
  /** HIBP breach count; present ONLY when breached (> 0). Absence ⇒ checked-clean. */
  breach?: number;
  /** zxcvbn score 0-4 from the last strength analysis. */
  strength?: number;
}

export interface HealthResultsPayload {
  perItem: Record<string, HealthPerItem>;
  /** Epoch ms of the last fully-completed breach scan; null if none completed. */
  scanCompletedAt: number | null;
  /** Unique passwords that could not be checked in the last breach scan. */
  breachFailedCount: number;
}

export interface BreachSaveEntry {
  id: string;
  v: string;
  breach?: number;
}

export interface StrengthSaveEntry {
  id: string;
  v: string;
  strength: number;
}

interface EncryptedBlob {
  encrypted: string;
  iv: string;
  tag: string;
}

interface StoredRecord {
  key: string;
  blob: EncryptedBlob;
}

function emptyPayload(): HealthResultsPayload {
  return { perItem: {}, scanCompletedAt: null, breachFailedCount: 0 };
}

function isValidPayload(value: unknown): value is HealthResultsPayload {
  if (typeof value !== 'object' || value === null) return false;
  const p = value as Record<string, unknown>;
  if (typeof p.perItem !== 'object' || p.perItem === null) return false;
  if (!(typeof p.scanCompletedAt === 'number' || p.scanCompletedAt === null)) return false;
  if (typeof p.breachFailedCount !== 'number') return false;
  return true;
}

/**
 * Serializes ALL mutating operations (both savers + clear) through a single
 * per-tab promise chain, so their read-modify-write against the one health
 * record can never interleave. Without this, a breach save and a strength save
 * that both loaded the pre-update snapshot would have the last-committer clobber
 * the other's contribution; and a logout `clear` could be overtaken by an
 * in-flight save that resurrects the just-cleared snapshot. Queueing clear after
 * any in-flight save closes both windows. Reads (`loadHealthResults`) are NOT
 * queued — a concurrent read just sees the current committed record.
 */
let writeQueue: Promise<unknown> = Promise.resolve();
function enqueueWrite(op: () => Promise<void>): Promise<void> {
  const run = writeQueue.then(op, op);
  // Keep the chain alive regardless of any op's outcome (ops swallow internally).
  writeQueue = run.then(
    () => undefined,
    () => undefined,
  );
  return run;
}

async function openDb(userId: string): Promise<IDBDatabase> {
  if (typeof indexedDB === 'undefined') {
    throw new Error('IndexedDB is not available');
  }
  const hash = await deriveUserHash(userId);
  const dbName = `${DB_NAME_PREFIX}-${hash}`;
  return new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open(dbName, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(RESULTS_STORE)) {
        db.createObjectStore(RESULTS_STORE, { keyPath: 'key' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () =>
      reject(request.error instanceof Error ? request.error : new Error('IndexedDB open failed'));
  });
}

function getStoredRecord(db: IDBDatabase): Promise<StoredRecord | undefined> {
  return new Promise((resolve, reject) => {
    const request = db.transaction(RESULTS_STORE).objectStore(RESULTS_STORE).get(RECORD_KEY);
    request.onsuccess = () => resolve(request.result as StoredRecord | undefined);
    request.onerror = () =>
      reject(request.error instanceof Error ? request.error : new Error('IndexedDB read failed'));
  });
}

function putStoredRecord(db: IDBDatabase, record: StoredRecord): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(RESULTS_STORE, 'readwrite');
    tx.objectStore(RESULTS_STORE).put(record);
    tx.oncomplete = () => resolve();
    tx.onerror = () =>
      reject(tx.error instanceof Error ? tx.error : new Error('IndexedDB write failed'));
  });
}

/**
 * Load and decrypt the health snapshot. Returns null on ANY failure (no record,
 * decrypt failure after a vault-key rotation, corruption, invalid shape, or
 * IndexedDB being unavailable) — all of which are treated as a clean cache miss.
 */
export async function loadHealthResults(
  userId: string,
  vaultKey: CryptoKey,
): Promise<HealthResultsPayload | null> {
  let db: IDBDatabase | undefined;
  try {
    db = await openDb(userId);
    const record = await getStoredRecord(db);
    if (!record) return null;
    const json = await cryptoService.decryptData(
      record.blob.encrypted,
      record.blob.iv,
      record.blob.tag,
      vaultKey,
    );
    const parsed: unknown = JSON.parse(json);
    return isValidPayload(parsed) ? parsed : null;
  } catch {
    return null;
  } finally {
    db?.close();
  }
}

async function writePayload(
  userId: string,
  vaultKey: CryptoKey,
  payload: HealthResultsPayload,
): Promise<void> {
  let db: IDBDatabase | undefined;
  try {
    const blob = await cryptoService.encryptData(JSON.stringify(payload), vaultKey);
    db = await openDb(userId);
    await putStoredRecord(db, { key: RECORD_KEY, blob });
  } catch {
    // Persistence degrades to session-only; never surface to the UI.
  } finally {
    db?.close();
  }
}

/**
 * Replace the breach portion of the snapshot after a fully-completed scan.
 * `entries` are ALL checked login items (breach set only when count > 0). The
 * strength score for a version-matched item is carried over; strength-only
 * entries for items not in this scan are preserved.
 */
export function saveBreachResults(
  userId: string,
  vaultKey: CryptoKey,
  entries: readonly BreachSaveEntry[],
  breachFailedCount: number,
  scanCompletedAt: number,
): Promise<void> {
  return enqueueWrite(async () => {
    const existing = (await loadHealthResults(userId, vaultKey)) ?? emptyPayload();
    const perItem: Record<string, HealthPerItem> = {};

    // Preserve strength for items not part of this breach scan.
    for (const [id, datum] of Object.entries(existing.perItem)) {
      if (datum.strength !== undefined) {
        perItem[id] = { v: datum.v, strength: datum.strength };
      }
    }
    // Rebuild the scanned items (breach wholesale-replaced; strength carried when version matches).
    for (const entry of entries) {
      const prev = existing.perItem[entry.id];
      const strength = prev?.v === entry.v ? prev.strength : undefined;
      perItem[entry.id] = {
        v: entry.v,
        ...(entry.breach !== undefined ? { breach: entry.breach } : {}),
        ...(strength !== undefined ? { strength } : {}),
      };
    }

    await writePayload(userId, vaultKey, { perItem, scanCompletedAt, breachFailedCount });
  });
}

/**
 * Merge in weak-strength scores. Preserves each item's breach datum when the
 * version matches; leaves `scanCompletedAt`/`breachFailedCount` untouched.
 */
export function saveStrengthScores(
  userId: string,
  vaultKey: CryptoKey,
  entries: readonly StrengthSaveEntry[],
): Promise<void> {
  return enqueueWrite(async () => {
    const existing = (await loadHealthResults(userId, vaultKey)) ?? emptyPayload();
    const perItem: Record<string, HealthPerItem> = { ...existing.perItem };

    for (const entry of entries) {
      const prev = existing.perItem[entry.id];
      const breach = prev?.v === entry.v ? prev.breach : undefined;
      perItem[entry.id] = {
        v: entry.v,
        strength: entry.strength,
        ...(breach !== undefined ? { breach } : {}),
      };
    }

    await writePayload(userId, vaultKey, {
      perItem,
      scanCompletedAt: existing.scanCompletedAt,
      breachFailedCount: existing.breachFailedCount,
    });
  });
}

/**
 * Delete this user's health snapshot (called on explicit logout). Queued behind
 * any in-flight save so a persist cannot land after the clear and resurrect a
 * cleared snapshot.
 */
export function clearHealthResults(userId: string): Promise<void> {
  return enqueueWrite(async () => {
    let db: IDBDatabase | undefined;
    try {
      db = await openDb(userId);
      const database = db;
      await new Promise<void>((resolve, reject) => {
        const tx = database.transaction(RESULTS_STORE, 'readwrite');
        tx.objectStore(RESULTS_STORE).clear();
        tx.oncomplete = () => resolve();
        tx.onerror = () =>
          reject(tx.error instanceof Error ? tx.error : new Error('IndexedDB clear failed'));
      });
    } catch {
      // Best-effort — a failed clear must never block logout.
    } finally {
      db?.close();
    }
  });
}
