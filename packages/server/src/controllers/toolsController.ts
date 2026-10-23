import type { Request, Response } from 'express';
import { catchAsync, httpErrors } from '@hiprax/errors';
import { createModuleLogger, errorMessage } from '../utils/logger.js';
import bcrypt from 'bcryptjs';
import mongoose from 'mongoose';
import { VaultItem } from '../models/VaultItem.js';
import { Folder } from '../models/Folder.js';
import { User } from '../models/User.js';
import { PwnedRangeCache } from '../models/PwnedRangeCache.js';
import { createAuditLog } from '../services/auditService.js';
import { config } from '../config/index.js';
import {
  StaleVaultKeyError,
  acquireVaultRotationLock,
  assertVaultKeyVersion,
  assertVaultNotRotating,
  getRequestContext,
  getUserId,
  pickAllowedFields,
  releaseVaultRotationLock,
  sendStaleVaultKey,
  vaultImportLockName,
} from '../utils/controllerHelpers.js';
import { createdRowId, isDuplicateIdError, ROW_ID_TAKEN_MESSAGE } from '../utils/rowIds.js';
import {
  countedBytes,
  countedBytesExpression,
  countedBytesOfNew,
  deltaOfPinnedUpdate,
  isDefiniteWriteFailure,
  measureStoredRows,
  releaseVaultWrite,
  reserveVaultWrite,
  settleVaultWrite,
  storedImage,
  versionPin,
  VaultRowLimitError,
  type RowMeasure,
  type VaultWriteReservation,
} from '../utils/vaultQuota.js';
import { acquireJobLock, releaseJobLock } from '../utils/jobLock.js';
import { supportsTransactions } from '../utils/transactionSupport.js';
import { estimateItemJsonSize, estimateFolderJsonSize } from '../utils/sizeEstimator.js';
import {
  EXPORTED_ROW_PROJECTION,
  ROW_CURSOR_BATCH_SIZE,
  closingMembers,
  forEachRow,
  jsonArrayOf,
  sendJsonStream,
} from '../utils/jsonStream.js';
import { sendDeadlineMs } from '../utils/heavyResponseBudget.js';
import { fetchRangeFromHibp } from '../utils/hibp.js';
import { noteOnDemandRangeInsert } from '../utils/breachRangeCap.js';
import {
  BreachMissBudgetError,
  breachMissBudgetFor,
  refuseBreachLookup,
  type BreachMissBudget,
} from '../utils/breachMissBudget.js';
import {
  APP_VERSION,
  MAX_ENCRYPTED_DATA_LENGTH,
  MAX_ENCRYPTED_NAME_LENGTH,
  MAX_ITEMS_PER_USER,
  MASTER_PASSWORD_PROOF_REFUSED_MESSAGE,
} from '@hvault/shared';
import type {
  CheckBreachInput,
  CheckBreachBatchInput,
  ImportInput,
  ExportInput,
} from '@hvault/shared';

const logger = createModuleLogger('tools-controller');

// ── HIBP response cache ─────────────────────────────────────────────
// Bounded per-process cache keyed by 5-char hash prefix, with 1-hour TTL
// and a hard insertion-order LRU cap. Map iteration preserves insertion
// order, so the first key returned by `keys().next()` is the oldest entry —
// giving us LRU eviction without an external dependency. Reads do not
// promote entries (we don't `delete()` + `set()` on hit) because the working
// set for HIBP traffic is much wider than the cap and promoting on read
// would cycle entries needlessly; the TTL handles staleness.

interface HibpCacheEntry {
  data: string;
  expires: number;
  /**
   * Measured UTF-8 byte length of {@link data}, stamped by {@link setHibpCacheEntry}
   * so eviction can subtract an entry's contribution from the running total without
   * re-measuring. Optional because callers construct entries without it (and some
   * tests populate the Map directly via `hibpCache.set`); a missing value counts as 0.
   */
  bytes?: number;
}

const HIBP_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

/**
 * Secondary ceiling on the NUMBER of cached HIBP responses. The BINDING bound is now
 * {@link HIBP_CACHE_MAX_BYTES} (see below): a real range is ~800 rows × ~44 B ≈ 36 KB,
 * so an entry-count cap alone bounds worst-case memory at ~360 MB — uncomfortably close
 * to the ~560 MB V8 heap ceiling under the app's `mem_limit: 1g` (raised from the earlier
 * 512 MB). The entry cap is retained only so a pathological run of tiny ranges cannot grow
 * the Map without bound while staying under the byte budget. The theoretical key space is
 * 16^5 (~1 M) unique 5-char prefixes.
 */
export const HIBP_CACHE_MAX_ENTRIES = 10_000;

/**
 * BINDING memory ceiling for the L1 cache, in bytes (from config, default 64 MiB).
 * Measured ~36 KB/range ⇒ 64 MiB ≈ 1,800 ranges per worker process. `max_memory_restart`
 * is enforced PER PM2 worker, not aggregate across `instances`, so the sizing is one
 * worker's full cache plus its ordinary heap against the threshold — NOT
 * `HIBP_CACHE_MAX_BYTES × instances`. Held in a module-level binding (rather than read
 * from `config` on every insert) so a test seam can shrink it cheaply; see
 * {@link __setHibpCacheMaxBytes}.
 */
let hibpCacheMaxBytes = config.HIBP_CACHE_MAX_BYTES;

/** Current L1 cache budget in bytes (test/introspection accessor). */
export function getHibpCacheMaxBytes(): number {
  return hibpCacheMaxBytes;
}

/**
 * Test seam: override the L1 byte budget so byte-eviction and the single-oversized-entry
 * path can be exercised without allocating tens of MiB of strings. Never called in
 * production. Restore with the value from {@link getHibpCacheMaxBytes} captured beforehand.
 */
export function __setHibpCacheMaxBytes(bytes: number): void {
  hibpCacheMaxBytes = bytes;
}

/**
 * Maximum number of concurrent outbound HIBP lookups a single batch request may
 * have in flight. Bounds how many sockets one request opens and caps its
 * wall-clock (each lookup carries a 10 s timeout), while still parallelizing
 * enough that a batch of cache-miss prefixes resolves quickly. Cache hits never
 * count against it (they are served without an outbound call).
 */
const HIBP_FANOUT_CONCURRENCY = 8;

export const hibpCache = new Map<string, HibpCacheEntry>();

/**
 * Running total of the measured UTF-8 bytes of every entry currently held in
 * {@link hibpCache}. Maintained incrementally by {@link setHibpCacheEntry} and
 * {@link pruneHibpCache} so eviction never has to walk the whole Map to size it.
 * Reads (`hibpCache.set`) and clears (`hibpCache.clear`) that bypass this module —
 * a few tests do — desync it; {@link setHibpCacheEntry} self-heals it to 0 whenever
 * it observes an empty Map, and {@link resetCacheAccessCount} zeroes it outright.
 */
let hibpCacheBytes = 0;

/**
 * A LOWER BOUND on the `expires` of every entry currently held in {@link hibpCache}, or
 * `0` meaning "unknown, a scan is required".
 *
 * It exists to keep the expired-victim search off the insert hot path. Without it,
 * {@link evictHibpToWithinLimits} walks the whole Map looking for an expired entry on
 * EVERY insert once the cache is full — and when nothing is expired that walk finds
 * nothing, so a sustained run of inserts against a full cache costs
 * `inserts × HIBP_CACHE_MAX_ENTRIES` iterations. The batch breach endpoint inserts up to
 * `HIBP_BATCH_MAX_PREFIXES` ranges per request across `HIBP_FANOUT_CONCURRENCY` parallel
 * fetches, so that is a real cost on a real path, and it is the same "never walk the whole
 * Map on the hot path" principle {@link hibpCacheBytes} already applies to sizing.
 *
 * Maintained the only way a lower bound safely can be:
 * - a full scan that finds NOTHING expired records the minimum it saw (the bound is then
 *   exact); a scan that stops early on a victim records nothing and leaves it unknown;
 * - {@link pruneHibpCache}'s sweep, which walks the whole Map anyway, records it too;
 * - an insert through {@link setHibpCacheEntry} lowers it to the new entry's `expires`,
 *   because a bound that ignored new entries would let an already-expired insert hide
 *   behind a future bound;
 * - evicting can only RAISE the true minimum, so it never invalidates the bound;
 * - {@link resetCacheAccessCount} and an observed-empty Map reset it to unknown.
 *
 * A raw `hibpCache.set` that bypasses this module (a few tests do) can leave the bound
 * stale-high, exactly as it already desyncs {@link hibpCacheBytes}. The consequence is
 * bounded and is never a correctness fault: that entry loses its eviction PRIORITY for
 * one round, `pruneHibpCache` still reaps it, and every read still treats it as a miss.
 */
let hibpEarliestExpiry = 0;

/** Measured byte total of the L1 cache (test/introspection accessor). */
export function getHibpCacheBytes(): number {
  return hibpCacheBytes;
}

// Periodic cache pruning — every 100 accesses, evict expired entries.
let cacheAccessCount = 0;
/** Test seam: reset the per-process cache bookkeeping (access counter AND byte total). */
export function resetCacheAccessCount(): void {
  cacheAccessCount = 0;
  hibpCacheBytes = 0;
  hibpEarliestExpiry = 0;
}
export function pruneHibpCache(): void {
  if (++cacheAccessCount % 100 !== 0) return;
  const now = Date.now();
  let earliest = Number.POSITIVE_INFINITY;
  for (const [key, value] of hibpCache) {
    if (value.expires < now) {
      hibpCache.delete(key);
      hibpCacheBytes -= value.bytes ?? 0;
    } else if (value.expires < earliest) {
      earliest = value.expires;
    }
  }
  if (hibpCacheBytes < 0) hibpCacheBytes = 0;
  // The sweep walked every entry, so what survived it establishes the bound exactly.
  hibpEarliestExpiry = Number.isFinite(earliest) ? earliest : 0;
}

/**
 * Evict entries — an EXPIRED one first, otherwise the OLDEST-inserted (Map iteration
 * is insertion-ordered) — until the cache is within BOTH the entry-count cap and the
 * byte budget. Never evicts below a single entry: if one entry alone exceeds the byte
 * budget it is kept, leaving the cache over budget by exactly that entry (documented
 * behaviour — the alternative is to refuse to cache a legitimately large range).
 */
function evictHibpToWithinLimits(): void {
  while (
    hibpCache.size > 1 &&
    (hibpCache.size > HIBP_CACHE_MAX_ENTRIES || hibpCacheBytes > hibpCacheMaxBytes)
  ) {
    const now = Date.now();
    let victimKey: string | undefined;
    // Skip the scan entirely while the recorded bound proves nothing can be expired yet;
    // see {@link hibpEarliestExpiry} for why that bound is safe.
    if (hibpEarliestExpiry === 0 || now >= hibpEarliestExpiry) {
      let earliest = Number.POSITIVE_INFINITY;
      for (const [existingKey, existingEntry] of hibpCache) {
        if (existingEntry.expires < now) {
          victimKey = existingKey;
          break;
        }
        if (existingEntry.expires < earliest) earliest = existingEntry.expires;
      }
      // A scan that reached the end without a victim measured the bound exactly; one that
      // stopped early saw only a prefix of the Map and must leave it unknown. `earliest` is
      // always finite in the first case: the loop above only runs while `size > 1`, so it
      // saw at least one entry and every entry sets it. No `isFinite` guard, therefore —
      // it would be a branch no input can take, which is a mutant nothing can kill.
      if (victimKey === undefined) {
        hibpEarliestExpiry = earliest;
      }
    }
    // No expired entry to harvest — fall back to oldest-insertion eviction.
    victimKey ??= hibpCache.keys().next().value;
    if (victimKey === undefined) break;
    const victim = hibpCache.get(victimKey);
    hibpCache.delete(victimKey);
    hibpCacheBytes -= victim?.bytes ?? 0;
  }
  if (hibpCacheBytes < 0) hibpCacheBytes = 0;
}

/**
 * Inserts a HIBP response into the cache, keeping the byte total accurate and enforcing
 * BOTH the {@link HIBP_CACHE_MAX_BYTES} budget and the {@link HIBP_CACHE_MAX_ENTRIES}
 * cap. An update-in-place adjusts the total by the delta (never double-counts); a fresh
 * insert then evicts (expired-first, else oldest) until within both limits.
 */
export function setHibpCacheEntry(key: string, entry: HibpCacheEntry): void {
  // Self-heal the running total after any external `hibpCache.clear()` that bypassed
  // this module: an empty Map holds zero bytes, and no bound describes it.
  if (hibpCache.size === 0) {
    hibpCacheBytes = 0;
    hibpEarliestExpiry = 0;
  }

  const bytes = Buffer.byteLength(entry.data, 'utf8');
  const stored: HibpCacheEntry = { data: entry.data, expires: entry.expires, bytes };
  // Lower the bound to cover the newcomer. Without this an already-expired insert would
  // hide behind a bound measured before it arrived and lose its eviction priority.
  if (hibpEarliestExpiry !== 0 && entry.expires < hibpEarliestExpiry) {
    hibpEarliestExpiry = entry.expires;
  }

  const existing = hibpCache.get(key);
  if (existing) {
    // Replace in place: no new slot, so adjust the total by the size delta only.
    hibpCacheBytes += bytes - (existing.bytes ?? 0);
    hibpCache.set(key, stored);
    evictHibpToWithinLimits();
    return;
  }

  hibpCache.set(key, stored);
  hibpCacheBytes += bytes;
  evictHibpToWithinLimits();
}

// ── Layered range lookup (L1 in-memory → L2 MongoDB → L3 HIBP) ───────
//
// L2 (`PwnedRangeCache`) is a PERSISTENT, CROSS-ACCOUNT cache of PUBLIC HIBP
// range data (survives restarts, shared across workers). Zero-knowledge is
// preserved: the server only ever receives the 5-char prefix, never a suffix or
// full hash, and nothing user-linked is stored. Fail-safe: a cache miss falls
// through to HIBP, and an HIBP failure with no cache surfaces as a 5xx (single)
// / errors[] (batch) — never a false "not breached". The single endpoint's
// status is whatever the error middleware maps the rejection to: a real
// `AxiosError` with no `.response` becomes 502, a non-axios rejection 500.

/**
 * What a shared lookup settles with when its CREATOR's fetch budget refused it:
 * nothing was fetched, and that says nothing about the budget of anyone who
 * joined, so each of them looks again with its own (see {@link getRange}).
 */
const NOT_FETCHED = Symbol('not fetched');

/**
 * Per-process coalescing of concurrent duplicate lookups (thundering-herd guard).
 * A lookup settles with the range, rejects only for an UPSTREAM failure with no
 * cached fallback, and settles with {@link NOT_FETCHED} when its creator's budget
 * refused it — never with that refusal, which belongs to the creator alone.
 */
export const rangeInFlight = new Map<string, Promise<string | typeof NOT_FETCHED>>();

const MS_PER_DAY = 86_400_000;

/**
 * Whether an L2 entry may be served without re-fetching. `seed`-sourced entries
 * (bulk-imported by the seed job) are TTL-exempt — their freshness is owned by
 * the operator re-running the seed, not by per-request refresh. `hibp`-sourced
 * entries expire after `BREACH_CACHE_TTL_DAYS`; the corpus is additive, so a
 * stale entry can only miss a very recently added breach, never wrongly clear one.
 */
function isRangeFresh(doc: { source: string; fetchedAt: Date }, now: number): boolean {
  if (doc.source === 'seed') return true;
  return doc.fetchedAt.getTime() + config.BREACH_CACHE_TTL_DAYS * MS_PER_DAY > now;
}

/**
 * Stores a range fetched on demand; returns whether that INSERTED a row.
 *
 * A row the seed command wrote is never overwritten, not even one it wrote while
 * this fetch was in flight: turning it into an on-demand row would put it under
 * the TTL and the row cap, which seeded rows are exempt from. Such a row fails the
 * filter, the upsert's insert then meets the unique `prefix` index, and that
 * duplicate-key refusal means "already stored": the lookup still answers with
 * what it fetched. The same holds when another worker inserted it first.
 *
 * `runValidators` is deliberately OMITTED here (unlike most update sites in this
 * codebase). Mongoose's `required` check on a String rejects '', and an EMPTY
 * range is a legitimate value: a prefix whose every row was count-0 padding has no
 * real breached suffixes. Adding the flag would make those prefixes fail to cache
 * and re-hit HIBP forever.
 */
async function storeFetchedRange(prefix: string, range: string): Promise<boolean> {
  try {
    const written = await PwnedRangeCache.updateOne(
      { prefix, source: { $ne: 'seed' } },
      { $set: { range, source: 'hibp', fetchedAt: new Date() } },
      { upsert: true },
    );
    return written.upsertedCount > 0;
  } catch (err: unknown) {
    if ((err as { code?: unknown } | null)?.code !== 11000) throw err;
    return false;
  }
}

/**
 * Resolve the (padding-stripped) HIBP range for a prefix through the cache
 * layers, charging `budget` (the requesting account's, REQUIRED: this is the one
 * path an account can make the server fetch through) for a fetch it causes.
 *
 * Throws when neither the cache nor HIBP can answer: an upstream failure, or a
 * {@link BreachMissBudgetError} when the account's budget is spent. In both cases
 * a stale cached range is served instead when there is one.
 */
export async function getRange(rawPrefix: string, budget: BreachMissBudget): Promise<string> {
  const prefix = rawPrefix.toUpperCase(); // canonical key (matches HIBP + the DB)
  const now = Date.now();

  const l1 = hibpCache.get(prefix);
  if (l1 && l1.expires > now) return l1.data;

  const pending = rangeInFlight.get(prefix);
  if (pending) {
    const outcome = await pending;
    if (outcome !== NOT_FETCHED) return outcome;
    // The lookup joined was refused its creator's budget: look again with ours.
    // Its creator has already freed the prefix (see the `finally` below), so this
    // cannot rejoin the refused lookup.
    return getRange(prefix, budget);
  }

  let refusal: unknown;
  const lookup = async (): Promise<string | typeof NOT_FETCHED> => {
    const doc = await PwnedRangeCache.findOne({ prefix }).lean();
    if (doc && isRangeFresh(doc, now)) {
      setHibpCacheEntry(prefix, { data: doc.range, expires: now + HIBP_CACHE_TTL_MS });
      return doc.range;
    }
    try {
      await budget.charge();
    } catch (err: unknown) {
      if (doc) {
        // Same fallback as an unreachable HIBP (below): real cached data, never a
        // false "safe", and not written to L1, so a later lookup fetches again.
        logger.warn('Breach fetch budget spent; serving stale range-cache entry', { prefix });
        return doc.range;
      }
      refusal = err;
      return NOT_FETCHED;
    }
    try {
      const range = await fetchRangeFromHibp(prefix);
      const inserted = await storeFetchedRange(prefix, range);
      setHibpCacheEntry(prefix, { data: range, expires: Date.now() + HIBP_CACHE_TTL_MS });
      // A NEW row is what grows the shared cache (a refresh rewrites one in
      // place), so only an insert counts toward the sampled cap eviction.
      if (inserted) await noteOnDemandRangeInsert();
      return range;
    } catch (err) {
      if (doc) {
        // Resilience: serve the stale L2 entry — REAL cached range data, so every
        // breach it already recorded is still reported. The only residual gap is a
        // breach ADDED upstream after this entry was cached (bounded by
        // BREACH_CACHE_TTL_DAYS), which serving stale-real-data risks but reporting
        // the prefix as "unchecked" would too; stale-real is the better fallback.
        // Deliberately NOT written to L1, so the next request retries L3.
        logger.warn('HIBP fetch failed; serving stale range-cache entry', { prefix });
        return doc.range;
      }
      throw err;
    }
  };
  const task = lookup();
  rangeInFlight.set(prefix, task);
  try {
    const outcome = await task;
    if (outcome === NOT_FETCHED) throw refusal;
    return outcome;
  } finally {
    // The entry is still this lookup's own. Nothing registers under a prefix
    // while an entry is there (a newcomer joins it instead), and this `await` was
    // registered on `task` before any joiner's, so it resumes first: a joiner
    // that looks again after a refusal finds the prefix already free.
    rangeInFlight.delete(prefix);
  }
}

// ── Helpers ──────────────────────────────────────────────────────────

const HEX_PREFIX_RE = /^[0-9a-fA-F]{5}$/;

export const ALLOWED_ITEM_FIELDS = new Set([
  'encryptedData',
  'dataIv',
  'dataTag',
  'encryptedName',
  'nameIv',
  'nameTag',
  'itemType',
  'tags',
  'favorite',
  'folderId',
  'passwordHistory',
]);

/**
 * Fields an import UPDATE is allowed to write. Deliberately NARROWER than
 * {@link ALLOWED_ITEM_FIELDS}: the six ciphertext fields and the optional
 * `passwordHistory` — and nothing else. Neither list names `searchHash`: no
 * keyed hash of a name is stored (F-12), and an older client that still sends
 * one has it dropped by the schema before this projection runs.
 *
 * `tags`, `favorite`, `folderId` and `itemType` are absent on purpose: an import
 * updates CONTENT and must never silently reorganize or retype a vault the user
 * has already curated. Projecting updates through the broader insert allowlist
 * would reintroduce exactly that, which is why this is a separate constant
 * rather than a reuse.
 *
 * This is the SECOND of two layers. `importUpdateItemSchema` has no such fields,
 * and Zod strips unknown keys before the controller runs, so today those keys
 * are already gone by the time this projection happens — which also means no
 * runtime test can observe which allowlist is passed here. This constant earns
 * its keep on the day someone widens that schema; keep both layers.
 */
export const ALLOWED_UPDATE_FIELDS = new Set([
  'encryptedName',
  'nameIv',
  'nameTag',
  'encryptedData',
  'dataIv',
  'dataTag',
  'passwordHistory',
]);

/**
 * TTL of the per-user import lock (`vault-import:<userId>`).
 *
 * Comfortably longer than one request's execution — a single batch is bounded
 * by the global 2 MB body parser and by `MAX_IMPORT_ITEMS` — yet short enough
 * that a process that dies mid-import does not lock the user out of retrying
 * for long.
 */
const IMPORT_LOCK_TTL_MS = 2 * 60 * 1000;

/** Single source of the per-user cap rejection message (the reservation's row refusal). */
function importCapExceededMessage(existingItemCount: number, netNewItems: number): string {
  return `Import would exceed the per-user item limit (${String(MAX_ITEMS_PER_USER)}). You currently have ${String(existingItemCount)} items and this import would add ${String(netNewItems)}.`;
}

// ── Export size estimation ──────────────────────────────────────────
// Per-row size estimation lives in `utils/sizeEstimator.ts` so the export and
// backup paths share the same conservative overhead constants. The
// response-wrapper overhead is local because it covers the export envelope
// specifically (backup payloads have a different envelope structure).

// Response envelope overhead: covers `{"success":true,"data":{"items":[],"folders":[],"metadata":{...}}}`
// plus the metadata block (exportDate ISO timestamp, version string, itemCount).
const RESPONSE_WRAPPER_OVERHEAD = 1024;

/**
 * Per-field length caps for imported items. These mirror the `maxlength`
 * constraints declared on the VaultItem model (see
 * `packages/server/src/models/VaultItem.ts`): the IV (24) and auth-tag (32)
 * caps are the base64 ceilings used throughout the schema layer.
 */
const IMPORT_FIELD_MAXLENGTHS: readonly { readonly field: string; readonly max: number }[] = [
  { field: 'encryptedData', max: MAX_ENCRYPTED_DATA_LENGTH },
  { field: 'encryptedName', max: MAX_ENCRYPTED_NAME_LENGTH },
  { field: 'dataIv', max: 24 },
  { field: 'nameIv', max: 24 },
  { field: 'dataTag', max: 32 },
  { field: 'nameTag', max: 32 },
];

/**
 * Rejects the whole import with a clear 400 if any row has an over-length
 * encrypted field. Applied to BOTH the rows an import inserts and the rows it
 * updates.
 *
 * `importInsertItemSchema` / `importUpdateItemSchema` already enforce the same
 * ceilings, so this is the defense-in-depth layer that matters only if those
 * bounds are ever loosened: an over-length field would otherwise trip a Mongoose
 * validator mid-write, leaving earlier rows persisted and the success-only
 * `import` audit log skipped — a partial, unaudited import.
 *
 * Scope the claim honestly: validating up front removes the FIELD-LENGTH route
 * to a partial import, not every route. On a topology with transactions the
 * request is genuinely atomic; on the sequential fallback a mid-loop 409 from
 * `matchedCount === 0` still leaves the preceding `insertMany` committed.
 */
function assertImportFieldLengths(items: readonly object[]): void {
  for (const item of items) {
    const row = item as Record<string, unknown>;
    for (const { field, max } of IMPORT_FIELD_MAXLENGTHS) {
      const value = row[field];
      if (typeof value === 'string' && value.length > max) {
        throw httpErrors.badRequest(
          `Import rejected: item field "${field}" exceeds the maximum length of ${String(max)} characters.`,
        );
      }
    }
  }
}

// ── Handlers ─────────────────────────────────────────────────────────

export const checkPasswordBreach = catchAsync(
  async (req: Request, res: Response): Promise<void> => {
    const { hashPrefix } = req.body as CheckBreachInput;

    pruneHibpCache();

    // Defense-in-depth: validate hex format even though the Zod schema already does.
    // Prevents SSRF if the schema validation is ever bypassed or misconfigured.
    if (!HEX_PREFIX_RE.test(hashPrefix)) {
      throw httpErrors.badRequest('Invalid hash prefix: must be exactly 5 hex characters');
    }

    // Layered lookup: L1 in-memory → L2 pwned_range_cache → L3 HIBP, a fetch
    // charged to this account's budget.
    let data: string;
    try {
      data = await getRange(hashPrefix, breachMissBudgetFor(getUserId(req)));
    } catch (err: unknown) {
      if (err instanceof BreachMissBudgetError) refuseBreachLookup(res, err);
      throw err;
    }

    res.status(200).json({
      success: true,
      data,
    });
  },
);

/**
 * Run `task` over `items` with at most `limit` promises in flight at once.
 *
 * A worker-pool pattern: `limit` workers each pull the next index from a shared
 * cursor (grabbed synchronously, so no two workers claim the same index) until
 * the list is exhausted. The task is responsible for handling its own rejections
 * — the batch handler catches per prefix — so this never rejects for a single
 * failed item.
 */
async function runWithConcurrency<T>(
  items: readonly T[],
  limit: number,
  task: (item: T) => Promise<void>,
): Promise<void> {
  if (items.length === 0) return;
  const workerCount = Math.min(limit, items.length);
  let cursor = 0;
  const worker = async (): Promise<void> => {
    while (cursor < items.length) {
      const index = cursor++;
      await task(items[index] as T);
    }
  };
  await Promise.all(Array.from({ length: workerCount }, () => worker()));
}

/**
 * Batched breach check: proxy several HIBP k-anonymity range lookups in one
 * request. The client sends the 5-char SHA-1 prefixes of its UNIQUE passwords
 * (deduplicated client-side); only prefixes ever leave the device, so the full
 * hash is never revealed to the server or to HIBP. Prefixes are deduped and
 * uppercase-normalized here too (so mixed-case duplicates collapse to one lookup
 * and share a canonical cache key), then resolved through the layered range cache
 * ({@link getRange}: in-memory L1 → persistent MongoDB L2 → HIBP L3) with bounded
 * fan-out concurrency for the cache-miss prefixes.
 *
 * The response carries `data` (prefix -> HIBP range text) for every resolved
 * prefix and `errors` (prefixes whose lookup failed). A failed prefix is reported
 * EXPLICITLY and never silently omitted or returned empty: the client counts it
 * as "not checked" rather than "not breached", so a transient upstream failure
 * can never be mistaken for a clean bill of health.
 */
export const checkPasswordBreachBatch = catchAsync(
  async (req: Request, res: Response): Promise<void> => {
    const { hashPrefixes } = req.body as CheckBreachBatchInput;

    pruneHibpCache();

    // Dedupe + uppercase-normalize before any lookup.
    const uniquePrefixes = [...new Set(hashPrefixes.map((p) => p.toUpperCase()))];

    // Defense-in-depth: re-validate every prefix even though the Zod schema
    // already did, keeping the SSRF guard local to the outbound call site.
    for (const prefix of uniquePrefixes) {
      if (!HEX_PREFIX_RE.test(prefix)) {
        throw httpErrors.badRequest('Invalid hash prefix: must be exactly 5 hex characters');
      }
    }

    const data: Record<string, string> = {};
    const errors: string[] = [];
    // ONE budget for the whole request: once it refuses, it refuses at once.
    const budget = breachMissBudgetFor(getUserId(req));
    let refusal: BreachMissBudgetError | undefined;

    // Every unique prefix routes through the layered cache (L1 in-memory →
    // L2 pwned_range_cache → L3 HIBP). L1/L2-warm prefixes resolve without any
    // outbound call, so fanning out over ALL prefixes (not just misses) is cheap
    // and preserves the exact response contract.
    await runWithConcurrency(uniquePrefixes, HIBP_FANOUT_CONCURRENCY, async (prefix) => {
      // The request is refused as a whole, so a prefix not started yet is left.
      if (refusal) return;
      try {
        data[prefix] = await getRange(prefix, budget);
      } catch (err) {
        if (err instanceof BreachMissBudgetError) {
          refusal = err;
          return;
        }
        // Report the prefix as unchecked — never omit it silently (the client
        // would read a missing prefix as "no breach").
        errors.push(prefix);
        logger.warn('HIBP batch lookup failed', {
          error: err instanceof Error ? err.message : 'unknown',
        });
      }
    });

    // A spent budget refuses the whole batch rather than answer part of it: the
    // client retries a 429 after `Retry-After`, never a prefix listed in
    // `errors`. Nothing fetched before the refusal is lost; it is in the shared
    // cache, so the retry gets it as a free hit.
    if (refusal) refuseBreachLookup(res, refusal);

    res.status(200).json({ success: true, data, errors });
  },
);

export const exportVault = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { authHash, portableFormat } = req.body as ExportInput;

  // Re-authentication is mandatory for vault export
  const user = await User.findById(userId).select('+authHash');
  if (!user) {
    throw httpErrors.notFound('User not found');
  }
  const isMatch = await bcrypt.compare(authHash, user.authHash);
  if (!isMatch) {
    const failCtx = getRequestContext(req);
    await createAuditLog(
      userId,
      'password_verification_failed',
      { endpoint: 'export' },
      failCtx.ip,
      failCtx.userAgent,
    );
    throw httpErrors.unauthorized(MASTER_PASSWORD_PROOF_REFUSED_MESSAGE);
  }

  const maxSizeBytes = config.EXPORT_MAX_SIZE_MB * 1024 * 1024;
  const refuseTooLarge = (): never => {
    throw httpErrors.payloadTooLarge(
      `Export size exceeds the maximum allowed size (${String(config.EXPORT_MAX_SIZE_MB)} MB)`,
    );
  };
  const liveItems = () =>
    VaultItem.find({ userId, deletedAt: { $exists: false } })
      .select(EXPORTED_ROW_PROJECTION)
      .batchSize(ROW_CURSOR_BATCH_SIZE)
      .lean()
      .cursor();
  const allFolders = () =>
    Folder.find({ userId })
      .select(EXPORTED_ROW_PROJECTION)
      .batchSize(ROW_CURSOR_BATCH_SIZE)
      .lean()
      .cursor();

  // The size is decided BEFORE the first byte, so a refusal is a whole 413 rather
  // than a truncated file: a walk of both cursors with the conservative field-length
  // estimator (see `estimateItemJsonSize`), one row at a time, stopping at the row
  // that crosses the budget.
  let estimatedSize = RESPONSE_WRAPPER_OVERHEAD;
  // `forEachRow` closes each cursor on every exit, the refusal thrown here included.
  await forEachRow(liveItems(), (item) => {
    estimatedSize += estimateItemJsonSize(item as unknown as Record<string, unknown>);
    if (estimatedSize > maxSizeBytes) refuseTooLarge();
  });
  await forEachRow(allFolders(), (folder) => {
    estimatedSize += estimateFolderJsonSize(folder as unknown as Record<string, unknown>);
    if (estimatedSize > maxSizeBytes) refuseTooLarge();
  });

  // Match the backup download pattern so browsers trigger a download rather
  // than rendering the JSON inline.
  const exportTimestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const exportFilename = `hvault-export-${exportTimestamp}.enc`;
  res.status(200);
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="${exportFilename}"`);

  const exportCtx = getRequestContext(req);
  const tally = { items: 0, folders: 0 };
  // An object rather than a `let`: the flag is set inside `record`, which the
  // compiler cannot see running before the check below.
  const recording = { done: false };
  // `portableFormat` is AUDIT METADATA ONLY (validated by exportSchema): its
  // sole effect is to record a distinct `export_plaintext` action for a
  // browser-side plaintext export. The response body is byte-identical whether
  // or not it is present — nothing branches on the value beyond the audit action
  // and its metadata.
  const record = async (completed: boolean): Promise<void> => {
    recording.done = true;
    await createAuditLog(
      userId,
      portableFormat ? 'export_plaintext' : 'export',
      {
        itemCount: tally.items,
        folderCount: tally.folders,
        completed,
        ...(portableFormat ? { portableFormat } : {}),
      },
      exportCtx.ip,
      exportCtx.userAgent,
    );
  };

  // Streamed from the cursors, with backpressure, under an absolute send deadline
  // derived from the estimate. Recorded once the content has been produced, before
  // the final byte; an export that ends early is recorded as `completed: false`,
  // because what reached the client before the cut still left the server.
  const outcome = await sendJsonStream(
    res,
    (async function* exportDocument() {
      yield '{"success":true,"data":{"items":';
      yield* jsonArrayOf(liveItems(), () => {
        tally.items += 1;
      });
      yield ',"folders":';
      yield* jsonArrayOf(allFolders(), () => {
        tally.folders += 1;
      });
      yield closingMembers({
        metadata: {
          exportDate: new Date().toISOString(),
          version: APP_VERSION,
          itemCount: tally.items,
        },
      });
      await record(true);
      yield '}';
    })(),
    { deadlineMs: sendDeadlineMs(estimatedSize), label: 'Vault export' },
  );

  // `record` cannot throw: it is one audit write, which swallows its own failures.
  if (!outcome.completed && !recording.done) {
    await record(false);
    return;
  }

  logger.info('Vault exported', { userId, itemCount: tally.items });
});

interface ImportOperationsParams {
  userId: string;
  format: ImportInput['format'];
  conflictStrategy: ImportInput['conflictStrategy'];
  operations: ImportInput['operations'];
  /** The vault-key generation every ciphertext field in `operations` was sealed under. */
  vaultKeyVersion: number | undefined;
}

/**
 * Executes a structured `operations` import.
 *
 * The server is a validated EXECUTOR here, never a matcher. Conflict resolution
 * happens on the CLIENT — the match key for a login is its site and username,
 * both of which live inside the encrypted blob, so the server physically cannot
 * compute it. This path therefore performs NO name matching of any kind and
 * does not act on `conflictStrategy` (retained as audit metadata only): it
 * validates ownership, caps and field lengths, then applies exactly the
 * `inserts` and `updates` it was handed.
 *
 * Order of operations is load-bearing:
 *   1. per-item encrypted-field lengths, over BOTH arrays, before any DB work
 *   2. strip `folderId`s the caller does not own (inserts only)
 *   3. verify every update target is a LIVE item of the caller's — a foreign,
 *      unknown or trashed id is a 400, never a silent skip
 *   4. the per-user item cap, measured against net-new INSERTS only
 *   5. the writes
 *
 * Steps 4 and 5 run under the per-user `vault-import:<userId>` JobLock and,
 * where the topology allows, a transaction — see the block comments below.
 */
async function executeImportOperations(
  req: Request,
  res: Response,
  { userId, format, conflictStrategy, operations, vaultKeyVersion }: ImportOperationsParams,
): Promise<void> {
  const { inserts, updates } = operations;

  // 1 ── Encrypted-field lengths across inserts AND updates, before any write.
  assertImportFieldLengths([...inserts, ...updates]);

  // 2 ── folderId ownership. A folder the caller does not own is stripped from
  // the row rather than failing it — unlike an unresolvable update target below,
  // which rejects the request. The asymmetry is deliberate: a foreign folder id
  // costs the item nothing but its placement, so importing it at the vault root
  // preserves the credential, whereas an update naming an item that is not the
  // caller's has no safe interpretation at all.
  const requestedFolderIds = inserts
    .map((item) => item.folderId)
    .filter((folderId): folderId is string => folderId !== undefined);
  const ownedFolderIds = new Set<string>();
  if (requestedFolderIds.length > 0) {
    const folders = await Folder.find({ _id: { $in: requestedFolderIds }, userId })
      .select('_id')
      .lean();
    for (const folder of folders) {
      ownedFolderIds.add(String(folder._id));
    }
  }

  // Every insert is mapped through the FIXED `ALLOWED_ITEM_FIELDS` projection,
  // never a spread, so an injected or prototype-polluting key on an import row
  // is inert even if the schema's unknown-key stripping is ever relaxed.
  //
  // The derived `_id` is spread in by name, past that projection, for the reason
  // `createdRowId` gives: an insert whose fields were sealed to the id its nonce
  // derives must be stored under exactly that id.
  const insertDocs: Record<string, unknown>[] = [];
  for (const item of inserts) {
    const doc = pickAllowedFields(item, ALLOWED_ITEM_FIELDS);
    if (typeof doc.folderId === 'string' && !ownedFolderIds.has(doc.folderId)) {
      delete doc.folderId;
    }
    // Every insert carries its id from here on (a derived one, or one minted now),
    // so after a partial failure the rows that landed can be measured by id.
    const rowId = await createdRowId(userId, item.idNonce);
    insertDocs.push({ ...doc, _id: new mongoose.Types.ObjectId(), ...rowId, userId });
  }
  const derivedIds = insertDocs
    .map((doc) => doc._id)
    .filter((id): id is string => typeof id === 'string');

  // 3 ── Update-target ownership. The lookup is scoped to LIVE items of this
  // user so it mirrors the client resolver's own matching scope (non-trashed,
  // owned). Anything unresolved rejects the whole request: silently skipping it
  // would report an update the vault never received, and re-running the import
  // would then not repair it.
  const updateIds = updates.map((update) => update.id);
  if (updateIds.length > 0) {
    // Two rows naming one id would both be applied (last write wins) and would
    // report `updatedCount` 2 for a single modified item, so the caller's own
    // accounting could no longer be reconciled against the response. Resolution
    // collapses to at most one operation per target, so a duplicate is a caller
    // defect: surface it rather than silently double-writing.
    if (new Set(updateIds).size !== updateIds.length) {
      throw httpErrors.badRequest(
        'Import rejected: the same item id appears more than once in "updates".',
      );
    }

    const ownedItems = await VaultItem.find({
      _id: { $in: updateIds },
      userId,
      deletedAt: { $exists: false },
    })
      .select('_id')
      .lean();
    const ownedItemIds = new Set(ownedItems.map((item) => String(item._id)));
    const unresolvedIds = new Set(updateIds.filter((id) => !ownedItemIds.has(id)));
    if (unresolvedIds.size > 0) {
      throw httpErrors.badRequest(
        `Import rejected: ${String(unresolvedIds.size)} update target(s) do not exist, are in the trash, or do not belong to you.`,
      );
    }
  }

  // 4+5 ── Serialize imports per user.
  //
  // The item cap itself is held by the account's row counter (the reservation
  // below, F-15), which every inserter shares. This lock is what keeps two
  // imports of one account from interleaving their derived-id pre-check, their
  // measures and their writes: a transaction alone does not bound concurrency on
  // every topology (a standalone deployment rejects multi-document transactions
  // outright), while `acquireJobLock` is an atomic upsert against the unique
  // `jobName` index and holds with or without them. The client sends its batches
  // sequentially, so it never self-contends.
  const lockName = vaultImportLockName(userId);
  const lockId = await acquireJobLock(lockName, IMPORT_LOCK_TTL_MS);
  if (lockId === null) {
    throw httpErrors.conflict('An import is already in progress. Please wait and retry.');
  }

  let insertedCount = 0;
  let updatedCount = 0;
  let insertedIds: string[] = [];
  let rotationLockId: string | null = null;

  try {
    // ── The vault-key exclusion lock ───────────────────────────────────────
    //
    // The generation check below is a READ, and a read is only worth the
    // distance to the write that trusts it. From here to `insertMany` lie the
    // reservation, a transaction start and, on the way in, everything already
    // done above; a rotation that raises its fence anywhere inside that span is
    // one both the fence read and the generation read have already decided does
    // not exist, and every row this handler then commits is sealed under a key
    // the rotation is in the middle of replacing. Those rows are stranded the
    // instant they land — the rotation enumerated the account before they
    // existed — and nothing tells the importer.
    //
    // This is the lock `bulkReEncrypt` takes BEFORE it raises that fence and
    // releases AFTER it lowers it, so holding it here means no rotation can
    // start: the two genuinely exclude each other instead of merely being
    // unlikely to interleave. A conditional filter cannot do the job on this
    // endpoint, because the write is an `insertMany` into another collection
    // and there is nothing on those documents to condition.
    //
    // Taken INSIDE this `try`, after the import lock, so the one `finally`
    // below releases both and in the reverse order. Acquisition order is fixed
    // — import lock outside, exclusion lock inside, never the other way — and
    // it is documented at `acquireVaultRotationLock`; every acquisition is
    // non-blocking, so no ordering can deadlock, but a stable order keeps that
    // reviewable rather than merely true today.
    rotationLockId = await acquireVaultRotationLock(userId);

    // A derived id that is already stored, refused BEFORE the first insert. The
    // standalone path has no transaction, and an ordered `insertMany` that meets a
    // duplicate `_id` keeps every row ahead of it, so leaving this to the
    // duplicate-key error would half-apply a batch. Under the import lock, so no
    // second import can store one of these ids in between; a create from another
    // endpoint still can, and that hairline is caught at the insert below.
    if (derivedIds.length > 0 && (await VaultItem.exists({ _id: { $in: derivedIds } }))) {
      throw httpErrors.conflict(ROW_ID_TAKEN_MESSAGE);
    }

    // ── The byte quota (F-24) and the item cap (F-15): ONE reservation ─────
    //
    // Every insert's size plus every update's growth (never its shrink), measured
    // in the database against the rows as they stand, AND one row per insert
    // against the item cap (net-new inserts only: an update rewrites a row that
    // already exists), in ONE conditional update on the account, so the request
    // is refused WHOLE, with 400, before any row is written. What landed is
    // settled once the outcome is known (below).
    //
    // The cap used to be a `countDocuments` here and again inside the
    // transaction. The import lock serialised imports, but a create from another
    // endpoint (`POST /items`, `POST /backup/restore`) could land between a count
    // and the insert and take the account past the cap. Every inserter now
    // reserves its rows in the same counters, so whichever reservation lands first
    // takes the last place and the other is refused.
    const updateSets = updates.map((update) => pickAllowedFields(update, ALLOWED_UPDATE_FIELDS));
    const measureTargets = async (
      session?: mongoose.ClientSession,
    ): Promise<Map<string, RowMeasure>> => {
      const measures = await measureStoredRows(
        'item',
        {
          _id: { $in: updates.map((update) => new mongoose.Types.ObjectId(update.id)) },
          userId: new mongoose.Types.ObjectId(userId),
          deletedAt: { $exists: false },
        },
        { $set: Object.fromEntries([...ALLOWED_UPDATE_FIELDS].map((field) => [field, true])) },
        session,
      );
      return new Map(measures.map((measure) => [String(measure._id), measure]));
    };
    const preMeasured = updates.length > 0 ? await measureTargets() : new Map<string, RowMeasure>();
    let insertBytes = 0;
    for (const doc of insertDocs) insertBytes += countedBytesOfNew('item', doc);
    let predicted = insertBytes;
    updates.forEach((update, index) => {
      const measure = preMeasured.get(update.id);
      if (measure) {
        predicted += Math.max(
          0,
          deltaOfPinnedUpdate('item', measure, { $set: updateSets[index] ?? {} }),
        );
      }
    });
    let reservation: VaultWriteReservation;
    try {
      reservation = await reserveVaultWrite(userId, {
        bytes: predicted,
        items: insertDocs.length,
      });
    } catch (err: unknown) {
      if (err instanceof VaultRowLimitError) {
        throw httpErrors.badRequest(importCapExceededMessage(err.stored, insertDocs.length));
      }
      throw err;
    }
    /**
     * The counted bytes, and the number, of the import rows that are stored after
     * an ordered insert failed part-way (standalone keeps the rows ahead of the
     * failure): measured by the database, by the ids every insert was given
     * before it was sent.
     *
     * Only the rows AHEAD of the first refused one are this request's: an ordered
     * insert stops there, and the refused id may belong to a row another request
     * created meanwhile (a duplicate derived id), which that request has counted.
     * A failure that names no row (a dropped connection) may have stored any
     * prefix, so every id is measured.
     */
    async function landedInserts(
      insertDocs: Record<string, unknown>[],
      userId: string,
      failure: unknown,
    ): Promise<{ bytes: number; rows: number }> {
      const writeErrors = (failure as { writeErrors?: unknown } | null)?.writeErrors;
      const refusedAt = Array.isArray(writeErrors)
        ? Math.min(
            ...writeErrors
              .map((writeError: unknown) => (writeError as { index?: unknown }).index)
              .filter((index): index is number => Number.isInteger(index)),
          )
        : insertDocs.length;
      const ids = insertDocs
        .slice(0, refusedAt)
        .map((doc) => new mongoose.Types.ObjectId(String(doc._id)));
      const rows = await VaultItem.collection
        .find(
          { _id: { $in: ids }, userId: new mongoose.Types.ObjectId(userId) },
          { projection: { counted: countedBytesExpression('item') }, readPreference: 'primary' },
        )
        .toArray();
      return {
        bytes: rows.reduce((sum, row) => sum + Number(row.counted), 0),
        rows: rows.length,
      };
    }

    /** The counted bytes this request's writes actually added; reset per attempt. */
    let landed = 0;
    /** The item rows this request's inserts actually added; reset per attempt. */
    let landedRows = 0;

    const execute = async (session?: mongoose.ClientSession): Promise<void> => {
      const sessionOpt = session ? { session } : {};
      const updateOptions = session ? { runValidators: true, session } : { runValidators: true };

      // The vault-key generation, checked HERE rather than at the top of the
      // handler. Between the two lie the field-length checks, the folder
      // lookups, the update-target lookups, `acquireJobLock` and the reservation
      // — hundreds of milliseconds in which a rotation can commit and leave
      // every row below sealed under a key the account has already replaced.
      // Inside the callback rather than merely inside the lock because
      // `withTransaction` may RE-RUN this after a transient error, and a guard
      // outside would not be re-evaluated on that second attempt.
      //
      // It THROWS rather than answering the 409 here, and that is the whole
      // reason `resolveVaultKeyVersion` is not used: answering and returning
      // normally from inside this callback would let the transaction COMMIT.
      // The refusal is rendered outside, where the transaction has unwound.
      await assertVaultKeyVersion(userId, vaultKeyVersion);

      // Reset per attempt: `withTransaction` may re-run this callback after a
      // transient error, and the aborted attempt's rows no longer exist.
      insertedCount = 0;
      updatedCount = 0;
      insertedIds = [];
      landed = 0;
      landedRows = 0;

      // The rows each update is pinned on: measured inside the transaction where
      // there is one (its snapshot is what the writes below see), else the
      // measure taken under the locks above.
      const measures = session && updates.length > 0 ? await measureTargets(session) : preMeasured;

      if (insertDocs.length > 0) {
        let created;
        try {
          created = await VaultItem.insertMany(insertDocs, sessionOpt);
        } catch (err: unknown) {
          // Standalone, an ordered insert keeps the rows ahead of the one that
          // failed: those landed, and are counted from the database.
          if (!session) {
            try {
              const partial = await landedInserts(insertDocs, userId, err);
              landed += partial.bytes;
              landedRows += partial.rows;
            } catch (measureErr: unknown) {
              // What landed cannot be read either: count every insert as landed (an
              // overcount the recount corrects) and report the insert's own error.
              logger.warn('Import could not measure the rows a failed insert left', {
                userId,
                error: errorMessage(measureErr),
              });
              landed += insertBytes;
              landedRows += insertDocs.length;
            }
          }
          if (isDuplicateIdError(err)) throw httpErrors.conflict(ROW_ID_TAKEN_MESSAGE);
          throw err;
        }
        for (const doc of created) landed += countedBytes('item', storedImage(doc));
        landedRows += created.length;
        insertedCount = created.length;
        // In insertion order, which `insertMany` preserves: the client checks each
        // against the id it sealed that row to.
        insertedIds = created.map((doc) => String(doc._id));
      }

      for (const [index, update] of updates.entries()) {
        // `runValidators: true` is load-bearing, not decoration: without it the
        // model's `passwordHistory` count and per-entry length validators never
        // fire on an update. Projected through the NARROW allowlist so an update
        // cannot reach `tags` / `favorite` / `folderId` / `itemType`. Pinned on the
        // row the quota measured (`__v` and `createdAt`), so its change is exact.
        const set = updateSets[index] ?? {};
        const measure = measures.get(update.id);
        let result: { matchedCount: number };
        try {
          result = measure
            ? await VaultItem.updateOne(
                { _id: update.id, userId, deletedAt: { $exists: false }, ...versionPin(measure) },
                { $set: set, $inc: { __v: 1 } },
                updateOptions,
              )
            : { matchedCount: 0 };
        } catch (err: unknown) {
          // Standalone, an update whose outcome is unknown (a dropped connection)
          // may have applied: what it could have added stays counted, an overcount
          // the recount corrects rather than an undercount the account could repeat.
          if (!session && measure && !isDefiniteWriteFailure(err)) {
            landed += Math.max(0, deltaOfPinnedUpdate('item', measure, { $set: set }));
          }
          throw err;
        }
        if (result.matchedCount === 0 || !measure) {
          throw httpErrors.conflict(
            'Import failed: an item it targeted was modified or removed mid-request. Please retry.',
          );
        }
        landed += deltaOfPinnedUpdate('item', measure, { $set: set });
        updatedCount++;
      }
    };

    // The `else` covers the topology that never had transactions at all — a
    // standalone deployment, and the default test harness. It is a real path,
    // not an optimistic one, and it still fails closed on the cap: the
    // reservation above decided it before either branch writes a row.
    //
    // What it deliberately does NOT cover: `supportsTransactions` only inspects
    // the URI's `replicaSet` option (`utils/transactionSupport.ts`), so a single
    // node ADVERTISING a replica set returns true here, takes the branch below,
    // and throws at `withTransaction` — a 500 that writes nothing. Catching that
    // to retry non-transactionally would be unsafe, because `execute` also
    // throws the generation 409 and the mid-request 409 from inside the callback, and
    // re-running after either would double-insert. `config/database.ts`'s
    // `verifyTopology` warns about the mismatch at boot instead.
    const transactional = supportsTransactions(mongoose.connection);
    try {
      if (transactional) {
        // Opened INSIDE the try: a session that cannot be started wrote nothing,
        // and the reservation is handed back below like any other refusal.
        const session = await mongoose.startSession();
        try {
          await session.withTransaction(async () => {
            await execute(session);
          });
        } finally {
          await session.endSession();
        }
      } else {
        await execute();
      }
    } catch (err: unknown) {
      // Settled by POSITION. A transaction that threw wrote nothing, unless its
      // commit's outcome is unknown, in which case the reservation is kept (an
      // overcount the recount corrects, never an undercount). Standalone, what
      // landed before the failure is counted and the rest handed back.
      const commitUnknown =
        err instanceof mongoose.mongo.MongoError &&
        err.hasErrorLabel('UnknownTransactionCommitResult');
      if (transactional) {
        if (!commitUnknown) await releaseVaultWrite(reservation);
      } else {
        await settleVaultWrite(reservation, landed, { items: landedRows });
      }
      throw err;
    }
    await settleVaultWrite(reservation, landed, { items: landedRows });
  } finally {
    // Reverse acquisition order, and the exclusion lock first because it is the
    // one whose loss blocks four other operations rather than one.
    if (rotationLockId !== null) {
      await releaseVaultRotationLock(userId, rotationLockId);
    }
    await releaseJobLock(lockName, lockId);
  }

  // Both locks are released BEFORE the response is written, deliberately. The
  // client sends its batches sequentially and fires batch n+1 the moment
  // batch n's response lands; responding while the release round-trip is still
  // in flight would 409 a legitimate multi-batch migration against its own lock.
  const importCtx = getRequestContext(req);
  await createAuditLog(
    userId,
    'import',
    { format, conflictStrategy, insertedCount, updatedCount },
    importCtx.ip,
    importCtx.userAgent,
  );

  logger.info('Vault imported', { userId, format, conflictStrategy, insertedCount, updatedCount });

  res.status(201).json({
    success: true,
    data: { insertedCount, updatedCount, insertedIds },
    message: `${String(insertedCount)} items imported, ${String(updatedCount)} items updated`,
  });
}

export const importVault = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { format, conflictStrategy, operations, vaultKeyVersion } = req.body as ImportInput;

  // Every imported row carries ciphertext encrypted with the caller's current
  // vault key — a rotation in flight would strand all of it. Fence before any
  // validation or writing, so the rejection is cheap.
  await assertVaultNotRotating(userId);

  try {
    await executeImportOperations(req, res, {
      userId,
      format,
      conflictStrategy,
      operations,
      vaultKeyVersion,
    });
  } catch (error) {
    // The stale-generation refusal, rendered HERE rather than where it is
    // raised. It is raised deep inside the transaction callback so that it
    // aborts the transaction; by the time it reaches this frame the transaction
    // has unwound, nothing has been written, and the per-user lock has already
    // been released by `executeImportOperations`'s own `finally` — which keeps
    // the release AHEAD of the response, the ordering that function's comment
    // calls deliberate. Uncaught it would still refuse with a 409; catching it
    // is what attaches the NUMBER the client re-seals under.
    if (error instanceof StaleVaultKeyError) {
      sendStaleVaultKey(res, error);
      return;
    }
    throw error;
  }
});
