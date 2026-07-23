import type { Request, Response } from 'express';
import { catchAsync, httpErrors } from '@hiprax/errors';
import { createLogger } from '@hiprax/logger';
import bcrypt from 'bcryptjs';
import mongoose from 'mongoose';
import { VaultItem } from '../models/VaultItem.js';
import { Folder } from '../models/Folder.js';
import { User } from '../models/User.js';
import { PwnedRangeCache } from '../models/PwnedRangeCache.js';
import { createAuditLog } from '../services/auditService.js';
import { config } from '../config/index.js';
import {
  assertVaultNotRotating,
  getRequestContext,
  getUserId,
  pickAllowedFields,
  vaultImportLockName,
} from '../utils/controllerHelpers.js';
import { acquireJobLock, releaseJobLock } from '../utils/jobLock.js';
import { supportsTransactions } from '../utils/transactionSupport.js';
import { estimateItemJsonSize, estimateFolderJsonSize } from '../utils/sizeEstimator.js';
import { fetchRangeFromHibp } from '../utils/hibp.js';
import {
  APP_VERSION,
  MAX_ENCRYPTED_DATA_LENGTH,
  MAX_ENCRYPTED_NAME_LENGTH,
  MAX_ITEMS_PER_USER,
} from '@hvault/shared';
import type {
  CheckBreachInput,
  CheckBreachBatchInput,
  ImportInput,
  ExportInput,
} from '@hvault/shared';

const logger = createLogger({ moduleName: 'tools-controller' });

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
export const HIBP_FANOUT_CONCURRENCY = 8;

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
}
export function pruneHibpCache(): void {
  if (++cacheAccessCount % 100 !== 0) return;
  const now = Date.now();
  for (const [key, value] of hibpCache) {
    if (value.expires < now) {
      hibpCache.delete(key);
      hibpCacheBytes -= value.bytes ?? 0;
    }
  }
  if (hibpCacheBytes < 0) hibpCacheBytes = 0;
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
    for (const [existingKey, existingEntry] of hibpCache) {
      if (existingEntry.expires < now) {
        victimKey = existingKey;
        break;
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
  // this module: an empty Map holds zero bytes.
  if (hibpCache.size === 0) hibpCacheBytes = 0;

  const bytes = Buffer.byteLength(entry.data, 'utf8');
  const stored: HibpCacheEntry = { data: entry.data, expires: entry.expires, bytes };

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
// through to HIBP, and an HIBP failure with no cache surfaces as 500 (single) /
// errors[] (batch) — never a false "not breached".

/** Per-process coalescing of concurrent duplicate L3 fetches (thundering-herd guard). */
export const rangeInFlight = new Map<string, Promise<string>>();

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
 * Resolve the (padding-stripped) HIBP range for a prefix through the cache
 * layers. Throws ONLY when L3 fails and there is no L2 fallback at all.
 */
export async function getRange(rawPrefix: string): Promise<string> {
  const prefix = rawPrefix.toUpperCase(); // canonical key (matches HIBP + the DB)
  const now = Date.now();

  const l1 = hibpCache.get(prefix);
  if (l1 && l1.expires > now) return l1.data;

  const pending = rangeInFlight.get(prefix);
  if (pending) return pending;

  const task = (async (): Promise<string> => {
    const doc = await PwnedRangeCache.findOne({ prefix }).lean();
    if (doc && isRangeFresh(doc, now)) {
      setHibpCacheEntry(prefix, { data: doc.range, expires: now + HIBP_CACHE_TTL_MS });
      return doc.range;
    }
    try {
      const range = await fetchRangeFromHibp(prefix);
      // `runValidators` is deliberately OMITTED here (unlike most update sites in
      // this codebase). Mongoose's `required` check on a String rejects '', and an
      // EMPTY range is a legitimate value: a prefix whose every row was count-0
      // padding has no real breached suffixes. Adding the flag would make those
      // prefixes fail to cache and re-hit HIBP forever.
      await PwnedRangeCache.updateOne(
        { prefix },
        { $set: { range, source: 'hibp', fetchedAt: new Date() } },
        { upsert: true },
      );
      setHibpCacheEntry(prefix, { data: range, expires: Date.now() + HIBP_CACHE_TTL_MS });
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
  })();

  rangeInFlight.set(prefix, task);
  try {
    return await task;
  } finally {
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
  'searchHash',
  'passwordHistory',
]);

/**
 * Fields an import UPDATE is allowed to write. Deliberately NARROWER than
 * {@link ALLOWED_ITEM_FIELDS}: the six ciphertext fields, the client-recomputed
 * `searchHash` (an overwrite replaces `encryptedName`, so the stored hash must
 * be refreshed alongside it or it strands against the old name), and the
 * optional `passwordHistory` — and nothing else.
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
  'searchHash',
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

/** Single source of the per-user cap rejection message (both cap checks). */
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

    // Layered lookup: L1 in-memory → L2 pwned_range_cache → L3 HIBP.
    const data = await getRange(hashPrefix);

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

    // Every unique prefix routes through the layered cache (L1 in-memory →
    // L2 pwned_range_cache → L3 HIBP). L1/L2-warm prefixes resolve without any
    // outbound call, so fanning out over ALL prefixes (not just misses) is cheap
    // and preserves the exact response contract.
    await runWithConcurrency(uniquePrefixes, HIBP_FANOUT_CONCURRENCY, async (prefix) => {
      try {
        data[prefix] = await getRange(prefix);
      } catch (err) {
        // Report the prefix as unchecked — never omit it silently (the client
        // would read a missing prefix as "no breach").
        errors.push(prefix);
        logger.warn('HIBP batch lookup failed', {
          error: err instanceof Error ? err.message : 'unknown',
        });
      }
    });

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
    throw httpErrors.unauthorized('Current password is incorrect');
  }

  const maxSizeBytes = config.EXPORT_MAX_SIZE_MB * 1024 * 1024;
  const items: unknown[] = [];
  let estimatedSize = RESPONSE_WRAPPER_OVERHEAD;

  // Use cursor-based streaming to check size incrementally and avoid loading
  // the entire result set into memory before discovering it's too large.
  // We estimate each item's JSON size from its field lengths instead of calling
  // JSON.stringify per item — this eliminates N wasted serializations in the
  // hot loop for large vaults. See `estimateItemJsonSize` for the conservative
  // overhead rationale.
  const itemCursor = VaultItem.find({ userId, deletedAt: { $exists: false } })
    .select('-sourceRefId')
    .lean()
    .cursor();
  for await (const item of itemCursor) {
    estimatedSize += estimateItemJsonSize(item as unknown as Record<string, unknown>);
    if (estimatedSize > maxSizeBytes) {
      throw httpErrors.payloadTooLarge(
        `Export size exceeds the maximum allowed size (${String(config.EXPORT_MAX_SIZE_MB)} MB)`,
      );
    }
    items.push(item);
  }

  const folders = await Folder.find({ userId }).select('-sourceRefId').lean();
  for (const folder of folders) {
    estimatedSize += estimateFolderJsonSize(folder as unknown as Record<string, unknown>);
  }
  if (estimatedSize > maxSizeBytes) {
    throw httpErrors.payloadTooLarge(
      `Export size exceeds the maximum allowed size (${String(config.EXPORT_MAX_SIZE_MB)} MB)`,
    );
  }

  const responsePayload = {
    items,
    folders,
    metadata: {
      exportDate: new Date().toISOString(),
      version: APP_VERSION,
      itemCount: items.length,
    },
  };

  // Single JSON serialization used for both the precise final size check AND
  // the response body. Previously this payload was stringified twice (once
  // here for size validation, once inside res.json()); now we do it once and
  // pass the pre-serialized string to res.send() to avoid the double work.
  const exportJson = JSON.stringify({ success: true, data: responsePayload });
  const exportSizeBytes = Buffer.byteLength(exportJson, 'utf-8');
  if (exportSizeBytes > maxSizeBytes) {
    throw httpErrors.payloadTooLarge(
      `Export size (${String(Math.ceil(exportSizeBytes / (1024 * 1024)))} MB) exceeds the maximum allowed size (${String(config.EXPORT_MAX_SIZE_MB)} MB)`,
    );
  }

  // `portableFormat` is AUDIT METADATA ONLY (validated by exportSchema): its
  // sole effect is to record a distinct `export_plaintext` action for a
  // browser-side plaintext export. The response body above is already fully
  // built and is byte-identical whether or not it is present — nothing below
  // branches on the value beyond the audit action and its metadata.
  const exportCtx = getRequestContext(req);
  await createAuditLog(
    userId,
    portableFormat ? 'export_plaintext' : 'export',
    {
      itemCount: items.length,
      folderCount: folders.length,
      ...(portableFormat ? { portableFormat } : {}),
    },
    exportCtx.ip,
    exportCtx.userAgent,
  );

  logger.info('Vault exported', { userId, itemCount: items.length });

  // Match the backup download pattern so browsers trigger a download rather
  // than rendering the JSON inline.
  const exportTimestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const exportFilename = `hvault-export-${exportTimestamp}.enc`;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="${exportFilename}"`);
  res.setHeader('Content-Length', String(exportSizeBytes));

  res.status(200).send(exportJson);
});

interface ImportOperationsParams {
  userId: string;
  format: ImportInput['format'];
  conflictStrategy: ImportInput['conflictStrategy'];
  operations: ImportInput['operations'];
}

/**
 * Executes a structured `operations` import.
 *
 * The server is a validated EXECUTOR here, never a matcher. Conflict resolution
 * happens on the CLIENT — the match key for a login is its site and username,
 * both of which live inside the encrypted blob, so the server physically cannot
 * compute it. This path therefore performs NO `searchHash` / `encryptedName`
 * matching and does not act on `conflictStrategy` (retained as audit metadata
 * only): it validates ownership, caps and field lengths, then applies exactly
 * the `inserts` and `updates` it was handed.
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
  { userId, format, conflictStrategy, operations }: ImportOperationsParams,
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
  // is inert even if the schema's `.strip()` is ever relaxed.
  const insertDocs = inserts.map((item) => {
    const doc = pickAllowedFields(item, ALLOWED_ITEM_FIELDS);
    if (typeof doc.folderId === 'string' && !ownedFolderIds.has(doc.folderId)) {
      delete doc.folderId;
    }
    return { ...doc, userId };
  });

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

  // 4+5 ── Serialize the cap check and the writes per user.
  //
  // Two mechanisms, both required. A transaction alone does not bound
  // concurrency on every topology — a standalone deployment rejects
  // multi-document transactions outright — so the JobLock is what actually
  // makes the cap unbreachable: `acquireJobLock` is an atomic upsert against the
  // unique `jobName` index and holds with or without transactions. The client
  // sends its batches sequentially, so it never self-contends.
  const lockName = vaultImportLockName(userId);
  const lockId = await acquireJobLock(lockName, IMPORT_LOCK_TTL_MS);
  if (lockId === null) {
    throw httpErrors.conflict('An import is already in progress. Please wait and retry.');
  }

  let insertedCount = 0;
  let updatedCount = 0;

  try {
    // Cap measured against NET-NEW inserts only (updates rewrite rows that
    // already exist), before any write, so a rejected import leaves nothing.
    const existingItemCount = await VaultItem.countDocuments({ userId });
    if (existingItemCount + insertDocs.length > MAX_ITEMS_PER_USER) {
      throw httpErrors.badRequest(importCapExceededMessage(existingItemCount, insertDocs.length));
    }

    const execute = async (session?: mongoose.ClientSession): Promise<void> => {
      const sessionOpt = session ? { session } : {};
      const updateOptions = session ? { runValidators: true, session } : { runValidators: true };

      // Re-measure against the state the writes will observe. The lock already
      // excludes a second import; this NARROWS — it does not close — the window
      // against rows created by other endpoints (`POST /items`,
      // `POST /backup/restore`) between the pre-check and the insert. A row those
      // commit after this transaction's read snapshot is invisible here and does
      // not write-conflict with our inserts, so the cap can still be overshot by
      // such a row. That hairline is pre-existing and shared with
      // `vaultController.createItem`'s own count-then-write check.
      const liveItemCount = await VaultItem.countDocuments({ userId }, sessionOpt);
      if (liveItemCount + insertDocs.length > MAX_ITEMS_PER_USER) {
        throw httpErrors.badRequest(importCapExceededMessage(liveItemCount, insertDocs.length));
      }

      // Reset per attempt: `withTransaction` may re-run this callback after a
      // transient error, and the aborted attempt's rows no longer exist.
      insertedCount = 0;
      updatedCount = 0;

      if (insertDocs.length > 0) {
        const created = await VaultItem.insertMany(insertDocs, sessionOpt);
        insertedCount = created.length;
      }

      for (const update of updates) {
        // `runValidators: true` is load-bearing, not decoration: without it the
        // model's `passwordHistory` count and per-entry length validators never
        // fire on an update. Projected through the NARROW allowlist so an update
        // cannot reach `tags` / `favorite` / `folderId` / `itemType`.
        const result = await VaultItem.updateOne(
          { _id: update.id, userId, deletedAt: { $exists: false } },
          { $set: pickAllowedFields(update, ALLOWED_UPDATE_FIELDS) },
          updateOptions,
        );
        if (result.matchedCount === 0) {
          throw httpErrors.conflict(
            'Import failed: an item it targeted was modified or removed mid-request. Please retry.',
          );
        }
        updatedCount++;
      }
    };

    // The `else` covers the topology that never had transactions at all — a
    // standalone deployment, and the default test harness. It is a real path,
    // not an optimistic one, and it still fails closed on the cap: the lock
    // serializes imports and the re-check runs there too.
    //
    // What it deliberately does NOT cover: `supportsTransactions` only inspects
    // the URI's `replicaSet` option (`utils/transactionSupport.ts`), so a single
    // node ADVERTISING a replica set returns true here, takes the branch below,
    // and throws at `withTransaction` — a 500 that writes nothing. Catching that
    // to retry non-transactionally would be unsafe, because `execute` also
    // throws the cap 400 and the mid-request 409 from inside the callback, and
    // re-running after either would double-insert. `config/database.ts`'s
    // `verifyTopology` warns about the mismatch at boot instead.
    const session = supportsTransactions(mongoose.connection)
      ? await mongoose.startSession()
      : null;
    if (session) {
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
  } finally {
    await releaseJobLock(lockName, lockId);
  }

  // The lock is released BEFORE the response is written, deliberately. The
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
    data: { insertedCount, updatedCount },
    message: `${String(insertedCount)} items imported, ${String(updatedCount)} items updated`,
  });
}

export const importVault = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { format, conflictStrategy, operations } = req.body as ImportInput;

  // Every imported row carries ciphertext encrypted with the caller's current
  // vault key — a rotation in flight would strand all of it. Fence before any
  // validation or writing, so the rejection is cheap.
  await assertVaultNotRotating(userId);

  await executeImportOperations(req, res, { userId, format, conflictStrategy, operations });
});
