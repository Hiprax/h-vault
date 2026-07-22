import type { Request, Response } from 'express';
import { catchAsync, httpErrors } from '@hiprax/errors';
import { createLogger } from '@hiprax/logger';
import axios from 'axios';
import bcrypt from 'bcryptjs';
import mongoose from 'mongoose';
import { VaultItem } from '../models/VaultItem.js';
import { Folder } from '../models/Folder.js';
import { User } from '../models/User.js';
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
import {
  APP_VERSION,
  MAX_ENCRYPTED_DATA_LENGTH,
  MAX_ENCRYPTED_NAME_LENGTH,
  MAX_ITEMS_PER_USER,
} from '@hvault/shared';
import type { CheckBreachInput, ImportInput, ExportInput } from '@hvault/shared';

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
}

const HIBP_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

/**
 * Hard ceiling on the number of cached HIBP responses. With ~25 KB per
 * entry, a 10,000-entry cap bounds steady-state memory at ~250 MB worst
 * case — well below the 512 MB Docker limit and far short of the
 * theoretical 16^5 (~1 M) unique 5-char prefixes that could otherwise
 * accumulate.
 */
export const HIBP_CACHE_MAX_ENTRIES = 10_000;

export const hibpCache = new Map<string, HibpCacheEntry>();

// Periodic cache pruning — every 100 accesses, evict expired entries.
let cacheAccessCount = 0;
export function resetCacheAccessCount(): void {
  cacheAccessCount = 0;
}
export function pruneHibpCache(): void {
  if (++cacheAccessCount % 100 !== 0) return;
  const now = Date.now();
  for (const [key, value] of hibpCache) {
    if (value.expires < now) hibpCache.delete(key);
  }
}

/**
 * Inserts a HIBP response into the cache, enforcing the hard
 * {@link HIBP_CACHE_MAX_ENTRIES} cap. Evicts an expired entry first when
 * available; otherwise drops the oldest insertion-ordered entry (LRU).
 */
export function setHibpCacheEntry(key: string, entry: HibpCacheEntry): void {
  if (hibpCache.has(key)) {
    hibpCache.set(key, entry);
    return;
  }

  if (hibpCache.size >= HIBP_CACHE_MAX_ENTRIES) {
    // Prefer evicting an already-expired entry to free a real slot.
    const now = Date.now();
    let evicted = false;
    for (const [existingKey, existingEntry] of hibpCache) {
      if (existingEntry.expires < now) {
        hibpCache.delete(existingKey);
        evicted = true;
        break;
      }
    }
    // No expired entry to harvest — fall back to oldest-insertion eviction.
    if (!evicted) {
      const oldestKey = hibpCache.keys().next().value;
      if (oldestKey !== undefined) {
        hibpCache.delete(oldestKey);
      }
    }
  }

  hibpCache.set(key, entry);
}

// ── Helpers ──────────────────────────────────────────────────────────

const HEX_PREFIX_RE = /^[0-9a-fA-F]{5}$/;

const ALLOWED_ITEM_FIELDS = new Set([
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
 */
const ALLOWED_UPDATE_FIELDS = new Set([
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
 * ceilings, so this is the defense-in-depth layer that keeps an import
 * all-or-nothing if those bounds are ever loosened: an over-length field
 * otherwise trips a Mongoose validator only mid-write, leaving earlier rows
 * persisted and the success-only `import` audit log skipped — a partial,
 * unaudited import. Validating up front (before any DB write) keeps it atomic.
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

    // Check in-memory cache first
    const cached = hibpCache.get(hashPrefix);
    if (cached && cached.expires > Date.now()) {
      res.status(200).json({
        success: true,
        data: cached.data,
      });
      return;
    }

    const response = await axios.get<string>(`https://api.pwnedpasswords.com/range/${hashPrefix}`, {
      headers: {
        'User-Agent': 'H-Vault-Password-Manager',
      },
      timeout: 10_000,
      responseType: 'text',
      maxRedirects: 0,
    });

    // Cache the response (bounded LRU with TTL — see setHibpCacheEntry)
    setHibpCacheEntry(hashPrefix, {
      data: response.data,
      expires: Date.now() + HIBP_CACHE_TTL_MS,
    });

    res.status(200).json({
      success: true,
      data: response.data,
    });
  },
);

export const exportVault = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { authHash } = req.body as ExportInput;

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

  const exportCtx = getRequestContext(req);
  await createAuditLog(
    userId,
    'export',
    { itemCount: items.length, folderCount: folders.length },
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

    // `supportsTransactions` inspects the URI's `replicaSet` option, so a single
    // node advertising one passes the check and then throws at `withTransaction`
    // — hence a real, working non-transactional fallback rather than an
    // optimistic single path. The fallback still fails closed on the cap: the
    // lock serializes imports and the re-check runs there too.
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
