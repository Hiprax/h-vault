import type { Request, Response } from 'express';
import { catchAsync, httpErrors } from '@hiprax/errors';
import { createLogger } from '@hiprax/logger';
import axios from 'axios';
import bcrypt from 'bcryptjs';
import type { Types } from 'mongoose';
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
} from '../utils/controllerHelpers.js';
import { estimateItemJsonSize, estimateFolderJsonSize } from '../utils/sizeEstimator.js';
import {
  APP_VERSION,
  ITEM_TYPES,
  MAX_ENCRYPTED_DATA_LENGTH,
  MAX_ENCRYPTED_NAME_LENGTH,
  MAX_IMPORT_ITEMS,
  MAX_ITEMS_PER_USER,
  MAX_TAG_LENGTH,
  MAX_TAGS_PER_ITEM,
} from '@hvault/shared';
import type { CheckBreachInput, ImportInput, ExportInput, ItemType } from '@hvault/shared';

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

// CSV import maps user-supplied column headers onto target field names via the
// request's `csvMapping`. Only these six encrypted fields are ever read back
// when the item is built, so writes are restricted to them: a mapping that
// points at any other key — including prototype-pollution vectors such as
// `__proto__`, `constructor` or `prototype` — is ignored instead of being
// written into the row. Defense-in-depth behind Zod, and it removes a
// remote-property-injection sink outright.
const CSV_ALLOWED_TARGET_FIELDS = new Set<string>([
  'encryptedData',
  'dataIv',
  'dataTag',
  'encryptedName',
  'nameIv',
  'nameTag',
]);

/**
 * Parses CSV text into an array of rows (each row is an array of field strings).
 * Handles quoted fields and escaped double-quotes per RFC 4180.
 */
function parseCSVData(text: string): string[][] {
  const lines = text.split(/\r?\n/).filter((l) => l.trim());
  return lines.map((line) => {
    const fields: string[] = [];
    let current = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i] ?? '';
      if (ch === '"') {
        if (inQuotes && line[i + 1] === '"') {
          current += '"';
          i++;
        } else {
          inQuotes = !inQuotes;
        }
      } else if (ch === ',' && !inQuotes) {
        fields.push(current.trim());
        current = '';
      } else {
        current += ch;
      }
    }
    fields.push(current.trim());
    return fields;
  });
}

// ── Handlers ─────────────────────────────────────────────────────────

const HEX_PREFIX_RE = /^[0-9a-fA-F]{5}$/;
const SEARCH_HASH_RE = /^[a-f0-9]{64}$/;
const OBJECT_ID_RE = /^[0-9a-fA-F]{24}$/;

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

// ── Export size estimation ──────────────────────────────────────────
// Per-row size estimation lives in `utils/sizeEstimator.ts` so the export and
// backup paths share the same conservative overhead constants. The
// response-wrapper overhead is local because it covers the export envelope
// specifically (backup payloads have a different envelope structure).

// Response envelope overhead: covers `{"success":true,"data":{"items":[],"folders":[],"metadata":{...}}}`
// plus the metadata block (exportDate ISO timestamp, version string, itemCount).
const RESPONSE_WRAPPER_OVERHEAD = 1024;

/**
 * Sanitizes an import item's searchHash, tags, and folderId to match the same
 * validation rules enforced by create/update schemas.
 */
function sanitizeImportFields(item: Record<string, unknown>): {
  tags: string[];
  searchHash: string | undefined;
  folderId: string | undefined;
} {
  // searchHash: must be 64-char lowercase hex string
  let searchHash: string | undefined;
  if (typeof item.searchHash === 'string' && SEARCH_HASH_RE.test(item.searchHash)) {
    searchHash = item.searchHash;
  }

  // folderId: must be valid 24-char hex ObjectId
  let folderId: string | undefined;
  if (typeof item.folderId === 'string' && OBJECT_ID_RE.test(item.folderId)) {
    folderId = item.folderId;
  }

  // tags: array of trimmed, non-empty strings, max length 50, max 20 items
  let tags: string[] = [];
  if (Array.isArray(item.tags)) {
    tags = (item.tags as unknown[])
      .filter((t): t is string => typeof t === 'string')
      .map((t) => t.trim())
      .filter((t) => t.length >= 1 && t.length <= MAX_TAG_LENGTH)
      .slice(0, MAX_TAGS_PER_ITEM);
  }

  return { tags, searchHash, folderId };
}

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
 * Rejects the whole import with a clear 400 if any item has an over-length
 * encrypted field. The shared `importSchema` only bounds the entire `data`
 * blob (1 MB), and the controller's non-empty filter ignores length — so
 * without this check an over-length field trips a Mongoose validator only
 * mid-write. In the `overwrite` conflict loop that means earlier items are
 * already persisted before the throw, and the success-only `import` audit log
 * is skipped, leaving a partial, unaudited import. Validating up front (before
 * any DB write) keeps import atomic: all-or-nothing.
 */
function assertImportFieldLengths(items: Record<string, unknown>[]): void {
  for (const item of items) {
    for (const { field, max } of IMPORT_FIELD_MAXLENGTHS) {
      const value = item[field];
      if (typeof value === 'string' && value.length > max) {
        throw httpErrors.badRequest(
          `Import rejected: item field "${field}" exceeds the maximum length of ${String(max)} characters.`,
        );
      }
    }
  }
}

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

export const importVault = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { format, data, csvMapping, conflictStrategy } = req.body as ImportInput;

  // Every imported row carries ciphertext encrypted with the caller's current
  // vault key — a rotation in flight would strand all of it. Fence before any
  // parsing so the rejection is cheap.
  await assertVaultNotRotating(userId);

  let itemsToCreate: Record<string, unknown>[] = [];

  if (format === 'json') {
    let parsed: unknown;
    try {
      parsed = JSON.parse(data);
    } catch {
      throw httpErrors.badRequest('Invalid JSON data');
    }

    if (
      typeof parsed !== 'object' ||
      parsed === null ||
      !('items' in parsed) ||
      !Array.isArray(parsed.items)
    ) {
      throw httpErrors.badRequest('Invalid import format: expected { items: [...] }');
    }

    const importData = parsed as { items: Record<string, unknown>[] };

    itemsToCreate = importData.items
      .filter((item) => {
        const type = (item.itemType as string | undefined) ?? 'login';
        return (ITEM_TYPES as readonly string[]).includes(type);
      })
      .map((item) => {
        const sanitized = sanitizeImportFields(item);
        return {
          userId,
          itemType: ((item.itemType as string | undefined) ?? 'login') as ItemType,
          encryptedData: (item.encryptedData as string | undefined) ?? '',
          dataIv: (item.dataIv as string | undefined) ?? '',
          dataTag: (item.dataTag as string | undefined) ?? '',
          encryptedName: (item.encryptedName as string | undefined) ?? '',
          nameIv: (item.nameIv as string | undefined) ?? '',
          nameTag: (item.nameTag as string | undefined) ?? '',
          tags: sanitized.tags,
          favorite: item.favorite === true,
          folderId: sanitized.folderId,
          searchHash: sanitized.searchHash,
        };
      });
  } else if (format === 'csv' && csvMapping && Object.keys(csvMapping).length > 0) {
    // Parse raw CSV data using the column-to-field mapping provided by the client
    const rows = parseCSVData(data);
    if (rows.length < 2) {
      throw httpErrors.badRequest('CSV data must have a header row and at least one data row');
    }

    const headers = rows[0] ?? [];
    const dataRows = rows.slice(1);

    itemsToCreate = dataRows.map((row) => {
      const mapped: Record<string, string> = {};
      headers.forEach((header, index) => {
        const fieldName = csvMapping[header];
        const cellValue = row[index];
        if (fieldName && CSV_ALLOWED_TARGET_FIELDS.has(fieldName) && cellValue !== undefined) {
          mapped[fieldName] = cellValue;
        }
      });

      return {
        userId,
        itemType: 'login' as const,
        // CSV imports store plaintext data as-is; actual encryption must happen on the client
        // before calling this endpoint. Here we pass through the mapped fields for items
        // that are already encrypted by the client.
        encryptedData: mapped.encryptedData ?? '',
        dataIv: mapped.dataIv ?? '',
        dataTag: mapped.dataTag ?? '',
        encryptedName: mapped.encryptedName ?? '',
        nameIv: mapped.nameIv ?? '',
        nameTag: mapped.nameTag ?? '',
        tags: [] as string[],
        favorite: false,
      };
    });
  } else {
    // For other formats (bitwarden, lastpass, keepass, csv without mapping),
    // attempt basic parsing. The data is expected to be already
    // re-encrypted by the client, so we just parse the structure.
    let parsed: unknown;
    try {
      parsed = JSON.parse(data);
    } catch {
      throw httpErrors.badRequest(
        `Unable to parse ${format} import data. Please ensure the data is in the correct format.`,
      );
    }

    if (
      typeof parsed !== 'object' ||
      parsed === null ||
      !('items' in parsed) ||
      !Array.isArray(parsed.items)
    ) {
      throw httpErrors.badRequest('Invalid import format: expected { items: [...] }');
    }

    const importData = parsed as { items: Record<string, unknown>[] };

    itemsToCreate = importData.items
      .filter((item) => {
        const type = (item.itemType as string | undefined) ?? 'login';
        return (ITEM_TYPES as readonly string[]).includes(type);
      })
      .map((item) => {
        const sanitized = sanitizeImportFields(item);
        return {
          userId,
          itemType: ((item.itemType as string | undefined) ?? 'login') as ItemType,
          encryptedData: (item.encryptedData as string | undefined) ?? '',
          dataIv: (item.dataIv as string | undefined) ?? '',
          dataTag: (item.dataTag as string | undefined) ?? '',
          encryptedName: (item.encryptedName as string | undefined) ?? '',
          nameIv: (item.nameIv as string | undefined) ?? '',
          nameTag: (item.nameTag as string | undefined) ?? '',
          tags: sanitized.tags,
          favorite: item.favorite === true,
          folderId: sanitized.folderId,
          searchHash: sanitized.searchHash,
        };
      });
  }

  if (itemsToCreate.length > MAX_IMPORT_ITEMS) {
    throw httpErrors.badRequest(
      `Import exceeds the maximum allowed item count (${String(MAX_IMPORT_ITEMS)}). Received ${String(itemsToCreate.length)} items.`,
    );
  }

  // Validate folderId ownership: strip any folderId values that don't belong to the user
  const userFolderIds = new Set(
    (await Folder.find({ userId }).select('_id').lean()).map((f) => String(f._id)),
  );
  for (const item of itemsToCreate) {
    if (typeof item.folderId === 'string' && !userFolderIds.has(item.folderId)) {
      item.folderId = undefined;
    }
  }

  const validItems = itemsToCreate.filter(
    (item) =>
      (typeof item.encryptedData === 'string' ? item.encryptedData.trim() : item.encryptedData) &&
      (typeof item.dataIv === 'string' ? item.dataIv.trim() : item.dataIv) &&
      (typeof item.dataTag === 'string' ? item.dataTag.trim() : item.dataTag) &&
      (typeof item.encryptedName === 'string' ? item.encryptedName.trim() : item.encryptedName) &&
      (typeof item.nameIv === 'string' ? item.nameIv.trim() : item.nameIv) &&
      (typeof item.nameTag === 'string' ? item.nameTag.trim() : item.nameTag),
  );
  const skippedCount = itemsToCreate.length - validItems.length;

  if (validItems.length === 0) {
    throw httpErrors.badRequest(
      'No valid items found to import (all items had missing encryption fields)',
    );
  }

  // Enforce per-item encrypted-field length caps before any DB write so an
  // over-length item cannot leave a partial, unaudited import (see
  // assertImportFieldLengths).
  assertImportFieldLengths(validItems);

  // Deduplication based on searchHash, with encryptedName fallback.
  // After vault key rotation, searchHashes change (they are HMAC-SHA256 of the item
  // name with the vault key). Items from an old export will have hashes from the old
  // key while existing items have hashes from the new key. To handle this, we fall
  // back to matching by encryptedName when searchHash doesn't match.
  //
  // Classification is write-free: matches are collected into `overwriteTargets`
  // and non-matches into `itemsToInsert`, so the per-user cap below can be
  // measured against the rows this import will actually INSERT. A blunt
  // `existing + validItems.length` sum falsely rejects a `skip` / `overwrite`
  // re-import of a user's own export (which inserts nothing for a match), and
  // running the overwrites during classification would persist part of the
  // import before a cap rejection could abort it. `keep_both` always inserts,
  // so there every valid item counts — that is the growth the cap bounds.
  let duplicateCount = 0;
  let itemsToInsert = validItems;
  const overwriteTargets: { existingId: Types.ObjectId; item: Record<string, unknown> }[] = [];

  if (conflictStrategy !== 'keep_both') {
    const importHashes = validItems
      .map((item) => item.searchHash as string | undefined)
      .filter((h): h is string => typeof h === 'string' && h.length > 0);

    // Fetch only the fields needed for deduplication (lean projection)
    const existingItems = await VaultItem.find({
      userId,
      deletedAt: { $exists: false },
    })
      .select('_id searchHash encryptedName')
      .lean();

    // Build lookup maps for both searchHash and encryptedName
    type DeduplicationEntry = (typeof existingItems)[number];
    const existingHashMap = new Map<string, DeduplicationEntry>();
    const existingNameMap = new Map<string, DeduplicationEntry>();
    for (const existing of existingItems) {
      if (existing.searchHash) {
        existingHashMap.set(existing.searchHash, existing);
      }
      if (existing.encryptedName) {
        existingNameMap.set(existing.encryptedName, existing);
      }
    }

    const hasAnyHashes = importHashes.length > 0;
    const hasAnyExisting = existingItems.length > 0;

    if (hasAnyHashes || hasAnyExisting) {
      /**
       * Finds a matching existing item by searchHash first (fast path),
       * then falls back to encryptedName matching (handles post-rotation imports).
       */
      const findExisting = (item: Record<string, unknown>) => {
        const hash = item.searchHash as string | undefined;
        if (hash) {
          const byHash = existingHashMap.get(hash);
          if (byHash) return byHash;
        }
        // Fallback: match by encryptedName (handles vault key rotation scenario
        // where searchHashes differ but encrypted names are identical since the
        // client re-encrypts with the current vault key before import)
        const name = item.encryptedName as string | undefined;
        if (name) {
          return existingNameMap.get(name);
        }
        return undefined;
      };

      if (conflictStrategy === 'skip') {
        itemsToInsert = validItems.filter((item) => {
          const existing = findExisting(item);
          if (existing) {
            duplicateCount++;
            return false;
          }
          return true;
        });
      } else {
        const toInsert: typeof validItems = [];
        for (const item of validItems) {
          const existing = findExisting(item);
          if (existing) {
            overwriteTargets.push({ existingId: existing._id, item });
          } else {
            toInsert.push(item);
          }
        }
        itemsToInsert = toInsert;
      }
    }
  }

  // Enforce the per-user vault item cap against net-new inserts only, BEFORE any
  // write, so an import that the cap rejects leaves nothing behind.
  const existingItemCount = await VaultItem.countDocuments({ userId });
  if (existingItemCount + itemsToInsert.length > MAX_ITEMS_PER_USER) {
    throw httpErrors.badRequest(
      `Import would exceed the per-user item limit (${String(MAX_ITEMS_PER_USER)}). You currently have ${String(existingItemCount)} items and this import would add ${String(itemsToInsert.length)}.`,
    );
  }

  for (const { existingId, item } of overwriteTargets) {
    await VaultItem.findOneAndUpdate(
      { _id: existingId, userId },
      { $set: pickAllowedFields(item, ALLOWED_ITEM_FIELDS) },
      { runValidators: true, upsert: false },
    );
  }
  const overwrittenCount = overwriteTargets.length;

  let importedCount = 0;
  if (itemsToInsert.length > 0) {
    const created = await VaultItem.insertMany(itemsToInsert);
    importedCount = created.length;
  }

  const importCtx = getRequestContext(req);
  await createAuditLog(
    userId,
    'import',
    { format, itemCount: importedCount + overwrittenCount, skippedCount, duplicateCount },
    importCtx.ip,
    importCtx.userAgent,
  );

  logger.info('Vault imported', {
    userId,
    format,
    itemCount: importedCount + overwrittenCount,
    skippedCount,
    duplicateCount,
    overwrittenCount,
  });

  res.status(201).json({
    success: true,
    data: {
      importedCount: importedCount + overwrittenCount,
      skippedCount,
      duplicateCount,
      overwrittenCount,
    },
    message: (() => {
      const total = importedCount + overwrittenCount;
      const parts: string[] = [`${String(total)} items imported successfully`];
      if (duplicateCount > 0) parts.push(`${String(duplicateCount)} duplicates skipped`);
      if (skippedCount > 0)
        parts.push(`${String(skippedCount)} skipped due to missing encryption fields`);
      return parts.join(' (') + (parts.length > 1 ? ')' : '');
    })(),
  });
});
