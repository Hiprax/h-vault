/**
 * Conservative byte-size estimators for vault items and folders, used to
 * enforce backup/export size guards without paying the cost of a full
 * `JSON.stringify` per row in the hot streaming loop.
 *
 * Design principle: every estimate MUST be >= the actual JSON byte length so
 * the incremental size guard cannot be bypassed. All overhead constants are
 * set conservatively higher than measured actuals, and every string is counted
 * at its JSON-ESCAPED length (see {@link jsonStringBytes}): the ciphertext fields
 * and tags accept any character, and JSON writes a control character as a
 * six-byte escape, so counting raw UTF-8 let a vault of such rows stream several
 * times the limit behind an estimate that admitted it.
 *
 * Used by both the export endpoint (`toolsController.exportData`) and the
 * backup collection paths (`backupController.collectBackupData`,
 * `backupScheduler.processUserBackup`). Centralizing the helpers prevents
 * drift across those three call sites.
 */

/**
 * The bytes `value` occupies inside JSON, WITHOUT its two quotes (the per-field
 * overheads cover those): what `JSON.stringify` writes for it, escapes included.
 * A string with nothing to escape costs one scan; one with escapes is measured
 * exactly.
 */
function jsonStringBytes(value: string): number {
  return Buffer.byteLength(JSON.stringify(value), 'utf-8') - 2;
}

// Fixed JSON overhead per vault item: covers _id, userId, itemType, folderId,
// favorite, createdAt, updatedAt, empty tags, JSON braces/colons/commas, and
// all encrypted field key names. Measured at ~400 bytes for a typical item;
// 600 adds a safety margin.
const PER_ITEM_JSON_OVERHEAD = 600;

// Fixed JSON overhead per folder: covers _id, userId, parentId, sortOrder,
// createdAt, updatedAt, JSON braces/colons/commas, and encrypted field key
// names.
const PER_FOLDER_JSON_OVERHEAD = 400;

// Per-tag JSON overhead: quotes + comma for each tag string in the tags array.
const PER_TAG_JSON_OVERHEAD = 4;

// Per password history entry JSON overhead: covers the changedAt timestamp
// (~30 bytes), object braces/colons/commas, and key names for
// encryptedPassword/iv/tag/changedAt.
const PER_PASSWORD_HISTORY_JSON_OVERHEAD = 120;

/**
 * Estimates the approximate JSON serialization size of a vault item document
 * without actually serializing it. Sums the byte lengths of the dominant
 * encrypted fields and adds conservative fixed overheads for JSON structure,
 * metadata fields, and smaller properties.
 */
export function estimateItemJsonSize(item: Record<string, unknown>): number {
  let size = PER_ITEM_JSON_OVERHEAD;

  // Dominant encrypted string fields — these are the bulk of the payload.
  const stringFields: readonly string[] = [
    'encryptedData',
    'encryptedName',
    'dataIv',
    'dataTag',
    'nameIv',
    'nameTag',
  ];
  for (const field of stringFields) {
    const value = item[field];
    if (typeof value === 'string') {
      size += jsonStringBytes(value);
    }
  }

  // Tags array: each string contributes its bytes plus quotes/comma overhead.
  if (Array.isArray(item.tags)) {
    for (const tag of item.tags) {
      if (typeof tag === 'string') {
        size += jsonStringBytes(tag) + PER_TAG_JSON_OVERHEAD;
      }
    }
  }

  // Password history entries can be sizable (up to PASSWORD_HISTORY_MAX per
  // item).
  if (Array.isArray(item.passwordHistory)) {
    for (const entry of item.passwordHistory) {
      if (typeof entry === 'object' && entry !== null) {
        const e = entry as Record<string, unknown>;
        const fieldNames: readonly string[] = ['encryptedPassword', 'iv', 'tag'];
        for (const fieldName of fieldNames) {
          const value = e[fieldName];
          if (typeof value === 'string') {
            size += jsonStringBytes(value);
          }
        }
        size += PER_PASSWORD_HISTORY_JSON_OVERHEAD;
      }
    }
  }

  return size;
}

/**
 * Estimates the approximate JSON serialization size of a folder document.
 * See {@link estimateItemJsonSize} for the design principle.
 */
export function estimateFolderJsonSize(folder: Record<string, unknown>): number {
  let size = PER_FOLDER_JSON_OVERHEAD;
  const stringFields: readonly string[] = ['encryptedName', 'nameIv', 'nameTag', 'icon', 'color'];
  for (const field of stringFields) {
    const value = folder[field];
    if (typeof value === 'string') {
      size += jsonStringBytes(value);
    }
  }
  return size;
}
