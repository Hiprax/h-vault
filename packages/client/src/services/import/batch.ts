import { MAX_IMPORT_DATA_LENGTH, MAX_IMPORT_ITEMS } from '@hvault/shared';
import type { ImportInsertItem, ImportUpdateItem } from '@hvault/shared';

/**
 * Split items into batches whose serialized size stays under `maxBytes`.
 *
 * The encrypted payload for a whole vault easily exceeds a sensible single
 * request body, so the client sends several sequential requests. Sizing is
 * measured on `JSON.stringify(item)` (plus a comma) against the array; the small
 * request wrapper is covered by the caller's headroom. Each batch is also capped
 * at {@link MAX_IMPORT_ITEMS}.
 *
 * A single item larger than `maxBytes` is placed in its own batch (it cannot be
 * split); the server will reject it and the caller surfaces that honestly.
 */
export function chunkBySize<T>(
  items: T[],
  maxBytes: number,
  maxCount: number = MAX_IMPORT_ITEMS,
): T[][] {
  const batches: T[][] = [];
  let current: T[] = [];
  let currentSize = 2; // for "[]"

  for (const item of items) {
    const itemSize = JSON.stringify(item).length + 1; // + separator
    const wouldOverflow = currentSize + itemSize > maxBytes;
    if (current.length > 0 && (wouldOverflow || current.length >= maxCount)) {
      batches.push(current);
      current = [];
      currentSize = 2;
    }
    current.push(item);
    currentSize += itemSize;
  }

  if (current.length > 0) batches.push(current);
  return batches;
}

/** One request's worth of resolved operations. */
export interface ImportOperationBatch {
  inserts: ImportInsertItem[];
  updates: ImportUpdateItem[];
}

/**
 * Default per-request byte budget for the structured `operations` payload.
 *
 * The real server-side bound is the GLOBAL 2 MB body parser (`/tools/import` is
 * not in `CUSTOM_BODY_LIMIT_PATHS`) plus the `MAX_IMPORT_ITEMS` count cap; the
 * legacy `MAX_IMPORT_DATA_LENGTH` string cap no longer applies to a structured
 * body. Keeping the client well inside that ceiling is a convention, not an
 * enforcement, so the budget stays at 90% of the old 1 MiB figure — roughly half
 * the parser limit, leaving room for the request envelope and for base64
 * ciphertext that estimates slightly under its serialized length.
 */
export const IMPORT_BATCH_MAX_BYTES = Math.floor(MAX_IMPORT_DATA_LENGTH * 0.9);

/**
 * Split resolved operations into size-bounded requests.
 *
 * Batching is TRANSPORT, never semantics: conflict resolution already ran once
 * over the whole import against the whole vault, so this may only slice the
 * result. It re-orders nothing, matches nothing and drops nothing — every
 * operation appears exactly once, in its original relative order, and splitting
 * the same resolution differently cannot change what the vault ends up holding.
 * That is what structurally eliminates the 0.2.0 batch-boundary defect.
 *
 * Inserts precede updates so the sequence is deterministic. Sizing reuses
 * {@link chunkBySize} over a tagged stream, which measures the wrapper too and
 * therefore over-estimates each row slightly — conservative in the safe
 * direction.
 */
export function chunkImportOperations(
  inserts: readonly ImportInsertItem[],
  updates: readonly ImportUpdateItem[],
  maxBytes: number = IMPORT_BATCH_MAX_BYTES,
  maxCount: number = MAX_IMPORT_ITEMS,
): ImportOperationBatch[] {
  type TaggedOperation =
    { kind: 'insert'; item: ImportInsertItem } | { kind: 'update'; item: ImportUpdateItem };

  const stream: TaggedOperation[] = [
    ...inserts.map((item): TaggedOperation => ({ kind: 'insert', item })),
    ...updates.map((item): TaggedOperation => ({ kind: 'update', item })),
  ];

  return chunkBySize(stream, maxBytes, maxCount).map((batch) => {
    const batchInserts: ImportInsertItem[] = [];
    const batchUpdates: ImportUpdateItem[] = [];
    for (const operation of batch) {
      if (operation.kind === 'insert') batchInserts.push(operation.item);
      else batchUpdates.push(operation.item);
    }
    return { inserts: batchInserts, updates: batchUpdates };
  });
}
