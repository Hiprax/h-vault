import { MAX_IMPORT_ITEMS } from '@hvault/shared';

/**
 * Split items into batches whose serialized size stays under `maxBytes`.
 *
 * The encrypted import payload for a whole vault easily exceeds the server's
 * single-request `data` cap (MAX_IMPORT_DATA_LENGTH), so the client sends several
 * sequential requests. Sizing is measured on `JSON.stringify(item)` (plus a
 * comma) against the array; the small `{"items":[...]}` wrapper is covered by the
 * caller's headroom. Each batch is also capped at {@link MAX_IMPORT_ITEMS}.
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
