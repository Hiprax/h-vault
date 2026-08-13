/**
 * Builds a backup document of a chosen size and quote density, for the restore
 * scenarios.
 *
 * QUOTE DENSITY IS THE POINT, not a detail. The client posts
 * `{ conflictStrategy, data: JSON.stringify(backup) }`, so the backup travels as
 * a JSON *string value* and every `"` inside it is escaped to `\"` on the wire.
 * A backup whose inner `data` is comfortably inside the 25 MiB schema cap can
 * therefore produce a request body several megabytes larger — which is the whole
 * reason `routes/backup.ts` mounts a 30 MB parser on that one route instead of
 * letting the global 2 MB parser apply. Building a document out of a few enormous
 * strings would have almost no quotes in it and would sail through a parser
 * limit that a REAL backup — thousands of small items, each with a full password
 * history — does not.
 */

/** Fixed-width filler for fields whose length is not what a scenario varies. */
const IV = 'i'.repeat(16);
const TAG = 't'.repeat(22);

export interface RestoreDocumentShape {
  /** How many item rows the backup carries. */
  items: number;
  /** Target byte length for the serialized backup (the inner `data` string). */
  targetBytes: number;
  /** Password-history entries per item: 4 keys and 4 values of quotes each. */
  historyEntries: number;
  /** Tags per item: two quotes and a comma each. */
  tags: number;
}

export interface RestoreDocument {
  /** The value that goes in the request's `data` field. */
  data: string;
  /** `data.length`, i.e. what `restoreBackupSchema.data.max()` measures. */
  dataBytes: number;
  /** The full request body's serialized length: what the parser's limit measures. */
  bodyBytes: number;
  /** How much the JSON escaping of `data` inflated the body, as a percentage. */
  inflationPct: number;
  /** How many rows it carries. */
  itemCount: number;
}

function buildItem(index: number, shape: RestoreDocumentShape, fillerBytes: number): unknown {
  return {
    itemType: 'login',
    encryptedData: 'd'.repeat(Math.max(fillerBytes, 1)),
    dataIv: IV,
    dataTag: TAG,
    encryptedName: `restored-${String(index)}`,
    nameIv: IV,
    nameTag: TAG,
    searchHash: index.toString(16).padStart(64, '0'),
    tags: Array.from({ length: shape.tags }, (_unused, t) => `tag${String(t)}`),
    favorite: false,
    passwordHistory: Array.from({ length: shape.historyEntries }, (_unused, h) => ({
      encryptedPassword: `hist-${String(index)}-${String(h)}`,
      iv: IV,
      tag: TAG,
      changedAt: new Date(Date.UTC(2026, 0, 1 + (h % 27))).toISOString(),
    })),
  };
}

/**
 * Produces a backup document as close to `targetBytes` as one uniform filler
 * length allows, and reports the three numbers the boundary cases assert on.
 *
 * The filler length is DERIVED from a measured template rather than guessed:
 * the per-row overhead depends on the history and tag counts, and a hardcoded
 * figure would silently stop hitting the target the first time either changes.
 */
export function buildRestoreDocument(shape: RestoreDocumentShape): RestoreDocument {
  // The LAST index, not the first: several fields embed the row number, so a row
  // near the end is tens of bytes longer than row 0. Sizing the filler against
  // row 0 overshoots the target by that difference times the row count — enough,
  // measured, to push a document aimed 200 KiB under the schema cap 100 KiB over
  // it, which turns a volume scenario into a 400.
  const templateBytes = JSON.stringify(buildItem(shape.items - 1, shape, 1)).length;
  const envelopeBytes = JSON.stringify({ version: '0.0.0', items: [], folders: [] }).length;
  const perItem = Math.floor((shape.targetBytes - envelopeBytes) / shape.items);
  // `templateBytes` already counts the one filler byte the template carries.
  const fillerBytes = Math.max(perItem - templateBytes, 1);

  const data = JSON.stringify({
    version: '0.0.0',
    items: Array.from({ length: shape.items }, (_unused, i) => buildItem(i, shape, fillerBytes)),
    folders: [],
  });
  const bodyBytes = JSON.stringify({ conflictStrategy: 'skip', data }).length;
  return {
    data,
    dataBytes: data.length,
    bodyBytes,
    inflationPct: Number(((bodyBytes / data.length - 1) * 100).toFixed(2)),
    itemCount: shape.items,
  };
}
