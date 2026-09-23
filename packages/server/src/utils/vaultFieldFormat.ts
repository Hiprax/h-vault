import { VAULT_FIELD_V2_IV_MARKER } from '@hvault/shared';

/**
 * Whether a payload carries any vault field in format v2: a field sealed to its
 * row, marked by `VAULT_FIELD_V2_IV_MARKER` at the start of its IV.
 *
 * The server cannot open a field and does not try to. What it can read is the
 * marker, and that is enough for the one question the two callers ask: did a
 * client that does not understand v2 send a v2 field back unchanged? Such a
 * client cannot produce a marked IV itself — its IVs are plain base64, which can
 * never contain the marker's `:` — so a marked IV in its payload is a field it
 * could not open and passed through verbatim. On a rotation that field is then
 * left under the retired key; on a restore it can land under an id it was not
 * sealed to. Either way it is lost, which is what the callers refuse.
 *
 * The fields read are exactly the IVs a vault row stores: an item's `nameIv`,
 * `dataIv` and every `passwordHistory[].iv`, and a folder's `nameIv`. Both inputs
 * are `unknown` because a restore's rows come from a parsed file, not a schema.
 */
export function carriesBoundField(items: unknown, folders: unknown): boolean {
  for (const item of rows(items)) {
    if (isMarked(item.nameIv) || isMarked(item.dataIv)) return true;
    for (const entry of rows(item.passwordHistory)) {
      if (isMarked(entry.iv)) return true;
    }
  }
  return rows(folders).some((folder) => isMarked(folder.nameIv));
}

/**
 * The object entries of what should be an array of rows, and nothing else. A
 * restore's rows come from a parsed file, so the array may be missing, may not be
 * an array, and may hold `null`s or strings; none of those can carry a field, and
 * none of them may throw here and turn a malformed file into a 500.
 */
function rows(value: unknown): Record<string, unknown>[] {
  if (!Array.isArray(value)) return [];
  return (value as unknown[]).filter(
    (entry): entry is Record<string, unknown> => typeof entry === 'object' && entry !== null,
  );
}

function isMarked(iv: unknown): boolean {
  return typeof iv === 'string' && iv.startsWith(VAULT_FIELD_V2_IV_MARKER);
}
