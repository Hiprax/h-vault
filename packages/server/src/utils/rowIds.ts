import { deriveRowId } from '@hvault/shared';

/**
 * The `_id` a created row is stored under, as a spreadable fragment.
 *
 * A client that sends `idNonce` has ALREADY sealed the row's fields to the id
 * `deriveRowId(userId, idNonce)` names, so the row must be stored under exactly
 * that id or it never opens again. That is why this is spread in EXPLICITLY at
 * each create rather than left to the field allowlists: `pickAllowedFields`
 * carries only the names it lists, and neither `idNonce` nor `id` is one of them,
 * so an allowlisted copy would drop the nonce and let Mongoose mint an id the
 * fields were never bound to — silently, behind a 201.
 *
 * No nonce means a server-minted id, exactly as before the field existed.
 */
export async function createdRowId(
  userId: string,
  idNonce: string | undefined,
): Promise<{ _id?: string }> {
  if (idNonce === undefined) return {};
  return { _id: await deriveRowId(userId, idNonce) };
}

/** What a create is told when the id its nonce derives is already stored. */
export const ROW_ID_TAKEN_MESSAGE =
  'A row with this id already exists. If this was a retry, reload to see it; otherwise try again.';

/**
 * Whether a write failed on a duplicate `_id`, as distinct from any other unique
 * index on the same collection.
 *
 * The distinction is the whole reason this exists: `Folder` also has a unique
 * `(userId, searchHash)` index, and "a folder with this name already exists" is
 * the wrong thing to tell a client whose derived id collided. The driver names the
 * violated index in two different ways: a single-document write carries
 * `keyPattern`, while a bulk write (`insertMany`) carries NO `keyPattern` at all,
 * only each write error's server message, `… index: _id_ dup key: …` — measured
 * against the real driver, which is why both are read.
 */
export function isDuplicateIdError(err: unknown): boolean {
  if (!isRecord(err) || err.code !== 11000) return false;
  if (namesIdIndex(err)) return true;
  if (!Array.isArray(err.writeErrors)) return false;
  return (err.writeErrors as unknown[]).some(
    (entry) =>
      isRecord(entry) && (namesIdIndex(entry) || (isRecord(entry.err) && namesIdIndex(entry.err))),
  );
}

/** The server's own wording for a duplicate on the `_id_` index. */
const ID_INDEX_DUPLICATE = ' index: _id_ dup key: ';

function namesIdIndex(error: Record<string, unknown>): boolean {
  const { keyPattern, errmsg } = error;
  if (isRecord(keyPattern)) {
    return Object.keys(keyPattern).length === 1 && Object.hasOwn(keyPattern, '_id');
  }
  return typeof errmsg === 'string' && errmsg.includes(ID_INDEX_DUPLICATE);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
