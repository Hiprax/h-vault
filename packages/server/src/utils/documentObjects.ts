import { DOCUMENT_TAG_BYTES } from '@hvault/shared';

/**
 * Object-key construction and segment-range arithmetic for the document store —
 * the ONE definition of both, because three unrelated call sites need identical
 * answers and a second copy of either is a silent-corruption bug rather than a
 * style problem:
 *
 *   * the documents controller, which assigns `objectKey` at upload init, checks
 *     the size of every uploaded part, and computes the `Range` header for a
 *     segment read;
 *   * the garbage-collection job, which parses a key back into the document id it
 *     names in order to decide whether an object is an orphan, and lists a user's
 *     objects by prefix;
 *   * the account-cascade helper, which erases every object a deleted user owns.
 *
 * The key layout is `u/<userId>/d/<documentId>`, both ids lowercase 24-character
 * ObjectId hex. Two properties of that layout are load-bearing:
 *
 *   1. Every object a user owns sits under the single prefix `u/<userId>/`, so an
 *      account erasure is one prefix listing rather than a per-row lookup, and it
 *      still reaches an object whose row has already been deleted.
 *   2. A key round-trips: `parseObjectKey(buildObjectKey(u, d))` returns exactly
 *      `{ userId: u, documentId: d }`. The orphan sweep depends on it — a key it
 *      cannot parse is a key it must not delete.
 *
 * The key is ALWAYS server-assigned. Nothing here accepts a client-supplied key,
 * and both builders refuse anything that is not an ObjectId, so a key that reaches
 * the storage engine can never contain a path segment, a traversal or a name.
 */

/**
 * A 24-character ObjectId in hex, case-insensitive on the way in.
 *
 * Case-insensitive because `ObjectId.isValid` is, so a hand-written key or a row
 * migrated by a tool could carry uppercase hex and still name a real document; the
 * builders normalise to lowercase so the value this module emits and the value
 * `_id.toString()` produces are the same string.
 */
const OBJECT_ID_PATTERN = /^[0-9a-fA-F]{24}$/;

/**
 * The key layout, anchored at both ends and with no optional segment, so a key
 * with a trailing slash, an extra path segment, a different prefix letter or a
 * non-hex id fails to parse rather than parsing into something plausible.
 */
const OBJECT_KEY_PATTERN = /^u\/([0-9a-fA-F]{24})\/d\/([0-9a-fA-F]{24})$/;

/** Reads an ObjectId-shaped argument, normalised to lowercase, or throws. */
function requireObjectId(value: string, label: string): string {
  if (!OBJECT_ID_PATTERN.test(value)) {
    throw new TypeError(`${label} must be a 24-character ObjectId hex string`);
  }
  return value.toLowerCase();
}

/** Reads an integer argument at or above a lower bound, or throws a `RangeError`. */
function requireIntegerAtLeast(value: number, minimum: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < minimum) {
    throw new RangeError(`${label} must be a safe integer of at least ${String(minimum)}`);
  }
}

/**
 * The prefix every object belonging to one user shares.
 *
 * Returned with its trailing slash, which is what makes a `ListObjectsV2` prefix
 * query exact: without it, `u/1` would also match `u/10…`, and a cascade delete
 * would reach into another account's objects.
 */
export function userObjectPrefix(userId: string): string {
  return `u/${requireObjectId(userId, 'userId')}/`;
}

/**
 * The storage key for one document. Server-assigned at upload init, never taken
 * from a request, and stored on the row so a later read does not have to rebuild
 * it (the row is authoritative; this function is how the row got its value).
 */
export function buildObjectKey(userId: string, documentId: string): string {
  return `${userObjectPrefix(userId)}d/${requireObjectId(documentId, 'documentId')}`;
}

/** The two ids a well-formed object key names. */
export interface ParsedObjectKey {
  userId: string;
  documentId: string;
}

/**
 * The inverse of {@link buildObjectKey}, or `null` when the key was not written by
 * it.
 *
 * `null` rather than a throw, because the ONE caller is the garbage collector's
 * orphan sweep, walking keys the engine reports rather than keys this code wrote.
 * An unrecognised key there is data to leave alone, not an exception to handle: the
 * sweep skips it, so a key some other tool put in the bucket survives, and a key
 * that cannot be tied to a document id can never be deleted on the strength of a
 * lookup that would have thrown.
 *
 * Both ids come back lowercase, so a caller may compare them with
 * `_id.toString()` directly.
 */
export function parseObjectKey(key: string): ParsedObjectKey | null {
  const match = OBJECT_KEY_PATTERN.exec(key);
  // This IS the null path, not a formality: `exec` returns null for every key this
  // module did not write, so both reads are `undefined` and the guard below is what
  // turns that into the documented `null`. Do not "simplify" it into a non-optional
  // read — the orphan sweep would then receive an object with two undefined ids and
  // go looking for a document called `undefined`.
  const userId = match?.[1];
  const documentId = match?.[2];
  if (userId === undefined || documentId === undefined) {
    return null;
  }
  return { userId: userId.toLowerCase(), documentId: documentId.toLowerCase() };
}

/** A byte range over the stored object, with an INCLUSIVE end, as HTTP uses. */
export interface SegmentRange {
  /** First byte of the segment, zero-based. */
  start: number;
  /**
   * LAST byte of the segment, inclusive — the value that goes into
   * `Range: bytes=<start>-<end>`. An exclusive end here would ask the engine for
   * one byte of the next segment and one byte short of this one, which decrypts to
   * nothing at all: the tag check fails and the failure looks like corruption.
   */
  end: number;
  /** `end - start + 1`, and the exact `Content-Length` of the segment response. */
  length: number;
}

/**
 * The byte range of segment `index` inside the stored object.
 *
 * The stored object is a pure concatenation of sealed segments, so the arithmetic
 * is total: every non-final segment is exactly `chunkPlaintextBytes +
 * DOCUMENT_TAG_BYTES` long, segment `i` therefore starts at `i` times that, and
 * the final segment runs to the end of the object.
 *
 * `chunkPlaintextBytes` comes from the ROW and never from
 * `DOCUMENT_PLAINTEXT_CHUNK_BYTES`: the constant is what a NEW upload is framed
 * with, and changing it later must not re-frame a document that already exists.
 * `ciphertextBytes` likewise comes from the row, where it is the sum of the part
 * sizes the engine actually reported at completion, so the range is anchored on the
 * real object length rather than on a size derived from the plaintext count.
 *
 * Throws rather than clamping. A caller asking for a segment the document does not
 * have, or holding a row whose framing columns cannot describe an object of that
 * length, has a bug or corrupt data; answering with a range that reads the wrong
 * bytes would surface as a decryption failure somewhere else entirely.
 *
 * What this deliberately does NOT enforce is the "no phantom empty final segment"
 * rule: a `chunkCount` of `n >= 2` whose final segment holds only a tag is
 * arithmetically representable and is refused at COMPLETION, where the part ledger
 * is verified, so that rule lives in exactly one place. Here the only question is
 * whether the numbers can describe an object at all.
 */
export function segmentRange(
  index: number,
  chunkCount: number,
  chunkPlaintextBytes: number,
  ciphertextBytes: number,
): SegmentRange {
  requireIntegerAtLeast(chunkCount, 1, 'chunkCount');
  requireIntegerAtLeast(chunkPlaintextBytes, 1, 'chunkPlaintextBytes');
  requireIntegerAtLeast(ciphertextBytes, DOCUMENT_TAG_BYTES, 'ciphertextBytes');
  requireIntegerAtLeast(index, 0, 'index');
  if (index >= chunkCount) {
    throw new RangeError(
      `index ${String(index)} is outside a document of ${String(chunkCount)} segment(s)`,
    );
  }

  const segmentCiphertextBytes = chunkPlaintextBytes + DOCUMENT_TAG_BYTES;
  const fullSegments = chunkCount - 1;
  // The object must hold every non-final segment in full plus at least the final
  // segment's tag, and cannot hold more than every segment in full. Outside that
  // window the row's own columns disagree, and no range computed from them is
  // trustworthy.
  const smallestObject = fullSegments * segmentCiphertextBytes + DOCUMENT_TAG_BYTES;
  const largestObject = chunkCount * segmentCiphertextBytes;
  if (ciphertextBytes < smallestObject || ciphertextBytes > largestObject) {
    throw new RangeError(
      `ciphertextBytes ${String(ciphertextBytes)} cannot hold ${String(chunkCount)} segment(s) of ` +
        `${String(chunkPlaintextBytes)} plaintext byte(s) each`,
    );
  }

  const start = index * segmentCiphertextBytes;
  const end = index === fullSegments ? ciphertextBytes - 1 : start + segmentCiphertextBytes - 1;
  return { start, end, length: end - start + 1 };
}

/**
 * The exact size, in bytes, that part `partNumber` of an upload must have.
 *
 * One crypto segment is one uploaded part is one downloaded range, so this is the
 * length {@link segmentRange} reports for the same segment — expressed in S3's
 * ONE-BASED part numbering, which is the only place in this design where an index
 * is not zero-based, and therefore exactly where an off-by-one would live.
 *
 * The COMPLETION path uses it to verify the ledger `ListParts` reports, where the
 * committed `ciphertextBytes` exists. The upload path cannot call it yet and should
 * not pretend otherwise: a staging row holds `declaredPlaintextBytes` and
 * `declaredChunkCount`, so reaching this from there needs the forward conversion
 * `ciphertext = plaintext + DOCUMENT_TAG_BYTES * chunkCount` — which already lives,
 * inline, in `documentResponseSchema`'s refine. Whoever needs it first should name
 * it `documentCiphertextBytesFor` in `@hvault/shared` beside `documentChunkCountFor`
 * and rewrite that refine to call it, rather than writing the identity a second
 * time here. Both matter because the engine itself does not: a short
 * middle part is ACCEPTED by the storage engine (measured), and it silently moves
 * every later segment boundary, so the server is the only thing standing between a
 * mis-sized part and a document that can never be decrypted.
 */
export function expectedPartSize(
  partNumber: number,
  chunkCount: number,
  chunkPlaintextBytes: number,
  ciphertextBytes: number,
): number {
  requireIntegerAtLeast(chunkCount, 1, 'chunkCount');
  requireIntegerAtLeast(partNumber, 1, 'partNumber');
  // Checked here, against partNumber, rather than left to segmentRange's index
  // check: a caller that sent part 14 of a 13-part upload deserves a message about
  // part 14, not about segment 13.
  if (partNumber > chunkCount) {
    throw new RangeError(
      `partNumber ${String(partNumber)} is outside an upload of ${String(chunkCount)} part(s)`,
    );
  }
  return segmentRange(partNumber - 1, chunkCount, chunkPlaintextBytes, ciphertextBytes).length;
}
