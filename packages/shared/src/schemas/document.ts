import { z } from 'zod';
import { objectIdSchema, paginationSchema } from './common.js';
import {
  DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
  DOCUMENT_NONCE_PREFIX_BYTES,
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  DOCUMENT_STREAM_SALT_BYTES,
  DOCUMENT_TAG_BYTES,
  MAX_DOCUMENT_CHUNK_COUNT,
  MAX_DOCUMENT_EXT_LENGTH,
  MAX_DOCUMENT_META_JSON_BYTES,
  MAX_DOCUMENT_MIME_LENGTH,
  MAX_DOCUMENT_NAME_LENGTH,
  MAX_DOCUMENT_NOTE_LENGTH,
  MAX_DOCUMENT_TAGS,
  MAX_DOCUMENT_TIMESTAMP_LENGTH,
  MAX_DOCUMENT_TRANSFORM_LABEL_LENGTH,
  MAX_ENCRYPTED_DOCUMENT_META_LENGTH,
  MAX_TAG_LENGTH,
} from '../constants/index.js';

// ---------------------------------------------------------------------------
// The encrypted document store's wire and blob schemas.
//
// The server stores ciphertext, a wrapped key and sizes. It never sees a
// filename, a MIME type, a tag, a note or a byte of content, so nothing below can
// be diagnosed later by looking at stored data: a disagreement between the two
// sides presents as a file that uploaded and will not open. Every bound is
// therefore a NAMED constant, and the derivations that relate them live in exactly
// one function each.
//
// `documentMetaSchema` runs in BOTH directions, exactly as `vaultItemDataSchemas`
// does: the browser parses the metadata it is about to seal (the write pre-flight)
// and parses it again after decrypting (the read). A value accepted on the way in
// and refused on the way out is a document the user can no longer read the name
// of, so the schema is permissive about FORMAT and strict about LENGTH.
//
// Every object here runs in STRIP mode, which is `z.object()`'s default: an
// unknown key is dropped rather than rejected. Do not re-add `.strip()`; see the
// note above `vaultItemDataSchemas` in `schemas/vault.ts`.
// ---------------------------------------------------------------------------

/**
 * The 24-character hex id of a document or of the upload that becomes one.
 *
 * Stricter than `vaultItemResponseSchema`'s `_id: z.string().min(1)`, and for a
 * reason that does not apply to a vault item: the document id is HKDF `info`
 * material (Section 1.4 binds the DEK wrap, the stream key and the metadata key
 * to it), so an id that differs from the real one by a single character derives
 * three different keys and produces a document that decrypts to nothing, with no
 * error anywhere until the AEAD fails. Refusing the wrong SHAPE up front is the
 * cheapest half of that check.
 *
 * Lower-case only, because that is what Mongo's ObjectId `toString()` and
 * `objectIdSchema`'s own transform both produce.
 */
const documentIdSchema = z.string().regex(/^[a-f0-9]{24}$/, 'Invalid document id');

/** A 64-character lower-case SHA-256 digest, anchored at both ends. */
const sha256Schema = (label: string): z.ZodString =>
  z.string().regex(/^[a-f0-9]{64}$/, `${label} must be 64 lowercase hexadecimal characters`);

/**
 * Padded standard base64 of exactly `bytes` raw bytes.
 *
 * `z.base64()` refuses base64url and refuses an unpadded string, and
 * `cryptoService.arrayBufferToBase64` emits `btoa` output, so the two agree by
 * construction. Pinning the exact byte count is what makes a TRUNCATED framing
 * field a 400 instead of a document that fails to decrypt three requests later: a
 * salt one byte short is still valid base64 and still fits any generous `.max()`.
 *
 * The LENGTH ALONE DOES NOT PIN THE BYTE COUNT, which is the whole reason the
 * padding check exists. Base64 emits `4 * ceil(n / 3)` characters, so 31, 32 and
 * 33 bytes all encode to 44 characters and a `.length(44)` accepts all three; what
 * distinguishes them is the padding (`==`, `=`, and none respectively). So the
 * padding is derived from the byte count too, and asserted both ways: the expected
 * run of `=` must be there, and one more must not.
 *
 * Only `streamSalt` and `noncePrefix` are pinned this way. They are the two
 * plaintext framing fields whose byte counts Phase 1 named
 * (`DOCUMENT_STREAM_SALT_BYTES`, `DOCUMENT_NONCE_PREFIX_BYTES`) precisely so both
 * sides agree, and both are parameters of the stored container format rather than
 * of one request. The IV and tag fields keep the vault's existing `max(24)` /
 * `max(32)` convention, because no named document constant describes them and one
 * bound written two ways in neighbouring files is how the two drift.
 */
const base64OfBytes = (bytes: number, label: string): z.ZodType<string, string> => {
  const length = Math.ceil(bytes / 3) * 4;
  const padding = (3 - (bytes % 3)) % 3;
  const message = `${label} must be padded standard base64 of exactly ${String(bytes)} bytes`;
  return z
    .base64(message)
    .length(length, message)
    .refine(
      (value) => value.endsWith('='.repeat(padding)) && !value.endsWith('='.repeat(padding + 1)),
      message,
    );
};

/**
 * `chunkCount = max(1, ceil(plaintextBytes / chunkPlaintextBytes))` — the framing
 * derivation of Section 1.4, in ONE place.
 *
 * The `max(1, …)` is not defensive padding: a zero-byte document is one segment
 * holding zero plaintext bytes and a tag, which is what the framing prototype
 * measured, and `ceil(0 / P)` is 0. Without it an empty file would claim no
 * segments at all and no `Range` read would ever be issued for it.
 *
 * Four callers rely on this being the only copy: the metadata schema's own
 * consistency refine, the row-response refine, the upload-init refine and the
 * browser that computes `declaredChunkCount` before it seals the first segment.
 */
export function documentChunkCountFor(plaintextBytes: number, chunkPlaintextBytes: number): number {
  return Math.max(1, Math.ceil(plaintextBytes / chunkPlaintextBytes));
}

/**
 * `plaintextBytes = ciphertextBytes - DOCUMENT_TAG_BYTES * chunkCount` — the size
 * identity of the container format, in ONE place.
 *
 * Every segment is its plaintext sealed under AES-256-GCM, so the stored object is
 * the file plus exactly one authentication tag per segment and nothing else. That
 * one sentence is the whole conversion, which is precisely why it must not be
 * written twice: the completion endpoint derives a document's `plaintextBytes` from
 * the part ledger with it, and {@link documentResponseSchema} re-checks the same
 * relationship on every row a client reads. Written out in both places, a change to
 * the framing would be applied to one of them and the disagreement would surface as
 * a document that uploaded and will not open.
 *
 * Stated in this direction rather than as `ciphertextBytes = plaintextBytes + …`
 * because that is the direction both callers need: the object's length is what the
 * storage engine reports, and the file's length is what has to be derived from it.
 * The forward conversion has no caller yet; `utils/documentObjects.ts` records where
 * it should live when one appears.
 */
export function documentPlaintextBytesFor(ciphertextBytes: number, chunkCount: number): number {
  return ciphertextBytes - DOCUMENT_TAG_BYTES * chunkCount;
}

/**
 * The UTF-8 byte length of the serialized metadata blob — the quantity that is
 * actually sealed, and the one `MAX_DOCUMENT_META_JSON_BYTES` bounds.
 *
 * Exported because the bound is a BYTE count while every field bound above it is a
 * Zod `.max()` over UTF-16 CODE UNITS, and that gap is the whole reason this
 * function exists: a 10,000-unit note in any non-Latin script is up to 30,000
 * bytes, so a schema that only counted units would accept a metadata object the
 * stored bound then refuses. The upload panel calls this to show the real cost
 * before a user is asked to shorten a note.
 */
export function documentMetaJsonByteLength(meta: unknown): number {
  // Typed `unknown` rather than trusting the return type, because the standard
  // library's signature is optimistic: `JSON.stringify` is DECLARED to return
  // `string` and really returns `undefined` for `undefined`, a function or a
  // symbol. Widening here is what makes the guard below a real narrowing rather
  // than a condition the linter is right to call dead — and the guard is what lets
  // the schema's refine call this without checking its own input first.
  const json: unknown = JSON.stringify(meta);
  return typeof json === 'string' ? new TextEncoder().encode(json).byteLength : 0;
}

/** The message {@link documentMetaSchema} reports when the sealed blob is too big. */
export const DOCUMENT_META_TOO_LARGE_MESSAGE = `Document metadata must serialize to ${String(MAX_DOCUMENT_META_JSON_BYTES)} UTF-8 bytes or fewer`;

/** The message every framing-consistency refine reports, so the three cannot word it differently. */
export const DOCUMENT_FRAMING_MISMATCH_MESSAGE =
  'chunkCount must equal ceil(plaintextBytes / chunkPlaintextBytes), and at least 1';

/**
 * Is `chunkCount` the count this plaintext size implies?
 *
 * ABSTAINS (returns true) when `chunkPlaintextBytes` is not a positive integer.
 * That branch is reachable and deliberate: an object-level refine in zod 4 still
 * runs when a FIELD failed one of its own checks (measured), so this predicate can
 * be handed a `chunkPlaintextBytes` of 0, and `ceil(n / 0)` is `Infinity`. The
 * field's own error already reports the real problem, and a second, arithmetically
 * meaningless issue beside it would only obscure it.
 */
function hasConsistentFraming(framing: {
  plaintextBytes: number;
  chunkPlaintextBytes: number;
  chunkCount: number;
}): boolean {
  if (!Number.isInteger(framing.chunkPlaintextBytes) || framing.chunkPlaintextBytes <= 0) {
    return true;
  }
  return (
    framing.chunkCount ===
    documentChunkCountFor(framing.plaintextBytes, framing.chunkPlaintextBytes)
  );
}

// ---------------------------------------------------------------------------
// The encrypted metadata blob
// ---------------------------------------------------------------------------

/**
 * The provenance of the upload panel's two optional in-browser transforms
 * (Section 1.13). Present only when at least one of them ran.
 *
 * Every field is required INSIDE the block: the block exists because a transform
 * ran, and a provenance record missing its tool or the digest of what the bytes
 * looked like beforehand records nothing anyone could act on.
 */
const documentTransformSchema = z.object({
  formatted: z.boolean(),
  repaired: z.boolean(),
  tool: z.string().min(1).max(MAX_DOCUMENT_TRANSFORM_LABEL_LENGTH),
  toolVersion: z.string().min(1).max(MAX_DOCUMENT_TRANSFORM_LABEL_LENGTH),
  originalSha256: sha256Schema('originalSha256'),
});

/**
 * The decrypted document metadata: everything the server is never allowed to see.
 *
 * `mime`, `ext` and `tags` are REQUIRED rather than defaulted, and empty values
 * are legal for the first two. A file picked from a disk may have no MIME type
 * (`File.type` is `''` for an unrecognised one) and a name with no dot has no
 * extension at all (`Dockerfile`, `.bashrc`), so refusing an empty string would
 * refuse ordinary files; but the blob is written by exactly one function, which
 * always emits all three, so a MISSING key is a bug in that function and is worth
 * a loud failure rather than a silent default.
 *
 * `capturedAt` is `z.iso.datetime()` WITHOUT `{ offset: true }`, so it must be a
 * `Z` instant. An offset-bearing local time would read differently depending on
 * the reader's zone, and the `dst` gate re-runs this suite in
 * `America/New_York` specifically to catch a value that does. It carries a LENGTH
 * bound as well as that shape check, for the reason
 * `MAX_DOCUMENT_TIMESTAMP_LENGTH` records: ISO 8601's fractional-second component
 * is one-or-more digits with no ceiling, so the shape alone admits a timestamp of
 * any size. `secretDataSchema.expiresAt` pairs its own ISO check with a `.max()`
 * for exactly this reason.
 */
export const documentMetaSchema = z
  .object({
    name: z.string().min(1).max(MAX_DOCUMENT_NAME_LENGTH),
    mime: z.string().max(MAX_DOCUMENT_MIME_LENGTH),
    // No charset rule and no `.toLowerCase()`: deriving the lookup key is the
    // caller's job (the lowercased segment after the last dot), and a regex here
    // would refuse the extension of a perfectly ordinary file — `md~`, `C++` —
    // on the read path, which degrades a stored document instead of the upload
    // that produced it.
    ext: z.string().max(MAX_DOCUMENT_EXT_LENGTH),
    plaintextBytes: z.number().int().min(0),
    sha256: sha256Schema('sha256'),
    // Deliberately NOT bounded by DOCUMENT_PLAINTEXT_CHUNK_BYTES. Decryption
    // reads this value from the row rather than from the constant precisely so
    // that changing the constant later cannot mis-frame a document that already
    // exists, and a `.max()` tied to today's constant would undo that the moment
    // the constant fell.
    chunkPlaintextBytes: z.number().int().positive(),
    chunkCount: z.number().int().min(1).max(MAX_DOCUMENT_CHUNK_COUNT),
    // `.trim()` runs BEFORE `.min(1)` and `.max()`, so both bounds measure the
    // stored value — the same construction the vault item schemas use, so the two
    // tag pickers cannot disagree about what a tag is.
    tags: z.array(z.string().trim().min(1).max(MAX_TAG_LENGTH)).max(MAX_DOCUMENT_TAGS),
    note: z.string().max(MAX_DOCUMENT_NOTE_LENGTH).optional(),
    transform: documentTransformSchema.optional(),
    capturedAt: z.iso.datetime().max(MAX_DOCUMENT_TIMESTAMP_LENGTH),
  })
  .refine(hasConsistentFraming, {
    message: DOCUMENT_FRAMING_MISMATCH_MESSAGE,
    path: ['chunkCount'],
  })
  // The BYTE budget, checked on the parsed object because that is what gets
  // sealed. It runs in both directions on purpose: it is the one bound whose
  // units differ from every field bound above it, so leaving it to a caller is
  // leaving it to be forgotten.
  .refine((meta) => documentMetaJsonByteLength(meta) <= MAX_DOCUMENT_META_JSON_BYTES, {
    message: DOCUMENT_META_TOO_LARGE_MESSAGE,
  });

// ---------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------

/** The message {@link initDocumentUploadSchema} reports when the declared framing disagrees. */
export const DOCUMENT_DECLARED_FRAMING_MESSAGE =
  'declaredChunkCount must equal ceil(declaredPlaintextBytes / the server chunk size), and at least 1';

// Three field groups that more than one schema carries, declared once each.
//
// This is the same "one definition per rule" reason the framing derivation is a
// function: the DEK trio crosses the wire twice (at init and again at completion,
// which is what makes a stale-version 409 recoverable), the two plaintext framing
// fields appear on the init body and on both row shapes, and the declared sizes
// appear on the init body and on the staging row that echoes it back. Written out
// per schema they were a copy-paste block, and a bound edited in one copy and not
// the other is a document that uploads and will not open.

/** The wrapped document key, as it crosses the wire at init and again at completion. */
const wrappedDekFields = {
  encryptedDek: z.string().min(1).max(200),
  dekIv: z.string().min(1).max(24),
  dekTag: z.string().min(1).max(32),
};

/** The two plaintext framing fields, pinned to their exact byte counts. */
const streamFramingFields = {
  streamSalt: base64OfBytes(DOCUMENT_STREAM_SALT_BYTES, 'streamSalt'),
  noncePrefix: base64OfBytes(DOCUMENT_NONCE_PREFIX_BYTES, 'noncePrefix'),
};

/**
 * What the client DECLARES about a transfer before it starts.
 *
 * There is no second `.max()` on `declaredPlaintextBytes`: the count bounds it
 * through the framing refine, and a second bound is a second thing to drift. The
 * operator's own size cap is enforced server-side, where it is configured.
 */
const declaredUploadFields = {
  declaredPlaintextBytes: z.number().int().min(0),
  declaredChunkCount: z.number().int().min(1).max(MAX_DOCUMENT_CHUNK_COUNT),
};

/**
 * One document's leg of a vault-key rotation: the id, and the DEK rewrapped under
 * the NEW vault key.
 *
 * This is the whole reason the store uses envelope encryption. A rotation rewraps
 * 32 bytes per document instead of re-uploading the file, so it stays possible
 * once an account holds gigabytes, and no object in the bucket is read or written
 * by it at all.
 *
 * It lives in this module, beside `wrappedDekFields`, rather than in
 * `schemas/vault.ts` where `bulkReEncryptSchema` composes it: the three ciphertext
 * bounds are declared exactly once on the wire side, and a rotation entry that
 * restated them would be the second copy that drifts.
 */
export const documentKeyRewrapSchema = z.object({
  id: objectIdSchema,
  ...wrappedDekFields,
});

/**
 * `POST /documents/uploads`: the wrapped DEK, the plaintext framing fields and the
 * declared size.
 *
 * Three things are deliberately absent. `chunkPlaintextBytes` is set by the SERVER
 * from its own constant and returned in the response, so a client cannot choose
 * its own framing. `vaultKeyVersion` is READ by the server from its own counter,
 * not declared here, and returned as an OBSERVATION of the account's generation
 * when the transfer opened — the completion is emphatically NOT checked against
 * that echo, but against the number the CLIENT sends, which is the only one that
 * says which vault key the client actually wrapped with. `objectKey` is
 * server-assigned and never client-supplied.
 */
export const initDocumentUploadSchema = z
  .object({
    ...wrappedDekFields,
    ...streamFramingFields,
    ...declaredUploadFields,
    folderId: objectIdSchema.optional(),
  })
  .refine(
    (data) =>
      hasConsistentFraming({
        plaintextBytes: data.declaredPlaintextBytes,
        chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
        chunkCount: data.declaredChunkCount,
      }),
    { message: DOCUMENT_DECLARED_FRAMING_MESSAGE, path: ['declaredChunkCount'] },
  );

/**
 * `POST /documents/uploads/:id/complete`: the sealed metadata AND the wrapped DEK
 * again.
 *
 * Sending the DEK a second time is what makes a stale-version 409 recoverable.
 * The staging row's copy is wrapped under whatever vault key was current at init;
 * `PUT /documents/:id` is walled off from the DEK by its own allowlist; and
 * re-initiating would mint a NEW upload id, which is bound into every HKDF `info`
 * and would therefore require re-encrypting every segment. So on a 409 the client
 * re-reads its profile, rewraps the DEK it still holds in memory under the new
 * vault key and retries THIS request alone, without re-sending a byte of the file.
 */
export const completeDocumentUploadSchema = z.object({
  encryptedMeta: z.string().min(1).max(MAX_ENCRYPTED_DOCUMENT_META_LENGTH),
  metaIv: z.string().min(1).max(24),
  metaTag: z.string().min(1).max(32),
  ...wrappedDekFields,
  vaultKeyVersion: z.number().int().min(0),
});

/**
 * `PUT /documents/:id`: the metadata blob, the favorite flag and the folder.
 *
 * Content is immutable after upload, so this schema cannot reach a framing field,
 * the DEK or the object key — a segment is never rewritten, which is what
 * guarantees a nonce is never reused under a stream key. Replacing bytes means a
 * new document. The server applies the same allowlist independently; this is the
 * wire half of it.
 */
export const updateDocumentSchema = z
  .object({
    encryptedMeta: z.string().min(1).max(MAX_ENCRYPTED_DOCUMENT_META_LENGTH).optional(),
    metaIv: z.string().min(1).max(24).optional(),
    metaTag: z.string().min(1).max(32).optional(),
    favorite: z.boolean().optional(),
    folderId: objectIdSchema.nullable().optional(),
  })
  .refine(
    (data) => {
      const hasMeta = data.encryptedMeta !== undefined;
      const hasIv = data.metaIv !== undefined;
      const hasTag = data.metaTag !== undefined;
      return hasMeta === hasIv && hasIv === hasTag;
    },
    { message: 'encryptedMeta, metaIv, and metaTag must all be provided together or all omitted' },
  );

// ---------------------------------------------------------------------------
// Query and path parameters
// ---------------------------------------------------------------------------

/**
 * `GET /documents`. No `name` sort: the name lives inside the encrypted blob, so
 * the server cannot order by it. No `trash` flag either — trashed documents have
 * their own route, exactly as trashed items do.
 */
export const listDocumentsSchema = paginationSchema.extend({
  folderId: objectIdSchema.optional(),
  // `z.stringbool()`, never `z.coerce.boolean()`: the latter is `Boolean(input)`,
  // which makes `?favorite=false` mean true. See `listVaultItemsSchema`.
  favorite: z.stringbool().optional(),
  sortBy: z.enum(['createdAt', 'updatedAt', 'favorite']).default('updatedAt'),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),
});

/** `GET /documents/trash`, mirroring `listTrashSchema`. */
export const listDocumentTrashSchema = paginationSchema.extend({
  sortBy: z.enum(['deletedAt', 'createdAt', 'updatedAt']).default('deletedAt'),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),
});

/**
 * A decimal integer path segment.
 *
 * NOT `z.coerce.number()`, which is `Number(value)` and therefore accepts `0x10`
 * as 16, `1e3` as 1000, `' 1 '` as 1 and `''` as **0** — four ways to address a
 * segment other than the one the URL appears to name. This admits canonical
 * decimal digits only, with no leading zero, and the range check runs on the
 * parsed number.
 */
const pathInteger = (label: string, min: number, max: number): z.ZodType<number, string> =>
  z
    .string()
    .regex(/^(0|[1-9]\d*)$/, `${label} must be a decimal integer`)
    .transform(Number)
    .pipe(z.number().int().min(min).max(max));

/**
 * `PUT /documents/uploads/:id/parts/:partNumber`.
 *
 * `id` is declared here even though `validateObjectId` also checks it, and that is
 * load-bearing rather than redundant: `validate()` REPLACES `req.params` wholesale
 * through `Object.defineProperty`, and `z.object()` strips by default, so a schema
 * naming only `partNumber` would DELETE `id` from the request and the controller
 * would read `undefined`.
 *
 * Part numbers are 1-based, because S3 part numbers are.
 */
export const documentPartParamsSchema = z.object({
  id: objectIdSchema,
  partNumber: pathInteger('partNumber', 1, MAX_DOCUMENT_CHUNK_COUNT),
});

/**
 * `GET /documents/:id/segments/:index`. Same `id`-must-be-declared rule as
 * {@link documentPartParamsSchema}.
 *
 * Segment indices are 0-based (they are the counter inside the AEAD nonce), so the
 * last addressable index is one below the chunk ceiling. Whether the index is
 * within THIS document's `chunkCount` is a row lookup and stays in the controller.
 */
export const documentSegmentParamsSchema = z.object({
  id: objectIdSchema,
  index: pathInteger('index', 0, MAX_DOCUMENT_CHUNK_COUNT - 1),
});

// ---------------------------------------------------------------------------
// API response validation (pre-decryption shape check)
// ---------------------------------------------------------------------------

/** The message {@link documentResponseSchema} reports when the two size columns disagree. */
export const DOCUMENT_CIPHERTEXT_SIZE_MISMATCH_MESSAGE =
  'ciphertextBytes must equal plaintextBytes plus one authentication tag per segment';

/**
 * A document row as the API sends it, validated BEFORE anything is decrypted, in
 * the spirit of `vaultItemResponseSchema`.
 *
 * `userId` and `objectKey` are intentionally absent: the row's `toJSON` strips
 * both, and a schema that required either would refuse every real response.
 *
 * The two refines are arithmetic identities the server itself establishes at
 * completion (`ciphertextBytes` is the sum of the part sizes, `chunkCount` their
 * count, and `plaintextBytes` is `ciphertextBytes - DOCUMENT_TAG_BYTES *
 * chunkCount`), so they cost nothing when the server is right and they are the
 * client's only chance to notice when it is not. They check the row against
 * ITSELF; comparing the row with the authenticated copy inside the metadata blob
 * is a separate, mandatory step and belongs to the code that holds the DEK.
 */
export const documentResponseSchema = z
  .object({
    _id: documentIdSchema,
    folderId: z.string().optional(),
    favorite: z.boolean(),
    // Ciphertext fields carry no `.max()` here, like `vaultItemResponseSchema`:
    // this is a shape check on the way IN, and refusing an over-long field would
    // lock the user out of a document the write path already accepted.
    encryptedDek: z.string().min(1),
    dekIv: z.string().min(1),
    dekTag: z.string().min(1),
    // The framing fields ARE exact, because the client is about to derive keys
    // from them and a wrong length can only end in a decryption failure with no
    // explanation.
    ...streamFramingFields,
    encryptedMeta: z.string().min(1),
    metaIv: z.string().min(1),
    metaTag: z.string().min(1),
    chunkPlaintextBytes: z.number().int().positive(),
    chunkCount: z.number().int().min(1).max(MAX_DOCUMENT_CHUNK_COUNT),
    // A zero-byte document is still one segment, so the smallest possible object
    // is exactly one authentication tag.
    ciphertextBytes: z.number().int().min(DOCUMENT_TAG_BYTES),
    plaintextBytes: z.number().int().min(0),
    purgePending: z.boolean().optional(),
    deletedAt: z.string().optional(),
    createdAt: z.string().min(1),
    updatedAt: z.string().min(1),
  })
  .refine(hasConsistentFraming, {
    message: DOCUMENT_FRAMING_MISMATCH_MESSAGE,
    path: ['chunkCount'],
  })
  .refine(
    (row) => row.plaintextBytes === documentPlaintextBytesFor(row.ciphertextBytes, row.chunkCount),
    { message: DOCUMENT_CIPHERTEXT_SIZE_MISMATCH_MESSAGE, path: ['ciphertextBytes'] },
  );

/**
 * A staging upload row as `GET /documents/uploads` and `GET /documents/uploads/:id`
 * send it: enough for the UI to list an abandoned upload, and enough for a retry
 * to skip the parts the server already holds.
 *
 * The wrapped DEK is deliberately not in this shape. The client holds the DEK in
 * memory for the life of the upload, the server's copy is wrapped under whatever
 * key was current at init, and STRIP mode drops the field silently if a future
 * handler sends it anyway.
 *
 * This is the ONE shape in this file that carries no framing-consistency refine,
 * and the asymmetry is deliberate rather than an omission: the declared pair on a
 * staging row is whatever `initDocumentUploadSchema` already accepted, so a row
 * echoing an inconsistent pair back cannot exist without the init refine having
 * been bypassed. The three shapes that DO carry one each describe a committed
 * document, where the numbers were derived rather than merely echoed.
 */
export const documentUploadResponseSchema = z.object({
  _id: documentIdSchema,
  folderId: z.string().optional(),
  ...streamFramingFields,
  ...declaredUploadFields,
  chunkPlaintextBytes: z.number().int().positive(),
  vaultKeyVersion: z.number().int().min(0),
  parts: z
    .array(
      z.object({
        partNumber: z.number().int().min(1).max(MAX_DOCUMENT_CHUNK_COUNT),
        // Every stored part is one sealed segment, so it is at least a tag and at
        // most a full ciphertext chunk. Both bounds are the framing constants
        // rather than round numbers.
        bytes: z.number().int().min(DOCUMENT_TAG_BYTES).max(DOCUMENT_CIPHERTEXT_CHUNK_BYTES),
      }),
    )
    .max(MAX_DOCUMENT_CHUNK_COUNT),
  receivedBytes: z.number().int().min(0),
  createdAt: z.string().min(1),
  expiresAt: z.string().min(1),
});

/**
 * The response to `POST /documents/uploads`. `uploadId` is the FUTURE document id,
 * which is what lets the client bind its HKDF `info` to the document before it
 * seals the first byte.
 */
export const initDocumentUploadResponseSchema = z.object({
  uploadId: documentIdSchema,
  vaultKeyVersion: z.number().int().min(0),
  chunkPlaintextBytes: z.number().int().positive(),
});

/**
 * `GET /documents/usage`. Trashed documents still occupy their object and still
 * count against `usedBytes`, which is why the UI has to be able to say so.
 */
export const documentUsageResponseSchema = z.object({
  documentCount: z.number().int().min(0),
  usedBytes: z.number().int().min(0),
  quotaBytes: z.number().int().positive(),
  maxDocumentSizeBytes: z.number().int().positive(),
});
