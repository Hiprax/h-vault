/**
 * documentCryptoService — the envelope and stream cryptography of the encrypted
 * document store, in the browser, on Web Crypto alone.
 *
 * Everything a document is made of is sealed here before a byte leaves the
 * machine. The server stores ciphertext, a wrapped key and three plaintext
 * framing values; it never sees the file, its name, its type, its tags or its
 * note.
 *
 * The key hierarchy, per document (the document id is the upload id, known
 * before the first byte is sealed, which is what lets every derivation be bound
 * to it):
 *
 *   DEK        = 32 random bytes
 *   WK         = HKDF-SHA256(ikm = raw vault key, salt = empty,
 *                            info = "hvault/doc/dek-wrap/v1|" || documentId, 256)
 *   wrapped    = AES-256-GCM(WK, dekIv, DEK)   -> { encryptedDek, dekIv, dekTag }
 *
 *   streamSalt = 32 random bytes   stored in PLAINTEXT on the row (a salt is not a secret)
 *   noncePrefix=  7 random bytes   stored in PLAINTEXT on the row
 *
 *   SK_stream  = HKDF-SHA256(ikm = DEK, salt = streamSalt,
 *                            info = "hvault/doc/stream/v1|" || documentId, 256)
 *   SK_meta    = HKDF-SHA256(ikm = DEK, salt = streamSalt,
 *                            info = "hvault/doc/meta/v1|"   || documentId, 256)
 *
 *   iv(i, isLast) = noncePrefix(7) || u32be(i) || (isLast ? 0x01 : 0x00)   // 12 bytes
 *   segment_i     = AES-256-GCM(SK_stream, iv(i, i === chunkCount - 1), plaintext slice)
 *   metadataBlob  = AES-256-GCM(SK_meta, metaIv, utf8(JSON.stringify(meta)))
 *
 * Four properties follow from putting the position INSIDE the nonce and the
 * document id inside every `info`, and each of them is a thing a hostile server
 * would otherwise be able to do undetectably: reorder segments (the index is in
 * the nonce), truncate a file (the last-segment flag is in the nonce),
 * substitute a segment or a whole document from another one (the id is in every
 * derivation, the DEK wrap included), or swap the plaintext framing values on
 * the row (a substituted salt or prefix derives a different key and fails to
 * open). None of that is detected after the fact: it simply does not decrypt.
 *
 * Three deliberate refusals to reuse code, each of which would be a defect:
 *
 *   - NOT `cryptoService.encryptData` / `decryptData`. Those run a `TextEncoder`
 *     and a `TextDecoder` over their payload, which is correct for the vault's
 *     JSON and catastrophic for a file: every byte sequence that is not valid
 *     UTF-8 comes back as U+FFFD, so a PNG, a PDF or a ZIP would round-trip to
 *     something that is not the file the user uploaded. A round-trip test over
 *     deliberately invalid UTF-8 pins this.
 *   - NOT `arrayBufferToBase64` for a segment. A segment is 8 MiB of binary that
 *     is uploaded as `application/octet-stream`; base64 would inflate it by a
 *     third and buy nothing. Base64 appears here only where the STORED shape is
 *     a string: the wrapped DEK and the sealed metadata blob.
 * **One obligation this module CANNOT enforce, so it is stated here.** A segment
 * nonce is derived, not random: `(streamKey, index, isLast)` determines it
 * completely. So a given triple may be sealed AT MOST ONCE, and a retry must
 * re-send bytes the caller still holds rather than re-reading them from disk. Two
 * different plaintexts under one AES-GCM nonce is the catastrophic case — it
 * hands an attacker the XOR of the two and a path to the authentication subkey,
 * which is a different order of failure from a segment that merely will not open.
 * The design's answer is that content is immutable after upload and that a
 * retried part re-encrypts the identical in-memory slice; the uploading store
 * owns that, and it is why the DEK is memory-only.
 *
 *   - NOT a second base64 or key-zeroing implementation. Those live in
 *     `cryptoService` and are called from here, because one definition per rule
 *     outranks the (real, but different) reason the two cipher paths are
 *     separate. Nothing else on that module is used, and nothing here imports a
 *     store.
 */

import {
  DOCUMENT_DEK_WRAP_INFO_PREFIX,
  DOCUMENT_META_INFO_PREFIX,
  DOCUMENT_NONCE_PREFIX_BYTES,
  DOCUMENT_STREAM_INFO_PREFIX,
  DOCUMENT_TAG_BYTES,
  documentMetaSchema,
  objectIdSchema,
} from '@hvault/shared';
import type { DocumentMeta } from '@hvault/shared';
import { cryptoService } from './cryptoService';

/**
 * The Data Encryption Key's length. A local constant rather than a shared one,
 * exactly as `cryptoService` keeps `VAULT_KEY_BYTES`: this is the size of a key
 * this module mints and consumes, not a bound any other package validates.
 */
const DEK_BYTES = 32;

/** Every key derived here is a 256-bit AES-GCM key. */
const DERIVED_KEY_BITS = 256;

/**
 * AES-GCM's IV, for every seal in this module, and the offsets at which the
 * segment nonce packs its index and its last-segment flag into it after the
 * prefix.
 *
 * Named for the primitive rather than for the segment because the metadata blob
 * and the DEK wrap use the same 12 bytes, drawn at random instead of derived. The
 * wire schemas bound the stored `dekIv` and `metaIv` at 24 base64 characters, so
 * a longer IV here would not fail in AES-GCM (which accepts any length) but would
 * be refused by the completion endpoint, with the whole file already uploaded.
 */
const IV_BYTES = 12;
const SEGMENT_INDEX_OFFSET = DOCUMENT_NONCE_PREFIX_BYTES;
const SEGMENT_FLAG_OFFSET = IV_BYTES - 1;

/**
 * The largest segment index the nonce can hold, because the index occupies four
 * big-endian bytes. `MAX_DOCUMENT_CHUNK_COUNT` is four orders of magnitude below
 * it, so this is not a limit anyone reaches; it is the point past which
 * `setUint32` would silently wrap and two different segments would share a
 * nonce.
 */
const MAX_SEGMENT_INDEX = 0xff_ff_ff_ff;

/** The last-segment flag, the byte that makes a truncated file fail to open. */
const LAST_SEGMENT_FLAG = 0x01;
const NOT_LAST_SEGMENT_FLAG = 0x00;

/**
 * A `Uint8Array` backed by a real `ArrayBuffer`.
 *
 * The annotation is not decoration. Since TypeScript made the typed arrays
 * generic over their buffer, `BufferSource` — what every SubtleCrypto call
 * accepts — is `ArrayBufferView<ArrayBuffer>`, and a bare `Uint8Array` widens to
 * `Uint8Array<ArrayBufferLike>`, which admits a `SharedArrayBuffer` and is
 * therefore NOT assignable to it. Naming the exact shape once here keeps every
 * signature in this module honest without a cast or a defensive copy of an 8 MiB
 * segment.
 */
export type DocumentBytes = Uint8Array<ArrayBuffer>;

/** The wrapped document key, in the shape the row and the wire both use. */
export interface WrappedDocumentKey {
  encryptedDek: string;
  dekIv: string;
  dekTag: string;
}

/** The sealed metadata blob, in the shape the row and the wire both use. */
export interface SealedDocumentMeta {
  encryptedMeta: string;
  metaIv: string;
  metaTag: string;
}

/**
 * Where a segment sits in its document: the row's nonce prefix, the segment's
 * own index, and whether it is the final one.
 *
 * One object rather than three positional parameters on purpose. `index` and
 * `isLast` are the two values that MUST agree between the seal and the open, and
 * a call site that transposes them, or that passes `isLast` for a segment that
 * is not the last, produces a document that uploads and never opens again. A
 * named field cannot be transposed.
 */
export interface SegmentFraming {
  noncePrefix: DocumentBytes;
  index: number;
  isLast: boolean;
}

/** 32 fresh random bytes: one document's Data Encryption Key. */
export function generateDek(): DocumentBytes {
  return globalThis.crypto.getRandomValues(new Uint8Array(DEK_BYTES));
}

/**
 * Overwrite a DEK's bytes.
 *
 * Called when an upload ends, is cancelled, or the vault locks. Best effort, in
 * the same sense `cryptoService.clearKey` is: JavaScript cannot promise the
 * runtime kept no copy. What it does guarantee is that the buffer the uploads
 * registry holds stops being a key, which is the difference between a lock that
 * secures the vault and one that leaves a key that decrypts user plaintext
 * resident for as long as the tab lives.
 */
export function zeroDek(dek: DocumentBytes): void {
  dek.fill(0);
}

/**
 * The document id, normalized.
 *
 * It is validated rather than trusted because it is an input to every `info`
 * string, and the domain separation those strings provide rests on the claim
 * that the trailing `|` cannot appear in the id. Parsing it as an ObjectId is
 * what makes that claim structurally true instead of merely likely.
 *
 * The shared schema also LOWERCASES, which matters: `deriveWrapKey` for
 * `66C0…` and for `66c0…` name the same document, so they must derive the same
 * key. `updateFolder` learned the same lesson the hard way, by lowercasing its
 * `:id` at the top of the handler.
 */
function normalizeDocumentId(documentId: string): string {
  const parsed = objectIdSchema.safeParse(documentId);
  if (!parsed.success) {
    throw new Error('Document id must be a 24-character hex ObjectId');
  }
  return parsed.data;
}

/** A DEK that is not 32 bytes is a truncated or foreign key, never a shorter one. */
function assertDekLength(dek: DocumentBytes): void {
  if (dek.length !== DEK_BYTES) {
    throw new Error(`Document key must be exactly ${String(DEK_BYTES)} bytes`);
  }
}

/**
 * Derive one 256-bit AES-GCM key with HKDF-SHA256.
 *
 * The `info` is the purpose prefix concatenated with the document id, so the
 * three keys of one document are independent of each other AND of every other
 * document's. The derived key is NON-extractable: nothing here needs its raw
 * bytes, and a key that cannot be exported cannot be exfiltrated by anything
 * that reaches the reference. The DEK is the material `zeroDek` clears.
 */
async function deriveDocumentKey(
  ikm: BufferSource,
  salt: BufferSource,
  infoPrefix: string,
  documentId: string,
): Promise<CryptoKey> {
  const base = await globalThis.crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await globalThis.crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info: new TextEncoder().encode(`${infoPrefix}${documentId}`),
    },
    base,
    DERIVED_KEY_BITS,
  );
  try {
    return await globalThis.crypto.subtle.importKey(
      'raw',
      bits,
      { name: 'AES-GCM', length: DERIVED_KEY_BITS },
      false,
      ['encrypt', 'decrypt'],
    );
  } finally {
    cryptoService.clearKey(bits);
  }
}

/**
 * The key that wraps ONE document's DEK, derived from the vault key and bound to
 * the document id.
 *
 * Binding the wrap to the document, rather than only to the account, is what
 * stops a hostile server from moving a wrapped key from one row to another. The
 * empty salt is RFC 5869 compliant here because the input keying material is
 * already a uniformly random 256-bit key, which is the same reasoning
 * `cryptoService`'s backup subkeys record.
 *
 * The vault key's raw bytes are needed as HKDF input material. It is already
 * imported as extractable and is already exported on every vault save and by
 * `vaultKeyEqualsRaw`, so this adds no exposure; the exported copy is zeroed in
 * `finally` either way.
 */
export async function deriveWrapKey(vaultKey: CryptoKey, documentId: string): Promise<CryptoKey> {
  const id = normalizeDocumentId(documentId);
  const rawVaultKey = await globalThis.crypto.subtle.exportKey('raw', vaultKey);
  try {
    return await deriveDocumentKey(
      rawVaultKey,
      new Uint8Array(0),
      DOCUMENT_DEK_WRAP_INFO_PREFIX,
      id,
    );
  } finally {
    cryptoService.clearKey(rawVaultKey);
  }
}

/**
 * The per-document stream key: what every segment of the file is sealed under.
 *
 * `streamSalt` is deliberately NOT length-checked. It is read back from the row,
 * and the read path is bound to what a document was stored with rather than to
 * today's constants — the same reason decryption reads `chunkPlaintextBytes`
 * from the row and never from `DOCUMENT_PLAINTEXT_CHUNK_BYTES`. A substituted
 * salt of any length simply derives a different key, and every segment then
 * fails to open, which is the behaviour that matters.
 */
export async function deriveStreamKey(
  dek: DocumentBytes,
  streamSalt: DocumentBytes,
  documentId: string,
): Promise<CryptoKey> {
  assertDekLength(dek);
  return deriveDocumentKey(
    dek,
    streamSalt,
    DOCUMENT_STREAM_INFO_PREFIX,
    normalizeDocumentId(documentId),
  );
}

/**
 * The per-document metadata key: what the name, type, tags and note are sealed
 * under. Derived from the same inputs as the stream key and separated only by
 * its `info`, so the metadata blob does not open under the stream key and vice
 * versa.
 */
export async function deriveMetaKey(
  dek: DocumentBytes,
  streamSalt: DocumentBytes,
  documentId: string,
): Promise<CryptoKey> {
  assertDekLength(dek);
  return deriveDocumentKey(
    dek,
    streamSalt,
    DOCUMENT_META_INFO_PREFIX,
    normalizeDocumentId(documentId),
  );
}

/**
 * Seal binary input under a fresh random IV, split into the three base64 fields
 * the row stores.
 *
 * The IV is generated HERE and the function takes none. For the metadata blob
 * that is the single most important line in this module (see {@link encryptMeta});
 * for the DEK wrap it is simply the same rule applied once.
 */
async function sealToFields(
  key: CryptoKey,
  plaintext: BufferSource,
): Promise<{ encrypted: string; iv: string; tag: string }> {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const sealed = new Uint8Array(
    await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: DOCUMENT_TAG_BYTES * 8 },
      key,
      plaintext,
    ),
  );
  const ciphertext = sealed.slice(0, sealed.length - DOCUMENT_TAG_BYTES);
  const tag = sealed.slice(sealed.length - DOCUMENT_TAG_BYTES);
  return {
    encrypted: cryptoService.arrayBufferToBase64(ciphertext.buffer),
    iv: cryptoService.arrayBufferToBase64(iv.buffer),
    tag: cryptoService.arrayBufferToBase64(tag.buffer),
  };
}

/**
 * Open the three base64 fields back into bytes. Throws — and returns nothing at
 * all — when the tag does not verify, which is what makes every stored document
 * tamper-evident rather than merely encrypted.
 */
async function openFromFields(
  key: CryptoKey,
  fields: { encrypted: string; iv: string; tag: string },
): Promise<DocumentBytes> {
  const ciphertext = new Uint8Array(cryptoService.base64ToArrayBuffer(fields.encrypted));
  const iv = new Uint8Array(cryptoService.base64ToArrayBuffer(fields.iv));
  const tag = new Uint8Array(cryptoService.base64ToArrayBuffer(fields.tag));

  const sealed = new Uint8Array(ciphertext.length + tag.length);
  sealed.set(ciphertext, 0);
  sealed.set(tag, ciphertext.length);

  return new Uint8Array(
    await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, tagLength: DOCUMENT_TAG_BYTES * 8 },
      key,
      sealed,
    ),
  );
}

/** Wrap a DEK under a document-bound wrapping key, for the row and the wire. */
export async function wrapDek(dek: DocumentBytes, wrapKey: CryptoKey): Promise<WrappedDocumentKey> {
  assertDekLength(dek);
  const { encrypted, iv, tag } = await sealToFields(wrapKey, dek);
  return { encryptedDek: encrypted, dekIv: iv, dekTag: tag };
}

/**
 * Unwrap a DEK. Rejects when the wrapping key belongs to another document,
 * another vault key or another account, because all three change the derived
 * key and none of them can forge the tag.
 */
export async function unwrapDek(
  wrapped: WrappedDocumentKey,
  wrapKey: CryptoKey,
): Promise<DocumentBytes> {
  const dek = await openFromFields(wrapKey, {
    encrypted: wrapped.encryptedDek,
    iv: wrapped.dekIv,
    tag: wrapped.dekTag,
  });
  // Authenticated, so a wrong length here means this client wrote it wrong
  // rather than that an attacker changed it — and a short key is exactly the
  // kind of wrongness that would otherwise keep working.
  assertDekLength(dek);
  return dek;
}

/**
 * The 12-byte segment nonce: `noncePrefix(7) || u32be(index) || flag(1)`.
 *
 * Every part of it is load-bearing. The prefix is per document, so two
 * documents never share a nonce even though they never share a key either. The
 * index is BIG-endian and occupies its own four bytes, so segment 3 cannot be
 * replayed as segment 300. The flag is what makes truncation visible: the final
 * segment is sealed under a nonce no other segment can have, so a server that
 * drops it leaves a previously-non-final segment that will not open as the last
 * one.
 */
function segmentIv(framing: SegmentFraming): DocumentBytes {
  if (framing.noncePrefix.length !== DOCUMENT_NONCE_PREFIX_BYTES) {
    // AES-GCM accepts an IV of ANY length, so a prefix of the wrong size would
    // not fail here — it would quietly produce a different framing that this
    // client could still read back and no other implementation could.
    throw new Error(
      `Document nonce prefix must be exactly ${String(DOCUMENT_NONCE_PREFIX_BYTES)} bytes`,
    );
  }
  if (!Number.isInteger(framing.index) || framing.index < 0 || framing.index > MAX_SEGMENT_INDEX) {
    throw new Error(`Document segment index must be an integer in 0..${String(MAX_SEGMENT_INDEX)}`);
  }

  const iv = new Uint8Array(IV_BYTES);
  iv.set(framing.noncePrefix, 0);
  new DataView(iv.buffer).setUint32(SEGMENT_INDEX_OFFSET, framing.index, false);
  iv[SEGMENT_FLAG_OFFSET] = framing.isLast ? LAST_SEGMENT_FLAG : NOT_LAST_SEGMENT_FLAG;
  return iv;
}

/**
 * Seal one segment. The result is `ciphertext || tag`, exactly as it is uploaded
 * and exactly as it is stored: the object in the bucket is the pure
 * concatenation of these, so one crypto segment is one uploaded part is one
 * downloaded range and there is no mapping table between the three to get wrong.
 *
 * Binary in, binary out: no base64, no `TextEncoder`. A byte sequence that is
 * not valid UTF-8 is the normal case here, not an edge case.
 *
 * The caller owns the rule this function cannot check: one `(index, isLast)` pair
 * is sealed at most once per stream key, over bytes it still holds. See the
 * module header.
 */
export async function encryptSegment(
  streamKey: CryptoKey,
  framing: SegmentFraming,
  plaintext: DocumentBytes,
): Promise<DocumentBytes> {
  const iv = segmentIv(framing);
  return new Uint8Array(
    await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: DOCUMENT_TAG_BYTES * 8 },
      streamKey,
      plaintext,
    ),
  );
}

/**
 * Open one segment, or throw and return nothing.
 *
 * There is no partial-plaintext path and there must never be one: the tag is
 * checked before any byte is handed back, so a flipped bit, a reordered
 * segment, a dropped final segment, a substituted salt or prefix, a foreign
 * document id and a foreign DEK all end here, in a rejection.
 */
export async function decryptSegment(
  streamKey: CryptoKey,
  framing: SegmentFraming,
  ciphertext: DocumentBytes,
): Promise<DocumentBytes> {
  if (ciphertext.length < DOCUMENT_TAG_BYTES) {
    // A segment is at least its own tag (a zero-byte document is one segment of
    // exactly DOCUMENT_TAG_BYTES). Anything shorter is a truncated response, and
    // saying so beats the engine's generic operation failure.
    throw new Error(`Document segment must be at least ${String(DOCUMENT_TAG_BYTES)} bytes`);
  }
  const iv = segmentIv(framing);
  return new Uint8Array(
    await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, tagLength: DOCUMENT_TAG_BYTES * 8 },
      streamKey,
      ciphertext,
    ),
  );
}

/**
 * Seal the document metadata — the name, MIME type, extension, size, digest,
 * framing, tags, note and transform provenance the server is never allowed to
 * see.
 *
 * **`metaIv` is generated here and this function accepts none.** That is the one
 * place in this design where a nonce could repeat under a fixed key, and the
 * immutability of the file's content does not cover it: `SK_meta` is
 * deterministic in (DEK, streamSalt, documentId) and is therefore fixed for the
 * document's whole life, while the metadata blob is deliberately MUTABLE — a
 * rename re-seals it. Two seals under one key with one IV hand anyone holding
 * both ciphertexts the XOR of the two plaintexts and a path to the
 * authentication subkey, so an IV parameter is a defect waiting for a caller
 * that reuses one, and the only way to make it unreachable is not to have it.
 *
 * The metadata is validated by the shared schema on the way in, and again on the
 * way out, because the sealed blob is the only copy: an object that is one field
 * over its bound would otherwise be stored and then refuse to load. The PARSED
 * object is what gets serialized, so the schema's byte budget measures exactly
 * the bytes this seals.
 */
export async function encryptMeta(
  metaKey: CryptoKey,
  meta: DocumentMeta,
): Promise<SealedDocumentMeta> {
  const validated = documentMetaSchema.parse(meta);
  const json = new TextEncoder().encode(JSON.stringify(validated));
  const { encrypted, iv, tag } = await sealToFields(metaKey, json);
  return { encryptedMeta: encrypted, metaIv: iv, metaTag: tag };
}

/**
 * Open the metadata blob and validate it.
 *
 * Three ways this refuses, all of them loud: the tag does not verify (a foreign
 * key, a tampered blob, or the stream key, which does not open it either); the
 * plaintext is not well-formed UTF-8; or the JSON does not satisfy the shared
 * schema.
 *
 * A document whose metadata will not open is rendered as undecodable, offering
 * move, favorite, trash, restore and permanent delete — never a document with a
 * guessed name, and never a RENAME. That last part is where a document differs
 * from an undecodable vault item, whose name is a separate ciphertext field it
 * can be given back: a document's name, type, size, tags, note and whole-file
 * checksum all live inside this one blob, so there is nothing to rewrite and no
 * key to rewrite it with. Sealing a fresh blob would be worse than refusing —
 * its framing could only be copied off the very row a reader is required to
 * check it against, which would make that check a tautology for this document
 * for ever, and its checksum would have to be invented.
 */
export async function decryptMeta(
  metaKey: CryptoKey,
  sealed: SealedDocumentMeta,
): Promise<DocumentMeta> {
  const bytes = await openFromFields(metaKey, {
    encrypted: sealed.encryptedMeta,
    iv: sealed.metaIv,
    tag: sealed.metaTag,
  });
  // `fatal: true` rather than the default: a lone surrogate or a stray
  // continuation byte would otherwise be replaced by U+FFFD and either parse as
  // a plausible name or fail somewhere less obvious than here.
  const json = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  return documentMetaSchema.parse(JSON.parse(json));
}
