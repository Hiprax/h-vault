/**
 * Shared driver for the three document-crypto suites (the adversarial suite, the
 * committed vectors and the property run).
 *
 * It holds what a CALLER of `documentCryptoService` has to do — walk a plaintext
 * in `chunkPlaintextBytes` slices, seal each one with its index and its
 * last-segment flag, and walk the segments back — plus the two assertions those
 * suites make over and over. Kept in one module for two reasons: three copies of
 * a chunking loop is exactly the duplication `deadcode`'s jscpd half measures,
 * and a refusal assertion that is subtly weaker in one file than in another is
 * how a fail-closed suite stops being one.
 *
 * The segment COUNT and the segment SIZES are never asserted here. Each suite
 * asserts those against `documentChunkCountFor` and against literals of its own,
 * so this driver cannot make a framing bug invisible by agreeing with it.
 */
import { expect } from 'vitest';
import {
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  DOCUMENT_TAG_BYTES,
  MAX_DOCUMENT_EXT_LENGTH,
  MAX_DOCUMENT_MIME_LENGTH,
  MAX_DOCUMENT_NAME_LENGTH,
  MAX_DOCUMENT_NOTE_LENGTH,
  MAX_DOCUMENT_TAGS,
  MAX_DOCUMENT_TRANSFORM_LABEL_LENGTH,
  MAX_TAG_LENGTH,
} from '@hvault/shared';
import type { DocumentMeta } from '@hvault/shared';
import {
  decryptSegment,
  encryptSegment,
  type DocumentBytes,
} from '../src/services/crypto/documentCryptoService';

/** 24 lower-case hex characters: the shape every document id has. */
export function documentId(seed: string): string {
  const hex = seed.replace(/[^0-9a-f]/g, '');
  return (hex + '0'.repeat(24)).slice(0, 24);
}

/**
 * `length` deterministic bytes.
 *
 * A seeded 32-bit LCG rather than `getRandomValues`, for two reasons that both
 * matter here: the suite's determinism contract wants a failing case to be
 * reproducible byte for byte, and `getRandomValues` refuses a request above
 * 65 536 bytes, which every multi-segment size in these suites exceeds. The
 * sequence is not uniform enough to be a key and is never used as one; it exists
 * so that two segments of one document differ, and so that a swapped or repeated
 * slice would be visible if the AEAD ever let one through.
 */
export function patternBytes(length: number, seed: number): DocumentBytes {
  const bytes = new Uint8Array(length);
  let state = seed >>> 0 || 1;
  for (let i = 0; i < length; i++) {
    state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
    bytes[i] = (state >>> 24) & 0xff;
  }
  return bytes;
}

/** Seal a whole plaintext into segments, the way an upload does. */
export async function sealDocument(
  streamKey: CryptoKey,
  noncePrefix: DocumentBytes,
  plaintext: DocumentBytes,
  chunkPlaintextBytes: number,
): Promise<DocumentBytes[]> {
  const chunkCount = Math.max(1, Math.ceil(plaintext.length / chunkPlaintextBytes));
  const segments: DocumentBytes[] = [];
  for (let index = 0; index < chunkCount; index++) {
    const slice = plaintext.slice(index * chunkPlaintextBytes, (index + 1) * chunkPlaintextBytes);
    segments.push(
      await encryptSegment(
        streamKey,
        { noncePrefix, index, isLast: index === chunkCount - 1 },
        slice,
      ),
    );
  }
  return segments;
}

/** Open a whole document, the way a download does, and concatenate the result. */
export async function openDocument(
  streamKey: CryptoKey,
  noncePrefix: DocumentBytes,
  segments: readonly DocumentBytes[],
): Promise<DocumentBytes> {
  const opened: DocumentBytes[] = [];
  for (let index = 0; index < segments.length; index++) {
    opened.push(
      await decryptSegment(
        streamKey,
        { noncePrefix, index, isLast: index === segments.length - 1 },
        segments[index]!,
      ),
    );
  }
  const total = opened.reduce((sum, part) => sum + part.length, 0);
  const plaintext = new Uint8Array(total);
  let offset = 0;
  for (const part of opened) {
    plaintext.set(part, offset);
    offset += part.length;
  }
  return plaintext;
}

/**
 * Byte-for-byte equality, asserted through a digest.
 *
 * `toEqual` over two 25 MB typed arrays is minutes of element-wise comparison, so
 * the size classes these suites exist to cover would be untestable with it. The
 * length is compared separately, so a prefix that happens to hash the same as a
 * longer buffer cannot pass — and SHA-256 makes the digest comparison as strong a
 * statement of identity as the element-wise one.
 */
export async function expectSameBytes(
  actual: DocumentBytes,
  expected: DocumentBytes,
  label: string,
): Promise<void> {
  expect(actual.length, `${label}: length`).toBe(expected.length);
  expect(await sha256Hex(actual), `${label}: digest`).toBe(await sha256Hex(expected));
}

/** Lower-case hex SHA-256, the digest form the metadata blob stores. */
export async function sha256Hex(bytes: DocumentBytes): Promise<string> {
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes));
  return Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Assert that an open REFUSES: it throws, and it hands the caller nothing.
 *
 * The second half is the one worth writing down. `rejects.toThrow()` alone would
 * still pass for an implementation that resolved with a partial plaintext and
 * threw afterwards, and "returns the bytes it managed to decrypt" is precisely
 * what an unauthenticated mode does. The sentinel proves the assignment never
 * happened.
 */
export async function expectRefusal(
  open: () => Promise<unknown>,
  expected: string | RegExp,
): Promise<void> {
  const sentinel = Symbol('never assigned');
  let leaked: unknown = sentinel;
  let thrown: unknown;
  try {
    leaked = await open();
  } catch (error) {
    thrown = error;
  }

  expect(leaked, 'a refused open must return nothing at all').toBe(sentinel);
  expect(thrown, 'a refused open must throw').toBeInstanceOf(Error);
  // The NAME is matched alongside the message, because that is what distinguishes
  // an authentication failure (`OperationError`) from a `TypeError` raised by a
  // typo in the test itself, and every AES-GCM failure carries a message too
  // uninformative to tell them apart on its own.
  const error = thrown as Error;
  expect(`${error.name}: ${error.message}`).toMatch(expected);
}

/**
 * What an AES-GCM tag failure looks like: an `OperationError` DOMException whose
 * message is deliberately uninformative.
 *
 * That silence is the design, not a shortcoming — a flipped byte, a reordered
 * segment, a truncated file, a substituted salt, a foreign document id and a
 * foreign key are indistinguishable to whoever caused them. So the NAME is what
 * these cases assert; matching only the message would let a `TypeError` from a
 * mistake in the test stand in for a real refusal.
 */
export const AEAD_REFUSAL = /^OperationError: /;

/** A metadata object that satisfies every bound in `documentMetaSchema`. */
export function metaFixture(overrides: Partial<DocumentMeta> = {}): DocumentMeta {
  return {
    name: 'quarterly-report.md',
    mime: 'text/markdown',
    ext: 'md',
    plaintextBytes: 6,
    sha256: 'a'.repeat(64),
    chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    chunkCount: 1,
    tags: ['work', 'finance'],
    note: 'Draft shared with the board.',
    capturedAt: '2026-08-31T12:34:56.789Z',
    ...overrides,
  };
}

/**
 * Seal arbitrary bytes under a key into the three base64 fields a row stores,
 * using SubtleCrypto directly.
 *
 * This is the suites' independent ORACLE, and it exists to build inputs the
 * service itself would never produce: a metadata blob holding invalid UTF-8, a
 * blob holding JSON that fails the schema, a wrapped key of the wrong length.
 * Those are the cases that prove the read path validates rather than trusts, and
 * they cannot be constructed through the service's own write path, which is
 * exactly what makes it worth writing this by hand once.
 */
export async function sealRaw(
  key: CryptoKey,
  bytes: DocumentBytes,
): Promise<{ encrypted: string; iv: string; tag: string }> {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const sealed = new Uint8Array(
    await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: DOCUMENT_TAG_BYTES * 8 },
      key,
      bytes,
    ),
  );
  const ciphertext = sealed.slice(0, sealed.length - DOCUMENT_TAG_BYTES);
  const tag = sealed.slice(sealed.length - DOCUMENT_TAG_BYTES);
  return {
    encrypted: toBase64(ciphertext),
    iv: toBase64(iv),
    tag: toBase64(tag),
  };
}

/** Standard padded base64 of a byte array, as `btoa` emits it. */
export function toBase64(bytes: DocumentBytes): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

/** Bytes from a lower-case hex string, for the committed vectors. */
export function fromHex(hex: string): DocumentBytes {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Open the three base64 fields with SubtleCrypto directly, WITHOUT the service.
 *
 * The inverse of {@link sealRaw}, and it exists for one question the service's
 * own read path cannot answer: what exactly did the write path SEAL? Both
 * `encryptMeta` and `decryptMeta` run the shared schema, so a normalization the
 * writer failed to apply would be applied again by the reader and the round trip
 * would look correct. Reading the sealed bytes here is what makes the difference
 * visible.
 */
export async function openRaw(
  key: CryptoKey,
  fields: { encrypted: string; iv: string; tag: string },
): Promise<string> {
  const ciphertext = fromBase64(fields.encrypted);
  const tag = fromBase64(fields.tag);
  const sealed = new Uint8Array(ciphertext.length + tag.length);
  sealed.set(ciphertext, 0);
  sealed.set(tag, ciphertext.length);

  const opened = await globalThis.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64(fields.iv), tagLength: DOCUMENT_TAG_BYTES * 8 },
    key,
    sealed,
  );
  return new TextDecoder('utf-8', { fatal: true }).decode(opened);
}

/**
 * Bytes from standard padded base64, as `atob` reads it.
 *
 * Not exported: `openRaw` above is its only caller, and the dead-code gate
 * reports an export nothing outside its own module reads.
 */
function fromBase64(base64: string): DocumentBytes {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Metadata whose every string field sits at its bound in THREE-BYTE characters:
 * the largest blob the shared schema can legally accept.
 *
 * It is built here rather than written out because that is the only honest way to
 * ask the question this fixture exists for — does the biggest metadata the write
 * pre-flight admits still fit the bound the WIRE schema puts on the stored
 * string? Those two bounds are a pair (`MAX_DOCUMENT_META_JSON_BYTES` counts
 * UTF-8 bytes; `MAX_ENCRYPTED_DOCUMENT_META_LENGTH` is its exact base64
 * expansion), and Section 1.5 records that the pair was wrong once already.
 */
export function worstCaseMetaFixture(): DocumentMeta {
  // U+4E2D: one UTF-16 code unit, which every field bound counts, and three UTF-8
  // bytes, which the blob's byte budget counts. That gap is the whole point.
  const wide = '中';
  return {
    name: wide.repeat(MAX_DOCUMENT_NAME_LENGTH),
    mime: wide.repeat(MAX_DOCUMENT_MIME_LENGTH),
    ext: wide.repeat(MAX_DOCUMENT_EXT_LENGTH),
    plaintextBytes: 6,
    sha256: 'a'.repeat(64),
    chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    chunkCount: 1,
    tags: Array.from({ length: MAX_DOCUMENT_TAGS }, () => wide.repeat(MAX_TAG_LENGTH)),
    note: wide.repeat(MAX_DOCUMENT_NOTE_LENGTH),
    transform: {
      formatted: true,
      repaired: true,
      tool: 'p'.repeat(MAX_DOCUMENT_TRANSFORM_LABEL_LENGTH),
      toolVersion: 'v'.repeat(MAX_DOCUMENT_TRANSFORM_LABEL_LENGTH),
      originalSha256: 'b'.repeat(64),
    },
    capturedAt: '2026-08-31T12:34:56.789Z',
  };
}
