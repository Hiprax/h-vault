/**
 * `documentCryptoService`, adversarially.
 *
 * A stored document is ciphertext in a bucket the server controls, framed by
 * three plaintext values on a row the server also controls. So the question this
 * suite answers is not "does it encrypt" but "what happens when the party
 * holding the ciphertext lies about it": if a hostile or broken server can
 * reorder segments, truncate a file, move a segment between documents or swap a
 * framing field and have the client accept the result, the AEAD framing bought
 * nothing.
 *
 * Two halves, and both are load-bearing:
 *
 *   - The SIZES. Every boundary the chunking arithmetic has — empty, one byte,
 *     exactly one segment, one byte over, two and three exact segments, and a
 *     remainder — with the segment count, the per-part sizes and the round trip
 *     asserted at each. An exact multiple of the plaintext chunk must produce NO
 *     phantom empty final segment, because a client that emits one and a server
 *     that rejects it disagree about a file that has already been uploaded.
 *   - The REFUSALS. Nine ways a document must fail to open, each of which is a
 *     real attack on a store whose bytes live somewhere the user does not
 *     control, plus the guards that turn a malformed call into a loud error
 *     rather than a differently-framed document.
 *
 * Every case here was measured before it was written (PLAN.md Section 1.3, 18/18
 * assertions on the framing prototype), so a red test in this file is a defect in
 * the implementation and never a surprising property of AES-GCM.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import {
  DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
  DOCUMENT_NONCE_PREFIX_BYTES,
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  DOCUMENT_STREAM_SALT_BYTES,
  DOCUMENT_TAG_BYTES,
  MAX_DOCUMENT_META_JSON_BYTES,
  MAX_DOCUMENT_NOTE_LENGTH,
  MAX_ENCRYPTED_DOCUMENT_META_LENGTH,
  completeDocumentUploadSchema,
  documentChunkCountFor,
  documentMetaJsonByteLength,
} from '@hvault/shared';
import type { DocumentMeta } from '@hvault/shared';
import { cryptoService } from '../src/services/crypto/cryptoService';
import {
  decryptMeta,
  decryptSegment,
  deriveMetaKey,
  deriveStreamKey,
  deriveWrapKey,
  encryptMeta,
  encryptSegment,
  generateDek,
  unwrapDek,
  wrapDek,
  zeroDek,
  type DocumentBytes,
} from '../src/services/crypto/documentCryptoService';
import {
  AEAD_REFUSAL,
  documentId,
  expectRefusal,
  expectSameBytes,
  metaFixture,
  openDocument,
  openRaw,
  patternBytes,
  sealDocument,
  sealRaw,
  toBase64,
  worstCaseMetaFixture,
} from './documentCryptoHarness';

/** The document under test, and a second one every cross-document case borrows from. */
const DOC_ID = documentId('66c0f1a2b3c4d5e6f7a8b9c0');
const OTHER_DOC_ID = documentId('66c0f1a2b3c4d5e6f7a8b9c1');

/**
 * The chunk size the refusal cases use.
 *
 * Deliberately NOT `DOCUMENT_PLAINTEXT_CHUNK_BYTES`: the service seals the slice
 * it is given and never reads that constant, because decryption frames a
 * document from the size stored on its own row. Sixty-four bytes therefore
 * exercises exactly the same code as eight mebibytes and leaves the suite fast
 * enough to state ten refusals instead of three.
 */
const SMALL_CHUNK = 64;

let vaultKey: CryptoKey;
let otherVaultKey: CryptoKey;
let dek: DocumentBytes;
let streamSalt: DocumentBytes;
let noncePrefix: DocumentBytes;
let streamKey: CryptoKey;
let metaKey: CryptoKey;

beforeAll(async () => {
  // Real vault keys through the real import path, exactly as `rotateVaultKey`
  // mints one. Not `deriveKeys`: 600k PBKDF2 iterations per call is not what
  // this suite is about.
  vaultKey = await cryptoService.importVaultKey(cryptoService.generateVaultKey());
  otherVaultKey = await cryptoService.importVaultKey(cryptoService.generateVaultKey());
  dek = generateDek();
  streamSalt = globalThis.crypto.getRandomValues(new Uint8Array(DOCUMENT_STREAM_SALT_BYTES));
  noncePrefix = globalThis.crypto.getRandomValues(new Uint8Array(DOCUMENT_NONCE_PREFIX_BYTES));
  streamKey = await deriveStreamKey(dek, streamSalt, DOC_ID);
  metaKey = await deriveMetaKey(dek, streamSalt, DOC_ID);
});

// ---------------------------------------------------------------------------
// The seven sizes
// ---------------------------------------------------------------------------

const P = DOCUMENT_PLAINTEXT_CHUNK_BYTES;

/**
 * The expected framing is written out as LITERALS and then cross-checked against
 * `documentChunkCountFor`. A table that computed its own expectations with the
 * same formula the code uses would agree with a broken formula.
 */
const SIZES = [
  { label: 'an empty document', bytes: 0, segments: 1, finalCiphertext: DOCUMENT_TAG_BYTES },
  { label: 'a single byte', bytes: 1, segments: 1, finalCiphertext: 1 + DOCUMENT_TAG_BYTES },
  {
    label: 'exactly one segment',
    bytes: P,
    segments: 1,
    finalCiphertext: DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
  },
  {
    label: 'one segment plus one byte',
    bytes: P + 1,
    segments: 2,
    finalCiphertext: 1 + DOCUMENT_TAG_BYTES,
  },
  {
    label: 'exactly two segments',
    bytes: 2 * P,
    segments: 2,
    finalCiphertext: DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
  },
  {
    label: 'exactly three segments',
    bytes: 3 * P,
    segments: 3,
    finalCiphertext: DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
  },
  {
    label: 'two segments plus a remainder',
    bytes: 2 * P + 1234,
    segments: 3,
    finalCiphertext: 1234 + DOCUMENT_TAG_BYTES,
  },
] as const;

describe('segment framing across every size boundary', () => {
  it.each(SIZES)(
    'round-trips $label byte-for-byte, in $segments segment(s)',
    async ({ bytes, segments: expectedSegments, finalCiphertext }) => {
      const plaintext = patternBytes(bytes, bytes + 1);
      const segments = await sealDocument(streamKey, noncePrefix, plaintext, P);

      // The literal and the shared derivation must agree, and that derivation is
      // what the server, the metadata blob and the download loop all use.
      expect(documentChunkCountFor(bytes, P)).toBe(expectedSegments);
      expect(segments).toHaveLength(expectedSegments);

      // Every NON-final part is exactly one ciphertext chunk. This is what makes
      // segment `i` start at `i * DOCUMENT_CIPHERTEXT_CHUNK_BYTES`, so a range
      // read needs no table, and it is what S3 requires of a multipart part.
      for (const part of segments.slice(0, -1)) {
        expect(part.length).toBe(DOCUMENT_CIPHERTEXT_CHUNK_BYTES);
      }

      // The final part is the remainder plus one tag. At an exact multiple that
      // is a FULL chunk, which is the assertion that rules out a phantom empty
      // final segment: an implementation that appended one would report
      // `expectedSegments + 1` above and 16 bytes here.
      const finalPart = segments[segments.length - 1]!;
      expect(finalPart.length).toBe(finalCiphertext);

      const totalCiphertext = segments.reduce((sum, part) => sum + part.length, 0);
      expect(totalCiphertext).toBe(bytes + DOCUMENT_TAG_BYTES * expectedSegments);

      await expectSameBytes(
        await openDocument(streamKey, noncePrefix, segments),
        plaintext,
        'round trip',
      );
    },
  );

  it('preserves bytes that are not valid UTF-8, which a string cipher would destroy', async () => {
    // The production change this test exists to catch: routing a segment through
    // `cryptoService.encryptData` / `decryptData`, which run a `TextEncoder` and
    // a `TextDecoder`. Each of these bytes — a NUL, two lone high bytes, a bare
    // continuation byte, a truncated two-byte sequence and the UTF-8 encoding of
    // a lone surrogate — comes back as U+FFFD through that path, so a PNG, a PDF
    // or a ZIP would download as something that is not the file that was
    // uploaded.
    const hostile = new Uint8Array([0x00, 0xff, 0xfe, 0x80, 0xc3, 0x28, 0xed, 0xa0, 0x80, 0x7f]);

    // The case can discriminate: a UTF-8 round trip really does change these
    // bytes. Without this line, a test asserting only equality would still pass
    // on a payload that happened to be valid UTF-8.
    const throughText = new TextEncoder().encode(new TextDecoder().decode(hostile));
    expect(Array.from(throughText)).not.toEqual(Array.from(hostile));

    const segments = await sealDocument(streamKey, noncePrefix, hostile, SMALL_CHUNK);
    const opened = await openDocument(streamKey, noncePrefix, segments);
    expect(Array.from(opened)).toEqual(Array.from(hostile));
  });
});

// ---------------------------------------------------------------------------
// The refusals
// ---------------------------------------------------------------------------

describe('a document that has been tampered with fails to open', () => {
  const PLAINTEXT_BYTES = 150;
  let plaintext: DocumentBytes;
  let segments: DocumentBytes[];

  beforeAll(async () => {
    plaintext = patternBytes(PLAINTEXT_BYTES, 7);
    segments = await sealDocument(streamKey, noncePrefix, plaintext, SMALL_CHUNK);
    expect(segments).toHaveLength(3);
  });

  /** The control. Every refusal below is attributable only because this passes. */
  it('opens untouched under the parameters it was sealed with', async () => {
    const opened = await openDocument(streamKey, noncePrefix, segments);
    await expectSameBytes(opened, plaintext, 'control');
  });

  it('refuses a flipped ciphertext byte', async () => {
    const tampered = segments[0]!.slice();
    tampered[10] = tampered[10]! ^ 0x01;
    await expectRefusal(
      () => decryptSegment(streamKey, { noncePrefix, index: 0, isLast: false }, tampered),
      AEAD_REFUSAL,
    );
  });

  it('refuses a flipped authentication tag byte', async () => {
    const tampered = segments[0]!.slice();
    tampered[tampered.length - 1] = tampered[tampered.length - 1]! ^ 0x01;
    await expectRefusal(
      () => decryptSegment(streamKey, { noncePrefix, index: 0, isLast: false }, tampered),
      AEAD_REFUSAL,
    );
  });

  it('refuses a dropped final segment, because the last-segment flag is in the nonce', async () => {
    // The truncation attack: the server returns segments 0 and 1 and claims the
    // document has two. The client then opens segment 1 as the LAST one, and
    // segment 1 was sealed as a non-final segment.
    await expectRefusal(
      () => decryptSegment(streamKey, { noncePrefix, index: 1, isLast: true }, segments[1]!),
      AEAD_REFUSAL,
    );
  });

  it('refuses two swapped segments, because the index is in the nonce', async () => {
    await expectRefusal(
      () => decryptSegment(streamKey, { noncePrefix, index: 1, isLast: false }, segments[0]!),
      AEAD_REFUSAL,
    );
    await expectRefusal(
      () => decryptSegment(streamKey, { noncePrefix, index: 0, isLast: false }, segments[1]!),
      AEAD_REFUSAL,
    );
  });

  it('refuses a substituted streamSalt', async () => {
    const substituted = globalThis.crypto.getRandomValues(
      new Uint8Array(DOCUMENT_STREAM_SALT_BYTES),
    );
    const wrongKey = await deriveStreamKey(dek, substituted, DOC_ID);
    await expectRefusal(
      () => decryptSegment(wrongKey, { noncePrefix, index: 0, isLast: false }, segments[0]!),
      AEAD_REFUSAL,
    );
  });

  it('refuses a substituted noncePrefix', async () => {
    const substituted = globalThis.crypto.getRandomValues(
      new Uint8Array(DOCUMENT_NONCE_PREFIX_BYTES),
    );
    await expectRefusal(
      () =>
        decryptSegment(
          streamKey,
          { noncePrefix: substituted, index: 0, isLast: false },
          segments[0]!,
        ),
      AEAD_REFUSAL,
    );
  });

  it('refuses a segment replayed under a different document id', async () => {
    const foreignKey = await deriveStreamKey(dek, streamSalt, OTHER_DOC_ID);
    await expectRefusal(
      () => decryptSegment(foreignKey, { noncePrefix, index: 0, isLast: false }, segments[0]!),
      AEAD_REFUSAL,
    );
  });

  it('refuses a different DEK', async () => {
    const foreignKey = await deriveStreamKey(generateDek(), streamSalt, DOC_ID);
    await expectRefusal(
      () => decryptSegment(foreignKey, { noncePrefix, index: 0, isLast: false }, segments[0]!),
      AEAD_REFUSAL,
    );
  });

  it('refuses the metadata blob under the stream key', async () => {
    const sealed = await encryptMeta(metaKey, metaFixture());
    await expectRefusal(() => decryptMeta(streamKey, sealed), AEAD_REFUSAL);
  });

  it("refuses the metadata blob under another document's metadata key", async () => {
    const sealed = await encryptMeta(metaKey, metaFixture());
    const foreignMetaKey = await deriveMetaKey(dek, streamSalt, OTHER_DOC_ID);
    await expectRefusal(() => decryptMeta(foreignMetaKey, sealed), AEAD_REFUSAL);
  });
});

// ---------------------------------------------------------------------------
// The framing guards
// ---------------------------------------------------------------------------

describe('a malformed framing is refused rather than silently reframed', () => {
  const PREFIX_MESSAGE = /nonce prefix must be exactly 7 bytes/;
  const INDEX_MESSAGE = /segment index must be an integer in 0\.\.4294967295/;

  it.each([6, 8])('refuses a %i-byte nonce prefix in both directions', async (length) => {
    // AES-GCM accepts an IV of any length, so a prefix of the wrong size would
    // NOT fail inside the primitive: it would produce a differently framed
    // document that only this build could read back.
    const wrongPrefix = new Uint8Array(length);
    await expectRefusal(
      () =>
        encryptSegment(
          streamKey,
          { noncePrefix: wrongPrefix, index: 0, isLast: true },
          new Uint8Array([1]),
        ),
      PREFIX_MESSAGE,
    );
    await expectRefusal(
      () =>
        decryptSegment(
          streamKey,
          { noncePrefix: wrongPrefix, index: 0, isLast: true },
          new Uint8Array(DOCUMENT_TAG_BYTES),
        ),
      PREFIX_MESSAGE,
    );
  });

  it.each([-1, 1.5, 2 ** 32, Number.NaN])('refuses the segment index %s', async (index) => {
    await expectRefusal(
      () => encryptSegment(streamKey, { noncePrefix, index, isLast: false }, new Uint8Array([1])),
      INDEX_MESSAGE,
    );
  });

  it('accepts the largest index the four-byte counter can hold', async () => {
    const index = 2 ** 32 - 1;
    const sealed = await encryptSegment(
      streamKey,
      { noncePrefix, index, isLast: true },
      new Uint8Array([9]),
    );
    const opened = await decryptSegment(streamKey, { noncePrefix, index, isLast: true }, sealed);
    expect(Array.from(opened)).toEqual([9]);
  });

  it('refuses a segment shorter than its own authentication tag', async () => {
    await expectRefusal(
      () =>
        decryptSegment(
          streamKey,
          { noncePrefix, index: 0, isLast: true },
          new Uint8Array(DOCUMENT_TAG_BYTES - 1),
        ),
      /segment must be at least 16 bytes/,
    );
  });
});

// ---------------------------------------------------------------------------
// The DEK wrap
// ---------------------------------------------------------------------------

describe('the document-bound DEK wrap', () => {
  it('round-trips under the same vault key and document id', async () => {
    const wrapKey = await deriveWrapKey(vaultKey, DOC_ID);
    const wrapped = await wrapDek(dek, wrapKey);
    const unwrapped = await unwrapDek(wrapped, wrapKey);

    expect(Array.from(unwrapped)).toEqual(Array.from(dek));
    // A COPY, not the same buffer: zeroing what the store holds must not reach
    // back into a key another caller is still using.
    expect(unwrapped).not.toBe(dek);
    // And the wrapped form is not the key sitting in plain sight.
    expect(wrapped.encryptedDek).not.toBe(toBase64(dek));
  });

  it("refuses another document's wrapping key", async () => {
    const wrapped = await wrapDek(dek, await deriveWrapKey(vaultKey, DOC_ID));
    const foreignKey = await deriveWrapKey(vaultKey, OTHER_DOC_ID);
    await expectRefusal(() => unwrapDek(wrapped, foreignKey), AEAD_REFUSAL);
  });

  it('refuses a wrapping key derived from a different vault key', async () => {
    const wrapped = await wrapDek(dek, await deriveWrapKey(vaultKey, DOC_ID));
    const rotatedKey = await deriveWrapKey(otherVaultKey, DOC_ID);
    await expectRefusal(() => unwrapDek(wrapped, rotatedKey), AEAD_REFUSAL);
  });

  it('treats an upper-case document id as the same document', async () => {
    // Mongo emits lower-case hex and `objectIdSchema` lower-cases, so the two
    // spellings name one document and must derive one key. `updateFolder`
    // learned this as a defect: an upper-case `:id` walked past a self-parent
    // check.
    const wrapped = await wrapDek(dek, await deriveWrapKey(vaultKey, DOC_ID));
    const upperCased = await deriveWrapKey(vaultKey, DOC_ID.toUpperCase());
    expect(Array.from(await unwrapDek(wrapped, upperCased))).toEqual(Array.from(dek));
  });

  it.each([
    ['too short', '66c0f1a2b3c4d5e6f7a8b9c'],
    ['not hexadecimal', '66c0f1a2b3c4d5e6f7a8b9cz'],
    ['carrying the info separator', '66c0f1a2b3c4d5e6f7a8b9|c'],
    ['empty', ''],
  ])('refuses a document id that is %s', async (_label, badId) => {
    const message = /24-character hex ObjectId/;
    await expectRefusal(() => deriveWrapKey(vaultKey, badId), message);
    await expectRefusal(() => deriveStreamKey(dek, streamSalt, badId), message);
    await expectRefusal(() => deriveMetaKey(dek, streamSalt, badId), message);
  });

  it('refuses to wrap or derive from a key that is not 32 bytes', async () => {
    const short = new Uint8Array(31);
    const message = /must be exactly 32 bytes/;
    const wrapKey = await deriveWrapKey(vaultKey, DOC_ID);
    await expectRefusal(() => wrapDek(short, wrapKey), message);
    await expectRefusal(() => deriveStreamKey(short, streamSalt, DOC_ID), message);
    await expectRefusal(() => deriveMetaKey(short, streamSalt, DOC_ID), message);
  });

  it('refuses an authentic wrap of the wrong length, which only this client could have written', async () => {
    // Authenticated, so nobody forged it: this is the shape a bug in a future
    // writer would take, and a 16-byte "DEK" that keeps working is exactly the
    // silent weakening the length check exists to stop.
    const wrapKey = await deriveWrapKey(vaultKey, DOC_ID);
    const raw = await sealRaw(wrapKey, new Uint8Array(16));
    await expectRefusal(
      () => unwrapDek({ encryptedDek: raw.encrypted, dekIv: raw.iv, dekTag: raw.tag }, wrapKey),
      /must be exactly 32 bytes/,
    );
  });

  it('mints a fresh 32-byte key per document and zeroes it on demand', async () => {
    const first = generateDek();
    const second = generateDek();
    expect(first).toHaveLength(32);
    expect(Array.from(first)).not.toEqual(Array.from(second));

    // Zeroing is not cosmetic: the zeroed buffer must no longer open the
    // document it used to.
    const doomed = generateDek();
    const key = await deriveStreamKey(doomed, streamSalt, DOC_ID);
    const sealed = await encryptSegment(
      key,
      { noncePrefix, index: 0, isLast: true },
      new Uint8Array([4, 2]),
    );
    zeroDek(doomed);
    expect(Array.from(doomed)).toEqual(Array.from(new Uint8Array(32)));
    const afterZeroing = await deriveStreamKey(doomed, streamSalt, DOC_ID);
    await expectRefusal(
      () => decryptSegment(afterZeroing, { noncePrefix, index: 0, isLast: true }, sealed),
      AEAD_REFUSAL,
    );
  });
});

// ---------------------------------------------------------------------------
// The metadata blob
// ---------------------------------------------------------------------------

describe('the sealed metadata blob', () => {
  it('round-trips every field the server is never allowed to see', async () => {
    const meta = metaFixture();
    const sealed = await encryptMeta(metaKey, meta);
    expect(await decryptMeta(metaKey, sealed)).toEqual(meta);
    // The name is not sitting in the stored string.
    expect(sealed.encryptedMeta).not.toContain(meta.name);
  });

  it('generates a FRESH metaIv on every seal, because SK_meta outlives the blob', async () => {
    // The one place in this design where a nonce could repeat under a fixed key.
    // `SK_meta` is deterministic in (DEK, streamSalt, documentId) and therefore
    // fixed for the document's whole life, while the blob is mutable: a rename
    // re-seals it. Two seals under one key with one IV hand anyone holding both
    // ciphertexts the XOR of the plaintexts and a path to the authentication
    // subkey.
    const meta = metaFixture();
    const first = await encryptMeta(metaKey, meta);
    const second = await encryptMeta(metaKey, meta);

    expect(second.metaIv).not.toBe(first.metaIv);
    expect(second.encryptedMeta).not.toBe(first.encryptedMeta);
    expect(await decryptMeta(metaKey, first)).toEqual(meta);
    expect(await decryptMeta(metaKey, second)).toEqual(meta);
  });

  it('accepts no IV parameter at all, so no caller can supply a repeated one', () => {
    // The signature is `(metaKey, meta)`. A third parameter could only be an IV,
    // and an IV a caller chooses is the defect the freshness rule exists to make
    // unreachable, so its absence is part of the contract rather than an accident
    // of the current implementation.
    expect(encryptMeta).toHaveLength(2);
  });

  it('refuses metadata whose framing contradicts itself, before it seals anything', async () => {
    // The write pre-flight. `chunkCount` must be
    // ceil(plaintextBytes / chunkPlaintextBytes); a blob that disagrees would
    // frame the download wrongly, and it is caught here rather than at read time,
    // when the file is already in the bucket.
    await expectRefusal(
      () => encryptMeta(metaKey, metaFixture({ plaintextBytes: 10 * P, chunkCount: 1 })),
      /chunkCount must equal/,
    );
  });

  it('refuses metadata that serializes past the byte budget', async () => {
    // Every field bound is a Zod `.max()` over UTF-16 CODE UNITS while the blob
    // is BYTES, and `JSON.stringify` escapes a control character to the six
    // characters of a `\u0007` escape. A note at its full code-unit bound made
    // of them is 60,000 bytes: legal by every field bound, and far past the
    // blob's.
    const note = '\u0007'.repeat(MAX_DOCUMENT_NOTE_LENGTH);
    await expectRefusal(() => encryptMeta(metaKey, metaFixture({ note })), /UTF-8 bytes or fewer/);
  });

  it('refuses a blob whose JSON does not satisfy the schema', async () => {
    // Constructed with the oracle, because the service's own write path cannot
    // produce it, which is the point: the read path validates rather than trusts
    // what came back from the server.
    const raw = await sealRaw(
      metaKey,
      new TextEncoder().encode(JSON.stringify({ ...metaFixture(), name: '' })),
    );
    await expectRefusal(
      () =>
        decryptMeta(metaKey, { encryptedMeta: raw.encrypted, metaIv: raw.iv, metaTag: raw.tag }),
      /too small|at least 1/i,
    );
  });

  it('refuses a blob that is authentic but not well-formed UTF-8', async () => {
    const raw = await sealRaw(metaKey, new Uint8Array([0xff, 0xfe, 0x80]));
    await expectRefusal(
      () =>
        decryptMeta(metaKey, { encryptedMeta: raw.encrypted, metaIv: raw.iv, metaTag: raw.tag }),
      /UTF-8|decode/i,
    );
  });

  it('refuses a blob that is authentic UTF-8 but not JSON', async () => {
    const raw = await sealRaw(metaKey, new TextEncoder().encode('not json at all'));
    await expectRefusal(
      () =>
        decryptMeta(metaKey, { encryptedMeta: raw.encrypted, metaIv: raw.iv, metaTag: raw.tag }),
      /JSON|Unexpected token/i,
    );
  });

  it('strips an unknown key rather than handing it to the reader', async () => {
    // STRIP mode is `z.object()`'s default and the read path relies on it: a
    // server that adds a field to a blob it cannot read is impossible, but a
    // client that WROTE one under an older build must not surface it.
    const raw = await sealRaw(
      metaKey,
      new TextEncoder().encode(JSON.stringify({ ...metaFixture(), smuggled: 'value' })),
    );
    const opened = await decryptMeta(metaKey, {
      encryptedMeta: raw.encrypted,
      metaIv: raw.iv,
      metaTag: raw.tag,
    });
    expect(opened).toEqual(metaFixture());
    expect(opened).not.toHaveProperty('smuggled');
  });
});

// ---------------------------------------------------------------------------
// What the write path actually seals, and how big it is allowed to be
// ---------------------------------------------------------------------------

describe('the metadata the write path seals', () => {
  it('seals the PARSED metadata, not the object the caller passed', async () => {
    // `tags` carries a `.trim()` and the schema strips unknown keys, so sealing
    // `meta` instead of the parse result would store an untrimmed tag and a
    // smuggled field. The round trip could never show it: `decryptMeta` parses
    // too, so the reader would normalize what the writer failed to. The sealed
    // BYTES are read here with SubtleCrypto directly, which is the only place the
    // difference is visible.
    const sealed = await encryptMeta(
      metaKey,
      metaFixture({ tags: ['  work  ', 'finance'] } as Partial<DocumentMeta>),
    );
    const json = await openRaw(metaKey, {
      encrypted: sealed.encryptedMeta,
      iv: sealed.metaIv,
      tag: sealed.metaTag,
    });

    expect(JSON.parse(json)).toEqual(metaFixture({ tags: ['work', 'finance'] }));
    expect(json).not.toContain('  work  ');
  });

  it('seals the largest legal metadata into a string the wire schema accepts', async () => {
    // The two bounds are a pair: MAX_DOCUMENT_META_JSON_BYTES counts the UTF-8
    // BYTES the browser seals, and MAX_ENCRYPTED_DOCUMENT_META_LENGTH is its exact
    // base64 expansion, which is what `POST /uploads/:id/complete` will enforce.
    // Section 1.5 records that this pair was wrong once already, and the failure
    // mode is the expensive kind: a 400 on the completion of a file that has
    // already been uploaded in full.
    const worst = worstCaseMetaFixture();
    const jsonBytes = documentMetaJsonByteLength(worst);
    expect(jsonBytes).toBeLessThanOrEqual(MAX_DOCUMENT_META_JSON_BYTES);
    // Not a trivial fraction of the budget either — a fixture that had quietly
    // stopped being the worst case would make this whole test vacuous.
    expect(jsonBytes).toBeGreaterThan(MAX_DOCUMENT_META_JSON_BYTES * 0.9);

    const sealed = await encryptMeta(metaKey, worst);
    expect(sealed.encryptedMeta.length).toBeLessThanOrEqual(MAX_ENCRYPTED_DOCUMENT_META_LENGTH);

    // The real wire schema, over the real sealed fields plus a real wrapped key:
    // the IV (16 characters), the tag (24) and the wrapped DEK (44) are bounded
    // there too, and none of those bounds is named by a document constant.
    const wrapped = await wrapDek(dek, await deriveWrapKey(vaultKey, DOC_ID));
    expect(() =>
      completeDocumentUploadSchema.parse({ ...sealed, ...wrapped, vaultKeyVersion: 0 }),
    ).not.toThrow();

    // And it still opens, which is the half a length check cannot tell you.
    expect(await decryptMeta(metaKey, sealed)).toEqual(worst);
  });

  it('ignores an IV a caller tries to hand it, however the argument is smuggled in', async () => {
    // Stronger than the arity check above, which `Function.length` would let a
    // DEFAULTED third parameter walk straight past: this calls `encryptMeta`
    // through a widened signature with the same IV twice, and the two seals must
    // still differ.
    const withIv = encryptMeta as unknown as (
      key: CryptoKey,
      meta: DocumentMeta,
      iv: Uint8Array,
    ) => Promise<{ encryptedMeta: string; metaIv: string; metaTag: string }>;
    const fixedIv = new Uint8Array(12).fill(7);

    const first = await withIv(metaKey, metaFixture(), fixedIv);
    const second = await withIv(metaKey, metaFixture(), fixedIv);

    expect(second.metaIv).not.toBe(first.metaIv);
    expect(first.metaIv).not.toBe(toBase64(fixedIv));
    expect(second.encryptedMeta).not.toBe(first.encryptedMeta);
  });
});
