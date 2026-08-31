/**
 * The document store's schemas, in both directions.
 *
 * `documentMetaSchema` is the narrowest part of this feature's data path, for the
 * same reason `vaultItemDataSchemas` is: it runs on the write pre-flight, before
 * the browser seals the blob, and again after decrypting it. A value it accepts on
 * the way in and refuses on the way out is not a validation nicety — it is a
 * document whose name, type and note the user can no longer read.
 *
 * Three classes of case below, and each exists because of a defect it can catch:
 *
 *  1. A BOUND AT THE LIMIT AND ONE PAST IT. `.max(255)` reads identically to
 *     `.min(255)` from any test that only sends a short value, so every bound is
 *     probed as a pair. The pair is what pins the number.
 *  2. AN UNANCHORED OR WIDENED FORMAT. `/^[a-f0-9]{64}$/` with either anchor
 *     removed still matches every valid digest, so nothing notices until
 *     `"<64 hex>; drop"` is an acceptable `sha256`.
 *  3. THE UNITS. Every field bound is a `.max()` over UTF-16 CODE UNITS while the
 *     sealed blob is UTF-8 BYTES, and the two differ by up to a factor of three.
 *     The worst-case blob is built here and asserted to fit, which is what turns a
 *     new field or a raised field bound into a red test rather than into a
 *     document that refuses to seal with the file already chosen.
 */
import { describe, it, expect } from 'vitest';
import type {
  CompleteDocumentUploadInput,
  DocumentMeta,
  DocumentPartParams,
  DocumentResponse,
  DocumentSegmentParams,
  DocumentUploadResponse,
  DocumentUsageResponse,
  InitDocumentUploadInput,
  InitDocumentUploadResponse,
  ListDocumentTrashInput,
  ListDocumentsInput,
  UpdateDocumentInput,
} from '../src/types/index.js';
import {
  DOCUMENT_CIPHERTEXT_SIZE_MISMATCH_MESSAGE,
  DOCUMENT_DECLARED_FRAMING_MESSAGE,
  DOCUMENT_FRAMING_MISMATCH_MESSAGE,
  DOCUMENT_META_TOO_LARGE_MESSAGE,
  completeDocumentUploadSchema,
  documentChunkCountFor,
  documentMetaJsonByteLength,
  documentMetaSchema,
  documentPartParamsSchema,
  documentResponseSchema,
  documentSegmentParamsSchema,
  documentUploadResponseSchema,
  documentUsageResponseSchema,
  initDocumentUploadResponseSchema,
  initDocumentUploadSchema,
  listDocumentTrashSchema,
  listDocumentsSchema,
  updateDocumentSchema,
} from '../src/schemas/document.js';
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
  PAGINATION_DEFAULTS,
} from '../src/constants/index.js';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const chars = (n: number, char = 'x'): string => char.repeat(n);
const HEX24 = 'a'.repeat(24);
const HEX64 = 'b'.repeat(64);
/** Padded base64 of `n` zero bytes — the shape the framing fields must carry. */
const base64Bytes = (n: number): string => Buffer.alloc(n).toString('base64');
const SALT = base64Bytes(DOCUMENT_STREAM_SALT_BYTES);
const PREFIX = base64Bytes(DOCUMENT_NONCE_PREFIX_BYTES);

/** A metadata blob every field of which is legal, with neither optional present. */
const validMeta: DocumentMeta = {
  name: 'quarterly-report.pdf',
  mime: 'application/pdf',
  ext: 'pdf',
  plaintextBytes: 1234,
  sha256: HEX64,
  chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  chunkCount: 1,
  tags: ['finance'],
  capturedAt: '2026-08-31T12:34:56.789Z',
};

const validInit: InitDocumentUploadInput = {
  encryptedDek: 'ZGVr',
  dekIv: 'aXY=',
  dekTag: 'dGFn',
  streamSalt: SALT,
  noncePrefix: PREFIX,
  declaredPlaintextBytes: 1234,
  declaredChunkCount: 1,
};

const validComplete: CompleteDocumentUploadInput = {
  encryptedMeta: 'bWV0YQ==',
  metaIv: 'aXY=',
  metaTag: 'dGFn',
  encryptedDek: 'ZGVr',
  dekIv: 'aXY=',
  dekTag: 'dGFn',
  vaultKeyVersion: 0,
};

const validRow: DocumentResponse = {
  _id: HEX24,
  favorite: false,
  encryptedDek: 'ZGVr',
  dekIv: 'aXY=',
  dekTag: 'dGFn',
  streamSalt: SALT,
  noncePrefix: PREFIX,
  encryptedMeta: 'bWV0YQ==',
  metaIv: 'aXY=',
  metaTag: 'dGFn',
  chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  chunkCount: 1,
  ciphertextBytes: 1234 + DOCUMENT_TAG_BYTES,
  plaintextBytes: 1234,
  createdAt: '2026-08-31T12:34:56.789Z',
  updatedAt: '2026-08-31T12:34:56.789Z',
};

const validUploadRow: DocumentUploadResponse = {
  _id: HEX24,
  streamSalt: SALT,
  noncePrefix: PREFIX,
  declaredPlaintextBytes: 1234,
  declaredChunkCount: 1,
  chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  vaultKeyVersion: 3,
  parts: [{ partNumber: 1, bytes: 1234 + DOCUMENT_TAG_BYTES }],
  receivedBytes: 1234 + DOCUMENT_TAG_BYTES,
  createdAt: '2026-08-31T12:34:56.789Z',
  expiresAt: '2026-09-01T12:34:56.789Z',
};

const paths = (result: {
  success: boolean;
  error?: { issues: { path: unknown[] }[] };
}): string[] =>
  result.success ? [] : (result.error?.issues ?? []).map((issue) => issue.path.join('.'));

/**
 * The ONE issue a single-fault payload produced.
 *
 * It asserts the count rather than just reaching for `issues[0]`, and that is the
 * point: every payload below changes exactly one thing, so a second issue means the
 * fixture is wrong or a refine fired that should not have — and a bare `issues[0]`
 * would let the case pass anyway while quietly testing something else.
 */
const onlyIssue = (result: { success: boolean; error?: { issues: unknown[] } }): unknown => {
  const issues = result.success ? [] : (result.error?.issues ?? []);
  expect(issues, 'expected exactly one issue from a single-fault payload').toHaveLength(1);
  return issues[0];
};

/**
 * The fixture minus one key — how every "missing required field" case is built.
 *
 * Rebuilt by filtering rather than by `delete`, so the fixture is never mutated and
 * a case cannot leak into the next one.
 */
const without = (source: object, field: string): Record<string, unknown> =>
  Object.fromEntries(Object.entries(source).filter(([key]) => key !== field));

// ---------------------------------------------------------------------------
// The framing derivation
// ---------------------------------------------------------------------------

describe('documentChunkCountFor — the one copy of the framing derivation', () => {
  it.each([
    { plaintextBytes: 0, expected: 1, why: 'an empty file is still one segment' },
    { plaintextBytes: 1, expected: 1, why: 'one byte' },
    { plaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES, expected: 1, why: 'exactly one segment' },
    {
      plaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES + 1,
      expected: 2,
      why: 'one segment plus one byte',
    },
    {
      plaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES * 2,
      expected: 2,
      why: 'exactly two segments',
    },
    {
      plaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES * 2 + 17,
      expected: 3,
      why: 'a three-segment remainder',
    },
  ])(
    'gives $expected segments for $plaintextBytes bytes ($why)',
    ({ plaintextBytes, expected }) => {
      expect(documentChunkCountFor(plaintextBytes, DOCUMENT_PLAINTEXT_CHUNK_BYTES)).toBe(expected);
    },
  );

  it('never returns 0, which is what would leave an empty document with no segment to read', () => {
    // The `max(1, …)` is the whole reason this is a function and not an
    // expression: `ceil(0 / P)` is 0, and a document claiming no segments is one
    // for which no Range read is ever issued.
    expect(documentChunkCountFor(0, DOCUMENT_PLAINTEXT_CHUNK_BYTES)).toBe(1);
    expect(documentChunkCountFor(0, 1)).toBe(1);
  });
});

describe('documentMetaJsonByteLength — bytes, not code units', () => {
  it('counts UTF-8 bytes, so a multi-byte string costs more than its length', () => {
    expect(documentMetaJsonByteLength('abc')).toBe(5); // two quotes plus three bytes
    // Three UTF-8 bytes per UTF-16 code unit is the worst case a real script
    // reaches, and the reason the stored bound is a byte budget.
    expect(documentMetaJsonByteLength('漢')).toBe(5);
    expect(documentMetaJsonByteLength({ a: '漢漢' })).toBe(
      new TextEncoder().encode('{"a":"漢漢"}').byteLength,
    );
  });

  it('counts the ESCAPE, not the character, for a control character', () => {
    // `JSON.stringify` writes `\u0007` — six bytes for one code unit. This is the
    // case the byte budget deliberately does not size for, and the reason the
    // refusal has to be loud rather than lossy.
    expect(documentMetaJsonByteLength('\u0007')).toBe(8);
  });

  it('reports 0 for a value JSON cannot represent, rather than throwing', () => {
    expect(documentMetaJsonByteLength(undefined)).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// documentMetaSchema
// ---------------------------------------------------------------------------

describe('documentMetaSchema — the encrypted blob', () => {
  it('accepts a blob with neither optional field, and adds neither', () => {
    const result = documentMetaSchema.safeParse(validMeta);
    expect(result.success, JSON.stringify(paths(result))).toBe(true);
    expect(result.success ? result.data : null).toEqual(validMeta);
    // The negative that matters: no `note: ''` and no `transform: {}` appear out
    // of nowhere. A default here would change the blob of every document that
    // never had one.
    expect(result.success ? 'note' in result.data : true).toBe(false);
    expect(result.success ? 'transform' in result.data : true).toBe(false);
  });

  it('accepts a blob carrying the note and the transform provenance', () => {
    const withBoth = {
      ...validMeta,
      note: 'the signed copy',
      transform: {
        formatted: true,
        repaired: false,
        tool: 'prettier',
        toolVersion: '3.9.5',
        originalSha256: 'c'.repeat(64),
      },
    };
    const result = documentMetaSchema.safeParse(withBoth);
    expect(result.success, JSON.stringify(paths(result))).toBe(true);
    expect(result.success ? result.data : null).toEqual(withBoth);
  });

  it('strips an unknown key instead of rejecting it', () => {
    const result = documentMetaSchema.safeParse({ ...validMeta, thumbnail: 'AAAA' });
    expect(result.success).toBe(true);
    expect(result.success ? 'thumbnail' in result.data : true).toBe(false);
  });

  it.each([
    'name',
    'mime',
    'ext',
    'plaintextBytes',
    'sha256',
    'chunkPlaintextBytes',
    'chunkCount',
    'tags',
    'capturedAt',
  ])('rejects a blob with no %s, and yields no partial value', (field) => {
    const payload = without(validMeta, field);
    const result = documentMetaSchema.safeParse(payload);
    expect(result.success).toBe(false);
    // The negative the plan asks for: a rejected object hands back NOTHING, so a
    // caller cannot half-use by reading `.data`.
    expect(Object.hasOwn(result, 'data')).toBe(false);
    expect(paths(result)).toContain(field);
  });

  it.each([
    { field: 'name', max: MAX_DOCUMENT_NAME_LENGTH },
    { field: 'mime', max: MAX_DOCUMENT_MIME_LENGTH },
    { field: 'ext', max: MAX_DOCUMENT_EXT_LENGTH },
    { field: 'note', max: MAX_DOCUMENT_NOTE_LENGTH },
  ])('bounds $field at $max characters, and refuses one more', ({ field, max }) => {
    expect(documentMetaSchema.safeParse({ ...validMeta, [field]: chars(max) }).success).toBe(true);
    const over = documentMetaSchema.safeParse({ ...validMeta, [field]: chars(max + 1) });
    expect(over.success).toBe(false);
    expect(paths(over)).toEqual([field]);
  });

  it('requires a name but accepts an empty mime and an empty extension', () => {
    // A file picked from a disk may have no recognised MIME type, and a name with
    // no dot has no extension at all (`Dockerfile`, `.bashrc`). Refusing those
    // would refuse ordinary files. A nameless document has nothing to display.
    expect(documentMetaSchema.safeParse({ ...validMeta, mime: '', ext: '' }).success).toBe(true);
    const noName = documentMetaSchema.safeParse({ ...validMeta, name: '' });
    expect(noName.success).toBe(false);
    expect(paths(noName)).toEqual(['name']);
  });

  it('bounds the tag list and each tag, and stores the trimmed value', () => {
    // An untagged document is the common case, so the array has no `.min()`: the
    // empty list must parse and must come back as an empty list rather than as a
    // missing key.
    const untagged = documentMetaSchema.safeParse({ ...validMeta, tags: [] });
    expect(untagged.success).toBe(true);
    expect(untagged.success ? untagged.data.tags : null).toEqual([]);

    const atCap = Array.from({ length: MAX_DOCUMENT_TAGS }, (_, i) => `tag-${String(i)}`);
    expect(documentMetaSchema.safeParse({ ...validMeta, tags: atCap }).success).toBe(true);
    expect(
      documentMetaSchema.safeParse({ ...validMeta, tags: [...atCap, 'one-too-many'] }).success,
    ).toBe(false);

    expect(
      documentMetaSchema.safeParse({ ...validMeta, tags: [chars(MAX_TAG_LENGTH)] }).success,
    ).toBe(true);
    expect(
      documentMetaSchema.safeParse({ ...validMeta, tags: [chars(MAX_TAG_LENGTH + 1)] }).success,
    ).toBe(false);

    // `.trim()` runs before both bounds, so the stored value is what is measured.
    const padded = documentMetaSchema.safeParse({ ...validMeta, tags: ['  finance  '] });
    expect(padded.success ? padded.data.tags : null).toEqual(['finance']);
    // And a tag that is nothing but whitespace is empty once trimmed, so it is
    // refused rather than stored as ''.
    expect(documentMetaSchema.safeParse({ ...validMeta, tags: ['   '] }).success).toBe(false);
    expect(documentMetaSchema.safeParse({ ...validMeta, tags: [''] }).success).toBe(false);
  });

  it.each([
    { value: HEX64, ok: true, why: '64 lowercase hex' },
    { value: HEX64.toUpperCase(), ok: false, why: 'uppercase hex' },
    { value: 'b'.repeat(63), ok: false, why: 'one character short' },
    { value: 'b'.repeat(65), ok: false, why: 'one character long' },
    { value: `${HEX64}; drop`, ok: false, why: 'a trailing payload (the missing $ anchor)' },
    { value: `drop ;${HEX64}`, ok: false, why: 'a leading payload (the missing ^ anchor)' },
    { value: 'g'.repeat(64), ok: false, why: 'non-hex characters' },
  ])('sha256: $why is $ok', ({ value, ok }) => {
    const result = documentMetaSchema.safeParse({ ...validMeta, sha256: value });
    expect(result.success).toBe(ok);
    if (!ok) expect(paths(result)).toEqual(['sha256']);
  });

  it.each([
    { value: '2026-08-31T12:34:56Z', ok: true, why: 'a UTC instant' },
    { value: '2026-08-31T12:34:56.789Z', ok: true, why: 'a UTC instant with milliseconds' },
    { value: '2026-08-31T12:34:56+05:30', ok: false, why: 'an offset-bearing local time' },
    { value: '2026-08-31T12:34:56', ok: false, why: 'a zone-less local time' },
    { value: '2026-08-31', ok: false, why: 'a date with no time' },
    { value: 'yesterday', ok: false, why: 'prose' },
  ])('capturedAt: $why is $ok', ({ value, ok }) => {
    // An offset-bearing value reads differently depending on the reader's zone,
    // which is exactly what the `dst` gate re-runs this suite to catch.
    const result = documentMetaSchema.safeParse({ ...validMeta, capturedAt: value });
    expect(result.success).toBe(ok);
    if (!ok) expect(paths(result)).toEqual(['capturedAt']);
  });

  it('bounds capturedAt by length as well as by shape', () => {
    // The ISO grammar's fractional-second component is `\.\d+`: one or more digits
    // with NO upper bound, so shape alone admits a timestamp of any length. Measured
    // on zod 4.4.3: `z.iso.datetime()` accepts a 30,021-character instant. A blob
    // whose every other field is minimal then has ~36 KB of metadata budget to spend
    // on one timestamp, which is the opposite of "every string carrying its named
    // bound" — and `secretDataSchema.expiresAt` already pairs its own permissive ISO
    // check with an explicit `.max()` for exactly this reason.
    const nanosecondPrecision = '2026-08-31T12:34:56.123456789Z';
    expect(nanosecondPrecision.length).toBeLessThanOrEqual(MAX_DOCUMENT_TIMESTAMP_LENGTH);
    expect(
      documentMetaSchema.safeParse({ ...validMeta, capturedAt: nanosecondPrecision }).success,
    ).toBe(true);

    // At the bound and one past it, built so the value is still a legal instant in
    // both cases: only the length differs, so the pair pins the number rather than
    // the grammar.
    const fractionDigitsAtCap = MAX_DOCUMENT_TIMESTAMP_LENGTH - '2026-08-31T12:34:56.Z'.length;
    const atCap = `2026-08-31T12:34:56.${chars(fractionDigitsAtCap, '9')}Z`;
    expect(atCap).toHaveLength(MAX_DOCUMENT_TIMESTAMP_LENGTH);
    expect(documentMetaSchema.safeParse({ ...validMeta, capturedAt: atCap }).success).toBe(true);

    const overCap = `2026-08-31T12:34:56.${chars(fractionDigitsAtCap + 1, '9')}Z`;
    const over = documentMetaSchema.safeParse({ ...validMeta, capturedAt: overCap });
    expect(over.success).toBe(false);
    expect(paths(over)).toEqual(['capturedAt']);

    // And the pathological case the bound exists for: a metadata object that is
    // legal in every other respect and is almost entirely one timestamp.
    const pathological = {
      ...validMeta,
      name: 'a',
      mime: '',
      ext: '',
      tags: [],
      capturedAt: `2026-08-31T12:34:56.${chars(30_000, '9')}Z`,
    };
    const refused = documentMetaSchema.safeParse(pathological);
    expect(refused.success).toBe(false);
    // The FIELD refuses it. The aggregate byte budget would not have: with every
    // other field minimal there is room for a 30 KB timestamp inside 36,864 bytes,
    // which is what makes this a field-level bound rather than a duplicate of the
    // budget refine.
    expect(paths(refused)).toEqual(['capturedAt']);
    expect(documentMetaJsonByteLength(pathological)).toBeLessThanOrEqual(
      MAX_DOCUMENT_META_JSON_BYTES,
    );
  });

  it.each([
    { field: 'plaintextBytes', value: 0, ok: true, why: 'an empty document' },
    { field: 'plaintextBytes', value: -1, ok: false, why: 'a negative size' },
    { field: 'plaintextBytes', value: 1.5, ok: false, why: 'a fractional size' },
    { field: 'plaintextBytes', value: Number.NaN, ok: false, why: 'NaN' },
    { field: 'plaintextBytes', value: Number.POSITIVE_INFINITY, ok: false, why: 'Infinity' },
    { field: 'chunkPlaintextBytes', value: 0, ok: false, why: 'a zero chunk size' },
    { field: 'chunkPlaintextBytes', value: -1, ok: false, why: 'a negative chunk size' },
  ])('$field: $why is $ok', ({ field, value, ok }) => {
    // `plaintextBytes` is varied together with the framing so a rejection can only
    // come from the field itself.
    const result = documentMetaSchema.safeParse({
      ...validMeta,
      [field]: value,
      chunkCount: 1,
      ...(field === 'plaintextBytes' ? {} : { plaintextBytes: 0 }),
    });
    expect(result.success).toBe(ok);
  });

  it('bounds chunkCount by MAX_DOCUMENT_CHUNK_COUNT, with the framing held consistent', () => {
    const atCap = {
      ...validMeta,
      plaintextBytes: MAX_DOCUMENT_CHUNK_COUNT * DOCUMENT_PLAINTEXT_CHUNK_BYTES,
      chunkCount: MAX_DOCUMENT_CHUNK_COUNT,
    };
    expect(documentMetaSchema.safeParse(atCap).success).toBe(true);

    const overCap = {
      ...validMeta,
      plaintextBytes: (MAX_DOCUMENT_CHUNK_COUNT + 1) * DOCUMENT_PLAINTEXT_CHUNK_BYTES,
      chunkCount: MAX_DOCUMENT_CHUNK_COUNT + 1,
    };
    const over = documentMetaSchema.safeParse(overCap);
    expect(over.success).toBe(false);
    // The refusal is the CAP, not the framing refine: the framing is deliberately
    // consistent here, so a mutant that deleted the `.max()` could not hide behind
    // the other message.
    expect(onlyIssue(over)).toMatchObject({ code: 'too_big', path: ['chunkCount'] });
    expect(paths(over)).toEqual(['chunkCount']);

    expect(documentMetaSchema.safeParse({ ...validMeta, chunkCount: 0 }).success).toBe(false);
  });

  describe('the framing consistency refine', () => {
    it.each([
      { plaintextBytes: 0, chunkCount: 1, why: 'an empty document is one segment' },
      { plaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES, chunkCount: 1, why: 'exactly one segment' },
      {
        plaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES + 1,
        chunkCount: 2,
        why: 'one segment plus a byte',
      },
      {
        plaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES * 3,
        chunkCount: 3,
        why: 'exactly three segments',
      },
    ])(
      'accepts $plaintextBytes bytes in $chunkCount segments ($why)',
      ({ plaintextBytes, chunkCount }) => {
        expect(
          documentMetaSchema.safeParse({ ...validMeta, plaintextBytes, chunkCount }).success,
        ).toBe(true);
      },
    );

    it.each([
      {
        plaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES + 1,
        chunkCount: 1,
        why: 'a truncated claim',
      },
      { plaintextBytes: 10, chunkCount: 2, why: 'a padded claim' },
      { plaintextBytes: 0, chunkCount: 2, why: 'a phantom final segment on an empty document' },
    ])(
      'refuses $plaintextBytes bytes in $chunkCount segments ($why)',
      ({ plaintextBytes, chunkCount }) => {
        const result = documentMetaSchema.safeParse({ ...validMeta, plaintextBytes, chunkCount });
        expect(result.success).toBe(false);
        expect(onlyIssue(result)).toMatchObject({
          message: DOCUMENT_FRAMING_MISMATCH_MESSAGE,
          path: ['chunkCount'],
        });
      },
    );

    it('abstains when the chunk size is not usable, instead of adding a meaningless second issue', () => {
      // An object-level refine in zod 4 still runs when a FIELD failed one of its
      // own checks, so this predicate can be handed a chunk size of 0 — and
      // `ceil(n / 0)` is Infinity. The negative that matters is that the ONLY
      // issue reported is the real one.
      const result = documentMetaSchema.safeParse({
        ...validMeta,
        chunkPlaintextBytes: 0,
        chunkCount: 1,
      });
      expect(result.success).toBe(false);
      expect(paths(result)).toEqual(['chunkPlaintextBytes']);
    });

    it('leaves chunkPlaintextBytes unbounded by the current constant, so an older document still frames', () => {
      // Decryption reads this value from the row, never from the constant, so that
      // changing the constant later cannot mis-frame a document that already
      // exists. A `.max()` tied to the current constant would undo that.
      const halfSize = Math.floor(DOCUMENT_PLAINTEXT_CHUNK_BYTES / 2);
      const older = {
        ...validMeta,
        chunkPlaintextBytes: halfSize,
        plaintextBytes: halfSize + 1,
        chunkCount: 2,
      };
      expect(documentMetaSchema.safeParse(older).success).toBe(true);
      const larger = {
        ...validMeta,
        chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES * 2,
        plaintextBytes: 5,
        chunkCount: 1,
      };
      expect(documentMetaSchema.safeParse(larger).success).toBe(true);
    });
  });

  describe('the byte budget', () => {
    /**
     * Every string field at its bound, in 3-byte characters, plus both digests,
     * an ISO instant, the three framing numbers and the transform record.
     *
     * Typed as `DocumentMeta` on purpose: a field added to the schema without
     * being added here is a compile error, which is the only way this measurement
     * stays honest.
     */
    const worstCase: DocumentMeta = {
      name: chars(MAX_DOCUMENT_NAME_LENGTH, '漢'),
      mime: chars(MAX_DOCUMENT_MIME_LENGTH, '漢'),
      ext: chars(MAX_DOCUMENT_EXT_LENGTH, '漢'),
      plaintextBytes: MAX_DOCUMENT_CHUNK_COUNT * DOCUMENT_PLAINTEXT_CHUNK_BYTES,
      sha256: HEX64,
      chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
      chunkCount: MAX_DOCUMENT_CHUNK_COUNT,
      tags: Array.from({ length: MAX_DOCUMENT_TAGS }, () => chars(MAX_TAG_LENGTH, '漢')),
      note: chars(MAX_DOCUMENT_NOTE_LENGTH, '漢'),
      transform: {
        formatted: true,
        repaired: true,
        tool: chars(MAX_DOCUMENT_TRANSFORM_LABEL_LENGTH, '漢'),
        toolVersion: chars(MAX_DOCUMENT_TRANSFORM_LABEL_LENGTH, '漢'),
        originalSha256: 'c'.repeat(64),
      },
      capturedAt: '2026-08-31T12:34:56.789Z',
    };

    it('admits a blob whose every field is individually at its bound', () => {
      // This is the assertion the budget exists for. If it fails, the schema and
      // MAX_DOCUMENT_META_JSON_BYTES disagree, and the user-visible symptom would
      // be an upload refused on the write pre-flight with every field legal.
      const measured = documentMetaJsonByteLength(worstCase);
      expect(
        measured,
        `worst-case metadata is ${String(measured)} bytes against a budget of ${String(MAX_DOCUMENT_META_JSON_BYTES)}`,
      ).toBeLessThanOrEqual(MAX_DOCUMENT_META_JSON_BYTES);
      expect(documentMetaSchema.safeParse(worstCase).success).toBe(true);
      // The 3-bytes-per-code-unit premise, stated rather than assumed: the blob is
      // far longer in bytes than in code units.
      expect(measured).toBeGreaterThan(JSON.stringify(worstCase).length);
    });

    it.each([
      { label: 'a control character', unit: '\u0007' },
      { label: 'a lone surrogate', unit: '\ud800' },
    ])('refuses a blob made of $label: legal by code units, over budget in bytes', ({ unit }) => {
      // The reachable over-budget cases, and there are TWO rather than one:
      // `JSON.stringify` escapes both a control character and a lone surrogate to
      // `\uXXXX`, six bytes for one code unit, so a note at exactly its own bound
      // still costs 60 KB. The control character is the case the constant's comment
      // documents; the lone surrogate is the likelier accident (a name truncated
      // mid-surrogate-pair by an upstream tool) and reaches the same branch.
      const escaped = { ...validMeta, note: chars(MAX_DOCUMENT_NOTE_LENGTH, unit) };
      expect(documentMetaJsonByteLength(escaped)).toBeGreaterThan(MAX_DOCUMENT_META_JSON_BYTES);
      const result = documentMetaSchema.safeParse(escaped);
      expect(result.success).toBe(false);
      expect(onlyIssue(result)).toMatchObject({ message: DOCUMENT_META_TOO_LARGE_MESSAGE });
      // And the field bound itself did NOT fire: the note is exactly at its cap.
      expect(paths(result)).toEqual(['']);
    });

    /**
     * A note whose JSON encoding costs EXACTLY `bytes` bytes.
     *
     * Six bytes per escaped code unit plus one per ASCII character, which is what
     * lets a case land ON a byte count rather than near one. The fattest note made
     * of well-formed text is 30,000 bytes, so the budget's own boundary is only
     * reachable through escapes.
     */
    const noteCostingBytes = (bytes: number): string => {
      const escapes = Math.floor(bytes / 6);
      return `${chars(escapes, '\u0007')}${chars(bytes - escapes * 6, 'x')}`;
    };

    it('accepts a blob of exactly the budget and refuses one byte more', () => {
      // The boundary pair, and the reason it is needed: without it the budget is
      // pinned only somewhere between 35,471 bytes (the fattest well-formed blob,
      // above) and 60,002 (the escaped one), so `<=` becoming `<`, or the constant
      // moving by a kilobyte either way, changes no test. The user-visible symptom
      // of that surviving mutant is an upload refused on the write pre-flight with
      // every field individually legal and the file already chosen.
      const overhead = documentMetaJsonByteLength({ ...validMeta, note: '' });
      const atBudget = {
        ...validMeta,
        note: noteCostingBytes(MAX_DOCUMENT_META_JSON_BYTES - overhead),
      };
      expect(documentMetaJsonByteLength(atBudget)).toBe(MAX_DOCUMENT_META_JSON_BYTES);
      // The note is well inside its OWN bound, so this pair can only be about the
      // byte budget and not about the field.
      expect(atBudget.note.length).toBeLessThan(MAX_DOCUMENT_NOTE_LENGTH);
      expect(documentMetaSchema.safeParse(atBudget).success).toBe(true);

      const overBudget = { ...validMeta, note: `${atBudget.note}x` };
      expect(documentMetaJsonByteLength(overBudget)).toBe(MAX_DOCUMENT_META_JSON_BYTES + 1);
      const result = documentMetaSchema.safeParse(overBudget);
      expect(result.success).toBe(false);
      expect(onlyIssue(result)).toMatchObject({ message: DOCUMENT_META_TOO_LARGE_MESSAGE });
      expect(paths(result)).toEqual(['']);
    });

    it('measures the PARSED object, so a stripped key cannot spend the budget', () => {
      // The blob that gets sealed is the schema's output, so an unknown key the
      // schema drops must not count against the budget — otherwise a caller could
      // be refused for bytes that were never going to be stored.
      const padding = chars(MAX_DOCUMENT_NOTE_LENGTH, '\u0007');
      expect(documentMetaSchema.safeParse({ ...validMeta, ignored: padding }).success).toBe(true);
    });
  });

  describe('the transform provenance', () => {
    const base = {
      formatted: true,
      repaired: false,
      tool: 'prettier',
      toolVersion: '3.9.5',
      originalSha256: 'c'.repeat(64),
    };

    it.each(['formatted', 'repaired', 'tool', 'toolVersion', 'originalSha256'])(
      'rejects a transform record with no %s',
      (field) => {
        const transform = without(base, field);
        const result = documentMetaSchema.safeParse({ ...validMeta, transform });
        expect(result.success).toBe(false);
        expect(paths(result)).toEqual([`transform.${field}`]);
      },
    );

    it.each(['tool', 'toolVersion'])('bounds %s by its named label length', (field) => {
      const atCap = { ...base, [field]: chars(MAX_DOCUMENT_TRANSFORM_LABEL_LENGTH) };
      expect(documentMetaSchema.safeParse({ ...validMeta, transform: atCap }).success).toBe(true);
      const over = { ...base, [field]: chars(MAX_DOCUMENT_TRANSFORM_LABEL_LENGTH + 1) };
      const result = documentMetaSchema.safeParse({ ...validMeta, transform: over });
      expect(result.success).toBe(false);
      expect(paths(result)).toEqual([`transform.${field}`]);
      // And an empty label is refused too: a provenance record naming no tool
      // records nothing anyone could act on.
      expect(
        documentMetaSchema.safeParse({ ...validMeta, transform: { ...base, [field]: '' } }).success,
      ).toBe(false);
    });

    it('requires the pre-transform digest to be a real digest', () => {
      const result = documentMetaSchema.safeParse({
        ...validMeta,
        transform: { ...base, originalSha256: 'C'.repeat(64) },
      });
      expect(result.success).toBe(false);
      expect(paths(result)).toEqual(['transform.originalSha256']);
    });
  });

  it('parses its own output back to the identical value (the two directions agree)', () => {
    const first = documentMetaSchema.parse({
      ...validMeta,
      tags: ['  finance  ', 'audit'],
      note: 'signed',
    });
    const second = documentMetaSchema.safeParse(JSON.parse(JSON.stringify(first)));
    expect(second.success).toBe(true);
    expect(second.success ? second.data : null).toEqual(first);
  });
});

// ---------------------------------------------------------------------------
// initDocumentUploadSchema
// ---------------------------------------------------------------------------

describe('initDocumentUploadSchema', () => {
  it('accepts a valid body and lower-cases the folder id', () => {
    const result = initDocumentUploadSchema.safeParse({
      ...validInit,
      folderId: 'A'.repeat(24),
    });
    expect(result.success, JSON.stringify(paths(result))).toBe(true);
    expect(result.success ? result.data.folderId : null).toBe('a'.repeat(24));
  });

  it('strips a client-supplied chunk size, an object key and a vault key version', () => {
    // The negatives that keep the client out of the server's framing decisions:
    // `chunkPlaintextBytes` is assigned by the server from its own constant,
    // `objectKey` is server-assigned, and `vaultKeyVersion` is READ from the user.
    const result = initDocumentUploadSchema.safeParse({
      ...validInit,
      chunkPlaintextBytes: 64,
      objectKey: 'u/someone-else/d/x',
      vaultKeyVersion: 99,
    });
    expect(result.success).toBe(true);
    expect(result.success ? Object.keys(result.data).sort() : []).toEqual(
      [
        'dekIv',
        'dekTag',
        'declaredChunkCount',
        'declaredPlaintextBytes',
        'encryptedDek',
        'noncePrefix',
        'streamSalt',
      ].sort(),
    );
  });

  it.each([
    'encryptedDek',
    'dekIv',
    'dekTag',
    'streamSalt',
    'noncePrefix',
    'declaredPlaintextBytes',
    'declaredChunkCount',
  ])('rejects a body with no %s, and yields no partial value', (field) => {
    const payload = without(validInit, field);
    const result = initDocumentUploadSchema.safeParse(payload);
    expect(result.success).toBe(false);
    expect(Object.hasOwn(result, 'data')).toBe(false);
    expect(paths(result)).toContain(field);
  });

  it.each([
    { field: 'encryptedDek', max: 200 },
    { field: 'dekIv', max: 24 },
    { field: 'dekTag', max: 32 },
  ])('bounds $field at $max characters and refuses an empty one', ({ field, max }) => {
    expect(initDocumentUploadSchema.safeParse({ ...validInit, [field]: chars(max) }).success).toBe(
      true,
    );
    expect(
      initDocumentUploadSchema.safeParse({ ...validInit, [field]: chars(max + 1) }).success,
    ).toBe(false);
    expect(initDocumentUploadSchema.safeParse({ ...validInit, [field]: '' }).success).toBe(false);
  });

  describe('the base64 framing fields', () => {
    it.each([
      { field: 'streamSalt', bytes: DOCUMENT_STREAM_SALT_BYTES },
      { field: 'noncePrefix', bytes: DOCUMENT_NONCE_PREFIX_BYTES },
    ])('accepts $field at exactly $bytes bytes and nothing else', ({ field, bytes }) => {
      const exact = base64Bytes(bytes);
      expect(initDocumentUploadSchema.safeParse({ ...validInit, [field]: exact }).success).toBe(
        true,
      );
      // The reason a length check ALONE is not enough, stated rather than
      // implied: base64 emits `4 * ceil(n / 3)` characters, so one byte more
      // encodes to exactly the same number of characters as the right count and is
      // distinguishable only by its padding. A `.length()` on its own accepts it.
      expect(base64Bytes(bytes + 1)).toHaveLength(exact.length);
      // One byte short is still valid base64 and still fits any generous `.max()`,
      // which is exactly why the byte count is pinned: a truncated salt derives a
      // different stream key and fails only at decryption, three requests later.
      for (const wrong of [base64Bytes(bytes - 1), base64Bytes(bytes + 1)]) {
        const result = initDocumentUploadSchema.safeParse({ ...validInit, [field]: wrong });
        expect(result.success, `${field}=${wrong}`).toBe(false);
        // One byte over encodes to the same 44 (or 12) characters as the right
        // count, so it is refused by the PADDING rather than by the length, and one
        // byte under trips both. Every issue must still be about this field.
        expect([...new Set(paths(result))]).toEqual([field]);
      }
    });

    it('refuses base64url, unpadded base64 and a non-base64 alphabet', () => {
      const raw = Buffer.alloc(DOCUMENT_STREAM_SALT_BYTES, 0xfb);
      const standard = raw.toString('base64');
      expect(
        initDocumentUploadSchema.safeParse({ ...validInit, streamSalt: standard }).success,
      ).toBe(true);
      // base64url swaps `+` and `/` for `-` and `_`; the same 32 bytes, a
      // different string, and a different value once the server decodes it.
      expect(standard).toContain('+');
      const urlSafe = raw.toString('base64url');
      expect(
        initDocumentUploadSchema.safeParse({ ...validInit, streamSalt: urlSafe }).success,
      ).toBe(false);
      expect(
        initDocumentUploadSchema.safeParse({
          ...validInit,
          noncePrefix: base64Bytes(DOCUMENT_NONCE_PREFIX_BYTES).replace(/=+$/, ''),
        }).success,
      ).toBe(false);
      expect(
        initDocumentUploadSchema.safeParse({ ...validInit, streamSalt: chars(44, '!') }).success,
      ).toBe(false);
    });
  });

  it('bounds declaredChunkCount by MAX_DOCUMENT_CHUNK_COUNT, with the framing held consistent', () => {
    const atCap = {
      ...validInit,
      declaredPlaintextBytes: MAX_DOCUMENT_CHUNK_COUNT * DOCUMENT_PLAINTEXT_CHUNK_BYTES,
      declaredChunkCount: MAX_DOCUMENT_CHUNK_COUNT,
    };
    expect(initDocumentUploadSchema.safeParse(atCap).success).toBe(true);
    const over = initDocumentUploadSchema.safeParse({
      ...validInit,
      declaredPlaintextBytes: (MAX_DOCUMENT_CHUNK_COUNT + 1) * DOCUMENT_PLAINTEXT_CHUNK_BYTES,
      declaredChunkCount: MAX_DOCUMENT_CHUNK_COUNT + 1,
    });
    expect(over.success).toBe(false);
    expect(onlyIssue(over)).toMatchObject({ code: 'too_big', path: ['declaredChunkCount'] });
    expect(
      initDocumentUploadSchema.safeParse({ ...validInit, declaredChunkCount: 0 }).success,
    ).toBe(false);
  });

  it.each([
    { declaredPlaintextBytes: 0, declaredChunkCount: 1, ok: true, why: 'an empty file' },
    {
      declaredPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
      declaredChunkCount: 1,
      ok: true,
      why: 'exactly one segment',
    },
    {
      declaredPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES + 1,
      declaredChunkCount: 2,
      ok: true,
      why: 'one segment plus a byte',
    },
    {
      declaredPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES + 1,
      declaredChunkCount: 1,
      ok: false,
      why: 'a count that under-claims the size',
    },
    {
      declaredPlaintextBytes: 10,
      declaredChunkCount: 4,
      ok: false,
      why: 'a count that over-claims the size',
    },
  ])('declared framing: $why is $ok', ({ declaredPlaintextBytes, declaredChunkCount, ok }) => {
    const result = initDocumentUploadSchema.safeParse({
      ...validInit,
      declaredPlaintextBytes,
      declaredChunkCount,
    });
    expect(result.success).toBe(ok);
    if (!ok) {
      expect(onlyIssue(result)).toMatchObject({
        message: DOCUMENT_DECLARED_FRAMING_MESSAGE,
        path: ['declaredChunkCount'],
      });
    }
  });

  it('refuses a negative declared size and a malformed folder id', () => {
    expect(
      initDocumentUploadSchema.safeParse({ ...validInit, declaredPlaintextBytes: -1 }).success,
    ).toBe(false);
    expect(initDocumentUploadSchema.safeParse({ ...validInit, folderId: 'nope' }).success).toBe(
      false,
    );
  });
});

// ---------------------------------------------------------------------------
// completeDocumentUploadSchema
// ---------------------------------------------------------------------------

describe('completeDocumentUploadSchema', () => {
  it('accepts a valid body carrying the sealed metadata AND the wrapped DEK', () => {
    // The DEK is sent a second time on purpose: it is what makes a stale-version
    // 409 recoverable by rewrapping rather than by re-uploading the file.
    const result = completeDocumentUploadSchema.safeParse(validComplete);
    expect(result.success, JSON.stringify(paths(result))).toBe(true);
    expect(result.success ? result.data : null).toEqual(validComplete);
  });

  it.each([
    'encryptedMeta',
    'metaIv',
    'metaTag',
    'encryptedDek',
    'dekIv',
    'dekTag',
    'vaultKeyVersion',
  ])('rejects a body with no %s, and yields no partial value', (field) => {
    const payload = without(validComplete, field);
    const result = completeDocumentUploadSchema.safeParse(payload);
    expect(result.success).toBe(false);
    expect(Object.hasOwn(result, 'data')).toBe(false);
    expect(paths(result)).toContain(field);
  });

  it.each([
    { field: 'encryptedMeta', max: MAX_ENCRYPTED_DOCUMENT_META_LENGTH },
    { field: 'metaIv', max: 24 },
    { field: 'metaTag', max: 32 },
    { field: 'encryptedDek', max: 200 },
    // The DEK trio is bounded here as well as on the init body, because this is
    // the copy the row is written from: `PUT /documents/:id` cannot reach the DEK,
    // so a bound widened only here would be the one nothing else caught.
    { field: 'dekIv', max: 24 },
    { field: 'dekTag', max: 32 },
  ])('bounds $field at $max characters and refuses an empty one', ({ field, max }) => {
    expect(
      completeDocumentUploadSchema.safeParse({ ...validComplete, [field]: chars(max) }).success,
    ).toBe(true);
    expect(
      completeDocumentUploadSchema.safeParse({ ...validComplete, [field]: chars(max + 1) }).success,
    ).toBe(false);
    expect(completeDocumentUploadSchema.safeParse({ ...validComplete, [field]: '' }).success).toBe(
      false,
    );
  });

  it('accepts vault key version 0 (an account that has never rotated) and refuses a fraction', () => {
    expect(
      completeDocumentUploadSchema.safeParse({ ...validComplete, vaultKeyVersion: 0 }).success,
    ).toBe(true);
    for (const value of [-1, 1.5, Number.NaN]) {
      expect(
        completeDocumentUploadSchema.safeParse({ ...validComplete, vaultKeyVersion: value })
          .success,
      ).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// updateDocumentSchema
// ---------------------------------------------------------------------------

describe('updateDocumentSchema', () => {
  it('accepts an empty body, and accepts each attribute on its own', () => {
    const empty = updateDocumentSchema.safeParse({});
    expect(empty.success).toBe(true);
    expect(empty.success ? empty.data : null).toEqual({});
    expect(updateDocumentSchema.safeParse({ favorite: true }).success).toBe(true);
    expect(updateDocumentSchema.safeParse({ folderId: null }).success).toBe(true);
    const upper = updateDocumentSchema.safeParse({ folderId: 'B'.repeat(24) });
    expect(upper.success ? upper.data.folderId : null).toBe('b'.repeat(24));
  });

  it('accepts the metadata trio together', () => {
    const payload: UpdateDocumentInput = {
      encryptedMeta: 'bWV0YQ==',
      metaIv: 'aXY=',
      metaTag: 'dGFn',
    };
    expect(updateDocumentSchema.safeParse(payload).success).toBe(true);
  });

  it.each([{ omit: 'encryptedMeta' }, { omit: 'metaIv' }, { omit: 'metaTag' }])(
    'refuses the metadata trio with $omit missing',
    ({ omit }) => {
      const trio: UpdateDocumentInput = {
        encryptedMeta: 'bWV0YQ==',
        metaIv: 'aXY=',
        metaTag: 'dGFn',
      };
      const result = updateDocumentSchema.safeParse(without(trio, omit));
      expect(result.success).toBe(false);
      expect(onlyIssue(result)).toMatchObject({
        message: 'encryptedMeta, metaIv, and metaTag must all be provided together or all omitted',
      });
    },
  );

  it('cannot reach a framing field, the DEK or the object key', () => {
    // Content is immutable after upload: a segment is never rewritten, which is
    // what guarantees a nonce is never reused under a stream key. This is the wire
    // half of that guarantee, and the assertion is that the keys are GONE from the
    // parsed value rather than merely unused by a handler.
    const result = updateDocumentSchema.safeParse({
      favorite: true,
      chunkCount: 99,
      chunkPlaintextBytes: 1,
      plaintextBytes: 1,
      ciphertextBytes: 1,
      streamSalt: SALT,
      noncePrefix: PREFIX,
      encryptedDek: 'ZGVr',
      dekIv: 'aXY=',
      dekTag: 'dGFn',
      objectKey: 'u/someone-else/d/x',
      userId: 'a'.repeat(24),
      deletedAt: '2026-08-31T12:34:56.789Z',
    });
    expect(result.success).toBe(true);
    expect(result.success ? Object.keys(result.data) : []).toEqual(['favorite']);
  });

  it('bounds the sealed blob and refuses a malformed folder id', () => {
    const trio = (encryptedMeta: string): unknown => ({
      encryptedMeta,
      metaIv: 'aXY=',
      metaTag: 'dGFn',
    });
    expect(
      updateDocumentSchema.safeParse(trio(chars(MAX_ENCRYPTED_DOCUMENT_META_LENGTH))).success,
    ).toBe(true);
    expect(
      updateDocumentSchema.safeParse(trio(chars(MAX_ENCRYPTED_DOCUMENT_META_LENGTH + 1))).success,
    ).toBe(false);
    expect(updateDocumentSchema.safeParse({ folderId: 'nope' }).success).toBe(false);
  });

  it.each([
    { field: 'metaIv', max: 24 },
    { field: 'metaTag', max: 32 },
  ])('bounds $field at $max characters, the same as on the completion body', ({ field, max }) => {
    // This is the OTHER endpoint that writes a sealed blob (a rename re-seals it),
    // so the two schemas have to agree: a bound widened on one of them alone lets a
    // value through that the model then refuses with a 500 instead of a 400.
    const withField = (value: string): unknown => ({
      encryptedMeta: 'bWV0YQ==',
      metaIv: 'aXY=',
      metaTag: 'dGFn',
      [field]: value,
    });
    expect(updateDocumentSchema.safeParse(withField(chars(max))).success).toBe(true);
    expect(updateDocumentSchema.safeParse(withField(chars(max + 1))).success).toBe(false);
    expect(updateDocumentSchema.safeParse(withField('')).success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Query schemas
// ---------------------------------------------------------------------------

describe('listDocumentsSchema', () => {
  it('defaults page, limit and the sort, so a bare query is fully populated', () => {
    const result = listDocumentsSchema.safeParse({});
    expect(result.success).toBe(true);
    const parsed: ListDocumentsInput | undefined = result.success ? result.data : undefined;
    expect(parsed).toEqual({
      page: PAGINATION_DEFAULTS.PAGE,
      limit: PAGINATION_DEFAULTS.LIMIT,
      sortBy: 'updatedAt',
      sortOrder: 'desc',
    });
  });

  it('reads ?favorite=false as FALSE', () => {
    // `z.coerce.boolean()` is `Boolean(input)`, which makes every non-empty string
    // true and inverts this filter. `z.stringbool()` is what keeps the query
    // meaning what it says, and it is deliberately strict about the vocabulary.
    expect(listDocumentsSchema.parse({ favorite: 'false' }).favorite).toBe(false);
    expect(listDocumentsSchema.parse({ favorite: 'true' }).favorite).toBe(true);
    expect(listDocumentsSchema.safeParse({ favorite: 'maybe' }).success).toBe(false);
  });

  it('offers no name sort, because the name is inside the encrypted blob', () => {
    for (const sortBy of ['createdAt', 'updatedAt', 'favorite']) {
      expect(listDocumentsSchema.safeParse({ sortBy }).success).toBe(true);
    }
    for (const sortBy of ['name', 'mime', 'plaintextBytes', 'deletedAt']) {
      expect(listDocumentsSchema.safeParse({ sortBy }).success, sortBy).toBe(false);
    }
  });

  it('keeps the pagination bounds it inherits, and coerces the numeric strings a query carries', () => {
    expect(listDocumentsSchema.parse({ page: '3', limit: '7' })).toMatchObject({
      page: 3,
      limit: 7,
    });
    expect(
      listDocumentsSchema.safeParse({ limit: String(PAGINATION_DEFAULTS.MAX_LIMIT) }).success,
    ).toBe(true);
    expect(
      listDocumentsSchema.safeParse({ limit: String(PAGINATION_DEFAULTS.MAX_LIMIT + 1) }).success,
    ).toBe(false);
    expect(listDocumentsSchema.safeParse({ page: '0' }).success).toBe(false);
    expect(listDocumentsSchema.safeParse({ folderId: 'nope' }).success).toBe(false);
  });
});

describe('listDocumentTrashSchema', () => {
  it('defaults to the most recently trashed first', () => {
    const result = listDocumentTrashSchema.safeParse({});
    expect(result.success).toBe(true);
    const parsed: ListDocumentTrashInput | undefined = result.success ? result.data : undefined;
    expect(parsed).toEqual({
      page: PAGINATION_DEFAULTS.PAGE,
      limit: PAGINATION_DEFAULTS.LIMIT,
      sortBy: 'deletedAt',
      sortOrder: 'desc',
    });
  });

  it('sorts by deletedAt, and refuses a sort the trash view has no column for', () => {
    expect(listDocumentTrashSchema.safeParse({ sortBy: 'deletedAt' }).success).toBe(true);
    expect(listDocumentTrashSchema.safeParse({ sortBy: 'favorite' }).success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Path parameter schemas
// ---------------------------------------------------------------------------

describe('documentPartParamsSchema', () => {
  it('keeps `id` in the parsed params, which is what stops the controller reading undefined', () => {
    // `validate()` REPLACES `req.params` wholesale and `z.object()` strips by
    // default, so a schema naming only `partNumber` would DELETE `id` from the
    // request. This is that guarantee, asserted rather than assumed.
    const result = documentPartParamsSchema.safeParse({ id: HEX24, partNumber: '2' });
    expect(result.success, JSON.stringify(paths(result))).toBe(true);
    const parsed: DocumentPartParams | undefined = result.success ? result.data : undefined;
    expect(parsed).toEqual({ id: HEX24, partNumber: 2 });
    // A NUMBER, not the string the router handed over: the controller compares it
    // with `declaredChunkCount`.
    expect(typeof parsed?.partNumber).toBe('number');
    expect(documentPartParamsSchema.safeParse({ partNumber: '2' }).success).toBe(false);
  });

  it('lower-cases the id, so a mixed-case path cannot bypass an ownership check', () => {
    const result = documentPartParamsSchema.safeParse({ id: 'A'.repeat(24), partNumber: '1' });
    expect(result.success ? result.data.id : null).toBe('a'.repeat(24));
  });

  it.each([
    { value: '1', ok: true, why: 'the first part' },
    { value: String(MAX_DOCUMENT_CHUNK_COUNT), ok: true, why: 'the last addressable part' },
    { value: '0', ok: false, why: 'zero (S3 part numbers are 1-based)' },
    { value: String(MAX_DOCUMENT_CHUNK_COUNT + 1), ok: false, why: 'one past the ceiling' },
    { value: '-1', ok: false, why: 'a negative number' },
    { value: '01', ok: false, why: 'a leading zero' },
    { value: '1.5', ok: false, why: 'a fraction' },
    { value: '0x10', ok: false, why: 'hexadecimal, which Number() would read as 16' },
    { value: '1e3', ok: false, why: 'exponential notation, which Number() would read as 1000' },
    { value: ' 1 ', ok: false, why: 'padding, which Number() would trim away' },
    { value: '', ok: false, why: 'an empty string, which Number() would read as 0' },
    { value: 'abc', ok: false, why: 'prose' },
  ])('partNumber: $why is $ok', ({ value, ok }) => {
    const result = documentPartParamsSchema.safeParse({ id: HEX24, partNumber: value });
    expect(result.success).toBe(ok);
    if (!ok) expect(paths(result)).toEqual(['partNumber']);
  });
});

describe('documentSegmentParamsSchema', () => {
  it.each([
    { value: '0', ok: true, expected: 0, why: 'the first segment (indices are 0-based)' },
    {
      value: String(MAX_DOCUMENT_CHUNK_COUNT - 1),
      ok: true,
      expected: MAX_DOCUMENT_CHUNK_COUNT - 1,
      why: 'the last addressable segment',
    },
    {
      value: String(MAX_DOCUMENT_CHUNK_COUNT),
      ok: false,
      expected: undefined,
      why: 'one past the ceiling',
    },
    { value: '-1', ok: false, expected: undefined, why: 'a negative index' },
    { value: 'abc', ok: false, expected: undefined, why: 'prose' },
  ])('index: $why is $ok', ({ value, ok, expected }) => {
    const result = documentSegmentParamsSchema.safeParse({ id: HEX24, index: value });
    expect(result.success).toBe(ok);
    if (ok) {
      const parsed: DocumentSegmentParams | undefined = result.success ? result.data : undefined;
      expect(parsed).toEqual({ id: HEX24, index: expected });
    }
  });

  it('declares `id` too, for the same reason the part schema does', () => {
    expect(documentSegmentParamsSchema.safeParse({ index: '0' }).success).toBe(false);
    const result = documentSegmentParamsSchema.safeParse({ id: HEX24, index: '0' });
    expect(result.success ? Object.keys(result.data).sort() : []).toEqual(['id', 'index']);
  });
});

// ---------------------------------------------------------------------------
// Response schemas
// ---------------------------------------------------------------------------

describe('documentResponseSchema', () => {
  it('accepts a row and strips the two columns the API never sends', () => {
    const result = documentResponseSchema.safeParse({
      ...validRow,
      userId: 'a'.repeat(24),
      objectKey: `u/${'a'.repeat(24)}/d/${HEX24}`,
      __v: 0,
    });
    expect(result.success, JSON.stringify(paths(result))).toBe(true);
    expect(result.success ? result.data : null).toEqual(validRow);
  });

  it('accepts the trash and purge columns when they are present, and does not invent them', () => {
    const trashed = { ...validRow, deletedAt: '2026-08-31T13:00:00.000Z', purgePending: true };
    expect(documentResponseSchema.safeParse(trashed).success).toBe(true);
    const active = documentResponseSchema.safeParse(validRow);
    expect(active.success ? 'deletedAt' in active.data : true).toBe(false);
    expect(active.success ? 'purgePending' in active.data : true).toBe(false);
  });

  it('accepts an empty document, whose object is exactly one authentication tag', () => {
    const empty = {
      ...validRow,
      plaintextBytes: 0,
      chunkCount: 1,
      ciphertextBytes: DOCUMENT_TAG_BYTES,
    };
    expect(documentResponseSchema.safeParse(empty).success).toBe(true);
    expect(
      documentResponseSchema.safeParse({ ...empty, ciphertextBytes: DOCUMENT_TAG_BYTES - 1 })
        .success,
    ).toBe(false);
  });

  it('refuses a row whose segment count disagrees with its plaintext size', () => {
    const result = documentResponseSchema.safeParse({
      ...validRow,
      plaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES + 1,
      chunkCount: 1,
      ciphertextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES + 1 + DOCUMENT_TAG_BYTES,
    });
    expect(result.success).toBe(false);
    expect(onlyIssue(result)).toMatchObject({
      message: DOCUMENT_FRAMING_MISMATCH_MESSAGE,
      path: ['chunkCount'],
    });
  });

  it('refuses a row whose two size columns are not one tag per segment apart', () => {
    // The identity the server establishes at completion: `plaintextBytes` IS
    // `ciphertextBytes - DOCUMENT_TAG_BYTES * chunkCount`, both derived from the
    // part ledger. Checking it costs nothing when the server is right and is the
    // client's only chance to notice when it is not.
    const twoSegments = {
      ...validRow,
      plaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES + 10,
      chunkCount: 2,
    };
    expect(
      documentResponseSchema.safeParse({
        ...twoSegments,
        ciphertextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES + 10 + DOCUMENT_TAG_BYTES * 2,
      }).success,
    ).toBe(true);
    const result = documentResponseSchema.safeParse({
      ...twoSegments,
      ciphertextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES + 10 + DOCUMENT_TAG_BYTES,
    });
    expect(result.success).toBe(false);
    expect(onlyIssue(result)).toMatchObject({
      message: DOCUMENT_CIPHERTEXT_SIZE_MISMATCH_MESSAGE,
      path: ['ciphertextBytes'],
    });
  });

  it.each([
    '_id',
    'favorite',
    'encryptedDek',
    'streamSalt',
    'encryptedMeta',
    'chunkCount',
    'createdAt',
  ])('rejects a row with no %s, and yields no partial value', (field) => {
    const payload = without(validRow, field);
    const result = documentResponseSchema.safeParse(payload);
    expect(result.success).toBe(false);
    expect(Object.hasOwn(result, 'data')).toBe(false);
  });

  it('refuses an id that is not a 24-character lower-case hex string', () => {
    // The id is HKDF `info` material: the wrong id derives three different keys
    // and produces a document that decrypts to nothing, with no error until the
    // AEAD fails.
    for (const _id of ['A'.repeat(24), 'a'.repeat(23), 'a'.repeat(25), 'zzz', '']) {
      expect(documentResponseSchema.safeParse({ ...validRow, _id }).success, _id).toBe(false);
    }
  });

  it('refuses a truncated framing field', () => {
    expect(
      documentResponseSchema.safeParse({
        ...validRow,
        streamSalt: base64Bytes(DOCUMENT_STREAM_SALT_BYTES - 1),
      }).success,
    ).toBe(false);
    expect(
      documentResponseSchema.safeParse({
        ...validRow,
        noncePrefix: base64Bytes(DOCUMENT_NONCE_PREFIX_BYTES + 1),
      }).success,
    ).toBe(false);
  });
});

describe('documentUploadResponseSchema', () => {
  it('accepts a staging row and drops the wrapped DEK the client does not need', () => {
    const result = documentUploadResponseSchema.safeParse({
      ...validUploadRow,
      encryptedDek: 'ZGVr',
      dekIv: 'aXY=',
      dekTag: 'dGFn',
      userId: 'a'.repeat(24),
      objectKey: 'u/x/d/y',
      s3UploadId: 'engine-side-id',
    });
    expect(result.success, JSON.stringify(paths(result))).toBe(true);
    expect(result.success ? result.data : null).toEqual(validUploadRow);
  });

  it('accepts an upload with no parts yet, and an entry per received part', () => {
    expect(
      documentUploadResponseSchema.safeParse({ ...validUploadRow, parts: [], receivedBytes: 0 })
        .success,
    ).toBe(true);
    const twoParts = documentUploadResponseSchema.safeParse({
      ...validUploadRow,
      declaredPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES + 10,
      declaredChunkCount: 2,
      parts: [
        { partNumber: 1, bytes: DOCUMENT_CIPHERTEXT_CHUNK_BYTES, etag: '"deadbeef"' },
        { partNumber: 2, bytes: 10 + DOCUMENT_TAG_BYTES },
      ],
    });
    expect(twoParts.success).toBe(true);
    // The engine's etag is stripped: it is a storage detail, and the client needs
    // only which parts arrived and how big they were.
    expect(twoParts.success ? twoParts.data.parts[0] : null).toEqual({
      partNumber: 1,
      bytes: DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
    });
  });

  it('bounds a part by one tag below and one ciphertext chunk above', () => {
    const withPart = (bytes: number): unknown => ({
      ...validUploadRow,
      parts: [{ partNumber: 1, bytes }],
    });
    expect(documentUploadResponseSchema.safeParse(withPart(DOCUMENT_TAG_BYTES)).success).toBe(true);
    expect(documentUploadResponseSchema.safeParse(withPart(DOCUMENT_TAG_BYTES - 1)).success).toBe(
      false,
    );
    expect(
      documentUploadResponseSchema.safeParse(withPart(DOCUMENT_CIPHERTEXT_CHUNK_BYTES)).success,
    ).toBe(true);
    expect(
      documentUploadResponseSchema.safeParse(withPart(DOCUMENT_CIPHERTEXT_CHUNK_BYTES + 1)).success,
    ).toBe(false);
    expect(
      documentUploadResponseSchema.safeParse({
        ...validUploadRow,
        parts: [{ partNumber: 0, bytes: DOCUMENT_TAG_BYTES }],
      }).success,
    ).toBe(false);
  });

  it.each(['_id', 'streamSalt', 'declaredChunkCount', 'vaultKeyVersion', 'parts', 'expiresAt'])(
    'rejects a staging row with no %s, and yields no partial value',
    (field) => {
      const result = documentUploadResponseSchema.safeParse(without(validUploadRow, field));
      expect(result.success).toBe(false);
      expect(Object.hasOwn(result, 'data')).toBe(false);
      expect(paths(result)).toContain(field);
    },
  );
});

describe('initDocumentUploadResponseSchema', () => {
  it('accepts the three values the client needs before it seals the first byte', () => {
    const payload: InitDocumentUploadResponse = {
      uploadId: HEX24,
      vaultKeyVersion: 0,
      chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    };
    const result = initDocumentUploadResponseSchema.safeParse(payload);
    expect(result.success, JSON.stringify(paths(result))).toBe(true);
    expect(result.success ? result.data : null).toEqual(payload);
  });

  it('refuses a malformed upload id, because it is the future document id', () => {
    for (const uploadId of ['A'.repeat(24), 'a'.repeat(23), 'not-an-id']) {
      expect(
        initDocumentUploadResponseSchema.safeParse({
          uploadId,
          vaultKeyVersion: 0,
          chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
        }).success,
        uploadId,
      ).toBe(false);
    }
  });

  it('refuses a chunk size of 0, which would make every segment boundary a division by zero', () => {
    expect(
      initDocumentUploadResponseSchema.safeParse({
        uploadId: HEX24,
        vaultKeyVersion: 0,
        chunkPlaintextBytes: 0,
      }).success,
    ).toBe(false);
  });
});

describe('documentUsageResponseSchema', () => {
  it('accepts an account with nothing stored, and an account at its quota', () => {
    const empty: DocumentUsageResponse = {
      documentCount: 0,
      usedBytes: 0,
      quotaBytes: 2048 * 1024 * 1024,
      maxDocumentSizeBytes: 100 * 1024 * 1024,
    };
    expect(documentUsageResponseSchema.safeParse(empty).success).toBe(true);
    expect(
      documentUsageResponseSchema.safeParse({
        ...empty,
        documentCount: 12,
        usedBytes: empty.quotaBytes,
      }).success,
    ).toBe(true);
  });

  it('refuses a quota or a size cap of zero, which would refuse every upload', () => {
    const base = {
      documentCount: 0,
      usedBytes: 0,
      quotaBytes: 1,
      maxDocumentSizeBytes: 1,
    };
    expect(documentUsageResponseSchema.safeParse({ ...base, quotaBytes: 0 }).success).toBe(false);
    expect(
      documentUsageResponseSchema.safeParse({ ...base, maxDocumentSizeBytes: 0 }).success,
    ).toBe(false);
    expect(documentUsageResponseSchema.safeParse({ ...base, usedBytes: -1 }).success).toBe(false);
    expect(documentUsageResponseSchema.safeParse({ ...base, documentCount: 1.5 }).success).toBe(
      false,
    );
  });
});
