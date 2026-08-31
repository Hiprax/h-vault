import { describe, it, expect } from 'vitest';
import { publicConfigDataSchema, publicConfigResponseSchema } from '../src/schemas/config.js';
import type { PublicConfig } from '../src/types/index.js';
import {
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  MAX_DOCUMENT_EXT_LENGTH,
  MAX_DOCUMENTS_PER_USER,
} from '../src/constants/index.js';

describe('publicConfigResponseSchema', () => {
  it('accepts a valid response envelope', () => {
    const result = publicConfigResponseSchema.safeParse({
      success: true,
      data: { fileEncryption: { maxSizeMB: 100 } },
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.data.fileEncryption.maxSizeMB).toBe(100);
    }
  });

  it('accepts an optional message field', () => {
    const result = publicConfigResponseSchema.safeParse({
      success: true,
      data: { fileEncryption: { maxSizeMB: 25 } },
      message: 'ok',
    });
    expect(result.success).toBe(true);
  });

  it('rejects a missing maxSizeMB', () => {
    const result = publicConfigResponseSchema.safeParse({
      success: true,
      data: { fileEncryption: {} },
    });
    expect(result.success).toBe(false);
  });

  it('rejects a missing fileEncryption object', () => {
    const result = publicConfigResponseSchema.safeParse({
      success: true,
      data: {},
    });
    expect(result.success).toBe(false);
  });

  it('rejects a negative maxSizeMB', () => {
    const result = publicConfigResponseSchema.safeParse({
      success: true,
      data: { fileEncryption: { maxSizeMB: -1 } },
    });
    expect(result.success).toBe(false);
  });

  it('rejects a zero maxSizeMB (must be positive)', () => {
    const result = publicConfigResponseSchema.safeParse({
      success: true,
      data: { fileEncryption: { maxSizeMB: 0 } },
    });
    expect(result.success).toBe(false);
  });

  it('rejects a non-integer maxSizeMB', () => {
    const result = publicConfigResponseSchema.safeParse({
      success: true,
      data: { fileEncryption: { maxSizeMB: 12.5 } },
    });
    expect(result.success).toBe(false);
  });

  it('rejects a success:false envelope', () => {
    const result = publicConfigResponseSchema.safeParse({
      success: false,
      data: { fileEncryption: { maxSizeMB: 100 } },
    });
    expect(result.success).toBe(false);
  });
});

describe('publicConfigDataSchema', () => {
  it('validates the inner PublicConfig shape independently', () => {
    const result = publicConfigDataSchema.safeParse({
      fileEncryption: { maxSizeMB: 1 },
    });
    expect(result.success).toBe(true);
  });

  it('rejects a negative maxSizeMB', () => {
    const result = publicConfigDataSchema.safeParse({
      fileEncryption: { maxSizeMB: -5 },
    });
    expect(result.success).toBe(false);
  });
});

/**
 * The `documents` block, in the three states a client has to tell apart: ABSENT
 * (a server older than the feature), present with `enabled: false` (this server,
 * with no object storage configured), and present with `enabled: true` and the
 * numbers.
 *
 * The first of those three is the one with a release-shaped failure mode, which is
 * why it is the first case below: a REQUIRED block here would make a current client
 * refuse an older server's whole envelope, and the visible symptom would be the
 * File Encryption cap silently falling back to its built-in default, in a feature
 * that has nothing to do with documents.
 */
describe('publicConfigDataSchema — the documents block', () => {
  const numbers = {
    enabled: true,
    maxSizeMB: 100,
    chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    maxDocuments: MAX_DOCUMENTS_PER_USER,
    quotaMB: 2_048,
    allowedExtensions: ['pdf', 'md'],
  };

  it('parses a payload carrying ONLY fileEncryption, and adds no block', () => {
    const result = publicConfigDataSchema.safeParse({ fileEncryption: { maxSizeMB: 100 } });
    expect(result.success).toBe(true);
    // The negative: no `documents: { enabled: false }` is invented on the client's
    // behalf, because "absent" and "disabled" are different facts about the server
    // and only the server can tell them apart.
    expect(result.success ? 'documents' in result.data : true).toBe(false);
  });

  it('parses { enabled: false } on its own', () => {
    const result = publicConfigDataSchema.safeParse({
      fileEncryption: { maxSizeMB: 100 },
      documents: { enabled: false },
    });
    expect(result.success).toBe(true);
    expect(result.success ? result.data.documents : null).toEqual({ enabled: false });
  });

  it('parses an enabled block carrying every number and the extension list', () => {
    const result = publicConfigDataSchema.safeParse({
      fileEncryption: { maxSizeMB: 100 },
      documents: numbers,
    });
    expect(result.success).toBe(true);
    expect(result.success ? result.data.documents : null).toEqual(numbers);
  });

  it('rejects a block with no enabled flag at all, and yields no partial config', () => {
    // `enabled` is what the client's feature flag reads; a block without it would
    // leave the UI deciding from the presence of the numbers instead.
    const result = publicConfigDataSchema.safeParse({
      fileEncryption: { maxSizeMB: 100 },
      documents: { maxSizeMB: 100, quotaMB: 2_048 },
    });
    expect(result.success).toBe(false);
    expect(Object.hasOwn(result, 'data')).toBe(false);
    expect(result.success ? [] : result.error.issues.map((issue) => issue.path.join('.'))).toEqual([
      'documents.enabled',
    ]);
  });

  it.each([
    { field: 'maxSizeMB', value: 0, why: 'a zero size cap' },
    { field: 'maxSizeMB', value: -1, why: 'a negative size cap' },
    { field: 'maxSizeMB', value: 12.5, why: 'a fractional size cap' },
    { field: 'maxSizeMB', value: '100', why: 'a numeric string' },
    { field: 'chunkPlaintextBytes', value: 0, why: 'a zero chunk size' },
    { field: 'maxDocuments', value: 0, why: 'a document ceiling of zero' },
    { field: 'quotaMB', value: -2_048, why: 'a negative quota' },
  ])('rejects $why on $field', ({ field, value }) => {
    const result = publicConfigDataSchema.safeParse({
      fileEncryption: { maxSizeMB: 100 },
      documents: { ...numbers, [field]: value },
    });
    expect(result.success).toBe(false);
    expect(Object.hasOwn(result, 'data')).toBe(false);
  });

  it('bounds each advertised extension by the same bound the metadata blob uses', () => {
    const withExtensions = (allowedExtensions: unknown): unknown => ({
      fileEncryption: { maxSizeMB: 100 },
      documents: { enabled: true, allowedExtensions },
    });
    expect(publicConfigDataSchema.safeParse(withExtensions([])).success).toBe(true);
    expect(
      publicConfigDataSchema.safeParse(withExtensions(['x'.repeat(MAX_DOCUMENT_EXT_LENGTH)]))
        .success,
    ).toBe(true);
    expect(
      publicConfigDataSchema.safeParse(withExtensions(['x'.repeat(MAX_DOCUMENT_EXT_LENGTH + 1)]))
        .success,
    ).toBe(false);
    expect(publicConfigDataSchema.safeParse(withExtensions(['pdf', 7])).success).toBe(false);
    expect(publicConfigDataSchema.safeParse(withExtensions('pdf,md')).success).toBe(false);
  });

  it('strips an unknown key inside the block instead of rejecting it', () => {
    const result = publicConfigDataSchema.safeParse({
      fileEncryption: { maxSizeMB: 100 },
      documents: { enabled: true, previewModes: ['image'] },
    });
    expect(result.success).toBe(true);
    expect(result.success ? result.data.documents : null).toEqual({ enabled: true });
  });

  it('rejects a null block, which is not the same thing as an absent one', () => {
    expect(
      publicConfigDataSchema.safeParse({
        fileEncryption: { maxSizeMB: 100 },
        documents: null,
      }).success,
    ).toBe(false);
  });

  it('carries the block through the response envelope', () => {
    const result = publicConfigResponseSchema.safeParse({
      success: true,
      data: { fileEncryption: { maxSizeMB: 100 }, documents: numbers },
    });
    expect(result.success).toBe(true);
    expect(result.success ? result.data.data.documents?.maxDocuments : null).toBe(
      MAX_DOCUMENTS_PER_USER,
    );
  });

  it('keeps the PublicConfig interface and the schema in step', () => {
    // The interface is what every server and client call site is typed against and
    // the schema is what validates the wire, so a field on one and not the other is
    // a silent divergence. Assigning a fully populated literal to the interface and
    // parsing the SAME value proves both directions agree.
    const config: PublicConfig = { fileEncryption: { maxSizeMB: 100 }, documents: numbers };
    const result = publicConfigDataSchema.safeParse(config);
    expect(result.success).toBe(true);
    expect(result.success ? result.data : null).toEqual(config);
    // And the older-server shape is assignable too, which is the type-level half of
    // the optionality the first case in this block asserts at runtime.
    const older: PublicConfig = { fileEncryption: { maxSizeMB: 25 } };
    expect(publicConfigDataSchema.safeParse(older).success).toBe(true);
  });
});
