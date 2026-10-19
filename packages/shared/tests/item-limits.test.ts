import { describe, it, expect } from 'vitest';
// Through the barrel, so a symbol the barrel forgot to re-export fails here rather
// than as an unresolvable import in a client chunk.
import {
  DEFAULT_CUSTOM_FIELDS_LIMIT,
  MAX_CUSTOM_FIELDS_PER_ITEM,
  MAX_ENCRYPTED_NAME_LENGTH,
  MAX_ITEM_NAME_BYTES,
  MIN_CUSTOM_FIELDS_LIMIT,
  cardDataSchema,
  noteDataSchema,
  publicConfigDataSchema,
  publicConfigResponseSchema,
  vaultConfigResponseSchema,
} from '../src/index.js';

/** Padded base64 length of `bytes` bytes: what a sealed name is stored as. */
function base64Length(bytes: number): number {
  return 4 * Math.ceil(bytes / 3);
}

function fields(count: number) {
  return Array.from({ length: count }, (_, i) => ({
    name: `Field ${String(i + 1)}`,
    value: `value ${String(i + 1)}`,
    type: 'text' as const,
  }));
}

describe('custom-field limit constants', () => {
  it('pins the default limit at 30 and the minimum at 1', () => {
    expect(DEFAULT_CUSTOM_FIELDS_LIMIT).toBe(30);
    expect(MIN_CUSTOM_FIELDS_LIMIT).toBe(1);
  });

  it('keeps the default inside the advertised range, never above the stored cap', () => {
    // A default above `MAX_CUSTOM_FIELDS_PER_ITEM` would let the editor build an
    // entry the decrypt-side schema then refuses.
    expect(DEFAULT_CUSTOM_FIELDS_LIMIT).toBeGreaterThanOrEqual(MIN_CUSTOM_FIELDS_LIMIT);
    expect(DEFAULT_CUSTOM_FIELDS_LIMIT).toBeLessThanOrEqual(MAX_CUSTOM_FIELDS_PER_ITEM);
  });
});

describe('MAX_ITEM_NAME_BYTES', () => {
  it('is the largest UTF-8 length whose sealed base64 fits MAX_ENCRYPTED_NAME_LENGTH', () => {
    expect(MAX_ITEM_NAME_BYTES).toBe(750);
    expect(base64Length(MAX_ITEM_NAME_BYTES)).toBeLessThanOrEqual(MAX_ENCRYPTED_NAME_LENGTH);
    // One byte more no longer fits: the bound is tight, not merely safe.
    expect(base64Length(MAX_ITEM_NAME_BYTES + 1)).toBeGreaterThan(MAX_ENCRYPTED_NAME_LENGTH);
  });
});

describe.each([
  ['noteDataSchema', noteDataSchema],
  ['cardDataSchema', cardDataSchema],
] as const)('%s customFields', (_label, schema) => {
  it('stays ABSENT when the stored data has none, injecting no key', () => {
    // The load-bearing half: a default would add `customFields: []` to every stored
    // entry's parsed data and move its import content hash.
    const parsed = schema.parse({}) as Record<string, unknown>;
    expect('customFields' in parsed).toBe(false);
  });

  it('keeps an empty list as an empty list', () => {
    const parsed = schema.parse({ customFields: [] }) as { customFields?: unknown[] };
    expect(parsed.customFields).toEqual([]);
  });

  it('accepts every field type, preserving each row', () => {
    const rows = [
      { name: 'PIN', value: '1234', type: 'hidden' },
      { name: 'Branch', value: 'Main St', type: 'text' },
      { name: 'Contactless', value: 'true', type: 'boolean' },
    ];
    const parsed = schema.parse({ customFields: rows }) as { customFields?: unknown[] };
    expect(parsed.customFields).toEqual(rows);
  });

  it('accepts exactly the stored cap and refuses one more', () => {
    expect(schema.safeParse({ customFields: fields(MAX_CUSTOM_FIELDS_PER_ITEM) }).success).toBe(
      true,
    );
    const over = schema.safeParse({ customFields: fields(MAX_CUSTOM_FIELDS_PER_ITEM + 1) });
    expect(over.success).toBe(false);
    expect(over.error?.issues[0]?.path).toEqual(['customFields']);
  });

  it('refuses a row with a blank name or an unknown type, at that row', () => {
    const blank = schema.safeParse({ customFields: [{ name: '', value: 'x', type: 'text' }] });
    expect(blank.success).toBe(false);
    expect(blank.error?.issues[0]?.path).toEqual(['customFields', 0, 'name']);

    const unknownType = schema.safeParse({
      customFields: [{ name: 'a', value: 'x', type: 'secret' }],
    });
    expect(unknownType.success).toBe(false);
    expect(unknownType.error?.issues[0]?.path).toEqual(['customFields', 0, 'type']);
  });
});

describe('publicConfigDataSchema: the vault block', () => {
  const base = { fileEncryption: { maxSizeMB: 100 } };

  it('is optional, and its absence adds no block', () => {
    const parsed = publicConfigDataSchema.parse(base);
    expect('vault' in parsed).toBe(false);
  });

  it.each([MIN_CUSTOM_FIELDS_LIMIT, DEFAULT_CUSTOM_FIELDS_LIMIT, MAX_CUSTOM_FIELDS_PER_ITEM])(
    'accepts a limit of %i',
    (customFieldsLimit) => {
      const parsed = publicConfigDataSchema.parse({ ...base, vault: { customFieldsLimit } });
      expect(parsed.vault?.customFieldsLimit).toBe(customFieldsLimit);
    },
  );

  it.each([
    ['zero', MIN_CUSTOM_FIELDS_LIMIT - 1],
    ['one above the stored cap', MAX_CUSTOM_FIELDS_PER_ITEM + 1],
    ['a fraction', 1.5],
    ['a string', '30'],
    ['null', null],
  ])('refuses %s', (_label, customFieldsLimit) => {
    expect(
      publicConfigDataSchema.safeParse({ ...base, vault: { customFieldsLimit } }).success,
    ).toBe(false);
  });

  it('refuses a vault block without the limit', () => {
    expect(publicConfigDataSchema.safeParse({ ...base, vault: {} }).success).toBe(false);
  });
});

describe('vaultConfigResponseSchema', () => {
  it('reads the limit out of an envelope whose other blocks are malformed', () => {
    const envelope = {
      success: true,
      data: {
        fileEncryption: { maxSizeMB: -1 },
        documents: { maxSizeMB: -1 },
        vault: { customFieldsLimit: 12 },
      },
    };
    expect(publicConfigResponseSchema.safeParse(envelope).success).toBe(false);

    const narrowed = vaultConfigResponseSchema.safeParse(envelope);
    expect(narrowed.success).toBe(true);
    expect(narrowed.success ? narrowed.data.data.vault?.customFieldsLimit : null).toBe(12);
    // Stripped, not carried: a caller cannot read a block nothing validated.
    expect(narrowed.success ? 'documents' in narrowed.data.data : true).toBe(false);
  });

  it('parses an envelope with no vault block as having none', () => {
    const narrowed = vaultConfigResponseSchema.safeParse({
      success: true,
      data: { fileEncryption: { maxSizeMB: 100 } },
    });
    expect(narrowed.success).toBe(true);
    expect(narrowed.success ? narrowed.data.data.vault : 'unparsed').toBeUndefined();
  });

  it('still refuses an envelope whose vault block is the broken one', () => {
    expect(
      vaultConfigResponseSchema.safeParse({
        success: true,
        data: { vault: { customFieldsLimit: 0 } },
      }).success,
    ).toBe(false);
  });
});
