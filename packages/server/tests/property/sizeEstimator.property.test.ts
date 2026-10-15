/**
 * The backup/export size estimator never undercounts what the stream writes (F-25).
 *
 * Downloads and exports are streamed, so the size limit is decided by this
 * estimate BEFORE the first byte, and nothing checks the real size afterwards.
 * The estimate must therefore be >= the bytes `JSON.stringify` produces for every
 * row the API can store. It used to count each string's raw UTF-8 length, but
 * JSON writes a control character as a six-byte escape (and `"` and `\` as two),
 * and the ciphertext fields and tags accept any character: a vault of such rows
 * streamed several times the limit, behind an estimate that admitted it.
 */
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { estimateFolderJsonSize, estimateItemJsonSize } from '../../src/utils/sizeEstimator.js';
import { propertyBanner, propertyRun } from '../../../../tests/harness/property.js';

const OBJECT_ID = '507f1f77bcf86cd799439011';
const ISO = '2026-10-14T12:00:00.000Z';

/** The characters JSON escapes, and lone surrogates, which it escapes too. */
const ESCAPED = fc.constantFrom('\u0000', '\u0001', '\u001f', '"', '\\', '\n', '\ud800', '\udfff');

/**
 * Any string at all (every code point, lone surrogates and control characters
 * included), and half the time one made only of characters JSON escapes, which a
 * uniform draw over code points almost never produces enough of to matter.
 */
const anyText = (maxLength: number) =>
  fc.oneof(fc.string({ unit: 'binary', maxLength }), fc.string({ unit: ESCAPED, maxLength }));

const itemArbitrary = fc.record({
  encryptedData: anyText(2_000),
  dataIv: anyText(24),
  dataTag: anyText(32),
  encryptedName: anyText(200),
  nameIv: anyText(24),
  nameTag: anyText(32),
  tags: fc.array(anyText(50), { maxLength: 20 }),
  passwordHistory: fc.option(
    fc.array(fc.record({ encryptedPassword: anyText(400), iv: anyText(24), tag: anyText(32) }), {
      maxLength: 10,
    }),
    { nil: undefined },
  ),
});

const folderArbitrary = fc.record({
  encryptedName: anyText(200),
  nameIv: anyText(24),
  nameTag: anyText(32),
  icon: fc.option(anyText(50), { nil: undefined }),
  color: fc.option(anyText(20), { nil: undefined }),
});

/** What an arbitrary draws. */
type Drawn<A> = A extends fc.Arbitrary<infer T> ? T : never;

/** The stored row as the stream serialises it: every fixed field at its longest. */
function itemRow(fields: Drawn<typeof itemArbitrary>): Record<string, unknown> {
  return {
    _id: OBJECT_ID,
    userId: OBJECT_ID,
    itemType: 'secure_note',
    folderId: OBJECT_ID,
    favorite: false,
    ...fields,
    passwordHistory: fields.passwordHistory?.map((entry) => ({ ...entry, changedAt: ISO })),
    deletedAt: ISO,
    createdAt: ISO,
    updatedAt: ISO,
    __v: 2_147_483_647,
  };
}

function folderRow(fields: Drawn<typeof folderArbitrary>): Record<string, unknown> {
  return {
    _id: OBJECT_ID,
    userId: OBJECT_ID,
    parentId: OBJECT_ID,
    sortOrder: 10_000,
    ...fields,
    createdAt: ISO,
    updatedAt: ISO,
    __v: 2_147_483_647,
  };
}

const jsonBytes = (value: unknown) => Buffer.byteLength(JSON.stringify(value), 'utf8');

describe('the size estimate is never below the streamed JSON', () => {
  it('a row whose ciphertext and tags are control characters is estimated at its escaped size', () => {
    const row = itemRow({
      encryptedData: '\u0001'.repeat(2_000),
      dataIv: '"'.repeat(24),
      dataTag: '\\'.repeat(32),
      encryptedName: '\u0000'.repeat(200),
      nameIv: '\u001f'.repeat(24),
      nameTag: '\n'.repeat(32),
      tags: Array.from({ length: 20 }, () => '\u0002'.repeat(50)),
      passwordHistory: Array.from({ length: 10 }, () => ({
        encryptedPassword: '\u0003'.repeat(400),
        iv: '\u0004'.repeat(24),
        tag: '\u0005'.repeat(32),
      })),
    });

    // Six bytes per control character in the stream; the estimate must cover it.
    expect(estimateItemJsonSize(row)).toBeGreaterThanOrEqual(jsonBytes(row));
  });

  it('every item the API can store', () => {
    fc.assert(
      fc.property(itemArbitrary, (fields) => {
        const row = itemRow(fields);
        expect(estimateItemJsonSize(row), propertyBanner()).toBeGreaterThanOrEqual(jsonBytes(row));
      }),
      propertyRun(),
    );
  });

  it('every folder the API can store', () => {
    fc.assert(
      fc.property(folderArbitrary, (fields) => {
        const row = folderRow(fields);
        expect(estimateFolderJsonSize(row), propertyBanner()).toBeGreaterThanOrEqual(
          jsonBytes(row),
        );
      }),
      propertyRun(),
    );
  });
});
