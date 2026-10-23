/**
 * The archive's path rules, as properties: for EVERY name a document or folder
 * could carry, each segment is portable, and for every sequence of documents a
 * run could archive, every path is unique and safe to extract.
 *
 * The names are drawn from two generators at once: arbitrary Unicode, lone
 * surrogates included, and a mixture of the fragments every rule exists for
 * (separators and their look-alikes, dots, device names, direction overrides,
 * decomposed accents, long runs), so the rules meet their adversaries far more
 * often than chance would arrange.
 */
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { validateFileName } from 'yauzl';
import {
  ArchivePathAllocator,
  FALLBACK_DOCUMENT_SEGMENT,
  archiveSegment,
} from '../../src/services/documents/archiveNames';
import type { DecryptedFolder } from '../../src/stores/vaultStore';
import { propertyBanner, propertyRun } from '../../../../tests/harness/property.js';

/**
 * Whether `segment` is safe as one path segment anywhere, stated independently
 * of how `archiveSegment` gets there.
 */
function portabilityProblems(segment: string): string[] {
  return [
    segment.length > 0 ? '' : 'empty',
    new TextEncoder().encode(segment).length <= 255 ? '' : 'longer than 255 bytes',
    segment === segment.normalize('NFC') ? '' : 'not NFC',
    /[\u0000-\u001f\u007f-\u009f/\\<>:"|?*\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069\u2044\u2215\u29f8\uff0f\uff3c]/u.test(
      segment,
    )
      ? 'forbidden character'
      : '',
    /[\ud800-\udfff]/u.test(segment) ? 'lone surrogate' : '',
    /[. ]$/.test(segment) ? 'trailing dot or space' : '',
    /^[.\u2024\uff0e]+$/.test(segment) ? 'dots only' : '',
    /^(?:con|prn|aux|nul|com[0-9\u00b9\u00b2\u00b3]|lpt[0-9\u00b9\u00b2\u00b3]) *(?:\.|$)/i.test(
      segment,
    )
      ? 'reserved device name'
      : '',
  ].filter((problem) => problem !== '');
}

const FRAGMENTS = [
  '..',
  '.',
  '/',
  '\\',
  ' ',
  'CON',
  'nul',
  'Com1',
  'LPT\u00b9',
  '\u202e',
  '\u2066',
  '\u0000',
  '\n',
  '\uff0e',
  '\u2024',
  '\u2215',
  '\uff0f',
  '<',
  ':',
  '*',
  '\ud800',
  '\udc00',
  'e\u0301',
  '\u00e9',
  '😀',
  '文',
  'a'.repeat(60),
  '.pdf',
  '.tar.gz',
  ' (2)',
];

const hostileName = fc
  .array(fc.constantFrom(...FRAGMENTS), { minLength: 0, maxLength: 24 })
  .map((parts) => parts.join(''));

const anyName = fc.oneof(fc.string({ unit: 'binary', maxLength: 300 }), hostileName);

describe('archiveSegment, for every name', () => {
  it('yields a portable segment', () => {
    fc.assert(
      fc.property(anyName, (name) => {
        const segment = archiveSegment(name, FALLBACK_DOCUMENT_SEGMENT);
        expect(
          portabilityProblems(segment),
          `${propertyBanner()} — ${JSON.stringify(name)}`,
        ).toEqual([]);
      }),
      propertyRun(),
    );
  });

  it('is idempotent: a safe segment is its own safe form', () => {
    fc.assert(
      fc.property(anyName, (name) => {
        const once = archiveSegment(name, FALLBACK_DOCUMENT_SEGMENT);
        expect(archiveSegment(once, FALLBACK_DOCUMENT_SEGMENT), propertyBanner()).toBe(once);
      }),
      propertyRun(),
    );
  });
});

const FOLDER_IDS = [
  '66c0f1a2b3c4d5e6f7a8b901',
  '66c0f1a2b3c4d5e6f7a8b902',
  '66c0f1a2b3c4d5e6f7a8b903',
  '66c0f1a2b3c4d5e6f7a8b904',
];

/** Up to four folders, any of them nested under any other, cycles included. */
const folderTree = fc
  .tuple(
    fc.array(anyName, { minLength: 4, maxLength: 4 }),
    fc.array(fc.option(fc.integer({ min: 0, max: 3 }), { nil: undefined }), {
      minLength: 4,
      maxLength: 4,
    }),
  )
  .map(([names, parents]): DecryptedFolder[] =>
    FOLDER_IDS.map((id, index) => {
      const parent = parents[index];
      return {
        id,
        name: names[index] ?? '',
        ...(parent === undefined ? {} : { parentId: FOLDER_IDS[parent] }),
        sortOrder: 0,
        createdAt: '2026-01-01T00:00:00.000Z',
        updatedAt: '2026-01-01T00:00:00.000Z',
        _raw: {} as DecryptedFolder['_raw'],
      };
    }),
  );

const placements = fc.array(
  fc.record({
    name: anyName,
    folder: fc.option(fc.integer({ min: 0, max: 4 }), { nil: undefined }),
  }),
  { maxLength: 30 },
);

describe('ArchivePathAllocator, for every run', () => {
  it('gives every document a unique path of portable segments that an extractor accepts', () => {
    fc.assert(
      fc.property(folderTree, placements, (folders, documents) => {
        const allocator = new ArchivePathAllocator(folders);
        const keys = new Set<string>();
        const directories = new Set<string>();
        for (const { name, folder } of documents) {
          const placement = allocator.place(
            name,
            folder === undefined ? undefined : (FOLDER_IDS[folder] ?? '66c0f1a2b3c4d5e6f7a8b9ff'),
          );
          allocator.reserve(placement);
          const { path } = placement;
          const where = `${propertyBanner()} — ${JSON.stringify(path)}`;
          expect(validateFileName(path), where).toBeNull();
          for (const segment of path.split('/')) {
            expect(portabilityProblems(segment), where).toEqual([]);
          }
          const key = path.normalize('NFC').toUpperCase();
          expect(keys.has(key), where).toBe(false);
          keys.add(key);
          const segments = key.split('/');
          for (let depth = 1; depth < segments.length; depth += 1) {
            directories.add(segments.slice(0, depth).join('/'));
          }
          expect(placement.pathBytes, where).toBe(new TextEncoder().encode(path).length);
        }
        // No file is named like a directory another file needs.
        for (const key of keys) {
          expect(directories.has(key), `${propertyBanner()} — ${key}`).toBe(false);
        }
      }),
      propertyRun(),
    );
  });
});
