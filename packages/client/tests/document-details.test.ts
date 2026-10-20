/**
 * `lib/documentDetails.ts`: the rules a document's typed details are checked
 * against before anything is sealed, pinned directly.
 *
 * Two of these refusals (more than twenty tags, a tag over fifty characters) used
 * to be reached by typing into the old comma-separated field. The tag editor now
 * refuses both at the field, as the vault item editor does, so typing no longer
 * reaches them; they still guard every caller (a bulk tag, the transform review,
 * a caller added later), and this is where their boundaries and exact sentences
 * stay pinned.
 */
import { describe, it, expect } from 'vitest';
import {
  MAX_DOCUMENT_META_JSON_BYTES,
  MAX_DOCUMENT_NAME_LENGTH,
  MAX_DOCUMENT_NOTE_LENGTH,
  MAX_DOCUMENT_TAGS,
  MAX_TAG_LENGTH,
} from '@hvault/shared';
import { documentMetaRefusal, nameFromStem, uploadRefusal } from '../src/lib/documentDetails';
import { DOCUMENT_TYPE_LOCKED_MESSAGE } from '../src/stores/documentsStore';
import { metaFixture } from './documentCryptoHarness';

const tagsOf = (count: number): string[] =>
  Array.from({ length: count }, (_, i) => `t${String(i)}`);

describe('documentMetaRefusal', () => {
  it('accepts metadata inside every bound', () => {
    expect(documentMetaRefusal(metaFixture())).toBeNull();
  });

  it('accepts exactly the most tags, and refuses one more with the exact sentence', () => {
    expect(documentMetaRefusal(metaFixture({ tags: tagsOf(MAX_DOCUMENT_TAGS) }))).toBeNull();
    expect(documentMetaRefusal(metaFixture({ tags: tagsOf(MAX_DOCUMENT_TAGS + 1) }))).toBe(
      `A document can carry at most ${String(MAX_DOCUMENT_TAGS)} tags.`,
    );
  });

  it('accepts a tag at the longest a tag may be, and refuses a longer one by name', () => {
    const longest = 'x'.repeat(MAX_TAG_LENGTH);
    const overlong = 'y'.repeat(MAX_TAG_LENGTH + 1);
    expect(documentMetaRefusal(metaFixture({ tags: ['fine', longest] }))).toBeNull();
    expect(documentMetaRefusal(metaFixture({ tags: ['fine', overlong] }))).toBe(
      `Tags can be at most ${String(MAX_TAG_LENGTH)} characters; "${overlong}" is longer.`,
    );
  });

  it('checks the count before the length, so a list that is both says the count', () => {
    const tags = [...tagsOf(MAX_DOCUMENT_TAGS), 'z'.repeat(MAX_TAG_LENGTH + 1)];
    expect(documentMetaRefusal(metaFixture({ tags }))).toBe(
      `A document can carry at most ${String(MAX_DOCUMENT_TAGS)} tags.`,
    );
  });

  it('accepts the longest note and refuses one character more', () => {
    expect(
      documentMetaRefusal(metaFixture({ note: 'n'.repeat(MAX_DOCUMENT_NOTE_LENGTH) })),
    ).toBeNull();
    expect(
      documentMetaRefusal(metaFixture({ note: 'n'.repeat(MAX_DOCUMENT_NOTE_LENGTH + 1) })),
    ).toBe(`A note can be at most ${String(MAX_DOCUMENT_NOTE_LENGTH)} characters.`);
  });

  it('refuses a blob over the byte budget with its own sentence', () => {
    // Every typed bound holds except the name, which no field check above counts:
    // the byte budget is the first rule it meets.
    const name = `${'中'.repeat(MAX_DOCUMENT_META_JSON_BYTES)}.md`;
    expect(documentMetaRefusal(metaFixture({ name }))).toBe(
      `The name, tags and note of a document have to fit in ${String(MAX_DOCUMENT_META_JSON_BYTES)} bytes once encoded. Shorten the note.`,
    );
  });

  it('lets the schema have the last word on a bound nobody types', () => {
    expect(documentMetaRefusal(metaFixture({ sha256: 'short' }))).toBe(
      'The details of this file cannot be stored with it.',
    );
  });
});

describe('uploadRefusal', () => {
  const input = {
    name: 'notes.txt',
    originalName: 'notes.txt',
    mime: 'text/plain',
  };

  it('accepts an upload whose details fit', () => {
    expect(uploadRefusal({ ...input, tags: tagsOf(MAX_DOCUMENT_TAGS) }, 10)).toBeNull();
  });

  it('measures the blob the store will seal and answers with the same sentences', () => {
    expect(uploadRefusal({ ...input, tags: tagsOf(MAX_DOCUMENT_TAGS + 1) }, 10)).toBe(
      `A document can carry at most ${String(MAX_DOCUMENT_TAGS)} tags.`,
    );
    const overlong = 'q'.repeat(MAX_TAG_LENGTH + 1);
    expect(uploadRefusal({ ...input, tags: [overlong] }, 10)).toBe(
      `Tags can be at most ${String(MAX_TAG_LENGTH)} characters; "${overlong}" is longer.`,
    );
  });
});

describe('nameFromStem', () => {
  it('puts the fixed suffix back on the trimmed stem', () => {
    expect(nameFromStem('  Q3 report ', '.pdf', 'report.pdf')).toEqual({ name: 'Q3 report.pdf' });
  });

  it('refuses an empty stem', () => {
    expect(nameFromStem('   ', '.pdf', 'report.pdf')).toEqual({
      refusal: 'A document needs a name.',
    });
  });

  it('refuses a stem that would change the type, including a dot typed into a bare name', () => {
    expect(nameFromStem('Make.file', '', 'Makefile')).toEqual({
      refusal: DOCUMENT_TYPE_LOCKED_MESSAGE,
    });
  });

  it('accepts the longest name and refuses one character more, extension included', () => {
    const suffix = '.md';
    const longest = 'a'.repeat(MAX_DOCUMENT_NAME_LENGTH - suffix.length);
    expect(nameFromStem(longest, suffix, 'x.md')).toEqual({ name: `${longest}${suffix}` });
    expect(nameFromStem(`${longest}a`, suffix, 'x.md')).toEqual({
      refusal: `A name can be at most ${String(MAX_DOCUMENT_NAME_LENGTH)} characters, including its extension.`,
    });
  });
});
