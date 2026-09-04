/**
 * `documentMatchesQuery` — what a person can find a document by, and what they
 * cannot.
 *
 * The negatives carry the weight here. The obvious implementation is to reuse the
 * vault's `valueMatches`, which walks the object; over a `DocumentMeta` that also
 * matches the file's SHA-256, its stream salt and its byte counts, so a query
 * would return rows for reasons nobody typed on purpose.
 */
import { describe, it, expect } from 'vitest';
import { DOCUMENT_PLAINTEXT_CHUNK_BYTES } from '@hvault/shared';
import { documentMatchesQuery } from '../src/lib/documentSearch';
import type { DecryptedDocument } from '../src/stores/documentsStore';

const SHA = 'deadbeef'.repeat(8);

function doc(overrides: Partial<NonNullable<DecryptedDocument['meta']>> = {}): DecryptedDocument {
  return {
    id: '66c0f1a2b3c4d5e6f7a8b9c0',
    favorite: false,
    createdAt: 'x',
    updatedAt: 'x',
    meta: {
      name: 'Tax Return 2025.pdf',
      mime: 'application/pdf',
      ext: 'pdf',
      plaintextBytes: 123456,
      sha256: SHA,
      chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
      chunkCount: 1,
      tags: ['finance', 'HMRC'],
      note: 'Filed in April, receipt in the drawer',
      capturedAt: '2026-01-01T00:00:00.000Z',
      ...overrides,
    },
    _raw: { streamSalt: 'c2FsdA==' } as DecryptedDocument['_raw'],
  };
}

describe('documentMatchesQuery', () => {
  it('matches the name, a tag and the note, case-insensitively', () => {
    expect(documentMatchesQuery(doc(), 'tax return')).toBe(true);
    expect(documentMatchesQuery(doc(), 'hmrc')).toBe(true);
    expect(documentMatchesQuery(doc(), 'drawer')).toBe(true);
  });

  it('matches the stored extension even when the name no longer carries it', () => {
    // The only state in which the extension branch DECIDES anything. `ext` is
    // taken from the file name at upload and a rename rewrites `name` without
    // touching it, so until someone renames a document its extension is a suffix
    // of its own name and the name branch always answers first. A fixture whose
    // name still ends in `.pdf` leaves this line untested and a mutant on it
    // alive.
    const renamed = doc({ name: 'taxes-2025', ext: 'pdf' });
    expect(documentMatchesQuery(renamed, 'pdf')).toBe(true);
    expect(documentMatchesQuery(renamed, 'taxes')).toBe(true);
  });

  it('matches everything on an empty query and nothing on an unrelated one', () => {
    expect(documentMatchesQuery(doc(), '')).toBe(true);
    expect(documentMatchesQuery(doc(), 'passport')).toBe(false);
  });

  it('does NOT match the checksum, the framing or the byte count', () => {
    // The three fields a whole-object walk would have matched. A reader pasting a
    // hash is not searching their filing cabinet, and a reader typing "123456"
    // certainly is not asking for a file that happens to be that many bytes.
    expect(documentMatchesQuery(doc(), SHA)).toBe(false);
    expect(documentMatchesQuery(doc(), 'deadbeef')).toBe(false);
    expect(documentMatchesQuery(doc(), '123456')).toBe(false);
    expect(documentMatchesQuery(doc(), 'c2FsdA==')).toBe(false);
    // Nor the MIME type, which is machine vocabulary rather than the user's.
    expect(documentMatchesQuery(doc(), 'application/pdf')).toBe(false);
  });

  it('matches a document with no note without reaching into `undefined`', () => {
    const noNote = doc();
    delete noNote.meta?.note;
    expect(documentMatchesQuery(noNote, 'tax')).toBe(true);
    expect(documentMatchesQuery(noNote, 'drawer')).toBe(false);
  });

  it('matches nothing for a document whose metadata will not open', () => {
    // There is no text to match: the name, the tags and the note are sealed under
    // a key this vault could not unwrap. The list reports how many such rows
    // exist, so they are accounted for rather than quietly missing.
    const degraded = { ...doc(), meta: null };
    expect(documentMatchesQuery(degraded, 'tax')).toBe(false);
    // Including on the empty query's own path, which returns before `meta` is read.
    expect(documentMatchesQuery(degraded, '')).toBe(true);
  });
});
