/**
 * Object keys and segment-range arithmetic for the document store
 * (`utils/documentObjects.ts`).
 *
 * Everything here is a pure function over numbers and strings, so the suite is a
 * specification rather than a smoke test: each case names the invariant it pins,
 * and the ones that matter most are the refusals. A range helper that answers
 * plausibly for an impossible input is worse than one that throws, because the
 * wrong bytes decrypt to a tag failure three layers away from the mistake.
 */
import { describe, it, expect } from 'vitest';
import {
  DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  DOCUMENT_TAG_BYTES,
} from '@hvault/shared';
import {
  buildObjectKey,
  expectedPartSize,
  parseObjectKey,
  segmentRange,
  userObjectPrefix,
} from '../src/utils/documentObjects.js';

const USER_ID = '66c0f1a2b3c4d5e6f7a8b9c0';
const DOCUMENT_ID = '507f1f77bcf86cd799439011';

// A deliberately small framing, so an assertion reads as arithmetic a human can
// check. The real constants are exercised separately below, because they are the
// framing every production document actually carries.
const SMALL_PLAINTEXT_CHUNK = 100;
const SMALL_CIPHERTEXT_CHUNK = SMALL_PLAINTEXT_CHUNK + DOCUMENT_TAG_BYTES;

describe('utils/documentObjects — object keys', () => {
  it('builds the documented layout and nothing else', () => {
    expect(buildObjectKey(USER_ID, DOCUMENT_ID)).toBe(
      'u/66c0f1a2b3c4d5e6f7a8b9c0/d/507f1f77bcf86cd799439011',
    );
  });

  it('places every document a user owns under that user prefix', () => {
    const prefix = userObjectPrefix(USER_ID);

    expect(prefix).toBe('u/66c0f1a2b3c4d5e6f7a8b9c0/');
    expect(buildObjectKey(USER_ID, DOCUMENT_ID).startsWith(prefix)).toBe(true);
    // The trailing slash is the whole point: without it this prefix would also
    // match another account whose id merely starts with these characters. No such
    // id can exist at 24 fixed characters, but the guarantee should not rest on
    // that, so assert the slash is there.
    expect(prefix.endsWith('/')).toBe(true);
  });

  it('round-trips a built key back to the two ids that made it', () => {
    expect(parseObjectKey(buildObjectKey(USER_ID, DOCUMENT_ID))).toEqual({
      userId: USER_ID,
      documentId: DOCUMENT_ID,
    });
  });

  it('normalises uppercase hex to the lowercase form _id.toString() emits', () => {
    const key = buildObjectKey(USER_ID.toUpperCase(), DOCUMENT_ID.toUpperCase());

    expect(key).toBe('u/66c0f1a2b3c4d5e6f7a8b9c0/d/507f1f77bcf86cd799439011');
    expect(parseObjectKey('u/66C0F1A2B3C4D5E6F7A8B9C0/d/507F1F77BCF86CD799439011')).toEqual({
      userId: USER_ID,
      documentId: DOCUMENT_ID,
    });
  });

  it.each([
    ['an empty string', ''],
    ['a short id', 'abc'],
    ['a long id', `${USER_ID}00`],
    ['non-hex characters', '66c0f1a2b3c4d5e6f7a8b9cz'],
    ['a path traversal', '../../etc/passwd'],
    ['a slash inside the id', '66c0f1a2b3c4d5e6/7a8b9c0'],
    ['a decrypted file name', 'invoice.pdf'],
  ])('refuses to build a key from %s', (_label, badId) => {
    expect(() => buildObjectKey(badId, DOCUMENT_ID)).toThrow(TypeError);
    expect(() => buildObjectKey(USER_ID, badId)).toThrow(TypeError);
    expect(() => userObjectPrefix(badId)).toThrow(/must be a 24-character ObjectId/);
  });

  it.each([
    ['a different prefix letter', 'x/66c0f1a2b3c4d5e6f7a8b9c0/d/507f1f77bcf86cd799439011'],
    ['a missing document marker', 'u/66c0f1a2b3c4d5e6f7a8b9c0/507f1f77bcf86cd799439011'],
    ['a trailing slash', 'u/66c0f1a2b3c4d5e6f7a8b9c0/d/507f1f77bcf86cd799439011/'],
    ['an extra path segment', 'u/66c0f1a2b3c4d5e6f7a8b9c0/d/507f1f77bcf86cd799439011/v2'],
    ['a leading slash', '/u/66c0f1a2b3c4d5e6f7a8b9c0/d/507f1f77bcf86cd799439011'],
    ['a non-hex document id', 'u/66c0f1a2b3c4d5e6f7a8b9c0/d/zzzf1f77bcf86cd799439011'],
    ['a truncated document id', 'u/66c0f1a2b3c4d5e6f7a8b9c0/d/507f1f77bcf86cd7994390'],
    ['a traversal in place of an id', 'u/../d/507f1f77bcf86cd799439011'],
    ['a bare user prefix', 'u/66c0f1a2b3c4d5e6f7a8b9c0/'],
    ['an empty string', ''],
    ['a newline-smuggled second key', 'u/66c0f1a2b3c4d5e6f7a8b9c0/d/507f1f77bcf86cd799439011\nu/x'],
  ])('returns null rather than throwing for %s', (_label, key) => {
    expect(parseObjectKey(key)).toBeNull();
  });
});

describe('utils/documentObjects — segment ranges', () => {
  it('reads segment 0 from the start of the object', () => {
    const range = segmentRange(0, 3, SMALL_PLAINTEXT_CHUNK, 2 * SMALL_CIPHERTEXT_CHUNK + 30);

    expect(range).toEqual({ start: 0, end: SMALL_CIPHERTEXT_CHUNK - 1, length: 116 });
  });

  it('reads a middle segment at its exact multiple of the segment size', () => {
    const range = segmentRange(1, 3, SMALL_PLAINTEXT_CHUNK, 2 * SMALL_CIPHERTEXT_CHUNK + 30);

    expect(range).toEqual({
      start: SMALL_CIPHERTEXT_CHUNK,
      end: 2 * SMALL_CIPHERTEXT_CHUNK - 1,
      length: SMALL_CIPHERTEXT_CHUNK,
    });
  });

  it('reads the last (short) segment to the end of the object', () => {
    const ciphertextBytes = 2 * SMALL_CIPHERTEXT_CHUNK + 30;
    const range = segmentRange(2, 3, SMALL_PLAINTEXT_CHUNK, ciphertextBytes);

    expect(range).toEqual({
      start: 2 * SMALL_CIPHERTEXT_CHUNK,
      end: ciphertextBytes - 1,
      length: 30,
    });
  });

  it('reads a last segment that happens to be exactly full', () => {
    const ciphertextBytes = 3 * SMALL_CIPHERTEXT_CHUNK;
    const range = segmentRange(2, 3, SMALL_PLAINTEXT_CHUNK, ciphertextBytes);

    // The boundary the framing prototype measured: a plaintext that is an exact
    // multiple of the chunk size produces a full FINAL segment and no phantom
    // empty one after it, so the last range still ends at the last byte.
    expect(range).toEqual({
      start: 2 * SMALL_CIPHERTEXT_CHUNK,
      end: ciphertextBytes - 1,
      length: SMALL_CIPHERTEXT_CHUNK,
    });
  });

  it('reads a zero-byte document as one segment holding only its tag', () => {
    expect(segmentRange(0, 1, SMALL_PLAINTEXT_CHUNK, DOCUMENT_TAG_BYTES)).toEqual({
      start: 0,
      end: DOCUMENT_TAG_BYTES - 1,
      length: DOCUMENT_TAG_BYTES,
    });
  });

  it('covers the object exactly once: contiguous ranges summing to ciphertextBytes', () => {
    const chunkCount = 5;
    const ciphertextBytes = 4 * SMALL_CIPHERTEXT_CHUNK + 17;

    let expectedStart = 0;
    let total = 0;
    for (let index = 0; index < chunkCount; index += 1) {
      const range = segmentRange(index, chunkCount, SMALL_PLAINTEXT_CHUNK, ciphertextBytes);
      expect(range.start).toBe(expectedStart);
      // The end is INCLUSIVE, which is what `Range: bytes=start-end` means. An
      // exclusive end would make this identity fail by one on every segment.
      expect(range.length).toBe(range.end - range.start + 1);
      expectedStart = range.end + 1;
      total += range.length;
    }

    expect(total).toBe(ciphertextBytes);
    expect(expectedStart).toBe(ciphertextBytes);
  });

  it('frames a real 20 MiB document with the production constants', () => {
    // Three segments: two full and a remainder, at the framing every uploaded
    // document actually uses.
    const plaintextBytes = 20 * 1024 * 1024;
    const chunkCount = 3;
    const ciphertextBytes = plaintextBytes + DOCUMENT_TAG_BYTES * chunkCount;

    const first = segmentRange(0, chunkCount, DOCUMENT_PLAINTEXT_CHUNK_BYTES, ciphertextBytes);
    const last = segmentRange(2, chunkCount, DOCUMENT_PLAINTEXT_CHUNK_BYTES, ciphertextBytes);

    // Every non-final part is exactly one storage-engine block wide, which is the
    // property that lets one crypto segment be one part be one range.
    expect(first.length).toBe(DOCUMENT_CIPHERTEXT_CHUNK_BYTES);
    expect(last.start).toBe(2 * DOCUMENT_CIPHERTEXT_CHUNK_BYTES);
    expect(last.end).toBe(ciphertextBytes - 1);
    expect(last.length).toBeLessThan(DOCUMENT_CIPHERTEXT_CHUNK_BYTES);
  });

  it.each([
    ['the segment after the last', 3],
    ['a negative index', -1],
    ['a fractional index', 1.5],
    ['a non-finite index', Number.NaN],
  ])('throws for %s instead of returning a plausible range', (_label, index) => {
    expect(() => segmentRange(index, 3, SMALL_PLAINTEXT_CHUNK, 3 * SMALL_CIPHERTEXT_CHUNK)).toThrow(
      RangeError,
    );
  });

  it('names the index and the segment count when the index is out of range', () => {
    expect(() => segmentRange(7, 3, SMALL_PLAINTEXT_CHUNK, 3 * SMALL_CIPHERTEXT_CHUNK)).toThrow(
      /index 7 is outside a document of 3 segment\(s\)/,
    );
  });

  it('throws when the row claims more segments than its byte count can hold', () => {
    // Three segments need at least two full ones plus a tag; one byte less is a
    // row whose own columns disagree, and any range derived from it reads the
    // wrong bytes.
    const tooSmall = 2 * SMALL_CIPHERTEXT_CHUNK + DOCUMENT_TAG_BYTES - 1;

    expect(() => segmentRange(0, 3, SMALL_PLAINTEXT_CHUNK, tooSmall)).toThrow(
      /cannot hold 3 segment\(s\)/,
    );
    expect(() =>
      segmentRange(0, 3, SMALL_PLAINTEXT_CHUNK, 2 * SMALL_CIPHERTEXT_CHUNK + DOCUMENT_TAG_BYTES),
    ).not.toThrow();
  });

  it('throws when the row claims fewer segments than its byte count needs', () => {
    expect(() => segmentRange(0, 3, SMALL_PLAINTEXT_CHUNK, 3 * SMALL_CIPHERTEXT_CHUNK + 1)).toThrow(
      /cannot hold 3 segment\(s\)/,
    );
  });

  it.each([
    ['a chunk count below one', 0, SMALL_PLAINTEXT_CHUNK, SMALL_CIPHERTEXT_CHUNK],
    ['a fractional chunk count', 2.5, SMALL_PLAINTEXT_CHUNK, 2 * SMALL_CIPHERTEXT_CHUNK],
    ['a zero chunk size', 3, 0, 3 * SMALL_CIPHERTEXT_CHUNK],
    ['a fractional chunk size', 3, 100.5, 3 * SMALL_CIPHERTEXT_CHUNK],
    ['an object smaller than one tag', 1, SMALL_PLAINTEXT_CHUNK, DOCUMENT_TAG_BYTES - 1],
    // Inside the size window, so ONLY the integer guard rejects it. Without that
    // guard this returns end 49.5 and a `Range: bytes=0-49.5` header no engine can
    // answer, which is why the case is here rather than left to the window check.
    ['a fractional object size', 1, SMALL_PLAINTEXT_CHUNK, 50.5],
  ])('throws for %s', (_label, chunkCount, chunkPlaintextBytes, ciphertextBytes) => {
    expect(() => segmentRange(0, chunkCount, chunkPlaintextBytes, ciphertextBytes)).toThrow(
      RangeError,
    );
  });
});

describe('utils/documentObjects — expected part sizes', () => {
  const chunkCount = 3;
  const ciphertextBytes = 2 * SMALL_CIPHERTEXT_CHUNK + 30;

  it('requires every non-final part to be exactly one full segment', () => {
    expect(expectedPartSize(1, chunkCount, SMALL_PLAINTEXT_CHUNK, ciphertextBytes)).toBe(
      SMALL_CIPHERTEXT_CHUNK,
    );
    expect(expectedPartSize(2, chunkCount, SMALL_PLAINTEXT_CHUNK, ciphertextBytes)).toBe(
      SMALL_CIPHERTEXT_CHUNK,
    );
  });

  it('allows only the final part to be short', () => {
    expect(expectedPartSize(3, chunkCount, SMALL_PLAINTEXT_CHUNK, ciphertextBytes)).toBe(30);
  });

  it('is the same length the matching zero-based segment range reports', () => {
    // The one place in this design where numbering is one-based, and therefore the
    // one place an off-by-one would hide. Pinned across every part of the upload.
    for (let partNumber = 1; partNumber <= chunkCount; partNumber += 1) {
      expect(expectedPartSize(partNumber, chunkCount, SMALL_PLAINTEXT_CHUNK, ciphertextBytes)).toBe(
        segmentRange(partNumber - 1, chunkCount, SMALL_PLAINTEXT_CHUNK, ciphertextBytes).length,
      );
    }
  });

  it.each([
    ['part 0, because S3 numbers parts from one', 0],
    ['a part past the declared count', 4],
    ['a negative part number', -1],
    ['a fractional part number', 2.5],
  ])('throws for %s', (_label, partNumber) => {
    expect(() =>
      expectedPartSize(partNumber, chunkCount, SMALL_PLAINTEXT_CHUNK, ciphertextBytes),
    ).toThrow(RangeError);
  });

  it('names the part number rather than the segment index when it is out of range', () => {
    expect(() => expectedPartSize(14, chunkCount, SMALL_PLAINTEXT_CHUNK, ciphertextBytes)).toThrow(
      /partNumber 14 is outside an upload of 3 part\(s\)/,
    );
  });
});
