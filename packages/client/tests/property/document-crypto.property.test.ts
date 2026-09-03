/**
 * The document container, as PROPERTIES rather than examples.
 *
 * `document-crypto.test.ts` states the seven sizes that matter and the nine ways
 * a document must refuse to open. Those are the cases a person thought of. What
 * a property adds here is the arbitrary one: any byte array, cut at any chunk
 * size, must come back byte-identical, and any single-byte change anywhere in the
 * stored object must make it refuse — including in the last tag, in the first
 * segment, and at the boundary between two of them.
 *
 * The chunk size is GENERATED rather than fixed at
 * `DOCUMENT_PLAINTEXT_CHUNK_BYTES`, and that is faithful rather than convenient:
 * a download frames a document from the `chunkPlaintextBytes` stored on its own
 * row, precisely so that changing the constant can never mis-frame a file that
 * already exists. So the service must be correct at every chunk size, and small
 * ones make hundreds of cases affordable where two 8 MiB ones would not.
 *
 * Real Web Crypto throughout, real keys, no stubbed randomness; only fast-check's
 * seed is pinned (`tests/harness/property.ts`).
 */
import { beforeAll, describe, expect, it } from 'vitest';
import fc from 'fast-check';
import {
  DOCUMENT_NONCE_PREFIX_BYTES,
  DOCUMENT_STREAM_SALT_BYTES,
  DOCUMENT_TAG_BYTES,
  documentChunkCountFor,
} from '@hvault/shared';
import {
  deriveStreamKey,
  generateDek,
  type DocumentBytes,
} from '../../src/services/crypto/documentCryptoService';
import {
  AEAD_REFUSAL,
  documentId,
  expectRefusal,
  openDocument,
  sealDocument,
  sha256Hex,
} from '../documentCryptoHarness';
import { CRYPTO_RUNS, propertyBanner, propertyRun } from '../../../../tests/harness/property.js';

const DOC_ID = documentId('66c0f1a2b3c4d5e6f7a8b9c0');

/**
 * Payloads a real document store holds: empty, tiny, and long enough to span
 * several segments at the generated chunk size. `fc.uint8Array` draws arbitrary
 * BYTES, which is the point — most of these are not valid UTF-8 in any encoding,
 * and a text-based cipher would corrupt them silently.
 */
const anyBytes = fc.uint8Array({ maxLength: 1_024 });

/** Chunk sizes small enough to be cheap, large enough to leave remainders. */
const anyChunkSize = fc.integer({ min: 1, max: 257 });

let streamKey: CryptoKey;
let noncePrefix: DocumentBytes;

beforeAll(async () => {
  const streamSalt = globalThis.crypto.getRandomValues(new Uint8Array(DOCUMENT_STREAM_SALT_BYTES));
  noncePrefix = globalThis.crypto.getRandomValues(new Uint8Array(DOCUMENT_NONCE_PREFIX_BYTES));
  streamKey = await deriveStreamKey(generateDek(), streamSalt, DOC_ID);
});

describe('the segmented container round-trips at every size and every framing', () => {
  it('returns exactly the bytes that were sealed, for any payload and any chunk size', async () => {
    await fc.assert(
      fc.asyncProperty(anyBytes, anyChunkSize, async (payload, chunkPlaintextBytes) => {
        const plaintext = new Uint8Array(payload);
        const segments = await sealDocument(streamKey, noncePrefix, plaintext, chunkPlaintextBytes);

        // The framing the row would record, derived by the shared function the
        // server and the metadata blob use.
        expect(segments, propertyBanner()).toHaveLength(
          documentChunkCountFor(plaintext.length, chunkPlaintextBytes),
        );
        // Every non-final part is a full chunk plus its tag, which is what makes
        // segment `i` start at a fixed offset and a range read need no table.
        for (const part of segments.slice(0, -1)) {
          expect(part.length, propertyBanner()).toBe(chunkPlaintextBytes + DOCUMENT_TAG_BYTES);
        }
        const total = segments.reduce((sum, part) => sum + part.length, 0);
        expect(total, propertyBanner()).toBe(
          plaintext.length + DOCUMENT_TAG_BYTES * segments.length,
        );

        const opened = await openDocument(streamKey, noncePrefix, segments);
        expect(opened.length, propertyBanner()).toBe(plaintext.length);
        expect(await sha256Hex(opened), propertyBanner()).toBe(await sha256Hex(plaintext));
      }),
      propertyRun({ numRuns: CRYPTO_RUNS }),
    );
  });

  it('refuses any single changed byte, wherever in the stored object it lands', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 1, maxLength: 512 }),
        anyChunkSize,
        fc.nat(),
        fc.integer({ min: 1, max: 255 }),
        async (payload, chunkPlaintextBytes, position, mask) => {
          const plaintext = new Uint8Array(payload);
          const segments = await sealDocument(
            streamKey,
            noncePrefix,
            plaintext,
            chunkPlaintextBytes,
          );

          // Land the change anywhere in the concatenated object: inside a
          // ciphertext, inside a tag, in the first segment or the last.
          const total = segments.reduce((sum, part) => sum + part.length, 0);
          let offset = position % total;
          let target = 0;
          while (offset >= segments[target]!.length) {
            offset -= segments[target]!.length;
            target += 1;
          }
          const tampered = segments.map((part, index) => (index === target ? part.slice() : part));
          const victim = tampered[target]!;
          victim[offset] = victim[offset]! ^ mask;

          await expectRefusal(() => openDocument(streamKey, noncePrefix, tampered), AEAD_REFUSAL);
        },
      ),
      propertyRun({ numRuns: CRYPTO_RUNS }),
    );
  });
});
