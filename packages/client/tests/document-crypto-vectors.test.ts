/**
 * The committed known-answer vector for the document container format.
 *
 * Everything else in this repository tests that `documentCryptoService` is
 * self-consistent: what it seals, it opens. That is exactly what a format
 * contract cannot be tested by, because a change to the HKDF `info` strings, to
 * the order of the nonce fields, or to the endianness of the segment counter
 * leaves a self-consistent implementation that can no longer read a single
 * document already sitting in a bucket. There is no migration for that: the
 * server holds ciphertext and a wrapped key, and nothing on the server can
 * re-frame it.
 *
 * So these values are FROZEN. They were computed against the design (PLAN.md
 * Section 1.3) before this module existed and reproduced by it afterwards, and
 * they may only change alongside a new version label inside the `info` strings
 * themselves and a path that can still read the old ones. A red test here means
 * every stored document has just become unreadable; it is never something to
 * re-record.
 *
 * What each vector pins:
 *   - the exact `info` bytes, including the `|` separator and the document id;
 *   - that `streamSalt` is the HKDF SALT and the DEK is the input keying
 *     material, rather than the other way round;
 *   - the nonce layout: a 7-byte prefix, then the index, then the flag;
 *   - that the index is BIG-endian (a little-endian counter agrees with this
 *     suite at index 0 and disagrees at index 3, which is why the second vector
 *     is at index 3);
 *   - that the last-segment flag is 0x01 and its absence is 0x00;
 *   - that a segment is `ciphertext || tag` with a 16-byte tag.
 */
import { describe, expect, it } from 'vitest';
import { DOCUMENT_TAG_BYTES } from '@hvault/shared';
import type { DocumentMeta } from '@hvault/shared';
import { cryptoService } from '../src/services/crypto/cryptoService';
import {
  decryptMeta,
  decryptSegment,
  deriveMetaKey,
  deriveStreamKey,
  deriveWrapKey,
  encryptSegment,
  unwrapDek,
} from '../src/services/crypto/documentCryptoService';
import {
  documentId,
  expectRefusal,
  fromHex,
  toBase64,
  AEAD_REFUSAL,
} from './documentCryptoHarness';

/** The DEK, bytes 0x00..0x1f. */
const DEK = fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
/** The stream salt, bytes 0xff..0xe0. */
const STREAM_SALT = fromHex('fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0');
/** The nonce prefix, bytes 01..07. */
const NONCE_PREFIX = fromHex('01020304050607');
/** The document id every `info` string ends with. */
const DOCUMENT_ID = documentId('66c0f1a2b3c4d5e6f7a8b9c0');

/** `"hvault"`, sealed as segment 0 with the last-segment flag set. */
const SEGMENT_ZERO_PLAINTEXT = 'hvault';
const SEGMENT_ZERO_CIPHERTEXT = 'WvqP+XoOy5nHJBvHKkac6D6h3iK8bA==';

/** The IV of segment 3 when it is NOT the last segment. */
const SEGMENT_THREE_IV = '010203040506070000000300';

describe('the committed document-format vector', () => {
  it('seals the vector plaintext to the exact committed ciphertext', async () => {
    const streamKey = await deriveStreamKey(DEK, STREAM_SALT, DOCUMENT_ID);
    const sealed = await encryptSegment(
      streamKey,
      { noncePrefix: NONCE_PREFIX, index: 0, isLast: true },
      new TextEncoder().encode(SEGMENT_ZERO_PLAINTEXT),
    );

    expect(toBase64(sealed)).toBe(SEGMENT_ZERO_CIPHERTEXT);
    // Six plaintext bytes and one tag, with the tag inline: the stored object is
    // the pure concatenation of segments, so a tag kept in its own column would
    // shift every later segment boundary.
    expect(sealed.length).toBe(SEGMENT_ZERO_PLAINTEXT.length + DOCUMENT_TAG_BYTES);
  });

  it('opens the committed ciphertext, which is the half that matters to a stored file', async () => {
    const streamKey = await deriveStreamKey(DEK, STREAM_SALT, DOCUMENT_ID);
    const opened = await decryptSegment(
      streamKey,
      { noncePrefix: NONCE_PREFIX, index: 0, isLast: true },
      Uint8Array.from(atob(SEGMENT_ZERO_CIPHERTEXT), (c) => c.charCodeAt(0)),
    );
    expect(new TextDecoder().decode(opened)).toBe(SEGMENT_ZERO_PLAINTEXT);
  });

  it('builds the nonce of segment 3 exactly as the format specifies', async () => {
    // The IV is not returned by the service and must not be: it is derived, not
    // chosen. So it is pinned the only way that proves the implementation uses
    // it — by opening the service's own output with the committed IV through
    // SubtleCrypto directly. A different prefix offset, a little-endian counter
    // or a flag in the wrong byte all fail this.
    const streamKey = await deriveStreamKey(DEK, STREAM_SALT, DOCUMENT_ID);
    const payload = new TextEncoder().encode('segment three');
    const sealed = await encryptSegment(
      streamKey,
      { noncePrefix: NONCE_PREFIX, index: 3, isLast: false },
      payload,
    );

    const opened = await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromHex(SEGMENT_THREE_IV), tagLength: DOCUMENT_TAG_BYTES * 8 },
      streamKey,
      sealed,
    );
    expect(new TextDecoder().decode(opened)).toBe('segment three');
  });

  it.each([
    ['a little-endian counter', '010203040506070300000000'],
    ['the last-segment flag set', '010203040506070000000301'],
    ['the counter one place too early', '010203040506000000030000'],
  ])('does not open segment 3 under %s', async (_label, iv) => {
    const streamKey = await deriveStreamKey(DEK, STREAM_SALT, DOCUMENT_ID);
    const sealed = await encryptSegment(
      streamKey,
      { noncePrefix: NONCE_PREFIX, index: 3, isLast: false },
      new TextEncoder().encode('segment three'),
    );

    await expectRefusal(
      () =>
        globalThis.crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: fromHex(iv), tagLength: DOCUMENT_TAG_BYTES * 8 },
          streamKey,
          sealed,
        ),
      AEAD_REFUSAL,
    );
  });
});

// ---------------------------------------------------------------------------
// The other two `info` strings
// ---------------------------------------------------------------------------

/**
 * The stream vector above pins ONE of the three HKDF `info` strings, because it
 * is the only one its ciphertext depends on. The metadata key and the DEK
 * wrapping key need their own, and for the same reason rather than for symmetry:
 * rename `'hvault/doc/meta/v1|'` to `'hvault/doc/metadata/v1|'` and every other
 * test in this phase still passes — the round trips stay self-consistent, and the
 * two cross-key negatives only prove that SK_meta differs from SK_stream and from
 * another document's, which survives the edit intact. Every metadata blob already
 * in a bucket would stop opening, with no migration possible, because the server
 * holds nothing but ciphertext.
 *
 * Both vectors run in the DECRYPT direction, which is the direction that matters
 * for stored data: can this build still open what an older one wrote? A seal
 * cannot be pinned that way in any case, since both of these functions mint their
 * own IV.
 *
 * Provenance: computed from PLAN.md Section 1.4 by a standalone script that
 * shares no code with the module under test, in the same way the stream vector
 * above was, then reproduced by it.
 */

/** The vault key of the wrap vector: bytes 0x40..0x5f. */
const VECTOR_VAULT_KEY = fromHex(
  '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
);

/** The DEK of the stream vector, wrapped under that vault key and this document id. */
const VECTOR_WRAPPED_DEK = {
  encryptedDek: '5Dg4eDSY3NuWYJfVbRMLqvBAOwYFtpGGhY2QNJYPr8k=',
  dekIv: 'CgsMDQ4PEBESExQV',
  dekTag: 'H6T95vI4SpPQtc+MHsf+/w==',
};

/**
 * The metadata of the vector, and the blob it seals to under `SK_meta`.
 *
 * `chunkPlaintextBytes` is 1024 rather than the real chunk size on purpose: the
 * blob is a format vector, so it should not move if the chunk constant ever does,
 * and the schema bounds this field only as a positive integer for exactly that
 * reason.
 */
const VECTOR_META: DocumentMeta = {
  name: 'vector.txt',
  mime: 'text/plain',
  ext: 'txt',
  plaintextBytes: 6,
  sha256: '6a3ff486bf698be7f4fe3626148fb9f88b8241521eb6562b854f2a14fcf0e54c',
  chunkPlaintextBytes: 1024,
  chunkCount: 1,
  tags: ['vector'],
  capturedAt: '2026-08-31T00:00:00.000Z',
};

const VECTOR_SEALED_META = {
  encryptedMeta:
    '2RU9p4HZUt6p+bGGltZqot0Idnk6A6oaFv7FQ5W1s5Wtc+5LrDWM4/CPERkTv6ytpFW6uK/u1tDnx+rwtsZ3ynJ6+Y8z3A0zLs41f71E6YgFZdM4RGDZYlGr1ALUijXakEcPIY6t6bvU+B9oH9VoesXX04OA0hjIX8tu4XeT3ea+LU6pm3XQW0YVIpWKo4sVOGtLXS3u61yb67MaZ4U5yUtF39iFq6lkjLtYJRQh0He+ANstJZWtQV3JnC5GAMusZoWz23MMkFupoV+qUku38o3jOxhxrgovzriJw92qXmCaUMFHBw3x6IRpuim7fajpFzONna4n0QU=',
  metaIv: 'GhscHR4fICEiIyQl',
  metaTag: 'c0YKo34oGEAcExuZ1jAOtQ==',
};

describe('the committed vectors for the other two derived keys', () => {
  it('opens the committed metadata blob under SK_meta', async () => {
    const metaKey = await deriveMetaKey(DEK, STREAM_SALT, DOCUMENT_ID);
    expect(await decryptMeta(metaKey, VECTOR_SEALED_META)).toEqual(VECTOR_META);
  });

  it('does not open the committed metadata blob under the stream key', async () => {
    // The negative that makes the vector above a statement about the META info
    // string specifically, rather than about "some key derived from this DEK".
    const streamKey = await deriveStreamKey(DEK, STREAM_SALT, DOCUMENT_ID);
    await expectRefusal(() => decryptMeta(streamKey, VECTOR_SEALED_META), AEAD_REFUSAL);
  });

  it('unwraps the committed DEK under the vault-key-bound wrapping key', async () => {
    const vaultKey = await cryptoService.importVaultKey(VECTOR_VAULT_KEY.buffer);
    const wrapKey = await deriveWrapKey(vaultKey, DOCUMENT_ID);
    expect(Array.from(await unwrapDek(VECTOR_WRAPPED_DEK, wrapKey))).toEqual(Array.from(DEK));
  });

  it('does not unwrap the committed DEK under another document id', async () => {
    const vaultKey = await cryptoService.importVaultKey(VECTOR_VAULT_KEY.buffer);
    const foreignKey = await deriveWrapKey(vaultKey, documentId('66c0f1a2b3c4d5e6f7a8b9c1'));
    await expectRefusal(() => unwrapDek(VECTOR_WRAPPED_DEK, foreignKey), AEAD_REFUSAL);
  });

  it('derives every document key as NON-extractable', async () => {
    // The module imports all three with `extractable: false`, and says so as a
    // security claim: a key that cannot be exported cannot be exfiltrated by
    // anything that reaches the reference. Flipping the flag would otherwise fail
    // nothing at all.
    const vaultKey = await cryptoService.importVaultKey(VECTOR_VAULT_KEY.buffer);
    const keys = [
      await deriveStreamKey(DEK, STREAM_SALT, DOCUMENT_ID),
      await deriveMetaKey(DEK, STREAM_SALT, DOCUMENT_ID),
      await deriveWrapKey(vaultKey, DOCUMENT_ID),
    ];
    for (const key of keys) {
      expect(key.extractable).toBe(false);
    }
    // The vault key itself IS extractable, by an existing and deliberate decision
    // (`cryptoService.importVaultKey`), which is what lets it be HKDF input
    // material here at all. Asserted so the contrast is stated rather than
    // assumed.
    expect(vaultKey.extractable).toBe(true);
  });
});
