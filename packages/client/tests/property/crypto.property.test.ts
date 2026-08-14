/**
 * `cryptoService`'s AES-256-GCM surface, as PROPERTIES rather than examples.
 *
 * This is the module the whole zero-knowledge claim rests on: everything a user
 * stores is `encryptData(JSON.stringify(data), vaultKey)`, and the ciphertext is
 * the ONLY copy. So the properties worth stating are the ones whose failure is
 * unrecoverable rather than merely wrong:
 *
 *   1. Whatever goes in comes back out, for any string a browser can hold —
 *      astral characters, NUL bytes, unpaired surrogates, half a megabyte of
 *      them.
 *   2. Every call uses a FRESH IV. This is the one property an example test
 *      almost never states, and the only one that catches the catastrophic
 *      misuse: a fixed-IV implementation passes a round-trip test, passes a
 *      wrong-key test, passes a tampering test, and leaks the XOR of two
 *      plaintexts to anyone holding both ciphertexts. AES-GCM with a repeated
 *      (key, IV) pair also exposes the authentication subkey, so forgery becomes
 *      possible — nonce reuse is the failure mode of GCM, not a nicety.
 *   3. A wrong key, a flipped tag byte or a flipped ciphertext byte REJECTS, and
 *      never hands back a partial plaintext. AES-GCM's tag check is what makes
 *      the vault tamper-evident, and "returns the bytes it managed to decrypt"
 *      is exactly what an unauthenticated mode would do.
 *
 * The real `cryptoService` is used throughout — no stubbed SubtleCrypto, no faked
 * randomness. Only the fast-check seed is pinned (see `tests/harness/property.ts`).
 */
import { beforeAll, describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { cryptoService } from '../../src/services/crypto/cryptoService';
import {
  CRYPTO_RUNS,
  HEAVY_RUNS,
  propertyBanner,
  propertyRun,
} from '../../../../tests/harness/property.js';

/** 12 bytes, base64 — the IV `encryptData` emits. */
const IV_BASE64_LENGTH = 16;
/** 16 bytes, base64 — the GCM tag `encryptData` splits off. */
const TAG_BASE64_LENGTH = 24;

/** The 500 kB payload class the plan names, in UTF-16 code units. */
const HALF_MEGABYTE = 500_000;

let vaultKey: CryptoKey;
let otherKey: CryptoKey;

beforeAll(async () => {
  // Real keys, through the real import path. Not `deriveKeys`: that is 600k
  // PBKDF2 iterations per call and derivation is not what these properties are
  // about (`crypto.test.ts` covers it), so the key here is generated exactly as
  // `rotateVaultKey` generates one.
  vaultKey = await cryptoService.importVaultKey(cryptoService.generateVaultKey());
  otherKey = await cryptoService.importVaultKey(cryptoService.generateVaultKey());
});

/**
 * The UTF-8 well-formed form of `text`: every UNPAIRED surrogate replaced by
 * U+FFFD, everything else untouched.
 *
 * This is the one place a round-trip through `encryptData`/`decryptData` is NOT
 * the identity, and it is a property of the Encoding Standard rather than of this
 * codebase: `TextEncoder.encode` is defined to emit U+FFFD for a lone surrogate
 * (a lone surrogate has no UTF-8 representation), and `TextDecoder` then decodes
 * that back as U+FFFD. `String.prototype.toWellFormed` does exactly this, but it
 * is ES2024 and this repository's `lib` is ES2022, so the rule is spelled out
 * here — and pinned by its own assertions below, so the oracle cannot quietly
 * become wrong.
 */
const UNPAIRED_SURROGATE =
  /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

function wellFormed(text: string): string {
  return text.replace(UNPAIRED_SURROGATE, '�');
}

/**
 * Strings a real vault holds: ASCII, unicode, astral pairs, NUL, control
 * characters and unpaired surrogates. `unit: 'binary'` is what puts the last of
 * those in the sample — the default grapheme unit never emits one.
 */
const anyString = fc.oneof(
  fc.string({ unit: 'binary', maxLength: 64 }),
  fc.string({ maxLength: 64 }),
  // Longer than a GCM block, so the ciphertext-distinctness half of the
  // freshness property below has inputs it can actually assert on (see there).
  fc.string({ unit: 'binary', minLength: 24, maxLength: 96 }),
  fc.constant(''),
  fc.constant('\u0000'),
  fc.constant('\uD800'),
  fc.constant('\uDFFF'),
  fc.constant('a😀b'),
  fc.json({ maxDepth: 3 }),
);

/** Flip one bit of a base64-encoded buffer, at `index`, and re-encode. */
function flipByte(base64: string, index: number): string {
  const bytes = new Uint8Array(cryptoService.base64ToArrayBuffer(base64));
  const at = index % bytes.length;
  bytes[at] = (bytes[at] ?? 0) ^ 0x01;
  return cryptoService.arrayBufferToBase64(bytes.buffer);
}

describe('the well-formed oracle this file compares against', () => {
  it('replaces only unpaired surrogates, and leaves everything else alone', () => {
    // The oracle is an assertion about the Encoding Standard, so it is pinned
    // rather than trusted. Without this, a wrong oracle would make the round-trip
    // property below vacuous in exactly the cases it exists for.
    expect(wellFormed('plain')).toBe('plain');
    expect(wellFormed('\u0000')).toBe('\u0000');
    expect(wellFormed('a😀b')).toBe('a😀b');
    expect(wellFormed('\uD800')).toBe('�');
    expect(wellFormed('\uDFFF')).toBe('�');
    expect(wellFormed('a\uD800\uD800b')).toBe('a��b');
    expect(wellFormed('\uDC00\uD800')).toBe('��');
  });
});

describe('encryptData / decryptData round-trip', () => {
  it('returns exactly what was encrypted, for any well-formed string', async () => {
    await fc.assert(
      fc.asyncProperty(anyString, async (plaintext) => {
        const { encrypted, iv, tag } = await cryptoService.encryptData(plaintext, vaultKey);
        const decrypted = await cryptoService.decryptData(encrypted, iv, tag, vaultKey);

        // The one lossy case is stated, not hidden: an unpaired surrogate has no
        // UTF-8 encoding, so it comes back as U+FFFD. Everything else is exact.
        expect(decrypted, propertyBanner()).toBe(wellFormed(plaintext));
        if (plaintext === wellFormed(plaintext)) {
          expect(decrypted, propertyBanner()).toBe(plaintext);
        }
      }),
      propertyRun({ numRuns: CRYPTO_RUNS }),
    );
  });

  it('emits a 12-byte IV and a 16-byte tag, and base64 that decodes to itself', async () => {
    await fc.assert(
      fc.asyncProperty(anyString, async (plaintext) => {
        const { encrypted, iv, tag } = await cryptoService.encryptData(plaintext, vaultKey);

        expect(iv, propertyBanner()).toHaveLength(IV_BASE64_LENGTH);
        expect(tag, propertyBanner()).toHaveLength(TAG_BASE64_LENGTH);
        expect(
          new Uint8Array(cryptoService.base64ToArrayBuffer(iv)),
          propertyBanner(),
        ).toHaveLength(12);
        expect(
          new Uint8Array(cryptoService.base64ToArrayBuffer(tag)),
          propertyBanner(),
        ).toHaveLength(16);
        // The ciphertext is the plaintext's byte length, GCM being a stream mode:
        // asserted because a ciphertext that carried the tag twice, or dropped a
        // block, would still round-trip while wasting or losing bytes.
        const encoded = new TextEncoder().encode(wellFormed(plaintext));
        expect(
          new Uint8Array(cryptoService.base64ToArrayBuffer(encrypted)).length,
          propertyBanner(),
        ).toBe(encoded.length);
      }),
      propertyRun({ numRuns: CRYPTO_RUNS }),
    );
  });

  it('round-trips a half-megabyte payload of arbitrary unicode', async () => {
    await fc.assert(
      fc.asyncProperty(fc.constantFrom('x', 'é', '中', '😀', '\u0000'), async (unit) => {
        // Built by repetition rather than generated character by character: the
        // property is about the SIZE class, and a 500 kB fast-check string costs
        // seconds to shrink for no extra information.
        const plaintext = unit.repeat(Math.ceil(HALF_MEGABYTE / unit.length));
        expect(plaintext.length).toBeGreaterThanOrEqual(HALF_MEGABYTE);

        const { encrypted, iv, tag } = await cryptoService.encryptData(plaintext, vaultKey);
        const decrypted = await cryptoService.decryptData(encrypted, iv, tag, vaultKey);

        expect(decrypted.length, propertyBanner()).toBe(plaintext.length);
        expect(decrypted === plaintext, propertyBanner()).toBe(true);
      }),
      propertyRun({ numRuns: HEAVY_RUNS }),
    );
  });
});

describe('encryptData is non-deterministic', () => {
  it('draws a fresh IV for every call, so one plaintext never has one ciphertext', async () => {
    // THE property this file exists for. A fixed-IV implementation satisfies
    // every other test in this file, and under GCM a repeated (key, IV) pair
    // leaks the XOR of the two plaintexts AND the authentication subkey.
    const CALLS = 8;

    await fc.assert(
      fc.asyncProperty(anyString, async (plaintext) => {
        const results = await Promise.all(
          Array.from({ length: CALLS }, () => cryptoService.encryptData(plaintext, vaultKey)),
        );

        const ivs = new Set(results.map((result) => result.iv));
        expect(
          ivs.size,
          `${propertyBanner()} — AES-GCM nonce reuse: ${String(CALLS)} calls produced ${String(ivs.size)} distinct IV(s)`,
        ).toBe(CALLS);

        // A distinct IV must actually change the ciphertext. Two identical
        // ciphertexts under different IVs would mean the IV is generated and then
        // ignored — which is nonce reuse wearing a disguise.
        //
        // Gated on 16 encoded bytes, and the bound is not arbitrary: GCM is a
        // stream mode, so the ciphertext is exactly as long as the plaintext, and
        // a ONE-byte plaintext has only 256 possible ciphertexts. Eight draws
        // then collide about 11% of the time — measured: this property failed on
        // the counterexample U+0000 (one NUL) with 7 distinct ciphertexts out
        // of 8, with a perfectly correct implementation. At 16 bytes a collision is a
        // ~2^-128 event per pair, which is the same negligibility the IVs
        // themselves rely on; below it, the claim is about arithmetic rather than
        // about the code, so it is not made.
        const encodedLength = new TextEncoder().encode(wellFormed(plaintext)).length;
        if (encodedLength >= 16) {
          const ciphertexts = new Set(results.map((result) => result.encrypted));
          expect(
            ciphertexts.size,
            `${propertyBanner()} — ${String(CALLS)} encryptions of one plaintext produced ${String(ciphertexts.size)} distinct ciphertext(s)`,
          ).toBe(CALLS);
        }

        // Every one of them still decrypts, so freshness is not bought with a
        // broken IV (a zero-length or truncated one would fail here).
        for (const { encrypted, iv, tag } of results) {
          expect(
            await cryptoService.decryptData(encrypted, iv, tag, vaultKey),
            propertyBanner(),
          ).toBe(wellFormed(plaintext));
        }
      }),
      propertyRun({ numRuns: CRYPTO_RUNS }),
    );
  });

  /**
   * The shrunk counterexample the freshness property found on its first run, at
   * `SEED=1337`, `numRuns=25`: the one-character plaintext U+0000, for which 8
   * encryptions produced 7 distinct ciphertexts.
   *
   * The implementation was CORRECT; the property was wrong. GCM is a stream mode,
   * so a one-byte plaintext has a one-byte ciphertext, and eight draws from 256
   * values collide about 11% of the time. Committed as its own test because it is
   * the case that decides where the ciphertext-distinctness claim may be made at
   * all: the IVs must still all differ (that claim has no size condition), while
   * the ciphertexts must not be required to.
   */
  it('REGRESSION: a one-byte plaintext still gets fresh IVs, though its ciphertexts may collide', async () => {
    const CALLS = 8;
    const oneByte = '\u0000';
    expect(new TextEncoder().encode(oneByte)).toHaveLength(1);

    const results = await Promise.all(
      Array.from({ length: CALLS }, () => cryptoService.encryptData(oneByte, vaultKey)),
    );

    expect(new Set(results.map((result) => result.iv)).size).toBe(CALLS);
    // Every one still decrypts to the same byte, which is what makes the
    // ciphertext collisions above harmless rather than a sign of reuse.
    for (const { encrypted, iv, tag } of results) {
      expect(await cryptoService.decryptData(encrypted, iv, tag, vaultKey)).toBe(oneByte);
    }
    // And the ciphertext is one byte, which is the whole reason a collision is
    // possible: stated so the exclusion in the property above is checkable.
    for (const { encrypted } of results) {
      expect(new Uint8Array(cryptoService.base64ToArrayBuffer(encrypted))).toHaveLength(1);
    }
  });

  it('never repeats an IV across many calls with different plaintexts either', async () => {
    // The same claim from the other side: a per-plaintext cache, or a counter
    // reset per call, would pass the property above only if it happened to be
    // per-call. 12 random bytes make a collision here effectively impossible, so
    // any repeat is a bug rather than luck.
    await fc.assert(
      fc.asyncProperty(fc.array(anyString, { minLength: 4, maxLength: 12 }), async (plaintexts) => {
        const ivs = new Set<string>();
        for (const plaintext of plaintexts) {
          const { iv } = await cryptoService.encryptData(plaintext, vaultKey);
          ivs.add(iv);
        }
        expect(ivs.size, propertyBanner()).toBe(plaintexts.length);
      }),
      propertyRun({ numRuns: CRYPTO_RUNS }),
    );
  });
});

describe('decryptData refuses anything that is not exactly what was encrypted', () => {
  it('rejects a wrong key, and yields no plaintext at all', async () => {
    await fc.assert(
      fc.asyncProperty(anyString, async (plaintext) => {
        const { encrypted, iv, tag } = await cryptoService.encryptData(plaintext, vaultKey);

        // `rejects` alone would be satisfied by a TypeError from a typo in this
        // test, so the outcome is captured and inspected: nothing may be
        // returned, and what is thrown must be the GCM tag check failing.
        let resolved: string | undefined;
        let thrown: unknown;
        try {
          resolved = await cryptoService.decryptData(encrypted, iv, tag, otherKey);
        } catch (error) {
          thrown = error;
        }

        expect(resolved, `${propertyBanner()} — a wrong key produced plaintext`).toBeUndefined();
        expect(thrown, propertyBanner()).toBeInstanceOf(Error);
        expect((thrown as Error).name, propertyBanner()).toBe('OperationError');
      }),
      propertyRun({ numRuns: CRYPTO_RUNS }),
    );
  });

  it.each(['tag', 'ciphertext', 'iv'] as const)(
    'rejects a single flipped bit in the %s',
    async (part) => {
      await fc.assert(
        fc.asyncProperty(
          // A non-empty plaintext, so the ciphertext has a byte to flip.
          anyString.filter((value) => value.length > 0),
          fc.nat({ max: 1_000 }),
          async (plaintext, index) => {
            const original = await cryptoService.encryptData(plaintext, vaultKey);
            const damaged = { ...original };
            if (part === 'tag') damaged.tag = flipByte(original.tag, index);
            if (part === 'iv') damaged.iv = flipByte(original.iv, index);
            if (part === 'ciphertext') damaged.encrypted = flipByte(original.encrypted, index);

            let resolved: string | undefined;
            let thrown: unknown;
            try {
              resolved = await cryptoService.decryptData(
                damaged.encrypted,
                damaged.iv,
                damaged.tag,
                vaultKey,
              );
            } catch (error) {
              thrown = error;
            }

            // The whole point of an AEAD: one flipped bit anywhere yields NOTHING,
            // not a plaintext with one wrong character. A mode without an
            // authentication tag would return the damaged plaintext instead.
            expect(
              resolved,
              `${propertyBanner()} — tampering with the ${part} still produced plaintext`,
            ).toBeUndefined();
            expect((thrown as Error | undefined)?.name, propertyBanner()).toBe('OperationError');
          },
        ),
        propertyRun({ numRuns: CRYPTO_RUNS }),
      );
    },
  );

  it('rejects a ciphertext decrypted under the IV of a different call', async () => {
    // The IV is stored beside the ciphertext, so a bug that mixed up two rows'
    // IVs — or a rotation that rewrote one and not the other — must fail loudly.
    await fc.assert(
      fc.asyncProperty(anyString, async (plaintext) => {
        const first = await cryptoService.encryptData(plaintext, vaultKey);
        const second = await cryptoService.encryptData(plaintext, vaultKey);

        // The same capture-and-inspect shape as the two properties above, and
        // for the same reason: a bare `rejects.toThrow()` is satisfied by ANY
        // rejection, including a `TypeError` raised by a typo in this test, so
        // it cannot tell "the tag check failed" from "the call does not exist".
        // `decryptData` does not wrap, so the GCM failure surfaces as WebCrypto's
        // own `OperationError`, exactly as it does for a wrong key.
        let resolved: string | undefined;
        let thrown: unknown;
        try {
          resolved = await cryptoService.decryptData(
            first.encrypted,
            second.iv,
            first.tag,
            vaultKey,
          );
        } catch (error) {
          thrown = error;
        }

        expect(
          resolved,
          `${propertyBanner()} — a mismatched IV produced plaintext`,
        ).toBeUndefined();
        expect(thrown, propertyBanner()).toBeInstanceOf(Error);
        expect((thrown as Error).name, propertyBanner()).toBe('OperationError');
      }),
      propertyRun({ numRuns: CRYPTO_RUNS }),
    );
  });
});
