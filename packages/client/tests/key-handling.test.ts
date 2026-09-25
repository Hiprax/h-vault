// @vitest-environment node
/**
 * How the key hierarchy's two password-derived secrets are handled once derived.
 *
 * The Master Encryption Key is the one key a vault-key rotation does NOT retire:
 * `rotateVaultKey` seals the new vault key under the SAME MEK, and the server
 * hands the sealed copy to every signed-in session. So raw MEK bytes, once
 * copied out of the page, unwrap every later vault key until the master
 * password changes. What stops the copy is the key being non-extractable, and
 * this file pins that on the key `deriveKeys` really returns: no fake
 * `CryptoKey`, no mocked `SubtleCrypto`, the real 600,000-iteration derivation.
 *
 * The iteration count is pinned here too, because it is the one number the
 * client and the server both record and only the client ever acts on.
 */
import { describe, it, expect, beforeAll, vi } from 'vitest';
import { KDF_ITERATIONS } from '@hvault/shared';
import { CryptoService } from '../src/services/crypto/cryptoService';

const PASSWORD = 'correct horse battery staple';
const EMAIL = 'Key.Handling@Example.test ';

let crypto: CryptoService;
let mek: CryptoKey;

beforeAll(async () => {
  crypto = new CryptoService();
  ({ masterEncryptionKey: mek } = await crypto.deriveKeys(PASSWORD, EMAIL));
});

describe('the Master Encryption Key returned by deriveKeys', () => {
  it('is a non-extractable AES-256-GCM key usable only to encrypt and decrypt', () => {
    expect(mek.type).toBe('secret');
    expect(mek.extractable).toBe(false);
    expect(mek.algorithm).toEqual({ name: 'AES-GCM', length: 256 });
    expect([...mek.usages].sort()).toEqual(['decrypt', 'encrypt']);
  });

  it.each(['raw', 'jwk'] as const)('refuses to be exported as %s', async (format) => {
    // The DOMException name is what a browser raises for an export of a
    // non-extractable key, so a key that is merely awkward to export (a format
    // mismatch, say) would fail this rather than pass it.
    await expect(globalThis.crypto.subtle.exportKey(format, mek)).rejects.toMatchObject({
      name: 'InvalidAccessError',
    });
  });

  it('still wraps a vault key that a fresh derivation of the same password unwraps', async () => {
    const vaultKey = await crypto.importVaultKey(crypto.generateVaultKey());
    const expected = new Uint8Array(await globalThis.crypto.subtle.exportKey('raw', vaultKey));

    const wrapped = await crypto.encryptVaultKey(vaultKey, mek);
    const { masterEncryptionKey: again } = await crypto.deriveKeys(PASSWORD, EMAIL);
    const unwrapped = await crypto.decryptVaultKey(
      wrapped.encrypted,
      wrapped.iv,
      wrapped.tag,
      again,
    );

    expect(new Uint8Array(unwrapped)).toEqual(expected);
    // The vault key itself stays extractable, by a separate and deliberate
    // decision: it is exported on every save and by the backup and search paths.
    expect(vaultKey.extractable).toBe(true);
  });

  it('still seals a rotated vault key the same MEK opens', async () => {
    const { newVaultKey, encrypted, iv, tag } = await crypto.rotateVaultKey(mek);
    const expected = new Uint8Array(await globalThis.crypto.subtle.exportKey('raw', newVaultKey));

    const unwrapped = await crypto.decryptVaultKey(encrypted, iv, tag, mek);

    expect(new Uint8Array(unwrapped)).toEqual(expected);
  });

  it('is left untouched by clearCryptoKey: no raw copy exists, so there is nothing to zero', async () => {
    const clearKey = vi.spyOn(crypto, 'clearKey');
    try {
      await expect(crypto.clearCryptoKey(mek)).resolves.toBeUndefined();
      // Nothing was exported, so nothing was handed to the zeroing routine.
      expect(clearKey).not.toHaveBeenCalled();
    } finally {
      clearKey.mockRestore();
    }

    // And the live handle keeps working, which is why lock and logout drop
    // their reference to it rather than relying on "clearing" it.
    const wrapped = await crypto.encryptVaultKey(
      await crypto.importVaultKey(crypto.generateVaultKey()),
      mek,
    );
    await expect(
      crypto.decryptVaultKey(wrapped.encrypted, wrapped.iv, wrapped.tag, mek),
    ).resolves.toBeInstanceOf(ArrayBuffer);
  });
});

describe('the password-based key derivations', () => {
  it('keep the shared KDF_ITERATIONS value of 600,000', () => {
    // Pinned against a literal on purpose: changing it would make every
    // existing vault and every backup undecryptable, and a test comparing the
    // constant with itself could not say so.
    expect(KDF_ITERATIONS).toBe(600_000);
  });

  it('derive the MEK and the auth material with exactly KDF_ITERATIONS, then one iteration', async () => {
    const deriveBits = vi.spyOn(globalThis.crypto.subtle, 'deriveBits');
    try {
      await crypto.deriveKeys(PASSWORD, EMAIL);
      const iterations = deriveBits.mock.calls.map(
        ([params]) => (params as Pbkdf2Params).iterations,
      );
      expect(iterations).toEqual([KDF_ITERATIONS, 1]);
    } finally {
      deriveBits.mockRestore();
    }
  });

  it('derive the backup encryption key with exactly KDF_ITERATIONS', async () => {
    const deriveKey = vi.spyOn(globalThis.crypto.subtle, 'deriveKey');
    try {
      const bek = await crypto.deriveBEK('backup password', new Uint8Array(16).buffer);
      expect(deriveKey).toHaveBeenCalledTimes(1);
      expect((deriveKey.mock.calls[0]![0] as Pbkdf2Params).iterations).toBe(KDF_ITERATIONS);
      expect(bek.extractable).toBe(false);
    } finally {
      deriveKey.mockRestore();
    }
  });
});
