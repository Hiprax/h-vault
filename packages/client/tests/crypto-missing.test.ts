// @vitest-environment node
import { describe, it, expect, beforeAll, vi } from 'vitest';
import { CryptoService } from '../src/services/crypto/cryptoService';

let crypto: CryptoService;

beforeAll(() => {
  crypto = new CryptoService();
});

// ---------------------------------------------------------------------------
// 1. clearCryptoKey() — security-critical
// ---------------------------------------------------------------------------

describe('clearCryptoKey', () => {
  // NOTE: a test titled "exports raw key material and zeros it for an extractable
  // CryptoKey" was removed here. It called `clearCryptoKey(mek)` but never
  // observed its effect (a CryptoKey is opaque); its actual assertions exercised
  // `generateVaultKey()`/`clearKey()` on an UNRELATED buffer — so gutting
  // `clearCryptoKey` to a no-op would not fail it. The genuine behaviour (that
  // `clearCryptoKey` exports the raw key and hands the 32-byte buffer to
  // `clearKey`, which zeros it) is asserted by the spy-based test below
  // ("after clearCryptoKey, the exported raw buffer is zeroed"), and `clearKey`'s
  // own zeroing is covered directly in crypto.test.ts.

  it('does NOT throw for a non-extractable CryptoKey (silently catches)', async () => {
    // Create a non-extractable AES-GCM key directly
    const nonExtractableKey = await globalThis.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false, // extractable = false
      ['encrypt', 'decrypt'],
    );

    // Should not throw — the catch block silently swallows the error
    await expect(crypto.clearCryptoKey(nonExtractableKey)).resolves.toBeUndefined();
  });

  it('after clearCryptoKey, the exported raw buffer is zeroed', async () => {
    // Create an extractable key
    const extractableKey = await globalThis.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true, // extractable = true
      ['encrypt', 'decrypt'],
    );

    // Spy on clearKey to verify it receives the exported buffer and zeros it
    const clearKeySpy = vi.spyOn(crypto, 'clearKey');

    await crypto.clearCryptoKey(extractableKey);

    // clearKey should have been called exactly once
    expect(clearKeySpy).toHaveBeenCalledTimes(1);

    // The argument should be an ArrayBuffer (the exported raw key material)
    const clearedBuffer = clearKeySpy.mock.calls[0]![0] as ArrayBuffer;
    expect(clearedBuffer).toBeInstanceOf(ArrayBuffer);
    expect(clearedBuffer.byteLength).toBe(32); // 256-bit key = 32 bytes

    // The buffer should now be all zeros (clearKey zeroed it)
    const view = new Uint8Array(clearedBuffer);
    for (const byte of view) {
      expect(byte).toBe(0);
    }

    clearKeySpy.mockRestore();
  });

  it('handles calling clearCryptoKey on an MEK from deriveKeys', async () => {
    const { masterEncryptionKey: mek } = await crypto.deriveKeys('password', 'email@test.com');

    // MEK is extractable (per source code: extractable = true)
    // clearCryptoKey should succeed without error
    await expect(crypto.clearCryptoKey(mek)).resolves.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// 2. Constructor error path (SubtleCrypto unavailable)
// ---------------------------------------------------------------------------

describe('CryptoService constructor', () => {
  it('throws with descriptive error message when crypto.subtle is undefined', () => {
    const originalSubtle = globalThis.crypto.subtle;

    try {
      // Make crypto.subtle undefined
      Object.defineProperty(globalThis.crypto, 'subtle', {
        value: undefined,
        configurable: true,
        writable: true,
      });

      expect(() => new CryptoService()).toThrow(
        'Web Crypto API (SubtleCrypto) is not available. A secure context (HTTPS or localhost) is required.',
      );
    } finally {
      // Restore original
      Object.defineProperty(globalThis.crypto, 'subtle', {
        value: originalSubtle,
        configurable: true,
        writable: true,
      });
    }
  });

  it('successfully constructs when crypto.subtle is available', () => {
    // The global beforeAll already proved this, but make it explicit
    const instance = new CryptoService();
    expect(instance).toBeInstanceOf(CryptoService);
  });
});

// ---------------------------------------------------------------------------
// 3. decryptData with tampered IV
// ---------------------------------------------------------------------------

describe('decryptData with tampered IV', () => {
  let vaultKey: CryptoKey;

  beforeAll(async () => {
    const rawVk = crypto.generateVaultKey();
    vaultKey = await crypto.importVaultKey(rawVk);
  });

  it('fails to decrypt with tampered IV bytes', async () => {
    const plaintext = 'sensitive-data-for-iv-tamper-test';
    const { encrypted, iv, tag } = await crypto.encryptData(plaintext, vaultKey);

    // Tamper with the IV — flip bits in the first byte
    const tamperedIvBytes = new Uint8Array(crypto.base64ToArrayBuffer(iv));
    tamperedIvBytes[0] ^= 0xff;
    const tamperedIv = crypto.arrayBufferToBase64(tamperedIvBytes.buffer as ArrayBuffer);

    // Decryption should fail with tampered IV
    await expect(crypto.decryptData(encrypted, tamperedIv, tag, vaultKey)).rejects.toThrow();
  });

  it('fails to decrypt when IV is completely replaced with random bytes', async () => {
    const plaintext = 'another-secret';
    const { encrypted, iv, tag } = await crypto.encryptData(plaintext, vaultKey);

    // Create a completely different random IV (same length)
    const originalIvBytes = new Uint8Array(crypto.base64ToArrayBuffer(iv));
    const randomIv = new Uint8Array(originalIvBytes.length);
    globalThis.crypto.getRandomValues(randomIv);
    const wrongIv = crypto.arrayBufferToBase64(randomIv.buffer as ArrayBuffer);

    await expect(crypto.decryptData(encrypted, wrongIv, tag, vaultKey)).rejects.toThrow();
  });

  it('fails to decrypt when a single bit is flipped in the IV', async () => {
    const plaintext = 'bit-flip-test';
    const { encrypted, iv, tag } = await crypto.encryptData(plaintext, vaultKey);

    // Flip just one bit (least significant bit of the last byte)
    const ivBytes = new Uint8Array(crypto.base64ToArrayBuffer(iv));
    ivBytes[ivBytes.length - 1] ^= 0x01;
    const tamperedIv = crypto.arrayBufferToBase64(ivBytes.buffer as ArrayBuffer);

    await expect(crypto.decryptData(encrypted, tamperedIv, tag, vaultKey)).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// 4. decryptData with tampered auth tag
// ---------------------------------------------------------------------------

describe('decryptData with tampered auth tag', () => {
  let vaultKey: CryptoKey;

  beforeAll(async () => {
    const rawVk = crypto.generateVaultKey();
    vaultKey = await crypto.importVaultKey(rawVk);
  });

  it('fails to decrypt when a bit is flipped in the auth tag', async () => {
    const plaintext = 'tag-tamper-test-data';
    const { encrypted, iv, tag } = await crypto.encryptData(plaintext, vaultKey);

    const tagBytes = new Uint8Array(crypto.base64ToArrayBuffer(tag));
    tagBytes[0] ^= 0xff;
    const tamperedTag = crypto.arrayBufferToBase64(tagBytes.buffer as ArrayBuffer);

    await expect(crypto.decryptData(encrypted, iv, tamperedTag, vaultKey)).rejects.toThrow();
  });

  it('fails to decrypt when auth tag is completely replaced', async () => {
    const plaintext = 'tag-replace-test';
    const { encrypted, iv, tag } = await crypto.encryptData(plaintext, vaultKey);

    const originalTagBytes = new Uint8Array(crypto.base64ToArrayBuffer(tag));
    const randomTag = new Uint8Array(originalTagBytes.length);
    globalThis.crypto.getRandomValues(randomTag);
    const wrongTag = crypto.arrayBufferToBase64(randomTag.buffer as ArrayBuffer);

    await expect(crypto.decryptData(encrypted, iv, wrongTag, vaultKey)).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// 5. decryptData with tampered ciphertext
// ---------------------------------------------------------------------------

describe('decryptData with tampered ciphertext', () => {
  let vaultKey: CryptoKey;

  beforeAll(async () => {
    const rawVk = crypto.generateVaultKey();
    vaultKey = await crypto.importVaultKey(rawVk);
  });

  it('fails to decrypt when a byte is flipped in the ciphertext', async () => {
    const plaintext = 'ciphertext-tamper-test';
    const { encrypted, iv, tag } = await crypto.encryptData(plaintext, vaultKey);

    const ciphertextBytes = new Uint8Array(crypto.base64ToArrayBuffer(encrypted));
    ciphertextBytes[0] ^= 0xff;
    const tamperedCiphertext = crypto.arrayBufferToBase64(ciphertextBytes.buffer as ArrayBuffer);

    await expect(crypto.decryptData(tamperedCiphertext, iv, tag, vaultKey)).rejects.toThrow();
  });

  it('fails to decrypt when ciphertext is truncated', async () => {
    const plaintext = 'truncation-test-data-long-enough';
    const { encrypted, iv, tag } = await crypto.encryptData(plaintext, vaultKey);

    const ciphertextBytes = new Uint8Array(crypto.base64ToArrayBuffer(encrypted));
    const truncated = ciphertextBytes.slice(0, Math.floor(ciphertextBytes.length / 2));
    const truncatedCiphertext = crypto.arrayBufferToBase64(truncated.buffer as ArrayBuffer);

    await expect(crypto.decryptData(truncatedCiphertext, iv, tag, vaultKey)).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// 6. Cross-key decryption failures
// ---------------------------------------------------------------------------

describe('cross-key decryption failures', () => {
  it('fails to decrypt vault key with a different MEK', async () => {
    const { masterEncryptionKey: mek1 } = await crypto.deriveKeys('password1', 'user1@test.com');
    const { masterEncryptionKey: mek2 } = await crypto.deriveKeys('password2', 'user2@test.com');

    const rawVaultKey = crypto.generateVaultKey();
    const vaultKey = await crypto.importVaultKey(rawVaultKey);

    const { encrypted, iv, tag } = await crypto.encryptVaultKey(vaultKey, mek1);

    await expect(crypto.decryptVaultKey(encrypted, iv, tag, mek2)).rejects.toThrow();
  });

  it('fails to decrypt data with a different vault key', async () => {
    const rawVk1 = crypto.generateVaultKey();
    const vaultKey1 = await crypto.importVaultKey(rawVk1);

    const rawVk2 = crypto.generateVaultKey();
    const vaultKey2 = await crypto.importVaultKey(rawVk2);

    const plaintext = 'secret-data-for-cross-key-test';
    const { encrypted, iv, tag } = await crypto.encryptData(plaintext, vaultKey1);

    await expect(crypto.decryptData(encrypted, iv, tag, vaultKey2)).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// 7. Edge cases: empty password, empty email in deriveKeys
// ---------------------------------------------------------------------------

describe('deriveKeys edge cases — empty inputs', () => {
  it('deriveKeys with empty string password still produces valid keys', async () => {
    const { masterEncryptionKey, authKey } = await crypto.deriveKeys('', 'user@example.com');

    expect(masterEncryptionKey).toBeDefined();
    expect(masterEncryptionKey.type).toBe('secret');
    expect(masterEncryptionKey.algorithm).toMatchObject({ name: 'AES-GCM' });

    expect(authKey).toBeInstanceOf(ArrayBuffer);
    expect(authKey.byteLength).toBe(32);
  });

  it('deriveKeys with empty string email still produces valid keys', async () => {
    const { masterEncryptionKey, authKey } = await crypto.deriveKeys('some-password', '');

    expect(masterEncryptionKey).toBeDefined();
    expect(masterEncryptionKey.type).toBe('secret');
    expect(masterEncryptionKey.algorithm).toMatchObject({ name: 'AES-GCM' });

    expect(authKey).toBeInstanceOf(ArrayBuffer);
    expect(authKey.byteLength).toBe(32);
  });

  it('deriveKeys with both empty strings produces valid keys', async () => {
    const { masterEncryptionKey, authKey } = await crypto.deriveKeys('', '');

    expect(masterEncryptionKey).toBeDefined();
    expect(masterEncryptionKey.type).toBe('secret');
    expect(masterEncryptionKey.algorithm).toMatchObject({ name: 'AES-GCM' });

    expect(authKey).toBeInstanceOf(ArrayBuffer);
    expect(authKey.byteLength).toBe(32);
  });

  it('empty password produces different keys than non-empty password', async () => {
    const result1 = await crypto.deriveKeys('', 'user@example.com');
    const result2 = await crypto.deriveKeys('non-empty', 'user@example.com');

    expect(crypto.getAuthHash(result1.authKey)).not.toBe(crypto.getAuthHash(result2.authKey));
  });

  it('empty email produces different keys than non-empty email', async () => {
    const result1 = await crypto.deriveKeys('password', '');
    const result2 = await crypto.deriveKeys('password', 'user@example.com');

    expect(crypto.getAuthHash(result1.authKey)).not.toBe(crypto.getAuthHash(result2.authKey));
  });

  it('both empty produces different keys than both non-empty', async () => {
    const result1 = await crypto.deriveKeys('', '');
    const result2 = await crypto.deriveKeys('password', 'user@example.com');

    expect(crypto.getAuthHash(result1.authKey)).not.toBe(crypto.getAuthHash(result2.authKey));
  });

  it('empty password keys can still encrypt and decrypt data', async () => {
    const { masterEncryptionKey: mek } = await crypto.deriveKeys('', 'user@example.com');
    const rawVaultKey = crypto.generateVaultKey();
    const vaultKey = await crypto.importVaultKey(rawVaultKey);

    // Encrypt vault key with MEK derived from empty password
    const { encrypted, iv, tag } = await crypto.encryptVaultKey(vaultKey, mek);

    // Decrypt it back
    const decryptedVK = await crypto.decryptVaultKey(encrypted, iv, tag, mek);
    expect(new Uint8Array(decryptedVK)).toEqual(new Uint8Array(rawVaultKey));
  });

  it('empty email keys can still encrypt and decrypt data', async () => {
    const { masterEncryptionKey: mek } = await crypto.deriveKeys('password', '');
    const rawVaultKey = crypto.generateVaultKey();
    const vaultKey = await crypto.importVaultKey(rawVaultKey);

    const { encrypted, iv, tag } = await crypto.encryptVaultKey(vaultKey, mek);
    const decryptedVK = await crypto.decryptVaultKey(encrypted, iv, tag, mek);
    expect(new Uint8Array(decryptedVK)).toEqual(new Uint8Array(rawVaultKey));
  });
});
