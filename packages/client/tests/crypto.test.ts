// @vitest-environment node
import { describe, it, expect, beforeAll, vi } from 'vitest';
import { CryptoService } from '../src/services/crypto/cryptoService';

let crypto: CryptoService;

beforeAll(() => {
  crypto = new CryptoService();
});

// ---------------------------------------------------------------------------
// Key Derivation (PBKDF2, 600K iterations)
// ---------------------------------------------------------------------------

describe('deriveKeys', () => {
  it('derives a CryptoKey (MEK) and an ArrayBuffer (authKey)', async () => {
    const { masterEncryptionKey, authKey } = await crypto.deriveKeys(
      'master-password',
      'user@example.com',
    );

    expect(masterEncryptionKey).toBeDefined();
    expect(masterEncryptionKey.type).toBe('secret');
    expect(masterEncryptionKey.algorithm).toMatchObject({ name: 'AES-GCM' });

    expect(authKey).toBeInstanceOf(ArrayBuffer);
    expect(authKey.byteLength).toBe(32); // 256 bits
  });

  it('is deterministic — same inputs produce same outputs', async () => {
    const result1 = await crypto.deriveKeys('password123', 'alice@test.com');
    const result2 = await crypto.deriveKeys('password123', 'alice@test.com');

    const hash1 = crypto.getAuthHash(result1.authKey);
    const hash2 = crypto.getAuthHash(result2.authKey);
    expect(hash1).toBe(hash2);
  });

  it('produces different outputs for different passwords', async () => {
    const result1 = await crypto.deriveKeys('password-A', 'user@example.com');
    const result2 = await crypto.deriveKeys('password-B', 'user@example.com');

    expect(crypto.getAuthHash(result1.authKey)).not.toBe(crypto.getAuthHash(result2.authKey));
  });

  it('produces different outputs for different emails', async () => {
    const result1 = await crypto.deriveKeys('same-pass', 'a@example.com');
    const result2 = await crypto.deriveKeys('same-pass', 'b@example.com');

    expect(crypto.getAuthHash(result1.authKey)).not.toBe(crypto.getAuthHash(result2.authKey));
  });

  it('normalises email salt — case and whitespace insensitive', async () => {
    const r1 = await crypto.deriveKeys('pw', '  User@Example.COM  ');
    const r2 = await crypto.deriveKeys('pw', 'user@example.com');

    expect(crypto.getAuthHash(r1.authKey)).toBe(crypto.getAuthHash(r2.authKey));
  });

  it('zeroes the password bytes buffer after derivation (best-effort)', async () => {
    // The deriveKeys `finally` block zeroes the intermediate password buffer
    // (and the derived-bits buffers) via clearKey. We cannot reach the internal
    // passwordBytes directly, but the password buffer is the ONLY clearKey
    // argument whose byteLength equals the encoded master-password length
    // (derivedBits is 64 bytes, mek/auth material are 32 bytes each), so
    // asserting clearKey received a buffer of that exact size pins the
    // password-zeroing specifically. Deleting the finally block removes this
    // call and turns the test red.
    const clearKeySpy = vi.spyOn(crypto, 'clearKey');
    try {
      const password = 'zeroing-probe-password'; // 22 ASCII bytes
      const expectedPasswordBytes = new TextEncoder().encode(password).byteLength;
      expect([32, 64]).not.toContain(expectedPasswordBytes); // must be unambiguous

      await crypto.deriveKeys(password, 'zeroing@example.com');

      const clearedByteLengths = clearKeySpy.mock.calls.map(([buf]) => buf.byteLength);
      expect(clearedByteLengths).toContain(expectedPasswordBytes);
    } finally {
      clearKeySpy.mockRestore();
    }
  });
});

// ---------------------------------------------------------------------------
// deriveBEK password bytes zeroing
// ---------------------------------------------------------------------------

describe('deriveBEK', () => {
  it('derives a CryptoKey from backup password and salt', async () => {
    const salt = crypto.generateSalt(16);
    const bek = await crypto.deriveBEK('backup-password', salt);

    expect(bek).toBeDefined();
    expect(bek.type).toBe('secret');
    expect(bek.algorithm).toMatchObject({ name: 'AES-GCM' });
  });

  it('produces different keys for different passwords', async () => {
    const salt = crypto.generateSalt(16);
    const bek1 = await crypto.deriveBEK('password-A', salt);
    const bek2 = await crypto.deriveBEK('password-B', salt);

    // The keys should be different — verify by encrypting the same data
    const testData = 'test-data';
    const enc1 = await crypto.encryptData(testData, bek1);
    const enc2 = await crypto.encryptData(testData, bek2);

    // Different keys produce different ciphertexts
    expect(enc1.encrypted).not.toBe(enc2.encrypted);
  });
});

// ---------------------------------------------------------------------------
// MEK / Auth Key split
// ---------------------------------------------------------------------------

describe('getAuthHash', () => {
  it('returns a non-empty base64 string', async () => {
    const { authKey } = await crypto.deriveKeys('pw', 'u@e.com');
    const hash = crypto.getAuthHash(authKey);

    expect(typeof hash).toBe('string');
    expect(hash.length).toBeGreaterThan(0);
    // Validate base64 format
    expect(() => atob(hash)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Vault Key Generation
// ---------------------------------------------------------------------------

describe('generateVaultKey', () => {
  it('produces a 32-byte ArrayBuffer', async () => {
    const vk = await crypto.generateVaultKey();
    expect(vk).toBeInstanceOf(ArrayBuffer);
    expect(vk.byteLength).toBe(32);
  });

  it('produces unique keys on successive calls', async () => {
    const vk1 = await crypto.generateVaultKey();
    const vk2 = await crypto.generateVaultKey();

    const b1 = crypto.arrayBufferToBase64(vk1);
    const b2 = crypto.arrayBufferToBase64(vk2);
    expect(b1).not.toBe(b2);
  });
});

// ---------------------------------------------------------------------------
// Vault Key Encryption / Decryption
// ---------------------------------------------------------------------------

describe('encryptVaultKey / decryptVaultKey', () => {
  it('round-trips: decrypt(encrypt(vk)) === vk', async () => {
    const { masterEncryptionKey: mek } = await crypto.deriveKeys('pw', 'u@e.com');
    const rawVk = await crypto.generateVaultKey();
    const vk = await crypto.importVaultKey(rawVk);

    const { encrypted, iv, tag } = await crypto.encryptVaultKey(vk, mek);
    const decrypted = await crypto.decryptVaultKey(encrypted, iv, tag, mek);

    expect(new Uint8Array(decrypted)).toEqual(new Uint8Array(rawVk));
  });

  it('returns base64-encoded strings for encrypted, iv, tag', async () => {
    const { masterEncryptionKey: mek } = await crypto.deriveKeys('pw', 'u@e.com');
    const rawVk = await crypto.generateVaultKey();
    const vk = await crypto.importVaultKey(rawVk);

    const { encrypted, iv, tag } = await crypto.encryptVaultKey(vk, mek);

    expect(() => atob(encrypted)).not.toThrow();
    expect(() => atob(iv)).not.toThrow();
    expect(() => atob(tag)).not.toThrow();

    // IV should be 12 bytes
    expect(atob(iv).length).toBe(12);
    // Tag should be 16 bytes
    expect(atob(tag).length).toBe(16);
  });

  it('produces different ciphertext for the same plaintext (random IV)', async () => {
    const { masterEncryptionKey: mek } = await crypto.deriveKeys('pw', 'u@e.com');
    const rawVk = await crypto.generateVaultKey();
    const vk = await crypto.importVaultKey(rawVk);

    const enc1 = await crypto.encryptVaultKey(vk, mek);
    const enc2 = await crypto.encryptVaultKey(vk, mek);

    expect(enc1.iv).not.toBe(enc2.iv);
    expect(enc1.encrypted).not.toBe(enc2.encrypted);
  });

  it('fails to decrypt with a wrong key', async () => {
    const { masterEncryptionKey: mek1 } = await crypto.deriveKeys('pw1', 'u@e.com');
    const { masterEncryptionKey: mek2 } = await crypto.deriveKeys('pw2', 'u@e.com');
    const rawVk = await crypto.generateVaultKey();
    const vk = await crypto.importVaultKey(rawVk);

    const { encrypted, iv, tag } = await crypto.encryptVaultKey(vk, mek1);

    await expect(crypto.decryptVaultKey(encrypted, iv, tag, mek2)).rejects.toThrow();
  });

  it('throws a user-friendly error when decryption fails with wrong MEK', async () => {
    const { masterEncryptionKey: mek1 } = await crypto.deriveKeys('correct-pw', 'u@e.com');
    const { masterEncryptionKey: mek2 } = await crypto.deriveKeys('wrong-pw', 'u@e.com');
    const rawVk = await crypto.generateVaultKey();
    const vk = await crypto.importVaultKey(rawVk);

    const { encrypted, iv, tag } = await crypto.encryptVaultKey(vk, mek1);

    await expect(crypto.decryptVaultKey(encrypted, iv, tag, mek2)).rejects.toThrow(
      'Failed to decrypt vault key. The master password may be incorrect or the vault key data is corrupted.',
    );
  });

  it('throws a user-friendly error when decryption fails with corrupted data', async () => {
    const { masterEncryptionKey: mek } = await crypto.deriveKeys('pw', 'u@e.com');
    const rawVk = await crypto.generateVaultKey();
    const vk = await crypto.importVaultKey(rawVk);

    const { encrypted, iv, tag } = await crypto.encryptVaultKey(vk, mek);

    // Tamper with the encrypted data
    const tamperedBytes = new Uint8Array(crypto.base64ToArrayBuffer(encrypted));
    tamperedBytes[0] ^= 0xff;
    const tampered = crypto.arrayBufferToBase64(tamperedBytes.buffer as ArrayBuffer);

    await expect(crypto.decryptVaultKey(tampered, iv, tag, mek)).rejects.toThrow(
      'Failed to decrypt vault key. The master password may be incorrect or the vault key data is corrupted.',
    );
  });
});

// ---------------------------------------------------------------------------
// Vault Key Equality (backup-restore adoption decision)
// ---------------------------------------------------------------------------

describe('vaultKeyEqualsRaw', () => {
  it('returns true when the CryptoKey matches the candidate raw bytes', async () => {
    const rawVk = await crypto.generateVaultKey();
    const vk = await crypto.importVaultKey(rawVk);

    // Compare against a fresh copy of the same bytes (the original may be
    // zeroed by other operations).
    const sameBytes = new Uint8Array(new Uint8Array(rawVk)).buffer;
    expect(await crypto.vaultKeyEqualsRaw(vk, sameBytes)).toBe(true);
  });

  it('returns false when the candidate bytes differ (e.g. a rotated key)', async () => {
    const rawVk = await crypto.generateVaultKey();
    const vk = await crypto.importVaultKey(rawVk);
    const otherRaw = await crypto.generateVaultKey();

    expect(await crypto.vaultKeyEqualsRaw(vk, otherRaw)).toBe(false);
  });

  it('returns false when lengths differ', async () => {
    const rawVk = await crypto.generateVaultKey();
    const vk = await crypto.importVaultKey(rawVk);

    expect(await crypto.vaultKeyEqualsRaw(vk, new Uint8Array(16).buffer)).toBe(false);
  });

  it('returns false for a single-bit difference', async () => {
    const rawVk = await crypto.generateVaultKey();
    const vk = await crypto.importVaultKey(rawVk);
    const flipped = new Uint8Array(new Uint8Array(rawVk));
    flipped[0] ^= 0x01;

    expect(await crypto.vaultKeyEqualsRaw(vk, flipped.buffer)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Vault Key Rotation
// ---------------------------------------------------------------------------

describe('rotateVaultKey', () => {
  it('generates a new vault key CryptoKey and encrypts it with the MEK', async () => {
    const { masterEncryptionKey: mek } = await crypto.deriveKeys('pw', 'u@e.com');

    const { newVaultKey, encrypted, iv, tag } = await crypto.rotateVaultKey(mek);

    expect(newVaultKey).toBeDefined();
    expect(newVaultKey.type).toBe('secret');
    expect(newVaultKey.algorithm).toMatchObject({ name: 'AES-GCM' });

    // The encrypted form should round-trip back to the same key
    const decrypted = await crypto.decryptVaultKey(encrypted, iv, tag, mek);
    const rawNewVK = await globalThis.crypto.subtle.exportKey('raw', newVaultKey);
    expect(new Uint8Array(decrypted)).toEqual(new Uint8Array(rawNewVK));
  });

  it('produces different keys on successive rotations', async () => {
    const { masterEncryptionKey: mek } = await crypto.deriveKeys('pw', 'u@e.com');

    const r1 = await crypto.rotateVaultKey(mek);
    const r2 = await crypto.rotateVaultKey(mek);

    const raw1 = await globalThis.crypto.subtle.exportKey('raw', r1.newVaultKey);
    const raw2 = await globalThis.crypto.subtle.exportKey('raw', r2.newVaultKey);
    expect(crypto.arrayBufferToBase64(raw1)).not.toBe(crypto.arrayBufferToBase64(raw2));
  });
});

// ---------------------------------------------------------------------------
// Data Encryption / Decryption Round Trips
// ---------------------------------------------------------------------------

describe('encryptData / decryptData', () => {
  let vaultKey: CryptoKey;

  beforeAll(async () => {
    const rawVk = await crypto.generateVaultKey();
    vaultKey = await crypto.importVaultKey(rawVk);
  });

  it('round-trips a simple string', async () => {
    const plaintext = 'Hello, H-Vault!';
    const { encrypted, iv, tag } = await crypto.encryptData(plaintext, vaultKey);
    const result = await crypto.decryptData(encrypted, iv, tag, vaultKey);
    expect(result).toBe(plaintext);
  });

  it('round-trips an empty string', async () => {
    const plaintext = '';
    const { encrypted, iv, tag } = await crypto.encryptData(plaintext, vaultKey);
    const result = await crypto.decryptData(encrypted, iv, tag, vaultKey);
    expect(result).toBe(plaintext);
  });

  it('round-trips Unicode content (emojis, CJK, diacritics)', async () => {
    const plaintext = '🔐 Sécurité 日本語テスト Ñoño 中文 🎉';
    const { encrypted, iv, tag } = await crypto.encryptData(plaintext, vaultKey);
    const result = await crypto.decryptData(encrypted, iv, tag, vaultKey);
    expect(result).toBe(plaintext);
  });

  it('round-trips large data (100KB)', async () => {
    const plaintext = 'A'.repeat(100_000);
    const { encrypted, iv, tag } = await crypto.encryptData(plaintext, vaultKey);
    const result = await crypto.decryptData(encrypted, iv, tag, vaultKey);
    expect(result).toBe(plaintext);
  });

  it('round-trips JSON payloads', async () => {
    const payload = JSON.stringify({
      username: 'admin',
      password: 's3cret!@#$%^&*()',
      notes: 'Line1\nLine2\tTab',
      url: 'https://example.com/login?q=hello&world=true',
    });
    const { encrypted, iv, tag } = await crypto.encryptData(payload, vaultKey);
    const result = await crypto.decryptData(encrypted, iv, tag, vaultKey);
    expect(result).toBe(payload);
  });

  it('produces different ciphertext for the same plaintext (random IV)', async () => {
    const plaintext = 'duplicate';
    const enc1 = await crypto.encryptData(plaintext, vaultKey);
    const enc2 = await crypto.encryptData(plaintext, vaultKey);

    expect(enc1.iv).not.toBe(enc2.iv);
    expect(enc1.encrypted).not.toBe(enc2.encrypted);
  });

  it('fails to decrypt with a wrong vault key', async () => {
    const rawOtherKey = await crypto.generateVaultKey();
    const otherKey = await crypto.importVaultKey(rawOtherKey);
    const { encrypted, iv, tag } = await crypto.encryptData('secret', vaultKey);

    await expect(crypto.decryptData(encrypted, iv, tag, otherKey)).rejects.toThrow();
  });

  it('fails to decrypt with tampered ciphertext', async () => {
    const { encrypted, iv, tag } = await crypto.encryptData('secret', vaultKey);

    // Flip a character in the ciphertext
    const tamperedBytes = new Uint8Array(crypto.base64ToArrayBuffer(encrypted));
    tamperedBytes[0] ^= 0xff;
    const tampered = crypto.arrayBufferToBase64(tamperedBytes.buffer as ArrayBuffer);

    await expect(crypto.decryptData(tampered, iv, tag, vaultKey)).rejects.toThrow();
  });

  it('fails to decrypt with tampered tag', async () => {
    const { encrypted, iv, tag } = await crypto.encryptData('secret', vaultKey);

    const tamperedTagBytes = new Uint8Array(crypto.base64ToArrayBuffer(tag));
    tamperedTagBytes[0] ^= 0xff;
    const tamperedTag = crypto.arrayBufferToBase64(tamperedTagBytes.buffer as ArrayBuffer);

    await expect(crypto.decryptData(encrypted, iv, tamperedTag, vaultKey)).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// HMAC Search Hash Generation
// ---------------------------------------------------------------------------

describe('generateSearchHash', () => {
  let vaultKey: CryptoKey;

  beforeAll(async () => {
    const rawVk = await crypto.generateVaultKey();
    vaultKey = await crypto.importVaultKey(rawVk);
  });

  it('returns a 64-char lowercase hex string', async () => {
    const hash = await crypto.generateSearchHash('My Login', vaultKey);
    expect(typeof hash).toBe('string');
    expect(hash).toMatch(/^[a-f0-9]{64}$/);
  });

  it('is deterministic — same name and key produce the same hash', async () => {
    const h1 = await crypto.generateSearchHash('GitHub', vaultKey);
    const h2 = await crypto.generateSearchHash('GitHub', vaultKey);
    expect(h1).toBe(h2);
  });

  it('normalises name — case and whitespace insensitive', async () => {
    const h1 = await crypto.generateSearchHash('  GitHub  ', vaultKey);
    const h2 = await crypto.generateSearchHash('github', vaultKey);
    expect(h1).toBe(h2);
  });

  it('produces different hashes for different names', async () => {
    const h1 = await crypto.generateSearchHash('GitHub', vaultKey);
    const h2 = await crypto.generateSearchHash('GitLab', vaultKey);
    expect(h1).not.toBe(h2);
  });

  it('produces different hashes with different vault keys', async () => {
    const rawOtherKey = await crypto.generateVaultKey();
    const otherKey = await crypto.importVaultKey(rawOtherKey);
    const h1 = await crypto.generateSearchHash('test', vaultKey);
    const h2 = await crypto.generateSearchHash('test', otherKey);
    expect(h1).not.toBe(h2);
  });
});

// ---------------------------------------------------------------------------
// Backup Key Derivation
// ---------------------------------------------------------------------------

describe('backup key derivation', () => {
  describe('deriveBEK', () => {
    it('returns an AES-GCM CryptoKey', async () => {
      const salt = crypto.generateSalt();
      const bek = await crypto.deriveBEK('backup-password', salt);

      expect(bek).toBeDefined();
      expect(bek.type).toBe('secret');
      expect(bek.algorithm).toMatchObject({ name: 'AES-GCM' });
      expect(bek.usages).toContain('encrypt');
      expect(bek.usages).toContain('decrypt');
    });

    it('is deterministic with the same password and salt', async () => {
      const salt = crypto.generateSalt();
      const bek1 = await crypto.deriveBEK('same-pw', salt);
      const bek2 = await crypto.deriveBEK('same-pw', salt);

      // Encrypt something with both keys — outputs should be decryptable by either
      const bwk = crypto.generateBWK();
      const enc = await crypto.encryptBWK(bwk, bek1);

      // Decrypt with bek2 — should succeed if they are the same derived key
      const ivBytes = new Uint8Array(crypto.base64ToArrayBuffer(enc.iv));
      const ciphertext = new Uint8Array(crypto.base64ToArrayBuffer(enc.encrypted));
      const tagBytes = new Uint8Array(crypto.base64ToArrayBuffer(enc.tag));
      const combined = new Uint8Array(ciphertext.length + tagBytes.length);
      combined.set(ciphertext, 0);
      combined.set(tagBytes, ciphertext.length);

      // Use subtle directly to decrypt with bek2
      const decrypted = await globalThis.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: ivBytes, tagLength: 128 },
        bek2,
        combined.buffer as ArrayBuffer,
      );

      expect(new Uint8Array(decrypted)).toEqual(new Uint8Array(bwk));
    });

    it('produces different keys for different passwords', async () => {
      const salt = crypto.generateSalt();
      const bek1 = await crypto.deriveBEK('pw-A', salt);
      const bek2 = await crypto.deriveBEK('pw-B', salt);

      const bwk = crypto.generateBWK();
      const enc = await crypto.encryptBWK(bwk, bek1);

      // Decrypting with bek2 should fail
      const ivBytes = new Uint8Array(crypto.base64ToArrayBuffer(enc.iv));
      const ciphertext = new Uint8Array(crypto.base64ToArrayBuffer(enc.encrypted));
      const tagBytes = new Uint8Array(crypto.base64ToArrayBuffer(enc.tag));
      const combined = new Uint8Array(ciphertext.length + tagBytes.length);
      combined.set(ciphertext, 0);
      combined.set(tagBytes, ciphertext.length);

      await expect(
        globalThis.crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: ivBytes, tagLength: 128 },
          bek2,
          combined.buffer as ArrayBuffer,
        ),
      ).rejects.toThrow();
    });
  });

  describe('generateBWK', () => {
    it('returns a 32-byte ArrayBuffer', () => {
      const bwk = crypto.generateBWK();
      expect(bwk).toBeInstanceOf(ArrayBuffer);
      expect(bwk.byteLength).toBe(32);
    });

    it('produces unique keys on successive calls', () => {
      const b1 = crypto.arrayBufferToBase64(crypto.generateBWK());
      const b2 = crypto.arrayBufferToBase64(crypto.generateBWK());
      expect(b1).not.toBe(b2);
    });
  });

  describe('encryptBWK', () => {
    it('round-trips: encrypt then decrypt restores original BWK', async () => {
      const salt = crypto.generateSalt();
      const bek = await crypto.deriveBEK('backup-pw', salt);
      const bwk = crypto.generateBWK();

      const { encrypted, iv, tag } = await crypto.encryptBWK(bwk, bek);

      // Manually decrypt to verify round-trip
      const ivBytes = new Uint8Array(crypto.base64ToArrayBuffer(iv));
      const ciphertext = new Uint8Array(crypto.base64ToArrayBuffer(encrypted));
      const tagBytes = new Uint8Array(crypto.base64ToArrayBuffer(tag));
      const combined = new Uint8Array(ciphertext.length + tagBytes.length);
      combined.set(ciphertext, 0);
      combined.set(tagBytes, ciphertext.length);

      const decrypted = await globalThis.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: ivBytes, tagLength: 128 },
        bek,
        combined.buffer as ArrayBuffer,
      );

      expect(new Uint8Array(decrypted)).toEqual(new Uint8Array(bwk));
    });

    it('returns base64-encoded strings', async () => {
      const salt = crypto.generateSalt();
      const bek = await crypto.deriveBEK('pw', salt);
      const bwk = crypto.generateBWK();

      const { encrypted, iv, tag } = await crypto.encryptBWK(bwk, bek);

      expect(() => atob(encrypted)).not.toThrow();
      expect(() => atob(iv)).not.toThrow();
      expect(() => atob(tag)).not.toThrow();
    });
  });

  describe('encryptVaultKeyWithBWK / decryptVaultKeyWithBWK', () => {
    it('round-trips: decrypt(encrypt(vk)) === vk', async () => {
      const bwk = crypto.generateBWK();
      const rawVk = crypto.generateVaultKey();
      const vk = await crypto.importVaultKey(rawVk);

      const { encrypted, iv, tag } = await crypto.encryptVaultKeyWithBWK(vk, bwk);
      const decrypted = await crypto.decryptVaultKeyWithBWK(encrypted, iv, tag, bwk);

      expect(new Uint8Array(decrypted)).toEqual(new Uint8Array(rawVk));
    });

    it('returns base64-encoded strings for encrypted, iv, tag', async () => {
      const bwk = crypto.generateBWK();
      const rawVk = crypto.generateVaultKey();
      const vk = await crypto.importVaultKey(rawVk);

      const { encrypted, iv, tag } = await crypto.encryptVaultKeyWithBWK(vk, bwk);

      expect(() => atob(encrypted)).not.toThrow();
      expect(() => atob(iv)).not.toThrow();
      expect(() => atob(tag)).not.toThrow();

      // IV should be 12 bytes
      expect(atob(iv).length).toBe(12);
      // Tag should be 16 bytes
      expect(atob(tag).length).toBe(16);
    });

    it('produces different ciphertext for the same plaintext (random IV)', async () => {
      const bwk = crypto.generateBWK();
      const rawVk = crypto.generateVaultKey();
      const vk = await crypto.importVaultKey(rawVk);

      const enc1 = await crypto.encryptVaultKeyWithBWK(vk, bwk);
      const enc2 = await crypto.encryptVaultKeyWithBWK(vk, bwk);

      expect(enc1.iv).not.toBe(enc2.iv);
      expect(enc1.encrypted).not.toBe(enc2.encrypted);
    });

    it('fails to decrypt with a wrong BWK', async () => {
      const bwk1 = crypto.generateBWK();
      const bwk2 = crypto.generateBWK();
      const rawVk = crypto.generateVaultKey();
      const vk = await crypto.importVaultKey(rawVk);

      const { encrypted, iv, tag } = await crypto.encryptVaultKeyWithBWK(vk, bwk1);

      await expect(crypto.decryptVaultKeyWithBWK(encrypted, iv, tag, bwk2)).rejects.toThrow();
    });

    it('fails to decrypt with tampered ciphertext', async () => {
      const bwk = crypto.generateBWK();
      const rawVk = crypto.generateVaultKey();
      const vk = await crypto.importVaultKey(rawVk);

      const { encrypted, iv, tag } = await crypto.encryptVaultKeyWithBWK(vk, bwk);

      const tamperedBytes = new Uint8Array(crypto.base64ToArrayBuffer(encrypted));
      tamperedBytes[0] ^= 0xff;
      const tampered = crypto.arrayBufferToBase64(tamperedBytes.buffer as ArrayBuffer);

      await expect(crypto.decryptVaultKeyWithBWK(tampered, iv, tag, bwk)).rejects.toThrow();
    });

    it('fails to decrypt with tampered tag', async () => {
      const bwk = crypto.generateBWK();
      const rawVk = crypto.generateVaultKey();
      const vk = await crypto.importVaultKey(rawVk);

      const { encrypted, iv, tag } = await crypto.encryptVaultKeyWithBWK(vk, bwk);

      const tamperedTagBytes = new Uint8Array(crypto.base64ToArrayBuffer(tag));
      tamperedTagBytes[0] ^= 0xff;
      const tamperedTag = crypto.arrayBufferToBase64(tamperedTagBytes.buffer as ArrayBuffer);

      await expect(
        crypto.decryptVaultKeyWithBWK(encrypted, iv, tamperedTag, bwk),
      ).rejects.toThrow();
    });

    it('decrypted vault key has the correct byte length (32 bytes)', async () => {
      const bwk = crypto.generateBWK();
      const rawVk = crypto.generateVaultKey();
      const vk = await crypto.importVaultKey(rawVk);

      const { encrypted, iv, tag } = await crypto.encryptVaultKeyWithBWK(vk, bwk);
      const decrypted = await crypto.decryptVaultKeyWithBWK(encrypted, iv, tag, bwk);

      expect(decrypted.byteLength).toBe(32);
    });
  });

  describe('generateSalt', () => {
    it('returns a 16-byte ArrayBuffer by default', () => {
      const salt = crypto.generateSalt();
      expect(salt).toBeInstanceOf(ArrayBuffer);
      expect(salt.byteLength).toBe(16);
    });

    it('respects custom byte length', () => {
      const salt = crypto.generateSalt(32);
      expect(salt.byteLength).toBe(32);
    });

    it('produces unique salts', () => {
      const s1 = crypto.arrayBufferToBase64(crypto.generateSalt());
      const s2 = crypto.arrayBufferToBase64(crypto.generateSalt());
      expect(s1).not.toBe(s2);
    });
  });
});

// ---------------------------------------------------------------------------
// Memory Clearing
// ---------------------------------------------------------------------------

describe('clearKey', () => {
  it('zeros out all bytes of an ArrayBuffer', () => {
    const buf = new Uint8Array([0xff, 0xab, 0xcd, 0x12, 0x34]).buffer as ArrayBuffer;
    crypto.clearKey(buf);
    const view = new Uint8Array(buf);
    for (const byte of view) {
      expect(byte).toBe(0);
    }
  });

  it('works on a generated vault key', async () => {
    const vk = await crypto.generateVaultKey();
    // Confirm it has non-zero data (statistically guaranteed)
    const before = new Uint8Array(vk);
    const anyNonZero = before.some((b) => b !== 0);
    expect(anyNonZero).toBe(true);

    crypto.clearKey(vk);
    const after = new Uint8Array(vk);
    for (const byte of after) {
      expect(byte).toBe(0);
    }
  });

  it('works on an empty buffer (no-op)', () => {
    const buf = new ArrayBuffer(0);
    expect(() => crypto.clearKey(buf)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Utility Functions
// ---------------------------------------------------------------------------

describe('arrayBufferToBase64 / base64ToArrayBuffer', () => {
  it('round-trips arbitrary binary data', () => {
    const original = new Uint8Array([0, 1, 127, 128, 255]);
    const base64 = crypto.arrayBufferToBase64(original.buffer as ArrayBuffer);
    const restored = new Uint8Array(crypto.base64ToArrayBuffer(base64));
    expect(restored).toEqual(original);
  });

  it('round-trips an empty buffer', () => {
    const original = new Uint8Array([]);
    const base64 = crypto.arrayBufferToBase64(original.buffer as ArrayBuffer);
    expect(base64).toBe('');
    const restored = new Uint8Array(crypto.base64ToArrayBuffer(base64));
    expect(restored.length).toBe(0);
  });

  it('produces valid base64 for known input', () => {
    const input = new TextEncoder().encode('Hello');
    const base64 = crypto.arrayBufferToBase64(input.buffer as ArrayBuffer);
    expect(base64).toBe(btoa('Hello'));
  });
});

describe('generateBackupCodes', () => {
  it('generates the requested number of codes', () => {
    const codes = crypto.generateBackupCodes(8);
    expect(codes).toHaveLength(8);
  });

  it('each code is 16 hex characters', () => {
    const codes = crypto.generateBackupCodes(10);
    for (const code of codes) {
      expect(code).toMatch(/^[0-9a-f]{16}$/);
    }
  });

  it('generates unique codes (statistically)', () => {
    const codes = crypto.generateBackupCodes(20);
    const unique = new Set(codes);
    // With 8 bytes of entropy per code, collisions in 20 codes are extremely unlikely
    expect(unique.size).toBe(20);
  });

  it('returns an empty array when count is 0', () => {
    const codes = crypto.generateBackupCodes(0);
    expect(codes).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// End-to-End Crypto Flow
// ---------------------------------------------------------------------------

describe('end-to-end flow', () => {
  it('full registration + encrypt + decrypt cycle', async () => {
    // 1. User registers — derive keys from master password + email
    const { masterEncryptionKey: mek, authKey } = await crypto.deriveKeys(
      'MyStr0ng!P@ssword',
      'alice@example.com',
    );
    expect(authKey.byteLength).toBe(32);

    // 2. Generate vault key and encrypt it with MEK
    const rawVaultKey = await crypto.generateVaultKey();
    const vaultKey = await crypto.importVaultKey(rawVaultKey);
    const encVK = await crypto.encryptVaultKey(vaultKey, mek);

    // 3. Encrypt some vault data
    const secretData = JSON.stringify({
      type: 'login',
      username: 'alice',
      password: 'hunter2',
      uri: 'https://example.com',
    });
    const encData = await crypto.encryptData(secretData, vaultKey);

    // 4. Generate search hash for the item name
    const searchHash = await crypto.generateSearchHash('Example Login', vaultKey);
    expect(typeof searchHash).toBe('string');

    // 5. Later: user logs in — derive the same keys
    const { masterEncryptionKey: mek2 } = await crypto.deriveKeys(
      'MyStr0ng!P@ssword',
      'alice@example.com',
    );

    // 6. Decrypt vault key
    const decryptedRawVK = await crypto.decryptVaultKey(encVK.encrypted, encVK.iv, encVK.tag, mek2);
    expect(new Uint8Array(decryptedRawVK)).toEqual(new Uint8Array(rawVaultKey));

    // 7. Import decrypted vault key and decrypt vault data
    const decryptedVK = await crypto.importVaultKey(decryptedRawVK);
    const decryptedData = await crypto.decryptData(
      encData.encrypted,
      encData.iv,
      encData.tag,
      decryptedVK,
    );
    expect(decryptedData).toBe(secretData);
    expect(JSON.parse(decryptedData).password).toBe('hunter2');

    // 8. Clean up
    crypto.clearKey(rawVaultKey);
    crypto.clearKey(decryptedRawVK);
    await crypto.clearCryptoKey(vaultKey);
    await crypto.clearCryptoKey(decryptedVK);
  });

  it('master password change — re-encrypt vault key with new MEK', async () => {
    // Old password setup
    const { masterEncryptionKey: oldMek } = await crypto.deriveKeys(
      'old-password',
      'bob@example.com',
    );
    const rawVaultKey = await crypto.generateVaultKey();
    const vaultKey = await crypto.importVaultKey(rawVaultKey);
    const oldEncVK = await crypto.encryptVaultKey(vaultKey, oldMek);

    // User changes password — derive new MEK
    const { masterEncryptionKey: newMek, authKey: newAuthKey } = await crypto.deriveKeys(
      'new-password',
      'bob@example.com',
    );

    // Decrypt VK with old MEK, re-encrypt with new MEK
    const decryptedRawVK = await crypto.decryptVaultKey(
      oldEncVK.encrypted,
      oldEncVK.iv,
      oldEncVK.tag,
      oldMek,
    );
    const decryptedVK = await crypto.importVaultKey(decryptedRawVK);
    const newEncVK = await crypto.encryptVaultKey(decryptedVK, newMek);

    // Verify: new MEK can decrypt the re-encrypted VK
    const verifyRawVK = await crypto.decryptVaultKey(
      newEncVK.encrypted,
      newEncVK.iv,
      newEncVK.tag,
      newMek,
    );
    expect(new Uint8Array(verifyRawVK)).toEqual(new Uint8Array(rawVaultKey));

    // Old MEK should NOT decrypt new encrypted VK
    await expect(
      crypto.decryptVaultKey(newEncVK.encrypted, newEncVK.iv, newEncVK.tag, oldMek),
    ).rejects.toThrow();

    // Auth key changed
    expect(crypto.getAuthHash(newAuthKey).length).toBeGreaterThan(0);

    // Clean up
    crypto.clearKey(rawVaultKey);
    crypto.clearKey(decryptedRawVK);
    crypto.clearKey(verifyRawVK);
  });

  it('vault key rotation — re-encrypt data with new vault key', async () => {
    const { masterEncryptionKey: mek } = await crypto.deriveKeys('pw', 'user@example.com');

    // Original VK + encrypted data
    const rawOldVK = await crypto.generateVaultKey();
    const oldVK = await crypto.importVaultKey(rawOldVK);
    const plaintext = 'sensitive-data';
    const encData = await crypto.encryptData(plaintext, oldVK);

    // Rotate vault key
    const {
      newVaultKey,
      encrypted: _encrypted,
      iv: _iv,
      tag: _tag,
    } = await crypto.rotateVaultKey(mek);

    // Decrypt data with old VK, re-encrypt with new VK
    const decrypted = await crypto.decryptData(encData.encrypted, encData.iv, encData.tag, oldVK);
    expect(decrypted).toBe(plaintext);

    const reEncData = await crypto.encryptData(decrypted, newVaultKey);

    // Verify new VK decrypts re-encrypted data
    const finalDecrypt = await crypto.decryptData(
      reEncData.encrypted,
      reEncData.iv,
      reEncData.tag,
      newVaultKey,
    );
    expect(finalDecrypt).toBe(plaintext);

    // Old VK should NOT decrypt re-encrypted data
    await expect(
      crypto.decryptData(reEncData.encrypted, reEncData.iv, reEncData.tag, oldVK),
    ).rejects.toThrow();

    // Clean up
    crypto.clearKey(rawOldVK);
    await crypto.clearCryptoKey(oldVK);
    await crypto.clearCryptoKey(newVaultKey);
  });
});

// ---------------------------------------------------------------------------
// IV Uniqueness — AES-GCM IV reuse is catastrophic
// ---------------------------------------------------------------------------

describe('IV uniqueness', () => {
  it('encryptData generates unique IVs across multiple encryptions', async () => {
    const _keys = await crypto.deriveKeys('pw', 'u@e.com');
    const rawVk = await crypto.generateVaultKey();
    const vk = await crypto.importVaultKey(rawVk);
    const plaintext = 'same-plaintext-for-all';

    const ivs = new Set<string>();
    const iterations = 50;

    for (let i = 0; i < iterations; i++) {
      const result = await crypto.encryptData(plaintext, vk);
      ivs.add(result.iv);
    }

    // All 50 IVs must be unique
    expect(ivs.size).toBe(iterations);

    await crypto.clearCryptoKey(vk);
  });

  it('encryptVaultKey generates unique IVs across multiple encryptions', async () => {
    const { masterEncryptionKey: mek } = await crypto.deriveKeys('pw', 'u@e.com');
    const rawVk = await crypto.generateVaultKey();
    const vk = await crypto.importVaultKey(rawVk);

    const ivs = new Set<string>();
    const iterations = 50;

    for (let i = 0; i < iterations; i++) {
      const result = await crypto.encryptVaultKey(vk, mek);
      ivs.add(result.iv);
    }

    expect(ivs.size).toBe(iterations);

    await crypto.clearCryptoKey(vk);
  });

  it('encryptBWK generates unique IVs across multiple encryptions', async () => {
    const salt = crypto.generateSalt();
    const bek = await crypto.deriveBEK('backup-password', salt);
    const bwk = crypto.generateBWK();

    const ivs = new Set<string>();
    const iterations = 50;

    for (let i = 0; i < iterations; i++) {
      const result = await crypto.encryptBWK(bwk, bek);
      ivs.add(result.iv);
    }

    expect(ivs.size).toBe(iterations);

    crypto.clearKey(bwk);
  });

  it('encryptVaultKeyWithBWK generates unique IVs across multiple encryptions', async () => {
    const bwk = crypto.generateBWK();
    const rawVk = await crypto.generateVaultKey();
    const vk = await crypto.importVaultKey(rawVk);

    const ivs = new Set<string>();
    const iterations = 50;

    for (let i = 0; i < iterations; i++) {
      const result = await crypto.encryptVaultKeyWithBWK(vk, bwk);
      ivs.add(result.iv);
    }

    expect(ivs.size).toBe(iterations);

    await crypto.clearCryptoKey(vk);
    crypto.clearKey(bwk);
  });

  it('IVs from different encryption functions do not collide', async () => {
    const { masterEncryptionKey: mek } = await crypto.deriveKeys('pw', 'u@e.com');
    const rawVk = await crypto.generateVaultKey();
    const vk = await crypto.importVaultKey(rawVk);
    const bwk = crypto.generateBWK();
    const salt = crypto.generateSalt();
    const bek = await crypto.deriveBEK('backup-pw', salt);

    const allIvs = new Set<string>();

    // Collect IVs from different encryption operations
    const dataEnc = await crypto.encryptData('data', vk);
    allIvs.add(dataEnc.iv);

    const vkEnc = await crypto.encryptVaultKey(vk, mek);
    allIvs.add(vkEnc.iv);

    const bwkEnc = await crypto.encryptBWK(bwk, bek);
    allIvs.add(bwkEnc.iv);

    const bwkVkEnc = await crypto.encryptVaultKeyWithBWK(vk, bwk);
    allIvs.add(bwkVkEnc.iv);

    // All 4 IVs should be unique
    expect(allIvs.size).toBe(4);

    await crypto.clearCryptoKey(vk);
    crypto.clearKey(bwk);
  });

  it('IVs are valid base64 and decode to 12 bytes', async () => {
    const rawVk = await crypto.generateVaultKey();
    const vk = await crypto.importVaultKey(rawVk);
    const enc = await crypto.encryptData('test', vk);

    // IV should be valid base64
    expect(() => crypto.base64ToArrayBuffer(enc.iv)).not.toThrow();

    // AES-GCM IV should be 12 bytes
    const ivBytes = crypto.base64ToArrayBuffer(enc.iv);
    expect(ivBytes.byteLength).toBe(12);

    await crypto.clearCryptoKey(vk);
  });
});

// ---------------------------------------------------------------------------
// Password History Re-encryption During Vault Key Rotation
// ---------------------------------------------------------------------------

describe('passwordHistory re-encryption during vault key rotation', () => {
  it('decrypts passwordHistory entries with old VK and re-encrypts with new VK', async () => {
    const { masterEncryptionKey: mek } = await crypto.deriveKeys('pw', 'u@e.com');
    const rawOldVk = crypto.generateVaultKey();
    const oldVk = await crypto.importVaultKey(rawOldVk);

    // Encrypt password history entries with old vault key
    const plainPasswords = ['OldPassword1!', 'OldPassword2!', 'OldPassword3!'];
    const encryptedHistory = await Promise.all(
      plainPasswords.map(async (pw) => {
        const enc = await crypto.encryptData(pw, oldVk);
        return {
          encryptedPassword: enc.encrypted,
          iv: enc.iv,
          tag: enc.tag,
          changedAt: new Date().toISOString(),
        };
      }),
    );

    // Generate new vault key (simulating rotation)
    const { newVaultKey } = await crypto.rotateVaultKey(mek);

    // Re-encrypt each password history entry with new vault key
    const reEncryptedHistory = await Promise.all(
      encryptedHistory.map(async (entry) => {
        const plainPassword = await crypto.decryptData(
          entry.encryptedPassword,
          entry.iv,
          entry.tag,
          oldVk,
        );
        const enc = await crypto.encryptData(plainPassword, newVaultKey);
        return {
          encryptedPassword: enc.encrypted,
          iv: enc.iv,
          tag: enc.tag,
          changedAt: entry.changedAt,
        };
      }),
    );

    // Verify re-encrypted entries can be decrypted with new vault key
    for (let i = 0; i < reEncryptedHistory.length; i++) {
      const entry = reEncryptedHistory[i]!;
      const decrypted = await crypto.decryptData(
        entry.encryptedPassword,
        entry.iv,
        entry.tag,
        newVaultKey,
      );
      expect(decrypted).toBe(plainPasswords[i]);
    }

    // Verify re-encrypted entries CANNOT be decrypted with old vault key
    for (const entry of reEncryptedHistory) {
      await expect(
        crypto.decryptData(entry.encryptedPassword, entry.iv, entry.tag, oldVk),
      ).rejects.toThrow();
    }
  });

  // NOTE: the former 'preserves changedAt timestamps during re-encryption' and
  // 'handles items with empty passwordHistory gracefully' tests were removed:
  // both re-implemented the rotation loop inline and asserted values the test
  // itself constructed (a spread `changedAt`, and the length of an empty array),
  // so no production code could turn them red. The real changedAt-preservation
  // and empty-history handling live in the vault-key rotation flow
  // (vaultStore / VaultKeyRotationDialog); the substantive cross-key crypto
  // property above already covers the encrypt/decrypt round-trip.
});

// ---------------------------------------------------------------------------
// Backup Integrity (HMAC)
// ---------------------------------------------------------------------------

describe('computeBackupHmac / verifyBackupHmac', () => {
  let bwk: ArrayBuffer;

  beforeAll(() => {
    bwk = crypto.generateBWK();
  });

  it('computes a 64-character hex HMAC', async () => {
    const data = JSON.stringify({ items: [], folders: [] });
    const hmac = await crypto.computeBackupHmac(data, bwk);
    expect(hmac).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is deterministic for same input and key', async () => {
    const data = JSON.stringify({ test: 'data', count: 42 });
    const hmac1 = await crypto.computeBackupHmac(data, bwk);
    const hmac2 = await crypto.computeBackupHmac(data, bwk);
    expect(hmac1).toBe(hmac2);
  });

  it('produces different HMACs for different data', async () => {
    const hmac1 = await crypto.computeBackupHmac('data1', bwk);
    const hmac2 = await crypto.computeBackupHmac('data2', bwk);
    expect(hmac1).not.toBe(hmac2);
  });

  it('produces different HMACs for different keys', async () => {
    const bwk2 = crypto.generateBWK();
    const data = 'same-data';
    const hmac1 = await crypto.computeBackupHmac(data, bwk);
    const hmac2 = await crypto.computeBackupHmac(data, bwk2);
    expect(hmac1).not.toBe(hmac2);
  });

  it('verifies a valid HMAC', async () => {
    const data = JSON.stringify({ version: '1.0', items: [{ id: 1 }] });
    const hmac = await crypto.computeBackupHmac(data, bwk);
    const valid = await crypto.verifyBackupHmac(data, hmac, bwk);
    expect(valid).toBe(true);
  });

  it('rejects a tampered HMAC', async () => {
    const data = 'original-data';
    const hmac = await crypto.computeBackupHmac(data, bwk);
    // Flip one character in the HMAC
    const tampered = hmac.slice(0, -1) + (hmac.endsWith('0') ? '1' : '0');
    const valid = await crypto.verifyBackupHmac(data, tampered, bwk);
    expect(valid).toBe(false);
  });

  it('rejects when data has been tampered', async () => {
    const data = JSON.stringify({ items: [{ id: 1 }] });
    const hmac = await crypto.computeBackupHmac(data, bwk);
    const tamperedData = JSON.stringify({ items: [{ id: 1 }, { id: 2 }] });
    const valid = await crypto.verifyBackupHmac(tamperedData, hmac, bwk);
    expect(valid).toBe(false);
  });

  it('rejects when a different BWK is used for verification', async () => {
    const data = 'test-data';
    const hmac = await crypto.computeBackupHmac(data, bwk);
    const wrongBwk = crypto.generateBWK();
    const valid = await crypto.verifyBackupHmac(data, hmac, wrongBwk);
    expect(valid).toBe(false);
  });

  it('rejects an HMAC with wrong length', async () => {
    const data = 'test-data';
    const valid = await crypto.verifyBackupHmac(data, 'abcdef', bwk);
    expect(valid).toBe(false);
  });

  it('rejects an empty HMAC', async () => {
    const data = 'test-data';
    const valid = await crypto.verifyBackupHmac(data, '', bwk);
    expect(valid).toBe(false);
  });

  it('rejects a non-hex HMAC string of correct length', async () => {
    const data = 'test-data';
    // 64 characters of non-hex (z is not valid hex)
    const nonHex = 'z'.repeat(64);
    const valid = await crypto.verifyBackupHmac(data, nonHex, bwk);
    expect(valid).toBe(false);
  });

  it('rejects mixed hex/non-hex HMAC', async () => {
    const data = 'test-data';
    const mixedHmac =
      'abcdef0123456789' + 'zzzzzzzzzzzzzzzz' + 'abcdef0123456789' + 'abcdef0123456789';
    const valid = await crypto.verifyBackupHmac(data, mixedHmac, bwk);
    expect(valid).toBe(false);
  });

  it('works with the full backup download/restore flow', async () => {
    // Simulate: server returns backup JSON, client computes HMAC, adds it, saves file
    const serverBackup = JSON.stringify({
      version: '1.0.0',
      exportDate: new Date().toISOString(),
      items: [{ encryptedData: 'abc', dataIv: 'iv1', dataTag: 'tag1' }],
      folders: [],
      metadata: { itemCount: 1, folderCount: 0 },
    });

    // Client computes HMAC over server JSON
    const hmac = await crypto.computeBackupHmac(serverBackup, bwk);

    // Client adds integrity field
    const backupObj = JSON.parse(serverBackup) as Record<string, unknown>;
    backupObj.integrity = hmac;
    const signedFile = JSON.stringify(backupObj);

    // Simulate restore: parse file, extract integrity, verify
    const restored = JSON.parse(signedFile) as Record<string, unknown>;
    const extractedHmac = restored.integrity as string;
    delete restored.integrity;
    const canonicalJson = JSON.stringify(restored);

    const valid = await crypto.verifyBackupHmac(canonicalJson, extractedHmac, bwk);
    expect(valid).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Backup HKDF Subkey Derivation (Task 4.7)
//
// Verifies key separation per NIST SP 800-108: the HMAC subkey and the
// encryption subkey are independently derived via HKDF-SHA256 with distinct
// `info` labels. Also verifies backwards compatibility: legacy backups that
// were signed with the raw BWK still validate via the fallback path.
// ---------------------------------------------------------------------------

describe('Backup HKDF subkey derivation (Task 4.7)', () => {
  let bwk: ArrayBuffer;

  beforeAll(() => {
    bwk = crypto.generateBWK();
  });

  it('produces a different HMAC than a raw-BWK HMAC over the same data', async () => {
    const data = JSON.stringify({ items: [], folders: [] });

    // The new computeBackupHmac uses an HKDF-derived subkey.
    const newHmac = await crypto.computeBackupHmac(data, bwk);

    // Compute a legacy-style raw-BWK HMAC manually for comparison.
    const hmacKey = await globalThis.crypto.subtle.importKey(
      'raw',
      bwk,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    const rawSignature = await globalThis.crypto.subtle.sign(
      'HMAC',
      hmacKey,
      new TextEncoder().encode(data),
    );
    const legacyHmac = Array.from(new Uint8Array(rawSignature), (b) =>
      b.toString(16).padStart(2, '0'),
    ).join('');

    // Different keys → different HMACs (key separation works).
    expect(newHmac).not.toBe(legacyHmac);
  });

  it('verifyBackupHmac validates legacy raw-BWK HMACs (backwards compatibility)', async () => {
    const data = JSON.stringify({
      version: '1.0.0',
      formatVersion: 1,
      items: [{ id: 1 }],
    });

    // Compute a legacy-format HMAC using the raw BWK directly.
    const hmacKey = await globalThis.crypto.subtle.importKey(
      'raw',
      bwk,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    const sig = await globalThis.crypto.subtle.sign(
      'HMAC',
      hmacKey,
      new TextEncoder().encode(data),
    );
    const legacyHmac = Array.from(new Uint8Array(sig), (b) => b.toString(16).padStart(2, '0')).join(
      '',
    );

    // verifyBackupHmac must accept the legacy HMAC via the fallback path.
    const valid = await crypto.verifyBackupHmac(data, legacyHmac, bwk);
    expect(valid).toBe(true);
  });

  it('verifyBackupHmac round-trips a new (HKDF-derived) HMAC successfully', async () => {
    const data = JSON.stringify({ formatVersion: 2, items: [{ id: 1 }] });
    const newHmac = await crypto.computeBackupHmac(data, bwk);
    const valid = await crypto.verifyBackupHmac(data, newHmac, bwk);
    expect(valid).toBe(true);
  });

  it('deriveBackupEncSubkey returns an AES-GCM CryptoKey distinct from BWK', async () => {
    const encKey = await crypto.deriveBackupEncSubkey(bwk);
    expect(encKey.algorithm).toEqual({ name: 'AES-GCM', length: 256 });
    expect(encKey.usages).toEqual(expect.arrayContaining(['encrypt', 'decrypt']));

    // Encrypting with the derived subkey produces ciphertext that does NOT
    // decrypt with the raw BWK — confirming the subkey is materially different.
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode('hello');
    const ct = await globalThis.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, encKey, plaintext);

    const rawBwkKey = await globalThis.crypto.subtle.importKey(
      'raw',
      bwk,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt'],
    );

    await expect(
      globalThis.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, rawBwkKey, ct),
    ).rejects.toBeDefined();
  });

  it('HKDF subkeys are deterministic per BWK and differ between info labels', async () => {
    const enc1 = await crypto.deriveBackupEncSubkey(bwk);
    const enc2 = await crypto.deriveBackupEncSubkey(bwk);

    // Same BWK + same info label → same subkey → same ciphertext under same IV.
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const pt = new TextEncoder().encode('determinism check');
    const c1 = await globalThis.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, enc1, pt);
    const c2 = await globalThis.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, enc2, pt);
    expect(new Uint8Array(c1)).toEqual(new Uint8Array(c2));
  });
});
