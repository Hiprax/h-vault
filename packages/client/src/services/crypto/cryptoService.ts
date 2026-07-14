/**
 * CryptoService - Zero-knowledge encryption service using exclusively the Web Crypto API.
 *
 * This is the most critical module in the H-Vault client. All cryptographic
 * operations rely on SubtleCrypto (window.crypto.subtle) with no third-party
 * crypto libraries. The design follows a zero-knowledge architecture: the server
 * never receives or can derive the master password, the Master Encryption Key,
 * or the plaintext vault key.
 *
 * Key hierarchy:
 *   Master Password + Email (salt)
 *     -> PBKDF2 (600k iterations, SHA-256, 512-bit output)
 *       -> first 256 bits = Master Encryption Key (MEK) - AES-GCM
 *       -> last  256 bits -> PBKDF2 (1 iteration) -> Authentication Key (sent to server)
 *
 *   Vault Key (random 256-bit) encrypted with MEK (AES-256-GCM)
 *   Vault data encrypted with Vault Key (AES-256-GCM)
 */

const PBKDF2_ITERATIONS = 600_000;
const AUTH_KEY_ITERATIONS = 1;
const KEY_LENGTH_BITS = 512;
const AES_KEY_BITS = 256;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const VAULT_KEY_BYTES = 32;
const BACKUP_CODE_BYTES = 8;

export class CryptoService {
  private readonly subtle: SubtleCrypto;

  constructor() {
    if (typeof globalThis.crypto.subtle === 'undefined') {
      throw new Error(
        'Web Crypto API (SubtleCrypto) is not available. A secure context (HTTPS or localhost) is required.',
      );
    }
    this.subtle = globalThis.crypto.subtle;
  }

  // ---------------------------------------------------------------------------
  // Key Derivation
  // ---------------------------------------------------------------------------

  /**
   * Derive the Master Encryption Key and Authentication Key from the master
   * password and the user's email address.
   *
   * 1. Import `masterPassword` as a raw PBKDF2 key.
   * 2. Derive 512 bits (64 bytes) with PBKDF2-SHA256, email as salt, 600k iterations.
   * 3. Split the output:
   *    - First 256 bits  -> Master Encryption Key (MEK), imported as AES-GCM CryptoKey
   *    - Last  256 bits  -> raw auth material
   * 4. Hash the raw auth material through PBKDF2 (1 iteration, email as salt)
   *    to produce the Authentication Key (sent to the server in place of the password).
   */
  async deriveKeys(
    masterPassword: string,
    email: string,
  ): Promise<{ masterEncryptionKey: CryptoKey; authKey: ArrayBuffer }> {
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(masterPassword);
    const salt = encoder.encode(email.trim().toLowerCase());

    // Import password as PBKDF2 base key
    const baseKey = await this.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, [
      'deriveBits',
    ]);

    // Derive 512 bits
    const derivedBits = await this.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt,
        iterations: PBKDF2_ITERATIONS,
        hash: 'SHA-256',
      },
      baseKey,
      KEY_LENGTH_BITS,
    );

    // Split: first 32 bytes = MEK material, last 32 bytes = auth material
    const mekBytes = derivedBits.slice(0, 32);
    const authMaterial = derivedBits.slice(32, 64);

    try {
      // Import MEK as AES-GCM CryptoKey (extractable so we can zero key material on lock/logout).
      // SECURITY TRADE-OFF: extractable keys allow `exportKey()` which means an XSS attacker
      // could export raw key material. This is a known, accepted trade-off: the benefit of
      // being able to zero key bytes in memory on lock/logout (via clearCryptoKey) outweighs
      // the marginal additional risk, because an XSS attacker who can call `exportKey()` could
      // also call `encrypt()`/`decrypt()` directly on the CryptoKey handle regardless.
      const masterEncryptionKey = await this.subtle.importKey(
        'raw',
        mekBytes,
        { name: 'AES-GCM', length: AES_KEY_BITS },
        true,
        ['encrypt', 'decrypt'],
      );

      // Zero mekBytes immediately after import — the CryptoKey now holds the material
      this.clearKey(mekBytes);

      // Further hash the auth material with PBKDF2 (1 iteration) to produce the auth key
      const authBaseKey = await this.subtle.importKey('raw', authMaterial, 'PBKDF2', false, [
        'deriveBits',
      ]);

      // Zero authMaterial immediately after import
      this.clearKey(authMaterial);

      const authKey = await this.subtle.deriveBits(
        {
          name: 'PBKDF2',
          salt,
          iterations: AUTH_KEY_ITERATIONS,
          hash: 'SHA-256',
        },
        authBaseKey,
        AES_KEY_BITS,
      );

      return { masterEncryptionKey, authKey };
    } finally {
      // Ensure all intermediate buffers are zeroed even on errors
      this.clearKey(passwordBytes.buffer);
      this.clearKey(derivedBits);
      this.clearKey(mekBytes);
      this.clearKey(authMaterial);
    }
  }

  /**
   * Convert the authentication key ArrayBuffer to a base64 string suitable for
   * transmission to the server.
   */
  getAuthHash(authKey: ArrayBuffer): string {
    return this.arrayBufferToBase64(authKey);
  }

  // ---------------------------------------------------------------------------
  // Vault Key Management
  // ---------------------------------------------------------------------------

  /**
   * Generate a random 256-bit (32-byte) vault key.
   */
  generateVaultKey(): ArrayBuffer {
    const key = new Uint8Array(VAULT_KEY_BYTES);
    globalThis.crypto.getRandomValues(key);
    return key.buffer;
  }

  /**
   * Import raw vault key bytes as an AES-GCM CryptoKey.
   *
   * The resulting CryptoKey is extractable so that we can export it for
   * encryption (e.g. when encrypting the vault key with MEK or BWK) and
   * for best-effort zeroing via `clearCryptoKey`.
   *
   * SECURITY TRADE-OFF: Same as MEK — extractable keys mean XSS can call
   * `exportKey()` to obtain raw key material. Accepted because XSS could
   * already call `encrypt()`/`decrypt()` on the handle directly.
   */
  async importVaultKey(rawKey: ArrayBuffer): Promise<CryptoKey> {
    return this.subtle.importKey('raw', rawKey, { name: 'AES-GCM', length: AES_KEY_BITS }, true, [
      'encrypt',
      'decrypt',
    ]);
  }

  /**
   * Encrypt the vault key with the Master Encryption Key using AES-256-GCM.
   *
   * WebCrypto's AES-GCM appends the 16-byte authentication tag to the
   * ciphertext. We separate the tag for storage so that the server can
   * persist the three components independently.
   *
   * Accepts a CryptoKey vault key — exports its raw bytes internally for
   * encryption, then zeroes the exported buffer.
   */
  async encryptVaultKey(
    vaultKey: CryptoKey,
    mek: CryptoKey,
  ): Promise<{ encrypted: string; iv: string; tag: string }> {
    let rawBytes: ArrayBuffer | undefined;
    try {
      rawBytes = await this.subtle.exportKey('raw', vaultKey);
      const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_BYTES));

      const ciphertextWithTag = await this.subtle.encrypt(
        { name: 'AES-GCM', iv, tagLength: TAG_BYTES * 8 },
        mek,
        rawBytes,
      );

      const fullBytes = new Uint8Array(ciphertextWithTag);
      const ciphertext = fullBytes.slice(0, fullBytes.length - TAG_BYTES);
      const tag = fullBytes.slice(fullBytes.length - TAG_BYTES);

      return {
        encrypted: this.arrayBufferToBase64(ciphertext.buffer),
        iv: this.arrayBufferToBase64(iv.buffer),
        tag: this.arrayBufferToBase64(tag.buffer),
      };
    } catch {
      throw new Error(
        'Failed to encrypt vault key. The encryption key may be invalid or the vault key data is corrupted.',
      );
    } finally {
      if (rawBytes) this.clearKey(rawBytes);
    }
  }

  /**
   * Decrypt the vault key using the Master Encryption Key.
   *
   * Reassemble the ciphertext + tag buffer before passing to WebCrypto.
   */
  async decryptVaultKey(
    encrypted: string,
    iv: string,
    tag: string,
    mek: CryptoKey,
  ): Promise<ArrayBuffer> {
    try {
      const ciphertext = new Uint8Array(this.base64ToArrayBuffer(encrypted));
      const ivBytes = new Uint8Array(this.base64ToArrayBuffer(iv));
      const tagBytes = new Uint8Array(this.base64ToArrayBuffer(tag));

      // Reconstruct ciphertext + tag
      const combined = new Uint8Array(ciphertext.length + tagBytes.length);
      combined.set(ciphertext, 0);
      combined.set(tagBytes, ciphertext.length);

      const decrypted = await this.subtle.decrypt(
        { name: 'AES-GCM', iv: ivBytes, tagLength: TAG_BYTES * 8 },
        mek,
        combined.buffer,
      );

      return decrypted;
    } catch {
      throw new Error(
        'Failed to decrypt vault key. The master password may be incorrect or the vault key data is corrupted.',
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Vault Key Rotation
  // ---------------------------------------------------------------------------

  /**
   * Generate a new random vault key and encrypt it with the current MEK.
   * Returns the new VK as a CryptoKey and the encrypted form for server storage.
   * The intermediate raw ArrayBuffer is zeroed immediately after import.
   */
  async rotateVaultKey(mek: CryptoKey): Promise<{
    newVaultKey: CryptoKey;
    encrypted: string;
    iv: string;
    tag: string;
  }> {
    const rawVaultKey = this.generateVaultKey();
    const newVaultKey = await this.importVaultKey(rawVaultKey);
    this.clearKey(rawVaultKey);
    const enc = await this.encryptVaultKey(newVaultKey, mek);
    return {
      newVaultKey,
      encrypted: enc.encrypted,
      iv: enc.iv,
      tag: enc.tag,
    };
  }

  // ---------------------------------------------------------------------------
  // Data Encryption / Decryption
  // ---------------------------------------------------------------------------

  /**
   * Encrypt an arbitrary UTF-8 string with the vault key using AES-256-GCM.
   *
   * The vault key CryptoKey is used directly — no per-call import needed.
   * The ciphertext and tag are separated for storage.
   */
  async encryptData(
    data: string,
    vaultKey: CryptoKey,
  ): Promise<{ encrypted: string; iv: string; tag: string }> {
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_BYTES));
    const encoder = new TextEncoder();
    const plaintext = encoder.encode(data);

    const ciphertextWithTag = await this.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: TAG_BYTES * 8 },
      vaultKey,
      plaintext,
    );

    const fullBytes = new Uint8Array(ciphertextWithTag);
    const ciphertext = fullBytes.slice(0, fullBytes.length - TAG_BYTES);
    const tag = fullBytes.slice(fullBytes.length - TAG_BYTES);

    return {
      encrypted: this.arrayBufferToBase64(ciphertext.buffer),
      iv: this.arrayBufferToBase64(iv.buffer),
      tag: this.arrayBufferToBase64(tag.buffer),
    };
  }

  /**
   * Decrypt an AES-256-GCM encrypted string back to UTF-8 plaintext.
   *
   * The vault key CryptoKey is used directly — no per-call import needed.
   */
  async decryptData(
    encrypted: string,
    iv: string,
    tag: string,
    vaultKey: CryptoKey,
  ): Promise<string> {
    const ciphertext = new Uint8Array(this.base64ToArrayBuffer(encrypted));
    const ivBytes = new Uint8Array(this.base64ToArrayBuffer(iv));
    const tagBytes = new Uint8Array(this.base64ToArrayBuffer(tag));

    // Reconstruct ciphertext + tag
    const combined = new Uint8Array(ciphertext.length + tagBytes.length);
    combined.set(ciphertext, 0);
    combined.set(tagBytes, ciphertext.length);

    const decrypted = await this.subtle.decrypt(
      { name: 'AES-GCM', iv: ivBytes, tagLength: TAG_BYTES * 8 },
      vaultKey,
      combined.buffer,
    );

    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  }

  // ---------------------------------------------------------------------------
  // Search Hash
  // ---------------------------------------------------------------------------

  /**
   * Generate a deterministic HMAC-SHA256 hash of an item name using the vault
   * key. This allows the server to perform equality-match lookups without
   * knowing the plaintext name.
   *
   * Exports the CryptoKey to raw bytes to re-import as an HMAC key, then
   * zeroes the exported buffer.
   */
  async generateSearchHash(name: string, vaultKey: CryptoKey): Promise<string> {
    const encoder = new TextEncoder();
    const message = encoder.encode(name.trim().toLowerCase());

    const rawBytes = await this.subtle.exportKey('raw', vaultKey);
    try {
      const hmacKey = await this.subtle.importKey(
        'raw',
        rawBytes,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign'],
      );

      const signature = await this.subtle.sign('HMAC', hmacKey, message);
      return Array.from(new Uint8Array(signature), (b) => b.toString(16).padStart(2, '0')).join('');
    } finally {
      this.clearKey(rawBytes);
    }
  }

  // ---------------------------------------------------------------------------
  // Backup Key Derivation
  // ---------------------------------------------------------------------------

  /**
   * Derive a Backup Encryption Key (BEK) from a backup password and salt
   * using PBKDF2 (600k iterations, SHA-256).
   */
  async deriveBEK(backupPassword: string, salt: ArrayBuffer): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(backupPassword);

    try {
      const baseKey = await this.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, [
        'deriveKey',
      ]);

      return await this.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: new Uint8Array(salt),
          iterations: PBKDF2_ITERATIONS,
          hash: 'SHA-256',
        },
        baseKey,
        { name: 'AES-GCM', length: AES_KEY_BITS },
        false,
        ['encrypt', 'decrypt'],
      );
    } finally {
      // Zero the password bytes to reduce exposure window
      this.clearKey(passwordBytes.buffer);
    }
  }

  /**
   * Generate a random Backup Wrapping Key (BWK) — 32 random bytes.
   */
  generateBWK(): ArrayBuffer {
    const key = new Uint8Array(VAULT_KEY_BYTES);
    globalThis.crypto.getRandomValues(key);
    return key.buffer;
  }

  /**
   * Encrypt the BWK with the BEK using AES-256-GCM.
   */
  async encryptBWK(
    bwk: ArrayBuffer,
    bek: CryptoKey,
  ): Promise<{ encrypted: string; iv: string; tag: string }> {
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_BYTES));

    const ciphertextWithTag = await this.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: TAG_BYTES * 8 },
      bek,
      bwk,
    );

    const fullBytes = new Uint8Array(ciphertextWithTag);
    const ciphertext = fullBytes.slice(0, fullBytes.length - TAG_BYTES);
    const tag = fullBytes.slice(fullBytes.length - TAG_BYTES);

    return {
      encrypted: this.arrayBufferToBase64(ciphertext.buffer),
      iv: this.arrayBufferToBase64(iv.buffer),
      tag: this.arrayBufferToBase64(tag.buffer),
    };
  }

  /**
   * Decrypt the BWK with the BEK using AES-256-GCM.
   * Used to verify the backup password is correct before restore operations.
   */
  async decryptBWK(
    encrypted: string,
    iv: string,
    tag: string,
    bek: CryptoKey,
  ): Promise<ArrayBuffer> {
    const ciphertext = new Uint8Array(this.base64ToArrayBuffer(encrypted));
    const ivBytes = new Uint8Array(this.base64ToArrayBuffer(iv));
    const tagBytes = new Uint8Array(this.base64ToArrayBuffer(tag));

    const combined = new Uint8Array(ciphertext.length + tagBytes.length);
    combined.set(ciphertext, 0);
    combined.set(tagBytes, ciphertext.length);

    return this.subtle.decrypt(
      { name: 'AES-GCM', iv: ivBytes, tagLength: TAG_BYTES * 8 },
      bek,
      combined,
    );
  }

  /**
   * Encrypt the vault key with BWK using AES-256-GCM.
   * Used to include a BWK-wrapped copy of the vault key in backups,
   * enabling cross-account restore without needing the original MEK.
   *
   * Exports the CryptoKey vault key to raw bytes internally, then zeroes them.
   */
  async encryptVaultKeyWithBWK(
    vaultKey: CryptoKey,
    bwk: ArrayBuffer,
  ): Promise<{ encrypted: string; iv: string; tag: string }> {
    const rawVaultKey = await this.subtle.exportKey('raw', vaultKey);
    try {
      const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_BYTES));

      const bwkCryptoKey = await this.subtle.importKey(
        'raw',
        bwk,
        { name: 'AES-GCM', length: AES_KEY_BITS },
        false,
        ['encrypt'],
      );

      const ciphertextWithTag = await this.subtle.encrypt(
        { name: 'AES-GCM', iv, tagLength: TAG_BYTES * 8 },
        bwkCryptoKey,
        rawVaultKey,
      );

      const fullBytes = new Uint8Array(ciphertextWithTag);
      const ciphertext = fullBytes.slice(0, fullBytes.length - TAG_BYTES);
      const tag = fullBytes.slice(fullBytes.length - TAG_BYTES);

      return {
        encrypted: this.arrayBufferToBase64(ciphertext.buffer),
        iv: this.arrayBufferToBase64(iv.buffer),
        tag: this.arrayBufferToBase64(tag.buffer),
      };
    } finally {
      this.clearKey(rawVaultKey);
    }
  }

  /**
   * Decrypt the vault key using BWK.
   * Used during cross-account backup restore when MEK-based decryption fails.
   */
  async decryptVaultKeyWithBWK(
    encrypted: string,
    iv: string,
    tag: string,
    bwk: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    const ciphertext = new Uint8Array(this.base64ToArrayBuffer(encrypted));
    const ivBytes = new Uint8Array(this.base64ToArrayBuffer(iv));
    const tagBytes = new Uint8Array(this.base64ToArrayBuffer(tag));

    const bwkCryptoKey = await this.subtle.importKey(
      'raw',
      bwk,
      { name: 'AES-GCM', length: AES_KEY_BITS },
      false,
      ['decrypt'],
    );

    const combined = new Uint8Array(ciphertext.length + tagBytes.length);
    combined.set(ciphertext, 0);
    combined.set(tagBytes, ciphertext.length);

    return this.subtle.decrypt(
      { name: 'AES-GCM', iv: ivBytes, tagLength: TAG_BYTES * 8 },
      bwkCryptoKey,
      combined,
    );
  }

  /**
   * Generate a random salt for BEK derivation.
   */
  generateSalt(bytes = 16): ArrayBuffer {
    const salt = new Uint8Array(bytes);
    globalThis.crypto.getRandomValues(salt);
    return salt.buffer;
  }

  // ---------------------------------------------------------------------------
  // Utility
  // ---------------------------------------------------------------------------

  /**
   * Convert an ArrayBuffer to a standard base64 string.
   */
  arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    const chunkSize = 8192;
    let binary = '';
    for (let i = 0; i < bytes.length; i += chunkSize) {
      const chunk = bytes.subarray(i, i + chunkSize);
      binary += String.fromCharCode.apply(null, chunk as unknown as number[]);
    }
    return btoa(binary);
  }

  /**
   * Convert a base64 string back to an ArrayBuffer.
   */
  base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  /**
   * Zero-fill an ArrayBuffer to clear sensitive key material from memory.
   *
   * Note: JavaScript does not guarantee that the GC will not have copied the
   * buffer contents elsewhere, but this is a best-effort measure to reduce
   * the window of exposure.
   */
  clearKey(key: ArrayBuffer): void {
    const view = new Uint8Array(key);
    view.fill(0);
  }

  /**
   * Best-effort clearing of a CryptoKey object by exporting its raw key
   * material and zeroing the resulting buffer. The CryptoKey must have been
   * imported with `extractable: true` for this to work.
   */
  async clearCryptoKey(key: CryptoKey): Promise<void> {
    try {
      const raw = await this.subtle.exportKey('raw', key);
      this.clearKey(raw);
    } catch {
      // Non-extractable key — nothing we can do
    }
  }

  /**
   * Constant-time comparison of an AES-GCM vault key against candidate raw
   * key bytes. Exports the CryptoKey to raw bytes, compares length-safely,
   * and zeroes the exported copy in `finally`.
   *
   * Used by the backup-restore flow to decide whether a backup's decrypted
   * vault key differs from the current in-memory vault key. Adoption (and the
   * master-password re-authentication it requires) is only needed when they
   * differ — a cross-account restore, or a same-account restore of a backup
   * taken before a vault-key rotation. When the keys are identical (the common
   * same-account, un-rotated case) adoption is a no-op and can be skipped.
   *
   * The vault key is already extractable and is exported on every save, so
   * this exposes no capability an in-page attacker did not already have.
   */
  async vaultKeyEqualsRaw(vaultKey: CryptoKey, rawCandidate: ArrayBuffer): Promise<boolean> {
    let raw: ArrayBuffer | undefined;
    try {
      raw = await this.subtle.exportKey('raw', vaultKey);
      const a = new Uint8Array(raw);
      const b = new Uint8Array(rawCandidate);
      if (a.length !== b.length) return false;
      let diff = 0;
      for (let i = 0; i < a.length; i++) {
        diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
      }
      return diff === 0;
    } finally {
      if (raw) this.clearKey(raw);
    }
  }

  // ---------------------------------------------------------------------------
  // Backup Subkey Derivation (HKDF)
  //
  // NIST SP 800-108 best practice: derive separate subkeys from a single root
  // key per cryptographic purpose (HMAC vs AES-GCM) so that an attack against
  // one primitive cannot leverage the same key bytes against the other. We
  // use HKDF-SHA256 with a fixed `info` string per purpose; the empty salt is
  // RFC 5869 compliant when the input keying material is already pseudorandom
  // (BWK is generated via `getRandomValues`).
  //
  // BACKWARDS COMPATIBILITY: legacy backups (formatVersion 1) used the raw
  // BWK directly as the HMAC key. `verifyBackupHmac` first attempts the new
  // HKDF-derived subkey and falls back to raw BWK so old backups still
  // restore. New downloads always use the HKDF-derived subkey.
  // ---------------------------------------------------------------------------

  /** HKDF info label for the backup HMAC subkey (formatVersion >= 2). */
  static readonly BACKUP_HMAC_INFO = 'hvault-backup-hmac-v1';
  /** HKDF info label for the backup AES-GCM encryption subkey (formatVersion >= 2). */
  static readonly BACKUP_ENC_INFO = 'hvault-backup-enc-v1';

  /**
   * Derive a 256-bit subkey from raw key material via HKDF-SHA256.
   * Returns raw bytes that the caller imports as the appropriate key type.
   */
  private async hkdfDeriveSubkey(rootKey: ArrayBuffer, info: string): Promise<ArrayBuffer> {
    const hkdfBaseKey = await this.subtle.importKey('raw', rootKey, 'HKDF', false, ['deriveBits']);
    return this.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(0),
        info: new TextEncoder().encode(info),
      },
      hkdfBaseKey,
      AES_KEY_BITS,
    );
  }

  // ---------------------------------------------------------------------------
  // Backup Integrity (HMAC)
  // ---------------------------------------------------------------------------

  /**
   * Compute an HMAC-SHA256 over backup data using an HKDF-derived subkey of
   * BWK (key separation per NIST SP 800-108). Returns the HMAC as a
   * lowercase hex string.
   *
   * Used when downloading a backup file — the HMAC is embedded in the file
   * so that restore can verify the backup has not been tampered with.
   */
  async computeBackupHmac(data: string, bwk: ArrayBuffer): Promise<string> {
    const encoder = new TextEncoder();
    const message = encoder.encode(data);

    const macSubkey = await this.hkdfDeriveSubkey(bwk, CryptoService.BACKUP_HMAC_INFO);
    try {
      const hmacKey = await this.subtle.importKey(
        'raw',
        macSubkey,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign'],
      );

      const signature = await this.subtle.sign('HMAC', hmacKey, message);
      return Array.from(new Uint8Array(signature), (b) => b.toString(16).padStart(2, '0')).join('');
    } finally {
      this.clearKey(macSubkey);
    }
  }

  /**
   * Verify an HMAC-SHA256 over backup data.
   *
   * Tries the HKDF-derived subkey first (formatVersion >= 2). On mismatch,
   * falls back to the raw BWK bytes (formatVersion 1 legacy behaviour) so
   * older backups generated before key separation still restore. Returns
   * true if either path verifies.
   *
   * Uses SubtleCrypto.verify() which performs constant-time comparison
   * internally, preventing timing side-channel attacks.
   */
  async verifyBackupHmac(data: string, hmac: string, bwk: ArrayBuffer): Promise<boolean> {
    const encoder = new TextEncoder();
    const message = encoder.encode(data);

    // Convert hex HMAC string to Uint8Array (strict hex validation)
    const hexPairs = hmac.match(/[0-9a-f]{2}/g);
    if (hexPairs?.length !== 32) return false;
    const hmacBytes = new Uint8Array(hexPairs.map((byte) => parseInt(byte, 16)));

    // Path 1: HKDF-derived subkey (current/new format)
    const macSubkey = await this.hkdfDeriveSubkey(bwk, CryptoService.BACKUP_HMAC_INFO);
    try {
      const subkeyHmac = await this.subtle.importKey(
        'raw',
        macSubkey,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['verify'],
      );
      const subkeyMatch = await this.subtle.verify('HMAC', subkeyHmac, hmacBytes, message);
      if (subkeyMatch) return true;
    } finally {
      this.clearKey(macSubkey);
    }

    // Path 2: legacy raw-BWK HMAC (formatVersion 1)
    const legacyHmacKey = await this.subtle.importKey(
      'raw',
      bwk,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify'],
    );
    return this.subtle.verify('HMAC', legacyHmacKey, hmacBytes, message);
  }

  /**
   * Derive a dedicated AES-GCM subkey from BWK via HKDF for use when encrypting
   * backup payload components (formatVersion >= 2). Exposed so future call
   * sites can opt into key separation without breaking already-stored
   * legacy ciphertexts (e.g. the server-stored `bwkEncryptedVaultKey` was
   * produced with raw BWK and must continue to decrypt with raw BWK).
   */
  async deriveBackupEncSubkey(bwk: ArrayBuffer): Promise<CryptoKey> {
    const raw = await this.hkdfDeriveSubkey(bwk, CryptoService.BACKUP_ENC_INFO);
    try {
      return await this.subtle.importKey(
        'raw',
        raw,
        { name: 'AES-GCM', length: AES_KEY_BITS },
        false,
        ['encrypt', 'decrypt'],
      );
    } finally {
      this.clearKey(raw);
    }
  }

  // ---------------------------------------------------------------------------
  // Backup Codes
  // ---------------------------------------------------------------------------

  /**
   * Generate an array of cryptographically random hex backup codes.
   * Each code is 16 hex characters (8 bytes / 64 bits of entropy).
   */
  generateBackupCodes(count: number): string[] {
    const codes: string[] = [];
    for (let i = 0; i < count; i++) {
      const bytes = new Uint8Array(BACKUP_CODE_BYTES);
      globalThis.crypto.getRandomValues(bytes);
      const hex = Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
      codes.push(hex);
    }
    return codes;
  }
}

/** Singleton instance for use throughout the application. */
export const cryptoService = new CryptoService();
