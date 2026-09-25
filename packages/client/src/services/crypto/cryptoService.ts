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
 *     -> PBKDF2 (KDF_ITERATIONS = 600k, SHA-256, 512-bit output)
 *       -> first 256 bits = Master Encryption Key (MEK) - AES-GCM
 *       -> last  256 bits -> PBKDF2 (1 iteration) -> Authentication Key (sent to server)
 *
 *   Vault Key (random 256-bit) encrypted with MEK (AES-256-GCM)
 *   Vault data encrypted with Vault Key (AES-256-GCM)
 */

import { KDF_ITERATIONS, VAULT_SEARCH_KEY_INFO } from '@hvault/shared';

/*
 * The PBKDF2 work factor for every password-based derivation here (the master
 * key and the backup key) is `KDF_ITERATIONS`, the ONE definition the server's
 * `User` model defaults `kdfIterations` to as well.
 *
 * It is a compile-time constant ON PURPOSE, and the server-supplied
 * `kdfIterations` (returned by login and by every profile read, and stored by
 * `authStore`) is deliberately NEVER read here. Deriving with a number the
 * server chose would hand a hostile or compromised server a KDF-downgrade
 * attack: answer `1`, and the next sign-in or unlock derives with a single
 * round, so the captured auth hash costs one hash per guess instead of
 * 600,000. Ignoring the server's value is what makes that impossible. A future
 * change of work factor therefore needs a migration that the CLIENT drives, not
 * a server-side setting.
 */
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
   * 2. Derive 512 bits (64 bytes) with PBKDF2-SHA256, email as salt, KDF_ITERATIONS rounds.
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
        iterations: KDF_ITERATIONS,
        hash: 'SHA-256',
      },
      baseKey,
      KEY_LENGTH_BITS,
    );

    // Split: first 32 bytes = MEK material, last 32 bytes = auth material
    const mekBytes = derivedBits.slice(0, 32);
    const authMaterial = derivedBits.slice(32, 64);

    try {
      // Import the MEK as a NON-extractable AES-GCM key. Nothing needs its raw
      // bytes: it only ever wraps and unwraps the vault key, through
      // `encrypt()`/`decrypt()` on this handle.
      //
      // Non-extractable is the property that matters, because the MEK is the one
      // key a vault-key rotation does not retire: `rotateVaultKey` seals the new
      // vault key under this SAME MEK and the server returns that wrapper to
      // every session, so exported MEK bytes would unwrap every later vault key
      // until the master password changes. Page script holding the handle can
      // still use it while the page is open; it cannot carry it away.
      //
      // `clearCryptoKey` cannot zero this key and never could: it zeroes a raw
      // copy it exports itself, never the live handle (see `clearCryptoKey`). What
      // retires the MEK on lock and logout is dropping every reference to it.
      const masterEncryptionKey = await this.subtle.importKey(
        'raw',
        mekBytes,
        { name: 'AES-GCM', length: AES_KEY_BITS },
        false,
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
   * encryption (e.g. when encrypting the vault key with MEK or BWK), as HKDF
   * input (once per key for the search subkey, and per document for its wrap
   * key), and for best-effort zeroing via `clearCryptoKey`. It is NOT exported
   * per item write: the search hash, which used to export it on every save, now
   * reads a memoised non-extractable subkey.
   *
   * SECURITY TRADE-OFF: an extractable key means page script can call
   * `exportKey()` to obtain raw key material. Accepted for the VAULT key (and
   * not for the MEK, which is non-extractable) because a rotation retires it:
   * the bytes of a superseded vault key open nothing written after the rotation,
   * while the MEK outlives every rotation.
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
    return this.sealAesGcm(data, vaultKey, undefined);
  }

  /**
   * {@link encryptData} with AES-GCM additional data, which the ciphertext is then
   * bound to: {@link decryptDataWithAad} opens it only with the same bytes.
   *
   * A PRIMITIVE, like its decrypt twin: it takes the additional data ready-made and
   * returns the plain triple, unmarked. A vault ROW's field is sealed through
   * `encryptVaultField` (`vaultField.ts`), which builds the one binding layout and
   * stamps the format marker on the IV; calling this directly for a row would
   * produce a bound field that no reader recognises as bound.
   */
  async encryptDataWithAad(
    data: string,
    vaultKey: CryptoKey,
    additionalData: Uint8Array<ArrayBuffer>,
  ): Promise<{ encrypted: string; iv: string; tag: string }> {
    return this.sealAesGcm(data, vaultKey, additionalData);
  }

  /**
   * The one AES-GCM seal both encrypts share, mirroring {@link openAesGcm}: with
   * `additionalData` undefined the parameter object carries no `additionalData`
   * key at all, which is exactly the call format v1 has always made.
   */
  private async sealAesGcm(
    data: string,
    vaultKey: CryptoKey,
    additionalData: Uint8Array<ArrayBuffer> | undefined,
  ): Promise<{ encrypted: string; iv: string; tag: string }> {
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_BYTES));
    const encoder = new TextEncoder();
    const plaintext = encoder.encode(data);

    const ciphertextWithTag = await this.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        tagLength: TAG_BYTES * 8,
        ...(additionalData === undefined ? {} : { additionalData }),
      },
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
   *
   * This is the format-v1 primitive: it authenticates the bytes and nothing
   * about where they were stored. A vault ROW's field is opened through
   * `decryptVaultField` (`vaultField.ts`), which routes an unmarked field here
   * unchanged and a bound one to {@link decryptDataWithAad}.
   */
  async decryptData(
    encrypted: string,
    iv: string,
    tag: string,
    vaultKey: CryptoKey,
  ): Promise<string> {
    return this.openAesGcm(encrypted, iv, tag, vaultKey, undefined);
  }

  /**
   * {@link decryptData} with AES-GCM additional data, which must equal the bytes
   * the field was sealed with or the tag check fails.
   *
   * Takes the additional data ready-made rather than building it, so that the
   * binding's byte layout has ONE definition (`vaultFieldAad`) and this stays a
   * primitive that knows nothing about rows.
   */
  async decryptDataWithAad(
    encrypted: string,
    iv: string,
    tag: string,
    vaultKey: CryptoKey,
    additionalData: Uint8Array<ArrayBuffer>,
  ): Promise<string> {
    return this.openAesGcm(encrypted, iv, tag, vaultKey, additionalData);
  }

  /**
   * The one AES-GCM open both decrypts share. With `additionalData` undefined the
   * parameter object carries no `additionalData` key at all, which is exactly the
   * call format v1 has always made.
   */
  private async openAesGcm(
    encrypted: string,
    iv: string,
    tag: string,
    vaultKey: CryptoKey,
    additionalData: Uint8Array<ArrayBuffer> | undefined,
  ): Promise<string> {
    const ciphertext = new Uint8Array(this.base64ToArrayBuffer(encrypted));
    const ivBytes = new Uint8Array(this.base64ToArrayBuffer(iv));
    const tagBytes = new Uint8Array(this.base64ToArrayBuffer(tag));

    // Reconstruct ciphertext + tag
    const combined = new Uint8Array(ciphertext.length + tagBytes.length);
    combined.set(ciphertext, 0);
    combined.set(tagBytes, ciphertext.length);

    const decrypted = await this.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: ivBytes,
        tagLength: TAG_BYTES * 8,
        ...(additionalData === undefined ? {} : { additionalData }),
      },
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
   * The search subkey of each vault key this session has hashed a name under.
   *
   * Keyed by the vault key's own handle, so a rotation, which installs a new
   * handle, gets a new entry, and the entry of a key nothing holds any more goes
   * with it. The value is the derivation's PROMISE, so concurrent first calls
   * share one derivation, and a derivation that rejects is evicted so the next
   * call can retry rather than inheriting the failure for the life of the key.
   */
  private readonly searchKeys = new WeakMap<CryptoKey, Promise<CryptoKey>>();

  /**
   * `SK_search = HKDF-SHA256(ikm = vault key, salt = empty, info =
   * VAULT_SEARCH_KEY_INFO)`, imported as a NON-extractable HMAC key.
   *
   * Two defects this replaces, both of the kind the backup key and the documents
   * already avoid (NIST SP 800-108 key separation). The vault key was used
   * directly as the HMAC key, so one key served AES-GCM and HMAC at once; and it
   * was EXPORTED on every item write to do it, putting the raw vault key on the
   * JavaScript heap once per save. Now the raw bytes are exported once per vault
   * key, as HKDF input, and zeroed before this resolves; the HMAC key itself never
   * exists as bytes script can read, since `deriveKey` produces it inside the
   * crypto engine and it is not extractable. The empty salt is RFC 5869 compliant
   * because the input keying material is already a uniformly random key.
   */
  private searchKeyFor(vaultKey: CryptoKey): Promise<CryptoKey> {
    const memoised = this.searchKeys.get(vaultKey);
    if (memoised) return memoised;
    const derived = (async () => {
      const raw = await this.subtle.exportKey('raw', vaultKey);
      try {
        const base = await this.subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey']);
        return await this.subtle.deriveKey(
          {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new Uint8Array(0),
            info: new TextEncoder().encode(VAULT_SEARCH_KEY_INFO),
          },
          base,
          { name: 'HMAC', hash: 'SHA-256', length: 256 },
          false,
          ['sign'],
        );
      } finally {
        this.clearKey(raw);
      }
    })();
    this.searchKeys.set(vaultKey, derived);
    derived.catch(() => {
      if (this.searchKeys.get(vaultKey) === derived) this.searchKeys.delete(vaultKey);
    });
    return derived;
  }

  /**
   * A deterministic HMAC-SHA256 of an item name, normalised by trimming and
   * lower-casing, under the vault key's search subkey (see `searchKeyFor`). It
   * lets the server compare names for equality without learning them.
   *
   * A hash computed before the subkey existed was taken under the raw vault key,
   * so the same name hashes differently in the two schemes. Nothing in this app
   * matches ITEMS by their hash (import identity is computed from decrypted
   * content), and a rotation or a re-seal recomputes every item's hash; a
   * folder's hash is written only by a restore and is not recomputed by either.
   */
  async generateSearchHash(name: string, vaultKey: CryptoKey): Promise<string> {
    const message = new TextEncoder().encode(name.trim().toLowerCase());
    const hmacKey = await this.searchKeyFor(vaultKey);
    const signature = await this.subtle.sign('HMAC', hmacKey, message);
    return Array.from(new Uint8Array(signature), (b) => b.toString(16).padStart(2, '0')).join('');
  }

  // ---------------------------------------------------------------------------
  // Backup Key Derivation
  // ---------------------------------------------------------------------------

  /**
   * Derive a Backup Encryption Key (BEK) from a backup password and salt
   * using PBKDF2 (KDF_ITERATIONS rounds, SHA-256).
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
          iterations: KDF_ITERATIONS,
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
   * Best-effort zeroing of a TRANSIENT raw copy of a key, never of the key.
   *
   * For an extractable key this exports the raw bytes and zeroes that buffer,
   * which is all script can do: a `CryptoKey`'s material lives outside the
   * JavaScript heap, and neither exporting nor zeroing a copy changes the live
   * handle, which goes on encrypting and decrypting until every reference to it
   * is dropped. For a non-extractable key (the MEK, the backup key) the export
   * is refused and this is a no-op. Callers retire a key by dropping their
   * reference to it; this call only narrows the window a raw copy exists in.
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
   * The vault key is extractable by design (see `importVaultKey`), so this
   * exposes no capability an in-page attacker does not already have; the copy it
   * exports is zeroed before it returns.
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
