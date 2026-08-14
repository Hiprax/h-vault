/**
 * The vault and backup FORMAT, implemented independently of the application.
 *
 * ---------------------------------------------------------------------------
 * WHY A SECOND IMPLEMENTATION, DELIBERATELY
 * ---------------------------------------------------------------------------
 *
 * The rule this repository records — never re-implement production code inside a
 * test and then test the copy — is about the UNIT UNDER TEST. The unit under
 * test in this directory is the DISASTER: a backup file leaving one database and
 * arriving in another, and a process dying mid-write. The crypto is the
 * instrument, not the subject.
 *
 * For that question a second implementation is the right instrument, for the
 * same reason a wire-format conformance reader is, and for one more reason that
 * is specific to this package: `packages/client/src/services/crypto/cryptoService.ts`
 * CANNOT be imported here. It is typed against the DOM lib (`SubtleCrypto`,
 * `CryptoKey`), and this package compiles with `lib: ["ES2022"]` and
 * `types: ["node"]` — measured, and it is nineteen `TS2749`s deep, not one
 * import away. That is the same structural boundary `test:upgrade` hit, which is
 * why its client leg exists at all.
 *
 * So this module states the FORMAT and reads and writes the bytes with it:
 *
 *   PBKDF2-SHA256, 600,000 iterations, the lowercased email as salt, 512 bits
 *   out: the first 256 are the master encryption key, the last 256 are put
 *   through one more PBKDF2 iteration to become the auth hash the server
 *   bcrypts. A random 256-bit vault key is AES-256-GCM-wrapped by the master
 *   encryption key; every stored value is AES-256-GCM under the vault key with a
 *   fresh 12-byte IV and its 16-byte tag stored separately, base64 each.
 *
 *   A backup password plus the stored 16-byte salt derive the backup encryption
 *   key the same way; it wraps a random backup wrapping key, and the BWK wraps a
 *   copy of the vault key so a backup can be opened on an account that no longer
 *   has the original. The file's `integrity` field is HMAC-SHA256 over the
 *   document with that field removed and re-serialized, under an HKDF-SHA256
 *   subkey of the BWK with the info string `hvault-backup-hmac-v1`.
 *
 * Because AES-GCM AUTHENTICATES, a successful decrypt here is an assertion
 * rather than a coincidence: the tag has to verify. The drill proves that half
 * too, by requiring a wrong master password and a wrong backup password to fail.
 *
 * WHAT IT DOES NOT CLAIM: nothing about `cryptoService.ts` itself. That module's
 * own behaviour — including `verifyBackupHmac`'s constant-time comparison and
 * its legacy raw-BWK fallback — is covered by `packages/client/tests/crypto.test.ts`
 * and by the client leg of `test:upgrade`. What is claimed here, and nowhere
 * else, is that a backup file this server produced opens on a different database
 * on a different mongod, to the same bytes.
 */
import type { webcrypto } from 'node:crypto';

/** The key hierarchy's PBKDF2 work factor. */
const PBKDF2_ITERATIONS = 600_000;

/** The second PBKDF2 pass that turns auth material into the transmitted hash. */
const AUTH_KEY_ITERATIONS = 1;

/** AES-256-GCM parameters: a fresh 12-byte IV per value, a 16-byte tag. */
const IV_BYTES = 12;
const TAG_BYTES = 16;

/** Vault key, backup wrapping key and HKDF subkey are all 256 bits. */
const KEY_BYTES = 32;

/** The HKDF info label that separates the backup MAC key from the wrapping key. */
const BACKUP_HMAC_INFO = 'hvault-backup-hmac-v1';

const { subtle } = globalThis.crypto;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** A stored AES-GCM triple, exactly as it crosses the wire and sits in Mongo. */
export interface Sealed {
  encrypted: string;
  iv: string;
  tag: string;
}

const toBase64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64');
const fromBase64 = (value: string): Uint8Array => new Uint8Array(Buffer.from(value, 'base64'));
const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

/** Cryptographically random bytes, for keys and salts. */
export function randomBytes(length: number): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

async function importAesKey(raw: Uint8Array): Promise<webcrypto.CryptoKey> {
  return subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
}

/**
 * Derives the master encryption key and the auth hash the server bcrypts, from a
 * master password and an email address.
 *
 * Costs one 600,000-iteration derivation, so call it once per account and reuse
 * the result — a suite that derives per test spends most of its time here.
 */
export async function deriveMasterKeys(
  masterPassword: string,
  email: string,
): Promise<{ masterEncryptionKey: webcrypto.CryptoKey; authHash: string }> {
  const salt = encoder.encode(email.trim().toLowerCase());

  const baseKey = await subtle.importKey('raw', encoder.encode(masterPassword), 'PBKDF2', false, [
    'deriveBits',
  ]);
  const derived = new Uint8Array(
    await subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
      baseKey,
      512,
    ),
  );

  const authBaseKey = await subtle.importKey('raw', derived.slice(32, 64), 'PBKDF2', false, [
    'deriveBits',
  ]);
  const authKey = await subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: AUTH_KEY_ITERATIONS, hash: 'SHA-256' },
    authBaseKey,
    256,
  );

  return {
    masterEncryptionKey: await importAesKey(derived.slice(0, 32)),
    authHash: toBase64(new Uint8Array(authKey)),
  };
}

/** Derives the backup encryption key from a backup password and its stored salt. */
export async function deriveBackupEncryptionKey(
  backupPassword: string,
  saltBase64: string,
): Promise<webcrypto.CryptoKey> {
  const baseKey = await subtle.importKey('raw', encoder.encode(backupPassword), 'PBKDF2', false, [
    'deriveBits',
  ]);
  const derived = await subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: fromBase64(saltBase64),
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    baseKey,
    256,
  );
  return importAesKey(new Uint8Array(derived));
}

/** A fresh 256-bit key, returned both as raw bytes and as an AES-GCM key. */
export async function generateKey(): Promise<{ raw: Uint8Array; key: webcrypto.CryptoKey }> {
  const raw = randomBytes(KEY_BYTES);
  return { raw, key: await importAesKey(raw) };
}

/**
 * AES-256-GCM seal with the tag held SEPARATELY from the ciphertext, which is
 * the shape every stored triple in this application has.
 */
export async function seal(plaintext: Uint8Array, key: webcrypto.CryptoKey): Promise<Sealed> {
  const iv = randomBytes(IV_BYTES);
  const combined = new Uint8Array(
    await subtle.encrypt({ name: 'AES-GCM', iv, tagLength: TAG_BYTES * 8 }, key, plaintext),
  );
  return {
    encrypted: toBase64(combined.slice(0, combined.length - TAG_BYTES)),
    iv: toBase64(iv),
    tag: toBase64(combined.slice(combined.length - TAG_BYTES)),
  };
}

/** Seals a UTF-8 string. */
export async function sealText(plaintext: string, key: webcrypto.CryptoKey): Promise<Sealed> {
  return seal(encoder.encode(plaintext), key);
}

/**
 * AES-256-GCM open. Rejects when the tag does not verify, which is what makes a
 * successful open in this suite an assertion rather than a coincidence.
 */
export async function open(sealed: Sealed, key: webcrypto.CryptoKey): Promise<Uint8Array> {
  const ciphertext = fromBase64(sealed.encrypted);
  const tag = fromBase64(sealed.tag);
  const combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext, 0);
  combined.set(tag, ciphertext.length);

  return new Uint8Array(
    await subtle.decrypt(
      { name: 'AES-GCM', iv: fromBase64(sealed.iv), tagLength: TAG_BYTES * 8 },
      key,
      combined,
    ),
  );
}

/** Opens a sealed triple to its UTF-8 string. */
export async function openText(sealed: Sealed, key: webcrypto.CryptoKey): Promise<string> {
  return decoder.decode(await open(sealed, key));
}

/**
 * The HMAC-SHA256 search hash of an item or folder name, as hex.
 *
 * Keyed on the RAW vault key (not an HKDF subkey), over the trimmed, lowercased
 * name — the server uses it for duplicate detection and never learns the name.
 */
export async function searchHashOf(name: string, rawVaultKey: Uint8Array): Promise<string> {
  const key = await subtle.importKey('raw', rawVaultKey, { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
  ]);
  return toHex(
    new Uint8Array(await subtle.sign('HMAC', key, encoder.encode(name.trim().toLowerCase()))),
  );
}

/** The HKDF-SHA256 subkey the backup file's `integrity` field is MACed under. */
async function backupMacKey(rawBwk: Uint8Array): Promise<webcrypto.CryptoKey> {
  const hkdfKey = await subtle.importKey('raw', rawBwk, 'HKDF', false, ['deriveBits']);
  const subkey = await subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: encoder.encode(BACKUP_HMAC_INFO),
    },
    hkdfKey,
    KEY_BYTES * 8,
  );
  return subtle.importKey('raw', subkey, { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
    'verify',
  ]);
}

/** Signs a backup document body, returning the hex string stored as `integrity`. */
export async function signBackup(body: string, rawBwk: Uint8Array): Promise<string> {
  const key = await backupMacKey(rawBwk);
  return toHex(new Uint8Array(await subtle.sign('HMAC', key, encoder.encode(body))));
}

/**
 * Verifies a backup document body against its `integrity` field.
 *
 * The comparison is `SubtleCrypto.verify`, which compares the whole MAC in
 * constant time — the same primitive, for the same reason, that the client's
 * `verifyBackupHmac` uses. A hex string that is not exactly 32 bytes is refused
 * before any comparison, so a truncated MAC cannot be padded into a match.
 */
export async function verifyBackup(
  body: string,
  integrityHex: string,
  rawBwk: Uint8Array,
): Promise<boolean> {
  const pairs = integrityHex.match(/[0-9a-f]{2}/g);
  if (pairs?.length !== KEY_BYTES || pairs.join('') !== integrityHex) return false;
  const key = await backupMacKey(rawBwk);
  return subtle.verify(
    'HMAC',
    key,
    new Uint8Array(pairs.map((byte) => Number.parseInt(byte, 16))),
    encoder.encode(body),
  );
}

/**
 * Splits a signed backup file into the body that was MACed and the MAC itself,
 * exactly as the client does on restore: take `integrity` out, re-serialize what
 * is left, and verify THAT.
 *
 * Returns a null MAC for a file that carries none — a pre-signature backup,
 * which the application accepts with a warning rather than refusing.
 */
export function splitSignedBackup(file: string): { body: string; integrity: string | null } {
  const parsed = JSON.parse(file) as Record<string, unknown>;
  const integrity = typeof parsed.integrity === 'string' ? parsed.integrity : null;
  delete parsed.integrity;
  return { body: JSON.stringify(parsed), integrity };
}
