/**
 * The N-1 fixture, and an INDEPENDENT reader for it.
 *
 * `tests/fixtures/v0.7.0-vault.json` is a vault as release 0.7.0 persisted it,
 * generated inside a detached worktree at that tag by that release's own
 * `CryptoService` and validated by that release's own schemas. Its provenance
 * block records who generated it, when, from which commit, what was verified and
 * what was not.
 *
 * ---------------------------------------------------------------------------
 * WHY THE READER BELOW IS A SECOND IMPLEMENTATION, DELIBERATELY
 * ---------------------------------------------------------------------------
 *
 * The obvious objection to re-deriving the key hierarchy here is the one this
 * repository already records: never re-implement production code inside a test
 * and then test the copy. That rule is about the UNIT UNDER TEST, and the unit
 * under test in this directory is not the crypto — it is the persisted DOCUMENT
 * and the schemas and models that read it. What is asserted is that data written
 * by the previous release is still accepted, still parses, and still parses to
 * exactly what the previous release made of it.
 *
 * For that question a second implementation is the RIGHT instrument, for the
 * same reason a wire-format conformance reader is: calling the application's own
 * decrypt would only prove the application agrees with itself, and would go green
 * in lockstep with any change made on both sides at once. This reader instead
 * states the FORMAT — PBKDF2-SHA256 over the master password with the lowercased
 * email as salt, 512 bits split into a 256-bit master encryption key and 256 bits
 * of auth material, AES-256-GCM with a 12-byte IV and its 16-byte tag stored
 * separately — and reads the bytes with it.
 *
 * It is not a substitute for the client's own crypto suite, and it is not
 * pretending to be one: it says nothing about `cryptoService.ts`. What it can say,
 * and what nothing else in the repository says, is that the FORMAT on disk in a
 * 0.7.0 database is still readable. Because it authenticates (AES-GCM verifies the
 * tag), a green decrypt is a real claim — and the suite proves that by requiring a
 * wrong master password to fail.
 */
import { readFileSync } from 'node:fs';
import type { webcrypto } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/** Resolved from this module's own URL, never `process.cwd()`. */
const here = path.dirname(fileURLToPath(import.meta.url));

/** AES-256-GCM authentication tag length, in bytes. */
const TAG_BYTES = 16;

/** The key hierarchy's PBKDF2 work factor, as 0.7.0 wrote it. */
const PBKDF2_ITERATIONS = 600_000;

/** The second PBKDF2 pass that turns auth material into the transmitted hash. */
const AUTH_KEY_ITERATIONS = 1;

interface FixtureItem {
  id: string;
  itemType: 'login' | 'secret' | 'note' | 'card' | 'identity';
  note: string;
  omits: string[];
  name: string;
  /** The exact UTF-8 string that was sealed. */
  plaintext: string;
  /** What release 0.7.0's own schemas made of `JSON.parse(plaintext)`. */
  parsedByV070: Record<string, unknown>;
  encryptedName: string;
  nameIv: string;
  nameTag: string;
  searchHash: string;
  encryptedData: string;
  dataIv: string;
  dataTag: string;
}

interface FixtureFolder {
  id: string;
  note: string;
  name: string;
  parent?: string;
  sourceRefId?: string;
  sortOrder: number;
  encryptedName: string;
  nameIv: string;
  nameTag: string;
  searchHash: string;
}

interface FixtureRefreshToken {
  id: string;
  note: string;
  omits: string[];
  rawToken: string;
  familyId: string;
  expiresInDays: number;
  absoluteExpiresInDays: number | null;
}

export interface NMinusOneFixture {
  provenance: {
    fixture: string;
    subject: string;
    generatedFromTag: string;
    generatedFromCommit: string;
    generatedBy: string;
    generatedOn: string;
    howGenerated: string[];
    verifiedThat: string[];
    notVerified: string[];
    neverRegenerate: string;
  };
  account: {
    email: string;
    masterPassword: string;
    kdfIterations: number;
    kdfAlgorithm: string;
    encryptionVersion: number;
    authHash: string;
    encryptedVaultKey: string;
    vaultKeyIv: string;
    vaultKeyTag: string;
    settingsNote: string;
    settings: Record<string, unknown>;
  };
  items: FixtureItem[];
  folders: FixtureFolder[];
  refreshTokens: FixtureRefreshToken[];
}

export const nMinusOneVault = JSON.parse(
  readFileSync(path.join(here, '..', 'fixtures', 'v0.7.0-vault.json'), 'utf-8'),
) as NMinusOneFixture;

const decodeBase64 = (value: string): Uint8Array => new Uint8Array(Buffer.from(value, 'base64'));

/**
 * Derives the master encryption key and the transmitted auth hash from a master
 * password and an email address, exactly as the format specifies.
 */
export async function deriveMasterKeys(
  masterPassword: string,
  email: string,
): Promise<{ masterEncryptionKey: webcrypto.CryptoKey; authHash: string }> {
  const { subtle } = globalThis.crypto;
  const encoder = new TextEncoder();
  const salt = encoder.encode(email.trim().toLowerCase());

  const baseKey = await subtle.importKey('raw', encoder.encode(masterPassword), 'PBKDF2', false, [
    'deriveBits',
  ]);
  const derived = await subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    baseKey,
    512,
  );

  const masterEncryptionKey = await subtle.importKey(
    'raw',
    derived.slice(0, 32),
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
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
    masterEncryptionKey,
    authHash: Buffer.from(new Uint8Array(authKey)).toString('base64'),
  };
}

/**
 * AES-256-GCM open, with the tag held separately from the ciphertext — the shape
 * every one of this application's stored triples has.
 *
 * Rejects when the tag does not verify, which is what makes a successful decrypt
 * in this suite an assertion rather than a coincidence.
 */
async function openSealed(
  sealed: { encrypted: string; iv: string; tag: string },
  key: webcrypto.CryptoKey,
): Promise<ArrayBuffer> {
  const ciphertext = decodeBase64(sealed.encrypted);
  const tag = decodeBase64(sealed.tag);
  const combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext, 0);
  combined.set(tag, ciphertext.length);

  return globalThis.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: decodeBase64(sealed.iv), tagLength: TAG_BYTES * 8 },
    key,
    combined,
  );
}

/**
 * Unwraps the account's vault key with the key derived from its master password.
 *
 * Returned as a decrypt-only key plus an HMAC key over the same bytes: the search
 * hash is an HMAC-SHA256 of the item name under the raw vault key, and this suite
 * verifies those too.
 */
export async function unwrapVaultKey(
  account: NMinusOneFixture['account'],
  masterEncryptionKey: webcrypto.CryptoKey,
): Promise<{ vaultKey: webcrypto.CryptoKey; searchHashKey: webcrypto.CryptoKey }> {
  const raw = await openSealed(
    {
      encrypted: account.encryptedVaultKey,
      iv: account.vaultKeyIv,
      tag: account.vaultKeyTag,
    },
    masterEncryptionKey,
  );
  const { subtle } = globalThis.crypto;
  return {
    vaultKey: await subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, [
      'decrypt',
    ]),
    searchHashKey: await subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, [
      'sign',
    ]),
  };
}

/** The HMAC-SHA256 search hash of an item name, as hex. */
export async function searchHashOf(
  name: string,
  searchHashKey: webcrypto.CryptoKey,
): Promise<string> {
  const signature = await globalThis.crypto.subtle.sign(
    'HMAC',
    searchHashKey,
    new TextEncoder().encode(name.trim().toLowerCase()),
  );
  return Array.from(new Uint8Array(signature), (byte) => byte.toString(16).padStart(2, '0')).join(
    '',
  );
}

/** Decrypts a sealed triple to its UTF-8 string. */
export async function openText(
  sealed: { encrypted: string; iv: string; tag: string },
  key: webcrypto.CryptoKey,
): Promise<string> {
  return new TextDecoder().decode(await openSealed(sealed, key));
}
