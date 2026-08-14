/**
 * `test:upgrade`, client leg — the previous release's ciphertext, opened by the
 * crypto this release actually ships.
 *
 * The server leg of this gate (`packages/server/tests/upgrade/n-minus-1.test.ts`)
 * proves that a 0.7.0 document is accepted by the current models and parses to
 * exactly what 0.7.0 parsed it to. It cannot prove the sentence the gate is
 * named for — "a vault written by the previous release DECRYPTS under the
 * current one" — because the decrypting code is `cryptoService.ts`, which lives
 * in this package and which a server test cannot import.
 *
 * So this file drives the same frozen fixture through the real
 * `cryptoService`: the same master password, the same wrapped vault key, the
 * same base64 triples, the same recorded search hashes. Every value it compares
 * against was produced by release 0.7.0 and is never regenerated, so there is no
 * lockstep: the golden cannot move when the implementation does. If a future
 * change to the key hierarchy, the tag handling, the salt normalisation or the
 * base64 encoding makes today's client unable to read a 0.7.0 vault, this is
 * what says so — and nothing else in the repository does.
 *
 * The fixture is READ FROM THE SERVER PACKAGE rather than copied here. Two
 * copies of a golden are two goldens, and the second one silently stops being
 * regenerated — or, worse, gets regenerated on its own. It is one artefact with
 * one provenance block, consumed from both sides.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { cryptoService } from '../../src/services/crypto/cryptoService';

/** Anchored on this module's own URL, never `process.cwd()`. */
const here = path.dirname(fileURLToPath(import.meta.url));

interface FixtureItem {
  id: string;
  name: string;
  plaintext: string;
  encryptedName: string;
  nameIv: string;
  nameTag: string;
  searchHash: string;
  encryptedData: string;
  dataIv: string;
  dataTag: string;
}

const fixture = JSON.parse(
  readFileSync(
    path.join(here, '..', '..', '..', 'server', 'tests', 'fixtures', 'v0.7.0-vault.json'),
    'utf-8',
  ),
) as {
  provenance: { generatedFromTag: string; generatedFromCommit: string };
  account: {
    email: string;
    masterPassword: string;
    authHash: string;
    encryptedVaultKey: string;
    vaultKeyIv: string;
    vaultKeyTag: string;
  };
  items: FixtureItem[];
};

const { account, items, provenance } = fixture;

/**
 * Derived once. 600,000 PBKDF2 iterations is the point of the work factor, and
 * it is the same derivation for every case below.
 */
let vaultKey: CryptoKey;
let derivedAuthHash: string;

beforeAll(async () => {
  const { masterEncryptionKey, authKey } = await cryptoService.deriveKeys(
    account.masterPassword,
    account.email,
  );
  derivedAuthHash = cryptoService.getAuthHash(authKey);
  const rawVaultKey = await cryptoService.decryptVaultKey(
    account.encryptedVaultKey,
    account.vaultKeyIv,
    account.vaultKeyTag,
    masterEncryptionKey,
  );
  vaultKey = await cryptoService.importVaultKey(rawVaultKey);
}, 60_000);

describe("the current client opens the previous release's vault", () => {
  it('is reading a fixture recorded from v0.7.0, not from this tree', () => {
    // Cheap, and load-bearing: every assertion below is only as meaningful as
    // the bytes being older than the code. The exact commit is pinned in the
    // server leg too; here it guards against this file being pointed at a
    // regenerated copy.
    expect(provenance.generatedFromTag).toBe('v0.7.0');
    expect(provenance.generatedFromCommit).toBe('8ab3c7609a505e65c02276e78e673eff4195d262');
    expect(items.length).toBeGreaterThan(0);
  });

  it('derives the same auth hash 0.7.0 sent to the server', async () => {
    // If this ever changes, every existing account is locked out on its next
    // sign-in: the server bcrypt-compares against the hash of a derivation
    // performed by whichever release the user registered under. There is no
    // recovery path — the master password is the only input and the server
    // cannot re-derive anything.
    expect(derivedAuthHash).toBe(account.authHash);
  });

  it('unwraps the vault key 0.7.0 wrapped, and refuses a wrong master password', async () => {
    // The unwrap already happened in `beforeAll`; reaching here at all means it
    // succeeded, and `vaultKey` is what the decrypts below use. What this adds
    // is the negative: AES-GCM authenticates, so a key derived from a different
    // password must REJECT rather than return plausible bytes. Without it,
    // "it decrypted" would not be a claim about anything.
    expect(vaultKey).toBeDefined();

    const wrong = await cryptoService.deriveKeys(`${account.masterPassword}-wrong`, account.email);
    await expect(
      cryptoService.decryptVaultKey(
        account.encryptedVaultKey,
        account.vaultKeyIv,
        account.vaultKeyTag,
        wrong.masterEncryptionKey,
      ),
    ).rejects.toThrow();
  }, 60_000);

  it.each(items.map((item) => [item.id, item] as const))(
    'decrypts %s to the exact bytes 0.7.0 sealed',
    async (_id, item) => {
      // Byte-identical, not "parses to the same object". The stored blob is what
      // a re-encrypt would have to reproduce, and the client's own schema
      // validation runs on the parse of exactly this string.
      expect(
        await cryptoService.decryptData(item.encryptedData, item.dataIv, item.dataTag, vaultKey),
      ).toBe(item.plaintext);

      // The name is sealed as its own triple, and it is the one an item that
      // fails its schema can still be renamed through — so it has to open
      // independently of the data.
      expect(
        await cryptoService.decryptData(item.encryptedName, item.nameIv, item.nameTag, vaultKey),
      ).toBe(item.name);

      // And the HMAC the server matches duplicates on. This is the assertion
      // that would catch a change to the trim/lowercase normalisation inside
      // `generateSearchHash`: every stored hash would be orphaned, and the only
      // symptom would be duplicate detection quietly ceasing to detect.
      expect(await cryptoService.generateSearchHash(item.name, vaultKey)).toBe(item.searchHash);
    },
    60_000,
  );
});
