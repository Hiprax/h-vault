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
import type { ItemType } from '@hvault/shared';
import { cryptoService } from '../../src/services/crypto/cryptoService';
import { decryptVaultField } from '../../src/services/crypto/vaultField';

/** Anchored on this module's own URL, never `process.cwd()`. */
const here = path.dirname(fileURLToPath(import.meta.url));

interface FixtureItem {
  id: string;
  itemType: ItemType;
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

/** HMAC-SHA256 of `message` under raw key bytes, as lower-case hex. */
async function hmacHex(key: ArrayBuffer, message: string): Promise<string> {
  const hmacKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await crypto.subtle.sign('HMAC', hmacKey, new TextEncoder().encode(message));
  return Array.from(new Uint8Array(signature), (b) => b.toString(16).padStart(2, '0')).join('');
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

      // The search hash. 0.7.0 keyed it with the raw vault key; this release keys
      // it with an HKDF subkey (key separation), so the recorded hash is NOT what
      // `generateSearchHash` produces any more, deliberately, and asserting it was
      // would pin the key reuse the change removed. Nothing is lost by that: the
      // server never matches ITEMS by this hash (import identity is computed from
      // decrypted content, `toolsController` performs no hash matching), and a
      // rotation or re-seal recomputes every item's hash.
      //
      // What still has to hold is the NORMALISATION, which both schemes share and
      // which a later change could break silently. So the recorded 0.7.0 hash is
      // reproduced from the 0.7.0 construction over `normalised`, and the current
      // hash is reproduced from the current construction over the SAME string:
      // together they tie today's normalisation to the one the fixture recorded.
      const normalised = item.name.trim().toLowerCase();
      const raw = await crypto.subtle.exportKey('raw', vaultKey);
      expect(await hmacHex(raw, normalised)).toBe(item.searchHash);
      const searchKey = await crypto.subtle.deriveBits(
        {
          name: 'HKDF',
          hash: 'SHA-256',
          salt: new Uint8Array(0),
          info: new TextEncoder().encode('hvault/item/search/v1'),
        },
        await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveBits']),
        256,
      );
      const current = await cryptoService.generateSearchHash(item.name, vaultKey);
      expect(current).toBe(await hmacHex(searchKey, normalised));
      expect(current).not.toBe(item.searchHash);
    },
    60_000,
  );

  it.each(items.map((item) => [item.id, item] as const))(
    'opens %s through the dual-read path the vault reads every row with',
    async (id, item) => {
      // `decryptItem` no longer calls `decryptData`: every row field goes through
      // `decryptVaultField`, which must route a 0.7.0 field (no marker, no
      // additional data) down the unchanged v1 path. The fixture's ids are labels,
      // not ObjectIds, so no v2 binding could even be built from them: a reader
      // that consulted the binding for an unmarked field would refuse all of
      // these, which is exactly the regression this case exists to catch.
      expect(item.dataIv.startsWith('v2:')).toBe(false);
      expect(
        await decryptVaultField(
          { encrypted: item.encryptedData, iv: item.dataIv, tag: item.dataTag },
          { role: 'item.data', rowId: id, itemType: item.itemType },
          vaultKey,
        ),
      ).toBe(item.plaintext);
      expect(
        await decryptVaultField(
          { encrypted: item.encryptedName, iv: item.nameIv, tag: item.nameTag },
          { role: 'item.name', rowId: id },
          vaultKey,
        ),
      ).toBe(item.name);
    },
    60_000,
  );
});
