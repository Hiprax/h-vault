/**
 * The id a created row is stored under, derived on both sides of the wire.
 *
 * The browser seals a new row's fields to this id BEFORE the row exists, and the
 * server stores the row under the id it derives itself. The two computations
 * share one function, and this file pins what it produces with vectors computed
 * independently (Node's `createHash`, not the function under test), so a change
 * to the layout is a visible edit here rather than a vault of rows that no
 * longer open.
 */
import { createHash } from 'node:crypto';
import { describe, it, expect, vi } from 'vitest';
import { deriveRowId, generateRowIdNonce } from '../src/utils/rowId.js';
import { bulkReEncryptSchema, createVaultItemSchema } from '../src/schemas/vault.js';
import { createFolderSchema } from '../src/schemas/folder.js';
import { importOperationsSchema } from '../src/schemas/user.js';

const USER = '64f1a2b3c4d5e6f708192a3b';
const NONCE = '66f1c2a000112233445566778899aabbccddeeff';

/** The derivation, restated with Node's own hash so the vector is not self-referential. */
function independently(userId: string, nonce: string): string {
  const digest = createHash('sha256')
    .update(`hvault/row-id/v1|${userId.toLowerCase()}|${nonce}`)
    .digest('hex');
  return nonce.slice(0, 8) + digest.slice(0, 16);
}

describe('deriveRowId', () => {
  it('matches the committed known-answer vectors', async () => {
    expect(await deriveRowId(USER, NONCE)).toBe('66f1c2a0169a4bf34f9d932c');
    expect(
      await deriveRowId('AAAAAAAAAAAAAAAAAAAAAAAA', 'ffffffff0123456789abcdef0123456789abcdef'),
    ).toBe('ffffffff012191aae4ea1092');
  });

  it('agrees with an independent computation for arbitrary inputs', async () => {
    for (let i = 0; i < 20; i++) {
      const nonce = generateRowIdNonce(1_700_000_000_000 + i * 1000);
      expect(await deriveRowId(USER, nonce)).toBe(independently(USER, nonce));
    }
  });

  it('is a well-formed ObjectId whose timestamp is the nonce’s', async () => {
    const id = await deriveRowId(USER, NONCE);
    expect(id).toMatch(/^[0-9a-f]{24}$/);
    expect(id.slice(0, 8)).toBe(NONCE.slice(0, 8));
  });

  it('binds the id to the user: the same nonce under another account is another id', async () => {
    const other = '64f1a2b3c4d5e6f708192a3c';
    const mine = await deriveRowId(USER, NONCE);
    const theirs = await deriveRowId(other, NONCE);
    expect(theirs).not.toBe(mine);
    // Only the bound tail differs; the timestamp half is the nonce's in both.
    expect(theirs.slice(0, 8)).toBe(mine.slice(0, 8));
  });

  it('reads the user id case-insensitively, as objectIdSchema canonicalises it', async () => {
    expect(await deriveRowId(USER.toUpperCase(), NONCE)).toBe(await deriveRowId(USER, NONCE));
  });

  it('refuses a user id that is not an ObjectId, and a malformed nonce', async () => {
    await expect(deriveRowId('not-an-id', NONCE)).rejects.toThrow(
      'A row id is derived from an ObjectId user id',
    );
    await expect(deriveRowId(`${USER}0`, NONCE)).rejects.toThrow('ObjectId user id');
    await expect(deriveRowId(USER, NONCE.toUpperCase())).rejects.toThrow(
      'A row id nonce is 40 lower-case hex characters',
    );
    await expect(deriveRowId(USER, NONCE.slice(1))).rejects.toThrow('40 lower-case hex');
    await expect(deriveRowId(USER, `${NONCE}0`)).rejects.toThrow('40 lower-case hex');
  });
});

describe('generateRowIdNonce', () => {
  it('stamps the seconds timestamp and 32 hex characters of randomness', () => {
    const nonce = generateRowIdNonce(0x66f1c2a0 * 1000 + 999);
    expect(nonce).toMatch(/^[0-9a-f]{40}$/);
    expect(nonce.slice(0, 8)).toBe('66f1c2a0');
    // Two nonces in the same second differ in their random half.
    expect(generateRowIdNonce(0)).not.toBe(generateRowIdNonce(0));
  });

  it('wraps a timestamp past 2^32 seconds into the eight characters it has', () => {
    expect(generateRowIdNonce(2 ** 32 * 1000).slice(0, 8)).toBe('00000000');
    expect(generateRowIdNonce(0).slice(0, 8)).toBe('00000000');
  });

  it('throws rather than fall back when no cryptographic generator exists', () => {
    vi.stubGlobal('crypto', undefined);
    try {
      expect(() => generateRowIdNonce()).toThrow('Cryptographic random API is unavailable');
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe('the idNonce wire field', () => {
  const item = {
    itemType: 'login',
    encryptedData: 'd',
    dataIv: 'i',
    dataTag: 't',
    encryptedName: 'n',
    nameIv: 'i',
    nameTag: 't',
  };

  it('is optional on an item and a folder create, and must be exactly the nonce alphabet', () => {
    expect(createVaultItemSchema.safeParse(item).success).toBe(true);
    const parsed = createVaultItemSchema.parse({ ...item, idNonce: NONCE });
    // Carried verbatim: the server hashes the spelling the browser sealed to.
    expect(parsed.idNonce).toBe(NONCE);
    expect(createVaultItemSchema.safeParse({ ...item, idNonce: NONCE.toUpperCase() }).success).toBe(
      false,
    );
    expect(createVaultItemSchema.safeParse({ ...item, idNonce: NONCE.slice(1) }).success).toBe(
      false,
    );
    const folder = { encryptedName: 'n', nameIv: 'i', nameTag: 't' };
    expect(createFolderSchema.parse({ ...folder, idNonce: NONCE }).idNonce).toBe(NONCE);
    expect(createFolderSchema.safeParse({ ...folder, idNonce: 'x' }).success).toBe(false);
  });

  it('refuses two import inserts naming one nonce, and names the repeat', () => {
    const insert = { ...item, searchHash: 'a'.repeat(64), idNonce: NONCE };
    const other = { ...insert, idNonce: `${NONCE.slice(0, 39)}0` };
    expect(importOperationsSchema.safeParse({ inserts: [insert, other] }).success).toBe(true);
    const repeated = importOperationsSchema.safeParse({ inserts: [insert, other, insert] });
    expect(repeated.success).toBe(false);
    expect(repeated.error?.issues).toHaveLength(1);
    expect(repeated.error?.issues[0]?.path).toEqual(['inserts', 2, 'idNonce']);
    // Inserts without a nonce are never "repeats" of each other.
    const bare = { ...insert, idNonce: undefined };
    expect(importOperationsSchema.safeParse({ inserts: [bare, bare] }).success).toBe(true);
  });
});

describe('the re-seal fields of a rotation', () => {
  const rotation = {
    authHash: 'h',
    items: [],
    newEncryptedVaultKey: 'k',
    newVaultKeyIv: 'i',
    newVaultKeyTag: 't',
  };

  it('requires the vault-key generation and an idempotency key on a re-seal, and nowhere else', () => {
    const key = '5f0c6f86-6f0e-4a55-9a8f-2d8d8d3b2a11';
    expect(bulkReEncryptSchema.safeParse(rotation).success).toBe(true);
    const missing = bulkReEncryptSchema.safeParse({ ...rotation, reseal: true });
    expect(missing.success).toBe(false);
    expect(missing.error?.issues.map((i) => i.path)).toEqual([
      ['vaultKeyVersion'],
      ['idempotencyKey'],
    ]);
    const noKey = bulkReEncryptSchema.safeParse({ ...rotation, reseal: true, vaultKeyVersion: 0 });
    expect(noKey.error?.issues.map((i) => i.path)).toEqual([['idempotencyKey']]);
    expect(
      bulkReEncryptSchema.safeParse({
        ...rotation,
        reseal: true,
        vaultKeyVersion: 0,
        idempotencyKey: key,
      }).success,
    ).toBe(true);
    expect(bulkReEncryptSchema.safeParse({ ...rotation, reseal: false }).success).toBe(true);
  });

  it('refuses a re-seal that would abandon an interrupted rotation', () => {
    const parsed = bulkReEncryptSchema.safeParse({
      ...rotation,
      reseal: true,
      vaultKeyVersion: 3,
      idempotencyKey: '5f0c6f86-6f0e-4a55-9a8f-2d8d8d3b2a11',
      discardPendingVaultKey: true,
    });
    expect(parsed.success).toBe(false);
    expect(parsed.error?.issues.map((i) => i.path)).toEqual([['discardPendingVaultKey']]);
    // Discarding alone is still an ordinary, accepted rotation.
    expect(
      bulkReEncryptSchema.safeParse({ ...rotation, discardPendingVaultKey: true }).success,
    ).toBe(true);
  });

  it('accepts only format 2 as the capability', () => {
    expect(bulkReEncryptSchema.safeParse({ ...rotation, vaultFieldFormat: 2 }).success).toBe(true);
    expect(bulkReEncryptSchema.safeParse({ ...rotation, vaultFieldFormat: 1 }).success).toBe(false);
    expect(bulkReEncryptSchema.safeParse({ ...rotation, vaultFieldFormat: 3 }).success).toBe(false);
  });
});
