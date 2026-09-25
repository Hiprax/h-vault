// @vitest-environment node
import { describe, it, expect, beforeAll, vi, afterEach } from 'vitest';
import {
  assertInsertedWhereSealed,
  buildImportOperations,
  chunkImportOperations,
  IMPORT_BATCH_MAX_BYTES,
  MAX_IMPORT_WARNINGS,
} from '../../src/services/import';
import type { ResolvableImportItem } from '../../src/services/import';
import { cryptoService } from '../../src/services/crypto/cryptoService';
import { decryptVaultField } from '../../src/services/crypto/vaultField';
import type { VaultFieldBinding } from '../../src/services/crypto/vaultField';
import {
  MAX_ENCRYPTED_DATA_LENGTH,
  deriveRowId,
  importInsertItemSchema,
  importUpdateItemSchema,
} from '@hvault/shared';
import type { ImportInsertItem, ImportUpdateItem, ItemType } from '@hvault/shared';

/**
 * `buildImportOperations` turns a RESOLVED import into the wire payload, and
 * `chunkImportOperations` slices that payload into requests. Between them they
 * own four guarantees worth proving directly: every row is sealed (format v2) to
 * the row it will be stored as — an insert to the id its nonce derives, an
 * overwrite to the matched row's id and stored type — a native row's stored data
 * string is sealed again byte for byte rather than its file ciphertext forwarded,
 * an overwrite keeps the previous password, and batching is transport only.
 */

let vaultKey: CryptoKey;

/** This session's user id, which every insert's row id is derived from (an ObjectId). */
const USER_ID = '64b7f0c2a1d3e4f5a6b7c8d9';
/** The existing row an overwrite targets, and an unrelated row of the same vault. */
const EXISTING_ID = '507f1f77bcf86cd799439011';
const OTHER_ROW_ID = '507f1f77bcf86cd799439012';

afterEach(() => {
  vi.restoreAllMocks();
});

/** Open one sealed triple under a binding (throws when the binding is wrong). */
function open(
  encrypted: string,
  iv: string,
  tag: string,
  binding: VaultFieldBinding,
): Promise<string> {
  return decryptVaultField({ encrypted, iv, tag }, binding, vaultKey);
}

beforeAll(async () => {
  vaultKey = await globalThis.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ]);
});

function loginRow(overrides: Partial<ResolvableImportItem> = {}): ResolvableImportItem {
  return {
    itemType: 'login',
    name: 'GitHub',
    data: {
      username: 'octocat',
      password: 'hunter2',
      uris: [{ uri: 'https://github.com', match: 'domain' }],
    },
    tags: [],
    favorite: false,
    ...overrides,
  };
}

/** A minimal existing-item stand-in with the fields the builder reads. */
function existingItem(
  id: string,
  data: Record<string, unknown>,
  passwordHistory?: { encryptedPassword: string; iv: string; tag: string; changedAt: string }[],
  itemType: ItemType = 'login',
) {
  return {
    id,
    itemType,
    name: 'GitHub',
    data,
    _raw: { ...(passwordHistory !== undefined ? { passwordHistory } : {}) },
  };
}

describe('buildImportOperations', () => {
  it('encrypts a parsed row into a schema-valid insert carrying no plaintext', async () => {
    const row = loginRow();
    const built = await buildImportOperations({
      inserts: [row],
      updates: [],
      userId: USER_ID,
      vaultKey,
    });

    expect(built.failedCount).toBe(0);
    expect(built.inserts).toHaveLength(1);
    expect(importInsertItemSchema.safeParse(built.inserts[0]).success).toBe(true);

    // Nothing the user typed survives into the payload.
    const serialized = JSON.stringify(built.inserts[0]);
    expect(serialized).not.toContain('octocat');
    expect(serialized).not.toContain('hunter2');
    expect(serialized).not.toContain('github.com');

    // …but it round-trips under the vault key, opened as the row whose id the
    // insert's nonce derives for this user.
    const insert = built.inserts[0] as ImportInsertItem;
    expect(insert.idNonce).toMatch(/^[0-9a-f]{40}$/);
    const rowId = await deriveRowId(USER_ID, insert.idNonce!);
    const name = await open(insert.encryptedName, insert.nameIv, insert.nameTag, {
      role: 'item.name',
      rowId,
    });
    expect(name).toBe('GitHub');
  });

  it('seals an insert through the v2 binding only, with the exact additional data', async () => {
    const withAad = vi.spyOn(cryptoService, 'encryptDataWithAad');
    const unbound = vi.spyOn(cryptoService, 'encryptData');

    const built = await buildImportOperations({
      inserts: [loginRow()],
      updates: [],
      userId: USER_ID,
      vaultKey,
    });
    const insert = built.inserts[0]!;
    const rowId = await deriveRowId(USER_ID, insert.idNonce!);

    // Never the unbound v1 primitive for a row field.
    expect(unbound).not.toHaveBeenCalled();
    expect(withAad).toHaveBeenCalledTimes(2);
    const aads = withAad.mock.calls.map(([, key, aad]) => {
      expect(key).toBe(vaultKey);
      expect(aad).toBeInstanceOf(Uint8Array);
      return new TextDecoder().decode(aad);
    });
    expect(aads).toEqual([
      `hvault/vault-field/v2|item.name|${rowId}`,
      `hvault/vault-field/v2|item.data|login|${rowId}`,
    ]);
    expect(withAad.mock.calls[0]?.[0]).toBe('GitHub');
    expect(JSON.parse(withAad.mock.calls[1]?.[0] ?? '')).toMatchObject({
      username: 'octocat',
      password: 'hunter2',
    });
    expect(insert.nameIv.startsWith('v2:')).toBe(true);
    expect(insert.dataIv.startsWith('v2:')).toBe(true);
  });

  it('seals a native row stored data string byte for byte to the NEW row', async () => {
    // Premise changed: a native row's file ciphertext is bound to the row it was
    // exported from, so it is no longer forwarded; the decrypted stored string is
    // sealed again, verbatim, to the row the insert will create.
    // Deliberately NOT what `JSON.stringify` of the parsed data would produce
    // (spacing, key order, a field the schema would strip), and different from
    // the row's parsed `data`, so a re-serialisation or a validate-and-seal of
    // `data` cannot pass for the verbatim path.
    const dataJson = '{"password":"hunter2",  "username":"octocat","legacyField":1}';
    const built = await buildImportOperations({
      inserts: [loginRow({ native: { dataJson }, data: { username: 'someone-else' } })],
      updates: [],
      userId: USER_ID,
      vaultKey,
    });

    expect(built.failedCount).toBe(0);
    const insert = built.inserts[0]!;
    expect(importInsertItemSchema.safeParse(insert).success).toBe(true);
    const rowId = await deriveRowId(USER_ID, insert.idNonce!);
    expect(
      await open(insert.encryptedData, insert.dataIv, insert.dataTag, {
        role: 'item.data',
        rowId,
        itemType: 'login',
      }),
    ).toBe(dataJson);
    expect(
      await open(insert.encryptedName, insert.nameIv, insert.nameTag, { role: 'item.name', rowId }),
    ).toBe('GitHub');
    await expect(
      open(insert.encryptedData, insert.dataIv, insert.dataTag, {
        role: 'item.data',
        rowId: OTHER_ROW_ID,
        itemType: 'login',
      }),
    ).rejects.toThrow();
    // The search hash is recomputed: an export may not carry one, and it is a
    // deterministic HMAC of the name under the vault key's search subkey.
    expect(insert.searchHash).toBe(await cryptoService.generateSearchHash('GitHub', vaultKey));
  });

  it('carries a native row previous passwords through, sealed to the new row', async () => {
    // Premise changed: the history now arrives as plaintext previous passwords and
    // is sealed to the NEW row, since it is read as that row's history from now on.
    const previousPasswords = [
      { password: 'older-secret', changedAt: '2026-01-01T00:00:00.000Z' },
      { password: 'oldest-secret', changedAt: '2025-06-01T00:00:00.000Z' },
    ];
    const built = await buildImportOperations({
      inserts: [loginRow({ native: { dataJson: '{"username":"octocat"}' }, previousPasswords })],
      updates: [],
      userId: USER_ID,
      vaultKey,
    });

    const insert = built.inserts[0]!;
    expect(importInsertItemSchema.safeParse(insert).success).toBe(true);
    const history = insert.passwordHistory ?? [];
    expect(history).toHaveLength(2);
    expect(history.map((entry) => entry.changedAt)).toEqual([
      '2026-01-01T00:00:00.000Z',
      '2025-06-01T00:00:00.000Z',
    ]);
    const rowId = await deriveRowId(USER_ID, insert.idNonce!);
    const recovered = await Promise.all(
      history.map((entry) => {
        expect(entry.iv.startsWith('v2:')).toBe(true);
        return open(entry.encryptedPassword, entry.iv, entry.tag, {
          role: 'item.password-history',
          rowId,
        });
      }),
    );
    expect(recovered).toEqual(['older-secret', 'oldest-secret']);
    await expect(
      open(history[0]!.encryptedPassword, history[0]!.iv, history[0]!.tag, {
        role: 'item.password-history',
        rowId: OTHER_ROW_ID,
      }),
    ).rejects.toThrow();
    // No plaintext password rides along.
    expect(JSON.stringify(insert)).not.toContain('older-secret');
  });

  it('omits passwordHistory on an insert that carries no previous passwords', async () => {
    const built = await buildImportOperations({
      inserts: [loginRow()],
      updates: [],
      userId: USER_ID,
      vaultKey,
    });
    expect(built.inserts[0]).not.toHaveProperty('passwordHistory');
  });

  it('retains the previous password when an update changes it', async () => {
    const existing = existingItem(EXISTING_ID, {
      username: 'octocat',
      password: 'old-password',
    });
    const built = await buildImportOperations({
      inserts: [],
      updates: [
        { incoming: loginRow({ data: { username: 'octocat', password: 'new' } }), existing },
      ],
      userId: USER_ID,
      vaultKey,
    });

    expect(built.updates).toHaveLength(1);
    const update = built.updates[0] as ImportUpdateItem;
    expect(update.id).toBe(EXISTING_ID);
    expect(importUpdateItemSchema.safeParse(update).success).toBe(true);
    expect(update.passwordHistory).toHaveLength(1);
    // An overwrite targets an existing row: it carries no nonce.
    expect(update).not.toHaveProperty('idNonce');

    const entry = update.passwordHistory![0]!;
    const recovered = await open(entry.encryptedPassword, entry.iv, entry.tag, {
      role: 'item.password-history',
      rowId: EXISTING_ID,
    });
    expect(recovered).toBe('old-password');
  });

  it('seals an overwrite to the matched row id and its STORED item type', async () => {
    // The stored type is the one the data is read under from then on, whatever
    // the incoming row claims, so it is the one bound.
    const existing = existingItem(EXISTING_ID, { content: 'old' }, undefined, 'secret');
    const incoming = loginRow({ itemType: 'note', name: 'Kit', data: { content: 'new' } });
    const built = await buildImportOperations({
      inserts: [],
      updates: [{ incoming, existing }],
      userId: USER_ID,
      vaultKey,
    });

    const update = built.updates[0]!;
    expect(update.nameIv.startsWith('v2:')).toBe(true);
    expect(
      await open(update.encryptedName, update.nameIv, update.nameTag, {
        role: 'item.name',
        rowId: EXISTING_ID,
      }),
    ).toBe('Kit');
    const data = await open(update.encryptedData, update.dataIv, update.dataTag, {
      role: 'item.data',
      rowId: EXISTING_ID,
      itemType: 'secret',
    });
    expect(JSON.parse(data)).toMatchObject({ content: 'new' });
    await expect(
      open(update.encryptedData, update.dataIv, update.dataTag, {
        role: 'item.data',
        rowId: EXISTING_ID,
        itemType: 'note',
      }),
    ).rejects.toThrow();
    await expect(
      open(update.encryptedName, update.nameIv, update.nameTag, {
        role: 'item.name',
        rowId: OTHER_ROW_ID,
      }),
    ).rejects.toThrow();
    // A non-login stored type retains no password history.
    expect(update).not.toHaveProperty('passwordHistory');
  });

  it('seals a native overwrite stored data string verbatim to the matched row', async () => {
    const dataJson = '{"username":"octocat",  "password":"rotated"}';
    const existing = existingItem(EXISTING_ID, { username: 'octocat', password: 'old' });
    const built = await buildImportOperations({
      inserts: [],
      updates: [
        {
          incoming: loginRow({
            native: { dataJson },
            data: { username: 'octocat', password: 'rotated' },
          }),
          existing,
        },
      ],
      userId: USER_ID,
      vaultKey,
    });

    const update = built.updates[0]!;
    expect(
      await open(update.encryptedData, update.dataIv, update.dataTag, {
        role: 'item.data',
        rowId: EXISTING_ID,
        itemType: 'login',
      }),
    ).toBe(dataJson);
    const entry = update.passwordHistory![0]!;
    expect(
      await open(entry.encryptedPassword, entry.iv, entry.tag, {
        role: 'item.password-history',
        rowId: EXISTING_ID,
      }),
    ).toBe('old');
  });

  it('omits password history when the password is unchanged', async () => {
    const existing = existingItem(EXISTING_ID, {
      username: 'octocat',
      password: 'same',
    });
    const built = await buildImportOperations({
      inserts: [],
      updates: [
        { incoming: loginRow({ data: { username: 'octocat', password: 'same' } }), existing },
      ],
      userId: USER_ID,
      vaultKey,
    });

    expect(built.updates[0]?.passwordHistory).toBeUndefined();
  });

  it('reports an unsealable UPDATE as a counted failure and emits no operation', async () => {
    const existing = existingItem(EXISTING_ID, { username: 'octocat' });
    const built = await buildImportOperations({
      inserts: [],
      updates: [
        {
          incoming: loginRow({ data: { uris: [{ uri: 'https://x.com', match: 'not-a-match' }] } }),
          existing,
        },
      ],
      userId: USER_ID,
      vaultKey,
    });

    expect(built.updates).toEqual([]);
    expect(built.failedCount).toBe(1);
    // An unsent update must be accounted for, not written off as a no-op.
    expect(built.failureReasons).toHaveLength(1);
  });

  it('reports a row whose ciphertext would exceed the field cap', async () => {
    // 100 custom fields of 50k each all satisfy the schema individually, yet the
    // encrypted payload lands far past MAX_ENCRYPTED_DATA_LENGTH.
    const huge = loginRow({
      name: 'Huge',
      data: {
        username: 'octocat',
        customFields: Array.from({ length: 100 }, (_, i) => ({
          name: `field-${String(i)}`,
          value: 'x'.repeat(50_000),
          type: 'text',
        })),
      },
    });

    const built = await buildImportOperations({
      inserts: [huge],
      updates: [],
      userId: USER_ID,
      vaultKey,
    });

    expect(built.inserts).toEqual([]);
    expect(built.failedCount).toBe(1);
    expect(built.failureReasons[0]).toMatch(/too large/i);
  });

  it('reports an over-large NATIVE row without sending it', async () => {
    // A native row's stored data string is sealed verbatim, skipping schema
    // validation, so the schema's per-field bounds never see it. The ciphertext
    // size guard is what turns a hand-edited export into ONE reported row instead
    // of a server-side 400 that kills the whole batch it rides in. (Premise
    // updated: the row is now re-sealed, so the guard is on ITS ciphertext.)
    const oversized = loginRow({
      name: 'Tampered export row',
      native: { dataJson: 'x'.repeat(MAX_ENCRYPTED_DATA_LENGTH) },
    });

    const built = await buildImportOperations({
      inserts: [oversized, loginRow()],
      updates: [],
      userId: USER_ID,
      vaultKey,
    });

    // The healthy row still goes; only the offending one is withheld.
    expect(built.inserts).toHaveLength(1);
    expect(built.failedCount).toBe(1);
    expect(built.failureReasons[0]).toMatch(/too large/i);
    expect(built.failureReasons[0]).toMatch(/Tampered export row/);
  });

  it('stops collecting failure reasons at MAX_IMPORT_WARNINGS but keeps counting', async () => {
    // The reasons feed a toast description and the caller spreads them
    // UNBOUNDED, so this cap is the only thing standing between a wholly
    // invalid file and a multi-hundred-kilobyte string rendered into the DOM.
    const bad = (i: number): ResolvableImportItem => ({
      itemType: 'card',
      name: `Overlong ${String(i)}`,
      data: { number: '4'.repeat(60) },
      tags: [],
      favorite: false,
    });
    const rows = Array.from({ length: MAX_IMPORT_WARNINGS + 2 }, (_, i) => bad(i));

    const built = await buildImportOperations({
      inserts: rows,
      updates: [],
      userId: USER_ID,
      vaultKey,
    });

    expect(built.failedCount).toBe(MAX_IMPORT_WARNINGS + 2);
    expect(built.failureReasons).toHaveLength(MAX_IMPORT_WARNINGS);
  });

  it('reports an unsealable row as a counted failure rather than dropping it silently', async () => {
    // A card number far past its schema cap fails validation for the whole item.
    const bad: ResolvableImportItem = {
      itemType: 'card',
      name: 'Overlong',
      data: { number: '4'.repeat(60) },
      tags: [],
      favorite: false,
    };
    const built = await buildImportOperations({
      inserts: [bad, loginRow()],
      updates: [],
      userId: USER_ID,
      vaultKey,
    });

    expect(built.inserts).toHaveLength(1);
    expect(built.failedCount).toBe(1);
    expect(built.failureReasons[0]).toMatch(/Overlong/);
  });
});

describe('assertInsertedWhereSealed', () => {
  // Fixed nonces (deterministic), each 40 lower-case hex characters.
  const NONCE_A = `65000000${'a'.repeat(32)}`;
  const NONCE_B = `65000001${'b'.repeat(32)}`;
  const REFUSAL = /stored imported entries under unexpected ids/;

  const sealedInsert = (idNonce?: string): ImportInsertItem => ({
    itemType: 'note',
    encryptedName: 'en',
    nameIv: 'v2:ni',
    nameTag: 'nt',
    encryptedData: 'ed',
    dataIv: 'v2:di',
    dataTag: 'dt',
    searchHash: 'a'.repeat(64),
    tags: [],
    favorite: false,
    ...(idNonce !== undefined ? { idNonce } : {}),
  });

  it('accepts ids that match, in insert order, the ids each nonce derives', async () => {
    const inserts = [sealedInsert(NONCE_A), sealedInsert(NONCE_B)];
    const ids = [await deriveRowId(USER_ID, NONCE_A), await deriveRowId(USER_ID, NONCE_B)];
    await expect(assertInsertedWhereSealed(USER_ID, inserts, ids)).resolves.toBeUndefined();
    // The server may spell an id in upper case; it is the same id.
    await expect(
      assertInsertedWhereSealed(
        USER_ID,
        inserts,
        ids.map((id) => id.toUpperCase()),
      ),
    ).resolves.toBeUndefined();
  });

  it('refuses the right ids in the wrong order', async () => {
    const inserts = [sealedInsert(NONCE_A), sealedInsert(NONCE_B)];
    const ids = [await deriveRowId(USER_ID, NONCE_B), await deriveRowId(USER_ID, NONCE_A)];
    await expect(assertInsertedWhereSealed(USER_ID, inserts, ids)).rejects.toThrow(REFUSAL);
  });

  it('refuses ids derived for another user', async () => {
    const otherUser = '64b7f0c2a1d3e4f5a6b7c8da';
    const inserts = [sealedInsert(NONCE_A)];
    await expect(
      assertInsertedWhereSealed(USER_ID, inserts, [await deriveRowId(otherUser, NONCE_A)]),
    ).rejects.toThrow(REFUSAL);
  });

  it('refuses a response with no insertedIds at all (a server that ignored the nonce)', async () => {
    await expect(
      assertInsertedWhereSealed(USER_ID, [sealedInsert(NONCE_A)], undefined),
    ).rejects.toThrow(REFUSAL);
  });

  it('refuses a length mismatch in either direction', async () => {
    const idA = await deriveRowId(USER_ID, NONCE_A);
    const idB = await deriveRowId(USER_ID, NONCE_B);
    // Fewer ids than inserts, even when every id given is correct.
    await expect(
      assertInsertedWhereSealed(USER_ID, [sealedInsert(NONCE_A), sealedInsert(NONCE_B)], [idA]),
    ).rejects.toThrow(REFUSAL);
    // More ids than inserts.
    await expect(
      assertInsertedWhereSealed(USER_ID, [sealedInsert(NONCE_A)], [idA, idB]),
    ).rejects.toThrow(REFUSAL);
    // No inserts and no ids is a match, not a refusal.
    await expect(assertInsertedWhereSealed(USER_ID, [], [])).resolves.toBeUndefined();
  });

  it('checks nothing at the position of an insert without a nonce, but still its length', async () => {
    const idB = await deriveRowId(USER_ID, NONCE_B);
    const inserts = [sealedInsert(), sealedInsert(NONCE_B)];
    // Any id where no nonce was sent: there is no derived id to compare it with.
    await expect(
      assertInsertedWhereSealed(USER_ID, inserts, ['507f1f77bcf86cd799439011', idB]),
    ).resolves.toBeUndefined();
    // The nonce-carrying neighbour is still checked…
    await expect(
      assertInsertedWhereSealed(USER_ID, inserts, [idB, '507f1f77bcf86cd799439011']),
    ).rejects.toThrow(REFUSAL);
    // …and a missing position is still a mismatch.
    await expect(assertInsertedWhereSealed(USER_ID, inserts, [idB])).rejects.toThrow(REFUSAL);
  });

  it('accepts the ids an actual built batch derives, and refuses them for a swapped batch', async () => {
    const built = await buildImportOperations({
      inserts: [loginRow({ name: 'One' }), loginRow({ name: 'Two' })],
      updates: [],
      userId: USER_ID,
      vaultKey,
    });
    const ids = await Promise.all(
      built.inserts.map((insert) => deriveRowId(USER_ID, insert.idNonce!)),
    );
    await expect(assertInsertedWhereSealed(USER_ID, built.inserts, ids)).resolves.toBeUndefined();
    await expect(
      assertInsertedWhereSealed(USER_ID, built.inserts, [...ids].reverse()),
    ).rejects.toThrow(REFUSAL);
  });
});

describe('chunkImportOperations', () => {
  const insert = (n: number): ImportInsertItem => ({
    itemType: 'login',
    encryptedName: `en${String(n)}`,
    nameIv: 'ni',
    nameTag: 'nt',
    encryptedData: `ed${String(n)}`,
    dataIv: 'di',
    dataTag: 'dt',
    searchHash: 'a'.repeat(64),
    tags: [],
    favorite: false,
  });

  const update = (n: number): ImportUpdateItem => ({
    id: '507f1f77bcf86cd7994390'.padEnd(22, '0') + String(n).padStart(2, '0'),
    encryptedName: `uen${String(n)}`,
    nameIv: 'ni',
    nameTag: 'nt',
    encryptedData: `ued${String(n)}`,
    dataIv: 'di',
    dataTag: 'dt',
    searchHash: 'b'.repeat(64),
  });

  it('keeps everything in one batch when it fits', () => {
    const batches = chunkImportOperations([insert(1), insert(2)], [update(1)]);
    expect(batches).toHaveLength(1);
    expect(batches[0]?.inserts).toHaveLength(2);
    expect(batches[0]?.updates).toHaveLength(1);
  });

  it('sends every operation exactly once, in order, however it is split', () => {
    const inserts = Array.from({ length: 7 }, (_, i) => insert(i));
    const updates = Array.from({ length: 5 }, (_, i) => update(i));

    for (const maxCount of [1, 2, 3, 5, 12, 100]) {
      const batches = chunkImportOperations(inserts, updates, IMPORT_BATCH_MAX_BYTES, maxCount);
      expect(batches.flatMap((b) => b.inserts)).toEqual(inserts);
      expect(batches.flatMap((b) => b.updates)).toEqual(updates);
    }
  });

  it('splits on the byte budget as well as the count', () => {
    const inserts = Array.from({ length: 4 }, (_, i) => insert(i));
    // Each serialized operation is well over 40 bytes, so the budget alone forces
    // one operation per request.
    const batches = chunkImportOperations(inserts, [], 40);
    expect(batches).toHaveLength(4);
    expect(batches.flatMap((b) => b.inserts)).toEqual(inserts);
  });

  it('produces no batches when there is nothing to send', () => {
    expect(chunkImportOperations([], [])).toEqual([]);
  });
});
