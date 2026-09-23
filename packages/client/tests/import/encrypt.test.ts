// @vitest-environment node
import { describe, it, expect, beforeAll } from 'vitest';
import { deriveRowId } from '@hvault/shared';
import {
  MAX_IMPORT_WARNINGS,
  buildImportOperations,
  parseImportData,
  validateImportItems,
} from '../../src/services/import';
import type { ParsedImportItem } from '../../src/services/import';
import { cryptoService } from '../../src/services/crypto/cryptoService';
import { decryptVaultField } from '../../src/services/crypto/vaultField';
import { sealImportItem } from '../../src/services/import/encrypt';

let vaultKey: CryptoKey;

/** This session's user id, which every insert's row id is derived from (an ObjectId). */
const USER_ID = '64b7f0c2a1d3e4f5a6b7c8d9';
/** An existing row an overwrite is sealed to, and a different row of the same vault. */
const ROW_ID = '507f1f77bcf86cd799439011';
const OTHER_ROW_ID = '507f1f77bcf86cd799439012';

beforeAll(async () => {
  vaultKey = await globalThis.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ]);
});

describe('buildImportOperations — validate + encrypt', () => {
  it('encrypts valid items (all six ciphertext fields + searchHash) and round-trips', async () => {
    const parsed: ParsedImportItem[] = [
      {
        itemType: 'login',
        name: 'GitHub',
        data: {
          username: 'octocat',
          password: 'hunter2',
          uris: [{ uri: 'https://github.com', match: 'domain' }],
        },
        tags: ['Work'],
        favorite: true,
      },
    ];
    const { inserts: items, failedCount: skipped } = await buildImportOperations({
      inserts: parsed,
      updates: [],
      userId: USER_ID,
      vaultKey,
    });
    expect(skipped).toBe(0);
    expect(items).toHaveLength(1);
    const item = items[0]!;
    for (const f of [
      'encryptedName',
      'nameIv',
      'nameTag',
      'encryptedData',
      'dataIv',
      'dataTag',
    ] as const) {
      expect(item[f].length).toBeGreaterThan(0);
    }
    expect(item.searchHash).toMatch(/^[a-f0-9]{64}$/);
    expect(item.tags).toEqual(['Work']);
    expect(item.favorite).toBe(true);

    // Sealed in format v2 to the row the server will store it as: the id derived
    // from the nonce the insert is sent with and this user's id.
    expect(item.idNonce).toMatch(/^[0-9a-f]{40}$/);
    expect(item.nameIv.startsWith('v2:')).toBe(true);
    expect(item.dataIv.startsWith('v2:')).toBe(true);
    const rowId = await deriveRowId(USER_ID, item.idNonce!);

    const name = await decryptVaultField(
      { encrypted: item.encryptedName, iv: item.nameIv, tag: item.nameTag },
      { role: 'item.name', rowId },
      vaultKey,
    );
    expect(name).toBe('GitHub');
    const dataField = { encrypted: item.encryptedData, iv: item.dataIv, tag: item.dataTag };
    const data = JSON.parse(
      await decryptVaultField(dataField, { role: 'item.data', rowId, itemType: 'login' }, vaultKey),
    ) as { username: string; uris: { uri: string }[] };
    expect(data.username).toBe('octocat');
    expect(data.uris[0]?.uri).toBe('https://github.com');

    // …and nowhere else: not under another row, not under another item type.
    await expect(
      decryptVaultField(
        dataField,
        { role: 'item.data', rowId: OTHER_ROW_ID, itemType: 'login' },
        vaultKey,
      ),
    ).rejects.toThrow();
    await expect(
      decryptVaultField(dataField, { role: 'item.data', rowId, itemType: 'note' }, vaultKey),
    ).rejects.toThrow();
  });

  it('refuses to seal an insert for a user id that is not an ObjectId', async () => {
    // The insert's id is derived from the user id, so one that cannot be an id
    // cannot name the row the fields would be sealed to.
    const parsed: ParsedImportItem[] = [
      { itemType: 'note', name: 'n', data: { content: 'x' }, tags: [], favorite: false },
    ];
    await expect(
      buildImportOperations({ inserts: parsed, updates: [], userId: 'user-1', vaultKey }),
    ).rejects.toThrow('A row id is derived from an ObjectId user id');
  });

  it('gives every insert its own nonce and therefore its own row', async () => {
    const parsed: ParsedImportItem[] = [
      { itemType: 'note', name: 'Same', data: { content: 'x' }, tags: [], favorite: false },
      { itemType: 'note', name: 'Same', data: { content: 'x' }, tags: [], favorite: false },
    ];
    const { inserts } = await buildImportOperations({
      inserts: parsed,
      updates: [],
      userId: USER_ID,
      vaultKey,
    });
    expect(inserts).toHaveLength(2);
    expect(inserts[0]!.idNonce).not.toBe(inserts[1]!.idNonce);
    // The second row's name is sealed to the second row, not the first.
    const firstRow = await deriveRowId(USER_ID, inserts[0]!.idNonce!);
    const second = inserts[1]!;
    await expect(
      decryptVaultField(
        { encrypted: second.encryptedName, iv: second.nameIv, tag: second.nameTag },
        { role: 'item.name', rowId: firstRow },
        vaultKey,
      ),
    ).rejects.toThrow();
  });

  it('skips items whose data fails schema validation and counts them', async () => {
    const parsed: ParsedImportItem[] = [
      { itemType: 'login', name: 'ok', data: { username: 'a' }, tags: [], favorite: false },
      {
        itemType: 'login',
        name: 'bad',
        data: { uris: [{ uri: 'https://x.com', match: 'not-a-match' }] },
        tags: [],
        favorite: false,
      },
    ];
    const {
      inserts: items,
      failedCount: skipped,
      failureReasons: warnings,
    } = await buildImportOperations({ inserts: parsed, updates: [], userId: USER_ID, vaultKey });
    expect(items).toHaveLength(1);
    expect(skipped).toBe(1);
    expect(warnings).toHaveLength(1);
  });

  it('validateImportItems keeps the transformed data and caps its warning list', () => {
    // The parse-time counterpart of the seal-time cap. Its warnings are spread
    // UNBOUNDED into the import report, so this bound is the only thing keeping
    // a wholly invalid file from building an enormous toast description.
    const good = (i: number): ParsedImportItem => ({
      itemType: 'login',
      name: `ok-${String(i)}`,
      // Deliberately raw: the survivor's data must come back schema-TRANSFORMED
      // (bare domain normalized, defaults filled), which is what makes a
      // re-import of the same file hash identically and stay a no-op.
      data: { username: 'a', uris: [{ uri: 'github.com', match: 'domain' }] },
      tags: [],
      favorite: false,
    });
    const bad = (i: number): ParsedImportItem => ({
      itemType: 'login',
      name: `bad-${String(i)}`,
      data: { uris: [{ uri: 'https://x.com', match: 'not-a-match' }] },
      tags: [],
      favorite: false,
    });

    const result = validateImportItems([
      good(0),
      ...Array.from({ length: MAX_IMPORT_WARNINGS + 2 }, (_, i) => bad(i)),
    ]);

    expect(result.items).toHaveLength(1);
    expect(result.items[0]?.data).toMatchObject({
      username: 'a',
      uris: [{ uri: 'https://github.com', match: 'domain' }],
    });
    expect(result.skipped).toBe(MAX_IMPORT_WARNINGS + 2);
    expect(result.warnings).toHaveLength(MAX_IMPORT_WARNINGS);

    // Each warning must NAME the item and the failing field, not just count.
    // These strings are spread verbatim into the import toast, and a count on
    // its own ("3 could not be converted") leaves the user unable to tell which
    // entry was lost or why — and re-running the import cannot reveal it, since
    // the same rows are skipped again just as silently. This is the assertion
    // that keeps that promise; it is made here rather than at the SettingsPage,
    // because after the import scalars were clamped no PARSER can produce an
    // item this function rejects, so a UI-level test would need a defect
    // elsewhere in order to reach the message at all.
    expect(result.warnings[0]).toContain('bad-0');
    expect(result.warnings[0]).toMatch(/uris\.0\.match/);
    // And it never names a survivor: a warning list that mentioned `ok-0` would
    // send the user looking for an item that imported perfectly well.
    for (const warning of result.warnings) expect(warning).not.toContain('ok-');
  });

  it('skips an item whose data is not an object at all (root-level validation error)', async () => {
    const parsed = [
      {
        itemType: 'login' as const,
        name: 'bad',
        data: 'i-am-a-string' as unknown as Record<string, unknown>,
        tags: [],
        favorite: false,
      },
    ];
    const {
      inserts: items,
      failedCount: skipped,
      failureReasons: warnings,
    } = await buildImportOperations({ inserts: parsed, updates: [], userId: USER_ID, vaultKey });
    expect(items).toHaveLength(0);
    expect(skipped).toBe(1);
    expect(warnings[0]).toContain('bad');
  });

  it('produces a deterministic search hash for the same name', async () => {
    const parsed: ParsedImportItem[] = [
      { itemType: 'note', name: 'Same', data: { content: 'x' }, tags: [], favorite: false },
    ];
    const a = await buildImportOperations({
      inserts: parsed,
      updates: [],
      userId: USER_ID,
      vaultKey,
    });
    const b = await buildImportOperations({
      inserts: parsed,
      updates: [],
      userId: USER_ID,
      vaultKey,
    });
    expect(a.inserts[0]!.searchHash).toBe(b.inserts[0]!.searchHash);
  });

  it('keeps a Bitwarden identity whose source email/phone fail the shared schema', async () => {
    // End-to-end of the parse→validate→encrypt path: the parser folds the
    // schema-invalid email/phone into notes, so the identity survives instead of
    // being skipped wholesale (which would lose name, address, passport, …).
    const bw = JSON.stringify({
      items: [
        {
          type: 4,
          name: 'Weird Identity',
          identity: {
            firstName: 'A',
            lastName: 'B',
            passportNumber: 'X1',
            email: 'a@b..c',
            phone: '+1 555 CALL-NOW',
          },
        },
      ],
    });
    const { items: parsed } = parseImportData('bitwarden', bw);
    const { inserts: items, failedCount: skipped } = await buildImportOperations({
      inserts: parsed,
      updates: [],
      userId: USER_ID,
      vaultKey,
    });
    expect(skipped).toBe(0);
    expect(items).toHaveLength(1);
    expect(items[0]?.itemType).toBe('identity');
  });

  it('never emits plaintext: ciphertext differs from the source name/data', async () => {
    const parsed: ParsedImportItem[] = [
      {
        itemType: 'login',
        name: 'PlaintextName',
        data: { password: 'PlaintextSecret' },
        tags: [],
        favorite: false,
      },
    ];
    const { inserts: items } = await buildImportOperations({
      inserts: parsed,
      updates: [],
      userId: USER_ID,
      vaultKey,
    });
    const item = items[0]!;
    expect(item.encryptedName).not.toContain('PlaintextName');
    expect(item.encryptedData).not.toContain('PlaintextSecret');
  });
});

describe('sealImportItem — sealing to a destination', () => {
  const note: ParsedImportItem = {
    itemType: 'note',
    name: 'Recovery kit',
    data: { content: 'keep me' },
    tags: [],
    favorite: false,
  };

  it('seals the name and data to exactly the destination row and type it is given', async () => {
    const result = await sealImportItem(note, { rowId: ROW_ID, itemType: 'note' }, vaultKey);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const { sealed } = result;

    expect(
      await decryptVaultField(
        { encrypted: sealed.encryptedName, iv: sealed.nameIv, tag: sealed.nameTag },
        { role: 'item.name', rowId: ROW_ID },
        vaultKey,
      ),
    ).toBe('Recovery kit');
    const dataField = { encrypted: sealed.encryptedData, iv: sealed.dataIv, tag: sealed.dataTag };
    expect(
      JSON.parse(
        await decryptVaultField(
          dataField,
          { role: 'item.data', rowId: ROW_ID, itemType: 'note' },
          vaultKey,
        ),
      ),
    ).toMatchObject({ content: 'keep me' });
    await expect(
      decryptVaultField(
        { encrypted: sealed.encryptedName, iv: sealed.nameIv, tag: sealed.nameTag },
        { role: 'item.name', rowId: OTHER_ROW_ID },
        vaultKey,
      ),
    ).rejects.toThrow();
    expect(sealed.searchHash).toBe(
      await cryptoService.generateSearchHash('Recovery kit', vaultKey),
    );
  });

  it('binds the data to the DESTINATION type, not the one the parsed row claims', async () => {
    // An overwrite passes the matched row's STORED type, which is the type the
    // data is read under from then on.
    const result = await sealImportItem(note, { rowId: ROW_ID, itemType: 'secret' }, vaultKey);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const dataField = {
      encrypted: result.sealed.encryptedData,
      iv: result.sealed.dataIv,
      tag: result.sealed.dataTag,
    };
    await expect(
      decryptVaultField(
        dataField,
        { role: 'item.data', rowId: ROW_ID, itemType: 'secret' },
        vaultKey,
      ),
    ).resolves.toContain('keep me');
    await expect(
      decryptVaultField(
        dataField,
        { role: 'item.data', rowId: ROW_ID, itemType: 'note' },
        vaultKey,
      ),
    ).rejects.toThrow();
  });

  it('throws rather than producing ciphertext for a destination that is not an ObjectId', async () => {
    await expect(
      sealImportItem(note, { rowId: 'row-1', itemType: 'note' }, vaultKey),
    ).rejects.toThrow('A vault field is bound to an ObjectId row id');
  });
});
