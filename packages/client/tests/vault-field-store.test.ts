/**
 * The vault's read path, over REAL AES-GCM, against a server that places bytes.
 *
 * Every other store suite mocks `cryptoService`, which is right for what they
 * test and useless for this: whether a ciphertext opens depends on the exact
 * bytes AES-GCM authenticates, and a mock authenticates nothing. So this file
 * seals real rows under a real key and hands them to `decryptExportResponse`,
 * which runs the same private `decryptItem`/`decryptFolder` every list fetch,
 * trash fetch and post-write refresh runs.
 *
 * The threat is a server that cannot read a byte and does not need to: it only
 * has to put genuine ciphertext in the wrong place. Format v1 cannot tell, which
 * is the residual these cases record rather than hide; format v2 names its row,
 * its field and (for the data) its item type inside the authenticated bytes.
 */
import { describe, expect, it, vi } from 'vitest';
import type { ExportResponse, IFolderResponse, IVaultItemResponse, ItemType } from '@hvault/shared';

vi.mock('../src/stores/encryptedStorage', () => ({
  encryptedStorage: {
    getItem: vi.fn().mockResolvedValue(null),
    setItem: vi.fn().mockResolvedValue(undefined),
    removeItem: vi.fn(),
  },
  isStorageDegraded: () => false,
}));

import { decryptExportResponse } from '../src/stores/vaultStore';
import { cryptoService } from '../src/services/crypto/cryptoService';
import { isUndecodableData } from '../src/lib/vaultData';
import { freshVaultKey, sealV2, specAad, type StoredTriple } from './support/vaultFieldSealer';

const BANK_ID = '66c0f1a2b3c4d5e6f7a8b9c0';
const FORUM_ID = '66c0f1a2b3c4d5e6f7a8b9c1';
const FOLDER_ID = '66c0f1a2b3c4d5e6f7a8b9c2';

const BANK_DATA = { username: 'alice', password: 'bank-secret' };
const FORUM_DATA = { username: 'alice', password: 'forum-secret' };

function itemRow(
  id: string,
  itemType: ItemType,
  name: StoredTriple,
  data: StoredTriple,
): IVaultItemResponse {
  return {
    _id: id,
    itemType,
    tags: [],
    favorite: false,
    encryptedName: name.encrypted,
    nameIv: name.iv,
    nameTag: name.tag,
    encryptedData: data.encrypted,
    dataIv: data.iv,
    dataTag: data.tag,
    createdAt: '2026-09-23T00:00:00.000Z',
    updatedAt: '2026-09-23T00:00:00.000Z',
  };
}

function folderRow(id: string, name: StoredTriple): IFolderResponse {
  return {
    _id: id,
    encryptedName: name.encrypted,
    nameIv: name.iv,
    nameTag: name.tag,
    sortOrder: 0,
    createdAt: '2026-09-23T00:00:00.000Z',
    updatedAt: '2026-09-23T00:00:00.000Z',
  };
}

function response(items: IVaultItemResponse[], folders: IFolderResponse[] = []): ExportResponse {
  return {
    items,
    folders,
    metadata: { exportDate: '2026-09-23T00:00:00.000Z', version: 'test', itemCount: items.length },
  };
}

async function v1(key: CryptoKey, plaintext: string): Promise<StoredTriple> {
  return cryptoService.encryptData(plaintext, key);
}

/** The two v2 rows most cases start from, each bound to its own id. */
async function boundPair(key: CryptoKey) {
  return {
    bankName: await sealV2(key, 'Bank', specAad('item.name', BANK_ID)),
    bankData: await sealV2(key, JSON.stringify(BANK_DATA), specAad('item.data', BANK_ID, 'login')),
    forumName: await sealV2(key, 'Forum', specAad('item.name', FORUM_ID)),
    forumData: await sealV2(
      key,
      JSON.stringify(FORUM_DATA),
      specAad('item.data', FORUM_ID, 'login'),
    ),
  };
}

describe('the vault read path opens format-v2 rows where they belong', () => {
  it('opens a bound row served under its own id, to the exact name and data', async () => {
    const key = await freshVaultKey();
    const { bankName, bankData } = await boundPair(key);

    const { items } = await decryptExportResponse(
      response([itemRow(BANK_ID, 'login', bankName, bankData)]),
      key,
    );

    expect(items).toHaveLength(1);
    expect(items[0]!.name).toBe('Bank');
    expect(items[0]!.data).toMatchObject(BANK_DATA);
    expect(isUndecodableData(items[0]!.data)).toBe(false);
  });

  it('opens a bound folder name served under its own id', async () => {
    const key = await freshVaultKey();
    const name = await sealV2(key, 'Finance', specAad('folder.name', FOLDER_ID));

    const { folders } = await decryptExportResponse(
      response([], [folderRow(FOLDER_ID, name)]),
      key,
    );

    expect(folders.map((f) => [f.id, f.name])).toEqual([[FOLDER_ID, 'Finance']]);
  });

  it('opens a bound row whose id the server spells in upper case, the same id', async () => {
    // ObjectIds are case-insensitive hex and `objectIdSchema` lower-cases them, so
    // the binding does too; refusing here would let a server break a row it
    // cannot otherwise touch just by re-spelling its id.
    const key = await freshVaultKey();
    const { bankName, bankData } = await boundPair(key);

    const { items } = await decryptExportResponse(
      response([itemRow(BANK_ID.toUpperCase(), 'login', bankName, bankData)]),
      key,
    );

    expect(items[0]!.name).toBe('Bank');
    expect(isUndecodableData(items[0]!.data)).toBe(false);
  });

  it('degrades a bound row whose data is not JSON to the raw placeholder, not a throw', async () => {
    const key = await freshVaultKey();
    const name = await sealV2(key, 'Bank', specAad('item.name', BANK_ID));
    const data = await sealV2(key, 'not json {', specAad('item.data', BANK_ID, 'login'));

    const { items } = await decryptExportResponse(
      response([itemRow(BANK_ID, 'login', name, data)]),
      key,
    );

    expect(items[0]!.name).toBe('Bank');
    expect(items[0]!.data).toEqual({ _raw: 'not json {' });
    expect(isUndecodableData(items[0]!.data)).toBe(true);
  });
});

describe('the vault read path refuses format-v2 bytes a server moved', () => {
  it('does not show one row’s data under another row when the server swaps them', async () => {
    const key = await freshVaultKey();
    const { bankName, bankData, forumName, forumData } = await boundPair(key);

    // The substitution the format exists to stop: the screen says "Forum", the
    // clipboard would get the bank password.
    const { items } = await decryptExportResponse(
      response([
        itemRow(BANK_ID, 'login', bankName, forumData),
        itemRow(FORUM_ID, 'login', forumName, bankData),
      ]),
      key,
    );

    expect(items).toHaveLength(2);
    for (const item of items) {
      expect(isUndecodableData(item.data), item.id).toBe(true);
      expect(JSON.stringify(item.data), item.id).not.toContain('secret');
    }
  });

  it('does not show one row’s NAME under another row', async () => {
    const key = await freshVaultKey();
    const { forumName, bankData } = await boundPair(key);

    const { items } = await decryptExportResponse(
      response([itemRow(BANK_ID, 'login', forumName, bankData)]),
      key,
    );

    // All-or-nothing per row: the store never shows half of one.
    expect(items[0]!.name).toBe('');
    expect(items[0]!.name).not.toBe('Forum');
    expect(isUndecodableData(items[0]!.data)).toBe(true);
  });

  it('does not open a row’s data triple placed in its own NAME slot', async () => {
    const key = await freshVaultKey();
    const { bankData } = await boundPair(key);

    const { items } = await decryptExportResponse(
      response([itemRow(BANK_ID, 'login', bankData, bankData)]),
      key,
    );

    expect(items[0]!.name).toBe('');
    expect(isUndecodableData(items[0]!.data)).toBe(true);
    expect(JSON.stringify(items[0])).not.toContain('bank-secret');
  });

  it('does not read a login’s data under another item type the server stamped on the row', async () => {
    // Every data schema is all-optional and strips, so a login read as a note
    // PARSES, loses its password and carries no validation flag: the next save
    // would write the stripped copy back. Bound, it does not open at all.
    const key = await freshVaultKey();
    const { bankName, bankData } = await boundPair(key);

    const { items } = await decryptExportResponse(
      response([itemRow(BANK_ID, 'note', bankName, bankData)]),
      key,
    );

    expect(isUndecodableData(items[0]!.data)).toBe(true);
    expect(items[0]!.data).not.toHaveProperty('content');
    expect(JSON.stringify(items[0]!.data)).not.toContain('bank-secret');
  });

  it('drops a folder name the server moved onto another folder', async () => {
    const key = await freshVaultKey();
    const name = await sealV2(key, 'Finance', specAad('folder.name', FOLDER_ID));

    const { folders } = await decryptExportResponse(response([], [folderRow(BANK_ID, name)]), key);

    expect(folders).toEqual([]);
  });

  it('does not open an item name the server moved onto a folder with the same id', async () => {
    // The role, not only the id, is bound: an id shared across two collections
    // still cannot carry one collection's bytes into the other.
    const key = await freshVaultKey();
    const { bankName } = await boundPair(key);

    const { folders } = await decryptExportResponse(
      response([], [folderRow(BANK_ID, bankName)]),
      key,
    );

    expect(folders).toEqual([]);
  });

  it('does not open a bound field whose marker the server stripped', async () => {
    const key = await freshVaultKey();
    const { bankName, bankData } = await boundPair(key);
    const stripped = { ...bankData, iv: bankData.iv.slice('v2:'.length) };

    const { items } = await decryptExportResponse(
      response([itemRow(BANK_ID, 'login', bankName, stripped)]),
      key,
    );

    expect(isUndecodableData(items[0]!.data)).toBe(true);
  });

  it('degrades a bound row with an id no binding can name, without failing the export', async () => {
    const key = await freshVaultKey();
    const { bankName, bankData, forumName, forumData } = await boundPair(key);

    const { items } = await decryptExportResponse(
      response([
        itemRow('not-an-object-id', 'login', bankName, bankData),
        itemRow(FORUM_ID, 'login', forumName, forumData),
      ]),
      key,
    );

    expect(isUndecodableData(items[0]!.data)).toBe(true);
    // The neighbour is untouched: one unreadable row costs nothing else.
    expect(items[1]!.name).toBe('Forum');
    expect(items[1]!.data).toMatchObject(FORUM_DATA);
  });
});

describe('the vault read path keeps reading format v1 exactly as before', () => {
  it('opens an unbound row, whatever its id looks like', async () => {
    const key = await freshVaultKey();

    const { items } = await decryptExportResponse(
      response([
        itemRow(
          'legacy-id-no-binding-needed',
          'login',
          await v1(key, 'Bank'),
          await v1(key, JSON.stringify(BANK_DATA)),
        ),
      ]),
      key,
    );

    expect(items[0]!.name).toBe('Bank');
    expect(items[0]!.data).toMatchObject(BANK_DATA);
  });

  it('still opens unbound triples a server swapped: the v1 residual, recorded', async () => {
    // This is the gap v2 closes for v2 fields and v1 cannot: a v1 triple carries no binding, so
    // it opens wherever it is placed, for as long as v1 is read at all, even after
    // its own row has been rewritten as v2 (the server may keep the old triple).
    // Dual-read keeps it that way on purpose; the assertion is here so that
    // changes to the v1 path are visible, not because this outcome is desirable.
    const key = await freshVaultKey();
    const bankData = await v1(key, JSON.stringify(BANK_DATA));

    const { items } = await decryptExportResponse(
      response([itemRow(FORUM_ID, 'login', await v1(key, 'Forum'), bankData)]),
      key,
    );

    expect(items[0]!.name).toBe('Forum');
    expect(items[0]!.data).toMatchObject(BANK_DATA);
  });
});
