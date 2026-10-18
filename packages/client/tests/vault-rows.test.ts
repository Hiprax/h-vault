/**
 * The one row reader shared by the vault-key rotation and the unreadable-entry
 * check, and the classifier a deletion is allowed to act on.
 *
 * The classifier runs on REAL WebCrypto, with rows sealed exactly as the app seals
 * them (format v1 and v2), because its whole job is to tell an AES-GCM refusal
 * from every other way a field can fail to open: a row is offered for deletion
 * only when every field it reads is REFUSED under every candidate key, and a
 * wrongly lenient verdict deletes an entry the user could still open.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { DocumentResponse, IFolderResponse, IVaultItemResponse } from '@hvault/shared';

const mockListItems = vi.fn();
const mockListTrash = vi.fn();
const mockListFolders = vi.fn();
const mockListDocuments = vi.fn();
const mockListDocumentTrash = vi.fn();

vi.mock('../src/services/api/vaultApi', () => ({
  listItemsApi: (...args: unknown[]) => mockListItems(...args) as unknown,
  listTrashApi: (...args: unknown[]) => mockListTrash(...args) as unknown,
  listFoldersApi: (...args: unknown[]) => mockListFolders(...args) as unknown,
}));

vi.mock('../src/services/api/documentsApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../src/services/api/documentsApi')>()),
  listDocumentsApi: (...args: unknown[]) => mockListDocuments(...args) as unknown,
  listDocumentTrashApi: (...args: unknown[]) => mockListDocumentTrash(...args) as unknown,
}));

import { cryptoService } from '../src/services/crypto/cryptoService';
import { encryptVaultField } from '../src/services/crypto/vaultField';
import { deriveWrapKey, wrapDek } from '../src/services/crypto/documentCryptoService';
import { MAX_DOCUMENT_PAGES } from '../src/services/api/documentsApi';
import {
  classifyFolder,
  classifyItem,
  decryptFolderNameUnderAnyKey,
  decryptItemUnderAnyKey,
  describeRowCounts,
  describeSkippedRows,
  enumerateAllDocumentRows,
  enumerateItemRows,
  enumerateRows,
  isAuthenticationFailure,
  listAllFolderRows,
  unwrapDekUnderAnyKey,
} from '../src/services/vault/vaultRows';

const ITEM_ID = '66c0f1a2b3c4d5e6f7a8b9c0';
const FOLDER_ID = '66c0f1a2b3c4d5e6f7a8b9c1';
const DOCUMENT_ID = '66c0f1a2b3c4d5e6f7a8b9c2';

/** A real AES-256-GCM vault key whose 32 bytes are all `fill`. */
function vaultKey(fill: number): Promise<CryptoKey> {
  return cryptoService.importVaultKey(new Uint8Array(32).fill(fill).buffer);
}

type Format = 'v1' | 'v2';

async function sealName(plaintext: string, key: CryptoKey, format: Format, rowId = ITEM_ID) {
  return format === 'v2'
    ? encryptVaultField(plaintext, { role: 'item.name', rowId }, key)
    : cryptoService.encryptData(plaintext, key);
}

async function sealData(plaintext: string, key: CryptoKey, format: Format, rowId = ITEM_ID) {
  return format === 'v2'
    ? encryptVaultField(plaintext, { role: 'item.data', rowId, itemType: 'login' }, key)
    : cryptoService.encryptData(plaintext, key);
}

/** A stored login, its name sealed under `nameKey` and its data under `dataKey`. */
async function itemRow(
  nameKey: CryptoKey,
  dataKey: CryptoKey = nameKey,
  format: Format = 'v2',
  overrides: Partial<IVaultItemResponse> = {},
): Promise<IVaultItemResponse> {
  const name = await sealName('Bank', nameKey, format);
  const data = await sealData('{"username":"ada"}', dataKey, format);
  return {
    _id: ITEM_ID,
    itemType: 'login',
    tags: [],
    favorite: false,
    encryptedName: name.encrypted,
    nameIv: name.iv,
    nameTag: name.tag,
    encryptedData: data.encrypted,
    dataIv: data.iv,
    dataTag: data.tag,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
    ...overrides,
  };
}

async function folderRow(
  key: CryptoKey,
  format: Format = 'v2',
  overrides: Partial<IFolderResponse> = {},
): Promise<IFolderResponse> {
  const name =
    format === 'v2'
      ? await encryptVaultField('Work', { role: 'folder.name', rowId: FOLDER_ID }, key)
      : await cryptoService.encryptData('Work', key);
  return {
    _id: FOLDER_ID,
    encryptedName: name.encrypted,
    nameIv: name.iv,
    nameTag: name.tag,
    sortOrder: 0,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
    ...overrides,
  };
}

/** One page of a paginated list, as the wire answers it. */
function page<T>(data: T[], totalPages: number) {
  return {
    data: { success: true, data, pagination: { page: 1, limit: 200, total: 0, totalPages } },
  };
}

let live: CryptoKey;
let earlier: CryptoKey;
let stranger: CryptoKey;

beforeEach(async () => {
  vi.clearAllMocks();
  live = await vaultKey(0x11);
  earlier = await vaultKey(0x22);
  stranger = await vaultKey(0x33);
});

describe('classifyItem: the verdict a deletion may act on', () => {
  for (const format of ['v1', 'v2'] as const) {
    it(`calls a ${format} row readable when its name and data open under one candidate`, async () => {
      expect(await classifyItem(await itemRow(live, live, format), [live])).toBe('readable');
    });

    it(`calls a ${format} row unreadable only when both fields are REFUSED under every candidate`, async () => {
      const row = await itemRow(stranger, stranger, format);
      expect(await classifyItem(row, [live, earlier])).toBe('unreadable');
    });

    it(`calls a ${format} row readable when only a LATER candidate opens it`, async () => {
      expect(await classifyItem(await itemRow(earlier, earlier, format), [live, earlier])).toBe(
        'readable',
      );
    });
  }

  it('calls a row damaged, never unreadable, when its name opens but its data does not', async () => {
    // The two halves under different keys: no key opens the row, yet part of it
    // opens, so it is not "sealed under a key this account lost" and is not deletable.
    expect(await classifyItem(await itemRow(live, stranger), [live])).toBe('damaged');
    expect(await classifyItem(await itemRow(stranger, live), [live])).toBe('damaged');
  });

  it('calls a row with a malformed field damaged, never unreadable', async () => {
    const row = await itemRow(stranger);
    // Not base64: decoding fails before any key is tried, which is no refusal.
    expect(await classifyItem({ ...row, encryptedData: '%%%not-base64%%%' }, [live])).toBe(
      'damaged',
    );
  });

  it('calls a bound row whose binding cannot be built damaged, never unreadable', async () => {
    // A `v2:` field on a row id that is not an ObjectId: the additional data
    // cannot be built, so nothing was refused.
    const row = await itemRow(stranger);
    expect(await classifyItem({ ...row, _id: 'not-an-object-id' }, [live])).toBe('damaged');
  });

  it('calls a row the store would reject for its shape damaged without opening anything', async () => {
    const row = await itemRow(stranger);
    const decrypt = vi.spyOn(cryptoService, 'decryptDataWithAad');
    const { createdAt: _dropped, ...shapeless } = row;
    expect(await classifyItem(shapeless as IVaultItemResponse, [live])).toBe('damaged');
    expect(decrypt).not.toHaveBeenCalled();
    decrypt.mockRestore();
  });

  it('ignores the password history either way', async () => {
    const history = [{ encryptedPassword: 'AAAA', iv: 'AAAA', tag: 'AAAA', changedAt: 'x' }];
    // A damaged history does not make a readable row deletable…
    expect(await classifyItem({ ...(await itemRow(live)), passwordHistory: history }, [live])).toBe(
      'readable',
    );
    // …and one the live key opens does not rescue a row whose own fields it cannot.
    const pw = await encryptVaultField(
      'old',
      { role: 'item.password-history', rowId: ITEM_ID },
      live,
    );
    const unreadable = {
      ...(await itemRow(stranger)),
      passwordHistory: [
        { encryptedPassword: pw.encrypted, iv: pw.iv, tag: pw.tag, changedAt: 'x' },
      ],
    };
    expect(await classifyItem(unreadable, [live])).toBe('unreadable');
  });

  it('refuses to judge without a candidate key', async () => {
    await expect(classifyItem(await itemRow(live), [])).rejects.toThrow(
      'A row cannot be judged without a candidate key',
    );
  });
});

describe('classifyFolder', () => {
  for (const format of ['v1', 'v2'] as const) {
    it(`calls a ${format} folder readable or unreadable by its name alone`, async () => {
      expect(await classifyFolder(await folderRow(live, format), [live])).toBe('readable');
      expect(await classifyFolder(await folderRow(stranger, format), [live, earlier])).toBe(
        'unreadable',
      );
      expect(await classifyFolder(await folderRow(earlier, format), [live, earlier])).toBe(
        'readable',
      );
    });
  }

  it('calls a malformed or shapeless folder damaged', async () => {
    const row = await folderRow(stranger);
    expect(await classifyFolder({ ...row, nameIv: '%%%' }, [live])).toBe('damaged');
    const { sortOrder: _dropped, ...shapeless } = row;
    expect(await classifyFolder(shapeless as IFolderResponse, [live])).toBe('damaged');
  });

  it('refuses to judge without a candidate key', async () => {
    await expect(classifyFolder(await folderRow(live), [])).rejects.toThrow(
      'A row cannot be judged without a candidate key',
    );
  });
});

describe('isAuthenticationFailure', () => {
  it('recognises AES-GCM refusing a key by name, and nothing else', async () => {
    const row = await itemRow(stranger);
    const refusal: unknown = await cryptoService
      .decryptDataWithAad(
        row.encryptedName,
        row.nameIv.slice(3),
        row.nameTag,
        live,
        new Uint8Array(1),
      )
      .catch((error: unknown) => error);
    expect(isAuthenticationFailure(refusal)).toBe(true);
    expect(isAuthenticationFailure({ name: 'OperationError' })).toBe(true);
    expect(isAuthenticationFailure(new Error('OperationError'))).toBe(false);
    expect(isAuthenticationFailure({ name: 'InvalidCharacterError' })).toBe(false);
    expect(isAuthenticationFailure(null)).toBe(false);
    expect(isAuthenticationFailure('OperationError')).toBe(false);
  });
});

describe('opening a whole row under the first candidate that opens it', () => {
  it('returns the plaintext, history included, with the index of the key that opened it', async () => {
    const pw = await encryptVaultField(
      'old-secret',
      { role: 'item.password-history', rowId: ITEM_ID },
      earlier,
    );
    const row = {
      ...(await itemRow(earlier)),
      passwordHistory: [
        { encryptedPassword: pw.encrypted, iv: pw.iv, tag: pw.tag, changedAt: '2026-02-02' },
      ],
    };
    expect(await decryptItemUnderAnyKey(row, [live, earlier])).toEqual({
      name: 'Bank',
      data: '{"username":"ada"}',
      history: [{ password: 'old-secret', changedAt: '2026-02-02' }],
      keyIndex: 1,
    });
  });

  it('opens a row all or nothing: a history entry no candidate opens fails the row', async () => {
    const pw = await encryptVaultField(
      'old',
      { role: 'item.password-history', rowId: ITEM_ID },
      stranger,
    );
    const row = {
      ...(await itemRow(live)),
      passwordHistory: [
        { encryptedPassword: pw.encrypted, iv: pw.iv, tag: pw.tag, changedAt: 'x' },
      ],
    };
    expect(await decryptItemUnderAnyKey(row, [live])).toBeNull();
  });

  it('returns null for a row no candidate opens, and a folder name with its key index', async () => {
    expect(await decryptItemUnderAnyKey(await itemRow(stranger), [live, earlier])).toBeNull();
    expect(await decryptFolderNameUnderAnyKey(await folderRow(earlier), [live, earlier])).toEqual({
      name: 'Work',
      keyIndex: 1,
    });
    expect(await decryptFolderNameUnderAnyKey(await folderRow(stranger), [live])).toBeNull();
  });

  it('unwraps a document key under the first candidate, bound to that document', async () => {
    const dek = new Uint8Array(32).fill(7);
    const wrapped = await wrapDek(dek, await deriveWrapKey(earlier, DOCUMENT_ID));
    const row = { _id: DOCUMENT_ID, ...wrapped } as unknown as DocumentResponse;

    const opened = await unwrapDekUnderAnyKey(row, [live, earlier]);
    expect(opened?.keyIndex).toBe(1);
    expect(Array.from(opened?.dek ?? [])).toEqual(Array.from(dek));
    expect(await unwrapDekUnderAnyKey(row, [live, stranger])).toBeNull();
    // The same wrapped key moved onto another document opens under no key.
    const moved = { ...row, _id: ITEM_ID } as DocumentResponse;
    expect(await unwrapDekUnderAnyKey(moved, [earlier])).toBeNull();
  });
});

describe('reading every row', () => {
  it('walks every page in order', async () => {
    const request = vi
      .fn()
      .mockResolvedValueOnce(page(['a'], 3))
      .mockResolvedValueOnce(page(['b'], 3))
      .mockResolvedValueOnce(page(['c'], 3));
    expect(await enumerateRows(request, 'boom')).toEqual(['a', 'b', 'c']);
    expect(request.mock.calls).toEqual([[1], [2], [3]]);
  });

  it('fails on a page count that is not a number, instead of stopping early', async () => {
    const request = vi.fn().mockResolvedValue(page(['a'], Number.NaN));
    await expect(enumerateRows(request, 'Failed to fetch the list')).rejects.toThrow(
      'Failed to fetch the list',
    );
    const infinite = vi.fn().mockResolvedValue(page(['a'], Number.POSITIVE_INFINITY));
    await expect(enumerateRows(infinite, 'Failed to fetch the list')).rejects.toThrow(
      'Failed to fetch the list',
    );
    expect(infinite).toHaveBeenCalledTimes(1);
  });

  it('fails on a refused page, keeping nothing it read', async () => {
    const request = vi
      .fn()
      .mockResolvedValueOnce(page(['a'], 2))
      .mockResolvedValueOnce({ data: { success: false, error: { code: 'X', message: 'no' } } });
    await expect(enumerateRows(request, 'Failed')).rejects.toThrow('Failed');
  });

  it('clamps an inflated page count to the ceiling it is given', async () => {
    const request = vi.fn().mockResolvedValue(page(['a'], 50));
    expect(await enumerateRows(request, 'boom', 2)).toEqual(['a', 'a']);
    expect(request).toHaveBeenCalledTimes(2);
  });

  it('reads active items, then the trash, at the largest page size', async () => {
    mockListItems.mockResolvedValueOnce(page(['i1'], 1));
    mockListTrash.mockResolvedValueOnce(page(['t1'], 1));
    expect(await enumerateItemRows()).toEqual(['i1', 't1']);
    expect(mockListItems).toHaveBeenCalledWith({ page: 1, limit: 200 });
    expect(mockListTrash).toHaveBeenCalledWith({ page: 1, limit: 200 });
  });

  it('names which list failed', async () => {
    mockListItems.mockResolvedValueOnce(page(['i1'], 1));
    mockListTrash.mockResolvedValueOnce({ data: { success: false } });
    await expect(enumerateItemRows()).rejects.toThrow('Failed to fetch trash items');
    mockListFolders.mockResolvedValueOnce({ data: { success: false } });
    await expect(listAllFolderRows()).rejects.toThrow('Failed to fetch folders');
  });

  it('reads every folder in one list', async () => {
    mockListFolders.mockResolvedValueOnce({ data: { success: true, data: ['f1', 'f2'] } });
    expect(await listAllFolderRows()).toEqual(['f1', 'f2']);
  });

  it('reads active then trashed documents, clamped to the account ceiling', async () => {
    mockListDocuments.mockResolvedValue(page(['d'], MAX_DOCUMENT_PAGES + 5));
    mockListDocumentTrash.mockResolvedValue(page(['x'], 1));
    const rows = await enumerateAllDocumentRows();
    expect(rows).toHaveLength(MAX_DOCUMENT_PAGES + 1);
    expect(rows.at(-1)).toBe('x');
    expect(mockListDocuments).toHaveBeenCalledTimes(MAX_DOCUMENT_PAGES);
  });
});

describe('counting rows by kind', () => {
  it('names each kind in a fixed order, plural-aware, and leaves out empty kinds', () => {
    expect(describeRowCounts({ document: 2, item: 1 })).toBe('1 item, 2 documents');
    expect(describeRowCounts({ folder: 0 })).toBe('');
    expect(
      describeSkippedRows([{ leg: 'folder' }, { leg: 'item' }, { leg: 'item' }, { leg: 'folder' }]),
    ).toBe('2 items, 2 folders');
  });
});
