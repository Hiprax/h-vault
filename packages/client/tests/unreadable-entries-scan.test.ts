/**
 * The unreadable-entry check: what it refuses to judge, what it names for deletion,
 * and the exact deletion request it builds.
 *
 * Rows are sealed with real WebCrypto under real keys; only the transport is
 * faked. A check that judged under a key that is not the account's, or while an
 * interrupted rotation could still open the rows, would name readable entries for
 * permanent deletion, so both stop it before a single row is read.
 */
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import type { DocumentResponse, IFolderResponse, IVaultItemResponse } from '@hvault/shared';

const mockGetProfile = vi.fn();
const mockReadDocumentsConfigFresh = vi.fn();
const mockListItems = vi.fn();
const mockListTrash = vi.fn();
const mockListFolders = vi.fn();
const mockListDocuments = vi.fn();
const mockListDocumentTrash = vi.fn();
const mockZeroDek = vi.fn();

vi.mock('../src/services/api/userApi', () => ({
  getProfileApi: () => mockGetProfile() as unknown,
}));
vi.mock('../src/services/api/configApi', () => ({
  readDocumentsConfigFresh: () => mockReadDocumentsConfigFresh() as unknown,
}));
vi.mock('../src/services/api/vaultApi', () => ({
  listItemsApi: (...args: unknown[]) => mockListItems(...args) as unknown,
  listTrashApi: (...args: unknown[]) => mockListTrash(...args) as unknown,
  listFoldersApi: () => mockListFolders() as unknown,
}));
vi.mock('../src/services/api/documentsApi', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../src/services/api/documentsApi')>()),
  listDocumentsApi: (...args: unknown[]) => mockListDocuments(...args) as unknown,
  listDocumentTrashApi: (...args: unknown[]) => mockListDocumentTrash(...args) as unknown,
}));
vi.mock('../src/services/crypto/documentCryptoService', async (importOriginal) => {
  const actual =
    await importOriginal<typeof import('../src/services/crypto/documentCryptoService')>();
  return {
    ...actual,
    zeroDek: (dek: Uint8Array<ArrayBuffer>) => {
      mockZeroDek(Array.from(dek));
      actual.zeroDek(dek);
    },
  };
});

import { cryptoService } from '../src/services/crypto/cryptoService';
import { encryptVaultField } from '../src/services/crypto/vaultField';
import { deriveWrapKey, wrapDek } from '../src/services/crypto/documentCryptoService';
import {
  buildPurgePayload,
  isCleanScan,
  scanUnreadableEntries,
  type UnreadableScan,
} from '../src/services/vault/unreadableEntries';

const ID = {
  readable: '66c0f1a2b3c4d5e6f7a8b9c0',
  lost: '66c0f1a2b3c4d5e6f7a8b9c1',
  lostInTrash: '66c0f1a2b3c4d5e6f7a8b9c2',
  half: '66c0f1a2b3c4d5e6f7a8b9c3',
  folderReadable: '66c0f1a2b3c4d5e6f7a8b9c4',
  folderLost: '66c0f1a2b3c4d5e6f7a8b9c5',
  folderDamaged: '66c0f1a2b3c4d5e6f7a8b9c8',
  docReadable: '66c0f1a2b3c4d5e6f7a8b9c6',
  docLost: '66c0f1a2b3c4d5e6f7a8b9c7',
};

let live: CryptoKey;
let lost: CryptoKey;
let mek: CryptoKey;
let wrapper: { encrypted: string; iv: string; tag: string };

function key(fill: number): Promise<CryptoKey> {
  return cryptoService.importVaultKey(new Uint8Array(32).fill(fill).buffer);
}

async function item(
  id: string,
  nameKey: CryptoKey,
  dataKey: CryptoKey = nameKey,
  extra: Partial<IVaultItemResponse> = {},
): Promise<IVaultItemResponse> {
  const name = await encryptVaultField('n', { role: 'item.name', rowId: id }, nameKey);
  const data = await encryptVaultField(
    '{}',
    { role: 'item.data', rowId: id, itemType: 'note' },
    dataKey,
  );
  return {
    _id: id,
    itemType: 'note',
    tags: [],
    favorite: false,
    encryptedName: name.encrypted,
    nameIv: name.iv,
    nameTag: name.tag,
    encryptedData: data.encrypted,
    dataIv: data.iv,
    dataTag: data.tag,
    createdAt: '2026-03-01T00:00:00.000Z',
    updatedAt: '2026-03-01T00:00:00.000Z',
    ...extra,
  };
}

async function folder(id: string, under: CryptoKey): Promise<IFolderResponse> {
  const name = await encryptVaultField('f', { role: 'folder.name', rowId: id }, under);
  return {
    _id: id,
    encryptedName: name.encrypted,
    nameIv: name.iv,
    nameTag: name.tag,
    sortOrder: 0,
    createdAt: '2026-03-02T00:00:00.000Z',
    updatedAt: '2026-03-02T00:00:00.000Z',
  };
}

async function documentRow(id: string, under: CryptoKey, fill: number): Promise<DocumentResponse> {
  const wrapped = await wrapDek(new Uint8Array(32).fill(fill), await deriveWrapKey(under, id));
  return { _id: id, ...wrapped } as unknown as DocumentResponse;
}

function page<T>(data: T[]) {
  return {
    data: { success: true, data, pagination: { page: 1, limit: 200, total: 0, totalPages: 1 } },
  };
}

function profile(overrides: Record<string, unknown> = {}) {
  return {
    data: {
      success: true,
      data: {
        encryptedVaultKey: wrapper.encrypted,
        vaultKeyIv: wrapper.iv,
        vaultKeyTag: wrapper.tag,
        interruptedRotation: false,
        ...overrides,
      },
    },
  };
}

beforeAll(async () => {
  live = await key(0x11);
  lost = await key(0x22);
  mek = await globalThis.crypto.subtle.importKey(
    'raw',
    new Uint8Array(32).fill(0x33),
    'AES-GCM',
    false,
    ['encrypt', 'decrypt'],
  );
  wrapper = await cryptoService.encryptVaultKey(live, mek);
});

/** The rows the lists answer with, as stored. */
let listed: IVaultItemResponse[];
let trashed: IVaultItemResponse[];
let folders: IFolderResponse[];

beforeEach(async () => {
  vi.clearAllMocks();
  listed = [
    await item(ID.readable, live),
    await item(ID.lost, lost),
    await item(ID.half, live, lost),
  ];
  trashed = [await item(ID.lostInTrash, lost, lost, { deletedAt: '2026-04-01T00:00:00.000Z' })];
  folders = [
    await folder(ID.folderReadable, live),
    await folder(ID.folderLost, lost),
    // Not even base64: damaged, never offered for deletion.
    { ...(await folder(ID.folderDamaged, lost)), nameIv: '%%%' },
  ];
  mockGetProfile.mockResolvedValue(profile());
  mockReadDocumentsConfigFresh.mockResolvedValue({ enabled: true });
  mockListItems.mockResolvedValue(page(listed));
  mockListTrash.mockResolvedValue(page(trashed));
  mockListFolders.mockResolvedValue({ data: { success: true, data: folders } });
  mockListDocuments.mockResolvedValue(page([await documentRow(ID.docReadable, live, 5)]));
  mockListDocumentTrash.mockResolvedValue(page([await documentRow(ID.docLost, lost, 6)]));
});

describe('scanUnreadableEntries', () => {
  it('names exactly the rows no stored key opens, with the IVs it judged them by', async () => {
    const onProfile = vi.fn();

    const outcome = await scanUnreadableEntries(live, mek, onProfile);

    expect(outcome.kind).toBe('scanned');
    const { scan } = outcome as { scan: UnreadableScan };
    expect(scan).toEqual({
      wrapper,
      items: [
        {
          id: ID.lost,
          nameIv: listed[1]!.nameIv,
          dataIv: listed[1]!.dataIv,
          itemType: 'note',
          createdAt: '2026-03-01T00:00:00.000Z',
          inTrash: false,
        },
        {
          id: ID.lostInTrash,
          nameIv: trashed[0]!.nameIv,
          dataIv: trashed[0]!.dataIv,
          itemType: 'note',
          createdAt: '2026-03-01T00:00:00.000Z',
          inTrash: true,
        },
      ],
      folders: [
        { id: ID.folderLost, nameIv: folders[1]!.nameIv, createdAt: '2026-03-02T00:00:00.000Z' },
      ],
      // Half-open or malformed: never offered for deletion, only counted.
      damaged: { items: 1, folders: 1 },
      documents: 1,
    });
    expect(onProfile).toHaveBeenCalledWith(profile().data.data);
    // Every document key that opened was zeroed; the one that did not never existed.
    expect(mockZeroDek).toHaveBeenCalledTimes(1);
    expect(mockZeroDek).toHaveBeenCalledWith(Array(32).fill(5));
  });

  it('refuses to judge, reading no row, when this session holds a key that is not the account’s', async () => {
    const other = await key(0x44);

    expect(await scanUnreadableEntries(other, mek, vi.fn())).toEqual({ kind: 'key-not-current' });
    expect(mockListItems).not.toHaveBeenCalled();
    expect(mockListFolders).not.toHaveBeenCalled();
  });

  it('refuses to judge when this session’s master key no longer opens the account’s wrapper', async () => {
    const otherMek = await globalThis.crypto.subtle.importKey(
      'raw',
      new Uint8Array(32).fill(0x55),
      'AES-GCM',
      false,
      ['encrypt', 'decrypt'],
    );

    expect(await scanUnreadableEntries(live, otherMek, vi.fn())).toEqual({
      kind: 'key-not-current',
    });
    expect(mockListItems).not.toHaveBeenCalled();
  });

  it('refuses to judge while an interrupted rotation could still open the rows', async () => {
    mockGetProfile.mockResolvedValue(profile({ interruptedRotation: true }));

    expect(await scanUnreadableEntries(live, mek, vi.fn())).toEqual({
      kind: 'interrupted-rotation',
    });
    expect(mockListItems).not.toHaveBeenCalled();
  });

  it('fails rather than calling the vault clean when it cannot read the account or the documents setting', async () => {
    mockGetProfile.mockResolvedValueOnce({ data: { success: false } });
    await expect(scanUnreadableEntries(live, mek, vi.fn())).rejects.toThrow(
      'Failed to read the account',
    );

    mockReadDocumentsConfigFresh.mockResolvedValueOnce(null);
    await expect(scanUnreadableEntries(live, mek, vi.fn())).rejects.toThrow(
      'Could not confirm whether documents are stored',
    );
  });

  it('reads no document list on a server without document storage', async () => {
    mockReadDocumentsConfigFresh.mockResolvedValue({ enabled: false });

    const outcome = await scanUnreadableEntries(live, mek, vi.fn());

    expect((outcome as { scan: UnreadableScan }).scan.documents).toBe(0);
    expect(mockListDocuments).not.toHaveBeenCalled();
    expect(mockListDocumentTrash).not.toHaveBeenCalled();
  });
});

describe('isCleanScan', () => {
  const clean: UnreadableScan = {
    wrapper: { encrypted: 'e', iv: 'i', tag: 't' },
    items: [],
    folders: [],
    damaged: { items: 0, folders: 0 },
    documents: 0,
  };
  const anItem = {
    id: 'a',
    nameIv: 'n',
    dataIv: 'd',
    itemType: 'note' as const,
    createdAt: 'c',
    inTrash: false,
  };

  it('is clean only when nothing at all is reported', () => {
    expect(isCleanScan(clean)).toBe(true);
    expect(isCleanScan({ ...clean, items: [anItem] })).toBe(false);
    expect(isCleanScan({ ...clean, folders: [{ id: 'f', nameIv: 'n', createdAt: 'c' }] })).toBe(
      false,
    );
    expect(isCleanScan({ ...clean, damaged: { items: 1, folders: 0 } })).toBe(false);
    expect(isCleanScan({ ...clean, damaged: { items: 0, folders: 1 } })).toBe(false);
    expect(isCleanScan({ ...clean, documents: 1 })).toBe(false);
  });
});

describe('buildPurgePayload', () => {
  it('names the proof, the wrapper judged under, and each row with its IVs, and nothing else', () => {
    const scan: UnreadableScan = {
      wrapper: { encrypted: 'wrapped', iv: 'wrap-iv', tag: 'wrap-tag' },
      items: [
        { id: 'i1', nameIv: 'n1', dataIv: 'd1', itemType: 'login', createdAt: 'c', inTrash: true },
      ],
      folders: [{ id: 'f1', nameIv: 'fn1', createdAt: 'c' }],
      damaged: { items: 3, folders: 2 },
      documents: 4,
    };

    expect(buildPurgePayload(scan, 'proof')).toEqual({
      authHash: 'proof',
      encryptedVaultKey: 'wrapped',
      vaultKeyIv: 'wrap-iv',
      vaultKeyTag: 'wrap-tag',
      items: [{ id: 'i1', nameIv: 'n1', dataIv: 'd1' }],
      folders: [{ id: 'f1', nameIv: 'fn1' }],
    });
  });
});
