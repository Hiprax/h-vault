/**
 * The encrypted export file is built from an allowlist: these tests pin that it
 * carries exactly the fields an import reads, that bookkeeping and any unknown
 * field never reach it, and, with real AES-GCM, that the row id it keeps is the
 * one thing that opens each sealed field.
 */
import { describe, expect, it } from 'vitest';
import type { ExportResponse } from '@hvault/shared';
import { buildNativeExportFile } from '../../src/services/export/nativeExport';
import { decryptVaultField, encryptVaultField } from '../../src/services/crypto/vaultField';
import { AEAD_REFUSAL, expectRefusal } from '../documentCryptoHarness';

const ITEM_ID = '66c0f1a2b3c4d5e6f7a8b9c0';
const FOLDER_ID = '66c0f1a2b3c4d5e6f7a8b9c1';
const PARENT_ID = '66c0f1a2b3c4d5e6f7a8b9c2';
const OTHER_ID = '66c0f1a2b3c4d5e6f7a8b9cf';

/** What the server's lean rows can hold beyond the contract: never in the file. */
const BOOKKEEPING = {
  userId: '66c0f1a2b3c4d5e6f7a8b9ff',
  __v: 3,
  createdAt: '2026-01-02T03:04:05.000Z',
  updatedAt: '2026-02-03T04:05:06.000Z',
  deletedAt: '2026-03-04T05:06:07.000Z',
  sourceRefId: '66c0f1a2b3c4d5e6f7a8b9ee',
  searchHash: 'a'.repeat(64),
  someFutureField: 'never exported by default',
};

const ITEM_KEYS = [
  '_id',
  'dataIv',
  'dataTag',
  'encryptedData',
  'encryptedName',
  'favorite',
  'folderId',
  'itemType',
  'nameIv',
  'nameTag',
  'passwordHistory',
  'tags',
];
const FOLDER_KEYS = [
  '_id',
  'color',
  'encryptedName',
  'icon',
  'nameIv',
  'nameTag',
  'parentId',
  'sortOrder',
];

function fullResponse(): ExportResponse {
  return {
    items: [
      {
        ...BOOKKEEPING,
        _id: ITEM_ID,
        itemType: 'login',
        folderId: FOLDER_ID,
        tags: ['work', 'mail'],
        favorite: true,
        encryptedData: 'data-ct',
        dataIv: 'v2:data-iv',
        dataTag: 'data-tag',
        encryptedName: 'name-ct',
        nameIv: 'v2:name-iv',
        nameTag: 'name-tag',
        passwordHistory: [
          {
            encryptedPassword: 'old-ct',
            iv: 'v2:old-iv',
            tag: 'old-tag',
            changedAt: '2025-12-31T23:59:59.000Z',
            _id: 'an entry id the file never needs',
          },
        ],
      },
    ],
    folders: [
      {
        ...BOOKKEEPING,
        _id: FOLDER_ID,
        parentId: PARENT_ID,
        encryptedName: 'folder-ct',
        nameIv: 'v2:folder-iv',
        nameTag: 'folder-tag',
        icon: 'briefcase',
        color: '#336699',
        sortOrder: 4,
      },
    ],
    metadata: {
      exportDate: '2026-10-23T10:00:00.000Z',
      version: '0.21.0',
      itemCount: 1,
      extra: 'not part of the file',
    },
  } as unknown as ExportResponse;
}

describe('buildNativeExportFile', () => {
  it('writes exactly the allowlisted fields of every item, folder and the metadata, with their values', () => {
    const file = buildNativeExportFile(fullResponse());

    expect(Object.keys(file)).toEqual(['items', 'folders', 'metadata']);
    expect(file.items).toHaveLength(1);
    expect(Object.keys(file.items[0]!).sort()).toEqual(ITEM_KEYS);
    expect(file.items[0]).toEqual({
      _id: ITEM_ID,
      itemType: 'login',
      folderId: FOLDER_ID,
      tags: ['work', 'mail'],
      favorite: true,
      encryptedData: 'data-ct',
      dataIv: 'v2:data-iv',
      dataTag: 'data-tag',
      encryptedName: 'name-ct',
      nameIv: 'v2:name-iv',
      nameTag: 'name-tag',
      passwordHistory: [
        {
          encryptedPassword: 'old-ct',
          iv: 'v2:old-iv',
          tag: 'old-tag',
          changedAt: '2025-12-31T23:59:59.000Z',
        },
      ],
    });
    expect(Object.keys(file.folders[0]!).sort()).toEqual(FOLDER_KEYS);
    expect(file.folders[0]).toEqual({
      _id: FOLDER_ID,
      parentId: PARENT_ID,
      encryptedName: 'folder-ct',
      nameIv: 'v2:folder-iv',
      nameTag: 'folder-tag',
      icon: 'briefcase',
      color: '#336699',
      sortOrder: 4,
    });
    expect(file.metadata).toEqual({
      exportDate: '2026-10-23T10:00:00.000Z',
      version: '0.21.0',
      itemCount: 1,
    });

    // NEGATIVE, over the serialized bytes the user actually downloads.
    const text = JSON.stringify(file);
    for (const key of Object.keys(BOOKKEEPING)) {
      expect(text).not.toContain(`"${key}"`);
    }
    expect(text).not.toContain('an entry id the file never needs');
  });

  it('leaves an optional field the row does not carry ABSENT, never null or undefined', () => {
    const response = {
      items: [
        {
          _id: ITEM_ID,
          itemType: 'note',
          folderId: null,
          tags: [],
          favorite: false,
          encryptedData: 'd',
          dataIv: 'i',
          dataTag: 't',
          encryptedName: 'n',
          nameIv: 'i',
          nameTag: 't',
        },
      ],
      folders: [
        {
          _id: FOLDER_ID,
          parentId: null,
          encryptedName: 'f',
          nameIv: 'i',
          nameTag: 't',
          sortOrder: 0,
        },
      ],
      metadata: { exportDate: 'x', version: 'y', itemCount: 1 },
    } as unknown as ExportResponse;

    const file = buildNativeExportFile(response);

    for (const key of ['folderId', 'passwordHistory']) {
      expect(file.items[0]).not.toHaveProperty(key);
    }
    for (const key of ['parentId', 'icon', 'color']) {
      expect(file.folders[0]).not.toHaveProperty(key);
    }
    // The required fields are all still there.
    expect(Object.keys(file.items[0]!).sort()).toEqual(
      ITEM_KEYS.filter((key) => key !== 'folderId' && key !== 'passwordHistory'),
    );
    expect(file.folders[0]!.sortOrder).toBe(0);
    expect(JSON.stringify(file)).not.toContain('null');
  });

  it('keeps an empty password history as an empty list, distinct from none at all', () => {
    const response = fullResponse();
    response.items[0]!.passwordHistory = [];

    expect(buildNativeExportFile(response).items[0]!.passwordHistory).toEqual([]);
  });

  it('keeps an empty vault a well-formed file', () => {
    const file = buildNativeExportFile({
      items: [],
      folders: [],
      metadata: { exportDate: 'x', version: 'y', itemCount: 0 },
    });

    expect(file).toEqual({
      items: [],
      folders: [],
      metadata: { exportDate: 'x', version: 'y', itemCount: 0 },
    });
  });
});

describe('the row id the file keeps is what opens each sealed field (real AES-GCM)', () => {
  async function sealedResponse(vaultKey: CryptoKey): Promise<ExportResponse> {
    const name = await encryptVaultField('Bank', { role: 'item.name', rowId: ITEM_ID }, vaultKey);
    const data = await encryptVaultField(
      '{"username":"alice"}',
      { role: 'item.data', rowId: ITEM_ID, itemType: 'login' },
      vaultKey,
    );
    const previous = await encryptVaultField(
      'old-secret',
      { role: 'item.password-history', rowId: ITEM_ID },
      vaultKey,
    );
    const folderName = await encryptVaultField(
      'Finance',
      { role: 'folder.name', rowId: FOLDER_ID },
      vaultKey,
    );
    return {
      items: [
        {
          ...BOOKKEEPING,
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
          passwordHistory: [
            {
              encryptedPassword: previous.encrypted,
              iv: previous.iv,
              tag: previous.tag,
              changedAt: '2026-01-01T00:00:00.000Z',
            },
          ],
        },
      ],
      folders: [
        {
          ...BOOKKEEPING,
          _id: FOLDER_ID,
          encryptedName: folderName.encrypted,
          nameIv: folderName.iv,
          nameTag: folderName.tag,
          sortOrder: 0,
        },
      ],
      metadata: { exportDate: 'x', version: 'y', itemCount: 1 },
    } as unknown as ExportResponse;
  }

  it('opens every field with the id written beside it, and refuses each one under an edited id', async () => {
    const vaultKey = await globalThis.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
    const file = buildNativeExportFile(await sealedResponse(vaultKey));
    const item = file.items[0]!;
    const folder = file.folders[0]!;
    const history = item.passwordHistory![0]!;

    // The id in the file opens all four fields.
    await expect(
      decryptVaultField(
        { encrypted: item.encryptedName, iv: item.nameIv, tag: item.nameTag },
        { role: 'item.name', rowId: item._id },
        vaultKey,
      ),
    ).resolves.toBe('Bank');
    await expect(
      decryptVaultField(
        { encrypted: item.encryptedData, iv: item.dataIv, tag: item.dataTag },
        { role: 'item.data', rowId: item._id, itemType: item.itemType },
        vaultKey,
      ),
    ).resolves.toBe('{"username":"alice"}');
    await expect(
      decryptVaultField(
        { encrypted: history.encryptedPassword, iv: history.iv, tag: history.tag },
        { role: 'item.password-history', rowId: item._id },
        vaultKey,
      ),
    ).resolves.toBe('old-secret');
    await expect(
      decryptVaultField(
        { encrypted: folder.encryptedName, iv: folder.nameIv, tag: folder.nameTag },
        { role: 'folder.name', rowId: folder._id },
        vaultKey,
      ),
    ).resolves.toBe('Finance');

    // An edited id opens none of them: the tag check refuses, nothing leaks.
    await expectRefusal(
      () =>
        decryptVaultField(
          { encrypted: item.encryptedName, iv: item.nameIv, tag: item.nameTag },
          { role: 'item.name', rowId: OTHER_ID },
          vaultKey,
        ),
      AEAD_REFUSAL,
    );
    await expectRefusal(
      () =>
        decryptVaultField(
          { encrypted: item.encryptedData, iv: item.dataIv, tag: item.dataTag },
          { role: 'item.data', rowId: OTHER_ID, itemType: item.itemType },
          vaultKey,
        ),
      AEAD_REFUSAL,
    );
    await expectRefusal(
      () =>
        decryptVaultField(
          { encrypted: history.encryptedPassword, iv: history.iv, tag: history.tag },
          { role: 'item.password-history', rowId: OTHER_ID },
          vaultKey,
        ),
      AEAD_REFUSAL,
    );
    await expectRefusal(
      () =>
        decryptVaultField(
          { encrypted: folder.encryptedName, iv: folder.nameIv, tag: folder.nameTag },
          { role: 'folder.name', rowId: OTHER_ID },
          vaultKey,
        ),
      AEAD_REFUSAL,
    );
  });
});
