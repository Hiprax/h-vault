/**
 * The encrypted vault export file (`hvault-export-<date>.enc`): the vault's
 * encrypted content and the references between its rows, and none of the
 * database's bookkeeping.
 *
 * The server streams every row it exports as it is stored, bookkeeping included
 * where the projection lets it through, and this file is one the owner keeps,
 * moves around and may hand to other tools. So it is built from an ALLOWLIST:
 * every field below is named, and a field added to a model later reaches the file
 * only when somebody adds it here on purpose. A denylist would leak it by default.
 *
 * ## What stays, and why each one is needed
 *
 *   * `_id` on every item and folder. Not bookkeeping: each format-v2 field is
 *     sealed with AES-GCM additional data naming its row id
 *     (`services/crypto/vaultField.ts`), so the import opens a row with the id
 *     it was exported under. Without it no v2 row decrypts; with an edited one
 *     that single row fails its tag check and is dropped. It grants nothing on
 *     the server: an import inserts under freshly derived ids and updates only
 *     rows it matched in the live vault.
 *   * `folderId`, which puts an item back in its folder (a folder the importing
 *     account does not own is stripped by the server), and `parentId`, which
 *     records where each folder sat in the tree.
 *   * The ciphertext, `itemType` (part of the data field's binding), `tags`,
 *     `favorite`, the folder's `icon`/`color`/`sortOrder`, and each retained
 *     previous password with the time it was changed.
 *
 * The owner's account id, the version counter and the row timestamps are not
 * written: no import ever read them, and the server takes all three from itself.
 *
 * An optional field the row does not carry stays ABSENT from the file, never
 * `null` or `undefined`: a reader telling "not set" from "set to nothing" must
 * see the same thing the database held.
 */

import type {
  ExportResponse,
  IFolderResponse,
  IPasswordHistoryEntry,
  IVaultItemResponse,
  ItemType,
} from '@hvault/shared';

/** One retained previous password, as the file carries it. */
interface NativeExportHistoryEntry {
  encryptedPassword: string;
  iv: string;
  tag: string;
  changedAt: string;
}

/** One vault item, as the file carries it. */
export interface NativeExportItem {
  _id: string;
  itemType: ItemType;
  folderId?: string;
  tags: string[];
  favorite: boolean;
  encryptedName: string;
  nameIv: string;
  nameTag: string;
  encryptedData: string;
  dataIv: string;
  dataTag: string;
  passwordHistory?: NativeExportHistoryEntry[];
}

/** One folder, as the file carries it. */
export interface NativeExportFolder {
  _id: string;
  parentId?: string;
  encryptedName: string;
  nameIv: string;
  nameTag: string;
  icon?: string;
  color?: string;
  sortOrder: number;
}

/** The whole file. */
export interface NativeExportFile {
  items: NativeExportItem[];
  folders: NativeExportFolder[];
  metadata: { exportDate: string; version: string; itemCount: number };
}

/**
 * An optional string field, copied only when the row holds a string there.
 *
 * `typeof` rather than `!== undefined`: a row written by an older release may
 * hold `null` in a reference it never set, and `null` is not a reference.
 */
function optionalString<K extends string>(
  key: K,
  value: string | undefined,
): Partial<Record<K, string>> {
  return typeof value === 'string' ? ({ [key]: value } as Record<K, string>) : {};
}

function exportHistoryEntry(entry: IPasswordHistoryEntry): NativeExportHistoryEntry {
  return {
    encryptedPassword: entry.encryptedPassword,
    iv: entry.iv,
    tag: entry.tag,
    changedAt: entry.changedAt,
  };
}

function exportItem(item: IVaultItemResponse): NativeExportItem {
  return {
    _id: item._id,
    itemType: item.itemType,
    ...optionalString('folderId', item.folderId),
    tags: item.tags,
    favorite: item.favorite,
    encryptedName: item.encryptedName,
    nameIv: item.nameIv,
    nameTag: item.nameTag,
    encryptedData: item.encryptedData,
    dataIv: item.dataIv,
    dataTag: item.dataTag,
    ...(Array.isArray(item.passwordHistory)
      ? { passwordHistory: item.passwordHistory.map(exportHistoryEntry) }
      : {}),
  };
}

function exportFolder(folder: IFolderResponse): NativeExportFolder {
  return {
    _id: folder._id,
    ...optionalString('parentId', folder.parentId),
    encryptedName: folder.encryptedName,
    nameIv: folder.nameIv,
    nameTag: folder.nameTag,
    ...optionalString('icon', folder.icon),
    ...optionalString('color', folder.color),
    sortOrder: folder.sortOrder,
  };
}

/** The `.enc` file for one export response, built from the allowlist above. */
export function buildNativeExportFile(data: ExportResponse): NativeExportFile {
  return {
    items: data.items.map(exportItem),
    folders: data.folders.map(exportFolder),
    metadata: {
      exportDate: data.metadata.exportDate,
      version: data.metadata.version,
      itemCount: data.metadata.itemCount,
    },
  };
}
