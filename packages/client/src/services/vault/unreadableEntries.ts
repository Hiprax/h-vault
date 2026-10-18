/**
 * Finding the entries no key the account stores can open, and naming them for
 * deletion.
 *
 * A master password reset replaces the vault key and keeps every row, so the
 * entries sealed before it stay stored, invisible (the vault cannot open them) and
 * counted against the storage quota. Only a browser holding the account's key can
 * tell which rows those are, so the check runs here, and it is careful about what
 * it concludes: it runs only after proving that the key this session holds IS the
 * account's current one, never while an interrupted rotation could still open
 * them, and it names a row for deletion only when no field it reads authenticates
 * under that key (`classifyItem`). Each named row carries the IVs it had when it was
 * judged, and the server deletes it only while they are unchanged.
 */
import type { IUserProfile, ItemType, PurgeUnreadableInput } from '@hvault/shared';
import { getProfileApi } from '../api/userApi';
import { readDocumentsConfigFresh } from '../api/configApi';
import { holdsAccountVaultKey, type WrappedVaultKey } from '../crypto/accountVaultKey';
import { zeroDek } from '../crypto/documentCryptoService';
import {
  classifyFolder,
  classifyItem,
  enumerateAllDocumentRows,
  enumerateItemRows,
  listAllFolderRows,
  unwrapDekUnderAnyKey,
} from './vaultRows';

/** One item no stored key opens, as the check found it. */
interface UnreadableItem {
  id: string;
  nameIv: string;
  dataIv: string;
  itemType: ItemType;
  createdAt: string;
  inTrash: boolean;
}

/** One folder no stored key opens, as the check found it. */
interface UnreadableFolder {
  id: string;
  nameIv: string;
  createdAt: string;
}

/** What a completed check found. */
export interface UnreadableScan {
  /** The wrapper the rows were judged under: the deletion's same-key proof. */
  wrapper: WrappedVaultKey;
  items: UnreadableItem[];
  folders: UnreadableFolder[];
  /** Rows the check would not judge (part opens, or malformed): never deleted. */
  damaged: { items: number; folders: number };
  /** Documents whose key no stored vault key unwraps (deleted on the Documents page). */
  documents: number;
}

/** Why a check stopped before reading a single row. */
export type UnreadableScanOutcome =
  | { kind: 'scanned'; scan: UnreadableScan }
  | { kind: 'key-not-current' }
  | { kind: 'interrupted-rotation' };

/** Whether a completed check found nothing at all to report. */
export function isCleanScan(scan: UnreadableScan): boolean {
  return (
    scan.items.length === 0 &&
    scan.folders.length === 0 &&
    scan.damaged.items === 0 &&
    scan.damaged.folders === 0 &&
    scan.documents === 0
  );
}

/**
 * Reads the account fresh, proves this session holds its current vault key, and
 * judges every row under that key. `onProfile` receives the profile the check read,
 * so the page shows what was judged against.
 */
export async function scanUnreadableEntries(
  vaultKey: CryptoKey,
  mek: CryptoKey,
  onProfile: (profile: IUserProfile) => void,
): Promise<UnreadableScanOutcome> {
  const body = (await getProfileApi()).data;
  if (!body.success) throw new Error('Failed to read the account');
  const profile = body.data;
  onProfile(profile);
  const wrapper: WrappedVaultKey = {
    encrypted: profile.encryptedVaultKey,
    iv: profile.vaultKeyIv,
    tag: profile.vaultKeyTag,
  };

  let current: boolean;
  try {
    current = await holdsAccountVaultKey(vaultKey, wrapper, mek);
  } catch {
    // The master key this session holds no longer opens the account's wrapper.
    current = false;
  }
  if (!current) return { kind: 'key-not-current' };
  // Rows an interrupted rotation re-sealed open under ITS key, which Finish
  // Rotation uses; judging them under the live key alone would call them lost.
  if (profile.interruptedRotation === true) return { kind: 'interrupted-rotation' };

  const keys = [vaultKey];
  const scan: UnreadableScan = {
    wrapper,
    items: [],
    folders: [],
    damaged: { items: 0, folders: 0 },
    documents: 0,
  };

  for (const item of await enumerateItemRows()) {
    const verdict = await classifyItem(item, keys);
    if (verdict === 'unreadable') {
      scan.items.push({
        id: item._id,
        nameIv: item.nameIv,
        dataIv: item.dataIv,
        itemType: item.itemType,
        createdAt: item.createdAt,
        inTrash: item.deletedAt !== undefined,
      });
    } else if (verdict === 'damaged') {
      scan.damaged.items += 1;
    }
  }

  for (const folder of await listAllFolderRows()) {
    const verdict = await classifyFolder(folder, keys);
    if (verdict === 'unreadable') {
      scan.folders.push({ id: folder._id, nameIv: folder.nameIv, createdAt: folder.createdAt });
    } else if (verdict === 'damaged') {
      scan.damaged.folders += 1;
    }
  }

  // Read fresh and refused on anything but an answer, as the rotation reads it: a
  // failed read is never taken to mean "this server stores no documents".
  const documentsConfig = await readDocumentsConfigFresh();
  if (documentsConfig === null) throw new Error('Could not confirm whether documents are stored');
  if (documentsConfig.enabled) {
    for (const row of await enumerateAllDocumentRows()) {
      const opened = await unwrapDekUnderAnyKey(row, keys);
      if (opened === null) {
        scan.documents += 1;
      } else {
        zeroDek(opened.dek);
      }
    }
  }

  return { kind: 'scanned', scan };
}

/**
 * The deletion request for a check's results, built field by field (never a spread
 * of a row): the master-password proof, the wrapper the rows were judged under, and
 * each row's id with the IVs it had when it was judged.
 */
export function buildPurgePayload(scan: UnreadableScan, authHash: string): PurgeUnreadableInput {
  return {
    authHash,
    encryptedVaultKey: scan.wrapper.encrypted,
    vaultKeyIv: scan.wrapper.iv,
    vaultKeyTag: scan.wrapper.tag,
    items: scan.items.map((item) => ({ id: item.id, nameIv: item.nameIv, dataIv: item.dataIv })),
    folders: scan.folders.map((folder) => ({ id: folder.id, nameIv: folder.nameIv })),
  };
}
