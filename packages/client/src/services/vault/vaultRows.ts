/**
 * Reading every row an account holds, and opening it under candidate keys.
 *
 * ONE implementation for the two things that need it: the vault-key rotation (and
 * its re-seal, finish, discard and recover modes) and the unreadable-entry check in
 * Settings. Both walk the WHOLE account (active and trashed items, folders, active
 * and trashed documents) and both must never work from a partial list: a rotation
 * that misses a row strands it, and a check that misses one calls the vault clean.
 */
import { folderResponseSchema, vaultItemResponseSchema } from '@hvault/shared';
import type {
  DocumentResponse,
  IFolderResponse,
  IVaultItemResponse,
  PaginatedResponse,
} from '@hvault/shared';
import { listFoldersApi, listItemsApi, listTrashApi } from '../api/vaultApi';
import {
  DOCUMENT_PAGE_SIZE,
  MAX_DOCUMENT_PAGES,
  listDocumentTrashApi,
  listDocumentsApi,
} from '../api/documentsApi';
import { decryptVaultField } from '../crypto/vaultField';
import { deriveWrapKey, unwrapDek, type DocumentBytes } from '../crypto/documentCryptoService';

/** Which collection a row belongs to. */
export type RotationLeg = 'item' | 'folder' | 'document';

/** The page size the item walks ask for: the largest the list routes accept. */
const ITEM_PAGE_SIZE = 200;

/**
 * Every row of one paginated list, straight off the wire, in page order.
 *
 * `maxPages` clamps an inflated `totalPages` (the document lists' ceiling is
 * derived from how many rows an account can actually hold). A reply whose
 * `totalPages` is not a finite number fails with `failure` rather than ending the
 * walk early: a list cut short is the one answer neither caller can survive.
 */
export async function enumerateRows<T>(
  request: (page: number) => Promise<{ data: PaginatedResponse<T> }>,
  failure: string,
  maxPages = Number.POSITIVE_INFINITY,
): Promise<T[]> {
  const rows: T[] = [];
  let page = 1;
  let totalPages: number;
  do {
    const body = (await request(page)).data;
    if (!body.success || !Number.isFinite(body.pagination.totalPages)) throw new Error(failure);
    totalPages = Math.min(body.pagination.totalPages, maxPages);
    rows.push(...body.data);
    page += 1;
  } while (page <= totalPages);
  return rows;
}

/**
 * Every item the account holds: the active list, then the trash. A trashed item is
 * sealed under the same vault key as an active one and can still be restored.
 */
export async function enumerateItemRows(): Promise<IVaultItemResponse[]> {
  return [
    ...(await enumerateRows(
      (page) => listItemsApi({ page, limit: ITEM_PAGE_SIZE }),
      'Failed to fetch vault items',
    )),
    ...(await enumerateRows(
      (page) => listTrashApi({ page, limit: ITEM_PAGE_SIZE }),
      'Failed to fetch trash items',
    )),
  ];
}

/** Every folder the account holds (one unpaginated list). */
export async function listAllFolderRows(): Promise<IFolderResponse[]> {
  const body = (await listFoldersApi()).data;
  if (!body.success) throw new Error('Failed to fetch folders');
  return body.data;
}

/**
 * Every document row, active then trashed, straight off the wire.
 *
 * Deliberately NOT `documentsStore`'s walk: that one exists to DISPLAY documents,
 * opens each row's metadata and drops a row it cannot validate. A rotation and a
 * check need the opposite of both: no metadata is opened (it is sealed under the
 * document's own key, which a rotation only rewraps), and no row is ever dropped.
 */
export async function enumerateAllDocumentRows(): Promise<DocumentResponse[]> {
  return [
    ...(await enumerateRows(
      (page) => listDocumentsApi({ page, limit: DOCUMENT_PAGE_SIZE }),
      'Failed to fetch documents',
      MAX_DOCUMENT_PAGES,
    )),
    ...(await enumerateRows(
      (page) => listDocumentTrashApi({ page, limit: DOCUMENT_PAGE_SIZE }),
      'Failed to fetch documents',
      MAX_DOCUMENT_PAGES,
    )),
  ];
}

// ---------------------------------------------------------------------------
// Opening a row's fields, each under its own binding
// ---------------------------------------------------------------------------

/** An item's name, opened under `key` against the row it belongs to. */
function openItemName(item: IVaultItemResponse, key: CryptoKey): Promise<string> {
  return decryptVaultField(
    { encrypted: item.encryptedName, iv: item.nameIv, tag: item.nameTag },
    { role: 'item.name', rowId: item._id },
    key,
  );
}

/** An item's data, opened under `key` against its row and item type. */
function openItemData(item: IVaultItemResponse, key: CryptoKey): Promise<string> {
  return decryptVaultField(
    { encrypted: item.encryptedData, iv: item.dataIv, tag: item.dataTag },
    { role: 'item.data', rowId: item._id, itemType: item.itemType },
    key,
  );
}

/** One retained previous password of an item, opened under `key`. */
function openHistoryEntry(
  item: IVaultItemResponse,
  entry: { encryptedPassword: string; iv: string; tag: string },
  key: CryptoKey,
): Promise<string> {
  return decryptVaultField(
    { encrypted: entry.encryptedPassword, iv: entry.iv, tag: entry.tag },
    { role: 'item.password-history', rowId: item._id },
    key,
  );
}

/** A folder's name, opened under `key` against the folder it belongs to. */
function openFolderName(folder: IFolderResponse, key: CryptoKey): Promise<string> {
  return decryptVaultField(
    { encrypted: folder.encryptedName, iv: folder.nameIv, tag: folder.nameTag },
    { role: 'folder.name', rowId: folder._id },
    key,
  );
}

// ---------------------------------------------------------------------------
// Opening a whole row under the first candidate key that opens it
// ---------------------------------------------------------------------------

/**
 * The plaintext of one vault item, decrypted as a UNIT.
 *
 * All-or-nothing on purpose: a row's name, data and password history are written
 * in one request under one key, so a key that opens the name opens the rest. A
 * per-field fallback would let a half-decrypted row be re-encrypted under the new
 * key with the other half carried across unchanged, which is a row nothing can
 * ever open again.
 */
export interface ItemPlaintext {
  name: string;
  data: string;
  /**
   * Each retained previous password beside the `changedAt` it was stored with.
   *
   * Paired rather than a parallel array indexed against the stored entries: with
   * two arrays the re-encrypt loop needs a lookup that TypeScript cannot prove is
   * in range under `noUncheckedIndexedAccess`, so it grows a fallback arm that
   * nothing can ever reach. Here there is no index at all.
   */
  history: { password: string; changedAt: string }[];
}

/**
 * Decrypts one item under the FIRST candidate key that opens it, with the index of
 * that key, or `null` when none does.
 *
 * Several candidates for two reasons: a crashed sequential rotation leaves rows on
 * both sides of the swap (finishing it carries both across), and a recovery offers
 * the backup's copy of an earlier key beside the live one. `null` means no candidate
 * opened the whole unit. It is NOT a verdict that the row is sealed under another
 * key (a malformed field fails the same way), which is why deletion is decided by
 * {@link classifyItem} and never by this.
 */
export async function decryptItemUnderAnyKey(
  item: IVaultItemResponse,
  keys: CryptoKey[],
): Promise<(ItemPlaintext & { keyIndex: number }) | null> {
  for (const [keyIndex, key] of keys.entries()) {
    try {
      // Opened against the row the rotation is about to rewrite, exactly as the
      // store reads it, so a format-v2 field is carried across under its own
      // binding rather than failing every candidate and being passed through
      // under a key the commit retires.
      const name = await openItemName(item, key);
      const data = await openItemData(item, key);
      const history: ItemPlaintext['history'] = [];
      for (const entry of item.passwordHistory ?? []) {
        history.push({
          password: await openHistoryEntry(item, entry, key),
          changedAt: entry.changedAt,
        });
      }
      return { name, data, history, keyIndex };
    } catch {
      // Not this key. A GCM tag mismatch is the only way this fails for a row
      // sealed under another candidate, and it is indistinguishable from
      // corruption, which is why exhausting the list is reported rather than
      // diagnosed.
    }
  }
  return null;
}

/** {@link decryptItemUnderAnyKey} for a folder's encrypted name. */
export async function decryptFolderNameUnderAnyKey(
  folder: IFolderResponse,
  keys: CryptoKey[],
): Promise<{ name: string; keyIndex: number } | null> {
  for (const [keyIndex, key] of keys.entries()) {
    try {
      return { name: await openFolderName(folder, key), keyIndex };
    } catch {
      // Not this key.
    }
  }
  return null;
}

/**
 * Unwraps one document's key (DEK) under the first candidate vault key that opens
 * it, with that key's index, or `null`. Both wrapping keys are bound to THIS
 * document's id, so a wrapped key moved from another document fails here. The
 * caller owns the DEK it gets back and zeroes it.
 */
export async function unwrapDekUnderAnyKey(
  row: DocumentResponse,
  keys: CryptoKey[],
): Promise<{ dek: DocumentBytes; keyIndex: number } | null> {
  for (const [keyIndex, key] of keys.entries()) {
    try {
      return { dek: await unwrapDek(row, await deriveWrapKey(key, row._id)), keyIndex };
    } catch {
      // Not this key; try the next candidate.
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Which rows no key opens: the verdict a deletion is allowed to act on
// ---------------------------------------------------------------------------

/**
 * Whether `error` is AES-GCM refusing a key: the authentication tag does not match.
 *
 * Matched by NAME. WebCrypto rejects with a `DOMException` named `OperationError`,
 * and under jsdom `instanceof DOMException` is false, so a class check would miss
 * it in the very tests that pin this. Anything else (malformed base64, a binding
 * that cannot be built) is NOT a wrong key, and must never read as one.
 */
export function isAuthenticationFailure(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    (error as { name?: unknown }).name === 'OperationError'
  );
}

/**
 * What a check concluded about one row:
 *
 * - `readable`: every sealed field this check reads opened under one candidate key.
 * - `unreadable`: every one of them failed AES-GCM authentication under EVERY
 *   candidate key. The only verdict a deletion may act on.
 * - `damaged`: anything else (part of the row opens, a field is malformed, the row
 *   is not even shaped like one). Never offered for deletion.
 */
export type RowVerdict = 'readable' | 'unreadable' | 'damaged';

type FieldVerdict = 'opened' | 'refused' | 'malformed';

async function fieldVerdict(open: () => Promise<string>): Promise<FieldVerdict> {
  try {
    await open();
    return 'opened';
  } catch (error) {
    return isAuthenticationFailure(error) ? 'refused' : 'malformed';
  }
}

/** Refuses a check with no candidate key: with none, every row would read as unreadable. */
function assertCandidates(keys: CryptoKey[]): void {
  if (keys.length === 0) throw new Error('A row cannot be judged without a candidate key');
}

/**
 * The verdict on one item, from its NAME and its DATA opened separately under each
 * candidate key (password history is not consulted: it cannot make a row
 * readable, and a damaged entry in it must not make a readable row deletable).
 * A row the store would reject for its shape is `damaged` before any key is tried.
 */
export async function classifyItem(
  item: IVaultItemResponse,
  keys: CryptoKey[],
): Promise<RowVerdict> {
  assertCandidates(keys);
  if (!vaultItemResponseSchema.safeParse(item).success) return 'damaged';
  let malformed = false;
  for (const key of keys) {
    const name = await fieldVerdict(() => openItemName(item, key));
    const data = await fieldVerdict(() => openItemData(item, key));
    if (name === 'opened' && data === 'opened') return 'readable';
    if (name === 'opened' || data === 'opened') return 'damaged';
    if (name === 'malformed' || data === 'malformed') malformed = true;
  }
  return malformed ? 'damaged' : 'unreadable';
}

/** The verdict on one folder, from its name under each candidate key. */
export async function classifyFolder(
  folder: IFolderResponse,
  keys: CryptoKey[],
): Promise<RowVerdict> {
  assertCandidates(keys);
  if (!folderResponseSchema.safeParse(folder).success) return 'damaged';
  let malformed = false;
  for (const key of keys) {
    const name = await fieldVerdict(() => openFolderName(folder, key));
    if (name === 'opened') return 'readable';
    if (name === 'malformed') malformed = true;
  }
  return malformed ? 'damaged' : 'unreadable';
}

/** "2 items, 1 folder": rows counted by leg, in a fixed order, plural-aware. */
export function describeRowCounts(counts: Partial<Record<RotationLeg, number>>): string {
  const parts: string[] = [];
  for (const leg of ['item', 'folder', 'document'] as const) {
    const count = counts[leg] ?? 0;
    if (count > 0) parts.push(`${String(count)} ${leg}${count === 1 ? '' : 's'}`);
  }
  return parts.join(', ');
}

/** {@link describeRowCounts} for a list of rows tagged with their leg. */
export function describeSkippedRows(rows: { leg: RotationLeg }[]): string {
  const counts: Partial<Record<RotationLeg, number>> = {};
  for (const row of rows) counts[row.leg] = (counts[row.leg] ?? 0) + 1;
  return describeRowCounts(counts);
}
