/**
 * Turn a RESOLVED import into the wire `operations` payload.
 *
 * Resolution (see `resolve.ts`) decides what happens to every incoming row;
 * this module is what finally produces ciphertext, and it runs AFTER that
 * decision so nothing is encrypted that will not be sent. Two shapes come out:
 *
 *  - `inserts` — a new item, carrying the six ciphertext fields, a search hash,
 *    tags/favorite and (native re-imports only) a folder id.
 *  - `updates` — an existing item to overwrite in place, naming the `_id` the
 *    resolver matched, with the search hash RECOMPUTED (an overwrite replaces
 *    `encryptedName`, so a stale hash would strand against the old name) and,
 *    when a login's password changes, the previous password prepended to
 *    `passwordHistory` by the SHARED helper `vaultStore.updateItem` also uses.
 *
 * Every row is sealed here, in format v2, to the row it will be stored as, and
 * that is only known once resolution has decided what happens to it: an insert
 * gets an id derived from a fresh nonce it is sent with (`newBoundRow`), and an
 * overwrite is sealed to the matched row's id and STORED type. That includes a
 * native H-Vault row, whose file ciphertext is bound to the row it was exported
 * from (or to nothing, in format v1) and so is never re-sent: extraction opens it
 * and this module seals its stored data string again, byte for byte. Its retained
 * previous passwords are sealed to the new row the same way.
 *
 * Nothing here matches, re-orders or drops silently: a row that cannot be sealed
 * is returned as a counted failure with a human-readable reason, so the caller's
 * accounting still sums to the number of rows parsed.
 */

import { deriveRowId } from '@hvault/shared';
import type { ImportInsertItem, ImportUpdateItem, IPasswordHistoryEntry } from '@hvault/shared';
import { buildPasswordHistoryPayload } from '../crypto/passwordHistory';
import { encryptVaultField, newBoundRow } from '../crypto/vaultField';
import { MAX_IMPORT_WARNINGS, sealImportFields, sealImportItem } from './encrypt';
import type { ImportDestination, SealImportResult } from './encrypt';
import type { ResolvableExistingItem, ResolvedUpdate } from './resolve';
import type { PreviousPassword, ResolvableImportItem } from './types';

/**
 * The extra field an `overwrite` target must expose beyond what the resolver
 * needs: its raw password history, which the shared builder prepends to.
 * `vaultStore`'s `DecryptedVaultItem` satisfies this structurally — the type is
 * declared here rather than imported so the import pipeline keeps its
 * store-independence.
 */
export interface ImportUpdateTarget extends ResolvableExistingItem {
  _raw: { passwordHistory?: IPasswordHistoryEntry[] | undefined };
}

export interface BuiltImportOperations {
  inserts: ImportInsertItem[];
  updates: ImportUpdateItem[];
  /** Rows that could not be sealed (validation or ciphertext-size failure). */
  failedCount: number;
  /** Bounded, human-readable reasons for the failures above. */
  failureReasons: string[];
}

export async function buildImportOperations<E extends ImportUpdateTarget>({
  inserts,
  updates,
  userId,
  vaultKey,
}: {
  inserts: readonly ResolvableImportItem[];
  updates: readonly ResolvedUpdate<ResolvableImportItem, E>[];
  /** This session's own user id, which each insert's id is derived from. */
  userId: string;
  vaultKey: CryptoKey;
}): Promise<BuiltImportOperations> {
  const insertPayloads: ImportInsertItem[] = [];
  const updatePayloads: ImportUpdateItem[] = [];
  const failureReasons: string[] = [];
  let failedCount = 0;

  const fail = (reason: string): void => {
    failedCount++;
    if (failureReasons.length < MAX_IMPORT_WARNINGS) failureReasons.push(reason);
  };

  for (const item of inserts) {
    const row = await newBoundRow(userId);
    const result = await sealRow(item, { rowId: row.rowId, itemType: item.itemType }, vaultKey);
    if (!result.ok) {
      fail(result.reason);
      continue;
    }
    // Only a native re-import carries one: restoring an item from an export must
    // not erase the previous passwords it was exported with. Sealed to the NEW
    // row, since the history is read as this row's from now on.
    const passwordHistory =
      item.previousPasswords === undefined
        ? undefined
        : await sealPreviousPasswords(item.previousPasswords, row.rowId, vaultKey);
    insertPayloads.push({
      itemType: item.itemType,
      ...result.sealed,
      tags: item.tags,
      favorite: item.favorite,
      ...(item.folderId !== undefined ? { folderId: item.folderId } : {}),
      ...(passwordHistory !== undefined ? { passwordHistory } : {}),
      idNonce: row.idNonce,
    });
  }

  for (const { incoming, existing } of updates) {
    // Sealed to the matched row, under the type it is STORED with: matching never
    // crosses item types, but the stored type is the one the data is read under,
    // so it is the one bound, whatever the incoming row claims.
    const result = await sealRow(
      incoming,
      { rowId: existing.id, itemType: existing.itemType },
      vaultKey,
    );
    if (!result.ok) {
      fail(result.reason);
      continue;
    }

    // An overwrite must never lose a password. The old one is encrypted and
    // prepended to the item's history by the same helper the interactive edit
    // path uses, so retention semantics cannot diverge between the two.
    // Matching never crosses item types, so gating on the EXISTING type also
    // gates the incoming one.
    const passwordHistory =
      existing.itemType === 'login'
        ? await buildPasswordHistoryPayload({
            existingRawHistory: existing._raw.passwordHistory,
            oldPassword: existing.data.password,
            newPassword: incoming.data.password,
            rowId: existing.id,
            vaultKey,
          })
        : undefined;

    updatePayloads.push({
      id: existing.id,
      ...result.sealed,
      ...(passwordHistory !== undefined ? { passwordHistory } : {}),
    });
  }

  return { inserts: insertPayloads, updates: updatePayloads, failedCount, failureReasons };
}

/**
 * Seal one row to its destination: a native re-import's stored data string
 * verbatim, anything else validated and serialised from its parsed data.
 *
 * The search hash is computed either way. It is a deterministic HMAC of the name
 * under the vault key's search subkey, so computing it costs nothing and covers
 * both an export that predates the field and an update whose name is replaced.
 */
async function sealRow(
  item: ResolvableImportItem,
  destination: ImportDestination,
  vaultKey: CryptoKey,
): Promise<SealImportResult> {
  if (item.native) {
    return sealImportFields(item.name, item.native.dataJson, destination, vaultKey);
  }
  return sealImportItem(item, destination, vaultKey);
}

/** Retained previous passwords, each sealed to the row whose history they are. */
async function sealPreviousPasswords(
  previous: readonly PreviousPassword[],
  rowId: string,
  vaultKey: CryptoKey,
): Promise<IPasswordHistoryEntry[]> {
  const sealed: IPasswordHistoryEntry[] = [];
  for (const entry of previous) {
    const field = await encryptVaultField(
      entry.password,
      { role: 'item.password-history', rowId },
      vaultKey,
    );
    sealed.push({
      encryptedPassword: field.encrypted,
      iv: field.iv,
      tag: field.tag,
      changedAt: entry.changedAt,
    });
  }
  return sealed;
}

/**
 * Refuses an import batch whose inserts the server did not store where their
 * fields were sealed.
 *
 * Each insert was sealed to the id its nonce derives for this user, and the server
 * echoes, in order, the id each insert was stored under. A server that ignored the
 * nonce (an older one, after a downgrade) would store every row under an id of its
 * own, and every one of them would be unreadable; that is reported, loudly, rather
 * than counted as imported. `insertedIds` is `undefined` from exactly such a server.
 */
export async function assertInsertedWhereSealed(
  userId: string,
  inserts: readonly ImportInsertItem[],
  insertedIds: readonly string[] | undefined,
): Promise<void> {
  const expected: string[] = [];
  for (const insert of inserts) {
    expected.push(insert.idNonce === undefined ? '' : await deriveRowId(userId, insert.idNonce));
  }
  const matches =
    insertedIds?.length === expected.length &&
    expected.every((id, index) => id === '' || insertedIds[index]?.toLowerCase() === id);
  if (!matches) {
    throw new Error(
      'The server stored imported entries under unexpected ids, so their encrypted fields cannot be read back. Stop importing, reload the app and check the server version.',
    );
  }
}
