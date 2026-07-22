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
 * A native H-Vault row is already encrypted under the CURRENT vault key, so its
 * ciphertext is re-sent verbatim rather than decrypt-and-re-encrypted; only the
 * deterministic search hash is recomputed (an older export may not carry one).
 *
 * Nothing here matches, re-orders or drops silently: a row that cannot be sealed
 * is returned as a counted failure with a human-readable reason, so the caller's
 * accounting still sums to the number of rows parsed.
 */

import { MAX_ENCRYPTED_DATA_LENGTH, MAX_ENCRYPTED_NAME_LENGTH } from '@hvault/shared';
import type { ImportInsertItem, ImportUpdateItem, IPasswordHistoryEntry } from '@hvault/shared';
import { cryptoService } from '../crypto/cryptoService';
import { buildPasswordHistoryPayload } from '../crypto/passwordHistory';
import { MAX_IMPORT_WARNINGS, sealImportItem } from './encrypt';
import type { SealImportResult } from './encrypt';
import type { ResolvableExistingItem, ResolvedUpdate } from './resolve';
import type { ResolvableImportItem } from './types';

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
  vaultKey,
}: {
  inserts: readonly ResolvableImportItem[];
  updates: readonly ResolvedUpdate<ResolvableImportItem, E>[];
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
    const result = await sealRow(item, vaultKey);
    if (!result.ok) {
      fail(result.reason);
      continue;
    }
    insertPayloads.push({
      itemType: item.itemType,
      ...result.sealed,
      tags: item.tags,
      favorite: item.favorite,
      ...(item.folderId !== undefined ? { folderId: item.folderId } : {}),
      // Only a native re-import carries one: restoring an item from an export
      // must not erase the previous passwords it was exported with.
      ...(item.passwordHistory !== undefined ? { passwordHistory: item.passwordHistory } : {}),
    });
  }

  for (const { incoming, existing } of updates) {
    const result = await sealRow(incoming, vaultKey);
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
 * Seal one row: re-use its existing ciphertext when it already has some (native
 * re-import), otherwise validate and encrypt its plaintext.
 *
 * The search hash is recomputed either way. It is a deterministic HMAC of the
 * name under the vault key, so recomputing costs nothing and covers both an
 * export that predates the field and an update whose name is being replaced.
 */
async function sealRow(item: ResolvableImportItem, vaultKey: CryptoKey): Promise<SealImportResult> {
  if (item.cipher) {
    // A row the vault itself wrote is always within these bounds, so this only
    // catches a tampered export — and catches it as ONE reported row rather than
    // as a server-side rejection of the whole batch it happens to ride in.
    if (
      item.cipher.encryptedName.length > MAX_ENCRYPTED_NAME_LENGTH ||
      item.cipher.encryptedData.length > MAX_ENCRYPTED_DATA_LENGTH
    ) {
      return { ok: false, reason: `Skipped "${item.name}": item is too large to store.` };
    }
    const searchHash = await cryptoService.generateSearchHash(item.name, vaultKey);
    return { ok: true, sealed: { ...item.cipher, searchHash } };
  }
  return sealImportItem(item, vaultKey);
}
