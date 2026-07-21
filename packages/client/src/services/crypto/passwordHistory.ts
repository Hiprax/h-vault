/**
 * Shared password-history builder.
 *
 * When a login's password changes, the OLD password is encrypted and prepended
 * to the item's `passwordHistory`, capped at {@link PASSWORD_HISTORY_MAX}
 * entries. This behaviour lives in ONE place so the two ciphertext-writing paths
 * that need it — an interactive edit through `vaultStore.updateItem` and an
 * `overwrite` import through the resolver-driven import flow — can never drift
 * apart. A change to retention semantics applies to both at once.
 *
 * The helper is deliberately narrow: it decides only whether the password
 * changed and, if so, produces the history payload. The CALLER is responsible
 * for restricting this to login items — a non-login has no `password` field, so
 * passing its (absent) values through is a no-op, but callers still gate on the
 * item type to keep intent explicit.
 */

import { PASSWORD_HISTORY_MAX } from '@hvault/shared';
import type { IPasswordHistoryEntry } from '@hvault/shared';
import { cryptoService } from './cryptoService';

export interface BuildPasswordHistoryArgs {
  /** The matched item's existing `passwordHistory` (its `_raw.passwordHistory`). */
  existingRawHistory: IPasswordHistoryEntry[] | undefined;
  /** The password currently stored on the item (decrypted). */
  oldPassword: unknown;
  /** The password the update would write (decrypted). */
  newPassword: unknown;
  vaultKey: CryptoKey;
}

/**
 * Build the `passwordHistory` payload for an update, or `undefined` when the
 * password did not change (so the caller omits the field entirely).
 *
 * A change is recorded ONLY when the old password is a non-empty string, the new
 * password is a string, and the two differ. The old password is encrypted with
 * the vault key, stamped with the current time, prepended to the existing
 * history, and the result is sliced to the {@link PASSWORD_HISTORY_MAX} most
 * recent entries. Existing entries are copied field-by-field so no extraneous
 * keys ride along into the request body.
 */
export async function buildPasswordHistoryPayload({
  existingRawHistory,
  oldPassword,
  newPassword,
  vaultKey,
}: BuildPasswordHistoryArgs): Promise<IPasswordHistoryEntry[] | undefined> {
  if (
    typeof oldPassword !== 'string' ||
    oldPassword.length === 0 ||
    typeof newPassword !== 'string' ||
    oldPassword === newPassword
  ) {
    return undefined;
  }

  const encrypted = await cryptoService.encryptData(oldPassword, vaultKey);

  const existingHistory = (existingRawHistory ?? []).map((entry) => ({
    encryptedPassword: entry.encryptedPassword,
    iv: entry.iv,
    tag: entry.tag,
    changedAt: entry.changedAt,
  }));

  return [
    {
      encryptedPassword: encrypted.encrypted,
      iv: encrypted.iv,
      tag: encrypted.tag,
      changedAt: new Date().toISOString(),
    },
    ...existingHistory,
  ].slice(0, PASSWORD_HISTORY_MAX);
}
