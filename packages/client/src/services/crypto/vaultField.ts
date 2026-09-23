/**
 * vaultField: which row and which field a vault ciphertext belongs to.
 *
 * A vault field (an item's name, its data, one of its password-history entries,
 * a folder's name) is an AES-256-GCM triple under the vault key. In format v1,
 * which every field written so far uses, the triple authenticates its own bytes
 * and nothing else, so a server that cannot read a byte can still put genuine
 * ciphertext in the wrong place: another row's data under this row's name, the
 * data in the name slot, a login's data under a note. Every one of those opens.
 *
 * Format v2 seals the same triple with AES-GCM additional data naming the field's
 * role and its row id, and for the data, the item type the data is read under:
 *
 *   aad(item.name)             = "hvault/vault-field/v2|item.name|"             || rowId
 *   aad(item.data)             = "hvault/vault-field/v2|item.data|" || itemType || "|" || rowId
 *   aad(item.password-history) = "hvault/vault-field/v2|item.password-history|" || rowId
 *   aad(folder.name)           = "hvault/vault-field/v2|folder.name|"           || rowId
 *
 * A v2 field moved anywhere else fails its tag check. It is refused, not detected
 * after the fact, which is the property `documentCryptoService` already gives
 * documents by putting the document id inside every derivation.
 *
 * What the binding does NOT do, stated so nobody claims it:
 *
 *   - Replay within a field. The same field of the same row carries the same
 *     additional data in every version of that row, so a server replaying an
 *     OLDER triple of that field onto the row it came from is not refused.
 *     Refusing it needs a version the client can check, which this format does
 *     not carry.
 *   - Downgrade. An unmarked field is opened as v1, in any slot of any row, for
 *     as long as v1 is read at all, and rewriting a row as v2 does not retire the
 *     v1 triples a server kept from before. So the substitution v2 refuses stays
 *     possible with any v1 triple still valid under the current key. Closing it
 *     needs those triples retired (a rotation to a new key does that) and a
 *     client-checkable "this vault is fully bound" state; this format provides
 *     neither.
 *   - Removing a row, or reordering, dropping or duplicating entries within one
 *     item's own password history (they share one binding, on purpose: an
 *     entry's position shifts every time a password changes).
 *
 * Three decisions, each of which would be a defect the other way:
 *
 *   - The marker is on the IV STRING (`VAULT_FIELD_V2_IV_MARKER`), not on the
 *     ciphertext. Every ciphertext bound is exact and v1 rows already sit on
 *     them (an item name is bounded only by its ciphertext), so a prefix there
 *     would refuse a re-seal of a row that exists today; every IV bound is 24
 *     characters against a 16-character value.
 *   - The marker SELECTS the format; nothing falls back. A marked field that
 *     fails is refused, an unmarked one is opened exactly as v1 always was.
 *     Retrying a failed v2 field without the additional data could never open
 *     it (GCM authenticates the additional data), and a server that wants v1
 *     semantics can simply present a v1 triple, so a fallback buys nothing and
 *     would cost every legacy read a second decryption.
 *   - No user id. Vault keys are per account and never shared, so an account
 *     boundary is already a key boundary, and the documents this models bind
 *     their id alone. A user id would only add a value that restore and import
 *     have to recover from a file, and a row that fails to decrypt forever when
 *     they recover the wrong one.
 *
 * This module is the ONE definition of the byte layout. Nothing here writes v2:
 * this release reads both formats and keeps writing v1.
 */

import { ITEM_TYPES, VAULT_FIELD_AAD_PREFIX, VAULT_FIELD_V2_IV_MARKER } from '@hvault/shared';
import type { ItemType, VaultFieldRole } from '@hvault/shared';
import { cryptoService } from './cryptoService';

/**
 * Where a field lives. `item.data` alone names the item type too, because the
 * type decides which schema the data is read under and every schema is lenient
 * enough to accept another type's data with fields silently stripped.
 */
export type VaultFieldBinding =
  | { readonly role: Exclude<VaultFieldRole, 'item.data'>; readonly rowId: string }
  | { readonly role: 'item.data'; readonly rowId: string; readonly itemType: ItemType };

/** A stored triple, as the server returns it. */
export interface VaultFieldCiphertext {
  readonly encrypted: string;
  readonly iv: string;
  readonly tag: string;
}

/** A 24-character hex ObjectId, in either case, and nothing else. */
const OBJECT_ID_RE = /^[0-9a-f]{24}$/i;

/**
 * The additional data a v2 field is sealed with, for exactly one binding.
 *
 * Throws on a row id that is not an ObjectId and on an item type outside
 * `ITEM_TYPES`, both of which the type system cannot rule out because callers
 * read them from a server response or a file. Refusing is what keeps the layout
 * unambiguous: with both tokens from closed or fixed-width alphabets that cannot
 * hold a `|`, no two bindings produce the same bytes. The id is lower-cased,
 * the same canonical form `objectIdSchema` gives it, so a server that re-spells
 * an id cannot make a row it cannot otherwise touch unreadable.
 */
export function vaultFieldAad(binding: VaultFieldBinding): Uint8Array<ArrayBuffer> {
  if (!OBJECT_ID_RE.test(binding.rowId)) {
    throw new Error('A vault field is bound to an ObjectId row id');
  }
  const rowId = binding.rowId.toLowerCase();
  let text: string;
  if (binding.role === 'item.data') {
    if (!(ITEM_TYPES as readonly string[]).includes(binding.itemType)) {
      throw new Error('A vault item’s data is bound to a known item type');
    }
    text = `${VAULT_FIELD_AAD_PREFIX}item.data|${binding.itemType}|${rowId}`;
  } else {
    text = `${VAULT_FIELD_AAD_PREFIX}${binding.role}|${rowId}`;
  }
  return new TextEncoder().encode(text);
}

/**
 * Whether a stored field is format v2, read off its IV alone.
 *
 * An exact prefix test with no trimming: `atob` ignores ASCII whitespace, so a
 * lenient test here and a strict one in the decoder would disagree about the
 * same string.
 */
export function isBoundField(iv: string): boolean {
  return iv.startsWith(VAULT_FIELD_V2_IV_MARKER);
}

/**
 * Open one vault field, in whichever format it is stored.
 *
 * An unmarked field goes to `cryptoService.decryptData` with exactly the
 * arguments every caller passed before v2 existed, and its binding is never
 * examined: a v1 vault is read by the same code path it always was, including
 * wherever no valid binding could be built. A marked field is opened with its
 * additional data, and a binding that cannot be built rejects here, inside the
 * decrypt, so every caller's existing per-row failure handling degrades that one
 * row instead of failing the list it is in.
 *
 * The binding is REQUIRED even for a v1 field, so that no call site can compile
 * without saying where its field lives.
 */
export async function decryptVaultField(
  field: VaultFieldCiphertext,
  binding: VaultFieldBinding,
  vaultKey: CryptoKey,
): Promise<string> {
  if (!isBoundField(field.iv)) {
    return cryptoService.decryptData(field.encrypted, field.iv, field.tag, vaultKey);
  }
  const additionalData = vaultFieldAad(binding);
  return cryptoService.decryptDataWithAad(
    field.encrypted,
    field.iv.slice(VAULT_FIELD_V2_IV_MARKER.length),
    field.tag,
    vaultKey,
    additionalData,
  );
}
