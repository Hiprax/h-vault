/**
 * Helpers for reasoning about a DECRYPTED vault item's `data` object.
 *
 * `vaultStore.decryptItem` keeps a PLACEHOLDER in `item.data` when a decrypted
 * payload fails schema validation or JSON parsing: either the partially-parsed
 * object stamped `{ ..., _validationError: true }` or the raw wrapper
 * `{ _raw: <original> }`. Such an object is NOT the item's real content, so any
 * consumer that treats `data` as genuine content must first exclude it.
 */

/**
 * True when the decrypted `data` object is the un-defaulted raw fallback that
 * `vaultStore` keeps after a schema-validation or JSON-parse failure.
 *
 * Two consumers rely on this, and they must agree: the detail view degrades such
 * an item to a read-only "could not be decoded" notice (routing metadata edits
 * through `updateItemMeta` so its real ciphertext is never overwritten), and the
 * import resolver excludes it from the match index entirely — a placeholder's key
 * would be meaningless, and making it an `overwrite` target would replace genuine
 * ciphertext with a re-encrypted placeholder.
 */
export function isUndecodableData(data: Record<string, unknown>): boolean {
  return data._validationError === true || '_raw' in data;
}
