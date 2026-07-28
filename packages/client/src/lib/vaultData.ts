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

/**
 * "Is ANY of these non-empty" — the presence predicate for a postal address, whose
 * fields are all stored with a `''` default.
 *
 * A list plus `.some`, never a `||` / `??` chain. `??` is outright WRONG here: `''`
 * is not nullish, so the chain short-circuits on the first field — the shipped
 * `showBillingAddress` bug, where a card whose street line was empty but whose city
 * was filled opened with the address section COLLAPSED. `prefer-nullish-coalescing`
 * is what pushes a `||` chain in that direction, so the list form is what both the
 * lint rule and the semantics accept. It also costs ONE branch where an n-term
 * chain costs n, which matters on a client whose branch-coverage threshold has
 * about a point of headroom.
 *
 * Defined here, next to {@link isUndecodableData}, because THREE call sites must
 * agree on it: the item form's section toggle, the form's decision whether to emit
 * an address at all, and the detail view's row guards.
 */
export function hasAnyValue(values: readonly (string | undefined)[]): boolean {
  return values.some((value) => Boolean(value));
}
