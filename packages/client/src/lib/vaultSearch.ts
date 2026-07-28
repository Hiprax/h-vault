import type { ItemType } from '@hvault/shared';

const TYPE_LABELS: Record<ItemType, string> = {
  login: 'Login',
  note: 'Note',
  card: 'Card',
  identity: 'Identity',
  secret: 'Secret',
};

/**
 * How many times {@link valueMatches} may DESCEND into a container.
 *
 * 2 is exactly what the decrypted schemas can produce. Counting hops from
 * `item.data`, a string is searched at:
 *   hop 1 (0 descents)  `data.password`, `data.notes`
 *   hop 2 (1 descent)   `data.address.city`, an element of a string array
 *   hop 3 (2 descents)  `data.uris[i].uri`, `data.customFields[i].value`
 * and a container at hop 4 is not entered. Note the string check runs BEFORE the
 * depth check, so `2` reaches three hops, not two — an off-by-one here silently
 * widens the walk past the contract.
 *
 * The bound is required rather than merely tidy: it is what makes a
 * self-referential object from a hand-crafted or corrupted blob terminate instead
 * of overflowing the stack, on every keystroke, over every item.
 */
const MAX_NESTED_DESCENTS = 2;

/**
 * True when `value`, or anything nested inside it within
 * {@link MAX_NESTED_DESCENTS}, contains `lowerQuery`.
 *
 * Arrays and plain objects go down the same path deliberately: `Object.values`
 * yields an array's elements and an object's field values alike, so one branch
 * covers `uris`, `customFields`, and the nested `address` / `billingAddress`
 * objects. That last case is the fix — the previous implementation handled only
 * strings and arrays, so NO address field (`street`, `street2`, `city`, `state`,
 * `zip`, `country`, `deliveryNotes`) had ever been searchable on an identity or a
 * card.
 */
function valueMatches(value: unknown, lowerQuery: string, descentsLeft: number): boolean {
  if (typeof value === 'string') return value.toLowerCase().includes(lowerQuery);
  if (descentsLeft <= 0 || typeof value !== 'object' || value === null) return false;
  return Object.values(value as Record<string, unknown>).some((nested) =>
    valueMatches(nested, lowerQuery, descentsLeft - 1),
  );
}

/**
 * Tests whether a vault item matches a search query.
 * Searches across the item name, tags, type label, and all decrypted data fields.
 */
export function itemMatchesSearch(
  item: {
    name: string;
    tags: string[];
    itemType: ItemType;
    data: Record<string, unknown>;
  },
  lowerQuery: string,
): boolean {
  // Search item name
  if (item.name.toLowerCase().includes(lowerQuery)) return true;

  // Search tags
  if (item.tags.some((tag) => tag.toLowerCase().includes(lowerQuery))) return true;

  // Search item type label
  if (TYPE_LABELS[item.itemType].toLowerCase().includes(lowerQuery)) return true;

  // Search through decrypted data fields, including nested objects and arrays
  // (see `valueMatches`). Every string is matched, including the secret ones: a
  // password has always been searchable here, and a login's backup codes are too.
  //
  // That is deliberate and not an oversight, and the reasoning SURVIVES the
  // widening to nested objects — it turns on what a match can DISPLAY, not on
  // which field matched. This function returns a boolean; the row it admits to
  // the list is labelled by `getItemSubtitle` (`lib/vaultDisplay.ts`), which
  // allowlists non-secret fields and reads NOTHING from a nested object. So the
  // newly-searchable fields — an address's `street`, `zip`, and in particular
  // `deliveryNotes`, which routinely holds a building access code — can be
  // searched FOR but still cannot be rendered by matching (asserted by
  // `vault-list-subtitle.test.tsx`). Searching only ever lets you find an item by
  // a value you already hold. Excluding one secret field and not the others would
  // be an inconsistent half-measure and the first exception in this function.
  return Object.values(item.data).some((value) =>
    valueMatches(value, lowerQuery, MAX_NESTED_DESCENTS),
  );
}
