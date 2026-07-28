/**
 * The postal-address vocabulary shared by a CARD's `billingAddress` and an
 * IDENTITY's `address`, and the helpers that let one be filled from the other.
 *
 * The shared schemas already state the relationship: `addressSchema` is the SIX
 * base fields, and `identityAddressSchema` is `addressSchema.extend({
 * deliveryNotes })`. An identity's address is therefore provably a superset of
 * what a card can hold, which is what makes "fill this card's billing address
 * from a saved identity" a total function rather than a lossy one — every field
 * this module copies exists on both shapes, under the same name, with the SAME
 * length bound (both sides read the one `MAX_ADDRESS_*` constant).
 *
 * Three rules govern `deliveryNotes`, and all three are load-bearing:
 *
 * 1. **It is never copied.** The base `addressSchema` runs in STRIP mode, so a
 *    `deliveryNotes` key inside a card's `billingAddress` is dropped on
 *    read-back — copying it would write a value the next decrypt silently
 *    discards, which is the quiet kind of data loss this codebase avoids.
 * 2. **It is never displayed.** Delivery instructions routinely carry a door
 *    code or an alarm code, which is why `getItemSubtitle` refuses to surface
 *    them on a vault-list row. A picker that renders many identities at once is
 *    the same exposure surface and follows the same rule.
 * 3. **It is never searched.** Search here matches exactly what is rendered
 *    ({@link addressSearchText}), so a value that cannot be shown cannot be
 *    probed for either.
 *
 * `BASE_ADDRESS_FIELDS` lives here rather than in `VaultItemForm` because three
 * consumers now have to agree on it: the form's stored-path error mapping, the
 * form's billing controls, and the picker that writes them.
 */

/**
 * The six fields of the base postal address, in the order a reader expects them.
 *
 * This is the ONE list. `readBaseAddress` and the fill both iterate it, so a
 * seventh base field added to `addressSchema` joins both by editing one line —
 * and, just as importantly, a field that is NOT on it (`deliveryNotes`) cannot
 * be reached by either, structurally rather than by convention.
 */
export const BASE_ADDRESS_FIELDS = [
  'street',
  'street2',
  'city',
  'state',
  'zip',
  'country',
] as const;

export type BaseAddressField = (typeof BASE_ADDRESS_FIELDS)[number];

/** The six base address fields, every one a string (`''` when absent). */
export type BaseAddress = Record<BaseAddressField, string>;

/**
 * Narrows an arbitrary key to one of the six base fields.
 *
 * The narrowing is the point, not the boolean: it is what stops
 * {@link billingFieldName} from ever being handed `deliveryNotes` and inventing a
 * `billingDeliveryNotes` control that does not and must not exist.
 */
export function isBaseAddressField(value: string): value is BaseAddressField {
  return (BASE_ADDRESS_FIELDS as readonly string[]).includes(value);
}

/**
 * The card form's control name for a base address field: `street2` ->
 * `billingStreet2`.
 *
 * A card models its billing address FLAT and prefixed, because a single
 * react-hook-form field name cannot collide with the identity form's unprefixed
 * `street`. Both the store-side error mapping and the picker's `setValue` calls
 * have to produce the same names, so the transformation is stated once.
 */
export function billingFieldName(field: BaseAddressField): string {
  return `billing${field.charAt(0).toUpperCase()}${field.slice(1)}`;
}

/**
 * The six card billing control names, in {@link BASE_ADDRESS_FIELDS} order.
 *
 * Derived rather than written out so it cannot fall behind the field list; the
 * form uses it to clear, validate and snapshot the whole section at once.
 */
export const BILLING_ADDRESS_FIELD_NAMES: readonly string[] =
  BASE_ADDRESS_FIELDS.map(billingFieldName);

/**
 * The six base fields of an arbitrary decrypted `address` / `billingAddress`
 * value, each coerced to a string.
 *
 * `value` is `unknown` on purpose: it comes out of a decrypted `data` blob,
 * which is typed `Record<string, unknown>`. Anything that is not a plain object
 * (absent, `null`, an array, a string) yields an all-empty address rather than
 * throwing, so a malformed payload degrades to "this identity has no address"
 * instead of breaking the form it is rendered in.
 *
 * Only the six base fields are read. `deliveryNotes` is not reachable from here
 * even if present — see the module docblock.
 */
export function readBaseAddress(value: unknown): BaseAddress {
  const source =
    typeof value === 'object' && value !== null && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : {};
  const address = {} as BaseAddress;
  for (const field of BASE_ADDRESS_FIELDS) {
    const raw = source[field];
    address[field] = typeof raw === 'string' ? raw : '';
  }
  return address;
}

/**
 * True when at least one base field holds something a reader would see.
 *
 * Trimmed, unlike `hasAnyValue` (`lib/vaultData`), and the difference is
 * deliberate. `hasAnyValue` answers "did the user put anything in this section"
 * for a form that must not discard a value it was given; this answers "is there
 * an address worth OFFERING", where an all-whitespace one is an option that
 * appears blank and fills nothing visible.
 */
export function hasBaseAddressValue(address: BaseAddress): boolean {
  return BASE_ADDRESS_FIELDS.some((field) => address[field].trim().length > 0);
}

/**
 * The address as the one to three lines a person would write on an envelope,
 * skipping every empty part.
 *
 * Grouping (rather than one line per field) is what keeps a picker row readable:
 * a six-line block for every option would push the list past a screen, and a
 * flat comma-join would read `1 Main St, , London, , 12345,` for the common case
 * of a partially-filled address.
 */
export function formatAddressLines(address: BaseAddress): string[] {
  const trimmed = (field: BaseAddressField): string => address[field].trim();
  const cityLine = [[trimmed('city'), trimmed('state')].filter(Boolean).join(', '), trimmed('zip')]
    .filter(Boolean)
    .join(' ');
  return [
    [trimmed('street'), trimmed('street2')].filter(Boolean).join(', '),
    cityLine,
    trimmed('country'),
  ].filter(Boolean);
}

/**
 * A single line summarising the address, for a picker row that has one line to
 * spend on it.
 */
export function formatAddressSummary(address: BaseAddress): string {
  return formatAddressLines(address).join(' · ');
}

/**
 * The haystack a saved-address option is searched against: exactly the strings
 * the option RENDERS, and nothing else.
 *
 * That equivalence is the whole safety argument. Searching a field the row
 * cannot display would turn the picker into an oracle — type a guess, watch the
 * list filter — over values (`deliveryNotes`, and by extension anything else
 * added to the identity schema later) that this surface deliberately never
 * shows. Building the haystack from the rendered strings makes the two
 * impossible to drift apart.
 */
export function addressSearchText(parts: readonly string[]): string {
  return parts.filter(Boolean).join(' ').toLowerCase();
}

/**
 * True when every whitespace-separated term of `query` appears in `haystack`.
 *
 * Token-wise rather than as one substring so the terms can be typed in any
 * order and drawn from different parts of the row — "ada london" finds the
 * London address on Ada's identity, which a substring match over
 * `"Home address Ada Lovelace · 1 Main St · London"` would not.
 *
 * `haystack` is expected to be lower-cased already (that is what
 * {@link addressSearchText} returns); the query is lower-cased here.
 */
export function matchesSearchQuery(haystack: string, query: string): boolean {
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  return terms.every((term) => haystack.includes(term));
}
