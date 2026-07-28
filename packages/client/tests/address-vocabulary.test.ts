import { describe, it, expect } from 'vitest';
import {
  BASE_ADDRESS_FIELDS,
  BILLING_ADDRESS_FIELD_NAMES,
  addressSearchText,
  billingFieldName,
  formatAddressLines,
  formatAddressSummary,
  hasBaseAddressValue,
  isBaseAddressField,
  matchesSearchQuery,
  readBaseAddress,
  type BaseAddress,
  type BaseAddressField,
} from '../src/lib/address';
import {
  cardDataSchema,
  identityDataSchema,
  MAX_ADDRESS_CITY_LENGTH,
  MAX_ADDRESS_COUNTRY_LENGTH,
  MAX_ADDRESS_STATE_LENGTH,
  MAX_ADDRESS_STREET_LENGTH,
  MAX_ADDRESS_ZIP_LENGTH,
} from '@hvault/shared';

/**
 * The postal-address vocabulary shared by a card's `billingAddress` and an
 * identity's `address`.
 *
 * What this file pins, in order of how expensive the mistake would be:
 *
 * 1. **`deliveryNotes` is unreachable.** Every helper here is driven by
 *    `BASE_ADDRESS_FIELDS`, so an identity-only field cannot be read, rendered,
 *    searched or turned into a control name. That is the invariant that keeps a
 *    door code out of a picker that renders many identities at once, and keeps a
 *    card from storing a key the shared schema strips on read-back.
 * 2. **The two sides share one bound per field**, which is what makes copying an
 *    identity's address into a card's billing address safe WITHOUT clamping —
 *    a clamp would silently truncate, and no clamp plus divergent bounds would
 *    store a value the next decrypt rejects.
 * 3. The formatting and matching contracts the picker depends on.
 *
 * It deliberately does NOT test the React picker (see
 * `tests/components/SavedAddressPicker.test.tsx`) or the form wiring (see
 * `tests/coverage-vault-item-form.test.tsx`).
 */

function address(overrides: Partial<BaseAddress> = {}): BaseAddress {
  return {
    street: '',
    street2: '',
    city: '',
    state: '',
    zip: '',
    country: '',
    ...overrides,
  };
}

describe('address vocabulary — the field list', () => {
  it('is exactly the six base fields, in envelope order', () => {
    expect(BASE_ADDRESS_FIELDS).toEqual(['street', 'street2', 'city', 'state', 'zip', 'country']);
  });

  it('does not contain deliveryNotes, which is identity-only', () => {
    expect(BASE_ADDRESS_FIELDS).not.toContain('deliveryNotes');
    expect(isBaseAddressField('deliveryNotes')).toBe(false);
  });

  it('narrows a real base field and rejects anything else', () => {
    expect(isBaseAddressField('street2')).toBe(true);
    expect(isBaseAddressField('country')).toBe(true);
    expect(isBaseAddressField('cardholderName')).toBe(false);
    expect(isBaseAddressField('')).toBe(false);
    // Prototype keys must not be admitted by a plain `includes` over an array.
    expect(isBaseAddressField('toString')).toBe(false);
  });
});

describe('address vocabulary — billing control names', () => {
  it('prefixes and capitalizes', () => {
    expect(billingFieldName('street')).toBe('billingStreet');
    expect(billingFieldName('street2')).toBe('billingStreet2');
    expect(billingFieldName('zip')).toBe('billingZip');
  });

  it('derives the control-name list from the field list, in the same order', () => {
    expect(BILLING_ADDRESS_FIELD_NAMES).toEqual([
      'billingStreet',
      'billingStreet2',
      'billingCity',
      'billingState',
      'billingZip',
      'billingCountry',
    ]);
    expect(BILLING_ADDRESS_FIELD_NAMES).toHaveLength(BASE_ADDRESS_FIELDS.length);
  });

  it('never produces a billingDeliveryNotes control name', () => {
    expect(BILLING_ADDRESS_FIELD_NAMES).not.toContain('billingDeliveryNotes');
  });
});

describe('address vocabulary — reading an unknown decrypted value', () => {
  it('reads the six base fields verbatim', () => {
    const result = readBaseAddress({
      street: '1 Main St',
      street2: 'Flat 2',
      city: 'London',
      state: 'Greater London',
      zip: 'EC1A 1BB',
      country: 'United Kingdom',
    });
    expect(result).toEqual({
      street: '1 Main St',
      street2: 'Flat 2',
      city: 'London',
      state: 'Greater London',
      zip: 'EC1A 1BB',
      country: 'United Kingdom',
    });
  });

  it('does NOT read deliveryNotes, even when the source carries one', () => {
    const result = readBaseAddress({
      street: '1 Main St',
      deliveryNotes: 'Door code 4821, alarm code 90210',
    });
    expect(result).not.toHaveProperty('deliveryNotes');
    expect(Object.values(result)).not.toContain('Door code 4821, alarm code 90210');
    expect(JSON.stringify(result)).not.toContain('4821');
  });

  it('ignores extra keys entirely', () => {
    const result = readBaseAddress({ street: 'x', ssn: '123-45-6789', passport: 'X1234' });
    expect(Object.keys(result).sort()).toEqual([...BASE_ADDRESS_FIELDS].sort());
  });

  it('yields an all-empty address for anything that is not a plain object', () => {
    const empty = address();
    expect(readBaseAddress(undefined)).toEqual(empty);
    expect(readBaseAddress(null)).toEqual(empty);
    expect(readBaseAddress('1 Main St')).toEqual(empty);
    expect(readBaseAddress(42)).toEqual(empty);
    expect(readBaseAddress(['1 Main St'])).toEqual(empty);
  });

  it('coerces a non-string field to an empty string rather than leaking it', () => {
    const result = readBaseAddress({ street: 12345, city: null, zip: { nested: true } });
    expect(result.street).toBe('');
    expect(result.city).toBe('');
    expect(result.zip).toBe('');
  });
});

describe('address vocabulary — presence', () => {
  it('is false for an all-empty address', () => {
    expect(hasBaseAddressValue(address())).toBe(false);
  });

  it('is false when every field is only whitespace', () => {
    expect(hasBaseAddressValue(address({ street: '   ', city: '\t\n' }))).toBe(false);
  });

  it('is true for any single filled field, including the ones a chain would skip', () => {
    for (const field of BASE_ADDRESS_FIELDS) {
      expect(hasBaseAddressValue(address({ [field]: 'value' }))).toBe(true);
    }
  });
});

describe('address vocabulary — formatting', () => {
  it('groups a full address into street, locality and country lines', () => {
    expect(
      formatAddressLines(
        address({
          street: '1 Main St',
          street2: 'Flat 2',
          city: 'London',
          state: 'Greater London',
          zip: 'EC1A 1BB',
          country: 'United Kingdom',
        }),
      ),
    ).toEqual(['1 Main St, Flat 2', 'London, Greater London EC1A 1BB', 'United Kingdom']);
  });

  it('emits no empty lines and no dangling separators for a partial address', () => {
    expect(formatAddressLines(address({ street: '1 Main St' }))).toEqual(['1 Main St']);
    expect(formatAddressLines(address({ street2: 'Flat 2' }))).toEqual(['Flat 2']);
    expect(formatAddressLines(address({ city: 'London' }))).toEqual(['London']);
    expect(formatAddressLines(address({ state: 'CA' }))).toEqual(['CA']);
    expect(formatAddressLines(address({ zip: '94105' }))).toEqual(['94105']);
    expect(formatAddressLines(address({ country: 'France' }))).toEqual(['France']);
    expect(formatAddressLines(address({ city: 'Paris', zip: '75001' }))).toEqual(['Paris 75001']);
    expect(formatAddressLines(address({ state: 'CA', zip: '94105' }))).toEqual(['CA 94105']);
  });

  it('returns no lines at all for an empty address', () => {
    expect(formatAddressLines(address())).toEqual([]);
    expect(formatAddressSummary(address())).toBe('');
  });

  it('trims each part rather than rendering padded values', () => {
    expect(formatAddressLines(address({ street: '  1 Main St  ', city: ' London ' }))).toEqual([
      '1 Main St',
      'London',
    ]);
  });

  it('joins the lines with a middle dot for a one-line summary', () => {
    expect(
      formatAddressSummary(address({ street: '1 Main St', city: 'London', country: 'UK' })),
    ).toBe('1 Main St · London · UK');
  });
});

describe('address vocabulary — search', () => {
  it('builds a lower-cased haystack out of the given parts, dropping empties', () => {
    expect(addressSearchText(['Home', '', 'Ada Lovelace', '1 Main St'])).toBe(
      'home ada lovelace 1 main st',
    );
  });

  it('matches when every term appears, in any order and from any part', () => {
    const haystack = addressSearchText(['Home address', 'Ada Lovelace', '1 Main St · London']);
    expect(matchesSearchQuery(haystack, 'ada london')).toBe(true);
    expect(matchesSearchQuery(haystack, 'london ada')).toBe(true);
    expect(matchesSearchQuery(haystack, 'ADA')).toBe(true);
    expect(matchesSearchQuery(haystack, 'main')).toBe(true);
  });

  it('fails when any single term is absent', () => {
    const haystack = addressSearchText(['Home address', 'Ada Lovelace', '1 Main St · London']);
    expect(matchesSearchQuery(haystack, 'ada paris')).toBe(false);
    expect(matchesSearchQuery(haystack, 'zzz')).toBe(false);
  });

  it('matches everything for an empty or whitespace-only query', () => {
    expect(matchesSearchQuery('anything', '')).toBe(true);
    expect(matchesSearchQuery('anything', '   ')).toBe(true);
  });
});

describe('address vocabulary — a card can hold every field an identity offers', () => {
  /**
   * The safety argument for filling a card's billing address from an identity:
   * every base field is bounded identically on both shapes, so a copied value
   * can never exceed the cap of the control it lands in and no clamping (which
   * would silently truncate) is required.
   *
   * Asserted THROUGH THE REAL SCHEMAS, never against a hand-written table of the
   * constants. A table only restates what the author believed; parsing proves it.
   * The distinction is not academic — narrowing `addressSchema.street` to
   * `max(50)` while leaving `MAX_ADDRESS_STREET_LENGTH` at 500 is exactly the
   * change that would start writing card billing addresses the card's own schema
   * rejects on the next decrypt, degrading the whole item to the "could not be
   * fully decoded" notice, and a table-based test would stay green through it.
   */
  const BOUNDS: Record<BaseAddressField, number> = {
    street: MAX_ADDRESS_STREET_LENGTH,
    street2: MAX_ADDRESS_STREET_LENGTH,
    city: MAX_ADDRESS_CITY_LENGTH,
    state: MAX_ADDRESS_STATE_LENGTH,
    zip: MAX_ADDRESS_ZIP_LENGTH,
    country: MAX_ADDRESS_COUNTRY_LENGTH,
  };

  function parsesOnCard(field: BaseAddressField, value: string): boolean {
    return cardDataSchema.safeParse({ billingAddress: { [field]: value } }).success;
  }

  function parsesOnIdentity(field: BaseAddressField, value: string): boolean {
    return identityDataSchema.safeParse({ address: { [field]: value } }).success;
  }

  it('accepts a value exactly at the documented bound on BOTH shapes', () => {
    for (const field of BASE_ADDRESS_FIELDS) {
      const atBound = 'x'.repeat(BOUNDS[field]);
      expect(parsesOnCard(field, atBound), `card rejected ${field} at its bound`).toBe(true);
      expect(parsesOnIdentity(field, atBound), `identity rejected ${field} at its bound`).toBe(
        true,
      );
    }
  });

  it('rejects one character past the documented bound on BOTH shapes', () => {
    for (const field of BASE_ADDRESS_FIELDS) {
      const overBound = 'x'.repeat(BOUNDS[field] + 1);
      expect(parsesOnCard(field, overBound), `card accepted ${field} past its bound`).toBe(false);
      expect(parsesOnIdentity(field, overBound), `identity accepted ${field} past its bound`).toBe(
        false,
      );
    }
  });

  /**
   * The property the fill actually depends on, stated directly and without
   * reference to any constant: whatever an identity accepts, a card accepts.
   * Probing a spread of lengths means this still fails if a bound moves on one
   * side only, even to a value nobody wrote down.
   */
  it('never accepts a length on an identity that a card would refuse', () => {
    for (const field of BASE_ADDRESS_FIELDS) {
      const bound = BOUNDS[field];
      for (const length of [0, 1, bound - 1, bound, bound + 1, bound * 2]) {
        const value = 'x'.repeat(Math.max(0, length));
        expect(
          parsesOnIdentity(field, value) && !parsesOnCard(field, value),
          `identity accepted ${field} at length ${String(length)} but a card did not`,
        ).toBe(false);
      }
    }
  });

  it('keeps deliveryNotes storable on an identity and stripped from a card', () => {
    const identity = identityDataSchema.safeParse({ address: { deliveryNotes: 'Door code 4821' } });
    expect(identity.success).toBe(true);
    expect((identity.data?.address as Record<string, unknown> | undefined)?.deliveryNotes).toBe(
      'Door code 4821',
    );

    // STRIP mode, not rejection: a card silently drops the key on read-back,
    // which is why the picker must never copy it in the first place.
    const card = cardDataSchema.safeParse({
      billingAddress: { city: 'London', deliveryNotes: 'Door code 4821' },
    });
    expect(card.success).toBe(true);
    expect(card.data?.billingAddress).not.toHaveProperty('deliveryNotes');
  });
});
