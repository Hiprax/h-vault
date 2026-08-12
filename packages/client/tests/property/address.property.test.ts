/**
 * The postal-address vocabulary, as properties — with one claim at the centre:
 * **`deliveryNotes` is never rendered, never copied and never searched.**
 *
 * That field routinely holds a door code or an alarm code. It exists on an
 * IDENTITY's address and has no meaning on a card's billing address, and the
 * codebase enforces the separation structurally rather than by convention: the
 * base `addressSchema` runs in STRIP mode, `BASE_ADDRESS_FIELDS` is the one list
 * everything address-shaped iterates, and the picker's search haystack is built
 * from the strings the row RENDERS.
 *
 * An example test can only show that one particular delivery note stayed out of
 * one particular rendering. What matters is the universal: for EVERY address a
 * user could type, no output of this module carries the value. So the generator
 * draws the six base fields from an alphabet that CANNOT contain the sentinel
 * marker, and the delivery note always does — which turns "the sentinel appears
 * in the output" from an unlikely coincidence into a proof of leakage.
 */
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import {
  BASE_ADDRESS_FIELDS,
  addressSearchText,
  billingFieldName,
  formatAddressLines,
  formatAddressSummary,
  hasBaseAddressValue,
  isBaseAddressField,
  matchesSearchQuery,
  readBaseAddress,
} from '../../src/lib/address';
import { cardDataSchema, identityDataSchema } from '@hvault/shared';
import {
  PROPERTY_RUNS,
  propertyBanner,
  propertyRun,
  stringFromAlphabet,
} from '../../../../tests/harness/property.js';

/**
 * The marker every generated delivery note carries, and that no base field can.
 *
 * It opens with U+E000, a PRIVATE-USE character, which is what makes the
 * exclusion a FACT about the generator rather than a probability: the six base
 * fields are drawn from {@link SAFE_ALPHABET}, which does not contain it, so this
 * marker appearing in a rendered string can only have come from the delivery
 * note. Written as an escape rather than as the literal character, which is
 * invisible in an editor and turns the file into "binary" for `grep`.
 */
const SENTINEL = '\uE000DOORCODE';

/** Latin letters, digits and the punctuation a real address uses — no sentinel. */
const SAFE_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,-/'";

const baseAddressArbitrary = fc.record({
  street: stringFromAlphabet(SAFE_ALPHABET, { maxLength: 16 }),
  street2: stringFromAlphabet(SAFE_ALPHABET, { maxLength: 10 }),
  city: stringFromAlphabet(SAFE_ALPHABET, { maxLength: 12 }),
  state: stringFromAlphabet(SAFE_ALPHABET, { maxLength: 8 }),
  zip: stringFromAlphabet(SAFE_ALPHABET, { maxLength: 8 }),
  country: stringFromAlphabet(SAFE_ALPHABET, { maxLength: 12 }),
});

/**
 * The same six fields drawn from letters and digits only.
 *
 * For the separator property below: every comma, space and slash in a rendered
 * line is then one the FORMATTER put there, which is the only thing that property
 * is about. Empty fields are still generated, because the sparse address is the
 * case that produced the `1 Main St, , London` class of bug.
 */
const separatorFreeAddressArbitrary = fc.record(
  Object.fromEntries(
    BASE_ADDRESS_FIELDS.map((field) => [
      field,
      stringFromAlphabet('abcdefghijklmnopqrstuvwxyz0123456789', { maxLength: 8 }),
    ]),
  ) as Record<(typeof BASE_ADDRESS_FIELDS)[number], fc.Arbitrary<string>>,
);

/** An identity's address: the six base fields plus a delivery note carrying the sentinel. */
const identityAddressArbitrary = fc
  .tuple(baseAddressArbitrary, stringFromAlphabet(SAFE_ALPHABET, { maxLength: 10 }))
  .map(([base, tail]) => ({ ...base, deliveryNotes: `${SENTINEL}${tail}` }));

/** All six base fields empty, for a case that names the one field it is about. */
const EMPTY_ADDRESS = readBaseAddress({});

describe('readBaseAddress', () => {
  it('reads exactly the six base fields, whatever it is handed', () => {
    fc.assert(
      fc.property(
        fc.oneof(
          identityAddressArbitrary,
          fc.constant(undefined),
          fc.constant(null),
          fc.string(),
          fc.array(fc.string()),
          fc.dictionary(fc.string(), fc.anything()),
        ),
        (value) => {
          const address = readBaseAddress(value);
          // The KEY SET is the assertion: a seventh key would be a field that
          // `formatAddressLines` and the card fill both start carrying for free.
          expect(Object.keys(address).sort(), propertyBanner()).toEqual(
            [...BASE_ADDRESS_FIELDS].sort(),
          );
          for (const field of BASE_ADDRESS_FIELDS) {
            expect(typeof address[field], propertyBanner()).toBe('string');
          }
          expect(Object.keys(address), propertyBanner()).not.toContain('deliveryNotes');
        },
      ),
      propertyRun(),
    );
  });

  it('never admits deliveryNotes, however it is spelled in the source object', () => {
    fc.assert(
      fc.property(identityAddressArbitrary, (address) => {
        const base = readBaseAddress(address);
        for (const value of Object.values(base)) {
          expect(
            value,
            `${propertyBanner()} — a base field carries the delivery note`,
          ).not.toContain(SENTINEL);
        }
      }),
      propertyRun(),
    );
  });
});

describe('formatAddressLines / formatAddressSummary', () => {
  it('never emits a line containing the delivery note', () => {
    // THE property this file exists for.
    fc.assert(
      fc.property(identityAddressArbitrary, (address) => {
        const lines = formatAddressLines(readBaseAddress(address));
        const summary = formatAddressSummary(readBaseAddress(address));

        for (const line of lines) {
          expect(
            line,
            `${propertyBanner()} — a rendered line leaked the delivery note`,
          ).not.toContain(SENTINEL);
        }
        expect(summary, propertyBanner()).not.toContain(SENTINEL);
      }),
      propertyRun(),
    );
  });

  it('emits no blank line and no dangling separator, however sparse the address', () => {
    // The documented failure mode of a flat comma-join: `1 Main St, , London, ,
    // 12345,` for a partially-filled address. Every line must carry content and
    // must not start or end with a separator.
    //
    // Drawn from a SEPARATOR-FREE alphabet, and that is the property being kept
    // honest rather than a convenience: the claim is about separators the
    // FORMATTER inserts, and a field whose own content is `","` (which the first
    // run of this property duly found) produces a line starting and ending with a
    // comma without the formatter having inserted anything. A user who types a
    // lone comma into "Apartment, suite, unit" is entitled to see it back.
    fc.assert(
      fc.property(separatorFreeAddressArbitrary, (address) => {
        for (const line of formatAddressLines(address)) {
          expect(line.trim(), propertyBanner()).not.toBe('');
          expect(line, propertyBanner()).not.toMatch(/^[,\s]|[,\s]$/);
          expect(line, propertyBanner()).not.toMatch(/,\s*,/);
        }
      }),
      propertyRun(),
    );
  });

  /**
   * The shrunk counterexample the separator property found on its first run, at
   * `SEED=1337`, `numRuns=100`: `{ street2: ',' }`, every other field empty.
   *
   * The formatter was CORRECT; the property was wrong. A user who types a lone
   * comma into "Apartment, suite, unit" gets a line that both starts and ends with
   * a comma, and the formatter inserted neither of them. Committed as its own test
   * because it fixes WHICH separators the property may complain about: only the
   * ones the formatter adds between two non-empty parts.
   */
  it('REGRESSION: a field whose own content is punctuation is rendered verbatim', () => {
    expect(
      formatAddressLines({ ...EMPTY_ADDRESS, street2: ',' }),
      'a lone comma the user typed is content, not a separator the formatter added',
    ).toEqual([',']);
    // With BOTH street fields filled, the one comma-space between them IS the
    // formatter's: the pair is what tells the two cases apart.
    expect(formatAddressLines({ ...EMPTY_ADDRESS, street: '1 Main St', street2: ',' })).toEqual([
      '1 Main St, ,',
    ]);
    // And with street2 empty there is no separator at all — the `1 Main St, ,
    // London` class this property exists to forbid.
    expect(formatAddressLines({ ...EMPTY_ADDRESS, street: '1 Main St', city: 'London' })).toEqual([
      '1 Main St',
      'London',
    ]);
  });

  it('renders every non-empty base field somewhere, and nothing else', () => {
    // The other half of "no leakage": a formatter that dropped `country` would
    // satisfy every exclusion property above while losing user data.
    fc.assert(
      fc.property(baseAddressArbitrary, (address) => {
        const joined = formatAddressLines(address).join('\n');
        for (const field of BASE_ADDRESS_FIELDS) {
          const value = address[field].trim();
          if (value !== '')
            expect(joined, `${propertyBanner()} — ${field} was dropped`).toContain(value);
        }
      }),
      propertyRun(),
    );
  });

  it('returns lines exactly when the address has a visible value', () => {
    fc.assert(
      fc.property(baseAddressArbitrary, (address) => {
        expect(formatAddressLines(address).length > 0, propertyBanner()).toBe(
          hasBaseAddressValue(address),
        );
      }),
      propertyRun(),
    );
  });
});

describe('the picker search haystack', () => {
  it('never matches a term that appears only in the delivery note', () => {
    // Searching a field the row cannot display would turn the picker into an
    // oracle: type a guess, watch the list filter. The haystack is built from the
    // RENDERED strings, so this is a property of that construction.
    fc.assert(
      fc.property(identityAddressArbitrary, fc.string({ maxLength: 6 }), (address, label) => {
        const rendered = [label, ...formatAddressLines(readBaseAddress(address))];
        const haystack = addressSearchText(rendered);

        expect(haystack, propertyBanner()).not.toContain(SENTINEL.toLowerCase());
        expect(
          matchesSearchQuery(haystack, address.deliveryNotes),
          `${propertyBanner()} — the delivery note was searchable`,
        ).toBe(false);
      }),
      propertyRun(),
    );
  });

  it('matches every term drawn from what the row actually renders', () => {
    fc.assert(
      fc.property(baseAddressArbitrary, (address) => {
        const lines = formatAddressLines(address);
        const haystack = addressSearchText(lines);
        for (const line of lines) {
          for (const term of line.split(/\s+/).filter(Boolean)) {
            expect(matchesSearchQuery(haystack, term), propertyBanner()).toBe(true);
          }
        }
        // Terms in any order, from different lines, still match — the documented
        // "ada london" case.
        const terms = lines.flatMap((line) => line.split(/\s+/)).filter(Boolean);
        if (terms.length > 1) {
          expect(
            matchesSearchQuery(haystack, [...terms].reverse().join(' ')),
            propertyBanner(),
          ).toBe(true);
        }
      }),
      propertyRun({ numRuns: Math.ceil(PROPERTY_RUNS / 2) }),
    );
  });
});

describe('filling a card billing address from an identity', () => {
  it('copies the six base fields verbatim and the delivery note never', () => {
    // The fill writes `billing<Field>` controls from `readBaseAddress`, so this is
    // the composition that actually runs. Both halves matter: nothing lost, and
    // nothing extra.
    fc.assert(
      fc.property(identityAddressArbitrary, (address) => {
        const base = readBaseAddress(address);
        const written = Object.fromEntries(
          BASE_ADDRESS_FIELDS.map((field) => [billingFieldName(field), base[field]]),
        );

        expect(Object.keys(written), propertyBanner()).toHaveLength(BASE_ADDRESS_FIELDS.length);
        expect(Object.keys(written), propertyBanner()).not.toContain('billingDeliveryNotes');
        for (const field of BASE_ADDRESS_FIELDS) {
          expect(written[billingFieldName(field)], propertyBanner()).toBe(address[field]);
          expect(isBaseAddressField(field), propertyBanner()).toBe(true);
        }
        expect(isBaseAddressField('deliveryNotes'), propertyBanner()).toBe(false);
      }),
      propertyRun(),
    );
  });

  it('is bounded identically on both sides, so a copied value survives read-back', () => {
    // The card and the identity read the SAME `MAX_ADDRESS_*` constant per field,
    // which is what makes the copy total: a value an identity accepts must be a
    // value the card's own schema accepts on the next decrypt. A divergence here
    // would store a billing address that degrades the card to "could not be fully
    // decoded".
    fc.assert(
      fc.property(identityAddressArbitrary, (address) => {
        const identity = identityDataSchema.parse({ address });
        expect(identity.address, propertyBanner()).toBeDefined();

        const card = cardDataSchema.parse({ billingAddress: readBaseAddress(identity.address) });
        expect(card.billingAddress, propertyBanner()).toEqual(readBaseAddress(address));
        // STRIP mode is the invariant, stated where it is relied on: even handed
        // the identity's address WHOLE, the card drops the delivery note.
        const whole = cardDataSchema.parse({ billingAddress: identity.address });
        expect(Object.keys(whole.billingAddress ?? {}), propertyBanner()).not.toContain(
          'deliveryNotes',
        );
        expect(JSON.stringify(whole), propertyBanner()).not.toContain(SENTINEL);
      }),
      propertyRun(),
    );
  });
});
