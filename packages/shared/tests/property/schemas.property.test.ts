/**
 * The decrypted item schemas, as PROPERTIES rather than examples.
 *
 * These five schemas are the narrowest part of this vault's data path and they
 * run in BOTH directions: `vaultStore.createItem`/`updateItem` parse before
 * encrypting, and `decryptItem` parses after decrypting. So a value the schema
 * accepts on the way in and rejects on the way out is not a validation nicety —
 * it is an item that shows "could not be fully decoded" and takes the user's
 * access to its own password with it.
 *
 * The central property is therefore a FIXED POINT: whatever the schema hands
 * back must itself be acceptable input, and parsing it again must change
 * nothing. That is what makes the two directions agree, and it is also what
 * keeps an item's import identity stable — `services/import/identity.ts` hashes
 * `canonicalJson({ name, data })` of the SCHEMA-VALIDATED data, so a schema that
 * rewrote its own output on the second pass would move the hash on an untouched
 * save and a re-import of the same file would insert a duplicate instead of
 * matching.
 *
 * Every generator below draws its bounds from `constants/index.ts` rather than
 * from a literal, and every one of them is biased to include the EXACT cap: the
 * interesting inputs for a length-bounded schema are at `max`, and a generator
 * that produces 12-character strings never visits the only value that can fail.
 */
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import {
  cardDataSchema,
  identityDataSchema,
  isValidIdentityEmail,
  loginDataSchema,
  noteDataSchema,
  secretDataSchema,
  vaultItemDataSchemas,
} from '../../src/schemas/vault.js';
import { normalizeUri } from '../../src/utils/index.js';
import {
  CUSTOM_FIELD_TYPES,
  ITEM_TYPES,
  MAX_ADDRESS_CITY_LENGTH,
  MAX_ADDRESS_COUNTRY_LENGTH,
  MAX_ADDRESS_DELIVERY_NOTES_LENGTH,
  MAX_ADDRESS_STATE_LENGTH,
  MAX_ADDRESS_STREET_LENGTH,
  MAX_ADDRESS_ZIP_LENGTH,
  MAX_CARD_BRAND_LENGTH,
  MAX_CARD_CARDHOLDER_NAME_LENGTH,
  MAX_CUSTOM_FIELDS_PER_ITEM,
  MAX_CUSTOM_FIELD_NAME_LENGTH,
  MAX_IDENTITY_COMPANY_LENGTH,
  MAX_IDENTITY_NAME_LENGTH,
  MAX_IDENTITY_PASSPORT_LENGTH,
  MAX_IDENTITY_SSN_LENGTH,
  MAX_LOGIN_BACKUP_CODES,
  MAX_LOGIN_BACKUP_CODE_LENGTH,
  MAX_LOGIN_PASSWORD_LENGTH,
  MAX_LOGIN_TOTP_LENGTH,
  MAX_LOGIN_USERNAME_LENGTH,
  MAX_NOTE_CONTENT_LENGTH,
  MAX_SECRET_DESCRIPTION_LENGTH,
  MAX_URIS_PER_ITEM,
  MAX_URI_LENGTH,
  NOTE_FORMATS,
  URI_MATCH_TYPES,
} from '../../src/constants/index.js';
import { PROPERTY_RUNS, propertyBanner, propertyRun } from '../../../../tests/harness/property.js';

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

/**
 * A bounded string that sometimes lands exactly ON the bound.
 *
 * `unit: 'binary'` rather than the default grapheme unit, so lone surrogates,
 * NUL and astral characters are all in the sample: `.max()` counts UTF-16 code
 * units, and a generator restricted to well-formed graphemes never exercises the
 * disagreement between "characters" and code units.
 *
 * The `filter` is where that disagreement is handled rather than hidden.
 * fast-check's `maxLength` counts UNITS OF THE UNIT ARBITRARY — code POINTS under
 * `'binary'` — while `z.string().max()` counts UTF-16 code units, so `maxLength:
 * 4` happily produces one NUL plus two astral characters, which is three code
 * points and five code units. Without the filter this generator produces input the schema legitimately
 * REJECTS, and the property then fails on the generator rather than on the code
 * (measured: it did, on `cvv`). Filtering keeps astral characters in the sample
 * for every bound wide enough to hold them.
 */
function boundedString(max: number): fc.Arbitrary<string> {
  return fc.oneof(
    {
      weight: 8,
      arbitrary: fc
        .string({ unit: 'binary', maxLength: Math.min(max, 24) })
        .filter((value) => value.length <= max),
    },
    // The cap itself, and one code unit under it. Weighted low because they are
    // expensive for a large bound, but present in every run.
    { weight: 1, arbitrary: fc.constant('x'.repeat(max)) },
    { weight: 1, arbitrary: fc.constant('x'.repeat(Math.max(0, max - 1))) },
  );
}

/** An optional field: sometimes absent, so the schema's own default is exercised. */
function optional<T>(arbitrary: fc.Arbitrary<T>): fc.Arbitrary<T | undefined> {
  return fc.option(arbitrary, { nil: undefined });
}

const customFieldArbitrary = fc.record({
  // `.min(1)`: a blank name is rejected by the schema, and `VaultItemForm`
  // strips such a row before it can be stored.
  name: fc
    .string({ unit: 'binary', minLength: 1, maxLength: 8 })
    .filter((value) => value.length >= 1 && value.length <= MAX_CUSTOM_FIELD_NAME_LENGTH),
  value: boundedString(MAX_NOTE_CONTENT_LENGTH),
  type: fc.constantFrom(...CUSTOM_FIELD_TYPES),
});

/**
 * A URI entry whose `uri` is short enough that the schema's `https://` prepend
 * cannot push it past `MAX_URI_LENGTH`.
 *
 * That bound is measured PRE-transform, so a bare domain of exactly
 * `MAX_URI_LENGTH` characters parses to a `MAX_URI_LENGTH + 8` one — which the
 * schema then refuses on the way back in. The importer already subtracts this
 * overhead (`clampUri` in `services/import/itemBuilders.ts`); the generator
 * subtracts it too, and the ONE input family that does not survive is pinned
 * explicitly as a known defect at the bottom of this file rather than being
 * quietly excluded here.
 */
const uriEntryArbitrary = fc
  .record({
    uri: fc.oneof(
      fc.constant(''),
      fc.webUrl(),
      fc.domain(),
      fc.constant(`mailto:${'a'.repeat(40)}@example.com`),
    ),
    match: fc.constantFrom(...URI_MATCH_TYPES),
  })
  .filter(({ uri, match }) => {
    if (match === 'regex') return uri.length <= MAX_URI_LENGTH;
    return normalizeUri(uri).length <= MAX_URI_LENGTH;
  });

const addressFields = {
  street: optional(boundedString(MAX_ADDRESS_STREET_LENGTH)),
  street2: optional(boundedString(MAX_ADDRESS_STREET_LENGTH)),
  city: optional(boundedString(MAX_ADDRESS_CITY_LENGTH)),
  state: optional(boundedString(MAX_ADDRESS_STATE_LENGTH)),
  zip: optional(boundedString(MAX_ADDRESS_ZIP_LENGTH)),
  country: optional(boundedString(MAX_ADDRESS_COUNTRY_LENGTH)),
};

const loginArbitrary = fc.record({
  username: optional(boundedString(MAX_LOGIN_USERNAME_LENGTH)),
  password: optional(boundedString(MAX_LOGIN_PASSWORD_LENGTH)),
  uris: optional(fc.array(uriEntryArbitrary, { maxLength: Math.min(MAX_URIS_PER_ITEM, 4) })),
  totp: optional(boundedString(MAX_LOGIN_TOTP_LENGTH)),
  backupCodes: optional(
    fc.array(boundedString(MAX_LOGIN_BACKUP_CODE_LENGTH), {
      maxLength: Math.min(MAX_LOGIN_BACKUP_CODES, 4),
    }),
  ),
  notes: optional(boundedString(MAX_NOTE_CONTENT_LENGTH)),
  customFields: optional(
    fc.array(customFieldArbitrary, { maxLength: Math.min(MAX_CUSTOM_FIELDS_PER_ITEM, 3) }),
  ),
});

/**
 * A secret's `expiresAt`, in every shape `secretDataSchema`'s three refines
 * accept: date-only, with a time, with seconds, with `Z`, and with a numeric
 * offset. The offset forms are the reason this file runs in a DST-observing zone
 * too — the third refine hands the value to `new Date()`, and a zone-less
 * datetime is parsed as LOCAL time.
 */
const expiresAtArbitrary = fc
  .tuple(
    // Year 100 and up, NOT 1: `Date.UTC(y, …)` maps a year in 0-99 to 1900-1999,
    // so the schema's calendar refine rejects every such date — including the
    // `0001-01-01` the editor's own error message advertises as the lower bound.
    // Pinned as a known defect at the bottom of this file; excluded here so the
    // fixed-point property fails for fixed-point reasons.
    fc.integer({ min: 100, max: 9999 }),
    fc.integer({ min: 1, max: 12 }),
    fc.integer({ min: 1, max: 28 }),
    fc.integer({ min: 0, max: 23 }),
    fc.integer({ min: 0, max: 59 }),
    fc.integer({ min: 0, max: 59 }),
    fc.constantFrom('', 'Z', '+05:30', '-08:00'),
    fc.constantFrom('date', 'minutes', 'seconds'),
  )
  .map(([year, month, day, hour, minute, second, zone, precision]) => {
    const pad = (value: number, width = 2): string => String(value).padStart(width, '0');
    const date = `${pad(year, 4)}-${pad(month)}-${pad(day)}`;
    if (precision === 'date') return date;
    const time =
      precision === 'minutes'
        ? `${pad(hour)}:${pad(minute)}`
        : `${pad(hour)}:${pad(minute)}:${pad(second)}`;
    return `${date}T${time}${zone}`;
  });

const secretArbitrary = fc.record({
  value: optional(boundedString(MAX_NOTE_CONTENT_LENGTH)),
  description: optional(boundedString(MAX_SECRET_DESCRIPTION_LENGTH)),
  expiresAt: optional(expiresAtArbitrary),
  customFields: optional(
    fc.array(customFieldArbitrary, { maxLength: Math.min(MAX_CUSTOM_FIELDS_PER_ITEM, 3) }),
  ),
});

const noteArbitrary = fc.record({
  content: optional(boundedString(MAX_NOTE_CONTENT_LENGTH)),
  format: optional(fc.constantFrom(...NOTE_FORMATS)),
});

const cardArbitrary = fc.record({
  cardholderName: optional(boundedString(MAX_CARD_CARDHOLDER_NAME_LENGTH)),
  number: optional(boundedString(30)),
  expMonth: optional(boundedString(2)),
  expYear: optional(boundedString(4)),
  cvv: optional(boundedString(4)),
  brand: optional(boundedString(MAX_CARD_BRAND_LENGTH)),
  notes: optional(boundedString(MAX_NOTE_CONTENT_LENGTH)),
  billingAddress: optional(fc.record(addressFields)),
});

/**
 * An identity. `email` and `phone` are drawn from the shapes
 * `isValidIdentityEmail`/`isValidIdentityPhone` accept, because an invalid one
 * is a rejection rather than a fixed point — and the rejection paths are already
 * covered by example tests.
 */
const identityArbitrary = fc.record({
  firstName: optional(boundedString(MAX_IDENTITY_NAME_LENGTH)),
  lastName: optional(boundedString(MAX_IDENTITY_NAME_LENGTH)),
  // Filtered through the schema's OWN predicate, not through fast-check's idea of
  // a valid address: `fc.emailAddress()` follows RFC 5322 and produces local
  // parts such as `!a`, which zod's pragmatic `z.email()` refuses. The property
  // under test is the fixed point, so an address the schema rejects outright is
  // a generator that never reaches it.
  email: optional(fc.oneof(fc.constant(''), fc.emailAddress()).filter(isValidIdentityEmail)),
  phone: optional(
    fc.oneof(fc.constant(''), fc.constant('+1 (555) 123-4567'), fc.constant('020 7946 0958')),
  ),
  address: optional(
    fc.record({
      ...addressFields,
      deliveryNotes: optional(boundedString(MAX_ADDRESS_DELIVERY_NOTES_LENGTH)),
    }),
  ),
  company: optional(boundedString(MAX_IDENTITY_COMPANY_LENGTH)),
  ssn: optional(boundedString(MAX_IDENTITY_SSN_LENGTH)),
  passport: optional(boundedString(MAX_IDENTITY_PASSPORT_LENGTH)),
  notes: optional(boundedString(MAX_NOTE_CONTENT_LENGTH)),
  customFields: optional(
    fc.array(customFieldArbitrary, { maxLength: Math.min(MAX_CUSTOM_FIELDS_PER_ITEM, 3) }),
  ),
});

/** The five schemas, each with a generator over its own shape. */
const SCHEMAS = [
  { itemType: 'login' as const, schema: loginDataSchema, arbitrary: loginArbitrary },
  { itemType: 'secret' as const, schema: secretDataSchema, arbitrary: secretArbitrary },
  { itemType: 'note' as const, schema: noteDataSchema, arbitrary: noteArbitrary },
  { itemType: 'card' as const, schema: cardDataSchema, arbitrary: cardArbitrary },
  { itemType: 'identity' as const, schema: identityDataSchema, arbitrary: identityArbitrary },
];

/** `JSON.parse(JSON.stringify(x))` — what a stored item is on the way back. */
function throughStorage(value: unknown): unknown {
  return JSON.parse(JSON.stringify(value));
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

describe('vaultItemDataSchemas — every schema is covered by a generator', () => {
  it('has one generator per item type, so a sixth type cannot be added untested', () => {
    // Not decoration: `SCHEMAS` drives every property below, and a new item type
    // would otherwise be property-tested by nothing at all while the file still
    // reported five green suites.
    expect(SCHEMAS.map((entry) => entry.itemType).sort()).toEqual([...ITEM_TYPES].sort());
    for (const { itemType, schema } of SCHEMAS) {
      expect(vaultItemDataSchemas[itemType]).toBe(schema);
    }
  });
});

describe.each(SCHEMAS)('$itemType data schema', ({ schema, arbitrary }) => {
  it('parses its own output back to the identical value (the fixed point)', () => {
    fc.assert(
      fc.property(arbitrary, (input) => {
        const first = schema.parse(input);
        const second = schema.safeParse(throughStorage(first));

        expect(
          second.success,
          `${propertyBanner()} — re-parse rejected the schema's own output`,
        ).toBe(true);
        // Deep equality, not a hash: a second pass that changed a key's ORDER
        // would still hash the same under `canonicalJson` (it sorts keys), but a
        // second pass that changed a VALUE is exactly the untouched-save drift
        // this property exists to forbid.
        expect(second.success ? second.data : null).toEqual(first);
      }),
      propertyRun(),
    );
  });

  it('is idempotent on a value that has already been parsed twice', () => {
    // A schema can be a fixed point at the second application and not at the
    // third (a transform that alternates). Cheap to rule out, and it is the
    // property a repeated save actually depends on.
    fc.assert(
      fc.property(arbitrary, (input) => {
        const once = schema.parse(input);
        const twice = schema.parse(throughStorage(once));
        const thrice = schema.parse(throughStorage(twice));
        expect(thrice, propertyBanner()).toEqual(twice);
      }),
      propertyRun({ numRuns: Math.ceil(PROPERTY_RUNS / 2) }),
    );
  });

  it('never returns a value JSON cannot carry', () => {
    // Everything the schema hands back is serialized into the encrypted blob by
    // `JSON.stringify`, so a `undefined` inside an ARRAY (which becomes `null`),
    // a `NaN` or an `Infinity` (both become `null`) would be silently rewritten
    // on the way to storage and fail on the way back.
    fc.assert(
      fc.property(arbitrary, (input) => {
        const parsed = schema.parse(input);
        const serialized = JSON.stringify(parsed);
        expect(serialized, propertyBanner()).toBeTypeOf('string');
        expect(JSON.parse(serialized), propertyBanner()).toEqual(parsed);
      }),
      propertyRun(),
    );
  });
});

describe('secretDataSchema — the expiry refines', () => {
  it('accepts every shape its own ISO grammar allows, from year 100 onward', () => {
    fc.assert(
      fc.property(expiresAtArbitrary, (expiresAt) => {
        const parsed = secretDataSchema.parse({ expiresAt });
        // The value is stored VERBATIM: no transform, no normalization. That is
        // what lets `combineExpiry` return the stored string unchanged when
        // neither control moved, and hence what keeps an untouched save from
        // moving the item's content hash.
        expect(parsed.expiresAt, propertyBanner()).toBe(expiresAt);
      }),
      propertyRun(),
    );
  });

  /**
   * The shrunk counterexample the fixed-point property found for `secret`, at
   * `SEED=1337`, `numRuns=100`: `{ expiresAt: '0001-01-01' }`.
   *
   * The mechanism is the two-digit-year legacy rule in `Date.UTC`. The calendar
   * refine builds `new Date(Date.UTC(year, month - 1, day))` and compares
   * `getUTCFullYear()` with `year`; for a year in 0-99 the constructor maps it to
   * 1900-1999, the comparison fails, and the value is rejected as "not a valid
   * calendar date".
   *
   * `combineExpiry` (VaultItemForm) already documents and avoids exactly this trap
   * — it builds its Date by mutation "rather than `new Date(y, m, d, …)`, whose
   * two-digit-year legacy behaviour maps year 50 to 1950" — so the schema is the
   * one place where it survives. The visible consequence is small but real: the
   * editor's own message advertises "Enter a date between 0001-01-01 and
   * 9999-12-31", and a date in the first century is then refused by the write
   * pre-flight instead. No stored value can be affected, because the same refine
   * runs on the way in.
   *
   * PINNED, NOT FIXED: changing which values the schema accepts is production
   * behavior, out of scope for a test phase (see the phase log's deferred-defect
   * entry). Asserting today's behavior makes the fix a deliberate edit here.
   */
  it('KNOWN DEFECT: rejects a first-century date, because Date.UTC maps year 0-99 into the 1900s', () => {
    for (const expiresAt of ['0001-01-01', '0050-06-15', '0099-12-31']) {
      const result = secretDataSchema.safeParse({ expiresAt });
      expect(result.success, expiresAt).toBe(false);
      expect(result.success ? [] : result.error.issues).toEqual([
        expect.objectContaining({
          path: ['expiresAt'],
          message: 'expiresAt must be a valid calendar date',
        }),
      ]);
    }
    // The first year that is NOT remapped, so the bound is stated rather than
    // implied: 100 parses, 99 does not.
    expect(secretDataSchema.safeParse({ expiresAt: '0100-01-01' }).success).toBe(true);
    // And the mechanism itself, so a reader does not have to take the claim on
    // trust: this is the remap the refine trips over.
    expect(new Date(Date.UTC(99, 0, 1)).getUTCFullYear()).toBe(1999);
    expect(new Date(Date.UTC(100, 0, 1)).getUTCFullYear()).toBe(100);
  });
});

describe('loginDataSchema — the URI transform', () => {
  it('normalizes a URI to a value that is already normalized', () => {
    // `normalizeUri` is applied by the schema on every parse, so a
    // non-idempotent one would rewrite the value on every save even when the
    // length bound is nowhere near.
    fc.assert(
      fc.property(uriEntryArbitrary, ({ uri, match }) => {
        const parsed = loginDataSchema.parse({ uris: [{ uri, match }] });
        const once = parsed.uris[0]?.uri ?? '';
        const twice = loginDataSchema.parse({ uris: [{ uri: once, match }] }).uris[0]?.uri ?? '';
        expect(twice, propertyBanner()).toBe(once);
      }),
      propertyRun(),
    );
  });

  /**
   * The shrunk counterexample the fixed-point property found on its first run,
   * committed as a named regression test.
   *
   * `SEED=1337`, `numRuns=100`, shrunk to `{ uris: [{ uri: 'x'.repeat(2048),
   * match: 'domain' }] }`. The mechanism: `uri` is bounded by
   * `z.string().max(MAX_URI_LENGTH)` BEFORE the transform that prepends
   * `https://`, so a bare domain of exactly 2048 characters parses to a 2056
   * character URI — and that output is no longer valid input.
   *
   * Reachable from the editor, not from an import: `clampUri`
   * (`services/import/itemBuilders.ts`) already subtracts the scheme's length
   * from the bound, but `VaultItemForm`'s own `uri` field bounds at
   * `MAX_URI_LENGTH` with no such allowance. Saving a 2041-2048 character bare
   * domain therefore stores it, `decryptItem` returns the grown value, and every
   * later save of that item is refused by the write pre-flight with "Too big" on
   * `uris.0.uri`.
   *
   * PINNED, NOT FIXED, and deliberately so: the fix changes production
   * validation behavior, which is out of scope for a test phase (see the phase
   * log's deferred-defect entry). This test asserts TODAY'S behavior so that the
   * fix, when it lands, is a visible, deliberate change here rather than a silent
   * one — and so the failure mode cannot get worse unnoticed in the meantime.
   */
  it('KNOWN DEFECT: a bare domain at the URI cap grows past it, so its own output no longer parses', () => {
    const bareDomainAtCap = 'x'.repeat(MAX_URI_LENGTH);
    const overhead = normalizeUri(bareDomainAtCap).length - bareDomainAtCap.length;
    expect(overhead).toBe('https://'.length);

    const first = loginDataSchema.parse({ uris: [{ uri: bareDomainAtCap, match: 'domain' }] });
    expect(first.uris[0]?.uri).toHaveLength(MAX_URI_LENGTH + overhead);

    const second = loginDataSchema.safeParse(throughStorage(first));
    expect(second.success).toBe(false);
    expect(second.success ? [] : second.error.issues).toEqual([
      expect.objectContaining({
        code: 'too_big',
        maximum: MAX_URI_LENGTH,
        path: ['uris', 0, 'uri'],
      }),
    ]);

    // One character below the overhead-adjusted bound is the last value that
    // round-trips, which is the bound `clampUri` computes.
    const safe = 'x'.repeat(MAX_URI_LENGTH - overhead);
    const parsedSafe = loginDataSchema.parse({ uris: [{ uri: safe, match: 'domain' }] });
    expect(loginDataSchema.safeParse(throughStorage(parsedSafe)).success).toBe(true);
  });
});
