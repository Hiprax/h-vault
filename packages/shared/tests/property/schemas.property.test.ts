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
import {
  documentChunkCountFor,
  documentMetaJsonByteLength,
  documentMetaSchema,
} from '../../src/schemas/document.js';
import { normalizeUri } from '../../src/utils/index.js';
import {
  CUSTOM_FIELD_TYPES,
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  ITEM_TYPES,
  MAX_DOCUMENT_CHUNK_COUNT,
  MAX_DOCUMENT_EXT_LENGTH,
  MAX_DOCUMENT_META_JSON_BYTES,
  MAX_DOCUMENT_MIME_LENGTH,
  MAX_DOCUMENT_NAME_LENGTH,
  MAX_DOCUMENT_NOTE_LENGTH,
  MAX_DOCUMENT_TAGS,
  MAX_DOCUMENT_TRANSFORM_LABEL_LENGTH,
  MAX_TAG_LENGTH,
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
 * A URI entry the schema accepts, measured the way the schema now measures it:
 * AFTER `normalizeUri` has prepended a scheme to a bare domain.
 *
 * The bound used to be checked PRE-transform, so a bare domain of exactly
 * `MAX_URI_LENGTH` characters parsed to a `MAX_URI_LENGTH + 8` one that the
 * schema then refused on the way back in. The check now sits after the
 * transform, which is the same bound `clampUri` (`services/import/itemBuilders.ts`)
 * has always computed — so this filter states the schema's real acceptance
 * condition rather than working around a gap in it. The boundary itself is
 * pinned by name at the bottom of this file.
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
    // From year 1, the lower bound the editor's own error message advertises.
    // This range used to start at 100, because the calendar refine built its
    // Date through `Date.UTC(y, …)`, whose two-digit-year legacy rule maps a
    // year in 0-99 to 1900-1999 and made every first-century date fail. The
    // refine now builds the Date by mutation, so the whole advertised range is
    // generated here and the boundary is pinned by name below.
    fc.integer({ min: 1, max: 9999 }),
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

// ---------------------------------------------------------------------------
// The document metadata blob
//
// Not a member of `SCHEMAS` below: that list is keyed by ITEM_TYPES and is
// asserted against it. The document blob holds the same position in its own
// feature that a vault item's data holds in the vault — sealed by the browser,
// parsed on the way in and again on the way out — so it gets the same laws.
// ---------------------------------------------------------------------------

/**
 * The EXPLICIT field enum the generator is built from.
 *
 * Explicit rather than derived from the schema, because the failure this guards
 * against is a field added to the schema and NOT to the generator: derive the list
 * and that field is generated as `undefined` forever while the suite still reports
 * three green properties over it. The two assertions below close the loop in both
 * directions — this list must equal the schema's own keys, and every entry must
 * actually be populated in a real sample.
 */
const DOCUMENT_META_FIELDS = [
  'name',
  'mime',
  'ext',
  'plaintextBytes',
  'sha256',
  'chunkPlaintextBytes',
  'chunkCount',
  'tags',
  'note',
  'transform',
  'capturedAt',
] as const;

/** A 32-byte digest, hex-encoded the way one really is: lower case by construction. */
const digestArbitrary = fc
  .uint8Array({ minLength: 32, maxLength: 32 })
  .map((bytes) => Buffer.from(bytes).toString('hex'));

/**
 * A tag the schema accepts, measured the way the schema measures it: AFTER
 * `.trim()`. Padded values are deliberately in the sample, because trimming is a
 * transform and a non-idempotent one would move a document's metadata on every
 * save.
 */
const documentTagArbitrary = fc.oneof(
  {
    weight: 8,
    arbitrary: fc
      .string({ unit: 'binary', minLength: 1, maxLength: 12 })
      .filter((value) => value.trim().length >= 1),
  },
  { weight: 1, arbitrary: fc.constant('x'.repeat(MAX_TAG_LENGTH)) },
  { weight: 1, arbitrary: fc.constant(`  ${'x'.repeat(MAX_TAG_LENGTH)}  `) },
);

/**
 * A CONSISTENT framing triple, because the schema refuses an inconsistent one and
 * a generator that produced inconsistent triples would test the refine rather than
 * the fixed point.
 *
 * Built from whole segments plus a remainder rather than from a flat integer, so
 * the sample lands on the three cases that matter: zero bytes, an exact multiple of
 * the chunk size, and a partial final segment. The chunk size itself is drawn from
 * several values, including 1 — the row carries this number, so a document written
 * under a different constant must still frame.
 */
const documentFramingArbitrary = fc
  .tuple(
    fc.constantFrom(
      DOCUMENT_PLAINTEXT_CHUNK_BYTES,
      Math.floor(DOCUMENT_PLAINTEXT_CHUNK_BYTES / 2),
      4096,
      1,
    ),
    fc.integer({ min: 0, max: 40 }),
    fc.integer({ min: 0, max: 4096 }),
  )
  .map(([chunkPlaintextBytes, wholeSegments, remainder]) => {
    const plaintextBytes =
      wholeSegments * chunkPlaintextBytes + Math.min(remainder, chunkPlaintextBytes - 1);
    return {
      chunkPlaintextBytes,
      plaintextBytes,
      chunkCount: documentChunkCountFor(plaintextBytes, chunkPlaintextBytes),
    };
  });

const documentMetaArbitrary = fc
  .tuple(
    documentFramingArbitrary,
    fc.record({
      // `.min(1)`: a nameless document has nothing to display.
      name: boundedString(MAX_DOCUMENT_NAME_LENGTH).filter((value) => value.length >= 1),
      mime: boundedString(MAX_DOCUMENT_MIME_LENGTH),
      ext: boundedString(MAX_DOCUMENT_EXT_LENGTH),
      sha256: digestArbitrary,
      tags: fc.array(documentTagArbitrary, { maxLength: Math.min(MAX_DOCUMENT_TAGS, 4) }),
      note: optional(boundedString(MAX_DOCUMENT_NOTE_LENGTH)),
      transform: optional(
        fc.record({
          formatted: fc.boolean(),
          repaired: fc.boolean(),
          tool: boundedString(MAX_DOCUMENT_TRANSFORM_LABEL_LENGTH).filter(
            (value) => value.length >= 1,
          ),
          toolVersion: boundedString(MAX_DOCUMENT_TRANSFORM_LABEL_LENGTH).filter(
            (value) => value.length >= 1,
          ),
          originalSha256: digestArbitrary,
        }),
      ),
      // A `Z` instant, which is the only form the schema accepts: an
      // offset-bearing local time reads differently per zone, and this file runs
      // in a DST-observing one as well as in UTC.
      capturedAt: fc
        .date({
          min: new Date('2020-01-01T00:00:00.000Z'),
          max: new Date('2030-12-31T23:59:59.999Z'),
          noInvalidDate: true,
        })
        .map((value) => value.toISOString()),
    }),
  )
  .map(([framing, fields]) => ({ ...fields, ...framing }))
  // A safety net rather than a workaround, and it should essentially never fire:
  // `boundedString` draws either a short binary string or the cap in ASCII, so the
  // whole blob stays far inside the byte budget. It is here so that a future
  // generator change which DOES exceed the budget fails as a filter-exhaustion
  // error naming this line, rather than as a mystifying rejection inside a property
  // whose subject is the fixed point.
  .filter((meta) => documentMetaJsonByteLength(meta) <= MAX_DOCUMENT_META_JSON_BYTES);

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

describe('documentMetaSchema — the encrypted blob, as properties', () => {
  it('has a generator for every field the schema declares, so a twelfth cannot be added untested', () => {
    // Both directions. The schema's keys must be exactly the enum above (a field
    // added to the schema and not here fails this), and every entry of that enum
    // must be populated by a real sample (an enum entry the generator forgot fails
    // the next assertion).
    expect(Object.keys(documentMetaSchema.shape).sort()).toEqual([...DOCUMENT_META_FIELDS].sort());

    const populated = new Set<string>();
    const absent = new Set<string>();
    fc.assert(
      fc.property(documentMetaArbitrary, (meta) => {
        for (const field of DOCUMENT_META_FIELDS) {
          (meta[field] === undefined ? absent : populated).add(field);
        }
      }),
      propertyRun({ numRuns: 200 }),
    );

    expect(
      [...populated].sort(),
      `${propertyBanner()} — a field no sample ever populated is generated by nothing`,
    ).toEqual([...DOCUMENT_META_FIELDS].sort());
    // And the fields that are ever ABSENT are exactly the two optional ones, which
    // is the stronger statement: it pins that the optional branch is exercised AND
    // that no required field is ever silently skipped.
    expect([...absent].sort(), propertyBanner()).toEqual(['note', 'transform']);
  });

  it('parses its own output back to the identical value (the fixed point)', () => {
    fc.assert(
      fc.property(documentMetaArbitrary, (input) => {
        const first = documentMetaSchema.parse(input);
        const second = documentMetaSchema.safeParse(throughStorage(first));
        expect(
          second.success,
          `${propertyBanner()} — re-parse rejected the schema's own output`,
        ).toBe(true);
        expect(second.success ? second.data : null).toEqual(first);
      }),
      propertyRun(),
    );
  });

  it('is idempotent on a value that has already been parsed twice', () => {
    fc.assert(
      fc.property(documentMetaArbitrary, (input) => {
        const once = documentMetaSchema.parse(input);
        const twice = documentMetaSchema.parse(throughStorage(once));
        const thrice = documentMetaSchema.parse(throughStorage(twice));
        expect(thrice, propertyBanner()).toEqual(twice);
      }),
      propertyRun({ numRuns: Math.ceil(PROPERTY_RUNS / 2) }),
    );
  });

  it('never returns a value JSON cannot carry, since the blob is sealed as JSON', () => {
    fc.assert(
      fc.property(documentMetaArbitrary, (input) => {
        const parsed = documentMetaSchema.parse(input);
        const serialized = JSON.stringify(parsed);
        expect(serialized, propertyBanner()).toBeTypeOf('string');
        expect(JSON.parse(serialized), propertyBanner()).toEqual(parsed);
      }),
      propertyRun(),
    );
  });

  it('accepts exactly the segment count the plaintext size implies, and neither neighbour', () => {
    // The framing refine, as a property rather than as three examples. One segment
    // too few is a TRUNCATED document and one too many is a phantom final segment;
    // both are what the index-and-last-flag nonce design exists to make
    // undetectable-proof, so neither may parse.
    fc.assert(
      fc.property(documentMetaArbitrary, (meta) => {
        expect(documentMetaSchema.safeParse(meta).success, propertyBanner()).toBe(true);
        for (const delta of [-1, 1]) {
          const chunkCount = meta.chunkCount + delta;
          if (chunkCount < 1 || chunkCount > MAX_DOCUMENT_CHUNK_COUNT) continue;
          const result = documentMetaSchema.safeParse({ ...meta, chunkCount });
          expect(
            result.success,
            `${propertyBanner()} — accepted ${String(chunkCount)} segments for ${String(meta.plaintextBytes)} bytes`,
          ).toBe(false);
        }
      }),
      propertyRun(),
    );
  });
});

describe('secretDataSchema — the expiry refines', () => {
  it('accepts every shape its own ISO grammar allows, across the whole advertised range', () => {
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
   * two-digit-year legacy behaviour maps year 50 to 1950" — so the schema was the
   * one place where it survived. The visible consequence was small but real: the
   * editor's own message advertises "Enter a date between 0001-01-01 and
   * 9999-12-31", and a date in the first century was then refused by the write
   * pre-flight instead.
   *
   * FIXED: the refine now builds its Date by mutation too, so the accepted range
   * matches the advertised one. This test pins BOTH halves of that fix — the
   * first century parses, AND an impossible date in the first century is still
   * refused — because the cheapest way to make the first half pass is to delete
   * the calendar check altogether, which would let `0001-02-30` through.
   */
  it('accepts a first-century date, and still rejects an impossible one in the same century', () => {
    for (const expiresAt of ['0001-01-01', '0050-06-15', '0099-12-31', '0004-02-29']) {
      const result = secretDataSchema.safeParse({ expiresAt });
      expect(result.success, `${expiresAt}: ${JSON.stringify(result.error?.issues ?? [])}`).toBe(
        true,
      );
      // Stored verbatim, like every other accepted shape: a zero-padded year is
      // not rewritten into a four-digit one on the way through.
      expect(result.success ? result.data.expiresAt : undefined).toBe(expiresAt);
    }

    // The calendar check itself must survive the fix. `0001-02-30` and
    // `0099-02-29` (1 and 99 are not leap years) are the two that a deleted
    // refine would silently start accepting.
    for (const expiresAt of ['0001-02-30', '0099-02-29', '2026-02-30', '2026-13-01']) {
      const result = secretDataSchema.safeParse({ expiresAt });
      expect(result.success, expiresAt).toBe(false);
      expect(result.success ? [] : result.error.issues).toEqual([
        expect.objectContaining({
          path: ['expiresAt'],
          message: 'expiresAt must be a valid calendar date',
        }),
      ]);
    }

    // And the mechanism the refine must NOT use, so a reader does not have to
    // take the claim on trust: this is the remap that caused the defect.
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
   * (`services/import/itemBuilders.ts`) already subtracted the scheme's length
   * from the bound, but the schema did not. Saving a 2041-2048 character bare
   * domain therefore stored it, `decryptItem` returned the grown value, and every
   * later save of that item was refused by the write pre-flight with "Too big" on
   * `uris.0.uri`.
   *
   * FIXED by moving the length check AFTER the transform, in one exported
   * predicate (`isValidUriLength`) that the editor's own mirror of this schema
   * calls too. The bound is therefore on the value that gets STORED, which is
   * the only length that has ever mattered, and the two boundaries cannot drift.
   *
   * The overhead is measured per value, never assumed: `normalizeUri` adds eight
   * characters to a bare domain, six to a protocol-relative one and none to a
   * value that already carries a scheme, so a flat subtraction would be wrong in
   * two of those three cases. Each is asserted below.
   */
  it('bounds a URI by its POST-transform length, measuring the prepended scheme per value', () => {
    const overhead = 'https://'.length;
    const parseUri = (
      uri: string,
      match = 'domain',
    ): ReturnType<typeof loginDataSchema.safeParse> =>
      loginDataSchema.safeParse({ uris: [{ uri, match }] });

    // The value that used to slip through and brick the item: accepted at parse,
    // grown to 2056, then rejected on read-back. It is now refused up front, on
    // the row it belongs to.
    const bareDomainAtCap = 'x'.repeat(MAX_URI_LENGTH);
    expect(normalizeUri(bareDomainAtCap)).toHaveLength(MAX_URI_LENGTH + overhead);
    const atCap = parseUri(bareDomainAtCap);
    expect(atCap.success).toBe(false);
    expect(atCap.success ? [] : atCap.error.issues).toEqual([
      expect.objectContaining({ path: ['uris', 0, 'uri'] }),
    ]);

    // The boundary is exact and is `clampUri`'s: 2040 is the last bare domain
    // that parses, its output is exactly at the cap, and that output re-parses.
    // That last clause is the fixed point this test exists for.
    const largestBareDomain = 'x'.repeat(MAX_URI_LENGTH - overhead);
    const parsed = loginDataSchema.parse({ uris: [{ uri: largestBareDomain, match: 'domain' }] });
    expect(parsed.uris[0]?.uri).toHaveLength(MAX_URI_LENGTH);
    expect(loginDataSchema.safeParse(throughStorage(parsed)).success).toBe(true);
    expect(parseUri('x'.repeat(MAX_URI_LENGTH - overhead + 1)).success).toBe(false);

    // The cap was NOT simply lowered by eight for everything. A value that
    // already carries its scheme is not grown, so the full 2048 is available to
    // it — and one more is not.
    expect(parseUri(`https://${'x'.repeat(MAX_URI_LENGTH - overhead)}`).success).toBe(true);
    expect(parseUri(`https://${'x'.repeat(MAX_URI_LENGTH - overhead + 1)}`).success).toBe(false);

    // A protocol-relative URI grows by six, not eight, so its input may be two
    // characters LONGER than a bare domain's. A flat "input ≤ 2040" rule would
    // reject this one; the per-value measurement accepts it.
    expect(normalizeUri('//x')).toBe('https://x');
    const protocolRelative = `//${'x'.repeat(MAX_URI_LENGTH - overhead)}`;
    expect(protocolRelative.length).toBeGreaterThan(MAX_URI_LENGTH - overhead);
    expect(normalizeUri(protocolRelative)).toHaveLength(MAX_URI_LENGTH);
    expect(parseUri(protocolRelative).success).toBe(true);
    expect(parseUri(`//${'x'.repeat(MAX_URI_LENGTH - overhead + 1)}`).success).toBe(false);

    // And a regex pattern is never transformed at all, so it gets the whole cap.
    expect(parseUri('x'.repeat(MAX_URI_LENGTH), 'regex').success).toBe(true);
    expect(parseUri('x'.repeat(MAX_URI_LENGTH + 1), 'regex').success).toBe(false);
  });
});
