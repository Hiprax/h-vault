import { z } from 'zod';
import { objectIdSchema, paginationSchema } from './common.js';
import {
  ITEM_TYPES,
  CUSTOM_FIELD_TYPES,
  URI_MATCH_TYPES,
  NOTE_FORMATS,
  MAX_TAGS_PER_ITEM,
  MAX_BULK_OPERATIONS,
  PASSWORD_HISTORY_MAX,
  MAX_ENCRYPTED_NAME_LENGTH,
  MAX_ENCRYPTED_DATA_LENGTH,
  MAX_NOTE_CONTENT_LENGTH,
  MAX_LOGIN_BACKUP_CODES,
  MAX_LOGIN_BACKUP_CODE_LENGTH,
  MAX_LOGIN_USERNAME_LENGTH,
  MAX_LOGIN_PASSWORD_LENGTH,
  MAX_LOGIN_TOTP_LENGTH,
  MAX_URI_LENGTH,
  MAX_URIS_PER_ITEM,
  MAX_CUSTOM_FIELD_NAME_LENGTH,
  MAX_CUSTOM_FIELDS_PER_ITEM,
  MAX_SECRET_DESCRIPTION_LENGTH,
  MAX_CARD_CARDHOLDER_NAME_LENGTH,
  MAX_CARD_BRAND_LENGTH,
  MAX_CARD_NUMBER_LENGTH,
  MAX_CARD_EXP_MONTH_LENGTH,
  MAX_CARD_EXP_YEAR_LENGTH,
  MAX_CARD_CVV_LENGTH,
  MAX_IDENTITY_NAME_LENGTH,
  MAX_IDENTITY_EMAIL_LENGTH,
  MAX_IDENTITY_PHONE_LENGTH,
  MAX_IDENTITY_COMPANY_LENGTH,
  MAX_IDENTITY_SSN_LENGTH,
  MAX_IDENTITY_PASSPORT_LENGTH,
  MAX_ADDRESS_STREET_LENGTH,
  MAX_ADDRESS_CITY_LENGTH,
  MAX_ADDRESS_STATE_LENGTH,
  MAX_ADDRESS_ZIP_LENGTH,
  MAX_ADDRESS_COUNTRY_LENGTH,
  MAX_ADDRESS_DELIVERY_NOTES_LENGTH,
} from '../constants/index.js';
import type { ItemType } from '../constants/index.js';
import { normalizeUri } from '../utils/index.js';

export const createVaultItemSchema = z.object({
  itemType: z.enum(ITEM_TYPES),
  folderId: objectIdSchema.optional(),
  tags: z.array(z.string().trim().min(1).max(50)).max(MAX_TAGS_PER_ITEM).default([]),
  favorite: z.boolean().default(false),
  encryptedData: z.string().min(1).max(MAX_ENCRYPTED_DATA_LENGTH),
  dataIv: z.string().min(1).max(24),
  dataTag: z.string().min(1).max(32),
  encryptedName: z.string().min(1).max(MAX_ENCRYPTED_NAME_LENGTH),
  nameIv: z.string().min(1).max(24),
  nameTag: z.string().min(1).max(32),
  searchHash: z
    .string()
    .regex(/^[a-f0-9]{64}$/)
    .optional(),
});

export const updateVaultItemSchema = z
  .object({
    folderId: objectIdSchema.nullable().optional(),
    tags: z.array(z.string().trim().min(1).max(50)).max(MAX_TAGS_PER_ITEM).optional(),
    favorite: z.boolean().optional(),
    encryptedData: z.string().min(1).max(MAX_ENCRYPTED_DATA_LENGTH).optional(),
    dataIv: z.string().min(1).max(24).optional(),
    dataTag: z.string().min(1).max(32).optional(),
    encryptedName: z.string().min(1).max(MAX_ENCRYPTED_NAME_LENGTH).optional(),
    nameIv: z.string().min(1).max(24).optional(),
    nameTag: z.string().min(1).max(32).optional(),
    searchHash: z
      .string()
      .regex(/^[a-f0-9]{64}$/)
      .optional(),
    passwordHistory: z
      .array(
        z.object({
          encryptedPassword: z.string().min(1).max(MAX_ENCRYPTED_DATA_LENGTH),
          iv: z.string().min(1).max(24),
          tag: z.string().min(1).max(32),
          // Accept both UTC (Z) and timezone offsets (+05:00) for consistency with expiresAt
          changedAt: z.iso.datetime({ offset: true }),
        }),
      )
      .max(PASSWORD_HISTORY_MAX)
      .optional(),
  })
  .refine(
    (data) => {
      const hasData = data.encryptedData !== undefined;
      const hasDataIv = data.dataIv !== undefined;
      const hasDataTag = data.dataTag !== undefined;
      return hasData === hasDataIv && hasDataIv === hasDataTag;
    },
    { message: 'encryptedData, dataIv, and dataTag must all be provided together or all omitted' },
  )
  .refine(
    (data) => {
      const hasName = data.encryptedName !== undefined;
      const hasNameIv = data.nameIv !== undefined;
      const hasNameTag = data.nameTag !== undefined;
      return hasName === hasNameIv && hasNameIv === hasNameTag;
    },
    { message: 'encryptedName, nameIv, and nameTag must all be provided together or all omitted' },
  );

export const listVaultItemsSchema = paginationSchema.extend({
  itemType: z.enum(ITEM_TYPES).optional(),
  folderId: objectIdSchema.optional(),
  // z.stringbool() parses canonical string booleans ("true"/"false", "1"/"0",
  // etc.) from query params so ?favorite=false / ?trash=false mean what they
  // say. z.coerce.boolean() (== Boolean(input)) treats any non-empty string as
  // true, inverting these filters. It is intentionally stricter: a non-canonical
  // value (e.g. ?trash=maybe) is rejected rather than silently coerced. An
  // absent param still yields undefined via .optional().
  favorite: z.stringbool().optional(),
  trash: z.stringbool().optional(),
  sortBy: z.enum(['createdAt', 'updatedAt', 'itemType', 'favorite']).default('updatedAt'),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),
});

export const listTrashSchema = paginationSchema.extend({
  sortBy: z.enum(['deletedAt', 'createdAt', 'updatedAt', 'itemType']).default('deletedAt'),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),
});

export const bulkDeleteSchema = z.object({
  ids: z.array(objectIdSchema).min(1).max(MAX_BULK_OPERATIONS),
});

export const bulkMoveSchema = z.object({
  ids: z.array(objectIdSchema).min(1).max(MAX_BULK_OPERATIONS),
  folderId: objectIdSchema.nullable(),
});

export const bulkReEncryptSchema = z.object({
  authHash: z.string().min(1).max(100),
  idempotencyKey: z.uuid().optional(),
  items: z
    .array(
      z.object({
        id: objectIdSchema,
        encryptedName: z.string().min(1).max(MAX_ENCRYPTED_NAME_LENGTH),
        nameIv: z.string().min(1).max(24),
        nameTag: z.string().min(1).max(32),
        encryptedData: z.string().min(1).max(MAX_ENCRYPTED_DATA_LENGTH),
        dataIv: z.string().min(1).max(24),
        dataTag: z.string().min(1).max(32),
        searchHash: z
          .string()
          .regex(/^[a-f0-9]{64}$/)
          .optional(),
        passwordHistory: z
          .array(
            z.object({
              encryptedPassword: z.string().min(1).max(MAX_ENCRYPTED_DATA_LENGTH),
              iv: z.string().min(1).max(24),
              tag: z.string().min(1).max(32),
              changedAt: z.iso.datetime({ offset: true }),
            }),
          )
          .max(PASSWORD_HISTORY_MAX)
          .optional(),
      }),
    )
    .min(0)
    .max(10_000),
  folders: z
    .array(
      z.object({
        id: objectIdSchema,
        encryptedName: z.string().min(1).max(MAX_ENCRYPTED_NAME_LENGTH),
        nameIv: z.string().min(1).max(24),
        nameTag: z.string().min(1).max(32),
      }),
    )
    .max(1000)
    .optional()
    .default([]),
  newEncryptedVaultKey: z.string().min(1).max(200),
  newVaultKeyIv: z.string().min(1).max(24),
  newVaultKeyTag: z.string().min(1).max(32),
});

// ---------------------------------------------------------------------------
// API response validation schemas (pre-decryption shape check)
// ---------------------------------------------------------------------------

/**
 * Validates the shape of a vault item response from the API before attempting
 * decryption. Catches malformed responses (missing fields, partial corruption)
 * early with a clear error instead of a cryptic decryption failure.
 *
 * `userId` is intentionally absent — the server strips it from every response
 * shape (toJSON transform + `.select('-userId')` projections) because the
 * authenticated session already determines the owner. Schema validation must
 * not require a field the API does not send.
 */
export const vaultItemResponseSchema = z.object({
  _id: z.string().min(1),
  itemType: z.enum(ITEM_TYPES),
  folderId: z.string().optional(),
  tags: z.array(z.string()),
  favorite: z.boolean(),
  encryptedData: z.string().min(1),
  dataIv: z.string().min(1),
  dataTag: z.string().min(1),
  encryptedName: z.string().min(1),
  nameIv: z.string().min(1),
  nameTag: z.string().min(1),
  searchHash: z.string().optional(),
  passwordHistory: z
    .array(
      z.object({
        encryptedPassword: z.string().min(1),
        iv: z.string().min(1),
        tag: z.string().min(1),
        changedAt: z.string().min(1),
      }),
    )
    .optional(),
  createdAt: z.string().min(1),
  updatedAt: z.string().min(1),
  deletedAt: z.string().optional(),
});

/**
 * Validates the shape of a folder response from the API before attempting
 * decryption.
 *
 * `userId` is intentionally absent for the same reason as
 * {@link vaultItemResponseSchema}.
 */
export const folderResponseSchema = z.object({
  _id: z.string().min(1),
  encryptedName: z.string().min(1),
  nameIv: z.string().min(1),
  nameTag: z.string().min(1),
  searchHash: z.string().optional(),
  parentId: z.string().optional(),
  icon: z.string().optional(),
  color: z.string().optional(),
  sortOrder: z.number(),
  createdAt: z.string().min(1),
  updatedAt: z.string().min(1),
});

// ---------------------------------------------------------------------------
// Decrypted vault item data schemas (client-side validation after decryption)
//
// EVERY schema below runs in STRIP mode: an unknown key is silently dropped from
// the parsed output rather than rejected. That is `z.object()`'s default and is
// relied on as an invariant, not an accident — see `addressSchema` for the case
// where it is what keeps a field off a whole item type. These declarations used
// to append a redundant `.strip()` to say so; zod documents that call as
// unnecessary ("This is the default behavior"), so it now lives here as one
// statement instead of six identical ones.
//
// Because they run on every DECRYPT (`vaultStore.decryptItem`) AND, since the
// client-side pre-flight was added, on every WRITE (`vaultStore.createItem` /
// `updateItem`), a rejection is user-visible in both directions: on the way out it
// degrades the item to the "could not be fully decoded" notice, and on the way in
// it blocks the save with a message. Keep them permissive about FORMAT and strict
// about LENGTH.
// ---------------------------------------------------------------------------

const customFieldSchema = z.object({
  name: z.string().min(1).max(MAX_CUSTOM_FIELD_NAME_LENGTH),
  value: z.string().max(MAX_NOTE_CONTENT_LENGTH),
  type: z.enum(CUSTOM_FIELD_TYPES),
});

/**
 * The message `isValidUriLength` reports, exported so the editor's own mirror of
 * this schema cannot word it differently.
 */
export const URI_TOO_LONG_MESSAGE = `URI must be ${String(MAX_URI_LENGTH)} characters or fewer, counting the https:// that a bare domain is given`;

/**
 * Does this URI fit `MAX_URI_LENGTH` once the transform below has run?
 *
 * The ONE definition of the URI length bound, in the same spirit as
 * `isValidIdentityEmail`/`isValidIdentityPhone`: `VaultItemForm`'s local mirror of
 * this schema calls it too, so the editor and the store cannot disagree about
 * which values are storable.
 *
 * The length is measured AFTER normalization, and that is the whole point. It used
 * to be measured before, as `z.string().max(MAX_URI_LENGTH)` on the input, so a bare
 * domain of exactly `MAX_URI_LENGTH` characters parsed happily into a
 * `MAX_URI_LENGTH + 8` one — a value this very schema then rejected on the way back
 * in, leaving the item editable exactly once. The overhead is also measured per
 * value rather than assumed: `normalizeUri` adds eight characters to a bare domain,
 * six to a protocol-relative one and none to a value that already carries a scheme,
 * so a flat subtraction would refuse values that are perfectly storable.
 *
 * Safe to call on either side of the transform: `normalizeUri` is idempotent.
 */
export function isValidUriLength(uri: string, match: string): boolean {
  return (match === 'regex' ? uri : normalizeUri(uri)).length <= MAX_URI_LENGTH;
}

const uriEntrySchema = z
  .object({
    // Deliberately unbounded HERE; the bound is the post-transform one below.
    // `normalizeUri` only ever prepends, so an output within the cap implies an
    // input within it, and there is no second, looser boundary to drift.
    uri: z.string(),
    match: z.enum(URI_MATCH_TYPES),
  })
  .transform((entry) => ({
    ...entry,
    // Auto-prepend https:// to bare domains (skip regex match type — those are patterns)
    uri: entry.match === 'regex' ? entry.uri : normalizeUri(entry.uri),
  }))
  .refine((entry) => isValidUriLength(entry.uri, entry.match), {
    message: URI_TOO_LONG_MESSAGE,
    path: ['uri'],
  })
  .refine(
    (entry) => {
      // Skip protocol validation for regex match type — the URI is a pattern, not a URL
      if (entry.match === 'regex') return true;
      return !entry.uri || /^(https?:|mailto:)/i.test(entry.uri);
    },
    { message: 'URI must start with http://, https://, or mailto:', path: ['uri'] },
  )
  .refine(
    (entry) => {
      if (entry.match !== 'regex') return true;
      try {
        // eslint-disable-next-line security/detect-non-literal-regexp -- intentional: validating user regex compiles
        new RegExp(entry.uri);
        return true;
      } catch {
        return false;
      }
    },
    { message: 'Invalid regular expression pattern', path: ['uri'] },
  );

export const loginDataSchema = z.object({
  username: z.string().max(MAX_LOGIN_USERNAME_LENGTH).optional().default(''),
  password: z.string().max(MAX_LOGIN_PASSWORD_LENGTH).optional().default(''),
  uris: z.array(uriEntrySchema).max(MAX_URIS_PER_ITEM).optional().default([]),
  totp: z.string().max(MAX_LOGIN_TOTP_LENGTH).optional(),
  // 2FA recovery codes for the THIRD-PARTY account this login belongs to — not
  // this vault's own account-level codes (see BACKUP_CODES_COUNT).
  //
  // Deliberately PERMISSIVE: length caps only. No charset rule, no `.min(1)`,
  // no `.transform()` and no `.catch()`. This schema runs on every DECRYPT
  // (`vaultStore.decryptItem`), and a failure there stamps `_validationError`
  // on the item, which `isUndecodableData` degrades to the read-only "could not
  // be fully decoded" notice — so one odd code would cost the user UI access to
  // the item's PASSWORD. Format strictness therefore lives at INPUT time, in
  // `parseBackupCodes` (utils/backupCodes.ts), the same split that already
  // strips blank custom-field names in `VaultItemForm`.
  //
  // `.transform()` is banned because it is the exact mechanism of the old
  // `uris` bug: a transform that GROWS the value after the length check stored
  // an over-cap value that then failed on decrypt (see `clampUri`). `.catch()`
  // is banned because it is the opposite of fail-soft: `_validationError`
  // preserves the ciphertext, whereas a `.catch([])` would show a normal,
  // editable login whose next save destroys the codes for good.
  //
  // `.optional()` with NO `.default([])`, unlike `uris`/`customFields`: a
  // default is what makes the type views dereference an absent array and throw
  // (see the UndecodableNotice docblock), it would inject `backupCodes: []` into
  // every existing login's parsed data, and it turns a correct defensive guard
  // into a lint-flagged redundant condition.
  backupCodes: z
    .array(z.string().max(MAX_LOGIN_BACKUP_CODE_LENGTH))
    .max(MAX_LOGIN_BACKUP_CODES)
    .optional(),
  notes: z.string().max(MAX_NOTE_CONTENT_LENGTH).optional(),
  customFields: z.array(customFieldSchema).max(MAX_CUSTOM_FIELDS_PER_ITEM).optional().default([]),
});

export const secretDataSchema = z.object({
  value: z.string().max(MAX_NOTE_CONTENT_LENGTH).optional().default(''),
  description: z.string().max(MAX_SECRET_DESCRIPTION_LENGTH).optional(),
  expiresAt: z
    .string()
    .max(100)
    .refine(
      (val) =>
        // eslint-disable-next-line security/detect-unsafe-regex -- anchored ISO 8601 regex on bounded input (max 100 chars)
        /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})?)?$/.test(val),
      { message: 'expiresAt must be a valid ISO 8601 date or datetime string' },
    )
    .refine(
      (val) => {
        const datePart = val.split('T')[0] ?? val;
        const [year, month, day] = datePart.split('-').map(Number) as [number, number, number];
        // Built by MUTATION, never `new Date(Date.UTC(year, …))`. `Date.UTC` applies
        // the two-digit-year legacy rule and maps a year in 0-99 to 1900-1999, so the
        // comparison below failed for every first-century date and the schema refused
        // dates the editor's own message ("between 0001-01-01 and 9999-12-31")
        // advertises as valid. `combineExpiry` in `VaultItemForm` already avoids this
        // exact trap the same way; this is the other half of it.
        const date = new Date(0);
        date.setUTCFullYear(year, month - 1, day);
        return (
          date.getUTCFullYear() === year &&
          date.getUTCMonth() === month - 1 &&
          date.getUTCDate() === day
        );
      },
      { message: 'expiresAt must be a valid calendar date' },
    )
    .refine(
      // The ISO regex above only constrains the SHAPE of the time part, so
      // impossible components (T99:99:99) pass it, and the calendar refine only
      // inspects the date half. Delegate the time half to the Date parser, which
      // rejects out-of-range hours/minutes/seconds for an ISO 8601 string.
      (val) => !val.includes('T') || !Number.isNaN(new Date(val).getTime()),
      { message: 'expiresAt must have a valid time component' },
    )
    .optional(),
  customFields: z.array(customFieldSchema).max(MAX_CUSTOM_FIELDS_PER_ITEM).optional().default([]),
});

export const noteDataSchema = z.object({
  content: z.string().max(MAX_NOTE_CONTENT_LENGTH).optional().default(''),
  format: z.enum(NOTE_FORMATS).optional().default('markdown'),
});

/**
 * The postal-address sub-shape, shared by a CARD's `billingAddress` and used as
 * the base of an IDENTITY's `address`.
 *
 * `street2` is the WHATWG `address-line2` peer of `street` (Bitwarden names the
 * same pair `address1`/`address2`), so both share one bound.
 *
 * This BASE shape deliberately carries no delivery instructions, and STRIP mode
 * (see the section header above) is what makes "delivery notes are identity-only"
 * an INVARIANT rather than a UI convention: a `deliveryNotes` key inside a card's
 * `billingAddress` is dropped on read-back, so it can never be stored, exported,
 * or displayed on a card.
 */
const addressSchema = z.object({
  street: z.string().max(MAX_ADDRESS_STREET_LENGTH).optional().default(''),
  street2: z.string().max(MAX_ADDRESS_STREET_LENGTH).optional().default(''),
  city: z.string().max(MAX_ADDRESS_CITY_LENGTH).optional().default(''),
  state: z.string().max(MAX_ADDRESS_STATE_LENGTH).optional().default(''),
  zip: z.string().max(MAX_ADDRESS_ZIP_LENGTH).optional().default(''),
  country: z.string().max(MAX_ADDRESS_COUNTRY_LENGTH).optional().default(''),
});

/**
 * An IDENTITY's address: {@link addressSchema} plus the free-text courier
 * instructions a shipping address carries and a billing address has no meaning
 * for ("leave with the concierge", "ring twice").
 *
 * Derived with `.extend()` rather than declared separately so the two shapes can
 * never drift and the identity shape is provably a superset of the base.
 */
const identityAddressSchema = addressSchema.extend({
  deliveryNotes: z.string().max(MAX_ADDRESS_DELIVERY_NOTES_LENGTH).optional().default(''),
});

export const cardDataSchema = z.object({
  cardholderName: z.string().max(MAX_CARD_CARDHOLDER_NAME_LENGTH).optional().default(''),
  number: z.string().max(MAX_CARD_NUMBER_LENGTH).optional().default(''),
  expMonth: z.string().max(MAX_CARD_EXP_MONTH_LENGTH).optional().default(''),
  expYear: z.string().max(MAX_CARD_EXP_YEAR_LENGTH).optional().default(''),
  cvv: z.string().max(MAX_CARD_CVV_LENGTH).optional().default(''),
  brand: z.string().max(MAX_CARD_BRAND_LENGTH).optional(),
  notes: z.string().max(MAX_NOTE_CONTENT_LENGTH).optional(),
  billingAddress: addressSchema.optional(),
});

/**
 * True when `value` is an acceptable identity email address. An EMPTY string is
 * acceptable — the field is optional and the form defaults it to `''`.
 *
 * Exported because `VaultItemForm`'s lenient input schema has to enforce the SAME
 * predicate: a local check that admits what this one rejects (a quoted local
 * part, say) lets the value through the form, past encryption, and into a stored
 * blob that fails `identityDataSchema` on the next decrypt — which degrades the
 * whole identity to the "could not be fully decoded" notice. One function, two
 * call sites, and each side keeps its own user-facing message.
 */
export function isValidIdentityEmail(value: string): boolean {
  return !value || z.email().safeParse(value).success;
}

/**
 * True when `value` is an acceptable identity phone number: an optional single
 * LEADING `+`, at least one digit somewhere, and nothing outside digits, spaces,
 * parentheses, dots and hyphens. An empty string is acceptable.
 *
 * Exported for the same reason as {@link isValidIdentityEmail}. The form's own
 * regex used to admit a `+` in the middle (`12+34`) and a punctuation-only value
 * with no digit at all (`(.)`), both of which this rejects.
 */
export function isValidIdentityPhone(value: string): boolean {
  return !value || /^\+?(?=.*\d)[\d\s().-]+$/.test(value);
}

export const identityDataSchema = z.object({
  firstName: z.string().max(MAX_IDENTITY_NAME_LENGTH).optional().default(''),
  lastName: z.string().max(MAX_IDENTITY_NAME_LENGTH).optional().default(''),
  email: z
    .string()
    .max(MAX_IDENTITY_EMAIL_LENGTH)
    .refine(isValidIdentityEmail, { message: 'Invalid email address' })
    .optional(),
  phone: z
    .string()
    .max(MAX_IDENTITY_PHONE_LENGTH)
    .refine(isValidIdentityPhone, { message: 'Invalid phone number' })
    .optional(),
  address: identityAddressSchema.optional(),
  company: z.string().max(MAX_IDENTITY_COMPANY_LENGTH).optional(),
  ssn: z.string().max(MAX_IDENTITY_SSN_LENGTH).optional(),
  passport: z.string().max(MAX_IDENTITY_PASSPORT_LENGTH).optional(),
  notes: z.string().max(MAX_NOTE_CONTENT_LENGTH).optional(),
  customFields: z.array(customFieldSchema).max(MAX_CUSTOM_FIELDS_PER_ITEM).optional().default([]),
});

/**
 * Map of item types to their decrypted data Zod schemas.
 * Used by the client to validate data after decryption.
 */
export const vaultItemDataSchemas: Record<ItemType, z.ZodType> = {
  login: loginDataSchema,
  secret: secretDataSchema,
  note: noteDataSchema,
  card: cardDataSchema,
  identity: identityDataSchema,
};
