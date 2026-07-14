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
// ---------------------------------------------------------------------------

const customFieldSchema = z.object({
  name: z.string().min(1).max(500),
  value: z.string().max(MAX_NOTE_CONTENT_LENGTH),
  type: z.enum(CUSTOM_FIELD_TYPES),
});

const uriEntrySchema = z
  .object({
    uri: z.string().max(2048),
    match: z.enum(URI_MATCH_TYPES),
  })
  .transform((entry) => ({
    ...entry,
    // Auto-prepend https:// to bare domains (skip regex match type — those are patterns)
    uri: entry.match === 'regex' ? entry.uri : normalizeUri(entry.uri),
  }))
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

export const loginDataSchema = z
  .object({
    username: z.string().max(500).optional().default(''),
    password: z.string().max(10_000).optional().default(''),
    uris: z.array(uriEntrySchema).max(100).optional().default([]),
    totp: z.string().max(500).optional(),
    notes: z.string().max(MAX_NOTE_CONTENT_LENGTH).optional(),
    customFields: z.array(customFieldSchema).max(100).optional().default([]),
  })
  .strip();

export const secretDataSchema = z
  .object({
    value: z.string().max(MAX_NOTE_CONTENT_LENGTH).optional().default(''),
    description: z.string().max(10_000).optional(),
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
          const date = new Date(Date.UTC(year, month - 1, day));
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
    customFields: z.array(customFieldSchema).max(100).optional().default([]),
  })
  .strip();

export const noteDataSchema = z
  .object({
    content: z.string().max(MAX_NOTE_CONTENT_LENGTH).optional().default(''),
    format: z.enum(NOTE_FORMATS).optional().default('markdown'),
  })
  .strip();

const addressSchema = z
  .object({
    street: z.string().max(500).optional().default(''),
    city: z.string().max(200).optional().default(''),
    state: z.string().max(200).optional().default(''),
    zip: z.string().max(20).optional().default(''),
    country: z.string().max(100).optional().default(''),
  })
  .strip();

export const cardDataSchema = z
  .object({
    cardholderName: z.string().max(300).optional().default(''),
    number: z.string().max(30).optional().default(''),
    expMonth: z.string().max(2).optional().default(''),
    expYear: z.string().max(4).optional().default(''),
    cvv: z.string().max(4).optional().default(''),
    brand: z.string().max(50).optional(),
    notes: z.string().max(MAX_NOTE_CONTENT_LENGTH).optional(),
    billingAddress: addressSchema.optional(),
  })
  .strip();

export const identityDataSchema = z
  .object({
    firstName: z.string().max(200).optional().default(''),
    lastName: z.string().max(200).optional().default(''),
    email: z
      .string()
      .max(254)
      .refine((val) => !val || z.email().safeParse(val).success, {
        message: 'Invalid email address',
      })
      .optional(),
    phone: z
      .string()
      .max(30)
      .refine((val) => !val || /^\+?(?=.*\d)[\d\s().-]+$/.test(val), {
        message: 'Invalid phone number',
      })
      .optional(),
    address: addressSchema.optional(),
    company: z.string().max(300).optional(),
    ssn: z.string().max(20).optional(),
    passport: z.string().max(50).optional(),
    notes: z.string().max(MAX_NOTE_CONTENT_LENGTH).optional(),
    customFields: z.array(customFieldSchema).max(100).optional().default([]),
  })
  .strip();

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
