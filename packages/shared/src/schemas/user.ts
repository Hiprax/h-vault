import { z } from 'zod';
import {
  THEMES,
  AUDIT_ACTIONS,
  AUDIT_LOG_PAGE_LIMIT,
  AUDIT_LOG_MAX_LIMIT,
  MAX_BACKUP_EMAILS,
  MAX_RESTORE_DATA_LENGTH,
  MAX_IMPORT_DATA_LENGTH,
  MAX_IMPORT_ITEMS,
  MAX_TAGS_PER_ITEM,
  MAX_ENCRYPTED_NAME_LENGTH,
  MAX_ENCRYPTED_DATA_LENGTH,
  PASSWORD_HISTORY_MAX,
  ITEM_TYPES,
} from '../constants/index.js';
import { objectIdSchema } from './common.js';

export const passwordGenOptionsSchema = z
  .object({
    length: z.number().int().min(8).max(128).default(20),
    uppercase: z.boolean().default(true),
    lowercase: z.boolean().default(true),
    numbers: z.boolean().default(true),
    symbols: z.boolean().default(true),
    excludeAmbiguous: z.boolean().default(false),
    minNumbers: z.number().int().min(0).default(1),
    minSymbols: z.number().int().min(0).default(1),
  })
  // Cross-field invariant: a password cannot satisfy `minNumbers` + `minSymbols`
  // required characters if its total `length` is smaller than their sum. This is
  // the first line of defense (the User model carries the same check as a
  // defense-in-depth backstop). The refinement runs after defaults are applied,
  // so all three operands are always concrete numbers here.
  .refine((o) => o.length >= o.minNumbers + o.minSymbols, {
    message: 'Password length must be at least the sum of minNumbers and minSymbols',
    path: ['length'],
  });

export const updateSettingsSchema = z.object({
  autoLockTimeout: z.number().int().min(1).max(1440).optional(),
  clipboardClearTimeout: z.number().int().min(5).max(300).optional(),
  defaultPasswordLength: z.number().int().min(8).max(128).optional(),
  defaultPasswordOptions: passwordGenOptionsSchema.optional(),
  theme: z.enum(THEMES).optional(),
  language: z.string().min(2).max(10).optional(),
});

export const setup2faSchema = z.object({
  password: z.string().min(1).max(500),
});

export const verify2faSchema = z.object({
  code: z
    .string()
    .min(6)
    .max(6)
    .refine((val) => /^\d{6}$/.test(val), { message: 'TOTP code must be exactly 6 digits' }),
});

export const disable2faSchema = z.object({
  code: z
    .string()
    .min(6)
    .max(16)
    .refine((val) => /^[a-zA-Z0-9]+$/.test(val), {
      message: 'Code must contain only alphanumeric characters',
    }),
  password: z.string().min(1).max(500),
});

export const regenerateBackupCodesSchema = z.object({
  password: z.string().min(1).max(500),
  code: z
    .string()
    .min(6)
    .max(16)
    .refine((val) => /^[a-zA-Z0-9]+$/.test(val), {
      message: 'Code must contain only alphanumeric characters',
    })
    .optional(),
});

export const checkBreachSchema = z.object({
  hashPrefix: z.string().regex(/^[0-9a-fA-F]{5}$/),
});

export const backupSetupSchema = z
  .object({
    authHash: z.string().min(1).max(100),
    encryptedBWK: z.string().min(1).max(500),
    bwkIv: z.string().min(1).max(24),
    bwkTag: z.string().min(1).max(32),
    bwkSalt: z.string().min(1).max(64),
    bwkEncryptedVaultKey: z.string().min(1).max(500).optional(),
    bwkVaultKeyIv: z.string().min(1).max(24).optional(),
    bwkVaultKeyTag: z.string().min(1).max(32).optional(),
  })
  .superRefine((data, ctx) => {
    const hasKey = data.bwkEncryptedVaultKey !== undefined;
    const hasIv = data.bwkVaultKeyIv !== undefined;
    const hasTag = data.bwkVaultKeyTag !== undefined;
    if (!(hasKey === hasIv && hasIv === hasTag)) {
      ctx.addIssue({
        code: 'custom',
        message:
          'bwkEncryptedVaultKey, bwkVaultKeyIv, and bwkVaultKeyTag must all be provided together or all omitted',
      });
    }
  });

export const backupSettingsSchema = z.object({
  enabled: z.boolean().optional(),
  scheduleHour: z.number().int().min(0).max(23).optional(),
  backupEmails: z.array(z.email().max(254).toLowerCase().trim()).max(MAX_BACKUP_EMAILS).optional(),
});

export const backupChangePasswordSchema = z
  .object({
    password: z.string().min(1).max(500),
    newEncryptedBWK: z.string().min(1).max(500),
    newBwkIv: z.string().min(1).max(24),
    newBwkTag: z.string().min(1).max(32),
    newBwkSalt: z.string().min(1).max(64),
    newBwkEncryptedVaultKey: z.string().min(1).max(500).optional(),
    newBwkVaultKeyIv: z.string().min(1).max(24).optional(),
    newBwkVaultKeyTag: z.string().min(1).max(32).optional(),
  })
  .refine(
    (data) => {
      const hasKey = data.newBwkEncryptedVaultKey !== undefined;
      const hasIv = data.newBwkVaultKeyIv !== undefined;
      const hasTag = data.newBwkVaultKeyTag !== undefined;
      return hasKey === hasIv && hasIv === hasTag;
    },
    {
      message:
        'newBwkEncryptedVaultKey, newBwkVaultKeyIv, and newBwkVaultKeyTag must all be provided together or all omitted',
    },
  );

export const deleteAccountSchema = z.object({
  password: z.string().min(1).max(500),
  code: z
    .string()
    .min(6)
    .max(16)
    .refine((val) => /^[a-zA-Z0-9]+$/.test(val), {
      message: 'Code must contain only alphanumeric characters',
    })
    .optional(),
});

export const auditLogQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(AUDIT_LOG_MAX_LIMIT).default(AUDIT_LOG_PAGE_LIMIT),
  action: z.enum(AUDIT_ACTIONS).optional(),
});

export const backupHistorySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(30).default(30),
});

export const restoreBackupSchema = z.object({
  conflictStrategy: z.enum(['skip', 'overwrite', 'keep_both']).default('skip'),
  data: z.string().min(1).max(MAX_RESTORE_DATA_LENGTH),
  // A restore NEVER replaces the caller's vault key. The client re-encrypts every
  // backup row to this account's current vault key before sending, so restore is a
  // plain, unprivileged add of rows already under the account's key — no vault-key
  // adoption and no master-password re-auth are accepted here.
});

export const exportSchema = z.object({
  // Export is JSON-only. The server serializes the encrypted vault as JSON and
  // ignores any other format, so the schema accepts only 'json' to keep the
  // request contract honest (CSV is an import-only format — see importSchema).
  format: z.literal('json').default('json'),
  authHash: z.string().min(1).max(100),
});

// ---------------------------------------------------------------------------
// Import wire contract
// ---------------------------------------------------------------------------
// Two shapes coexist during the migration (added additively, see PLAN.md Phase
// 2). The legacy `data` shape carries a JSON string of already-encrypted native
// items; the new `operations` shape carries explicit `inserts` and `updates`,
// where each update names the `_id` it targets. Conflict resolution has moved to
// the client (the only place the plaintext exists), so the server becomes a
// validated executor: it validates ownership, caps, and field lengths but makes
// no matching decisions of its own. Exactly one of `data`/`operations` must be
// present. The legacy field is retired once both consumers have switched.

/**
 * One encrypted item to INSERT. This mirrors today's import item shape (the
 * fields the server maps through its fixed `ALLOWED_ITEM_FIELDS` projection).
 * `searchHash` is required because every non-import creation path writes one and
 * the backup/restore flow relies on its presence (see PLAN.md § 1.4).
 */
export const importInsertItemSchema = z.object({
  itemType: z.enum(ITEM_TYPES),
  encryptedName: z.string().min(1).max(MAX_ENCRYPTED_NAME_LENGTH),
  nameIv: z.string().min(1).max(24),
  nameTag: z.string().min(1).max(32),
  encryptedData: z.string().min(1).max(MAX_ENCRYPTED_DATA_LENGTH),
  dataIv: z.string().min(1).max(24),
  dataTag: z.string().min(1).max(32),
  searchHash: z.string().regex(/^[a-f0-9]{64}$/),
  tags: z.array(z.string().trim().min(1).max(50)).max(MAX_TAGS_PER_ITEM).default([]),
  favorite: z.boolean().default(false),
  folderId: objectIdSchema.optional(),
});

/**
 * A password-history entry carried on an import update. Bounded in the schema
 * (not just by the model validators, which fire only under `runValidators`)
 * because `assertImportFieldLengths` walks only top-level string fields and would
 * not catch an oversized nested history array. The per-entry caps mirror
 * `models/VaultItem.ts` (`encryptedPassword` maxlength 5_000, iv 24, tag 32).
 */
export const importUpdatePasswordHistoryEntrySchema = z.object({
  encryptedPassword: z.string().min(1).max(5_000),
  iv: z.string().min(1).max(24),
  tag: z.string().min(1).max(32),
  // Accept both UTC (Z) and timezone offsets (+05:00), matching vault.ts.
  changedAt: z.iso.datetime({ offset: true }),
});

/**
 * One existing item to UPDATE in place. Carries `id` (reusing the shared
 * `objectIdSchema` — a case-insensitive hex ObjectId with a lowercase transform),
 * the six ciphertext fields, a client-recomputed `searchHash` (an overwrite
 * replaces `encryptedName`, so the stored hash must be refreshed alongside it),
 * and an optional bounded `passwordHistory`. It deliberately does NOT carry
 * `tags`/`favorite`/`folderId`: an import updates content only and must not
 * silently reorganize an existing vault.
 */
export const importUpdateItemSchema = z.object({
  id: objectIdSchema,
  encryptedName: z.string().min(1).max(MAX_ENCRYPTED_NAME_LENGTH),
  nameIv: z.string().min(1).max(24),
  nameTag: z.string().min(1).max(32),
  encryptedData: z.string().min(1).max(MAX_ENCRYPTED_DATA_LENGTH),
  dataIv: z.string().min(1).max(24),
  dataTag: z.string().min(1).max(32),
  searchHash: z.string().regex(/^[a-f0-9]{64}$/),
  passwordHistory: z
    .array(importUpdatePasswordHistoryEntrySchema)
    .max(PASSWORD_HISTORY_MAX)
    .optional(),
});

/**
 * The structured import payload: explicit `inserts` and `updates`. Both default
 * to `[]` so a caller may send only one kind. The combined length bound (1..
 * `MAX_IMPORT_ITEMS`) is enforced on `importSchema` itself, so it can produce a
 * clear message when `operations` is present but empty.
 */
export const importOperationsSchema = z.object({
  inserts: z.array(importInsertItemSchema).default([]),
  updates: z.array(importUpdateItemSchema).default([]),
});

export const importSchema = z
  .object({
    // Zero-knowledge import: the browser parses the source file, converts each
    // entry to a vault item, encrypts it with the vault key, and sends
    // already-encrypted items. The server never parses plaintext and never
    // encrypts. `format` and `conflictStrategy` are audit-only metadata that
    // record which source the user imported from and which strategy the client
    // applied; the server acts on neither (resolution already happened on the
    // client). `csv`/`json` cover generic CSV and native H-Vault exports.
    format: z.enum([
      'bitwarden',
      'lastpass',
      'keepass',
      'chrome',
      'firefox',
      'onepassword',
      'csv',
      'json',
    ]),
    conflictStrategy: z.enum(['skip', 'overwrite', 'keep_both']).optional().default('skip'),
    // Legacy shape (retired in a later phase): a JSON string of encrypted items.
    data: z.string().min(1).max(MAX_IMPORT_DATA_LENGTH).optional(),
    // New shape: explicit inserts/updates the server validates and executes.
    operations: importOperationsSchema.optional(),
  })
  // Exactly one of `data` / `operations` must be present (XOR). Neither is an
  // empty request; both is ambiguous.
  .refine((val) => (val.data !== undefined) !== (val.operations !== undefined), {
    message: 'Provide exactly one of "data" or "operations"',
    path: ['operations'],
  })
  // When `operations` is present, its combined item count must be in range. The
  // legacy `data` byte cap does not apply to the structured shape (PLAN.md §1.7).
  .refine(
    (val) => {
      if (val.operations === undefined) return true;
      const total = val.operations.inserts.length + val.operations.updates.length;
      return total >= 1 && total <= MAX_IMPORT_ITEMS;
    },
    {
      message: `operations must contain between 1 and ${String(MAX_IMPORT_ITEMS)} items`,
      path: ['operations'],
    },
  );
