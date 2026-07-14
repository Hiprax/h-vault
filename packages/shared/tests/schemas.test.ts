import { describe, it, expect } from 'vitest';
import { objectIdSchema, paginationSchema } from '../src/schemas/common.js';
import {
  emailSchema,
  registerSchema,
  loginSchema,
  login2faSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  verifyEmailSchema,
  changePasswordSchema,
  unlockAccountSchema,
  resendVerificationSchema,
} from '../src/schemas/auth.js';
import {
  createVaultItemSchema,
  updateVaultItemSchema,
  listVaultItemsSchema,
  bulkDeleteSchema,
  bulkMoveSchema,
  bulkReEncryptSchema,
  listTrashSchema,
  loginDataSchema,
  secretDataSchema,
  noteDataSchema,
  cardDataSchema,
  identityDataSchema,
  vaultItemDataSchemas,
  vaultItemResponseSchema,
  folderResponseSchema,
} from '../src/schemas/vault.js';
import {
  createFolderSchema,
  updateFolderSchema,
  deleteFolderQuerySchema,
  reorderFolderSchema,
} from '../src/schemas/folder.js';
import {
  passwordGenOptionsSchema,
  updateSettingsSchema,
  setup2faSchema,
  verify2faSchema,
  disable2faSchema,
  checkBreachSchema,
  backupSetupSchema,
  backupSettingsSchema,
  backupChangePasswordSchema,
  backupHistorySchema,
  auditLogQuerySchema,
  restoreBackupSchema,
  exportSchema,
  importSchema,
  regenerateBackupCodesSchema,
  deleteAccountSchema,
} from '../src/schemas/user.js';

const VALID_OBJECT_ID = 'a'.repeat(24);

// ---------------------------------------------------------------------------
// Common schemas
// ---------------------------------------------------------------------------
describe('objectIdSchema', () => {
  it('accepts a valid 24-char hex string', () => {
    expect(objectIdSchema.safeParse(VALID_OBJECT_ID).success).toBe(true);
  });

  it('rejects a non-hex string', () => {
    expect(objectIdSchema.safeParse('zzzzzzzzzzzzzzzzzzzzzzzz').success).toBe(false);
  });

  it('rejects a string that is too short', () => {
    expect(objectIdSchema.safeParse('abc123').success).toBe(false);
  });

  it('rejects a string that is too long', () => {
    expect(objectIdSchema.safeParse('a'.repeat(25)).success).toBe(false);
  });

  it('accepts lowercase hex ObjectId', () => {
    const result = objectIdSchema.safeParse('507f1f77bcf86cd799439011');
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data).toBe('507f1f77bcf86cd799439011');
    }
  });

  it('normalizes uppercase hex ObjectId to lowercase', () => {
    const result = objectIdSchema.safeParse('507F1F77BCF86CD799439011');
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data).toBe('507f1f77bcf86cd799439011');
    }
  });

  it('normalizes mixed-case hex ObjectId to lowercase', () => {
    const result = objectIdSchema.safeParse('507f1F77bcF86cD799439011');
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data).toBe('507f1f77bcf86cd799439011');
    }
  });

  it('rejects non-hex characters', () => {
    expect(objectIdSchema.safeParse('not-a-valid-id----------').success).toBe(false);
  });
});

describe('paginationSchema', () => {
  it('provides default page and limit', () => {
    const result = paginationSchema.parse({});
    expect(result.page).toBe(1);
    expect(result.limit).toBe(50);
  });

  it('coerces string values', () => {
    const result = paginationSchema.parse({ page: '2', limit: '25' });
    expect(result.page).toBe(2);
    expect(result.limit).toBe(25);
  });

  it('rejects page less than 1', () => {
    expect(paginationSchema.safeParse({ page: 0 }).success).toBe(false);
  });

  it('rejects limit over 200', () => {
    expect(paginationSchema.safeParse({ limit: 201 }).success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Auth schemas
// ---------------------------------------------------------------------------
describe('emailSchema', () => {
  it('accepts a valid email', () => {
    expect(emailSchema.safeParse('user@example.com').success).toBe(true);
  });

  it('lowercases the email', () => {
    const result = emailSchema.parse('USER@Example.COM');
    expect(result).toBe('user@example.com');
  });

  it('lowercases the email through registerSchema and rejects (does not trim) padded input', () => {
    // The object schema still applies emailSchema's `.toLowerCase()`.
    const result = registerSchema.parse({
      email: 'USER@Example.COM',
      authHash: 'hash',
      encryptedVaultKey: 'key',
      vaultKeyIv: 'iv',
      vaultKeyTag: 'tag',
      kdfIterations: 600_000,
      kdfAlgorithm: 'PBKDF2-SHA256',
    });
    expect(result.email).toBe('user@example.com');

    // Zod 4 validates the email FORMAT before the `.trim()` transform runs, so a
    // padded email is REJECTED outright rather than silently trimmed. This
    // pins the real whitespace behaviour: if the chain were ever reordered to
    // trim before validating, this would start succeeding and flip to `true`.
    expect(emailSchema.safeParse(' user@example.com ').success).toBe(false);
    expect(emailSchema.safeParse('user@example.com ').success).toBe(false);
  });

  it('rejects invalid email', () => {
    expect(emailSchema.safeParse('not-an-email').success).toBe(false);
  });

  it('rejects email over 254 characters', () => {
    const longEmail = 'a'.repeat(243) + '@example.com'; // 255 chars
    expect(emailSchema.safeParse(longEmail).success).toBe(false);
  });

  // ── TLD-required refinement (defends against typo lockout) ─────────
  it('rejects bare-host emails without a TLD-style dot', () => {
    expect(emailSchema.safeParse('a@b').success).toBe(false);
    expect(emailSchema.safeParse('user@localhost').success).toBe(false);
    expect(emailSchema.safeParse('admin@intranet').success).toBe(false);
  });

  it('rejects emails ending in a trailing dot', () => {
    expect(emailSchema.safeParse('user@example.').success).toBe(false);
  });

  it('rejects emails with consecutive dots in the domain', () => {
    expect(emailSchema.safeParse('user@example..com').success).toBe(false);
  });

  it('accepts conventional TLD addresses', () => {
    expect(emailSchema.safeParse('a@b.co').success).toBe(true);
    expect(emailSchema.safeParse('user@example.com').success).toBe(true);
    expect(emailSchema.safeParse('firstname.lastname@example.com').success).toBe(true);
    expect(emailSchema.safeParse('user+tag@example.co.uk').success).toBe(true);
  });

  it('accepts punycode-encoded internationalized domain names (IDN)', () => {
    // Punycode-encoded IDN domains are common in practice; the refinement
    // allows any non-whitespace, non-`@`, non-`.` chars around the dots, which
    // covers xn-- punycode labels. (Raw unicode in the domain is rejected by
    // z.email() upstream — it expects the host to be punycoded already.)
    expect(emailSchema.safeParse('user@xn--80ak6aa92e.com').success).toBe(true);
  });
});

describe('registerSchema', () => {
  const validRegister = {
    email: 'test@example.com',
    authHash: 'somehash',
    encryptedVaultKey: 'encryptedkey',
    vaultKeyIv: 'iv-value',
    vaultKeyTag: 'tag-value',
    kdfIterations: 600_000,
    kdfAlgorithm: 'PBKDF2-SHA256' as const,
  };

  it('accepts valid registration data', () => {
    expect(registerSchema.safeParse(validRegister).success).toBe(true);
  });

  it('defaults encryptionVersion to 1', () => {
    const result = registerSchema.parse(validRegister);
    expect(result.encryptionVersion).toBe(1);
  });

  it('rejects kdfIterations below 500,000', () => {
    expect(registerSchema.safeParse({ ...validRegister, kdfIterations: 499_999 }).success).toBe(
      false,
    );
    expect(registerSchema.safeParse({ ...validRegister, kdfIterations: 100_000 }).success).toBe(
      false,
    );
  });

  it('accepts kdfIterations at lower bound 500,000', () => {
    expect(registerSchema.safeParse({ ...validRegister, kdfIterations: 500_000 }).success).toBe(
      true,
    );
  });

  it('accepts kdfIterations at standard 600,000', () => {
    expect(registerSchema.safeParse({ ...validRegister, kdfIterations: 600_000 }).success).toBe(
      true,
    );
  });

  it('rejects kdfIterations above 10,000,000', () => {
    expect(registerSchema.safeParse({ ...validRegister, kdfIterations: 10_000_001 }).success).toBe(
      false,
    );
  });

  it('accepts kdfIterations at upper bound 10,000,000', () => {
    expect(registerSchema.safeParse({ ...validRegister, kdfIterations: 10_000_000 }).success).toBe(
      true,
    );
  });

  it('rejects wrong kdfAlgorithm', () => {
    expect(registerSchema.safeParse({ ...validRegister, kdfAlgorithm: 'AES-256' }).success).toBe(
      false,
    );
  });
});

describe('loginSchema', () => {
  it('accepts valid login', () => {
    const result = loginSchema.safeParse({
      email: 'test@example.com',
      authHash: 'hash',
    });
    expect(result.success).toBe(true);
  });

  it('accepts login with deviceInfo', () => {
    const result = loginSchema.safeParse({
      email: 'test@example.com',
      authHash: 'hash',
      deviceInfo: { userAgent: 'Chrome', fingerprint: 'abc' },
    });
    expect(result.success).toBe(true);
  });
});

describe('login2faSchema', () => {
  it('accepts valid 2FA login', () => {
    const result = login2faSchema.safeParse({
      tempToken: 'some-token',
      code: '123456',
    });
    expect(result.success).toBe(true);
  });

  it('rejects code shorter than 6 chars', () => {
    expect(login2faSchema.safeParse({ tempToken: 'token', code: '12345' }).success).toBe(false);
  });

  it('rejects code longer than 16 chars', () => {
    expect(login2faSchema.safeParse({ tempToken: 'token', code: '1'.repeat(17) }).success).toBe(
      false,
    );
  });

  it('rejects tempToken longer than 2000 chars', () => {
    expect(login2faSchema.safeParse({ tempToken: 'a'.repeat(2001), code: '123456' }).success).toBe(
      false,
    );
  });

  it('accepts alphanumeric backup code', () => {
    expect(login2faSchema.safeParse({ tempToken: 'token', code: 'ABCD1234EFGH5678' }).success).toBe(
      true,
    );
  });

  it('rejects code with null byte', () => {
    expect(login2faSchema.safeParse({ tempToken: 'token', code: '12345\x00' }).success).toBe(false);
  });

  it('rejects code with special characters', () => {
    expect(login2faSchema.safeParse({ tempToken: 'token', code: '<script>' }).success).toBe(false);
  });

  it('rejects code with spaces', () => {
    expect(login2faSchema.safeParse({ tempToken: 'token', code: '123 456' }).success).toBe(false);
  });
});

describe('forgotPasswordSchema', () => {
  it('accepts valid email', () => {
    expect(forgotPasswordSchema.safeParse({ email: 'a@b.com' }).success).toBe(true);
  });
});

describe('resetPasswordSchema', () => {
  it('accepts valid reset data', () => {
    const result = resetPasswordSchema.safeParse({
      token: 'reset-token',
      email: 'user@example.com',
      newAuthHash: 'hash',
      newEncryptedVaultKey: 'key',
      newVaultKeyIv: 'iv',
      newVaultKeyTag: 'tag',
    });
    expect(result.success).toBe(true);
  });

  it('rejects missing email', () => {
    expect(
      resetPasswordSchema.safeParse({
        token: 'reset-token',
        newAuthHash: 'hash',
        newEncryptedVaultKey: 'key',
        newVaultKeyIv: 'iv',
        newVaultKeyTag: 'tag',
      }).success,
    ).toBe(false);
  });

  it('rejects invalid email', () => {
    expect(
      resetPasswordSchema.safeParse({
        token: 'reset-token',
        email: 'not-an-email',
        newAuthHash: 'hash',
        newEncryptedVaultKey: 'key',
        newVaultKeyIv: 'iv',
        newVaultKeyTag: 'tag',
      }).success,
    ).toBe(false);
  });

  it('rejects token longer than 2000 chars', () => {
    expect(
      resetPasswordSchema.safeParse({
        token: 'a'.repeat(2001),
        email: 'user@example.com',
        newAuthHash: 'hash',
        newEncryptedVaultKey: 'key',
        newVaultKeyIv: 'iv',
        newVaultKeyTag: 'tag',
      }).success,
    ).toBe(false);
  });
});

describe('verifyEmailSchema', () => {
  it('accepts valid token', () => {
    expect(verifyEmailSchema.safeParse({ token: 'verify-token' }).success).toBe(true);
  });

  it('rejects empty token', () => {
    expect(verifyEmailSchema.safeParse({ token: '' }).success).toBe(false);
  });

  it('rejects token longer than 2000 chars', () => {
    expect(verifyEmailSchema.safeParse({ token: 'a'.repeat(2001) }).success).toBe(false);
  });
});

describe('changePasswordSchema', () => {
  it('accepts valid change password data', () => {
    const result = changePasswordSchema.safeParse({
      currentAuthHash: 'old',
      newAuthHash: 'new',
      newEncryptedVaultKey: 'key',
      newVaultKeyIv: 'iv',
      newVaultKeyTag: 'tag',
    });
    expect(result.success).toBe(true);
  });
});

describe('unlockAccountSchema', () => {
  it('accepts valid token', () => {
    expect(unlockAccountSchema.safeParse({ token: 'unlock-token' }).success).toBe(true);
  });

  it('rejects token longer than 2000 chars', () => {
    expect(unlockAccountSchema.safeParse({ token: 'a'.repeat(2001) }).success).toBe(false);
  });
});

describe('resendVerificationSchema', () => {
  it('accepts a valid email', () => {
    expect(resendVerificationSchema.safeParse({ email: 'user@example.com' }).success).toBe(true);
  });

  it('lowercases the email', () => {
    const result = resendVerificationSchema.parse({ email: 'USER@Example.COM' });
    expect(result.email).toBe('user@example.com');
  });

  it('rejects an invalid email', () => {
    expect(resendVerificationSchema.safeParse({ email: 'not-an-email' }).success).toBe(false);
  });

  it('rejects an empty email', () => {
    expect(resendVerificationSchema.safeParse({ email: '' }).success).toBe(false);
  });

  it('rejects email over 254 characters', () => {
    const longEmail = 'a'.repeat(243) + '@example.com'; // 255 chars
    expect(resendVerificationSchema.safeParse({ email: longEmail }).success).toBe(false);
  });

  it('rejects missing email field', () => {
    expect(resendVerificationSchema.safeParse({}).success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Vault schemas
// ---------------------------------------------------------------------------
describe('createVaultItemSchema', () => {
  const validItem = {
    itemType: 'login' as const,
    encryptedData: 'data',
    dataIv: 'iv',
    dataTag: 'tag',
    encryptedName: 'name',
    nameIv: 'niv',
    nameTag: 'ntag',
  };

  it('accepts valid vault item', () => {
    expect(createVaultItemSchema.safeParse(validItem).success).toBe(true);
  });

  it('defaults tags to empty array', () => {
    const result = createVaultItemSchema.parse(validItem);
    expect(result.tags).toEqual([]);
  });

  it('defaults favorite to false', () => {
    const result = createVaultItemSchema.parse(validItem);
    expect(result.favorite).toBe(false);
  });

  it('rejects invalid item type', () => {
    expect(createVaultItemSchema.safeParse({ ...validItem, itemType: 'unknown' }).success).toBe(
      false,
    );
  });

  it('accepts optional folderId', () => {
    const result = createVaultItemSchema.safeParse({
      ...validItem,
      folderId: VALID_OBJECT_ID,
    });
    expect(result.success).toBe(true);
  });

  it('rejects tags exceeding maximum', () => {
    const result = createVaultItemSchema.safeParse({
      ...validItem,
      tags: Array.from({ length: 21 }, (_, i) => `tag${String(i)}`),
    });
    expect(result.success).toBe(false);
  });

  it('accepts valid searchHash', () => {
    const result = createVaultItemSchema.safeParse({
      ...validItem,
      searchHash: 'a'.repeat(64),
    });
    expect(result.success).toBe(true);
  });

  it('rejects invalid searchHash format', () => {
    const result = createVaultItemSchema.safeParse({
      ...validItem,
      searchHash: 'not-a-hash',
    });
    expect(result.success).toBe(false);
  });
});

describe('updateVaultItemSchema', () => {
  it('accepts partial update (favorite only)', () => {
    const result = updateVaultItemSchema.safeParse({ favorite: true });
    expect(result.success).toBe(true);
  });

  it('rejects mismatched encrypted data fields', () => {
    const result = updateVaultItemSchema.safeParse({
      encryptedData: 'data',
      // missing dataIv and dataTag
    });
    expect(result.success).toBe(false);
  });

  it('accepts all encrypted data fields together', () => {
    const result = updateVaultItemSchema.safeParse({
      encryptedData: 'data',
      dataIv: 'iv',
      dataTag: 'tag',
    });
    expect(result.success).toBe(true);
  });

  it('rejects mismatched encrypted name fields', () => {
    const result = updateVaultItemSchema.safeParse({
      encryptedName: 'name',
      // missing nameIv and nameTag
    });
    expect(result.success).toBe(false);
  });

  it('accepts valid password history with ISO datetime changedAt', () => {
    const result = updateVaultItemSchema.safeParse({
      passwordHistory: [
        {
          encryptedPassword: 'encrypted',
          iv: 'iv-value',
          tag: 'tag-value',
          changedAt: '2025-01-15T10:30:00Z',
        },
      ],
    });
    expect(result.success).toBe(true);
  });

  it('rejects password history with invalid changedAt format', () => {
    const result = updateVaultItemSchema.safeParse({
      passwordHistory: [
        {
          encryptedPassword: 'encrypted',
          iv: 'iv-value',
          tag: 'tag-value',
          changedAt: 'not-a-date',
        },
      ],
    });
    expect(result.success).toBe(false);
  });

  it('rejects password history with non-string changedAt', () => {
    const result = updateVaultItemSchema.safeParse({
      passwordHistory: [
        {
          encryptedPassword: 'encrypted',
          iv: 'iv-value',
          tag: 'tag-value',
          changedAt: 12345,
        },
      ],
    });
    expect(result.success).toBe(false);
  });

  it('rejects password history exceeding max entries', () => {
    const entries = Array.from({ length: 11 }, () => ({
      encryptedPassword: 'encrypted',
      iv: 'iv-value',
      tag: 'tag-value',
      changedAt: '2025-01-15T10:30:00Z',
    }));
    const result = updateVaultItemSchema.safeParse({
      passwordHistory: entries,
    });
    expect(result.success).toBe(false);
  });

  it('accepts password history with timezone offset changedAt (consistent with expiresAt)', () => {
    const offsets = [
      '2025-01-15T10:30:00+05:00',
      '2025-01-15T10:30:00-04:00',
      '2025-01-15T10:30:00+00:00',
    ];
    for (const changedAt of offsets) {
      const result = updateVaultItemSchema.safeParse({
        passwordHistory: [
          {
            encryptedPassword: 'encrypted',
            iv: 'iv-value',
            tag: 'tag-value',
            changedAt,
          },
        ],
      });
      expect(result.success).toBe(true);
    }
  });

  it('accepts password history with milliseconds in changedAt', () => {
    const result = updateVaultItemSchema.safeParse({
      passwordHistory: [
        {
          encryptedPassword: 'encrypted',
          iv: 'iv-value',
          tag: 'tag-value',
          changedAt: '2025-01-15T10:30:00.123Z',
        },
      ],
    });
    expect(result.success).toBe(true);
  });

  it('rejects password history with empty string changedAt', () => {
    const result = updateVaultItemSchema.safeParse({
      passwordHistory: [
        {
          encryptedPassword: 'encrypted',
          iv: 'iv-value',
          tag: 'tag-value',
          changedAt: '',
        },
      ],
    });
    expect(result.success).toBe(false);
  });

  it('accepts password history with exactly max entries', () => {
    const entries = Array.from({ length: 10 }, (_, i) => ({
      encryptedPassword: `encrypted-${i}`,
      iv: 'iv-value',
      tag: 'tag-value',
      changedAt: `2025-01-${String(i + 1).padStart(2, '0')}T10:30:00Z`,
    }));
    const result = updateVaultItemSchema.safeParse({
      passwordHistory: entries,
    });
    expect(result.success).toBe(true);
  });

  it('accepts empty password history array', () => {
    const result = updateVaultItemSchema.safeParse({
      passwordHistory: [],
    });
    expect(result.success).toBe(true);
  });
});

describe('listVaultItemsSchema', () => {
  it('defaults sortBy to updatedAt', () => {
    const result = listVaultItemsSchema.parse({});
    expect(result.sortBy).toBe('updatedAt');
  });

  it('defaults sortOrder to desc', () => {
    const result = listVaultItemsSchema.parse({});
    expect(result.sortOrder).toBe('desc');
  });

  it('accepts favorite as sortBy', () => {
    const result = listVaultItemsSchema.safeParse({ sortBy: 'favorite' });
    expect(result.success).toBe(true);
  });

  it('accepts all valid item types as filter', () => {
    for (const type of ['login', 'secret', 'note', 'card', 'identity']) {
      expect(listVaultItemsSchema.safeParse({ itemType: type }).success).toBe(true);
    }
  });

  // ── Boolean query filter coercion (favorite / trash) ────────────────
  // Regression guard: z.coerce.boolean() treated any non-empty string as true,
  // so ?favorite=false / ?trash=false inverted the filter. z.stringbool()
  // parses canonical string booleans correctly.
  it('parses trash="false" as false (not inverted)', () => {
    expect(listVaultItemsSchema.parse({ trash: 'false' }).trash).toBe(false);
  });

  it('parses trash="true" as true', () => {
    expect(listVaultItemsSchema.parse({ trash: 'true' }).trash).toBe(true);
  });

  it('parses trash="0" as false and trash="1" as true', () => {
    expect(listVaultItemsSchema.parse({ trash: '0' }).trash).toBe(false);
    expect(listVaultItemsSchema.parse({ trash: '1' }).trash).toBe(true);
  });

  it('parses favorite="false" as false (not inverted)', () => {
    expect(listVaultItemsSchema.parse({ favorite: 'false' }).favorite).toBe(false);
  });

  it('parses favorite="true" as true', () => {
    expect(listVaultItemsSchema.parse({ favorite: 'true' }).favorite).toBe(true);
  });

  it('parses favorite="0" as false and favorite="1" as true', () => {
    expect(listVaultItemsSchema.parse({ favorite: '0' }).favorite).toBe(false);
    expect(listVaultItemsSchema.parse({ favorite: '1' }).favorite).toBe(true);
  });

  it('yields undefined for favorite/trash when the param is absent', () => {
    const result = listVaultItemsSchema.parse({});
    expect(result.favorite).toBeUndefined();
    expect(result.trash).toBeUndefined();
  });

  it('rejects a non-canonical boolean value (stricter than coerce)', () => {
    expect(listVaultItemsSchema.safeParse({ trash: 'maybe' }).success).toBe(false);
    expect(listVaultItemsSchema.safeParse({ favorite: 'yes-please' }).success).toBe(false);
  });
});

describe('bulkDeleteSchema', () => {
  it('accepts an array of valid IDs', () => {
    const result = bulkDeleteSchema.safeParse({
      ids: [VALID_OBJECT_ID],
    });
    expect(result.success).toBe(true);
  });

  it('rejects empty array', () => {
    expect(bulkDeleteSchema.safeParse({ ids: [] }).success).toBe(false);
  });

  it('rejects more than 100 IDs', () => {
    const ids = Array.from({ length: 101 }, () => VALID_OBJECT_ID);
    expect(bulkDeleteSchema.safeParse({ ids }).success).toBe(false);
  });
});

describe('bulkMoveSchema', () => {
  it('accepts valid move with folderId', () => {
    const result = bulkMoveSchema.safeParse({
      ids: [VALID_OBJECT_ID],
      folderId: VALID_OBJECT_ID,
    });
    expect(result.success).toBe(true);
  });

  it('accepts null folderId (move to root)', () => {
    const result = bulkMoveSchema.safeParse({
      ids: [VALID_OBJECT_ID],
      folderId: null,
    });
    expect(result.success).toBe(true);
  });
});

describe('listTrashSchema', () => {
  it('defaults sortBy to deletedAt', () => {
    const result = listTrashSchema.parse({});
    expect(result.sortBy).toBe('deletedAt');
  });

  it('defaults sortOrder to desc', () => {
    const result = listTrashSchema.parse({});
    expect(result.sortOrder).toBe('desc');
  });

  it('accepts valid trash sort options', () => {
    for (const sortBy of ['deletedAt', 'createdAt', 'updatedAt', 'itemType']) {
      expect(listTrashSchema.safeParse({ sortBy }).success).toBe(true);
    }
  });

  it('rejects invalid sortBy', () => {
    expect(listTrashSchema.safeParse({ sortBy: 'name' }).success).toBe(false);
  });
});

describe('bulkReEncryptSchema', () => {
  const validReEncrypt = {
    authHash: 'current-auth-hash',
    items: [
      {
        id: VALID_OBJECT_ID,
        encryptedName: 'enc-name',
        nameIv: 'niv',
        nameTag: 'ntag',
        encryptedData: 'enc-data',
        dataIv: 'div',
        dataTag: 'dtag',
      },
    ],
    newEncryptedVaultKey: 'new-key',
    newVaultKeyIv: 'new-iv',
    newVaultKeyTag: 'new-tag',
  };

  it('accepts valid re-encrypt payload', () => {
    expect(bulkReEncryptSchema.safeParse(validReEncrypt).success).toBe(true);
  });

  it('accepts empty items array', () => {
    expect(bulkReEncryptSchema.safeParse({ ...validReEncrypt, items: [] }).success).toBe(true);
  });

  it('rejects items over 10,000', () => {
    const bigItems = Array.from({ length: 10_001 }, () => validReEncrypt.items[0]!);
    expect(bulkReEncryptSchema.safeParse({ ...validReEncrypt, items: bigItems }).success).toBe(
      false,
    );
  });

  it('rejects empty authHash', () => {
    expect(bulkReEncryptSchema.safeParse({ ...validReEncrypt, authHash: '' }).success).toBe(false);
  });

  it('accepts optional searchHash in items', () => {
    const withHash = {
      ...validReEncrypt,
      items: [{ ...validReEncrypt.items[0]!, searchHash: 'a'.repeat(64) }],
    };
    expect(bulkReEncryptSchema.safeParse(withHash).success).toBe(true);
  });

  it('rejects invalid searchHash format', () => {
    const withBadHash = {
      ...validReEncrypt,
      items: [{ ...validReEncrypt.items[0]!, searchHash: 'not-a-hash' }],
    };
    expect(bulkReEncryptSchema.safeParse(withBadHash).success).toBe(false);
  });

  it('accepts folders array in bulkReEncrypt', () => {
    const withFolders = {
      ...validReEncrypt,
      folders: [
        { id: '507f1f77bcf86cd799439011', encryptedName: 'enc', nameIv: 'iv1', nameTag: 'tag1' },
      ],
    };
    expect(bulkReEncryptSchema.safeParse(withFolders).success).toBe(true);
  });

  it('defaults folders to empty array when not provided', () => {
    const result = bulkReEncryptSchema.parse(validReEncrypt);
    expect(result.folders).toEqual([]);
  });

  it('rejects folders exceeding max count (1000)', () => {
    const bigFolders = Array.from({ length: 1001 }, (_, i) => ({
      id: `507f1f77bcf86cd79943${String(i).padStart(4, '0')}`,
      encryptedName: 'enc',
      nameIv: 'iv1',
      nameTag: 'tag1',
    }));
    expect(bulkReEncryptSchema.safeParse({ ...validReEncrypt, folders: bigFolders }).success).toBe(
      false,
    );
  });

  it('accepts optional idempotencyKey as valid UUID', () => {
    const withKey = { ...validReEncrypt, idempotencyKey: '550e8400-e29b-41d4-a716-446655440000' };
    expect(bulkReEncryptSchema.safeParse(withKey).success).toBe(true);
  });

  it('accepts payload without idempotencyKey', () => {
    expect(bulkReEncryptSchema.safeParse(validReEncrypt).success).toBe(true);
  });

  it('rejects non-UUID idempotencyKey', () => {
    const withBadKey = { ...validReEncrypt, idempotencyKey: 'not-a-uuid' };
    expect(bulkReEncryptSchema.safeParse(withBadKey).success).toBe(false);
  });

  it('accepts items with passwordHistory', () => {
    const withHistory = {
      ...validReEncrypt,
      items: [
        {
          ...validReEncrypt.items[0]!,
          passwordHistory: [
            {
              encryptedPassword: 'enc-pw',
              iv: 'pw-iv',
              tag: 'pw-tag',
              changedAt: '2024-01-15T10:30:00Z',
            },
          ],
        },
      ],
    };
    expect(bulkReEncryptSchema.safeParse(withHistory).success).toBe(true);
  });

  it('accepts items without passwordHistory (backward compatible)', () => {
    // The base validReEncrypt has no passwordHistory — should still pass
    expect(bulkReEncryptSchema.safeParse(validReEncrypt).success).toBe(true);
    const result = bulkReEncryptSchema.parse(validReEncrypt);
    expect(result.items[0]!.passwordHistory).toBeUndefined();
  });

  it('rejects passwordHistory entries with invalid changedAt format', () => {
    const withBadDate = {
      ...validReEncrypt,
      items: [
        {
          ...validReEncrypt.items[0]!,
          passwordHistory: [
            { encryptedPassword: 'enc-pw', iv: 'pw-iv', tag: 'pw-tag', changedAt: 'not-a-date' },
          ],
        },
      ],
    };
    expect(bulkReEncryptSchema.safeParse(withBadDate).success).toBe(false);
  });

  it('rejects passwordHistory exceeding max entries', () => {
    const tooManyEntries = Array.from({ length: 11 }, () => ({
      encryptedPassword: 'enc',
      iv: 'iv1',
      tag: 'tag',
      changedAt: '2024-01-15T10:30:00Z',
    }));
    const withTooMany = {
      ...validReEncrypt,
      items: [{ ...validReEncrypt.items[0]!, passwordHistory: tooManyEntries }],
    };
    expect(bulkReEncryptSchema.safeParse(withTooMany).success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Decrypted vault item data schemas
// ---------------------------------------------------------------------------
describe('loginDataSchema', () => {
  it('accepts empty object with defaults', () => {
    const result = loginDataSchema.parse({});
    expect(result.username).toBe('');
    expect(result.password).toBe('');
    expect(result.uris).toEqual([]);
    expect(result.customFields).toEqual([]);
  });

  it('accepts full login data', () => {
    const result = loginDataSchema.safeParse({
      username: 'user',
      password: 'pass',
      uris: [{ uri: 'https://example.com', match: 'domain' }],
      totp: 'secret',
      notes: 'some notes',
      customFields: [{ name: 'field1', value: 'val1', type: 'text' }],
    });
    expect(result.success).toBe(true);
  });

  it('strips unknown fields (strip mode)', () => {
    const result = loginDataSchema.safeParse({
      username: 'user',
      extraField: 'value',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data).not.toHaveProperty('extraField');
    }
  });

  it('accepts URIs with http, https, and mailto protocols', () => {
    const validUris = ['https://example.com', 'http://localhost:3000', 'mailto:user@example.com'];
    for (const uri of validUris) {
      const result = loginDataSchema.safeParse({
        uris: [{ uri, match: 'domain' }],
      });
      expect(result.success).toBe(true);
    }
  });

  it('accepts empty URI string', () => {
    const result = loginDataSchema.safeParse({
      uris: [{ uri: '', match: 'domain' }],
    });
    expect(result.success).toBe(true);
  });

  it('rejects URIs with dangerous protocols', () => {
    const invalid = [
      'javascript:alert(1)',
      'data:text/html,<h1>x</h1>',
      'ftp://example.com',
      'file:///etc/passwd',
    ];
    for (const uri of invalid) {
      const result = loginDataSchema.safeParse({
        uris: [{ uri, match: 'domain' }],
      });
      expect(result.success).toBe(false);
    }
  });

  it('rejects URIs exceeding 2048 characters', () => {
    const longUri = 'https://example.com/' + 'a'.repeat(2030);
    const result = loginDataSchema.safeParse({
      uris: [{ uri: longUri, match: 'domain' }],
    });
    expect(result.success).toBe(false);
  });

  it('accepts valid regex pattern when match is regex', () => {
    const result = loginDataSchema.safeParse({
      uris: [{ uri: 'https?://example\\.com/.*', match: 'regex' }],
    });
    expect(result.success).toBe(true);
  });

  it('rejects invalid regex pattern when match is regex', () => {
    const result = loginDataSchema.safeParse({
      uris: [{ uri: 'https://example.com/[invalid', match: 'regex' }],
    });
    expect(result.success).toBe(false);
  });

  it('allows non-http URI when match is regex (protocol check skipped for regex)', () => {
    // Regex patterns don't need to follow http/https/mailto protocol rules
    const result = loginDataSchema.safeParse({
      uris: [{ uri: '.*example\\.com.*', match: 'regex' }],
    });
    expect(result.success).toBe(true);
  });

  it('does not apply regex validation for non-regex match types', () => {
    // An invalid regex string is fine for non-regex match types because
    // it will not be compiled as a regex
    const result = loginDataSchema.safeParse({
      uris: [{ uri: 'https://example.com/[invalid', match: 'domain' }],
    });
    expect(result.success).toBe(true);
  });

  it('accepts bare domains and normalizes them to https://', () => {
    const result = loginDataSchema.safeParse({
      uris: [{ uri: 'example.com', match: 'domain' }],
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.uris[0]?.uri).toBe('https://example.com');
    }
  });

  it('normalizes bare domains with paths', () => {
    const result = loginDataSchema.safeParse({
      uris: [{ uri: 'example.com/login', match: 'exact' }],
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.uris[0]?.uri).toBe('https://example.com/login');
    }
  });

  it('does not normalize regex match type URIs', () => {
    const result = loginDataSchema.safeParse({
      uris: [{ uri: 'example\\.com', match: 'regex' }],
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.uris[0]?.uri).toBe('example\\.com');
    }
  });

  it('still rejects javascript: URIs after normalization', () => {
    const result = loginDataSchema.safeParse({
      uris: [{ uri: 'javascript:alert(1)', match: 'domain' }],
    });
    expect(result.success).toBe(false);
  });
});

describe('secretDataSchema', () => {
  it('accepts empty object with defaults', () => {
    const result = secretDataSchema.parse({});
    expect(result.value).toBe('');
    expect(result.customFields).toEqual([]);
  });

  it('accepts full secret data', () => {
    const result = secretDataSchema.safeParse({
      value: 'my-secret',
      description: 'desc',
      expiresAt: '2025-12-31',
      customFields: [],
    });
    expect(result.success).toBe(true);
  });

  it('accepts expiresAt as date-only string', () => {
    expect(secretDataSchema.safeParse({ expiresAt: '2025-12-31' }).success).toBe(true);
  });

  it('accepts expiresAt as datetime-local without timezone', () => {
    expect(secretDataSchema.safeParse({ expiresAt: '2025-06-15T14:30' }).success).toBe(true);
  });

  it('accepts expiresAt as full ISO 8601 with Z', () => {
    expect(secretDataSchema.safeParse({ expiresAt: '2026-12-31T23:59:00.000Z' }).success).toBe(
      true,
    );
  });

  it('accepts expiresAt as ISO 8601 with timezone offset', () => {
    expect(secretDataSchema.safeParse({ expiresAt: '2025-12-31T23:59:00+05:30' }).success).toBe(
      true,
    );
  });

  it('accepts expiresAt as ISO 8601 with seconds', () => {
    expect(secretDataSchema.safeParse({ expiresAt: '2025-12-31T23:59:00' }).success).toBe(true);
  });

  it('rejects expiresAt with invalid format', () => {
    expect(secretDataSchema.safeParse({ expiresAt: 'not-a-date' }).success).toBe(false);
  });

  it('rejects expiresAt with random text', () => {
    expect(secretDataSchema.safeParse({ expiresAt: 'tomorrow' }).success).toBe(false);
  });

  it('rejects expiresAt with unix timestamp string', () => {
    expect(secretDataSchema.safeParse({ expiresAt: '1735689600' }).success).toBe(false);
  });

  it('accepts expiresAt as undefined (optional)', () => {
    expect(secretDataSchema.safeParse({ value: 'secret' }).success).toBe(true);
  });

  it('rejects expiresAt with invalid month (13)', () => {
    expect(secretDataSchema.safeParse({ expiresAt: '2025-13-01' }).success).toBe(false);
  });

  it('rejects expiresAt with month 0', () => {
    expect(secretDataSchema.safeParse({ expiresAt: '2025-00-15' }).success).toBe(false);
  });

  it('rejects expiresAt with Feb 30', () => {
    expect(secretDataSchema.safeParse({ expiresAt: '2025-02-30' }).success).toBe(false);
  });

  it('rejects expiresAt with Feb 29 in non-leap year', () => {
    expect(secretDataSchema.safeParse({ expiresAt: '2025-02-29' }).success).toBe(false);
  });

  it('accepts expiresAt with Feb 29 in leap year', () => {
    expect(secretDataSchema.safeParse({ expiresAt: '2024-02-29' }).success).toBe(true);
  });

  it('rejects expiresAt with day 0', () => {
    expect(secretDataSchema.safeParse({ expiresAt: '2025-06-00' }).success).toBe(false);
  });

  it('accepts valid calendar date', () => {
    expect(secretDataSchema.safeParse({ expiresAt: '2025-06-15' }).success).toBe(true);
  });

  it('accepts valid datetime with calendar date validation', () => {
    expect(secretDataSchema.safeParse({ expiresAt: '2025-06-15T14:30:00Z' }).success).toBe(true);
  });

  // Time components: the ISO regex only constrains the SHAPE of the time part and
  // the calendar refine only looks at the date half, so impossible clock values
  // used to slip through.
  it('rejects expiresAt with impossible time components (T99:99:99)', () => {
    expect(secretDataSchema.safeParse({ expiresAt: '2026-06-15T99:99:99Z' }).success).toBe(false);
  });

  it('rejects expiresAt with an out-of-range hour', () => {
    expect(secretDataSchema.safeParse({ expiresAt: '2026-06-15T25:00:00Z' }).success).toBe(false);
  });

  it('rejects expiresAt with an out-of-range minute', () => {
    expect(secretDataSchema.safeParse({ expiresAt: '2026-06-15T12:60' }).success).toBe(false);
  });

  it('rejects expiresAt with an out-of-range second', () => {
    expect(secretDataSchema.safeParse({ expiresAt: '2026-06-15T12:30:61Z' }).success).toBe(false);
  });

  it('rejects expiresAt with an out-of-range timezone offset', () => {
    expect(secretDataSchema.safeParse({ expiresAt: '2026-06-15T12:30:00+99:00' }).success).toBe(
      false,
    );
  });

  it('still accepts boundary-valid time components', () => {
    for (const value of [
      '2026-06-15T00:00:00Z',
      '2026-06-15T23:59:59.999Z',
      '2026-06-15T23:59',
      '2026-06-15T23:59:59+05:30',
    ]) {
      expect(secretDataSchema.safeParse({ expiresAt: value }).success).toBe(true);
    }
  });

  it('leaves date-only values unaffected by the time-component check', () => {
    expect(secretDataSchema.safeParse({ expiresAt: '2026-06-15' }).success).toBe(true);
    expect(secretDataSchema.safeParse({ expiresAt: '2026-02-30' }).success).toBe(false);
  });
});

describe('noteDataSchema', () => {
  it('defaults format to markdown', () => {
    const result = noteDataSchema.parse({});
    expect(result.format).toBe('markdown');
  });

  it('accepts plaintext format', () => {
    const result = noteDataSchema.safeParse({
      content: 'hello',
      format: 'plaintext',
    });
    expect(result.success).toBe(true);
  });

  it('rejects invalid format', () => {
    expect(noteDataSchema.safeParse({ format: 'html' }).success).toBe(false);
  });
});

describe('cardDataSchema', () => {
  it('accepts empty object with defaults', () => {
    const result = cardDataSchema.parse({});
    expect(result.cardholderName).toBe('');
    expect(result.number).toBe('');
  });

  it('accepts full card data', () => {
    const result = cardDataSchema.safeParse({
      cardholderName: 'John Doe',
      number: '4111111111111111',
      expMonth: '12',
      expYear: '2025',
      cvv: '123',
      brand: 'Visa',
    });
    expect(result.success).toBe(true);
  });

  it('accepts card data with billing address', () => {
    const result = cardDataSchema.safeParse({
      cardholderName: 'John Doe',
      number: '4111111111111111',
      expMonth: '12',
      expYear: '2025',
      cvv: '123',
      brand: 'Visa',
      billingAddress: {
        street: '123 Main St',
        city: 'Springfield',
        state: 'IL',
        zip: '62701',
        country: 'US',
      },
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.billingAddress?.street).toBe('123 Main St');
      expect(result.data.billingAddress?.city).toBe('Springfield');
    }
  });

  it('accepts card data without billing address', () => {
    const result = cardDataSchema.safeParse({
      cardholderName: 'Jane Doe',
      number: '5500000000000004',
      expMonth: '06',
      expYear: '2028',
      cvv: '321',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.billingAddress).toBeUndefined();
    }
  });

  it('accepts billing address with partial fields', () => {
    const result = cardDataSchema.safeParse({
      cardholderName: 'Test',
      number: '1234',
      billingAddress: {
        city: 'New York',
        country: 'US',
      },
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.billingAddress?.city).toBe('New York');
      expect(result.data.billingAddress?.street).toBe('');
    }
  });
});

describe('identityDataSchema', () => {
  it('accepts empty object with defaults', () => {
    const result = identityDataSchema.parse({});
    expect(result.firstName).toBe('');
    expect(result.lastName).toBe('');
  });

  it('accepts full identity with address', () => {
    const result = identityDataSchema.safeParse({
      firstName: 'John',
      lastName: 'Doe',
      email: 'john@example.com',
      phone: '555-0100',
      address: {
        street: '123 Main St',
        city: 'Springfield',
        state: 'IL',
        zip: '62701',
        country: 'US',
      },
      company: 'ACME',
    });
    expect(result.success).toBe(true);
  });

  it('accepts empty email and phone (optional fields)', () => {
    const result = identityDataSchema.safeParse({ firstName: 'A', lastName: 'B' });
    expect(result.success).toBe(true);
  });

  it('accepts valid email formats', () => {
    const emails = ['user@example.com', 'a@b.co', 'user+tag@domain.org'];
    for (const email of emails) {
      const result = identityDataSchema.safeParse({ email });
      expect(result.success).toBe(true);
    }
  });

  it('rejects invalid email formats', () => {
    const invalid = ['not-an-email', 'missing@tld', '@no-local.com', 'spaces in@email.com'];
    for (const email of invalid) {
      const result = identityDataSchema.safeParse({ email });
      expect(result.success).toBe(false);
    }
  });

  it('accepts empty string email (optional field)', () => {
    expect(identityDataSchema.safeParse({ email: '' }).success).toBe(true);
  });

  it('rejects email with dot-only domain (user@.com)', () => {
    expect(identityDataSchema.safeParse({ email: 'user@.com' }).success).toBe(false);
  });

  it('rejects email without TLD dot (user@com)', () => {
    expect(identityDataSchema.safeParse({ email: 'user@com' }).success).toBe(false);
  });

  it('rejects email exceeding 254 characters', () => {
    const longEmail = 'a'.repeat(246) + '@test.com';
    const result = identityDataSchema.safeParse({ email: longEmail });
    expect(result.success).toBe(false);
  });

  it('accepts valid phone formats', () => {
    const phones = [
      '+1 (555) 123-4567',
      '555-0100',
      '+44 20 7946 0958',
      '(800) 555-0199',
      '123.456.7890',
      '1',
      '+1',
      '(1)',
    ];
    for (const phone of phones) {
      const result = identityDataSchema.safeParse({ phone });
      expect(result.success).toBe(true);
    }
  });

  it('rejects invalid phone formats', () => {
    const invalid = ['abc!!!', 'phone: 555', 'call me'];
    for (const phone of invalid) {
      const result = identityDataSchema.safeParse({ phone });
      expect(result.success).toBe(false);
    }
  });

  it('rejects phone numbers with no digits (separator-only)', () => {
    const noDigits = ['+--++', '()()()', '...', '   ', '(.-)', '+'];
    for (const phone of noDigits) {
      const result = identityDataSchema.safeParse({ phone });
      expect(result.success).toBe(false);
    }
  });

  it('rejects phone with multiple leading plus signs', () => {
    const result = identityDataSchema.safeParse({ phone: '++1234567890' });
    expect(result.success).toBe(false);
  });

  it('rejects phone exceeding 30 characters', () => {
    const longPhone = '1'.repeat(31);
    const result = identityDataSchema.safeParse({ phone: longPhone });
    expect(result.success).toBe(false);
  });
});

describe('vaultItemDataSchemas', () => {
  it('has a schema for every item type', () => {
    expect(vaultItemDataSchemas.login).toBeDefined();
    expect(vaultItemDataSchemas.secret).toBeDefined();
    expect(vaultItemDataSchemas.note).toBeDefined();
    expect(vaultItemDataSchemas.card).toBeDefined();
    expect(vaultItemDataSchemas.identity).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// M11: Verify type exports are derived from Zod schemas (z.output)
// ---------------------------------------------------------------------------
describe('vault item data types derived from schemas', () => {
  it('loginDataSchema output matches ILoginData shape', () => {
    const parsed = loginDataSchema.parse({});
    expect(parsed).toHaveProperty('username');
    expect(parsed).toHaveProperty('password');
    expect(parsed).toHaveProperty('uris');
    expect(parsed).toHaveProperty('customFields');
    expect(typeof parsed.username).toBe('string');
    expect(Array.isArray(parsed.uris)).toBe(true);
    expect(Array.isArray(parsed.customFields)).toBe(true);
  });

  it('secretDataSchema output matches ISecretData shape', () => {
    const parsed = secretDataSchema.parse({});
    expect(parsed).toHaveProperty('value');
    expect(parsed).toHaveProperty('customFields');
    expect(typeof parsed.value).toBe('string');
  });

  it('noteDataSchema output matches INoteData shape', () => {
    const parsed = noteDataSchema.parse({});
    expect(parsed).toHaveProperty('content');
    expect(parsed).toHaveProperty('format');
    expect(parsed.format).toBe('markdown');
  });

  it('cardDataSchema output matches ICardData shape', () => {
    const parsed = cardDataSchema.parse({});
    expect(parsed).toHaveProperty('cardholderName');
    expect(parsed).toHaveProperty('number');
    expect(parsed).toHaveProperty('expMonth');
    expect(parsed).toHaveProperty('expYear');
    expect(parsed).toHaveProperty('cvv');
  });

  it('identityDataSchema output matches IIdentityData shape', () => {
    const parsed = identityDataSchema.parse({});
    expect(parsed).toHaveProperty('firstName');
    expect(parsed).toHaveProperty('lastName');
    expect(parsed).toHaveProperty('customFields');
    expect(Array.isArray(parsed.customFields)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Decrypted data schema max-length constraints
// ---------------------------------------------------------------------------
describe('decrypted data schema max-length constraints', () => {
  describe('customFieldSchema', () => {
    it('rejects empty custom field name (min 1)', () => {
      const result = loginDataSchema.safeParse({
        customFields: [{ name: '', value: 'val', type: 'text' }],
      });
      expect(result.success).toBe(false);
    });

    it('accepts non-empty custom field name', () => {
      const result = loginDataSchema.safeParse({
        customFields: [{ name: 'f', value: 'val', type: 'text' }],
      });
      expect(result.success).toBe(true);
    });

    it('rejects custom field name exceeding 500 chars', () => {
      const result = loginDataSchema.safeParse({
        customFields: [{ name: 'a'.repeat(501), value: 'val', type: 'text' }],
      });
      expect(result.success).toBe(false);
    });

    it('rejects custom field value exceeding 50000 chars', () => {
      const result = loginDataSchema.safeParse({
        customFields: [{ name: 'f', value: 'a'.repeat(50_001), type: 'text' }],
      });
      expect(result.success).toBe(false);
    });
  });

  describe('loginDataSchema max-length', () => {
    it('rejects username exceeding 500 chars', () => {
      expect(loginDataSchema.safeParse({ username: 'a'.repeat(501) }).success).toBe(false);
    });

    it('rejects password exceeding 10000 chars', () => {
      expect(loginDataSchema.safeParse({ password: 'a'.repeat(10_001) }).success).toBe(false);
    });

    it('rejects totp exceeding 500 chars', () => {
      expect(loginDataSchema.safeParse({ totp: 'a'.repeat(501) }).success).toBe(false);
    });

    it('rejects notes exceeding 50000 chars', () => {
      expect(loginDataSchema.safeParse({ notes: 'a'.repeat(50_001) }).success).toBe(false);
    });

    it('accepts values at the limit', () => {
      const result = loginDataSchema.safeParse({
        username: 'a'.repeat(500),
        password: 'a'.repeat(10_000),
        totp: 'a'.repeat(500),
        notes: 'a'.repeat(50_000),
      });
      expect(result.success).toBe(true);
    });
  });

  describe('secretDataSchema max-length', () => {
    it('rejects value exceeding 50000 chars', () => {
      expect(secretDataSchema.safeParse({ value: 'a'.repeat(50_001) }).success).toBe(false);
    });

    it('rejects description exceeding 10000 chars', () => {
      expect(secretDataSchema.safeParse({ description: 'a'.repeat(10_001) }).success).toBe(false);
    });

    it('rejects expiresAt exceeding 100 chars', () => {
      expect(secretDataSchema.safeParse({ expiresAt: 'a'.repeat(101) }).success).toBe(false);
    });

    it('accepts values at the limit', () => {
      const result = secretDataSchema.safeParse({
        value: 'a'.repeat(50_000),
        description: 'a'.repeat(10_000),
      });
      expect(result.success).toBe(true);
    });
  });

  describe('noteDataSchema max-length', () => {
    it('rejects content exceeding 50000 chars', () => {
      expect(noteDataSchema.safeParse({ content: 'a'.repeat(50_001) }).success).toBe(false);
    });

    it('accepts content at the limit', () => {
      expect(noteDataSchema.safeParse({ content: 'a'.repeat(50_000) }).success).toBe(true);
    });
  });

  describe('cardDataSchema max-length', () => {
    it('rejects cardholderName exceeding 300 chars', () => {
      expect(cardDataSchema.safeParse({ cardholderName: 'a'.repeat(301) }).success).toBe(false);
    });

    it('rejects number exceeding 30 chars', () => {
      expect(cardDataSchema.safeParse({ number: '1'.repeat(31) }).success).toBe(false);
    });

    it('rejects expMonth exceeding 2 chars', () => {
      expect(cardDataSchema.safeParse({ expMonth: '123' }).success).toBe(false);
    });

    it('rejects expYear exceeding 4 chars', () => {
      expect(cardDataSchema.safeParse({ expYear: '20251' }).success).toBe(false);
    });

    it('rejects cvv exceeding 4 chars', () => {
      expect(cardDataSchema.safeParse({ cvv: '12345' }).success).toBe(false);
    });

    it('rejects brand exceeding 50 chars', () => {
      expect(cardDataSchema.safeParse({ brand: 'a'.repeat(51) }).success).toBe(false);
    });

    it('rejects notes exceeding 50000 chars', () => {
      expect(cardDataSchema.safeParse({ notes: 'a'.repeat(50_001) }).success).toBe(false);
    });

    it('accepts values at the limit', () => {
      const result = cardDataSchema.safeParse({
        cardholderName: 'a'.repeat(300),
        number: '1'.repeat(30),
        expMonth: '12',
        expYear: '2025',
        cvv: '1234',
        brand: 'a'.repeat(50),
      });
      expect(result.success).toBe(true);
    });
  });

  describe('addressSchema max-length (via cardDataSchema billingAddress)', () => {
    it('rejects street exceeding 500 chars', () => {
      expect(
        cardDataSchema.safeParse({
          billingAddress: { street: 'a'.repeat(501) },
        }).success,
      ).toBe(false);
    });

    it('rejects city exceeding 200 chars', () => {
      expect(
        cardDataSchema.safeParse({
          billingAddress: { city: 'a'.repeat(201) },
        }).success,
      ).toBe(false);
    });

    it('rejects state exceeding 200 chars', () => {
      expect(
        cardDataSchema.safeParse({
          billingAddress: { state: 'a'.repeat(201) },
        }).success,
      ).toBe(false);
    });

    it('rejects zip exceeding 20 chars', () => {
      expect(
        cardDataSchema.safeParse({
          billingAddress: { zip: 'a'.repeat(21) },
        }).success,
      ).toBe(false);
    });

    it('rejects country exceeding 100 chars', () => {
      expect(
        cardDataSchema.safeParse({
          billingAddress: { country: 'a'.repeat(101) },
        }).success,
      ).toBe(false);
    });

    it('accepts address fields at the limit', () => {
      const result = cardDataSchema.safeParse({
        billingAddress: {
          street: 'a'.repeat(500),
          city: 'a'.repeat(200),
          state: 'a'.repeat(200),
          zip: 'a'.repeat(20),
          country: 'a'.repeat(100),
        },
      });
      expect(result.success).toBe(true);
    });
  });

  describe('identityDataSchema max-length', () => {
    it('rejects firstName exceeding 200 chars', () => {
      expect(identityDataSchema.safeParse({ firstName: 'a'.repeat(201) }).success).toBe(false);
    });

    it('rejects lastName exceeding 200 chars', () => {
      expect(identityDataSchema.safeParse({ lastName: 'a'.repeat(201) }).success).toBe(false);
    });

    it('rejects company exceeding 300 chars', () => {
      expect(identityDataSchema.safeParse({ company: 'a'.repeat(301) }).success).toBe(false);
    });

    it('rejects ssn exceeding 20 chars', () => {
      expect(identityDataSchema.safeParse({ ssn: 'a'.repeat(21) }).success).toBe(false);
    });

    it('rejects passport exceeding 50 chars', () => {
      expect(identityDataSchema.safeParse({ passport: 'a'.repeat(51) }).success).toBe(false);
    });

    it('rejects notes exceeding 50000 chars', () => {
      expect(identityDataSchema.safeParse({ notes: 'a'.repeat(50_001) }).success).toBe(false);
    });

    it('accepts values at the limit', () => {
      const result = identityDataSchema.safeParse({
        firstName: 'a'.repeat(200),
        lastName: 'a'.repeat(200),
        company: 'a'.repeat(300),
        ssn: 'a'.repeat(20),
        passport: 'a'.repeat(50),
        notes: 'a'.repeat(50_000),
      });
      expect(result.success).toBe(true);
    });
  });
});

// ---------------------------------------------------------------------------
// Folder schemas
// ---------------------------------------------------------------------------
describe('createFolderSchema', () => {
  it('accepts valid folder', () => {
    const result = createFolderSchema.safeParse({
      encryptedName: 'name',
      nameIv: 'iv',
      nameTag: 'tag',
    });
    expect(result.success).toBe(true);
  });

  it('defaults sortOrder to 0', () => {
    const result = createFolderSchema.parse({
      encryptedName: 'name',
      nameIv: 'iv',
      nameTag: 'tag',
    });
    expect(result.sortOrder).toBe(0);
  });

  it('accepts optional parentId', () => {
    const result = createFolderSchema.safeParse({
      encryptedName: 'name',
      nameIv: 'iv',
      nameTag: 'tag',
      parentId: VALID_OBJECT_ID,
    });
    expect(result.success).toBe(true);
  });

  it('accepts valid icon name', () => {
    const result = createFolderSchema.safeParse({
      encryptedName: 'name',
      nameIv: 'iv',
      nameTag: 'tag',
      icon: 'folder-lock',
    });
    expect(result.success).toBe(true);
  });

  it('rejects icon with invalid characters', () => {
    const result = createFolderSchema.safeParse({
      encryptedName: 'name',
      nameIv: 'iv',
      nameTag: 'tag',
      icon: 'folder icon!',
    });
    expect(result.success).toBe(false);
  });

  it('accepts valid hex color', () => {
    const result = createFolderSchema.safeParse({
      encryptedName: 'name',
      nameIv: 'iv',
      nameTag: 'tag',
      color: '#ff00aa',
    });
    expect(result.success).toBe(true);
  });

  it('rejects non-hex color string', () => {
    const result = createFolderSchema.safeParse({
      encryptedName: 'name',
      nameIv: 'iv',
      nameTag: 'tag',
      color: 'blue',
    });
    expect(result.success).toBe(false);
  });

  it('rejects color without hash prefix', () => {
    const result = createFolderSchema.safeParse({
      encryptedName: 'name',
      nameIv: 'iv',
      nameTag: 'tag',
      color: 'ff00aa',
    });
    expect(result.success).toBe(false);
  });

  it('rejects 3-digit hex color shorthand', () => {
    const result = createFolderSchema.safeParse({
      encryptedName: 'name',
      nameIv: 'iv',
      nameTag: 'tag',
      color: '#f0a',
    });
    expect(result.success).toBe(false);
  });

  it('accepts sortOrder at upper bound (10000)', () => {
    const result = createFolderSchema.safeParse({
      encryptedName: 'name',
      nameIv: 'iv',
      nameTag: 'tag',
      sortOrder: 10000,
    });
    expect(result.success).toBe(true);
  });

  it('rejects sortOrder above upper bound', () => {
    const result = createFolderSchema.safeParse({
      encryptedName: 'name',
      nameIv: 'iv',
      nameTag: 'tag',
      sortOrder: 10001,
    });
    expect(result.success).toBe(false);
  });

  it('rejects negative sortOrder', () => {
    const result = createFolderSchema.safeParse({
      encryptedName: 'name',
      nameIv: 'iv',
      nameTag: 'tag',
      sortOrder: -1,
    });
    expect(result.success).toBe(false);
  });
});

describe('updateFolderSchema', () => {
  it('rejects mismatched name fields', () => {
    const result = updateFolderSchema.safeParse({
      encryptedName: 'name',
      // missing nameIv and nameTag
    });
    expect(result.success).toBe(false);
  });

  it('accepts all name fields together', () => {
    const result = updateFolderSchema.safeParse({
      encryptedName: 'name',
      nameIv: 'iv',
      nameTag: 'tag',
    });
    expect(result.success).toBe(true);
  });

  it('accepts nullable parentId', () => {
    const result = updateFolderSchema.safeParse({ parentId: null });
    expect(result.success).toBe(true);
  });

  it('accepts sortOrder at upper bound (10000)', () => {
    const result = updateFolderSchema.safeParse({ sortOrder: 10000 });
    expect(result.success).toBe(true);
  });

  it('rejects sortOrder above upper bound', () => {
    const result = updateFolderSchema.safeParse({ sortOrder: 10001 });
    expect(result.success).toBe(false);
  });

  it('rejects negative sortOrder', () => {
    const result = updateFolderSchema.safeParse({ sortOrder: -1 });
    expect(result.success).toBe(false);
  });
});

describe('deleteFolderQuerySchema', () => {
  it('defaults action to move', () => {
    const result = deleteFolderQuerySchema.parse({});
    expect(result.action).toBe('move');
  });

  it('accepts delete action', () => {
    expect(deleteFolderQuerySchema.safeParse({ action: 'delete' }).success).toBe(true);
  });

  it('rejects invalid action', () => {
    expect(deleteFolderQuerySchema.safeParse({ action: 'archive' }).success).toBe(false);
  });
});

describe('reorderFolderSchema', () => {
  it('accepts valid sort order', () => {
    expect(reorderFolderSchema.safeParse({ sortOrder: 0 }).success).toBe(true);
    expect(reorderFolderSchema.safeParse({ sortOrder: 5 }).success).toBe(true);
  });

  it('rejects negative sort order', () => {
    expect(reorderFolderSchema.safeParse({ sortOrder: -1 }).success).toBe(false);
  });

  it('accepts max sort order of 10000', () => {
    expect(reorderFolderSchema.safeParse({ sortOrder: 10000 }).success).toBe(true);
  });

  it('rejects sort order exceeding 10000', () => {
    expect(reorderFolderSchema.safeParse({ sortOrder: 10001 }).success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// User schemas
// ---------------------------------------------------------------------------
describe('passwordGenOptionsSchema', () => {
  it('provides sensible defaults', () => {
    const result = passwordGenOptionsSchema.parse({});
    expect(result.length).toBe(20);
    expect(result.uppercase).toBe(true);
    expect(result.lowercase).toBe(true);
    expect(result.numbers).toBe(true);
    expect(result.symbols).toBe(true);
    expect(result.excludeAmbiguous).toBe(false);
    expect(result.minNumbers).toBe(1);
    expect(result.minSymbols).toBe(1);
  });

  it('rejects length below 8', () => {
    expect(passwordGenOptionsSchema.safeParse({ length: 7 }).success).toBe(false);
  });

  it('rejects length above 128', () => {
    expect(passwordGenOptionsSchema.safeParse({ length: 129 }).success).toBe(false);
  });

  it('rejects non-integer length', () => {
    expect(passwordGenOptionsSchema.safeParse({ length: 10.5 }).success).toBe(false);
  });

  it('rejects negative minNumbers', () => {
    expect(passwordGenOptionsSchema.safeParse({ minNumbers: -1 }).success).toBe(false);
  });

  it('rejects length below minNumbers + minSymbols (ungenerable config)', () => {
    const result = passwordGenOptionsSchema.safeParse({
      length: 10,
      minNumbers: 8,
      minSymbols: 5,
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.some((i) => i.path.includes('length'))).toBe(true);
    }
  });

  it('accepts length exactly equal to minNumbers + minSymbols (boundary)', () => {
    expect(
      passwordGenOptionsSchema.safeParse({ length: 10, minNumbers: 5, minSymbols: 5 }).success,
    ).toBe(true);
  });

  it('accepts length greater than minNumbers + minSymbols', () => {
    expect(
      passwordGenOptionsSchema.safeParse({ length: 20, minNumbers: 3, minSymbols: 2 }).success,
    ).toBe(true);
  });

  it('rejects when bumping minNumbers alone breaks the invariant against the default length', () => {
    // length defaults to 20; minSymbols defaults to 1 → 25 + 1 > 20
    expect(passwordGenOptionsSchema.safeParse({ minNumbers: 25 }).success).toBe(false);
  });
});

describe('updateSettingsSchema', () => {
  it('accepts empty object (all optional)', () => {
    expect(updateSettingsSchema.safeParse({}).success).toBe(true);
  });

  it('accepts valid settings', () => {
    const result = updateSettingsSchema.safeParse({
      autoLockTimeout: 15,
      clipboardClearTimeout: 30,
      defaultPasswordLength: 24,
      theme: 'dark',
      language: 'en',
    });
    expect(result.success).toBe(true);
  });

  it('rejects autoLockTimeout below 1', () => {
    expect(updateSettingsSchema.safeParse({ autoLockTimeout: 0 }).success).toBe(false);
  });

  it('rejects autoLockTimeout above 1440', () => {
    expect(updateSettingsSchema.safeParse({ autoLockTimeout: 1441 }).success).toBe(false);
  });

  it('rejects clipboardClearTimeout below 5', () => {
    expect(updateSettingsSchema.safeParse({ clipboardClearTimeout: 4 }).success).toBe(false);
  });

  it('rejects clipboardClearTimeout above 300', () => {
    expect(updateSettingsSchema.safeParse({ clipboardClearTimeout: 301 }).success).toBe(false);
  });

  it('rejects invalid theme', () => {
    expect(updateSettingsSchema.safeParse({ theme: 'neon' }).success).toBe(false);
  });

  it('accepts all valid themes', () => {
    for (const theme of ['light', 'dark', 'system']) {
      expect(updateSettingsSchema.safeParse({ theme }).success).toBe(true);
    }
  });

  it('accepts nested defaultPasswordOptions', () => {
    const result = updateSettingsSchema.safeParse({
      defaultPasswordOptions: { length: 32, uppercase: false },
    });
    expect(result.success).toBe(true);
  });

  it('rejects nested defaultPasswordOptions that violate length >= minNumbers + minSymbols', () => {
    const result = updateSettingsSchema.safeParse({
      defaultPasswordOptions: { length: 8, minNumbers: 6, minSymbols: 6 },
    });
    expect(result.success).toBe(false);
  });

  it('rejects language shorter than 2 chars', () => {
    expect(updateSettingsSchema.safeParse({ language: 'e' }).success).toBe(false);
  });

  it('rejects language longer than 10 chars', () => {
    expect(updateSettingsSchema.safeParse({ language: 'a'.repeat(11) }).success).toBe(false);
  });

  it('rejects defaultPasswordLength below 8', () => {
    expect(updateSettingsSchema.safeParse({ defaultPasswordLength: 7 }).success).toBe(false);
  });

  it('rejects defaultPasswordLength above 128', () => {
    expect(updateSettingsSchema.safeParse({ defaultPasswordLength: 129 }).success).toBe(false);
  });
});

describe('setup2faSchema', () => {
  it('accepts valid password', () => {
    expect(setup2faSchema.safeParse({ password: 'mypassword' }).success).toBe(true);
  });

  it('rejects empty password', () => {
    expect(setup2faSchema.safeParse({ password: '' }).success).toBe(false);
  });

  it('rejects password over 500 chars', () => {
    expect(setup2faSchema.safeParse({ password: 'a'.repeat(501) }).success).toBe(false);
  });
});

describe('verify2faSchema', () => {
  it('accepts 6-digit code', () => {
    expect(verify2faSchema.safeParse({ code: '123456' }).success).toBe(true);
  });

  it('rejects code shorter than 6', () => {
    expect(verify2faSchema.safeParse({ code: '12345' }).success).toBe(false);
  });

  it('rejects code longer than 6', () => {
    expect(verify2faSchema.safeParse({ code: '1234567' }).success).toBe(false);
  });

  it('rejects non-digit TOTP code', () => {
    expect(verify2faSchema.safeParse({ code: 'abcdef' }).success).toBe(false);
  });

  it('rejects TOTP code with special characters', () => {
    expect(verify2faSchema.safeParse({ code: '12345!' }).success).toBe(false);
  });

  it('rejects TOTP code with null byte', () => {
    expect(verify2faSchema.safeParse({ code: '12345\x00' }).success).toBe(false);
  });
});

describe('disable2faSchema', () => {
  it('accepts 6-digit code with password', () => {
    expect(disable2faSchema.safeParse({ code: '123456', password: 'authHash' }).success).toBe(true);
  });

  it('accepts backup code (up to 16 chars) with password', () => {
    expect(
      disable2faSchema.safeParse({ code: 'abcdef1234567890', password: 'authHash' }).success,
    ).toBe(true);
  });

  it('rejects code shorter than 6', () => {
    expect(disable2faSchema.safeParse({ code: '12345', password: 'authHash' }).success).toBe(false);
  });

  it('rejects code longer than 16', () => {
    expect(disable2faSchema.safeParse({ code: '1'.repeat(17), password: 'authHash' }).success).toBe(
      false,
    );
  });

  it('rejects missing password', () => {
    expect(disable2faSchema.safeParse({ code: '123456' }).success).toBe(false);
  });

  it('rejects empty password', () => {
    expect(disable2faSchema.safeParse({ code: '123456', password: '' }).success).toBe(false);
  });

  it('rejects code with null byte', () => {
    expect(disable2faSchema.safeParse({ code: '12345\x00', password: 'authHash' }).success).toBe(
      false,
    );
  });

  it('rejects code with special characters', () => {
    expect(disable2faSchema.safeParse({ code: '<script>', password: 'authHash' }).success).toBe(
      false,
    );
  });
});

describe('regenerateBackupCodesSchema', () => {
  it('accepts password only', () => {
    expect(regenerateBackupCodesSchema.safeParse({ password: 'mypass' }).success).toBe(true);
  });

  it('accepts password with valid TOTP code', () => {
    expect(
      regenerateBackupCodesSchema.safeParse({ password: 'mypass', code: '123456' }).success,
    ).toBe(true);
  });

  it('accepts password with alphanumeric backup code', () => {
    expect(
      regenerateBackupCodesSchema.safeParse({ password: 'mypass', code: 'ABCD1234EFGH5678' })
        .success,
    ).toBe(true);
  });

  it('rejects code with special characters', () => {
    expect(
      regenerateBackupCodesSchema.safeParse({ password: 'mypass', code: '<script>' }).success,
    ).toBe(false);
  });

  it('rejects code with null byte', () => {
    expect(
      regenerateBackupCodesSchema.safeParse({ password: 'mypass', code: '12345\x00' }).success,
    ).toBe(false);
  });

  it('rejects empty password', () => {
    expect(regenerateBackupCodesSchema.safeParse({ password: '' }).success).toBe(false);
  });

  it('rejects password exceeding 500 chars', () => {
    expect(regenerateBackupCodesSchema.safeParse({ password: 'a'.repeat(501) }).success).toBe(
      false,
    );
  });

  it('rejects code shorter than 6 chars', () => {
    expect(
      regenerateBackupCodesSchema.safeParse({ password: 'mypass', code: '12345' }).success,
    ).toBe(false);
  });

  it('rejects code longer than 16 chars', () => {
    expect(
      regenerateBackupCodesSchema.safeParse({ password: 'mypass', code: 'ABCD1234EFGH56789' })
        .success,
    ).toBe(false);
  });

  it('accepts password at max length (500 chars)', () => {
    expect(regenerateBackupCodesSchema.safeParse({ password: 'a'.repeat(500) }).success).toBe(true);
  });
});

describe('deleteAccountSchema', () => {
  it('accepts password only', () => {
    expect(deleteAccountSchema.safeParse({ password: 'mypass' }).success).toBe(true);
  });

  it('accepts password with valid code', () => {
    expect(deleteAccountSchema.safeParse({ password: 'mypass', code: '123456' }).success).toBe(
      true,
    );
  });

  it('accepts password with alphanumeric backup code', () => {
    expect(
      deleteAccountSchema.safeParse({ password: 'mypass', code: 'ABCD1234EFGH5678' }).success,
    ).toBe(true);
  });

  it('rejects code with special characters', () => {
    expect(deleteAccountSchema.safeParse({ password: 'mypass', code: '<script>' }).success).toBe(
      false,
    );
  });

  it('rejects code with null byte', () => {
    expect(deleteAccountSchema.safeParse({ password: 'mypass', code: '12345\x00' }).success).toBe(
      false,
    );
  });

  it('rejects empty password', () => {
    expect(deleteAccountSchema.safeParse({ password: '' }).success).toBe(false);
  });

  it('rejects missing password field entirely', () => {
    expect(deleteAccountSchema.safeParse({}).success).toBe(false);
  });

  it('rejects password exceeding 500 chars', () => {
    expect(deleteAccountSchema.safeParse({ password: 'a'.repeat(501) }).success).toBe(false);
  });

  it('accepts password at max length (500 chars)', () => {
    expect(deleteAccountSchema.safeParse({ password: 'a'.repeat(500) }).success).toBe(true);
  });

  it('rejects code shorter than 6 chars', () => {
    expect(deleteAccountSchema.safeParse({ password: 'mypass', code: '12345' }).success).toBe(
      false,
    );
  });

  it('rejects code longer than 16 chars', () => {
    expect(
      deleteAccountSchema.safeParse({ password: 'mypass', code: 'ABCD1234EFGH56789' }).success,
    ).toBe(false);
  });
});

describe('checkBreachSchema', () => {
  it('accepts valid 5-char hex prefix', () => {
    expect(checkBreachSchema.safeParse({ hashPrefix: 'A1B2C' }).success).toBe(true);
  });

  it('rejects non-hex characters', () => {
    expect(checkBreachSchema.safeParse({ hashPrefix: 'ZZZZZ' }).success).toBe(false);
  });

  it('rejects prefix shorter than 5', () => {
    expect(checkBreachSchema.safeParse({ hashPrefix: 'A1B2' }).success).toBe(false);
  });

  it('rejects prefix longer than 5', () => {
    expect(checkBreachSchema.safeParse({ hashPrefix: 'A1B2C3' }).success).toBe(false);
  });
});

describe('backupSetupSchema', () => {
  const validSetup = {
    authHash: 'valid-auth-hash',
    encryptedBWK: 'encrypted-key',
    bwkIv: 'iv-value',
    bwkTag: 'tag-value',
    bwkSalt: 'salt-value',
  };

  it('accepts valid backup setup', () => {
    expect(backupSetupSchema.safeParse(validSetup).success).toBe(true);
  });

  it('rejects missing authHash', () => {
    const { authHash: _, ...withoutAuth } = validSetup;
    expect(backupSetupSchema.safeParse(withoutAuth).success).toBe(false);
  });

  it('rejects empty authHash', () => {
    expect(backupSetupSchema.safeParse({ ...validSetup, authHash: '' }).success).toBe(false);
  });

  it('rejects authHash over 100 chars', () => {
    expect(backupSetupSchema.safeParse({ ...validSetup, authHash: 'a'.repeat(101) }).success).toBe(
      false,
    );
  });

  it('rejects empty encryptedBWK', () => {
    expect(backupSetupSchema.safeParse({ ...validSetup, encryptedBWK: '' }).success).toBe(false);
  });

  it('rejects encryptedBWK over 500 chars', () => {
    expect(
      backupSetupSchema.safeParse({ ...validSetup, encryptedBWK: 'a'.repeat(501) }).success,
    ).toBe(false);
  });

  it('rejects empty bwkIv', () => {
    expect(backupSetupSchema.safeParse({ ...validSetup, bwkIv: '' }).success).toBe(false);
  });

  it('rejects bwkIv over 24 chars', () => {
    expect(backupSetupSchema.safeParse({ ...validSetup, bwkIv: 'a'.repeat(25) }).success).toBe(
      false,
    );
  });

  it('rejects bwkTag over 32 chars', () => {
    expect(backupSetupSchema.safeParse({ ...validSetup, bwkTag: 'a'.repeat(33) }).success).toBe(
      false,
    );
  });

  it('rejects bwkSalt over 64 chars', () => {
    expect(backupSetupSchema.safeParse({ ...validSetup, bwkSalt: 'a'.repeat(65) }).success).toBe(
      false,
    );
  });

  it('accepts optional bwkEncryptedVaultKey fields', () => {
    const result = backupSetupSchema.safeParse({
      ...validSetup,
      bwkEncryptedVaultKey: 'encrypted-vault-key',
      bwkVaultKeyIv: 'vault-key-iv',
      bwkVaultKeyTag: 'vault-key-tag',
    });
    expect(result.success).toBe(true);
  });

  it('rejects bwkEncryptedVaultKey over 500 chars', () => {
    expect(
      backupSetupSchema.safeParse({
        ...validSetup,
        bwkEncryptedVaultKey: 'a'.repeat(501),
      }).success,
    ).toBe(false);
  });

  it('rejects empty bwkEncryptedVaultKey', () => {
    expect(backupSetupSchema.safeParse({ ...validSetup, bwkEncryptedVaultKey: '' }).success).toBe(
      false,
    );
  });

  it('rejects bwkVaultKeyIv over 24 chars', () => {
    expect(
      backupSetupSchema.safeParse({ ...validSetup, bwkVaultKeyIv: 'a'.repeat(25) }).success,
    ).toBe(false);
  });

  it('rejects bwkVaultKeyTag over 32 chars', () => {
    expect(
      backupSetupSchema.safeParse({ ...validSetup, bwkVaultKeyTag: 'a'.repeat(33) }).success,
    ).toBe(false);
  });

  it('rejects partial bwkEncryptedVaultKey triplet (only key)', () => {
    expect(
      backupSetupSchema.safeParse({ ...validSetup, bwkEncryptedVaultKey: 'key' }).success,
    ).toBe(false);
  });

  it('rejects partial bwkEncryptedVaultKey triplet (key + iv, missing tag)', () => {
    expect(
      backupSetupSchema.safeParse({
        ...validSetup,
        bwkEncryptedVaultKey: 'key',
        bwkVaultKeyIv: 'iv',
      }).success,
    ).toBe(false);
  });

  it('rejects partial bwkEncryptedVaultKey triplet (key + tag, missing iv)', () => {
    expect(
      backupSetupSchema.safeParse({
        ...validSetup,
        bwkEncryptedVaultKey: 'key',
        bwkVaultKeyTag: 'tag',
      }).success,
    ).toBe(false);
  });

  it('accepts all three bwkVaultKey fields together', () => {
    expect(
      backupSetupSchema.safeParse({
        ...validSetup,
        bwkEncryptedVaultKey: 'key',
        bwkVaultKeyIv: 'iv',
        bwkVaultKeyTag: 'tag',
      }).success,
    ).toBe(true);
  });

  it('accepts none of the bwkVaultKey fields', () => {
    expect(backupSetupSchema.safeParse(validSetup).success).toBe(true);
  });
});

describe('backupSettingsSchema', () => {
  it('accepts empty object (all optional)', () => {
    expect(backupSettingsSchema.safeParse({}).success).toBe(true);
  });

  it('accepts valid settings', () => {
    const result = backupSettingsSchema.safeParse({
      enabled: true,
      scheduleHour: 14,
      backupEmails: ['user@example.com'],
    });
    expect(result.success).toBe(true);
  });

  it('rejects scheduleHour below 0', () => {
    expect(backupSettingsSchema.safeParse({ scheduleHour: -1 }).success).toBe(false);
  });

  it('rejects scheduleHour above 23', () => {
    expect(backupSettingsSchema.safeParse({ scheduleHour: 24 }).success).toBe(false);
  });

  it('accepts valid backupEmails array', () => {
    const result = backupSettingsSchema.safeParse({ backupEmails: ['a@b.com', 'c@d.com'] });
    expect(result.success).toBe(true);
  });

  it('rejects invalid email in backupEmails', () => {
    expect(backupSettingsSchema.safeParse({ backupEmails: ['not-email'] }).success).toBe(false);
  });

  it('lowercases backupEmails', () => {
    const result = backupSettingsSchema.parse({ backupEmails: ['User@Example.COM'] });
    expect(result.backupEmails![0]).toBe('user@example.com');
  });

  it('rejects backupEmails over 10 entries', () => {
    const emails = Array.from({ length: 11 }, (_, i) => `user${String(i)}@example.com`);
    expect(backupSettingsSchema.safeParse({ backupEmails: emails }).success).toBe(false);
  });

  it('rejects backupEmail over 254 chars in array', () => {
    const longEmail = 'a'.repeat(243) + '@example.com';
    expect(backupSettingsSchema.safeParse({ backupEmails: [longEmail] }).success).toBe(false);
  });

  it('accepts empty backupEmails array', () => {
    expect(backupSettingsSchema.safeParse({ backupEmails: [] }).success).toBe(true);
  });
});

describe('backupChangePasswordSchema', () => {
  const validChange = {
    password: 'current-password',
    newEncryptedBWK: 'new-key',
    newBwkIv: 'new-iv',
    newBwkTag: 'new-tag',
    newBwkSalt: 'new-salt',
  };

  it('accepts valid change', () => {
    expect(backupChangePasswordSchema.safeParse(validChange).success).toBe(true);
  });

  it('rejects empty newEncryptedBWK', () => {
    expect(
      backupChangePasswordSchema.safeParse({ ...validChange, newEncryptedBWK: '' }).success,
    ).toBe(false);
  });

  it('rejects missing fields', () => {
    expect(backupChangePasswordSchema.safeParse({ newEncryptedBWK: 'key' }).success).toBe(false);
  });

  it('rejects empty password', () => {
    expect(backupChangePasswordSchema.safeParse({ ...validChange, password: '' }).success).toBe(
      false,
    );
  });

  it('rejects password over 500 chars', () => {
    expect(
      backupChangePasswordSchema.safeParse({ ...validChange, password: 'a'.repeat(501) }).success,
    ).toBe(false);
  });

  it('rejects newBwkIv over 24 chars', () => {
    expect(
      backupChangePasswordSchema.safeParse({ ...validChange, newBwkIv: 'a'.repeat(25) }).success,
    ).toBe(false);
  });

  it('rejects newBwkTag over 32 chars', () => {
    expect(
      backupChangePasswordSchema.safeParse({ ...validChange, newBwkTag: 'a'.repeat(33) }).success,
    ).toBe(false);
  });

  it('rejects newBwkSalt over 64 chars', () => {
    expect(
      backupChangePasswordSchema.safeParse({ ...validChange, newBwkSalt: 'a'.repeat(65) }).success,
    ).toBe(false);
  });

  it('accepts optional newBwkEncryptedVaultKey fields', () => {
    const result = backupChangePasswordSchema.safeParse({
      ...validChange,
      newBwkEncryptedVaultKey: 'new-encrypted-vault-key',
      newBwkVaultKeyIv: 'new-vk-iv',
      newBwkVaultKeyTag: 'new-vk-tag',
    });
    expect(result.success).toBe(true);
  });

  it('rejects newBwkEncryptedVaultKey over 500 chars', () => {
    expect(
      backupChangePasswordSchema.safeParse({
        ...validChange,
        newBwkEncryptedVaultKey: 'a'.repeat(501),
      }).success,
    ).toBe(false);
  });

  it('rejects newBwkVaultKeyIv over 24 chars', () => {
    expect(
      backupChangePasswordSchema.safeParse({
        ...validChange,
        newBwkVaultKeyIv: 'a'.repeat(25),
      }).success,
    ).toBe(false);
  });

  it('rejects newBwkVaultKeyTag over 32 chars', () => {
    expect(
      backupChangePasswordSchema.safeParse({
        ...validChange,
        newBwkVaultKeyTag: 'a'.repeat(33),
      }).success,
    ).toBe(false);
  });

  it('rejects partial newBwkVaultKey triplet (only key)', () => {
    expect(
      backupChangePasswordSchema.safeParse({
        ...validChange,
        newBwkEncryptedVaultKey: 'key',
      }).success,
    ).toBe(false);
  });

  it('rejects partial newBwkVaultKey triplet (key + iv, missing tag)', () => {
    expect(
      backupChangePasswordSchema.safeParse({
        ...validChange,
        newBwkEncryptedVaultKey: 'key',
        newBwkVaultKeyIv: 'iv',
      }).success,
    ).toBe(false);
  });

  it('rejects partial newBwkVaultKey triplet (key + tag, missing iv)', () => {
    expect(
      backupChangePasswordSchema.safeParse({
        ...validChange,
        newBwkEncryptedVaultKey: 'key',
        newBwkVaultKeyTag: 'tag',
      }).success,
    ).toBe(false);
  });

  it('accepts all three newBwkVaultKey fields together', () => {
    expect(
      backupChangePasswordSchema.safeParse({
        ...validChange,
        newBwkEncryptedVaultKey: 'key',
        newBwkVaultKeyIv: 'iv',
        newBwkVaultKeyTag: 'tag',
      }).success,
    ).toBe(true);
  });

  it('accepts none of the newBwkVaultKey fields', () => {
    expect(backupChangePasswordSchema.safeParse(validChange).success).toBe(true);
  });
});

describe('backupHistorySchema', () => {
  it('provides defaults for page and limit', () => {
    const result = backupHistorySchema.parse({});
    expect(result.page).toBe(1);
    expect(result.limit).toBe(30);
  });

  it('coerces string values', () => {
    const result = backupHistorySchema.parse({ page: '3', limit: '10' });
    expect(result.page).toBe(3);
    expect(result.limit).toBe(10);
  });

  it('rejects page below 1', () => {
    expect(backupHistorySchema.safeParse({ page: 0 }).success).toBe(false);
  });

  it('rejects negative page', () => {
    expect(backupHistorySchema.safeParse({ page: -1 }).success).toBe(false);
  });

  it('rejects limit above 30', () => {
    expect(backupHistorySchema.safeParse({ limit: 31 }).success).toBe(false);
  });

  it('rejects limit below 1', () => {
    expect(backupHistorySchema.safeParse({ limit: 0 }).success).toBe(false);
  });

  it('accepts boundary values', () => {
    expect(backupHistorySchema.safeParse({ page: 1, limit: 1 }).success).toBe(true);
    expect(backupHistorySchema.safeParse({ page: 1, limit: 30 }).success).toBe(true);
  });

  it('rejects non-integer page', () => {
    expect(backupHistorySchema.safeParse({ page: 1.5 }).success).toBe(false);
  });

  it('rejects non-integer limit', () => {
    expect(backupHistorySchema.safeParse({ limit: 2.5 }).success).toBe(false);
  });
});

describe('auditLogQuerySchema', () => {
  it('provides defaults for page and limit', () => {
    const result = auditLogQuerySchema.parse({});
    expect(result.page).toBe(1);
    expect(result.limit).toBe(20);
  });

  it('coerces string values', () => {
    const result = auditLogQuerySchema.parse({ page: '2', limit: '50' });
    expect(result.page).toBe(2);
    expect(result.limit).toBe(50);
  });

  it('rejects limit above 100', () => {
    expect(auditLogQuerySchema.safeParse({ limit: 101 }).success).toBe(false);
  });

  it('rejects page below 1', () => {
    expect(auditLogQuerySchema.safeParse({ page: 0 }).success).toBe(false);
  });

  it('accepts valid audit action filter', () => {
    expect(auditLogQuerySchema.safeParse({ action: 'login' }).success).toBe(true);
    expect(auditLogQuerySchema.safeParse({ action: 'item_create' }).success).toBe(true);
  });

  it('rejects invalid audit action', () => {
    expect(auditLogQuerySchema.safeParse({ action: 'invalid_action' }).success).toBe(false);
  });
});

describe('restoreBackupSchema', () => {
  it('defaults conflictStrategy to skip', () => {
    const result = restoreBackupSchema.parse({ data: '{"items":[]}' });
    expect(result.conflictStrategy).toBe('skip');
  });

  it('accepts all conflict strategies', () => {
    for (const strategy of ['skip', 'overwrite', 'keep_both']) {
      expect(
        restoreBackupSchema.safeParse({ data: 'data', conflictStrategy: strategy }).success,
      ).toBe(true);
    }
  });

  it('rejects empty data', () => {
    expect(restoreBackupSchema.safeParse({ data: '' }).success).toBe(false);
  });

  it('rejects data over 25MB', () => {
    expect(restoreBackupSchema.safeParse({ data: 'a'.repeat(26_214_401) }).success).toBe(false);
  });

  it('rejects invalid conflictStrategy', () => {
    expect(restoreBackupSchema.safeParse({ data: 'data', conflictStrategy: 'merge' }).success).toBe(
      false,
    );
  });

  it('accepts data at exactly 25MB boundary', () => {
    expect(restoreBackupSchema.safeParse({ data: 'a'.repeat(26_214_400) }).success).toBe(true);
  });

  it('accepts data at 1MB (well within 25MB limit)', () => {
    expect(restoreBackupSchema.safeParse({ data: 'a'.repeat(1_048_576) }).success).toBe(true);
  });

  it('silently ignores a legacy adoptVaultKey key (unknown fields are stripped, not rejected)', () => {
    const result = restoreBackupSchema.safeParse({
      data: '{"items":[]}',
      adoptVaultKey: {
        encryptedVaultKey: 'enc-key',
        vaultKeyIv: 'vk-iv',
        vaultKeyTag: 'vk-tag',
      },
      authHash: 'auth-hash-value',
    });
    expect(result.success).toBe(true);
    // The removed fields are dropped, never surfaced on the parsed output.
    expect(result.data).not.toHaveProperty('adoptVaultKey');
    expect(result.data).not.toHaveProperty('authHash');
  });

  it('parses a minimal restore body of only { data } (conflictStrategy defaults to skip)', () => {
    const result = restoreBackupSchema.parse({ data: '{"items":[]}' });
    expect(result.conflictStrategy).toBe('skip');
  });

  it('defines only { conflictStrategy, data } — no vault-key-adoption / re-auth keys', () => {
    // Guards the regression the sibling test guards against, but non-vacuously:
    // asserting the schema's own key set fails the moment `adoptVaultKey` or
    // `authHash` is re-added, whereas a `not.toHaveProperty` on a parsed result
    // (which never supplied those keys) cannot.
    expect(Object.keys(restoreBackupSchema.shape).sort()).toEqual(['conflictStrategy', 'data']);
  });
});

describe('exportSchema', () => {
  it('defaults format to json when authHash is provided', () => {
    const result = exportSchema.parse({ authHash: 'test-hash' });
    expect(result.format).toBe('json');
  });

  it('rejects csv format (export is JSON-only; CSV is an import-only format)', () => {
    expect(exportSchema.safeParse({ format: 'csv', authHash: 'test-hash' }).success).toBe(false);
  });

  it('rejects invalid format', () => {
    expect(exportSchema.safeParse({ format: 'xml', authHash: 'test-hash' }).success).toBe(false);
  });

  it('requires authHash', () => {
    expect(exportSchema.safeParse({ format: 'json' }).success).toBe(false);
    expect(exportSchema.safeParse({}).success).toBe(false);
  });

  it('rejects empty authHash', () => {
    expect(exportSchema.safeParse({ format: 'json', authHash: '' }).success).toBe(false);
  });

  it('rejects authHash exceeding max length', () => {
    expect(exportSchema.safeParse({ format: 'json', authHash: 'x'.repeat(101) }).success).toBe(
      false,
    );
  });
});

describe('importSchema', () => {
  it('accepts all valid formats', () => {
    for (const format of ['bitwarden', 'lastpass', 'keepass', 'csv', 'json']) {
      expect(importSchema.safeParse({ format, data: 'some-data' }).success).toBe(true);
    }
  });

  it('rejects invalid format', () => {
    expect(importSchema.safeParse({ format: '1password', data: 'data' }).success).toBe(false);
  });

  it('rejects empty data', () => {
    expect(importSchema.safeParse({ format: 'json', data: '' }).success).toBe(false);
  });

  it('rejects data over 1MB', () => {
    expect(importSchema.safeParse({ format: 'json', data: 'a'.repeat(1_048_577) }).success).toBe(
      false,
    );
  });

  it('accepts optional csvMapping', () => {
    const result = importSchema.safeParse({
      format: 'csv',
      data: 'some-csv',
      csvMapping: { name: 'col1', password: 'col2' },
    });
    expect(result.success).toBe(true);
  });

  it('accepts csvMapping with exactly 50 keys', () => {
    const mapping: Record<string, string> = {};
    for (let i = 0; i < 50; i++) {
      mapping[`key${i}`] = `val${i}`;
    }
    const result = importSchema.safeParse({
      format: 'csv',
      data: 'some-csv',
      csvMapping: mapping,
    });
    expect(result.success).toBe(true);
  });

  it('rejects csvMapping with more than 50 keys', () => {
    const mapping: Record<string, string> = {};
    for (let i = 0; i < 51; i++) {
      mapping[`key${i}`] = `val${i}`;
    }
    const result = importSchema.safeParse({
      format: 'csv',
      data: 'some-csv',
      csvMapping: mapping,
    });
    expect(result.success).toBe(false);
  });

  it('accepts valid conflictStrategy values', () => {
    for (const strategy of ['skip', 'overwrite', 'keep_both']) {
      const result = importSchema.safeParse({
        format: 'json',
        data: 'data',
        conflictStrategy: strategy,
      });
      expect(result.success).toBe(true);
    }
  });

  it('defaults conflictStrategy to skip when not provided', () => {
    const result = importSchema.parse({ format: 'json', data: 'data' });
    expect(result.conflictStrategy).toBe('skip');
  });

  it('rejects invalid conflictStrategy values', () => {
    const result = importSchema.safeParse({
      format: 'json',
      data: 'data',
      conflictStrategy: 'delete_all',
    });
    expect(result.success).toBe(false);
  });
});

// =========================================================================
// vaultItemResponseSchema — API response shape validation
// =========================================================================

describe('vaultItemResponseSchema', () => {
  const validItem = {
    _id: '507f1f77bcf86cd799439011',
    userId: '507f1f77bcf86cd799439012',
    itemType: 'login' as const,
    tags: ['work'],
    favorite: false,
    encryptedData: 'ciphertext',
    dataIv: 'iv12bytes',
    dataTag: 'tag16bytes',
    encryptedName: 'encname',
    nameIv: 'niv',
    nameTag: 'ntg',
    createdAt: '2025-01-01T00:00:00Z',
    updatedAt: '2025-01-01T00:00:00Z',
  };

  it('accepts a valid vault item response', () => {
    expect(vaultItemResponseSchema.safeParse(validItem).success).toBe(true);
  });

  it('accepts optional fields (folderId, searchHash, deletedAt, passwordHistory)', () => {
    const result = vaultItemResponseSchema.safeParse({
      ...validItem,
      folderId: '507f1f77bcf86cd799439013',
      searchHash: 'hash',
      deletedAt: '2025-06-01T00:00:00Z',
      passwordHistory: [
        { encryptedPassword: 'ep', iv: 'iv', tag: 'tg', changedAt: '2025-01-01T00:00:00Z' },
      ],
    });
    expect(result.success).toBe(true);
  });

  it('rejects when _id is missing', () => {
    const { _id: _, ...rest } = validItem;
    expect(vaultItemResponseSchema.safeParse(rest).success).toBe(false);
  });

  it('rejects when encryptedData is empty string', () => {
    expect(vaultItemResponseSchema.safeParse({ ...validItem, encryptedData: '' }).success).toBe(
      false,
    );
  });

  it('rejects when dataIv is missing', () => {
    const { dataIv: _, ...rest } = validItem;
    expect(vaultItemResponseSchema.safeParse(rest).success).toBe(false);
  });

  it('rejects when nameTag is empty', () => {
    expect(vaultItemResponseSchema.safeParse({ ...validItem, nameTag: '' }).success).toBe(false);
  });

  it('rejects invalid itemType', () => {
    expect(vaultItemResponseSchema.safeParse({ ...validItem, itemType: 'wallet' }).success).toBe(
      false,
    );
  });

  it('rejects when createdAt is missing', () => {
    const { createdAt: _, ...rest } = validItem;
    expect(vaultItemResponseSchema.safeParse(rest).success).toBe(false);
  });

  it('rejects when tags is not an array', () => {
    expect(vaultItemResponseSchema.safeParse({ ...validItem, tags: 'tag' }).success).toBe(false);
  });

  it('rejects when favorite is not a boolean', () => {
    expect(vaultItemResponseSchema.safeParse({ ...validItem, favorite: 'yes' }).success).toBe(
      false,
    );
  });
});

// =========================================================================
// folderResponseSchema — API response shape validation
// =========================================================================

describe('folderResponseSchema', () => {
  const validFolder = {
    _id: '507f1f77bcf86cd799439011',
    userId: '507f1f77bcf86cd799439012',
    encryptedName: 'encname',
    nameIv: 'niv',
    nameTag: 'ntg',
    sortOrder: 0,
    createdAt: '2025-01-01T00:00:00Z',
    updatedAt: '2025-01-01T00:00:00Z',
  };

  it('accepts a valid folder response', () => {
    expect(folderResponseSchema.safeParse(validFolder).success).toBe(true);
  });

  it('accepts optional fields (searchHash, parentId, icon, color)', () => {
    const result = folderResponseSchema.safeParse({
      ...validFolder,
      searchHash: 'hash',
      parentId: '507f1f77bcf86cd799439013',
      icon: 'folder',
      color: '#ff0000',
    });
    expect(result.success).toBe(true);
  });

  it('rejects when encryptedName is empty', () => {
    expect(folderResponseSchema.safeParse({ ...validFolder, encryptedName: '' }).success).toBe(
      false,
    );
  });

  it('rejects when sortOrder is missing', () => {
    const { sortOrder: _, ...rest } = validFolder;
    expect(folderResponseSchema.safeParse(rest).success).toBe(false);
  });

  it('rejects when sortOrder is not a number', () => {
    expect(folderResponseSchema.safeParse({ ...validFolder, sortOrder: 'zero' }).success).toBe(
      false,
    );
  });

  it('rejects when _id is missing', () => {
    const { _id: _, ...rest } = validFolder;
    expect(folderResponseSchema.safeParse(rest).success).toBe(false);
  });

  it('rejects when nameIv is missing', () => {
    const { nameIv: _, ...rest } = validFolder;
    expect(folderResponseSchema.safeParse(rest).success).toBe(false);
  });
});
