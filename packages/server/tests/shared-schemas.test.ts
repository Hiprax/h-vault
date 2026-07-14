import { describe, it, expect } from 'vitest';
import {
  emailSchema,
  registerSchema,
  createVaultItemSchema,
  updateVaultItemSchema,
  listVaultItemsSchema,
  createFolderSchema,
  updateFolderSchema,
  deleteFolderQuerySchema,
  backupSetupSchema,
  backupChangePasswordSchema,
  unlockAccountSchema,
  setup2faSchema,
  verify2faSchema,
  disable2faSchema,
  secretDataSchema,
  loginDataSchema,
  identityDataSchema,
  paginationSchema,
  updateSettingsSchema,
  auditLogQuerySchema,
  noteDataSchema,
  maskEmail,
  formatBytes,
  generateId,
  ITEM_TYPES,
  THEMES,
  AUDIT_ACTIONS,
  PAGINATION_DEFAULTS,
} from '@hvault/shared';
import type {
  Setup2faInput,
  Verify2faInput,
  Disable2faInput,
  UnlockAccountInput,
} from '@hvault/shared';

// ---------------------------------------------------------------------------
// Task 5.1: Missing type exports
// ---------------------------------------------------------------------------
describe('Task 5.1 — Type exports for 2FA and unlock schemas', () => {
  it('should export Setup2faInput type that matches schema', () => {
    const input: Setup2faInput = { password: 'test123' };
    const result = setup2faSchema.safeParse(input);
    expect(result.success).toBe(true);
  });

  it('should export Verify2faInput type that matches schema', () => {
    const input: Verify2faInput = { code: '123456', secret: 'JBSWY3DPEHPK3PXP' };
    const result = verify2faSchema.safeParse(input);
    expect(result.success).toBe(true);
  });

  it('should export Disable2faInput type that matches schema', () => {
    const input: Disable2faInput = { code: '123456', password: 'authHash' };
    const result = disable2faSchema.safeParse(input);
    expect(result.success).toBe(true);
  });

  it('should export UnlockAccountInput type that matches schema', () => {
    const input: UnlockAccountInput = { token: 'some-token' };
    const result = unlockAccountSchema.safeParse(input);
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Task 5.2: Email max length (254 chars)
// ---------------------------------------------------------------------------
describe('Task 5.2 — Email max length validation', () => {
  it('should accept a valid email', () => {
    const result = emailSchema.safeParse('user@example.com');
    expect(result.success).toBe(true);
  });

  it('should accept an email at exactly 254 characters and reject one at 255', () => {
    // Build a well-formed address of an exact total length. The local part is the
    // RFC-max 64 chars; the domain is filled with dot-separated <=63-char labels
    // (z.email()'s regex rejects labels longer than that), so the address is a
    // genuine email that only the `.max(254)` bound governs at the boundary.
    const buildEmail = (total: number): string => {
      const local = 'a'.repeat(64);
      let remaining = total - (local.length + 1); // subtract "@"
      const labels: string[] = [];
      while (remaining > 0) {
        const take = Math.min(63, remaining);
        labels.push('b'.repeat(take));
        remaining -= take;
        if (remaining > 0) remaining -= 1; // the joining dot
      }
      return `${local}@${labels.join('.')}`;
    };

    const at254 = buildEmail(254);
    expect(at254).toHaveLength(254);
    // Exercise the REAL schema, not the string's own length.
    expect(emailSchema.safeParse(at254).success).toBe(true);

    const at255 = buildEmail(255);
    expect(at255).toHaveLength(255);
    expect(emailSchema.safeParse(at255).success).toBe(false);
  });

  it('should reject an email exceeding 254 characters', () => {
    const longLocal = 'a'.repeat(200);
    const longEmail = `${longLocal}@${'b'.repeat(60)}.com`;
    expect(longEmail.length).toBeGreaterThan(254);
    const result = emailSchema.safeParse(longEmail);
    expect(result.success).toBe(false);
  });

  it('should reject an invalid email format', () => {
    const result = emailSchema.safeParse('not-an-email');
    expect(result.success).toBe(false);
  });

  it('should lowercase email', () => {
    const result = emailSchema.safeParse('User@Example.COM');
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data).toBe('user@example.com');
    }
  });
});

// ---------------------------------------------------------------------------
// Task 5.3: Upper bounds on encrypted data fields
// ---------------------------------------------------------------------------
describe('Task 5.3 — Upper bounds on encrypted data fields', () => {
  describe('createVaultItemSchema', () => {
    const validItem = {
      itemType: 'login' as const,
      encryptedData: 'abc',
      dataIv: 'iv12345678901234',
      dataTag: 'tag12345678901234567890',
      encryptedName: 'name',
      nameIv: 'iv12345678901234',
      nameTag: 'tag12345678901234567890',
    };

    it('should accept valid encrypted data', () => {
      const result = createVaultItemSchema.safeParse(validItem);
      expect(result.success).toBe(true);
    });

    it('should reject encryptedData exceeding 500,000 chars', () => {
      const result = createVaultItemSchema.safeParse({
        ...validItem,
        encryptedData: 'a'.repeat(500_001),
      });
      expect(result.success).toBe(false);
    });

    it('should reject dataIv exceeding 24 chars', () => {
      const result = createVaultItemSchema.safeParse({
        ...validItem,
        dataIv: 'a'.repeat(25),
      });
      expect(result.success).toBe(false);
    });

    it('should reject dataTag exceeding 32 chars', () => {
      const result = createVaultItemSchema.safeParse({
        ...validItem,
        dataTag: 'a'.repeat(33),
      });
      expect(result.success).toBe(false);
    });

    it('should reject encryptedName exceeding 1000 chars', () => {
      const result = createVaultItemSchema.safeParse({
        ...validItem,
        encryptedName: 'a'.repeat(1001),
      });
      expect(result.success).toBe(false);
    });

    it('should reject nameIv exceeding 24 chars', () => {
      const result = createVaultItemSchema.safeParse({
        ...validItem,
        nameIv: 'a'.repeat(25),
      });
      expect(result.success).toBe(false);
    });

    it('should reject nameTag exceeding 32 chars', () => {
      const result = createVaultItemSchema.safeParse({
        ...validItem,
        nameTag: 'a'.repeat(33),
      });
      expect(result.success).toBe(false);
    });
  });

  describe('updateVaultItemSchema', () => {
    it('should reject oversized optional encrypted fields', () => {
      const result = updateVaultItemSchema.safeParse({
        encryptedData: 'a'.repeat(500_001),
      });
      expect(result.success).toBe(false);
    });

    it('should reject oversized passwordHistory iv', () => {
      const result = updateVaultItemSchema.safeParse({
        passwordHistory: [
          {
            encryptedPassword: 'abc',
            iv: 'a'.repeat(25),
            tag: 'abc',
            changedAt: new Date().toISOString(),
          },
        ],
      });
      expect(result.success).toBe(false);
    });

    it('should reject oversized passwordHistory tag', () => {
      const result = updateVaultItemSchema.safeParse({
        passwordHistory: [
          {
            encryptedPassword: 'abc',
            iv: 'abc',
            tag: 'a'.repeat(33),
            changedAt: new Date().toISOString(),
          },
        ],
      });
      expect(result.success).toBe(false);
    });
  });

  describe('createFolderSchema', () => {
    it('should reject encryptedName exceeding 1000 chars', () => {
      const result = createFolderSchema.safeParse({
        encryptedName: 'a'.repeat(1001),
        nameIv: 'iv',
        nameTag: 'tag',
      });
      expect(result.success).toBe(false);
    });

    it('should reject nameIv exceeding 24 chars', () => {
      const result = createFolderSchema.safeParse({
        encryptedName: 'name',
        nameIv: 'a'.repeat(25),
        nameTag: 'tag',
      });
      expect(result.success).toBe(false);
    });

    it('should reject nameTag exceeding 32 chars', () => {
      const result = createFolderSchema.safeParse({
        encryptedName: 'name',
        nameIv: 'iv',
        nameTag: 'a'.repeat(33),
      });
      expect(result.success).toBe(false);
    });
  });

  describe('updateVaultItemSchema — encryption triplet validation', () => {
    it('should reject partial data triplet (missing dataTag)', () => {
      const result = updateVaultItemSchema.safeParse({
        encryptedData: 'data',
        dataIv: 'iv',
      });
      expect(result.success).toBe(false);
    });

    it('should reject partial data triplet (missing dataIv)', () => {
      const result = updateVaultItemSchema.safeParse({
        encryptedData: 'data',
        dataTag: 'tag',
      });
      expect(result.success).toBe(false);
    });

    it('should reject partial data triplet (only encryptedData)', () => {
      const result = updateVaultItemSchema.safeParse({
        encryptedData: 'data',
      });
      expect(result.success).toBe(false);
    });

    it('should accept complete data triplet', () => {
      const result = updateVaultItemSchema.safeParse({
        encryptedData: 'data',
        dataIv: 'iv',
        dataTag: 'tag',
      });
      expect(result.success).toBe(true);
    });

    it('should reject partial name triplet (missing nameTag)', () => {
      const result = updateVaultItemSchema.safeParse({
        encryptedName: 'name',
        nameIv: 'iv',
      });
      expect(result.success).toBe(false);
    });

    it('should accept complete name triplet', () => {
      const result = updateVaultItemSchema.safeParse({
        encryptedName: 'name',
        nameIv: 'iv',
        nameTag: 'tag',
      });
      expect(result.success).toBe(true);
    });

    it('should accept no triplet fields at all', () => {
      const result = updateVaultItemSchema.safeParse({
        favorite: true,
      });
      expect(result.success).toBe(true);
    });
  });

  describe('updateFolderSchema', () => {
    it('should reject oversized optional folder fields', () => {
      const result = updateFolderSchema.safeParse({
        encryptedName: 'a'.repeat(1001),
      });
      expect(result.success).toBe(false);
    });

    it('should reject partial name triplet (missing nameTag)', () => {
      const result = updateFolderSchema.safeParse({
        encryptedName: 'name',
        nameIv: 'iv',
      });
      expect(result.success).toBe(false);
    });

    it('should reject partial name triplet (only encryptedName)', () => {
      const result = updateFolderSchema.safeParse({
        encryptedName: 'name',
      });
      expect(result.success).toBe(false);
    });

    it('should accept complete name triplet', () => {
      const result = updateFolderSchema.safeParse({
        encryptedName: 'name',
        nameIv: 'iv',
        nameTag: 'tag',
      });
      expect(result.success).toBe(true);
    });

    it('should accept no name fields', () => {
      const result = updateFolderSchema.safeParse({
        sortOrder: 5,
      });
      expect(result.success).toBe(true);
    });
  });

  describe('registerSchema encrypted fields', () => {
    const validRegister = {
      email: 'test@example.com',
      authHash: 'hash',
      encryptedVaultKey: 'key',
      vaultKeyIv: 'iv',
      vaultKeyTag: 'tag',
      kdfIterations: 600_000,
      kdfAlgorithm: 'PBKDF2-SHA256' as const,
    };

    it('should reject authHash exceeding 100 chars', () => {
      const result = registerSchema.safeParse({
        ...validRegister,
        authHash: 'a'.repeat(101),
      });
      expect(result.success).toBe(false);
    });

    it('should reject encryptedVaultKey exceeding 200 chars', () => {
      const result = registerSchema.safeParse({
        ...validRegister,
        encryptedVaultKey: 'a'.repeat(201),
      });
      expect(result.success).toBe(false);
    });

    it('should reject vaultKeyIv exceeding 24 chars', () => {
      const result = registerSchema.safeParse({
        ...validRegister,
        vaultKeyIv: 'a'.repeat(25),
      });
      expect(result.success).toBe(false);
    });

    it('should reject vaultKeyTag exceeding 32 chars', () => {
      const result = registerSchema.safeParse({
        ...validRegister,
        vaultKeyTag: 'a'.repeat(33),
      });
      expect(result.success).toBe(false);
    });
  });

  describe('backupSetupSchema encrypted fields', () => {
    it('should reject encryptedBWK exceeding 500 chars', () => {
      const result = backupSetupSchema.safeParse({
        authHash: 'valid-hash',
        encryptedBWK: 'a'.repeat(501),
        bwkIv: 'iv',
        bwkTag: 'tag',
        bwkSalt: 'salt',
      });
      expect(result.success).toBe(false);
    });

    it('should reject bwkIv exceeding 24 chars', () => {
      const result = backupSetupSchema.safeParse({
        authHash: 'valid-hash',
        encryptedBWK: 'key',
        bwkIv: 'a'.repeat(25),
        bwkTag: 'tag',
        bwkSalt: 'salt',
      });
      expect(result.success).toBe(false);
    });

    it('should reject bwkSalt exceeding 100 chars', () => {
      const result = backupSetupSchema.safeParse({
        authHash: 'valid-hash',
        encryptedBWK: 'key',
        bwkIv: 'iv',
        bwkTag: 'tag',
        bwkSalt: 'a'.repeat(101),
      });
      expect(result.success).toBe(false);
    });
  });

  describe('backupChangePasswordSchema encrypted fields', () => {
    it('should reject newEncryptedBWK exceeding 500 chars', () => {
      const result = backupChangePasswordSchema.safeParse({
        newEncryptedBWK: 'a'.repeat(501),
        newBwkIv: 'iv',
        newBwkTag: 'tag',
        newBwkSalt: 'salt',
      });
      expect(result.success).toBe(false);
    });
  });
});

// ---------------------------------------------------------------------------
// Task 5.4: CustomField type consistency
// ---------------------------------------------------------------------------
describe('Task 5.4 — CustomField type consistency', () => {
  describe('secretDataSchema allows boolean custom fields', () => {
    it('should accept custom field with type boolean', () => {
      const result = secretDataSchema.safeParse({
        value: 'my-secret',
        customFields: [{ name: 'isActive', value: 'true', type: 'boolean' }],
      });
      expect(result.success).toBe(true);
    });

    it('should accept custom field with type text', () => {
      const result = secretDataSchema.safeParse({
        value: 'my-secret',
        customFields: [{ name: 'note', value: 'hello', type: 'text' }],
      });
      expect(result.success).toBe(true);
    });

    it('should accept custom field with type hidden', () => {
      const result = secretDataSchema.safeParse({
        value: 'my-secret',
        customFields: [{ name: 'apiKey', value: 'key123', type: 'hidden' }],
      });
      expect(result.success).toBe(true);
    });

    it('should reject custom field with invalid type', () => {
      const result = secretDataSchema.safeParse({
        value: 'my-secret',
        customFields: [{ name: 'test', value: 'val', type: 'invalid' }],
      });
      expect(result.success).toBe(false);
    });
  });

  describe('loginDataSchema allows boolean custom fields', () => {
    it('should accept custom field with type boolean', () => {
      const result = loginDataSchema.safeParse({
        username: 'user',
        password: 'pass',
        customFields: [{ name: 'isActive', value: 'true', type: 'boolean' }],
      });
      expect(result.success).toBe(true);
    });
  });

  describe('both schemas use same custom field types', () => {
    const types = ['text', 'hidden', 'boolean'] as const;

    for (const fieldType of types) {
      it(`loginDataSchema accepts custom field type '${fieldType}'`, () => {
        const result = loginDataSchema.safeParse({
          customFields: [{ name: 'f', value: 'v', type: fieldType }],
        });
        expect(result.success).toBe(true);
      });

      it(`secretDataSchema accepts custom field type '${fieldType}'`, () => {
        const result = secretDataSchema.safeParse({
          customFields: [{ name: 'f', value: 'v', type: fieldType }],
        });
        expect(result.success).toBe(true);
      });
    }
  });
});

// ---------------------------------------------------------------------------
// Task 5.5: Tag validation and max length constraints
// ---------------------------------------------------------------------------
describe('Task 5.5 — Tag validation and max length constraints', () => {
  const validItem = {
    itemType: 'login' as const,
    encryptedData: 'abc',
    dataIv: 'iv12345678901234',
    dataTag: 'tag12345678901234567890',
    encryptedName: 'name',
    nameIv: 'iv12345678901234',
    nameTag: 'tag12345678901234567890',
  };

  describe('createVaultItemSchema', () => {
    it('should accept valid tags', () => {
      const result = createVaultItemSchema.safeParse({
        ...validItem,
        tags: ['work', 'personal'],
      });
      expect(result.success).toBe(true);
    });

    it('should reject empty string tags', () => {
      const result = createVaultItemSchema.safeParse({
        ...validItem,
        tags: [''],
      });
      expect(result.success).toBe(false);
    });

    it('should reject tags exceeding 50 characters', () => {
      const result = createVaultItemSchema.safeParse({
        ...validItem,
        tags: ['a'.repeat(51)],
      });
      expect(result.success).toBe(false);
    });

    it('should accept tag at exactly 50 characters', () => {
      const result = createVaultItemSchema.safeParse({
        ...validItem,
        tags: ['a'.repeat(50)],
      });
      expect(result.success).toBe(true);
    });

    it('should reject more than 20 tags', () => {
      const tags = Array.from({ length: 21 }, (_, i) => `tag${i}`);
      const result = createVaultItemSchema.safeParse({
        ...validItem,
        tags,
      });
      expect(result.success).toBe(false);
    });

    it('should accept exactly 20 tags', () => {
      const tags = Array.from({ length: 20 }, (_, i) => `tag${i}`);
      const result = createVaultItemSchema.safeParse({
        ...validItem,
        tags,
      });
      expect(result.success).toBe(true);
    });

    it('should trim whitespace from tags', () => {
      const result = createVaultItemSchema.safeParse({
        ...validItem,
        tags: ['  work  ', '  personal  '],
      });
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.tags).toEqual(['work', 'personal']);
      }
    });

    it('should reject whitespace-only tags (empty after trim)', () => {
      const result = createVaultItemSchema.safeParse({
        ...validItem,
        tags: ['   '],
      });
      expect(result.success).toBe(false);
    });

    it('should default to empty array', () => {
      const result = createVaultItemSchema.safeParse(validItem);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.tags).toEqual([]);
      }
    });
  });

  describe('updateVaultItemSchema', () => {
    it('should reject empty string tags in updates', () => {
      const result = updateVaultItemSchema.safeParse({ tags: [''] });
      expect(result.success).toBe(false);
    });

    it('should reject tags exceeding 50 chars in updates', () => {
      const result = updateVaultItemSchema.safeParse({
        tags: ['a'.repeat(51)],
      });
      expect(result.success).toBe(false);
    });

    it('should reject more than 20 tags in updates', () => {
      const tags = Array.from({ length: 21 }, (_, i) => `tag${i}`);
      const result = updateVaultItemSchema.safeParse({ tags });
      expect(result.success).toBe(false);
    });

    it('should allow omitting tags (optional)', () => {
      const result = updateVaultItemSchema.safeParse({ favorite: true });
      expect(result.success).toBe(true);
    });
  });
});

// ---------------------------------------------------------------------------
// Task 5.6: Replace hardcoded enums with constants
// ---------------------------------------------------------------------------
describe('Task 5.6 — Schemas use constants for enum values', () => {
  const validItem = {
    itemType: 'login' as const,
    encryptedData: 'abc',
    dataIv: 'iv12345678901234',
    dataTag: 'tag12345678901234567890',
    encryptedName: 'name',
    nameIv: 'iv12345678901234',
    nameTag: 'tag12345678901234567890',
  };

  describe('vault schemas accept all ITEM_TYPES', () => {
    for (const itemType of ITEM_TYPES) {
      it(`createVaultItemSchema accepts itemType '${itemType}'`, () => {
        const result = createVaultItemSchema.safeParse({
          ...validItem,
          itemType,
        });
        expect(result.success).toBe(true);
      });

      it(`listVaultItemsSchema accepts itemType '${itemType}'`, () => {
        const result = listVaultItemsSchema.safeParse({ itemType });
        expect(result.success).toBe(true);
      });
    }

    it('should reject an invalid item type', () => {
      const result = createVaultItemSchema.safeParse({
        ...validItem,
        itemType: 'unknown',
      });
      expect(result.success).toBe(false);
    });
  });

  describe('updateSettingsSchema accepts all THEMES', () => {
    for (const theme of THEMES) {
      it(`accepts theme '${theme}'`, () => {
        const result = updateSettingsSchema.safeParse({ theme });
        expect(result.success).toBe(true);
      });
    }

    it('should reject an invalid theme', () => {
      const result = updateSettingsSchema.safeParse({ theme: 'neon' });
      expect(result.success).toBe(false);
    });
  });

  describe('auditLogQuerySchema accepts all AUDIT_ACTIONS', () => {
    for (const action of AUDIT_ACTIONS) {
      it(`accepts action '${action}'`, () => {
        const result = auditLogQuerySchema.safeParse({ action });
        expect(result.success).toBe(true);
      });
    }

    it('should reject an invalid action', () => {
      const result = auditLogQuerySchema.safeParse({ action: 'invalid_action' });
      expect(result.success).toBe(false);
    });
  });

  describe('noteDataSchema uses NOTE_FORMATS constant', () => {
    it('accepts markdown format', () => {
      const result = noteDataSchema.safeParse({ content: 'hello', format: 'markdown' });
      expect(result.success).toBe(true);
    });

    it('accepts plaintext format', () => {
      const result = noteDataSchema.safeParse({ content: 'hello', format: 'plaintext' });
      expect(result.success).toBe(true);
    });

    it('rejects invalid format', () => {
      const result = noteDataSchema.safeParse({ content: 'hello', format: 'html' });
      expect(result.success).toBe(false);
    });
  });
});

// ---------------------------------------------------------------------------
// Task 5.7: Utility function edge cases
// ---------------------------------------------------------------------------
describe('Task 5.7 — Utility function edge cases', () => {
  describe('generateId', () => {
    it('should return a non-empty string', () => {
      const id = generateId();
      expect(id.length).toBeGreaterThan(0);
    });

    it('should return unique values', () => {
      const ids = new Set(Array.from({ length: 100 }, () => generateId()));
      expect(ids.size).toBe(100);
    });

    it('should return a hex string (no Math.random base-36)', () => {
      const id = generateId();
      expect(id).toMatch(/^[a-f0-9]+$/);
    });
  });

  describe('maskEmail', () => {
    it('should mask a normal email', () => {
      expect(maskEmail('john@example.com')).toBe('j***n@example.com');
    });

    it('should handle single-character local part', () => {
      expect(maskEmail('a@example.com')).toBe('a***@example.com');
    });

    it('should handle two-character local part', () => {
      expect(maskEmail('ab@example.com')).toBe('a***b@example.com');
    });

    it('should handle multiple @ signs using lastIndexOf', () => {
      const result = maskEmail('user@org@example.com');
      expect(result).toBe('u***g@example.com');
    });

    it('should return *** for email without @', () => {
      expect(maskEmail('noemail')).toBe('***');
    });

    it('should return *** for email starting with @', () => {
      expect(maskEmail('@domain.com')).toBe('***');
    });

    it('should return *** for empty string', () => {
      expect(maskEmail('')).toBe('***');
    });
  });

  describe('formatBytes', () => {
    it('should return 0 B for zero', () => {
      expect(formatBytes(0)).toBe('0 B');
    });

    it('should format bytes', () => {
      expect(formatBytes(500)).toBe('500 B');
    });

    it('should format kilobytes', () => {
      expect(formatBytes(1024)).toBe('1 KB');
    });

    it('should format megabytes', () => {
      expect(formatBytes(1048576)).toBe('1 MB');
    });

    it('should format gigabytes', () => {
      expect(formatBytes(1073741824)).toBe('1 GB');
    });

    it('should format terabytes', () => {
      expect(formatBytes(1099511627776)).toBe('1 TB');
    });

    it('should handle negative numbers', () => {
      expect(formatBytes(-1024)).toBe('0 B');
    });

    it('should handle negative megabytes', () => {
      expect(formatBytes(-5242880)).toBe('0 B');
    });

    it('should handle NaN', () => {
      expect(formatBytes(NaN)).toBe('0 B');
    });

    it('should handle Infinity', () => {
      expect(formatBytes(Infinity)).toBe('0 B');
    });

    it('should handle very large values (beyond TB)', () => {
      const petabyte = 1099511627776 * 1024;
      const result = formatBytes(petabyte);
      expect(result).toBe('1024 TB');
    });
  });
});

// ---------------------------------------------------------------------------
// Task 5.8: searchHash format validation
// ---------------------------------------------------------------------------
describe('Task 5.8 — searchHash format validation', () => {
  const validItem = {
    itemType: 'login' as const,
    encryptedData: 'abc',
    dataIv: 'iv12345678901234',
    dataTag: 'tag12345678901234567890',
    encryptedName: 'name',
    nameIv: 'iv12345678901234',
    nameTag: 'tag12345678901234567890',
  };
  const validHash = 'a'.repeat(64);

  describe('createVaultItemSchema', () => {
    it('should accept a valid 64-char hex searchHash', () => {
      const result = createVaultItemSchema.safeParse({
        ...validItem,
        searchHash: validHash,
      });
      expect(result.success).toBe(true);
    });

    it('should accept omitted searchHash', () => {
      const result = createVaultItemSchema.safeParse(validItem);
      expect(result.success).toBe(true);
    });

    it('should reject searchHash shorter than 64 chars', () => {
      const result = createVaultItemSchema.safeParse({
        ...validItem,
        searchHash: 'a'.repeat(63),
      });
      expect(result.success).toBe(false);
    });

    it('should reject searchHash longer than 64 chars', () => {
      const result = createVaultItemSchema.safeParse({
        ...validItem,
        searchHash: 'a'.repeat(65),
      });
      expect(result.success).toBe(false);
    });

    it('should reject searchHash with uppercase hex', () => {
      const result = createVaultItemSchema.safeParse({
        ...validItem,
        searchHash: 'A'.repeat(64),
      });
      expect(result.success).toBe(false);
    });

    it('should reject searchHash with non-hex characters', () => {
      const result = createVaultItemSchema.safeParse({
        ...validItem,
        searchHash: 'g'.repeat(64),
      });
      expect(result.success).toBe(false);
    });

    it('should accept a real HMAC-SHA256 hex hash', () => {
      const result = createVaultItemSchema.safeParse({
        ...validItem,
        searchHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      });
      expect(result.success).toBe(true);
    });
  });

  describe('updateVaultItemSchema', () => {
    it('should accept a valid searchHash in updates', () => {
      const result = updateVaultItemSchema.safeParse({
        searchHash: validHash,
      });
      expect(result.success).toBe(true);
    });

    it('should reject invalid searchHash in updates', () => {
      const result = updateVaultItemSchema.safeParse({
        searchHash: 'not-a-valid-hash',
      });
      expect(result.success).toBe(false);
    });

    it('should allow omitting searchHash in updates', () => {
      const result = updateVaultItemSchema.safeParse({
        favorite: true,
      });
      expect(result.success).toBe(true);
    });
  });
});

// ---------------------------------------------------------------------------
// Phase 5 — Schema & Type fixes
// ---------------------------------------------------------------------------

describe('Task 5.2 — identityDataSchema includes company field', () => {
  it('should accept identity data with optional company', () => {
    const result = identityDataSchema.safeParse({
      firstName: 'John',
      lastName: 'Doe',
      company: 'Acme Corp',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.company).toBe('Acme Corp');
    }
  });

  it('should accept identity data without company', () => {
    const result = identityDataSchema.safeParse({
      firstName: 'John',
      lastName: 'Doe',
    });
    expect(result.success).toBe(true);
  });
});

describe('Task 5.5 — paginationSchema uses PAGINATION_DEFAULTS', () => {
  it('should default page to PAGINATION_DEFAULTS.PAGE', () => {
    const result = paginationSchema.safeParse({});
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.page).toBe(PAGINATION_DEFAULTS.PAGE);
    }
  });

  it('should default limit to PAGINATION_DEFAULTS.LIMIT', () => {
    const result = paginationSchema.safeParse({});
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.limit).toBe(PAGINATION_DEFAULTS.LIMIT);
    }
  });

  it('should reject limit exceeding PAGINATION_DEFAULTS.MAX_LIMIT', () => {
    const result = paginationSchema.safeParse({
      limit: PAGINATION_DEFAULTS.MAX_LIMIT + 1,
    });
    expect(result.success).toBe(false);
  });

  it('should accept limit at exactly PAGINATION_DEFAULTS.MAX_LIMIT', () => {
    const result = paginationSchema.safeParse({
      limit: PAGINATION_DEFAULTS.MAX_LIMIT,
    });
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Task 6.11: passwordHistory array max length constraint
// ---------------------------------------------------------------------------
describe('Task 6.11 — passwordHistory array max length (10)', () => {
  it('should accept passwordHistory with 10 entries', () => {
    const entries = Array.from({ length: 10 }, (_, i) => ({
      encryptedPassword: `enc${i}`,
      iv: 'iv12345678901234',
      tag: 'tag12345678901234567890',
      changedAt: new Date().toISOString(),
    }));
    const result = updateVaultItemSchema.safeParse({ passwordHistory: entries });
    expect(result.success).toBe(true);
  });

  it('should reject passwordHistory with more than 10 entries', () => {
    const entries = Array.from({ length: 11 }, (_, i) => ({
      encryptedPassword: `enc${i}`,
      iv: 'iv12345678901234',
      tag: 'tag12345678901234567890',
      changedAt: new Date().toISOString(),
    }));
    const result = updateVaultItemSchema.safeParse({ passwordHistory: entries });
    expect(result.success).toBe(false);
  });

  it('should allow omitting passwordHistory', () => {
    const result = updateVaultItemSchema.safeParse({ favorite: true });
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Task 6.13: deleteFolderQuerySchema validation
// ---------------------------------------------------------------------------
describe('Task 6.13 — deleteFolderQuerySchema validates action param', () => {
  it('should accept action=move', () => {
    const result = deleteFolderQuerySchema.safeParse({ action: 'move' });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.action).toBe('move');
    }
  });

  it('should accept action=delete', () => {
    const result = deleteFolderQuerySchema.safeParse({ action: 'delete' });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.action).toBe('delete');
    }
  });

  it('should default to move when action is omitted', () => {
    const result = deleteFolderQuerySchema.safeParse({});
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.action).toBe('move');
    }
  });

  it('should reject invalid action values', () => {
    const result = deleteFolderQuerySchema.safeParse({ action: 'invalid' });
    expect(result.success).toBe(false);
  });
});
