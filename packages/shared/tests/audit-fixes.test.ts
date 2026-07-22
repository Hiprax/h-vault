/**
 * Tests for shared package fix tasks from the comprehensive audit.
 *
 * Covers:
 * - Task 3.2: passwordHistory schema min(1) enforcement
 * - Task 3.3: identityDataSchema includes customFields
 * - Task 3.16: Token fields have max(2000) length
 * - Task 3.17: csvMapping max 50 keys
 * - Task 4.1: formatBytes edge cases (NaN, Infinity, negative)
 * - Task 4.2: ResendVerificationInput type exists
 * - Task 4.3: Named constants (MAX_FOLDER_NESTING_DEPTH, MAX_IMPORT_ITEMS, AUTH_TAG_BYTES)
 */
import { describe, it, expect } from 'vitest';
import {
  login2faSchema,
  verifyEmailSchema,
  resetPasswordSchema,
  unlockAccountSchema,
} from '../src/schemas/auth.js';
import { updateVaultItemSchema, identityDataSchema } from '../src/schemas/vault.js';
import { importSchema } from '../src/schemas/user.js';
import { formatBytes } from '../src/utils/index.js';
import {
  MAX_FOLDER_NESTING_DEPTH,
  MAX_IMPORT_ITEMS,
  MAX_SESSIONS,
  AUTH_TAG_BYTES,
  AUDIT_ACTIONS,
} from '../src/constants/index.js';

// ---------------------------------------------------------------------------
// Task 3.2: passwordHistory schema min(1) enforcement
// ---------------------------------------------------------------------------
describe('Task 3.2: passwordHistory min(1) validation', () => {
  it('should reject empty encryptedPassword in passwordHistory', () => {
    const result = updateVaultItemSchema.safeParse({
      passwordHistory: [
        {
          encryptedPassword: '',
          iv: 'iv-value',
          tag: 'tag-value',
          changedAt: '2025-01-15T10:30:00Z',
        },
      ],
    });
    expect(result.success).toBe(false);
  });

  it('should reject empty iv in passwordHistory', () => {
    const result = updateVaultItemSchema.safeParse({
      passwordHistory: [
        {
          encryptedPassword: 'encrypted',
          iv: '',
          tag: 'tag-value',
          changedAt: '2025-01-15T10:30:00Z',
        },
      ],
    });
    expect(result.success).toBe(false);
  });

  it('should reject empty tag in passwordHistory', () => {
    const result = updateVaultItemSchema.safeParse({
      passwordHistory: [
        {
          encryptedPassword: 'encrypted',
          iv: 'iv-value',
          tag: '',
          changedAt: '2025-01-15T10:30:00Z',
        },
      ],
    });
    expect(result.success).toBe(false);
  });

  it('should accept non-empty encryption fields', () => {
    const result = updateVaultItemSchema.safeParse({
      passwordHistory: [
        {
          encryptedPassword: 'enc',
          iv: 'i',
          tag: 't',
          changedAt: '2025-01-15T10:30:00Z',
        },
      ],
    });
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Task 3.3: identityDataSchema includes customFields
// ---------------------------------------------------------------------------
describe('Task 3.3: identityDataSchema customFields', () => {
  it('should accept identity data with customFields', () => {
    const result = identityDataSchema.safeParse({
      firstName: 'John',
      lastName: 'Doe',
      customFields: [{ name: 'Nickname', value: 'JD', type: 'text' }],
    });
    expect(result.success).toBe(true);
  });

  it('should default customFields to empty array', () => {
    const result = identityDataSchema.parse({ firstName: 'John', lastName: 'Doe' });
    expect(result.customFields).toEqual([]);
  });

  it('should accept identity without customFields', () => {
    const result = identityDataSchema.safeParse({
      firstName: 'John',
    });
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Task 3.16: Token fields max(2000) length
// ---------------------------------------------------------------------------
describe('Task 3.16: Token fields max length', () => {
  it('login2faSchema rejects tempToken over 2000 chars', () => {
    const result = login2faSchema.safeParse({
      tempToken: 'a'.repeat(2001),
      code: '123456',
    });
    expect(result.success).toBe(false);
  });

  it('login2faSchema accepts tempToken at 2000 chars', () => {
    const result = login2faSchema.safeParse({
      tempToken: 'a'.repeat(2000),
      code: '123456',
    });
    expect(result.success).toBe(true);
  });

  it('verifyEmailSchema rejects token over 2000 chars', () => {
    const result = verifyEmailSchema.safeParse({
      token: 'a'.repeat(2001),
    });
    expect(result.success).toBe(false);
  });

  it('resetPasswordSchema rejects token over 2000 chars', () => {
    const result = resetPasswordSchema.safeParse({
      token: 'a'.repeat(2001),
      newAuthHash: 'hash',
      newEncryptedVaultKey: 'key',
      newVaultKeyIv: 'iv',
      newVaultKeyTag: 'tag',
    });
    expect(result.success).toBe(false);
  });

  it('unlockAccountSchema rejects token over 2000 chars', () => {
    const result = unlockAccountSchema.safeParse({
      token: 'a'.repeat(2001),
    });
    expect(result.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Task 3.17 (revised): import is zero-knowledge — csvMapping is no longer part
// of the wire schema. Column mapping happens client-side before encryption, and
// the server receives only already-encrypted items. A legacy csvMapping field is
// silently stripped rather than validated.
// ---------------------------------------------------------------------------
describe('importSchema no longer carries csvMapping', () => {
  it('strips a legacy csvMapping field of any size', () => {
    const mapping: Record<string, string> = {};
    for (let i = 0; i < 60; i++) {
      mapping[`key${i}`] = `val${i}`;
    }
    const result = importSchema.safeParse({
      format: 'csv',
      operations: {
        inserts: [
          {
            itemType: 'login',
            encryptedName: 'enc-name',
            nameIv: 'name-iv',
            nameTag: 'name-tag',
            encryptedData: 'enc-data',
            dataIv: 'data-iv',
            dataTag: 'data-tag',
            searchHash: 'a'.repeat(64),
          },
        ],
      },
      csvMapping: mapping,
    });
    expect(result.success).toBe(true);
    expect(result.success && 'csvMapping' in result.data).toBe(false);
  });

  it('strips a legacy csvMapping alongside the operations shape', () => {
    // The `operations` contract must preserve the same top-level strip behavior:
    // an unknown wire field never reaches the controller.
    const result = importSchema.safeParse({
      format: 'csv',
      operations: {
        inserts: [
          {
            itemType: 'login',
            encryptedName: 'enc-name',
            nameIv: 'name-iv',
            nameTag: 'name-tag',
            encryptedData: 'enc-data',
            dataIv: 'data-iv',
            dataTag: 'data-tag',
            searchHash: 'a'.repeat(64),
          },
        ],
      },
      csvMapping: { name: 'col1' },
    });
    expect(result.success).toBe(true);
    expect(result.success && 'csvMapping' in result.data).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Task 4.1: formatBytes edge cases
// ---------------------------------------------------------------------------
describe('Task 4.1: formatBytes edge cases', () => {
  it('should return "0 B" for NaN', () => {
    expect(formatBytes(NaN)).toBe('0 B');
  });

  it('should return "0 B" for Infinity', () => {
    expect(formatBytes(Infinity)).toBe('0 B');
  });

  it('should return "0 B" for -Infinity', () => {
    expect(formatBytes(-Infinity)).toBe('0 B');
  });

  it('should return "0 B" for negative numbers', () => {
    expect(formatBytes(-100)).toBe('0 B');
  });

  it('should handle 0 bytes correctly', () => {
    expect(formatBytes(0)).toBe('0 B');
  });

  it('should handle normal values correctly', () => {
    expect(formatBytes(1024)).toBe('1 KB');
    expect(formatBytes(1048576)).toBe('1 MB');
    expect(formatBytes(1536)).toBe('1.5 KB');
  });
});

// ---------------------------------------------------------------------------
// Task 4.3: Named constants exist
// ---------------------------------------------------------------------------
describe('Task 4.3: Named constants', () => {
  it('MAX_FOLDER_NESTING_DEPTH should be 50', () => {
    expect(MAX_FOLDER_NESTING_DEPTH).toBe(50);
  });

  it('MAX_IMPORT_ITEMS should be 10,000', () => {
    expect(MAX_IMPORT_ITEMS).toBe(10_000);
  });

  it('AUTH_TAG_BYTES should be 16', () => {
    expect(AUTH_TAG_BYTES).toBe(16);
  });

  it('MAX_SESSIONS should be 50', () => {
    expect(MAX_SESSIONS).toBe(50);
  });
});

// ---------------------------------------------------------------------------
// Task 2.4: item_restore is in AUDIT_ACTIONS
// ---------------------------------------------------------------------------
describe('Task 2.4: AUDIT_ACTIONS includes item_restore', () => {
  it('should include item_restore in AUDIT_ACTIONS', () => {
    expect((AUDIT_ACTIONS as readonly string[]).includes('item_restore')).toBe(true);
  });
});
