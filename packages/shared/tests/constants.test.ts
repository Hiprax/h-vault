import { describe, it, expect } from 'vitest';
import {
  APP_NAME,
  KDF_ITERATIONS,
  KDF_ALGORITHM,
  ENCRYPTION_VERSION,
  VAULT_KEY_BITS,
  MEK_BITS,
  AUTH_KEY_BITS,
  IV_BYTES,
  SALT_BYTES,
  BCRYPT_ROUNDS,
  REFRESH_TOKEN_EXPIRY_DAYS,
  MAX_SESSIONS,
  MAX_TRUSTED_DEVICES,
  AUTO_LOCK_TIMEOUT_MINUTES,
  CLIPBOARD_CLEAR_SECONDS,
  TRASH_AUTO_PURGE_DAYS,
  MAX_LOGIN_ATTEMPTS,
  LOGIN_RATE_LIMIT_WINDOW_MINUTES,
  LOGIN_RATE_LIMIT_MAX_PER_IP,
  LOGIN_RATE_LIMIT_MAX_PER_ACCOUNT,
  BACKUP_CODES_COUNT,
  DEFAULT_PASSWORD_LENGTH,
  MAX_TAGS_PER_ITEM,
  MAX_BULK_OPERATIONS,
  PASSWORD_HISTORY_MAX,
  LOCKOUT_DURATION_MINUTES,
  AUDIT_LOG_PAGE_LIMIT,
  AUDIT_LOG_MAX_LIMIT,
  ITEM_TYPES,
  THEMES,
  URI_MATCH_TYPES,
  CUSTOM_FIELD_TYPES,
  NOTE_FORMATS,
  AUDIT_ACTIONS,
  BACKUP_STATUSES,
  ERROR_CODES,
  PAGINATION_DEFAULTS,
  MAX_SORT_ORDER,
  MAX_ENCRYPTED_NAME_LENGTH,
  MAX_ENCRYPTED_DATA_LENGTH,
  MAX_NOTE_CONTENT_LENGTH,
  MAX_RESTORE_DATA_LENGTH,
  MAX_IMPORT_DATA_LENGTH,
  MAX_FILE_ENCRYPTION_SIZE_MB,
  FILE_ENCRYPTION_FILE_EXTENSION,
} from '../src/constants/index.js';

// ---------------------------------------------------------------------------
// Security constants
// ---------------------------------------------------------------------------
describe('Security constants', () => {
  it('KDF_ITERATIONS is at least 600,000', () => {
    expect(KDF_ITERATIONS).toBeGreaterThanOrEqual(600_000);
  });

  it('KDF_ALGORITHM is PBKDF2-SHA256', () => {
    expect(KDF_ALGORITHM).toBe('PBKDF2-SHA256');
  });

  it('ENCRYPTION_VERSION is 1', () => {
    expect(ENCRYPTION_VERSION).toBe(1);
  });

  it('VAULT_KEY_BITS is 256', () => {
    expect(VAULT_KEY_BITS).toBe(256);
  });

  it('MEK_BITS is 256', () => {
    expect(MEK_BITS).toBe(256);
  });

  it('AUTH_KEY_BITS is 256', () => {
    expect(AUTH_KEY_BITS).toBe(256);
  });

  it('IV_BYTES is 12', () => {
    expect(IV_BYTES).toBe(12);
  });

  it('SALT_BYTES is 32', () => {
    expect(SALT_BYTES).toBe(32);
  });

  it('BCRYPT_ROUNDS is 12', () => {
    expect(BCRYPT_ROUNDS).toBe(12);
  });
});

// ---------------------------------------------------------------------------
// Auth & session constants
// ---------------------------------------------------------------------------
describe('Auth & session constants', () => {
  it('REFRESH_TOKEN_EXPIRY_DAYS is 7', () => {
    expect(REFRESH_TOKEN_EXPIRY_DAYS).toBe(7);
  });

  it('MAX_SESSIONS is 50', () => {
    expect(MAX_SESSIONS).toBe(50);
  });

  it('MAX_TRUSTED_DEVICES is 10', () => {
    expect(MAX_TRUSTED_DEVICES).toBe(10);
  });

  it('AUTO_LOCK_TIMEOUT_MINUTES is 15', () => {
    expect(AUTO_LOCK_TIMEOUT_MINUTES).toBe(15);
  });

  it('CLIPBOARD_CLEAR_SECONDS is 30', () => {
    expect(CLIPBOARD_CLEAR_SECONDS).toBe(30);
  });

  it('MAX_LOGIN_ATTEMPTS is 10', () => {
    expect(MAX_LOGIN_ATTEMPTS).toBe(10);
  });

  it('LOCKOUT_DURATION_MINUTES is 30', () => {
    expect(LOCKOUT_DURATION_MINUTES).toBe(30);
  });
});

// ---------------------------------------------------------------------------
// App constants
// ---------------------------------------------------------------------------
describe('App constants', () => {
  it('APP_NAME is H-Vault', () => {
    expect(APP_NAME).toBe('H-Vault');
  });

  it('TRASH_AUTO_PURGE_DAYS is 30', () => {
    expect(TRASH_AUTO_PURGE_DAYS).toBe(30);
  });

  it('BACKUP_CODES_COUNT is 8', () => {
    expect(BACKUP_CODES_COUNT).toBe(8);
  });

  it('DEFAULT_PASSWORD_LENGTH is 20', () => {
    expect(DEFAULT_PASSWORD_LENGTH).toBe(20);
  });

  it('MAX_TAGS_PER_ITEM is 20', () => {
    expect(MAX_TAGS_PER_ITEM).toBe(20);
  });

  it('MAX_BULK_OPERATIONS is 100', () => {
    expect(MAX_BULK_OPERATIONS).toBe(100);
  });

  it('PASSWORD_HISTORY_MAX is 10', () => {
    expect(PASSWORD_HISTORY_MAX).toBe(10);
  });
});

// ---------------------------------------------------------------------------
// Schema limit constants
// ---------------------------------------------------------------------------
describe('Schema limit constants', () => {
  it('MAX_SORT_ORDER is 10,000', () => {
    expect(MAX_SORT_ORDER).toBe(10_000);
  });

  it('MAX_ENCRYPTED_NAME_LENGTH is 1,000', () => {
    expect(MAX_ENCRYPTED_NAME_LENGTH).toBe(1_000);
  });

  it('MAX_ENCRYPTED_DATA_LENGTH is 500,000', () => {
    expect(MAX_ENCRYPTED_DATA_LENGTH).toBe(500_000);
  });

  it('MAX_NOTE_CONTENT_LENGTH is 50,000', () => {
    expect(MAX_NOTE_CONTENT_LENGTH).toBe(50_000);
  });

  it('MAX_RESTORE_DATA_LENGTH is 26,214,400 (25 MB)', () => {
    expect(MAX_RESTORE_DATA_LENGTH).toBe(26_214_400);
  });

  it('MAX_IMPORT_DATA_LENGTH is 1,048,576 (1 MB)', () => {
    expect(MAX_IMPORT_DATA_LENGTH).toBe(1_048_576);
  });
});

// ---------------------------------------------------------------------------
// File Encryption tool constants
// ---------------------------------------------------------------------------
describe('File Encryption constants', () => {
  it('MAX_FILE_ENCRYPTION_SIZE_MB is 100', () => {
    expect(MAX_FILE_ENCRYPTION_SIZE_MB).toBe(100);
  });

  it('FILE_ENCRYPTION_FILE_EXTENSION is .enc', () => {
    expect(FILE_ENCRYPTION_FILE_EXTENSION).toBe('.enc');
  });
});

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------
describe('Pagination defaults', () => {
  it('defaults are correct', () => {
    expect(PAGINATION_DEFAULTS.PAGE).toBe(1);
    expect(PAGINATION_DEFAULTS.LIMIT).toBe(50);
    expect(PAGINATION_DEFAULTS.MAX_LIMIT).toBe(200);
  });

  it('AUDIT_LOG_PAGE_LIMIT is 20', () => {
    expect(AUDIT_LOG_PAGE_LIMIT).toBe(20);
  });

  it('AUDIT_LOG_MAX_LIMIT is 100', () => {
    expect(AUDIT_LOG_MAX_LIMIT).toBe(100);
  });
});

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------
describe('Rate limiting constants', () => {
  it('LOGIN_RATE_LIMIT_WINDOW_MINUTES is 15', () => {
    expect(LOGIN_RATE_LIMIT_WINDOW_MINUTES).toBe(15);
  });

  it('LOGIN_RATE_LIMIT_MAX_PER_IP is 10', () => {
    expect(LOGIN_RATE_LIMIT_MAX_PER_IP).toBe(10);
  });

  it('LOGIN_RATE_LIMIT_MAX_PER_ACCOUNT is 20', () => {
    expect(LOGIN_RATE_LIMIT_MAX_PER_ACCOUNT).toBe(20);
  });
});

// ---------------------------------------------------------------------------
// Enum arrays
// ---------------------------------------------------------------------------
describe('Enum arrays', () => {
  it('ITEM_TYPES contains all 5 types', () => {
    expect(ITEM_TYPES).toEqual(['login', 'secret', 'note', 'card', 'identity']);
    expect(ITEM_TYPES).toHaveLength(5);
  });

  it('THEMES contains light, dark, system', () => {
    expect(THEMES).toEqual(['light', 'dark', 'system']);
  });

  it('URI_MATCH_TYPES contains all 4 types', () => {
    expect(URI_MATCH_TYPES).toEqual(['domain', 'exact', 'startsWith', 'regex']);
  });

  it('CUSTOM_FIELD_TYPES contains text, hidden, boolean', () => {
    expect(CUSTOM_FIELD_TYPES).toEqual(['text', 'hidden', 'boolean']);
  });

  it('NOTE_FORMATS contains markdown and plaintext', () => {
    expect(NOTE_FORMATS).toEqual(['markdown', 'plaintext']);
  });

  it('BACKUP_STATUSES contains success and failed', () => {
    expect(BACKUP_STATUSES).toEqual(['success', 'failed']);
  });

  it('AUDIT_ACTIONS contains expected actions', () => {
    expect(AUDIT_ACTIONS).toContain('login');
    expect(AUDIT_ACTIONS).toContain('login_failed');
    expect(AUDIT_ACTIONS).toContain('item_create');
    expect(AUDIT_ACTIONS).toContain('backup_triggered');
    expect(AUDIT_ACTIONS).toContain('trash_auto_purge');
    expect(AUDIT_ACTIONS).toContain('2fa_backup_codes_regenerated');
    expect(AUDIT_ACTIONS.length).toBeGreaterThanOrEqual(26);
  });

  it('AUDIT_ACTIONS has exactly 38 distinct operations (keep README in sync)', () => {
    // The README "Audit Logging" feature line documents this exact count
    // ("38 distinct operations"). If a new audit action is added, bump both
    // this assertion and the README number together.
    expect(AUDIT_ACTIONS.length).toBe(38);
    expect(new Set(AUDIT_ACTIONS).size).toBe(AUDIT_ACTIONS.length);
  });

  it('includes the export_plaintext action for browser-side portable exports', () => {
    expect(AUDIT_ACTIONS).toContain('export_plaintext');
  });
});

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------
describe('Error codes', () => {
  it('has all expected error codes', () => {
    expect(ERROR_CODES.VALIDATION_ERROR).toBe('VALIDATION_ERROR');
    expect(ERROR_CODES.INVALID_CREDENTIALS).toBe('INVALID_CREDENTIALS');
    expect(ERROR_CODES.ACCOUNT_LOCKED).toBe('ACCOUNT_LOCKED');
    expect(ERROR_CODES.EMAIL_NOT_VERIFIED).toBe('EMAIL_NOT_VERIFIED');
    expect(ERROR_CODES.TOKEN_EXPIRED).toBe('TOKEN_EXPIRED');
    expect(ERROR_CODES.TOKEN_INVALID).toBe('TOKEN_INVALID');
    expect(ERROR_CODES.TOKEN_REUSE_DETECTED).toBe('TOKEN_REUSE_DETECTED');
    expect(ERROR_CODES.UNAUTHORIZED).toBe('UNAUTHORIZED');
    expect(ERROR_CODES.FORBIDDEN).toBe('FORBIDDEN');
    expect(ERROR_CODES.NOT_FOUND).toBe('NOT_FOUND');
    expect(ERROR_CODES.CONFLICT).toBe('CONFLICT');
    expect(ERROR_CODES.RATE_LIMIT).toBe('RATE_LIMIT');
    expect(ERROR_CODES.TWO_FA_REQUIRED).toBe('TWO_FA_REQUIRED');
    expect(ERROR_CODES.TWO_FA_INVALID).toBe('TWO_FA_INVALID');
    expect(ERROR_CODES.TWO_FA_ALREADY_ENABLED).toBe('TWO_FA_ALREADY_ENABLED');
    expect(ERROR_CODES.TWO_FA_NOT_ENABLED).toBe('TWO_FA_NOT_ENABLED');
    expect(ERROR_CODES.INTERNAL_ERROR).toBe('INTERNAL_ERROR');
    expect(ERROR_CODES.BACKUP_TOO_LARGE).toBe('BACKUP_TOO_LARGE');
    expect(ERROR_CODES.BACKUP_NOT_CONFIGURED).toBe('BACKUP_NOT_CONFIGURED');
    expect(ERROR_CODES.IMPORT_PARSE_ERROR).toBe('IMPORT_PARSE_ERROR');
    expect(ERROR_CODES.ENCRYPTION_ERROR).toBe('ENCRYPTION_ERROR');
    expect(ERROR_CODES.DECRYPTION_ERROR).toBe('DECRYPTION_ERROR');
  });

  it('error code keys match values', () => {
    for (const [key, value] of Object.entries(ERROR_CODES)) {
      expect(key).toBe(value);
    }
  });
});
