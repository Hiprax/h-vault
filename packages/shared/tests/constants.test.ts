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
  AUTO_LOCK_MIN_MINUTES,
  AUTO_LOCK_MAX_MINUTES,
  LOCK_ON_HIDDEN_DEFAULT,
  LOCK_ON_HIDDEN_DELAY_MINUTES,
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
  MAX_LOGIN_BACKUP_CODES,
  MAX_LOGIN_BACKUP_CODE_LENGTH,
  MAX_LOGIN_BACKUP_CODES_INPUT_LENGTH,
  MAX_FILE_ENCRYPTION_SIZE_MB,
  FILE_ENCRYPTION_FILE_EXTENSION,
  MAX_ADDRESS_STREET_LENGTH,
  MAX_ADDRESS_CITY_LENGTH,
  MAX_ADDRESS_STATE_LENGTH,
  MAX_ADDRESS_ZIP_LENGTH,
  MAX_ADDRESS_COUNTRY_LENGTH,
  MAX_ADDRESS_DELIVERY_NOTES_LENGTH,
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
  MAX_IDENTITY_NAME_LENGTH,
  MAX_IDENTITY_EMAIL_LENGTH,
  MAX_IDENTITY_PHONE_LENGTH,
  MAX_IDENTITY_COMPANY_LENGTH,
  MAX_IDENTITY_SSN_LENGTH,
  MAX_IDENTITY_PASSPORT_LENGTH,
} from '../src/constants/index.js';
import {
  cardDataSchema,
  identityDataSchema,
  isValidIdentityEmail,
  isValidIdentityPhone,
  loginDataSchema,
  secretDataSchema,
} from '../src/schemas/vault.js';

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
// Login backup-code constants
// ---------------------------------------------------------------------------
describe('Login backup-code constants', () => {
  it('MAX_LOGIN_BACKUP_CODES is 50', () => {
    expect(MAX_LOGIN_BACKUP_CODES).toBe(50);
  });

  it('MAX_LOGIN_BACKUP_CODE_LENGTH is 128', () => {
    expect(MAX_LOGIN_BACKUP_CODE_LENGTH).toBe(128);
  });

  it('MAX_LOGIN_BACKUP_CODES_INPUT_LENGTH is 20,000', () => {
    expect(MAX_LOGIN_BACKUP_CODES_INPUT_LENGTH).toBe(20_000);
  });

  it('is independent of the account-level BACKUP_CODES_COUNT', () => {
    // Two unrelated features. BACKUP_CODES_COUNT is how many codes H-Vault mints
    // for its OWN account 2FA; MAX_LOGIN_BACKUP_CODES is how many a login item may
    // store for a third-party account.
    expect(BACKUP_CODES_COUNT).toBe(8);
    expect(MAX_LOGIN_BACKUP_CODES).not.toBe(BACKUP_CODES_COUNT);
  });

  it('bounds one paste well above the largest legitimate one', () => {
    // Six characters per code covers array quoting plus a separator, so this is the
    // worst legitimate paste; the ceiling must clear it with room to spare rather
    // than being a magic number.
    expect(MAX_LOGIN_BACKUP_CODES_INPUT_LENGTH).toBeGreaterThan(
      MAX_LOGIN_BACKUP_CODES * (MAX_LOGIN_BACKUP_CODE_LENGTH + 6),
    );
  });
});

// ---------------------------------------------------------------------------
// Postal-address constants
// ---------------------------------------------------------------------------
describe('Postal-address constants', () => {
  it('MAX_ADDRESS_STREET_LENGTH is 500', () => {
    expect(MAX_ADDRESS_STREET_LENGTH).toBe(500);
  });

  it('MAX_ADDRESS_CITY_LENGTH is 200', () => {
    expect(MAX_ADDRESS_CITY_LENGTH).toBe(200);
  });

  it('MAX_ADDRESS_STATE_LENGTH is 200', () => {
    expect(MAX_ADDRESS_STATE_LENGTH).toBe(200);
  });

  it('MAX_ADDRESS_ZIP_LENGTH is 20', () => {
    expect(MAX_ADDRESS_ZIP_LENGTH).toBe(20);
  });

  it('MAX_ADDRESS_COUNTRY_LENGTH is 100', () => {
    expect(MAX_ADDRESS_COUNTRY_LENGTH).toBe(100);
  });

  it('MAX_ADDRESS_DELIVERY_NOTES_LENGTH is 1,000', () => {
    expect(MAX_ADDRESS_DELIVERY_NOTES_LENGTH).toBe(1_000);
  });

  it('gives both street lines the same bound', () => {
    // They are the WHATWG address-line1/address-line2 peers and hold the same kind
    // of value, so one number serves both; two could only drift apart.
    const shape = cardDataSchema.parse({ billingAddress: {} }).billingAddress;
    expect(shape).toBeDefined();
    expect(
      cardDataSchema.safeParse({
        billingAddress: { street: 'a'.repeat(MAX_ADDRESS_STREET_LENGTH) },
      }).success,
    ).toBe(true);
    expect(
      cardDataSchema.safeParse({
        billingAddress: { street2: 'a'.repeat(MAX_ADDRESS_STREET_LENGTH) },
      }).success,
    ).toBe(true);
  });

  it('lets delivery notes hold more than a courier will transmit', () => {
    // Amazon's Shipping API caps its own `deliveryNotes` at 250 characters for
    // transmission to a driver's device. This is the user's stored copy, which they
    // paste into whatever checkout form is in front of them, so it must not be the
    // binding limit.
    expect(MAX_ADDRESS_DELIVERY_NOTES_LENGTH).toBeGreaterThan(250);
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

  it('LOGIN_RATE_LIMIT_MAX_PER_IP is 20', () => {
    expect(LOGIN_RATE_LIMIT_MAX_PER_IP).toBe(20);
  });

  it('LOGIN_RATE_LIMIT_MAX_PER_ACCOUNT is 20', () => {
    expect(LOGIN_RATE_LIMIT_MAX_PER_ACCOUNT).toBe(20);
  });

  it('the per-IP budget covers several complete 2FA sign-ins', () => {
    // A 2FA sign-in costs two slots (`/auth/login` then `/auth/login/2fa`), so the
    // ceiling has to be comfortably more than twice a plausible number of people
    // behind one address. This is the constraint the number was chosen against —
    // pinning only the literal above would not notice if the ratio stopped making
    // sense.
    const SLOTS_PER_2FA_SIGN_IN = 2;
    expect(LOGIN_RATE_LIMIT_MAX_PER_IP / SLOTS_PER_2FA_SIGN_IN).toBeGreaterThanOrEqual(10);
  });

  it('the per-IP budget is not looser than the per-account one', () => {
    // Per-email counting is the precise anti-guessing control and must stay at
    // least as tight; an IP ceiling below it would make the per-account limiter
    // unreachable and therefore dead.
    expect(LOGIN_RATE_LIMIT_MAX_PER_ACCOUNT).toBeLessThanOrEqual(LOGIN_RATE_LIMIT_MAX_PER_IP);
  });
});

// ---------------------------------------------------------------------------
// Auto-lock
// ---------------------------------------------------------------------------
describe('Auto-lock constants', () => {
  it('AUTO_LOCK_MIN_MINUTES is 1 and AUTO_LOCK_MAX_MINUTES is 1440', () => {
    expect(AUTO_LOCK_MIN_MINUTES).toBe(1);
    expect(AUTO_LOCK_MAX_MINUTES).toBe(1440);
  });

  it('the default timeout sits inside its own bounds', () => {
    expect(AUTO_LOCK_TIMEOUT_MINUTES).toBeGreaterThanOrEqual(AUTO_LOCK_MIN_MINUTES);
    expect(AUTO_LOCK_TIMEOUT_MINUTES).toBeLessThanOrEqual(AUTO_LOCK_MAX_MINUTES);
  });

  it('hidden-tab locking is OFF by default', () => {
    // Deliberate, and a behaviour change: it used to be unconditional and pinned
    // to a flat 30 seconds, so briefly switching tabs locked the vault regardless
    // of the timeout the user had configured. The idle timeout governs on its own
    // now unless the user opts in.
    expect(LOCK_ON_HIDDEN_DEFAULT).toBe(false);
  });

  it('the hidden-lock delay default sits inside the same bounds', () => {
    expect(LOCK_ON_HIDDEN_DELAY_MINUTES).toBeGreaterThanOrEqual(AUTO_LOCK_MIN_MINUTES);
    expect(LOCK_ON_HIDDEN_DELAY_MINUTES).toBeLessThanOrEqual(AUTO_LOCK_MAX_MINUTES);
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

  it('AUDIT_ACTIONS has exactly 41 distinct operations (keep README in sync)', () => {
    // The README "Audit Logging" feature line documents this exact count
    // ("41 distinct operations"). If a new audit action is added, bump both
    // this assertion and the README number together.
    expect(AUDIT_ACTIONS.length).toBe(41);
    expect(new Set(AUDIT_ACTIONS).size).toBe(AUDIT_ACTIONS.length);
  });

  it('includes the trusted-device audit actions', () => {
    expect(AUDIT_ACTIONS).toContain('trusted_device_grant');
    expect(AUDIT_ACTIONS).toContain('trusted_device_revoke');
    expect(AUDIT_ACTIONS).toContain('trusted_device_rejected');
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

// ---------------------------------------------------------------------------
// Per-field item-data bounds
//
// Each of these was an inline literal in `schemas/vault.ts` and, separately, an
// inline literal in `services/import/itemBuilders.ts`. They are now one named
// constant used by the stored schema, the item form's lenient input schema and the
// import clamp — the same reason the postal-address bounds above are named. An input
// cap looser than the stored cap stores a value the schema later REJECTS, and a
// rejected value degrades the WHOLE item to the "could not be fully decoded" notice.
//
// The assertions pin the VALUES (so a change is deliberate) and, for each one, that
// the stored schema really is bound by it — a constant nothing enforces would be a
// comfortable lie.
// ---------------------------------------------------------------------------
describe('Per-field item-data bounds', () => {
  it.each([
    ['MAX_LOGIN_USERNAME_LENGTH', MAX_LOGIN_USERNAME_LENGTH, 500],
    ['MAX_LOGIN_PASSWORD_LENGTH', MAX_LOGIN_PASSWORD_LENGTH, 10_000],
    ['MAX_LOGIN_TOTP_LENGTH', MAX_LOGIN_TOTP_LENGTH, 500],
    ['MAX_URI_LENGTH', MAX_URI_LENGTH, 2_048],
    ['MAX_URIS_PER_ITEM', MAX_URIS_PER_ITEM, 100],
    ['MAX_CUSTOM_FIELD_NAME_LENGTH', MAX_CUSTOM_FIELD_NAME_LENGTH, 500],
    ['MAX_CUSTOM_FIELDS_PER_ITEM', MAX_CUSTOM_FIELDS_PER_ITEM, 100],
    ['MAX_SECRET_DESCRIPTION_LENGTH', MAX_SECRET_DESCRIPTION_LENGTH, 10_000],
    ['MAX_CARD_CARDHOLDER_NAME_LENGTH', MAX_CARD_CARDHOLDER_NAME_LENGTH, 300],
    ['MAX_CARD_BRAND_LENGTH', MAX_CARD_BRAND_LENGTH, 50],
    ['MAX_IDENTITY_NAME_LENGTH', MAX_IDENTITY_NAME_LENGTH, 200],
    ['MAX_IDENTITY_EMAIL_LENGTH', MAX_IDENTITY_EMAIL_LENGTH, 254],
    ['MAX_IDENTITY_PHONE_LENGTH', MAX_IDENTITY_PHONE_LENGTH, 30],
    ['MAX_IDENTITY_COMPANY_LENGTH', MAX_IDENTITY_COMPANY_LENGTH, 300],
    ['MAX_IDENTITY_SSN_LENGTH', MAX_IDENTITY_SSN_LENGTH, 20],
    ['MAX_IDENTITY_PASSPORT_LENGTH', MAX_IDENTITY_PASSPORT_LENGTH, 50],
  ])('%s is %i', (_name, actual, expected) => {
    expect(actual).toBe(expected);
  });

  it.each([
    ['username', MAX_LOGIN_USERNAME_LENGTH],
    ['password', MAX_LOGIN_PASSWORD_LENGTH],
    ['totp', MAX_LOGIN_TOTP_LENGTH],
    ['notes', MAX_NOTE_CONTENT_LENGTH],
  ])('bounds loginDataSchema.%s at its named constant', (field, max) => {
    expect(loginDataSchema.safeParse({ [field]: 'a'.repeat(max) }).success).toBe(true);
    expect(loginDataSchema.safeParse({ [field]: 'a'.repeat(max + 1) }).success).toBe(false);
  });

  it('bounds secretDataSchema.description at its named constant', () => {
    const at = 'a'.repeat(MAX_SECRET_DESCRIPTION_LENGTH);
    expect(secretDataSchema.safeParse({ description: at }).success).toBe(true);
    expect(secretDataSchema.safeParse({ description: `${at}a` }).success).toBe(false);
  });

  it.each([
    ['cardholderName', MAX_CARD_CARDHOLDER_NAME_LENGTH],
    ['brand', MAX_CARD_BRAND_LENGTH],
  ])('bounds cardDataSchema.%s at its named constant', (field, max) => {
    expect(cardDataSchema.safeParse({ [field]: 'a'.repeat(max) }).success).toBe(true);
    expect(cardDataSchema.safeParse({ [field]: 'a'.repeat(max + 1) }).success).toBe(false);
  });

  it.each([
    ['firstName', MAX_IDENTITY_NAME_LENGTH],
    ['lastName', MAX_IDENTITY_NAME_LENGTH],
    ['company', MAX_IDENTITY_COMPANY_LENGTH],
    ['ssn', MAX_IDENTITY_SSN_LENGTH],
    ['passport', MAX_IDENTITY_PASSPORT_LENGTH],
  ])('bounds identityDataSchema.%s at its named constant', (field, max) => {
    expect(identityDataSchema.safeParse({ [field]: 'a'.repeat(max) }).success).toBe(true);
    expect(identityDataSchema.safeParse({ [field]: 'a'.repeat(max + 1) }).success).toBe(false);
  });

  it('bounds a custom field name and the list length at their named constants', () => {
    const field = (name: string) => ({ name, value: 'v', type: 'text' as const });
    expect(
      loginDataSchema.safeParse({
        customFields: [field('a'.repeat(MAX_CUSTOM_FIELD_NAME_LENGTH))],
      }).success,
    ).toBe(true);
    expect(
      loginDataSchema.safeParse({
        customFields: [field('a'.repeat(MAX_CUSTOM_FIELD_NAME_LENGTH + 1))],
      }).success,
    ).toBe(false);
    const many = (count: number) => Array.from({ length: count }, (_, i) => field(`f${String(i)}`));
    expect(
      loginDataSchema.safeParse({ customFields: many(MAX_CUSTOM_FIELDS_PER_ITEM) }).success,
    ).toBe(true);
    expect(
      loginDataSchema.safeParse({ customFields: many(MAX_CUSTOM_FIELDS_PER_ITEM + 1) }).success,
    ).toBe(false);
  });

  it('bounds the URI list and each URI at their named constants', () => {
    const uri = (value: string) => ({ uri: value, match: 'exact' as const });
    // Measured PRE-transform, which is why `clampUri` exists on the import side.
    expect(
      loginDataSchema.safeParse({ uris: [uri(`https://e.com/${'a'.repeat(MAX_URI_LENGTH - 14)}`)] })
        .success,
    ).toBe(true);
    expect(
      loginDataSchema.safeParse({ uris: [uri(`https://e.com/${'a'.repeat(MAX_URI_LENGTH)}`)] })
        .success,
    ).toBe(false);
    const list = (count: number) =>
      Array.from({ length: count }, (_, i) => uri(`https://e${String(i)}.com`));
    expect(loginDataSchema.safeParse({ uris: list(MAX_URIS_PER_ITEM) }).success).toBe(true);
    expect(loginDataSchema.safeParse({ uris: list(MAX_URIS_PER_ITEM + 1) }).success).toBe(false);
  });

  it('keeps the SSN and passport bounds generous against real formats', () => {
    // A US SSN is 11 characters with its dashes; several states issue longer national
    // identification strings. An ICAO passport number is 9. A cap that is too small
    // silently costs the user a real value; one that is too large costs only bytes.
    expect(MAX_IDENTITY_SSN_LENGTH).toBeGreaterThan(11);
    expect(MAX_IDENTITY_PASSPORT_LENGTH).toBeGreaterThan(9);
  });
});

// ---------------------------------------------------------------------------
// The identity email / phone format predicates
//
// Exported because `VaultItemForm`'s lenient input schema has to enforce the SAME
// predicate: a local check that admits what the stored one rejects lets the value
// through the form, past encryption, and into a blob that fails on the next decrypt,
// degrading the whole identity. The form's old local regexes did exactly that.
// ---------------------------------------------------------------------------
describe('isValidIdentityEmail / isValidIdentityPhone', () => {
  it('accepts an empty string, because the field is optional', () => {
    expect(isValidIdentityEmail('')).toBe(true);
    expect(isValidIdentityPhone('')).toBe(true);
  });

  it.each(['ada@example.com', 'ada+work@sub.example.co.uk'])('accepts the email %s', (value) => {
    expect(isValidIdentityEmail(value)).toBe(true);
  });

  it.each([
    ['consecutive dots in the local part', 'a..b@example.com'],
    ['a leading dot', '.ada@example.com'],
    ['a quoted local part', '"ada"@example.com'],
    ['no TLD', 'ada@example'],
    ['no local part', '@example.com'],
  ])('rejects an email with %s', (_label, value) => {
    expect(isValidIdentityEmail(value)).toBe(false);
  });

  it.each(['5', '+44 20 7946 0958', '(020) 7946-0958', '020.7946.0958'])(
    'accepts the phone %s',
    (value) => {
      expect(isValidIdentityPhone(value)).toBe(true);
    },
  );

  it.each([
    ['a plus sign that is not leading', '12+34'],
    ['no digit at all', '(.)'],
    ['letters', 'call me'],
    ['two leading plus signs', '++44'],
  ])('rejects a phone with %s', (_label, value) => {
    expect(isValidIdentityPhone(value)).toBe(false);
  });

  it('is the SAME predicate identityDataSchema enforces', () => {
    // The alignment asserted rather than assumed: if the schema ever stopped using
    // these functions, a form built on them would drift back out of step.
    for (const value of ['a..b@example.com', 'ada@example.com', '']) {
      expect(identityDataSchema.safeParse({ email: value }).success).toBe(
        isValidIdentityEmail(value),
      );
    }
    for (const value of ['12+34', '+44 20 7946 0958', '']) {
      expect(identityDataSchema.safeParse({ phone: value }).success).toBe(
        isValidIdentityPhone(value),
      );
    }
  });
});
