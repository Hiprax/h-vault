import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
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
  MIN_PASSWORD_LENGTH,
  MAX_PASSWORD_LENGTH,
  MAX_PASSWORD_CLASS_MINIMUM,
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
  MAX_CARD_CVV_LENGTH,
  MAX_CARD_EXP_MONTH_LENGTH,
  MAX_CARD_EXP_YEAR_LENGTH,
  MAX_CARD_NUMBER_LENGTH,
  MAX_IDENTITY_NAME_LENGTH,
  MAX_IDENTITY_EMAIL_LENGTH,
  MAX_IDENTITY_PHONE_LENGTH,
  MAX_IDENTITY_COMPANY_LENGTH,
  MAX_IDENTITY_SSN_LENGTH,
  MAX_IDENTITY_PASSPORT_LENGTH,
  MAX_TAG_LENGTH,
  DOCUMENT_TAG_BYTES,
  DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  DOCUMENT_STREAM_SALT_BYTES,
  DOCUMENT_NONCE_PREFIX_BYTES,
  MAX_DOCUMENTS_PER_ROTATION,
  MAX_DOCUMENTS_PER_USER,
  MAX_DOCUMENT_CHUNK_COUNT,
  MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER,
  MAX_IN_FLIGHT_PART_UPLOADS,
  MAX_IN_FLIGHT_PART_UPLOADS_PER_USER,
  MAX_IN_FLIGHT_LARGE_BODY_REQUESTS,
  MAX_IN_FLIGHT_LARGE_BODY_REQUESTS_PER_USER,
  MIN_SUSTAINED_UPLOAD_BYTES_PER_SECOND,
  MAX_DOCUMENT_NAME_LENGTH,
  MAX_DOCUMENT_MIME_LENGTH,
  MAX_DOCUMENT_EXT_LENGTH,
  MAX_DOCUMENT_NOTE_LENGTH,
  MAX_DOCUMENT_TAGS,
  MAX_DOCUMENT_TIMESTAMP_LENGTH,
  MAX_DOCUMENT_TRANSFORM_LABEL_LENGTH,
  MAX_DOCUMENT_META_JSON_BYTES,
  MAX_ENCRYPTED_DOCUMENT_META_LENGTH,
  MAX_FORMATTABLE_SIZE_BYTES,
  MAX_TRANSFORM_EXCERPT_LENGTH,
  MAX_TRANSFORM_MESSAGE_LENGTH,
  REPAIRABLE_TRANSFORM_SYNTAXES,
  TRANSFORM_SYNTAXES,
  TRANSFORM_SYNTAX_NAMES,
  MAX_PREVIEW_BYTES,
  MAX_PREVIEW_TABLE_CELLS,
  MAX_PREVIEW_TABLE_COLUMNS,
  MAX_PREVIEW_TEXT_LINES,
  PREVIEW_MODES,
  PREVIEW_MODE_NAMES,
  PREVIEW_MAGIC_BYTES,
  DOCUMENT_STREAM_INFO_PREFIX,
  DOCUMENT_META_INFO_PREFIX,
  DOCUMENT_DEK_WRAP_INFO_PREFIX,
} from '../src/constants/index.js';
import {
  cardDataSchema,
  identityDataSchema,
  isValidIdentityEmail,
  isValidIdentityPhone,
  loginDataSchema,
  secretDataSchema,
} from '../src/schemas/vault.js';
import {
  canRepairSyntax,
  previewModeForName,
  transformSyntaxForExtension,
  transformSyntaxForName,
} from '../src/utils/index.js';

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

  it('MIN_PASSWORD_LENGTH and MAX_PASSWORD_LENGTH are the bounds they replaced', () => {
    // These were inline literals in four unlinked places. Naming them must not
    // move them: a different value makes an already-stored length unsavable.
    expect(MIN_PASSWORD_LENGTH).toBe(8);
    expect(MAX_PASSWORD_LENGTH).toBe(128);
    expect(DEFAULT_PASSWORD_LENGTH).toBeGreaterThanOrEqual(MIN_PASSWORD_LENGTH);
    expect(DEFAULT_PASSWORD_LENGTH).toBeLessThanOrEqual(MAX_PASSWORD_LENGTH);
  });

  it('MAX_PASSWORD_CLASS_MINIMUM keeps the generator table small enough to build', () => {
    expect(MAX_PASSWORD_CLASS_MINIMUM).toBe(5);
    // The generator's counting table is (length + 1) x (minimum + 1)^4 states.
    // Measured at 73 ms to build at this size; raising the constant is a
    // deliberate act that has to move this number with it.
    const states = (MAX_PASSWORD_LENGTH + 1) * (MAX_PASSWORD_CLASS_MINIMUM + 1) ** 4;
    expect(states).toBe(167_184);
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
// Document-store constants
//
// The three relationships below are pinned as DERIVATIONS rather than as their
// own literals, because the failure they exist to catch is someone "rounding"
// the plaintext chunk to a whole 8 MiB. That edit looks tidy, passes every
// per-field bound, and silently makes each non-final uploaded part 8 MiB plus 16
// bytes: the parts stop being uniform, and every segment boundary after the first
// is off by a growing multiple of 16 bytes, so the file uploads and then fails to
// decrypt from segment 1 onwards.
// ---------------------------------------------------------------------------
describe('Document-store constants', () => {
  it.each([
    ['DOCUMENT_TAG_BYTES', DOCUMENT_TAG_BYTES, 16],
    ['DOCUMENT_STREAM_SALT_BYTES', DOCUMENT_STREAM_SALT_BYTES, 32],
    ['DOCUMENT_NONCE_PREFIX_BYTES', DOCUMENT_NONCE_PREFIX_BYTES, 7],
    ['MAX_DOCUMENTS_PER_USER', MAX_DOCUMENTS_PER_USER, 5_000],
    ['MAX_DOCUMENTS_PER_ROTATION', MAX_DOCUMENTS_PER_ROTATION, 5_003],
    ['MAX_DOCUMENT_CHUNK_COUNT', MAX_DOCUMENT_CHUNK_COUNT, 10_000],
    ['MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER', MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER, 3],
    ['MAX_IN_FLIGHT_PART_UPLOADS', MAX_IN_FLIGHT_PART_UPLOADS, 4],
    ['MAX_IN_FLIGHT_PART_UPLOADS_PER_USER', MAX_IN_FLIGHT_PART_UPLOADS_PER_USER, 3],
    ['MAX_IN_FLIGHT_LARGE_BODY_REQUESTS', MAX_IN_FLIGHT_LARGE_BODY_REQUESTS, 2],
    ['MAX_IN_FLIGHT_LARGE_BODY_REQUESTS_PER_USER', MAX_IN_FLIGHT_LARGE_BODY_REQUESTS_PER_USER, 1],
    ['MIN_SUSTAINED_UPLOAD_BYTES_PER_SECOND', MIN_SUSTAINED_UPLOAD_BYTES_PER_SECOND, 131_072],
    ['MAX_DOCUMENT_NAME_LENGTH', MAX_DOCUMENT_NAME_LENGTH, 255],
    ['MAX_DOCUMENT_MIME_LENGTH', MAX_DOCUMENT_MIME_LENGTH, 255],
    ['MAX_DOCUMENT_EXT_LENGTH', MAX_DOCUMENT_EXT_LENGTH, 32],
    ['MAX_DOCUMENT_NOTE_LENGTH', MAX_DOCUMENT_NOTE_LENGTH, 10_000],
    ['MAX_DOCUMENT_TAGS', MAX_DOCUMENT_TAGS, 20],
    ['MAX_DOCUMENT_TRANSFORM_LABEL_LENGTH', MAX_DOCUMENT_TRANSFORM_LABEL_LENGTH, 64],
    ['MAX_DOCUMENT_TIMESTAMP_LENGTH', MAX_DOCUMENT_TIMESTAMP_LENGTH, 40],
    ['MAX_DOCUMENT_META_JSON_BYTES', MAX_DOCUMENT_META_JSON_BYTES, 36_864],
    ['MAX_ENCRYPTED_DOCUMENT_META_LENGTH', MAX_ENCRYPTED_DOCUMENT_META_LENGTH, 49_152],
    ['MAX_FORMATTABLE_SIZE_BYTES', MAX_FORMATTABLE_SIZE_BYTES, 5_242_880],
    ['MAX_TRANSFORM_MESSAGE_LENGTH', MAX_TRANSFORM_MESSAGE_LENGTH, 2_000],
    ['MAX_TRANSFORM_EXCERPT_LENGTH', MAX_TRANSFORM_EXCERPT_LENGTH, 200],
  ])('%s is %i', (_name, actual, expected) => {
    expect(actual).toBe(expected);
  });

  it('derives the plaintext chunk as the ciphertext chunk minus exactly one tag', () => {
    expect(DOCUMENT_PLAINTEXT_CHUNK_BYTES).toBe(
      DOCUMENT_CIPHERTEXT_CHUNK_BYTES - DOCUMENT_TAG_BYTES,
    );
    // The negative that names the actual mistake: the plaintext chunk is NOT the
    // round power of two, and one segment of plaintext never fills a whole part.
    expect(DOCUMENT_PLAINTEXT_CHUNK_BYTES).not.toBe(DOCUMENT_CIPHERTEXT_CHUNK_BYTES);
    expect(DOCUMENT_PLAINTEXT_CHUNK_BYTES % (1024 * 1024)).not.toBe(0);
  });

  it('keeps a non-final part an exact multiple of 1 MiB and above the S3 floor', () => {
    // Engines re-serialise an object's block list per block, and several (R2 among
    // them) require every part but the last to be identical in size, so the part
    // size has to be a whole number of mebibytes. S3's own floor for a non-final
    // part is 5 MiB.
    expect(DOCUMENT_CIPHERTEXT_CHUNK_BYTES % (1024 * 1024)).toBe(0);
    expect(DOCUMENT_CIPHERTEXT_CHUNK_BYTES).toBeGreaterThanOrEqual(5 * 1024 * 1024);
    // Written as the relation rather than as the decimal byte count, so that this
    // file holds no copy of the number the scan below forbids duplicating: one part
    // is exactly one storage block at the committed `block_size = "8M"`.
    expect(DOCUMENT_CIPHERTEXT_CHUNK_BYTES).toBe(8 * 1024 * 1024);
  });

  it('leaves the size cap, not the segment ceiling, as the binding limit', () => {
    // MAX_DOCUMENT_SIZE_MB is bounded at 1024 by the server's own schema, so the
    // segment ceiling must cover more than a maximally configured document: if it
    // did not, an operator raising the size cap would get uploads refused for a
    // reason no message mentions.
    expect(MAX_DOCUMENT_CHUNK_COUNT * DOCUMENT_PLAINTEXT_CHUNK_BYTES).toBeGreaterThan(
      1024 * 1024 * 1024,
    );
    expect(MAX_DOCUMENT_CHUNK_COUNT).toBe(10_000);
  });

  it('shares the in-flight part budget so one account can never hold all of it, or be refused early', () => {
    // THE TWO RELATIONS, neither of which is either literal above.
    //
    // Strictly BELOW the process budget, because "one identity cannot wedge the
    // process" is what the share is for: set the two equal and the share is inert
    // while every test that mentions it still passes.
    expect(MAX_IN_FLIGHT_PART_UPLOADS_PER_USER).toBeLessThan(MAX_IN_FLIGHT_PART_UPLOADS);
    // …and at least what a CONFORMING client presents: a transfer sends its parts
    // one at a time, so an account can have one part in flight per transfer the
    // server let it open. Below this, the server refuses what its own init cap
    // authorised — and the client's retry ladder is three steps long, so the third
    // transfer would exhaust it and fail rather than merely wait.
    expect(MAX_IN_FLIGHT_PART_UPLOADS_PER_USER).toBeGreaterThanOrEqual(
      MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER,
    );
  });

  it('shares the in-flight large-body budget so one account can never hold all of it', () => {
    // The same relation as the part share, and for the same reason: equal, the
    // share is inert and one account's two stalled restores hold every slot.
    expect(MAX_IN_FLIGHT_LARGE_BODY_REQUESTS_PER_USER).toBeLessThan(
      MAX_IN_FLIGHT_LARGE_BODY_REQUESTS,
    );
    // …and at least one, or no account could ever restore or rotate at all.
    expect(MAX_IN_FLIGHT_LARGE_BODY_REQUESTS_PER_USER).toBeGreaterThanOrEqual(1);
  });

  it('lets a rotation name every row an account can actually hold, not just the advertised limit', () => {
    // THE RELATION, which is what this pair is for, and it is not the literal
    // above. The document count is checked only when a transfer is OPENED, so
    // `MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER` transfers can pass the same
    // reading of `MAX_DOCUMENTS_PER_USER - 1` and all commit: the reachable
    // maximum is `MAX_DOCUMENTS_PER_USER + MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER
    // - 1`. A rotation payload must name EVERY row, so a wire cap at or below the
    // advertised limit locks such an account out of rotating its vault key for
    // ever. This is the assertion that fails if either input constant moves and
    // the rotation bound does not follow it.
    expect(MAX_DOCUMENTS_PER_ROTATION).toBeGreaterThanOrEqual(
      MAX_DOCUMENTS_PER_USER + MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER - 1,
    );
    // The client's page ceiling has to reach the same row, and that half is pinned
    // in `packages/client/tests/documents-api.test.ts`, where those two constants
    // live.
  });

  it('fills a 12-byte GCM nonce exactly: prefix, segment index, last-segment flag', () => {
    // iv(i, isLast) = noncePrefix(7) || u32be(i) || (isLast ? 0x01 : 0x00). A prefix
    // changed without rethinking that layout either overruns the nonce or leaves a
    // constant zero byte where the counter should be, and AES-GCM nonce reuse under
    // one stream key is a total break rather than a degradation.
    expect(DOCUMENT_NONCE_PREFIX_BYTES + 4 + 1).toBe(IV_BYTES);
  });

  it('derives the stored metadata bound as the exact base64 expansion of the byte budget', () => {
    // AES-GCM ciphertext is exactly as long as its plaintext and the tag is stored
    // in its own column, so the stored base64 string is the byte budget grown by
    // 4/3 and nothing else. Pinned as the derivation because moving either number
    // alone is what refuses a document whose every field is legal: too small a
    // stored bound rejects a blob the browser was allowed to build, too large a one
    // is a bound nothing enforces.
    expect(MAX_ENCRYPTED_DOCUMENT_META_LENGTH).toBe((MAX_DOCUMENT_META_JSON_BYTES / 3) * 4);
    // Divisible by 3, so the expansion is exact rather than padded.
    expect(MAX_DOCUMENT_META_JSON_BYTES % 3).toBe(0);
  });

  it('fits metadata whose every text field is maximal CJK, not merely maximal ASCII', () => {
    // The field bounds are UTF-16 CODE UNITS (that is what a Zod `.max()` counts),
    // and the byte budget is BYTES, so the two are only equal for ASCII. Measured
    // with a real encoder rather than a multiplier, on a real string: a 10,000
    // character note in a non-Latin script is a document any user may write, and it
    // is 3 bytes per character on the wire.
    const codeUnitBudget =
      MAX_DOCUMENT_NAME_LENGTH +
      MAX_DOCUMENT_MIME_LENGTH +
      MAX_DOCUMENT_EXT_LENGTH +
      MAX_DOCUMENT_NOTE_LENGTH +
      MAX_DOCUMENT_TAGS * MAX_TAG_LENGTH;
    const worstCaseTextBytes = new TextEncoder().encode('\u6587'.repeat(codeUnitBudget)).length;
    expect(worstCaseTextBytes).toBe(codeUnitBudget * 3);
    // Plus the hex digest, and an allowance for the JSON keys, the numbers, the
    // timestamp and the transform record. 2 KiB is far above what eleven short keys
    // and a handful of integers cost. The shape is no longer hypothetical: with
    // `documentMetaSchema` defined, the same worst case measured against the real
    // field set is 35_472 bytes, and `document-schema.test.ts` asserts THAT
    // directly. This case stays because it is the arithmetic reason the budget is
    // what it is, and it fails if a field bound is raised without the budget.
    const structureAllowance = 2_048;
    expect(worstCaseTextBytes + 64 + structureAllowance).toBeLessThanOrEqual(
      MAX_DOCUMENT_META_JSON_BYTES,
    );
    // The negative, stated the way round that can actually fail: a budget sized for
    // ASCII would NOT have held this, which is the mistake this test exists to stop
    // anyone repeating.
    expect(worstCaseTextBytes).toBeGreaterThan(codeUnitBudget + 64 + structureAllowance);
  });

  it('gives each derived key its own info prefix, separated by a character hex cannot hold', () => {
    const prefixes = [
      DOCUMENT_STREAM_INFO_PREFIX,
      DOCUMENT_META_INFO_PREFIX,
      DOCUMENT_DEK_WRAP_INFO_PREFIX,
    ];
    // The exact strings, because they are FORMAT constants: a rename makes every
    // document already stored under the old value undecryptable, so it has to be a
    // visible edit here as well as in the known-answer vector a later phase commits.
    expect(DOCUMENT_STREAM_INFO_PREFIX).toBe('hvault/doc/stream/v1|');
    expect(DOCUMENT_META_INFO_PREFIX).toBe('hvault/doc/meta/v1|');
    expect(DOCUMENT_DEK_WRAP_INFO_PREFIX).toBe('hvault/doc/dek-wrap/v1|');
    // Distinctness is the whole point: two purposes sharing an info string derive
    // the SAME key, and a metadata blob would then open under the stream key.
    expect(new Set(prefixes).size).toBe(prefixes.length);
    for (const prefix of prefixes) {
      expect(prefix.startsWith('hvault/doc/')).toBe(true);
      expect(prefix.endsWith('|')).toBe(true);
      // The separator appears ONCE, at the end. A prefix carrying a second `|`
      // (`'hvault/doc|stream/v1|'`) would let two different (prefix, documentId)
      // pairs concatenate to the same info string, and `|` cannot appear in the 24
      // hex characters of an ObjectId, so the last one is unambiguous.
      expect(prefix.indexOf('|')).toBe(prefix.length - 1);
    }
  });

  it('does not restate either chunk size as an inline decimal literal in any source file', () => {
    // A second copy of either byte count is how the two sides of the framing drift
    // apart: the constant is changed, the copy is not, and the mismatch surfaces as
    // a stored document that will not decrypt rather than as a failing build. The
    // scan covers comments as well as code, because a comment that restates a
    // number drifts exactly as silently as an assignment does.
    //
    // The roots are an INCLUDE list, not the whole tree minus an exclude list: an
    // exclude list has to name every build directory, coverage directory, mutation
    // sandbox and local cache that happens to exist on the machine running this,
    // and a missing entry either fails on somebody else's checkout or reads a
    // 100,000-file cache. Everything this rule governs lives under one of these.
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
    const roots = [
      path.join('packages', 'shared', 'src'),
      path.join('packages', 'shared', 'tests'),
      path.join('packages', 'shared', 'scripts'),
      path.join('packages', 'server', 'src'),
      path.join('packages', 'server', 'tests'),
      path.join('packages', 'server', 'scripts'),
      path.join('packages', 'client', 'src'),
      path.join('packages', 'client', 'tests'),
      path.join('packages', 'client', 'scripts'),
      'scripts',
      'e2e',
      'docker',
      'tests',
    ];
    // Build output can still appear INSIDE a scanned root.
    const skippedDirectories = new Set(['node_modules', 'dist', 'coverage', 'build']);
    const scannedExtensions = new Set(['.ts', '.tsx', '.mjs', '.cjs', '.js']);
    // The one file allowed to hold them: their definition.
    const definition = path.join('packages', 'shared', 'src', 'constants', 'index.ts');

    /**
     * Matches the value written with or without numeric separators, and only when
     * it is the WHOLE number, so an occurrence inside a longer digit run (a hash, a
     * timestamp) is not a false positive. Arithmetic spellings (`8 * 1024 * 1024`)
     * are deliberately out of scope: they state the relationship rather than
     * restating the number, which is what this test is asking for.
     */
    const literalPattern = (value: number): RegExp =>
      new RegExp(`(?<![\\d_.])${String(value).split('').join('_?')}(?![\\d_])`);
    const ciphertextNeedle = literalPattern(DOCUMENT_CIPHERTEXT_CHUNK_BYTES);
    const plaintextNeedle = literalPattern(DOCUMENT_PLAINTEXT_CHUNK_BYTES);

    const scanned: string[] = [];
    const offenders: string[] = [];
    const walk = (directory: string): void => {
      for (const entry of readdirSync(directory, { withFileTypes: true })) {
        if (entry.isDirectory()) {
          if (!skippedDirectories.has(entry.name)) walk(path.join(directory, entry.name));
          continue;
        }
        if (!entry.isFile() || !scannedExtensions.has(path.extname(entry.name))) continue;
        const absolute = path.join(directory, entry.name);
        const relative = path.relative(repoRoot, absolute);
        scanned.push(relative);
        if (relative === definition) continue;
        const contents = readFileSync(absolute, 'utf-8');
        // The ciphertext chunk size COLLIDES with MAX_IMPORT_FILE_SIZE_BYTES, which
        // holds the same 8 MiB value for an entirely unrelated reason. A file that
        // names that constant and no document constant is talking about the import
        // ceiling, and failing it here would send the next reader hunting through
        // document chunking for a bug that is not there. Nothing exercises this
        // exemption today (both definitions live in the one file the scan skips): it
        // exists so the first test that pins the import ceiling by its literal fails
        // for its own reason rather than for this one.
        const aboutTheImportCeiling =
          contents.includes('MAX_IMPORT_FILE_SIZE_BYTES') && !contents.includes('DOCUMENT_');
        if (plaintextNeedle.test(contents)) offenders.push(relative);
        else if (!aboutTheImportCeiling && ciphertextNeedle.test(contents))
          offenders.push(relative);
      }
    };
    for (const root of roots) walk(path.join(repoRoot, root));

    expect(offenders).toEqual([]);
    // ...and the WALK really enumerated this repository, so a broken traversal or a
    // root that has been renamed cannot pass by finding nothing. The denominator is
    // asserted for the same reason the pipeline's own scans assert theirs.
    expect(scanned).toContain(definition);
    expect(scanned.length).toBeGreaterThan(300);
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

  it('AUDIT_ACTIONS has exactly 47 distinct operations (keep README in sync)', () => {
    // The README "Audit Logging" feature line documents this exact count
    // ("47 distinct operations"). If a new audit action is added, bump both
    // this assertion and the README number together.
    expect(AUDIT_ACTIONS.length).toBe(47);
    expect(new Set(AUDIT_ACTIONS).size).toBe(AUDIT_ACTIONS.length);
  });

  it('audits spending a backup code, separately from regenerating the batch', () => {
    // Two distinct events that the log used to conflate into one — and, before
    // that, into none: spending a code produced a server log line and no row at
    // all. They must stay separate, because "someone used a recovery credential
    // on my account" and "someone replaced my recovery credentials" call for
    // different reactions from the person reading the log.
    expect(AUDIT_ACTIONS).toContain('2fa_backup_code_used');
    expect(AUDIT_ACTIONS).toContain('2fa_backup_codes_regenerated');
    expect(AUDIT_ACTIONS.filter((action) => action.startsWith('2fa_'))).toEqual([
      '2fa_enable',
      '2fa_disable',
      '2fa_backup_codes_regenerated',
      '2fa_backup_code_used',
    ]);
  });

  it('includes the trusted-device audit actions', () => {
    expect(AUDIT_ACTIONS).toContain('trusted_device_grant');
    expect(AUDIT_ACTIONS).toContain('trusted_device_revoke');
    expect(AUDIT_ACTIONS).toContain('trusted_device_rejected');
  });

  it('includes the export_plaintext action for browser-side portable exports', () => {
    expect(AUDIT_ACTIONS).toContain('export_plaintext');
  });

  it('audits the five document mutations, and audits no document READ', () => {
    // The five are one per mutation the document store performs. The negative is
    // the load-bearing half: no read is audited anywhere in this codebase, and one
    // download is one request per segment, so a `document_download` action would
    // put thousands of rows in front of the ones a user opens the log to find.
    expect(AUDIT_ACTIONS).toContain('document_create');
    expect(AUDIT_ACTIONS).toContain('document_update');
    expect(AUDIT_ACTIONS).toContain('document_delete');
    expect(AUDIT_ACTIONS).toContain('document_restore');
    expect(AUDIT_ACTIONS).toContain('document_purge');
    expect(AUDIT_ACTIONS.filter((action) => action.startsWith('document_'))).toHaveLength(5);
    expect(AUDIT_ACTIONS).not.toContain('document_download');
    expect(AUDIT_ACTIONS).not.toContain('document_read');
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
    // The four that were inline literals in `cardDataSchema` until the import's
    // scalar clamp became their third consumer. They belong here for this file's
    // own stated reason: a constant nothing enforces is a comfortable lie, and a
    // clamp that disagrees with its schema by one character is exactly what
    // discards a whole card at validation.
    ['number', MAX_CARD_NUMBER_LENGTH],
    ['expMonth', MAX_CARD_EXP_MONTH_LENGTH],
    ['expYear', MAX_CARD_EXP_YEAR_LENGTH],
    ['cvv', MAX_CARD_CVV_LENGTH],
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

// ---------------------------------------------------------------------------
// Document preview: the extension-to-mode map, and the rule that reads it
// ---------------------------------------------------------------------------
// This map is asked the same question by two different programs — the
// application, deciding whether to create a frame at all, and the isolated
// sandbox document, told the answer so it can pick a renderer. The failure a
// disagreement produces is an EMPTY RECTANGLE rather than an error, so the map's
// membership and the derivation rule are pinned here rather than trusted.
describe('PREVIEW_MODES and previewModeForName', () => {
  it.each([
    ['a shell script', 'deploy.sh', 'code'],
    ['a README', 'README.md', 'markdown'],
    ['an image', 'diagram.png', 'image'],
    ['a video', 'clip.mp4', 'media'],
    ['plain text', 'notes.txt', 'text'],
    ['stored HTML', 'invoice.html', 'html'],
    ['a spreadsheet export', 'export.csv', 'text'],
    ['a config file', 'nginx.conf', 'code'],
    ['a systemd unit', 'hvault.service', 'code'],
    ['structured data', 'package.json', 'code'],
  ])('resolves %s to its mode', (_label, name, mode) => {
    expect(previewModeForName(name)).toBe(mode);
  });

  it('gives a name with no extension no preview at all', () => {
    // A DECISION, not an oversight: recognising these would need a second lookup
    // keyed by whole filename, which is a second source of truth for one
    // question. `.bashrc` and `.env` have a LEADING dot only, which is not an
    // extension under the same rule that makes `archive.tar.gz` a `gz`.
    for (const name of ['Dockerfile', 'Makefile', 'LICENSE', '.bashrc', '.env', 'hosts']) {
      expect(previewModeForName(name)).toBe('none');
    }
    // A name ending in a dot has an EMPTY extension, which is also no extension.
    expect(previewModeForName('report.')).toBe('none');
  });

  it('is case-insensitive, because a case-sensitive lookup is the obvious bug', () => {
    expect(previewModeForName('DEPLOY.SH')).toBe(previewModeForName('deploy.sh'));
    expect(previewModeForName('Deploy.Sh')).toBe(previewModeForName('deploy.sh'));
    expect(previewModeForName('README.MD')).toBe('markdown');
  });

  it('keys on the LAST segment, so a double extension is not a special case', () => {
    // `archive.tar.gz` is a `gz` — which no renderer handles — and NOT a
    // `tar.gz`. Pinned because "helpfully" recognising compound extensions is
    // the change that would silently make this map two rules instead of one.
    expect(previewModeForName('archive.tar.gz')).toBe('none');
    expect(previewModeForName('backup.tar')).toBe('none');
    expect(previewModeForName('script.min.js')).toBe('code');
  });

  it('names PDF explicitly rather than leaving it unrecognised', () => {
    // The distinction the interface renders: "PDFs are download-only" reads
    // differently from "unrecognised type", and PDF is a DECISION — a PDF
    // renderer is a large third-party parser with a documented history of
    // executing attacker JavaScript in its host page (CVE-2024-4367 in pdf.js).
    expect(PREVIEW_MODES['pdf']).toBe('none');
    expect(previewModeForName('statement.pdf')).toBe('none');
  });

  it('gives every entry one of the seven declared modes', () => {
    // The check that catches a typo'd mode name, which would otherwise mean "no
    // renderer" silently: the sandbox `switch`es on the mode and its default
    // branch is "unsupported", so `'markdwon'` would present as a file that
    // simply refuses to preview.
    for (const [extension, mode] of Object.entries(PREVIEW_MODES)) {
      expect(PREVIEW_MODE_NAMES, `${extension} declares mode ${mode}`).toContain(mode);
    }
    expect(PREVIEW_MODE_NAMES).toHaveLength(7);
  });

  it('answers "none" for a name whose extension is an inherited property name', () => {
    // A document name is chosen by whoever handed the user the file, and the
    // extension rule hands whatever follows the last dot straight to a lookup. On
    // an ordinary object literal `PREVIEW_MODES['constructor']` resolves to the
    // `Object` FUNCTION through the prototype chain, and `?? 'none'` never fires
    // because a function is not nullish — so `notes.constructor` is offered a
    // preview, and the mode posted into the sandbox is a value structured clone
    // refuses. That throws inside the host's handshake handler AFTER the listener
    // and the deadline are gone, which leaves the preview on its spinner for ever
    // with no fallback: the one outcome the viewer is built never to have.
    //
    // `__proto__` is the same hazard with a different value (`Object.prototype`),
    // and both are reachable because the rule lowercases: `toString` and
    // `valueOf` become `tostring`/`valueof` and miss, while these two do not.
    for (const name of ['notes.constructor', 'notes.__proto__']) {
      expect(previewModeForName(name), name).toBe('none');
    }
  });

  it('has no prototype, so no inherited name can be read out of it as a mode', () => {
    // The structural half of the case above, asserted on the DATA rather than on
    // one helper: `previewModeForName` is not the only reader — `sniff.ts` looks
    // up `PREVIEW_MODES[actual.ext]` directly — so a guard added to the helper
    // alone would leave the other call site exactly as it was.
    expect(Object.getPrototypeOf(PREVIEW_MODES)).toBeNull();
    expect(Object.getPrototypeOf(PREVIEW_MAGIC_BYTES)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// The in-browser transforms: which extensions they understand, and which of
// them may be REPAIRED
// ---------------------------------------------------------------------------
// The same shape as the preview map above and, like it, asked by two programs
// whose answers have to agree: the upload panel, deciding whether a checkbox is
// offered at all and which sentence to show beside a disabled one, and the
// isolated sandbox document, picking a Prettier parser and a plugin set. A
// disagreement between them is a checkbox that is offered and then fails, or a
// file that could have been formatted and silently was not — neither of which
// looks like a bug in this map from where the user is standing.
describe('TRANSFORM_SYNTAXES, transformSyntaxForName and canRepairSyntax', () => {
  it.each([
    ['strict JSON', 'package.json', 'json'],
    ['JSON with comments', 'tsconfig.jsonc', 'json'],
    ['JSON5', 'config.json5', 'json'],
    ['JSON Lines', 'events.jsonl', 'jsonl'],
    ['newline-delimited JSON', 'events.ndjson', 'jsonl'],
    ['a README', 'README.md', 'markdown'],
    ['long-form Markdown', 'notes.markdown', 'markdown'],
    ['YAML', 'compose.yaml', 'yaml'],
    ['YAML, short spelling', 'compose.yml', 'yaml'],
  ])('resolves %s to its syntax', (_label, name, syntax) => {
    expect(transformSyntaxForName(name)).toBe(syntax);
  });

  it('answers null for everything else, which is what disables the checkbox', () => {
    // The negatives are the load-bearing half. A formatter offered for a type it
    // cannot read is a checkbox the user ticks and then watches fail, after the
    // file has been chosen.
    for (const name of ['photo.png', 'archive.tar.gz', 'main.ts', 'notes.txt', 'report.pdf']) {
      expect(transformSyntaxForName(name), name).toBeNull();
    }
    // No extension at all, a LEADING dot only, and a trailing dot — the same
    // three shapes `previewModeForName` answers `'none'` for, under the same
    // single derivation rule.
    for (const name of ['Dockerfile', 'Makefile', '.bashrc', 'report.']) {
      expect(transformSyntaxForName(name), name).toBeNull();
    }
    expect(transformSyntaxForExtension('')).toBeNull();
  });

  it('answers null for an extension that is an inherited property name', () => {
    // The same hazard as the preview map's, and it surfaces earlier here: a
    // truthy answer makes the upload panel offer the Format checkbox for a file
    // no formatter can read, and the engine then refuses it with a sentence about
    // the parser rather than about the file type.
    for (const name of ['data.constructor', 'data.__proto__']) {
      expect(transformSyntaxForName(name), name).toBeNull();
    }
    expect(Object.getPrototypeOf(TRANSFORM_SYNTAXES)).toBeNull();
  });

  it('is case-insensitive through the extension rule, not a second lowercase entry', () => {
    expect(transformSyntaxForName('PACKAGE.JSON')).toBe('json');
    expect(transformSyntaxForName('Compose.YML')).toBe('yaml');
    // …and the MAP itself is lowercase-only, so nothing looks up an upper-case
    // key directly and finds one. That is what keeps the lowercasing in ONE
    // place instead of two entries per extension.
    expect(transformSyntaxForExtension('JSON')).toBeNull();
  });

  it('keys on the LAST segment, exactly as the preview map does', () => {
    // Not a `yml`: `values.prod.yaml` is, and `bundle.yaml.gz` is not.
    expect(transformSyntaxForName('values.prod.yaml')).toBe('yaml');
    expect(transformSyntaxForName('bundle.yaml.gz')).toBeNull();
  });

  it('offers repair for the JSON family and NOTHING else', () => {
    // A decision rather than a gap, and the reason is that the alternative is
    // silent: guessing at YAML indentation changes what a document MEANS, and
    // Markdown has no parse failure to repair. Both still get a parse check
    // through the formatter, so a broken YAML is reported rather than uploaded
    // blindly.
    expect(canRepairSyntax('json')).toBe(true);
    expect(canRepairSyntax('jsonl')).toBe(true);
    expect(canRepairSyntax('markdown')).toBe(false);
    expect(canRepairSyntax('yaml')).toBe(false);
    expect([...REPAIRABLE_TRANSFORM_SYNTAXES].sort()).toEqual(['json', 'jsonl']);
  });

  it('gives every entry one of the four declared syntaxes, and every syntax an entry', () => {
    // Both directions. A typo'd value would make an extension resolve to a
    // syntax the engine has no branch for; a declared syntax no extension maps
    // to would be a parser nothing can ever reach.
    for (const [extension, syntax] of Object.entries(TRANSFORM_SYNTAXES)) {
      expect(TRANSFORM_SYNTAX_NAMES, `${extension} declares syntax ${syntax}`).toContain(syntax);
    }
    expect(TRANSFORM_SYNTAX_NAMES).toHaveLength(4);
    expect([...new Set(Object.values(TRANSFORM_SYNTAXES))].sort()).toEqual(
      [...TRANSFORM_SYNTAX_NAMES].sort(),
    );
  });

  it('is a STRICTER set than the preview map, never a wider one', () => {
    // Every formattable extension must also be previewable, because the panel
    // that offers a transform and the viewer that shows the result are two views
    // of one file. The reverse does NOT hold — a `.png` previews and cannot be
    // formatted — so this is asserted in one direction only, deliberately.
    for (const extension of Object.keys(TRANSFORM_SYNTAXES)) {
      expect(PREVIEW_MODES[extension], `${extension} is formattable`).toBeDefined();
      expect(PREVIEW_MODES[extension], `${extension} is formattable`).not.toBe('none');
    }
  });

  it('freezes both, so a caller cannot teach one program an extension the other lacks', () => {
    expect(Object.isFrozen(TRANSFORM_SYNTAXES)).toBe(true);
    expect(Object.isFrozen(REPAIRABLE_TRANSFORM_SYNTAXES)).toBe(true);
  });

  it('uses only lowercase, dotless extensions as keys', () => {
    // The lookup key is what `documentExtension` returns, and it lowercases and
    // strips the dot. A key written as `.md` or `MD` would be dead: present in
    // the map, matched by nothing, and invisible to every other assertion here.
    for (const extension of Object.keys(PREVIEW_MODES)) {
      expect(extension).toBe(extension.toLowerCase());
      expect(extension).not.toContain('.');
      expect(extension.length).toBeGreaterThan(0);
    }
  });

  it('registers a magic-byte signature only for a type it offers to preview', () => {
    // A strict SUBSET. A signature for a type the map does not name at all could
    // never be reached from either direction: the sniffer looks a CLAIM up by
    // extension, and it identifies an IMPOSTOR by the mode the matched
    // extension carries, so an extension with no mode has no answer to give.
    //
    // `pdf` is the interesting member and the reason this is a subset rather
    // than an intersection: its mode is `none`, so it is never previewed, and
    // its signature exists purely so that a PDF wearing another extension can be
    // named. That is the second direction, and it is what makes the row live
    // rather than dead weight.
    const previewable = new Set(Object.keys(PREVIEW_MODES));
    for (const extension of Object.keys(PREVIEW_MAGIC_BYTES)) {
      expect(previewable, `${extension} has a signature but no mode`).toContain(extension);
    }
    expect(Object.keys(PREVIEW_MAGIC_BYTES).length).toBeLessThan(previewable.size);
    expect(PREVIEW_MAGIC_BYTES['pdf'], 'a PDF must be identifiable by name').toBeDefined();
  });

  it('declares every signature as real byte values, anchored at byte 0', () => {
    // Every signature is a run from byte 0, and a marker that sits after a
    // container header is written as wildcards followed by the marker. A byte
    // outside 0..255 is a transcription slip that would make the sniffer refuse
    // every file of that type.
    //
    // The two shape rules are what keep the wildcard from becoming a second way
    // of writing an offset: a LEADING wildcard is an offset written the long
    // way, and a TRAILING one constrains nothing, so both are refused. Every
    // alternative must also constrain at least one byte, since an all-wildcard
    // signature matches every file in existence.
    for (const [extension, alternatives] of Object.entries(PREVIEW_MAGIC_BYTES)) {
      expect(alternatives.length, `${extension} has no signature`).toBeGreaterThan(0);
      for (const alternative of alternatives) {
        const { bytes } = alternative;
        expect(bytes.length, `${extension} has an empty signature`).toBeGreaterThan(0);
        expect(bytes[0], `${extension} starts with a wildcard`).not.toBeNull();
        expect(bytes[bytes.length - 1], `${extension} ends with a wildcard`).not.toBeNull();
        for (const byte of bytes) {
          if (byte === null) continue;
          expect(Number.isInteger(byte)).toBe(true);
          expect(byte).toBeGreaterThanOrEqual(0);
          expect(byte).toBeLessThanOrEqual(0xff);
        }
      }
    }
  });

  it('never leaves one file ambiguous between two formats that render differently', () => {
    // THE invariant this table exists to hold, and the one whose absence let a
    // self-contradictory encoding ship. Two alternatives are simultaneously
    // satisfiable when every position both of them constrain agrees; when they
    // belong to extensions with DIFFERENT preview modes, one file can then look
    // like an image and like a video at once.
    //
    // That is tolerable only while it is RESOLVABLE, and the sniffer resolves it
    // by specificity: the alternative that constrains more bytes wins. So what is
    // forbidden here is a DRAW — two satisfiable alternatives, different modes,
    // the same number of concrete bytes — because there is then no principled
    // answer to "what does this file actually look like".
    //
    // This is exactly the shape the shipped table had: `webp` and `wav` both
    // written as a bare `RIFF`, four concrete bytes each, `image` against
    // `media`. Rewriting either of them that way again fails here.
    //
    // The pairs that ARE satisfiable today are all decisive: `ico` (4 bytes)
    // against the ISO base-media family (5) and against `avif` (9), where the
    // file that would satisfy both is an icon declaring 29,798 images.
    const concrete = (bytes: readonly (number | null)[]): number =>
      bytes.filter((byte) => byte !== null).length;
    const satisfiable = (a: readonly (number | null)[], b: readonly (number | null)[]): boolean => {
      const shared = Math.min(a.length, b.length);
      for (let index = 0; index < shared; index += 1) {
        const left = a[index];
        const right = b[index];
        if (left === null || left === undefined) continue;
        if (right === null || right === undefined) continue;
        if (left !== right) return false;
      }
      return true;
    };

    const entries = Object.entries(PREVIEW_MAGIC_BYTES);
    for (const [extension, alternatives] of entries) {
      for (const [other, otherAlternatives] of entries) {
        if (other === extension) continue;
        if (PREVIEW_MODES[extension] === PREVIEW_MODES[other]) continue;
        for (const alternative of alternatives) {
          for (const otherAlternative of otherAlternatives) {
            if (!satisfiable(alternative.bytes, otherAlternative.bytes)) continue;
            expect(
              concrete(alternative.bytes),
              `${extension} (${String(PREVIEW_MODES[extension])}) and ${other} (${String(PREVIEW_MODES[other])}) are satisfied by one file and constrain equally many bytes, so neither can win`,
            ).not.toBe(concrete(otherAlternative.bytes));
          }
        }
      }
    }
  });

  it('keeps the MP3 frame sync away from the UTF-16LE byte-order mark', () => {
    // The trap in widening the sync: eleven set bits is `0xFF` then a byte with
    // its top three bits set, and the lazy spelling of that is "0xFF followed by
    // anything >= 0xE0". That admits `0xFF 0xFE`, which is the UTF-16LE
    // byte-order mark Windows PowerShell writes at the head of every redirected
    // `.log` and `.txt` — so a genuine text file would be reported as an MP3.
    // Only the six Layer III combinations are listed, and `0xFE` (Layer I) is
    // not one of them.
    const seconds = (PREVIEW_MAGIC_BYTES['mp3'] ?? [])
      .filter((signature) => signature.bytes[0] === 0xff)
      .map((signature) => signature.bytes[1]);
    expect(seconds).toEqual(expect.arrayContaining([0xfb, 0xfa, 0xf3, 0xf2, 0xe3, 0xe2]));
    expect(seconds).not.toContain(0xfe);
    expect(seconds).not.toContain(0xff);
  });

  it('pins the two preview budgets both sides read', () => {
    // MAX_PREVIEW_BYTES is a MEMORY budget before it is a UI one: the app holds
    // the whole plaintext, the channel hands the same buffer to the sandbox, and
    // a renderer builds its own representation on top, so the peak is a small
    // multiple of the file. It matches the restore cap this project already
    // lives with, so an operator meets one figure rather than two.
    expect(MAX_PREVIEW_BYTES).toBe(26_214_400);
    expect(MAX_PREVIEW_BYTES).toBe(MAX_RESTORE_DATA_LENGTH);
    // Anything the upload panel is willing to FORMAT must also be previewable,
    // or a user could reformat a file in the browser and then be told it is too
    // large to look at. The two bounds are set independently, so the ordering
    // between them is worth pinning rather than assuming.
    expect(MAX_PREVIEW_BYTES).toBeGreaterThan(MAX_FORMATTABLE_SIZE_BYTES);
    expect(MAX_PREVIEW_TEXT_LINES).toBe(50_000);
    // The row cap is not a NODE budget on its own, because a table's node count
    // is rows TIMES columns and the width comes from the file: a 25 MiB line of
    // commas is under MAX_PREVIEW_BYTES and asks for twenty-six million cells in
    // one row. The width cap and the product cap are what bound it, and the
    // ordering between the three is the property worth pinning rather than the
    // three numbers on their own.
    expect(MAX_PREVIEW_TABLE_COLUMNS).toBe(1_000);
    expect(MAX_PREVIEW_TABLE_CELLS).toBe(250_000);
    // A budget smaller than one full-width row would render no table at all.
    expect(MAX_PREVIEW_TABLE_CELLS).toBeGreaterThan(MAX_PREVIEW_TABLE_COLUMNS);
    // And the product cap has to be the binding one, or it is decoration: the
    // other two together still permit fifty million cells.
    expect(MAX_PREVIEW_TABLE_CELLS).toBeLessThan(
      MAX_PREVIEW_TEXT_LINES * MAX_PREVIEW_TABLE_COLUMNS,
    );
  });
});
