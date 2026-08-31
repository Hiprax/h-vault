export const APP_NAME = 'H-Vault';
export { APP_VERSION } from '../generated/version.js';

export const KDF_ITERATIONS = 600_000;
export const KDF_ALGORITHM = 'PBKDF2-SHA256' as const;
export const ENCRYPTION_VERSION = 1;
export const VAULT_KEY_BITS = 256;
export const MEK_BITS = 256;
export const AUTH_KEY_BITS = 256;
export const IV_BYTES = 12;
export const SALT_BYTES = 32;

export const BCRYPT_ROUNDS = 12;
export const REFRESH_TOKEN_EXPIRY_DAYS = 7;
export const AUTO_LOCK_TIMEOUT_MINUTES = 15;
// Bounds for the user-configurable `autoLockTimeout` and `lockOnHiddenDelay`
// settings. Exported so the wire schema (`updateSettingsSchema`) and the client's
// `useAutoLock` deadline model read the SAME numbers instead of restating them.
export const AUTO_LOCK_MIN_MINUTES = 1;
export const AUTO_LOCK_MAX_MINUTES = 1440;

// Defaults for the OPT-IN "lock as soon as the tab is hidden" control.
//
// Hidden-tab locking used to be unconditional and on a hardcoded
// `Math.min(30_000, autoLockTimeout / 2)` — so with any realistic setting it was
// a flat 30 seconds, and minimising the browser briefly locked the vault no
// matter what the user had configured. It is now a setting the user turns on,
// with a delay they choose, and it is OFF by default: `autoLockTimeout` alone
// governs unless the user asks for more. The idle deadline keeps running while
// the tab is hidden either way (nothing generates activity events there), so a
// hidden tab still locks on schedule with this off.
export const LOCK_ON_HIDDEN_DEFAULT = false;
export const LOCK_ON_HIDDEN_DELAY_MINUTES = 1;

export const CLIPBOARD_CLEAR_SECONDS = 30;
// Bounds for the user-configurable `clipboardClearTimeout` setting. Exported so
// the wire schema (`updateSettingsSchema`) and the client-side erase scheduler
// clamp against the SAME numbers: the scheduler arms a real timer from whatever
// the profile response carries, so a malformed or hostile value (0, NaN,
// Infinity) would otherwise erase a freshly copied secret immediately.
export const CLIPBOARD_CLEAR_MIN_SECONDS = 5;
export const CLIPBOARD_CLEAR_MAX_SECONDS = 300;
export const TRASH_AUTO_PURGE_DAYS = 30;
export const MAX_LOGIN_ATTEMPTS = 10;

// ---------------------------------------------------------------------------
// Credential-attempt rate limiting
// ---------------------------------------------------------------------------
//
// These three are the SINGLE source of truth for the server's `authLimiter` and
// `accountLimiter` (`middleware/rateLimiter.ts`), which import them rather than
// restating the numbers inline.
//
// They bound CREDENTIAL ATTEMPTS ONLY — deliberate, human-initiated tries at a
// password or an email link: register, login, the 2FA step, forgot-password and
// resend-verification. Session-maintenance traffic the APP issues on its own
// (`/auth/refresh`, `/auth/verify-unlock`) must NEVER be counted here, and is
// not: it has its own limiters. Mounting `authLimiter` on those two was a real,
// shipped defect — a single open tab spends ~3 refreshes per 15-minute window at
// `JWT_ACCESS_EXPIRY=5m`, and every vault unlock spent 2 more, so ordinary use
// drained the budget and the user's NEXT LOGIN was 429'd on its first attempt,
// with no way back in until the window rolled over.
export const LOGIN_RATE_LIMIT_WINDOW_MINUTES = 15;
// Per-IP ceiling. A 2FA sign-in costs two (`/login` then `/login/2fa`), so this
// is ~10 complete sign-ins per window from one address — enough headroom for a
// household or an office behind one NAT, while still far below anything useful
// for guessing. The precise anti-brute-force controls are elsewhere and unchanged:
// per-email counting below, `MAX_LOGIN_ATTEMPTS` account lockout, and the
// progressive per-email delay.
export const LOGIN_RATE_LIMIT_MAX_PER_IP = 20;
export const LOGIN_RATE_LIMIT_MAX_PER_ACCOUNT = 20;
export const BACKUP_CODES_COUNT = 8;
export const DEFAULT_PASSWORD_LENGTH = 20;
export const MAX_TAGS_PER_ITEM = 20;
export const MAX_TAG_LENGTH = 50;
export const MAX_BULK_OPERATIONS = 100;
export const PASSWORD_HISTORY_MAX = 10;
export const LOCKOUT_DURATION_MINUTES = 30;
export const AUDIT_LOG_PAGE_LIMIT = 20;
export const AUDIT_LOG_MAX_LIMIT = 100;
export const MAX_FOLDER_NESTING_DEPTH = 50;
export const MAX_IMPORT_ITEMS = 10_000;
export const MAX_SESSIONS = 50;
export const MAX_TRUSTED_DEVICES = 10;
export const AUTH_TAG_BYTES = 16;
export const MAX_BACKUP_EMAILS = 10;
export const MAX_ITEMS_PER_USER = 10_000;
export const MAX_FOLDERS_PER_USER = 500;
export const MAX_SORT_ORDER = 10_000;
export const MAX_ENCRYPTED_NAME_LENGTH = 1_000;
export const MAX_ENCRYPTED_DATA_LENGTH = 500_000;
export const MAX_NOTE_CONTENT_LENGTH = 50_000;
export const MAX_RESTORE_DATA_LENGTH = 26_214_400;

// Bounds for a LOGIN ITEM's `backupCodes`: the 2FA recovery codes issued by the
// THIRD-PARTY account that login belongs to. Unrelated to BACKUP_CODES_COUNT
// above, which is how many codes H-Vault mints for its OWN account-level 2FA.
//
// 50 codes: real sets are far smaller (Google issues 10, GitHub 16, Microsoft a
// single recovery key), so 50 covers several regenerated batches kept side by
// side and is never the binding limit, while still refusing a pasted document.
// 128 chars: errs generous on purpose. A cap that is too small rejects a real
// code, which costs the user their account recovery; a cap that is too large
// costs only bytes. 128 clears every shape in the wild — a 25-char Microsoft
// recovery key, a 40-char 1Password Secret Key, the 88-char base64 of a 64-byte
// key — with room to spare.
export const MAX_LOGIN_BACKUP_CODES = 50;
export const MAX_LOGIN_BACKUP_CODE_LENGTH = 128;
// Ceiling on the RAW text the backup-code parser will tokenize. The worst
// legitimate paste is MAX_LOGIN_BACKUP_CODES * (MAX_LOGIN_BACKUP_CODE_LENGTH + 6)
// once array quoting is counted, so this leaves roughly 3x headroom; past it the
// parser rejects in constant time instead of scanning a whole pasted page.
export const MAX_LOGIN_BACKUP_CODES_INPUT_LENGTH = 20_000;

// Per-field plaintext ceilings for the DECRYPTED item-data schemas
// (`schemas/vault.ts`). Named rather than inline for the same reason the address
// bounds below are: THREE places must agree on each number — the stored schema,
// `VaultItemForm`'s lenient input schema, and the import clamp in
// `services/import/itemBuilders.ts`. An input cap looser than the stored cap
// stores a value the schema later REJECTS, and a rejected value degrades the
// WHOLE item to the "could not be fully decoded" notice; an input cap with no
// visible error message makes Save a dead button. Every value below is the
// literal the field already carried, so nothing about validation changes.
export const MAX_LOGIN_USERNAME_LENGTH = 500;
export const MAX_LOGIN_PASSWORD_LENGTH = 10_000;
export const MAX_LOGIN_TOTP_LENGTH = 500;
// Measured POST-transform, on the value that is actually STORED: `uriEntrySchema`
// prepends a scheme to a bare domain and only then applies this bound, through the
// exported `isValidUriLength` that `VaultItemForm` calls too. It used to be measured
// on the input, so a bare domain of exactly this length parsed into a value eight
// characters longer that the same schema then rejected on read-back — an item the
// editor could open and never save again. `clampUri` (itemBuilders.ts) has always
// computed the bound this way and is now simply in agreement with the schema.
export const MAX_URI_LENGTH = 2_048;
export const MAX_URIS_PER_ITEM = 100;
export const MAX_CUSTOM_FIELD_NAME_LENGTH = 500;
export const MAX_CUSTOM_FIELDS_PER_ITEM = 100;
export const MAX_SECRET_DESCRIPTION_LENGTH = 10_000;
export const MAX_CARD_CARDHOLDER_NAME_LENGTH = 300;
export const MAX_CARD_BRAND_LENGTH = 50;
// The four card scalars that were still inline literals in `cardDataSchema`. They
// are named now because a third consumer arrived: the import's `clampNotesAndFields`
// bounds each of them, and a clamp that disagrees with the schema by one character
// is exactly the drift that discards a whole card at validation. The values are the
// literals the schema already carried, so nothing about validation changes. They are
// deliberately far wider than the item form's own rules (13-19 digits, `01`-`12`, a
// four-digit year, 3-4 CVV digits), because an IMPORTED card is not required to be
// well formed — the vault's job there is to store what the source file held.
export const MAX_CARD_NUMBER_LENGTH = 30;
export const MAX_CARD_EXP_MONTH_LENGTH = 2;
export const MAX_CARD_EXP_YEAR_LENGTH = 4;
export const MAX_CARD_CVV_LENGTH = 4;
// Shared by an identity's `firstName` and `lastName`, which hold the same kind of
// value and could only drift as two numbers.
export const MAX_IDENTITY_NAME_LENGTH = 200;
// 254 is the RFC 5321 ceiling on a whole address (a 64-char local part plus `@`
// plus a 253-char domain cannot all be maximal at once).
export const MAX_IDENTITY_EMAIL_LENGTH = 254;
export const MAX_IDENTITY_PHONE_LENGTH = 30;
export const MAX_IDENTITY_COMPANY_LENGTH = 300;
// A national identification number and a passport number. Both are SECRETS: the
// item form masks them behind a reveal control and `getItemSubtitle` must never
// put either on a vault-list row. The caps are generous against the widest real
// formats (a US SSN is 11 chars with dashes; an ICAO passport number is 9, but
// several states issue longer national-ID strings).
export const MAX_IDENTITY_SSN_LENGTH = 20;
export const MAX_IDENTITY_PASSPORT_LENGTH = 50;

// Bounds for the postal-address sub-shape shared by a CARD's billing address and
// an IDENTITY's address (`addressSchema` in schemas/vault.ts). Named rather than
// inline because THREE places must agree on them: the stored schema, the item
// form's lenient input schema, and the import clamp. A clamp that mirrors a
// literal it cannot see is one edit away from admitting a value the stored schema
// rejects, and a stored value the schema rejects degrades the WHOLE item to the
// "could not be fully decoded" notice. The five values below are the literals
// those fields already carried, so nothing about validation changes.
//
// `street` and `street2` share ONE bound on purpose: they are the WHATWG
// `address-line1`/`address-line2` peers (Bitwarden names the same pair
// `address1`/`address2`) and hold the same kind of value, so two numbers for one
// concept could only drift.
export const MAX_ADDRESS_STREET_LENGTH = 500;
export const MAX_ADDRESS_CITY_LENGTH = 200;
export const MAX_ADDRESS_STATE_LENGTH = 200;
export const MAX_ADDRESS_ZIP_LENGTH = 20;
export const MAX_ADDRESS_COUNTRY_LENGTH = 100;
// Free-text courier instructions on an IDENTITY's address only ("leave with the
// concierge"), never on a card's billing address. 1,000 rather than the 250 that
// Amazon's Shipping API transmits to a driver's device: 250 is the ceiling of what
// a courier will ACT on, whereas this is the user's own stored copy, which they
// paste into whatever checkout form is in front of them. A cap that is too small
// silently truncates a real value; one that is too large costs only bytes, the
// same trade MAX_LOGIN_BACKUP_CODE_LENGTH resolves the same way. Raising a stored
// cap later is safe; lowering one is not.
export const MAX_ADDRESS_DELIVERY_NOTES_LENGTH = 1_000;

// Per-request byte budget the CLIENT batches an import against. It is a client
// convention, not a server bound: the structured `operations` body is bounded
// server-side by the global 2 MB body parser and by MAX_IMPORT_ITEMS.
export const MAX_IMPORT_DATA_LENGTH = 1_048_576;
// Client-side raw-import-file ceiling. Import parsing + encryption happen in the
// browser, and the encrypted payload is split into batches each kept under
// MAX_IMPORT_DATA_LENGTH before upload, so the raw file itself may be larger than
// a single request body. This guards the browser from an unbounded FileReader
// read; the real per-user ceiling stays MAX_ITEMS_PER_USER.
export const MAX_IMPORT_FILE_SIZE_BYTES = 8_388_608;

// Maximum number of 5-char SHA-1 hash prefixes the breach-check batch endpoint
// accepts (and the client sends) per request. It bounds the server's per-request
// HIBP fan-out and is the divisor the batch rate-limit budget is sized against,
// so a full-vault breach scan never exhausts the limiter mid-scan.
export const HIBP_BATCH_MAX_PREFIXES = 100;

// File Encryption tool (client-side, account-agnostic). The size cap is a
// client-enforced guardrail (the file is encrypted in the browser and never
// uploaded, so the server cannot enforce it); this value is the fallback used
// when the operator-configured limit from GET /config is unreachable.
export const MAX_FILE_ENCRYPTION_SIZE_MB = 100;
// Filename hint for encrypted output. The authoritative format marker lives
// inside the container (the crypto package's magic bytes); this is only a
// download-name suffix.
export const FILE_ENCRYPTION_FILE_EXTENSION = '.enc';

// ---------------------------------------------------------------------------
// Document store
//
// Bounds for the encrypted document store. Every one of them has THREE readers
// that have to agree: the browser that seals a document, the server that
// validates and stores the ciphertext, and the test that pins the boundary. They
// are named here rather than written inline in a schema or a controller because
// the server never sees a document's name, type, tags or bytes, so a
// disagreement between the two sides cannot be diagnosed later by looking at the
// stored data: it presents as a file that uploaded and will not open.
// ---------------------------------------------------------------------------

// The AES-GCM tag length of one document segment, and of the sealed metadata
// blob. Deliberately its own constant rather than an alias of AUTH_TAG_BYTES:
// this one is a parameter of the STORED container format, frozen for the life of
// every document already in a bucket, whereas AUTH_TAG_BYTES describes the
// account cryptography and is free to move if that ever changes cipher. They
// hold the same value today because both are AES-256-GCM.
export const DOCUMENT_TAG_BYTES = 16;
// One crypto segment is one uploaded part is one downloaded range: the three
// chunkings are the same number, so there is no mapping table between them that
// could be wrong. 8 MiB satisfies three independent constraints at once: it is
// above S3's 5 MiB floor for a non-final multipart part; it is an exact multiple
// of 1 MiB, which engines that re-serialise an object's block list per block
// need, and it is uniform, which engines such as Cloudflare R2 require; and it
// keeps one buffered part small enough that MAX_IN_FLIGHT_PART_UPLOADS of them
// fit inside a modest container memory limit.
export const DOCUMENT_CIPHERTEXT_CHUNK_BYTES = 8_388_608;
// The plaintext one segment holds: the ciphertext chunk MINUS one tag, which is
// what makes every non-final uploaded part exactly DOCUMENT_CIPHERTEXT_CHUNK_BYTES
// and segment `i` start at `i * DOCUMENT_CIPHERTEXT_CHUNK_BYTES`. It must never be
// "rounded" up to a whole 8 MiB: that makes each non-final part 8 MiB plus 16
// bytes, the parts stop being uniform, and every segment boundary after the first
// is off by a growing multiple of 16 bytes. A test pins it as this subtraction
// rather than as its own literal for exactly that reason. Decryption reads
// `chunkPlaintextBytes` from the stored row and never from this constant, so
// changing it later cannot mis-frame a document that already exists.
export const DOCUMENT_PLAINTEXT_CHUNK_BYTES = 8_388_592;
// Per-stream HKDF salt, 32 bytes like SALT_BYTES, and the 7-byte nonce prefix
// that precedes the 4-byte big-endian segment index and the 1-byte last-segment
// flag inside each 12-byte GCM IV. Both are stored in PLAINTEXT on the row (a
// salt is not a secret), and both are covered by the segment's own
// authentication: substituting either one makes the segment fail to decrypt.
export const DOCUMENT_STREAM_SALT_BYTES = 32;
export const DOCUMENT_NONCE_PREFIX_BYTES = 7;

// Per-user ceiling on stored documents, trashed ones included. Half of
// MAX_ITEMS_PER_USER on purpose: a document row is far heavier than a vault item
// (it owns an object in the bucket and a metadata blob), and the binding limit an
// operator actually tunes is the byte quota, not the count. This one exists so a
// runaway client cannot mint rows without bound.
export const MAX_DOCUMENTS_PER_USER = 5_000;
// Ceiling on the segments of ONE document, which also bounds the part ledger the
// server keeps for an upload and the number of range reads a download costs. At
// DOCUMENT_PLAINTEXT_CHUNK_BYTES per segment this is far above the largest
// configurable document, so the size cap binds first in every real
// configuration; this is the structural guard that keeps a hostile
// `declaredChunkCount` from asking the server to hold an unbounded ledger.
export const MAX_DOCUMENT_CHUNK_COUNT = 10_000;
// How many staging uploads one user may hold open at once. Three is enough for a
// person dragging in a handful of files while one large transfer runs, and low
// enough that the quota arithmetic (committed bytes plus in-flight declared
// bytes) cannot be inflated by opening uploads that are never completed.
export const MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER = 3;
// Parts the SERVER buffers concurrently, PER WORKER PROCESS, across all users:
// the semaphore the part handler takes before its body parser runs. Four parts at
// DOCUMENT_CIPHERTEXT_CHUNK_BYTES is 32 MiB of buffered ciphertext per process,
// which fits the Docker deployment's single node process inside its 1 GB memory
// limit. A pm2 deployment runs two instances and has no memory limit of its own,
// so its ceiling is 64 MiB across the pair. Raising this raises that product, so
// it is a memory budget before it is a throughput knob.
export const MAX_IN_FLIGHT_PART_UPLOADS = 4;

// Plaintext metadata bounds. These live inside the ENCRYPTED metadata blob, so
// they are enforced by a shared schema that runs in both directions (on the
// browser's write pre-flight and again on read), never by the server, which sees
// only the sealed bytes.
//
// 255 for the name and the MIME type, measured in UTF-16 code units, because that
// is what a Zod `.max()` counts. 255 units is exactly NTFS's own filename limit;
// ext4 bounds a filename at 255 BYTES instead, so a name of 255 multi-byte
// characters is legal here and may still be shortened by the browser when it
// writes the download to such a filesystem. That is the right trade for a store
// whose names are ciphertext to the server: the bound protects the metadata blob,
// and the filesystem gets the last word on its own directory entry. The longest
// registered MIME type is comfortably shorter than this.
export const MAX_DOCUMENT_NAME_LENGTH = 255;
export const MAX_DOCUMENT_MIME_LENGTH = 255;
// The lowercased segment after the last dot of the name. 32 is generous against
// every real extension (`markdown`, `properties`, `sqlite3`) without admitting a
// second filename in disguise.
export const MAX_DOCUMENT_EXT_LENGTH = 32;
// The user's own note about a document. Five times shorter than
// MAX_NOTE_CONTENT_LENGTH because it annotates a file rather than being the
// content itself, and because it is sealed into a blob whose own bound is
// MAX_ENCRYPTED_DOCUMENT_META_LENGTH below.
export const MAX_DOCUMENT_NOTE_LENGTH = 10_000;
// Tags per document, matching MAX_TAGS_PER_ITEM so the two tag pickers behave the
// same way. Each tag is bounded by MAX_TAG_LENGTH, which is the one definition of
// how long a tag may be anywhere in this application.
export const MAX_DOCUMENT_TAGS = 20;
// The metadata blob is bounded in TWO named steps, because the two sides measure
// different things and only one of them is a byte count.
//
// MAX_DOCUMENT_META_JSON_BYTES bounds the UTF-8 BYTES of the serialized metadata
// JSON, which is what the browser actually seals. Every field bound above is a Zod
// `.max()` over UTF-16 CODE UNITS, and one code unit costs up to 3 UTF-8 bytes
// (Cyrillic 2, CJK 3; an astral character is 2 units and 4 bytes, so 2 per unit),
// so the worst case a real user can write is three times the code-unit budget:
// (255 + 255 + 32 + 10_000 + 20 * 50) * 3 = 34_626 bytes, plus the 64-character
// hex digest and the JSON structure itself. 36 KiB covers 34_626 + 64 and leaves
// about 2.1 KiB for the keys, the numbers, the timestamp and the transform record,
// which is several times what eleven short keys and a handful of integers cost. It deliberately does NOT cover a
// note made of control characters, which `JSON.stringify` escapes to `\u0007` at
// six bytes per unit: sizing for that would nearly triple every stored blob to
// serve input no human wrote, and the refusal is loud rather than lossy.
//
// MAX_ENCRYPTED_DOCUMENT_META_LENGTH bounds the STORED string, which is base64 of
// the ciphertext and therefore pure ASCII. AES-GCM ciphertext is exactly as long
// as its plaintext, and the tag lives in its own column, so this is exactly the
// base64 expansion of the byte budget: 36_864 / 3 * 4. A test pins that
// derivation, because a stored bound that is merely "about right" is what refuses
// a document whose every field is individually legal, on the write pre-flight,
// with the file already chosen. A CODE-UNIT count is the wrong shape for either
// number, which is why neither of them is one.
export const MAX_DOCUMENT_META_JSON_BYTES = 36_864;
export const MAX_ENCRYPTED_DOCUMENT_META_LENGTH = 49_152;

// Ceiling past which the upload panel's optional format and repair transforms are
// unavailable. Both run in the browser and hold the whole document plus its
// reformatted copy in memory, and a formatter is superlinear on pathological
// input, so this is a responsiveness budget rather than a correctness one: past
// it the file still uploads, untransformed.
export const MAX_FORMATTABLE_SIZE_BYTES = 5_242_880;

// HKDF `info` prefixes, concatenated with the document id to bind every derived
// key to ONE document: the stream key, the metadata key and the DEK wrapping key.
// The trailing `|` is a separator that cannot appear in a 24-character hex
// ObjectId, so no two (prefix, id) pairs can produce the same info string. These
// are FORMAT constants: changing one makes every document already stored under it
// undecryptable, which is why a committed known-answer vector pins them.
export const DOCUMENT_STREAM_INFO_PREFIX = 'hvault/doc/stream/v1|';
export const DOCUMENT_META_INFO_PREFIX = 'hvault/doc/meta/v1|';
export const DOCUMENT_DEK_WRAP_INFO_PREFIX = 'hvault/doc/dek-wrap/v1|';

export const ITEM_TYPES = ['login', 'secret', 'note', 'card', 'identity'] as const;
export type ItemType = (typeof ITEM_TYPES)[number];

export const THEMES = ['light', 'dark', 'system'] as const;
export type Theme = (typeof THEMES)[number];

export const URI_MATCH_TYPES = ['domain', 'exact', 'startsWith', 'regex'] as const;
export type UriMatchType = (typeof URI_MATCH_TYPES)[number];

export const CUSTOM_FIELD_TYPES = ['text', 'hidden', 'boolean'] as const;
export type CustomFieldType = (typeof CUSTOM_FIELD_TYPES)[number];

export const NOTE_FORMATS = ['markdown', 'plaintext'] as const;
export type NoteFormat = (typeof NOTE_FORMATS)[number];

export const AUDIT_ACTIONS = [
  'login',
  'login_failed',
  'logout',
  'password_change',
  'password_verification_failed',
  '2fa_enable',
  '2fa_disable',
  'item_create',
  'item_update',
  'item_delete',
  'item_restore',
  'export',
  'export_plaintext',
  'import',
  'session_revoke',
  'vault_lock',
  'vault_unlock',
  'backup_triggered',
  'backup_sent',
  'backup_failed',
  'backup_restored',
  'backup_password_changed',
  'folder_create',
  'folder_update',
  'folder_delete',
  'folder_reorder',
  'account_unlock',
  'account_delete',
  'backup_setup',
  'backup_settings_update',
  'backup_download',
  'trash_auto_purge',
  '2fa_backup_codes_regenerated',
  'rotation_recovery',
  'deletion_cleanup',
  'settings_update',
  'email_verified',
  'registration',
  'trusted_device_grant',
  'trusted_device_revoke',
  'trusted_device_rejected',
] as const;
export type AuditAction = (typeof AUDIT_ACTIONS)[number];

export const BACKUP_STATUSES = ['success', 'failed'] as const;
export type BackupStatus = (typeof BACKUP_STATUSES)[number];

export const ERROR_CODES = {
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',
  ACCOUNT_LOCKED: 'ACCOUNT_LOCKED',
  EMAIL_NOT_VERIFIED: 'EMAIL_NOT_VERIFIED',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  TOKEN_INVALID: 'TOKEN_INVALID',
  TOKEN_REUSE_DETECTED: 'TOKEN_REUSE_DETECTED',
  UNAUTHORIZED: 'UNAUTHORIZED',
  FORBIDDEN: 'FORBIDDEN',
  NOT_FOUND: 'NOT_FOUND',
  CONFLICT: 'CONFLICT',
  RATE_LIMIT: 'RATE_LIMIT',
  TWO_FA_REQUIRED: 'TWO_FA_REQUIRED',
  TWO_FA_INVALID: 'TWO_FA_INVALID',
  TWO_FA_ALREADY_ENABLED: 'TWO_FA_ALREADY_ENABLED',
  TWO_FA_NOT_ENABLED: 'TWO_FA_NOT_ENABLED',
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  BACKUP_TOO_LARGE: 'BACKUP_TOO_LARGE',
  BACKUP_NOT_CONFIGURED: 'BACKUP_NOT_CONFIGURED',
  IMPORT_PARSE_ERROR: 'IMPORT_PARSE_ERROR',
  ENCRYPTION_ERROR: 'ENCRYPTION_ERROR',
  DECRYPTION_ERROR: 'DECRYPTION_ERROR',
  EMAIL_MISMATCH: 'EMAIL_MISMATCH',
} as const;
export type ErrorCode = (typeof ERROR_CODES)[keyof typeof ERROR_CODES];

export const PAGINATION_DEFAULTS = {
  PAGE: 1,
  LIMIT: 50,
  MAX_LIMIT: 200,
} as const;
