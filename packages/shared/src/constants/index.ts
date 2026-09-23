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

// The generated-password length bounds. Named because four places have to agree
// on them and nothing forced them to: the wire schema, the settings schema, the
// generator's length slider and the OpenAPI description string.
export const MIN_PASSWORD_LENGTH = 8;
export const MAX_PASSWORD_LENGTH = 128;

/**
 * The largest per-class minimum the generator will honour, e.g. "at least this
 * many digits".
 *
 * A COST bound, and deliberately NOT a wire bound. The generator counts the
 * valid passwords for a given policy with a dynamic program whose state space is
 * the product of `(minimum + 1)` over the four character classes, so this caps
 * it at `(MAX_PASSWORD_LENGTH + 1) * 6^4` states. Measured on a four-core
 * desktop: 73 ms to build the table at this value and 438 ms at 10, against
 * 0.07 ms to generate once it is built and memoised.
 *
 * It is enforced where that cost is paid, by the generator's spec builder, by
 * the settings read path and by the stepper controls. It is NOT enforced in
 * `passwordGenOptionsSchema`, because narrowing an accepted request range is a
 * breaking OpenAPI change that `audit:openapi` grades at `--fail-on WARN`, and
 * it would demand a MAJOR version bump for a field no client has ever sent. A
 * larger stored value is clamped on read rather than rejected.
 *
 * Five covers every password policy in the wild with headroom. Minimums only
 * ever REDUCE entropy, so there is no security argument for a larger cap.
 */
export const MAX_PASSWORD_CLASS_MINIMUM = 5;
export const MAX_TAGS_PER_ITEM = 20;
export const MAX_TAG_LENGTH = 50;
export const MAX_BULK_OPERATIONS = 100;
export const PASSWORD_HISTORY_MAX = 10;
export const LOCKOUT_DURATION_MINUTES = 30;
export const AUDIT_LOG_PAGE_LIMIT = 20;
export const AUDIT_LOG_MAX_LIMIT = 100;
// The BACKUP history's page bounds, and they are the AUDIT log's on purpose.
// `swagger.ts` documents both log endpoints from ONE `pageParams(100, 20)` call,
// because how a log is paged is one decision rather than two. Written as bare
// literals in the schema, the backup half had drifted to 30/30 — so the server
// refused, with a 400, requests its own published contract permits. Naming them
// here is what stops that happening again.
export const BACKUP_HISTORY_PAGE_LIMIT = 20;
export const BACKUP_HISTORY_MAX_LIMIT = 100;
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
// How many documents ONE ROTATION payload may name, which is deliberately NOT
// `MAX_DOCUMENTS_PER_USER`.
//
// The count is checked when a transfer is OPENED and never again
// (`documentController`'s init: `documentCount >= MAX_DOCUMENTS_PER_USER`), and a
// transfer already open commits whatever the count does afterwards. So an account
// at `MAX_DOCUMENTS_PER_USER - 1` may open a transfer, then another, then a third
// — each reading a count that still fits, because only a COMPLETION moves it —
// and all three commit. The highest number of rows an account can actually hold is
// therefore `MAX_DOCUMENTS_PER_USER + MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER - 1`,
// and a fourth transfer cannot be opened until it is back under the limit.
//
// That "and a fourth cannot be opened" is the whole derivation, and it is a
// property of the SERVER rather than of arithmetic. TWO things in
// `documentController`'s init establish it, and either one alone is not enough:
//
//   1. The per-user `document-init:<userId>` JobLock. The concurrency check is
//      itself a read followed by a write, so unserialized, N simultaneous opens
//      all read zero live transfers and all commit — the overshoot has no bound
//      at all, and an account carried past this constant can never rotate its
//      vault key again.
//   2. The ORDER of the two counts: live transfers first, committed documents
//      second. A completion holds a DIFFERENT lock (per upload) and can land
//      between them, so reading documents first pairs a count taken before three
//      completions with a live-transfer count of zero taken after them — both
//      pass, and the account finishes on exactly this constant, leaving the
//      slack described below at zero.
//
// Anything that removes that lock, or swaps those two reads, invalidates the
// number below rather than merely the comment above it.
//
// A rotation must name EVERY row the account holds — the handler compares
// distinct ids against an UNFILTERED `countDocuments`, because a trashed document
// is sealed under the same vault key as an active one. So a wire cap set to the
// advertised limit locks such an account out of rotating its vault key for ever,
// in both directions at once: too long for the schema (400) and too short for the
// coverage check (409), with permanently deleting documents the only way out.
//
// The extra unit of slack over the reachable maximum is deliberate. This cap
// bounds a request BODY; it enforces nothing, because `assertRotationCoversEveryRow`
// is what decides whether a rotation is legitimate. An over-generous cap therefore
// admits nothing extra, while a cap one row short bricks a vault key — so the
// asymmetry is resolved in favour of slack, and the slack is named rather than
// accidental.
export const MAX_DOCUMENTS_PER_ROTATION =
  MAX_DOCUMENTS_PER_USER + MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER;
// Parts the SERVER buffers concurrently, PER WORKER PROCESS, across all users:
// the semaphore the part handler takes before its body parser runs. Four parts at
// DOCUMENT_CIPHERTEXT_CHUNK_BYTES is 32 MiB of buffered ciphertext per process,
// which fits the Docker deployment's single node process inside its 1 GB memory
// limit. A pm2 deployment runs two instances and has no memory limit of its own,
// so its ceiling is 64 MiB across the pair. Raising this raises that product, so
// it is a memory budget before it is a throughput knob.
export const MAX_IN_FLIGHT_PART_UPLOADS = 4;
// ONE IDENTITY's share of the budget above, and the reason it exists is not
// fairness in the abstract: the slot is taken BEFORE the body parser runs, so a
// request that declares a Content-Length and then sends nothing holds one without
// spending a byte, a valid upload id or a single unit of quota. Without a share,
// MAX_IN_FLIGHT_PART_UPLOADS such requests from ONE account hold the whole
// process budget for as long as the server will wait for a body, and every other
// account's part uploads queue behind them.
//
// Three, because that is what a CONFORMING client can have in flight at once and
// not one more: a transfer sends its parts sequentially, and
// MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER is how many transfers the server lets
// one account hold open. So the refusal is unreachable for the browser this
// application ships, and reachable only by a client doing something it was never
// able to do.
//
// It must stay strictly BELOW MAX_IN_FLIGHT_PART_UPLOADS, which is what makes the
// guarantee "one identity can never take every slot" true rather than aspirational
// — raising MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER therefore means raising the
// process budget too, and that product is memory (see above).
export const MAX_IN_FLIGHT_PART_UPLOADS_PER_USER = 3;

// Requests the SERVER admits concurrently, PER WORKER PROCESS, across all users,
// to the two routes that accept a 30 MB JSON body: POST /backup/restore and POST
// /vault/items/bulk-reencrypt. The slot is taken before that body is read and held
// until the handler has finished with it, so this is the number of whole large
// operations resident at once. Like MAX_IN_FLIGHT_PART_UPLOADS it is a MEMORY
// budget before it is a throughput knob, and the two figures it is sized against
// are recorded in docker-compose.yml beside the app's `mem_limit: 1g`:
//
//   * the V8 HEAP ceiling Node picks under that limit is 560 MB, and parsing a
//     full 25 MiB restore payload measures 57 MB of heap, on top of the ~30 MB body
//     string it was parsed from: roughly 90-110 MB of heap per operation;
//   * the whole-process RSS growth of one 26 MB restore measures 111-143 MB and a
//     10,000-item rotation 67-126 MB (scripts/ci/lib/resource-budgets.mjs), and
//     RSS is what counts against the 1 GB cgroup limit.
//
// Two is therefore ~220 MB of heap against 560 and ~290 MB of RSS against 1 GB,
// leaving room for the process's own baseline, the HIBP range cache, the parts
// above and ordinary traffic. Three would put ~330 MB of heap in these alone.
// Two is also the floor, not only the ceiling: with the per-user share below at
// one, a budget of one would let a single account hold all of it.
export const MAX_IN_FLIGHT_LARGE_BODY_REQUESTS = 2;
// ONE IDENTITY's share of the budget above: a second concurrent large-body request
// from an account that already has one in flight is REFUSED, not queued. Without
// it, two requests that declare a Content-Length and then send nothing hold every
// slot for as long as the server will wait for a body, and every other account's
// restore and key rotation waits behind them.
//
// One, because a conforming client can never have two: both handlers take the
// per-account vault-rotation lock, so the second of two concurrent requests was
// already refused with 409 after its 30 MB had been parsed. The share refuses the
// same request with the same status before a byte of it is read. It must stay
// strictly BELOW MAX_IN_FLIGHT_LARGE_BODY_REQUESTS, for the same reason the part
// share must.
export const MAX_IN_FLIGHT_LARGE_BODY_REQUESTS_PER_USER = 1;

// The slowest sustained uplink this deployment stands behind, in bytes per second
// (128 KiB/s is about 1 Mbit/s). It is not a throttle and nothing measures against
// it: it is the DIVISOR that turns a byte budget into a deadline, and it is named
// once because two deadlines are derived from it and they must not drift apart.
//
//   * the server's whole-request receive deadline, from the largest body any route
//     accepts (30 MB, the backup-restore and key-rotation parser): 240 seconds;
//   * the part route's own body deadline, from one sealed segment
//     (DOCUMENT_CIPHERTEXT_CHUNK_BYTES): 64 seconds.
//
// The second is the tighter one on purpose. A part upload holds one of
// MAX_IN_FLIGHT_PART_UPLOADS slots from before its body is read, so the time the
// server is prepared to wait for THAT body is the time one account can deny a slot
// to everybody else. A restore or rotation body also holds a slot from before it is
// read (MAX_IN_FLIGHT_LARGE_BODY_REQUESTS), but the deadline for it IS the
// whole-request one: that deadline was derived from exactly this body, so a
// route-scoped copy would restate the same number. What bounds one account's hold
// there is its share of one slot, not a tighter clock.
export const MIN_SUSTAINED_UPLOAD_BYTES_PER_SECOND = 128 * 1024;

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
// The provenance labels the upload panel's optional transforms record inside the
// metadata blob: `transform.tool` (the package that rewrote the bytes) and
// `transform.toolVersion` (its exact version). ONE bound for both, because they
// are the same kind of value and a package name and a semver are both short; 64
// units is generous against `prettier`/`jsonrepair` and a version string, and
// narrow enough that the pair costs at most 384 of the metadata budget's bytes
// (measured: the whole worst-case blob is 35_472 bytes of the 36_864 below).
// They are the only two free-text fields in the blob that no user types, so the
// bound exists to keep a hostile or buggy writer from spending the budget here
// rather than to accommodate anyone.
export const MAX_DOCUMENT_TRANSFORM_LABEL_LENGTH = 64;
// The metadata blob's `capturedAt`, an ISO 8601 instant in UTC.
//
// A bound is needed here even though the field also carries an ISO format check,
// because ISO 8601's fractional-second component is one-or-more digits with no
// upper bound: measured, a bare datetime check accepts a 30,021-character instant,
// and a blob whose every other field is minimal would then have most of the byte
// budget available to spend on one timestamp. 40 units holds the longest instant
// anyone can legitimately produce with room to spare — `Date.prototype.toISOString`
// emits 24 (`2026-08-31T12:34:56.789Z`) and nanosecond precision reaches 30 — while
// being far too short to be worth abusing. Only a `Z` instant is accepted, so no
// allowance is made for a `+HH:MM` offset.
export const MAX_DOCUMENT_TIMESTAMP_LENGTH = 40;
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
// about 2.1 KiB for the keys, the numbers, the timestamp and the transform record.
// MEASURED against the real schema rather than estimated: every string field at its
// bound in 3-byte characters, both hex digests, an ISO instant, the three framing
// numbers and the transform record serialize to 35_472 bytes, so 1_392 bytes are
// spare and the budget provably admits a metadata object whose every field is
// individually legal (`document-schema.test.ts` builds that object and asserts it,
// which is what turns a new field or a raised field bound into a red test rather
// than a document that refuses to seal). It deliberately does NOT cover a value
// made of code units `JSON.stringify` ESCAPES, each of which costs six bytes: a
// control character (`\u0007`) or a lone surrogate (`\ud800`, which is how a name
// truncated mid-surrogate-pair by an upstream tool arrives). Sizing for those
// would nearly triple every stored blob to serve input no human wrote, and the
// refusal is loud rather than lossy.
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

/**
 * A frozen lookup table keyed by a FILE EXTENSION, with no prototype.
 *
 * Every table this builds is read as `TABLE[extension]`, and `extension` is
 * whatever follows the last dot of a name that was chosen by whoever handed the
 * user the file. On an ordinary object literal that lookup walks the prototype
 * chain, so `'constructor'` answers the `Object` FUNCTION and `'__proto__'`
 * answers `Object.prototype` — neither of which is nullish, so the `?? fallback`
 * every reader writes never fires and a value that is not a member of the table's
 * own value type escapes into code that was typed as though it could not.
 *
 * Measured, before this existed: a document named `notes.constructor` was offered
 * a preview, and the mode posted into the sandbox was a function, which structured
 * clone refuses — the `postMessage` threw inside the host's handshake handler
 * AFTER the window listener and the handshake deadline had already been torn
 * down, so the viewer sat on its spinner for ever with no fallback and nothing to
 * report. That is the one outcome the whole preview protocol is built never to
 * have.
 *
 * Fixed at the DATA rather than at each reader, because the readers are the
 * problem: there are seven of these tables across two packages, `sniff.ts` reads
 * two of them directly, and a guard is a discipline every future call site has to
 * remember. A null prototype makes the inherited names simply absent, so every
 * present and future `TABLE[ext] ?? fallback` is correct by construction.
 * `Object.create(null)` for exactly this hazard is already the house pattern —
 * `packages/client/src/services/import/identity.ts` uses it so a `__proto__` key
 * is hashed as data.
 *
 * Nothing else changes: `Object.keys`, `Object.entries`, `Object.freeze` and
 * spread all behave identically on a null-prototype object, and every reader of
 * these tables either indexes them or iterates them.
 */
export function extensionTable<T>(entries: Record<string, T>): Readonly<Record<string, T>> {
  return Object.freeze(Object.assign(Object.create(null) as Record<string, T>, entries));
}

// The vocabulary of the two in-browser transforms: which extensions each one
// understands, and which of them REPAIR can be offered for.
//
// It sits here, beside PREVIEW_MODES and shaped like it, because the same
// question is asked by two different programs and their answers have to agree.
// The application asks it to decide whether a checkbox is offered at all and, if
// not, which reason to show; the isolated sandbox document asks it to pick a
// Prettier parser and a plugin set. Two copies would diverge the day someone
// teaches one of them about a new extension, and the symptom would be a checkbox
// that is offered and then fails, or a file that could have been formatted and
// silently was not.
//
// The KEY is what `documentExtension` returns: the lowercased segment after the
// LAST dot. The VALUE is the SYNTAX rather than the extension, because that is
// what actually decides handling: `.json`, `.jsonc` and `.json5` differ only in
// which Prettier parser reads them, while `.jsonl` and `.ndjson` are a different
// shape entirely (one document PER LINE, repaired and formatted line by line, so
// a record may never be broken across lines).
export const TRANSFORM_SYNTAX_NAMES = ['json', 'jsonl', 'markdown', 'yaml'] as const;
export type TransformSyntax = (typeof TRANSFORM_SYNTAX_NAMES)[number];

export const TRANSFORM_SYNTAXES: Readonly<Record<string, TransformSyntax>> = extensionTable({
  json: 'json',
  jsonc: 'json',
  json5: 'json',
  jsonl: 'jsonl',
  ndjson: 'jsonl',
  md: 'markdown',
  markdown: 'markdown',
  yaml: 'yaml',
  yml: 'yaml',
});

// Repair is the JSON family and NOTHING else, and the omissions are decisions
// rather than gaps. A heuristic that guessed at YAML indentation would change
// meaning silently, which is the one failure mode a repair tool must never have;
// and Markdown has no parse failure to repair, because every byte of it is
// already valid Markdown. Both still get a PARSE CHECK through the formatter, so
// a broken YAML is reported rather than uploaded blindly.
export const REPAIRABLE_TRANSFORM_SYNTAXES: readonly TransformSyntax[] = Object.freeze([
  'json',
  'jsonl',
]);

// The ONE free-text field a transform FAILURE carries across the port: ONE line
// of the offending document, which is what makes "line 4, column 12" actionable.
// It is bounded because it is displayed in the application's chrome, and an
// unbounded string chosen by the least-trusted component in the system is a
// denial-of-service on the very panel that has to explain what went wrong. (The
// failure's SENTENCE is not a field at all: the frame sends a code and the
// application words it, so there is no tool wording to bound.)
export const MAX_TRANSFORM_EXCERPT_LENGTH = 200;

// The two tool versions a transform records as provenance, sealed into the
// document's encrypted metadata as the only record of what rewrote the bytes.
//
// Written down rather than read at runtime, and that is a deliberate trade with
// a gate behind it. `jsonrepair` publishes no version at all; Prettier publishes
// one on its standalone module but does not declare it in `standalone.d.ts`, so
// reading it would take a cast and a fallback branch that nothing can reach.
// `packages/client/tests/document-format.test.ts` reads both packages' own
// `package.json` and asserts they agree with these, so a dependency bump that
// forgets them is a failing test rather than a metadata record that quietly
// describes the wrong software.
//
// HERE rather than beside the engine, because BOTH programs need them: the
// sandbox's engine stamps its reply with them, and the application refuses any
// reply whose labels are not exactly what its own request can produce (see
// `transformToolLabels`). A label the frame chose would be shown beside the
// upload button and sealed into the document for good.
export const JSONREPAIR_VERSION = '3.15.0';
export const PRETTIER_VERSION = '3.9.6';

// HKDF `info` prefixes, concatenated with the document id to bind every derived
// key to ONE document: the stream key, the metadata key and the DEK wrapping key.
// The trailing `|` is a separator that cannot appear in a 24-character hex
// ObjectId, so no two (prefix, id) pairs can produce the same info string. These
// are FORMAT constants: changing one makes every document already stored under it
// undecryptable, which is why a committed known-answer vector pins them.
export const DOCUMENT_STREAM_INFO_PREFIX = 'hvault/doc/stream/v1|';
export const DOCUMENT_META_INFO_PREFIX = 'hvault/doc/meta/v1|';
export const DOCUMENT_DEK_WRAP_INFO_PREFIX = 'hvault/doc/dek-wrap/v1|';

// ---------------------------------------------------------------------------
// DOCUMENT PREVIEW
// ---------------------------------------------------------------------------
// The application decides WHETHER a preview is offered; the isolated sandbox
// document decides HOW to render it. Both read the numbers and the map below,
// and neither restates them, because the two answers have to agree: an app that
// offers a preview for a type the sandbox has no renderer for shows the user an
// empty rectangle, and an app that declines one the sandbox could render shows a
// needless download button.
// ---------------------------------------------------------------------------

// The seven ways a stored document can be presented. `none` is a first-class
// answer rather than the absence of one: it is what the detail view reads to say
// "download to view" with a reason, and PREVIEW_MODES names it explicitly for
// the types this project has deliberately DECIDED not to render (PDF), as
// distinct from the ones it simply does not recognise.
export const PREVIEW_MODE_NAMES = [
  'image',
  'text',
  'code',
  'markdown',
  'html',
  'media',
  'none',
] as const;
export type PreviewMode = (typeof PREVIEW_MODE_NAMES)[number];

// The size past which a document is download-only.
//
// A MEMORY budget before it is a UI one, and the multiplier is what makes it
// small: the application holds the whole decrypted plaintext, the channel hands
// the SAME buffer to the sandbox, and a renderer then builds its own
// representation on top of it, so the peak is a small multiple of the file. 25
// MiB keeps that comfortably inside a tab on a modest machine, and it is the
// same number this project already lives with for a backup restore
// (MAX_RESTORE_DATA_LENGTH), so an operator meets one figure rather than two.
export const MAX_PREVIEW_BYTES = 26_214_400;
// Lines past which the text renderer truncates, with a notice and the byte count
// rather than silently. A single-line 25 MiB file is one DOM text node and is
// fine; 50,000 SEPARATE lines is 50,000 nodes, and it is the node count rather
// than the byte count that stops a tab responding.
export const MAX_PREVIEW_TEXT_LINES = 50_000;

// The widest a previewed delimited file is rendered, in columns.
//
// The row cap above is not a node budget on its own: a table's node count is
// rows TIMES columns, and the width of a CSV is decided by the file rather than
// by the reader. A 25 MiB line of nothing but commas is comfortably under
// MAX_PREVIEW_BYTES and asks for twenty-six million cells in one row, which
// stops the tab before it can show anything at all. Real delimited data is a
// few dozen columns wide, so this is a bound on the pathological case and not a
// limit anybody's spreadsheet meets. Fields past it are COUNTED and not kept,
// exactly as rows past the row cap are, so the notice can name the real width.
export const MAX_PREVIEW_TABLE_COLUMNS = 1_000;
// The total number of cells a previewed delimited file may render.
//
// The column cap alone still permits 50,000 x 1,000, so the product needs its
// own ceiling. This one is what today's ordinary worst case already costs: a
// five-column file at the row cap. Past it, ROWS are dropped rather than
// columns, because a table missing its right-hand columns is unreadable while
// one missing its later rows is simply shorter — and the reader is told which
// of the two happened.
export const MAX_PREVIEW_TABLE_CELLS = 250_000;

// Extension to render mode. The lookup key is what `documentExtension` returns:
// the LOWERCASED segment after the LAST dot of the decrypted name. A name with
// no dot, and a name whose only dot is leading, therefore has no extension and
// resolves to `none` — `Dockerfile`, `Makefile`, `.bashrc` and `.env` are all
// download-only, which is a decision rather than an oversight (recognising them
// needs a second lookup keyed by whole filename, i.e. a second source of truth
// for one question).
//
// Two consequences worth stating rather than discovering. UPLOADING is not
// restricted by this map at all: every type uploads, and a type absent here is
// simply download-only. And a `code` preview is NOT redacted in any way, which
// is correct for a store whose whole content is sensitive by definition, but it
// does mean a previewed `prod.env` shows its secrets on screen exactly as a
// revealed password field would. (`prod.env` has the extension `env`; the file
// `.env` has none, and is download-only, by the rule above.)
//
// ADDING AN EXTENSION HERE IS CHEAP AND SAFE, and that property should govern
// the decision: every text-family renderer emits text nodes and executes
// nothing, and an extension with no matching highlighter language degrades to
// plain text. The worst outcome of a generous list is an unhighlighted preview;
// the worst outcome of a stingy one is a needless download. Membership is pinned
// by a test so an addition is a visible edit rather than a silent one.
export const PREVIEW_MODES: Readonly<Record<string, PreviewMode>> = extensionTable({
  // Raster and vector images, all through `<img>`. SVG is NEVER inlined: an
  // `<img>` cannot run the script an inline SVG can.
  png: 'image',
  jpg: 'image',
  jpeg: 'image',
  gif: 'image',
  webp: 'image',
  avif: 'image',
  bmp: 'image',
  ico: 'image',
  svg: 'image',

  // Plain and tabular text, rendered as text nodes with no language grammar.
  txt: 'text',
  text: 'text',
  log: 'text',
  csv: 'text',
  tsv: 'text',

  // Highlightable source and structured data. Shell scripts and configuration
  // files are deliberately included: they are among the things a person most
  // often stores and most wants to read without downloading.
  sh: 'code',
  bash: 'code',
  zsh: 'code',
  fish: 'code',
  ps1: 'code',
  bat: 'code',
  cmd: 'code',
  py: 'code',
  rb: 'code',
  pl: 'code',
  lua: 'code',
  sql: 'code',
  r: 'code',
  js: 'code',
  mjs: 'code',
  cjs: 'code',
  ts: 'code',
  tsx: 'code',
  jsx: 'code',
  c: 'code',
  h: 'code',
  cpp: 'code',
  hpp: 'code',
  cs: 'code',
  java: 'code',
  kt: 'code',
  go: 'code',
  rs: 'code',
  php: 'code',
  swift: 'code',
  diff: 'code',
  patch: 'code',
  conf: 'code',
  cfg: 'code',
  properties: 'code',
  env: 'code',
  service: 'code',
  json: 'code',
  jsonc: 'code',
  json5: 'code',
  jsonl: 'code',
  ndjson: 'code',
  yaml: 'code',
  yml: 'code',
  toml: 'code',
  xml: 'code',
  ini: 'code',

  // Markdown through remark/rehype with the sanitizer's GitHub-derived schema,
  // so a README renders the way GitHub renders one.
  md: 'markdown',
  markdown: 'markdown',
  mdown: 'markdown',
  mkd: 'markdown',

  // Stored HTML through the SAME sanitizing pipeline. Never assigned to an
  // element's innerHTML: the sanitized tree becomes DOM nodes directly, because
  // serialising it back to a string and re-parsing it is the mutation-XSS shape.
  html: 'html',
  htm: 'html',
  xhtml: 'html',

  // Audio and video through `<video controls>` / `<audio controls>`, from a blob
  // URL the sandbox mints itself (one minted by the application would not
  // resolve in an opaque origin).
  mp4: 'media',
  m4v: 'media',
  webm: 'media',
  ogv: 'media',
  mp3: 'media',
  m4a: 'media',
  aac: 'media',
  wav: 'media',
  flac: 'media',
  opus: 'media',
  ogg: 'media',
  oga: 'media',

  // Named, and DECIDED. A PDF renderer is a large third-party parser with a
  // documented history of executing attacker JavaScript in its host page
  // (CVE-2024-4367 in pdf.js), it is the only renderer that would have needed a
  // worker and a WebAssembly module the isolated document cannot load by URL,
  // and carrying it would have forced `connect-src` and `worker-src` open for
  // every other format too. Listing it as `none` rather than omitting it is what
  // lets the interface say "PDFs are download-only" instead of "unrecognised
  // type".
  pdf: 'none',
});

/**
 * One leading-byte signature: the bytes a format begins with, with `null` for
 * "any byte here".
 *
 * ---------------------------------------------------------------------------
 * WHY A WILDCARD AND NOT AN OFFSET
 * ---------------------------------------------------------------------------
 *
 * This interface used to carry an `offset` instead, so that `ftyp` could be
 * declared "at byte 4 of an MP4". That shape could not express the format it was
 * written for. WebP is `RIFF`, then a four-byte length, then `WEBP` — a
 * CONJUNCTION of two constraints — while a GIF is `GIF87a` OR `GIF89a`, an
 * ALTERNATION. A flat list of `{offset, bytes}` has exactly one operator, and
 * whichever one is chosen the other format is handled wrongly: read as
 * alternatives, every RIFF container matches both `webp` and `wav`, so the
 * sniffer cannot answer "what does this file actually look like" for either;
 * read as a conjunction, no GIF is ever recognised, because no file is both
 * GIF87a and GIF89a.
 *
 * A wildcard collapses that to one operator. Every value below is a list of
 * ALTERNATIVES, each of which is a run of bytes anchored at byte 0, and a
 * "signature at byte 4" is written as four wildcards followed by the marker.
 * That is also the notation this feature's design uses for it (`RIFF....WEBP`).
 *
 * The change pays for itself immediately on the ISO base-media family. Written
 * with an offset, `ftyp` at byte 4 is four printable ASCII bytes and nothing
 * constrains the first four; written from byte 0, the leading byte is the top
 * octet of the box's big-endian size, which is `0x00` for every conformant file
 * (an `ftyp` box is tens of bytes, and both special sizes — 0 for
 * "to end of file" and 1 for "64-bit size follows" — also start `0x00`). Pinning
 * it costs nothing and is what stops a CSV whose first cells are `col,ftyp`
 * being reported as a video.
 */
export interface PreviewSignature {
  /**
   * The bytes, from byte 0. `null` matches any byte at that position.
   *
   * A signature must not begin or end with a wildcard: a leading one is an
   * offset written the long way, and a trailing one constrains nothing at all.
   * `packages/shared/tests/constants.test.ts` asserts both.
   */
  readonly bytes: readonly (number | null)[];
}

// What a file's first bytes must look like for its extension's claim to be
// believed. The sandbox compares them before rendering anything, and a mismatch
// refuses the preview and says what the file actually looks like.
//
// Deliberately PARTIAL, and its keys are a strict SUBSET of PREVIEW_MODES's: a
// check can only exist for a format that HAS an unambiguous magic number. Text,
// markdown, HTML, source code, SVG and INI have none, and inventing one for them
// would refuse legitimate files.
//
// THE TABLE IS READ IN TWO DIRECTIONS, and the second is why `pdf` has a row
// despite being a `none` mode that is never previewed. Forwards, it CONFIRMS a
// claim: a `.png` whose bytes are not a PNG is refused. Backwards, it IDENTIFIES
// an impostor: bytes that positively match some other format's signature are how
// a PDF renamed `.md` is refused instead of being handed to the markdown parser.
// A row here is therefore not dead weight merely because its own mode is never
// rendered — it is the vocabulary the sniffer answers "what IS this" in.
//
// Every value is a list of ALTERNATIVES: a format may have more than one legal
// opening (GIF87a and GIF89a; an MP3 with an ID3 tag and one without). Within an
// alternative, every non-wildcard byte must match.
export const PREVIEW_MAGIC_BYTES: Readonly<Record<string, readonly PreviewSignature[]>> =
  extensionTable({
    png: [{ bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] }],
    jpg: [{ bytes: [0xff, 0xd8, 0xff] }],
    jpeg: [{ bytes: [0xff, 0xd8, 0xff] }],
    // 'GIF87a' and 'GIF89a'.
    gif: [
      { bytes: [0x47, 0x49, 0x46, 0x38, 0x37, 0x61] },
      { bytes: [0x47, 0x49, 0x46, 0x38, 0x39, 0x61] },
    ],
    // 'RIFF', a four-byte little-endian length, then 'WEBP'. The length is the
    // wildcard run, and the pair is ONE alternative: 'RIFF' alone is also a WAV,
    // an AVI and half a dozen other containers.
    webp: [
      {
        bytes: [0x52, 0x49, 0x46, 0x46, null, null, null, null, 0x57, 0x45, 0x42, 0x50],
      },
    ],
    bmp: [{ bytes: [0x42, 0x4d] }],
    ico: [{ bytes: [0x00, 0x00, 0x01, 0x00] }],
    // ISO base media: a big-endian box size, then 'ftyp', then the major brand.
    // The leading 0x00 is the size's top octet — see PreviewSignature above for
    // why it is safe to pin and what it buys.
    //
    // THREE brands, because requiring exactly 'avif' refuses real files: 'avis'
    // is the major brand of an AVIF image sequence, and 'mif1' is the MIAF
    // compatibility brand that encoders in the wild emit for still AVIF. Being
    // wrong in this direction refuses a picture the browser would have shown, so
    // the list errs towards admitting; a file that is admitted and then will not
    // decode is reported by the renderer, which is a better answer than a
    // refusal that names the wrong reason.
    avif: [
      { bytes: [0x00, null, null, null, 0x66, 0x74, 0x79, 0x70, 0x61, 0x76, 0x69, 0x66] },
      { bytes: [0x00, null, null, null, 0x66, 0x74, 0x79, 0x70, 0x61, 0x76, 0x69, 0x73] },
      { bytes: [0x00, null, null, null, 0x66, 0x74, 0x79, 0x70, 0x6d, 0x69, 0x66, 0x31] },
    ],
    mp4: [{ bytes: [0x00, null, null, null, 0x66, 0x74, 0x79, 0x70] }],
    m4v: [{ bytes: [0x00, null, null, null, 0x66, 0x74, 0x79, 0x70] }],
    m4a: [{ bytes: [0x00, null, null, null, 0x66, 0x74, 0x79, 0x70] }],
    // Matroska/WebM EBML header.
    webm: [{ bytes: [0x1a, 0x45, 0xdf, 0xa3] }],
    // 'OggS'.
    ogg: [{ bytes: [0x4f, 0x67, 0x67, 0x53] }],
    oga: [{ bytes: [0x4f, 0x67, 0x67, 0x53] }],
    ogv: [{ bytes: [0x4f, 0x67, 0x67, 0x53] }],
    opus: [{ bytes: [0x4f, 0x67, 0x67, 0x53] }],
    // 'ID3' for a tagged file, or a bare MPEG audio frame sync.
    //
    // The sync is eleven set bits: 0xFF, then a byte whose top three bits are
    // set, whose next two encode the MPEG version and whose next two encode the
    // layer. Only the SIX Layer III combinations are listed — MPEG-1 (0xFA,
    // 0xFB), MPEG-2 (0xF2, 0xF3) and MPEG-2.5 (0xE2, 0xE3), with the low bit
    // being the CRC flag. Listing only 0xFB, as this table did, refuses every
    // untagged MPEG-2 file and every CRC-protected one.
    //
    // Do NOT "simplify" this to "0xFF followed by anything >= 0xE0". That admits
    // 0xFF 0xFE, which is the UTF-16LE byte-order mark Windows PowerShell writes
    // at the head of every redirected .log and .txt, and a genuine text file
    // would then be reported as an MP3.
    mp3: [
      { bytes: [0x49, 0x44, 0x33] },
      { bytes: [0xff, 0xfb] },
      { bytes: [0xff, 0xfa] },
      { bytes: [0xff, 0xf3] },
      { bytes: [0xff, 0xf2] },
      { bytes: [0xff, 0xe3] },
      { bytes: [0xff, 0xe2] },
    ],
    // 'RIFF', a four-byte little-endian length, then 'WAVE' — the same shape as
    // WebP and for the same reason.
    wav: [
      {
        bytes: [0x52, 0x49, 0x46, 0x46, null, null, null, null, 0x57, 0x41, 0x56, 0x45],
      },
    ],
    // 'fLaC'. A file that some Windows taggers produce carries an ID3v2 header in
    // front of this, and is refused: that is a DECISION rather than an oversight,
    // because such a file is not conformant and browsers do not decode it either,
    // so admitting it would trade a clear refusal for a silent failure to play.
    flac: [{ bytes: [0x66, 0x4c, 0x61, 0x43] }],
    // '%PDF-'. Never previewed — `pdf` is a `none` mode — and present for the
    // BACKWARDS direction described above: this row is what lets a PDF renamed
    // `.md` be refused by name.
    pdf: [{ bytes: [0x25, 0x50, 0x44, 0x46, 0x2d] }],
  });

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
  // Spending one of those codes. A backup code is a RECOVERY credential — issued
  // in a batch, kept where the authenticator app is not — so its use is a thing
  // the account owner needs to see, and it used to produce a server log line and
  // nothing else. It is its own action rather than a field on the `login` row
  // because the audit log's UI renders the action and never the metadata, so a
  // marker alone would be invisible to the only person it is written for; the
  // `login` row carries `backupCode` as well, for anything reading the API.
  '2fa_backup_code_used',
  'rotation_recovery',
  'deletion_cleanup',
  'settings_update',
  'email_verified',
  'registration',
  'trusted_device_grant',
  'trusted_device_revoke',
  'trusted_device_rejected',
  // The document store's five mutations, and deliberately only five. There is no
  // download action: no read is audited anywhere in this codebase, and one
  // download is many segment requests, so auditing it would bury every other row
  // in the log a user actually reads. The trash auto-purge cron reuses
  // `trash_auto_purge` rather than adding a sixth, because it is the same
  // scheduled operation reaching a second collection.
  'document_create',
  'document_update',
  'document_delete',
  'document_restore',
  'document_purge',
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
