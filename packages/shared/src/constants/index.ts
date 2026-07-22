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
export const CLIPBOARD_CLEAR_SECONDS = 30;
export const TRASH_AUTO_PURGE_DAYS = 30;
export const MAX_LOGIN_ATTEMPTS = 10;
export const LOGIN_RATE_LIMIT_WINDOW_MINUTES = 15;
export const LOGIN_RATE_LIMIT_MAX_PER_IP = 10;
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
export const AUTH_TAG_BYTES = 16;
export const MAX_BACKUP_EMAILS = 10;
export const MAX_ITEMS_PER_USER = 10_000;
export const MAX_FOLDERS_PER_USER = 500;
export const MAX_SORT_ORDER = 10_000;
export const MAX_ENCRYPTED_NAME_LENGTH = 1_000;
export const MAX_ENCRYPTED_DATA_LENGTH = 500_000;
export const MAX_NOTE_CONTENT_LENGTH = 50_000;
export const MAX_RESTORE_DATA_LENGTH = 26_214_400;
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

// File Encryption tool (client-side, account-agnostic). The size cap is a
// client-enforced guardrail (the file is encrypted in the browser and never
// uploaded, so the server cannot enforce it); this value is the fallback used
// when the operator-configured limit from GET /config is unreachable.
export const MAX_FILE_ENCRYPTION_SIZE_MB = 100;
// Filename hint for encrypted output. The authoritative format marker lives
// inside the container (the crypto package's magic bytes); this is only a
// download-name suffix.
export const FILE_ENCRYPTION_FILE_EXTENSION = '.enc';

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
