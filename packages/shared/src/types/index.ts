import type { z } from 'zod';
import type {
  registerSchema,
  loginSchema,
  login2faSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  verifyEmailSchema,
  changePasswordSchema,
  unlockAccountSchema,
  verifyUnlockSchema,
  resendVerificationSchema,
} from '../schemas/auth.js';
import type {
  createVaultItemSchema,
  updateVaultItemSchema,
  listVaultItemsSchema,
  listTrashSchema,
  bulkDeleteSchema,
  bulkMoveSchema,
  bulkReEncryptSchema,
  loginDataSchema,
  secretDataSchema,
  noteDataSchema,
  cardDataSchema,
  identityDataSchema,
} from '../schemas/vault.js';
import type {
  createFolderSchema,
  updateFolderSchema,
  deleteFolderQuerySchema,
  reorderFolderSchema,
} from '../schemas/folder.js';
import type {
  updateSettingsSchema,
  passwordGenOptionsSchema,
  checkBreachSchema,
  backupSetupSchema,
  backupSettingsSchema,
  backupChangePasswordSchema,
  restoreBackupSchema,
  auditLogQuerySchema,
  backupHistorySchema,
  exportSchema,
  importSchema,
  setup2faSchema,
  verify2faSchema,
  disable2faSchema,
  regenerateBackupCodesSchema,
  deleteAccountSchema,
} from '../schemas/user.js';
import type { paginationSchema } from '../schemas/common.js';
import type { ItemType, AuditAction, BackupStatus, ErrorCode, Theme } from '../constants/index.js';

// Auth types
export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type Login2faInput = z.infer<typeof login2faSchema>;
export type ForgotPasswordInput = z.infer<typeof forgotPasswordSchema>;
export type ResetPasswordInput = z.infer<typeof resetPasswordSchema>;
export type VerifyEmailInput = z.infer<typeof verifyEmailSchema>;
export type ChangePasswordInput = z.infer<typeof changePasswordSchema>;
export type UnlockAccountInput = z.infer<typeof unlockAccountSchema>;
export type VerifyUnlockInput = z.infer<typeof verifyUnlockSchema>;
export type ResendVerificationInput = z.infer<typeof resendVerificationSchema>;

// 2FA types
export type Setup2faInput = z.infer<typeof setup2faSchema>;
export type Verify2faInput = z.infer<typeof verify2faSchema>;
export type Disable2faInput = z.infer<typeof disable2faSchema>;
export type RegenerateBackupCodesInput = z.infer<typeof regenerateBackupCodesSchema>;
export type DeleteAccountInput = z.infer<typeof deleteAccountSchema>;

// Vault types
export type CreateVaultItemInput = z.infer<typeof createVaultItemSchema>;
export type UpdateVaultItemInput = z.infer<typeof updateVaultItemSchema>;
export type ListVaultItemsInput = z.infer<typeof listVaultItemsSchema>;
export type ListTrashInput = z.infer<typeof listTrashSchema>;
export type BulkDeleteInput = z.infer<typeof bulkDeleteSchema>;
export type BulkMoveInput = z.infer<typeof bulkMoveSchema>;
export type BulkReEncryptInput = z.infer<typeof bulkReEncryptSchema>;

// Folder types
export type CreateFolderInput = z.infer<typeof createFolderSchema>;
export type UpdateFolderInput = z.infer<typeof updateFolderSchema>;
export type DeleteFolderQuery = z.infer<typeof deleteFolderQuerySchema>;
export type ReorderFolderInput = z.infer<typeof reorderFolderSchema>;

// User/Settings types
export type UpdateSettingsInput = z.infer<typeof updateSettingsSchema>;
export type PasswordGenOptions = z.infer<typeof passwordGenOptionsSchema>;
export type CheckBreachInput = z.infer<typeof checkBreachSchema>;
export type BackupSetupInput = z.infer<typeof backupSetupSchema>;
export type BackupSettingsInput = z.infer<typeof backupSettingsSchema>;
export type BackupChangePasswordInput = z.infer<typeof backupChangePasswordSchema>;
export type RestoreBackupInput = z.infer<typeof restoreBackupSchema>;
export type AuditLogQueryInput = z.infer<typeof auditLogQuerySchema>;
export type BackupHistoryInput = z.infer<typeof backupHistorySchema>;
export type ExportInput = z.infer<typeof exportSchema>;
export type ImportInput = z.infer<typeof importSchema>;
export type PaginationInput = z.infer<typeof paginationSchema>;

// API response types
export type ApiResponse<T> =
  | { success: true; data: T; message?: string }
  | { success: false; error: { code: ErrorCode; message: string } };

export type PaginatedResponse<T> =
  | {
      success: true;
      data: T[];
      message?: string;
      pagination: {
        page: number;
        limit: number;
        total: number;
        totalPages: number;
      };
    }
  | { success: false; error: { code: ErrorCode; message: string } };

// Auth response types — discriminated union prevents impossible states
export interface TwoFactorRequiredLoginResponse {
  twoFactorRequired: true;
  tempToken: string;
}

export interface SuccessfulLoginResponse {
  accessToken: string;
  encryptedVaultKey: string;
  vaultKeyIv: string;
  vaultKeyTag: string;
  kdfIterations: number;
  kdfAlgorithm: 'PBKDF2-SHA256';
}

export type LoginResponse = TwoFactorRequiredLoginResponse | SuccessfulLoginResponse;

export interface RegisterResponse {
  emailSent: boolean;
}

export interface EmailStatusResponse {
  emailSent: boolean;
}

// Vault item interfaces (server-side document shapes).
// Note: `userId` is omitted because the API strips it from responses — the
// authenticated session already identifies the owner. See
// `vaultItemResponseSchema` for the runtime validation counterpart.
export interface IVaultItemResponse {
  _id: string;
  itemType: ItemType;
  folderId?: string | undefined;
  tags: string[];
  favorite: boolean;
  encryptedData: string;
  dataIv: string;
  dataTag: string;
  encryptedName: string;
  nameIv: string;
  nameTag: string;
  searchHash?: string | undefined;
  passwordHistory?: IPasswordHistoryEntry[] | undefined;
  createdAt: string;
  updatedAt: string;
  deletedAt?: string | undefined;
}

export interface IPasswordHistoryEntry {
  encryptedPassword: string;
  iv: string;
  tag: string;
  changedAt: string;
}

// Folder response (see `IVaultItemResponse` for `userId` omission rationale).
export interface IFolderResponse {
  _id: string;
  encryptedName: string;
  nameIv: string;
  nameTag: string;
  searchHash?: string | undefined;
  parentId?: string | undefined;
  icon?: string | undefined;
  color?: string | undefined;
  sortOrder: number;
  createdAt: string;
  updatedAt: string;
}

// Vault export payload (the `data` field of the `POST /tools/export` envelope).
// The server streams encrypted items/folders verbatim — the encrypted blobs are
// opaque to the client, which serializes the whole payload back to a download
// file. `items`/`folders` carry at least the encrypted response fields below;
// the server's `.lean()` query also includes internal fields (e.g. `userId`)
// that are not part of the consumed contract.
export interface IExportMetadata {
  exportDate: string;
  version: string;
  itemCount: number;
}

export interface ExportResponse {
  items: IVaultItemResponse[];
  folders: IFolderResponse[];
  metadata: IExportMetadata;
}

// User profile response
export interface IUserProfile {
  _id: string;
  email: string;
  emailVerified: boolean;
  twoFactorEnabled: boolean;
  kdfIterations: number;
  kdfAlgorithm: 'PBKDF2-SHA256';
  encryptionVersion: number;
  settings: IUserSettings;
  createdAt: string;
  updatedAt: string;
}

export interface IUserSettings {
  autoLockTimeout: number;
  clipboardClearTimeout: number;
  defaultPasswordLength: number;
  defaultPasswordOptions: PasswordGenOptions;
  theme: Theme;
  language: string;
  backup: IBackupSettings;
}

export interface IBackupSettings {
  enabled: boolean;
  scheduleHour: number;
  /** @deprecated Use backupEmails instead. Kept for backward compat reading old data. */
  backupEmail?: string;
  backupEmails?: string[];
  encryptedBWK?: string;
  bwkIv?: string;
  bwkTag?: string;
  bwkSalt?: string;
  bwkEncryptedVaultKey?: string;
  bwkVaultKeyIv?: string;
  bwkVaultKeyTag?: string;
  lastBackupAt?: string;
  lastBackupStatus?: BackupStatus;
  isConfigured: boolean;
}

// Session info
export interface ISessionInfo {
  _id: string;
  deviceInfo: {
    userAgent: string;
    ip: string;
    fingerprint: string;
  };
  createdAt: string;
  expiresAt: string;
  current: boolean;
}

// Audit log entry
export interface IAuditLogEntry {
  _id: string;
  action: AuditAction;
  metadata?: Record<string, unknown>;
  ipAddress: string;
  userAgent: string;
  timestamp: string;
}

// Backup restore response
export interface IItemSkipReason {
  itemId: string;
  /**
   * Why the item was not stored as-requested:
   * - `invalid_item_type` — itemType is not a recognized enum value
   * - `missing_encryption_fields` — required ciphertext/iv/tag fields absent
   * - `conflict_skipped` — already exists, conflictStrategy was `skip`
   * - `trashed_auto_restored` — item existed in trash and was auto-restored
   *   regardless of the conflictStrategy. Surfaced so the client can warn the
   *   user that their `skip` selection did not apply to trashed entries.
   * - `invalid_item_data` — the item passed the structural checks but a
   *   persistence-layer validator rejected it (e.g. an over-length encrypted
   *   field, or an un-castable field such as a malformed passwordHistory
   *   `changedAt` in a tampered/legacy backup). The item is skipped instead of
   *   aborting the whole restore. Note: `_id` duplicate-key collisions no longer
   *   occur here — non-owned items are inserted with a fresh server-minted `_id`,
   *   so a backup's foreign/duplicate `_id` can never collide.
   */
  reason:
    | 'invalid_item_type'
    | 'missing_encryption_fields'
    | 'conflict_skipped'
    | 'trashed_auto_restored'
    | 'invalid_item_data';
}

export interface IFolderSkipReason {
  folderId: string;
  /**
   * Why the folder was not stored as-requested:
   * - `conflict_skipped` — already exists, conflictStrategy was `skip` (or a
   *   keep_both duplicate whose searchHash still collided after the strip).
   * - `invalid_folder_data` — the folder passed the structural checks but a
   *   persistence-layer validator rejected it (e.g. a missing/over-length
   *   required field or an un-castable field). The folder is skipped instead of
   *   aborting the whole restore, mirroring the item loop's `invalid_item_data`.
   *   Note: non-owned folders are inserted with a fresh server-minted `_id`, so a
   *   backup's foreign/duplicate `_id` never collides; a residual `(userId,
   *   searchHash)` collision is resolved by retrying without the hash, so E11000
   *   only reaches this skip path in a rare concurrent-write race.
   */
  reason: 'conflict_skipped' | 'invalid_folder_data';
}

export interface IRestoreBackupResponse {
  itemsRestored: number;
  itemsSkipped: number;
  foldersRestored: number;
  foldersSkipped: number;
  itemSkipReasons: IItemSkipReason[];
  folderSkipReasons: IFolderSkipReason[];
}

// Backup file structure (generated by server, optionally signed by client)
export interface IBackupFile {
  version: string;
  exportDate: string;
  items: Record<string, unknown>[];
  folders: Record<string, unknown>[];
  encryptedVaultKey?: string;
  vaultKeyIv?: string;
  vaultKeyTag?: string;
  backupEncryption?: {
    encryptedBWK?: string;
    bwkIv?: string;
    bwkTag?: string;
    bwkSalt?: string;
    bwkEncryptedVaultKey?: string;
    bwkVaultKeyIv?: string;
    bwkVaultKeyTag?: string;
  };
  metadata: {
    itemCount: number;
    folderCount: number;
  };
  /** HMAC-SHA256 integrity signature computed client-side using BWK. Optional for backward compatibility with older backups. */
  integrity?: string;
}

// Backup log entry
export interface IBackupLogEntry {
  _id: string;
  status: BackupStatus;
  fileSizeBytes?: number;
  itemCount?: number;
  errorMessage?: string;
  sentTo: string[];
  timestamp: string;
}

// Refresh token (server-side document)
export interface IRefreshToken {
  _id: string;
  userId: string;
  tokenHash: string;
  familyId: string;
  deviceInfo: {
    userAgent: string;
    ip: string;
    fingerprint: string;
  };
  expiresAt: string;
  usedAt?: string;
  createdAt: string;
}

// Full user document interface (server-side)
export interface IUser {
  _id: string;
  email: string;
  emailVerified: boolean;
  authHash: string;
  encryptedVaultKey: string;
  vaultKeyIv: string;
  vaultKeyTag: string;
  kdfIterations: number;
  kdfAlgorithm: 'PBKDF2-SHA256';
  encryptionVersion: number;
  twoFactorEnabled: boolean;
  twoFactorSecret?: string;
  pendingTwoFactorSecret?: string;
  pendingTwoFactorExpiry?: string;
  backupCodes?: string[];
  failedLoginAttempts: number;
  lockoutUntil?: string;
  lastRotationKey?: string;
  lastRotationAt?: string;
  rotationInProgress?: boolean;
  pendingEncryptedVaultKey?: string;
  pendingVaultKeyIv?: string;
  pendingVaultKeyTag?: string;
  lastTotpTimestamp?: number;
  deletionPending?: boolean;
  passwordChangedAt?: string;
  settings: IUserSettings;
  createdAt: string;
  updatedAt: string;
}

// Decrypted data shapes (client-side only) — derived from Zod schemas to
// prevent manual interface drift. `z.output` gives the post-parse shape
// (with defaults applied), so fields with `.optional().default()` are
// non-optional in the output type.
// Note: `name` is NOT part of the encrypted data blob — it is encrypted
// separately as `encryptedName` and lives on the vault item envelope.
export type ILoginData = z.output<typeof loginDataSchema>;
export type ISecretData = z.output<typeof secretDataSchema>;
export type INoteData = z.output<typeof noteDataSchema>;
export type ICardData = z.output<typeof cardDataSchema>;
export type IIdentityData = z.output<typeof identityDataSchema>;

/** Address sub-shape used by identity items. */
export type IAddress = NonNullable<IIdentityData['address']>;

// Public (unauthenticated) server configuration surfaced via GET /config.
// Contains only non-sensitive, operator-tunable values the client needs before
// authentication — currently the File Encryption tool's client-side size cap.
export interface PublicConfig {
  fileEncryption: {
    maxSizeMB: number;
  };
}

// Health check
export interface HealthCheckResponse {
  status: 'ok' | 'error';
  uptime: number;
  version: string;
  timestamp: string;
  database: 'connected' | 'disconnected';
}

// 2FA setup
export interface TwoFactorSetupResponse {
  secret: string;
  otpauthUri: string;
  qrCodeDataUrl: string;
}

export interface TwoFactorVerifyResponse {
  backupCodes: string[];
}
