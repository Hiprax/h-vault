import { describe, it, expect } from 'vitest';

// Import from the barrel (src/index.ts) to ensure coverage of re-exports
import {
  // Schemas — common
  objectIdSchema,
  paginationSchema,
  // Schemas — auth
  registerSchema,
  loginSchema,
  login2faSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  verifyEmailSchema,
  changePasswordSchema,
  unlockAccountSchema,
  emailSchema,
  resendVerificationSchema,
  // Schemas — vault
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
  vaultItemDataSchemas,
  // Schemas — folder
  createFolderSchema,
  updateFolderSchema,
  deleteFolderQuerySchema,
  reorderFolderSchema,
  // Schemas — user
  passwordGenOptionsSchema,
  updateSettingsSchema,
  setup2faSchema,
  verify2faSchema,
  disable2faSchema,
  regenerateBackupCodesSchema,
  deleteAccountSchema,
  checkBreachSchema,
  backupSetupSchema,
  backupSettingsSchema,
  backupChangePasswordSchema,
  backupHistorySchema,
  auditLogQuerySchema,
  restoreBackupSchema,
  exportSchema,
  importSchema,
  importInsertItemSchema,
  importUpdateItemSchema,
  importOperationsSchema,
  // Schemas — config
  publicConfigDataSchema,
  publicConfigResponseSchema,
  // Constants
  APP_NAME,
  APP_VERSION,
  KDF_ITERATIONS,
  ITEM_TYPES,
  THEMES,
  ERROR_CODES,
  PAGINATION_DEFAULTS,
  AUDIT_ACTIONS,
  BACKUP_STATUSES,
  MAX_FOLDER_NESTING_DEPTH,
  MAX_IMPORT_ITEMS,
  MAX_SESSIONS,
  AUTH_TAG_BYTES,
  MAX_BACKUP_EMAILS,
  MAX_FOLDERS_PER_USER,
  MAX_SORT_ORDER,
  MAX_ENCRYPTED_NAME_LENGTH,
  MAX_ENCRYPTED_DATA_LENGTH,
  MAX_NOTE_CONTENT_LENGTH,
  MAX_RESTORE_DATA_LENGTH,
  MAX_IMPORT_DATA_LENGTH,
  MAX_FILE_ENCRYPTION_SIZE_MB,
  FILE_ENCRYPTION_FILE_EXTENSION,
  // Utils
  maskEmail,
  formatBytes,
  generateId,
  normalizeUri,
} from '../src/index.js';

describe('barrel exports (src/index.ts)', () => {
  it('exports all common schemas', () => {
    expect(objectIdSchema).toBeDefined();
    expect(paginationSchema).toBeDefined();
  });

  it('exports all auth schemas', () => {
    expect(registerSchema).toBeDefined();
    expect(loginSchema).toBeDefined();
    expect(login2faSchema).toBeDefined();
    expect(forgotPasswordSchema).toBeDefined();
    expect(resetPasswordSchema).toBeDefined();
    expect(verifyEmailSchema).toBeDefined();
    expect(changePasswordSchema).toBeDefined();
    expect(unlockAccountSchema).toBeDefined();
    expect(emailSchema).toBeDefined();
    expect(resendVerificationSchema).toBeDefined();
  });

  it('exports all vault schemas', () => {
    expect(createVaultItemSchema).toBeDefined();
    expect(updateVaultItemSchema).toBeDefined();
    expect(listVaultItemsSchema).toBeDefined();
    expect(listTrashSchema).toBeDefined();
    expect(bulkDeleteSchema).toBeDefined();
    expect(bulkMoveSchema).toBeDefined();
    expect(bulkReEncryptSchema).toBeDefined();
  });

  it('exports all decrypted vault item data schemas', () => {
    expect(loginDataSchema).toBeDefined();
    expect(secretDataSchema).toBeDefined();
    expect(noteDataSchema).toBeDefined();
    expect(cardDataSchema).toBeDefined();
    expect(identityDataSchema).toBeDefined();
    expect(vaultItemDataSchemas).toBeDefined();
    expect(vaultItemDataSchemas.login).toBe(loginDataSchema);
    expect(vaultItemDataSchemas.secret).toBe(secretDataSchema);
    expect(vaultItemDataSchemas.note).toBe(noteDataSchema);
    expect(vaultItemDataSchemas.card).toBe(cardDataSchema);
    expect(vaultItemDataSchemas.identity).toBe(identityDataSchema);
  });

  it('exports all folder schemas', () => {
    expect(createFolderSchema).toBeDefined();
    expect(updateFolderSchema).toBeDefined();
    expect(deleteFolderQuerySchema).toBeDefined();
    expect(reorderFolderSchema).toBeDefined();
  });

  it('exports all user schemas', () => {
    expect(passwordGenOptionsSchema).toBeDefined();
    expect(updateSettingsSchema).toBeDefined();
    expect(setup2faSchema).toBeDefined();
    expect(verify2faSchema).toBeDefined();
    expect(disable2faSchema).toBeDefined();
    expect(regenerateBackupCodesSchema).toBeDefined();
    expect(deleteAccountSchema).toBeDefined();
    expect(checkBreachSchema).toBeDefined();
    expect(backupSetupSchema).toBeDefined();
    expect(backupSettingsSchema).toBeDefined();
    expect(backupChangePasswordSchema).toBeDefined();
    expect(backupHistorySchema).toBeDefined();
    expect(auditLogQuerySchema).toBeDefined();
    expect(restoreBackupSchema).toBeDefined();
    expect(exportSchema).toBeDefined();
    expect(importSchema).toBeDefined();
    expect(importInsertItemSchema).toBeDefined();
    expect(importUpdateItemSchema).toBeDefined();
    expect(importOperationsSchema).toBeDefined();
  });

  it('exports config schemas', () => {
    expect(publicConfigDataSchema).toBeDefined();
    expect(publicConfigResponseSchema).toBeDefined();
  });

  it('exports constants', () => {
    expect(APP_NAME).toBe('H-Vault');
    expect(APP_VERSION).toBeDefined();
    expect(KDF_ITERATIONS).toBe(600_000);
    expect(ITEM_TYPES).toContain('login');
    expect(THEMES).toContain('dark');
    expect(ERROR_CODES.UNAUTHORIZED).toBe('UNAUTHORIZED');
    expect(PAGINATION_DEFAULTS.PAGE).toBe(1);
    expect(AUDIT_ACTIONS).toContain('login');
    expect(BACKUP_STATUSES).toContain('success');
    expect(MAX_FOLDER_NESTING_DEPTH).toBe(50);
    expect(MAX_IMPORT_ITEMS).toBe(10_000);
    expect(MAX_SESSIONS).toBe(50);
    expect(AUTH_TAG_BYTES).toBe(16);
    expect(MAX_BACKUP_EMAILS).toBe(10);
    expect(MAX_FOLDERS_PER_USER).toBe(500);
    expect(MAX_SORT_ORDER).toBe(10_000);
    expect(MAX_ENCRYPTED_NAME_LENGTH).toBe(1_000);
    expect(MAX_ENCRYPTED_DATA_LENGTH).toBe(500_000);
    expect(MAX_NOTE_CONTENT_LENGTH).toBe(50_000);
    expect(MAX_RESTORE_DATA_LENGTH).toBe(26_214_400);
    expect(MAX_IMPORT_DATA_LENGTH).toBe(1_048_576);
    expect(MAX_FILE_ENCRYPTION_SIZE_MB).toBe(100);
    expect(FILE_ENCRYPTION_FILE_EXTENSION).toBe('.enc');
  });

  it('exports utility functions', () => {
    expect(typeof maskEmail).toBe('function');
    expect(typeof formatBytes).toBe('function');
    expect(typeof generateId).toBe('function');
    expect(typeof normalizeUri).toBe('function');
  });
});
