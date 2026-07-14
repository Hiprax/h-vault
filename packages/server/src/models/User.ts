import mongoose, { Schema, type Model, type HydratedDocument, type Types } from 'mongoose';
import {
  KDF_ITERATIONS,
  KDF_ALGORITHM,
  ENCRYPTION_VERSION,
  AUTO_LOCK_TIMEOUT_MINUTES,
  CLIPBOARD_CLEAR_SECONDS,
  DEFAULT_PASSWORD_LENGTH,
  MAX_BACKUP_EMAILS,
} from '@hvault/shared';
import type { Theme, BackupStatus } from '@hvault/shared';

// ----- Sub-interfaces -----

export interface IPasswordGenOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
  excludeAmbiguous: boolean;
  minNumbers: number;
  minSymbols: number;
}

export interface IBackupSettingsDoc {
  enabled: boolean;
  scheduleHour: number;
  backupEmails?: string[] | undefined;
  encryptedBWK?: string | undefined;
  bwkIv?: string | undefined;
  bwkTag?: string | undefined;
  bwkSalt?: string | undefined;
  bwkEncryptedVaultKey?: string | undefined;
  bwkVaultKeyIv?: string | undefined;
  bwkVaultKeyTag?: string | undefined;
  lastBackupAt?: Date | undefined;
  lastBackupStatus?: BackupStatus | undefined;
  isConfigured: boolean;
}

export interface IUserSettings {
  autoLockTimeout: number;
  clipboardClearTimeout: number;
  defaultPasswordLength: number;
  defaultPasswordOptions: IPasswordGenOptions;
  theme: Theme;
  language: string;
  backup: IBackupSettingsDoc;
}

// ----- Main Interface -----

export interface IUser {
  _id: Types.ObjectId;
  email: string;
  emailVerified: boolean;
  authHash: string;
  encryptedVaultKey: string;
  vaultKeyIv: string;
  vaultKeyTag: string;
  kdfIterations: number;
  kdfAlgorithm: string;
  encryptionVersion: number;
  twoFactorEnabled: boolean;
  twoFactorSecret?: string | undefined;
  pendingTwoFactorSecret?: string | undefined;
  pendingTwoFactorExpiry?: Date | undefined;
  backupCodes?: string[] | undefined;
  failedLoginAttempts: number;
  lockoutUntil?: Date | undefined;
  lastRotationKey?: string | undefined;
  lastRotationAt?: Date | undefined;
  rotationInProgress: boolean;
  pendingEncryptedVaultKey?: string | undefined;
  pendingVaultKeyIv?: string | undefined;
  pendingVaultKeyTag?: string | undefined;
  lastTotpTimestamp?: number | undefined;
  deletionPending?: boolean | undefined;
  passwordChangedAt: Date;
  settings: IUserSettings;
  createdAt: Date;
  updatedAt: Date;
}

export type UserDocument = HydratedDocument<IUser>;

// ----- Sub-Schemas -----

const passwordGenOptionsSchema = new Schema<IPasswordGenOptions>(
  {
    length: {
      type: Number,
      default: DEFAULT_PASSWORD_LENGTH,
      validate: {
        validator: function (value: number) {
          // `this` may be the subdocument (on save) or the query (on update
          // validators). Narrow via a structural read so we only use sibling
          // values when present; otherwise the parent path validator below
          // catches the invariant.
          const ctx = this as unknown as Partial<IPasswordGenOptions> | undefined;
          const minNumbers = typeof ctx?.minNumbers === 'number' ? ctx.minNumbers : 0;
          const minSymbols = typeof ctx?.minSymbols === 'number' ? ctx.minSymbols : 0;
          return value >= minNumbers + minSymbols;
        },
        message: 'Password length must be at least the sum of minNumbers and minSymbols',
      },
    },
    uppercase: { type: Boolean, default: true },
    lowercase: { type: Boolean, default: true },
    numbers: { type: Boolean, default: true },
    symbols: { type: Boolean, default: true },
    excludeAmbiguous: { type: Boolean, default: false },
    minNumbers: { type: Number, default: 1 },
    minSymbols: { type: Number, default: 1 },
  },
  { _id: false },
);

// Defense-in-depth: validate the full subdocument at the parent path so the
// constraint is enforced even when only sibling fields (minNumbers/minSymbols)
// are bumped without changing `length`, and during `findOneAndUpdate` where a
// field-level `this` may be bound to the query rather than the subdocument.
const passwordGenOptionsCrossFieldValidator = {
  validator: function (value: IPasswordGenOptions | undefined | null) {
    if (!value) return true;
    const length = typeof value.length === 'number' ? value.length : 0;
    const minNumbers = typeof value.minNumbers === 'number' ? value.minNumbers : 0;
    const minSymbols = typeof value.minSymbols === 'number' ? value.minSymbols : 0;
    return length >= minNumbers + minSymbols;
  },
  message: 'Password length must be at least the sum of minNumbers and minSymbols',
};

const backupSettingsSchema = new Schema<IBackupSettingsDoc>(
  {
    enabled: { type: Boolean, default: false },
    scheduleHour: { type: Number, default: 3, min: 0, max: 23 },
    backupEmails: {
      type: [{ type: String, maxlength: 254 }],
      default: [],
      validate: {
        validator: (v: string[]) => v.length <= MAX_BACKUP_EMAILS,
        message: `backupEmails cannot exceed ${String(MAX_BACKUP_EMAILS)} entries`,
      },
    },
    encryptedBWK: { type: String, maxlength: 500 },
    bwkIv: { type: String, maxlength: 24 },
    bwkTag: { type: String, maxlength: 32 },
    bwkSalt: { type: String, maxlength: 64 },
    bwkEncryptedVaultKey: { type: String, maxlength: 500 },
    bwkVaultKeyIv: { type: String, maxlength: 24 },
    bwkVaultKeyTag: { type: String, maxlength: 32 },
    lastBackupAt: { type: Date },
    lastBackupStatus: { type: String, enum: ['success', 'failed'] },
    isConfigured: { type: Boolean, default: false },
  },
  { _id: false },
);

const userSettingsSchema = new Schema<IUserSettings>(
  {
    autoLockTimeout: { type: Number, default: AUTO_LOCK_TIMEOUT_MINUTES },
    clipboardClearTimeout: { type: Number, default: CLIPBOARD_CLEAR_SECONDS },
    defaultPasswordLength: { type: Number, default: DEFAULT_PASSWORD_LENGTH },
    defaultPasswordOptions: {
      type: passwordGenOptionsSchema,
      default: () => ({}),
      validate: passwordGenOptionsCrossFieldValidator,
    },
    theme: { type: String, enum: ['light', 'dark', 'system'], default: 'system' },
    language: { type: String, default: 'en' },
    backup: { type: backupSettingsSchema, default: () => ({}) },
  },
  { _id: false },
);

// ----- Main Schema -----

const userSchema = new Schema<IUser>(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      maxlength: 254,
    },
    emailVerified: { type: Boolean, default: false },
    authHash: { type: String, required: true, select: false, maxlength: 100 },
    encryptedVaultKey: { type: String, required: true, maxlength: 200 },
    vaultKeyIv: { type: String, required: true, maxlength: 24 },
    vaultKeyTag: { type: String, required: true, maxlength: 32 },
    kdfIterations: { type: Number, required: true, default: KDF_ITERATIONS },
    kdfAlgorithm: { type: String, required: true, default: KDF_ALGORITHM },
    encryptionVersion: { type: Number, required: true, default: ENCRYPTION_VERSION },
    twoFactorEnabled: { type: Boolean, default: false },
    twoFactorSecret: { type: String, select: false, maxlength: 500 },
    pendingTwoFactorSecret: { type: String, select: false, maxlength: 500 },
    pendingTwoFactorExpiry: { type: Date, select: false },
    backupCodes: { type: [String], select: false },
    failedLoginAttempts: { type: Number, default: 0 },
    lockoutUntil: { type: Date },
    lastRotationKey: { type: String, default: undefined },
    lastRotationAt: { type: Date, default: undefined },
    rotationInProgress: { type: Boolean, default: false },
    pendingEncryptedVaultKey: { type: String, maxlength: 200, default: undefined },
    pendingVaultKeyIv: { type: String, maxlength: 24, default: undefined },
    pendingVaultKeyTag: { type: String, maxlength: 32, default: undefined },
    lastTotpTimestamp: { type: Number, default: undefined },
    deletionPending: { type: Boolean, default: undefined },
    passwordChangedAt: { type: Date, required: true, default: () => new Date(0) },
    settings: { type: userSettingsSchema, default: () => ({}) },
  },
  {
    timestamps: true,
    collection: 'users',
    toJSON: {
      transform(_doc, ret) {
        const {
          authHash: _authHash,
          twoFactorSecret: _twoFactorSecret,
          backupCodes: _backupCodes,
          passwordChangedAt: _passwordChangedAt,
          __v,
          ...rest
        } = ret;
        return rest;
      },
    },
  },
);

// ----- Indexes -----
// Note: email index is already created by `unique: true` on the field definition
userSchema.index({ emailVerified: 1 });
userSchema.index({ lockoutUntil: 1 }, { sparse: true });
userSchema.index({
  'settings.backup.enabled': 1,
  'settings.backup.scheduleHour': 1,
});
// Supports the zombie-user cleanup scan in `jobs/tokenCleanup.ts`
// (`User.find({ deletionPending: true })`, every 6h). `deletionPending` defaults
// to `undefined`, so it is absent on virtually every user; a partial index keyed
// on `{ deletionPending: true }` therefore holds only the tiny set of users
// mid-deletion and is planner-eligible for the exact-equality query (avoiding a
// full COLLSCAN of `users`).
userSchema.index({ deletionPending: 1 }, { partialFilterExpression: { deletionPending: true } });

// ----- Model -----

export const User: Model<IUser> = mongoose.model<IUser>('User', userSchema);
