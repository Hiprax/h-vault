import mongoose, { Schema, type Model, type Types } from 'mongoose';
import {
  KDF_ITERATIONS,
  KDF_ALGORITHM,
  ENCRYPTION_VERSION,
  AUTO_LOCK_TIMEOUT_MINUTES,
  LOCK_ON_HIDDEN_DEFAULT,
  LOCK_ON_HIDDEN_DELAY_MINUTES,
  CLIPBOARD_CLEAR_SECONDS,
  DEFAULT_PASSWORD_LENGTH,
  MAX_BACKUP_EMAILS,
} from '@hvault/shared';
import type { Theme, BackupStatus } from '@hvault/shared';

// ----- Sub-interfaces -----

interface IPasswordGenOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
  excludeAmbiguous: boolean;
  minUppercase: number;
  minLowercase: number;
  minNumbers: number;
  minSymbols: number;
}

interface IBackupSettingsDoc {
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
  lockOnHidden: boolean;
  lockOnHiddenDelay: number;
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
  /**
   * Identifies the LOCK EPISODE a `lockoutUntil` belongs to.
   *
   * Minted when a lockout begins, carried UNCHANGED through every re-lock, and
   * cleared only when the lockout is genuinely discharged (the emailed link is
   * used, an authentication completes, a served lockout is spent, the password is
   * reset). The emailed unlock token's `stateHash` binds to this value.
   *
   * It exists because binding that token to `lockoutUntil` made it die on the
   * next failed attempt: `failedLoginAttempts` is cleared only where an
   * authentication COMPLETES, so an abandoned lockout sits at the threshold for
   * ever and every later wrong password re-wrote the deadline, invalidating the
   * one recovery link the owner had been sent while the `=== MAX_FAILED_ATTEMPTS`
   * mail guard suppressed a replacement. Anyone who knew an email address could
   * hold an account locked indefinitely, and this product's password reset mints a
   * fresh vault key, so the remaining "recovery" was total data loss.
   *
   * Opaque and server-minted. Several tokens can name the same episode; they are
   * the same capability, and the first one used clears this field and kills them
   * all at once.
   */
  lockoutEpisodeId?: string | undefined;
  /**
   * When the unlock link currently outstanding for {@link lockoutEpisodeId} was
   * minted. Read only to decide whether a re-lock needs to mail a replacement,
   * which it does exactly when the outstanding token would expire before the new
   * lockout ends. Cleared with the rest of the episode.
   */
  lockoutNotifiedAt?: Date | undefined;
  lastRotationKey?: string | undefined;
  lastRotationAt?: Date | undefined;
  rotationInProgress: boolean;
  pendingEncryptedVaultKey?: string | undefined;
  pendingVaultKeyIv?: string | undefined;
  pendingVaultKeyTag?: string | undefined;
  lastTotpTimestamp?: number | undefined;
  /**
   * How many times this account's vault key has been rotated.
   *
   * Incremented ONLY by a successful `bulkReEncrypt`, in the same update document
   * that `$set`s the new vault key, so the two can never disagree. A document
   * upload records the version its DEK was wrapped under at init and completion
   * refuses with 409 when it no longer matches — which is what stops a rotation
   * that ran mid-transfer from committing a DEK nothing can unwrap. A password
   * change must NOT touch it: that flow re-wraps the SAME vault key under a new
   * MEK, so an upload spanning a password change is still valid.
   *
   * OPTIONAL in this interface even though the schema defaults it to 0, and the
   * asymmetry is the point. A hydrated read applies the default on the way out,
   * so `User.findById()` always yields a number — but a `.lean()` read or a raw
   * collection read of an account created BEFORE this field existed yields
   * `undefined`, and those reads are what the hot paths use. Declaring it
   * required would type that `undefined` as a `number` and hand every consumer a
   * silent `NaN` the first time it did arithmetic on an older account. Read it as
   * `?? 0`.
   */
  vaultKeyVersion?: number | undefined;
  deletionPending?: boolean | undefined;
  passwordChangedAt: Date;
  settings: IUserSettings;
  createdAt: Date;
  updatedAt: Date;
}

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
    // The two newer minimums default to 0 because nothing is stored for them.
    // `minNumbers`/`minSymbols` keep their default of 1, which Mongoose has been
    // materialising on every account since this subdocument existed, so changing
    // it would move stored data rather than preserve it.
    //
    // None of the four carries `min`/`max`. A model-level maximum would be the
    // only narrowing in this change set and could fail a save on a legacy
    // document; the bound is applied by the generator and the settings read
    // path, which clamp rather than reject.
    minUppercase: { type: Number, default: 0 },
    minLowercase: { type: Number, default: 0 },
    minNumbers: { type: Number, default: 1 },
    minSymbols: { type: Number, default: 1 },
  },
  { _id: false },
);

// Defense-in-depth: validate the full subdocument at the parent path so the
// constraint is enforced even when only sibling minimums are bumped without
// changing `length`, and during `findOneAndUpdate` where a field-level `this`
// may be bound to the query rather than the subdocument.
//
// Counts a minimum only while its class is enabled, matching
// `passwordGenOptionsSchema`. The two must agree, and the reason the shared
// schema counts this way is that its per-field defaults are applied
// independently of the class booleans, so `{ numbers: false, minNumbers: 1 }` is
// a shape it emits and which is already persisted here.
const numberOr = (value: unknown, fallback: number): number =>
  typeof value === 'number' ? value : fallback;

// A class counts as enabled unless it is explicitly switched off, so a legacy
// document that predates one of these booleans is treated as having it on,
// matching the schema defaults. Takes `unknown` because the declared type says
// `boolean` while a lean read of an old document may carry nothing at all.
const classEnabled = (value: unknown): boolean => value !== false;

const passwordGenOptionsCrossFieldValidator = {
  validator: function (value: IPasswordGenOptions | undefined | null) {
    if (!value) return true;
    const length = numberOr(value.length, 0);
    const required =
      (classEnabled(value.uppercase) ? numberOr(value.minUppercase, 0) : 0) +
      (classEnabled(value.lowercase) ? numberOr(value.minLowercase, 0) : 0) +
      (classEnabled(value.numbers) ? numberOr(value.minNumbers, 0) : 0) +
      (classEnabled(value.symbols) ? numberOr(value.minSymbols, 0) : 0);
    return length >= required;
  },
  message: 'Password length must be at least the sum of the required character minimums',
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
    lockOnHidden: { type: Boolean, default: LOCK_ON_HIDDEN_DEFAULT },
    lockOnHiddenDelay: { type: Number, default: LOCK_ON_HIDDEN_DELAY_MINUTES },
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
    // Both default to `undefined` rather than to a value, because their ABSENCE is
    // the state "no lock episode is running" that the start-or-extend write in
    // `authController` relies on: its `$ifNull` mints an identity only when the
    // field is missing or null, which is what makes exactly one of N concurrent
    // failed attempts the one that starts the episode.
    //
    // `select: false` on both, unlike `lockoutUntil` beside them, because
    // `getProfile` answers with a `.lean()` spread of the whole document minus two
    // named fields — so anything not hidden at the schema is on the wire. Neither
    // of these is a credential (the unlock link is a signed JWT; knowing the
    // episode identity forges nothing) and only the account's own session could
    // read them, but they are internal bookkeeping with no client that wants them,
    // and an opt-out projection is the wrong place to decide that. The two readers
    // that DO want `lockoutEpisodeId` ask for it by name, and both are covered by
    // tests that go red the moment one stops: `registerFailedAuthAttempt`'s
    // read-back would mail no link at all, and `unlockAccount` would reject every
    // link there is.
    lockoutEpisodeId: { type: String, select: false, default: undefined },
    lockoutNotifiedAt: { type: Date, select: false, default: undefined },
    lastRotationKey: { type: String, default: undefined },
    lastRotationAt: { type: Date, default: undefined },
    rotationInProgress: { type: Boolean, default: false },
    pendingEncryptedVaultKey: { type: String, maxlength: 200, default: undefined },
    pendingVaultKeyIv: { type: String, maxlength: 24, default: undefined },
    pendingVaultKeyTag: { type: String, maxlength: 32, default: undefined },
    lastTotpTimestamp: { type: Number, default: undefined },
    // `default: 0` rather than `default: undefined`, so a freshly created account
    // starts at a definite version and the very first upload has something to
    // compare against. Existing accounts have no such value written for them:
    // there is no backfill migration, because the only consumer treats a missing
    // value as 0 and MongoDB's `$inc` does the same, so a legacy account is
    // indistinguishable from one that has never rotated — which is exactly what it
    // is. See the field's docblock on `IUser` for why it is typed optional anyway.
    vaultKeyVersion: { type: Number, default: 0 },
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
