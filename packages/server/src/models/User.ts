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
  BACKUP_RECIPIENT_STATES,
  MAX_BACKUP_EMAILS,
  MAX_RELEASE_VERSION_LENGTH,
  SHOW_RELEASE_NOTES_DEFAULT,
  SECURITY_NOTIFICATION_PREFERENCE_EVENTS,
} from '@hvault/shared';
import type {
  Theme,
  BackupStatus,
  BackupRecipientState,
  SecurityNotificationPreferenceEvent,
} from '@hvault/shared';

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

/**
 * One address mailed backups may go to (F-05). The rules that move an entry
 * between states live in `utils/backupRecipients.ts` and nowhere else.
 */
export interface IBackupRecipientDoc {
  email: string;
  state: BackupRecipientState;
  /** When the address confirmed, or was recognised as the account's own verified address. */
  confirmedAt?: Date | null | undefined;
  /**
   * When the OWNER last approved this address with the master password. Null for
   * an address carried over by migration v4 (the owner never approved it under
   * these rules, and a recipient's click must not be what grandfathers it in) and
   * for a suspended one.
   */
  approvedAt?: Date | null | undefined;
  /** A confirmation mail is owed to this address (approved, pending, not yet mailed). */
  confirmationDue?: boolean | undefined;
  /** When the confirmation now outstanding was claimed for sending. */
  confirmationSentAt?: Date | null | undefined;
  /**
   * How many times sending this entry's confirmation has FAILED since the owner
   * last approved it. After a few the job stops retrying (each attempt spends the
   * account's daily email budget), until the owner saves the list again.
   */
  confirmationAttempts?: number | undefined;
  /**
   * What the confirmation token is bound to, beside the account and the address.
   * ROTATED on every state change, so a link minted before one (a confirmation
   * already used, a recovery that suspended the entry) is refused afterwards.
   */
  nonce?: string | undefined;
}

interface IBackupSettingsDoc {
  enabled: boolean;
  scheduleHour: number;
  backupRecipients?: IBackupRecipientDoc[] | undefined;
  /**
   * Bumped by EVERY write of {@link backupRecipients}. The owner's list update
   * reads it and writes only while it has not moved, so a confirmation, a
   * suspension or the confirmation job landing in between is never overwritten
   * by a list computed from what came before it.
   */
  recipientsRevision?: number | undefined;
  /**
   * When the owner was last told that a backup was NOT mailed because nobody on the
   * list has confirmed. Told once per such episode: cleared whenever the list is
   * saved, a recipient confirms, recipients are suspended or a backup is delivered.
   */
  undeliverableNoticedAt?: Date | null | undefined;
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
  showReleaseNotes: boolean;
  /**
   * Which security events the owner is emailed about (F-26). Stored only where the
   * owner turned one OFF: an absent or `true` entry means "email me", and every
   * reply fills the missing ones in (`withSettingsDefaults`).
   */
  notifications?: Partial<Record<SecurityNotificationPreferenceEvent, boolean>> | undefined;
  backup: IBackupSettingsDoc;
}

/**
 * One factor's lockout state: the counter, the deadline, the episode the unlock
 * link is bound to, and when that link was mailed. The password factor stores
 * the same four facts in the legacy top-level fields.
 */
interface ISecondFactorLockout {
  failedAttempts?: number | undefined;
  until?: Date | undefined;
  episodeId?: string | undefined;
  notifiedAt?: Date | undefined;
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
  /**
   * The SECOND factor's lockout state, kept apart from the four fields above.
   *
   * Those four are the PASSWORD factor's state and keep their names, because
   * moving them would race live increments during a migration, orphan the
   * pinned sparse `lockoutUntil` index, read as "no lockout" to an N-1 rollback
   * and invalidate every unlock link in flight (its token is bound to
   * `lockoutEpisodeId`). This sub-document is the same four facts for the second
   * factor: written ONLY by a wrong TOTP or backup code (through the one verifier
   * in `utils/secondFactor.ts`), read ONLY by the second-factor step, and cleared
   * only by that factor's own discharges. A wrong password never touches it and a
   * wrong code never touches the password's fields: one shared counter let ten
   * wrong codes refuse the correct password with a distinct answer, which told a
   * guesser the password was right.
   *
   * Absent means "no state". It is never stored as `null`: an `$inc` on a path
   * below a `null` parent is refused by the server, so every discharge `$unset`s
   * the whole sub-document instead.
   */
  secondFactorLockout?: ISecondFactorLockout | undefined;
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
  /**
   * The newest release whose notes this account has acknowledged: the "what's
   * new" watermark.
   *
   * Written at registration (to the release the account was created on, so a new
   * account is never shown the history it arrived after) and afterwards only by
   * `POST /releases/seen`, which moves it FORWARD only and never past the running
   * version. An account created before the field existed has none, and reads as
   * `RELEASE_NOTES_BASELINE_VERSION`: the release before the notes shipped, so it
   * is shown them once.
   *
   * `select: false` because exactly one controller reads it and the profile route
   * spreads the whole document: this keeps the watermark out of the profile
   * response instead of relying on every future reader to drop it.
   */
  releaseNotesSeenVersion?: string | undefined;
  deletionPending?: boolean | undefined;
  /**
   * The bytes this account's vault rows occupy (F-24): every item and folder,
   * trashed ones included until they are purged, each counted as its stored BSON
   * size without its placement fields (`utils/vaultQuota.ts` defines the measure).
   * Written ONLY through `utils/vaultQuota.ts`: a conditional reservation before a
   * write that grows the vault, a correction after it, and the hourly recount.
   *
   * ABSENT means "not installed yet" (an account created before the quota existed),
   * never zero and never "over quota": the first write that needs it installs it
   * from the rows, and the recount and migration v3 install it for idle accounts.
   */
  vaultBytes?: number | undefined;
  /**
   * Bumped by every write of {@link vaultBytes}. The recount writes its total only
   * if this has not moved since it read the counter, so a recount can never erase a
   * reservation that landed while it was counting.
   */
  quotaEpoch?: number | undefined;
  /** When the recount last wrote {@link vaultBytes}; it takes the oldest (and absent) first. */
  quotaRecountedAt?: Date | undefined;
  /** When {@link vaultBytes} was last written by a write path; the recount leaves a busy account alone. */
  vaultBytesWrittenAt?: Date | undefined;
  /**
   * The number of vault item and folder rows the account owns, TRASHED ROWS
   * INCLUDED, which is what `MAX_ITEMS_PER_USER` and `MAX_FOLDERS_PER_USER`
   * count (F-15). Kept beside {@link vaultBytes} and moved by the same
   * conditional update, so a cap is ONE write rather than a count followed by an
   * insert. Absent (or either field absent) means "not installed yet", exactly as
   * for {@link vaultBytes}; written only through `utils/vaultQuota.ts`, and by
   * migration v6, which installs them where they are still absent.
   */
  counters?: { items?: number | undefined; folders?: number | undefined } | undefined;
  /**
   * The backup feature's emails sent for this account on one UTC day (F-05):
   * `utils/outboundMailBudget.ts` claims each send here before it happens.
   * Absent means none today.
   */
  outboundMail?: { day: string; count: number } | undefined;
  /**
   * The LAST security notice mailed to the owner (F-26): which one (`key`, the event
   * and a digest of what it said) and when. A notice identical to it within the hour
   * is not sent again; any other notice is, so the owner's latest mail is always
   * true. `utils/securityNotifications.ts` claims it with one conditional update,
   * written WITHOUT touching `updatedAt` (which the profile returns), before it
   * sends. `select: false` and never in any reply: one of the events (a correct
   * password presented during a lockout) must not be learnable through any API, and
   * a field or a timestamp that moved only after a correct guess would be the very
   * oracle the lockout's uniform answer exists to remove.
   */
  securityNotices?: { key: string; at: Date } | undefined;
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

const backupRecipientSchema = new Schema<IBackupRecipientDoc>(
  {
    email: { type: String, required: true, lowercase: true, trim: true, maxlength: 254 },
    state: { type: String, required: true, enum: BACKUP_RECIPIENT_STATES },
    confirmedAt: { type: Date, default: null },
    approvedAt: { type: Date, default: null },
    confirmationDue: { type: Boolean, default: false },
    confirmationSentAt: { type: Date, default: null },
    confirmationAttempts: { type: Number, default: 0, min: 0 },
    // `select: false` because the profile, the settings replies and the list update
    // all answer from reads of this document; every one of them also builds the
    // recipient list it returns field by field, so this is the second of two
    // things keeping the nonce off the wire, not the only one.
    nonce: { type: String, select: false, maxlength: 128 },
  },
  { _id: false },
);

const backupSettingsSchema = new Schema<IBackupSettingsDoc>(
  {
    enabled: { type: Boolean, default: false },
    scheduleHour: { type: Number, default: 3, min: 0, max: 23 },
    // No default: ABSENT is "never configured", which `confirmedRecipientsFor`
    // reads as the account's own verified address, and migration v4 converts only
    // documents that do not carry the field yet.
    backupRecipients: {
      type: [backupRecipientSchema],
      default: undefined,
      validate: {
        validator: (v: IBackupRecipientDoc[] | undefined) =>
          v === undefined || v.length <= MAX_BACKUP_EMAILS,
        message: `backupRecipients cannot exceed ${String(MAX_BACKUP_EMAILS)} entries`,
      },
    },
    recipientsRevision: { type: Number, default: undefined },
    undeliverableNoticedAt: { type: Date, default: undefined },
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
    showReleaseNotes: { type: Boolean, default: SHOW_RELEASE_NOTES_DEFAULT },
    // One optional Boolean per event and NO default: absent is "email me", so an
    // event added later is on for every account without a backfill.
    notifications: {
      type: new Schema<Partial<Record<SecurityNotificationPreferenceEvent, boolean>>>(
        Object.fromEntries(
          SECURITY_NOTIFICATION_PREFERENCE_EVENTS.map((event) => [event, { type: Boolean }]),
        ),
        { _id: false },
      ),
      default: undefined,
    },
    backup: { type: backupSettingsSchema, default: () => ({}) },
  },
  { _id: false },
);

const secondFactorLockoutSchema = new Schema<ISecondFactorLockout>(
  {
    failedAttempts: { type: Number, default: undefined },
    until: { type: Date, default: undefined },
    episodeId: { type: String, default: undefined },
    notifiedAt: { type: Date, default: undefined },
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
    // `select: false` for the reasons its password twins above carry, and one
    // more: every reader goes through `utils/lockout.ts`, which asks for it by
    // name, so a projection that forgets it cannot silently read "not locked".
    secondFactorLockout: { type: secondFactorLockoutSchema, select: false, default: undefined },
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
    // No schema default, deliberately: a HYDRATED read applies defaults, so a
    // default here would make every legacy account look as if it had seen the
    // current notes, and the next `save()` of such a document would persist that.
    // Registration writes the value explicitly instead.
    releaseNotesSeenVersion: {
      type: String,
      select: false,
      maxlength: MAX_RELEASE_VERSION_LENGTH,
      default: undefined,
    },
    deletionPending: { type: Boolean, default: undefined },
    // No schema default on any of the four: ABSENT is the state "not installed yet"
    // that the quota helper installs from the rows, and a default would make every
    // hydrated legacy account read as an empty vault (see the docblocks on `IUser`).
    // The three bookkeeping fields are `select: false` because the profile answers
    // with a spread of the whole document.
    vaultBytes: { type: Number, default: undefined },
    quotaEpoch: { type: Number, default: undefined, select: false },
    quotaRecountedAt: { type: Date, default: undefined, select: false },
    vaultBytesWrittenAt: { type: Date, default: undefined, select: false },
    // The row counters behind the per-user caps (F-15), under the same rule: no
    // default, because absent is "not installed yet" and a default would read as
    // an empty vault. `select: false` keeps them out of the profile's spread; the
    // quota module reads them through the driver.
    counters: {
      type: new Schema<{ items?: number; folders?: number }>(
        { items: { type: Number }, folders: { type: Number } },
        { _id: false },
      ),
      select: false,
      default: undefined,
    },
    // No default and `select: false`: absent is "nothing sent today", and nothing
    // but the budget helper reads it (the profile spreads the whole document).
    outboundMail: {
      type: new Schema<{ day: string; count: number }>(
        { day: { type: String, maxlength: 10 }, count: { type: Number, min: 0 } },
        { _id: false },
      ),
      default: undefined,
      select: false,
    },
    // No default and `select: false`: see the interface. Nothing but the
    // notification helper reads it.
    securityNotices: {
      type: new Schema<{ key: string; at: Date }>(
        { key: { type: String, maxlength: 100 }, at: { type: Date } },
        { _id: false },
      ),
      default: undefined,
      select: false,
    },
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
// The hourly vault-quota recount takes the accounts recounted longest ago (and those
// never recounted, which sort first) in bounded batches.
userSchema.index({ quotaRecountedAt: 1 });
// The hourly confirmation step (`jobs/maintenance.ts`) finds the accounts that owe a
// recipient a confirmation mail. Partial, so it holds only those few accounts and the
// step never walks `users`.
userSchema.index(
  { 'settings.backup.backupRecipients.confirmationDue': 1 },
  { partialFilterExpression: { 'settings.backup.backupRecipients.confirmationDue': true } },
);

// ----- Model -----

export const User: Model<IUser> = mongoose.model<IUser>('User', userSchema);
