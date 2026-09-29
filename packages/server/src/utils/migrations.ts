import crypto from 'node:crypto';
import mongoose from 'mongoose';
import { MAX_BACKUP_EMAILS, maskEmail } from '@hvault/shared';
import { z } from 'zod';
import { createModuleLogger } from './logger.js';
import { Migration } from '../models/Migration.js';
import { JobLock } from '../models/JobLock.js';
import { acquireJobLock, releaseJobLock } from './jobLock.js';

const logger = createModuleLogger('migrations');

/**
 * Distributed-lock identity for the migration runner. Acquiring this lock
 * serializes migration application across clustered workers / hosts.
 */
const MIGRATION_LOCK_NAME = 'migrations';
/**
 * Lock TTL. Generous enough for any boot-time data migration; if a holder
 * crashes mid-run, the JobLock TTL index reaps the lock so the next boot can
 * re-acquire and resume.
 */
const MIGRATION_LOCK_TTL_MS = 10 * 60 * 1000;

export interface MigrationDefinition {
  version: number;
  name: string;
  up: () => Promise<void>;
}

/**
 * Registry of all migration scripts. Each migration has a unique version number,
 * a descriptive name, and an `up` function that performs the migration.
 *
 * Migrations are applied in version order and tracked in the `migrations`
 * collection so they run only once.
 */
const migrations: MigrationDefinition[] = [
  {
    version: 1,
    name: 'initial-schema',
    up() {
      // v1: baseline — current schema as of initial release.
      // No data transformations needed; this migration exists solely to
      // establish the migration tracking baseline.
      logger.info('Migration v1: baseline schema recorded');
      return Promise.resolve();
    },
  },
  {
    version: 2,
    name: 'audit-log-bounds',
    async up() {
      await migrateAuditLogIndexTiebreak();
      await maskLegacyErasureRecords();
    },
  },
  // v3 is the vault-quota counter install of the tenant-admission work, not yet
  // written; versions are applied by set membership, never by "greater than the
  // highest applied", so a v3 added later still runs on a database that has v4.
  {
    version: 4,
    name: 'backup-recipients',
    up: migrateBackupRecipients,
  },
];

/** How many accounts one write batch of migration v4 converts. */
const BACKUP_RECIPIENT_MIGRATION_BATCH = 500;
/** A recipient address as the recipient schema accepts it. */
const MIGRATED_RECIPIENT_EMAIL = z.email().max(254);

/**
 * v4 — backup recipients become entries that must confirm (F-05).
 *
 * Every account that stored a plain `settings.backup.backupEmails` list gets
 * `settings.backup.backupRecipients` instead: its own verified address
 * `confirmed`, every other address `pending` and NOT approved (invalid entries
 * dropped, duplicates merged, at most MAX_BACKUP_EMAILS kept), and the old field
 * removed. The older single `backupEmail` is REMOVED WITHOUT BEING COPIED: no
 * release this one replaces ever mailed it (only the list was read), so copying
 * it would bring back an address its owner had replaced, and would stop the
 * backups an account with no list receives at its own address today. It sends NO
 * mail and owes none: a
 * confirmation is only ever mailed for an address the OWNER approves with the
 * master password, because the recipient's click proves the recipient agrees,
 * never that the owner put the address there. Until the owner approves the list
 * those addresses receive nothing, the account's own address keeps receiving, and
 * a run with neither tells the owner.
 *
 * Raw collection reads and writes (the model no longer declares the old fields),
 * in batches, each write conditioned on the account not having a recipient list
 * yet, so a re-run, or a list the owner saved meanwhile, is left alone.
 */
async function migrateBackupRecipients(): Promise<void> {
  const users = mongoose.connection.collection('users');
  // The index the hourly confirmation step is HINTED onto, built here as v2 builds
  // its own: production runs with `autoIndex` off, and a deployment that has not
  // run `create-indexes` yet must not have that step throw every hour. The spec is
  // a literal, the same one `models/User.ts` declares; an existing identical index
  // is a no-op, and one of the same name built differently is left to
  // `create-indexes` to report.
  try {
    await users.createIndex(
      { 'settings.backup.backupRecipients.confirmationDue': 1 },
      { partialFilterExpression: { 'settings.backup.backupRecipients.confirmationDue': true } },
    );
  } catch (error: unknown) {
    if (!hasCode(error, INDEX_OPTIONS_CONFLICT) && !hasCode(error, INDEX_KEY_SPECS_CONFLICT)) {
      throw error;
    }
  }
  // No recipient list yet, or an EMPTY one (a hydrated save of the new schema
  // cannot write one, but nothing else guarantees it), beside an old list.
  const noRecipients = {
    $or: [
      { 'settings.backup.backupRecipients': { $exists: false } },
      { 'settings.backup.backupRecipients': { $size: 0 } },
    ],
  };
  const cursor = users.find(
    { ...noRecipients, 'settings.backup.backupEmails.0': { $exists: true } },
    { projection: { email: 1, emailVerified: 1, 'settings.backup.backupEmails': 1 } },
  );
  let batch: mongoose.mongo.AnyBulkWriteOperation[] = [];
  let converted = 0;
  const now = new Date();
  for await (const account of cursor) {
    // The query guarantees `settings.backup.backupEmails.0` exists, so the path is
    // there; the value is still raw data, and anything but an array lists nobody.
    const { backupEmails } = (account.settings as { backup: { backupEmails: unknown } }).backup;
    const listed: unknown[] = Array.isArray(backupEmails) ? backupEmails : [];
    const email = String(account.email);
    const verified = account.emailVerified === true;
    // The same rules the recipient schema applies, because every later hydrated
    // save of the account re-validates these entries: one bad entry would make
    // that save fail.
    const addresses = [
      ...new Set(
        listed
          .filter((value): value is string => typeof value === 'string')
          .map((value) => value.trim().toLowerCase())
          .filter((value) => MIGRATED_RECIPIENT_EMAIL.safeParse(value).success),
      ),
    ].slice(0, MAX_BACKUP_EMAILS);
    const recipients = addresses.map((address) =>
      address === email && verified
        ? {
            email: address,
            state: 'confirmed',
            confirmedAt: now,
            approvedAt: now,
            confirmationDue: false,
            confirmationSentAt: null,
            confirmationAttempts: 0,
            nonce: crypto.randomBytes(32).toString('hex'),
          }
        : {
            email: address,
            state: 'pending',
            confirmedAt: null,
            approvedAt: null,
            confirmationDue: false,
            confirmationSentAt: null,
            confirmationAttempts: 0,
            nonce: crypto.randomBytes(32).toString('hex'),
          },
    );
    batch.push({
      updateOne: {
        filter: { _id: account._id, ...noRecipients },
        update: {
          $set: {
            'settings.backup.backupRecipients': recipients,
            'settings.backup.recipientsRevision': 1,
          },
          $unset: { 'settings.backup.backupEmails': '', 'settings.backup.backupEmail': '' },
        },
      },
    });
    if (batch.length >= BACKUP_RECIPIENT_MIGRATION_BATCH) {
      converted += (await users.bulkWrite(batch, { ordered: false })).modifiedCount;
      batch = [];
    }
  }
  if (batch.length > 0) {
    converted += (await users.bulkWrite(batch, { ordered: false })).modifiedCount;
  }
  // Every other account carries only the old schema's EMPTY default (`[]`) and
  // perhaps a stale single `backupEmail` nothing ever read: nothing to convert, so
  // both just go. An account with no list keeps mailing its own verified address,
  // as it always did. A non-empty old list is kept only on an account it has not
  // been converted for yet (a batch that failed), so the next run still finds it.
  const cleared = await users.updateMany(
    {
      $and: [
        {
          $or: [
            { 'settings.backup.backupEmails': { $exists: true } },
            { 'settings.backup.backupEmail': { $exists: true } },
          ],
        },
        {
          $or: [
            { 'settings.backup.backupEmails.0': { $exists: false } },
            { 'settings.backup.backupRecipients.0': { $exists: true } },
          ],
        },
      ],
    },
    { $unset: { 'settings.backup.backupEmails': '', 'settings.backup.backupEmail': '' } },
  );
  logger.info(
    `Migration v4: converted the backup recipients of ${String(converted)} account(s); cleared the empty legacy field on ${String(cleared.modifiedCount)}`,
  );
}

/** `IndexNotFound`: dropping an index that is not there. */
const INDEX_NOT_FOUND = 27;
/** `NamespaceNotFound`: dropping an index of a collection that does not exist. */
const NAMESPACE_NOT_FOUND = 26;
/** `IndexOptionsConflict`: an index on these keys exists with other options or name. */
const INDEX_OPTIONS_CONFLICT = 85;
/** `IndexKeySpecsConflict`: an index of this name exists on other keys. */
const INDEX_KEY_SPECS_CONFLICT = 86;

function hasCode(error: unknown, code: number): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === code;
}

/**
 * v2 — the audit log's two page indexes gain `_id` (F-02), and the two they
 * replace are dropped.
 *
 * `GET /user/audit-log` sorts `{timestamp: -1, _id: -1}`, a total order its
 * `skip`/`limit` pages need; the old `{userId, timestamp}` and `{userId, action,
 * timestamp}` cannot serve the `_id` half, so every page was a blocking sort over
 * every row the account had. `models/AuditLog.ts` now declares the extended pair,
 * but `create-indexes` never removes an index the schema stopped declaring (the
 * only index it drops is a declared expiry index it rebuilds), so without this
 * the two superseded indexes would linger on every existing deployment and cost
 * every audit insert for nothing.
 *
 * The new pair is built FIRST, here, and only then are the old ones dropped: a
 * deployment that boots before its operator has run `create-indexes` (PM2, where
 * that step is manual) must never pass through a moment with neither, and
 * `createIndex` of an index that already exists is a no-op. The specs are written
 * out rather than read from the model, because a migration records what one
 * version of the schema needed and must not change meaning when the model does.
 * Only these two indexes are named: building the model's whole index set here
 * could fail the boot on an operator's own TTL (a changed retention is an options
 * conflict until `create-indexes` rebuilds that index; see `ttlIndexReconcile.ts`).
 *
 * Idempotent: every step tolerates having already happened, and a collection
 * that does not exist yet is simply created with the right indexes.
 */
async function migrateAuditLogIndexTiebreak(): Promise<void> {
  const auditLogs = mongoose.connection.collection('audit_logs');
  for (const keys of [
    { userId: 1, timestamp: -1, _id: -1 },
    { userId: 1, action: 1, timestamp: -1, _id: -1 },
  ] as const) {
    try {
      await auditLogs.createIndex(keys);
    } catch (error: unknown) {
      // An operator who built one by hand under another name or options already
      // has what the page needs; refusing the boot over it would help nobody.
      if (!hasCode(error, INDEX_OPTIONS_CONFLICT) && !hasCode(error, INDEX_KEY_SPECS_CONFLICT)) {
        throw error;
      }
      logger.warn('Migration v2: an audit index on these keys already exists as built', { keys });
    }
  }
  for (const name of ['userId_1_timestamp_-1', 'userId_1_action_1_timestamp_-1']) {
    try {
      await auditLogs.dropIndex(name);
      logger.info(`Migration v2: dropped superseded audit index ${name}`);
    } catch (error: unknown) {
      if (!hasCode(error, INDEX_NOT_FOUND) && !hasCode(error, NAMESPACE_NOT_FOUND)) throw error;
    }
  }
}

/**
 * v2, second step — the erasure records written before this version name the
 * erased account's address in clear (`metadata.deletedEmail`), for a year. Each
 * is rewritten to the masked form the cascade now writes (`metadata.maskedEmail`,
 * `maskEmail` from shared), and the plaintext field removed.
 *
 * Idempotent because the field is RENAMED: a row already rewritten no longer
 * carries `deletedEmail`, so it is never masked twice (and `maskEmail` is not
 * idempotent on a one-character local part). Each update is conditioned on the
 * value it read.
 */
async function maskLegacyErasureRecords(): Promise<void> {
  const auditLogs = mongoose.connection.collection('audit_logs');
  const legacy = auditLogs.find(
    {
      userId: null,
      action: { $in: ['account_delete', 'deletion_cleanup'] },
      'metadata.deletedEmail': { $type: 'string' },
    },
    { projection: { 'metadata.deletedEmail': 1 } },
  );
  let pending: mongoose.mongo.AnyBulkWriteOperation[] = [];
  let masked = 0;
  const flush = async (): Promise<void> => {
    if (pending.length === 0) return;
    const result = await auditLogs.bulkWrite(pending, { ordered: false });
    masked += result.modifiedCount;
    pending = [];
  };
  for await (const row of legacy) {
    const plain = (row as { metadata?: { deletedEmail?: unknown } }).metadata?.deletedEmail;
    if (typeof plain !== 'string') continue;
    pending.push({
      updateOne: {
        filter: { _id: row._id, 'metadata.deletedEmail': plain },
        update: {
          $set: { 'metadata.maskedEmail': maskEmail(plain) },
          $unset: { 'metadata.deletedEmail': '' },
        },
      },
    });
    if (pending.length >= 500) await flush();
  }
  await flush();
  if (masked > 0) {
    logger.info(`Migration v2: masked the address in ${String(masked)} erasure record(s)`);
  }
}

/**
 * Build the `JobLock.jobName` and `Migration.version` unique indexes before the
 * migration lock is acquired.
 *
 * The migration runner's mutual exclusion depends on the UNIQUE index on
 * `JobLock.jobName` (two workers both upserting the `migrations` lock are
 * serialized only because the second hits an E11000) and the tracking dedup
 * depends on the UNIQUE index on `Migration.version`. In production `autoIndex`
 * is disabled and index creation is a separate manual step
 * (`npm run create-indexes`), so on a fresh cluster boot these indexes may not
 * exist yet — leaving the lock without any uniqueness to serialize on and
 * allowing duplicate `Migration.version` rows (which then break the manual
 * `create-indexes` step). Build these two tiny indexes idempotently here,
 * regardless of `NODE_ENV`, so mutual exclusion never depends on the manual
 * step. `createIndexes()` on an already-indexed collection is a safe no-op.
 */
async function ensureLockIndexes(): Promise<void> {
  await JobLock.createIndexes();
  await Migration.createIndexes();
}

/** True for a MongoDB duplicate-key (E11000) error. */
function isDuplicateKeyError(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 11000;
}

/**
 * Apply every pending migration in version order. Assumes the caller holds the
 * migration lock so this runs without concurrency, but each tracking insert is
 * still guarded against E11000 as defense-in-depth (the `version` unique index
 * is the final barrier against double-recording).
 */
async function applyPendingMigrations(migrationList: MigrationDefinition[]): Promise<void> {
  const applied = await Migration.find().lean();
  const appliedVersions = new Set(applied.map((m) => m.version));

  const pending = migrationList
    .filter((m) => !appliedVersions.has(m.version))
    .sort((a, b) => a.version - b.version);

  if (pending.length === 0) {
    logger.info('No pending migrations');
    return;
  }

  logger.info(`Running ${String(pending.length)} pending migration(s)...`);

  for (const migration of pending) {
    logger.info(`Applying migration v${String(migration.version)}: ${migration.name}`);
    // Run the side effects first; the tracking row is only written once `up()`
    // resolves, so a failed migration is left un-recorded and retried next boot.
    await migration.up();
    try {
      await Migration.create({
        version: migration.version,
        name: migration.name,
        appliedAt: new Date(),
      });
    } catch (error: unknown) {
      if (isDuplicateKeyError(error)) {
        logger.warn(
          `Migration v${String(migration.version)} was already recorded by another process; skipping tracking insert`,
        );
        continue;
      }
      throw error;
    }
    logger.info(`Migration v${String(migration.version)} applied successfully`);
  }

  logger.info('All migrations applied');
}

/**
 * Run all pending migrations in version order.
 *
 * Called at server startup after the database connection is established.
 * Each migration is applied at most once — the `migrations` collection tracks
 * which versions have already been applied.
 *
 * Concurrency: `runMigrations()` runs on every clustered worker at boot (PM2
 * cluster mode starts multiple instances). A distributed lock ensures only one
 * process applies migrations at a time, preventing two workers from racing the
 * find→up()→create sequence and double-applying a non-idempotent migration (or
 * crashing a worker on the `version` unique-index E11000). A process that loses
 * the lock skips cleanly — the holder records the versions, which the loser
 * would otherwise have seen as already-applied.
 *
 * @param migrationList Override the migration registry (used by tests).
 */
export async function runMigrations(
  migrationList: MigrationDefinition[] = migrations,
): Promise<void> {
  // Build the JobLock/Migration unique indexes BEFORE acquiring the lock, so the
  // lock's uniqueness (and the migration-version dedup) is guaranteed even on a
  // fresh production boot where autoIndex is off and indexes are not yet built.
  await ensureLockIndexes();

  const lockId = await acquireJobLock(MIGRATION_LOCK_NAME, MIGRATION_LOCK_TTL_MS);
  if (!lockId) {
    logger.info('Migrations are being applied by another process; skipping on this instance');
    return;
  }

  try {
    await applyPendingMigrations(migrationList);
  } finally {
    try {
      await releaseJobLock(MIGRATION_LOCK_NAME, lockId);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      logger.warn(`Failed to release migration lock: ${message}`);
    }
  }
}
