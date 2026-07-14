import { createLogger } from '@hiprax/logger';
import { Migration } from '../models/Migration.js';
import { JobLock } from '../models/JobLock.js';
import { acquireJobLock, releaseJobLock } from './jobLock.js';

const logger = createLogger({ moduleName: 'migrations' });

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
];

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
