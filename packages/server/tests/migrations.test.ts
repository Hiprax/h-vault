import { describe, it, expect, vi, beforeEach } from 'vitest';
import mongoose from 'mongoose';
import { runMigrations, type MigrationDefinition } from '../src/utils/migrations.js';
import { Migration } from '../src/models/Migration.js';
import { JobLock } from '../src/models/JobLock.js';
// Importing the production index registry both exercises it and registers every
// listed model on the shared Mongoose instance.
import { indexedModels } from '../scripts/indexedModels.js';

describe('Database migrations', () => {
  beforeEach(async () => {
    // The migration concurrency guard and the defense-in-depth tracking insert
    // both rely on unique indexes (JobLock.jobName and Migration.version).
    await JobLock.ensureIndexes();
    await Migration.ensureIndexes();
  });

  // ── T12 (a): create-indexes model list is complete ──────────────────

  describe('production index registry (create-indexes coverage)', () => {
    it('includes every registered model that declares indexes', () => {
      const listed = new Set(indexedModels.map((m) => m.name));

      for (const name of mongoose.modelNames()) {
        const schemaIndexes = mongoose.model(name).schema.indexes();
        if (schemaIndexes.length > 0) {
          expect(
            listed.has(name),
            `indexedModels (used by create-indexes) must include "${name}" — it declares indexes that production must build`,
          ).toBe(true);
        }
      }
    });

    it('includes the Migration model so its unique version index is built in production', () => {
      const listed = new Set(indexedModels.map((m) => m.name));
      expect(listed.has('Migration')).toBe(true);

      // The Migration model genuinely declares an index (unique version), so it
      // is exactly the kind of model the previous list silently omitted.
      const migrationIndexes = Migration.schema.indexes();
      expect(migrationIndexes.length).toBeGreaterThan(0);
    });
  });

  // ── T12 (b): runMigrations is idempotent & concurrency-safe ─────────

  describe('runMigrations', () => {
    it('applies a pending migration and records it', async () => {
      const up = vi.fn(() => Promise.resolve());
      const list: MigrationDefinition[] = [{ version: 2001, name: 'apply-once', up }];

      await runMigrations(list);

      expect(up).toHaveBeenCalledTimes(1);
      const doc = await Migration.findOne({ version: 2001 });
      expect(doc).not.toBeNull();
      expect(doc?.name).toBe('apply-once');
    });

    it('does not re-run an already-applied migration', async () => {
      const up = vi.fn(() => Promise.resolve());
      const list: MigrationDefinition[] = [{ version: 2002, name: 'idempotent', up }];

      await runMigrations(list);
      await runMigrations(list);

      expect(up).toHaveBeenCalledTimes(1);
      expect(await Migration.countDocuments({ version: 2002 })).toBe(1);
    });

    it('does not record a migration whose up() throws (so it can be retried)', async () => {
      const up = vi.fn(() => Promise.reject(new Error('migration boom')));
      const list: MigrationDefinition[] = [{ version: 2003, name: 'fails', up }];

      await expect(runMigrations(list)).rejects.toThrow('migration boom');
      expect(await Migration.countDocuments({ version: 2003 })).toBe(0);
    });

    it('applies each migration exactly once under concurrent runs', async () => {
      const up = vi.fn(() => Promise.resolve());
      const list: MigrationDefinition[] = [{ version: 2004, name: 'concurrent', up }];

      // Two workers booting simultaneously both call runMigrations. The lock
      // must ensure up() runs once and exactly one tracking row is written.
      await Promise.all([runMigrations(list), runMigrations(list)]);

      expect(up).toHaveBeenCalledTimes(1);
      expect(await Migration.countDocuments({ version: 2004 })).toBe(1);
    });

    it('skips cleanly when another process holds the migration lock', async () => {
      // Simulate another instance currently holding the lock (not expired).
      await JobLock.create({
        jobName: 'migrations',
        lockedBy: 'other-instance',
        lockedAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000),
      });

      const up = vi.fn(() => Promise.resolve());
      const list: MigrationDefinition[] = [{ version: 2005, name: 'locked-out', up }];

      // Must return cleanly (no throw) without applying anything.
      await expect(runMigrations(list)).resolves.toBeUndefined();
      expect(up).not.toHaveBeenCalled();
      expect(await Migration.countDocuments({ version: 2005 })).toBe(0);
    });

    it('releases the lock after applying so a later run can re-acquire it', async () => {
      const up = vi.fn(() => Promise.resolve());
      await runMigrations([{ version: 2006, name: 'first', up }]);

      // Lock must have been released (deleted) in the finally block.
      expect(await JobLock.countDocuments({ jobName: 'migrations' })).toBe(0);

      // A subsequent run with a new migration must succeed (re-acquire the lock).
      const up2 = vi.fn(() => Promise.resolve());
      await runMigrations([{ version: 2007, name: 'second', up: up2 }]);
      expect(up2).toHaveBeenCalledTimes(1);
      expect(await Migration.countDocuments({ version: 2007 })).toBe(1);
    });
  });
});
