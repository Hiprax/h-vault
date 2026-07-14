import { describe, it, expect } from 'vitest';
import mongoose from 'mongoose';
import { User } from '../src/models/User.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { BackupLog } from '../src/models/BackupLog.js';
import { JobLock } from '../src/models/JobLock.js';

// ---- Helpers for explain()-based index-usage assertions ----
// A query may be served by an index (IXSCAN) or a full collection scan
// (COLLSCAN). These helpers walk the explain() winning-plan tree so a test can
// prove the cleanup-job queries actually hit an index rather than just that an
// index object exists.

interface PlanNode {
  stage?: string;
  inputStage?: PlanNode;
  inputStages?: PlanNode[];
  [k: string]: unknown;
}

interface ExplainResult {
  queryPlanner: { winningPlan: PlanNode };
}

/** Collect every `stage` name in an explain() winning-plan tree, depth-first. */
function collectStages(plan: PlanNode | undefined): string[] {
  if (!plan) return [];
  const stages: string[] = [];
  if (typeof plan.stage === 'string') stages.push(plan.stage);
  if (plan.inputStage) stages.push(...collectStages(plan.inputStage));
  if (Array.isArray(plan.inputStages)) {
    for (const child of plan.inputStages) stages.push(...collectStages(child));
  }
  return stages;
}

/** Find the first plan node with the given `stage`, depth-first. */
function findStageNode(plan: PlanNode | undefined, stage: string): PlanNode | undefined {
  if (!plan) return undefined;
  if (plan.stage === stage) return plan;
  const fromSingle = findStageNode(plan.inputStage, stage);
  if (fromSingle) return fromSingle;
  if (Array.isArray(plan.inputStages)) {
    for (const child of plan.inputStages) {
      const found = findStageNode(child, stage);
      if (found) return found;
    }
  }
  return undefined;
}

describe('Database indexes', () => {
  describe('User model indexes', () => {
    it('should have a compound index on backup settings for scheduler queries', async () => {
      await User.ensureIndexes();
      const indexes = await User.collection.indexes();

      const backupIndex = indexes.find(
        (idx) =>
          idx.key['settings.backup.enabled'] === 1 && idx.key['settings.backup.scheduleHour'] === 1,
      );

      expect(backupIndex).toBeDefined();
    });

    it('should have an index on emailVerified', async () => {
      await User.ensureIndexes();
      const indexes = await User.collection.indexes();

      const emailVerifiedIndex = indexes.find((idx) => idx.key['emailVerified'] === 1);
      expect(emailVerifiedIndex).toBeDefined();
    });

    it('should have a sparse index on lockoutUntil', async () => {
      await User.ensureIndexes();
      const indexes = await User.collection.indexes();

      const lockoutIndex = indexes.find((idx) => idx.key['lockoutUntil'] === 1);
      expect(lockoutIndex).toBeDefined();
      expect(lockoutIndex!.sparse).toBe(true);
    });

    it('should have a partial index on deletionPending for the zombie-user cleanup job', async () => {
      await User.ensureIndexes();
      const indexes = (await User.collection.indexes()) as {
        key: Record<string, number>;
        partialFilterExpression?: Record<string, unknown>;
        [k: string]: unknown;
      }[];

      const index = indexes.find((idx) => idx.key['deletionPending'] === 1);
      expect(index).toBeDefined();
      // Only users mid-deletion are indexed — keeps the index tiny.
      expect(index!.partialFilterExpression).toEqual({ deletionPending: true });
    });

    it('zombie-user cleanup query (deletionPending: true) uses an index, not a COLLSCAN', async () => {
      await User.ensureIndexes();

      const makeUser = (i: number, zombie: boolean) => ({
        email: `idx-${zombie ? 'zombie' : 'normal'}-${String(i)}@example.com`,
        authHash: 'x',
        encryptedVaultKey: 'x',
        vaultKeyIv: 'x',
        vaultKeyTag: 'x',
        ...(zombie ? { deletionPending: true } : {}),
      });
      // A realistic skew: the vast majority of users are NOT pending deletion,
      // so the planner must clearly prefer the selective partial index.
      await User.insertMany([
        ...Array.from({ length: 120 }, (_v, i) => makeUser(i, false)),
        ...Array.from({ length: 6 }, (_v, i) => makeUser(i, true)),
      ]);

      const explain = (await User.find({ deletionPending: true })
        .lean()
        .explain('queryPlanner')) as unknown as ExplainResult;

      const stages = collectStages(explain.queryPlanner.winningPlan);
      expect(stages).toContain('IXSCAN');
      expect(stages).not.toContain('COLLSCAN');
      // Prove the partial deletionPending index is the one used (not a vacuous
      // IXSCAN on some other index the planner might pick in the future).
      const ixscan = findStageNode(explain.queryPlanner.winningPlan, 'IXSCAN');
      expect(ixscan?.['indexName']).toBe('deletionPending_1');
    });
  });

  describe('RefreshToken model indexes', () => {
    it('should have a range index on expiresAt for cleanup queries (no TTL)', async () => {
      await RefreshToken.ensureIndexes();
      const indexes = await RefreshToken.collection.indexes();

      // The TTL index moved to `usedAt`. `expiresAt` is now a plain index
      // so the cleanup cron can sweep unused-and-expired tokens efficiently
      // without MongoDB pre-empting the reuse-detection window.
      const expiresIndex = indexes.find((idx) => idx.key['expiresAt'] === 1);
      expect(expiresIndex).toBeDefined();
      expect(expiresIndex!.expireAfterSeconds).toBeUndefined();
    });

    it('should have a TTL index on usedAt covering the reuse-detection window', async () => {
      await RefreshToken.ensureIndexes();
      const indexes = await RefreshToken.collection.indexes();

      const ttlIndex = indexes.find(
        (idx) =>
          idx.key['usedAt'] === 1 &&
          typeof idx.expireAfterSeconds === 'number' &&
          idx.expireAfterSeconds > 0,
      );

      expect(ttlIndex).toBeDefined();
      // Reuse-detection window is 7 days = 7 * 24 * 60 * 60 = 604800 seconds
      expect(ttlIndex!.expireAfterSeconds).toBe(7 * 24 * 60 * 60);
    });

    it('should have a compound index on userId and familyId', async () => {
      await RefreshToken.ensureIndexes();
      const indexes = await RefreshToken.collection.indexes();

      const compoundIndex = indexes.find(
        (idx) => idx.key['userId'] === 1 && idx.key['familyId'] === 1,
      );

      expect(compoundIndex).toBeDefined();
    });
  });

  describe('AuditLog model indexes', () => {
    it('should have a TTL index on timestamp for auto-cleanup', async () => {
      await AuditLog.ensureIndexes();
      const indexes = await AuditLog.collection.indexes();

      const ttlIndex = indexes.find(
        (idx) =>
          idx.key['timestamp'] === 1 &&
          typeof idx.expireAfterSeconds === 'number' &&
          idx.expireAfterSeconds > 0,
      );

      expect(ttlIndex).toBeDefined();
      // Default is 365 days = 365 * 24 * 60 * 60 = 31536000
      expect(ttlIndex!.expireAfterSeconds).toBe(365 * 24 * 60 * 60);
    });

    it('should have a compound index on userId and timestamp', async () => {
      await AuditLog.ensureIndexes();
      const indexes = (await AuditLog.collection.indexes()) as {
        key: Record<string, number>;
        [k: string]: unknown;
      }[];

      const compoundIndex = indexes.find(
        (idx) => idx.key['userId'] === 1 && idx.key['timestamp'] === -1,
      );

      expect(compoundIndex).toBeDefined();
    });

    it('should have a compound index on userId, action, and timestamp', async () => {
      await AuditLog.ensureIndexes();
      const indexes = (await AuditLog.collection.indexes()) as {
        key: Record<string, number>;
        [k: string]: unknown;
      }[];

      const compoundIndex = indexes.find(
        (idx) => idx.key['userId'] === 1 && idx.key['action'] === 1 && idx.key['timestamp'] === -1,
      );

      expect(compoundIndex).toBeDefined();
    });
  });

  describe('VaultItem model indexes', () => {
    it('should have a compound index on (userId, itemType)', async () => {
      await VaultItem.ensureIndexes();
      const indexes = (await VaultItem.collection.indexes()) as {
        key: Record<string, number>;
        [k: string]: unknown;
      }[];

      const index = indexes.find((idx) => idx.key['userId'] === 1 && idx.key['itemType'] === 1);

      expect(index).toBeDefined();
    });

    it('should have a compound index on (userId, folderId)', async () => {
      await VaultItem.ensureIndexes();
      const indexes = (await VaultItem.collection.indexes()) as {
        key: Record<string, number>;
        [k: string]: unknown;
      }[];

      const index = indexes.find((idx) => idx.key['userId'] === 1 && idx.key['folderId'] === 1);

      expect(index).toBeDefined();
    });

    it('should have a compound index on (userId, favorite)', async () => {
      await VaultItem.ensureIndexes();
      const indexes = (await VaultItem.collection.indexes()) as {
        key: Record<string, number>;
        [k: string]: unknown;
      }[];

      const index = indexes.find((idx) => idx.key['userId'] === 1 && idx.key['favorite'] === 1);

      expect(index).toBeDefined();
    });

    it('should have a compound index on (userId, deletedAt)', async () => {
      await VaultItem.ensureIndexes();
      const indexes = (await VaultItem.collection.indexes()) as {
        key: Record<string, number>;
        [k: string]: unknown;
      }[];

      const index = indexes.find((idx) => idx.key['userId'] === 1 && idx.key['deletedAt'] === -1);

      expect(index).toBeDefined();
    });

    it('should have a compound index on (userId, updatedAt desc)', async () => {
      await VaultItem.ensureIndexes();
      const indexes = (await VaultItem.collection.indexes()) as {
        key: Record<string, number>;
        [k: string]: unknown;
      }[];

      const index = indexes.find((idx) => idx.key['userId'] === 1 && idx.key['updatedAt'] === -1);

      expect(index).toBeDefined();
    });

    it('should have a sparse compound index on (userId, searchHash)', async () => {
      await VaultItem.ensureIndexes();
      const indexes = (await VaultItem.collection.indexes()) as {
        key: Record<string, number>;
        sparse?: boolean;
        [k: string]: unknown;
      }[];

      const index = indexes.find((idx) => idx.key['userId'] === 1 && idx.key['searchHash'] === 1);

      expect(index).toBeDefined();
      expect(index!.sparse).toBe(true);
    });

    it('should have a compound index on (userId, tags)', async () => {
      await VaultItem.ensureIndexes();
      const indexes = (await VaultItem.collection.indexes()) as {
        key: Record<string, number>;
        [k: string]: unknown;
      }[];

      const index = indexes.find((idx) => idx.key['userId'] === 1 && idx.key['tags'] === 1);

      expect(index).toBeDefined();
    });

    it('should have a non-unique partial compound index on (userId, sourceRefId) for restore idempotency', async () => {
      await VaultItem.ensureIndexes();
      const indexes = (await VaultItem.collection.indexes()) as {
        key: Record<string, number>;
        unique?: boolean;
        partialFilterExpression?: Record<string, unknown>;
        [k: string]: unknown;
      }[];

      const index = indexes.find((idx) => idx.key['userId'] === 1 && idx.key['sourceRefId'] === 1);

      expect(index).toBeDefined();
      // NON-unique: keep_both may mint multiple rows from one source.
      expect(index!.unique).toBeUndefined();
      // Partial (NOT sparse): a compound sparse index would index every doc since
      // `userId` is always present. The partial filter restricts it to only the
      // restore-provenance rows that carry a `sourceRefId`.
      expect(index!.partialFilterExpression).toEqual({ sourceRefId: { $type: 'string' } });
      expect(index!.sparse).toBeUndefined();
    });

    it('should have a sparse standalone index on deletedAt for the trash auto-purge job', async () => {
      await VaultItem.ensureIndexes();
      const indexes = (await VaultItem.collection.indexes()) as {
        key: Record<string, number>;
        sparse?: boolean;
        [k: string]: unknown;
      }[];

      // The standalone deletedAt index, NOT the (userId, deletedAt desc) compound:
      // the trash purge query filters on deletedAt with no userId predicate.
      const index = indexes.find(
        (idx) => idx.key['deletedAt'] === 1 && idx.key['userId'] === undefined,
      );

      expect(index).toBeDefined();
      expect(index!.sparse).toBe(true);
    });

    it('trash auto-purge query (deletedAt $lte) uses an index, not a COLLSCAN', async () => {
      await VaultItem.ensureIndexes();

      const userId = new mongoose.Types.ObjectId();
      const base = {
        userId,
        itemType: 'login' as const,
        encryptedData: 'x',
        dataIv: 'x',
        dataTag: 'x',
        encryptedName: 'x',
        nameIv: 'x',
        nameTag: 'x',
      };
      const oldDate = new Date('2000-01-01T00:00:00.000Z');
      // Mostly-active items (no deletedAt → excluded from the sparse index) with a
      // small soft-deleted minority, so the planner clearly prefers the index.
      await VaultItem.insertMany([
        ...Array.from({ length: 120 }, () => ({ ...base })),
        ...Array.from({ length: 12 }, () => ({ ...base, deletedAt: oldDate })),
      ]);

      const explain = (await VaultItem.find({ deletedAt: { $lte: new Date() } })
        .select('_id userId')
        .limit(500)
        .explain('queryPlanner')) as unknown as ExplainResult;

      const stages = collectStages(explain.queryPlanner.winningPlan);
      expect(stages).toContain('IXSCAN');
      expect(stages).not.toContain('COLLSCAN');
      // Prove the standalone sparse deletedAt index is the one used — not, e.g.,
      // the (userId, deletedAt) compound (which can't seek a userId-less query).
      const ixscan = findStageNode(explain.queryPlanner.winningPlan, 'IXSCAN');
      expect(ixscan?.['indexName']).toBe('deletedAt_1');
    });
  });

  describe('Folder model indexes', () => {
    it('should have a compound index on (userId, parentId)', async () => {
      await Folder.ensureIndexes();
      const indexes = (await Folder.collection.indexes()) as {
        key: Record<string, number>;
        [k: string]: unknown;
      }[];

      const index = indexes.find((idx) => idx.key['userId'] === 1 && idx.key['parentId'] === 1);

      expect(index).toBeDefined();
    });

    it('should have a compound index on (userId, sortOrder)', async () => {
      await Folder.ensureIndexes();
      const indexes = (await Folder.collection.indexes()) as {
        key: Record<string, number>;
        [k: string]: unknown;
      }[];

      const index = indexes.find((idx) => idx.key['userId'] === 1 && idx.key['sortOrder'] === 1);

      expect(index).toBeDefined();
    });

    it('should have a unique compound index on (userId, searchHash) with partial filter', async () => {
      await Folder.ensureIndexes();
      const indexes = (await Folder.collection.indexes()) as {
        key: Record<string, number>;
        unique?: boolean;
        partialFilterExpression?: Record<string, unknown>;
        [k: string]: unknown;
      }[];

      const index = indexes.find((idx) => idx.key['userId'] === 1 && idx.key['searchHash'] === 1);

      expect(index).toBeDefined();
      expect(index!.unique).toBe(true);
      expect(index!.partialFilterExpression).toBeDefined();
    });

    it('should have a non-unique partial compound index on (userId, sourceRefId) for restore idempotency', async () => {
      await Folder.ensureIndexes();
      const indexes = (await Folder.collection.indexes()) as {
        key: Record<string, number>;
        unique?: boolean;
        partialFilterExpression?: Record<string, unknown>;
        [k: string]: unknown;
      }[];

      const index = indexes.find((idx) => idx.key['userId'] === 1 && idx.key['sourceRefId'] === 1);

      expect(index).toBeDefined();
      // NON-unique: keep_both may mint multiple rows from one source.
      expect(index!.unique).toBeUndefined();
      // Partial (NOT sparse): a compound sparse index would index every doc since
      // `userId` is always present. The partial filter restricts it to only the
      // restore-provenance rows that carry a `sourceRefId`.
      expect(index!.partialFilterExpression).toEqual({ sourceRefId: { $type: 'string' } });
      expect(index!.sparse).toBeUndefined();
    });
  });

  describe('BackupLog model indexes', () => {
    it('should have a compound index on (userId, timestamp desc)', async () => {
      await BackupLog.ensureIndexes();
      const indexes = (await BackupLog.collection.indexes()) as {
        key: Record<string, number>;
        [k: string]: unknown;
      }[];

      const index = indexes.find((idx) => idx.key['userId'] === 1 && idx.key['timestamp'] === -1);

      expect(index).toBeDefined();
    });

    it('should have a compound index on (userId, status)', async () => {
      await BackupLog.ensureIndexes();
      const indexes = (await BackupLog.collection.indexes()) as {
        key: Record<string, number>;
        [k: string]: unknown;
      }[];

      const index = indexes.find((idx) => idx.key['userId'] === 1 && idx.key['status'] === 1);

      expect(index).toBeDefined();
    });

    it('should have a TTL index on timestamp for auto-cleanup', async () => {
      await BackupLog.ensureIndexes();
      const indexes = (await BackupLog.collection.indexes()) as {
        key: Record<string, number>;
        expireAfterSeconds?: number;
        [k: string]: unknown;
      }[];

      const ttlIndex = indexes.find(
        (idx) =>
          idx.key['timestamp'] === 1 &&
          typeof idx.expireAfterSeconds === 'number' &&
          idx.expireAfterSeconds > 0,
      );

      expect(ttlIndex).toBeDefined();
      // Default is BACKUP_RETENTION_DAYS (30) = 30 * 24 * 60 * 60 = 2592000
      expect(ttlIndex!.expireAfterSeconds).toBe(30 * 24 * 60 * 60);
    });
  });

  describe('JobLock model indexes', () => {
    it('should have a unique index on jobName', async () => {
      await JobLock.ensureIndexes();
      const indexes = (await JobLock.collection.indexes()) as {
        key: Record<string, number>;
        unique?: boolean;
        [k: string]: unknown;
      }[];

      const index = indexes.find((idx) => idx.key['jobName'] === 1);

      expect(index).toBeDefined();
      expect(index!.unique).toBe(true);
    });

    it('should have a TTL index on expiresAt for automatic cleanup', async () => {
      await JobLock.ensureIndexes();
      const indexes = (await JobLock.collection.indexes()) as {
        key: Record<string, number>;
        expireAfterSeconds?: number;
        [k: string]: unknown;
      }[];

      const ttlIndex = indexes.find(
        (idx) => idx.key['expiresAt'] === 1 && idx.expireAfterSeconds === 0,
      );

      expect(ttlIndex).toBeDefined();
    });
  });

  // NOTE: A "Connection pool config" test was removed here. It asserted only
  // `mongoose.connection.readyState === 1` — a precondition of the entire suite,
  // not the pool sizing its name advertised. The real maxPoolSize/minPoolSize
  // wiring lives in `config/database.ts`'s `connectDatabase`, which the test
  // harness (tests/setup.ts) deliberately bypasses: it connects via a bare
  // `mongoose.connect(uri)` with no pool options, so the connected client's
  // options reflect the driver defaults, NOT `config.MONGO_*_POOL_SIZE`. The
  // block therefore could not be repaired to assert the pool settings in this
  // harness (and the config-level `min > max` rejection is covered by
  // config.test.ts). Removed rather than left as false coverage.
});
