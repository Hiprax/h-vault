/**
 * A changed retention setting must not stop the stack from starting.
 *
 * Three TTL indexes take `expireAfterSeconds` from the configuration
 * (`AUDIT_LOG_RETENTION_DAYS`, `BACKUP_RETENTION_DAYS`, `BREACH_CACHE_TTL_DAYS`).
 * After an operator changes one, the index already in the database no longer
 * matches the schema, `createIndexes` fails with IndexOptionsConflict, and the
 * `create-indexes` bootstrap step the app waits on exits 1. The entry points now
 * build indexes through `createIndexesWithCurrentRetention`, which rebuilds a TTL
 * index whose retention alone changed and leaves every other conflict to fail.
 *
 * Real mongod throughout: what is under test is how the server treats indexes.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { PwnedRangeCache } from '../src/models/PwnedRangeCache.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { BackupLog } from '../src/models/BackupLog.js';
import { User } from '../src/models/User.js';
import { config } from '../src/config/index.js';
import { createIndexesWithCurrentRetention } from '../src/utils/ttlIndexReconcile.js';

const DAY_S = 86_400;

interface IndexInfo {
  name: string;
  key: Record<string, number>;
  expireAfterSeconds?: number;
  partialFilterExpression?: Record<string, unknown>;
}

async function indexesOf(
  model: typeof PwnedRangeCache | typeof AuditLog | typeof BackupLog,
): Promise<IndexInfo[]> {
  return (await model.collection.indexes()) as IndexInfo[];
}

/**
 * Puts the index a deployment built under an OLDER retention in place of the
 * current one: same name, same key, same partial filter, other `expireAfterSeconds`.
 */
async function installOldRangeTtl(options: {
  expireAfterSeconds: number;
  partialFilterExpression?: Record<string, unknown>;
}): Promise<void> {
  await PwnedRangeCache.createIndexes();
  await PwnedRangeCache.collection.dropIndex('fetchedAt_1');
  await PwnedRangeCache.collection.createIndex(
    { fetchedAt: 1 },
    {
      name: 'fetchedAt_1',
      expireAfterSeconds: options.expireAfterSeconds,
      partialFilterExpression: options.partialFilterExpression ?? { source: 'hibp' },
    },
  );
}

const CURRENT_RANGE_TTL = config.BREACH_CACHE_TTL_DAYS * 4 * DAY_S;
/** A retention the configuration does not carry: what an earlier setting built. */
const OLD_RANGE_TTL = CURRENT_RANGE_TTL + 7 * DAY_S;

afterEach(async () => {
  vi.restoreAllMocks();
  // Leave the model's own index set behind for the rest of the file.
  const ttl = (await indexesOf(PwnedRangeCache)).find((index) => index.name === 'fetchedAt_1');
  if (ttl?.expireAfterSeconds !== CURRENT_RANGE_TTL) {
    await PwnedRangeCache.collection.dropIndex('fetchedAt_1').catch(() => undefined);
  }
  await PwnedRangeCache.createIndexes();
});

describe('building indexes after a retention setting changed', () => {
  it('shows the defect it repairs: a bare createIndexes refuses the changed TTL', async () => {
    await installOldRangeTtl({ expireAfterSeconds: OLD_RANGE_TTL });

    await expect(PwnedRangeCache.createIndexes()).rejects.toMatchObject({
      codeName: 'IndexOptionsConflict',
    });
  });

  it('rebuilds the TTL index with the configured retention, same name, same filter', async () => {
    await installOldRangeTtl({ expireAfterSeconds: OLD_RANGE_TTL });
    await PwnedRangeCache.collection.insertOne({
      prefix: 'ABCDE',
      range: 'KEPT:1',
      source: 'hibp',
      fetchedAt: new Date(),
    });

    const rebuilt = await createIndexesWithCurrentRetention(PwnedRangeCache);

    expect(rebuilt).toEqual([
      { name: 'fetchedAt_1', fromSeconds: OLD_RANGE_TTL, toSeconds: CURRENT_RANGE_TTL },
    ]);
    const ttl = (await indexesOf(PwnedRangeCache)).filter(
      (index) => typeof index.expireAfterSeconds === 'number',
    );
    expect(ttl).toHaveLength(1);
    expect(ttl[0]!.name).toBe('fetchedAt_1');
    expect(ttl[0]!.expireAfterSeconds).toBe(CURRENT_RANGE_TTL);
    expect(ttl[0]!.partialFilterExpression).toEqual({ source: 'hibp' });
    // Every other index is still there, and no row went with the old index.
    const names = (await indexesOf(PwnedRangeCache)).map((index) => index.name).sort();
    expect(names).toEqual(['_id_', 'fetchedAt_1', 'prefix_1', 'source_1_fetchedAt_1__id_1']);
    expect(await PwnedRangeCache.countDocuments({ prefix: 'ABCDE' })).toBe(1);
  });

  it('drops nothing when the retention has not changed, and a second run is a no-op', async () => {
    await PwnedRangeCache.createIndexes();
    const dropIndex = vi.spyOn(PwnedRangeCache.collection, 'dropIndex');

    expect(await createIndexesWithCurrentRetention(PwnedRangeCache)).toEqual([]);
    expect(await createIndexesWithCurrentRetention(PwnedRangeCache)).toEqual([]);

    expect(dropIndex).not.toHaveBeenCalled();
  });

  it('leaves any other conflict in place and still reports it', async () => {
    // Same key, other retention AND another partial filter: not a retention change.
    await installOldRangeTtl({
      expireAfterSeconds: OLD_RANGE_TTL,
      partialFilterExpression: { source: 'seed' },
    });
    const dropIndex = vi.spyOn(PwnedRangeCache.collection, 'dropIndex');

    // 85 or 86, depending on whether the server matches the conflict by key or by
    // name: either way a conflict, reported, never repaired.
    await expect(createIndexesWithCurrentRetention(PwnedRangeCache)).rejects.toMatchObject({
      codeName: expect.stringMatching(/^Index(Options|KeySpecs)Conflict$/),
    });

    expect(dropIndex).not.toHaveBeenCalled();
    const ttl = (await indexesOf(PwnedRangeCache)).find((index) => index.name === 'fetchedAt_1');
    expect(ttl?.expireAfterSeconds).toBe(OLD_RANGE_TTL);
    expect(ttl?.partialFilterExpression).toEqual({ source: 'seed' });
  });

  it('leaves a non-TTL index on the same key alone', async () => {
    await PwnedRangeCache.createIndexes();
    await PwnedRangeCache.collection.dropIndex('fetchedAt_1');
    await PwnedRangeCache.collection.createIndex({ fetchedAt: 1 }, { name: 'fetchedAt_1' });
    const dropIndex = vi.spyOn(PwnedRangeCache.collection, 'dropIndex');

    await expect(createIndexesWithCurrentRetention(PwnedRangeCache)).rejects.toMatchObject({
      codeName: expect.stringMatching(/^Index(Options|KeySpecs)Conflict$/),
    });

    expect(dropIndex).not.toHaveBeenCalled();
  });

  it('builds every index on a collection that does not exist yet', async () => {
    await PwnedRangeCache.collection.drop().catch(() => undefined);

    expect(await createIndexesWithCurrentRetention(PwnedRangeCache)).toEqual([]);

    const ttl = (await indexesOf(PwnedRangeCache)).find((index) => index.name === 'fetchedAt_1');
    expect(ttl?.expireAfterSeconds).toBe(CURRENT_RANGE_TTL);
  });

  it('repairs the audit log retention the same way, keeping the rows', async () => {
    await AuditLog.createIndexes();
    await AuditLog.collection.dropIndex('timestamp_1');
    await AuditLog.collection.createIndex(
      { timestamp: 1 },
      { name: 'timestamp_1', expireAfterSeconds: 30 * DAY_S },
    );
    await AuditLog.collection.insertOne({
      userId: null,
      action: 'login',
      timestamp: new Date(),
      count: 1,
    });

    expect(await createIndexesWithCurrentRetention(AuditLog)).toEqual([
      {
        name: 'timestamp_1',
        fromSeconds: 30 * DAY_S,
        toSeconds: config.AUDIT_LOG_RETENTION_DAYS * DAY_S,
      },
    ]);

    const ttl = (await indexesOf(AuditLog)).find((index) => index.name === 'timestamp_1');
    expect(ttl?.expireAfterSeconds).toBe(config.AUDIT_LOG_RETENTION_DAYS * DAY_S);
    expect(await AuditLog.countDocuments({})).toBe(1);
  });

  it('repairs the backup log retention the same way', async () => {
    await BackupLog.createIndexes();
    await BackupLog.collection.dropIndex('timestamp_1');
    await BackupLog.collection.createIndex(
      { timestamp: 1 },
      { name: 'timestamp_1', expireAfterSeconds: 2 * DAY_S },
    );

    expect(await createIndexesWithCurrentRetention(BackupLog)).toEqual([
      {
        name: 'timestamp_1',
        fromSeconds: 2 * DAY_S,
        toSeconds: config.BACKUP_RETENTION_DAYS * DAY_S,
      },
    ]);
    const ttl = (await indexesOf(BackupLog)).find((index) => index.name === 'timestamp_1');
    expect(ttl?.expireAfterSeconds).toBe(config.BACKUP_RETENTION_DAYS * DAY_S);
  });

  it('still rebuilds when another run dropped the index first', async () => {
    await installOldRangeTtl({ expireAfterSeconds: OLD_RANGE_TTL });
    const realDropIndex = PwnedRangeCache.collection.dropIndex.bind(PwnedRangeCache.collection);
    vi.spyOn(PwnedRangeCache.collection, 'dropIndex').mockImplementationOnce(async (name) => {
      // The concurrent run's drop lands first; ours then finds nothing to drop.
      await realDropIndex(name as string);
      return realDropIndex(name as string);
    });

    const rebuilt = await createIndexesWithCurrentRetention(PwnedRangeCache);

    expect(rebuilt.map((change) => change.name)).toEqual(['fetchedAt_1']);
    const ttl = (await indexesOf(PwnedRangeCache)).find((index) => index.name === 'fetchedAt_1');
    expect(ttl?.expireAfterSeconds).toBe(CURRENT_RANGE_TTL);
  });

  it('reports a failure to read the indexes instead of building over it', async () => {
    const createIndexes = vi.spyOn(PwnedRangeCache, 'createIndexes');
    vi.spyOn(PwnedRangeCache.collection, 'indexes').mockRejectedValueOnce(
      Object.assign(new Error('not authorized'), { code: 13 }),
    );

    await expect(createIndexesWithCurrentRetention(PwnedRangeCache)).rejects.toThrow(
      'not authorized',
    );

    expect(createIndexes).not.toHaveBeenCalled();
  });

  it('builds a TTL index a deployment does not have yet (the upgrade to this version)', async () => {
    await PwnedRangeCache.createIndexes();
    await PwnedRangeCache.collection.dropIndex('fetchedAt_1');
    const dropIndex = vi.spyOn(PwnedRangeCache.collection, 'dropIndex');

    expect(await createIndexesWithCurrentRetention(PwnedRangeCache)).toEqual([]);

    expect(dropIndex).not.toHaveBeenCalled();
    const ttl = (await indexesOf(PwnedRangeCache)).find((index) => index.name === 'fetchedAt_1');
    expect(ttl?.expireAfterSeconds).toBe(CURRENT_RANGE_TTL);
    expect(ttl?.partialFilterExpression).toEqual({ source: 'hibp' });
  });

  it('builds the indexes of a model with no TTL index, dropping nothing', async () => {
    const dropIndex = vi.spyOn(User.collection, 'dropIndex');
    const createIndexes = vi.spyOn(User, 'createIndexes');

    expect(await createIndexesWithCurrentRetention(User)).toEqual([]);

    expect(dropIndex).not.toHaveBeenCalled();
    expect(createIndexes).toHaveBeenCalledTimes(1);
  });

  it('reports a drop that fails for any reason but the index already being gone', async () => {
    await installOldRangeTtl({ expireAfterSeconds: OLD_RANGE_TTL });
    vi.spyOn(PwnedRangeCache.collection, 'dropIndex').mockRejectedValueOnce(
      Object.assign(new Error('not authorized'), { code: 13 }),
    );

    await expect(createIndexesWithCurrentRetention(PwnedRangeCache)).rejects.toThrow(
      'not authorized',
    );

    const ttl = (await indexesOf(PwnedRangeCache)).find((index) => index.name === 'fetchedAt_1');
    expect(ttl?.expireAfterSeconds).toBe(OLD_RANGE_TTL);
  });

  it('still rebuilds when the whole collection went while it was dropping', async () => {
    await installOldRangeTtl({ expireAfterSeconds: OLD_RANGE_TTL });
    vi.spyOn(PwnedRangeCache.collection, 'dropIndex').mockImplementationOnce(async () => {
      await PwnedRangeCache.collection.drop();
      throw Object.assign(new Error('ns does not exist'), { code: 26 });
    });

    const rebuilt = await createIndexesWithCurrentRetention(PwnedRangeCache);

    expect(rebuilt.map((change) => change.name)).toEqual(['fetchedAt_1']);
    const ttl = (await indexesOf(PwnedRangeCache)).find((index) => index.name === 'fetchedAt_1');
    expect(ttl?.expireAfterSeconds).toBe(CURRENT_RANGE_TTL);
  });
});
