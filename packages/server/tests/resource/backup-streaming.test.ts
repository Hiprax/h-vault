/**
 * `collectBackupData` streams, and the 413 lands BEFORE the vault is in memory.
 *
 * This is the only assertion in the repository that can tell the shipped
 * implementation from the obvious refactor of it. `backupController` collects a
 * backup through `Folder.find(...).cursor()` and `VaultItem.find(...).cursor()`,
 * accumulating a conservative per-row size estimate and throwing 413 the moment
 * the running total passes the operator's `BACKUP_MAX_SIZE_MB`. Rewrite those two
 * loops as `await VaultItem.find({ userId }).lean()` and every existing test
 * still passes — the endpoint returns the same 413 for the same vault, with the
 * same message — while the process now materialises the entire collection first.
 * On an account near `MAX_ITEMS_PER_USER` with large items that is the difference
 * between tens of megabytes and hundreds, on a request an unauthenticated rate
 * limiter never sees because the caller is authenticated.
 *
 * So the invariant is pinned from two independent directions, and neither alone
 * is enough:
 *
 *   • DOCUMENTS DELIVERED, read from mongod's own `metrics.document.returned`.
 *     A cursor that stops asking leaves most of the collection on the server;
 *     `find().lean()` drains it. This is the crisp, deterministic half — it does
 *     not care how loaded the machine is.
 *   • PEAK RSS GROWTH, sampled across the request. This is the half that states
 *     the actual cost, and it is the one with a noise band; see `budgets.ts`.
 *
 * The vault is 10,000 items (`MAX_ITEMS_PER_USER`) of ~10 KB ciphertext each, so
 * the collection is roughly four times the 25 MiB budget and the abort has to
 * happen around item 2,400 of 10,000. Sizing it just past the cap would prove
 * nothing: the abort would land on the last row either way.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import app from '../../src/app.js';
import { config } from '../../src/config/index.js';
import { MAX_ITEMS_PER_USER } from '@hvault/shared';
import { AuditLog } from '../../src/models/AuditLog.js';
import { BackupLog } from '../../src/models/BackupLog.js';
import { createTestUser, authHeader, type TestUser } from '../helpers.js';
import { configureBackupEncryption, seedVault } from './fixtures.js';
import { documentsReturned, measure, recordScenarioCase } from './measure.js';
import { RESOURCE_BUDGETS } from '../../../../scripts/ci/lib/resource-budgets.mjs';

/**
 * Ciphertext bytes per item. Chosen so the whole vault is ~4x the 25 MiB backup
 * budget: the estimator adds ~800 bytes of fixed overhead per row, so the abort
 * is expected around `25 MiB / 10.8 KB` = ~2,430 rows.
 */
const DATA_BYTES = 10_000;

const budget = RESOURCE_BUDGETS.backupStreaming;

describe('backup collection streams and aborts before the vault is materialised', () => {
  let user: TestUser;
  let seeded: { count: number; seedMs: number; collectionBytes: number };

  beforeAll(async () => {
    user = await createTestUser();
    await configureBackupEncryption(user.id);
    seeded = await seedVault(user.id, { count: MAX_ITEMS_PER_USER, dataBytes: DATA_BYTES });
  }, 300_000);

  it('refuses an oversized vault with 413 without reading every row', async () => {
    const before = await documentsReturned();
    const run = await measure(async () =>
      request(app)
        .get('/api/v1/backup/download')
        .set('Authorization', authHeader(user.accessToken)),
    );
    const delivered = (await documentsReturned()) - before;

    recordScenarioCase('backup-streaming', 'oversized-vault-413', {
      invariant:
        'collectBackupData aborts with 413 before the vault is materialised: mongod delivers a fraction of the collection and peak RSS stays inside the budget',
      items: seeded.count,
      dataBytesPerItem: DATA_BYTES,
      collectionMb: Number((seeded.collectionBytes / (1024 * 1024)).toFixed(2)),
      backupMaxSizeMb: config.BACKUP_MAX_SIZE_MB,
      seedMs: seeded.seedMs,
      status: run.result.status,
      documentsDelivered: delivered,
      deliveredFraction: Number((delivered / seeded.count).toFixed(4)),
      durationMs: run.durationMs,
      rssGrowthMb: run.rssGrowthMb,
      peakRssMb: run.peakRssMb,
      rssStartMb: run.rssStartMb,
      processMaxRssMb: run.processMaxRssMb,
      budget,
    });

    // The refusal itself, and its status: a 500 here would also "not materialise
    // the vault", so the shape of the failure is part of the invariant.
    expect(run.result.status).toBe(413);
    expect(run.result.body).toMatchObject({ success: false, statusCode: 413 });

    // The negative: nothing was written on the way to the refusal. A backup that
    // 413s must leave no BackupLog row and no audit trail claiming a download.
    expect(await BackupLog.countDocuments({ userId: user.id })).toBe(0);
    expect(await AuditLog.countDocuments({ userId: user.id, action: 'backup_download' })).toBe(0);

    // The streaming invariant. `delivered` counts the documents mongod handed
    // over — the user lookup and the folder cursor contribute a handful, so the
    // comparison is against the ITEM count with that slack folded in rather than
    // against an exact figure.
    expect(delivered).toBeLessThan(seeded.count);
    expect(delivered).toBeLessThanOrEqual(Math.floor(seeded.count * budget.deliveredFraction));

    // The memory budget.
    expect(run.durationMs).toBeLessThan(budget.durationMs);
    expect(run.rssGrowthMb).toBeLessThan(budget.rssGrowthMb);
  }, 300_000);
});
