/**
 * A vault at `MAX_ITEMS_PER_USER`, sized just under `BACKUP_MAX_SIZE_MB`, still
 * backs up — inside a time and memory budget.
 *
 * The sibling scenario (`backup-streaming.test.ts`) proves the refusal path
 * stops early. This one proves the other side of the same boundary: the largest
 * backup the operator's configuration actually permits is one the server can
 * still produce. Both halves are needed, because a "fix" for either is trivially
 * available at the other's expense — clamp the estimator down and every large
 * vault 413s; drop the guard and the process pages out.
 *
 * `POST /backup/trigger` rather than `GET /backup/download`, deliberately.
 * Both call the same `collectBackupData`, but supertest drives the app IN THIS
 * PROCESS, so measuring the download endpoint would fold superagent's own buffer
 * of a 20 MB response body into a number this file presents as the server's
 * cost. The trigger endpoint returns counts, so what the budget measures is the
 * collection itself. (With no SMTP configured — `vitest.config.ts` pins the SMTP
 * vars empty — the trigger path also skips the `Buffer.from(json)` attachment
 * copy, which is stated here rather than corrected for: the budget is a ceiling
 * on the collection, and the attachment copy is a second, separately obvious
 * cost that no cursor rewrite can hide.)
 */
import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import app from '../../src/app.js';
import { config } from '../../src/config/index.js';
import { MAX_ITEMS_PER_USER } from '@hvault/shared';
import { BackupLog } from '../../src/models/BackupLog.js';
import { createTestUser, authHeader, getCsrf, type TestUser } from '../helpers.js';
import { configureBackupEncryption, seedVault } from './fixtures.js';
import { measure, recordScenarioCase } from './measure.js';
import { RESOURCE_BUDGETS } from '../../../../scripts/ci/lib/resource-budgets.mjs';

/**
 * Ciphertext bytes per item, chosen so 10,000 rows land just UNDER the 25 MiB
 * budget rather than near the middle of it.
 *
 * `utils/sizeEstimator.ts` charges 600 bytes of fixed overhead per item plus the
 * length of every encrypted field, so a row here estimates at ~2,380 bytes and
 * the vault at ~23.8 MB against a 26,214,400-byte cap. The serialized document
 * is smaller still (the estimator is deliberately conservative), which is what
 * the endpoint's second, exact `fileSizeBytes` check then confirms.
 */
const DATA_BYTES = 1_600;

const budget = RESOURCE_BUDGETS.backupFullVault;

describe('a full vault at the backup size boundary', () => {
  let user: TestUser;
  let seeded: { count: number; seedMs: number; collectionBytes: number };

  beforeAll(async () => {
    user = await createTestUser();
    await configureBackupEncryption(user.id);
    seeded = await seedVault(user.id, { count: MAX_ITEMS_PER_USER, dataBytes: DATA_BYTES });
  }, 300_000);

  it('collects every one of the 10,000 items within the time and memory budget', async () => {
    const { token, cookie } = await getCsrf(request(app));
    const run = await measure(async () =>
      request(app)
        .post('/api/v1/backup/trigger')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', token)
        .set('Cookie', cookie)
        .send(),
    );
    const maxSizeBytes = config.BACKUP_MAX_SIZE_MB * 1024 * 1024;
    const body = run.result.body as {
      success?: boolean;
      data?: { itemCount?: number; fileSizeBytes?: number };
    };

    recordScenarioCase('backup-full-vault', 'collects-every-row', {
      invariant:
        'a vault at MAX_ITEMS_PER_USER sized just under BACKUP_MAX_SIZE_MB collects completely, inside the time and memory budget',
      items: seeded.count,
      dataBytesPerItem: DATA_BYTES,
      collectionMb: Number((seeded.collectionBytes / (1024 * 1024)).toFixed(2)),
      backupMaxSizeMb: config.BACKUP_MAX_SIZE_MB,
      seedMs: seeded.seedMs,
      status: run.result.status,
      itemCount: body.data?.itemCount ?? null,
      fileSizeBytes: body.data?.fileSizeBytes ?? null,
      durationMs: run.durationMs,
      rssGrowthMb: run.rssGrowthMb,
      peakRssMb: run.peakRssMb,
      rssStartMb: run.rssStartMb,
      processMaxRssMb: run.processMaxRssMb,
      budget,
    });

    expect(run.result.status).toBe(200);
    expect(body.success).toBe(true);
    // Every row, not "about that many": a cursor that stops one batch early
    // would still produce a plausible backup and silently lose the tail.
    expect(body.data?.itemCount).toBe(MAX_ITEMS_PER_USER);
    // Under the cap, and the endpoint's own exact check agrees with the
    // estimator's conservative one.
    expect(body.data?.fileSizeBytes).toBeGreaterThan(0);
    expect(body.data?.fileSizeBytes).toBeLessThan(maxSizeBytes);

    // The success is recorded, and recorded once.
    const logs = await BackupLog.find({ userId: user.id }).lean();
    expect(logs).toHaveLength(1);
    expect(logs[0]?.status).toBe('success');
    expect(logs[0]?.itemCount).toBe(MAX_ITEMS_PER_USER);

    expect(run.durationMs).toBeLessThan(budget.durationMs);
    expect(run.rssGrowthMb).toBeLessThan(budget.rssGrowthMb);
  }, 300_000);
});
