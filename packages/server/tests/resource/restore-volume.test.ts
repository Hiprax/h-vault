/**
 * A backup at the 25 MiB restore cap goes back in — and the request body it
 * arrives in is BIGGER than that cap.
 *
 * `restoreBackupSchema` bounds `data` at `MAX_RESTORE_DATA_LENGTH` (26,214,400
 * bytes), and `routes/backup.ts` mounts a 30 MB body parser on this one route
 * for a reason recorded there in prose and asserted nowhere: the client sends
 * `{ conflictStrategy, data: JSON.stringify(backup) }`, so the backup is a JSON
 * STRING VALUE and every quote inside it doubles on the wire. A real backup —
 * thousands of small items, each with a password history and tags — is a few per
 * cent quotes, so a document that is legal by the schema arrives as a body of
 * 27-29 MB. Under the global 2 MB parser, or under a 26 MB one "matching" the
 * schema cap, that is a 413 before Zod ever runs: a backup this application
 * produced and cannot restore.
 *
 * WHAT IS NEW HERE IS THE COST, NOT THE ACCEPTANCE.
 * `phase7-backup-restore.test.ts` already drives a quote-dense near-maximum
 * document through this route and asserts it is parsed, processed and persisted;
 * that test owns the semantics and runs on every push. This scenario runs the
 * same shape under measurement — how long the largest legal restore takes and
 * what it costs in memory — which is the half nothing measured, and it restates
 * the premises it depends on (the document is inside the cap, the body is over
 * 26 MB) because a builder change that quietly stopped producing an inflated
 * body would otherwise leave a green test measuring the wrong thing.
 *
 * `restore-body-boundary.test.ts` holds the other two sides, neither of which
 * was covered anywhere: a `data` over the schema cap, and a body over the
 * parser's own limit.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import { MAX_IMPORT_ITEMS, MAX_RESTORE_DATA_LENGTH } from '@hvault/shared';
import app from '../../src/app.js';
import { VaultItem } from '../../src/models/VaultItem.js';
import { createTestUser, authHeader, getCsrf, type TestUser } from '../helpers.js';
import { buildRestoreDocument, type RestoreDocument } from './restoreDocument.js';
import { measure, recordScenarioCase } from './measure.js';
import { RESOURCE_BUDGETS } from '../../../../scripts/ci/lib/resource-budgets.mjs';

/**
 * 200 KiB below the schema cap. Close enough that the scenario is about the
 * boundary, far enough that the builder's one-filler-length rounding cannot
 * overshoot it and turn a volume test into a 400.
 */
const TARGET_BYTES = MAX_RESTORE_DATA_LENGTH - 200 * 1024;

/**
 * The row count and per-row field counts that make the document quote-dense.
 * `MAX_IMPORT_ITEMS` rows is the most a restore accepts, and it is also what
 * makes the quotes-per-byte ratio realistic: the same bytes in a hundred huge
 * rows would barely inflate at all.
 */
const HISTORY_ENTRIES = 10;
const TAGS_PER_ITEM = 20;

/** The inflation the 30 MB parser exists for. Asserted, not assumed. */
const MIN_INFLATION_PCT = 4;

const budget = RESOURCE_BUDGETS.restoreVolume;

describe('a restore at the 25 MiB cap', () => {
  let user: TestUser;
  let document: RestoreDocument;

  beforeAll(async () => {
    user = await createTestUser();
    document = buildRestoreDocument({
      items: MAX_IMPORT_ITEMS,
      targetBytes: TARGET_BYTES,
      historyEntries: HISTORY_ENTRIES,
      tags: TAGS_PER_ITEM,
    });
  }, 300_000);

  it('accepts a body inflated past 26 MB by JSON escaping and restores every row', async () => {
    const { token, cookie } = await getCsrf(request(app));
    const run = await measure(async () =>
      request(app)
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', token)
        .set('Cookie', cookie)
        .send({ conflictStrategy: 'skip', data: document.data }),
    );
    const stored = await VaultItem.countDocuments({ userId: user.id });

    recordScenarioCase('restore-volume', 'accepts-inflated-body', {
      invariant:
        'a backup within the 25 MiB schema cap whose escaped request body exceeds 26 MB is accepted by the 30 MB route parser and restored in full, inside the time and memory budget',
      items: document.itemCount,
      dataBytes: document.dataBytes,
      bodyBytes: document.bodyBytes,
      inflationPct: document.inflationPct,
      maxRestoreDataLength: MAX_RESTORE_DATA_LENGTH,
      status: run.result.status,
      storedRows: stored,
      durationMs: run.durationMs,
      rssGrowthMb: run.rssGrowthMb,
      peakRssMb: run.peakRssMb,
      rssStartMb: run.rssStartMb,
      processMaxRssMb: run.processMaxRssMb,
      budget,
    });

    // The premises this scenario rests on. Stated as assertions because a
    // builder change that quietly stopped producing an over-26 MB body would
    // otherwise leave a green test that no longer covers the parser at all.
    expect(document.dataBytes).toBeLessThanOrEqual(MAX_RESTORE_DATA_LENGTH);
    expect(document.inflationPct).toBeGreaterThanOrEqual(MIN_INFLATION_PCT);
    expect(document.bodyBytes).toBeGreaterThan(26 * 1000 * 1000);

    // Accepted — and specifically NOT 413, which is the failure a narrower
    // parser produces and the one this route's own comment is about.
    expect(run.result.status).toBe(200);
    expect(run.result.body).toMatchObject({
      success: true,
      data: { itemsRestored: MAX_IMPORT_ITEMS },
    });
    // Every row landed. A restore that skipped rows would still answer 200.
    expect(stored).toBe(MAX_IMPORT_ITEMS);

    expect(run.durationMs).toBeLessThan(budget.durationMs);
    expect(run.rssGrowthMb).toBeLessThan(budget.rssGrowthMb);
  }, 300_000);
});
