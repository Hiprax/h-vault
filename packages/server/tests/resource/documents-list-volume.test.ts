/**
 * An account holding `MAX_DOCUMENTS_PER_USER` documents, walked page by page
 * through the real list route, inside a time and memory budget — and still
 * paginating in the DATABASE rather than in the handler.
 *
 * ## The operation this measures is a real one, not a synthetic worst case
 *
 * Two callers walk the whole document list, and both are named in the client:
 * `documentsStore.fetchAllPages`, and — the one that cannot be allowed to drop a
 * row — the vault-key rotation's `enumerateDocumentRows`, which reads every active
 * and every trashed document so each wrapped key can be rewrapped. Both page at
 * `PAGINATION_DEFAULTS.MAX_LIMIT`, so a full account is
 * `ceil(MAX_DOCUMENTS_PER_USER / PAGINATION_DEFAULTS.MAX_LIMIT)` requests. Nothing
 * in the repository had ever executed that walk against a full account: every list
 * test seeds a handful of rows, so the page arithmetic, the projection and the
 * per-page cost were all verified at a volume where none of them can go wrong.
 *
 * ## The regression this can actually see
 *
 * `sendDocumentPage` asks mongod for one page, with a skip-and-limit pair derived
 * from the requested page, beside a `countDocuments`. The failure mode that matters is the handler
 * paginating in JavaScript instead — reading the account and slicing it — which is
 * invisible to every functional test, because the response is byte-identical. It is
 * not invisible to mongod: `metrics.document.returned` is how many documents the
 * server handed to clients, so the honest walk delivers a little over one account
 * (one page each, plus the authenticating user lookup and the count's single
 * aggregation row) while the JavaScript version delivers one WHOLE account per
 * page. The measured separation is 1.0x against 25x, and `deliveredFraction` below
 * is the ceiling between them. This is the same seam, and the same argument, as
 * `backup-streaming.test.ts`'s cursor assertion.
 *
 * ## What the budget can and cannot see
 *
 * The duration and RSS ceilings are ORDER-OF-MAGNITUDE ceilings, as everywhere in
 * this directory: they catch a hang, a per-row round trip, or a page that started
 * materialising the account. They cannot see a 20% drift, and `deliveredFraction`
 * is the assertion with real teeth.
 *
 * ## One measured scenario per file
 *
 * The rule from `measure.ts`: V8 does not return freed pages promptly, so a second
 * heavy case in this worker would measure its growth from a floor this one raised.
 */
import { describe, it, expect, beforeAll, vi } from 'vitest';
import request from 'supertest';
import { MAX_DOCUMENTS_PER_USER, PAGINATION_DEFAULTS } from '@hvault/shared';

vi.mock('../../src/config/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/config/index.js')>();
  return { ...actual, storageConfigured: true };
});

// The list route reads no object, but the router-level `requireStorage` guard runs
// on it — so the double is installed to make a MISSING one loud rather than
// silently satisfying a call this scenario does not expect anybody to make.
vi.mock('../../src/services/storage/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/services/storage/index.js')>();
  return {
    ...actual,
    getStorage: () => {
      throw new Error('the document list route reached object storage, which it must never do');
    },
  };
});

import app from '../../src/app.js';
import { Document } from '../../src/models/Document.js';
import { authHeader, createTestUser, type TestUser } from '../helpers.js';
import { seedDocuments } from './fixtures.js';
import { documentsReturned, measure, recordScenarioCase } from './measure.js';
import { RESOURCE_BUDGETS } from '../../../../scripts/ci/lib/resource-budgets.mjs';

/** The page size both whole-list walkers use, derived rather than restated. */
const PAGE_SIZE = PAGINATION_DEFAULTS.MAX_LIMIT;

/** How many requests a full account costs at that page size. */
const EXPECTED_PAGES = Math.ceil(MAX_DOCUMENTS_PER_USER / PAGE_SIZE);

/**
 * The sealed metadata blob's length per row.
 *
 * Sized so the response is realistic rather than trivial: a real blob carries the
 * name, the MIME type, the extension, the whole-file digest and the tags, base64 of
 * an AES-GCM sealing of a few hundred bytes of JSON. It is well under
 * `MAX_ENCRYPTED_DOCUMENT_META_LENGTH`, because the point here is the row COUNT.
 */
const META_BYTES = 512;

/** One mebibyte of plaintext per row, so `usedBytes` arithmetic has real magnitude. */
const PLAINTEXT_BYTES = 1024 * 1024;

const budget = RESOURCE_BUDGETS.documentsListVolume;

interface ListedRow {
  _id: string;
  objectKey?: unknown;
  userId?: unknown;
}

interface ListPage {
  data: ListedRow[];
  pagination: { page: number; limit: number; total: number; totalPages: number };
}

describe('a document list at MAX_DOCUMENTS_PER_USER', () => {
  let user: TestUser;
  let seeded: { count: number; seedMs: number; collectionBytes: number };

  beforeAll(async () => {
    user = await createTestUser({ email: 'documents-list-volume@example.com' });
    seeded = await seedDocuments(user.id, {
      count: MAX_DOCUMENTS_PER_USER,
      metaBytes: META_BYTES,
      plaintextBytes: PLAINTEXT_BYTES,
    });
  }, 300_000);

  it('walks every page of a full account inside the budget, without materialising it in the handler', async () => {
    const seededIds = (await Document.find({ userId: user.id }).select('_id').lean()).map((row) =>
      String(row._id),
    );
    expect(seededIds).toHaveLength(MAX_DOCUMENTS_PER_USER);

    const before = await documentsReturned();
    const run = await measure(async () => {
      const pages: ListPage[] = [];
      for (let page = 1; page <= EXPECTED_PAGES; page += 1) {
        const response = await request(app)
          .get(`/api/v1/documents?page=${String(page)}&limit=${String(PAGE_SIZE)}`)
          .set('Authorization', authHeader(user.accessToken));
        expect(response.status, JSON.stringify(response.body).slice(0, 400)).toBe(200);
        pages.push(response.body as ListPage);
      }
      return pages;
    });
    const delivered = (await documentsReturned()) - before;

    const rows = run.result.flatMap((page) => page.data);
    const ids = rows.map((row) => row._id);
    const distinct = new Set(ids);
    const deliveredFraction = Number((delivered / MAX_DOCUMENTS_PER_USER).toFixed(4));
    const leakedProjection = rows.filter(
      (row) => row.objectKey !== undefined || row.userId !== undefined,
    ).length;

    recordScenarioCase('documents-list-volume', 'walks-a-full-account', {
      invariant:
        'a full account is listed page by page inside the time and memory budget, every row appearing exactly once, with the paging done by mongod rather than in the handler',
      documents: seeded.count,
      metaBytesPerRow: META_BYTES,
      collectionMb: Number((seeded.collectionBytes / (1024 * 1024)).toFixed(2)),
      seedMs: seeded.seedMs,
      pageSize: PAGE_SIZE,
      pagesRead: run.result.length,
      rowsReturned: rows.length,
      distinctRowsReturned: distinct.size,
      documentsDelivered: delivered,
      deliveredFraction,
      durationMs: run.durationMs,
      rssGrowthMb: run.rssGrowthMb,
      peakRssMb: run.peakRssMb,
      rssStartMb: run.rssStartMb,
      processMaxRssMb: run.processMaxRssMb,
      budget,
    });

    // The walk is the walk the client performs: exactly as many requests as the
    // page arithmetic predicts, and every page agreeing on the total.
    expect(run.result).toHaveLength(EXPECTED_PAGES);
    for (const page of run.result) {
      expect(page.pagination.total).toBe(MAX_DOCUMENTS_PER_USER);
      expect(page.pagination.totalPages).toBe(EXPECTED_PAGES);
      expect(page.pagination.limit).toBe(PAGE_SIZE);
    }

    // EVERY ROW, EXACTLY ONCE. This is the invariant the rotation depends on and
    // the one `skip`-based paging breaks when the sort is not a total order: a row
    // that changes rank between two requests is returned twice or not at all, and
    // a row the walk never sees is a document left under a superseded key.
    expect(rows).toHaveLength(MAX_DOCUMENTS_PER_USER);
    expect(distinct.size).toBe(MAX_DOCUMENTS_PER_USER);
    expect([...distinct].sort()).toEqual([...seededIds].sort());

    // THE FIRST NEGATIVE. The handler did not read the account per page: mongod
    // delivered a little over one account in total, not one per request.
    expect(deliveredFraction).toBeLessThan(budget.deliveredFraction);

    // THE SECOND NEGATIVE. `DOCUMENT_PROJECTION` still strips the two columns that
    // must never reach a client — the owner id and the object key, which is the
    // only string in this system that addresses ciphertext in the bucket — on all
    // five thousand rows and not merely on the first page anyone eyeballed.
    expect(leakedProjection).toBe(0);

    expect(run.durationMs).toBeLessThan(budget.durationMs);
    expect(run.rssGrowthMb).toBeLessThan(budget.rssGrowthMb);
  }, 300_000);
});
