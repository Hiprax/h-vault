/**
 * A paged walk of the vault list where every 200-row page is over 8 MiB, inside a
 * memory budget, returning every row exactly once with the pagination the client
 * trusts.
 *
 * The regression this exists for (F-25): a page was built as a lean array, then a
 * JSON string, then a buffer, three copies of up to ~180 MB (200 rows of up to half
 * a megabyte), on a route with no limiter. The rows are now serialized from the
 * cursor one at a time. The correctness half (same rows, same order, same
 * `totalPages`, never fewer per page) is pinned in the push tier by
 * `tests/vault-list-pages.test.ts`; this measures the cost.
 *
 * Raw sockets that scan each page for its row ids as it streams, never holding it,
 * for the reason the download
 * scenario gives: supertest would hold every body in this process.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import mongoose from 'mongoose';
import type { AddressInfo } from 'node:net';
import app from '../../src/app.js';
import { createTestUser, type TestUser } from '../helpers.js';
import { VaultItem } from '../../src/models/VaultItem.js';
import { measure, recordScenarioCase } from './measure.js';
import { RESOURCE_BUDGETS } from '../../../../scripts/ci/lib/resource-budgets.mjs';

// Rows near the half-megabyte cap, so a 200-row page is ~90 MB: the size at which
// building a page three times over is what the process pays, and what the
// row-at-a-time path does not.
const ITEMS = 300;
const DATA_BYTES = 450_000;
const LIMIT = 200;
const SEED_BATCH = 20;

const budget = RESOURCE_BUDGETS.vaultListVolume;

let server: http.Server;
let port: number;
let user: TestUser;

beforeAll(async () => {
  server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  port = (server.address() as AddressInfo).port;
}, 60_000);

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

interface Page {
  ids: string[];
  totalPages: number;
  bytes: number;
}

/** Row ids as they stream past: `_id` is every row's first member. */
const ROW_ID = /\{"_id":"([0-9a-f]{24})"/g;
const PAGINATION = /"totalPages":(\d+)/;

/**
 * One page, scanned as it arrives and never held: the ids are picked out of a
 * rolling window, so the client costs the process a chunk at a time, not a page.
 */
function fetchPage(page: number): Promise<Page> {
  return new Promise((resolve, reject) => {
    const req = http.get(
      {
        host: '127.0.0.1',
        port,
        path: `/api/v1/vault/items?page=${String(page)}&limit=${String(LIMIT)}`,
        headers: { authorization: `Bearer ${user.accessToken}` },
      },
      (res) => {
        const ids: string[] = [];
        let window = '';
        let bytes = 0;
        res.setEncoding('utf8');
        res.on('data', (chunk: string) => {
          bytes += Buffer.byteLength(chunk);
          window += chunk;
          let lastEnd = 0;
          for (const match of window.matchAll(ROW_ID)) {
            ids.push(match[1]!);
            lastEnd = (match.index ?? 0) + match[0].length;
          }
          // Keep only a tail long enough to hold a match split across chunks.
          window = window.slice(Math.max(lastEnd, window.length - 64));
        });
        res.on('end', () => {
          const totalPages = Number(PAGINATION.exec(window)?.[1] ?? NaN);
          resolve({ ids, totalPages, bytes });
        });
        res.on('error', reject);
      },
    );
    req.on('error', reject);
  });
}

describe('a full walk of the vault list at 200 rows a page', () => {
  beforeAll(async () => {
    user = await createTestUser();
    // Seeded here rather than with `fixtures.seedVault`, in small batches around ONE
    // shared ciphertext string: that fixture's 500-row batches of fresh strings
    // leave a few hundred megabytes of freed heap behind, which the page the
    // measurement then builds would simply reuse, hiding the very cost it measures.
    const data = 'd'.repeat(DATA_BYTES);
    for (let base = 0; base < ITEMS; base += SEED_BATCH) {
      await VaultItem.collection.insertMany(
        Array.from({ length: Math.min(SEED_BATCH, ITEMS - base) }, (_unused, offset) => ({
          userId: new mongoose.Types.ObjectId(user.id),
          itemType: 'login',
          encryptedData: data,
          dataIv: 'i'.repeat(16),
          dataTag: 't'.repeat(22),
          encryptedName: `name-${String(base + offset)}`,
          nameIv: 'i'.repeat(16),
          nameTag: 't'.repeat(22),
          tags: [],
          favorite: false,
          createdAt: new Date(),
          updatedAt: new Date(),
        })),
      );
    }
  }, 600_000);

  it('returns every row exactly once, full pages, within the time and memory budget', async () => {
    const run = await measure(async () => {
      const ids: string[] = [];
      const pageBytes: number[] = [];
      let totalPages = 1;
      for (let page = 1; page <= totalPages; page += 1) {
        const result = await fetchPage(page);
        ids.push(...result.ids);
        pageBytes.push(result.bytes);
        totalPages = result.totalPages;
      }
      return { ids, pageBytes, totalPages };
    });

    recordScenarioCase('vault-list-volume', 'walk-every-page', {
      invariant:
        'a walk of a 300-row vault of ~450 KB rows at 200 rows a page (each page far over 8 MiB) returns every row once with the true totalPages inside the memory budget',
      items: ITEMS,
      dataBytesPerItem: DATA_BYTES,
      pages: run.result.totalPages,
      pageBytes: run.result.pageBytes,
      rows: run.result.ids.length,
      durationMs: run.durationMs,
      rssGrowthMb: run.rssGrowthMb,
      peakRssMb: run.peakRssMb,
      rssStartMb: run.rssStartMb,
      processMaxRssMb: run.processMaxRssMb,
      budget,
    });

    expect(run.result.totalPages).toBe(Math.ceil(ITEMS / LIMIT));
    expect(run.result.ids).toHaveLength(ITEMS);
    expect(new Set(run.result.ids).size).toBe(ITEMS);
    for (const bytes of run.result.pageBytes) expect(bytes).toBeGreaterThan(8 * 1024 * 1024);
    expect(run.result.pageBytes).toHaveLength(2);
    expect(run.durationMs).toBeLessThan(budget.durationMs);
    expect(run.rssGrowthMb).toBeLessThan(budget.rssGrowthMb);
  }, 600_000);
});
