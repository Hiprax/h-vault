/**
 * F-25: the two vault list routes are serialised from the cursor, a row at a
 * time, instead of as a lean array, a string and a buffer (a 200-row page of
 * half-megabyte rows is ~180 MB built three times over). What must NOT change is
 * the contract the client's walk depends on (`vaultStore.fetchItems` and the trash
 * walk request page N at limit 200 and trust `totalPages`): the same rows, in the
 * same order, never fewer per page, and the same `pagination`. A short page would
 * move the next `skip` past rows the client never saw, the items would vanish
 * from the UI, and every later key rotation would be refused for not covering
 * them.
 *
 * Each page here is over 8 MiB, so the body arrives in many chunks.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import app from '../src/app.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { authHeader, createTestUser, sampleVaultItem, type TestUser } from './helpers.js';

const ROWS = 470;
const LIMIT = 200;
const DATA_BYTES = 42_000;

let user: TestUser;

async function walk(path: string): Promise<{ ids: string[]; pages: request.Response[] }> {
  const ids: string[] = [];
  const pages: request.Response[] = [];
  let page = 1;
  let totalPages = 1;
  do {
    const res = await request(app)
      .get(`/api/v1/vault/${path}?page=${String(page)}&limit=${String(LIMIT)}`)
      .set('Authorization', authHeader(user.accessToken));
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/^application\/json/);
    pages.push(res);
    ids.push(...(res.body.data as { _id: string }[]).map((row) => row._id));
    totalPages = res.body.pagination.totalPages as number;
    page += 1;
  } while (page <= totalPages);
  return { ids, pages };
}

/**
 * Seeded per test: the suite truncates every collection after each one. `ROWS`
 * rows, every seventh trashed, so 402 live ones: three pages at 200, the first
 * two over 8 MiB each.
 */
async function seed(dataBytes: number): Promise<void> {
  user = await createTestUser();
  const base = new Date('2026-09-01T00:00:00.000Z').getTime();
  // Ties on `updatedAt` in blocks of ten, so the `_id` tiebreak is exercised too.
  await VaultItem.insertMany(
    Array.from({ length: ROWS }, (_, index) => ({
      userId: user.id,
      ...sampleVaultItem({ encryptedData: String(index % 10).repeat(dataBytes) }),
      ...(index % 7 === 0 ? { deletedAt: new Date(base + index) } : {}),
      createdAt: new Date(base + Math.floor(index / 10)),
      updatedAt: new Date(base + Math.floor(index / 10)),
    })),
    { timestamps: false } as never,
  );
}

beforeEach(async () => {
  await seed(DATA_BYTES);
}, 120_000);

describe('GET /vault/items pages', () => {
  it('returns every live row exactly once, a full page at a time, with the pagination the walk trusts', async () => {
    const live = await VaultItem.countDocuments({ userId: user.id, deletedAt: null });
    const { ids, pages } = await walk('items');

    expect(new Set(ids).size).toBe(ids.length);
    expect(ids).toHaveLength(live);
    expect(pages.map((p) => (p.body.data as unknown[]).length)).toEqual([
      LIMIT,
      LIMIT,
      live - 2 * LIMIT,
    ]);
    for (const [index, page] of pages.entries()) {
      expect(page.body.success).toBe(true);
      expect(page.body.pagination).toEqual({
        page: index + 1,
        limit: LIMIT,
        total: live,
        totalPages: Math.ceil(live / LIMIT),
      });
    }
    // A page is over 8 MiB of JSON.
    expect(Buffer.byteLength(JSON.stringify(pages[0]!.body))).toBeGreaterThan(8 * 1024 * 1024);
  }, 120_000);

  it('serves exactly the rows, fields and order of the query it always ran', async () => {
    const res = await request(app)
      .get(`/api/v1/vault/items?page=2&limit=${String(LIMIT)}&sortBy=updatedAt&sortOrder=desc`)
      .set('Authorization', authHeader(user.accessToken));
    // The first two pages of the query the route has always run, and page 2 of it.
    const firstTwoPages = await VaultItem.find({ userId: user.id, deletedAt: null })
      .select('-userId -sourceRefId')
      .sort({ updatedAt: -1, _id: -1 })
      .limit(2 * LIMIT)
      .lean();
    const expected = firstTwoPages.slice(LIMIT);
    expect(expected).toHaveLength(LIMIT);

    expect(res.body.data).toEqual(JSON.parse(JSON.stringify(expected)));
    // The owner and the provenance never reach the wire.
    expect(JSON.stringify(res.body.data)).not.toContain(user.id);
    expect(res.body.data[0]).not.toHaveProperty('sourceRefId');
  }, 60_000);

  it('answers a page past the end with an empty list and the true totals', async () => {
    const live = await VaultItem.countDocuments({ userId: user.id, deletedAt: null });
    const res = await request(app)
      .get(`/api/v1/vault/items?page=9&limit=${String(LIMIT)}`)
      .set('Authorization', authHeader(user.accessToken));
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      success: true,
      data: [],
      pagination: { page: 9, limit: LIMIT, total: live, totalPages: Math.ceil(live / LIMIT) },
    });
  });

  it('keeps filters: favourites only, from the same stream', async () => {
    await VaultItem.updateOne({ userId: user.id, deletedAt: null }, { $set: { favorite: true } });
    const res = await request(app)
      .get('/api/v1/vault/items?favorite=true')
      .set('Authorization', authHeader(user.accessToken));
    expect(res.body.pagination.total).toBe(1);
    expect(res.body.data).toHaveLength(1);
    expect(res.body.data[0].favorite).toBe(true);
    await VaultItem.updateMany({ userId: user.id }, { $set: { favorite: false } });
  });
});

describe('GET /vault/items/trash pages', () => {
  it('returns every trashed row exactly once with the pagination the trash walk trusts', async () => {
    const trashed = await VaultItem.countDocuments({
      userId: user.id,
      deletedAt: { $exists: true, $ne: null },
    });
    const { ids, pages } = await walk('items/trash');
    expect(new Set(ids).size).toBe(trashed);
    expect(ids).toHaveLength(trashed);
    expect(pages[0]!.body.pagination).toEqual({
      page: 1,
      limit: LIMIT,
      total: trashed,
      totalPages: Math.ceil(trashed / LIMIT),
    });
  });

  it('never lists another account’s rows', async () => {
    const other = await createTestUser();
    await VaultItem.create({ userId: other.id, ...sampleVaultItem(), deletedAt: new Date() });
    const res = await request(app)
      .get('/api/v1/vault/items/trash?limit=200')
      .set('Authorization', authHeader(user.accessToken));
    const ids = (res.body.data as { _id: string }[]).map((row) => row._id);
    const foreign = await VaultItem.findOne({
      userId: new mongoose.Types.ObjectId(other.id),
    }).lean();
    expect(ids).not.toContain(String(foreign!._id));
  });
});
