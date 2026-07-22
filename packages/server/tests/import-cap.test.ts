/**
 * Import cap — the per-user item cap counts NET-NEW inserts.
 *
 * `toolsController.importVault` used to check `existing + <every parsed item>`
 * against MAX_ITEMS_PER_USER, so a re-import of a user's own export — which
 * rewrites rows in place rather than adding them — was falsely rejected once the
 * vault approached the cap. The cap is now measured against the rows the import
 * will actually INSERT (`operations.inserts`), and it is measured BEFORE any
 * write, so a rejected import cannot leave part of its updates behind.
 *
 * Covers:
 *   • an updates-only request at the cap succeeds (net-new = 0).
 *   • an inserts-only request at the cap is rejected.
 *   • the existing + net-new == cap boundary is allowed.
 *   • atomicity: a cap rejection applies none of the request's updates.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import request from 'supertest';
import { MAX_ITEMS_PER_USER } from '@hvault/shared';
import app from '../src/app.js';
import { VaultItem } from '../src/models/VaultItem.js';
import {
  createTestUser,
  authHeader,
  sampleVaultItem,
  seedItem,
  getCsrf,
  rawItems,
  type TestUser,
} from './helpers.js';

const API = '/api/v1';

async function postImport(
  token: string,
  operations: Record<string, unknown>,
  conflictStrategy?: 'skip' | 'overwrite' | 'keep_both',
): Promise<request.Response> {
  const agent = request.agent(app);
  const csrf = await getCsrf(agent);
  const payload: Record<string, unknown> = { format: 'json', operations };
  if (conflictStrategy) payload.conflictStrategy = conflictStrategy;

  return agent
    .post(`${API}/tools/import`)
    .set('Authorization', authHeader(token))
    .set('x-csrf-token', csrf.token)
    .set('Cookie', csrf.cookie)
    .send(payload);
}

/** A distinct, well-formed (lowercase hex, 64-char) searchHash per index. */
function searchHashFor(index: number): string {
  return index.toString(16).padStart(64, '0');
}

/** One `inserts[]` row that satisfies `importInsertItemSchema`. */
function insertRow(
  index: number,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return sampleVaultItem({
    encryptedName: `name-${String(index)}`,
    searchHash: searchHashFor(index),
    ...overrides,
  });
}

/** One `updates[]` row that satisfies `importUpdateItemSchema`. */
function updateRow(id: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id,
    encryptedName: 'updated-name',
    nameIv: 'updated-name-iv',
    nameTag: 'updated-name-tag',
    encryptedData: 'updated',
    dataIv: 'updated-data-iv',
    dataTag: 'updated-data-tag',
    searchHash: searchHashFor(999),
    ...overrides,
  };
}

/**
 * Pins the user's existing item count one below the cap, so a 1+ row net-new
 * insert would cross it. Seeding 10,000 real rows would be prohibitively slow.
 *
 * The stub is PERSISTENT (`mockResolvedValue`), not single-shot. `vi.spyOn`
 * retains the real implementation, so with `mockResolvedValueOnce` a second
 * `countDocuments` call anywhere in the request would quietly fall through to
 * the true count (3, say) and the pin would stop pinning — the assertions below
 * would then pass or fail for a reason unrelated to the cap. The executor
 * deliberately counts TWICE (once before taking the per-user lock, once again
 * against the state the writes observe), so a single-shot pin is not safe to
 * reach for on this endpoint at all. `vi.restoreAllMocks()` in `afterEach`
 * clears it between tests.
 */
function pinExistingItemCount(count: number): void {
  vi.spyOn(VaultItem, 'countDocuments').mockResolvedValue(count as never);
}

describe('import per-user cap counts net-new inserts', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ── Re-import of the user's own export at the cap ────────────────────

  it('accepts an updates-only re-import at the cap (net-new is 0)', async () => {
    const seeded: Record<string, unknown>[] = [];
    for (const index of [0, 1, 2]) {
      seeded.push(
        await seedItem(user.id, {
          encryptedName: `name-${String(index)}`,
          searchHash: searchHashFor(index),
          encryptedData: 'original',
        }),
      );
    }

    pinExistingItemCount(MAX_ITEMS_PER_USER - 1);

    const res = await postImport(
      user.accessToken,
      { updates: seeded.map((item) => updateRow(String(item._id))) },
      'skip',
    );

    expect(res.status).toBe(201);
    expect(res.body.data).toEqual({ insertedCount: 0, updatedCount: 3 });

    const stored = await rawItems(user.id);
    expect(stored).toHaveLength(3);
    expect(stored.every((item) => item.encryptedData === 'updated')).toBe(true);
  });

  // ── Every insert counts, whatever the client's strategy was ──────────

  it('rejects an inserts-only import at the cap', async () => {
    for (const index of [0, 1, 2]) {
      await seedItem(user.id, {
        encryptedName: `name-${String(index)}`,
        searchHash: searchHashFor(index),
      });
    }

    pinExistingItemCount(MAX_ITEMS_PER_USER - 1);

    const res = await postImport(
      user.accessToken,
      { inserts: [insertRow(10), insertRow(11), insertRow(12)] },
      'keep_both',
    );

    expect(res.status).toBe(400);
    expect(JSON.stringify(res.body)).toMatch(/per-user item limit/i);
    // The new rows were never minted; only the three seeded ones remain.
    expect(await rawItems(user.id)).toHaveLength(3);
  });

  it('rejects an import whose net-new inserts would cross the cap', async () => {
    pinExistingItemCount(MAX_ITEMS_PER_USER - 1);

    const res = await postImport(
      user.accessToken,
      { inserts: [insertRow(10), insertRow(11), insertRow(12)] },
      'skip',
    );

    expect(res.status).toBe(400);
    expect(JSON.stringify(res.body)).toMatch(/per-user item limit/i);
    expect(await rawItems(user.id)).toHaveLength(0);
  });

  it('allows an import that lands exactly on the cap', async () => {
    pinExistingItemCount(MAX_ITEMS_PER_USER - 3);

    const res = await postImport(user.accessToken, {
      inserts: [insertRow(10), insertRow(11), insertRow(12)],
    });

    expect(res.status).toBe(201);
    expect(res.body.data).toEqual({ insertedCount: 3, updatedCount: 0 });
    expect(await rawItems(user.id)).toHaveLength(3);
  });

  // ── Atomicity: a cap rejection must not persist partial updates ──────

  it('writes nothing when the cap rejects a mixed update + insert import', async () => {
    const seeded: Record<string, unknown>[] = [];
    for (const index of [0, 1]) {
      seeded.push(
        await seedItem(user.id, {
          encryptedName: `name-${String(index)}`,
          searchHash: searchHashFor(index),
          encryptedData: 'original',
        }),
      );
    }

    // Two rows are updates (net-new 0) and three are inserts — so net-new is 3
    // and the cap rejects. The updates must not have been applied first.
    pinExistingItemCount(MAX_ITEMS_PER_USER - 1);

    const res = await postImport(user.accessToken, {
      updates: seeded.map((item) => updateRow(String(item._id), { encryptedData: 'mutated' })),
      inserts: [insertRow(10), insertRow(11), insertRow(12)],
    });

    expect(res.status).toBe(400);
    expect(JSON.stringify(res.body)).toMatch(/per-user item limit/i);

    const stored = await rawItems(user.id);
    expect(stored).toHaveLength(2);
    expect(stored.every((item) => item.encryptedData === 'original')).toBe(true);
  });
});
