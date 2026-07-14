/**
 * Phase 4 — import-cap: the per-user item cap counts NET-NEW inserts.
 *
 * `toolsController.importVault` used to check `existing + <every parsed item>`
 * against MAX_ITEMS_PER_USER, so a `skip` / `overwrite` re-import of a user's
 * own export — which inserts zero rows for every match — was falsely rejected
 * once the vault approached the cap. The cap is now measured against the rows
 * the import will actually INSERT, and it is measured BEFORE any write, so a
 * rejected import cannot leave part of its overwrites behind.
 *
 * Covers:
 *   • skip / overwrite re-import at the cap succeeds (net-new = 0).
 *   • keep_both still counts every item (it always inserts).
 *   • A genuinely over-cap import (net-new inserts exceed the cap) still 400s.
 *   • Overwrite atomicity: a cap rejection writes nothing at all.
 *   • The existing + net-new == cap boundary is allowed.
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
  items: Record<string, unknown>[],
  conflictStrategy?: 'skip' | 'overwrite' | 'keep_both',
): Promise<request.Response> {
  const agent = request.agent(app);
  const csrf = await getCsrf(agent);
  const payload: Record<string, unknown> = {
    format: 'json',
    data: JSON.stringify({ items }),
  };
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

function importRow(
  index: number,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return sampleVaultItem({
    encryptedName: `name-${String(index)}`,
    searchHash: searchHashFor(index),
    ...overrides,
  });
}

/**
 * Pins the user's existing item count one below the cap for the single
 * `countDocuments` call `importVault` makes, so a 1+ row net-new insert would
 * cross it. Seeding 10,000 real rows would be prohibitively slow.
 */
function pinExistingItemCount(count: number): void {
  vi.spyOn(VaultItem, 'countDocuments').mockResolvedValueOnce(count as never);
}

describe('Phase 4 — import per-user cap counts net-new inserts', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ── Re-import of the user's own export at the cap ────────────────────

  it('accepts a skip re-import at the cap (every row is a duplicate; net-new is 0)', async () => {
    for (const index of [0, 1, 2]) {
      await seedItem(user.id, {
        encryptedName: `name-${String(index)}`,
        searchHash: searchHashFor(index),
      });
    }

    pinExistingItemCount(MAX_ITEMS_PER_USER - 1);

    const res = await postImport(
      user.accessToken,
      [importRow(0), importRow(1), importRow(2)],
      'skip',
    );

    expect(res.status).toBe(201);
    expect(res.body.data.duplicateCount).toBe(3);
    expect(res.body.data.importedCount).toBe(0);
    expect(await rawItems(user.id)).toHaveLength(3);
  });

  it('accepts an overwrite re-import at the cap and updates the matches in place', async () => {
    for (const index of [0, 1, 2]) {
      await seedItem(user.id, {
        encryptedName: `name-${String(index)}`,
        searchHash: searchHashFor(index),
        encryptedData: 'original',
      });
    }

    pinExistingItemCount(MAX_ITEMS_PER_USER - 1);

    const res = await postImport(
      user.accessToken,
      [0, 1, 2].map((index) => importRow(index, { encryptedData: 'updated' })),
      'overwrite',
    );

    expect(res.status).toBe(201);
    expect(res.body.data.overwrittenCount).toBe(3);

    const stored = await rawItems(user.id);
    expect(stored).toHaveLength(3);
    expect(stored.every((item) => item.encryptedData === 'updated')).toBe(true);
  });

  // ── keep_both always inserts, so every row still counts ──────────────

  it('rejects a keep_both import at the cap because every row is an insert', async () => {
    for (const index of [0, 1, 2]) {
      await seedItem(user.id, {
        encryptedName: `name-${String(index)}`,
        searchHash: searchHashFor(index),
      });
    }

    pinExistingItemCount(MAX_ITEMS_PER_USER - 1);

    const res = await postImport(
      user.accessToken,
      [importRow(0), importRow(1), importRow(2)],
      'keep_both',
    );

    expect(res.status).toBe(400);
    expect(JSON.stringify(res.body)).toMatch(/per-user item limit/i);
    // The duplicated rows were never minted.
    expect(await rawItems(user.id)).toHaveLength(3);
  });

  // ── A genuine over-cap import is still rejected ──────────────────────

  it('rejects an import whose net-new inserts would cross the cap', async () => {
    pinExistingItemCount(MAX_ITEMS_PER_USER - 1);

    const res = await postImport(
      user.accessToken,
      [importRow(10), importRow(11), importRow(12)],
      'skip',
    );

    expect(res.status).toBe(400);
    expect(JSON.stringify(res.body)).toMatch(/per-user item limit/i);
    expect(await rawItems(user.id)).toHaveLength(0);
  });

  it('allows an import that lands exactly on the cap', async () => {
    pinExistingItemCount(MAX_ITEMS_PER_USER - 3);

    const res = await postImport(
      user.accessToken,
      [importRow(10), importRow(11), importRow(12)],
      'keep_both',
    );

    expect(res.status).toBe(201);
    expect(res.body.data.importedCount).toBe(3);
    expect(await rawItems(user.id)).toHaveLength(3);
  });

  // ── Atomicity: a cap rejection must not persist partial overwrites ───

  it('writes nothing when the cap rejects a mixed overwrite + insert import', async () => {
    for (const index of [0, 1]) {
      await seedItem(user.id, {
        encryptedName: `name-${String(index)}`,
        searchHash: searchHashFor(index),
        encryptedData: 'original',
      });
    }

    // Two rows match (overwrites, net-new 0) and three are new — so net-new is
    // 3 and the cap rejects. The overwrites must not have been applied first.
    pinExistingItemCount(MAX_ITEMS_PER_USER - 1);

    const res = await postImport(
      user.accessToken,
      [
        importRow(0, { encryptedData: 'mutated' }),
        importRow(1, { encryptedData: 'mutated' }),
        importRow(10),
        importRow(11),
        importRow(12),
      ],
      'overwrite',
    );

    expect(res.status).toBe(400);
    expect(JSON.stringify(res.body)).toMatch(/per-user item limit/i);

    const stored = await rawItems(user.id);
    expect(stored).toHaveLength(2);
    expect(stored.every((item) => item.encryptedData === 'original')).toBe(true);
  });
});
