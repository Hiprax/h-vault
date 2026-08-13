/**
 * A full-vault key rotation: 10,000 items re-encrypted in one request, inside a
 * time and memory budget, and all-or-nothing.
 *
 * `POST /items/bulk-reencrypt` is the single largest thing a user can ask this
 * server to do. It carries every item's new ciphertext in one body — which is
 * why that route mounts its own 30 MB parser instead of the global 2 MB one —
 * and it is the operation whose partial failure is unrecoverable: an item
 * written with the NEW key while the user's stored vault key is rolled back to
 * the OLD one is an item its owner can never decrypt again.
 *
 * Nothing EXECUTED that at volume. `vault.test.ts` sends a 10,000-item payload
 * through this route to prove the 30 MB parser accepts it, but with a
 * deliberately bogus `authHash` — so the request is parsed and then refused at
 * authentication, and no rotation happens. Every rotation test that reaches the
 * controller uses a handful of items. This file measures the success path with
 * the full ten thousand; `rotation-atomicity.test.ts` holds the other half — a
 * full-vault rotation carrying one unknown id, which must change nothing at all.
 *
 * Both run against a standalone mongod, which is the topology
 * `supportsTransactions()` reports false for, so both exercise the SEQUENTIAL
 * fallback: the path where atomicity is the application's own snapshot-and-abort
 * logic rather than the database's. That is the harder half to get right and the
 * one a volume test can actually stress.
 *
 * One measured scenario per file, per the rule in `measure.ts`: the suite's
 * `afterEach` truncates every collection, so a seeded vault survives exactly one
 * test anyway, and a second heavy request in this worker would raise the RSS
 * floor the budget below is measured from.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import app from '../../src/app.js';
import { MAX_ITEMS_PER_USER } from '@hvault/shared';
import { User } from '../../src/models/User.js';
import { VaultItem } from '../../src/models/VaultItem.js';
import { createTestUser, authHeader, getCsrf, type TestUser } from '../helpers.js';
import { seedVault } from './fixtures.js';
import { measure, recordScenarioCase } from './measure.js';
import { RESOURCE_BUDGETS } from '../../../../scripts/ci/lib/resource-budgets.mjs';

/** Ciphertext bytes per item, before and after the rotation. ~18 MB of body. */
const DATA_BYTES = 1_600;

/** What the rotation writes, so "did every row change?" is one query. */
const ROTATED_DATA = 'r'.repeat(DATA_BYTES);
const ROTATED_NAME = 'rotated-name';

const budget = RESOURCE_BUDGETS.rotationVolume;

interface RotationPayloadItem {
  id: string;
  encryptedName: string;
  nameIv: string;
  nameTag: string;
  encryptedData: string;
  dataIv: string;
  dataTag: string;
}

function rotationBody(ids: string[], authHash: string): Record<string, unknown> {
  return {
    authHash,
    items: ids.map((id): RotationPayloadItem => ({
      id,
      encryptedName: ROTATED_NAME,
      nameIv: 'n'.repeat(16),
      nameTag: 'n'.repeat(22),
      encryptedData: ROTATED_DATA,
      dataIv: 'v'.repeat(16),
      dataTag: 'g'.repeat(22),
    })),
    folders: [],
    newEncryptedVaultKey: 'rotated-vault-key',
    newVaultKeyIv: 'k'.repeat(16),
    newVaultKeyTag: 'k'.repeat(22),
  };
}

describe('a full-vault key rotation', () => {
  let user: TestUser;
  let seeded: { count: number; seedMs: number; collectionBytes: number };
  let itemIds: string[];

  beforeAll(async () => {
    user = await createTestUser();
    seeded = await seedVault(user.id, { count: MAX_ITEMS_PER_USER, dataBytes: DATA_BYTES });
    const rows = await VaultItem.find({ userId: user.id }).select('_id').lean();
    itemIds = rows.map((row) => String(row._id));
  }, 300_000);

  it('re-encrypts all 10,000 items in one request, within the time and memory budget', async () => {
    const { token, cookie } = await getCsrf(request(app));
    const run = await measure(async () =>
      request(app)
        .post('/api/v1/vault/items/bulk-reencrypt')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', token)
        .set('Cookie', cookie)
        .send(rotationBody(itemIds, user.authHash)),
    );

    const rotated = await VaultItem.countDocuments({
      userId: user.id,
      encryptedData: ROTATED_DATA,
    });
    const after = await User.findById(user.id).lean();

    recordScenarioCase('rotation-volume', 'reencrypts-every-row', {
      invariant:
        'a 10,000-item bulk-reencrypt completes inside the time and memory budget and leaves every row carrying the new ciphertext',
      items: seeded.count,
      dataBytesPerItem: DATA_BYTES,
      collectionMb: Number((seeded.collectionBytes / (1024 * 1024)).toFixed(2)),
      seedMs: seeded.seedMs,
      status: run.result.status,
      rotatedRows: rotated,
      durationMs: run.durationMs,
      rssGrowthMb: run.rssGrowthMb,
      peakRssMb: run.peakRssMb,
      rssStartMb: run.rssStartMb,
      processMaxRssMb: run.processMaxRssMb,
      budget,
    });

    expect(run.result.status).toBe(200);
    expect(run.result.body).toMatchObject({
      success: true,
      data: { updatedCount: itemIds.length },
    });

    // All of them, and the vault key that decrypts them, moved together.
    expect(rotated).toBe(MAX_ITEMS_PER_USER);
    expect(after?.encryptedVaultKey).toBe('rotated-vault-key');
    // The write fence is DOWN afterwards. Left raised, every subsequent
    // ciphertext-creating request 409s until a login happens to recover it.
    expect(after?.rotationInProgress).not.toBe(true);
    expect(after?.pendingEncryptedVaultKey).toBeUndefined();

    expect(run.durationMs).toBeLessThan(budget.durationMs);
    expect(run.rssGrowthMb).toBeLessThan(budget.rssGrowthMb);
  }, 300_000);
});
