/**
 * The two cross-user background sweeps SEEK. They do not scan.
 *
 * Two indexes in this schema exist for one reason each, and both reasons are
 * about a job that runs on a timer over a whole collection:
 *
 *   • `VaultItem` carries a standalone SPARSE `{ deletedAt: 1 }`, on top of the
 *     compound `{ userId: 1, deletedAt: -1 }`, because `trashCleanup` asks
 *     `{ deletedAt: { $lte: cutoff } }` across EVERY user — and a compound index
 *     whose first key is `userId` cannot serve a query that does not mention it.
 *     Sparse rather than a `{ $exists: true }` partial, because a partial index
 *     is not planner-eligible for a `$lte` range.
 *   • `User` carries `{ deletionPending: 1 }` with
 *     `partialFilterExpression: { deletionPending: true }`, because
 *     `tokenCleanup`'s zombie sweep asks `{ deletionPending: true }` across every
 *     account — a GDPR erasure that was interrupted, so it must be found again.
 *
 * Delete either index and nothing turns red: both jobs still return exactly the
 * right documents, from a COLLSCAN, on a collection that is small in every other
 * test in this suite. The cost only appears on a real deployment, where the sweep
 * reads every row of the largest collection in the database, every six hours.
 *
 * So the assertion is on the QUERY PLAN, at a volume where the planner has a
 * genuine choice to make. Both plans are compared as text rather than by walking
 * `winningPlan`, because MongoDB's slot-based engine nests the classic stages one
 * level deeper (`queryPlan`) than the classic engine does and the shape is a
 * server-version detail; "an IXSCAN on this index, and no COLLSCAN anywhere" is
 * the claim, and it survives either shape.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import { VaultItem } from '../../src/models/VaultItem.js';
import { User } from '../../src/models/User.js';
import { seedVault } from './fixtures.js';
import { recordScenarioCase } from './measure.js';
import { createTestUser } from '../helpers.js';

/** Enough rows that a COLLSCAN is a real cost and the planner has a choice. */
const ITEMS = 5_000;
const TRASHED = 200;
const USERS = 1_000;
const PENDING_DELETION = 5;

/** Small rows: this scenario is about the plan, not about bytes. */
const DATA_BYTES = 64;

function planText(explained: unknown): string {
  const plan = (explained as { queryPlanner?: { winningPlan?: unknown } }).queryPlanner
    ?.winningPlan;
  return JSON.stringify(plan ?? explained);
}

describe('the cross-user cleanup sweeps use their indexes', () => {
  // `beforeEach`, not `beforeAll`: the suite's global `afterEach` truncates every
  // collection, so a fixture seeded once would leave the second test explaining a
  // query plan over an EMPTY collection — where a COLLSCAN is both correct and
  // free, and the assertion below would be measuring nothing.
  beforeEach(async () => {
    const owner = await createTestUser();
    await seedVault(owner.id, { count: ITEMS, dataBytes: DATA_BYTES });
    // A minority of rows are trashed, which is the real distribution: a sparse
    // index only wins when most documents are not in it.
    const trashable = await VaultItem.find({ userId: owner.id })
      .select('_id')
      .limit(TRASHED)
      .lean();
    await VaultItem.updateMany(
      { _id: { $in: trashable.map((row) => row._id) } },
      { $set: { deletedAt: new Date(Date.now() - 40 * 24 * 60 * 60 * 1000) } },
    );

    const authHash = await bcrypt.hash('resource-suite', 4);
    const others = Array.from({ length: USERS }, (_unused, i) => ({
      email: `resource-${String(i)}-${crypto.randomUUID()}@example.com`,
      authHash,
      emailVerified: true,
      encryptedVaultKey: 'k',
      vaultKeyIv: 'i',
      vaultKeyTag: 't',
      kdfIterations: 600_000,
      kdfAlgorithm: 'PBKDF2-SHA256',
      encryptionVersion: 1,
      ...(i < PENDING_DELETION ? { deletionPending: true } : {}),
    }));
    await User.insertMany(others, { ordered: false });
  }, 300_000);

  it("backs trashCleanup's cross-user cutoff scan with the sparse deletedAt index", async () => {
    const cutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const explained: unknown = await VaultItem.find({ deletedAt: { $lte: cutoff } })
      .limit(500)
      .explain('queryPlanner');
    const text = planText(explained);

    recordScenarioCase('job-index-plans', 'trash-cleanup-seeks', {
      invariant:
        "trashCleanup's cross-user `{ deletedAt: { $lte: cutoff } }` scan is served by the standalone sparse deletedAt index, not by a COLLSCAN",
      items: ITEMS,
      trashed: TRASHED,
      usesIndexScan: text.includes('IXSCAN'),
      usesCollectionScan: text.includes('COLLSCAN'),
    });

    expect(text).toContain('IXSCAN');
    expect(text).toContain('deletedAt');
    expect(text).not.toContain('COLLSCAN');

    // The plan is only worth anything if it returns the right rows.
    expect(await VaultItem.countDocuments({ deletedAt: { $lte: cutoff } })).toBe(TRASHED);
  }, 300_000);

  it("backs tokenCleanup's zombie sweep with the partial deletionPending index", async () => {
    const explained: unknown = await User.find({ deletionPending: true }).explain('queryPlanner');
    const text = planText(explained);

    recordScenarioCase('job-index-plans', 'zombie-sweep-seeks', {
      invariant:
        "tokenCleanup's cross-user `{ deletionPending: true }` sweep is served by the partial deletionPending index, not by a COLLSCAN",
      users: USERS,
      pendingDeletion: PENDING_DELETION,
      usesIndexScan: text.includes('IXSCAN'),
      usesCollectionScan: text.includes('COLLSCAN'),
    });

    expect(text).toContain('IXSCAN');
    expect(text).toContain('deletionPending');
    expect(text).not.toContain('COLLSCAN');

    expect(await User.countDocuments({ deletionPending: true })).toBe(PENDING_DELETION);
  }, 300_000);
});
