/**
 * Phase 6 — server-executor: the TRANSACTION (replica-set) branch of the
 * structured `operations` import.
 *
 * The default harness (tests/setup.ts) connects to a STANDALONE
 * mongodb-memory-server, which rejects multi-document transactions, so every
 * other import test exercises only the non-transactional fallback. The shipped
 * stack runs a replica set (`docker-compose.yml` pins `rs0`), which makes the
 * transactional branch the PRODUCTION path — it must not go unexercised. This
 * file stands up a single-node replica set so `supportsTransactions(...)` is
 * genuinely true and `session.withTransaction(...)` actually runs, following the
 * pattern established by `vault-rotation-transaction.test.ts`.
 *
 * Covers:
 *   • a mixed request commits inserts and updates together
 *   • a failure part-way through rolls the ALREADY-INSERTED rows back — the
 *     discriminator that proves the transaction, not the fallback, ran
 *   • the cap re-check performed INSIDE the transaction aborts the whole request
 *   • (Phase 10) the per-user cap survives OVERLAPPING imports on this topology
 *     too — the standalone half of that guarantee is in
 *     `import-cap-concurrency.test.ts`
 */
import { describe, it, expect, beforeAll, afterAll, afterEach, vi } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import { MongoMemoryReplSet } from 'mongodb-memory-server';
import { MAX_ITEMS_PER_USER } from '@hvault/shared';
import app from '../src/app.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { supportsTransactions } from '../src/utils/transactionSupport.js';
import { createTestUser, authHeader, sampleVaultItem, seedItem, getCsrf } from './helpers.js';
import type { TestUser } from './helpers.js';

function searchHashFor(index: number): string {
  return index.toString(16).padStart(64, '0');
}

function insertRow(index: number): Record<string, unknown> {
  return sampleVaultItem({
    encryptedName: `inserted-name-${String(index)}`,
    encryptedData: `inserted-data-${String(index)}`,
    searchHash: searchHashFor(index),
  });
}

function updateRow(id: string): Record<string, unknown> {
  return {
    id,
    encryptedName: 'updated-name',
    nameIv: 'updated-name-iv',
    nameTag: 'updated-name-tag',
    encryptedData: 'updated-data',
    dataIv: 'updated-data-iv',
    dataTag: 'updated-data-tag',
    searchHash: searchHashFor(999),
  };
}

describe('Import operations — transaction (replica-set) branch', () => {
  let replSet: MongoMemoryReplSet;
  let user: TestUser;

  beforeAll(async () => {
    // setup.ts's beforeAll already connected mongoose to a standalone server.
    // Drop that and reconnect to a replica set so the transactional branch is
    // reachable; setup.ts's afterAll still stops its own (now idle) server.
    await mongoose.disconnect();
    replSet = await MongoMemoryReplSet.create({
      replSet: { count: 1, storageEngine: 'wiredTiger' },
    });
    await mongoose.connect(replSet.getUri());

    // Build every model's indexes on THIS connection. Two reasons: the
    // collections must exist before a transaction writes to them, and
    // `acquireJobLock` — which the import path takes per user — depends entirely
    // on the unique `jobName` index for mutual exclusion.
    await Promise.all(Object.values(mongoose.models).map((model) => model.createIndexes()));

    // Fail loudly rather than silently asserting the fallback branch.
    expect(supportsTransactions(mongoose.connection)).toBe(true);
  }, 60_000);

  afterAll(async () => {
    await mongoose.disconnect();
    await replSet.stop();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  async function postOperations(operations: Record<string, unknown>): Promise<request.Response> {
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);

    return agent
      .post('/api/v1/tools/import')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf.token)
      .set('Cookie', csrf.cookie)
      .send({ format: 'json', operations });
  }

  it('commits inserts and updates together', async () => {
    user = await createTestUser();
    const existing = await seedItem(user.id, { encryptedData: 'original-data' });

    const res = await postOperations({
      inserts: [insertRow(1), insertRow(2)],
      updates: [updateRow(String(existing._id))],
    });

    expect(res.status).toBe(201);
    expect(res.body.data).toEqual({ insertedCount: 2, updatedCount: 1 });

    const stored = await VaultItem.find({ userId: user.id }).lean();
    expect(stored).toHaveLength(3);
    expect(stored.filter((item) => item.encryptedData === 'updated-data')).toHaveLength(1);
  });

  it('rolls the inserts back when a later update fails, leaving the vault untouched', async () => {
    user = await createTestUser();
    const existing = await seedItem(user.id, { encryptedData: 'original-data' });

    // Inserts run before updates, so a rejecting `updateOne` fails the request
    // with rows already written in this session. Under the transaction they must
    // disappear; the non-transactional fallback would leave them behind. That
    // difference is what proves which branch executed.
    vi.spyOn(VaultItem, 'updateOne').mockRejectedValue(new Error('simulated write failure'));

    const res = await postOperations({
      inserts: [insertRow(1), insertRow(2)],
      updates: [updateRow(String(existing._id))],
    });

    expect(res.status).toBe(500);

    const stored = await VaultItem.find({ userId: user.id }).lean();
    expect(stored).toHaveLength(1);
    expect(stored[0]!.encryptedData).toBe('original-data');
  });

  it('aborts when the cap re-check inside the transaction sees the vault at the limit', async () => {
    user = await createTestUser();

    // The first count (taken before the lock) passes; the second — the one made
    // against the state the writes actually observe — trips the cap. Only the
    // in-transaction re-check can reject here, so this targets it specifically.
    vi.spyOn(VaultItem, 'countDocuments')
      .mockResolvedValueOnce(0 as never)
      .mockResolvedValue(MAX_ITEMS_PER_USER as never);

    const res = await postOperations({ inserts: [insertRow(1)] });

    expect(res.status).toBe(400);
    expect(JSON.stringify(res.body)).toMatch(/per-user item limit/i);

    const stored = await VaultItem.find({ userId: user.id }).lean();
    expect(stored).toHaveLength(0);
  });

  it('releases the per-user lock after a transactional import so the next batch lands', async () => {
    user = await createTestUser();

    const first = await postOperations({ inserts: [insertRow(1)] });
    const second = await postOperations({ inserts: [insertRow(2)] });

    expect([first.status, second.status]).toEqual([201, 201]);
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(2);
  });

  // ── Phase 10 — the cap under overlapping imports ─────────────────────
  //
  // A transaction does NOT bound concurrency: two sessions can each read a count
  // of N, each insert, and each commit, because a count is not a document the
  // other session write-conflicts with. So even here the cap is held by the
  // per-user JobLock, and the in-transaction re-check only narrows the window
  // against OTHER endpoints. These two tests pin that on the topology production
  // actually runs (`docker-compose.yml` pins the `rs0` replica set), which the
  // standalone harness can never reach.

  /**
   * Shrinks the user's effective headroom to `headroom` NET-NEW rows by calling
   * THROUGH to the real count and adding a fixed offset — so the value the
   * executor sees still tracks what has actually been written. A flat
   * `mockResolvedValue` would pin it to a constant and the cap could then never
   * notice rows a racing request had just committed, which is the very
   * interaction under test.
   *
   * Deliberately a local copy of the one in `import-cap-concurrency.test.ts`
   * rather than a shared export: that file drives the STANDALONE connection and
   * this one a replica set, and the two must stay independently readable. Keep
   * them in step if either changes.
   */
  function pinHeadroom(headroom: number): void {
    const realCountDocuments = VaultItem.countDocuments.bind(VaultItem) as unknown as (
      filter?: Record<string, unknown>,
      options?: Record<string, unknown>,
    ) => Promise<number>;
    const offset = MAX_ITEMS_PER_USER - headroom;

    vi.spyOn(VaultItem, 'countDocuments').mockImplementation(((
      filter?: Record<string, unknown>,
      options?: Record<string, unknown>,
    ) => realCountDocuments(filter, options).then((count) => count + offset)) as never);
  }

  it('409s an overlapping import while the first one holds an OPEN transaction', async () => {
    user = await createTestUser();
    pinHeadroom(4);

    // Park the first import inside `insertMany` — which on this topology means
    // inside `session.withTransaction`, with the transaction still open and its
    // rows invisible to everyone else. The second request must be refused by the
    // lock rather than wedging behind the transaction or reading a stale count.
    let announceArrival!: () => void;
    const parked = new Promise<void>((resolve) => {
      announceArrival = resolve;
    });
    let openGate!: () => void;
    const gate = new Promise<void>((resolve) => {
      openGate = resolve;
    });

    const realInsertMany = VaultItem.insertMany.bind(VaultItem) as unknown as (
      docs: unknown[],
      options?: Record<string, unknown>,
    ) => Promise<unknown[]>;
    let firstWrite = true;
    vi.spyOn(VaultItem, 'insertMany').mockImplementation((async (
      docs: unknown[],
      options?: Record<string, unknown>,
    ) => {
      if (firstWrite) {
        firstWrite = false;
        announceArrival();
        await gate;
      }
      return realInsertMany(docs, options);
    }) as never);

    const first = postOperations({ inserts: [insertRow(1), insertRow(2), insertRow(3)] });
    await parked;

    const second = await postOperations({ inserts: [insertRow(4), insertRow(5), insertRow(6)] });
    expect(second.status).toBe(409);
    expect(JSON.stringify(second.body)).toMatch(/import is already in progress/i);

    openGate();
    expect((await first).status).toBe(201);

    const stored = await VaultItem.find({ userId: user.id }).lean();
    expect(stored).toHaveLength(3);
  });

  it('never leaves the vault above the cap when several imports are fired at once', async () => {
    user = await createTestUser();
    const HEADROOM = 4;
    const ROWS_PER_REQUEST = 3;
    const REQUESTS = 4;
    pinHeadroom(HEADROOM);

    const responses = await Promise.all(
      Array.from({ length: REQUESTS }, (_, requestIndex) =>
        postOperations({
          inserts: Array.from({ length: ROWS_PER_REQUEST }, (_, rowIndex) =>
            insertRow(requestIndex * ROWS_PER_REQUEST + rowIndex),
          ),
        }),
      ),
    );

    // 201 (it ran), 409 (the lock refused it) and 400 (the cap refused it) are
    // the only legal outcomes. A transient transaction abort surfacing as a 500
    // would be a real defect, not a benign loss of the race.
    for (const res of responses) {
      expect([201, 400, 409]).toContain(res.status);
    }

    const accepted = responses.filter((res) => res.status === 201);
    expect(accepted.length).toBeGreaterThanOrEqual(1);

    const reported = accepted.reduce(
      (total, res) => total + (res.body.data.insertedCount as number),
      0,
    );
    const stored = await VaultItem.find({ userId: user.id }).lean();

    expect(stored.length).toBeLessThanOrEqual(HEADROOM);
    expect(stored).toHaveLength(reported);
  });
});
