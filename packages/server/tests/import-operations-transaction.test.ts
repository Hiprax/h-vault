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
});
