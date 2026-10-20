/**
 * The four per-row document writes are budgeted per USER on `documentWrite:`,
 * never on the shared `general:` bucket.
 *
 * ## The gap this file closes
 *
 * `PUT /documents/:id`, `DELETE /documents/:id`, `POST /documents/:id/restore` and
 * `DELETE /documents/:id/permanent` sat on `generalAuthLimiter`: 60 a minute in
 * ONE `general:<userId>` bucket shared with the profile, the document list and
 * logout. The documents page now has bulk actions that send one of these per
 * selected document, as the vault's bulk tag and purge do, so a bulk action over
 * more than a minute's worth of documents would have been refused part-way
 * (half the selection deleted) and would then have refused the sign-out after it.
 * The budget here is derived from the per-user document cap instead, and it is
 * separate from `general:`, which is what the cases below observe.
 *
 * ## How the ceiling is reached
 *
 * As `mutation-limiters.test.ts` does it: the counter document is SEEDED at the
 * budget in the real `rateLimits` collection, and the next request through the
 * real router must be refused before its controller runs. `isProduction` is
 * forced for this file's module graph (every limiter is a pass-through outside
 * production), and `storageConfigured` too, because the documents router refuses
 * everything with a 503 ahead of its limiters on a server without a bucket.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import express from 'express';
import request from 'supertest';
import mongoose from 'mongoose';
import { createErrorMiddleware } from '@hiprax/errors';
import { DOCUMENT_PLAINTEXT_CHUNK_BYTES, DOCUMENT_TAG_BYTES } from '@hvault/shared';

vi.mock('../src/config/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/config/index.js')>();
  return { ...actual, isProduction: true, storageConfigured: true };
});

import documentRouter from '../src/routes/documents.js';
import {
  DOCUMENT_WRITE_RATE_LIMIT_MAX,
  VAULT_WRITE_RATE_LIMIT_WINDOW_MS,
} from '../src/middleware/rateLimiter.js';
import { RATE_LIMIT_COLLECTION } from '../src/middleware/rateLimitStore.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { Document } from '../src/models/Document.js';
import { buildObjectKey } from '../src/utils/documentObjects.js';
import { authHeader, createTestUser, type TestUser } from './helpers.js';

/** The general bucket's per-minute ceiling, as `coverage-rate-limiter.test.ts` pins it. */
const GENERAL_LIMIT = 60;

/** The real documents router, with no CSRF middleware (it would 403 first). */
function createApp() {
  const app = express();
  app.set('trust proxy', 1);
  app.use(express.json());
  app.use('/api/v1/documents', documentRouter);
  app.use(createErrorMiddleware({ exposeServerErrors: false }));
  return app;
}

function rateLimits() {
  return mongoose.connection.db!.collection<{
    _id: string;
    counter: number;
    expirationDate: Date;
  }>(RATE_LIMIT_COLLECTION);
}

async function counters(): Promise<Map<string, number>> {
  const docs = await rateLimits().find({}).toArray();
  return new Map(docs.map((doc) => [doc._id, doc.counter]));
}

/** Put `key` at `counter` hits inside a live window, as the store itself would. */
async function seedCounter(key: string, counter: number): Promise<void> {
  await rateLimits().insertOne({
    _id: key,
    counter,
    expirationDate: new Date(Date.now() + VAULT_WRITE_RATE_LIMIT_WINDOW_MS),
  });
}

/** A committed document row, in the shape a completion leaves (no object needed here). */
async function seedDocument(user: TestUser, deletedAt?: Date): Promise<string> {
  const documentId = new mongoose.Types.ObjectId();
  await Document.create({
    _id: documentId,
    userId: user.id,
    objectKey: buildObjectKey(user.id, documentId.toHexString()),
    encryptedDek: 'dek-ciphertext',
    dekIv: 'dek-iv',
    dekTag: 'dek-tag',
    encryptedMeta: 'meta-ciphertext',
    metaIv: 'meta-iv',
    metaTag: 'meta-tag',
    streamSalt: Buffer.alloc(32, 11).toString('base64'),
    noncePrefix: Buffer.alloc(7, 5).toString('base64'),
    chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    chunkCount: 1,
    ciphertextBytes: 1024 + DOCUMENT_TAG_BYTES,
    plaintextBytes: 1024,
    ...(deletedAt === undefined ? {} : { deletedAt }),
  });
  return documentId.toHexString();
}

describe('per-row document writes are budgeted per user, apart from general:', () => {
  beforeEach(async () => {
    await rateLimits().deleteMany({});
  });

  it('counts a favorite, a trash and a restore against documentWrite:<user>, and never against general:', async () => {
    const app = createApp();
    const user = await createTestUser();
    const auth = authHeader(user.accessToken);
    const id = await seedDocument(user);

    const favorited = await request(app)
      .put(`/api/v1/documents/${id}`)
      .set('x-forwarded-for', '203.0.113.10')
      .set('Authorization', auth)
      .send({ favorite: true });
    expect(favorited.status).toBe(200);
    const trashed = await request(app)
      .delete(`/api/v1/documents/${id}`)
      .set('x-forwarded-for', '203.0.113.11')
      .set('Authorization', auth);
    expect(trashed.status).toBe(200);
    const restored = await request(app)
      .post(`/api/v1/documents/${id}/restore`)
      .set('x-forwarded-for', '203.0.113.12')
      .set('Authorization', auth);
    expect(restored.status).toBe(200);

    // Three different addresses, one account: one counter, on the account.
    expect([...(await counters()).entries()]).toEqual([[`documentWrite:${user.id}`, 3]]);
  });

  it('refuses a write past the budget BEFORE the controller runs: nothing changes, no audit row', async () => {
    const app = createApp();
    const alice = await createTestUser();
    const bob = await createTestUser();
    const aliceDoc = await seedDocument(alice);
    const bobDoc = await seedDocument(bob);
    await seedCounter(`documentWrite:${alice.id}`, DOCUMENT_WRITE_RATE_LIMIT_MAX);

    for (const send of [
      () => request(app).put(`/api/v1/documents/${aliceDoc}`).send({ favorite: true }),
      () => request(app).delete(`/api/v1/documents/${aliceDoc}`),
      () => request(app).post(`/api/v1/documents/${aliceDoc}/restore`),
      () => request(app).delete(`/api/v1/documents/${aliceDoc}/permanent`),
    ]) {
      const blocked = await send()
        .set('x-forwarded-for', '198.51.100.30')
        .set('Authorization', authHeader(alice.accessToken));
      expect(blocked.status).toBe(429);
      expect((blocked.body as { message: string }).message).toBe(
        'Too many document changes, please try again later',
      );
      expect(blocked.headers['retry-after']).toBeDefined();
    }
    const row = await Document.findById(aliceDoc).lean();
    expect(row?.favorite).not.toBe(true);
    expect(row?.deletedAt).toBeUndefined();
    expect(row?.purgePending).toBeFalsy();
    expect(await AuditLog.countDocuments({ userId: alice.id })).toBe(0);

    // Another account behind the SAME address is untouched by Alice's budget.
    const other = await request(app)
      .put(`/api/v1/documents/${bobDoc}`)
      .set('x-forwarded-for', '198.51.100.30')
      .set('Authorization', authHeader(bob.accessToken))
      .send({ favorite: true });
    expect(other.status).toBe(200);

    // And Alice's ordinary reads, on `general:`, still answer.
    const list = await request(app)
      .get('/api/v1/documents/usage')
      .set('Authorization', authHeader(alice.accessToken));
    expect(list.status).toBe(200);
  });

  it('keeps writing documents while the general bucket is exhausted', async () => {
    // The direction the old placement got wrong: a full `general:` bucket (a busy
    // minute of page loads) used to refuse the next document write too.
    const app = createApp();
    const user = await createTestUser();
    const id = await seedDocument(user);
    await seedCounter(`general:${user.id}`, GENERAL_LIMIT);

    const res = await request(app)
      .put(`/api/v1/documents/${id}`)
      .set('Authorization', authHeader(user.accessToken))
      .send({ favorite: true });

    expect(res.status).toBe(200);
    expect((await Document.findById(id).lean())?.favorite).toBe(true);
    expect((await counters()).get(`general:${user.id}`)).toBe(GENERAL_LIMIT);
    expect((await counters()).get(`documentWrite:${user.id}`)).toBe(1);
  });
});
