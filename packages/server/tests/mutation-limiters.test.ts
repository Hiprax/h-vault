/**
 * Every audit-writing vault and folder mutation is budgeted, per USER, and the
 * budget is its own.
 *
 * ## The gap this file closes
 *
 * Each item and folder mutation writes an `AuditLog` row, and that collection
 * keeps a row for 365 days. None of the nine routes carried a limiter, so a valid
 * session (or a stolen one) could write audit rows as fast as the server would
 * accept requests. The user, backup and document routers had already been given
 * one for exactly that reason (`routes/user.ts`: "an unlimited endpoint let a
 * valid session flood the audit log").
 *
 * ## Why not `generalAuthLimiter`
 *
 * The client fans out ONE request per row with `Promise.all` and no 429 retry: a
 * bulk tag, a bulk purge of the trash and a folder drag each send a request per
 * item. `generalAuthLimiter` is 60 per minute in ONE `general:<userId>` bucket
 * shared with the profile, the folder list and logout, so a 61-item bulk tag
 * would have been refused partway through (leaving half the selection tagged)
 * and then refused the logout that followed it. The two budgets here are derived
 * from the per-user caps instead, and they are separate from each other and from
 * `general:`, which is what the cases below observe.
 *
 * ## How the ceiling is reached
 *
 * Without twenty thousand requests: the counter document is SEEDED at the budget
 * in the real `rateLimits` collection, in the shape `MongoRateLimitStore` writes,
 * and the next request through the real router must be refused. That is the real
 * limiter reading the real store, and it lets each case assert what matters most
 * about a refusal: the controller never ran, so no row and no audit entry exist.
 *
 * `isProduction` is forced for this file's module graph only, exactly as
 * `auth-limiter-isolation.test.ts` does it, because every limiter is a
 * pass-through outside production.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import express from 'express';
import cookieParser from 'cookie-parser';
import request from 'supertest';
import mongoose from 'mongoose';
import { createErrorMiddleware } from '@hiprax/errors';

vi.mock('../src/config/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/config/index.js')>();
  return { ...actual, isProduction: true };
});

import vaultRouter from '../src/routes/vault.js';
import folderRouter from '../src/routes/folders.js';
import userRouter from '../src/routes/user.js';
import {
  FOLDER_WRITE_RATE_LIMIT_MAX,
  HEAVY_OP_RATE_LIMIT_MAX,
  VAULT_WRITE_RATE_LIMIT_WINDOW_MS,
  TWO_FACTOR_VERIFY_RATE_LIMIT_MAX,
  VAULT_ITEM_WRITE_RATE_LIMIT_MAX,
} from '../src/middleware/rateLimiter.js';
import { RATE_LIMIT_COLLECTION } from '../src/middleware/rateLimitStore.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { createTestUser, authHeader, sampleVaultItem, sampleFolder } from './helpers.js';

/**
 * The real vault, folder and user routers on ONE app, with no CSRF middleware:
 * CSRF runs app-wide ahead of the routers and would refuse every request here
 * with a 403 before any limiter counted it.
 */
function createApp() {
  const app = express();
  app.set('trust proxy', 1);
  app.use(express.json());
  app.use(cookieParser());
  app.use('/api/v1/vault', vaultRouter);
  app.use('/api/v1/folders', folderRouter);
  app.use('/api/v1/user', userRouter);
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

describe('vault and folder mutations are budgeted per user', () => {
  beforeEach(async () => {
    await rateLimits().deleteMany({});
  });

  it('counts every item mutation against vaultWrite:<user>, and never against general: or folderWrite:', async () => {
    const app = createApp();
    const user = await createTestUser();
    const auth = authHeader(user.accessToken);

    const created = await request(app)
      .post('/api/v1/vault/items')
      .set('x-forwarded-for', '203.0.113.10')
      .set('Authorization', auth)
      .send(sampleVaultItem());
    expect(created.status).toBe(201);
    const id = (created.body as { data: { _id: string } }).data._id;

    // A different source address for every request: the budget is the account's.
    const steps = [
      request(app).put(`/api/v1/vault/items/${id}`).send({ favorite: true }),
      request(app).delete(`/api/v1/vault/items/${id}`),
      request(app).post(`/api/v1/vault/items/restore/${id}`),
      request(app).delete(`/api/v1/vault/items/${id}`),
      request(app).delete(`/api/v1/vault/items/${id}/permanent`),
    ];
    for (const [index, step] of steps.entries()) {
      const res = await step
        .set('x-forwarded-for', `203.0.113.${String(11 + index)}`)
        .set('Authorization', auth);
      expect(res.status, `step ${String(index)}`).toBe(200);
    }

    const counted = await counters();
    expect(counted.get(`vaultWrite:${user.id}`)).toBe(6);
    expect([...counted.keys()]).toEqual([`vaultWrite:${user.id}`]);
    // The positive control: these routes really do write the audit rows the
    // budget exists to bound, one per request and nothing else.
    const audited = await AuditLog.find({ userId: user.id }).sort({ timestamp: 1, _id: 1 }).lean();
    expect(audited.map((row) => row.action)).toEqual([
      'item_create',
      'item_update',
      'item_delete',
      'item_restore',
      'item_delete',
      'item_delete',
    ]);
  });

  it('counts every folder mutation against folderWrite:<user>, and never against vaultWrite:', async () => {
    const app = createApp();
    const user = await createTestUser();
    const auth = authHeader(user.accessToken);

    const created = await request(app)
      .post('/api/v1/folders')
      .set('x-forwarded-for', '203.0.113.20')
      .set('Authorization', auth)
      .send(sampleFolder());
    expect(created.status).toBe(201);
    const id = (created.body as { data: { _id: string } }).data._id;

    const renamed = await request(app)
      .put(`/api/v1/folders/${id}`)
      .set('x-forwarded-for', '203.0.113.21')
      .set('Authorization', auth)
      .send({ encryptedName: 'renamed', nameIv: 'iv', nameTag: 'tag' });
    expect(renamed.status).toBe(200);

    const sorted = await request(app)
      .put(`/api/v1/folders/${id}/sort`)
      .set('x-forwarded-for', '203.0.113.22')
      .set('Authorization', auth)
      .send({ sortOrder: 3 });
    expect(sorted.status).toBe(200);

    const deleted = await request(app)
      .delete(`/api/v1/folders/${id}`)
      .set('x-forwarded-for', '203.0.113.23')
      .set('Authorization', auth);
    expect(deleted.status).toBe(200);

    const counted = await counters();
    expect([...counted.entries()]).toEqual([[`folderWrite:${user.id}`, 4]]);
  });

  it('refuses the item mutation past the budget BEFORE the controller runs: no row, no audit entry', async () => {
    const app = createApp();
    const alice = await createTestUser();
    const bob = await createTestUser();
    const sharedIp = '203.0.113.30';
    await seedCounter(`vaultWrite:${alice.id}`, VAULT_ITEM_WRITE_RATE_LIMIT_MAX);

    // A fresh address buys nothing: the counter is the account's.
    const blocked = await request(app)
      .post('/api/v1/vault/items')
      .set('x-forwarded-for', '198.51.100.30')
      .set('Authorization', authHeader(alice.accessToken))
      .send(sampleVaultItem());

    expect(blocked.status).toBe(429);
    expect((blocked.body as { message: string }).message).toBe(
      'Too many vault changes, please try again later',
    );
    expect(blocked.headers['retry-after']).toBeDefined();
    expect(await VaultItem.countDocuments({ userId: alice.id })).toBe(0);
    expect(await AuditLog.countDocuments({ userId: alice.id })).toBe(0);

    // Another account behind the SAME address is untouched by Alice's budget.
    const other = await request(app)
      .post('/api/v1/vault/items')
      .set('x-forwarded-for', sharedIp)
      .set('Authorization', authHeader(bob.accessToken))
      .send(sampleVaultItem());
    expect(other.status).toBe(201);

    // Exhausting the item budget costs Alice nothing anywhere else: her folder
    // writes and her ordinary reads (the `general:` bucket) still answer.
    const folderWrite = await request(app)
      .post('/api/v1/folders')
      .set('x-forwarded-for', sharedIp)
      .set('Authorization', authHeader(alice.accessToken))
      .send(sampleFolder());
    expect(folderWrite.status).toBe(201);
    const folderList = await request(app)
      .get('/api/v1/folders')
      .set('x-forwarded-for', sharedIp)
      .set('Authorization', authHeader(alice.accessToken));
    expect(folderList.status).toBe(200);
  });

  it('refuses the folder mutation past the budget BEFORE the controller runs, and leaves the item budget alone', async () => {
    const app = createApp();
    const user = await createTestUser();
    const auth = authHeader(user.accessToken);
    await seedCounter(`folderWrite:${user.id}`, FOLDER_WRITE_RATE_LIMIT_MAX);

    const blocked = await request(app)
      .post('/api/v1/folders')
      .set('x-forwarded-for', '198.51.100.40')
      .set('Authorization', auth)
      .send(sampleFolder());

    expect(blocked.status).toBe(429);
    expect((blocked.body as { message: string }).message).toBe(
      'Too many folder changes, please try again later',
    );
    expect(await Folder.countDocuments({ userId: user.id })).toBe(0);
    expect(await AuditLog.countDocuments({ userId: user.id })).toBe(0);

    const item = await request(app)
      .post('/api/v1/vault/items')
      .set('x-forwarded-for', '198.51.100.40')
      .set('Authorization', auth)
      .send(sampleVaultItem());
    expect(item.status).toBe(201);
  });

  it('answers one request under the budget, so the ceiling is the budget and not one below it', async () => {
    const app = createApp();
    const user = await createTestUser();
    await seedCounter(`vaultWrite:${user.id}`, VAULT_ITEM_WRITE_RATE_LIMIT_MAX - 1);

    const last = await request(app)
      .post('/api/v1/vault/items')
      .set('x-forwarded-for', '198.51.100.50')
      .set('Authorization', authHeader(user.accessToken))
      .send(sampleVaultItem());
    expect(last.status).toBe(201);

    const next = await request(app)
      .post('/api/v1/vault/items')
      .set('x-forwarded-for', '198.51.100.51')
      .set('Authorization', authHeader(user.accessToken))
      .send(sampleVaultItem());
    expect(next.status).toBe(429);
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(1);
  });
});

describe('heavy operations are budgeted per user, not per address', () => {
  beforeEach(async () => {
    await rateLimits().deleteMany({});
  });

  it('keys the counter on the account, so one account cannot spend another behind the same address', async () => {
    const app = createApp();
    const alice = await createTestUser();
    const bob = await createTestUser();
    const sharedIp = '203.0.113.60';

    const first = await request(app)
      .delete('/api/v1/vault/items/trash/empty')
      .set('x-forwarded-for', sharedIp)
      .set('Authorization', authHeader(alice.accessToken));
    expect(first.status).toBe(200);
    expect([...(await counters()).entries()]).toEqual([[`heavy:${alice.id}`, 1]]);

    await rateLimits().deleteMany({});
    await seedCounter(`heavy:${alice.id}`, HEAVY_OP_RATE_LIMIT_MAX);

    // Rotating the address does not reset Alice's budget…
    const rotated = await request(app)
      .delete('/api/v1/vault/items/trash/empty')
      .set('x-forwarded-for', '198.51.100.61')
      .set('Authorization', authHeader(alice.accessToken));
    expect(rotated.status).toBe(429);

    // …and Alice's exhausted budget is not Bob's, though they share an address.
    const neighbour = await request(app)
      .delete('/api/v1/vault/items/trash/empty')
      .set('x-forwarded-for', sharedIp)
      .set('Authorization', authHeader(bob.accessToken));
    expect(neighbour.status).toBe(200);

    const keys = [...(await counters()).keys()].sort();
    expect(keys).toEqual([`heavy:${alice.id}`, `heavy:${bob.id}`].sort());
    expect(keys).not.toContain(`heavy:${sharedIp}`);
  });
});

describe('2FA setup verification is budgeted per user', () => {
  beforeEach(async () => {
    await rateLimits().deleteMany({});
  });

  it('counts against twoFactorVerify:<user> and never against the address-keyed token: bucket', async () => {
    const app = createApp();
    const user = await createTestUser();

    // No setup is pending, so the controller refuses; the limiter counted first.
    const res = await request(app)
      .post('/api/v1/user/2fa/verify')
      .set('x-forwarded-for', '203.0.113.70')
      .set('Authorization', authHeader(user.accessToken))
      .send({ code: '123456' });
    expect(res.status).toBe(400);

    expect([...(await counters()).entries()]).toEqual([[`twoFactorVerify:${user.id}`, 1]]);
  });

  it('refuses past the budget from any address, and leaves a neighbour on the same address alone', async () => {
    const app = createApp();
    const alice = await createTestUser();
    const bob = await createTestUser();
    const sharedIp = '203.0.113.71';
    await seedCounter(`twoFactorVerify:${alice.id}`, TWO_FACTOR_VERIFY_RATE_LIMIT_MAX);

    const blocked = await request(app)
      .post('/api/v1/user/2fa/verify')
      .set('x-forwarded-for', '198.51.100.71')
      .set('Authorization', authHeader(alice.accessToken))
      .send({ code: '123456' });
    expect(blocked.status).toBe(429);
    expect((blocked.body as { message: string }).message).toBe(
      'Too many verification attempts, please try again later',
    );

    const neighbour = await request(app)
      .post('/api/v1/user/2fa/verify')
      .set('x-forwarded-for', sharedIp)
      .set('Authorization', authHeader(bob.accessToken))
      .send({ code: '123456' });
    // Reaches the controller, which refuses because no setup is pending.
    expect(neighbour.status).toBe(400);
  });
});
