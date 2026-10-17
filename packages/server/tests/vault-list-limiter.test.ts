/**
 * F-25: the two vault list routes carry their own per-account budget.
 *
 * `GET /vault/items` and `GET /vault/items/trash` had no limiter at all, and a
 * page can carry 200 rows of up to half a megabyte each. They are budgeted by
 * `vaultListLimiter`, derived from the most pages a full vault takes to walk, and
 * deliberately NOT by `generalAuthLimiter`: that is one 60-a-minute bucket shared
 * with logout, so a full vault load would refuse the logout after it.
 *
 * Limiters are no-ops outside production, so the config module is mocked to say
 * production, and the ceiling is reached by SEEDING the counter document, as
 * `mutation-limiters.test.ts` does.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import express from 'express';
import cookieParser from 'cookie-parser';
import request from 'supertest';
import mongoose from 'mongoose';
import { createErrorMiddleware } from '@hiprax/errors';
import { MAX_ITEMS_PER_USER, PAGINATION_DEFAULTS } from '@hvault/shared';

vi.mock('../src/config/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/config/index.js')>();
  return { ...actual, isProduction: true };
});

import vaultRouter from '../src/routes/vault.js';
import authRouter from '../src/routes/auth.js';
import {
  VAULT_LIST_RATE_LIMIT_MAX,
  VAULT_LIST_RATE_LIMIT_WINDOW_MS,
  VAULT_LIST_RELOAD_FACTOR,
} from '../src/middleware/rateLimiter.js';
import { RATE_LIMIT_COLLECTION } from '../src/middleware/rateLimitStore.js';
import { createTestUser, authHeader } from './helpers.js';

function createApp() {
  const app = express();
  app.set('trust proxy', 1);
  app.use(express.json());
  app.use(cookieParser());
  app.use('/api/v1/vault', vaultRouter);
  app.use('/api/v1/auth', authRouter);
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

async function seedCounter(key: string, counter: number): Promise<void> {
  await rateLimits().insertOne({
    _id: key,
    counter,
    expirationDate: new Date(Date.now() + VAULT_LIST_RATE_LIMIT_WINDOW_MS),
  });
}

describe('vaultListLimiter budget', () => {
  it('is the pages a full vault takes to walk at the largest page, times the reload factor', () => {
    const pagesPerFullWalk = Math.ceil(MAX_ITEMS_PER_USER / PAGINATION_DEFAULTS.MAX_LIMIT);
    expect(pagesPerFullWalk).toBe(50);
    expect(VAULT_LIST_RATE_LIMIT_MAX).toBe(pagesPerFullWalk * VAULT_LIST_RELOAD_FACTOR);
    // The client walks the vault (every item page, and the trash) EACH time the vault
    // page mounts, and `/vault` and `/vault/:id` are sibling routes, so opening an
    // item and coming back is a visit. A full vault's visit is at most 51 pages (50
    // of items and the trash's first, since trashed rows count toward the same cap).
    // Ordinary use must never meet the budget: one visit every fifteen seconds, for
    // the whole window. (The first derivation assumed eight reloads a window, on
    // sign-in, unlock, reconnect and bulk actions only; the client's real triggers
    // falsified it: the eighth visit to a full vault was refused and the list emptied.)
    const pagesPerVisit = pagesPerFullWalk + 1;
    const visitsPerWindow = VAULT_LIST_RATE_LIMIT_WINDOW_MS / 15_000;
    expect(visitsPerWindow).toBe(60);
    expect(VAULT_LIST_RATE_LIMIT_MAX).toBeGreaterThanOrEqual(pagesPerVisit * visitsPerWindow);
    // ...and still a bound: not an unlimited stream of 200-row pages (under four a
    // second, sustained, for the largest vault).
    expect(VAULT_LIST_RATE_LIMIT_MAX).toBeLessThanOrEqual(pagesPerVisit * visitsPerWindow * 1.05);
    expect(VAULT_LIST_RATE_LIMIT_WINDOW_MS).toBe(15 * 60 * 1000);
  });
});

describe('the list routes are budgeted per account, apart from logout', () => {
  beforeEach(async () => {
    await rateLimits().deleteMany({});
  });

  it('counts both list routes against vaultList:<user> and nothing else', async () => {
    const app = createApp();
    const user = await createTestUser();
    const auth = authHeader(user.accessToken);

    expect((await request(app).get('/api/v1/vault/items').set('Authorization', auth)).status).toBe(
      200,
    );
    expect(
      (await request(app).get('/api/v1/vault/items/trash').set('Authorization', auth)).status,
    ).toBe(200);

    const counted = await counters();
    expect(counted.get(`vaultList:${user.id}`)).toBe(2);
    expect([...counted.keys()]).toEqual([`vaultList:${user.id}`]);
  });

  it('refuses the page past the budget with 429 while a logout in the same window still succeeds', async () => {
    const app = createApp();
    const user = await createTestUser();
    const auth = authHeader(user.accessToken);
    await seedCounter(`vaultList:${user.id}`, VAULT_LIST_RATE_LIMIT_MAX);

    const refused = await request(app).get('/api/v1/vault/items').set('Authorization', auth);
    expect(refused.status).toBe(429);
    const trash = await request(app).get('/api/v1/vault/items/trash').set('Authorization', auth);
    expect(trash.status).toBe(429);

    const logout = await request(app).post('/api/v1/auth/logout').set('Authorization', auth);
    expect(logout.status).toBe(200);
    // The logout spent its own bucket, not the list's.
    expect((await counters()).get(`general:${user.id}`)).toBe(1);
  });

  it('admits the last page inside the budget', async () => {
    const app = createApp();
    const user = await createTestUser();
    await seedCounter(`vaultList:${user.id}`, VAULT_LIST_RATE_LIMIT_MAX - 1);
    const res = await request(app)
      .get('/api/v1/vault/items')
      .set('Authorization', authHeader(user.accessToken));
    expect(res.status).toBe(200);
  });

  it('keeps one account’s budget off another’s', async () => {
    const app = createApp();
    const spent = await createTestUser();
    const other = await createTestUser();
    await seedCounter(`vaultList:${spent.id}`, VAULT_LIST_RATE_LIMIT_MAX);
    const res = await request(app)
      .get('/api/v1/vault/items')
      .set('Authorization', authHeader(other.accessToken));
    expect(res.status).toBe(200);
  });
});
