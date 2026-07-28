/**
 * Rate-limit budget isolation on the auth router.
 *
 * ## The bug this file exists to prevent
 *
 * `routes/auth.ts` mounted `authLimiter` on SEVEN endpoints, and every limiter in
 * `middleware/rateLimiter.ts` keys on a single flat `<prefix><ip>` — so
 * `/register`, `/login`, `/login/2fa`, `/forgot-password`, `/resend-verification`
 * **and `/refresh` and `/verify-unlock`** all drew from ONE bucket.
 *
 * The last two are not credential attempts. They are what the application does on
 * its own, constantly: with `JWT_ACCESS_EXPIRY=5m` an idle open tab spends about
 * three of the budget's slots per window just refreshing, and every vault unlock
 * spent two more (a refresh followed by the verify). A handful of ordinary
 * lock-and-unlock cycles therefore drained the budget, and the user's next
 * `POST /auth/login` was refused with 429 **on its first attempt** — locked out of
 * their own password manager until the window rolled over, with nothing they could
 * do about it and no indication why.
 *
 * ## Why nothing caught it
 *
 * Every limiter is a pass-through no-op unless `isProduction` (`rateLimiter.ts`),
 * and the E2E harness pins `NODE_ENV=development`. The existing suites asserted
 * only that a limiter was MOUNTED, never what mounting it cost. So this file
 * forces `isProduction` true and drives the REAL router over HTTP, asserting the
 * property that actually matters and that a mounting check cannot express:
 *
 *   **Spending one budget must not spend another.**
 *
 * It is checked in both directions, because either one alone can be satisfied by
 * accident.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import express from 'express';
import cookieParser from 'cookie-parser';
import request from 'supertest';
import { createErrorMiddleware } from '@hiprax/errors';
import { LOGIN_RATE_LIMIT_MAX_PER_IP } from '@hvault/shared';

/**
 * Force `isProduction` for this file's module graph only, so the router below
 * carries the REAL limiters rather than pass-throughs.
 *
 * `vi.mock` (hoisted, evaluated once) rather than `vi.resetModules()` +
 * `vi.doMock`: resetting the registry re-evaluates `models/User.ts` against the
 * mongoose singleton, which is externalised and therefore NOT reset, and mongoose
 * throws `OverwriteModelError` on the second `mongoose.model('User')`.
 */
vi.mock('../src/config/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/config/index.js')>();
  return { ...actual, isProduction: true };
});

import authRouter from '../src/routes/auth.js';
import { REFRESH_RATE_LIMIT_MAX } from '../src/middleware/rateLimiter.js';
import { RATE_LIMIT_COLLECTION } from '../src/middleware/rateLimitStore.js';
import mongoose from 'mongoose';
import { createTestUser, authHeader } from './helpers.js';

const AUTH_LIMIT = LOGIN_RATE_LIMIT_MAX_PER_IP;

/**
 * The real auth router, with no CSRF middleware.
 *
 * CSRF is applied app-wide in `app.ts` BEFORE the routers, and it would reject
 * every request here with a 403 raised ahead of the route-level limiters — which
 * would make this file prove nothing at all. Omitting it is what lets each request
 * actually reach the limiter under test.
 */
function createAuthApp() {
  const app = express();
  app.set('trust proxy', 1);
  app.use(express.json());
  app.use(cookieParser());
  app.use('/api/v1/auth', authRouter);
  app.use(createErrorMiddleware({ exposeServerErrors: false }));
  return app;
}

/** Counters persist in Mongo across requests; clear them between tests. */
async function clearRateLimits(): Promise<void> {
  await mongoose.connection.db!.collection(RATE_LIMIT_COLLECTION).deleteMany({});
}

/**
 * Spend `count` slots of the per-IP credential budget.
 *
 * A DIFFERENT email each time, deliberately: `accountLimiter` (20 per email) also
 * sits on `/login`, and reusing one address would let it, rather than
 * `authLimiter`, produce the 429 — the test would then pass while proving
 * something else entirely.
 */
async function spendCredentialBudget(
  app: express.Express,
  ip: string,
  count: number,
): Promise<number[]> {
  const statuses: number[] = [];
  for (let i = 0; i < count; i++) {
    const res = await request(app)
      .post('/api/v1/auth/login')
      .set('x-forwarded-for', ip)
      .send({ email: `spender-${String(i)}@example.com`, authHash: 'wrong-hash' });
    statuses.push(res.status);
  }
  return statuses;
}

describe('session maintenance must not spend the credential budget', () => {
  beforeEach(async () => {
    await clearRateLimits();
  });

  it('exhausting the login budget does NOT rate-limit POST /auth/refresh', async () => {
    const app = createAuthApp();
    const ip = '203.0.113.201';

    const statuses = await spendCredentialBudget(app, ip, AUTH_LIMIT + 1);
    expect(statuses[AUTH_LIMIT]).toBe(429);

    // The refresh has no cookie, so the controller answers 401 "Refresh token not
    // provided". That is fine and is the point: what must NOT happen is a 429
    // raised before the controller ever runs.
    const refresh = await request(app).post('/api/v1/auth/refresh').set('x-forwarded-for', ip);
    expect(refresh.status).not.toBe(429);
    expect(refresh.status).toBe(401);
  });

  it('exhausting the login budget does NOT rate-limit POST /auth/verify-unlock', async () => {
    const app = createAuthApp();
    const ip = '203.0.113.202';
    const user = await createTestUser();

    const statuses = await spendCredentialBudget(app, ip, AUTH_LIMIT + 1);
    expect(statuses[AUTH_LIMIT]).toBe(429);

    // A REAL authenticated unlock, with the correct hash: it must succeed. This is
    // the exact moment the shipped bug bit — the user's vault auto-locked, they
    // typed the right master password, and the server refused them.
    const unlock = await request(app)
      .post('/api/v1/auth/verify-unlock')
      .set('x-forwarded-for', ip)
      .set('Authorization', authHeader(user.accessToken))
      .send({ authHash: user.rawPassword });

    expect(unlock.status).not.toBe(429);
    expect(unlock.status).toBe(200);
  });

  it('exhausting the refresh budget does NOT rate-limit POST /auth/login', async () => {
    const app = createAuthApp();
    const ip = '203.0.113.203';
    const ua = 'IsolationProbe/1.0';

    for (let i = 0; i < REFRESH_RATE_LIMIT_MAX; i++) {
      const res = await request(app)
        .post('/api/v1/auth/refresh')
        .set('x-forwarded-for', ip)
        .set('user-agent', ua);
      expect(res.status).toBe(401);
    }
    const blocked = await request(app)
      .post('/api/v1/auth/refresh')
      .set('x-forwarded-for', ip)
      .set('user-agent', ua);
    expect(blocked.status).toBe(429);

    // Same client, same instant: logging in must still be possible.
    const login = await request(app)
      .post('/api/v1/auth/login')
      .set('x-forwarded-for', ip)
      .set('user-agent', ua)
      .send({ email: 'someone@example.com', authHash: 'wrong-hash' });

    expect(login.status).not.toBe(429);
    expect(login.status).toBe(401);
  });

  it('exhausting one user’s unlock budget does NOT rate-limit their login', async () => {
    const app = createAuthApp();
    const ip = '203.0.113.204';
    const user = await createTestUser();

    // `unlockLimiter` is 5 per user per 5 minutes.
    const UNLOCK_LIMIT = 5;
    for (let i = 0; i < UNLOCK_LIMIT; i++) {
      const res = await request(app)
        .post('/api/v1/auth/verify-unlock')
        .set('x-forwarded-for', ip)
        .set('Authorization', authHeader(user.accessToken))
        .send({ authHash: 'definitely-wrong' });
      expect(res.status).toBe(401);
    }
    const blocked = await request(app)
      .post('/api/v1/auth/verify-unlock')
      .set('x-forwarded-for', ip)
      .set('Authorization', authHeader(user.accessToken))
      .send({ authHash: 'definitely-wrong' });
    expect(blocked.status).toBe(429);

    // Logging out and back in is the user's escape hatch from a locked vault they
    // cannot unlock. If the unlock budget could close it, they would have no way
    // back in at all.
    const login = await request(app)
      .post('/api/v1/auth/login')
      .set('x-forwarded-for', ip)
      .send({ email: user.email, authHash: user.rawPassword });

    expect(login.status).not.toBe(429);
    expect(login.status).toBe(200);
  });
});

describe('the buckets the auth router actually writes', () => {
  beforeEach(async () => {
    await clearRateLimits();
  });

  /**
   * Names the invariant structurally as well as behaviourally: a refresh and an
   * unlock must never touch a key any credential endpoint counts against. If a
   * future change re-mounts `authLimiter` on either route, this fails with a
   * message that says exactly what went wrong, rather than as a mysterious 429 in
   * an unrelated test.
   */
  it('neither /refresh nor /verify-unlock writes an auth: counter', async () => {
    const app = createAuthApp();
    const ip = '203.0.113.205';
    const user = await createTestUser();

    await request(app).post('/api/v1/auth/refresh').set('x-forwarded-for', ip);
    await request(app)
      .post('/api/v1/auth/verify-unlock')
      .set('x-forwarded-for', ip)
      .set('Authorization', authHeader(user.accessToken))
      .send({ authHash: user.rawPassword });

    const docs = await mongoose.connection
      .db!.collection(RATE_LIMIT_COLLECTION)
      .find({}, { projection: { _id: 1 } })
      .toArray();
    // The store keys counters by `_id` (see `MongoRateLimitStore.increment`).
    const keys = (docs as unknown as { _id: string }[]).map((d) => d._id);

    expect(keys.some((k) => k.startsWith('auth:'))).toBe(false);
    expect(keys.some((k) => k.startsWith('refresh:'))).toBe(true);
    expect(keys.some((k) => k.startsWith('unlock:'))).toBe(true);
  });

  it('/login does write an auth: counter (the control for the assertion above)', async () => {
    const app = createAuthApp();
    const ip = '203.0.113.206';

    await request(app)
      .post('/api/v1/auth/login')
      .set('x-forwarded-for', ip)
      .send({ email: 'control@example.com', authHash: 'wrong-hash' });

    const docs = await mongoose.connection
      .db!.collection(RATE_LIMIT_COLLECTION)
      .find({}, { projection: { _id: 1 } })
      .toArray();
    // The store keys counters by `_id` (see `MongoRateLimitStore.increment`).
    const keys = (docs as unknown as { _id: string }[]).map((d) => d._id);

    expect(keys).toContain(`auth:${ip}`);
  });
});
