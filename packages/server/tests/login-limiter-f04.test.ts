/**
 * F-04 — no pre-handler budget keyed on the victim's identity can refuse the
 * victim, and no caller-supplied string becomes a rate-limit key.
 *
 * `accountLimiter` counted every `POST /auth/login` naming an e-mail, successful
 * or not, BEFORE the body was validated, and keyed the counter on the raw string.
 * So twenty requests naming `victim@` from anywhere 429'd the owner's CORRECT
 * password from any device for the rest of the window, and a 200,000-character
 * "e-mail" (a 400 from Zod) still wrote a `rateLimits` document with a 200 KB
 * `_id`. Once unproven answers during a lockout are uniform (F-03), the
 * per-account limiter brakes nothing the handler's own lockout does not, so it is
 * removed; the IP-keyed `authLimiter` stays as the pre-handler budget.
 *
 * Limiters are no-ops outside production, so this file turns production on for
 * the rate-limiter module and drives the real auth router against the real
 * MongoDB-backed store (the seeded-counter technique of
 * `mutation-limiters.test.ts`, with real requests where the count is small).
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';

vi.mock('../src/config/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/config/index.js')>();
  return { ...actual, isProduction: true };
});

import express from 'express';
import cookieParser from 'cookie-parser';
import request from 'supertest';
import crypto from 'node:crypto';
import mongoose from 'mongoose';
import { createErrorMiddleware } from '@hiprax/errors';
import { LOGIN_RATE_LIMIT_MAX_PER_IP, MAX_LOGIN_ATTEMPTS } from '@hvault/shared';
import authRouter from '../src/routes/auth.js';
import * as rateLimiters from '../src/middleware/rateLimiter.js';
import { RATE_LIMIT_COLLECTION } from '../src/middleware/rateLimitStore.js';
import { hashToken } from '../src/utils/token.js';
import { createTestUser } from './helpers.js';

const DAY_MS = 24 * 60 * 60 * 1000;

function createApp() {
  const app = express();
  app.set('trust proxy', 1);
  app.use(express.json({ limit: '2mb' }));
  app.use(cookieParser());
  app.use('/api/v1/auth', authRouter);
  app.use(createErrorMiddleware({ exposeServerErrors: false }));
  return app;
}

function rateLimits() {
  return mongoose.connection.db!.collection<{ _id: string; counter: number }>(
    RATE_LIMIT_COLLECTION,
  );
}

async function seedProof(userId: string): Promise<string> {
  const raw = crypto.randomBytes(32).toString('hex');
  await mongoose.connection.collection('device_proofs').insertOne({
    tokenHash: hashToken(raw),
    userId: new mongoose.Types.ObjectId(userId),
    expiresAt: new Date(Date.now() + 30 * DAY_MS),
    failures: 0,
    singleUse: false,
    createdAt: new Date(),
  });
  return raw;
}

function login(
  app: express.Express,
  ip: string,
  body: Record<string, unknown>,
  cookie?: string,
): request.Test {
  const req = request(app).post('/api/v1/auth/login').set('x-forwarded-for', ip);
  if (cookie !== undefined) req.set('Cookie', cookie);
  return req.send(body);
}

describe('F-04 — the victim is never refused by a budget named after it', () => {
  beforeEach(async () => {
    await rateLimits().deleteMany({});
  });

  it(
    'twenty failed logins naming victim@ from one address do not refuse the owner elsewhere: ' +
      'a proven owner signs in, an unproven one gets the uniform 401',
    async () => {
      const app = createApp();
      const victim = await createTestUser({ emailVerified: true });

      for (let i = 0; i < 20; i++) {
        const res = await login(app, '198.51.100.7', {
          email: victim.email,
          authHash: `stranger-${i}`,
        });
        expect(res.status).toBe(401);
      }

      const proof = await seedProof(victim.id);
      const proven = await login(
        app,
        '203.0.113.20',
        { email: victim.email, authHash: victim.rawPassword },
        `__hv_device=${proof}`,
      );
      expect(proven.status).toBe(200);
      expect(proven.body.data.accessToken).toEqual(expect.any(String));

      const unproven = await login(app, '203.0.113.21', {
        email: victim.email,
        authHash: victim.rawPassword,
      });
      expect(unproven.status).toBe(401);
      expect(unproven.body.message).toBe('Invalid email or password');

      // No counter anywhere is keyed on the e-mail.
      const keys = (await rateLimits().find({}).toArray()).map((doc) => doc._id);
      expect(keys.some((key) => key.includes(victim.email))).toBe(false);
      expect(keys.some((key) => key.startsWith('account:'))).toBe(false);
    },
    60_000,
  );

  it('a one-megabyte e-mail is a 400 and leaves no over-long rate-limit key behind', async () => {
    const app = createApp();
    const huge = `${'a'.repeat(1_000_000)}@example.com`;

    const res = await login(app, '198.51.100.8', { email: huge, authHash: 'x' });
    expect(res.status).toBe(400);

    const docs = await rateLimits().find({}).toArray();
    expect(docs.length).toBeGreaterThan(0);
    for (const doc of docs) {
      expect(doc._id.length).toBeLessThan(100);
    }
  });

  it('the IP-keyed budget still holds: 25 failed logins from one address end in 429', async () => {
    const app = createApp();
    const user = await createTestUser({ emailVerified: true });
    const statuses: number[] = [];
    for (let i = 0; i < 25; i++) {
      const res = await login(app, '198.51.100.9', { email: user.email, authHash: `g-${i}` });
      statuses.push(res.status);
    }
    expect(statuses.slice(0, LOGIN_RATE_LIMIT_MAX_PER_IP).every((s) => s === 401)).toBe(true);
    expect(statuses.slice(LOGIN_RATE_LIMIT_MAX_PER_IP).every((s) => s === 429)).toBe(true);
    // The handler never saw the refused ones: the account's counter is at the cap
    // the first twenty reached, and no further.
    const stored = await mongoose.connection
      .collection('users')
      .findOne({ _id: new mongoose.Types.ObjectId(user.id) });
    expect(stored!['failedLoginAttempts']).toBe(MAX_LOGIN_ATTEMPTS);
  }, 60_000);

  it('the rate-limiter module no longer exports a per-account limiter or its key builder', () => {
    const exported = Object.keys(rateLimiters);
    expect(exported).not.toContain('accountLimiter');
    expect(exported).not.toContain('buildAccountKey');
    expect(exported).not.toContain('skipAccountLimiter');
    expect(exported).toContain('authLimiter');
  });
});
