/**
 * T14 — `POST /auth/login` must tolerate a missing or non-JSON body.
 *
 * In Express 5 (body-parser 2.x) a request with a non-JSON `Content-Type` (e.g.
 * `text/plain`) or no body leaves `req.body === undefined`. This file used to pin
 * the per-account limiter's key and skip helpers (`buildAccountKey`,
 * `skipAccountLimiter`), which were the first code on the route to read the body
 * and had to survive that. F-04 removed the per-account limiter and both helpers
 * with it, so what is pinned now is the property they protected, on the real
 * route with production limiters forced on: such a request is a clean 400 from
 * validation, never a 500, and it leaves no rate-limit key derived from the body.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';

vi.mock('../src/config/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/config/index.js')>();
  return { ...actual, isProduction: true };
});

import express from 'express';
import request from 'supertest';
import mongoose from 'mongoose';
import { createErrorMiddleware } from '@hiprax/errors';
import authRouter from '../src/routes/auth.js';
import { RATE_LIMIT_COLLECTION } from '../src/middleware/rateLimitStore.js';

function createApp() {
  const app = express();
  app.set('trust proxy', 1);
  app.use(express.json());
  app.use('/api/v1/auth', authRouter);
  app.use(createErrorMiddleware({ exposeServerErrors: false }));
  return app;
}

async function storedKeys(): Promise<string[]> {
  const docs = await mongoose.connection
    .db!.collection<{ _id: string }>(RATE_LIMIT_COLLECTION)
    .find({})
    .toArray();
  return docs.map((doc) => doc._id).sort();
}

describe('POST /auth/login with an unusable body (T14)', () => {
  beforeEach(async () => {
    await mongoose.connection.db!.collection(RATE_LIMIT_COLLECTION).deleteMany({});
  });

  it('a bodyless POST is a clean 400, counted only against the address', async () => {
    const res = await request(createApp())
      .post('/api/v1/auth/login')
      .set('x-forwarded-for', '203.0.113.7');

    expect(res.status).toBe(400);
    expect(await storedKeys()).toEqual(['auth:203.0.113.7']);
  });

  it('a text/plain body is a clean 400, and nothing is keyed on its content', async () => {
    const res = await request(createApp())
      .post('/api/v1/auth/login')
      .set('x-forwarded-for', '203.0.113.9')
      .set('Content-Type', 'text/plain')
      .send('email=someone@example.com');

    expect(res.status).toBe(400);
    expect(await storedKeys()).toEqual(['auth:203.0.113.9']);
  });

  it.each([
    ['a number', 12345],
    ['null', null],
    ['a boolean', true],
    ['an empty string', ''],
  ])('an e-mail that is %s is a clean 400, never a 500', async (_label, email) => {
    const res = await request(createApp())
      .post('/api/v1/auth/login')
      .set('x-forwarded-for', '198.51.100.1')
      .send({ email, authHash: 'x' });

    expect(res.status).toBe(400);
    expect((await storedKeys()).every((key) => key.startsWith('auth:'))).toBe(true);
  });
});
