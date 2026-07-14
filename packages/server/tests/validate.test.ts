import { describe, it, expect } from 'vitest';
import request from 'supertest';
import express from 'express';
import { z } from 'zod';
import { errorMiddleware } from '@hiprax/errors';
import { validate } from '../src/middleware/validate.js';
import app from '../src/app.js';
import { createTestUser, authHeader, sampleVaultItem, getCsrf } from './helpers.js';

/**
 * The `validate` middleware must be resilient to Express 5's getter-only
 * `req.query` and `req.params` properties. These tests lock in that Zod
 * defaults and coercions reach the downstream handler even when the
 * middleware runs before any code that reassigns `req.query`.
 */
describe('validate middleware — query coercion and defaults', () => {
  it('applies Zod defaults to req.query in a minimal isolated app', async () => {
    const testApp = express();
    testApp.use(express.json());

    const schema = z.object({
      page: z.coerce.number().int().min(1).default(1),
      limit: z.coerce.number().int().min(1).default(50),
      name: z.string().default('anonymous'),
    });

    testApp.get('/test', validate(schema, 'query'), (req, res) => {
      // Downstream handler must see the coerced + defaulted values, not raw strings.
      res.status(200).json({ query: req.query });
    });
    testApp.use(errorMiddleware);

    // No query params at all — defaults should apply.
    const res1 = await request(testApp).get('/test');
    expect(res1.status).toBe(200);
    expect(res1.body.query).toEqual({ page: 1, limit: 50, name: 'anonymous' });
    expect(typeof res1.body.query.page).toBe('number');
    expect(typeof res1.body.query.limit).toBe('number');

    // Mixed: explicit page (string in URL), no limit, overridden name.
    const res2 = await request(testApp).get('/test?page=3&name=alice');
    expect(res2.status).toBe(200);
    expect(res2.body.query).toEqual({ page: 3, limit: 50, name: 'alice' });
    expect(typeof res2.body.query.page).toBe('number');
  });

  it('coerces query params to numbers on real /vault/items endpoint (defaults applied)', async () => {
    const user = await createTestUser();

    // GET with NO query params — pagination defaults should kick in.
    const res = await request(app)
      .get('/api/v1/vault/items')
      .set('Authorization', authHeader(user.accessToken))
      .expect(200);

    expect(res.body.success).toBe(true);
    // Defaults from paginationSchema: page=1, limit=50. Both must be numbers.
    expect(res.body.pagination.page).toBe(1);
    expect(res.body.pagination.limit).toBe(50);
    expect(typeof res.body.pagination.page).toBe('number');
    expect(typeof res.body.pagination.limit).toBe('number');
  });

  it('coerces explicit string query params to numbers on /vault/items', async () => {
    const user = await createTestUser();
    const agent = request.agent(app);
    const { token: csrfToken, cookie: csrfCookie } = await getCsrf(agent);

    // Seed a single item so the handler runs its filter/count logic.
    await agent
      .post('/api/v1/vault/items')
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', csrfCookie)
      .set('x-csrf-token', csrfToken)
      .send(sampleVaultItem())
      .expect(201);

    // Explicit page/limit as strings in the URL — z.coerce.number must parse them.
    const res = await request(app)
      .get('/api/v1/vault/items?page=1&limit=10')
      .set('Authorization', authHeader(user.accessToken))
      .expect(200);

    expect(res.body.pagination.page).toBe(1);
    expect(res.body.pagination.limit).toBe(10);
    expect(typeof res.body.pagination.page).toBe('number');
    expect(typeof res.body.pagination.limit).toBe('number');
  });

  it('rejects query params that fail validation with 400', async () => {
    const testApp = express();
    testApp.use(express.json());

    const schema = z.object({
      page: z.coerce.number().int().min(1).default(1),
    });

    testApp.get('/test', validate(schema, 'query'), (_req, res) => {
      res.status(200).json({ ok: true });
    });
    testApp.use(errorMiddleware);

    // page=0 violates .min(1) — should 400.
    const res = await request(testApp).get('/test?page=0');
    expect(res.status).toBe(400);
  });

  it('applies Zod transforms to req.params', async () => {
    const testApp = express();
    testApp.use(express.json());

    const schema = z.object({
      id: z.string().transform((s) => s.toUpperCase()),
    });

    testApp.get('/test/:id', validate(schema, 'params'), (req, res) => {
      res.status(200).json({ params: req.params });
    });
    testApp.use(errorMiddleware);

    const res = await request(testApp).get('/test/abc');
    expect(res.status).toBe(200);
    expect(res.body.params.id).toBe('ABC');
  });
});
