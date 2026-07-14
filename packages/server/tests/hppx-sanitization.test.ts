import request from 'supertest';
import { describe, it, expect, beforeEach } from 'vitest';
import { sanitize } from 'hppx';
import app from '../src/app.js';
import { createTestUser, authHeader, getCsrf, seedItem, type TestUser } from './helpers.js';

/**
 * Regression tests for the hppx HTTP Parameter Pollution config used in
 * `app.ts`:
 *
 *   hppx({ whitelist: ['tags', 'ids'], mergeStrategy: 'keepLast', sources: ['query', 'body'] })
 *
 * `checkBodyContentType` is deliberately left at its default (`'urlencoded'`).
 * The app is a JSON API and hppx collapses ANY array value at a processed path
 * via `keepLast`; if JSON bodies were sanitized (`checkBodyContentType: 'any'`),
 * legitimate array fields (items, folders, uris, passwordHistory, ...) would be
 * silently truncated to their last element. The load-bearing test below drives
 * the REAL `app` (not a hand-rolled clone of the config) end-to-end so that a
 * change to the actual `hppx(...)` call in `app.ts` is what makes it fail.
 */

const API = '/api/v1';

describe('hppx sanitize() — library collapse + whitelist semantics (documentation)', () => {
  it('collapses non-whitelisted duplicate keys to the last value (keepLast)', () => {
    const cleaned = sanitize(
      { extra: ['first', 'second'], tags: ['a', 'b'], ids: ['1', '2'] },
      { whitelist: ['tags', 'ids'], mergeStrategy: 'keepLast' },
    );
    expect(cleaned.extra).toBe('second');
  });

  it('preserves arrays for whitelisted keys (tags, ids)', () => {
    const cleaned = sanitize(
      { extra: ['first', 'second'], tags: ['a', 'b'], ids: ['1', '2'] },
      { whitelist: ['tags', 'ids'], mergeStrategy: 'keepLast' },
    );
    expect(cleaned.tags).toEqual(['a', 'b']);
    expect(cleaned.ids).toEqual(['1', '2']);
  });
});

describe('hppx wiring in the REAL app (app.ts)', () => {
  let agent: request.Agent;
  let user: TestUser;

  beforeEach(async () => {
    agent = request.agent(app);
    user = await createTestUser({ emailVerified: true });
  });

  it('does NOT collapse a multi-element JSON array body field (passwordHistory) through the real middleware stack', async () => {
    // Seed a login item, then update it with a TWO-element passwordHistory array
    // in a JSON body. `passwordHistory` is NOT on the hppx whitelist, so if
    // app.ts ever set `checkBodyContentType: 'any'`, hppx's keepLast would collapse
    // the array to its last element — a single object — and Zod's array validator
    // would reject the request with 400. With the default ('urlencoded') the JSON
    // body is left untouched and both elements survive.
    const item = await seedItem(user.id, { itemType: 'login' });
    const { token: csrfToken, cookie: csrfCookie } = await getCsrf(agent);

    const passwordHistory = [
      {
        encryptedPassword: 'old-pass-1',
        iv: 'iv-1',
        tag: 'tag-1',
        changedAt: new Date().toISOString(),
      },
      {
        encryptedPassword: 'old-pass-2',
        iv: 'iv-2',
        tag: 'tag-2',
        changedAt: new Date().toISOString(),
      },
    ];

    const res = await agent
      .put(`${API}/vault/items/${String(item._id)}`)
      .set('Authorization', authHeader(user.accessToken))
      .set('Content-Type', 'application/json')
      .set('Cookie', csrfCookie)
      .set('x-csrf-token', csrfToken)
      .send({ passwordHistory });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    // BOTH entries must survive in order — the whole point of the default config.
    expect(res.body.data.passwordHistory).toHaveLength(2);
    expect(res.body.data.passwordHistory[0].encryptedPassword).toBe('old-pass-1');
    expect(res.body.data.passwordHistory[1].encryptedPassword).toBe('old-pass-2');
  });

  it('preserves a whitelisted multi-element JSON array body field (tags) through the real middleware stack', async () => {
    const item = await seedItem(user.id, { itemType: 'login' });
    const { token: csrfToken, cookie: csrfCookie } = await getCsrf(agent);

    const res = await agent
      .put(`${API}/vault/items/${String(item._id)}`)
      .set('Authorization', authHeader(user.accessToken))
      .set('Content-Type', 'application/json')
      .set('Cookie', csrfCookie)
      .set('x-csrf-token', csrfToken)
      .send({ tags: ['alpha', 'beta', 'gamma'] });

    expect(res.status).toBe(200);
    expect(res.body.data.tags).toEqual(['alpha', 'beta', 'gamma']);
  });
});
