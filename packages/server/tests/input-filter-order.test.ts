/**
 * F-13: the operator and prototype-pollution filter runs LAST, over the query and
 * the body, and a parameter-limit refusal is the client's error.
 *
 * `hppx` does more than collapse duplicates: it EXPANDS dotted and bracketed keys
 * into nested objects (`folderId[$ne]=x` and `email.$ne=` become
 * `{ folderId: { $ne: 'x' } }` and `{ email: { $ne: '' } }`). Any filter that runs
 * before it judges the flat key, which carries no leading `$`, and lets the
 * operator through. So the filter has to run after the expansion, and over
 * `req.query` as well as `req.body`.
 *
 * Everything here drives the REAL `app`. What the routes are handed is observed by
 * a probe spliced into the real stack immediately in front of the first route, so
 * it sees exactly what every route sees, whatever order the middleware above it is
 * in. The one seam is a pass-through around `hppx` that can be told to fail the
 * next request with an error of the test's choosing; untold, it is the real
 * middleware with the real options.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import app from '../src/app.js';
import { authHeader, createTestUser, getCsrf } from './helpers.js';

const { injected } = vi.hoisted(() => ({ injected: { error: null as unknown } }));

vi.mock('hppx', async (importOriginal) => {
  const actual = await importOriginal<typeof import('hppx')>();
  const factory = (options: Parameters<typeof actual.default>[0]): RequestHandler => {
    const real = actual.default(options) as unknown as RequestHandler;
    return (req, res, next) => {
      if (injected.error !== null) {
        const error = injected.error;
        injected.error = null;
        next(error);
        return;
      }
      void real(req, res, next);
    };
  };
  return { ...actual, default: factory };
});

interface Seen {
  path: string;
  query: unknown;
  body: unknown;
}

const seen: Seen[] = [];

/** Records what a route would be handed. */
function probe(req: Request, _res: Response, next: NextFunction): void {
  seen.push({ path: req.path, query: req.query, body: req.body as unknown });
  next();
}

interface StackLayer {
  handle?: { stack?: unknown };
  route?: unknown;
}

const stack = (app as unknown as { router: { stack: StackLayer[] } }).router.stack;
let probeLayer: StackLayer | undefined;

beforeAll(() => {
  app.use(probe);
  probeLayer = stack.pop();
  const firstRoute = stack.findIndex(
    (layer) => layer.route !== undefined || Array.isArray(layer.handle?.stack),
  );
  expect(firstRoute).toBeGreaterThan(0);
  stack.splice(firstRoute, 0, probeLayer!);
});

afterAll(() => {
  const at = stack.indexOf(probeLayer!);
  if (at >= 0) stack.splice(at, 1);
});

beforeEach(() => {
  seen.length = 0;
  injected.error = null;
});

/** Every key at any depth that could become a Mongo operator or touch a prototype. */
function forbiddenKeysIn(value: unknown, path = ''): string[] {
  if (value === null || typeof value !== 'object') return [];
  const found: string[] = [];
  for (const key of Object.keys(value)) {
    const at = path === '' ? key : `${path}.${key}`;
    if (
      key.startsWith('$') ||
      key === '__proto__' ||
      key === 'constructor' ||
      key === 'prototype'
    ) {
      found.push(at);
    }
    found.push(...forbiddenKeysIn((value as Record<string, unknown>)[key], at));
  }
  return found;
}

/** The one request the probe saw. */
function onlySeen(): Seen {
  expect(seen).toHaveLength(1);
  return seen[0]!;
}

/** `name` followed by `levels` bracketed segments, e.g. `a[b][b]`. */
function bracketed(name: string, levels: number): string {
  return `${name}${'[b]'.repeat(levels)}`;
}

/** `name` followed by `levels` dotted segments, e.g. `a.b.b`. */
function dotted(name: string, levels: number): string {
  return `${name}${'.b'.repeat(levels)}`;
}

describe('F-13: what the routes are handed has no operator key, from the query or the body', () => {
  it('a bracketed operator in the QUERY (`folderId[$ne]=x`) reaches no route', async () => {
    const user = await createTestUser({ emailVerified: true });

    const res = await request(app)
      .get('/api/v1/vault/items?folderId[$ne]=x')
      .set('Authorization', authHeader(user.accessToken));

    const handed = onlySeen();
    expect(forbiddenKeysIn(handed.query)).toEqual([]);
    // The whole query, not a spot check: the operator is gone and the field is left
    // as the empty object validation then refuses.
    expect(handed.query).toStrictEqual({ folderId: {} });
    expect(res.status).toBe(400);
    expect(res.body).toMatchObject({ success: false, statusCode: 400 });
  });

  it('a dotted operator in the QUERY (`folderId.$ne=x`) reaches no route', async () => {
    await request(app).get('/api/v1/health?folderId.$ne=x&keep=1');

    const handed = onlySeen();
    expect(forbiddenKeysIn(handed.query)).toEqual([]);
    expect(handed.query).toStrictEqual({ folderId: {}, keep: '1' });
  });

  it('a top-level operator key in the QUERY (`$where=1`) reaches no route', async () => {
    await request(app).get('/api/v1/health?$where=1&keep=1');

    const handed = onlySeen();
    expect(forbiddenKeysIn(handed.query)).toEqual([]);
    expect(handed.query).toStrictEqual({ keep: '1' });
  });

  it('a prototype key in the QUERY reaches no route and pollutes nothing', async () => {
    await request(app).get('/api/v1/health?constructor[prototype][polluted]=1&keep=1');

    const handed = onlySeen();
    expect(forbiddenKeysIn(handed.query)).toEqual([]);
    expect(handed.query).toStrictEqual({ keep: '1' });
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it('a DOTTED operator in a urlencoded login body (`email.$ne=`) reaches no route', async () => {
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);
    seen.length = 0;

    const res = await agent
      .post('/api/v1/auth/login')
      .set('x-csrf-token', csrf.token)
      .set('Cookie', csrf.cookie)
      .type('form')
      .send('email.$ne=&authHash=guess');

    const handed = onlySeen();
    expect(forbiddenKeysIn(handed.body)).toEqual([]);
    expect(handed.body).toStrictEqual({ email: {}, authHash: 'guess' });
    // Refused by validation: an empty object is not an address, so no account was
    // looked up and no session was issued.
    expect(res.status).toBe(400);
    expect(res.headers['set-cookie'] ?? []).not.toEqual(
      expect.arrayContaining([expect.stringMatching(/^refreshToken=/)]),
    );
  });

  it('a BRACKETED operator in a urlencoded login body (`email[$ne]=`) reaches no route', async () => {
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);
    seen.length = 0;

    const res = await agent
      .post('/api/v1/auth/login')
      .set('x-csrf-token', csrf.token)
      .set('Cookie', csrf.cookie)
      .type('form')
      .send('email[$ne]=&authHash=guess');

    const handed = onlySeen();
    expect(forbiddenKeysIn(handed.body)).toEqual([]);
    expect(handed.body).toStrictEqual({ email: {}, authHash: 'guess' });
    expect(res.status).toBe(400);
  });

  it('keeps a whitelisted repeated query parameter an ARRAY (`tags[]=a&tags[]=b`)', async () => {
    await request(app).get('/api/v1/health?tags[]=a&tags[]=b');
    expect(onlySeen().query).toStrictEqual({ tags: ['a', 'b'] });

    seen.length = 0;
    await request(app).get('/api/v1/health?tags=a&tags=b');
    expect(onlySeen().query).toStrictEqual({ tags: ['a', 'b'] });
  });

  it('still hands a non-whitelisted repeated query parameter on as its LAST value', async () => {
    await request(app).get('/api/v1/health?sortOrder=asc&sortOrder=desc');
    expect(onlySeen().query).toStrictEqual({ sortOrder: 'desc' });
  });

  it('leaves a JSON body to the filter alone: hppx does not touch it, nothing is collapsed', async () => {
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);
    seen.length = 0;

    await agent
      .post('/api/v1/auth/login')
      .set('x-csrf-token', csrf.token)
      .set('Cookie', csrf.cookie)
      .send({ email: { $ne: '' }, authHash: 'guess', probe: ['a', 'b'] });

    expect(onlySeen().body).toStrictEqual({ email: {}, authHash: 'guess', probe: ['a', 'b'] });
  });
});

describe('F-13: a parameter-limit refusal is a 400, and only that', () => {
  const NESTED_TOO_DEEP = {
    success: false,
    statusCode: 400,
    message: 'Request parameters are nested too deeply',
  };

  it('a query nested 25 levels deep in BRACKETS is a 400 that reaches no route', async () => {
    const res = await request(app).get(`/api/v1/health?${bracketed('a', 25)}=1`);

    expect(res.status).toBe(400);
    expect(res.body).toMatchObject(NESTED_TOO_DEEP);
    expect(seen).toEqual([]);
  });

  it('a query nested 25 levels deep in DOTS is a 400 that reaches no route', async () => {
    const res = await request(app).get(`/api/v1/health?${dotted('a', 25)}=1`);

    expect(res.status).toBe(400);
    expect(res.body).toMatchObject(NESTED_TOO_DEEP);
    expect(seen).toEqual([]);
  });

  it('a query nested exactly to the limit (20 levels below the name) is still answered', async () => {
    const res = await request(app).get(`/api/v1/health?${bracketed('a', 20)}=1`);

    expect(res.status).toBe(200);
    expect(seen).toHaveLength(1);
  });

  it('one level past the limit (21 below the name) is the 400', async () => {
    const res = await request(app).get(`/api/v1/health?${bracketed('a', 21)}=1`);

    expect(res.status).toBe(400);
    expect(res.body).toMatchObject(NESTED_TOO_DEEP);
    expect(seen).toEqual([]);
  });

  it('a urlencoded body nested 25 levels deep is a 400 that reaches no route', async () => {
    const res = await request(app)
      .post('/api/v1/auth/login')
      .type('form')
      .send(`${bracketed('a', 25)}=1`);

    expect(res.status).toBe(400);
    expect(res.body).toMatchObject(NESTED_TOO_DEEP);
    expect(seen).toEqual([]);
  });

  it('a urlencoded body with more keys than the limit (5,000) is a 400 that reaches no route', async () => {
    // 1,000 parameters (the parser's own ceiling) of six nested keys each: 6,000.
    const body = Array.from({ length: 1000 }, (_, i) => `p${String(i)}[a][b][c][d][e]=1`).join('&');

    const res = await request(app).post('/api/v1/auth/login').type('form').send(body);

    expect(res.status).toBe(400);
    expect(res.body).toMatchObject({
      success: false,
      statusCode: 400,
      message: 'Request has too many parameters',
    });
    expect(seen).toEqual([]);
  });

  it('an UNRELATED error out of the parameter filter is still a 500', async () => {
    injected.error = new Error('unrelated failure inside the parameter filter');

    const res = await request(app).get('/api/v1/health');

    expect(res.status).toBe(500);
    expect(res.body).toMatchObject({ success: false, statusCode: 500 });
    expect(seen).toEqual([]);
  });

  it('an unrelated error whose text merely RESEMBLES a limit error is still a 500', async () => {
    // A subclass is not what hppx throws for a limit; only a plain Error is mapped.
    injected.error = new TypeError('Maximum object depth (20) exceeded');

    const res = await request(app).get('/api/v1/health');

    expect(res.status).toBe(500);
    expect(seen).toEqual([]);
  });
});
