/**
 * `sanitizeRequestBody`, the one Mongo-injection and prototype-pollution filter.
 *
 * It is mounted in two kinds of place: once at app level, behind the global 2 MB
 * parser, and again on each route that brings its own parser, immediately after
 * it. `security-headers.test.ts` proves both kinds of mount over the wire and
 * `route-table.test.ts` proves every route-level JSON parser is followed by it;
 * this file pins what the filter itself does, on the real middleware with nothing
 * faked but the request object it is handed.
 */
import { describe, it, expect, vi } from 'vitest';
import type { NextFunction, Request, Response } from 'express';
import { MAX_REQUEST_BODY_DEPTH, sanitizeRequestBody } from '../src/middleware/sanitizeBody.js';

/** Runs the middleware over one body; returns the body it left and how `next` was called. */
function run(body: unknown): { body: unknown; next: ReturnType<typeof vi.fn> } {
  const req = { body } as Request;
  const next = vi.fn();
  sanitizeRequestBody(req, {} as Response, next as unknown as NextFunction);
  return { body: req.body as unknown, next };
}

/** `depth` levels of `{"a": …}` around a leaf, parsed the way the body parser would. */
function nestedObject(depth: number): unknown {
  return JSON.parse(`${'{"a":'.repeat(depth)}"leaf"${'}'.repeat(depth)}`);
}

describe('sanitizeRequestBody', () => {
  it('strips $-prefixed keys at every depth, including inside arrays', () => {
    const { body, next } = run(
      JSON.parse('{"$gt":1,"a":{"$ne":null,"b":[{"$where":"x","c":1},"$plain"]},"d$e":2}'),
    );

    // A `$` in the MIDDLE of a key is not an operator and survives, as does a string
    // VALUE that starts with `$`: only a key can smuggle an operator into a query.
    expect(body).toStrictEqual({ a: { b: [{ c: 1 }, '$plain'] }, d$e: 2 });
    expect(next).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenCalledWith();
  });

  it('strips __proto__, constructor and prototype keys without polluting any prototype', () => {
    const { body } = run(
      JSON.parse(
        '{"__proto__":{"isAdmin":true},"constructor":{"prototype":{"isAdmin":true}},' +
          '"prototype":{"polluted":true},"nested":{"__proto__":{"isAdmin":true},"keep":true}}',
      ),
    );

    expect(body).toStrictEqual({ nested: { keep: true } });
    expect(Object.hasOwn(body as object, '__proto__')).toBe(false);
    expect(Object.getPrototypeOf(body)).toBe(Object.prototype);
    // A `__proto__` copied by assignment would not show up as a key: it would have
    // become the copy's prototype, which is what these two catch.
    expect(Object.getPrototypeOf((body as { nested: object }).nested)).toBe(Object.prototype);
  });

  it('returns a NEW object and leaves the parsed original untouched', () => {
    const original = JSON.parse('{"$gt":1,"keep":"v"}') as Record<string, unknown>;
    const { body } = run(original);

    expect(body).not.toBe(original);
    expect(original).toStrictEqual({ $gt: 1, keep: 'v' });
  });

  it('keeps every JSON scalar, and arrays at the top level, exactly', () => {
    expect(
      run(JSON.parse('{"s":"x","n":0,"f":1.5,"t":true,"z":false,"nil":null}')).body,
    ).toStrictEqual({ s: 'x', n: 0, f: 1.5, t: true, z: false, nil: null });
    expect(run(JSON.parse('[{"$gt":1,"k":1},[{"$ne":2}],3]')).body).toStrictEqual([
      { k: 1 },
      [{}],
      3,
    ]);
  });

  it('passes a request with no parsed body, or a non-object body, through untouched', () => {
    for (const body of [undefined, null, '', 'text', 0]) {
      const { body: after, next } = run(body);
      expect(after).toBe(body);
      expect(next).toHaveBeenCalledTimes(1);
      expect(next).toHaveBeenCalledWith();
    }
  });

  describe(`the nesting bound (${MAX_REQUEST_BODY_DEPTH} levels)`, () => {
    it('accepts a body exactly at the bound', () => {
      const { body, next } = run(nestedObject(MAX_REQUEST_BODY_DEPTH));

      expect(body).toStrictEqual(nestedObject(MAX_REQUEST_BODY_DEPTH));
      expect(next).toHaveBeenCalledWith();
    });

    it('refuses one level past the bound with a 400, leaving the body unsanitized', () => {
      const deep = nestedObject(MAX_REQUEST_BODY_DEPTH + 1);
      const { body, next } = run(deep);

      expect(next).toHaveBeenCalledTimes(1);
      const [error] = next.mock.calls[0] as [{ statusCode?: number; message?: string }];
      expect(error).toBeInstanceOf(Error);
      expect(error.statusCode).toBe(400);
      expect(error.message).toBe('Request body is nested too deeply');
      // Nothing downstream may read a half-sanitized body: it is left as parsed and
      // the request goes to the error handler instead.
      expect(body).toBe(deep);
    });

    it('counts array levels exactly as it counts object levels', () => {
      const atBound = JSON.parse(
        `${'['.repeat(MAX_REQUEST_BODY_DEPTH)}1${']'.repeat(MAX_REQUEST_BODY_DEPTH)}`,
      ) as unknown;
      const pastBound = JSON.parse(
        `${'['.repeat(MAX_REQUEST_BODY_DEPTH + 1)}1${']'.repeat(MAX_REQUEST_BODY_DEPTH + 1)}`,
      ) as unknown;

      expect(run(atBound).next).toHaveBeenCalledWith();
      const [error] = run(pastBound).next.mock.calls[0] as [{ statusCode?: number }];
      expect(error.statusCode).toBe(400);
    });

    it('refuses a body deep enough to overflow a recursive walk, rather than throwing', () => {
      // 10,000 levels overflowed the stack of the original recursive filter, and a
      // synchronous throw in middleware is a 500. The bound turns it into a 400
      // long before recursion depth matters.
      const { next } = run(nestedObject(10_000));
      const [error] = next.mock.calls[0] as [{ statusCode?: number }];
      expect(error.statusCode).toBe(400);
    });

    it('sits comfortably above the deepest body any request schema accepts', () => {
      // The deepest legitimate body today is an import: body → operations → inserts[]
      // → item → passwordHistory[] → entry, six levels. A bound near that would turn
      // a harmless schema change into refused requests; this is the real shape, one
      // level of each, parsed rather than compared against the constant.
      const importShaped = JSON.parse(
        '{"operations":{"inserts":[{"passwordHistory":[{"iv":"x"}]}]}}',
      ) as unknown;
      const { body, next } = run(importShaped);
      expect(body).toStrictEqual(importShaped);
      expect(next).toHaveBeenCalledWith();
    });
  });

  describe('the query (F-13)', () => {
    /**
     * A request whose `query` is what Express 5 gives it: an accessor on the
     * prototype with no setter, re-parsed on every read, so plain assignment
     * cannot replace it.
     */
    function expressLikeRequest(query: unknown, body?: unknown): Request {
      const proto = {};
      Object.defineProperty(proto, 'query', { get: () => query, configurable: true });
      const req = Object.create(proto) as Request;
      if (body !== undefined) req.body = body;
      return req;
    }

    function runRequest(req: Request): ReturnType<typeof vi.fn> {
      const next = vi.fn();
      sanitizeRequestBody(req, {} as Response, next as unknown as NextFunction);
      return next;
    }

    it('installs a filtered copy of the query over the getter-only original', () => {
      // `hppx` hands the query on with the keys it expanded; this is that shape.
      const parsed = Object.assign(Object.create(null) as Record<string, unknown>, {
        folderId: { $ne: 'x' },
        $where: '1',
        tags: ['a', { $gt: '' }],
        keep: '1',
      });
      const req = expressLikeRequest(parsed);

      const next = runRequest(req);

      expect(next).toHaveBeenCalledTimes(1);
      expect(next).toHaveBeenCalledWith();
      expect(req.query).toStrictEqual({ folderId: {}, tags: ['a', {}], keep: '1' });
      const installed = Object.getOwnPropertyDescriptor(req, 'query');
      expect(installed).toMatchObject({ writable: true, enumerable: true, configurable: true });
      // The parsed original is not edited in place.
      expect(parsed.$where).toBe('1');
    });

    it('filters the body and the query of the same request', () => {
      const req = expressLikeRequest({ $gt: '', q: 'v' }, { $ne: 1, b: 'v' });

      runRequest(req);

      expect(req.body).toStrictEqual({ b: 'v' });
      expect(req.query).toStrictEqual({ q: 'v' });
    });

    it('leaves an absent or scalar query alone, installing nothing', () => {
      for (const query of [undefined, null, 'text']) {
        const req = expressLikeRequest(query);
        const next = runRequest(req);
        expect(next).toHaveBeenCalledWith();
        expect(Object.hasOwn(req, 'query')).toBe(false);
        expect(req.query).toBe(query);
      }
    });

    it('refuses a query past the bound with its own 400, leaving body AND query as parsed', () => {
      const deepQuery = nestedObject(MAX_REQUEST_BODY_DEPTH + 1);
      const body = { $ne: 1, keep: 'v' };
      const req = expressLikeRequest(deepQuery, body);

      const next = runRequest(req);

      expect(next).toHaveBeenCalledTimes(1);
      const [error] = next.mock.calls[0] as [{ statusCode?: number; message?: string }];
      expect(error).toBeInstanceOf(Error);
      expect(error.statusCode).toBe(400);
      expect(error.message).toBe('Request query is nested too deeply');
      // Nothing half-filtered survives: neither source was replaced.
      expect(req.body).toBe(body);
      expect(Object.hasOwn(req, 'query')).toBe(false);
    });

    it('accepts a query exactly at the bound', () => {
      const req = expressLikeRequest(nestedObject(MAX_REQUEST_BODY_DEPTH));

      expect(runRequest(req)).toHaveBeenCalledWith();
      expect(req.query).toStrictEqual(nestedObject(MAX_REQUEST_BODY_DEPTH));
    });

    it('reports a body past the bound as the BODY, and installs no query', () => {
      const req = expressLikeRequest({ $gt: '' }, nestedObject(MAX_REQUEST_BODY_DEPTH + 1));

      const next = runRequest(req);

      const [error] = next.mock.calls[0] as [{ message?: string }];
      expect(error.message).toBe('Request body is nested too deeply');
      expect(Object.hasOwn(req, 'query')).toBe(false);
    });
  });
});
