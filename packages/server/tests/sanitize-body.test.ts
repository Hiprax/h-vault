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
});
