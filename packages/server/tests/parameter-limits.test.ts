/**
 * `refuseParameterLimitErrors` (F-13): `hppx`'s two limit refusals become 400s and
 * nothing else changes. The limit cases run the REAL `hppx` past its real bounds,
 * so a release that rewords its errors fails here; the pass-through cases use a
 * stand-in that forwards a chosen value, because no real input makes `hppx` fail
 * any other way.
 */
import { describe, expect, it, vi } from 'vitest';
import hppx from 'hppx';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { refuseParameterLimitErrors } from '../src/middleware/parameterLimits.js';

const appHppx = (): RequestHandler =>
  hppx({
    whitelist: ['tags', 'ids'],
    mergeStrategy: 'keepLast',
    sources: ['query', 'body'],
  }) as unknown as RequestHandler;

/** Runs `middleware` once over a request carrying `query`; returns `next`'s mock. */
function runWithQuery(middleware: RequestHandler, query: Record<string, unknown>) {
  const req = { query, headers: {}, path: '/' } as unknown as Request;
  const next = vi.fn();
  void middleware(req, {} as Response, next as unknown as NextFunction);
  return { req, next };
}

/** A stand-in middleware that calls `next` with exactly `args`. */
function forwarding(...args: unknown[]): RequestHandler {
  return (_req, _res, next) => {
    (next as (...a: unknown[]) => void)(...args);
  };
}

describe('refuseParameterLimitErrors over the real hppx', () => {
  it('turns the depth refusal into a 400 naming the nesting', () => {
    const { next } = runWithQuery(refuseParameterLimitErrors(appHppx()), {
      [`a${'[b]'.repeat(21)}`]: '1',
    });

    expect(next).toHaveBeenCalledTimes(1);
    const [error] = next.mock.calls[0] as [{ statusCode?: number; message?: string }];
    expect(error).toBeInstanceOf(Error);
    expect(error.statusCode).toBe(400);
    expect(error.message).toBe('Request parameters are nested too deeply');
  });

  it('turns the key-count refusal into a 400 naming the count', () => {
    const query: Record<string, unknown> = {};
    for (let i = 0; i < 5001; i += 1) query[`k${String(i)}`] = '1';

    const { next } = runWithQuery(refuseParameterLimitErrors(appHppx()), query);

    const [error] = next.mock.calls[0] as [{ statusCode?: number; message?: string }];
    expect(error.statusCode).toBe(400);
    expect(error.message).toBe('Request has too many parameters');
  });

  it('is silent below both bounds: next() with no argument and the query expanded', () => {
    const { req, next } = runWithQuery(refuseParameterLimitErrors(appHppx()), {
      [`a${'[b]'.repeat(20)}`]: '1',
      'tags[]': ['x', 'y'],
    });

    expect(next).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenCalledWith();
    expect((req.query as { tags: unknown }).tags).toEqual(['x', 'y']);
  });

  it('without the wrapper, the same refusal is a bare Error with no status (the 500 it was)', () => {
    const { next } = runWithQuery(appHppx(), { [`a${'[b]'.repeat(21)}`]: '1' });

    const [error] = next.mock.calls[0] as [{ statusCode?: number; message?: string }];
    expect(Object.getPrototypeOf(error)).toBe(Error.prototype);
    expect(error.statusCode).toBeUndefined();
    expect(error.message).toBe('Maximum object depth (20) exceeded');
  });
});

describe('refuseParameterLimitErrors passes everything else through verbatim', () => {
  it.each([
    ['an unrelated Error', new Error('database unavailable')],
    ['a TypeError worded like a limit', new TypeError('Maximum object depth (20) exceeded')],
    ['a RangeError worded like a limit', new RangeError('Maximum key count (5000) exceeded')],
    [
      'a plain Error that only CONTAINS the text',
      new Error('x Maximum object depth (20) exceeded'),
    ],
    ['text AFTER the depth sentence', new Error('Maximum object depth (20) exceeded.')],
    ['text AFTER the key sentence', new Error('Maximum key count (5000) exceeded!')],
    ['text BEFORE the key sentence', new Error('x Maximum key count (5000) exceeded')],
    ['a string', 'Maximum key count (5000) exceeded'],
    ["the router's 'route' signal", 'route'],
    ['null, which Express reads as no error', null],
  ])('%s', (_label, value) => {
    const { next } = runWithQuery(refuseParameterLimitErrors(forwarding(value)), {});

    expect(next).toHaveBeenCalledTimes(1);
    expect(next.mock.calls[0]![0]).toBe(value);
  });

  it('a call with no argument stays a call with no error', () => {
    const { next } = runWithQuery(refuseParameterLimitErrors(forwarding()), {});

    expect(next).toHaveBeenCalledTimes(1);
    expect(next.mock.calls[0]![0]).toBeUndefined();
  });
});
