import type { NextFunction, Request, Response } from 'express';
import { httpErrors } from '@hiprax/errors';

/**
 * MongoDB operator injection and prototype-pollution prevention for request bodies
 * AND query strings (a custom middleware: express-mongo-sanitize is incompatible
 * with Express 5).
 *
 * WHERE IT MUST RUN: after everything that BUILDS the values it filters, because a
 * filter judges the keys it is shown and nothing produced later. That is two kinds
 * of mount, and both are required:
 *
 *   1. once at app level, after the global parsers AND after `hppx` (`app.ts`);
 *   2. on every route that brings its OWN parser, straight after it. The global
 *      parser skips those paths (`CUSTOM_BODY_LIMIT_PATHS` in `app.ts`), so the
 *      app-level mount sees an unparsed body there and filters only the query.
 *
 * Why after `hppx`: it is not only a duplicate-collapser. It EXPANDS dotted and
 * bracketed keys into nested objects, in the query (Express 5's own "simple"
 * parser leaves `folderId[$ne]` as one literal key) and in a urlencoded body (whose
 * parser leaves `email.$ne` as one literal key). Those keys start with no `$`, so a
 * filter that ran first passed them, and `hppx` then turned them into
 * `{ folderId: { $ne: … } }` and `{ email: { $ne: … } }` on the way to the
 * routes. An earlier version of this comment said query strings could not carry an
 * operator under Express 5; through `hppx` they could.
 *
 * The second kind of mount was missing once too: both 30 MB routes reached their
 * controllers unfiltered while the comment here claimed every body was covered,
 * and only because both schemas happen to be plain `z.object()` (whose strip mode
 * drops an unknown key) was it not exploitable. `tests/route-table.test.ts` now
 * requires, over the real router stack, that every route-level JSON parser is
 * followed by this middleware and nothing else; `tests/input-filter-order.test.ts`
 * pins the app-level order over the wire.
 *
 * WHAT IT DOES NOT FILTER:
 *
 * - Route params are always plain strings (no nested objects possible).
 * - COOKIES are the one other source, and they are handled elsewhere rather
 *   than here: `cookieParser()` JSON-decodes any `j:`-prefixed value, so
 *   `req.cookies[x]` really can be an object or a number. Nothing reads one
 *   except through `utils/cookies.ts` `readStringCookie`, which yields a value
 *   only when it is a non-empty string, so no cookie ever reaches a query as an
 *   operand. Narrow there, not here — see that file for why.
 *
 * Zod validation on every endpoint catches unexpected shapes downstream as a
 * second line, not the first.
 *
 * `req.query` is a getter-only property in Express 5 (it re-parses the URL on every
 * read), so the filtered copy is installed with `Object.defineProperty`, exactly as
 * `middleware/validate.ts` installs a validated one.
 */

/**
 * The deepest body (or query), in object and array levels, the filter will walk.
 * A request past it is refused with 400. A query never gets near it in practice:
 * `hppx` refuses one past 20 levels first (`middleware/parameterLimits.ts`).
 *
 * The walk is recursive, and an unbounded one overflowed the stack at 10,000 levels
 * — a 20 KB body, well inside every parser limit — which surfaced as a 500. The
 * deepest body any request schema accepts today is six levels (an import:
 * body → operations → inserts[] → item → passwordHistory[] → entry), so 32 leaves
 * wide room for schemas to grow while keeping the recursion trivially shallow.
 */
export const MAX_REQUEST_BODY_DEPTH = 32;

const TOO_DEEP_MESSAGE = 'Request body is nested too deeply';
const QUERY_TOO_DEEP_MESSAGE = 'Request query is nested too deeply';

/** Returned up the walk in place of a value once the bound is passed. */
const TOO_DEEP: unique symbol = Symbol('request body too deep');

/** The keys that are never copied: operator injection and prototype pollution vectors. */
function isForbiddenKey(key: string): boolean {
  return key.startsWith('$') || key === '__proto__' || key === 'constructor' || key === 'prototype';
}

/**
 * A copy of `value` with every forbidden key removed at every depth, or
 * {@link TOO_DEEP}. `depth` is the level `value` sits at, the body itself being 1.
 * The copy is always a fresh plain object or array, so a `__proto__` key on the
 * parsed input can never become a prototype on the output.
 */
function sanitizeValue(value: unknown, depth: number): unknown {
  if (value === null || typeof value !== 'object') return value;
  if (depth > MAX_REQUEST_BODY_DEPTH) return TOO_DEEP;

  if (Array.isArray(value)) {
    const cleanEntries: unknown[] = [];
    for (const entry of value) {
      const cleanEntry = sanitizeValue(entry, depth + 1);
      if (cleanEntry === TOO_DEEP) return TOO_DEEP;
      cleanEntries.push(cleanEntry);
    }
    return cleanEntries;
  }

  const source = value as Record<string, unknown>;
  const clean: Record<string, unknown> = {};
  for (const key of Object.keys(source)) {
    if (isForbiddenKey(key)) continue;
    const cleanEntry = sanitizeValue(source[key], depth + 1);
    if (cleanEntry === TOO_DEEP) return TOO_DEEP;
    clean[key] = cleanEntry;
  }
  return clean;
}

/** Returned in place of a copy when there is nothing to filter. */
const NOTHING_TO_FILTER: unique symbol = Symbol('nothing to filter');

/** The filtered copy of one parsed source, {@link TOO_DEEP}, or {@link NOTHING_TO_FILTER}. */
function sanitizeSource(value: unknown): unknown {
  if (value === null || typeof value !== 'object') return NOTHING_TO_FILTER;
  return sanitizeValue(value, 1);
}

/**
 * Replaces a parsed object or array body, and the parsed query, with their
 * sanitized copies. A request with no parsed body, or a scalar one, keeps it
 * untouched, and likewise for the query. A body or query past
 * {@link MAX_REQUEST_BODY_DEPTH} goes to the error handler as a 400 and BOTH are
 * left as parsed, so nothing downstream ever reads a half-filtered request.
 */
export function sanitizeRequestBody(req: Request, _res: Response, next: NextFunction): void {
  const body = sanitizeSource(req.body);
  if (body === TOO_DEEP) {
    next(httpErrors.badRequest(TOO_DEEP_MESSAGE));
    return;
  }
  const query = sanitizeSource(req.query);
  if (query === TOO_DEEP) {
    next(httpErrors.badRequest(QUERY_TOO_DEEP_MESSAGE));
    return;
  }
  if (body !== NOTHING_TO_FILTER) req.body = body;
  if (query !== NOTHING_TO_FILTER) {
    Object.defineProperty(req, 'query', {
      value: query,
      writable: true,
      configurable: true,
      enumerable: true,
    });
  }
  next();
}
