import type { NextFunction, Request, Response } from 'express';
import { httpErrors } from '@hiprax/errors';

/**
 * MongoDB operator injection and prototype-pollution prevention for request bodies
 * (a custom middleware: express-mongo-sanitize is incompatible with Express 5).
 *
 * WHERE IT MUST RUN: immediately after whatever parsed the body, because before
 * that `req.body` is `undefined` and there is nothing to filter. That is two kinds
 * of mount, and both are required:
 *
 *   1. once at app level, straight after the global 2 MB parser (`app.ts`);
 *   2. on every route that brings its OWN parser, straight after it. The global
 *      parser skips those paths (`CUSTOM_BODY_LIMIT_PATHS` in `app.ts`), so the
 *      app-level mount sees an unparsed body there and filters nothing.
 *
 * The second kind was missing once: both 30 MB routes reached their controllers
 * unfiltered while the comment here claimed every body was covered, and only
 * because both schemas happen to be plain `z.object()` (whose strip mode drops an
 * unknown key) was it not exploitable. `tests/route-table.test.ts` now requires,
 * over the real router stack, that every route-level JSON parser is followed by
 * this middleware and nothing else.
 *
 * WHY ONLY THE BODY:
 *
 * - Route params are always plain strings (no nested objects possible).
 * - Query params CAN contain nested objects via bracket syntax in Express 4
 *   (e.g. ?tags[$ne]=foo), but Express 5's default query parser ("simple")
 *   does NOT parse bracket notation — it treats them as literal characters,
 *   so operator injection via query strings is not possible.
 * - Zod validation on all endpoints catches any unexpected shapes downstream
 *   as a defense-in-depth measure.
 * - COOKIES are the one other source, and they are handled elsewhere rather
 *   than here: `cookieParser()` JSON-decodes any `j:`-prefixed value, so
 *   `req.cookies[x]` really can be an object or a number. Nothing reads one
 *   except through `utils/cookies.ts` `readStringCookie`, which yields a value
 *   only when it is a non-empty string, so no cookie ever reaches a query as an
 *   operand. Narrow there, not here — see that file for why.
 *
 * Additionally, req.query and req.params are read-only getters in Express 5.
 */

/**
 * The deepest body, in object and array levels, the filter will walk. A request
 * past it is refused with 400.
 *
 * The walk is recursive, and an unbounded one overflowed the stack at 10,000 levels
 * — a 20 KB body, well inside every parser limit — which surfaced as a 500. The
 * deepest body any request schema accepts today is six levels (an import:
 * body → operations → inserts[] → item → passwordHistory[] → entry), so 32 leaves
 * wide room for schemas to grow while keeping the recursion trivially shallow.
 */
export const MAX_REQUEST_BODY_DEPTH = 32;

const TOO_DEEP_MESSAGE = 'Request body is nested too deeply';

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

/**
 * Replaces a parsed object or array body with its sanitized copy. A request with no
 * parsed body, or a scalar one, passes through untouched. A body past
 * {@link MAX_REQUEST_BODY_DEPTH} goes to the error handler as a 400 and is left as
 * parsed, so nothing downstream ever reads a half-filtered body.
 */
export function sanitizeRequestBody(req: Request, _res: Response, next: NextFunction): void {
  const body: unknown = req.body;
  if (body === null || typeof body !== 'object') {
    next();
    return;
  }
  const clean = sanitizeValue(body, 1);
  if (clean === TOO_DEEP) {
    next(httpErrors.badRequest(TOO_DEEP_MESSAGE));
    return;
  }
  req.body = clean;
  next();
}
