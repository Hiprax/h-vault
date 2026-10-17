import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { httpErrors } from '@hiprax/errors';

/**
 * Turns `hppx`'s parameter-limit refusals into the 400 they are.
 *
 * `hppx` bounds what it will expand and walk (20 levels, 5,000 keys), and past
 * either bound it THROWS a plain `Error` and hands it to `next`. Nothing on that
 * error says it is the client's fault, so the error handler answered a malformed
 * query string (`?a[b][b]…`, twenty-one levels deep) with a 500. A limit refusal is
 * a request the server declines to read, which is a 400; every other error that
 * comes out of the middleware is a real failure and passes through untouched.
 *
 * The limit errors are recognised by their exact text, because that is all `hppx`
 * gives them (0.4.0: `dist/index.mjs` builds them at `:119`, `:196`, `:213`, `:383`
 * and `:388`, and forwards them from its one `catch` at `:676-686`). Only a PLAIN
 * `Error` carrying one of those two sentences is mapped. If a later release
 * rewords them, the end-to-end tests in `tests/input-filter-order.test.ts` drive
 * the real middleware past both bounds and fail.
 *
 * An over-long array is not among them: `hppx` truncates it to 1,000 elements
 * rather than refusing it.
 */
const LIMIT_REFUSALS: readonly { pattern: RegExp; message: string }[] = [
  {
    pattern: /^Maximum object depth \(\d+\) exceeded$/,
    message: 'Request parameters are nested too deeply',
  },
  {
    pattern: /^Maximum key count \(\d+\) exceeded$/,
    message: 'Request has too many parameters',
  },
];

/** The 400 sentence for an `hppx` limit refusal, or `null` for any other error. */
function limitRefusalMessage(error: unknown): string | null {
  if (!(error instanceof Error) || Object.getPrototypeOf(error) !== Error.prototype) return null;
  const refusal = LIMIT_REFUSALS.find(({ pattern }) => pattern.test(error.message));
  return refusal?.message ?? null;
}

/**
 * `middleware` with its parameter-limit refusals answered as 400s. Every other
 * call of `next`, with or without an argument, is forwarded exactly as made.
 */
export function refuseParameterLimitErrors(middleware: RequestHandler): RequestHandler {
  return function parameterLimits(req: Request, res: Response, next: NextFunction): void {
    const forward = (error?: unknown): void => {
      if (error === undefined) {
        next();
        return;
      }
      const message = limitRefusalMessage(error);
      if (message !== null) {
        next(httpErrors.badRequest(message));
        return;
      }
      next(error as Parameters<NextFunction>[0]);
    };
    void middleware(req, res, forward);
  };
}
