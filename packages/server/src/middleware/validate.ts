import type { Request, Response, NextFunction } from 'express';
import type { z } from 'zod';
import { httpErrors } from '@hiprax/errors';

/** Allowed request properties to validate. */
type RequestLocation = 'body' | 'query' | 'params';

/**
 * Creates an Express middleware that validates `req[location]` against the
 * provided Zod schema. On success the parsed (and potentially transformed)
 * data replaces the original value on the request. On failure a 400 Bad
 * Request error is forwarded to the Express error handler.
 *
 * @param schema  A Zod schema (object, effect, etc.)
 * @param location  Which part of the request to validate (defaults to `'body'`)
 */
export function validate(schema: z.ZodType, location: RequestLocation = 'body') {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const result = schema.safeParse(req[location]);

    if (!result.success) {
      const issues = result.error.issues.map((issue) => ({
        path: issue.path.join('.'),
        message: issue.message,
      }));

      const message = issues
        .map((i) => (i.path ? `${i.path}: ${i.message}` : i.message))
        .join('; ');

      next(httpErrors.badRequest(message));
      return;
    }

    // Replace the raw data with the parsed + transformed data.
    //
    // Express 5 defines `req.query` and `req.params` as getter-only properties,
    // so a plain assignment via bracket notation would throw (or silently fail)
    // unless upstream middleware (e.g. `hppx`) has already redefined them as
    // writable. Use `Object.defineProperty` for `query` and `params` to override
    // the getter defensively — this decouples us from middleware ordering and
    // guarantees Zod-coerced values (defaults, `z.coerce.number()`, etc.) are
    // visible to downstream handlers.
    if (location === 'query' || location === 'params') {
      Object.defineProperty(req, location, {
        value: result.data,
        writable: true,
        configurable: true,
        enumerable: true,
      });
    } else {
      (req as unknown as Record<string, unknown>)[location] = result.data;
    }
    next();
  };
}
