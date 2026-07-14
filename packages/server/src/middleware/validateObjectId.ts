import type { Request, Response, NextFunction } from 'express';
import mongoose from 'mongoose';
import { httpErrors } from '@hiprax/errors';

/**
 * Express middleware that validates `req.params[paramName]` is a valid MongoDB ObjectId.
 * Returns 400 Bad Request with a clean message for invalid IDs, preventing Mongoose CastError leaks.
 *
 * @param paramName  The route parameter name to validate (defaults to `'id'`)
 */
export function validateObjectId(paramName = 'id') {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const raw = req.params[paramName];
    const value = Array.isArray(raw) ? raw[0] : raw;
    if (!value || !mongoose.Types.ObjectId.isValid(value)) {
      next(httpErrors.badRequest(`Invalid ${paramName} format`));
      return;
    }
    next();
  };
}
