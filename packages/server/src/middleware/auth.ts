import passport from 'passport';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import type { Algorithm } from 'jsonwebtoken';
import type { Request, Response, NextFunction } from 'express';
import { httpErrors } from '@hiprax/errors';
import { createLogger } from '@hiprax/logger';
import { config } from '../config/index.js';
import { User } from '../models/User.js';

const logger = createLogger({ moduleName: 'auth-middleware' });

/** Shape of the JWT payload after decoding. */
interface JwtPayload {
  userId: string;
  iat: number;
  exp: number;
}

/** The user object attached to `req.user` after successful authentication. */
export interface AuthenticatedUser {
  _id: string;
}

// ── Passport JWT strategy ──────────────────────────────────────────────

const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: config.JWT_ACCESS_SECRET,
  algorithms: ['HS256'] as Algorithm[],
};

passport.use(
  new JwtStrategy(jwtOptions, (payload: JwtPayload, done) => {
    if (!payload.userId || typeof payload.userId !== 'string') {
      done(null, false);
      return;
    }

    if (typeof payload.iat !== 'number') {
      done(null, false);
      return;
    }

    User.findById(payload.userId)
      .select('_id emailVerified passwordChangedAt deletionPending')
      .lean()
      .then((dbUser) => {
        if (!dbUser) {
          done(null, false);
          return;
        }

        if (!dbUser.emailVerified) {
          done(null, false);
          return;
        }

        // Reject any access token belonging to a user whose account is
        // pending cascade-deletion. The refresh handler already enforces
        // this contract, but the JWT itself is valid for 5 minutes after
        // deleteAccount returns 200 — without this check the user could
        // continue to hit any authenticated endpoint until the access
        // token expires (or until cascade-cleanup races them to the
        // database). Mirror the emailVerified rejection style.
        if (dbUser.deletionPending === true) {
          logger.warn('JWT rejected: user is pending deletion', {
            userId: payload.userId,
          });
          done(null, false);
          return;
        }

        // Reject any JWT that was issued at or before the user's password was
        // last changed. This ensures that access tokens become invalid
        // immediately after a password change, rather than remaining usable
        // until their 15-minute expiry window closes. `passwordChangedAt` has
        // a default of new Date(0) for legacy users so it is always present.
        //
        // JWT `iat` has second-level precision while `passwordChangedAt` has
        // millisecond precision. We ceil passwordChangedAt to the next full
        // second so that any token issued in the SAME second as the change
        // is rejected — tokens with iat exactly equal to the ceilinged value
        // are accepted (they were issued strictly AFTER the change). This is
        // strictly-safe: legitimate flows require the user to log in again
        // after a password change, which happens in a later second.
        const tokenIssuedAtSec = payload.iat;
        const passwordChangedAtSec = Math.ceil(dbUser.passwordChangedAt.getTime() / 1000);
        if (tokenIssuedAtSec < passwordChangedAtSec) {
          logger.warn('JWT rejected: issued before password change', {
            userId: payload.userId,
          });
          done(null, false);
          return;
        }

        const user: AuthenticatedUser = { _id: payload.userId };
        done(null, user);
      })
      .catch((err: unknown) => {
        done(err, false);
      });
  }),
);

// ── Helpers ────────────────────────────────────────────────────────────

/**
 * Type guard that narrows an unknown Express `req.user` to `AuthenticatedUser`.
 */
function isAuthenticatedUser(user: unknown): user is AuthenticatedUser {
  return (
    typeof user === 'object' &&
    user !== null &&
    '_id' in user &&
    typeof (user as AuthenticatedUser)._id === 'string'
  );
}

// ── Middleware exports ─────────────────────────────────────────────────

/**
 * Requires a valid JWT in the `Authorization: Bearer <token>` header.
 * On success, attaches the decoded user to `req.user`.
 * On failure, responds with 401 Unauthorized.
 */
export function authenticate(req: Request, res: Response, next: NextFunction): void {
  (
    passport.authenticate(
      'jwt',
      { session: false },
      (err: unknown, user: unknown, info: unknown) => {
        if (err) {
          logger.error('Authentication error', { error: err });
          next(httpErrors.internalServerError('Authentication error'));
          return;
        }

        if (!user || !isAuthenticatedUser(user)) {
          const message =
            info && typeof info === 'object' && 'message' in info
              ? (info as { message: string }).message
              : 'Invalid or expired token';

          next(httpErrors.unauthorized(message));
          return;
        }

        req.user = user;
        next();
      },
    ) as (req: Request, res: Response, next: NextFunction) => void
  )(req, res, next);
}

/**
 * Optionally authenticates the user.
 * If a valid token is present, `req.user` is populated.
 * If no token or an invalid token is provided, the request continues without a user.
 */
export function optionalAuth(req: Request, res: Response, next: NextFunction): void {
  (
    passport.authenticate('jwt', { session: false }, (err: unknown, user: unknown) => {
      if (err) {
        logger.warn('Optional auth encountered an error', { error: err });
        next();
        return;
      }

      if (user && isAuthenticatedUser(user)) {
        req.user = user;
      }

      next();
    }) as (req: Request, res: Response, next: NextFunction) => void
  )(req, res, next);
}
