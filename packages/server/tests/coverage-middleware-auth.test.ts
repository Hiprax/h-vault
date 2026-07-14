import { describe, it, expect, afterEach, vi } from 'vitest';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import passport from 'passport';
import type { Request, Response, NextFunction } from 'express';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { optionalAuth } from '../src/middleware/auth.js';
import { createTestUser, authHeader, JWT_SECRET } from './helpers.js';

/**
 * Behavioral coverage for the Passport JWT strategy and the `authenticate` /
 * `optionalAuth` middleware (`src/middleware/auth.ts`).
 *
 * Every rejection branch of the strategy is an auth bypass if it regresses, so
 * each one is driven through the REAL Express app (`GET /api/v1/user/profile`
 * is the cheapest authenticated endpoint) and asserted on both the status and
 * the error body — not just the status.
 */

// ── Local token helpers ────────────────────────────────────────────────
// The strategy reads `payload.userId` and `payload.iat` directly, so the tests
// that target those branches must be able to mint payloads the production
// signer would never emit (missing userId, numeric userId, absent iat, an
// explicit iat). `helpers.generateAccessToken` cannot express those.

interface RawJwtPayload {
  userId?: unknown;
  iat?: number;
  exp?: number;
}

/** Signs an arbitrary payload with the real access secret + algorithm. */
function signRaw(payload: RawJwtPayload, opts: jwt.SignOptions = {}): string {
  return jwt.sign(payload as object, JWT_SECRET, { algorithm: 'HS256', ...opts });
}

const nowSec = (): number => Math.floor(Date.now() / 1000);

/** A future expiry so `exp` never interferes with the branch under test. */
const futureExp = (): number => nowSec() + 900;

/** Type-safe stand-in for the `User.findById(...).select(...).lean()` chain. */
function mockFindByIdRejecting(error: Error): void {
  vi.spyOn(User, 'findById').mockReturnValue({
    select: () => ({
      lean: () => Promise.reject(error),
    }),
  } as unknown as ReturnType<typeof User.findById>);
}

afterEach(() => {
  vi.restoreAllMocks();
});

// ═══════════════════════════════════════════════════════════════════════
// Payload-shape rejections (before any DB lookup)
// ═══════════════════════════════════════════════════════════════════════

describe('JWT strategy: payload shape validation', () => {
  it('rejects a correctly-signed token whose payload has no userId', async () => {
    // The signature is valid — only the claim set is wrong. If the guard were
    // dropped, `User.findById(undefined)` would run instead of a clean 401.
    const token = signRaw({ iat: nowSec(), exp: futureExp() });

    const res = await request(app)
      .get('/api/v1/user/profile')
      .set('Authorization', authHeader(token));

    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
    expect(res.body.message).toBe('Invalid or expired token');
  });

  it('rejects a token whose userId is a number rather than a string', async () => {
    const user = await createTestUser();
    // A numeric userId that Mongo could still cast is the dangerous shape: the
    // typeof check is the only thing standing between it and a DB lookup.
    const token = signRaw({ userId: 12345, iat: nowSec(), exp: futureExp() });

    const res = await request(app)
      .get('/api/v1/user/profile')
      .set('Authorization', authHeader(token));

    expect(res.status).toBe(401);
    expect(res.body.message).toBe('Invalid or expired token');

    // Sanity: the same endpoint DOES authenticate a well-formed token, so the
    // 401 above is attributable to the payload shape and nothing else.
    const ok = await request(app)
      .get('/api/v1/user/profile')
      .set('Authorization', authHeader(user.accessToken));
    expect(ok.status).toBe(200);
  });

  it('rejects a token with no iat claim', async () => {
    const user = await createTestUser();
    // `noTimestamp` omits `iat` entirely — without an iat the
    // passwordChangedAt comparison below would silently become `NaN < x` and
    // never reject, so the strategy must refuse the token outright.
    const token = signRaw({ userId: user.id, exp: futureExp() }, { noTimestamp: true });

    const decoded = jwt.decode(token) as Record<string, unknown>;
    expect(decoded['iat']).toBeUndefined();

    const res = await request(app)
      .get('/api/v1/user/profile')
      .set('Authorization', authHeader(token));

    expect(res.status).toBe(401);
    expect(res.body.message).toBe('Invalid or expired token');
  });

  it('surfaces the passport-jwt failure message when no token is supplied', async () => {
    const res = await request(app).get('/api/v1/user/profile');

    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
    expect(res.body.message).toBe('No auth token');
  });

  it('surfaces the passport-jwt failure message for a malformed token', async () => {
    const res = await request(app)
      .get('/api/v1/user/profile')
      .set('Authorization', authHeader('not-a-jwt'));

    expect(res.status).toBe(401);
    expect(res.body.message).toBe('jwt malformed');
  });

  it('rejects a token signed with the wrong secret', async () => {
    const user = await createTestUser();
    const forged = jwt.sign({ userId: user.id }, 'a-different-secret-that-is-32-chars!!', {
      algorithm: 'HS256',
      expiresIn: '15m',
    });

    const res = await request(app)
      .get('/api/v1/user/profile')
      .set('Authorization', authHeader(forged));

    expect(res.status).toBe(401);
    expect(res.body.message).toBe('invalid signature');
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Account-state rejections (after the DB lookup)
// ═══════════════════════════════════════════════════════════════════════

describe('JWT strategy: account state rejections', () => {
  it('rejects a token for a user that no longer exists', async () => {
    const user = await createTestUser();
    await User.deleteOne({ _id: user.id });

    const res = await request(app)
      .get('/api/v1/user/profile')
      .set('Authorization', authHeader(user.accessToken));

    expect(res.status).toBe(401);
    expect(res.body.message).toBe('Invalid or expired token');
  });

  it('rejects a user whose email is not verified', async () => {
    const user = await createTestUser({ emailVerified: false });

    const res = await request(app)
      .get('/api/v1/user/profile')
      .set('Authorization', authHeader(user.accessToken));

    expect(res.status).toBe(401);
    expect(res.body.message).toBe('Invalid or expired token');
  });

  it('rejects a zombie account (deletionPending) whose access token is still live', async () => {
    const user = await createTestUser();

    // Pre-condition: the very same token works right up until the flag is set.
    const before = await request(app)
      .get('/api/v1/user/profile')
      .set('Authorization', authHeader(user.accessToken));
    expect(before.status).toBe(200);

    await User.updateOne({ _id: user.id }, { $set: { deletionPending: true } });

    const after = await request(app)
      .get('/api/v1/user/profile')
      .set('Authorization', authHeader(user.accessToken));

    expect(after.status).toBe(401);
    expect(after.body.message).toBe('Invalid or expired token');

    // The rejection came from the strategy, not from the row having vanished —
    // the cascade cleanup has not run yet.
    const stillThere = await User.findById(user.id).lean();
    expect(stillThere).not.toBeNull();
  });

  it('rejects a zombie account on a vault endpoint too (not just /user)', async () => {
    const user = await createTestUser();
    await User.updateOne({ _id: user.id }, { $set: { deletionPending: true } });

    const res = await request(app)
      .get('/api/v1/vault/items')
      .set('Authorization', authHeader(user.accessToken));

    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// passwordChangedAt vs iat — the ceil-to-second boundary
// ═══════════════════════════════════════════════════════════════════════

describe('JWT strategy: iat vs passwordChangedAt (ceil-to-second boundary)', () => {
  /**
   * `passwordChangedAt` carries millisecond precision; `iat` only seconds. The
   * strategy ceils the former, so a token minted in the SAME second as the
   * change is rejected and only `iat >= ceil(passwordChangedAt)` is admitted.
   * Both sides of that exact boundary are pinned here — an off-by-one in either
   * direction is either a live auth bypass (an old token keeps working after a
   * password change) or an instant logout of a legitimately-fresh token.
   */
  const setup = async (): Promise<{ id: string; changedAtSec: number }> => {
    const user = await createTestUser();
    const changedAtSec = nowSec() - 10;
    // .500 of a second past the whole second → ceil() lands on changedAtSec + 1.
    await User.updateOne(
      { _id: user.id },
      { $set: { passwordChangedAt: new Date(changedAtSec * 1000 + 500) } },
    );
    return { id: user.id, changedAtSec };
  };

  it('ACCEPTS a token whose iat equals ceil(passwordChangedAt)', async () => {
    const { id, changedAtSec } = await setup();
    const token = signRaw({ userId: id, iat: changedAtSec + 1, exp: futureExp() });

    const res = await request(app)
      .get('/api/v1/user/profile')
      .set('Authorization', authHeader(token));

    expect(res.status).toBe(200);
    expect(String(res.body.data._id)).toBe(id);
  });

  it('REJECTS a token whose iat is one second below ceil(passwordChangedAt)', async () => {
    const { id, changedAtSec } = await setup();
    // iat === changedAtSec: issued within the same second as the change (and in
    // fact 500 ms before it), so it must not be honoured.
    const token = signRaw({ userId: id, iat: changedAtSec, exp: futureExp() });

    const res = await request(app)
      .get('/api/v1/user/profile')
      .set('Authorization', authHeader(token));

    expect(res.status).toBe(401);
    expect(res.body.message).toBe('Invalid or expired token');
  });

  it('ACCEPTS a token issued well after the password change', async () => {
    const { id, changedAtSec } = await setup();
    const token = signRaw({ userId: id, iat: changedAtSec + 5, exp: futureExp() });

    const res = await request(app)
      .get('/api/v1/user/profile')
      .set('Authorization', authHeader(token));

    expect(res.status).toBe(200);
    expect(String(res.body.data._id)).toBe(id);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// DB failure path — done(err, false) → 500, never a silent pass-through
// ═══════════════════════════════════════════════════════════════════════

describe('authenticate: database error path', () => {
  it('returns 500 "Authentication error" when the user lookup rejects', async () => {
    const user = await createTestUser();
    mockFindByIdRejecting(new Error('mongo unavailable'));

    const res = await request(app)
      .get('/api/v1/user/profile')
      .set('Authorization', authHeader(user.accessToken));

    // Critically: NOT a 200. A DB outage must fail closed.
    expect(res.status).toBe(500);
    expect(res.body.success).toBe(false);
    expect(res.body.message).toBe('Authentication error');
  });
});

// ═══════════════════════════════════════════════════════════════════════
// isAuthenticatedUser type guard
// ═══════════════════════════════════════════════════════════════════════

describe('authenticate: isAuthenticatedUser type guard', () => {
  interface PassportInternals {
    _strategies: Record<string, passport.Strategy | undefined>;
  }

  it('rejects with 401 when the strategy yields a user without a string _id', async () => {
    const internals = passport as unknown as PassportInternals;
    const realStrategy = internals._strategies['jwt'];
    expect(realStrategy).toBeTruthy();

    // Swap in a strategy that *succeeds* with a structurally invalid user. This
    // is the only way to reach the guard: the real strategy can never emit this
    // shape. The guard is the last line of defence should a future strategy
    // (or a passport upgrade) hand the middleware something unexpected — if it
    // were removed, `req.user` would be the junk object below and the profile
    // controller would happily run with it.
    const bogus = {
      name: 'jwt',
      authenticate(this: { success: (user: unknown) => void }): void {
        this.success({ notAnId: 42 });
      },
    };
    passport.use('jwt', bogus as unknown as passport.Strategy);

    try {
      const res = await request(app)
        .get('/api/v1/user/profile')
        .set('Authorization', authHeader('anything'));

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe('Invalid or expired token');
    } finally {
      if (realStrategy) {
        passport.use('jwt', realStrategy);
      }
    }

    // The real strategy is back: a normal token authenticates again, proving
    // the swap above was scoped and the assertions are not an artifact.
    const user = await createTestUser();
    const ok = await request(app)
      .get('/api/v1/user/profile')
      .set('Authorization', authHeader(user.accessToken));
    expect(ok.status).toBe(200);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// optionalAuth — populates req.user when valid, never blocks otherwise
// ═══════════════════════════════════════════════════════════════════════

describe('optionalAuth middleware', () => {
  interface MaybeAuthedRequest {
    headers: Record<string, string>;
    user?: unknown;
  }

  const run = async (
    headers: Record<string, string>,
  ): Promise<{ req: MaybeAuthedRequest; nextArgs: unknown[] }> => {
    const req: MaybeAuthedRequest = { headers };
    let nextArgs: unknown[] | undefined;
    const done = new Promise<void>((resolve) => {
      const next: NextFunction = (...args: unknown[]) => {
        nextArgs = args;
        resolve();
      };
      optionalAuth(req as unknown as Request, {} as Response, next);
    });
    await done;
    return { req, nextArgs: nextArgs ?? [] };
  };

  it('attaches req.user for a valid token', async () => {
    const user = await createTestUser();

    const { req, nextArgs } = await run({ authorization: `Bearer ${user.accessToken}` });

    expect(nextArgs).toHaveLength(0); // next() with no error
    expect(req.user).toEqual({ _id: user.id });
  });

  it('continues without a user when the token is invalid', async () => {
    const { req, nextArgs } = await run({ authorization: 'Bearer garbage' });

    expect(nextArgs).toHaveLength(0); // continues — must NOT propagate an error
    expect(req.user).toBeUndefined();
  });

  it('continues without a user when no Authorization header is present', async () => {
    const { req, nextArgs } = await run({});

    expect(nextArgs).toHaveLength(0);
    expect(req.user).toBeUndefined();
  });

  it('does not attach a user for a token belonging to an unverified account', async () => {
    const user = await createTestUser({ emailVerified: false });

    const { req, nextArgs } = await run({ authorization: `Bearer ${user.accessToken}` });

    expect(nextArgs).toHaveLength(0);
    expect(req.user).toBeUndefined();
  });

  it('swallows a database error and continues without a user', async () => {
    const user = await createTestUser();
    mockFindByIdRejecting(new Error('mongo unavailable'));

    const { req, nextArgs } = await run({ authorization: `Bearer ${user.accessToken}` });

    // optionalAuth deliberately does NOT surface the error — but it also must
    // not authenticate anyone off the back of it.
    expect(nextArgs).toHaveLength(0);
    expect(req.user).toBeUndefined();
  });
});
