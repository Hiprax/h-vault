import { rateLimit, ipKeyGenerator, type Store } from 'express-rate-limit';
import type { Request, Response, NextFunction } from 'express';
import crypto from 'node:crypto';
import { MongoRateLimitStore } from './rateLimitStore.js';
import { httpErrors } from '@hiprax/errors';
import { createLogger } from '@hiprax/logger';
import { isProduction } from '../config/index.js';
import { REFRESH_COOKIE_NAME } from '../constants/index.js';
import { MAX_ITEMS_PER_USER, HIBP_BATCH_MAX_PREFIXES } from '@hvault/shared';
import { MAX_IP_ADDRESS_LENGTH } from '../utils/controllerHelpers.js';

const logger = createLogger({ moduleName: 'rate-limiter' });

const FIFTEEN_MINUTES_MS = 15 * 60 * 1000;

/**
 * IPv6 subnet prefix length that every IP-keyed rate limiter collapses an IPv6
 * client to before keying.
 *
 * A /64 is the smallest universally-routed IPv6 network (one LAN). Under SLAAC
 * and privacy extensions the low 64 bits are the interface identifier, fully
 * controlled by the end host and trivially rotated, so a raw /128 key lets a
 * single client on a routed allocation (2^64 addresses in a /64) rotate the
 * source address between request batches and land each one in a distinct
 * `auth:<ip>` / `csrf:<ip>` / … bucket — defeating the IP-keyed limiters
 * entirely. Masking to /64 folds an attacker's whole single allocation into ONE
 * bucket. `ipKeyGenerator` returns IPv4 addresses unchanged, so IPv4 keying is
 * unaffected. (express-rate-limit's default is /56; /64 is chosen as the
 * conservative, well-understood single-network boundary that exactly matches
 * the host-bits-are-attacker-controlled threat model.)
 */
const IPV6_RATE_LIMIT_SUBNET = 64;

/**
 * Release any resources held by the rate limiter stores during graceful shutdown.
 *
 * There are none: {@link MongoRateLimitStore} issues its counters over the
 * connection Mongoose already owns, so it opens no client of its own and there is
 * nothing here to close — `mongoose.connection.close()`, which the shutdown
 * sequence already performs, closes the one connection they all share.
 *
 * The function is kept (rather than deleted and unwired from `server.ts`) as the
 * seam where a future store WITH its own connection would be torn down, so the
 * shutdown sequence does not have to be revisited to add one back.
 */
export function closeRateLimitStore(): Promise<void> {
  return Promise.resolve();
}

/**
 * In non-production modes (test + development), return a pass-through middleware
 * so that rate-limiting state never interferes with local development or tests.
 * In production, return `undefined` so the caller falls through to the real
 * rate-limit middleware.
 */
function noopIfNonProduction():
  ((_req: Request, _res: Response, next: NextFunction) => void) | undefined {
  if (!isProduction) return (_req, _res, next) => next();
  return undefined;
}

function createStore(windowMs: number): Store | undefined {
  // In non-production mode, skip the MongoDB store so that tests can use
  // MongoMemoryServer and development is not encumbered by rate limits.
  if (!isProduction) return undefined;

  return new MongoRateLimitStore(windowMs);
}

/**
 * Resolve the best-available client identifier for rate limiting.
 *
 * `req.ip` is Express's normalised IP (honours `trust proxy`). When that is
 * missing, fall back to the raw TCP remote address, which is always populated
 * once the request has reached the handler. Returning `null` signals a
 * catastrophic "no peer identity" state that the rate limiter must refuse —
 * otherwise every unidentified request would collapse into a single shared
 * counter and a single attacker could exhaust the bucket for everyone (F3.2).
 *
 * The resolved IP is first routed through express-rate-limit's
 * {@link ipKeyGenerator} (IPv6 → {@link IPV6_RATE_LIMIT_SUBNET} network prefix;
 * IPv4 and any non-IP string returned unchanged) so an attacker cannot rotate
 * source addresses within a single IPv6 allocation to fragment the IP-keyed
 * limiters — see {@link IPV6_RATE_LIMIT_SUBNET}. The subnet normalization runs
 * BEFORE the length clamp: a valid IPv6 collapses to a short `<network>/64`
 * form, while a spoofed arbitrary-length `X-Forwarded-For` value (never a valid
 * IP) passes through `ipKeyGenerator` untouched and is then clamped.
 *
 * The result is clamped to {@link MAX_IP_ADDRESS_LENGTH} so a `TRUST_PROXY=true`
 * deployment cannot be tricked into fragmenting rate-limit buckets via
 * arbitrary-length `X-Forwarded-For` rotation. Express returns the full
 * attacker-controlled string verbatim from `req.ip`; without the slice each
 * unique value lands in a distinct MongoDB bucket and IP-keyed limiters
 * (`authLimiter`, `csrfLimiter`, `tokenVerifyLimiter`, `heavyOpLimiter`,
 * `healthLimiter`, `metricsLimiter`) degrade to "no rate limit" for the
 * attacker.
 */
function normalizeIp(ip: string): string {
  const keyed = ipKeyGenerator(ip, IPV6_RATE_LIMIT_SUBNET);
  return keyed.length > MAX_IP_ADDRESS_LENGTH ? keyed.slice(0, MAX_IP_ADDRESS_LENGTH) : keyed;
}

export function resolveClientKey(req: Request): string | null {
  if (typeof req.ip === 'string' && req.ip.length > 0) {
    return normalizeIp(req.ip);
  }
  const socketIp = req.socket.remoteAddress;
  if (typeof socketIp === 'string' && socketIp.length > 0) {
    return normalizeIp(socketIp);
  }
  return null;
}

/**
 * Wrap a rate-limit middleware with a pre-flight check that guarantees a
 * client identifier is available before the underlying limiter runs. If both
 * `req.ip` and `req.socket.remoteAddress` are missing — which should never
 * happen in practice but can surface if `trust proxy` is broken, the request
 * arrives over an unusual transport, or middleware strips the socket — reject
 * with 500 `RATE_LIMIT_FAILED` instead of silently merging every anonymous
 * request into a single shared counter.
 *
 * F3.2: this replaces the previous `req.ip ?? '127.0.0.1'` fallback, which
 * let one attacker with a broken `trust proxy` setup exhaust the bucket for
 * every other anonymous request hitting the same limiter.
 */
function withClientKeyGuard(
  limiterName: string,
  limiter: (req: Request, res: Response, next: NextFunction) => void,
): (req: Request, res: Response, next: NextFunction) => void {
  return (req, res, next) => {
    if (resolveClientKey(req) === null) {
      logger.error('Rate limiter could not resolve client identifier', {
        limiter: limiterName,
        path: req.path,
      });
      next(
        httpErrors.internalServerError(
          'RATE_LIMIT_FAILED: unable to identify client for rate limiting. Check TRUST_PROXY configuration.',
        ),
      );
      return;
    }
    limiter(req, res, next);
  };
}

/**
 * Build a prefixed key generator so that each rate limiter gets its own
 * isolated counter in the shared MongoDB collection.
 *
 * The prefix is embedded in the key itself rather than passed to the store as a
 * `prefix` option. Every limiter's counters share one collection, so isolation
 * has to hold no matter what the store does with an option it is free to ignore —
 * and two limiters colliding on a key would silently merge their budgets.
 *
 * F3.2: key resolution is guarded by `withClientKeyGuard` before the limiter
 * ever runs, so `resolveClientKey` is guaranteed to return a non-null string
 * here. The `?? ''` fallback is a TypeScript safety net that should never
 * trigger in practice.
 */
function prefixedKeyGenerator(prefix: string): (req: Request) => string {
  return (req: Request) => `${prefix}${resolveClientKey(req) ?? ''}`;
}

/**
 * Auth rate limiter (login, register, etc.).
 * Allows **10 requests per 15-minute window** per IP address.
 */
const authStore = createStore(FIFTEEN_MINUTES_MS);
export const authLimiter =
  noopIfNonProduction() ??
  withClientKeyGuard(
    'authLimiter',
    rateLimit({
      windowMs: FIFTEEN_MINUTES_MS,
      limit: 10,
      standardHeaders: true,
      legacyHeaders: false,
      validate: { singleCount: false },
      keyGenerator: prefixedKeyGenerator('auth:'),
      ...(authStore ? { store: authStore } : {}),
      handler: (_req, _res, next, options) => {
        logger.warn('Auth rate limit exceeded', {
          windowMs: options.windowMs,
          limit: options.limit,
        });
        next(
          httpErrors.tooManyRequests('Too many authentication attempts, please try again later'),
        );
      },
    }),
  );

/**
 * Read the `email` field from a login request body defensively.
 *
 * In Express 5 (body-parser 2.x), a request with a non-JSON `Content-Type`
 * (e.g. `text/plain`, `multipart/form-data`) or no body at all leaves
 * `req.body === undefined` — body-parser sets `req.body = undefined` and
 * returns early rather than coercing it to `{}`. `accountLimiter` is the
 * first middleware on `POST /login` to touch the body (it runs before
 * `validate`), so an unguarded `(req.body as …).email` would throw a
 * `TypeError` here and surface as a 500 before Zod ever returns a clean 400.
 * The optional chain yields `undefined` for a missing body instead.
 */
function getRequestEmail(req: Request): unknown {
  return (req.body as Record<string, unknown> | undefined)?.email;
}

/**
 * Per-account rate-limit key generator. Keys by lowercased email when present;
 * otherwise falls back to the already-guarded client key (see
 * {@link withClientKeyGuard}). A valid key is always required because
 * express-rate-limit evaluates `skip` and the key generator independently —
 * the `account:no-email:<ip>` form is the safe fallback for the no-email path
 * that {@link skipAccountLimiter} excludes from counting.
 */
export function buildAccountKey(req: Request): string {
  const email = getRequestEmail(req);
  if (typeof email === 'string' && email.length > 0) {
    return `account:email:${email.toLowerCase()}`;
  }
  return `account:no-email:${resolveClientKey(req) ?? ''}`;
}

/**
 * Skip per-account counting for requests with no usable `email`. Such requests
 * are already constrained by the IP-keyed `authLimiter` (which runs before
 * `accountLimiter` on the route), so counting them against the generous
 * per-account limit would only let the no-email path borrow that bucket. When
 * skipped, the request falls through to `validate`, which returns a clean 400.
 */
export function skipAccountLimiter(req: Request): boolean {
  const email = getRequestEmail(req);
  return typeof email !== 'string' || email.length === 0;
}

/**
 * Per-account login rate limiter.
 * Allows **20 login attempts per 15-minute window** per email address.
 */
const accountStore = createStore(FIFTEEN_MINUTES_MS);
export const accountLimiter =
  noopIfNonProduction() ??
  withClientKeyGuard(
    'accountLimiter',
    rateLimit({
      windowMs: FIFTEEN_MINUTES_MS,
      limit: 20,
      standardHeaders: true,
      legacyHeaders: false,
      ...(accountStore ? { store: accountStore } : {}),
      validate: { singleCount: false, keyGeneratorIpFallback: false },
      keyGenerator: buildAccountKey,
      skip: skipAccountLimiter,
      handler: (_req, _res, next, options) => {
        logger.warn('Per-account rate limit exceeded', {
          windowMs: options.windowMs,
          limit: options.limit,
        });
        next(
          httpErrors.tooManyRequests(
            'Too many login attempts for this account, please try again later',
          ),
        );
      },
    }),
  );

/**
 * Token verification rate limiter (email verification, password reset, account unlock).
 * Allows **20 requests per 15-minute window** per IP address.
 *
 * These endpoints are already protected by single-use JWT tokens, so they
 * need less aggressive rate limiting than destructive operations.  A higher
 * limit ensures that legitimate users can always verify their email, even if
 * they refresh the page or click the link multiple times.
 */
const tokenVerifyStore = createStore(FIFTEEN_MINUTES_MS);
export const tokenVerifyLimiter =
  noopIfNonProduction() ??
  withClientKeyGuard(
    'tokenVerifyLimiter',
    rateLimit({
      windowMs: FIFTEEN_MINUTES_MS,
      limit: 20,
      standardHeaders: true,
      legacyHeaders: false,
      validate: { singleCount: false },
      keyGenerator: prefixedKeyGenerator('token:'),
      ...(tokenVerifyStore ? { store: tokenVerifyStore } : {}),
      handler: (_req, _res, next, options) => {
        logger.warn('Token verification rate limit exceeded', {
          windowMs: options.windowMs,
          limit: options.limit,
        });
        next(httpErrors.tooManyRequests('Too many verification attempts, please try again later'));
      },
    }),
  );

/**
 * Password verification rate limiter for authenticated endpoints that accept
 * `authHash` or `password` in the request body (change-password, 2fa/setup,
 * 2fa/disable, regenerate-backup-codes, backup/setup, backup/change-password,
 * backup/restore).
 *
 * Allows **5 requests per 15-minute window** per authenticated user.
 *
 * Keyed by userId (extracted from JWT) rather than IP so that an attacker
 * cannot rotate IPs to bypass the limit.
 */
const passwordVerifyStore = createStore(FIFTEEN_MINUTES_MS);
export const passwordVerifyLimiter =
  noopIfNonProduction() ??
  withClientKeyGuard(
    'passwordVerifyLimiter',
    rateLimit({
      windowMs: FIFTEEN_MINUTES_MS,
      limit: 5,
      standardHeaders: true,
      legacyHeaders: false,
      validate: { singleCount: false },
      keyGenerator: (req: Request) => {
        const userId = req.user?._id ?? resolveClientKey(req) ?? '';
        return `pwverify:${userId}`;
      },
      ...(passwordVerifyStore ? { store: passwordVerifyStore } : {}),
      handler: (_req, _res, next, options) => {
        logger.warn('Password verification rate limit exceeded', {
          windowMs: options.windowMs,
          limit: options.limit,
        });
        next(
          httpErrors.tooManyRequests(
            'Too many password verification attempts, please try again later',
          ),
        );
      },
    }),
  );

/**
 * CSRF token rate limiter.
 * Allows **30 requests per 15-minute window** per IP address.
 *
 * The CSRF token endpoint is lightweight but should still be rate-limited
 * to prevent abuse (e.g., token harvesting).
 */
const csrfStore = createStore(FIFTEEN_MINUTES_MS);
export const csrfLimiter =
  noopIfNonProduction() ??
  withClientKeyGuard(
    'csrfLimiter',
    rateLimit({
      windowMs: FIFTEEN_MINUTES_MS,
      limit: 30,
      standardHeaders: true,
      legacyHeaders: false,
      validate: { singleCount: false },
      keyGenerator: prefixedKeyGenerator('csrf:'),
      ...(csrfStore ? { store: csrfStore } : {}),
      handler: (_req, _res, next, options) => {
        logger.warn('CSRF token rate limit exceeded', {
          windowMs: options.windowMs,
          limit: options.limit,
        });
        next(httpErrors.tooManyRequests('Too many requests, please try again later'));
      },
    }),
  );

/**
 * Breach check rate limiter (HIBP password breach endpoint).
 * Allows **30 requests per 15-minute window** per authenticated user.
 *
 * Keyed by userId (extracted from JWT) rather than IP so that an attacker
 * cannot rotate IPs to bypass the limit.
 */
const breachCheckStore = createStore(FIFTEEN_MINUTES_MS);
export const breachCheckLimiter =
  noopIfNonProduction() ??
  withClientKeyGuard(
    'breachCheckLimiter',
    rateLimit({
      windowMs: FIFTEEN_MINUTES_MS,
      limit: 30,
      standardHeaders: true,
      legacyHeaders: false,
      validate: { singleCount: false },
      keyGenerator: (req: Request) => {
        const userId = req.user?._id ?? resolveClientKey(req) ?? '';
        return `breach:${userId}`;
      },
      ...(breachCheckStore ? { store: breachCheckStore } : {}),
      handler: (_req, _res, next, options) => {
        logger.warn('Breach check rate limit exceeded', {
          windowMs: options.windowMs,
          limit: options.limit,
        });
        next(httpErrors.tooManyRequests('Too many breach check requests, please try again later'));
      },
    }),
  );

/**
 * Batched breach check rate limiter (HIBP password breach batch endpoint).
 *
 * The batch endpoint checks up to {@link HIBP_BATCH_MAX_PREFIXES} prefixes per
 * request, so a full-vault scan of the worst case (an all-distinct vault at
 * {@link MAX_ITEMS_PER_USER}) needs `ceil(MAX_ITEMS_PER_USER /
 * HIBP_BATCH_MAX_PREFIXES)` requests. The budget MUST cover that in a single
 * window, or a legitimate scan would be 429'd partway and the unchecked
 * passwords would be reported as "not checked" — a partial result, never a false
 * "safe". The 3x multiplier leaves room for a few full re-scans (the server's
 * HIBP cache makes re-scans cheap) without becoming an open-ended proxy. Keyed by
 * userId so IP rotation cannot bypass it.
 */
const breachBatchStore = createStore(FIFTEEN_MINUTES_MS);

/**
 * Requests one authenticated user may spend on `/tools/check-password-breach/batch`
 * per window. Exported so it can be checked against the worst-case batch count a
 * full-vault scan implies rather than restated from memory — see
 * `tests/breach-batch-budget.test.ts`, which derives that count from the real
 * shared constants and fails if the two drift apart.
 */
export const BREACH_BATCH_RATE_LIMIT_MAX =
  Math.ceil(MAX_ITEMS_PER_USER / HIBP_BATCH_MAX_PREFIXES) * 3;

/** Window the {@link BREACH_BATCH_RATE_LIMIT_MAX} budget is spent over. */
export const BREACH_BATCH_RATE_LIMIT_WINDOW_MS = FIFTEEN_MINUTES_MS;

export const breachBatchLimiter =
  noopIfNonProduction() ??
  withClientKeyGuard(
    'breachBatchLimiter',
    rateLimit({
      windowMs: BREACH_BATCH_RATE_LIMIT_WINDOW_MS,
      limit: BREACH_BATCH_RATE_LIMIT_MAX,
      standardHeaders: true,
      legacyHeaders: false,
      validate: { singleCount: false },
      keyGenerator: (req: Request) => {
        const userId = req.user?._id ?? resolveClientKey(req) ?? '';
        return `breachBatch:${userId}`;
      },
      ...(breachBatchStore ? { store: breachBatchStore } : {}),
      handler: (_req, _res, next, options) => {
        logger.warn('Breach batch rate limit exceeded', {
          windowMs: options.windowMs,
          limit: options.limit,
        });
        next(httpErrors.tooManyRequests('Too many breach check requests, please try again later'));
      },
    }),
  );

/**
 * Unlock verification rate limiter.
 * Allows **5 requests per 5-minute window** per authenticated user.
 *
 * Keyed by userId (extracted from JWT) to prevent IP-rotation bypass.
 * Stricter than authLimiter since unlock attempts indicate a locked vault
 * where an attacker may be brute-forcing the master password.
 */
const FIVE_MINUTES_MS = 5 * 60 * 1000;
const unlockStore = createStore(FIVE_MINUTES_MS);
export const unlockLimiter =
  noopIfNonProduction() ??
  withClientKeyGuard(
    'unlockLimiter',
    rateLimit({
      windowMs: FIVE_MINUTES_MS,
      limit: 5,
      standardHeaders: true,
      legacyHeaders: false,
      validate: { singleCount: false },
      keyGenerator: (req: Request) => {
        const userId = req.user?._id ?? resolveClientKey(req) ?? '';
        return `unlock:${userId}`;
      },
      ...(unlockStore ? { store: unlockStore } : {}),
      handler: (_req, _res, next, options) => {
        logger.warn('Unlock rate limit exceeded', {
          windowMs: options.windowMs,
          limit: options.limit,
        });
        next(httpErrors.tooManyRequests('Too many unlock attempts, please try again later'));
      },
    }),
  );

/**
 * Refresh token rate limiter.
 * Allows **5 requests per 5-minute window** per refresh-token session.
 *
 * The refresh endpoint is unauthenticated (it issues new access tokens),
 * so we key by IP + user-agent hash + refresh-token hash. Including the
 * refresh-token hash isolates per-session buckets, so multiple users behind
 * the same NAT (corporate VPN, household) running the same pinned browser
 * version each get their own quota — they do not collide on a single
 * 5-req/5-min bucket and exhaust each other's refresh quota.
 *
 * If the refresh cookie is missing (legitimate first-refresh edge case where
 * the browser dropped the cookie, or an outright invalid request), we fall
 * back to the IP+UA key — the controller will reject the missing-cookie case
 * with 401 anyway, and we still want a rate limit for that path.
 */
export function buildRefreshKey(req: Request): string {
  const ip = resolveClientKey(req) ?? '';
  const ua = req.headers['user-agent'] ?? '';
  // djb2 hash to differentiate devices sharing the same IP
  let hash = 5381;
  for (let i = 0; i < ua.length; i++) {
    hash = ((hash << 5) + hash + ua.charCodeAt(i)) | 0;
  }
  const uaHash = (hash >>> 0).toString(36);

  const cookies = req.cookies as Record<string, unknown> | undefined;
  const refreshCookie = cookies?.[REFRESH_COOKIE_NAME];
  if (typeof refreshCookie === 'string' && refreshCookie.length > 0) {
    // SHA-256(refreshToken)[0..16] gives 64 bits of entropy — ample for
    // bucket separation without leaking the token to any rate-limit store.
    const refreshHash = crypto
      .createHash('sha256')
      .update(refreshCookie)
      .digest('hex')
      .slice(0, 16);
    return `refresh:${ip}:${uaHash}:${refreshHash}`;
  }
  return `refresh:${ip}:${uaHash}`;
}

const refreshStore = createStore(FIVE_MINUTES_MS);
export const refreshLimiter =
  noopIfNonProduction() ??
  withClientKeyGuard(
    'refreshLimiter',
    rateLimit({
      windowMs: FIVE_MINUTES_MS,
      limit: 5,
      standardHeaders: true,
      legacyHeaders: false,
      validate: { singleCount: false },
      keyGenerator: buildRefreshKey,
      ...(refreshStore ? { store: refreshStore } : {}),
      handler: (_req, _res, next, options) => {
        logger.warn('Refresh token rate limit exceeded', {
          windowMs: options.windowMs,
          limit: options.limit,
        });
        next(httpErrors.tooManyRequests('Too many token refresh attempts, please try again later'));
      },
    }),
  );

/**
 * General authenticated endpoint rate limiter.
 * Allows **60 requests per 1-minute window** per authenticated user.
 *
 * Applied to read-heavy authenticated endpoints (profile, sessions, audit log,
 * folders list) that could be abused with a compromised JWT.
 */
const ONE_MINUTE_MS = 60 * 1000;
const generalAuthStore = createStore(ONE_MINUTE_MS);
export const generalAuthLimiter =
  noopIfNonProduction() ??
  withClientKeyGuard(
    'generalAuthLimiter',
    rateLimit({
      windowMs: ONE_MINUTE_MS,
      limit: 60,
      standardHeaders: true,
      legacyHeaders: false,
      validate: { singleCount: false },
      keyGenerator: (req: Request) => {
        const userId = req.user?._id ?? resolveClientKey(req) ?? '';
        return `general:${userId}`;
      },
      ...(generalAuthStore ? { store: generalAuthStore } : {}),
      handler: (_req, _res, next, options) => {
        logger.warn('General auth rate limit exceeded', {
          windowMs: options.windowMs,
          limit: options.limit,
        });
        next(httpErrors.tooManyRequests('Too many requests, please try again later'));
      },
    }),
  );

/**
 * Heavy operation rate limiter (empty trash, backup download, etc.).
 * Allows **10 requests per 15-minute window** per IP address.
 *
 * These endpoints can trigger significant database load (unbounded deletes,
 * full data collection), so a tighter limit prevents abuse.
 */
const heavyOpStore = createStore(FIFTEEN_MINUTES_MS);
export const heavyOpLimiter =
  noopIfNonProduction() ??
  withClientKeyGuard(
    'heavyOpLimiter',
    rateLimit({
      windowMs: FIFTEEN_MINUTES_MS,
      limit: 10,
      standardHeaders: true,
      legacyHeaders: false,
      validate: { singleCount: false },
      keyGenerator: prefixedKeyGenerator('heavy:'),
      ...(heavyOpStore ? { store: heavyOpStore } : {}),
      handler: (_req, _res, next, options) => {
        logger.warn('Heavy operation rate limit exceeded', {
          windowMs: options.windowMs,
          limit: options.limit,
        });
        next(httpErrors.tooManyRequests('Too many requests, please try again later'));
      },
    }),
  );

/**
 * Import rate limiter.
 * Allows **60 requests per 15-minute window** per authenticated user.
 *
 * Import is a zero-knowledge bulk operation: the client parses and encrypts every
 * item locally, then sends the encrypted rows in several sequential requests
 * (see the client's `chunkBySize`), so a large migration needs a higher,
 * DEDICATED budget. Sharing `heavyOpLimiter`'s 10-req/IP budget with export /
 * backup / bulk operations would let a multi-batch import stall mid-migration (or
 * a prior export burn a slot). Keyed by userId, not IP, so IP rotation cannot
 * bypass it and a shared IP does not conflate distinct users' imports; per-user
 * data growth stays independently bounded by MAX_ITEMS_PER_USER.
 */
const importStore = createStore(FIFTEEN_MINUTES_MS);

/**
 * Requests one authenticated user may spend on `/tools/import` per window.
 *
 * Exported so the budget can be checked against the worst-case batch count a
 * single migration implies rather than restated from memory — see
 * `tests/import-cap-concurrency.test.ts`, which derives that count from the real
 * shared constants and fails if the two drift apart.
 */
export const IMPORT_RATE_LIMIT_MAX = 60;

/** Window the {@link IMPORT_RATE_LIMIT_MAX} budget is spent over. */
export const IMPORT_RATE_LIMIT_WINDOW_MS = FIFTEEN_MINUTES_MS;

export const importLimiter =
  noopIfNonProduction() ??
  withClientKeyGuard(
    'importLimiter',
    rateLimit({
      windowMs: IMPORT_RATE_LIMIT_WINDOW_MS,
      limit: IMPORT_RATE_LIMIT_MAX,
      standardHeaders: true,
      legacyHeaders: false,
      validate: { singleCount: false },
      keyGenerator: (req: Request) => {
        const userId = req.user?._id ?? resolveClientKey(req) ?? '';
        return `import:${userId}`;
      },
      ...(importStore ? { store: importStore } : {}),
      handler: (_req, _res, next, options) => {
        logger.warn('Import rate limit exceeded', {
          windowMs: options.windowMs,
          limit: options.limit,
        });
        next(httpErrors.tooManyRequests('Too many import requests, please try again later'));
      },
    }),
  );

/**
 * Health check rate limiter.
 * Allows **60 requests per 1-minute window** per IP address.
 *
 * The /health endpoint is unauthenticated and the request logger silences it
 * by default to keep healthcheck noise out of structured logs. Without a
 * limiter, an attacker can flood the endpoint indefinitely with no signal.
 * Successful healthchecks remain quiet (the logger still skips 200s); 429
 * responses fall through the error path and surface abuse loudly.
 *
 * Deliberately NOT `createStore()`. This limiter guards /health and /config —
 * the two endpoints that must still answer while MongoDB is unreachable, and
 * neither of which touches the database (health reads
 * `mongoose.connection.readyState`, an in-process integer; config returns a
 * static number). A MongoDB-backed store made them depend on the very thing
 * they exist to report on: mongoose never clears `connection.db`, so the store
 * issued its upsert against a stale-but-live handle and blocked for the whole
 * `serverSelectionTimeoutMS` (5 s) before rejecting, and express-rate-limit
 * fails closed by default — so an outage turned the designed 503
 * `{ database: 'disconnected' }` into a redacted 500 that BOTH container
 * healthchecks (`timeout: 5s`) killed as a timeout before it was even written.
 * Omitting `store` falls back to express-rate-limit's own MemoryStore, whose
 * increment is a synchronous Map write: no I/O, no stall, the true 503 in
 * milliseconds. The trade is a per-process counter instead of a cluster-shared
 * one — under PM2 the ceiling becomes 60/min/IP *per instance* on two endpoints
 * that perform no I/O and return sub-kilobyte JSON, which is immaterial.
 * `passOnStoreError` is NOT the fix: it fires only after the 5 s rejection, so
 * it removes neither the stall nor the timeout, and it would drop the limit
 * entirely on two unauthenticated endpoints exactly when the database is down.
 */
export const healthLimiter =
  noopIfNonProduction() ??
  withClientKeyGuard(
    'healthLimiter',
    rateLimit({
      windowMs: ONE_MINUTE_MS,
      limit: 60,
      standardHeaders: true,
      legacyHeaders: false,
      validate: { singleCount: false },
      keyGenerator: prefixedKeyGenerator('health:'),
      handler: (_req, _res, next, options) => {
        logger.warn('Health check rate limit exceeded', {
          windowMs: options.windowMs,
          limit: options.limit,
        });
        next(httpErrors.tooManyRequests('Too many requests, please try again later'));
      },
    }),
  );

/**
 * Metrics endpoint rate limiter.
 * Allows **60 requests per 1-minute window** per IP address.
 *
 * The /metrics endpoint is unauthenticated (gated only by a static
 * `x-metrics-token` header) and is only mounted when METRICS_TOKEN is set.
 * Without a limiter an attacker can flood it and make unlimited timing-safe
 * token-guess attempts. Mirrors healthLimiter, but with an isolated `metrics:`
 * counter so health-check traffic and metrics traffic never share a bucket.
 *
 * In-memory for the same reason as {@link healthLimiter}, and the case is
 * stronger here: /metrics is a pure in-process diagnostic (uptime,
 * `process.memoryUsage()`, `mongoose.connection.readyState`) whose entire value
 * during an outage is reporting `database.state: 'disconnected'` — the very
 * field monitoring scrapes to DETECT the outage. Backing it with MongoDB meant
 * a database outage replaced that signal with a redacted 500. Note also that
 * `passOnStoreError` would be especially wrong on this endpoint: bounding
 * timing-safe token-guess attempts is this limiter's whole job, and failing
 * open on any store error would remove that bound. The token comparison runs in
 * the controller AFTER this limiter, so a valid and an invalid token remain
 * indistinguishable here — the in-memory store introduces no new oracle.
 */
export const metricsLimiter =
  noopIfNonProduction() ??
  withClientKeyGuard(
    'metricsLimiter',
    rateLimit({
      windowMs: ONE_MINUTE_MS,
      limit: 60,
      standardHeaders: true,
      legacyHeaders: false,
      validate: { singleCount: false },
      keyGenerator: prefixedKeyGenerator('metrics:'),
      handler: (_req, _res, next, options) => {
        logger.warn('Metrics rate limit exceeded', {
          windowMs: options.windowMs,
          limit: options.limit,
        });
        next(httpErrors.tooManyRequests('Too many requests, please try again later'));
      },
    }),
  );
