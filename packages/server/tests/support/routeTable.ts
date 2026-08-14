/**
 * The HTTP surface, as data.
 *
 * Every route this server mounts is classified here exactly once: its method
 * and mounted path, whether it takes an id the caller must OWN, whether it sits
 * behind `authenticate`, whether CSRF applies, and which rate limiters it
 * carries. Two suites consume it:
 *
 *   * `tests/route-table.test.ts` proves the table and the real Express router
 *     stack describe the same surface, in BOTH directions. A route added to
 *     `src/routes/*.ts` — or to `src/app.ts` — fails that suite until it is
 *     classified here, which is the whole point: the previous cross-user
 *     coverage was written per endpoint by hand, so a route added tomorrow got
 *     no IDOR check at all and nothing said so.
 *   * `tests/authz-matrix.test.ts` drives one cross-user matrix per row.
 *
 * ---------------------------------------------------------------------------
 * WHY THE STACK IS READ THE WAY IT IS
 * ---------------------------------------------------------------------------
 *
 * Express 5's `Layer` keeps no copy of the path it was mounted at: the mount
 * lives inside a path-to-regexp matcher closure (`layer.matchers`). So a mount
 * prefix cannot be extracted — but it CAN be interrogated, which is what
 * {@link collectAppRoutes} does. It probes each mounted router with every
 * prefix in {@link ROUTER_MOUNTS} and accepts the one whose match consumes
 * exactly that prefix. That distinction is load-bearing: `healthRoutes` and
 * `configRoutes` are mounted at `/api/v1`, so their matchers also match
 * `/api/v1/auth/...` — but with `match.path === '/api/v1'`, never
 * `'/api/v1/auth'`. Requiring the matched span to equal the candidate is what
 * keeps each router bound to its own mount.
 *
 * A mounted router that matches NO declared prefix is reported rather than
 * skipped ({@link CollectedRoutes.unknownMounts}), so moving a router to a new
 * prefix, or mounting a new one, fails the suite instead of quietly leaving its
 * routes unclassified.
 *
 * The limiter column is verified by FUNCTION IDENTITY, not by name or by
 * reading the source: `rateLimiter.ts` returns a distinct pass-through closure
 * per export outside production, so each limiter is still its own object under
 * test and `LIMITER_NAMES` can name it. That is what turns this column from a
 * comment into a check — the shipped defect it guards against (the credential
 * limiter mounted on `/auth/refresh`, so ordinary session maintenance drained
 * the login budget) is invisible to any test that only exercises the endpoint.
 *
 * Middleware mounted at a PATH rather than at the root is reported too, against
 * {@link MIDDLEWARE_MOUNTS}. `app.use('/api/docs', swaggerUi.serve, …)` is the
 * one such mount today and is allowlisted there (it serves the Swagger UI and
 * is covered by `swagger.test.ts`). Without that check, `app.use('/api/v1/x',
 * someHandler)` would be neither a route nor a router and would answer requests
 * while being invisible to every assertion here.
 */
import type { Express } from 'express';
import * as rateLimiters from '../../src/middleware/rateLimiter.js';

export type HttpMethod = 'get' | 'post' | 'put' | 'delete';

/**
 * The resource a route's `:id` names. `authz-matrix.test.ts` maps each one to a
 * seeding scenario, and a row naming a resource with no scenario fails there.
 */
export type OwnedResource =
  'vaultItem' | 'trashedVaultItem' | 'folder' | 'session' | 'trustedDevice';

/**
 * When a route is mounted at all.
 *
 * `always` and `nonProduction` are present under test; the other two are not,
 * and `route-table.test.ts` asserts their ABSENCE. That absence is a real
 * check, not bookkeeping: `/api/v1/metrics` is registered only inside
 * `if (config.METRICS_TOKEN)`, and dropping that guard would publish an
 * unauthenticated metrics endpoint — which would show up here as a route the
 * table says should not exist.
 */
type Registration = 'always' | 'nonProduction' | 'metricsToken' | 'production';

export interface RouteRow {
  readonly method: HttpMethod;
  /** The full mounted path, exactly as Express declares it — `:id`, not a value. */
  readonly path: string;
  /** `required` means the route sits behind `authenticate` and 401s without a bearer token. */
  readonly auth: 'required' | 'none';
  /** `required` means `doubleCsrfProtection` rejects the request without `x-csrf-token`. */
  readonly csrf: 'required' | 'exempt';
  /** Rate limiters mounted on this route, in the order they run. */
  readonly limiters: readonly string[];
  /** Non-null when the path carries an id whose owner the server must check. */
  readonly owned: { readonly param: string; readonly resource: OwnedResource } | null;
  readonly when: Registration;
  /** Why a row is not `always`, or anything else a reader needs. */
  readonly note?: string;
}

/** Every prefix a router is mounted at in `src/app.ts`. */
export const ROUTER_MOUNTS = [
  '/api/v1/auth',
  '/api/v1/vault',
  '/api/v1/folders',
  '/api/v1/user',
  '/api/v1/tools',
  '/api/v1/backup',
  // Last: `healthRoutes` and `configRoutes` mount here, and a longer prefix
  // must be preferred when both would match. `collectAppRoutes` requires the
  // matched span to equal the candidate, so order is not load-bearing — but
  // leaving the broadest one at the end keeps that obvious to a reader.
  '/api/v1',
] as const;

/**
 * Prefixes where `app.ts` mounts MIDDLEWARE rather than a router.
 *
 * An allowlist, not a description: anything path-scoped that is not one of
 * these is reported as unclassified, because a plain handler mounted under
 * `/api/v1/...` answers requests without ever appearing as a route.
 */
const MIDDLEWARE_MOUNTS = ['/api/docs'] as const;

/**
 * The surface. Grouped by router, in mount order, and within a router in the
 * order the routes are declared — so a diff against `src/routes/*.ts` reads
 * straight down.
 */
export const ROUTE_TABLE: readonly RouteRow[] = [
  // ── app.ts, mounted directly ──────────────────────────────────────────
  {
    method: 'get',
    path: '/api/v1/csrf-token',
    auth: 'none',
    csrf: 'exempt',
    limiters: ['csrfLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'get',
    path: '/api/v1/docs.json',
    auth: 'none',
    csrf: 'exempt',
    limiters: [],
    owned: null,
    when: 'nonProduction',
    note: 'Mounted when NODE_ENV !== production or ENABLE_SWAGGER is set. The docs are unauthenticated.',
  },
  {
    method: 'get',
    path: '/api/v1/metrics',
    auth: 'none',
    csrf: 'exempt',
    limiters: ['metricsLimiter'],
    owned: null,
    when: 'metricsToken',
    note: 'Registered only when METRICS_TOKEN is set; the handler then requires a matching x-metrics-token. Unset, the endpoint must not exist at all.',
  },
  {
    method: 'get',
    // `String(/^(?!\/api\/).*/)` — the SPA catch-all, which serves index.html
    // with a per-request CSP nonce. Registered only in production.
    path: '/^(?!\\/api\\/).*/',
    auth: 'none',
    csrf: 'exempt',
    limiters: [],
    owned: null,
    when: 'production',
    note: 'Static SPA fallback; excludes /api/ by construction. Mounted only when NODE_ENV === production.',
  },

  // ── /api/v1/auth ──────────────────────────────────────────────────────
  {
    method: 'post',
    path: '/api/v1/auth/register',
    auth: 'none',
    csrf: 'required',
    limiters: ['authLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'post',
    path: '/api/v1/auth/login',
    auth: 'none',
    csrf: 'required',
    limiters: ['authLimiter', 'accountLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'post',
    path: '/api/v1/auth/login/2fa',
    auth: 'none',
    csrf: 'required',
    limiters: ['authLimiter', 'tokenVerifyLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'post',
    path: '/api/v1/auth/refresh',
    auth: 'none',
    csrf: 'required',
    // `refreshLimiter` ALONE, keyed by IP. Mounting `authLimiter` here is the
    // defect `auth-limiter-isolation.test.ts` exists to prevent, and this row
    // is what states the intended shape as data.
    limiters: ['refreshLimiter'],
    owned: null,
    when: 'always',
    note: 'Authenticated by the refresh cookie, not by a bearer token, so auth is `none` here.',
  },
  {
    method: 'post',
    path: '/api/v1/auth/lock',
    auth: 'required',
    csrf: 'required',
    limiters: ['generalAuthLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'post',
    path: '/api/v1/auth/logout',
    auth: 'required',
    csrf: 'required',
    limiters: ['generalAuthLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'post',
    path: '/api/v1/auth/logout-all',
    auth: 'required',
    csrf: 'required',
    limiters: ['generalAuthLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'post',
    path: '/api/v1/auth/verify-unlock',
    auth: 'required',
    csrf: 'required',
    limiters: ['unlockLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'post',
    path: '/api/v1/auth/verify-email',
    auth: 'none',
    csrf: 'required',
    limiters: ['tokenVerifyLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'post',
    path: '/api/v1/auth/resend-verification',
    auth: 'none',
    csrf: 'required',
    limiters: ['authLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'post',
    path: '/api/v1/auth/forgot-password',
    auth: 'none',
    csrf: 'required',
    limiters: ['authLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'post',
    path: '/api/v1/auth/reset-password',
    auth: 'none',
    csrf: 'required',
    limiters: ['tokenVerifyLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'post',
    path: '/api/v1/auth/unlock-account',
    auth: 'none',
    csrf: 'required',
    limiters: ['tokenVerifyLimiter'],
    owned: null,
    when: 'always',
  },

  // ── /api/v1/vault (router-level `authenticate`) ───────────────────────
  {
    method: 'get',
    path: '/api/v1/vault/items',
    auth: 'required',
    csrf: 'exempt',
    limiters: [],
    owned: null,
    when: 'always',
  },
  {
    method: 'get',
    path: '/api/v1/vault/items/trash',
    auth: 'required',
    csrf: 'exempt',
    limiters: [],
    owned: null,
    when: 'always',
  },
  {
    method: 'get',
    path: '/api/v1/vault/items/:id',
    auth: 'required',
    csrf: 'exempt',
    limiters: [],
    owned: { param: 'id', resource: 'vaultItem' },
    when: 'always',
  },
  {
    method: 'post',
    path: '/api/v1/vault/items',
    auth: 'required',
    csrf: 'required',
    limiters: [],
    owned: null,
    when: 'always',
    note: 'Takes an owned folderId in the BODY; covered by phase7-cross-user-edge-cases.test.ts.',
  },
  {
    method: 'put',
    path: '/api/v1/vault/items/:id',
    auth: 'required',
    csrf: 'required',
    limiters: [],
    owned: { param: 'id', resource: 'vaultItem' },
    when: 'always',
    note: 'Also takes an owned folderId in the BODY, which the matrix does not model; covered by cross-user-isolation.test.ts.',
  },
  {
    method: 'delete',
    path: '/api/v1/vault/items/:id',
    auth: 'required',
    csrf: 'required',
    limiters: [],
    owned: { param: 'id', resource: 'vaultItem' },
    when: 'always',
  },
  {
    method: 'delete',
    path: '/api/v1/vault/items/:id/permanent',
    auth: 'required',
    csrf: 'required',
    limiters: [],
    owned: { param: 'id', resource: 'trashedVaultItem' },
    when: 'always',
  },
  {
    method: 'post',
    path: '/api/v1/vault/items/restore/:id',
    auth: 'required',
    csrf: 'required',
    limiters: [],
    owned: { param: 'id', resource: 'trashedVaultItem' },
    when: 'always',
  },
  {
    method: 'post',
    path: '/api/v1/vault/items/bulk-delete',
    auth: 'required',
    csrf: 'required',
    limiters: ['heavyOpLimiter'],
    owned: null,
    when: 'always',
    note: 'Takes owned ids in the BODY, which this table does not model; covered by cross-user-isolation.test.ts.',
  },
  {
    method: 'post',
    path: '/api/v1/vault/items/bulk-move',
    auth: 'required',
    csrf: 'required',
    limiters: ['heavyOpLimiter'],
    owned: null,
    when: 'always',
    note: 'Takes owned ids and a target folderId in the BODY; covered by phase7-cross-user-edge-cases.test.ts.',
  },
  {
    method: 'post',
    path: '/api/v1/vault/items/bulk-reencrypt',
    auth: 'required',
    csrf: 'required',
    limiters: ['passwordVerifyLimiter'],
    owned: null,
    when: 'always',
    note: 'Takes owned ids in the BODY; covered by phase7-cross-user-edge-cases.test.ts. The 30 MB body parser ahead of the limiter is not one.',
  },
  {
    method: 'delete',
    path: '/api/v1/vault/items/trash/empty',
    auth: 'required',
    csrf: 'required',
    limiters: ['heavyOpLimiter'],
    owned: null,
    when: 'always',
  },

  // ── /api/v1/folders (router-level `authenticate`) ─────────────────────
  {
    method: 'get',
    path: '/api/v1/folders/',
    auth: 'required',
    csrf: 'exempt',
    limiters: ['generalAuthLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'post',
    path: '/api/v1/folders/',
    auth: 'required',
    csrf: 'required',
    limiters: [],
    owned: null,
    when: 'always',
    note: 'Takes an owned parentId in the BODY; covered by phase7-cross-user-edge-cases.test.ts.',
  },
  {
    method: 'put',
    path: '/api/v1/folders/:id',
    auth: 'required',
    csrf: 'required',
    limiters: [],
    owned: { param: 'id', resource: 'folder' },
    when: 'always',
  },
  {
    method: 'delete',
    path: '/api/v1/folders/:id',
    auth: 'required',
    csrf: 'required',
    limiters: [],
    owned: { param: 'id', resource: 'folder' },
    when: 'always',
  },
  {
    method: 'put',
    path: '/api/v1/folders/:id/sort',
    auth: 'required',
    csrf: 'required',
    limiters: [],
    owned: { param: 'id', resource: 'folder' },
    when: 'always',
  },

  // ── /api/v1/user (router-level `authenticate`) ────────────────────────
  {
    method: 'get',
    path: '/api/v1/user/profile',
    auth: 'required',
    csrf: 'exempt',
    limiters: ['generalAuthLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'put',
    path: '/api/v1/user/settings',
    auth: 'required',
    csrf: 'required',
    limiters: ['generalAuthLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'put',
    path: '/api/v1/user/change-password',
    auth: 'required',
    csrf: 'required',
    limiters: ['passwordVerifyLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'post',
    path: '/api/v1/user/2fa/setup',
    auth: 'required',
    csrf: 'required',
    limiters: ['passwordVerifyLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'post',
    path: '/api/v1/user/2fa/verify',
    auth: 'required',
    csrf: 'required',
    limiters: ['tokenVerifyLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'delete',
    path: '/api/v1/user/2fa',
    auth: 'required',
    csrf: 'required',
    limiters: ['passwordVerifyLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'post',
    path: '/api/v1/user/2fa/regenerate-backup-codes',
    auth: 'required',
    csrf: 'required',
    limiters: ['passwordVerifyLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'get',
    path: '/api/v1/user/sessions',
    auth: 'required',
    csrf: 'exempt',
    limiters: ['generalAuthLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'delete',
    path: '/api/v1/user/sessions/:id',
    auth: 'required',
    csrf: 'required',
    limiters: ['generalAuthLimiter'],
    owned: { param: 'id', resource: 'session' },
    when: 'always',
  },
  {
    method: 'get',
    path: '/api/v1/user/trusted-devices',
    auth: 'required',
    csrf: 'exempt',
    limiters: ['generalAuthLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'delete',
    path: '/api/v1/user/trusted-devices',
    auth: 'required',
    csrf: 'required',
    limiters: ['generalAuthLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'delete',
    path: '/api/v1/user/trusted-devices/:id',
    auth: 'required',
    csrf: 'required',
    limiters: ['generalAuthLimiter'],
    owned: { param: 'id', resource: 'trustedDevice' },
    when: 'always',
  },
  {
    method: 'get',
    path: '/api/v1/user/audit-log',
    auth: 'required',
    csrf: 'exempt',
    limiters: ['generalAuthLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'delete',
    path: '/api/v1/user/',
    auth: 'required',
    csrf: 'required',
    limiters: ['passwordVerifyLimiter'],
    owned: null,
    when: 'always',
    note: 'GDPR account deletion. Scoped to the caller by construction — it takes no id.',
  },

  // ── /api/v1/tools (router-level `authenticate`) ───────────────────────
  {
    method: 'post',
    path: '/api/v1/tools/check-password-breach',
    auth: 'required',
    csrf: 'required',
    limiters: ['breachCheckLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'post',
    path: '/api/v1/tools/check-password-breach/batch',
    auth: 'required',
    csrf: 'required',
    limiters: ['breachBatchLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'post',
    path: '/api/v1/tools/export',
    auth: 'required',
    csrf: 'required',
    limiters: ['heavyOpLimiter', 'passwordVerifyLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'post',
    path: '/api/v1/tools/import',
    auth: 'required',
    csrf: 'required',
    // `importLimiter`, deliberately NOT `heavyOpLimiter`: a migration is sent
    // as several batches and would exhaust the shared 10/IP heavy-op budget.
    limiters: ['importLimiter'],
    owned: null,
    when: 'always',
    note: "Takes owned update ids in the BODY; covered by cross-user-isolation.test.ts's import suite.",
  },

  // ── /api/v1/backup (router-level `authenticate`) ──────────────────────
  {
    method: 'post',
    path: '/api/v1/backup/setup',
    auth: 'required',
    csrf: 'required',
    limiters: ['passwordVerifyLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'put',
    path: '/api/v1/backup/settings',
    auth: 'required',
    csrf: 'required',
    limiters: ['generalAuthLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'post',
    path: '/api/v1/backup/trigger',
    auth: 'required',
    csrf: 'required',
    limiters: ['heavyOpLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'get',
    path: '/api/v1/backup/download',
    auth: 'required',
    csrf: 'exempt',
    limiters: ['heavyOpLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'get',
    path: '/api/v1/backup/history',
    auth: 'required',
    csrf: 'exempt',
    limiters: ['generalAuthLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'put',
    path: '/api/v1/backup/change-password',
    auth: 'required',
    csrf: 'required',
    limiters: ['passwordVerifyLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'post',
    path: '/api/v1/backup/restore',
    auth: 'required',
    csrf: 'required',
    limiters: ['passwordVerifyLimiter'],
    owned: null,
    when: 'always',
    note: 'The 30 MB body parser ahead of the limiter is not a limiter.',
  },

  // ── /api/v1 (health, config) ──────────────────────────────────────────
  {
    method: 'get',
    path: '/api/v1/health',
    auth: 'none',
    csrf: 'exempt',
    limiters: ['healthLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'get',
    path: '/api/v1/config',
    auth: 'none',
    csrf: 'exempt',
    limiters: ['healthLimiter'],
    owned: null,
    when: 'always',
  },
];

/** `GET /api/v1/vault/items/:id` — the key both suites index rows by. */
export const rowKey = (row: { method: string; path: string }): string =>
  `${row.method.toUpperCase()} ${row.path}`;

/** Rows that exist under test, i.e. everything the two suites can actually call. */
export const isMountedUnderTest = (row: RouteRow): boolean =>
  row.when === 'always' || row.when === 'nonProduction';

// ---------------------------------------------------------------------------
// Reading the real router stack
// ---------------------------------------------------------------------------

/**
 * Every function exported by the rate-limiter module, by name.
 *
 * A namespace import rather than fifteen named ones on purpose: a limiter added
 * to `rateLimiter.ts` and mounted on a route is then named automatically, so
 * the table cannot silently omit it. With named imports, an unrecognised
 * middleware is indistinguishable from a validator closure and the new limiter
 * would go unnoticed in both directions.
 */
export const LIMITER_NAMES = new Map<unknown, string>(
  Object.entries(rateLimiters)
    .filter(
      (entry): entry is [string, (...args: unknown[]) => unknown] => typeof entry[1] === 'function',
    )
    .map(([name, fn]) => [fn, name]),
);

interface ObservedRoute {
  readonly method: HttpMethod;
  readonly path: string;
  readonly limiters: readonly string[];
  /** The router prefix this route came from, or `null` when `app.ts` mounts it directly. */
  readonly mount: string | null;
}

export interface CollectedRoutes {
  readonly routes: readonly ObservedRoute[];
  /**
   * Anything mounted at a path this file does not declare: a router at a prefix
   * outside {@link ROUTER_MOUNTS}, or middleware at a path outside
   * {@link MIDDLEWARE_MOUNTS}. Either one answers requests that no row covers.
   */
  readonly unknownMounts: readonly string[];
  /** Layers this reader cannot classify (a router nested inside a router). */
  readonly unsupported: readonly string[];
}

/** The private shape of an Express 5 / router@2 layer, as far as this reader needs it. */
interface RouterLayer {
  name: string;
  /**
   * router@2 sets this when the layer was mounted at `/` with `end: false`, i.e.
   * `app.use(fn)` — middleware that runs for every request. `false` means the
   * layer is bound to a PATH, which for a plain handler is a mount this file has
   * to know about. See `node_modules/router/lib/layer.js`.
   */
  slash?: boolean;
  handle?: { stack?: unknown[] };
  route?: {
    path: unknown;
    methods: Record<string, boolean>;
    stack?: { handle?: unknown }[];
  };
}

const asLayer = (value: unknown): RouterLayer => value as RouterLayer;

/** The matchers array, defensively — a shape change here must fail loudly, not silently. */
const matchersOf = (layer: RouterLayer): ((path: string) => false | { path: string })[] => {
  const raw = (layer as unknown as { matchers?: unknown }).matchers;
  return Array.isArray(raw) ? (raw as ((path: string) => false | { path: string })[]) : [];
};

/**
 * The prefix a mounted router answers to, or `null`.
 *
 * `match.path` must EQUAL the candidate: a router mounted at `/api/v1` matches
 * `/api/v1/auth/x` too, but consumes only `/api/v1`, so requiring equality is
 * what stops it from claiming every longer prefix as well.
 */
function mountOf(layer: RouterLayer, candidates: readonly string[]): string | null {
  for (const candidate of candidates) {
    const matched = matchersOf(layer).some((match) => {
      const result = match(`${candidate}/__hvault_mount_probe__`);
      return result !== false && result.path === candidate;
    });
    if (matched) return candidate;
  }
  return null;
}

const methodsOf = (route: NonNullable<RouterLayer['route']>): HttpMethod[] =>
  Object.entries(route.methods)
    .filter(([, enabled]) => enabled)
    .map(([method]) => method as HttpMethod);

const limitersOf = (route: NonNullable<RouterLayer['route']>): string[] =>
  (route.stack ?? [])
    .map((entry) => LIMITER_NAMES.get(entry.handle))
    .filter((name): name is string => name !== undefined);

/**
 * Walks the real Express app and reports every route it would answer, with the
 * limiters mounted on each.
 *
 * A route path is stringified because the production SPA fallback is declared
 * with a RegExp rather than a string, and an unclassified RegExp route must be
 * comparable against the table like any other.
 */
export function collectAppRoutes(app: Express): CollectedRoutes {
  const routes: ObservedRoute[] = [];
  const unknownMounts: string[] = [];
  const unsupported: string[] = [];

  const stack = (app as unknown as { router: { stack: unknown[] } }).router.stack;

  for (const raw of stack) {
    const layer = asLayer(raw);

    if (layer.route) {
      for (const method of methodsOf(layer.route)) {
        routes.push({
          method,
          path: String(layer.route.path),
          limiters: limitersOf(layer.route),
          mount: null,
        });
      }
      continue;
    }

    const children = layer.handle?.stack;
    if (!Array.isArray(children)) {
      // Plain middleware. Global (`app.use(fn)`) is none of this file's
      // business; PATH-SCOPED middleware answers requests under a prefix and
      // must therefore be one this file knows about, or it is invisible to
      // every assertion here.
      if (layer.slash !== true && mountOf(layer, MIDDLEWARE_MOUNTS) === null) {
        unknownMounts.push(`middleware "${layer.name}" at an unrecognised path`);
      }
      continue;
    }

    const mount = mountOf(layer, ROUTER_MOUNTS);
    if (mount === null) {
      unknownMounts.push(`router "${layer.name}" at an unrecognised prefix`);
      continue;
    }

    for (const rawChild of children) {
      const child = asLayer(rawChild);
      if (child.route) {
        const suffix = String(child.route.path);
        for (const method of methodsOf(child.route)) {
          routes.push({
            method,
            path: `${mount}${suffix}`,
            limiters: limitersOf(child.route),
            mount,
          });
        }
        continue;
      }
      // Router-level middleware (`router.use(authenticate)`) has no stack of its
      // own and is not a route. A nested ROUTER does, and this reader does not
      // resolve its mount — so it is reported rather than dropped.
      if (Array.isArray(child.handle?.stack)) {
        unsupported.push(`${mount} → nested router (${child.name})`);
      }
    }
  }

  return { routes, unknownMounts, unsupported };
}
