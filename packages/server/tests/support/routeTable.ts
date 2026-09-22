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
import {
  holdPartUploadSlot,
  parsePartUploadBody,
  requirePartContentLength,
} from '../../src/middleware/documentPartBody.js';
import { holdLargeBodySlot, parseLargeJsonBody } from '../../src/middleware/largeBodyAdmission.js';
import { sanitizeRequestBody } from '../../src/middleware/sanitizeBody.js';

export type HttpMethod = 'get' | 'post' | 'put' | 'delete';

/**
 * The resource a route's `:id` names. `authz-matrix.test.ts` maps each one to a
 * seeding scenario, and a row naming a resource with no scenario fails there.
 */
export type OwnedResource =
  | 'vaultItem'
  | 'trashedVaultItem'
  | 'folder'
  | 'session'
  | 'trustedDevice'
  | 'document'
  | 'trashedDocument'
  | 'documentUpload';

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
  /**
   * EVERY named middleware in front of the handler, in the order it runs: the
   * limiters, plus the body-admission middlewares (length guard, slot holder,
   * route-level body parser, the large-body handler wrapper). Declared only on a
   * route that carries admission middleware; absent, it is `limiters`, and
   * `route-table.test.ts` asserts that such a route carries none.
   *
   * It exists because `limiters` cannot see a parser. The shipped defect it pins
   * is ORDER, not membership: both 30 MB routes carried the right limiter AFTER
   * their parser, so every assertion that the limiter was present stayed green.
   */
  readonly chain?: readonly string[];
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
  '/api/v1/documents',
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
    path: '/sandbox.html',
    auth: 'none',
    csrf: 'exempt',
    limiters: [],
    owned: null,
    when: 'production',
    note:
      'The isolated document every stored file is rendered inside. Mounted only when ' +
      'NODE_ENV === production. Its whole isolation is the per-response ' +
      'Content-Security-Policy the route attaches (config/sandboxCsp.ts), so a copy ' +
      'answered off disk would carry helmet’s application policy instead — which is why ' +
      'the document is EMITTED OUTSIDE the express.static root (config/clientArtifacts.ts) ' +
      'rather than merely routed ahead of it: Express 5 matches the raw pathname while ' +
      'send decodes it, so /sandbox%2Ehtml, //sandbox.html, /sandbox.htm%6C and ' +
      '/%73andbox.html all miss this route. It is unauthenticated by design: it holds no ' +
      'data, receives every byte it renders over a MessagePort, and its own policy denies ' +
      'it any network access.',
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
    limiters: ['vaultItemWriteLimiter'],
    owned: null,
    when: 'always',
    note: 'Takes an owned folderId in the BODY; covered by phase7-cross-user-edge-cases.test.ts.',
  },
  {
    method: 'put',
    path: '/api/v1/vault/items/:id',
    auth: 'required',
    csrf: 'required',
    limiters: ['vaultItemWriteLimiter'],
    owned: { param: 'id', resource: 'vaultItem' },
    when: 'always',
    note: 'Also takes an owned folderId in the BODY, which the matrix does not model; covered by cross-user-isolation.test.ts.',
  },
  {
    method: 'delete',
    path: '/api/v1/vault/items/:id',
    auth: 'required',
    csrf: 'required',
    limiters: ['vaultItemWriteLimiter'],
    owned: { param: 'id', resource: 'vaultItem' },
    when: 'always',
  },
  {
    method: 'delete',
    path: '/api/v1/vault/items/:id/permanent',
    auth: 'required',
    csrf: 'required',
    limiters: ['vaultItemWriteLimiter'],
    owned: { param: 'id', resource: 'trashedVaultItem' },
    when: 'always',
  },
  {
    method: 'post',
    path: '/api/v1/vault/items/restore/:id',
    auth: 'required',
    csrf: 'required',
    limiters: ['vaultItemWriteLimiter'],
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
    // The limiter and the slot BEFORE the 30 MB parser, the sanitizer straight
    // after it, and the handler wrapped so the slot outlives an aborted response.
    chain: [
      'passwordVerifyLimiter',
      'holdLargeBodySlot',
      'parseLargeJsonBody',
      'sanitizeRequestBody',
      'largeBodyHandler',
    ],
    owned: null,
    when: 'always',
    note: 'Takes owned ids in the BODY; covered by phase7-cross-user-edge-cases.test.ts. Admission is pinned by large-body-admission.test.ts.',
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
    limiters: ['folderWriteLimiter'],
    owned: null,
    when: 'always',
    note: 'Takes an owned parentId in the BODY; covered by phase7-cross-user-edge-cases.test.ts.',
  },
  {
    method: 'put',
    path: '/api/v1/folders/:id',
    auth: 'required',
    csrf: 'required',
    limiters: ['folderWriteLimiter'],
    owned: { param: 'id', resource: 'folder' },
    when: 'always',
  },
  {
    method: 'delete',
    path: '/api/v1/folders/:id',
    auth: 'required',
    csrf: 'required',
    limiters: ['folderWriteLimiter'],
    owned: { param: 'id', resource: 'folder' },
    when: 'always',
  },
  {
    method: 'put',
    path: '/api/v1/folders/:id/sort',
    auth: 'required',
    csrf: 'required',
    limiters: ['folderWriteLimiter'],
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
    limiters: ['twoFactorVerifyLimiter'],
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
    // as several batches and would exhaust the shared 10-per-user heavy-op budget.
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
    chain: [
      'passwordVerifyLimiter',
      'holdLargeBodySlot',
      'parseLargeJsonBody',
      'sanitizeRequestBody',
      'largeBodyHandler',
    ],
    owned: null,
    when: 'always',
    note: 'Admission (limiter, slot, then the 30 MB parser) is pinned by large-body-admission.test.ts.',
  },

  // ── /api/v1/documents (router-level `authenticate`, then `requireStorage`) ──
  //
  // `requireStorage` is router-level and answers 503 where the operator has
  // configured no object storage, so it is not a limiter and does not appear in
  // the column below. It sits AHEAD of every route-level limiter here, which is
  // why an unconfigured deployment spends no rate-limit budget.
  {
    method: 'get',
    // Trailing slash, as the two `/api/v1/folders/` rows carry: `collectAppRoutes`
    // composes an observed path as mount + the router's own declaration, and a
    // router root is declared as `'/'`.
    path: '/api/v1/documents/',
    auth: 'required',
    csrf: 'exempt',
    limiters: ['generalAuthLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'get',
    path: '/api/v1/documents/trash',
    auth: 'required',
    csrf: 'exempt',
    limiters: ['generalAuthLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'get',
    path: '/api/v1/documents/usage',
    auth: 'required',
    csrf: 'exempt',
    limiters: ['generalAuthLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'delete',
    path: '/api/v1/documents/trash/empty',
    auth: 'required',
    csrf: 'required',
    // The ONLY document route carrying `heavyOpLimiter`, and the only one that
    // should: it is one genuinely unbounded operation, up to
    // MAX_DOCUMENTS_PER_USER rows each with an object delete. Every per-row
    // document route deliberately carries `generalAuthLimiter` instead, because
    // this per-user budget of 10 per 15 minutes is shared with export, backup
    // download and every bulk vault operation.
    limiters: ['heavyOpLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'get',
    path: '/api/v1/documents/uploads',
    auth: 'required',
    csrf: 'exempt',
    limiters: ['generalAuthLimiter'],
    owned: null,
    when: 'always',
  },
  {
    method: 'post',
    path: '/api/v1/documents/uploads',
    auth: 'required',
    csrf: 'required',
    // `documentUploadLimiter`, deliberately NOT `heavyOpLimiter`: init, complete
    // and abort are three requests per transfer, and the per-user heavy-op budget
    // of 10 per 15 minutes is shared with export, backup and every bulk vault
    // operation.
    limiters: ['documentUploadLimiter'],
    owned: null,
    when: 'always',
    note: 'Takes an owned folderId in the BODY, which this table does not model; covered by document-uploads.test.ts.',
  },
  {
    method: 'get',
    path: '/api/v1/documents/uploads/:id',
    auth: 'required',
    csrf: 'exempt',
    limiters: ['generalAuthLimiter'],
    owned: { param: 'id', resource: 'documentUpload' },
    when: 'always',
  },
  {
    method: 'delete',
    path: '/api/v1/documents/uploads/:id',
    auth: 'required',
    csrf: 'required',
    limiters: ['documentUploadLimiter'],
    owned: { param: 'id', resource: 'documentUpload' },
    when: 'always',
  },
  {
    method: 'put',
    path: '/api/v1/documents/uploads/:id/parts/:partNumber',
    auth: 'required',
    csrf: 'required',
    // The ONLY route in this application whose body is not JSON. It carries a
    // route-level `express.raw` for `application/octet-stream`, and two
    // middlewares ahead of it that are not limiters and so do not appear in the
    // column: a 411 guard, and the slot holder — which has to be AHEAD of the
    // parser, because a slot taken after the body is buffered bounds no memory at
    // all. The slot holder is THREE controls in one, and only the first is a
    // budget over time: it charges this account's share of the process-wide
    // in-flight budget (503 past it), takes one of `MAX_IN_FLIGHT_PART_UPLOADS`
    // slots, and arms the deadline by which this part's body must have arrived.
    limiters: ['documentPartLimiter'],
    chain: [
      'documentPartLimiter',
      'requirePartContentLength',
      'holdPartUploadSlot',
      'parsePartUploadBody',
    ],
    owned: { param: 'id', resource: 'documentUpload' },
    when: 'always',
    note: 'Takes a second path parameter, :partNumber, which authz-matrix.test.ts supplies through its scenario.',
  },
  {
    method: 'post',
    path: '/api/v1/documents/uploads/:id/complete',
    auth: 'required',
    csrf: 'required',
    // The third request of one transfer, so it shares that transfer's budget with
    // init and abort rather than carrying one of its own.
    limiters: ['documentUploadLimiter'],
    owned: { param: 'id', resource: 'documentUpload' },
    when: 'always',
    note: 'The only route that creates a documents row; a repeat completion is reported as the row the first one committed.',
  },
  {
    method: 'get',
    path: '/api/v1/documents/:id',
    auth: 'required',
    csrf: 'exempt',
    limiters: ['generalAuthLimiter'],
    owned: { param: 'id', resource: 'document' },
    when: 'always',
  },
  {
    method: 'put',
    path: '/api/v1/documents/:id',
    auth: 'required',
    csrf: 'required',
    limiters: ['generalAuthLimiter'],
    owned: { param: 'id', resource: 'document' },
    when: 'always',
    note: 'Metadata and attributes only. The allowlist cannot reach a framing field, the wrapped key or the object key, and it is deliberately not rotation-fenced.',
  },
  {
    method: 'delete',
    path: '/api/v1/documents/:id',
    auth: 'required',
    csrf: 'required',
    limiters: ['generalAuthLimiter'],
    owned: { param: 'id', resource: 'document' },
    when: 'always',
    note: 'Soft delete. The object stays in the bucket and the document still counts against the quota.',
  },
  {
    method: 'post',
    path: '/api/v1/documents/:id/restore',
    auth: 'required',
    csrf: 'required',
    limiters: ['generalAuthLimiter'],
    owned: { param: 'id', resource: 'trashedDocument' },
    when: 'always',
  },
  {
    method: 'delete',
    path: '/api/v1/documents/:id/permanent',
    auth: 'required',
    csrf: 'required',
    // `generalAuthLimiter`, NOT `heavyOpLimiter`: this is a per-row route, and
    // that per-user budget of 10 per 15 minutes would 429 a user who purged
    // eleven documents and then lock them out of emptying their vault trash.
    limiters: ['generalAuthLimiter'],
    owned: { param: 'id', resource: 'trashedDocument' },
    when: 'always',
    note: 'Marks purgePending, deletes the object, then deletes the row, so a crash between any two leaves a marker the collector finishes.',
  },
  {
    method: 'get',
    path: '/api/v1/documents/:id/segments/:index',
    auth: 'required',
    csrf: 'exempt',
    // `documentReadLimiter`, not `generalAuthLimiter`: one download is one
    // request per segment, so this is the only read whose volume scales with the
    // operator's own size cap, and its ceiling is derived from it.
    limiters: ['documentReadLimiter'],
    owned: { param: 'id', resource: 'document' },
    when: 'always',
    note: 'Takes a second path parameter, :index, which authz-matrix.test.ts supplies through its scenario. The only route in this application that answers with raw bytes rather than a JSON envelope.',
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
  /** Every limiter and admission middleware on the route, in stack order. */
  readonly chain: readonly string[];
  /**
   * EVERY handler on the route, in order, named as in `chain` where it can be and
   * `<other>` where it cannot (a validator, a controller). `chain` drops the unnamed
   * ones, so only this can say what sits directly after a given middleware.
   */
  readonly stack: readonly string[];
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
  /**
   * Body parsers mounted at ROUTER level (`router.use(express.json())`). One of
   * those runs before every route's limiter in that router, so none may exist.
   */
  readonly routerLevelParsers: readonly string[];
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

/** The chain name of `sanitizeRequestBody`. */
export const BODY_SANITIZER = 'sanitizeRequestBody';

/**
 * The body-admission middlewares, by FUNCTION IDENTITY, exactly as the limiters
 * are named: each is a module-level export, so the one mounted is the one named.
 * `sanitizeRequestBody` is not admission, but it belongs in the chain for the same
 * reason the parsers do: WHERE it sits is the control (straight after a route's own
 * parser), and a chain that could not show it could not pin that.
 */
export const ADMISSION_NAMES = new Map<unknown, string>([
  [requirePartContentLength, 'requirePartContentLength'],
  [holdPartUploadSlot, 'holdPartUploadSlot'],
  [parsePartUploadBody, 'parsePartUploadBody'],
  [holdLargeBodySlot, 'holdLargeBodySlot'],
  [parseLargeJsonBody, 'parseLargeJsonBody'],
  [sanitizeRequestBody, BODY_SANITIZER],
]);

/** The route-level parsers named above. */
export const NAMED_BODY_PARSERS: ReadonlySet<string> = new Set([
  'parsePartUploadBody',
  'parseLargeJsonBody',
]);

/** The slot holders named above: what must stand between the limiters and a parser. */
export const SLOT_HOLDERS: ReadonlySet<string> = new Set([
  'holdPartUploadSlot',
  'holdLargeBodySlot',
]);

/**
 * The function names `body-parser` 2.x gives the middleware it returns
 * (`lib/types/{json,raw,text,urlencoded}.js`). Matched BY NAME, as the fallback
 * for a parser that is not one of the exports above: a fresh `express.json()`
 * written inline on a route has no identity to look up, and it is exactly the
 * mount that would reintroduce the defect. The limit of it, stated: a parser
 * wrapped in another function carries that function's name and escapes this.
 */
export const BODY_PARSER_FUNCTION_NAMES: ReadonlySet<string> = new Set([
  'jsonParser',
  'rawParser',
  'textParser',
  'urlencodedParser',
]);

/**
 * The route-level parsers whose output is a parsed OBJECT, and so must be followed
 * immediately by {@link BODY_SANITIZER}: the app-level sanitizer runs before any
 * route-level parser, and sees nothing of what one produces.
 *
 * `parsePartUploadBody` is deliberately absent. It is a raw parser and its body is
 * a `Buffer` of ciphertext: there are no keys in it to inject, and walking a
 * `Buffer` as an object would replace the ciphertext with a map of its indices. An
 * unnamed `jsonParser`/`urlencodedParser` is covered by {@link isStructuredBodyParser}.
 */
export const STRUCTURED_BODY_PARSERS: ReadonlySet<string> = new Set(['parseLargeJsonBody']);

/** The prefix an un-exported body parser is reported under. */
export const UNNAMED_PARSER_PREFIX = 'unnamedBodyParser:';

/** The name `holdingLargeBodySlot` gives the handler it wraps. */
export const LARGE_BODY_HANDLER = 'largeBodyHandler';

/** The chain name of one stack entry, or `undefined` for anything else (validators, handlers). */
function chainNameOf(handle: unknown): string | undefined {
  const named = LIMITER_NAMES.get(handle) ?? ADMISSION_NAMES.get(handle);
  if (named !== undefined) return named;
  if (typeof handle !== 'function') return undefined;
  if (BODY_PARSER_FUNCTION_NAMES.has(handle.name)) return `${UNNAMED_PARSER_PREFIX}${handle.name}`;
  if (handle.name === LARGE_BODY_HANDLER) return LARGE_BODY_HANDLER;
  return undefined;
}

/** Whether a chain name is a body parser, named or not. */
export const isBodyParser = (name: string): boolean =>
  NAMED_BODY_PARSERS.has(name) || name.startsWith(UNNAMED_PARSER_PREFIX);

/** Whether a chain name is a parser whose output must be sanitized before anything reads it. */
export const isStructuredBodyParser = (name: string): boolean =>
  STRUCTURED_BODY_PARSERS.has(name) ||
  name === `${UNNAMED_PARSER_PREFIX}jsonParser` ||
  name === `${UNNAMED_PARSER_PREFIX}urlencodedParser`;

const chainOf = (route: NonNullable<RouterLayer['route']>): string[] =>
  (route.stack ?? [])
    .map((entry) => chainNameOf(entry.handle))
    .filter((name): name is string => name !== undefined);

/** The name every unclassified handler is reported under in {@link ObservedRoute.stack}. */
export const OTHER_HANDLER = '<other>';

const stackOf = (route: NonNullable<RouterLayer['route']>): string[] =>
  (route.stack ?? []).map((entry) => chainNameOf(entry.handle) ?? OTHER_HANDLER);

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
  const routerLevelParsers: string[] = [];

  const stack = (app as unknown as { router: { stack: unknown[] } }).router.stack;

  for (const raw of stack) {
    const layer = asLayer(raw);

    if (layer.route) {
      for (const method of methodsOf(layer.route)) {
        routes.push({
          method,
          path: String(layer.route.path),
          limiters: limitersOf(layer.route),
          chain: chainOf(layer.route),
          stack: stackOf(layer.route),
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
            chain: chainOf(child.route),
            stack: stackOf(child.route),
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
        continue;
      }
      const name = chainNameOf(child.handle);
      if (name !== undefined && isBodyParser(name)) {
        routerLevelParsers.push(`${mount} → router-level ${name}`);
      }
    }
  }

  return { routes, unknownMounts, unsupported, routerLevelParsers };
}
