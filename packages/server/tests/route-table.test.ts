/**
 * The route table is exhaustive, and it is exhaustive in both directions.
 *
 * `tests/support/routeTable.ts` classifies every route this server mounts. That
 * classification is what `authz-matrix.test.ts` drives its cross-user matrix
 * from, so the table going stale is not a documentation problem — it is the
 * matrix silently not testing a route. The failures worth having here are
 * therefore all DRIFT failures:
 *
 *   1. A route the app mounts that the table does not classify. This is the one
 *      that closes R4: a route added to `src/routes/*.ts` tomorrow fails this
 *      suite until someone says whether it takes an owned id.
 *   2. A route the table claims that the app does not mount — a rename or a
 *      deletion that would otherwise leave the matrix asserting against a
 *      404-by-absence and calling it isolation.
 *   3. A limiter column that has stopped describing the middleware actually
 *      mounted. Read by function identity, so it cannot be satisfied by a
 *      similarly-named export.
 *   4. A conditionally-mounted route appearing unconditionally. `/api/v1/metrics`
 *      lives inside `if (config.METRICS_TOKEN)`; with no token set it must not
 *      exist at all, and this is what notices if that guard is dropped.
 *
 * The stack is READ from the real `app`, never regexed out of the source.
 */
import { describe, it, expect } from 'vitest';
import app from '../src/app.js';
import * as rateLimiters from '../src/middleware/rateLimiter.js';
import {
  LIMITER_NAMES,
  ROUTE_TABLE,
  ROUTER_MOUNTS,
  collectAppRoutes,
  isMountedUnderTest,
  rowKey,
  type RouteRow,
} from './support/routeTable.js';

const observed = collectAppRoutes(app);
const observedKeys = observed.routes.map(rowKey).sort();
const declaredUnderTest = ROUTE_TABLE.filter(isMountedUnderTest);
const declaredKeys = declaredUnderTest.map(rowKey).sort();
const observedByKey = new Map(observed.routes.map((route) => [rowKey(route), route]));

/** Routes declared in `src/routes/*.ts`, i.e. everything under a router mount. */
const ROUTER_FILE_ROUTES = 57;

describe('the route table matches the real Express router stack', () => {
  it('resolves every mounted router and every path-scoped middleware', () => {
    // A router mounted at a prefix the table does not know would have every one
    // of its routes silently unclassified, and a plain handler mounted under a
    // path — `app.use('/api/v1/legacy', handler)` — would answer requests while
    // being neither a route nor a router. Both are checked before the set
    // comparison below rather than left to surface as a confusing diff.
    expect(observed.unknownMounts, 'layer(s) mounted at a path the table does not know').toEqual(
      [],
    );
    expect(observed.unsupported, 'router layer(s) this reader cannot classify').toEqual([]);
  });

  it('can name every rate limiter the middleware module exports', () => {
    // The limiter column is read by function IDENTITY, and that only works
    // while each limiter export is its own object. Outside production every one
    // of them is a pass-through, and they are distinct only because
    // `noopIfNonProduction()` constructs a fresh closure per call. Hoisting that
    // to a single shared constant would collapse this map to one entry and make
    // `limitersOf` report one arbitrary name for every limiter — with every
    // assertion above still green. This is the check that would not be.
    const functionExports = Object.values(rateLimiters).filter(
      (value) => typeof value === 'function',
    );
    expect(functionExports.length).toBeGreaterThan(10);
    expect(LIMITER_NAMES.size).toBe(functionExports.length);
  });

  it('classifies every route the app mounts', () => {
    const unclassified = observedKeys.filter((key) => !declaredKeys.includes(key));
    expect(
      unclassified,
      'route(s) the app mounts that tests/support/routeTable.ts does not classify — ' +
        'add a row (and, if it takes an owned id, a matrix scenario) before merging',
    ).toEqual([]);
  });

  it('mounts every route the table claims', () => {
    const missing = declaredKeys.filter((key) => !observedKeys.includes(key));
    expect(missing, 'route(s) the table declares that the app does not mount').toEqual([]);
  });

  it('still covers all 57 routes declared in src/routes/*.ts', () => {
    // A count, beside the set comparison, because the set comparison alone stays
    // green when a route is deleted from a router AND its row from the table in
    // the same change. The routers are the product's whole API surface, so the
    // number is worth pinning: it should move only in a change that deliberately
    // adds or removes an endpoint.
    const underRouter = observed.routes.filter((route) => route.mount !== null);
    expect(underRouter).toHaveLength(ROUTER_FILE_ROUTES);
    // Every one of them resolved to a prefix `app.ts` really mounts.
    for (const route of underRouter) {
      expect(ROUTER_MOUNTS).toContain(route.mount);
    }
  });

  it('leaves a conditionally-mounted route unmounted under test', () => {
    // `metricsToken`: registering /api/v1/metrics without METRICS_TOKEN would
    // publish an unauthenticated metrics endpoint. `production`: the SPA
    // fallback. Neither may appear in this environment, and a row that claims
    // to be conditional while the app mounts it unconditionally is a lie the
    // set comparison above would report as "unclassified" without saying why.
    const conditional = ROUTE_TABLE.filter((row) => !isMountedUnderTest(row));
    expect(conditional.length).toBeGreaterThan(0);
    for (const row of conditional) {
      expect(
        observedKeys,
        `${rowKey(row)} (${row.when}) must not be mounted under test`,
      ).not.toContain(rowKey(row));
      expect(row.note, `${rowKey(row)} must say why it is conditional`).toBeTruthy();
    }
  });

  it('declares the limiters each route actually carries, in order', () => {
    // Identity-checked against the real middleware, so this is the only place
    // in the suite that can catch a limiter mounted on the wrong endpoint —
    // the class of defect that put the credential budget on /auth/refresh and
    // let ordinary session maintenance lock users out of logging in.
    for (const row of declaredUnderTest) {
      const route = observedByKey.get(rowKey(row));
      expect(route, `${rowKey(row)} is not mounted`).toBeDefined();
      expect(route!.limiters, `limiters on ${rowKey(row)}`).toEqual(row.limiters);
    }
  });
});

describe('the route table is internally consistent', () => {
  it('classifies each method + path exactly once', () => {
    const keys = ROUTE_TABLE.map(rowKey);
    const duplicates = keys.filter((key, index) => keys.indexOf(key) !== index);
    expect(duplicates).toEqual([]);
  });

  it('exempts exactly the safe methods from CSRF', () => {
    // Honestly: this IS `SAFE_METHODS` from `middleware/csrf.ts` restated, and
    // the column carries no information the method does not. It is here for one
    // narrow reason — a row cannot be flipped to `exempt` to excuse a missing
    // observation — and the real check on that column is over the wire, in
    // `authz-matrix.test.ts`, where every `required` row is shown to answer 403
    // with no token and every `exempt` row to answer without one.
    for (const row of ROUTE_TABLE) {
      const expected = row.method === 'get' ? 'exempt' : 'required';
      expect(row.csrf, `csrf on ${rowKey(row)}`).toBe(expected);
    }
  });

  // The two rules below check the table against itself. That is all they can
  // do, and it is worth two lines: they are what makes `owned` a decision
  // rather than a field someone can leave blank.
  it('names only a parameter the path actually carries', () => {
    for (const row of ROUTE_TABLE.filter(
      (entry): entry is RouteRow & { owned: NonNullable<RouteRow['owned']> } =>
        entry.owned !== null,
    )) {
      expect(row.path, `${rowKey(row)} declares :${row.owned.param}`).toContain(
        `:${row.owned.param}`,
      );
    }
  });

  it('classifies every path parameter as owned', () => {
    // The inverse of the rule above, and the one with teeth: a new `:id` route
    // added to the table with `owned: null` would take an id from the caller
    // and get no IDOR check at all. Any future parameter that genuinely is not
    // an owned resource has to be argued for here, in this test.
    const withParams = ROUTE_TABLE.filter((row) => row.path.includes('/:'));
    for (const row of withParams) {
      expect(
        row.owned,
        `${rowKey(row)} takes a path parameter but declares no owner`,
      ).not.toBeNull();
    }
  });
});
