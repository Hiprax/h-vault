/**
 * The DECLARED mutation scope, in one place.
 *
 * Three consumers read this module and no fourth may restate it:
 *
 *   1. `stryker.config.mjs`      — what Stryker mutates, and with which runner.
 *   2. `scripts/ci/mutation-gate.mjs` — the `test:mutation` gate.
 *   3. `scripts/ci/ratchet-check.mjs`  — the direction map's core-module keys.
 *
 * A second declaration is the whole failure mode here: mutation scope is a
 * DENOMINATOR, so a config that quietly stops mutating a directory raises the
 * score while covering less code, and a copy of the scope elsewhere is how the
 * two drift apart without a diff that looks like a weakening. The ratchet
 * defends the EFFECT (`mutation.filesMutated`, superset) rather than these
 * globs, for the reason its own header gives: narrowing scope normally GROWS a
 * glob list.
 *
 * ---------------------------------------------------------------------------
 * WHY THE SCOPE IS WHAT IT IS
 * ---------------------------------------------------------------------------
 *
 * `packages/*​/src/**` minus the coverage-excluded entry points, minus
 * `packages/client/src/components/ui/**`. Every exclusion below is one the
 * coverage configuration already makes, with the same written justification —
 * so the mutation denominator and the coverage denominator describe the same
 * body of code, and neither can be narrowed on its own without the other
 * disagreeing.
 *
 * The one addition is `components/ui/**`: presentational primitives whose
 * mutants are overwhelmingly cosmetic (a class-name string, a default variant),
 * which is a different question from "does this application do the right
 * thing". They stay MEASURED for coverage and are exercised by the component
 * suites; they are simply not the oracle's subject.
 *
 * ---------------------------------------------------------------------------
 * WHY ONE RUN PER PACKAGE
 * ---------------------------------------------------------------------------
 *
 * Stryker's Vitest runner takes ONE vitest config, and this repository has
 * three, with three different environments (node, node + a real mongod, jsdom).
 * One run per package is therefore not a convenience, it is the only shape that
 * runs each mutant against the suite that is supposed to kill it.
 *
 * Every leg runs with the REPO ROOT as its project root, never the package
 * directory. Stryker copies the project root into its sandbox, and a
 * package-scoped copy would leave `docker-compose.yml`, `scripts/ci/**` and
 * `.testfortress/**` outside it — which several suites read through
 * `../../<path>` — so the dry run would fail before a single mutant was tested.
 */

/** `packages/client/src/components/ui/**` — see the header. */
export const PRESENTATIONAL_EXCLUDE = '!packages/client/src/components/ui/**';

/**
 * The legs, in ascending order of cost. `shared` first is deliberate: it is the
 * cheapest leg by an order of magnitude, so a broken configuration is reported
 * in a minute rather than in an hour.
 *
 * THEY RUN ONE AFTER ANOTHER, and that is a requirement rather than a
 * simplification. Measured on the reference machine (4 cores): with the client
 * leg's three runners busy, the server leg's DRY RUN failed on a 30-second test
 * timeout — `batch7-fixes.test.ts`'s HIBP cache bound, which inserts 15,000
 * entries. The same test against the same INSTRUMENTED sources takes 7.3 s when
 * the machine is free, so the cause was CPU starvation and not instrumentation
 * overhead. A test that fails for want of a core is recorded by Stryker as a
 * KILLED mutant, which inflates the score with tests that never really ran, and
 * in the dry run it takes the whole leg down instead.
 */
export const MUTATION_LEGS = [
  {
    id: 'shared',
    package: 'packages/shared',
    vitestConfig: 'packages/shared/vitest.mutation.config.ts',
    mutate: [
      'packages/shared/src/**/*.ts',
      '!packages/shared/src/**/*.d.ts',
      // Written by `scripts/inject-version.js` at build time and gitignored:
      // there is no source file to fix a survivor in.
      '!packages/shared/src/generated/**',
      // Type-only declarations. They erase to nothing, so they carry no mutants
      // — excluded so the DECLARED scope says so rather than implying coverage
      // of something that cannot be covered.
      '!packages/shared/src/types/**',
    ],
    // No datastore and no DOM: the suite is pure computation, so the legs can
    // use every core.
    concurrency: 3,
  },
  {
    id: 'client',
    package: 'packages/client',
    vitestConfig: 'packages/client/vitest.mutation.config.ts',
    mutate: [
      'packages/client/src/**/*.ts',
      'packages/client/src/**/*.tsx',
      '!packages/client/src/**/*.d.ts',
      // Process entry point: `ReactDOM.createRoot` against a real `#root` as an
      // import side effect (coverage excludes it for the same reason).
      '!packages/client/src/main.tsx',
      // Web Worker thread entry points: jsdom has no `Worker`, so these files
      // never execute under the runner at all and every mutant in one would
      // survive for a reason that has nothing to do with the tests.
      '!packages/client/src/**/*.worker.ts',
      PRESENTATIONAL_EXCLUDE,
    ],
    concurrency: 3,
  },
  {
    id: 'server',
    package: 'packages/server',
    vitestConfig: 'packages/server/vitest.mutation.config.ts',
    mutate: [
      'packages/server/src/**/*.ts',
      '!packages/server/src/**/*.d.ts',
      // Process entry point: binds the port, installs signal handlers and
      // schedules the cron jobs as a side effect of import.
      '!packages/server/src/server.ts',
      // The same class: connects, takes a job lock and runs the import as a
      // side effect of import. Its testable half is `cli/seedBreachesArgs.ts`,
      // which stays in scope.
      '!packages/server/src/cli/seedBreaches.ts',
    ],
    // TWO runner processes, not three, and the number is a measurement rather
    // than a preference.
    //
    // Every server test file spawns a REAL mongod. `tests/mongoHarness.ts` now
    // gives each Stryker runner a disjoint port band (its band index includes
    // `STRYKER_MUTATOR_WORKER`, added for exactly this gate — without it every
    // runner computes the same band, because they share a parent pid and each
    // pins vitest to one worker), so concurrency is safe from the port race. It
    // is capped at 2 for the OTHER hazard: a mutant run is judged by whether the
    // suite fails, and a suite starved of CPU fails on a 30-second test timeout
    // that has nothing to do with the mutation. On four cores, three runners
    // plus three mongods is where that starts; two leaves the measurement alone.
    concurrency: 2,
  },
];

/**
 * The higher-threshold modules from the plan's §1.7. These are PATH PREFIXES
 * matched against the measured file set, so a new file inside one joins its
 * module automatically.
 */
export const CORE_MODULES = [
  'packages/client/src/services/crypto/',
  'packages/shared/src/schemas/',
  'packages/server/src/middleware/rateLimiter.ts',
  'packages/server/src/controllers/vaultController.ts',
  'packages/client/src/services/import/',
  'packages/server/src/utils/folderGraph.ts',
];

/**
 * A baseline key for a module path.
 *
 * Dots are replaced because `ratchet-check.mjs` flattens the baseline on `.`
 * and resolves a field's direction through a wildcard over the LAST segment:
 * a key ending `rateLimiter.ts` would flatten to a path whose wildcard is
 * `mutation.modules.…rateLimiter.*`, which is declared nowhere, and the field
 * would fail the run as having no declared direction. The bundle budgets carry
 * the same sanitisation for the same reason (`keySafe` there). Matching is done
 * with BOTH sides sanitised, so the transformation cannot change which files a
 * module claims.
 */
export const moduleKey = (modulePath) => modulePath.replace(/\./g, '_');

/** Every glob, in leg order: what `mutation.scopeGlobs` records. */
export const MUTATION_SCOPE_GLOBS = MUTATION_LEGS.flatMap((leg) => leg.mutate);

/** The leg ids, for CLI validation and error messages. */
export const MUTATION_LEG_IDS = MUTATION_LEGS.map((leg) => leg.id);

/** Where each leg's Stryker artifacts land (gitignored). */
export const MUTATION_TMP_DIR = '.stryker-tmp';
export const incrementalFileFor = (id) => `${MUTATION_TMP_DIR}/incremental-${id}.json`;
export const jsonReportFor = (id) => `${MUTATION_TMP_DIR}/report-${id}.json`;
