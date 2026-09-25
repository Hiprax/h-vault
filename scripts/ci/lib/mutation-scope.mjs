/**
 * The DECLARED mutation scope, in one place.
 *
 * Its consumers read this module and none may restate it:
 *
 *   1. `scripts/ci/lib/stryker-config.mjs` (loaded by `stryker.config.mjs`)
 *      — what Stryker mutates, and with which runner.
 *   2. `scripts/ci/mutation-gate.mjs` — the `test:mutation` campaign.
 *   3. `scripts/ci/mutation-diff-gate.mjs` — `test:mutation:diff`, which selects
 *      the changed files through `legForFile` and so can never narrow the scope.
 *   4. `scripts/ci/ratchet-check.mjs` — the direction map's core-module keys,
 *      the per-leg fields and reports, and the per-change floor and budgets.
 *   5. `scripts/ci/lib/mutation-evidence.mjs` — the module keys a per-module
 *      score is recorded under.
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
import path from 'node:path';

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
  // The document controller joins them for the same reason the vault controller
  // is here: it is the only thing standing between a mis-framed upload and a
  // stored object nobody can ever open again. Its size rules are the kind of
  // check a mutation survives quietly — an equality relaxed to a bound, a
  // boundary moved by one — and the suites around it are exactly the suites that
  // would keep passing.
  'packages/server/src/controllers/documentController.ts',
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

/**
 * Does this leg's declared scope select `file`? LAST MATCH WINS, which is
 * Stryker's own rule for a `mutate` list mixing patterns and `!` negations, so
 * this answers the question Stryker will answer rather than a tidier one.
 *
 * One definition, read by the campaign gate's pre-flight, by the diff-scoped
 * gate's file selection and by `gate-surface.test.ts`: three copies of a
 * last-match loop is three places for "which files are in scope" to disagree,
 * and scope is a denominator.
 */
export function legSelects(leg, file) {
  let selected = false;
  for (const glob of leg.mutate) {
    if (glob.startsWith('!')) {
      if (path.matchesGlob(file, glob.slice(1))) selected = false;
    } else if (path.matchesGlob(file, glob)) {
      selected = true;
    }
  }
  return selected;
}

/** The leg whose declared scope selects `file`, or `undefined` when none does. */
export const legForFile = (file) => MUTATION_LEGS.find((leg) => legSelects(leg, file));

/**
 * The per-leg evidence file every COMPLETED leg writes into the report
 * directory, beside the merged `mutation.json`.
 *
 * It is what makes a leg bankable on its own. The merged report is written only
 * by a run in which all three legs completed, and one of them is measured in
 * days, so while it was the only artifact no leg could ever hold a floor. A leg's
 * own file describes exactly the code that leg mutated, so the ratchet can read
 * it as `mutation.legs.<id>.*` without mistaking one package for the whole
 * declared scope, which is the mistake the merged report's all-or-nothing rule
 * exists to prevent.
 */
export const legReportFor = (id) => `mutation-${id}.json`;

/** The inverse of `legReportFor`: the leg a report name belongs to, if any. */
export const legOfReport = (name) => MUTATION_LEG_IDS.find((id) => legReportFor(id) === name);

/** Where each leg's Stryker artifacts land (gitignored). */
export const MUTATION_TMP_DIR = '.stryker-tmp';
export const incrementalFileFor = (id) => `${MUTATION_TMP_DIR}/incremental-${id}.json`;
export const jsonReportFor = (id) => `${MUTATION_TMP_DIR}/report-${id}.json`;

// ---------------------------------------------------------------------------
// the per-change leg: `test:mutation:diff`
// ---------------------------------------------------------------------------

/**
 * The floor for the mutants a change owns, in percent.
 *
 * 85 is the changed-code target the project's testing doctrine sets for this
 * gate, taken as written rather than measured off one change: the score of one
 * run belongs to that change, not to the suite, so a floor copied from whichever
 * change happened to be measured first would be arbitrary in both directions.
 * It is a committed constant read by the gate AND injected into the ratchet as
 * `mutationDiff.floor` (direction higher), so it can be raised with a written
 * reason and never quietly lowered.
 */
export const MUTATION_DIFF_FLOOR = 85;

/**
 * How many of a change's mutants each leg tests, at most, beyond the one
 * location per changed file that is always taken — the leg's DENOMINATOR, and
 * the reason the per-change tier has a bounded cost at all.
 *
 * A change that owns fewer mutants than this is tested in full, which is the
 * ordinary case. A larger one is sampled, deterministically and disclosed (see
 * `lib/mutation-diff.mjs`), and the whole population stays under the campaign's
 * own floor at tier 2. Ratcheted as `mutationDiff.budget.<leg>` (direction
 * higher): a larger budget always tests a superset of a smaller one, so the
 * number can only grow.
 *
 * MEASURED, per leg, because the three legs differ in cost per mutant by two
 * orders of magnitude. On the reference machine (4 cores), over this plan's
 * 85-file branch diff, each leg's mutant phase — AFTER its dry run, which the
 * budget cannot shorten — cost: shared about 0.4 s of wall clock per mutant
 * (127 in 52 s, dry run included), client about 1.5 s (83 in ~2 min), and server
 * about 27 s at its concurrency of 2 (80 in ~37 min), because a surviving or
 * static server mutant runs every covering test file and each boots a real
 * mongod. Each budget is sized for a mutant phase of about three minutes on
 * shared and client and about nine on the server, beside dry runs measured at
 * seconds, ~5.5 minutes and ~7 minutes respectively for a change touching widely
 * imported modules. Those per-mutant figures were taken under the file shuffle
 * the mutation configs used to inherit, which made every KILLED static mutant pay
 * for a random share of its suite; with the kill-seeking file order
 * (`tests/harness/mutationSequencer.ts`) the whole gate over a 104-file branch
 * diff fell from 63–67 minutes to 30m 26s on the same plans (compared mutant by
 * mutant, the shared and client legs changed no status; the server leg's
 * kill count was unchanged), and to 21m 00s once the leaf sample below and four
 * killed static survivors were added. A static mutant that SURVIVES is now the one thing that
 * still costs a whole related suite.
 *
 * The one location per changed file the stratification always takes can exceed
 * a budget; that is deliberate (no changed file goes unmeasured). It costs one
 * span's mutants, never a subtree (`lib/mutation-diff.mjs` decision (c)): taking
 * whichever candidate hashed lowest, block and object literal included, planned
 * 83 server mutants on a 32-file change against this budget of 20, and one leaf
 * span per file plans 50.
 */
export const MUTATION_DIFF_BUDGETS = { shared: 200, client: 120, server: 20 };

/**
 * A hang guard per leg, never the cost control. The budget above is what bounds
 * the cost; Stryker's own per-mutant timeout and dry-run timeout bound a wedged
 * mutant. This only catches a run that is stuck as a whole, and expiring it is
 * "could not run" (exit 2), never a verdict. Generous on purpose: a deadline that
 * a busy machine could reach would turn the gate into a coin toss, the argument
 * `mutation-gate.mjs` decision (e) makes for having none at all.
 *
 * So it SCALES WITH THE PLAN, because the budget does not bound the planned
 * count: the stratification takes one location per changed file whatever the
 * budget says. A flat hour was reached by a healthy run. Measured on the
 * reference machine over a 105-file branch diff, the server leg planned 81
 * mutants against its budget of 20, its dry run took 8m20s, its mutants cost
 * about 38 s each at its concurrency of 2, and the flat guard stopped it at 80
 * of 81, still progressing. The deadline is therefore an hour, or a dry-run
 * allowance of about three and a half times that measured dry run plus two
 * minutes per planned mutant (about three times that per-mutant cost),
 * whichever is larger. It grows with the plan and never
 * shrinks below the hour a small change always had.
 */
const MUTATION_DIFF_LEG_MIN_DEADLINE_MS = 60 * 60 * 1000;
const MUTATION_DIFF_LEG_DRY_RUN_ALLOWANCE_MS = 30 * 60 * 1000;
const MUTATION_DIFF_LEG_PER_MUTANT_ALLOWANCE_MS = 2 * 60 * 1000;

/**
 * The hang guard for one leg that plans `planned` mutants.
 *
 * @param {number} planned
 * @returns {number} milliseconds
 */
export function mutationDiffLegDeadlineMs(planned) {
  if (!Number.isInteger(planned) || planned < 0) {
    throw new RangeError(
      `a leg plans a whole, non-negative number of mutants, not ${String(planned)}`,
    );
  }
  return Math.max(
    MUTATION_DIFF_LEG_MIN_DEADLINE_MS,
    MUTATION_DIFF_LEG_DRY_RUN_ALLOWANCE_MS + MUTATION_DIFF_LEG_PER_MUTANT_ALLOWANCE_MS * planned,
  );
}

/** The per-change leg's report: deliberately not `mutation-<leg>.json`'s shape. */
export const MUTATION_DIFF_REPORT = 'mutation-diff.json';

/** Its per-leg Stryker artifacts, kept apart from the campaign's by name. */
export const diffPlanFor = (id) => `${MUTATION_TMP_DIR}/diff-plan-${id}.json`;
export const diffJsonReportFor = (id) => `${MUTATION_TMP_DIR}/diff-report-${id}.json`;
