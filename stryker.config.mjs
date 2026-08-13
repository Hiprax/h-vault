/**
 * Stryker configuration — the `test:mutation` gate's subject.
 *
 * ONE config file, parameterised by `HVAULT_MUTATION_LEG`, because Stryker's
 * Vitest runner takes exactly one vitest config and this repository has three
 * suites with three different environments. `scripts/ci/mutation-gate.mjs` runs
 * one leg per package and merges the three reports; running a leg by hand is
 *
 *     HVAULT_MUTATION_LEG=shared npx stryker run
 *
 * The scope itself lives in `scripts/ci/lib/mutation-scope.mjs` and is imported
 * rather than restated here, so the gate, the ratchet and this file can never
 * disagree about what is being mutated. That is also why this is `.mjs` and not
 * the `.json` a default `stryker init` writes: a JSON config would be a second
 * copy of the denominator.
 *
 * Not configured, deliberately:
 *   - `thresholds.break`. The floor is `.testfortress/baseline.json`'s
 *     `mutation.overall`, enforced per leg AND overall by the gate, so there is
 *     exactly one place the number lives and it is the one the ratchet reads.
 *     A `break` here would be a second, hand-maintained copy of it.
 *   - a dashboard reporter. Every gate in this repository runs locally and
 *     reports locally; nothing uploads.
 */
import {
  MUTATION_LEGS,
  MUTATION_LEG_IDS,
  MUTATION_TMP_DIR,
  incrementalFileFor,
  jsonReportFor,
} from './scripts/ci/lib/mutation-scope.mjs';

const requested = process.env['HVAULT_MUTATION_LEG'];
const named = MUTATION_LEGS.find((candidate) => candidate.id === requested);
if (requested !== undefined && !named) {
  throw new Error(
    `stryker.config.mjs: HVAULT_MUTATION_LEG must be one of ${MUTATION_LEG_IDS.join(', ')}, ` +
      `got ${JSON.stringify(requested)}.`,
  );
}
// An UNSET variable falls back to the first leg and says so, loudly, rather than
// throwing. A throw here would be the tidier-looking choice and it is the wrong
// one: this file is a config that tools LOAD in order to read it — knip's Stryker
// plugin imports it to discover which runner package is in use, and a config that
// refuses to load turns both Stryker dependencies into "unused devDependency"
// findings and the `deadcode` gate red. The fallback is safe because it can only
// under-report: a bare `npx stryker run` measures one leg and writes
// `.stryker-tmp/report-<leg>.json`, and nothing downstream reads that — the
// merged `mutation.json` every other gate consumes is written only by
// `mutation-gate.mjs`, which always names its leg.
const leg = named ?? MUTATION_LEGS[0];
if (!named) {
  process.emitWarning(
    `HVAULT_MUTATION_LEG is unset — running the "${leg.id}" leg only. ` +
      `The whole declared scope is \`npm run test:mutation\` (legs: ${MUTATION_LEG_IDS.join(', ')}).`,
  );
}

export default {
  // The report the gate reads. `html` is deliberately absent: it is a browser
  // artifact nothing in the pipeline consumes, and it costs a megabyte per leg.
  reporters: ['json', 'progress'],
  jsonReporter: { fileName: jsonReportFor(leg.id) },
  testRunner: 'vitest',
  vitest: { configFile: leg.vitestConfig },
  mutate: leg.mutate,
  // Incremental mode is what makes this gate re-runnable at all: the first run
  // over ~53,000 lines of source is hours, and every later run re-tests only
  // the mutants whose code — or whose killing test — actually changed.
  // `--force` (the gate's `--full`) rebuilds it from nothing.
  incremental: true,
  incrementalFile: incrementalFileFor(leg.id),
  tempDirName: `${MUTATION_TMP_DIR}/sandbox-${leg.id}`,
  concurrency: leg.concurrency,
  // MEASURED, not ignored — and this is the single most consequential line in
  // the file, because `ignoreStatic: true` removes a mutant from the SCORE'S
  // DENOMINATOR rather than merely from the run.
  //
  // A "static" mutant is one whose code executes while the module is being
  // loaded rather than inside a test. In this codebase that is not an edge
  // case, it is the security contract: every Zod bound is built at module
  // scope, so `.max(100)` → `.max(101)` on `authHash` is a static mutant.
  // Measured on the first run of the `shared` leg, `ignoreStatic: true`
  // discarded 684 of 2,008 mutants — 249 of them in `schemas/vault.ts` and 212
  // in `schemas/user.ts`, which are inside a module the plan gives the HIGHER
  // threshold to. `schemas/common.ts` reported one tested mutant against ten
  // ignored ones. A 90% score over a tenth of the schemas is not a measurement.
  //
  // The cost is real: a static mutant has no per-test coverage, so it is tested
  // against the whole suite. `bail` keeps that cheap for the ones that die and
  // expensive only for the ones that survive, which is the right way round.
  ignoreStatic: false,
  // Copying `.git`, the built output and the coverage directories into the
  // sandbox costs minutes per leg and changes nothing: no test reads them.
  // (`node_modules` is symlinked by Stryker itself and is not listed here.)
  ignorePatterns: [
    '.git',
    '.stryker-tmp',
    'packages/*/dist',
    'packages/*/coverage',
    'playwright-report',
    'test-results',
    'logs',
  ],
  // Long enough for a real mongod to start inside a mutant run, short enough
  // that a mutant which wedges an event loop is reported rather than waited on.
  // Stryker's timeout is `timeoutMS + timeoutFactor * <the dry run's time>`, so
  // this is added to a measured baseline rather than being the whole budget.
  timeoutMS: 60_000,
  timeoutFactor: 2,
  // The dry run boots the entire package suite once (a real mongod per file on
  // the server leg), which does not fit the 5-minute default.
  dryRunTimeoutMinutes: 30,
  disableTypeChecks: false,
};
