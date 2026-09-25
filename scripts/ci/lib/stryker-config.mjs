/**
 * The Stryker configuration itself, as a function of the environment.
 *
 * `stryker.config.mjs` at the repository root is what Stryker loads, and it is
 * one line: this function applied to `process.env`. The function lives here so
 * the two gates that plan against it — `mutation-gate.mjs` and
 * `mutation-diff-gate.mjs` — and the gate-surface tests can read a configuration
 * WITHOUT evaluating the root file's default export, which warns when no leg is
 * named because a bare `npx stryker run` would measure one leg only.
 *
 * The rationale for every key is beside it below; the root file's header says
 * why the configuration is JavaScript and parameterised rather than a JSON file.
 */
import { readFileSync } from 'node:fs';
import {
  MUTATION_LEGS,
  MUTATION_LEG_IDS,
  MUTATION_TMP_DIR,
  diffJsonReportFor,
  incrementalFileFor,
  jsonReportFor,
} from './mutation-scope.mjs';

/**
 * The configuration for one leg, from an environment. Exported so the gate
 * surface can inspect BOTH modes without spawning Stryker; the default export
 * below is this function applied to the real environment, which is all Stryker
 * itself ever reads.
 *
 * Two modes, one file:
 *
 *   - the CAMPAIGN (`test:mutation`): the leg's whole declared scope,
 *     incremental, reporting to `.stryker-tmp/report-<leg>.json`.
 *   - the PER-CHANGE leg (`test:mutation:diff`), selected by
 *     `HVAULT_MUTATION_DIFF_PLAN` naming a plan file the gate wrote: exactly the
 *     plan's ranges, FROM SCRATCH (`incremental: false` — a cache is per-machine
 *     state no reviewer can see, and the doctrine forbids it inside this gate),
 *     reporting to `diff-report-<leg>.json` in its own sandbox so it can never
 *     overwrite the campaign's evidence or its incremental file. Everything else
 *     — above all `ignoreStatic: false` — is shared, because the per-change leg
 *     is the SAME oracle over fewer mutants, not a cheaper one.
 *
 * @param {Record<string, string | undefined>} env
 */
export function buildStrykerConfig(env) {
  const requested = env['HVAULT_MUTATION_LEG'];
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
  const planFile = env['HVAULT_MUTATION_DIFF_PLAN'];
  if (!named && planFile === undefined) {
    process.emitWarning(
      `HVAULT_MUTATION_LEG is unset — running the "${leg.id}" leg only. ` +
        `The whole declared scope is \`npm run test:mutation\` (legs: ${MUTATION_LEG_IDS.join(', ')}).`,
    );
  }
  const plan = planFile === undefined ? null : readDiffPlan(planFile, named);
  const config = campaignConfig(leg);
  if (!plan) return config;
  return {
    ...config,
    mutate: plan.mutate,
    jsonReporter: { fileName: diffJsonReportFor(leg.id) },
    incremental: false,
    incrementalFile: `${MUTATION_TMP_DIR}/incremental-diff-${leg.id}.json`,
    tempDirName: `${MUTATION_TMP_DIR}/sandbox-diff-${leg.id}`,
  };
}

/**
 * A per-change plan, refused unless it names the leg it is being run for and
 * carries at least one range. An empty `mutate` list would not mean "nothing":
 * it would fall through to Stryker's default, which mutates everything.
 */
function readDiffPlan(planFile, named) {
  if (!named) {
    throw new Error('stryker.config.mjs: a diff plan needs HVAULT_MUTATION_LEG to name its leg.');
  }
  const plan = JSON.parse(readFileSync(planFile, 'utf8'));
  if (plan?.leg !== named.id) {
    throw new Error(
      `stryker.config.mjs: the diff plan is for ${JSON.stringify(plan?.leg)}, not ${JSON.stringify(named.id)}.`,
    );
  }
  if (!Array.isArray(plan.mutate) || plan.mutate.length === 0) {
    throw new Error('stryker.config.mjs: the diff plan names no ranges to mutate.');
  }
  return /** @type {{ leg: string, mutate: string[] }} */ (plan);
}

/** The campaign's configuration for one leg; the per-change mode overrides five keys of it. */
const campaignConfig = (leg) => ({
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
  // expensive only for the ones that survive, which is the right way round —
  // but only because each leg's `vitest.mutation.config.ts` visits the test
  // files killer-first (`tests/harness/mutationSequencer.ts`). Under the base
  // configs' seeded file shuffle, which those configs inherited until then, a
  // dying static mutant still walked a random share of the suite before its
  // killer came up: MEASURED on one 47-file client plan, 8,753 tests for nine
  // static mutants, against 515 in the kill-seeking order with every verdict
  // unchanged. A SURVIVING static mutant runs every related test in any order,
  // which is why it is the costliest thing a change can leave behind.
  ignoreStatic: false,
  // Copying `.git`, the built output and the coverage directories into the
  // sandbox costs minutes per leg and changes nothing: no test reads them.
  // (`node_modules` is symlinked by Stryker itself and is not listed here.)
  //
  // `.cache` is the biggest of them by two orders of magnitude and was the one
  // missing: it is the local pipeline's scratch space, and on a machine that has
  // run `sast` even once it holds the CodeQL bundle and its database — MEASURED
  // at 3.1 GB (2.5 GB bundle + 604 MB database) on the reference host. Stryker
  // copies the sandbox once per RUNNER, so that is ~9 GB per leg of pure
  // overhead. Worse than slow: `verify:selftest` caught it CRASHING the gate
  // outright with `EISDIR: copyfile … .cache/codeql`, which is how it was found.
  // `.dockerignore` excludes `**/.cache` for exactly this reason and says so.
  //
  // This changes what is COPIED, never what is MUTATED: the denominator comes
  // from the `mutate` globs above, which only ever name `packages/*/src/**`, and
  // `mutation.filesMutated` is ratcheted as a SUPERSET so a narrowed denominator
  // would fail the ratchet rather than pass quietly. Verified by re-running the
  // `shared` leg and confirming it still reports 2,469 mutants at 88.09 %.
  ignorePatterns: [
    '.git',
    '.stryker-tmp',
    '.cache',
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
});
