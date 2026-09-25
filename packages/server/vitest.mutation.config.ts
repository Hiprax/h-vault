import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';
import baseConfig from './vitest.config.js';
import { MutationRunLedger, mutationSequence } from '../../tests/harness/mutationSequencer.js';

/**
 * The vitest configuration Stryker's runner drives for the `server` leg of
 * `test:mutation`.
 *
 * It NARROWS NOTHING. `include` is inherited untouched, because the whole point
 * of the oracle is to ask the suite that runs on every push whether it asserts
 * anything — a mutation run against a subset would answer a question nobody
 * asked. Besides the pinned `root` (below), three things differ from the base
 * config, and all three are plumbing:
 *
 *   - the JUnit reporter. Stryker re-runs the suite once per mutant, so this
 *     config would rewrite `.testfortress/reports/junit-server.xml` thousands of
 *     times and leave the LAST MUTANT'S RUN behind as the artifact
 *     `audit:ratchet:full` reads the package's test count from.
 *   - coverage. Stryker's runner disables the collector anyway (it installs its
 *     own per-test coverage), and leaving it enabled would race the real run's
 *     `coverage/.tmp` directory.
 *   - the ORDER of the test FILES (`mutationSequence` and `MutationRunLedger`,
 *     from `tests/harness/mutationSequencer.ts`), with `cache: false` beside
 *     it. Stryker drives a single vitest worker that bails at the first
 *     failure, so a static mutant, which runs every related test, pays for
 *     every file ahead of its killer; under the base config's seeded file
 *     shuffle that was a random share of the suite per mutant. Here the files
 *     go killer-first, then direct importers of the mutated file, then
 *     cheapest-first. This is NOT the base config's order-independence check
 *     switched off: that check runs, unchanged, in the suite this config is
 *     derived from and ten times over in `test:flake`, and the file order here
 *     decides only how many passing files run before a failing one, never
 *     whether one fails, so it cannot change a verdict. Tests inside each file
 *     are still shuffled with the pinned seed. `cache: false` keeps vitest's
 *     per-machine results file out of the order and out of the run.
 *
 * `dot` rather than `default`, because the human-readable reporter's per-file
 * output is written once per mutant and drowns Stryker's progress bar.
 *
 * `root` is PINNED to this directory and that is the load-bearing line. Vitest
 * resolves `root` from the CWD, not from the config file, and Stryker runs from
 * the repository root (it must: several suites read `../../docker-compose.yml`
 * and `../../scripts/ci/**`, so a package-scoped sandbox would not contain the
 * files the dry run needs). Left to default, vitest scanned the whole sandbox
 * with its DEFAULT include, matched nothing through `--related`, and Stryker
 * exited with "No tests were executed" before testing a single mutant.
 */
const baseTest = baseConfig.test!;

export default defineConfig({
  ...baseConfig,
  test: {
    ...baseTest,
    root: path.dirname(fileURLToPath(import.meta.url)),
    reporters: ['dot', new MutationRunLedger()],
    coverage: { ...baseTest.coverage, enabled: false },
    sequence: mutationSequence(baseTest.sequence),
    cache: false,
  },
});
