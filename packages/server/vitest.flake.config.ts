import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';
import baseConfig from './vitest.config.js';

/**
 * The vitest configuration `test:flake` drives for this package's leg.
 *
 * It NARROWS NOTHING, for the same reason `vitest.mutation.config.ts` narrows
 * nothing: the question is whether the suite that runs on every push has a
 * verdict independent of order, and a flake hunt over a subset would answer a
 * question nobody asked. `include` and `exclude` are inherited untouched and
 * `gate-surface.test.ts` asserts that both still equal the base config's.
 *
 * Two things are removed, and BOTH are required for correctness rather than for
 * speed:
 *
 *   - **The JUnit report is redirected**, never suppressed. `test:flake` runs
 *     this suite ten times; pointed at `junit-server.xml` it would overwrite the
 *     artifact `audit:ratchet:full` reads this package's test count from, and
 *     leave the TENTH run's result standing in for `test:unit`'s evidence. It is
 *     redirected rather than dropped because the gate parses it after every run
 *     to name the tests that failed — a flake report that says "run 7 failed"
 *     without saying WHAT failed is a bug report nobody can act on.
 *
 *     A CLI override was tried first and does not work: an explicit
 *     `outputFile` inside a configured reporter tuple wins over
 *     `--outputFile.junit=…`, measured, so the run still wrote `junit-server.xml`.
 *     Hence a config file.
 *
 *   - **Coverage is disabled.** Ten instrumented runs would race the real run's
 *     `coverage/.tmp` directory (the failure `VITEST_COVERAGE_DIR` exists for)
 *     and would overwrite the LCOV document `audit:ratchet:full` reads the
 *     measured file set from. This is not a coverage gate and never was:
 *     `test:integration` enforces the thresholds on every push and keeps doing so.
 *
 * `root` is pinned for the same reason the mutation config pins it: vitest
 * resolves `root` from the CWD, and a gate that invoked this config from the
 * repository root would otherwise scan the wrong tree.
 *
 * The SEED is deliberately NOT set here. The gate varies the ORDER seed per run
 * with `--sequence.seed=<n>` (which does override the config, measured) while
 * leaving the DATA seed at its pinned value, so ten runs differ in order alone.
 */
const baseTest = baseConfig.test!;

/** Redirected, not suppressed — see the note above. */
const junitReporter: ['junit', { outputFile: string }] = [
  'junit',
  {
    outputFile: path.resolve(
      path.dirname(fileURLToPath(import.meta.url)),
      '../../.testfortress/reports/junit-flake-server.xml',
    ),
  },
];

export default defineConfig({
  ...baseConfig,
  test: {
    ...baseTest,
    root: path.dirname(fileURLToPath(import.meta.url)),
    // `dot` rather than `default`: ten runs of the per-file listing is thousands
    // of lines of noise around the one thing this gate reports.
    reporters: ['dot', junitReporter],
    coverage: { ...baseTest.coverage, enabled: false },
  },
});
