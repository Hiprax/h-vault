import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';
import baseConfig from './vitest.config.js';

/**
 * The vitest configuration Stryker's runner drives for the `server` leg of
 * `test:mutation`.
 *
 * It NARROWS NOTHING. `include` is inherited untouched, because the whole point
 * of the oracle is to ask the suite that runs on every push whether it asserts
 * anything — a mutation run against a subset would answer a question nobody
 * asked. Two things are removed and both are pure plumbing:
 *
 *   - the JUnit reporter. Stryker re-runs the suite once per mutant, so this
 *     config would rewrite `.testfortress/reports/junit-server.xml` thousands of
 *     times and leave the LAST MUTANT'S RUN behind as the artifact
 *     `audit:ratchet:full` reads the package's test count from.
 *   - coverage. Stryker's runner disables the collector anyway (it installs its
 *     own per-test coverage), and leaving it enabled would race the real run's
 *     `coverage/.tmp` directory.
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
    reporters: ['dot'],
    coverage: { ...baseTest.coverage, enabled: false },
  },
});
