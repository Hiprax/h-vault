import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';
import baseConfig from './vitest.config.js';
import { propertyJunitReport } from '../../tests/harness/propertyReport.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * This package's leg of the `test:property` suite: the folder-graph model.
 *
 * Every file here also runs under `test:integration`, which is the whole server
 * suite — so this narrows NOTHING. It exists for the same two reasons
 * `test:security` does: "no sequence of folder operations can produce a cycle or
 * a chain deeper than the cap, and `hasCycle` agrees with a hand-checked
 * reference" deserves a gate a reviewer can point at when a guard in
 * `folderController` is refactored, and that gate must be able to fail on its
 * own.
 *
 * The membership is declared HERE rather than as positional filters on the
 * command line: a config that names its files is a suite definition, whereas a
 * filter on a runner invocation is the shape the integrity doctrine forbids.
 *
 * The list is kept honest by `gate-surface.test.ts`, which asserts every entry
 * exists on disk. Vitest itself is NOT that guard: it exits non-zero only when
 * the include set matches NOTHING, so renaming one file would leave the others
 * running and this gate quietly smaller.
 */
export const SERVER_PROPERTY_SUITE = ['tests/property/folderGraph.property.test.ts'];

/**
 * Its OWN JUnit report, per package AND per zone — see
 * `tests/harness/propertyReport.ts`. Pointed at the package's own
 * `junit-server.xml` it would overwrite the artifact `audit:ratchet:full` reads
 * the server package's test count from, and a subset's count would then be
 * ratcheted as the whole suite's.
 */
const junitReporter: ['junit', { outputFile: string }] = [
  'junit',
  {
    outputFile: path.resolve(
      __dirname,
      '../../.testfortress/reports',
      propertyJunitReport('server'),
    ),
  },
];

const baseTest = baseConfig.test!;

export default defineConfig({
  ...baseConfig,
  test: {
    ...baseTest,
    // Assigned, never merged: `mergeConfig` concatenates arrays, which would
    // leave the base's default include beside this one (running the whole suite)
    // and two JUnit reporters writing two files.
    include: SERVER_PROPERTY_SUITE,
    reporters: ['default', junitReporter],
    // No coverage from this run. The percentages belong to `test:integration`, which
    // runs these same files inside the whole suite; a second `--coverage` run
    // over one file would report a number about nothing and race the first
    // run's `.tmp` scratch directory (see `coverageDir` in the base config).
    coverage: { ...baseTest.coverage, enabled: false },
  },
});
