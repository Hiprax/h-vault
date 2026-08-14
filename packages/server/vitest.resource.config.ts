import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';
import baseConfig from './vitest.config.js';
import { RESOURCE_SCENARIOS } from '../../scripts/ci/lib/resource-budgets.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * This package's `test:resource` gate: the volume and memory budgets.
 *
 * The membership comes from `scripts/ci/lib/resource-budgets.mjs`, the same
 * module the scenarios read their ceilings from and the gate reads its expected
 * report list from — so "which files are in this suite" has one definition.
 * vitest errors only on an EMPTY match, so a half-stale hardcoded list would
 * shrink this gate in silence.
 */
export const RESOURCE_SUITE = RESOURCE_SCENARIOS.map((scenario) => scenario.file);

/**
 * Its OWN JUnit report, for the same reason as every other subset gate: pointed
 * at `junit-server.xml` it would overwrite the artifact `audit:ratchet:full`
 * reads the server package's test count from.
 *
 * Deliberately NOT declared in `.testfortress/verify.json` — `test:resource` is
 * Tier 2, so it does not run during `npm run ci`, and a declared-but-absent
 * report makes `tests.count` UNMEASURED on every push. The same rule
 * `fuzz-gate.mjs` records. `resource.json` is the declared artifact.
 */
const junitReporter: ['junit', { outputFile: string }] = [
  'junit',
  {
    outputFile: path.resolve(__dirname, '../../.testfortress/reports/junit-resource.xml'),
  },
];

const baseTest = baseConfig.test!;

export default defineConfig({
  ...baseConfig,
  test: {
    ...baseTest,
    include: RESOURCE_SUITE,
    // The base config excludes `tests/resource/**` so the push tier does not run
    // these, and `...baseTest` above inherits that exclusion — which would cancel
    // the `include` right beside it and leave this gate running nothing. Restated
    // without that entry, so the one suite whose whole purpose is these files can
    // actually see them.
    exclude: ['**/node_modules/**', '**/dist/**'],
    reporters: ['default', junitReporter],
    coverage: { ...baseTest.coverage, enabled: false },
    /**
     * The scenarios run ONE AT A TIME, and this is the only suite in the
     * repository where that is a requirement rather than a way to dodge a race.
     *
     * What these files measure is wall-clock duration and peak RSS. Run three at
     * once on a four-core machine, each with its own mongod and its own
     * 10,000-row vault, and every duration reflects the contention rather than
     * the code — which turns a budget into a coin toss, and a coin toss into a
     * deleted gate. Nothing here shares state: each file has its own mongod, its
     * own user and its own vault, and the base config's `sequence.shuffle` is
     * inherited and still reorders these files. What is serialized is the
     * MEASUREMENT, not the isolation.
     *
     * The base config's warning against `fileParallelism: false` still stands
     * everywhere else, and for the reason it gives: in a correctness suite,
     * single-worker execution hides shared state instead of fixing it.
     */
    fileParallelism: false,
  },
});
