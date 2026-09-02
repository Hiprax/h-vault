import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';
import baseConfig from './vitest.config.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * This package's `test:storage` gate: the storage port against a REAL engine.
 *
 * The membership is declared here rather than globbed, for the reason every
 * other named subset in this repository states: vitest errors only on an EMPTY
 * match, so a list that has gone stale in part shrinks a gate in silence.
 * `gate-surface.test.ts` compares this array against both the config's own
 * `include` and the files on disk, in both directions, so a suite cannot fall
 * between the two configs and be run by neither.
 */
export const STORAGE_SUITE = ['tests/storage/conformance.test.ts'];

/**
 * Its OWN JUnit report, for the same reason as every other subset gate: pointed
 * at `junit-server.xml` it would overwrite the artifact `audit:ratchet:full`
 * reads the server package's test count from.
 *
 * Deliberately NOT declared in `.testfortress/verify.json`. `storage.json` is the
 * declared artifact, and this one is written, read by the gate for its headcount,
 * and left undeclared — the rule `fuzz-gate.mjs`, `resource-gate.mjs` and
 * `recovery-gate.mjs` all record. Here the reason is the mirror image of theirs:
 * they are Tier 2 and a declared report would be permanently unmeasured on a
 * push, while this gate IS Tier 1 — but it carries `countsTests: false` because
 * these tests are its own and summing them into `tests.count` beside a JUnit
 * this suite rewrites would make the headcount depend on whether Docker was
 * running.
 *
 * The hook timeouts are inherited untouched. One container is started per FILE in
 * a `beforeAll` and is ready in about a second, but a machine that has never
 * pulled the image is fetching ~28 MB first — so the SUITE's own `beforeAll`
 * carries the longer explicit timeout rather than this config relaxing every hook
 * in the package for the sake of one of them.
 */
const junitReporter: ['junit', { outputFile: string }] = [
  'junit',
  {
    outputFile: path.resolve(__dirname, '../../.testfortress/reports/junit-storage.xml'),
  },
];

const baseTest = baseConfig.test!;

export default defineConfig({
  ...baseConfig,
  test: {
    ...baseTest,
    include: STORAGE_SUITE,
    // The base config excludes `tests/storage/**` so the push tier's ordinary
    // server suite does not try to start a container, and `...baseTest` above
    // inherits that exclusion — which would cancel the `include` right beside it
    // and leave this gate running nothing. Restated without that entry, so the
    // one suite whose whole purpose is these files can actually see them. The
    // same shape `vitest.resource.config.ts` carries, and for the same reason.
    exclude: ['**/node_modules/**', '**/dist/**'],
    reporters: ['default', junitReporter],
    // Disabled for the reason the flake and mutation configs give: an
    // instrumented run here would race the real run's `coverage/.tmp` directory
    // and overwrite the LCOV document `audit:ratchet:full` reads the measured
    // file set from. This is not a coverage gate — `s3Provider.ts` is covered on
    // every push by `tests/s3-provider.test.ts`, which mocks the SDK boundary,
    // and `test:integration` enforces the thresholds.
    coverage: { ...baseTest.coverage, enabled: false },
  },
});
