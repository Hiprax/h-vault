import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';
import baseConfig from './vitest.config.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * This package's leg of the `test:fuzz` gate: the seven import parsers, driven
 * with arbitrary bytes, hostile documents and a committed corpus.
 *
 * Every file here also runs under `test:unit`, which is the whole client suite —
 * so this narrows NOTHING. It exists for the same reason `test:security` and
 * `test:property` do: "no import file, however hostile, crashes a parser, hangs
 * it, or produces an item its own schema rejects" is a claim someone has to be
 * able to point at when a parser is touched, and that claim needs a gate that
 * can fail on its own.
 *
 * The membership is declared HERE rather than as positional filters on the
 * command line: a config that names its files is a suite definition, whereas a
 * filter on a runner invocation is the shape the integrity doctrine forbids.
 * `gate-surface.test.ts` asserts every entry exists on disk, because vitest
 * exits non-zero only when the include set matches NOTHING — a list that has
 * gone stale in part would otherwise shrink this gate in silence.
 */
export const CLIENT_FUZZ_SUITE = ['tests/fuzz/parsers.fuzz.test.ts'];

/**
 * Its OWN JUnit report. Pointed at `junit-client.xml` it would overwrite the
 * artifact `audit:ratchet:full` reads the client package's test count from, and
 * a subset's count would then be ratcheted as the whole suite's.
 *
 * This report is deliberately NOT declared in `.testfortress/verify.json`; see
 * the header of `scripts/ci/fuzz-gate.mjs` for why a T2 gate's JUnit must stay
 * undeclared.
 */
const junitReporter: ['junit', { outputFile: string }] = [
  'junit',
  {
    outputFile: path.resolve(__dirname, '../../.testfortress/reports/junit-fuzz-client.xml'),
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
    include: CLIENT_FUZZ_SUITE,
    reporters: ['default', junitReporter],
    // A million-column row and a fifty-thousand-row bomb are seconds each,
    // seven parsers over. The per-test budgets inside the suite are the real
    // assertion; this only has to be larger than they are.
    testTimeout: 180_000,
    // No coverage from this run. The percentages belong to `test:unit`, which
    // runs these same files inside the whole suite; a second `--coverage` run
    // over one file would report a number about nothing and race the first run's
    // `.tmp` scratch directory (see `coverageDir` in the base config).
    coverage: { ...baseTest.coverage, enabled: false },
  },
});
