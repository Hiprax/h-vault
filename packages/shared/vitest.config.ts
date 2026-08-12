import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';
import { SEED, PINNED_LOCALE, PINNED_TZ } from './tests/determinism.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Isolate V8 coverage output when a secondary (out-of-band) gate runs alongside
// the primary one: two `vitest run --coverage` invocations sharing a
// `reportsDirectory` race on its `.tmp` scratch folder and crash with
// "Something removed the coverage directory". `VITEST_COVERAGE_DIR`, when set,
// gives each run its own directory; unset, it resolves to the canonical
// `<pkg>/coverage` that CI's artifact upload consumes (Vitest's default — no
// behavior change).
const coverageDir = process.env.VITEST_COVERAGE_DIR
  ? path.resolve(process.env.VITEST_COVERAGE_DIR, 'shared')
  : path.resolve(__dirname, 'coverage');

// The gate surface's report directory (`.testfortress/reports`), resolved from
// this file rather than from `process.cwd()` so the JUnit report lands in the
// same place whether the suite is run from the package or from the repo root.
// The tuple is annotated rather than inferred: an unannotated `['junit', {…}]`
// inside an array literal widens to `(string | {…})[]`, which does not match
// vitest's reporter tuple type — and the resulting error is reported against
// an unrelated property further down the config.
const junitReporter: ['junit', { outputFile: string }] = [
  'junit',
  { outputFile: path.resolve(__dirname, '../../.testfortress/reports/junit-shared.xml') },
];

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    setupFiles: ['./tests/setup.ts'],
    testTimeout: 10_000,
    // `default` keeps the human output; `junit` is what the pipeline reads. A
    // suite whose only output is a terminal cannot be ratcheted or audited.
    reporters: ['default', junitReporter],
    // Order independence is a property of the suite, so it is MEASURED on every
    // run rather than hoped for. Shuffling files exposes cross-file state;
    // shuffling tests (which reorders `describe` blocks within a file too)
    // exposes the in-file kind. The seed is pinned so a failing order is
    // reproducible: an unseeded shuffle turns a real defect into an anecdote.
    // Never "fix" a failure here by switching this off (Forbidden Action 7) — a
    // suite that only passes in declaration order is a suite with an undeclared
    // dependency.
    sequence: {
      shuffle: true,
      seed: SEED,
      // Pinned rather than inherited: `'stack'` is the resolved default, but
      // Vitest's CLI help advertises `(default: "parallel")`, and teardown order
      // is something a suite should decide rather than discover. Kept identical
      // across the three packages so a hook behaves the same wherever it lives.
      hooks: 'stack',
    },
    // The determinism pins, in the config so they apply before the first module
    // of a test file is evaluated, and NOT as a `TZ=UTC npm test` prefix: this
    // project is developed on Windows too, where that prefix is not valid shell
    // syntax, so a prefix-based pin is one half the contributors silently do not
    // get. `tests/setup.ts` re-applies them (see `tests/determinism.ts`), and
    // `tests/determinism.test.ts` asserts both halves are present. `LC_ALL` is
    // pinned alongside `LANG` because glibc and ICU resolve `LC_ALL` first.
    env: {
      TZ: PINNED_TZ,
      LANG: PINNED_LOCALE,
      LC_ALL: PINNED_LOCALE,
      SEED: String(SEED),
    },
    coverage: {
      // `cobertura` sits beside lcov because patch-coverage tooling reads
      // Cobertura XML and nothing here should have to re-derive it from lcov.
      provider: 'v8',
      reporter: ['text', 'lcov', 'cobertura'],
      reportsDirectory: coverageDir,
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.d.ts', 'src/**/*.test.ts', 'src/generated/**', 'src/types/**'],
      thresholds: {
        lines: 95,
        functions: 95,
        branches: 90,
        statements: 95,
      },
    },
  },
});
