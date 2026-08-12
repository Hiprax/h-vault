import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

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
    testTimeout: 10_000,
    // `default` keeps the human output; `junit` is what the pipeline reads. A
    // suite whose only output is a terminal cannot be ratcheted or audited.
    reporters: ['default', junitReporter],
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
