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

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    testTimeout: 10_000,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
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
