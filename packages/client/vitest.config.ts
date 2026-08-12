import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import { SEED, PINNED_LOCALE, PINNED_TZ } from './tests/determinism.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

// Vitest's default resolve conditions exclude 'browser', so a bare
// `@hiprax/crypto` import would load the package's Node build (`dist/index.js`,
// 128 MiB Argon2id default, Node-only file methods). Production ships the
// BROWSER build (`dist/index.browser.js`, 32 MiB default, SubtleCrypto +
// hash-wasm). A scoped alias — computed from the resolved package location so
// it works regardless of npm hoisting — makes the client test runner exercise
// the exact build users get. (A global `resolve.conditions: ['browser']` is
// both unreliable for externalized deps and over-broad, so we alias only this
// one package.) hash-wasm is a pure-WASM dependency of the browser build and
// resolves normally under jsdom.
const hipraxCryptoBrowserBuild = path.join(
  path.dirname(require.resolve('@hiprax/crypto/package.json')),
  'dist/index.browser.js',
);

// Where V8 coverage is written. Two `vitest run --coverage` invocations that
// share a `reportsDirectory` race on its `.tmp` scratch folder — one clears or
// recreates it while the other is still reading, producing the fatal
// "Something removed the coverage directory" unhandled rejection. This happens
// whenever a secondary (out-of-band) verification gate runs alongside the
// primary one. `VITEST_COVERAGE_DIR`, when set, gives each run an isolated
// directory; unset, it resolves to the canonical `<pkg>/coverage` that CI's
// artifact upload consumes (identical to Vitest's default — no behavior change).
const coverageDir = process.env.VITEST_COVERAGE_DIR
  ? path.resolve(process.env.VITEST_COVERAGE_DIR, 'client')
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
  { outputFile: path.resolve(__dirname, '../../.testfortress/reports/junit-client.xml') },
];

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      'virtual:pwa-register/react': path.resolve(
        __dirname,
        'tests/__mocks__/virtual-pwa-register-react.ts',
      ),
      '@hiprax/crypto': hipraxCryptoBrowserBuild,
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./tests/setup.ts'],
    testTimeout: 15_000,
    css: false,
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
      include: ['src/**/*.ts', 'src/**/*.tsx'],
      // Only the DOM entry point is excluded. The API wrappers were previously
      // hidden as "thin axios wrappers with no business logic", but the request
      // they build IS their contract — a wrong verb, URL or payload shape is a
      // real, shippable bug — so they are measured and asserted like any other
      // module. The three 5-line page re-exports are likewise cheap to measure
      // honestly rather than exclude.
      exclude: [
        'src/**/*.d.ts',
        'src/**/*.test.ts',
        'src/**/*.test.tsx',
        // Process entry point: calls ReactDOM.createRoot against a real #root
        // node as an import side effect. Nothing to assert that the build does
        // not already prove.
        'src/main.tsx',
        // Web Worker thread entry points. jsdom has no `Worker`, so these files
        // never execute under the test runner (the analyzer takes its main-thread
        // fallback). They are deliberately thin wires — `onmessage -> scorePasswords
        // -> postMessage` — with every unit of real logic living in the directly
        // tested pure modules they import. Measuring them would only report a
        // structurally-unreachable 0%, exactly like `main.tsx`.
        'src/**/*.worker.ts',
      ],
      thresholds: {
        lines: 90,
        functions: 90,
        branches: 90,
        statements: 90,
      },
    },
  },
});
