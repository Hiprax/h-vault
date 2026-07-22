import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

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
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
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
