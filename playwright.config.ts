import { defineConfig, devices } from '@playwright/test';
import { resolveDevPort } from './packages/client/vite.config.helpers';
// Extensionless on purpose, like the import above: Playwright loads this config
// through a CommonJS require path, and its TypeScript loader resolves the `.ts`
// source from a bare specifier.
import { PINNED_LOCALE, PINNED_TZ, SEED } from './tests/harness/determinism';

/**
 * Playwright E2E test configuration for H-Vault.
 *
 * Tests run against the full stack (server + client) to verify critical
 * security flows: registration, login, 2FA, vault CRUD, and lock/unlock.
 *
 * Usage:
 *   npx playwright test            # Run all E2E tests
 *   npx playwright test --ui       # Run with UI mode
 *   npx playwright test --headed   # Run with visible browser
 */

/**
 * The client dev-server port, resolved from the SAME helper Vite uses, so the
 * probe URL below and the server Vite actually binds can never disagree (a
 * mismatch shows up as an unexplained 180s "Timed out waiting from
 * config.webServer"). Override both at once with `VITE_PORT`.
 */
const CLIENT_PORT = resolveDevPort();
const CLIENT_ORIGIN = `http://127.0.0.1:${String(CLIENT_PORT)}`;

/**
 * The gate surface's report. Deliberately RELATIVE: Playwright resolves a
 * reporter's `outputFile` against the config's own directory, so this is already
 * anchored to the repository root rather than to `process.cwd()` — and it must
 * not be built from `import.meta.url`, because Playwright loads this file
 * through a CommonJS require path (the root package.json is not `type: module`)
 * and `import.meta` there is a syntax error that kills the whole E2E gate before
 * a single spec runs.
 */
const JUNIT_REPORT = '.testfortress/reports/junit-e2e.xml';

/**
 * The determinism pins, applied INSIDE the harness rather than as a
 * `TZ=UTC npx playwright test` prefix — this project is developed on Windows too,
 * where that prefix is not valid shell syntax, so a prefix-based pin is one half
 * the contributors silently do not get.
 *
 * This assignment covers the Playwright runner process and, by inheritance, the
 * dev server and the in-memory mongod that `e2e/start-server.ts` spawns. The
 * BROWSER is pinned separately, in `use` below: a Chromium context takes its
 * timezone and locale from launch options, not from the parent's environment, and
 * the browser is where the app's date rendering (secret expiry countdowns, the
 * vault-health "last checked" label) actually happens.
 */
process.env.TZ = PINNED_TZ;
process.env['LANG'] = PINNED_LOCALE;
process.env['LC_ALL'] = PINNED_LOCALE;
process.env['SEED'] = String(SEED);

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  // `junit` is unconditional: it is the report the pipeline reads, and a gate
  // whose only output is a terminal cannot be ratcheted or audited. `list`
  // streams progress, and the HTML report is pinned to `open: 'never'` — its
  // default (`on-failure`) launches a browser, which hangs a git hook forever.
  reporter: process.env.CI
    ? [['github'], ['junit', { outputFile: JUNIT_REPORT }]]
    : [['list'], ['html', { open: 'never' }], ['junit', { outputFile: JUNIT_REPORT }]],
  timeout: 30_000,
  expect: {
    timeout: 10_000,
  },
  use: {
    baseURL: process.env.E2E_BASE_URL ?? CLIENT_ORIGIN,
    // The browser's own clock zone and locale. `PINNED_TZ` is an IANA id, which is
    // exactly what `timezoneId` wants; `locale` cannot take `C.UTF-8` (not a BCP-47
    // tag), so it is the app's single shipped language. Without these two the
    // browser follows the host, and every rendered date — the secret-expiry
    // countdown, the "last checked" label — becomes a function of where the
    // machine is, which is how a date assertion passes in Berlin and fails in Denver.
    timezoneId: PINNED_TZ,
    locale: 'en-US',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  // An explicit `webServer: undefined` is not assignable under
  // `exactOptionalPropertyTypes`, so drop the key entirely when the caller
  // points the run at an already-running stack via `E2E_BASE_URL`.
  ...(process.env.E2E_BASE_URL
    ? {}
    : {
        webServer: {
          command: 'npx tsx e2e/start-server.ts',
          url: `${CLIENT_ORIGIN}/api/v1/health`,
          reuseExistingServer: !process.env.CI,
          timeout: 180_000,
        },
      }),
});
