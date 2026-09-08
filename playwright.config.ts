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
 * `includeProjectInTestName` is NOT the reporter's default, and this run needs it.
 *
 * With two engine projects over the same files, the JUnit report otherwise holds
 * two `<testsuite name="clipboard-hygiene.spec.ts">` elements whose only
 * difference is a `hostname` attribute that nothing here reads — so a failing test
 * name, which is what `scripts/ci/flake-run.mjs` reports and what an investigation
 * starts from, would not say which engine produced it. With it on, every name
 * carries its `[chromium]` or `[firefox]` prefix and the artifact says what the
 * terminal said.
 */
const JUNIT_OPTIONS = { outputFile: JUNIT_REPORT, includeProjectInTestName: true };

/**
 * The specs that run on a SECOND engine, and the reason there are exactly two.
 *
 * Everything else this suite asserts is application behaviour — a form validates,
 * a route redirects, ciphertext leaves the browser sealed — and those answers do
 * not change with the engine rendering them. These two do, because both are built
 * on platform policy that Chromium and Gecko implement DIFFERENTLY:
 *
 *  - `clipboard-hygiene.spec.ts` drives `services/clipboard/clipboardService.ts`,
 *    whose entire refusal-retry state machine exists because a browser may refuse
 *    a clipboard write outright: Chromium gates it on a Permissions API entry and
 *    on document focus, Gecko and WebKit on TRANSIENT USER ACTIVATION for every
 *    write. The permission is the visible difference — Gecko has no such name and
 *    Playwright rejects it — and the spec's `grantClipboardWrite` is the one line
 *    that has to know about it. What a second engine buys beyond that is a second
 *    independent set of platform rules over the same guard, which is the only way
 *    to find out that a claim made about one of them is not a claim about the
 *    others: this leg is how the "Chromium is the permissive case" reading was
 *    measured wrong, since the deadline erase is refused on BOTH.
 *  - `auto-lock.spec.ts` turns on page visibility, on `document.hidden`, and on
 *    whether a virtual clock's fast-forward fires the timers the guard armed —
 *    all of which are engine-owned.
 *
 * Adding the other nineteen specs would roughly double the gate's executions to
 * re-assert answers that do not vary, so the scope is deliberately narrow and
 * stated here rather than inferred from a glob.
 */
export const FIREFOX_SUITE = ['clipboard-hygiene.spec.ts', 'auto-lock.spec.ts'] as const;

/**
 * The two engine projects, exported because the derived configs must choose
 * between them EXPLICITLY.
 *
 * A `TestProject.testMatch` overrides a top-level `testMatch`, so a config that
 * spreads this one and narrows its file set — `playwright.a11y.config.ts` does
 * exactly that — would still pick up the Firefox project's own two specs and
 * silently report four tests as two. Naming the projects makes that choice a line
 * of code in each derived config instead of a surprise.
 */
export const CHROMIUM_PROJECT = {
  name: 'chromium',
  use: { ...devices['Desktop Chrome'] },
};

/**
 * The cross-browser leg.
 *
 * It is a PROJECT inside this config rather than a separate config with its own
 * gate id, for two reasons and one constraint.
 *
 * The constraint: `e2e/start-server.ts` binds MongoDB on the fixed port 27017, one
 * dev server on one port, and one storage-engine container, so no two Playwright
 * runs can be in flight at once. That does not forbid a second SEQUENTIAL gate —
 * `test:a11y` already is one — so it is a constraint on the shape rather than a
 * proof. The two reasons are proportionality and cost: standing the whole stack up
 * a second time (a bring-up this config budgets 420 s for) to re-run two of
 * twenty-one specs on another engine buys nothing, and a new gate id obliges a
 * `verify:selftest` defect case, a README gate-table row checked in both
 * directions, and a `gate-surface.test.ts` entry — machinery for a leg that is
 * already attributable without any of it.
 *
 * As a project it shares the single `webServer` below, and because the run is
 * single-worker and unparallelised it goes strictly after the Chromium project
 * against that same stack — no second server, no shared-state race.
 *
 * It is still its own reported leg. The console reporters prefix every title with
 * the project name for free, but the JUnit reporter does NOT: its
 * `includeProjectInTestName` defaults to false, so without it `junit-e2e.xml`
 * carries two identically-named suites distinguished only by a `hostname`
 * attribute nothing in this pipeline reads. `scripts/ci/flake-run.mjs` builds its
 * failing-test list from `classname › name`, so the flake gate could not have said
 * WHICH engine flaked — in the one leg where the two are most likely to differ.
 * The reporter below turns it on, which is what makes the attribution a property
 * of the artifact rather than of the terminal somebody happened to be watching.
 */
export const FIREFOX_PROJECT = {
  name: 'firefox',
  use: { ...devices['Desktop Firefox'] },
  testMatch: [...FIREFOX_SUITE],
};

/**
 * The determinism pins, applied INSIDE the harness rather than as a
 * `TZ=UTC npx playwright test` prefix — this project is developed on Windows too,
 * where that prefix is not valid shell syntax, so a prefix-based pin is one half
 * the contributors silently do not get.
 *
 * This assignment covers the Playwright runner process and, by inheritance, the
 * dev server and the in-memory mongod that `e2e/start-server.ts` spawns. The
 * BROWSER is pinned separately, in `use` below: a browser context takes its
 * timezone and locale from launch options, not from the parent's environment —
 * that is true of both engines in `projects` — and the browser is where the app's
 * date rendering (secret expiry countdowns, the vault-health "last checked"
 * label) actually happens.
 */
process.env.TZ = PINNED_TZ;
process.env['LANG'] = PINNED_LOCALE;
process.env['LC_ALL'] = PINNED_LOCALE;
process.env['SEED'] = String(SEED);

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  // PINNED AT ZERO, unconditionally, and the `process.env.CI ? 2 : 0` this
  // replaced was a live cheat rather than a theoretical one. `release.yml` runs
  // `npm run ci` on `ubuntu-latest`, where GitHub sets `CI=true` — so the one
  // hosted run whose whole purpose is to make "every published release was built
  // from a commit that passed" a FACT was the one run that retried its E2E
  // failures twice and reported the third attempt. A retry does not fix a race,
  // it hides it; `test:flake` is where the rate is measured instead.
  retries: 0,
  workers: 1,
  // `junit` is unconditional: it is the report the pipeline reads, and a gate
  // whose only output is a terminal cannot be ratcheted or audited. `list`
  // streams progress, and the HTML report is pinned to `open: 'never'` — its
  // default (`on-failure`) launches a browser, which hangs a git hook forever.
  reporter: process.env.CI
    ? [['github'], ['junit', JUNIT_OPTIONS]]
    : [['list'], ['html', { open: 'never' }], ['junit', JUNIT_OPTIONS]],
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
  projects: [CHROMIUM_PROJECT, FIREFOX_PROJECT],
  // An explicit `webServer: undefined` is not assignable under
  // `exactOptionalPropertyTypes`, so drop the key entirely when the caller
  // points the run at an already-running stack via `E2E_BASE_URL`.
  ...(process.env.E2E_BASE_URL
    ? {}
    : {
        webServer: {
          // `node --import tsx`, NOT `npx tsx`, and the difference is a leak
          // rather than a preference. Playwright waits for the process it
          // launched to close and then lets the run finish; `npx tsx <file>`
          // puts TWO wrappers in front of the harness, and the outer one closes
          // as soon as it has forwarded the signal — so the teardown below was
          // reported as "Terminated the WebServer" 102 ms after the signal, with
          // its `docker rm -f` still in flight and the harness then dying with
          // its parent. MEASURED: `[e2e] signal received, tearing down` printed,
          // `[e2e] teardown complete` never did, and a storage engine was left
          // running. Run this way the harness IS the launched process, so the
          // close Playwright waits for is the teardown's own.
          command: 'node --import tsx e2e/start-server.ts',
          url: `${CLIENT_ORIGIN}/api/v1/health`,
          reuseExistingServer: !process.env.CI,
          // RAISED from 180 s, and only in the direction that cannot hide a
          // defect. `e2e/start-server.ts` now does three things before the dev
          // server answers this URL: it starts an in-memory mongod, it starts the
          // real object-storage engine in a container, and it waits for that
          // engine to answer a HeadBucket through the server's own S3 client. On a
          // machine that has never pulled the pinned image, `docker run` fetches
          // it first — unbounded work that has nothing to do with this
          // application — and the engine's own readiness deadline is 60 s on top.
          // A budget is not a gate: expiring early would report a slow first pull
          // as "the stack never came up", while a longer one costs nothing on a
          // healthy run and only delays a genuine failure's report.
          timeout: 420_000,
          // WITHOUT THIS, PLAYWRIGHT SIGKILLS THE HARNESS AND EVERY RUN LEAKS.
          // MEASURED, in `node_modules/playwright/lib/runner/index.js`: the
          // webServer's `attemptToGracefullyClose` throws `skip graceful shutdown`
          // unless this key is set, and the fallback is
          // `process.kill(-pid, 'SIGKILL')` over the whole process group. Nothing
          // survives that — not the SIGTERM handler in `e2e/start-server.ts`, not
          // the dev server's `exit` handler, not the harness's synchronous
          // `process.on('exit')` last resort. So the teardown that file was
          // carefully written to perform never ran at all: `npm run ci` was
          // stranding a mongod dbPath under RAM-backed /tmp AND a storage-engine
          // container per run, twice over (`test:e2e` and `test:a11y`), on runs
          // that ended green.
          //
          // With it, the group gets SIGTERM and the existing teardown runs. The
          // timeout is the ceiling on that teardown before Playwright force-kills
          // anyway, so it is sized for the slowest honest one (`mongod.stop()`
          // plus `docker rm -f`, about two seconds) with room for a loaded
          // machine, and NEVER 0 — which this API reads as "wait for ever".
          gracefulShutdown: { signal: 'SIGTERM', timeout: 30_000 },
        },
      }),
});
