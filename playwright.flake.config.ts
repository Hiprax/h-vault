import { defineConfig } from '@playwright/test';
import base from './playwright.config';

/**
 * `test:flake`'s end-to-end leg — the whole Playwright suite, every spec run
 * three times, with retries pinned OFF.
 *
 * The same shape as `playwright.a11y.config.ts`: a second, separately-reported
 * invocation of a suite that already runs, narrowing nothing. There is no
 * `testMatch` here and there must never be one — this leg's whole claim is
 * about the suite `test:e2e` runs, and a filtered version of it would be a
 * flake measurement of something other than the gate it describes.
 *
 * ## The three settings that are pinned rather than inherited
 *
 * 1. **`repeatEach: 3`.** Declared here rather than passed as `--repeat-each=3`
 *    on the command line, because a flag is something a future edit of the gate
 *    can drop silently while the gate keeps reporting a flake rate. Three
 *    executions per test is the sample; one is the thing this phase exists to
 *    say is not a measurement.
 *
 * 2. **`retries: 0`, unconditionally.** The base config computes
 *    `process.env.CI ? 2 : 0`, which is 0 for every local run today — but this
 *    leg's verdict is precisely "does a test pass on its FIRST attempt, every
 *    time", so it must not be one environment variable away from being a lie.
 *    `e2e/helpers.ts` records that the retry count this pipeline's E2E gate used
 *    to carry concealed two genuine failures; a retried flake measurement would
 *    conceal them again, and this time silently.
 *
 * 3. **`forbidOnly: true`, unconditionally.** Same argument from the other side:
 *    a stray `.only` shrinks the suite to one test, and three green executions
 *    of one test would be reported as a clean sample of two hundred. `test:e2e`
 *    passes `--forbid-only` as a flag; here it is a property of the config,
 *    because this gate is the one that would be most convincingly wrong.
 *
 * ## Its own report, and no HTML reporter
 *
 * Pointed at `junit-e2e.xml` this would overwrite the E2E gate's evidence, which
 * `audit:ratchet:full` reads the end-to-end headcount from — the failure
 * `playwright.a11y.config.ts` records. The HTML reporter is dropped for the same
 * reason it is dropped there: a second run would replace `playwright-report/`
 * with this one, so an investigation would open the wrong artifact.
 */
const JUNIT_REPORT = '.testfortress/reports/junit-flake-e2e.xml';

/** Executions per test. Named so the gate's report and this config cannot disagree. */
export const FLAKE_REPEAT_EACH = 3;

export default defineConfig({
  ...base,
  repeatEach: FLAKE_REPEAT_EACH,
  retries: 0,
  forbidOnly: true,
  reporter: [['list'], ['junit', { outputFile: JUNIT_REPORT }]],
});
