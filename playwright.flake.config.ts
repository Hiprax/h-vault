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
 * For the same reason `projects` is INHERITED rather than pinned, which is the
 * opposite choice to the accessibility config beside it and is deliberate: the
 * base config runs a Chromium project over every spec and a Firefox project over
 * the clipboard and auto-lock specs, so inheriting both is what keeps this leg a
 * measurement of the gate. A second engine is also where a flake rate is most
 * likely to differ, because the two specs it runs turn on clipboard activation
 * and visibility policy rather than on application logic.
 * `flake.e2eExecutions` is ratcheted higher-is-better, so those extra executions
 * raise the floor rather than needing a baseline edit — but they DO spend wall
 * clock inside `E2E_DEADLINE_MS` in `scripts/ci/flake-run.mjs`, which is the
 * number to look at first if this leg ever reports exit 124.
 *
 * ## The three settings that are pinned rather than inherited
 *
 * 1. **`repeatEach: 3`.** Declared here rather than passed as `--repeat-each=3`
 *    on the command line, because a flag is something a future edit of the gate
 *    can drop silently while the gate keeps reporting a flake rate. Three
 *    executions per test is the sample; one is the thing this phase exists to
 *    say is not a measurement.
 *
 * 2. **`retries: 0`, unconditionally.** The base config pins the same value today,
 *    but it once computed `process.env.CI ? 2 : 0` — and this leg's verdict is
 *    precisely "does a test pass on its FIRST attempt, every time", so it must not
 *    be one environment variable away from being a lie even if the base drifts.
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

/**
 * The project name has to reach the report here for the same reason it does in the
 * base config, and it matters MORE in this leg: `scripts/ci/flake-run.mjs` names
 * the tests that failed by `classname › name`, read straight out of this file, and
 * without the prefix two engines' runs of the same spec are one indistinguishable
 * name. A flake report that cannot say which engine flaked is a flake report about
 * nothing.
 */
const JUNIT_OPTIONS = { outputFile: JUNIT_REPORT, includeProjectInTestName: true };

/** Executions per test. Named so the gate's report and this config cannot disagree. */
export const FLAKE_REPEAT_EACH = 3;

export default defineConfig({
  ...base,
  repeatEach: FLAKE_REPEAT_EACH,
  retries: 0,
  forbidOnly: true,
  reporter: [['list'], ['junit', JUNIT_OPTIONS]],
});
