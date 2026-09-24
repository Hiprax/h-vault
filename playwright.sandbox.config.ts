import { defineConfig } from '@playwright/test';
import base, { CHROMIUM_PROJECT } from './playwright.config';

/**
 * `test:sandbox` — the isolated render document, rendered by a real browser
 * under the headers a deployment actually sends.
 *
 * Every other browser run in this repository drives the Vite dev server, which
 * has neither helmet nor Nginx: `/sandbox.html` arrives there with NO
 * Content-Security-Policy at all, so the tailored per-response policy in
 * `packages/server/src/config/sandboxCsp.ts` and the two headers scoped to
 * `sandbox-assets/` were proven over HTTP (`test:smoke`, `test:deploy`) and never
 * inside an engine. The risk that leaves is a policy correct on the wire that
 * still breaks a renderer — a `blob:` media source or a `data:` image refused by
 * a browser rule no HTTP assertion can see. This config closes it by pointing the
 * viewer specs at a server that sends the real headers:
 *
 *  - `scripts/ci/sandbox-gate.mjs` (push tier) stages the BUILT artifact exactly
 *    as `test:smoke` does, boots it in production mode beside a real mongod and
 *    the pinned object-storage engine, and runs this config against it;
 *  - `scripts/ci/deploy-drill.mjs` (release tier) runs it again through the
 *    Compose stack's one published port, where the inner Nginx serves
 *    `sandbox-assets/` from its own literal header set and adds its header floor
 *    to the proxied document.
 *
 * ## The target arrives through `E2E_BASE_URL`, and there is no fallback
 *
 * The base config drops its `webServer` whenever `E2E_BASE_URL` is set, and this
 * config drops it UNCONDITIONALLY: a run of these specs against a dev server it
 * started itself would be a green gate about the one server that sends none of
 * the headers in question. Without `E2E_BASE_URL` the base's dev-server origin is
 * left as the target and nothing is started there, so the run fails on its first
 * navigation — and if a dev server from an earlier run happens to be listening,
 * `sandbox-policy.prod.ts` fails on the very first preview, because it asserts the
 * policy the frame was actually served under.
 *
 * ## Three things this config must keep (the same three as the a11y config)
 *
 * 1. **`projects` pinned to Chromium alone.** A `TestProject.testMatch` REPLACES
 *    the top-level one rather than intersecting with it, so spreading the base and
 *    narrowing `testMatch` here is not enough: the Firefox project would ignore the
 *    narrowing and run the clipboard and auto-lock specs against the production
 *    server inside this gate. Naming the project is the fix.
 * 2. **Its own JUnit report, with the project in every test name.** Pointed at
 *    `junit-e2e.xml` it would overwrite the E2E gate's evidence, which
 *    `audit:ratchet:full` reads the headcount from. The Nginx leg writes a SECOND
 *    name (`HVAULT_SANDBOX_LEG=nginx`), so a release run keeps both.
 * 3. **No HTML reporter**, which would replace `playwright-report/` with this run.
 *
 * ## Why `sandbox-policy.prod.ts` has no `.spec.ts` suffix
 *
 * The base config has no `testMatch` of its own, so Playwright's default pattern
 * (`*.spec.ts`, `*.test.ts`) decides what `test:e2e` runs — and that file asserts
 * the production policy, which the dev server does not send. Named outside that
 * pattern, it is SELECTED here by name instead of being excluded there, so no
 * ignore list exists anywhere: `test:e2e` and `test:flake` are exactly the suites
 * they were.
 */
export const SANDBOX_SUITE = ['document-viewer.spec.ts', 'sandbox-policy.prod.ts'] as const;

/**
 * The two legs this config runs as, each with its own report. Exported so
 * `gate-surface.test.ts` can hold both names equal to the ones the two gates read
 * (`scripts/ci/lib/sandbox-browser.mjs`).
 */
export const SANDBOX_JUNIT_REPORTS = {
  express: '.testfortress/reports/junit-sandbox.xml',
  nginx: '.testfortress/reports/junit-sandbox-nginx.xml',
} as const;

const leg = process.env['HVAULT_SANDBOX_LEG'] === 'nginx' ? 'nginx' : 'express';

// No `webServer`, whatever the base carried: see the second section above.
const { webServer: _devServer, ...withoutDevServer } = base;

export default defineConfig({
  ...withoutDevServer,
  testMatch: [...SANDBOX_SUITE],
  projects: [CHROMIUM_PROJECT],
  reporter: [
    ['list'],
    ['junit', { outputFile: SANDBOX_JUNIT_REPORTS[leg], includeProjectInTestName: true }],
  ],
});
