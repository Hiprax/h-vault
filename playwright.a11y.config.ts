import { defineConfig } from '@playwright/test';
import base from './playwright.config';

/**
 * `test:a11y` — the accessibility suite, run as its own gate.
 *
 * The same shape as `packages/server/vitest.security.config.ts`: a NAMED SUBSET
 * of a suite that already runs, re-run under its own name so that "this
 * application is keyboard operable and free of serious machine-detectable
 * accessibility defects" is a claim somebody can point at, with its own report,
 * rather than two files buried in a six-minute end-to-end run.
 *
 * Nothing is narrowed by this. `playwright.config.ts` has no `testMatch` of its
 * own, so both files below ALSO run inside `test:e2e` on every push; this config
 * only adds a second, separately-reported invocation. The task carries
 * `countsTests: false` in the manifest for exactly that reason — counting them
 * twice would ratchet the same two tests as though they were four.
 *
 * ## Two things this config must keep
 *
 * 1. **Its own JUnit report.** Pointed at `junit-e2e.xml` it would overwrite the
 *    E2E gate's evidence, and `audit:ratchet:full` reads that file for the test
 *    headcount — the failure `vitest.security.config.ts` records, in the other
 *    runner.
 * 2. **No HTML reporter.** The base config pairs one with `open: 'never'` and
 *    writes it to `playwright-report/`; a second run would overwrite the E2E
 *    run's report with a two-test one, which is how an investigation ends up
 *    looking at the wrong artifact.
 */
export const A11Y_SUITE = ['a11y.spec.ts', 'a11y-keyboard.spec.ts'] as const;

const JUNIT_REPORT = '.testfortress/reports/junit-a11y.xml';

export default defineConfig({
  ...base,
  testMatch: [...A11Y_SUITE],
  reporter: [['list'], ['junit', { outputFile: JUNIT_REPORT }]],
});
