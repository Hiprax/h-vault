#!/usr/bin/env node
/**
 * `test:a11y` — the accessibility suite, run as its own gate.
 *
 * Two specs, driven by `playwright.a11y.config.ts` against the real application:
 * `e2e/a11y.spec.ts` runs axe over fifteen views and modals in the authenticated
 * DOM, and `e2e/a11y-keyboard.spec.ts` pins the focus and keyboard behaviours a
 * scanner cannot infer.
 *
 *   node scripts/ci/a11y-gate.mjs        the gate (this is what the pipeline runs)
 *   npm run test:a11y                    the same thing
 *
 * While iterating, a single spec is a plain Playwright invocation:
 *
 *   npx playwright test e2e/a11y.spec.ts
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. AN AXE RUN OVER NOTHING LOOKS EXACTLY LIKE A CLEAN ONE. Both report zero
 *     violations, so "the suite passed" is not evidence that anything was
 *     scanned. This gate therefore requires the run to have produced a scan for
 *     EVERY id in `e2e/a11yViews.ts`, and fails naming the ones it did not — a
 *     view that quietly stopped being visited is a gate that quietly stopped
 *     existing. The spec asserts the same thing from the inside; both checks are
 *     kept because they fail in different ways (a deleted step versus a spec that
 *     never ran at all).
 *
 *  b. THE THRESHOLD IS `serious` AND `critical`, AND IT IS NOT CONFIGURABLE HERE.
 *     Every violation axe reports is recorded, whatever its impact, so the
 *     moderate and minor debt is visible and can be paid down; only the top two
 *     impacts fail. A flag that let a caller pick the threshold would be the one
 *     knob needed to make this gate green without touching the application.
 *
 *  c. A MISSING OR STALE SCAN FILE IS A FAILURE, NEVER AN EMPTY PASS. The specs
 *     write `a11y-scans.json`; this gate deletes it BEFORE the run, so a report
 *     left over from an earlier run cannot satisfy (a).
 *
 *  d. BOTH SPECS MUST HAVE RUN. The JUnit report is checked for a suite per file
 *     in `A11Y_SUITE`, because a `testMatch` that has gone stale in part matches
 *     the remaining file and passes — Playwright only errors when NOTHING
 *     matches, the same trap `vitest.security.config.ts` records.
 */
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { runNpm } from './lib/proc.mjs';
import { color, note, warn } from './lib/ui.mjs';
import { ensureReportDir, reportPath, writeJsonReport } from './lib/reports.mjs';

/** Mirrors `A11Y_BLOCKING_IMPACTS` in e2e/a11yViews.ts. */
const BLOCKING_IMPACTS = ['serious', 'critical', 'unknown'];

/**
 * Mirrors `A11Y_SUITE` in playwright.a11y.config.ts.
 *
 * Restated rather than imported for the reason `property-gate.mjs` restates its
 * report names: this file is plain ESM and the config is TypeScript. The two are
 * held together by `gate-surface.test.ts`, which reads the real constant.
 */
const SUITE = ['a11y.spec.ts', 'a11y-keyboard.spec.ts'];

const SCANS = 'a11y-scans.json';
const JUNIT = 'junit-a11y.xml';

/** The canonical view ids, read from the module the spec itself uses. */
function declaredViews() {
  const source = readFileSync(new URL('../../e2e/a11yViews.ts', import.meta.url), 'utf8');
  const block = /export const A11Y_VIEWS = \[([\s\S]*?)\n\] as const/.exec(source);
  if (!block) return null;
  return [...block[1].matchAll(/id:\s*'([^']+)'/g)].map((match) => match[1]);
}

ensureReportDir();

// (c) A stale scan file would satisfy the completeness check for a run that
// scanned nothing.
rmSync(reportPath(SCANS), { force: true });
rmSync(reportPath(JUNIT), { force: true });

const started = Date.now();
// `npm exec` rather than a bare `npx`, because `runNpm` is the helper that knows
// how spawning npm differs on Windows — and no `logFile` here: the pipeline
// runner tees THIS script's output, so a second transcript would capture the
// child twice and leave the gate's own lines out of it.
const code = await runNpm([
  'exec',
  '--',
  'playwright',
  'test',
  '--config',
  'playwright.a11y.config.ts',
  // A `.only` left in either spec would silently shrink this gate to one test.
  '--forbid-only',
]);
const durationMs = Date.now() - started;

const views = declaredViews();
const problems = [];
if (views === null) problems.push('could not read A11Y_VIEWS from e2e/a11yViews.ts');

let scans = [];
if (!existsSync(reportPath(SCANS))) {
  problems.push(`the run wrote no ${SCANS}, so nothing proves any view was scanned`);
} else {
  try {
    scans = JSON.parse(readFileSync(reportPath(SCANS), 'utf8')).scans ?? [];
  } catch {
    problems.push(`${SCANS} is not readable JSON`);
  }
}

// (a) Every declared view must have been scanned.
const scanned = new Set(scans.map((scan) => scan.view));
const missingViews = (views ?? []).filter((view) => !scanned.has(view));
if (missingViews.length > 0) {
  problems.push(`never scanned: ${missingViews.join(', ')}`);
}

// (d) Both specs must appear in the run's own JUnit report.
const junit = existsSync(reportPath(JUNIT)) ? readFileSync(reportPath(JUNIT), 'utf8') : '';
if (!junit) problems.push(`the run wrote no ${JUNIT}`);
const missingSuites = SUITE.filter((file) => !junit.includes(`name="${file}"`));
if (junit && missingSuites.length > 0) {
  problems.push(`no results for: ${missingSuites.join(', ')} — the suite has shrunk`);
}

// (b) The findings themselves.
const byImpact = {};
const blocking = [];
for (const scan of scans) {
  for (const violation of scan.violations ?? []) {
    byImpact[violation.impact] = (byImpact[violation.impact] ?? 0) + 1;
    if (BLOCKING_IMPACTS.includes(violation.impact)) {
      blocking.push({ view: scan.view, ...violation });
    }
  }
}

const payload = {
  version: 1,
  task: 'test:a11y',
  checkedAt: new Date().toISOString(),
  durationMs,
  exitCode: code,
  blockingImpacts: BLOCKING_IMPACTS,
  suite: SUITE,
  viewsDeclared: views?.length ?? 0,
  viewsScanned: scanned.size,
  // The gated numbers. `serious` and `critical` are ratcheted in
  // `.testfortress/baseline.json`; the rest are recorded so the debt below the
  // gate is visible and can only be paid down deliberately.
  violations: {
    critical: byImpact['critical'] ?? 0,
    serious: byImpact['serious'] ?? 0,
    moderate: byImpact['moderate'] ?? 0,
    minor: byImpact['minor'] ?? 0,
    // A violation axe could not grade. Blocking, and published here too — it
    // used to be counted into `byImpact` and then dropped from the payload, so a
    // finding of unknown severity appeared in no number this gate reports.
    unknown: byImpact['unknown'] ?? 0,
  },
  problems,
  blocking,
  scans,
};
writeJsonReport('a11y.json', payload);

if (code !== 0 || problems.length > 0 || blocking.length > 0) {
  if (code !== 0)
    console.error(color.red(`  ✖ the accessibility suite failed — exit ${String(code)}`));
  for (const problem of problems) console.error(color.red(`  ✖ ${problem}`));
  for (const violation of blocking) {
    console.error(
      color.red(
        `  ✖ ${violation.view}: ${violation.id} [${violation.impact}] — ${violation.help} (${violation.nodes.map((node) => node.target).join(', ')})`,
      ),
    );
  }
  warn('a11y.json carries the full findings, including the moderate and minor ones');
  process.exit(1);
}

note(
  `a11y.json — ${String(scanned.size)} views, 0 serious/critical, ` +
    `${String(payload.violations.moderate)} moderate, ${String(payload.violations.minor)} minor ` +
    `(automated scanning finds roughly a third of real accessibility defects: this is a floor)`,
);
