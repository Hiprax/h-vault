#!/usr/bin/env node
/**
 * `test:resource` — the volume and memory budgets.
 *
 * Seven scenarios, run one at a time against a real mongod, over vaults at
 * `MAX_ITEMS_PER_USER` (10,000 items): the backup collector's streaming abort,
 * the largest backup the configuration permits, a full-vault key rotation and its
 * all-or-nothing refusal, a ~25 MiB restore through the route's own 30 MB parser,
 * that parser's boundary from above, and the query plans behind the two
 * cross-user cleanup sweeps.
 *
 *   node scripts/ci/resource-gate.mjs        the gate (this is what the pipeline runs)
 *   npm run test:resource                    the same thing
 *
 * While iterating, a plain vitest invocation runs the same suite:
 *
 *   npm run test:resource -w packages/server
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. THE BUDGETS LIVE IN `lib/resource-budgets.mjs`, NOT HERE. The scenarios
 *     assert against them, this gate restates the verdict, and
 *     `ratchet-check.mjs` reads them out of that module into its own comparison
 *     with direction `lower`. Three readers, one definition: a ceiling cannot be
 *     raised in one place and stay green in another.
 *
 *  b. A SCENARIO THAT WRITES NO REPORT IS A FAILURE, not an absence. That is the
 *     shape a silently narrowed suite produces — a bad `include`, a renamed file,
 *     a `describe` that never ran — and it is indistinguishable from a passing
 *     run if you only read the exit code. The scenario reports are deleted before
 *     the run for the same reason: a stale file from an earlier run would satisfy
 *     the check on behalf of a scenario that did not execute.
 *
 *  c. THE DEADLINE IS THE GATE'S OWN. These scenarios build 10,000-row vaults and
 *     post 28 MB bodies; a wedged cursor or a rotation that has become one round
 *     trip per item does not fail, it hangs, and a hook that never returns looks
 *     like a slow machine until someone kills it. `LEG_DEADLINE_MS` turns that
 *     into a failure with a name.
 *
 *  d. THIS GATE IS TIER 2 AND ITS NUMBERS ARE NOT RATCHETED. Peak RSS and
 *     wall-clock duration have a noise band, and this gate does not run during
 *     `npm run ci` — so a ratchet on the MEASURED values would be both flaky and
 *     permanently unmeasured on every push (the rule `fuzz-gate.mjs` records
 *     about declared reports). What IS pinned, on every push, is the ceiling
 *     itself: `baseline.json` records each budget, `ratchet-check.mjs` injects
 *     the committed constants into the comparison as `lower`-is-better fields,
 *     and `audit:ratchet:full` fails when a ceiling has been raised — so raising
 *     one is a visible edit in two files rather than a quiet one in the suite
 *     that enforces it.
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import path from 'node:path';
import { TIMEOUT_EXIT, runNpm } from './lib/proc.mjs';
import { color, note, warn } from './lib/ui.mjs';
import { ensureReportDir, reportPath, writeJsonReport } from './lib/reports.mjs';
import { NOISE_BAND, RESOURCE_BUDGETS, RESOURCE_SCENARIOS } from './lib/resource-budgets.mjs';

/**
 * The wall-clock deadline for the whole suite.
 *
 * Measured on the reference machine at ~60 s end to end, dominated by the
 * 10,000-row restore. Fifteen minutes is an order of magnitude of headroom: far
 * too coarse to fire on a loaded machine, far too tight for a genuinely wedged
 * operation to hide behind.
 */
const LEG_DEADLINE_MS = 900_000;

/** Where the scenarios drop their numbers. Mirrors `tests/resource/measure.ts`. */
const SCENARIO_DIR = reportPath('resource-scenarios');

/** The `tests="N"` attribute of a JUnit document, or null when it cannot be read. */
function testCount(file) {
  if (!existsSync(file)) return null;
  const xml = readFileSync(file, 'utf8');
  const outer = /<testsuites[^>]*\btests="(\d+)"/.exec(xml);
  if (outer) return Number(outer[1]);
  const suites = [...xml.matchAll(/<testsuite[^>]*\btests="(\d+)"/g)].map((m) => Number(m[1]));
  return suites.length > 0 ? suites.reduce((a, b) => a + b, 0) : null;
}

/** The budget key for a scenario id: `backup-full-vault` → `backupFullVault`. */
const budgetKey = (id) => id.replace(/-([a-z])/g, (_all, ch) => ch.toUpperCase());

ensureReportDir();

// (b) Nothing from a previous run may stand in for this one.
rmSync(SCENARIO_DIR, { recursive: true, force: true });
rmSync(reportPath('junit-resource.xml'), { force: true });
mkdirSync(SCENARIO_DIR, { recursive: true });

const started = Date.now();
console.log(color.bold('\n  resource: volume and memory budgets over a full vault'));

const code = await runNpm(['run', 'test:resource', '-w', 'packages/server'], {
  // (c) On expiry `proc.mjs` SIGKILLs the npm child and resolves with
  // TIMEOUT_EXIT immediately, so a wedged grandchild is orphaned rather than
  // reaped — which leaks a process but can never leave this gate hanging on the
  // deadline meant to end it.
  timeoutMs: LEG_DEADLINE_MS,
});
const durationMs = Date.now() - started;
const timedOut = code === TIMEOUT_EXIT;
const tests = testCount(reportPath('junit-resource.xml'));

const scenarios = [];
const problems = [];

for (const declared of RESOURCE_SCENARIOS) {
  const file = path.join(SCENARIO_DIR, `${declared.id}.json`);
  if (!existsSync(file)) {
    problems.push(`${declared.id} wrote no report — ${declared.subject}`);
    scenarios.push({ ...declared, status: 'missing' });
    continue;
  }
  let measured;
  try {
    measured = JSON.parse(readFileSync(file, 'utf8'));
  } catch (error) {
    problems.push(`${declared.id} wrote an unreadable report: ${String(error)}`);
    scenarios.push({ ...declared, status: 'unreadable' });
    continue;
  }
  const cases = measured.cases ?? {};
  const caseIds = Object.keys(cases);
  if (caseIds.length !== declared.cases) {
    problems.push(
      `${declared.id} recorded ${String(caseIds.length)} case(s), expected ${String(declared.cases)} — ${caseIds.join(', ') || 'none'}`,
    );
  }

  // (a) The scenario already asserted this; restating it here is what puts the
  // verdict in `resource.json` beside the number that produced it. Budgets are
  // matched to the cases that carry a duration, so an unmeasured case needs no
  // declaration of its own.
  const budget = RESOURCE_BUDGETS[budgetKey(declared.id)];
  const overBudget = [];
  if (budget) {
    for (const [caseId, payload] of Object.entries(cases)) {
      if (typeof payload.durationMs !== 'number') continue;
      if (payload.durationMs >= budget.durationMs) {
        overBudget.push(
          `${caseId}: durationMs ${String(payload.durationMs)} >= ${String(budget.durationMs)}`,
        );
      }
      if (payload.rssGrowthMb >= budget.rssGrowthMb) {
        overBudget.push(
          `${caseId}: rssGrowthMb ${String(payload.rssGrowthMb)} >= ${String(budget.rssGrowthMb)}`,
        );
      }
    }
  }
  for (const breach of overBudget) problems.push(`${declared.id} is over budget: ${breach}`);
  scenarios.push({
    ...declared,
    status: overBudget.length > 0 ? 'over-budget' : 'pass',
    ...measured,
  });
}

// A scenario report that belongs to no declared scenario means the suite grew a
// file the gate does not know about — the same drift as a missing one, from the
// other direction.
const declaredIds = new Set(RESOURCE_SCENARIOS.map((scenario) => scenario.id));
for (const entry of readdirSync(SCENARIO_DIR)) {
  const id = entry.replace(/\.json$/, '');
  if (!declaredIds.has(id)) {
    problems.push(`${id} reported but is not declared in RESOURCE_SCENARIOS`);
  }
}

const failed = code !== 0 || timedOut || tests === null || problems.length > 0;

writeJsonReport('resource.json', {
  version: 1,
  task: 'test:resource',
  checkedAt: new Date().toISOString(),
  durationMs,
  seed: process.env['SEED'] ?? '1337',
  deadlineMs: LEG_DEADLINE_MS,
  exitCode: code,
  timedOut,
  // Every scenario also has its own JUnit report, and the task carries
  // `countsTests: false` in the manifest, so this total is reporting only — it
  // never enters the ratchet's headcount.
  tests,
  budgets: RESOURCE_BUDGETS,
  noiseBand: NOISE_BAND,
  problems,
  scenarios,
});

if (timedOut) {
  console.error(
    color.red(
      `  ✖ the resource suite exceeded the ${String(LEG_DEADLINE_MS)}ms deadline — treat this as a hang, not a slow machine`,
    ),
  );
} else if (code !== 0) {
  console.error(color.red(`  ✖ the resource suite failed — exit ${String(code)}`));
} else if (tests === null) {
  console.error(color.red('  ✖ the resource suite exited 0 but wrote no junit-resource.xml'));
}
for (const problem of problems) console.error(color.red(`      ${problem}`));

if (failed) {
  warn('resource budgets not met');
  process.exit(1);
}

note(
  `resource.json — ${String(scenarios.length)} scenarios, ${String(tests)} tests in ${String(durationMs)}ms, every budget met`,
);
