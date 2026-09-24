#!/usr/bin/env node
/**
 * `test:mutation:diff` — the oracle, over the lines this change touched.
 *
 * `test:mutation` is the whole campaign and it is measured in hours to days, so
 * it lives at tier 2 and does not run on a push. The doctrine's answer to an
 * expensive kind of testing is to SPLIT it, never to postpone it: the cheap half
 * runs on every push, and the campaign keeps its own task, its own tier and its
 * own floor. This is the cheap half. Coverage already proves the changed lines
 * RAN (`coverage:check`, 100% on changed lines); this proves they are ASSERTED.
 *
 *   node scripts/ci/mutation-diff-gate.mjs     the gate (what the pipeline runs)
 *   npm run test:mutation:diff                 the same thing
 *   HVAULT_DIFF_BASE=<ref> npm run test:mutation:diff    compare against another ref
 *
 * Exit codes: 0 = the change's mutants meet the floor · 1 = they do not ·
 * 2 = could not run (no diff base, Stryker failed, the plan and the run
 * disagree, or a leg hit its hang guard).
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. THE SUBJECT IS DERIVED FROM GIT AT RUN TIME, never committed. The same
 *     merge base `coverage:check` uses (`lib/diff-base.mjs`) and the same
 *     working-tree diff (`lib/changed-diff.mjs`), so the two per-change gates
 *     always measure the same change. It is the one form of selection a gate may
 *     make, because nobody wrote it down: a committed file list would be a test
 *     filter under another name.
 *
 *  b. CHANGED LINES, NOT CHANGED FILES. The doctrine's mutation entry says to
 *     mutate the changed FILES; the project's own testing standard says
 *     "mutation diff-scoped on changed lines". Lines are the reading this gate
 *     implements, and the choice is recorded rather than hidden: whole files
 *     would make a one-line fix to a 3,000-line controller cost a thousand
 *     server mutants, which is the campaign again under a T1 label. Which
 *     mutants a change owns is decision (a) of `lib/mutation-diff.mjs`.
 *
 *  c. FROM SCRATCH, AND APART FROM THE CAMPAIGN. `incremental: false` — a cache
 *     is per-machine state no reviewer can see — and its own plan, report and
 *     sandbox names, so this gate can never overwrite the campaign's evidence
 *     (see `stryker.config.mjs`). The scope is the campaign's own
 *     (`legForFile`), so this gate cannot quietly narrow it either.
 *
 *  d. A BUDGET BOUNDS THE COST, AND THE BUDGET IS THE DENOMINATOR. A change that
 *     owns more mutants than a leg's committed budget is sampled — keyed,
 *     monotone, stratified, and DISCLOSED in the report — and the budget is a
 *     ratcheted number that can only grow. The whole population stays under the
 *     campaign's floor. The per-leg deadline is a hang guard only; it can never
 *     produce a verdict.
 *
 *  e. THE PLAN IS VERIFIED AGAINST THE RUN. The planned mutant set is computed
 *     before Stryker starts, with the same instrumenter Stryker uses (pinned to
 *     its exact version), and the run must have tested exactly that set. A
 *     mismatch is "could not run": a verdict over a set nobody planned is a
 *     verdict about something else.
 *
 *  f. THE CHANGE CANNOT EXCUSE ITS OWN MUTANTS. An `Ignored` mutant on a changed
 *     line counts AGAINST the change (the only way to get one is a directive
 *     comment on those very lines). The one excuse is a dated, owned
 *     `EQUIV-MUTANT` entry in the suppression ledger pinned to the file, which
 *     excuses at most its `maxHits` survivors there — the mechanism
 *     `coverage:check` gives `COV-DIFF-EXEMPT`, for the same reason: an
 *     equivalent mutant is one no test can kill, and a gate with no legitimate
 *     way past it gets deleted rather than met.
 *
 *  g. THE LEGS RUN ONE AFTER ANOTHER, like the campaign's, for the campaign's
 *     reason: a CPU-starved test times out, and Stryker records a timeout as a
 *     KILL, so parallel legs would inflate the very score this gate enforces.
 */
import { existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { Instrumenter } from '@stryker-mutator/instrumenter';
import { TIMEOUT_EXIT, captureExe, repoRoot, runExe } from './lib/proc.mjs';
import { color, note, warn } from './lib/ui.mjs';
import { ensureReportDir, reportPath, writeJsonReport } from './lib/reports.mjs';
import { buildChangedDiff } from './lib/changed-diff.mjs';
import { resolveDiffBase } from './lib/diff-base.mjs';
import {
  CORE_MODULES,
  MUTATION_DIFF_BUDGETS,
  MUTATION_DIFF_FLOOR,
  MUTATION_DIFF_LEG_DEADLINE_MS,
  MUTATION_DIFF_REPORT,
  MUTATION_LEGS,
  diffJsonReportFor,
  diffPlanFor,
  legForFile,
} from './lib/mutation-scope.mjs';
import { createTally, pct, sortedSurvivors, tallyReport } from './lib/mutation-evidence.mjs';
import {
  apiMutantKey,
  candidateMutants,
  changedLinesByFile,
  planSample,
  rankMutants,
  reportMutantKey,
  strykerRange,
} from './lib/mutation-diff.mjs';
import { buildStrykerConfig } from './lib/stryker-config.mjs';

const EXIT_FAILED = 1;
const EXIT_CANNOT_RUN = 2;
const started = Date.now();

ensureReportDir();
// A report left by an earlier run must never read as this run's verdict.
rmSync(reportPath(MUTATION_DIFF_REPORT), { force: true });

const cannotRun = (message) => {
  console.error(color.red(`  ✖ test:mutation:diff cannot run: ${message}`));
  process.exit(EXIT_CANNOT_RUN);
};

const git = (args) => {
  const result = captureExe('git', args);
  return result.ok ? result.stdout.trim() : null;
};

// ---------------------------------------------------------------------------
// (a) the change
// ---------------------------------------------------------------------------
let diffBase;
try {
  diffBase = resolveDiffBase({ git, requested: process.env['HVAULT_DIFF_BASE'] });
} catch (error) {
  cannotRun(error instanceof Error ? error.message : String(error));
}
const { ref, mergeBase, onTrunk } = diffBase;

const isRegularFile = (rel) =>
  statSync(path.join(repoRoot, rel), { throwIfNoEntry: false })?.isFile() === true;
const untracked = (git(['ls-files', '--others', '--exclude-standard']) ?? '')
  .split('\n')
  .filter(Boolean)
  .filter((rel) => legForFile(rel) !== undefined && isRegularFile(rel));
let unifiedDiff = '';
try {
  unifiedDiff = buildChangedDiff({
    mergeBase,
    untracked,
    git: (args) => captureExe('git', args),
  });
} catch (error) {
  cannotRun(error instanceof Error ? error.message : String(error));
}
const changedLines = changedLinesByFile(unifiedDiff);
const changedFiles = [...changedLines.keys()]
  .filter((rel) => legForFile(rel) !== undefined && isRegularFile(rel))
  .sort();

// ---------------------------------------------------------------------------
// (e) the mutants each file owns, found by Stryker's own instrumenter
// ---------------------------------------------------------------------------
// The mutator options come from the one Stryker configuration, so a mutator
// excluded there is excluded here. An ignorer plugin cannot be resolved outside
// Stryker, so a configuration that declares one is refused rather than planned
// against without it.
const strykerConfig = buildStrykerConfig({ HVAULT_MUTATION_LEG: MUTATION_LEGS[0].id });
if (Array.isArray(strykerConfig.ignorers) && strykerConfig.ignorers.length > 0) {
  cannotRun('stryker.config.mjs declares ignorer plugins, which this gate cannot plan against');
}
const instrumenterOptions = {
  plugins: strykerConfig.mutator?.plugins ?? null,
  excludedMutations: strykerConfig.mutator?.excludedMutations ?? [],
  ignorers: [],
};
const quiet = () => {};
const instrumenter = new Instrumenter({
  trace: quiet,
  debug: quiet,
  info: quiet,
  warn: quiet,
  error: quiet,
  fatal: quiet,
  isTraceEnabled: () => false,
  isDebugEnabled: () => false,
  isInfoEnabled: () => false,
  isWarnEnabled: () => false,
  isErrorEnabled: () => false,
  isFatalEnabled: () => false,
});

const isCore = (file) => CORE_MODULES.some((modulePath) => file.startsWith(modulePath));
/** @type {Map<string, { file: string, candidates: any[], all: any[], ranks: Map<any, string> }[]>} */
const filesByLeg = new Map(MUTATION_LEGS.map((leg) => [leg.id, []]));
for (const file of changedFiles) {
  const source = readFileSync(path.join(repoRoot, file), 'utf8');
  let all;
  try {
    ({ mutants: all } = await instrumenter.instrument(
      [{ name: file, content: source, mutate: true }],
      instrumenterOptions,
    ));
  } catch (error) {
    cannotRun(
      `${file} could not be instrumented: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  const candidates = candidateMutants(all, /** @type {Set<number>} */ (changedLines.get(file)));
  const leg = /** @type {{ id: string }} */ (legForFile(file));
  filesByLeg.get(leg.id)?.push({
    file,
    candidates,
    all,
    ranks: rankMutants(all, source, mergeBase),
  });
}

// ---------------------------------------------------------------------------
// (d) plan, run and verify, one leg at a time (g)
// ---------------------------------------------------------------------------
/** Ledgered equivalent mutants, the one excuse (f). */
const today = new Date().toISOString().slice(0, 10);
const ledgerFile = path.join(repoRoot, '.testfortress', 'suppressions.json');
const ledger = existsSync(ledgerFile) ? JSON.parse(readFileSync(ledgerFile, 'utf8')) : {};
const equivalents = (Array.isArray(ledger.entries) ? ledger.entries : []).filter(
  (entry) =>
    entry.rule === 'EQUIV-MUTANT' &&
    typeof entry.file === 'string' &&
    typeof entry.expires === 'string' &&
    entry.expires >= today,
);

const legResults = [];
const overall = createTally();
const excused = [];

for (const leg of MUTATION_LEGS) {
  const files = /** @type {any[]} */ (filesByLeg.get(leg.id));
  const budget = MUTATION_DIFF_BUDGETS[leg.id];
  const candidateFiles = files.filter((entry) => entry.candidates.length > 0);
  const candidateCount = candidateFiles.reduce((n, entry) => n + entry.candidates.length, 0);
  if (candidateCount === 0) {
    // Nothing this change touched carries a mutant here: Stryker is not started.
    legResults.push({ id: leg.id, changedFiles: files.length, candidates: 0, planned: 0, budget });
    continue;
  }

  const plan = planSample({ files: candidateFiles, budget, isCore });
  const candidateKeys = new Set(
    candidateFiles.flatMap((entry) => entry.candidates.map(apiMutantKey)),
  );
  const plannedKeys = new Set(plan.planned.map(apiMutantKey));
  const strayed = [...plannedKeys].filter((key) => !candidateKeys.has(key));
  if (strayed.length > 0) {
    cannotRun(
      `${leg.id}: the plan reaches ${String(strayed.length)} mutant(s) the change does not own, e.g. ${strayed[0]}`,
    );
  }
  const unmeasured = candidateFiles
    .map((entry) => entry.file)
    .filter((file) => !plan.planned.some((mutant) => mutant.fileName === file));
  if (unmeasured.length > 0) {
    cannotRun(`${leg.id}: the plan leaves changed file(s) unmeasured: ${unmeasured.join(', ')}`);
  }

  console.log(
    color.bold(
      `\n  mutation:diff ${leg.package} — ${String(plan.planned.length)} of ${String(candidateCount)} changed-line mutant(s) ` +
        `across ${String(candidateFiles.length)} file(s)${plan.sampled ? ` (sampled; budget ${String(budget)})` : ''}`,
    ),
  );
  const planFile = path.join(repoRoot, diffPlanFor(leg.id));
  // Stryker creates `.stryker-tmp/` itself, but only once it runs; on a fresh
  // checkout the plan is the first thing written there.
  mkdirSync(path.dirname(planFile), { recursive: true });
  writeFileSync(
    planFile,
    `${JSON.stringify({ leg: leg.id, mutate: [...new Set(plan.seeds.map((s) => strykerRange(s.fileName, s.location)))] }, null, 2)}\n`,
  );
  const reportFile = path.join(repoRoot, diffJsonReportFor(leg.id));
  rmSync(reportFile, { force: true });

  const legStarted = Date.now();
  const code = await runExe(
    process.execPath,
    [path.join('node_modules', '@stryker-mutator', 'core', 'bin', 'stryker.js'), 'run'],
    {
      env: { HVAULT_MUTATION_LEG: leg.id, HVAULT_MUTATION_DIFF_PLAN: planFile },
      timeoutMs: MUTATION_DIFF_LEG_DEADLINE_MS,
    },
  );
  const durationMs = Date.now() - legStarted;
  if (code === TIMEOUT_EXIT) {
    cannotRun(
      `${leg.id}: Stryker was still running at the ${String(MUTATION_DIFF_LEG_DEADLINE_MS / 60000)}-minute hang guard`,
    );
  }
  if (code !== 0 || !existsSync(reportFile)) {
    cannotRun(
      `${leg.id}: stryker exited ${String(code)}${existsSync(reportFile) ? '' : ' and wrote no report'}`,
    );
  }

  const report = JSON.parse(readFileSync(reportFile, 'utf8'));
  const tested = new Set();
  let staticMutants = 0;
  for (const [file, entry] of Object.entries(report.files ?? {})) {
    for (const mutant of entry.mutants ?? []) {
      tested.add(reportMutantKey(file, mutant));
      if (mutant.static) staticMutants++;
    }
  }
  const notTested = [...plannedKeys].filter((key) => !tested.has(key));
  const notPlanned = [...tested].filter((key) => !plannedKeys.has(key));
  if (notTested.length > 0 || notPlanned.length > 0) {
    cannotRun(
      `${leg.id}: Stryker tested a different set from the plan — ${String(notTested.length)} planned but not tested, ` +
        `${String(notPlanned.length)} tested but not planned (e.g. ${notTested[0] ?? notPlanned[0]}). ` +
        'The instrumenter this gate uses and the one inside Stryker disagree.',
    );
  }

  const legTally = tallyReport(report, createTally(), { ignoredIsAlive: true });
  tallyReport(report, overall, { ignoredIsAlive: true });
  let killed = 0;
  let scored = 0;
  for (const stats of legTally.perFile.values()) {
    killed += stats.killed;
    scored += stats.total;
  }
  legResults.push({
    id: leg.id,
    changedFiles: files.length,
    candidateFiles: candidateFiles.length,
    candidates: candidateCount,
    planned: plan.planned.length,
    seeds: plan.seeds.length,
    sampled: plan.sampled,
    budget,
    staticMutants,
    byStatus: legTally.byStatus,
    killed,
    scored,
    score: pct(killed, scored),
    durationMs,
  });
  console.log(
    color.gray(
      `      ${String(killed)}/${String(scored)} killed (${String(pct(killed, scored))}%) in ${String(Math.round(durationMs / 1000))}s`,
    ),
  );
}

// ---------------------------------------------------------------------------
// the verdict, after the one excuse (f)
// ---------------------------------------------------------------------------
const survivors = sortedSurvivors(overall);
const remaining = [];
const capacity = new Map(equivalents.map((entry) => [entry, Number(entry.maxHits ?? 1)]));
for (const survivor of survivors) {
  const entry = equivalents.find(
    (candidate) => candidate.file === survivor.file && (capacity.get(candidate) ?? 0) > 0,
  );
  if (entry) {
    capacity.set(entry, (capacity.get(entry) ?? 0) - 1);
    excused.push({ ...survivor, ledger: entry.id });
  } else {
    remaining.push(survivor);
  }
}
let killedTotal = 0;
let scoredTotal = 0;
for (const stats of overall.perFile.values()) {
  killedTotal += stats.killed;
  scoredTotal += stats.total;
}
const denominator = scoredTotal - excused.length;
const score = denominator > 0 ? pct(killedTotal, denominator) : null;
const passed = score === null || score >= MUTATION_DIFF_FLOOR;

writeJsonReport(MUTATION_DIFF_REPORT, {
  version: 1,
  task: 'test:mutation:diff',
  checkedAt: new Date().toISOString(),
  durationMs: Date.now() - started,
  base: { ref, mergeBase, onTrunk },
  // The HMAC key the sample was drawn with: the merge base, which the author of
  // the change does not choose.
  sampleKey: mergeBase,
  incremental: false,
  floor: MUTATION_DIFF_FLOOR,
  budgets: MUTATION_DIFF_BUDGETS,
  changedFiles,
  legs: legResults,
  // Timeouts count as kills, so their number is shown beside the score: on a
  // starved machine it is the score's inflation, measured.
  byStatus: overall.byStatus,
  killed: killedTotal,
  scored: scoredTotal,
  excused,
  score,
  passed,
  survivors: remaining,
  notes: [
    'A mutant belongs to the change when it touches a changed line and contains no mutant lying wholly on unchanged lines.',
    'A pure rename, or a change that only deletes lines, owns no mutants.',
  ],
});

const sampledLegs = legResults.filter((leg) => leg.sampled).map((leg) => leg.id);
console.log(
  color.bold(
    `\n  mutation:diff: ${score === null ? 'no changed-line mutants' : `${String(score)}%`} — ` +
      `${String(killedTotal)}/${String(denominator)} killed across ${String(changedFiles.length)} changed file(s)` +
      `${excused.length > 0 ? `, ${String(excused.length)} excused by the ledger` : ''}` +
      `${sampledLegs.length > 0 ? `; sampled in ${sampledLegs.join(', ')}` : ''}`,
  ),
);
if (!passed) {
  warn(
    `the changed lines' mutation score ${String(score)}% is below the floor of ${String(MUTATION_DIFF_FLOOR)}%`,
  );
  for (const survivor of remaining.slice(0, 25)) {
    console.error(
      color.red(
        `      ${survivor.file}:${String(survivor.line)} ${survivor.mutator} → ${survivor.replacement} (${survivor.status})`,
      ),
    );
  }
  if (remaining.length > 25)
    console.error(
      color.gray(`      … and ${String(remaining.length - 25)} more in ${MUTATION_DIFF_REPORT}`),
    );
  console.error(
    color.gray(
      '      Each survivor is a claim the tests do not make: write the assertion, or ledger it as ' +
        'EQUIV-MUTANT with the reason no test can kill it.',
    ),
  );
  process.exit(EXIT_FAILED);
}
note(
  `${MUTATION_DIFF_REPORT} — ${score === null ? 'nothing to mutate' : `${String(score)}% ≥ ${String(MUTATION_DIFF_FLOOR)}%`} in ` +
    `${String(Math.round((Date.now() - started) / 1000))}s`,
);
