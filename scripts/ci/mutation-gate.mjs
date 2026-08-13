#!/usr/bin/env node
/**
 * `test:mutation` — the oracle.
 *
 * Coverage proves a line was EXECUTED. Only mutation proves it was ASSERTED:
 * Stryker changes the production code — a `>` for a `>=`, a `&&` for a `||`, a
 * bound, a string, a whole block — and asks whether any test notices. A mutant
 * that survives names a specific claim this suite does not actually make.
 *
 *   node scripts/ci/mutation-gate.mjs          the gate (what the pipeline runs)
 *   npm run test:mutation                      the same thing
 *   npm run test:mutation -- --full            rebuild, ignoring incremental state
 *   npm run test:mutation -- --leg=shared      one leg, while iterating
 *
 * `--leg` is a DEVELOPMENT flag and is deliberately absent from the registered
 * command: a committed filter that runs part of a gate and reports the whole
 * gate's name is the narrowing this project's doctrine forbids. A `--leg` run
 * therefore refuses to write the merged report at all (see (d)).
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. THE SCORE IS COMPUTED HERE, FROM THE PER-MUTANT STATUSES, and the
 *     denominator is stated rather than implied: killed + timed-out, over
 *     killed + timed-out + survived + no-coverage. `Ignored` mutants are
 *     excluded from BOTH — they are the ones a configuration chose not to test —
 *     which is exactly why `mutation.totalMutants` (that denominator) is
 *     ratcheted upward: shrinking what gets tested shows up as a smaller
 *     denominator even when the percentage rises. `stryker.config.mjs` sets
 *     `ignoreStatic: false` so this repository ignores none.
 *
 *  b. THE FLOOR IS `.testfortress/baseline.json`, NOT A THRESHOLD IN THE
 *     STRYKER CONFIG. One number in one place: the ratchet reads it, this gate
 *     enforces it, and `ratchet-check --accept` is the only thing that moves it
 *     — upward. A `thresholds.break` in the Stryker config would be a second,
 *     hand-maintained copy of a number that already exists, and the two would
 *     disagree the first time someone edited one.
 *
 *  c. A NARROWED SCOPE FAILS HERE TOO, NOT ONLY IN THE RATCHET. The measured
 *     file set is compared against the baseline's before the score is: a run
 *     that mutates fewer files than the last one is reported as the scope
 *     regression it is, at the moment it happens, rather than at the end of a
 *     `verify:full` an hour later.
 *
 *  d. A PARTIAL RUN NEVER WRITES THE REPORT. `--leg` runs one package; its
 *     numbers describe a fraction of the declared scope, and a `mutation.json`
 *     containing them would be read by the ratchet as the whole thing — with a
 *     smaller file set (a scope regression) and a score over different code.
 *     So a partial run prints and exits, leaving the last complete report alone.
 *
 *  e. THERE IS NO WALL-CLOCK DEADLINE, unlike `fuzz`, `upgrade` and `recovery`.
 *     A full run over ~53,000 lines is hours; a deadline that could fire on a
 *     loaded machine would turn the slowest gate in the repository into a coin
 *     toss. The hang this gate could actually suffer — one mutant wedging an
 *     event loop — is already bounded per mutant by Stryker's own
 *     `timeoutMS`/`timeoutFactor`, and a wedged mutant is reported as Timeout,
 *     which counts as killed because a test suite that hangs on a mutation has
 *     detected it.
 */
import { existsSync, readFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { repoRoot, runExe } from './lib/proc.mjs';
import { color, note, warn } from './lib/ui.mjs';
import { ensureReportDir, writeJsonReport } from './lib/reports.mjs';
import {
  CORE_MODULES,
  MUTATION_LEGS,
  MUTATION_LEG_IDS,
  MUTATION_SCOPE_GLOBS,
  incrementalFileFor,
  jsonReportFor,
  moduleKey,
} from './lib/mutation-scope.mjs';

const REPORT = 'mutation.json';
const BASELINE = path.join(repoRoot, '.testfortress', 'baseline.json');

const argv = process.argv.slice(2);
const full = argv.includes('--full');
const legFilter = (argv.find((a) => a.startsWith('--leg=')) ?? '').slice('--leg='.length);
if (legFilter && !MUTATION_LEG_IDS.includes(legFilter)) {
  console.error(
    color.red(`mutation-gate: unknown leg ${JSON.stringify(legFilter)}`),
    color.gray(`known legs: ${MUTATION_LEG_IDS.join(', ')}`),
  );
  process.exit(2);
}
const legs = MUTATION_LEGS.filter((leg) => !legFilter || leg.id === legFilter);

/** Statuses that count as a kill, and the ones that count against you. */
const KILLED = new Set(['Killed', 'Timeout']);
const ALIVE = new Set(['Survived', 'NoCoverage']);
const pct = (killed, total) => (total > 0 ? +((killed / total) * 100).toFixed(2) : 0);

ensureReportDir();

const baseline = existsSync(BASELINE) ? JSON.parse(readFileSync(BASELINE, 'utf8')) : null;
const recorded = baseline?.mutation;

/**
 * Does any leg's declared scope still select this file? Last match wins, which
 * is Stryker's own rule for a `mutate` list mixing patterns and `!` negations.
 */
function inDeclaredScope(file) {
  for (const leg of MUTATION_LEGS) {
    let selected = false;
    for (const glob of leg.mutate) {
      if (glob.startsWith('!')) {
        if (path.matchesGlob(file, glob.slice(1))) selected = false;
      } else if (path.matchesGlob(file, glob)) {
        selected = true;
      }
    }
    if (selected) return true;
  }
  return false;
}

/**
 * (c), the cheap half — run BEFORE Stryker, because the answer takes
 * milliseconds and the run takes hours.
 *
 * Every file the baseline says was mutated must still be selected by the
 * declared globs. A file that has been DELETED is not a narrowing: its code is
 * gone, so there is nothing left to assert about it, and the ratchet's superset
 * check is where that reduction is argued for with a `BASELINE-REDUCTION` entry.
 * A file that still exists but is no longer selected is the Forbidden Action
 * this gate exists to make expensive, and waiting an hour to say so would mean
 * nobody ever runs the gate that says it.
 */
const narrowed = (recorded?.filesMutated ?? []).filter(
  (file) => existsSync(path.join(repoRoot, file)) && !inDeclaredScope(file),
);
if (narrowed.length > 0) {
  warn(`scope narrowed: ${String(narrowed.length)} file(s) left the declared mutation scope`);
  for (const file of narrowed.slice(0, 10)) console.error(color.red(`      ${file}`));
  console.error(
    color.gray(
      '      The declared scope is packages/*/src/** minus the coverage-excluded entry points ' +
        'and the presentational primitives. Shrinking it raises the score while covering less code.',
    ),
  );
  process.exit(1);
}

const started = Date.now();
const legResults = [];
/** @type {Map<string, {killed: number, total: number, ignored: number}>} */
const perFile = new Map();
/** @type {{file: string, line: number, mutator: string, replacement: string, status: string}[]} */
const alive = [];
const byStatus = {};

for (const leg of legs) {
  console.log(color.bold(`\n  mutation: ${leg.package}`));
  const reportFile = path.join(repoRoot, jsonReportFor(leg.id));
  // A stale report would let a leg that crashed before writing anything be read
  // as if it had run — the same rule every other gate here follows.
  rmSync(reportFile, { force: true });
  if (full) rmSync(path.join(repoRoot, incrementalFileFor(leg.id)), { force: true });

  const legStarted = Date.now();
  const code = await runExe(
    process.execPath,
    [
      path.join('node_modules', '@stryker-mutator', 'core', 'bin', 'stryker.js'),
      'run',
      ...(full ? ['--force'] : []),
    ],
    { env: { HVAULT_MUTATION_LEG: leg.id } },
  );
  const durationMs = Date.now() - legStarted;

  if (code !== 0 || !existsSync(reportFile)) {
    console.error(
      color.red(
        `  ✖ ${leg.package} — stryker exited ${String(code)}${existsSync(reportFile) ? '' : ' and wrote no report'}`,
      ),
    );
    legResults.push({ ...legSummary(leg, durationMs), exitCode: code, status: 'fail' });
    continue;
  }

  const report = JSON.parse(readFileSync(reportFile, 'utf8'));
  let killed = 0;
  let scored = 0;
  let ignored = 0;
  for (const [file, entry] of Object.entries(report.files ?? {})) {
    const stats = perFile.get(file) ?? { killed: 0, total: 0, ignored: 0 };
    for (const mutant of entry.mutants ?? []) {
      byStatus[mutant.status] = (byStatus[mutant.status] ?? 0) + 1;
      if (KILLED.has(mutant.status)) {
        killed++;
        scored++;
        stats.killed++;
        stats.total++;
      } else if (ALIVE.has(mutant.status)) {
        scored++;
        stats.total++;
        alive.push({
          file,
          line: mutant.location?.start?.line ?? 0,
          mutator: mutant.mutatorName,
          replacement: String(mutant.replacement ?? '').slice(0, 120),
          status: mutant.status,
        });
      } else {
        ignored++;
        stats.ignored++;
      }
    }
    perFile.set(file, stats);
  }
  legResults.push({
    ...legSummary(leg, durationMs),
    exitCode: code,
    status: 'pass',
    mutants: scored,
    killed,
    ignored,
    score: pct(killed, scored),
  });
  console.log(
    color.green(
      `  ✔ ${leg.package} — ${String(pct(killed, scored))}% of ${String(scored)} mutants killed in ${String(Math.round(durationMs / 1000))}s`,
    ),
  );
}

function legSummary(leg, durationMs) {
  return {
    id: leg.id,
    package: leg.package,
    vitestConfig: leg.vitestConfig,
    concurrency: leg.concurrency,
    durationMs,
  };
}

const brokenLegs = legResults.filter((leg) => leg.status !== 'pass');

// (d) A partial run reports and stops. Nothing downstream may read a fraction of
// the declared scope as if it were the whole of it, and there are two ways to
// end up with one: asking for a single leg, or having a leg fail. A leg that
// dies in its dry run — which is how a broken configuration presents — would
// otherwise leave a `mutation.json` describing the other two packages, and the
// ratchet reads that file as the whole declared scope.
if (legFilter || brokenLegs.length > 0) {
  for (const leg of legResults) {
    note(`${leg.package}: ${String(leg.score ?? 0)}% of ${String(leg.mutants ?? 0)} mutants`);
  }
  warn(
    legFilter
      ? `--leg=${legFilter} is a partial run: ${REPORT} was NOT written and no floor was checked.`
      : `${String(brokenLegs.length)} leg(s) failed: ${REPORT} was NOT written, because a report ` +
          'missing a package would be read as a shrunken scope rather than as a broken run.',
  );
  for (const leg of brokenLegs) {
    console.error(color.red(`      ${leg.package} — exit ${String(leg.exitCode)}`));
  }
  process.exit(brokenLegs.length > 0 ? 1 : 0);
}

const totalKilled = [...perFile.values()].reduce((n, f) => n + f.killed, 0);
const totalScored = [...perFile.values()].reduce((n, f) => n + f.total, 0);
const filesMutated = [...perFile.keys()].sort();

/** Per-core-module scores, by PATH PREFIX over the measured file set. */
const modules = {};
for (const modulePath of CORE_MODULES) {
  let killed = 0;
  let total = 0;
  for (const [file, stats] of perFile) {
    if (file.startsWith(modulePath)) {
      killed += stats.killed;
      total += stats.total;
    }
  }
  if (total > 0) modules[moduleKey(modulePath)] = pct(killed, total);
}

const overall = pct(totalKilled, totalScored);
const payload = {
  version: 1,
  task: 'test:mutation',
  checkedAt: new Date().toISOString(),
  durationMs: Date.now() - started,
  incremental: !full,
  // The shape `ratchet-check.mjs` reads. It recomputes the score from these
  // statuses rather than trusting the headline above, so a report that claims a
  // number it did not measure is caught by the gate that reads it.
  files: Object.fromEntries(
    filesMutated.map((file) => {
      const stats = perFile.get(file);
      return [
        file,
        {
          mutants: [
            ...Array.from({ length: stats.killed }, () => ({ status: 'Killed' })),
            ...Array.from({ length: stats.total - stats.killed }, () => ({ status: 'Survived' })),
            ...Array.from({ length: stats.ignored }, () => ({ status: 'Ignored' })),
          ],
        },
      ];
    }),
  ),
  overall,
  totalMutants: totalScored,
  filesMutated,
  modules,
  scopeGlobs: MUTATION_SCOPE_GLOBS,
  coreModules: CORE_MODULES,
  byStatus,
  legs: legResults,
  // Every survivor, with enough to find it. This list IS the triage queue: the
  // doctrine allows three answers per entry — write the assertion, ledger it as
  // EQUIV-MUTANT with a reason, or delete the code — and no fourth.
  survivors: alive.sort(
    (a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.mutator.localeCompare(b.mutator),
  ),
};
writeJsonReport(REPORT, payload);

// ---------------------------------------------------------------------------
// the floor (b) and the scope (c)
// ---------------------------------------------------------------------------
const failures = [];

if (!recorded) {
  // The bootstrap, and the ONLY path that passes without a floor. It is not a
  // hole: `ratchet-check.mjs` lists `mutation.overall` and `mutation.filesMutated`
  // among its REQUIRED_FIELDS, so a baseline with no mutation block fails
  // `audit:ratchet:full` as ABSENT until the measured numbers are recorded.
  warn(
    'no mutation block in baseline.json — this run has no floor to hold. ' +
      'Record it with: npm run audit:ratchet:full && node scripts/ci/ratchet-check.mjs --accept --reason "..."',
  );
} else {
  const lost = (recorded.filesMutated ?? []).filter((file) => !filesMutated.includes(file));
  if (lost.length > 0) {
    failures.push(
      `scope narrowed: ${String(lost.length)} file(s) are no longer mutated, e.g. ${lost.slice(0, 3).join(', ')}`,
    );
  }
  if (typeof recorded.totalMutants === 'number' && totalScored < recorded.totalMutants) {
    failures.push(
      `denominator shrank: ${String(totalScored)} mutants tested, baseline ${String(recorded.totalMutants)}`,
    );
  }
  if (typeof recorded.overall === 'number' && overall < recorded.overall) {
    failures.push(`overall ${String(overall)}% is below the recorded ${String(recorded.overall)}%`);
  }
  for (const [key, want] of Object.entries(recorded.modules ?? {})) {
    const got = modules[key];
    if (got === undefined) {
      failures.push(`core module ${key} was not measured at all`);
    } else if (got < want) {
      failures.push(`core module ${key}: ${String(got)}% is below the recorded ${String(want)}%`);
    }
  }
}

console.log(
  color.bold(
    `\n  mutation: ${String(overall)}% overall — ${String(totalKilled)}/${String(totalScored)} killed, ` +
      `${String(alive.length)} survivor(s) across ${String(filesMutated.length)} file(s)`,
  ),
);
for (const [key, score] of Object.entries(modules)) {
  console.log(color.gray(`      core ${key}: ${String(score)}%`));
}

if (failures.length > 0) {
  warn(`${String(failures.length)} mutation failure(s)`);
  for (const line of failures) console.error(color.red(`      ${line}`));
  process.exit(1);
}

note(
  `${REPORT} — ${String(overall)}% over ${String(totalScored)} mutants, ${String(alive.length)} survivor(s), ` +
    `${String(Math.round(payload.durationMs / 1000))}s`,
);
