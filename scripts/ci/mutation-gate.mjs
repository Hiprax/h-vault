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
 *   npm run test:mutation -- --leg=shared      one leg: to iterate, or to bank it
 *
 * `--leg` is deliberately absent from the registered command: a committed filter
 * that runs part of a gate and reports the whole gate's name is the narrowing
 * this project's doctrine forbids. A `--leg` run therefore never writes the
 * merged report (see (d)); it writes that leg's OWN evidence and holds the leg
 * to the leg's OWN floor (see (f)), which is a different claim under a different
 * name and cannot be mistaken for the whole.
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
 *  d. A PARTIAL RUN NEVER WRITES THE MERGED REPORT. `--leg` runs one package;
 *     its numbers describe a fraction of the declared scope, and a
 *     `mutation.json` containing them would be read by the ratchet as the whole
 *     thing — with a smaller file set (a scope regression) and a score over
 *     different code. So a partial run leaves the last complete merged report
 *     alone, and so does a full run in which any leg failed.
 *
 *  e. THERE IS NO WALL-CLOCK DEADLINE, unlike `fuzz`, `upgrade` and `recovery`.
 *     A full run over ~53,000 lines is hours; a deadline that could fire on a
 *     loaded machine would turn the slowest gate in the repository into a coin
 *     toss. The hang this gate could actually suffer — one mutant wedging an
 *     event loop — is already bounded per mutant by Stryker's own
 *     `timeoutMS`/`timeoutFactor`, and a wedged mutant is reported as Timeout,
 *     which counts as killed because a test suite that hangs on a mutation has
 *     detected it.
 *
 *  f. EVERY LEG IS BANKED, AND HELD, ON ITS OWN. The merged floor is
 *     all-or-nothing across three legs by design (d), and one of those legs is
 *     measured in DAYS on the reference machine, so while the merged figures were
 *     the only floor the oracle never held one at all. Each leg that completes
 *     therefore writes `mutation-<leg>.json` — its own evidence, over exactly the
 *     code it mutated — and is compared against `mutation.legs.<leg>.*` in the
 *     baseline: the same four checks as the merged floor (lost files, a smaller
 *     denominator, a lower score, a lower or unmeasured core module), in a full
 *     run and in a `--leg` run alike. A leg with NO recorded floor is reported
 *     UNBANKED and fails the run; it never passes silently, and its evidence is
 *     still written, because that file is what records its first floor. The
 *     merged figures keep their own floor, checked only when all three legs
 *     completed in one run, and a per-leg floor never stands in for it.
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
  legReportFor,
  legSelects,
} from './lib/mutation-scope.mjs';
import {
  createTally,
  evidenceFiles,
  floorFailures,
  isBanked,
  sortedSurvivors,
  summariseTally,
  tallyReport,
} from './lib/mutation-evidence.mjs';

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

ensureReportDir();

const baseline = existsSync(BASELINE) ? JSON.parse(readFileSync(BASELINE, 'utf8')) : null;
/** The merged floor and every per-leg floor, as recorded. Either may be absent. */
const recorded = baseline?.mutation;
const recordedLegs = recorded?.legs ?? {};

/** Does any leg's declared scope still select this file? */
const inDeclaredScope = (file) => MUTATION_LEGS.some((leg) => legSelects(leg, file));

/**
 * The exact command that records a floor nobody has recorded yet. `--seed` names
 * the narrowest family that is actually absent, because the ratchet refuses to
 * seed a family that is partly present: once one leg is banked, `mutation` is
 * partly present and the next leg has to be named on its own.
 */
function seedCommand(family, legId) {
  // The ratchet records a floor only from a from-scratch run (its decision (i)):
  // a report this run wrote incrementally would be refused, so the steps start
  // with a `--full` re-run whenever this run was not already one.
  //
  // SEPARATE steps, never chained with `&&`: the re-run of a leg that holds no
  // floor exits 1 by design (it is UNBANKED until the accept records it), and
  // so does `audit:ratchet:full` while a field is absent, so a chain would stop
  // before the one step that records anything — after hours of mutation.
  const steps = [
    ...(full ? [] : [`npm run test:mutation -- ${legId ? `--leg=${legId} ` : ''}--full`]),
    'npm run audit:ratchet:full   (review what it reports; a failure here is expected only for the absent floor)',
    `node scripts/ci/ratchet-check.mjs --accept --seed ${family} --reason "..."`,
  ];
  return steps.map((step, index) => `\n        ${String(index + 1)}. ${step}`).join('');
}
const seedFamilyFor = (legId) =>
  recorded && Object.keys(recorded).length > 0 ? `mutation.legs.${legId}` : 'mutation';

/**
 * (c), the cheap half — run BEFORE Stryker, because the answer takes
 * milliseconds and the run takes hours.
 *
 * Every file ANY recorded floor says was mutated — the merged campaign's or one
 * leg's — must still be selected by the declared globs. A file that has been
 * DELETED is not a narrowing: its code is gone, so there is nothing left to
 * assert about it, and the ratchet's superset check is where that reduction is
 * argued for with a `BASELINE-REDUCTION` entry. A file that still exists but is
 * no longer selected is the Forbidden Action this gate exists to make expensive,
 * and waiting an hour to say so would mean nobody ever runs the gate that says it.
 *
 * The UNION, not the merged set alone: until the slowest leg completes there is
 * no merged set, and a pre-flight that consulted only it would check nothing at
 * all while two legs held floors.
 */
const everRecorded = new Set([
  ...(recorded?.filesMutated ?? []),
  ...Object.values(recordedLegs).flatMap((leg) => leg?.filesMutated ?? []),
]);
const narrowed = [...everRecorded]
  .sort()
  .filter((file) => existsSync(path.join(repoRoot, file)) && !inDeclaredScope(file));
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
/** Every completed leg, accumulated: what the merged report describes. */
const merged = createTally();
/** Floor failures, per leg as each completes and then for the merged figures. */
const failures = [];

for (const leg of legs) {
  console.log(color.bold(`\n  mutation: ${leg.package}`));
  const reportFile = path.join(repoRoot, jsonReportFor(leg.id));
  // A stale report would let a leg that crashed before writing anything be read
  // as if it had run — the same rule every other gate here follows. The leg's
  // own evidence file goes for the same reason: it must describe THIS run.
  rmSync(reportFile, { force: true });
  rmSync(path.join(repoRoot, '.testfortress', 'reports', legReportFor(leg.id)), { force: true });
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
  const legTally = tallyReport(report);
  tallyReport(report, merged);
  const measured = summariseTally(legTally, CORE_MODULES);
  legResults.push({
    ...legSummary(leg, durationMs),
    exitCode: code,
    status: 'pass',
    mutants: measured.totalMutants,
    killed: measured.killed,
    ignored: [...legTally.perFile.values()].reduce((n, f) => n + f.ignored, 0),
    score: measured.overall,
  });

  // (f) The leg's own evidence, written the moment the leg completes and
  // whichever way the rest of the run goes, because a leg that ran completely
  // measured its package completely.
  writeJsonReport(legReportFor(leg.id), {
    version: 1,
    task: 'test:mutation',
    leg: leg.id,
    package: leg.package,
    checkedAt: new Date().toISOString(),
    durationMs,
    incremental: !full,
    files: evidenceFiles(legTally),
    overall: measured.overall,
    totalMutants: measured.totalMutants,
    filesMutated: measured.filesMutated,
    modules: measured.modules,
    scopeGlobs: leg.mutate,
    byStatus: legTally.byStatus,
    survivors: sortedSurvivors(legTally),
  });

  // (f) …and the leg's own floor, checked against the leg's own record.
  const legFloor = recordedLegs[leg.id];
  if (!isBanked(legFloor)) {
    failures.push(
      `${leg.id}: UNBANKED — no floor is recorded for this leg, so it held nothing. ` +
        `Record it with: ${seedCommand(seedFamilyFor(leg.id), leg.id)}`,
    );
  } else {
    failures.push(...floorFailures(leg.id, legFloor, measured));
  }

  console.log(
    color.green(
      `  ✔ ${leg.package} — ${String(measured.overall)}% of ${String(measured.totalMutants)} mutants killed in ${String(Math.round(durationMs / 1000))}s`,
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

/** Prints the floor failures collected so far and exits 1, or returns when there are none. */
function reportFailures() {
  if (failures.length === 0) return;
  warn(`${String(failures.length)} mutation failure(s)`);
  for (const line of failures) console.error(color.red(`      ${line}`));
  process.exit(1);
}

// (d) A partial run never writes the merged report. Nothing downstream may read
// a fraction of the declared scope as if it were the whole of it, and there are
// two ways to end up with one: asking for a single leg, or having a leg fail. A
// leg that dies in its dry run — which is how a broken configuration presents —
// would otherwise leave a `mutation.json` describing the other two packages, and
// the ratchet reads that file as the whole declared scope. The legs that DID
// complete have already written, and been held to, their own floors above.
if (legFilter || brokenLegs.length > 0) {
  for (const leg of legResults) {
    note(`${leg.package}: ${String(leg.score ?? 0)}% of ${String(leg.mutants ?? 0)} mutants`);
  }
  warn(
    legFilter
      ? `--leg=${legFilter} is a partial run: ${REPORT} was NOT written; the leg's own ` +
          `${legReportFor(legFilter)} was, and its own floor was checked.`
      : `${String(brokenLegs.length)} leg(s) failed: ${REPORT} was NOT written, because a report ` +
          'missing a package would be read as a shrunken scope rather than as a broken run.',
  );
  for (const leg of brokenLegs) {
    failures.push(`${leg.id}: stryker exited ${String(leg.exitCode)} — the leg did not complete`);
  }
  reportFailures();
  process.exit(0);
}

const measured = summariseTally(merged, CORE_MODULES);
const survivors = sortedSurvivors(merged);
const payload = {
  version: 1,
  task: 'test:mutation',
  checkedAt: new Date().toISOString(),
  durationMs: Date.now() - started,
  incremental: !full,
  // The shape `ratchet-check.mjs` reads. It recomputes the score from these
  // statuses rather than trusting the headline above, so a report that claims a
  // number it did not measure is caught by the gate that reads it.
  files: evidenceFiles(merged),
  overall: measured.overall,
  totalMutants: measured.totalMutants,
  filesMutated: measured.filesMutated,
  modules: measured.modules,
  scopeGlobs: MUTATION_SCOPE_GLOBS,
  coreModules: CORE_MODULES,
  byStatus: merged.byStatus,
  legs: legResults,
  // Every survivor, with enough to find it. This list IS the triage queue: the
  // doctrine allows three answers per entry — write the assertion, ledger it as
  // EQUIV-MUTANT with a reason, or delete the code — and no fourth.
  survivors,
};
writeJsonReport(REPORT, payload);

// ---------------------------------------------------------------------------
// the merged floor (b) and the scope (c)
// ---------------------------------------------------------------------------
if (!isBanked(recorded)) {
  // THE BOOTSTRAP, AND IT FAILS. This branch used to pass with a warning, on the
  // stated grounds that `ratchet-check.mjs` listed `mutation.overall` and
  // `mutation.filesMutated` among its REQUIRED_FIELDS so a missing block would
  // be caught there instead. That was true when it was written and is not true
  // now: those two are required only once the baseline carries them, so the
  // safety net this comment promised had been removed from under it, and a
  // registered gate spent hours mutating the whole codebase and then exited 0
  // having held nothing. A judge found it by reading both files; the hash pinned
  // nothing, because deleting a check deletes its comparison too.
  //
  // `isBanked`, not `!recorded`, and the difference became load-bearing the day
  // legs could be banked on their own: a baseline holding only
  // `mutation.legs.*` is a `mutation` block, and the old test treated it as a
  // recorded MERGED floor and compared every merged figure against `undefined`
  // — which is to say, passed them all.
  //
  // It is a FAILURE rather than a hard exit at the top of the file on purpose:
  // the legs still run and `mutation.json` is still written above, because that
  // report is exactly what an operator needs in order to record the first
  // baseline. A gate that refused to run could never be bootstrapped; a gate
  // that passes with no floor is not a gate.
  //
  // `--seed` is part of that command and not a decoration. `--accept` alone
  // CANNOT create this block: the ratchet's comparison loop is driven by the
  // baseline's own keys, so a family it has never carried is measured and then
  // never compared, and only `improvements` are written.
  const mergedFamily =
    recorded && Object.keys(recorded).length > 0
      ? 'mutation.overall,mutation.totalMutants,mutation.filesMutated,mutation.modules'
      : 'mutation';
  failures.push(
    'merged: no merged mutation floor in baseline.json — this run held no floor over the whole ' +
      `declared scope. Record it with: ${seedCommand(mergedFamily)}`,
  );
} else {
  failures.push(...floorFailures('merged', recorded, measured));
}

console.log(
  color.bold(
    `\n  mutation: ${String(measured.overall)}% overall — ${String(measured.killed)}/${String(measured.totalMutants)} killed, ` +
      `${String(survivors.length)} survivor(s) across ${String(measured.filesMutated.length)} file(s)`,
  ),
);
for (const [key, score] of Object.entries(measured.modules)) {
  console.log(color.gray(`      core ${key}: ${String(score)}%`));
}

reportFailures();

note(
  `${REPORT} — ${String(measured.overall)}% over ${String(measured.totalMutants)} mutants, ${String(survivors.length)} survivor(s), ` +
    `${String(Math.round(payload.durationMs / 1000))}s`,
);
