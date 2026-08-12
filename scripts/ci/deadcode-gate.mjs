#!/usr/bin/env node
/**
 * `deadcode` — code nothing reaches, and code written more than once.
 *
 *   knip   unused files, exports, exported types and dependencies, plus
 *          dependencies used without being declared
 *   jscpd  copy-paste duplication over packages/*(/src), against a committed ceiling
 *
 *   node scripts/ci/deadcode-gate.mjs           check, write deadcode.json
 *   node scripts/ci/deadcode-gate.mjs --json    the report on stdout as well
 *
 * Exit codes: 0 = nothing unused and duplication within the ceiling · 1 = a
 * finding · 2 = could not run.
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. THE ANSWER TO A FINDING IS DELETION, NEVER AN IGNORE ENTRY. knip.jsonc
 *     carries no `ignore*` key and .jscpd.json no `ignore` list, deliberately;
 *     adding one is how a dead-code gate is made green without removing a line,
 *     which is the widened exclusion the integrity doctrine forbids. An export
 *     used only inside its own module loses its `export` keyword; a dependency
 *     that really is used gets declared.
 *
 *  b. THE DUPLICATION CEILING IS THE MEASURED VALUE AND ONLY EVER FALLS. It
 *     lives in .jscpd.json (`threshold`, which jscpd itself enforces) and in
 *     .testfortress/baseline.json (`duplication.percentage`, lower-is-better,
 *     which the ratchet enforces). Two places on purpose: the first fails the
 *     run, the second fails any attempt to raise the first.
 *
 *  c. AN UNPARSEABLE OR ABSENT TOOL REPORT IS A FAILURE. jscpd exiting non-zero
 *     with no JSON is a broken gate, not a clean tree, and its report is deleted
 *     before the run so a stale file from an earlier one cannot stand in for it.
 *
 *  d. EVERY CATEGORY knip REPORTS IS COUNTED, INCLUDING THE ONES THAT ARE ZERO
 *     TODAY. `unlisted` (a dependency imported but never declared) and
 *     `unresolved` (an import that resolves to nothing) are the two that catch a
 *     package working only because npm hoisted someone else's dependency into
 *     the tree — the failure mode that survives every test suite and breaks on a
 *     clean install.
 */
import { existsSync, readFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { summariseKnip } from './lib/knip-report.mjs';
import { captureNpm, repoRoot } from './lib/proc.mjs';
import { reportPath, writeJsonReport } from './lib/reports.mjs';
import { color, symbol } from './lib/ui.mjs';

const EXIT_OK = 0;
const EXIT_FINDINGS = 1;
const EXIT_CANNOT_RUN = 2;

/** Collapse detectors for the duplication scan; measured today: 190 files, 52,851 lines. */
const MIN_EXPECTED_SOURCES = 50;
const MIN_EXPECTED_LINES = 10_000;

const asJson = process.argv.includes('--json');
const fatal = (message) => {
  console.error(color.red(`${symbol.fail} deadcode: ${message}`));
  process.exit(EXIT_CANNOT_RUN);
};

// ---------------------------------------------------------------------------
// knip — unused files, exports and dependencies
// ---------------------------------------------------------------------------
// Through the npm script that names the tool, for the reason `captureNpm` gives.
// No `--no-exit-code`: knip exits 1 when it finds something, and this gate reads
// its report to decide — a flag that forces a zero exit is a neutered gate even
// when something downstream still judges the output.
const knipRun = captureNpm(['run', '--silent', 'deadcode:unused']);
let knipIssues;
try {
  knipIssues = JSON.parse(knipRun.stdout.trim() || '{}').issues;
} catch {
  fatal(
    `knip produced output this gate cannot parse (exit ${String(knipRun.status)}): ` +
      `${(knipRun.stderr || knipRun.stdout).trim().slice(0, 400)}`,
  );
}
if (!Array.isArray(knipIssues)) fatal('knip reported no "issues" array');

// Counted in `lib/knip-report.mjs`, where the "an unknown category is still
// counted" property is unit-tested.
const { counts: deadcode, findings: knipFindings } = summariseKnip(knipIssues);

// `files` is knip's one category whose entries are the files themselves; when it
// reports a file the `file` field IS the finding, so the count above is right and
// the name is redundant. Nothing else to special-case.
const unusedTotal = Object.values(deadcode).reduce((sum, count) => sum + count, 0);

/**
 * knip's own verdict must agree with this one.
 *
 * knip exits 1 when it has anything to report. If it said so and the counting
 * above found nothing, the adjudication is broken — a category renamed upstream,
 * a reporter shape changed — and the gate would print "0 unused" over a report
 * that says otherwise. That is the exact failure this cross-check exists to make
 * impossible, and it is why the counting loop reads every array-valued key
 * rather than a fixed list.
 */
if (knipRun.status !== 0 && unusedTotal === 0) {
  fatal(
    `knip exited ${String(knipRun.status)} but this gate counted 0 findings — the two disagree, so ` +
      'the adjudication is broken (a renamed issue category?), not the tree clean',
  );
}

// ---------------------------------------------------------------------------
// jscpd — duplication against the committed ceiling
// ---------------------------------------------------------------------------
const jscpdDir = reportPath('jscpd');
const jscpdReport = path.join(jscpdDir, 'jscpd-report.json');
// (c) A report from an earlier run must never be able to stand in for this one.
rmSync(jscpdDir, { recursive: true, force: true });

const configPath = path.join(repoRoot, '.jscpd.json');
if (!existsSync(configPath)) fatal('.jscpd.json is missing; there is no duplication ceiling');
const jscpdConfig = JSON.parse(readFileSync(configPath, 'utf8'));
const ceiling = Number(jscpdConfig.threshold);
if (!Number.isFinite(ceiling)) fatal('.jscpd.json declares no numeric `threshold`');

const jscpdRun = captureNpm(['run', '--silent', 'deadcode:duplication']);
if (!existsSync(jscpdReport)) {
  fatal(
    `jscpd wrote no report (exit ${String(jscpdRun.status)}): ` +
      `${(jscpdRun.stderr || jscpdRun.stdout).trim().slice(0, 400)}`,
  );
}

let statistics;
try {
  statistics = JSON.parse(readFileSync(jscpdReport, 'utf8')).statistics.total;
} catch (error) {
  fatal(`could not read jscpd's report: ${error.message}`);
}

/**
 * The measured duplication, plus the denominator that makes it mean something.
 *
 * `percentage` is REPORTED rounded to 2 dp (so it can be compared with the
 * ceiling a human wrote) but COMPARED unrounded below: rounding first would let
 * a true 2.8949% pass a 2.89 ceiling that jscpd itself, which compares the raw
 * value, had just failed — the gate overruling the tool in the permissive
 * direction.
 */
const exactPercentage = Number(statistics.percentage);
const duplication = {
  percentage: Number(exactPercentage.toFixed(2)),
  clones: Number(statistics.clones),
  duplicatedLines: Number(statistics.duplicatedLines),
  totalLines: Number(statistics.lines),
  sources: Number(statistics.sources),
  ceiling,
};

// A scan of nothing duplicates nothing. Point `.jscpd.json`'s `path` at a
// directory that does not exist and every number above is 0, which reads as a
// pristine codebase — so the denominator has a floor, the same guard
// `license-gate.mjs` uses on its package closure. These are collapse detectors,
// deliberately far below the measured 190 files / 52,851 lines rather than
// ratchets: files get deleted for good reasons, and the ratchet is where
// direction is enforced.
if (duplication.sources < MIN_EXPECTED_SOURCES || duplication.totalLines < MIN_EXPECTED_LINES) {
  fatal(
    `jscpd scanned ${String(duplication.sources)} file(s) / ${String(duplication.totalLines)} line(s), ` +
      `expected at least ${String(MIN_EXPECTED_SOURCES)} / ${String(MIN_EXPECTED_LINES)} — the scan ` +
      'covered almost nothing, and duplication measured over nothing is 0%',
  );
}

// ---------------------------------------------------------------------------
// report
// ---------------------------------------------------------------------------
const overCeiling = exactPercentage > ceiling;
const report = {
  version: 1,
  checkedAt: new Date().toISOString(),
  deadcode,
  duplication,
  findings: knipFindings,
};
writeJsonReport('deadcode.json', report);
if (asJson) process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);

if (unusedTotal > 0) {
  console.error(color.red(`\n${symbol.fail} Unused code:\n`));
  for (const finding of knipFindings.slice(0, 40)) {
    console.error(
      `  ${color.cyan(finding.file)}  ${color.yellow(`[${finding.category}]`)} ${finding.name ?? ''}`,
    );
  }
  if (knipFindings.length > 40) {
    console.error(color.gray(`  … ${String(knipFindings.length - 40)} more (see deadcode.json)`));
  }
  console.error(
    color.gray(
      '\n  Delete it. An unused export that is used inside its own module loses the `export` ' +
        'keyword;\n  a dependency that is genuinely used gets declared. Adding an ignore entry is ' +
        'not an option.\n',
    ),
  );
}

if (overCeiling) {
  console.error(
    color.red(
      `\n${symbol.fail} Duplication ${String(duplication.percentage)}% exceeds the ceiling ${String(ceiling)}% ` +
        `(${String(duplication.clones)} clones, ${String(duplication.duplicatedLines)} of ${String(duplication.totalLines)} lines)`,
    ),
  );
  console.error(
    color.gray('  The ceiling is the measured value and only moves down. Factor the clone out.\n'),
  );
}

if (unusedTotal > 0 || overCeiling) process.exit(EXIT_FINDINGS);

console.log(
  color.green(
    `${symbol.pass} deadcode: 0 unused files/exports/dependencies · ` +
      `duplication ${String(duplication.percentage)}% of ${String(duplication.totalLines)} lines ` +
      `(ceiling ${String(ceiling)}%, ${String(duplication.clones)} clones)`,
  ),
);
process.exit(EXIT_OK);
