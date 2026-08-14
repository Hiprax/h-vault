#!/usr/bin/env node
/**
 * `coverage:check` — the coverage floors, and 100% on the lines this change
 * touched.
 *
 * The suites already fail below their configured thresholds, so this gate is not
 * here to repeat them. It is here for the two things a whole-tree percentage
 * cannot see:
 *
 *   1. A percentage is an AVERAGE over ~11,000 lines. A new module landing with
 *      no tests at all moves the client's 98.69% by hundredths — well inside the
 *      noise of ordinary work — so the number stays green while the code that
 *      shipped today is the code nothing asserts. Patch coverage asks the only
 *      question that scales: is what you just wrote covered?
 *   2. A file in NO coverage report is indistinguishable, in every report, from a
 *      file that does not exist. So a new production module added outside the
 *      measured scope reads as 100% patch coverage over zero lines. That is the
 *      hole that would make this gate's own claim false, and closing it is why
 *      `lib/coverage-scope.mjs` exists.
 *
 *   node scripts/ci/coverage-check.mjs      the gate (this is what the pipeline runs)
 *   npm run coverage:check                  the same thing
 *   HVAULT_DIFF_BASE=<ref> npm run coverage:check    compare against another ref
 *
 * Exit codes: 0 = green · 1 = a floor breached, an uncovered changed line, or an
 * unmeasured changed file · 2 = could not run.
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. THE ARTIFACTS COME FROM THE MANIFEST, NOT FROM A LIST HERE. `verify.json`
 *     already declares which task produces which Cobertura document; hard-coding
 *     the three paths would mean a fourth package could be added to the repo and
 *     to the manifest and still be silently ungated here.
 *
 *  b. A COVERAGE REPORT OLDER THAN THE FILES IT DESCRIBES IS REFUSED, and
 *     refused as "could not run" rather than failed. This gate is the one place
 *     a stale artifact is actively dangerous: `diff-cover` would compare TODAY's
 *     diff against YESTERDAY's execution data and report the new lines as
 *     covered, because the lines it is looking at are not the lines that ran.
 *     Inside the pipeline the ordering makes this unreachable (`dependsOn` the
 *     two suites); run by hand it is one forgotten `npm test` away.
 *
 *     "The files it describes" is the MEASURED SET, not the whole `src/` tree,
 *     and the distinction is what keeps this check from swallowing the one in
 *     (2) above. A brand-new production file is by definition newer than every
 *     report, but it does not make the report wrong about the files it does
 *     cover — it makes that file unmeasured, which is a FAILURE with a name
 *     rather than an unrunnable gate with a directory mtime.
 *
 *  c. THE VERDICT IS COMPUTED HERE, NOT TAKEN FROM `--fail-under`. diff-cover
 *     can fail a run on its own, but it knows nothing about the ledger, so a
 *     dated, expiring, approved exemption could not be honoured without either
 *     lowering `--fail-under` below 100 (a threshold weakened for everyone, to
 *     excuse one line) or post-processing its result. The second is what this
 *     does: diff-cover computes, the ledger excuses, and this file decides.
 *
 *  d. AN EXEMPTION IS A LEDGER ENTRY AND NOTHING ELSE. No pragma, no ignore
 *     file, no per-path exclusion list: `COV-DIFF-EXEMPT` in
 *     `.testfortress/suppressions.json`, pinned to one file, bounded by
 *     `maxHits`, owned, reasoned and DATED — so it expires on its own and the
 *     gate goes red again rather than staying quietly excused forever. Expiry is
 *     evaluated here as well as by the integrity scan, because an exemption that
 *     only the scanner polices would still be excusing lines after it lapsed.
 *
 *  e. THE DIFF BASE MUST RESOLVE, or the gate cannot run. Falling back to "no
 *     base, therefore nothing changed, therefore 100%" would turn every
 *     environment with an unusual checkout into a silent pass — which is the
 *     failure mode this whole tier exists to remove.
 */
import { existsSync, readFileSync, rmSync, statSync } from 'node:fs';
import path from 'node:path';
import { color, note, warn } from './lib/ui.mjs';
import { loadManifest, writeJsonReport } from './lib/reports.mjs';
import { repoRoot, captureExe } from './lib/proc.mjs';
import { parseLcov } from './lib/lcov.mjs';
import { inCoverageScope, packageOfPath, COVERAGE_SCOPE_GLOBS } from './lib/coverage-scope.mjs';

const TF = path.join(repoRoot, '.testfortress');
const EXIT_FAILED = 1;
const EXIT_CANNOT_RUN = 2;
/** The one rule id that excuses an uncovered changed line. See decision (d). */
const EXEMPT_RULE = 'COV-DIFF-EXEMPT';

const posix = (p) => p.split(path.sep).join('/');
const cannotRun = (message) => {
  console.error(color.red(`  ✖ coverage:check cannot run: ${message}`));
  process.exit(EXIT_CANNOT_RUN);
};

const git = (args) => {
  const result = captureExe('git', args);
  return result.ok ? result.stdout.trim() : null;
};

// ---------------------------------------------------------------------------
// (a) the coverage artifacts this repository declares
// ---------------------------------------------------------------------------
const { manifest, error: manifestError } = loadManifest();
if (manifestError) cannotRun(manifestError);

/** @type {{task: string, cobertura: string, lcov: string, package: string}[]} */
const artifacts = [];
for (const [task, spec] of Object.entries(manifest.tasks ?? {})) {
  for (const rel of spec?.coverage ?? []) {
    const cobertura = posix(rel);
    const pkg = packageOfPath(cobertura);
    if (!pkg) cannotRun(`${cobertura} (${task}) is not inside a package`);
    artifacts.push({
      task,
      package: pkg,
      cobertura,
      // Written by the same vitest run, beside the document the manifest names.
      lcov: posix(path.join(path.dirname(cobertura), 'lcov.info')),
    });
  }
}
if (artifacts.length === 0) {
  cannotRun('no task in .testfortress/verify.json declares a coverage report');
}

for (const artifact of artifacts) {
  for (const rel of [artifact.cobertura, artifact.lcov]) {
    if (!existsSync(path.join(repoRoot, rel))) {
      cannotRun(`${rel} is missing — run ${artifact.task} first`);
    }
  }
}

// ---------------------------------------------------------------------------
// the floors, from the baseline the ratchet also reads
// ---------------------------------------------------------------------------
const baselinePath = path.join(TF, 'baseline.json');
if (!existsSync(baselinePath)) cannotRun('.testfortress/baseline.json is missing');
const baseline = JSON.parse(readFileSync(baselinePath, 'utf8'));

const problems = [];
/** @type {Record<string, object>} */
const packages = {};
/** Repo-relative, so a changed file can be tested for membership. */
const measured = new Set();

for (const artifact of artifacts) {
  const parsed = parseLcov(readFileSync(path.join(repoRoot, artifact.lcov), 'utf8'));

  // (b) freshness, against the files this report claims to describe.
  const reportMtime = statSync(path.join(repoRoot, artifact.lcov)).mtimeMs;
  for (const rel of parsed.filesMeasured ?? []) {
    const source = path.join(repoRoot, artifact.package, rel);
    const stat = statSync(source, { throwIfNoEntry: false });
    if (stat && stat.mtimeMs > reportMtime) {
      cannotRun(
        `${artifact.package}/${rel} has changed since ${artifact.lcov} was written, so that report ` +
          'describes different code and every line number in it is suspect. ' +
          `Re-run ${artifact.task}.`,
      );
    }
  }

  for (const rel of parsed.filesMeasured ?? []) {
    measured.add(posix(path.join(artifact.package, rel)));
  }
  const floors = baseline.packages?.[artifact.package]?.coverage ?? {};
  // A metric with no recorded floor is not checked at all — the loop below
  // `continue`s past it — so deleting `branch` from one package's baseline block
  // would silently remove that gate while this one still printed "every package
  // floor held". Every metric is named individually rather than asking whether
  // ALL THREE are missing, because the partial case is the likelier edit and the
  // one that reads as intact. That is not a failing gate, it is an ABSENT one,
  // which is what exit 2 is for.
  const withoutFloor = ['line', 'branch', 'function'].filter(
    (metric) => typeof floors[metric] !== 'number',
  );
  if (withoutFloor.length > 0) {
    cannotRun(
      `${artifact.package} has a coverage report but no recorded floor for ` +
        `${withoutFloor.join(', ')} in .testfortress/baseline.json ` +
        `(packages["${artifact.package}"].coverage). ` +
        'A metric whose floor is missing is not being held to one.',
    );
  }
  const breached = [];
  for (const metric of ['line', 'branch', 'function']) {
    const floor = floors[metric];
    const got = parsed[metric];
    if (typeof floor !== 'number') continue;
    if (typeof got !== 'number') {
      problems.push(`${artifact.package}: ${metric} coverage could not be measured from LCOV`);
      continue;
    }
    if (got < floor) {
      breached.push(metric);
      problems.push(
        `${artifact.package}: ${metric} coverage is ${String(got)}%, below the recorded floor of ${String(floor)}% — ` +
          'coverage ratchets upward only',
      );
    }
  }
  packages[artifact.package] = {
    task: artifact.task,
    line: parsed.line,
    branch: parsed.branch,
    function: parsed.function,
    linesTotal: parsed.linesTotal,
    filesMeasured: parsed.filesMeasured?.length ?? 0,
    floors: {
      line: floors.line ?? null,
      branch: floors.branch ?? null,
      function: floors.function ?? null,
    },
    breached,
  };
}

// ---------------------------------------------------------------------------
// (e) the diff base
// ---------------------------------------------------------------------------
const requestedBase = process.env['HVAULT_DIFF_BASE'];
const candidates = requestedBase ? [requestedBase] : ['main', 'origin/main'];
const base = candidates.find((ref) => git(['rev-parse', '--verify', '--quiet', `${ref}^{commit}`]));
if (!base) {
  cannotRun(
    `none of ${candidates.join(', ')} resolves to a commit, so there is no trunk to compare against. ` +
      'Set HVAULT_DIFF_BASE to the ref this branch forked from.',
  );
}
if (!git(['rev-parse', '--verify', '--quiet', 'HEAD^{commit}'])) {
  cannotRun('HEAD does not resolve to a commit, so there is nothing to diff');
}
const rawMergeBase = git(['merge-base', base, 'HEAD']) ?? base;
const headSha = git(['rev-parse', 'HEAD']);
/**
 * A build ON the trunk has no diff against the trunk, and "no changed lines" is
 * reported as 100% patch coverage — so this gate checked NOTHING for exactly the
 * run that matters most: `release.yml` builds a push to `main`, where `main` and
 * `HEAD` are the same commit. Anyone committing straight to `main` locally got
 * the same free pass.
 *
 * The last commit is the honest subject there: on the trunk, "this change" IS
 * `HEAD^..HEAD`. A repository whose HEAD has no parent keeps the empty diff,
 * because there is genuinely nothing before it to compare with.
 */
const onTrunk = headSha !== null && rawMergeBase === headSha;
const firstParent = onTrunk ? git(['rev-parse', '--verify', '--quiet', 'HEAD^{commit}~1']) : null;
// A trunk build whose HEAD has no parent is one of two very different things: a
// genuine root commit (there is nothing before it, and an empty diff is honest),
// or a SHALLOW clone whose graft boundary is HEAD (the history exists and this
// machine cannot see it, so an empty diff is a lie that reads as 100%). They are
// indistinguishable from the rev alone, so ask git which one this is.
if (onTrunk && firstParent === null && git(['rev-parse', '--is-shallow-repository']) === 'true') {
  cannotRun(
    'this is a shallow clone of the trunk, so the commit before HEAD is not present and ' +
      '"the lines this change touched" cannot be identified. Fetch the history (fetch-depth: 0) ' +
      'and re-run.',
  );
}
const mergeBase = firstParent ?? rawMergeBase;

// ---------------------------------------------------------------------------
// the changed production files: committed, staged, unstaged and untracked
//
// Enumerated here as well as inside diff-cover because the two answer different
// questions. diff-cover reports on the changed lines it can find IN A COVERAGE
// REPORT; this set is every changed production file, including the ones no
// report mentions — which is the whole point of the check below.
// ---------------------------------------------------------------------------
const lines = (out) => (out ? out.split('\n').filter(Boolean).map(posix) : []);
const changedFiles = new Set([
  // Two dots, from the ALREADY-RESOLVED merge base: `a...b` asks git to resolve
  // the merge base itself, which would be the same answer computed twice and a
  // second place for the two halves of this gate to disagree about what "since
  // the trunk" means.
  ...lines(git(['diff', '--name-only', '--diff-filter=d', `${mergeBase}..HEAD`])),
  ...lines(git(['diff', '--name-only', '--diff-filter=d', 'HEAD'])),
  ...lines(git(['ls-files', '--others', '--exclude-standard'])),
]);
const changedProduction = [...changedFiles]
  .filter((rel) => inCoverageScope(rel))
  .filter((rel) => existsSync(path.join(repoRoot, rel)))
  .sort();

const unmeasured = changedProduction.filter((rel) => !measured.has(rel));
for (const rel of unmeasured) {
  problems.push(
    `${rel} is production code inside the measured scope but appears in no coverage report, ` +
      'so its patch coverage is unknown rather than 100% — a file nothing measured looks ' +
      'exactly like a file that does not exist. Either it has no tests, or the suites have ' +
      'not been re-run since it was added.',
  );
}

// ---------------------------------------------------------------------------
// (c) diff-cover computes; the ledger excuses; this file decides
// ---------------------------------------------------------------------------
const diffJson = path.join(TF, 'reports', 'diff-cover.json');
// Deleted BEFORE the tool runs, for the same reason `local-ci.mjs` clears every
// gate's declared reports: a document left by an earlier run would make the
// "did diff-cover produce a result?" check pass for a run that produced
// nothing, and this gate would then measure yesterday's diff against today's
// tree and report it as green.
rmSync(diffJson, { force: true });
const diffCover = captureExe('diff-cover', [
  ...artifacts.map((artifact) => artifact.cobertura),
  // The RESOLVED base, not the ref: on a branch the two are the same answer
  // (`diff-cover` resolves `main...HEAD` to this very commit), and on the trunk
  // — where `main` IS `HEAD` — passing the ref means diffing a commit against
  // itself and reporting 100% over zero lines. See `mergeBase` above.
  '--compare-branch',
  mergeBase,
  '--include-untracked',
  '--format',
  `json:${diffJson}`,
  '--quiet',
]);
if (!existsSync(diffJson)) {
  cannotRun(
    `diff-cover wrote no report (exit ${String(diffCover.status)}). ${diffCover.stderr.trim() || diffCover.stdout.trim()}`,
  );
}
const diff = JSON.parse(readFileSync(diffJson, 'utf8'));

// ---------------------------------------------------------------------------
// (d) the ledger
// ---------------------------------------------------------------------------
const today = new Date().toISOString().slice(0, 10);
let ledgerEntries = [];
try {
  ledgerEntries =
    JSON.parse(readFileSync(path.join(TF, 'suppressions.json'), 'utf8')).entries ?? [];
} catch {
  // No ledger is not an error: it means nothing is excused.
}
const exemptions = ledgerEntries.filter((entry) => entry.rule === EXEMPT_RULE);

/** @type {{file: string, lines: number[], exempted: number[], entry: string|null}[]} */
const uncovered = [];
let exemptedLines = 0;
let unexcusedLines = 0;

for (const [file, stats] of Object.entries(diff.src_stats ?? {})) {
  const violations = stats.violation_lines ?? [];
  if (violations.length === 0) continue;
  const rel = posix(file);
  const entry = exemptions.find((candidate) => posix(candidate.file ?? '') === rel);
  const live = entry && entry.expires >= today ? entry : null;
  const capacity = live ? (live.maxHits ?? 1) : 0;
  const exempted = violations.slice(0, capacity);
  const remaining = violations.slice(capacity);
  exemptedLines += exempted.length;
  unexcusedLines += remaining.length;
  uncovered.push({
    file: rel,
    lines: violations,
    exempted,
    entry: live?.id ?? null,
  });
  if (remaining.length > 0) {
    const because = entry
      ? live
        ? `${live.id} covers only ${String(capacity)} line(s)`
        : `${entry.id} expired on ${entry.expires}`
      : 'no COV-DIFF-EXEMPT ledger entry covers it';
    problems.push(
      `${rel}: ${String(remaining.length)} changed line(s) are not covered — ` +
        `${remaining.slice(0, 8).join(', ')}${remaining.length > 8 ? ', …' : ''} (${because})`,
    );
  }
}

// An exemption nobody is using is debt provisioned and never paid down; the same
// rule the integrity scan applies to its own entries. An EXPIRED entry is
// skipped here: it has already been reported above as the reason its file's
// lines are unexcused, and reporting it twice sends the reader after two
// problems where there is one.
for (const entry of exemptions) {
  if (entry.expires < today) continue;
  const used = uncovered.find((row) => row.entry === entry.id);
  if (!used) {
    problems.push(
      `${entry.id} exempts ${String(entry.file)} from diff coverage but no uncovered changed line there needs it — prune the entry (this is the good outcome)`,
    );
  }
}

// ---------------------------------------------------------------------------
// report and verdict
// ---------------------------------------------------------------------------
const totalLines = diff.total_num_lines ?? 0;
// With no changed production line there is nothing to be uncovered, and 100 is
// the honest reading: it is the value the ratchet pins, and reporting `null`
// here would make the field UNMEASURED on every run against an unchanged tree.
const measuredPercent = totalLines === 0 ? 100 : (diff.total_percent_covered ?? 0);
/**
 * What the ratchet compares, and it counts a LEDGERED line as covered.
 *
 * `coverage.diff` is pinned at 100, so reporting the raw percentage would mean a
 * dated, approved, judge-signed exemption turned this gate green and
 * `audit:ratchet:full` red — an escape valve blocked by a second gate nobody
 * routed it through.
 *
 * What bounds the debt is the ledger entry itself, and it is worth stating
 * exactly, because an earlier version of this comment claimed the entry counts
 * against `suppressions.count` and it does not: `COV-DIFF-EXEMPT` is in the
 * ledger's `exemptFromTotal`, precisely so a sanctioned escape valve is not
 * blocked by the ceiling it exists to lower. It is bounded instead by the three
 * things every entry carries — an expiry no more than 90 days out, at most
 * `maxHitsPerEntry` occurrences, and a named approver (`policy.requireApproval`,
 * which the scanner enforces as a non-empty `approvedBy`) — plus the raw
 * percentage reported beside this one, so the uncovered line is visible in the
 * artifact even while it is excused.
 */
const effectivePercent =
  totalLines === 0 ? 100 : +(((totalLines - unexcusedLines) / totalLines) * 100).toFixed(2);

writeJsonReport('coverage.json', {
  version: 1,
  task: 'coverage:check',
  checkedAt: new Date().toISOString(),
  // What the ratchet reads. Everything else here is evidence for a human.
  coverage: { diff: effectivePercent },
  diff: {
    base,
    mergeBase,
    // True when this build IS the trunk, so the subject is `HEAD~1..HEAD` rather
    // than a branch's whole diff. Recorded because it changes what the number
    // below describes.
    onTrunk,
    describedAs: diff.diff_name,
    totalLines,
    coveredPercent: measuredPercent,
    effectivePercent,
    uncoveredLines: diff.total_num_violations ?? 0,
    exemptedLines,
    unexcusedLines,
    changedProductionFiles: changedProduction,
    unmeasuredFiles: unmeasured,
    uncovered,
  },
  packages,
  scopeGlobs: COVERAGE_SCOPE_GLOBS,
  problems,
});

if (problems.length > 0) {
  for (const problem of problems) console.error(color.red(`      ${problem}`));
  warn(`${String(problems.length)} coverage violation(s)`);
  process.exit(EXIT_FAILED);
}

note(
  // The EFFECTIVE base, not the ref: on the trunk they differ, and a line that
  // says "vs main" while the subject was `HEAD~1` describes a comparison nobody
  // made.
  `coverage.json — ${String(totalLines)} changed production line(s) vs ${onTrunk ? `${base} (HEAD~1)` : base}, ` +
    `${String(measuredPercent)}% covered${exemptedLines > 0 ? ` (${String(exemptedLines)} ledgered)` : ''}, ` +
    `${String(changedProduction.length)} changed file(s) all measured, every package floor held`,
);
