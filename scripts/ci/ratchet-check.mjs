#!/usr/bin/env node
/**
 * `audit:ratchet` — the half of the anti-cheat surface a line scan cannot see.
 *
 * `integrity-scan.mjs` finds markers. The cheat it cannot find is moving the
 * goalposts: a coverage or mutation percentage whose DENOMINATOR the author
 * controls is not a gate at all, because narrowing the measured scope raises the
 * number while covering less code, and nothing in the diff distinguishes a
 * legitimate `include` from a narrowed one — the difference is direction, not
 * syntax. Direction is what this file enforces, against
 * `.testfortress/baseline.json`.
 *
 *   node scripts/ci/ratchet-check.mjs                      compare everything
 *   node scripts/ci/ratchet-check.mjs --tier 0             the cheap fields only
 *   node scripts/ci/ratchet-check.mjs --json               report on stdout
 *   node scripts/ci/ratchet-check.mjs --accept --reason "" record improvements
 *
 * Exit codes: 0 = no regression · 1 = regression or unmeasured field · 2 = could
 * not run.
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. RATCHET THE MEASURED FILE SET, NOT THE CONFIG GLOBS. "scopeGlobs may not
 *     shrink" is unenforceable: the standard way to narrow coverage scope GROWS
 *     the glob list (`["src/**"]` becomes `["src/**", "!src/legacy/**"]`), so a
 *     superset check on globs passes the exact cheat it was meant to catch.
 *     Every coverage report enumerates the files it instrumented, so that set is
 *     what is compared. It reads the EFFECT rather than the DECLARATION.
 *
 *  b. EVERY FIELD DECLARES A DIRECTION, AND AN UNDECLARED ONE IS A HARD ERROR.
 *     "Upward" is wrong for more than half of these: warnings,
 *     `suppressions.count`, `suppressions.totalHits` and `flake.failures` are
 *     all lower-is-better, so there is no safe default and this file refuses to
 *     guess. A wrong default would silently record a regression as an
 *     improvement.
 *
 *  c. A MISSING REPORT IS A FAILURE, NEVER A PASS. Deleting a task from the
 *     manifest removes its numbers, and a ratchet that skips absent metrics then
 *     guards nothing. Skipping a test gate therefore makes this gate red: the
 *     remedy is to run the gate, never to delete the baseline field. The ONE
 *     exception is named, narrow and conditional — see DEFERRABLE, which covers
 *     a measurement whose gate is registered at TIER 2 and therefore does not
 *     run on a push at all. Deferral survives only while the owning task is
 *     still registered at that tier, and the owning gate enforces the same floor
 *     itself; delete or move it and the fields go back to being hard failures.
 *
 *  d. A FIELD THAT NEVER ENTERS THE BASELINE HAS NO GATE. This is the mirror of
 *     (c) and the easier mistake, because it is silent: omitting
 *     `coverage.filesMeasured` disables the scope-narrowing defence with no
 *     signal at all. So the required fields are checked for PRESENCE, and the
 *     baseline's own sorted field list is pinned, which makes deleting a field
 *     later a regression in its own right.
 *
 *  e. PATHS ARE NORMALISED TO REPO-RELATIVE POSIX. LCOV writes absolute `SF:`
 *     paths and a clean-room run happens inside a temporary worktree, so an
 *     un-normalised file set reports every file as lost and the release gate
 *     could never pass.
 *
 *  f. A REPORT OLDER THAN THE NEWEST SOURCE FILE DESCRIBES A DIFFERENT TREE.
 *     Without that check a stale artifact validates a changed one: delete two
 *     hundred tests, do not re-run the suite, and yesterday's JUnit still
 *     satisfies `tests.count`.
 *
 *  g. `--accept` MOVES EACH FIELD ONLY IN ITS IMPROVING DIRECTION, requires a
 *     reason, and refuses while anything is failing or unmeasured. There is no
 *     flag that worsens a number. A justified reduction is a
 *     `BASELINE-REDUCTION` ledger entry plus judge sign-off, which the scanner
 *     exempts from the entry ceiling so the escape valve is not self-blocking.
 *
 * ---------------------------------------------------------------------------
 * PORT NOTES — deliberate differences from the reference implementation.
 * ---------------------------------------------------------------------------
 *
 *  1. `flake.*` AND `mutation.*` ARE REQUIRED CONDITIONALLY, NOT UNCONDITIONALLY.
 *     This note used to say neither had an extractor and that the phase adding
 *     one would move the fields into REQUIRED_FIELDS outright. Phases 16 and 19
 *     shipped `test:mutation` and `test:flake`, and outright is the wrong shape:
 *     under (c) a baseline field with no report is a hard failure, so a field
 *     required before its gate has ever produced a measurement defines a
 *     permanently red gate — and the cheapest escape from one of those is
 *     deleting baseline fields, which is the pressure this file exists to
 *     remove. Both are therefore required the moment a baseline carries their
 *     block at all (MUTATION_REQUIRED_FIELDS, FLAKE_REQUIRED_FIELDS), which is
 *     strict from the first real run and unsatisfiable in no state. The tier-2
 *     half of the problem — a gate that is registered but does not run on a push
 *     — is handled by DEFERRABLE rather than by leaving the field out.
 *     `selftest`'s per-task registry enforces the registration obligation.
 *  2. REQUIRED FIELDS ARE SATISFIED PER PACKAGE. In a monorepo the honest place
 *     for coverage is `packages.<pkg>.coverage.*`; a global average lets a
 *     well-tested package subsidise a neglected one. So presence is checked
 *     against both the plain path and the per-package form.
 *  3. THE TIER SELECTS WHICH REPORTS ARE READ, not merely which fields are
 *     compared. `audit:ratchet` runs inside T0, before the suites have run in
 *     that same invocation, so walking every artifact would read JUnit and
 *     coverage files from the PREVIOUS run and report them stale — a red gate
 *     produced by the runner's own ordering rather than by anything wrong. T0
 *     reads the reports that supply T0 fields, and nothing else.
 *  4. A METRIC WHOSE INPUT REPORT IS ABSENT IS UNMEASURED, NEVER PARTIAL. The
 *     manifest says which JUnit and coverage artifacts a full run produces; if
 *     one is missing, `tests.count` is reported UNMEASURED instead of being
 *     summed from the survivors. A partial sum would read as "200 tests were
 *     deleted", which sends the reader after the wrong problem.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
// The committed BUDGETS, imported as source rather than read from a report, for
// the reason `tasks` is read from the manifest: they are not measurements, they
// are the ceilings, and a ceiling that may only move DOWN is exactly the kind of
// thing this file exists to pin. Reading them from source also means they are
// always available — `test:resource` is Tier 2 and does not run during a push, so
// a budget sourced from its report would be UNMEASURED on every push and turn
// this gate permanently red (port note 1's mistake, one layer along).
import {
  CHUNK_BUDGETS_KB,
  DEFAULT_CHUNK_BUDGET_KB,
  HTML_SHELL_BUDGET_KB,
  INITIAL_PAYLOAD_BUDGET_KB,
} from './lib/bundle-budgets.mjs';
import { RESOURCE_BUDGETS } from './lib/resource-budgets.mjs';
// The one function shared with the mutation gate: a core module is a PATH, and
// a baseline key may not contain a dot. Imported rather than restated so the
// gate that writes `mutation.modules.*` and the gate that reads it cannot
// disagree about what a module key is.
import { moduleKey } from './lib/mutation-scope.mjs';
// The one parser for an LCOV document, shared with `coverage-check.mjs` — see
// `fromLcov` below. `pct` comes with it for the same reason.
import { parseLcov, pct } from './lib/lcov.mjs';

const ROOT = process.cwd();
const TF = join(ROOT, '.testfortress');
const BASELINE = join(TF, 'baseline.json');
const MANIFEST = join(TF, 'verify.json');
const REPORTS = join(TF, 'reports');

const argv = process.argv.slice(2);
const has = (f) => argv.includes(f);
const val = (f) => {
  const i = argv.indexOf(f);
  if (i >= 0 && argv[i + 1] && !argv[i + 1].startsWith('--')) return argv[i + 1];
  const inline = argv.find((a) => a.startsWith(`${f}=`));
  return inline ? inline.slice(f.length + 1) : undefined;
};
const fail = (m) => {
  console.error(`ratchet-check: ${m}`);
  process.exit(2);
};

// ---------------------------------------------------------------------------
// (b) the direction map. No default: an unlisted field is an error.
// ---------------------------------------------------------------------------
const DIRECTION = {
  'coverage.line': 'higher',
  'coverage.branch': 'higher',
  'coverage.function': 'higher',
  'coverage.statement': 'higher',
  'coverage.diff': 'higher',
  'coverage.linesTotal': 'higher',
  'coverage.filesMeasured': 'superset',
  'coverage.scopeGlobs': 'info',
  'mutation.overall': 'higher',
  'mutation.totalMutants': 'higher',
  'mutation.filesMutated': 'superset',
  'mutation.scopeGlobs': 'info',
  'mutation.modules.*': 'higher',
  'tests.count': 'higher',
  // Duplication and unused code: every one of these is lower-is-better, and
  // `duplication.ceiling` is here deliberately. It mirrors `.jscpd.json`'s
  // `threshold`, which is what jscpd itself fails on, so raising that ceiling to
  // make room for a new clone is a regression this file rejects — the number
  // that enforces the rule cannot be edited without tripping the rule.
  'duplication.percentage': 'lower',
  'duplication.clones': 'lower',
  'duplication.duplicatedLines': 'lower',
  'duplication.ceiling': 'lower',
  // The two denominators are `info`: source files and lines both move for
  // legitimate reasons, and gating them would punish deleting code. They cannot
  // be gamed to lower the percentage either, because `clones` and
  // `duplicatedLines` are ratcheted in ABSOLUTE terms. A scan that collapses to
  // nothing is caught in the gate itself, by a floor on both.
  'duplication.totalLines': 'info',
  'duplication.sources': 'info',
  'deadcode.*': 'lower',
  // Config-lint debt, per tool. One scalar over three linters would let a
  // hadolint regression hide behind a spectral improvement, so each is ratcheted
  // separately; `inputsExamined` is higher-is-better because a leg that examines
  // fewer files than it used to is a weaker gate, whatever its finding count says.
  'config.belowError.*': 'lower',
  'config.inputsExamined.*': 'higher',
  // The SIZE of the committed OpenAPI base, for the same reason as
  // `config.inputsExamined` and `a11y.viewsScanned`: an addition is never a
  // breaking change, so a snapshot that shrank makes `audit:openapi` report "0
  // breaking changes" having compared the served contract against almost
  // nothing. The finding count cannot show that; the denominator can. Removing
  // an endpoint in a genuine MAJOR release therefore costs an `--accept` with a
  // written reason, which is exactly the friction that decision deserves.
  'openapi.snapshotPaths': 'higher',
  'openapi.snapshotOperations': 'higher',
  // Accessibility. The two impacts that FAIL the gate are ratcheted at zero, so
  // the number cannot creep; `viewsScanned` is higher-is-better because an axe
  // run over nothing reports zero violations exactly like an axe run over a
  // clean page — a shrinking surface is the one regression the violation counts
  // themselves can never show. The `moderate` and `minor` findings are recorded
  // in `a11y.json` and deliberately NOT ratcheted: gating them would mean a new
  // view could not be added until its unrelated landmark debt was paid off,
  // which prices scanning MORE of the application as a regression.
  'a11y.critical': 'lower',
  'a11y.serious': 'lower',
  'a11y.viewsScanned': 'higher',
  // Size and volume budgets. These are CEILINGS, not measurements, so
  // lower-is-better means "a budget may be tightened, never quietly raised".
  // Their measured counterparts are `info`: a chunk that grows within its budget
  // is ordinary feature work, and gating every byte would price adding a page as
  // a regression. What must not happen silently is the ceiling moving to
  // accommodate one.
  'bundle.budgetKb.*': 'lower',
  'bundle.defaultChunkBudgetKb': 'lower',
  'bundle.initialPayloadBudgetKb': 'lower',
  'bundle.htmlShellBudgetKb': 'lower',
  'bundle.measured.*': 'info',
  'resource.budgetMs.*': 'lower',
  'resource.budgetRssMb.*': 'lower',
  'resource.deliveredFractionCeiling.*': 'lower',
  'resource.noiseBandPct.*': 'info',
  'warnings.*': 'lower',
  'suppressions.count': 'lower',
  'suppressions.totalHits': 'lower',
  // Two sample sizes and one failure count, and the directions are what make the
  // trio a gate rather than a statistic. `runs` and `e2eExecutions` are
  // higher-is-better so NEITHER half of the sample can quietly shrink — dropping
  // the end-to-end leg entirely would otherwise LOWER `failures`, which reads as
  // an improvement. `failures` is lower-is-better so an observed flake can never
  // be accepted into the baseline and stop being a failure.
  'flake.runs': 'higher',
  'flake.e2eExecutions': 'higher',
  'flake.failures': 'lower',
  'performance.p95Ms.*': 'lower',
  'performance.p99Ms.*': 'lower',
  'performance.peakRssMb.*': 'lower',
  'performance.cpuSeconds.*': 'lower',
  'performance.artifactSizeKb.*': 'lower',
  'performance.bundleSizeKb.*': 'lower',
  'performance.noiseBandPct.*': 'info',
  tasks: 'superset',
  'meta.fields': 'superset',
  'integrity.*': 'pin',
};

/**
 * (d) Absent from the baseline means no gate at all, so these must be present.
 * `mutation.filesMutated` and `flake.*` are deliberately absent from this list
 * until their extractors exist — see port note 1.
 */
const REQUIRED_FIELDS = [
  'coverage.filesMeasured', // the scope-narrowing defence
  'suppressions.count',
  'suppressions.totalHits',
  'tasks', // a disappearing gate is a regression
  'meta.fields', // a disappearing baseline field is a regression
  'integrity', // the scanner's blind-spot fingerprints
];

/**
 * The mutation oracle's two load-bearing fields, required as soon as the
 * baseline carries a `mutation` block AT ALL.
 *
 * Conditional rather than unconditional, and the condition is the honest half of
 * the rule. Before the first complete run there is no measurement, and the two
 * ways to satisfy an unconditional requirement then are both worse than waiting:
 * invent a number, or record one from a partial run over a fraction of the
 * declared scope. Once a real block exists the pair is mandatory, because a
 * block carrying `overall` without `filesMutated` reads as a gate while
 * silently disabling the scope-narrowing defence — the mutation-side twin of
 * omitting `coverage.filesMeasured`.
 *
 * Deleting the block to escape the requirement is not a way out: `meta.fields`
 * pins the baseline's own sorted field list as a superset, so removing a field
 * that was once recorded is itself a regression.
 */
const MUTATION_REQUIRED_FIELDS = ['mutation.overall', 'mutation.filesMutated'];

/**
 * The flake hunt's three load-bearing fields, required as soon as the baseline
 * carries a `flake` block AT ALL. Same conditional shape as
 * MUTATION_REQUIRED_FIELDS, for the same reason and one more that is specific to
 * this gate and sharper.
 *
 * THE SHARED REASON. Before the first complete run there is no measurement, and
 * both ways to satisfy an unconditional requirement then are worse than waiting:
 * invent a number, or record one from a shortened sample. `flake-run.mjs`
 * refuses to write a report at all under `--runs`/`--only` precisely so the
 * second cannot happen by accident.
 *
 * THE REASON SPECIFIC TO THIS GATE, and it is why the requirement lives here
 * rather than in `gate-surface.test.ts` where the equivalent mutation assertions
 * sit. `test:flake` runs every package suite TEN TIMES, and `gate-surface.test.ts`
 * is inside that suite. An assertion there that "the baseline carries a flake
 * record" would be a postcondition of the run asserting itself mid-run: ten runs
 * would each fail that one test, `flake.json` would report `failures: 10`, and
 * `--accept` refuses a failing report — so the record could never be written,
 * and the gate could never go green by any change to production code. That is
 * not a strict gate, it is an unsatisfiable one, and an unsatisfiable gate is
 * deleted rather than met. Checking it HERE puts it outside the sample it
 * describes, where it can actually bind.
 *
 * All three fields, not just `failures`: a zero-run sample also reports zero
 * failures, so `runs` and `e2eExecutions` are what make that number mean
 * anything. Deleting the block to escape the requirement is not a way out —
 * `meta.fields` pins the baseline's own field list as a superset.
 */
const FLAKE_REQUIRED_FIELDS = ['flake.runs', 'flake.failures', 'flake.e2eExecutions'];

/** Fields cheap enough for T0: no test artifact needed. */
const TIER0_PREFIXES = ['suppressions.', 'integrity.', 'tasks', 'meta.fields'];
/** (Port note 3) Which reports T0 is allowed to read. */
const TIER0_REPORTS = ['integrity.json'];

/**
 * Measurements produced by a TIER 2 gate, and what to do when they are absent.
 *
 * This is the narrow, named exception to decision (c), and it exists because
 * decision (c) and the tier system otherwise contradict each other. `test:mutation`
 * is Tier 2: it is hours long and does not run during `npm run ci`. Requiring a
 * FRESH `mutation.json` on every push would therefore make `audit:ratchet:full`
 * permanently red — and the cheapest escape from a permanently red gate is
 * deleting the baseline fields, which is the pressure this file exists to remove.
 *
 * DEFERRED IS NOT SKIPPED. Three things hold the field to account instead:
 *
 *   1. `owner` must still be a registered task at `tier`. Deleting `test:mutation`
 *      from the manifest, or quietly moving it to a tier that never runs, turns
 *      every field under `prefix` back into a hard UNMEASURED failure. (`tasks`
 *      is separately ratcheted as a superset, so the deletion fails twice.)
 *   2. The owning gate enforces the same floor ITSELF, at the moment it has the
 *      number: `mutation-gate.mjs` reads this baseline and fails on a lower
 *      score, a smaller denominator or a lost file. The ratchet is the second
 *      reader, not the only one.
 *   3. When the report IS fresh — inside `verify:full`, where the gate runs
 *      before this one — every field is compared for real, superset check
 *      included. Deferral is a property of the run, not of the field.
 *
 * `flake.*` is here for exactly the same reason and under exactly the same three
 * conditions. `test:flake` is ten complete runs of every suite plus the whole
 * Playwright suite three times over — about an hour — so it is Tier 2 and does
 * not run on a push. Its own gate enforces the floor at the moment it has the
 * number (zero failures, or it exits 1), `test:flake` must still be a registered
 * tier-2 task or both fields become hard UNMEASURED failures, and inside
 * `verify:full` the report IS fresh and both are compared for real.
 *
 * Note which direction each moves, because they are opposites and that is the
 * point: `flake.runs` is higher-is-better, so the SAMPLE can never quietly
 * shrink — a gate that dropped to three runs would otherwise report a cleaner
 * bound over less evidence — while `flake.failures` is lower-is-better, so an
 * observed flake can never quietly be normalised into the baseline.
 */
const DEFERRABLE = [
  { prefix: 'mutation.', report: 'mutation.json', owner: 'test:mutation', tier: 2 },
  { prefix: 'flake.', report: 'flake.json', owner: 'test:flake', tier: 2 },
];

const deferrableForReport = (base) => DEFERRABLE.find((entry) => entry.report === base);
const deferrableForField = (path) => DEFERRABLE.find((entry) => path.startsWith(entry.prefix));

function directionFor(path, problems) {
  const direct = DIRECTION[path];
  if (direct) return direct;
  const wild = DIRECTION[path.replace(/\.[^.]+$/, '.*')];
  if (wild) return wild;
  problems.push(path);
  return null;
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
const posix = (p) => p.split(sep).join('/');

/** (e) repo-relative POSIX, so absolute LCOV paths and clean-room worktrees compare. */
function normPath(p) {
  let s = posix(String(p)).trim();
  const r = posix(ROOT);
  if (s.startsWith(r)) s = s.slice(r.length);
  const m = s.match(/(?:^|\/)((?:packages|scripts|e2e|src|lib|app|tests?)\/.*)$/);
  if (m) s = m[1];
  return s.replace(/^\.?\//, '');
}

function safeStat(p) {
  try {
    return statSync(p);
  } catch {
    return null;
  }
}

function walk(dir, out = []) {
  let names;
  try {
    names = readdirSync(dir);
  } catch {
    return out;
  }
  for (const n of names) {
    const p = join(dir, n);
    const st = safeStat(p);
    if (!st) continue;
    if (st.isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}

/** (f) newest source mtime: any report older than this describes a different tree. */
function newestSourceMtime() {
  let newest = 0;
  try {
    const out = execFileSync(
      'git',
      ['ls-files', '-z', '--cached', '--others', '--exclude-standard'],
      {
        cwd: ROOT,
        maxBuffer: 128 << 20,
      },
    ).toString('utf8');
    for (const rel of out.split('\0').filter(Boolean)) {
      const p = posix(rel);
      // `.testfortress/` holds the gate surface itself (manifest, ledger,
      // baseline, reports); editing the ledger must not invalidate the reports
      // it is compared against.
      if (p.startsWith('.testfortress/') || p.includes('node_modules/')) continue;
      const st = safeStat(join(ROOT, rel));
      if (st && st.mtimeMs > newest) newest = st.mtimeMs;
    }
  } catch {
    /* not a repo: no freshness check is possible */
  }
  return newest;
}

// ---------------------------------------------------------------------------
// extractors. Each returns a flat { "path.to.field": value } map.
// Regex-based so this file stays dependency-free, which is adequate for the
// well-formed output of the tools named and is the first thing to replace with
// a real parser if that stops being true.
// ---------------------------------------------------------------------------
/**
 * The LCOV totals, parsed by `lib/lcov.mjs` rather than here.
 *
 * `coverage-check.mjs` enforces the same floors at the moment it measures them,
 * and two readers of one artifact is the intended shape — but two PARSERS of it
 * would eventually disagree about what "the branch percentage" means, and the
 * more generous one would be whichever happened to run. This function is now
 * only the mapping from those totals onto baseline field names.
 */
function fromLcov(text) {
  const totals = parseLcov(text, normPath);
  return {
    'coverage.line': totals.line,
    'coverage.branch': totals.branch,
    'coverage.function': totals.function,
    'coverage.linesTotal': totals.linesTotal,
    'coverage.filesMeasured': totals.filesMeasured,
  };
}

function fromJunit(xml) {
  const outer = xml.match(/<testsuites[^>]*\btests="(\d+)"/);
  if (outer) return Number(outer[1]);
  const suites = [...xml.matchAll(/<testsuite[^>]*\btests="(\d+)"/g)].map((m) => Number(m[1]));
  return suites.length ? suites.reduce((a, b) => a + b, 0) : undefined;
}

/**
 * The mutation report, read as EVIDENCE rather than as a headline.
 *
 * Three things here are deliberate:
 *
 *  - The score is RECOMPUTED from the per-mutant statuses. `mutation.json`
 *    carries an `overall` of its own, and it is not read: a gate that reports a
 *    number it did not measure is exactly what this file exists to catch, and
 *    the two computations disagreeing is a defect worth surfacing rather than
 *    hiding behind whichever one is more convenient.
 *  - `Ignored` mutants are excluded from the denominator, matching the gate's
 *    own definition and Stryker's. They are the mutants a CONFIGURATION chose
 *    not to test, which is why `mutation.totalMutants` is ratcheted upward:
 *    turning `ignoreStatic` on would raise the percentage while shrinking this
 *    number, and the smaller denominator is what fails the run.
 *  - Module keys are matched with BOTH sides sanitised through `moduleKey`.
 *    A core module is a path, three of the six end in `.ts`, and an unsanitised
 *    key would flatten to a field whose wildcard is
 *    `mutation.modules.…rateLimiter.*` — declared nowhere, so the field would
 *    fail as having no direction. Sanitising both sides cannot change which
 *    files a module claims.
 */
function fromMutationJson(json, baselineModules) {
  const out = {};
  if (!json.files || typeof json.files !== 'object') return out;
  const perFile = new Map();
  let total = 0;
  let killed = 0;
  for (const raw of Object.keys(json.files)) {
    const f = normPath(raw);
    let t = 0;
    let k = 0;
    for (const m of json.files[raw].mutants ?? []) {
      if (m.status === 'Ignored') continue;
      t++;
      if (['Killed', 'Timeout'].includes(m.status)) k++;
    }
    perFile.set(f, { t, k });
    total += t;
    killed += k;
  }
  out['mutation.filesMutated'] = [...perFile.keys()].sort();
  out['mutation.totalMutants'] = total;
  if (total) out['mutation.overall'] = pct(killed, total);
  for (const mod of baselineModules) {
    let t = 0;
    let k = 0;
    for (const [f, v] of perFile) {
      if (moduleKey(normPath(f)).startsWith(moduleKey(normPath(mod)))) {
        t += v.t;
        k += v.k;
      }
    }
    if (t) out[`mutation.modules.${moduleKey(mod)}`] = pct(k, t);
  }
  return out;
}

const fromFlakeJson = (json) => {
  const out = {};
  if (typeof json.runs === 'number') out['flake.runs'] = json.runs;
  if (typeof json.failures === 'number') out['flake.failures'] = json.failures;
  return out;
};

// ---------------------------------------------------------------------------
// collect
// ---------------------------------------------------------------------------
if (!existsSync(BASELINE)) fail(`${BASELINE} not found; nothing to ratchet against`);
const baselineRaw = JSON.parse(readFileSync(BASELINE, 'utf8'));
const baselineModules = Object.keys(baselineRaw.mutation?.modules ?? {});
const baselinePackages = Object.keys(baselineRaw.packages ?? {});
const manifestRaw = existsSync(MANIFEST) ? JSON.parse(readFileSync(MANIFEST, 'utf8')) : null;

const tier = val('--tier');
const tier0 = tier === '0';

/**
 * The artifacts a COMPLETE run produces, read from the manifest rather than
 * hard-coded, so registering a test task automatically extends what this gate
 * expects to see. Port note 4 turns an absent one into UNMEASURED.
 *
 * `countsTests: false` on a task keeps its JUnit report REQUIRED and FRESH while
 * leaving it out of the `tests.count` sum. Exactly one kind of task needs that:
 * one that re-runs tests another gate already counted (`test:security` runs a
 * named subset of the server suite as its own gate). Summing it would make
 * `tests.count` stop being a headcount and ratchet the same tests twice — and
 * because the field is higher-is-better, nothing would ever complain.
 */
function declaredArtifacts() {
  const junit = [];
  const coverage = [];
  for (const [task, t] of Object.entries(manifestRaw?.tasks ?? {})) {
    if (t?.composite === true) continue;
    for (const r of Array.isArray(t?.report) ? t.report : t?.report ? [t.report] : []) {
      if (String(r).endsWith('.xml')) {
        junit.push({
          task,
          rel: `${manifestRaw.reportDir}/${r}`,
          countsTests: t?.countsTests !== false,
        });
      }
    }
    for (const c of t?.coverage ?? []) coverage.push({ task, rel: posix(String(c)) });
  }
  return { junit, coverage };
}

/**
 * Which package a coverage artifact belongs to. Declared per task in the
 * manifest as a repo-relative path, so the package is the baseline key that
 * prefixes it.
 */
const packageOf = (rel) => baselinePackages.find((k) => posix(rel).startsWith(`${posix(k)}/`));

function collect() {
  const cur = {};
  const seen = [];
  const stale = [];
  const notes = [];
  const newestSrc = newestSourceMtime();

  const freshness = (abs, rel) => {
    const st = safeStat(abs);
    if (!st) return 'absent';
    if (newestSrc && st.mtimeMs < newestSrc) {
      stale.push(rel);
      return 'stale';
    }
    return 'fresh';
  };

  // --- the JSON reports in .testfortress/reports -------------------------
  for (const p of walk(REPORTS)) {
    const rel = posix(relative(ROOT, p));
    const base = rel.split('/').pop();
    if (tier0 && !TIER0_REPORTS.includes(base)) continue;
    // The name is checked BEFORE the mtime, deliberately. This directory also
    // holds artifacts nothing here reads (`summary.json`, this gate's own
    // output), and asking whether those are stale would let an unrelated file
    // fail the run.
    const known =
      base === 'integrity.json' ||
      base === 'warnings.json' ||
      base === 'coverage.json' ||
      base === 'deadcode.json' ||
      base === 'config.sarif' ||
      base === 'openapi-compat.json' ||
      base === 'a11y.json' ||
      base.includes('mutation') ||
      base.includes('flake');
    if (!known) continue;
    // A deferrable report is checked for freshness WITHOUT being recorded as
    // stale: its gate did not run in this invocation, so "older than the newest
    // source file" is the expected state on a push rather than a finding. The
    // compare loop turns that into a DEFERRED field, which is where the
    // conditions in `DEFERRABLE` are enforced.
    const deferrable = deferrableForReport(base);
    if (deferrable) {
      const st = safeStat(p);
      if (!st || (newestSrc && st.mtimeMs < newestSrc)) continue;
    } else if (freshness(p, rel) !== 'fresh') continue;

    let j;
    try {
      j = JSON.parse(readFileSync(p, 'utf8'));
    } catch {
      continue;
    }
    let got = {};
    if (base === 'integrity.json') {
      const s = j.summary ?? {};
      const sup = s.suppressions ?? {};
      if ((sup.count ?? s.ledgerEntries) !== undefined) {
        got['suppressions.count'] = sup.count ?? s.ledgerEntries;
      }
      if ((sup.totalHits ?? s.coveredOccurrences) !== undefined) {
        got['suppressions.totalHits'] = sup.totalHits ?? s.coveredOccurrences;
      }
      for (const [k, v] of Object.entries(s.fingerprints ?? {})) got[`integrity.${k}`] = v;
    } else if (base === 'deadcode.json') {
      // Both halves of the `deadcode` gate: knip's per-category counts and
      // jscpd's duplication, including the ceiling jscpd itself enforces.
      for (const [key, value] of Object.entries(j.deadcode ?? {})) got[`deadcode.${key}`] = value;
      for (const [key, value] of Object.entries(j.duplication ?? {})) {
        got[`duplication.${key}`] = value;
      }
    } else if (base === 'config.sarif') {
      // The per-tool numbers live in the SARIF driver's properties, which is
      // where a SARIF consumer expects tool-specific data.
      const props = j.runs?.[0]?.tool?.driver?.properties ?? {};
      for (const [tool, count] of Object.entries(props.belowError ?? {})) {
        got[`config.belowError.${tool}`] = count;
      }
      for (const [tool, count] of Object.entries(props.inputsExamined ?? {})) {
        got[`config.inputsExamined.${tool}`] = count;
      }
    } else if (base === 'openapi-compat.json') {
      // Only the size of the BASE. The breaking-change count is the gate's own
      // verdict and is already zero-or-fail; what the gate cannot see about
      // itself is a snapshot that stopped describing the API.
      const snap = j.snapshot ?? {};
      if (typeof snap.paths === 'number') got['openapi.snapshotPaths'] = snap.paths;
      if (typeof snap.operations === 'number') {
        got['openapi.snapshotOperations'] = snap.operations;
      }
    } else if (base === 'a11y.json') {
      // Only the two gated impacts and the size of the scanned surface. The
      // gate's own report carries the rest.
      if (typeof j.violations?.critical === 'number') got['a11y.critical'] = j.violations.critical;
      if (typeof j.violations?.serious === 'number') got['a11y.serious'] = j.violations.serious;
      if (typeof j.viewsScanned === 'number') got['a11y.viewsScanned'] = j.viewsScanned;
    } else if (base === 'coverage.json') {
      // ONLY the patch-coverage number. The per-package percentages, the
      // denominators and the measured file set are read from the LCOV documents
      // further down, which is the artifact the suites themselves write — this
      // gate's report would be a second-hand copy of them, and a ratchet reading
      // a number a gate re-stated rather than the one the tool emitted is how
      // the two quietly stop describing the same run.
      //
      // The value counts a LEDGERED line as covered; `coverage-check.mjs` says
      // why, and the debt it defers to is `suppressions.count`, which ratchets
      // down.
      if (typeof j.coverage?.diff === 'number') got['coverage.diff'] = j.coverage.diff;
    } else if (base === 'warnings.json') {
      // `null` means UNMEASURED in warnings.json and is deliberately not `0`;
      // passing it through as a number would fabricate a clean result.
      for (const [k, v] of Object.entries(j)) if (typeof v === 'number') got[`warnings.${k}`] = v;
    } else if (base.includes('mutation')) {
      got = fromMutationJson(j, baselineModules);
    } else if (base.includes('flake')) {
      got = fromFlakeJson(j);
    }
    const useful = Object.entries(got).filter(([, v]) => v !== undefined);
    if (useful.length) {
      seen.push(rel);
      for (const [k, v] of useful) cur[k] = v;
    }
  }

  if (tier0) return { cur, seen, stale, notes };

  // --- test counts, per declared JUnit artifact (port note 4) -------------
  const { junit, coverage } = declaredArtifacts();
  let total = 0;
  let complete = junit.length > 0;
  for (const { task, rel, countsTests } of junit) {
    const abs = join(ROOT, rel);
    const state = freshness(abs, rel);
    if (state !== 'fresh') {
      complete = false;
      notes.push(`${rel} (${task}) is ${state}, so tests.count cannot be measured`);
      continue;
    }
    const n = fromJunit(readFileSync(abs, 'utf8'));
    if (n === undefined) {
      complete = false;
      notes.push(`${rel} (${task}) has no test count`);
      continue;
    }
    seen.push(rel);
    // Freshness and parseability are still REQUIRED above — the report has to
    // exist and be from this run — but a re-run of tests another gate already
    // counted does not add to the headcount.
    if (!countsTests) continue;
    total += n;
    const pkg = /junit-([a-z0-9]+)\.xml$/.exec(rel)?.[1];
    const key = baselinePackages.find((k) => k.endsWith(`/${pkg}`)) ?? pkg;
    if (key) cur[`packages.${key}.tests.count`] = n;
  }
  if (complete) cur['tests.count'] = total;

  // --- coverage, from the LCOV beside each declared Cobertura report ------
  for (const { task, rel } of coverage) {
    const pkg = packageOf(rel);
    // LCOV carries the `SF:` records the measured-file-set defence needs, and
    // vitest writes it beside the Cobertura report the manifest names.
    const lcov = posix(join(dirname(rel), 'lcov.info'));
    const abs = join(ROOT, lcov);
    const state = freshness(abs, lcov);
    if (state !== 'fresh') {
      notes.push(`${lcov} (${task}) is ${state}, so ${pkg ?? 'coverage'} cannot be measured`);
      continue;
    }
    const got = fromLcov(readFileSync(abs, 'utf8'));
    seen.push(lcov);
    for (const [k, v] of Object.entries(got)) {
      if (v === undefined) continue;
      cur[pkg ? `packages.${pkg}.${k}` : k] = v;
    }
  }

  return { cur, seen, stale, notes };
}

// ---------------------------------------------------------------------------
// compare
// ---------------------------------------------------------------------------
/** Flatten, but keep `packages` keys intact (a package id contains a slash). */
function flatten(obj, prefix = '', out = {}) {
  for (const [k, v] of Object.entries(obj ?? {})) {
    const path = prefix ? `${prefix}.${k}` : k;
    if (prefix === '' && k === 'packages') {
      for (const [pkg, metrics] of Object.entries(v ?? {}))
        flatten(metrics, `packages.${pkg}`, out);
    } else if (v && typeof v === 'object' && !Array.isArray(v)) flatten(v, path, out);
    else out[path] = v;
  }
  return out;
}

const base = flatten(baselineRaw);
const { cur, seen, stale, notes } = collect();

if (manifestRaw?.tasks) cur['tasks'] = Object.keys(manifestRaw.tasks).sort();

// The committed ceilings, from source. Like `tasks` above, these are read from
// the repository rather than from a report: they are what the gates enforce, not
// what the gates measured, so they are always present and can never be
// UNMEASURED. Injected outside `collect()` for exactly that reason — `collect()`
// answers "what did this run observe", and these are not observations.
//
// The key is DOT-SANITISED, and that is load-bearing rather than cosmetic:
// `flatten` splits a baseline path on `.`, and `directionFor` only falls back to
// a wildcard over the LAST segment. A chunk literally named
// `passwordStrength.worker` would flatten to
// `bundle.budgetKb.passwordStrength.worker`, whose wildcard is
// `bundle.budgetKb.passwordStrength.*` — which is declared nowhere, so the field
// would be reported as having no direction and fail the run.
const keySafe = (name) => name.replace(/\./g, '_');
if (!tier0) {
  for (const [chunk, budget] of Object.entries(CHUNK_BUDGETS_KB)) {
    cur[`bundle.budgetKb.${keySafe(chunk)}`] = budget;
  }
  cur['bundle.defaultChunkBudgetKb'] = DEFAULT_CHUNK_BUDGET_KB;
  cur['bundle.initialPayloadBudgetKb'] = INITIAL_PAYLOAD_BUDGET_KB;
  cur['bundle.htmlShellBudgetKb'] = HTML_SHELL_BUDGET_KB;
  for (const [scenario, budget] of Object.entries(RESOURCE_BUDGETS)) {
    cur[`resource.budgetMs.${scenario}`] = budget.durationMs;
    cur[`resource.budgetRssMb.${scenario}`] = budget.rssGrowthMb;
    if (typeof budget.deliveredFraction === 'number') {
      cur[`resource.deliveredFractionCeiling.${scenario}`] = budget.deliveredFraction;
    }
  }
}

const inTier0 = (p) => TIER0_PREFIXES.some((t) => p.startsWith(t));
/** `meta.*` is bookkeeping; `meta.fields` is compared against the computed list below. */
const skipMeta = (p) =>
  ['version', 'recordedAt', 'commit', 'reason'].includes(p) || p.startsWith('meta.');

const regressions = [];
const improvements = [];
const missing = [];
/** Tier-2 measurements this invocation did not produce; see DEFERRABLE. */
const deferred = [];
const undeclared = [];
const absent = [];

// (d) + port note 2: required fields must be present, per package or plainly.
const requiredFields = [
  ...REQUIRED_FIELDS,
  ...(baselineRaw.mutation ? MUTATION_REQUIRED_FIELDS : []),
  ...(baselineRaw.flake ? FLAKE_REQUIRED_FIELDS : []),
];
for (const req of requiredFields) {
  const present = Object.keys(base).some(
    (p) =>
      p === req ||
      p.startsWith(`${req}.`) ||
      (p.startsWith('packages.') && (p.endsWith(`.${req}`) || p.includes(`.${req}.`))),
  );
  if (!present) {
    absent.push({
      path: req,
      detail:
        'required baseline field is absent, so its gate does not exist; a metric that never enters the baseline is never checked',
    });
  }
}

for (const [path, want] of Object.entries(base)) {
  if (skipMeta(path)) continue;
  const lookup = path.startsWith('packages.')
    ? path.replace(/^packages\.[^.]*(?:\/[^.]*)*\./, '')
    : path;
  const dir = directionFor(lookup, undeclared);
  if (!dir || dir === 'info') continue;
  if (tier0 && !inTier0(path)) continue;

  const got = cur[path];
  if (got === undefined) {
    // A Tier 2 measurement whose gate is still registered at its declared tier
    // is DEFERRED, not unmeasured — see the DEFERRABLE table. Anything else,
    // including a deferrable field whose owning task has been deleted or moved,
    // is the hard failure decision (c) requires.
    const deferrable = deferrableForField(path);
    const owner = deferrable ? manifestRaw?.tasks?.[deferrable.owner] : undefined;
    if (deferrable && owner?.tier === deferrable.tier) {
      deferred.push({ path, want, owner: deferrable.owner, report: deferrable.report });
      continue;
    }
    missing.push({
      path,
      want,
      detail: deferrable
        ? `${deferrable.owner} is no longer a registered tier-${String(deferrable.tier)} task, so nothing produces ${deferrable.report}`
        : 'no fresh report supplies this field; a metric that stops being measured stops being a gate',
    });
    continue;
  }
  if (dir === 'pin') {
    if (String(got) !== String(want)) {
      regressions.push({ path, want, got, dir, detail: 'pinned value changed' });
    }
    continue;
  }
  if (dir === 'superset') {
    const w = new Set(Array.isArray(want) ? want : []);
    const g = new Set(Array.isArray(got) ? got : []);
    const lost = [...w].filter((x) => !g.has(x));
    if (lost.length) {
      const why =
        path === 'tasks'
          ? 'a registered gate disappeared, so it can no longer fail'
          : path === 'meta.fields'
            ? 'a baseline field was deleted, which silently removes its gate'
            : 'something stopped being measured, which raises a percentage while covering less code';
      regressions.push({
        path,
        want: w.size,
        got: g.size,
        dir,
        detail: `${lost.length} entr(ies) no longer present, e.g. ${lost.slice(0, 3).join(', ')}: ${why}`,
      });
    } else if (g.size > w.size) improvements.push({ path, want: w.size, got: g.size, dir });
    continue;
  }
  const nw = Number(want);
  const ng = Number(got);
  if (Number.isNaN(nw) || Number.isNaN(ng)) continue;
  const worse = dir === 'higher' ? ng < nw : ng > nw;
  const better = dir === 'higher' ? ng > nw : ng < nw;
  if (worse) regressions.push({ path, want: nw, got: ng, dir, detail: `${dir}-is-better` });
  else if (better) improvements.push({ path, want: nw, got: ng, dir });
}

// (d) pin the baseline's own field list, so a later deletion is a regression.
const currentFields = Object.keys(base)
  .filter((p) => !skipMeta(p) && p !== 'meta.fields')
  .sort();
if (Array.isArray(baselineRaw.meta?.fields)) {
  const lost = baselineRaw.meta.fields.filter((f) => !currentFields.includes(f));
  if (lost.length) {
    regressions.push({
      path: 'meta.fields',
      want: baselineRaw.meta.fields.length,
      got: currentFields.length,
      dir: 'superset',
      detail: `baseline field(s) deleted: ${lost.slice(0, 3).join(', ')}`,
    });
  }
}

const blocking =
  regressions.length + missing.length + absent.length + undeclared.length + stale.length;

// ---------------------------------------------------------------------------
// accept, or report
// ---------------------------------------------------------------------------
if (has('--accept')) {
  const reason = val('--reason');
  if (!reason) {
    fail(
      '--accept requires --reason; an unexplained baseline edit is what the ratchet exists to prevent',
    );
  }
  // `--tier 0` compares a SUBSET, so `blocking` below would be computed without
  // ever looking at coverage, the measured file set or the test count. Accepting
  // from that position writes a new baseline while a regression it never
  // examined still stands, which is the "refuses while anything is failing"
  // guarantee quietly narrowed to "refuses while a cheap field is failing".
  if (tier !== undefined) {
    fail(
      '--accept requires the FULL comparison; drop --tier so every field is examined before a baseline is written',
    );
  }
  if (blocking) {
    console.error('ratchet-check: refusing to accept while anything is failing or unmeasured.');
    for (const r of regressions) {
      console.error(
        `  REGRESSION ${r.path}: ${JSON.stringify(r.want)} -> ${JSON.stringify(r.got)} (${r.dir}-is-better)`,
      );
    }
    for (const m of missing) console.error(`  UNMEASURED ${m.path}`);
    for (const a of absent) console.error(`  ABSENT     ${a.path}`);
    for (const s of stale) console.error(`  STALE      ${s}`);
    console.error(
      'A justified reduction needs a BASELINE-REDUCTION ledger entry and judge sign-off, then re-run.',
    );
    process.exit(1);
  }
  const next = JSON.parse(JSON.stringify(baselineRaw));
  const setPath = (o, p, v) => {
    const keys = p.startsWith('packages.')
      ? ['packages', p.split('.')[1], ...p.split('.').slice(2)]
      : p.split('.');
    let n = o;
    for (const s of keys.slice(0, -1)) n = n[s] ??= {};
    n[keys.at(-1)] = v;
  };
  for (const i of improvements) setPath(next, i.path, cur[i.path]);
  next.recordedAt = new Date().toISOString().slice(0, 10);
  next.reason = reason;
  try {
    next.commit = execFileSync('git', ['rev-parse', '--short', 'HEAD'], { cwd: ROOT })
      .toString()
      .trim();
  } catch {
    /* leave the recorded commit as it was */
  }
  next.meta = {
    ...(next.meta ?? {}),
    fields: Object.keys(flatten(next))
      .filter((p) => !skipMeta(p) && p !== 'meta.fields')
      .sort(),
  };
  writeFileSync(BASELINE, `${JSON.stringify(next, null, 2)}\n`);
  // `--json` means stdout carries exactly one JSON document and nothing else,
  // the same contract the pipeline runner honours; the human line goes to
  // stderr so a machine consumer of an accept run is not handed a mixed stream.
  const accepted = {
    accepted: improvements.map((i) => ({ path: i.path, value: cur[i.path] })),
    reason,
    regressions: [],
    missing: [],
    absent: [],
    undeclared: [],
    staleReports: [],
    deferred,
    improvements,
  };
  if (has('--json')) console.log(JSON.stringify(accepted, null, 2));
  else
    console.log(`ratchet-check: accepted ${improvements.length} improvement(s). Reason: ${reason}`);
  process.exit(0);
}

const result = {
  checkedAt: new Date().toISOString(),
  tier: tier ?? 'all',
  reportsRead: seen,
  regressions,
  missing,
  absent,
  undeclared,
  staleReports: stale,
  deferred,
  notes,
  improvements,
};
// The two tiers write two files. One report name shared by two registered tasks
// would mean the second run silently overwrites the first's evidence, and the
// gate surface's own drift test forbids it.
if (existsSync(REPORTS)) {
  writeFileSync(
    join(REPORTS, tier0 ? 'ratchet-tier0.json' : 'ratchet.json'),
    `${JSON.stringify(result, null, 2)}\n`,
  );
}

if (has('--json')) console.log(JSON.stringify(result, null, 2));
else {
  for (const a of absent) console.error(`ABSENT       ${a.path}  ${a.detail}`);
  for (const u of undeclared) {
    console.error(
      `NO-DIRECTION ${u}  no direction declared for this field; add it to DIRECTION rather than guessing`,
    );
  }
  for (const s of stale) {
    console.error(
      `STALE        ${s}  older than the newest source file, so it describes a different tree`,
    );
  }
  for (const d of deferred) {
    console.error(
      `DEFERRED     ${d.path}  (baseline ${JSON.stringify(d.want)})  not measured in this run; ` +
        `${d.owner} is tier 2 and produces ${d.report}. It enforces this floor itself.`,
    );
  }
  for (const n of notes) console.error(`note         ${n}`);
  for (const m of missing) {
    console.error(`MISSING      ${m.path}  (baseline ${JSON.stringify(m.want)})  ${m.detail}`);
  }
  for (const r of regressions) {
    console.error(
      `REGRESSION   ${r.path}  ${JSON.stringify(r.want)} -> ${JSON.stringify(r.got)}  ${r.detail}`,
    );
  }
  for (const i of improvements) {
    console.error(`improved     ${i.path}  ${JSON.stringify(i.want)} -> ${JSON.stringify(i.got)}`);
  }
  console.error(
    `\nratchet: ${regressions.length} regression(s), ${missing.length} unmeasured, ${absent.length} absent-from-baseline, ` +
      `${undeclared.length} undeclared-direction, ${stale.length} stale report(s), ` +
      `${deferred.length} deferred to a tier-2 gate, ` +
      `${improvements.length} improvement(s) from ${seen.length} report(s).`,
  );
  if (improvements.length && !blocking) {
    console.error('Run with --accept --reason "..." to record the improvements.');
  }
}

process.exit(blocking ? 1 : 0);
