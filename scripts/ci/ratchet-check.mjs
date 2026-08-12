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
 *     remedy is to run the gate, never to delete the baseline field.
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
 *  1. `mutation.*` AND `flake.*` ARE NOT REQUIRED FIELDS YET, because this
 *     repository has no extractor for them until Phases 16 and 19 add
 *     `test:mutation` and `test:flake`. Under (c) a baseline field with no
 *     report is a hard failure, so requiring them now would define a
 *     permanently red gate — and the cheapest escape from a permanently red gate
 *     is deleting baseline fields, which is the pressure this file exists to
 *     remove. Those two phases add the field AND its entry in REQUIRED_FIELDS in
 *     the same change; `selftest`'s per-task registry is where that obligation
 *     is enforced.
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
  'warnings.*': 'lower',
  'suppressions.count': 'lower',
  'suppressions.totalHits': 'lower',
  'flake.runs': 'higher',
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

/** Fields cheap enough for T0: no test artifact needed. */
const TIER0_PREFIXES = ['suppressions.', 'integrity.', 'tasks', 'meta.fields'];
/** (Port note 3) Which reports T0 is allowed to read. */
const TIER0_REPORTS = ['integrity.json'];

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
const pct = (hit, total) => (total ? +((hit / total) * 100).toFixed(2) : undefined);

function fromLcov(text) {
  const files = [...text.matchAll(/^SF:(.+)$/gm)].map((m) => normPath(m[1]));
  const sum = (re) => [...text.matchAll(re)].reduce((n, m) => n + Number(m[1]), 0);
  const lf = sum(/^LF:(\d+)$/gm);
  const lh = sum(/^LH:(\d+)$/gm);
  const brf = sum(/^BRF:(\d+)$/gm);
  const brh = sum(/^BRH:(\d+)$/gm);
  const fnf = sum(/^FNF:(\d+)$/gm);
  const fnh = sum(/^FNH:(\d+)$/gm);
  return {
    'coverage.line': pct(lh, lf),
    'coverage.branch': pct(brh, brf),
    'coverage.function': pct(fnh, fnf),
    'coverage.linesTotal': lf || undefined,
    'coverage.filesMeasured': files.length ? [...new Set(files)].sort() : undefined,
  };
}

function fromJunit(xml) {
  const outer = xml.match(/<testsuites[^>]*\btests="(\d+)"/);
  if (outer) return Number(outer[1]);
  const suites = [...xml.matchAll(/<testsuite[^>]*\btests="(\d+)"/g)].map((m) => Number(m[1]));
  return suites.length ? suites.reduce((a, b) => a + b, 0) : undefined;
}

function fromMutationJson(json, baselineModules) {
  const out = {};
  if (json.files && typeof json.files === 'object') {
    const perFile = new Map();
    let total = 0;
    let killed = 0;
    for (const raw of Object.keys(json.files)) {
      const f = normPath(raw);
      let t = 0;
      let k = 0;
      for (const m of json.files[raw].mutants ?? []) {
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
        if (f.startsWith(normPath(mod))) {
          t += v.t;
          k += v.k;
        }
      }
      if (t) out[`mutation.modules.${mod}`] = pct(k, t);
    }
  }
  if (typeof json.mutationScore === 'number') out['mutation.overall'] = json.mutationScore;
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
      base === 'deadcode.json' ||
      base === 'config.sarif' ||
      base === 'a11y.json' ||
      base.includes('mutation') ||
      base.includes('flake');
    if (!known) continue;
    if (freshness(p, rel) !== 'fresh') continue;

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
    } else if (base === 'a11y.json') {
      // Only the two gated impacts and the size of the scanned surface. The
      // gate's own report carries the rest.
      if (typeof j.violations?.critical === 'number') got['a11y.critical'] = j.violations.critical;
      if (typeof j.violations?.serious === 'number') got['a11y.serious'] = j.violations.serious;
      if (typeof j.viewsScanned === 'number') got['a11y.viewsScanned'] = j.viewsScanned;
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

const inTier0 = (p) => TIER0_PREFIXES.some((t) => p.startsWith(t));
/** `meta.*` is bookkeeping; `meta.fields` is compared against the computed list below. */
const skipMeta = (p) =>
  ['version', 'recordedAt', 'commit', 'reason'].includes(p) || p.startsWith('meta.');

const regressions = [];
const improvements = [];
const missing = [];
const undeclared = [];
const absent = [];

// (d) + port note 2: required fields must be present, per package or plainly.
for (const req of REQUIRED_FIELDS) {
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
    missing.push({
      path,
      want,
      detail:
        'no fresh report supplies this field; a metric that stops being measured stops being a gate',
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
      `${improvements.length} improvement(s) from ${seen.length} report(s).`,
  );
  if (improvements.length && !blocking) {
    console.error('Run with --accept --reason "..." to record the improvements.');
  }
}

process.exit(blocking ? 1 : 0);
