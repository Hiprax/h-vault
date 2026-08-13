#!/usr/bin/env node
/**
 * `audit:integrity` — the anti-cheat gate.
 *
 * A green build only means something if the definition of green cannot be
 * edited to reach it. This scanner is the half of that which is visible in the
 * tree: it finds every marker that weakens a check (a skipped test, a silenced
 * analyser, a neutered command, a swallowed failure), and it fails unless each
 * one is either absent or written down in `.testfortress/suppressions.json`
 * with an owner, a reason and an expiry. The other half — a threshold or a
 * measured SCOPE moving the wrong way, which no single revision can show — is
 * `audit:ratchet`'s job (`scripts/ci/ratchet-check.mjs`).
 *
 *   node scripts/ci/integrity-scan.mjs            human output
 *   node scripts/ci/integrity-scan.mjs --json     the report on stdout
 *   node scripts/ci/integrity-scan.mjs --quiet    report file only
 *
 * Exit codes: 0 = clean · 1 = violations · 2 = could not run.
 *
 * It never auto-fixes, never auto-ledgers and never rewrites the baseline. A
 * gate that repairs its own findings is a gate that reports nothing.
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS. Each closes a hole a previous version actually had;
 * none of them is a simplification opportunity.
 * ---------------------------------------------------------------------------
 *
 *  a. UNTRACKED FILES ARE ENUMERATED (`--others --exclude-standard`). Work in
 *     this repository is never staged by the process that produces it, so an
 *     index-only listing (`git ls-files`) would leave every new script, test and
 *     config invisible — precisely the set that matters.
 *
 *  b. THE LEDGER MATCHES ON THE EXACT RULE ID, never on `kind`. Several rules
 *     share a kind, so a kind fallback lets one honest entry in a file silently
 *     excuse every other marker in that same file.
 *
 *  c. FORBIDDEN RULES ARE SCOPED, NOT GLOBAL. `|| true` in a gate definition is
 *     a defeated gate; `rm -rf tmp || true` in a teardown script is correct
 *     code. So a forbidden rule is unexcusable ONLY inside a gate-defining file
 *     (`GATE_FILES` + `integrity.config.json → gateFiles`). Elsewhere it is
 *     still detected but is ledgerable with a REQUIRED `symbol` and a shorter
 *     max age. In prose it is report-only: a document that describes this
 *     standard must be able to quote the patterns it forbids.
 *
 *  d. OPERATOR-ADDED EXCLUDES CANNOT HIDE A FORBIDDEN MARKER. `config.exclude`
 *     applies to ledgerable rules only — excluding a path stops the hit from
 *     being generated at all, which would have exactly the effect of excusing
 *     it, and "no entry can excuse a forbidden rule" would then be false in
 *     practice. Every exclude glob is itself a `SCAN-EXCLUDE` marker needing its
 *     own entry.
 *
 *  e. CAPACITY IS BOUNDED AND RATCHETED. An entry covers `maxHits` occurrences
 *     (default 1, ceiling `policy.maxHitsPerEntry`), the sum is recorded in the
 *     baseline, and both may only fall. Without both, one entry with
 *     `maxHits: 200` reproduces blanket suppression under a single justification.
 *     Capacity that is provisioned but unused is reported too, so the ledger
 *     states the real debt rather than a comfortable over-estimate.
 *
 *  f. DATES ARE MEASURED AGAINST TODAY, NOT AGAINST EACH OTHER. Checking only
 *     `expires - created <= maxAgeDays` is defeated by future-dating `created`:
 *     `created 2099-01-01, expires 2099-03-01` is a 59-day window that never
 *     expires in any observable horizon.
 *
 *  g. STALENESS IS EXEMPTED PER RULE, NOT PER KIND. Only the genuinely
 *     marker-less ids (`MARKERLESS`) are exempt. Every pattern rule has a
 *     checkable marker, so its entry must go stale when the marker goes away —
 *     otherwise fixing the problem leaves the exception in the ledger forever,
 *     inflating the count the ratchet reads.
 *
 *  h. ONLY `.testfortress/reports/**` IS EXCLUDED under `.testfortress/`. The
 *     config, the manifest and the ledger live there: excluding the config would
 *     let one line void the scan, and excluding the manifest would let a
 *     neutered gate command hide in the one file where every gate is defined.
 *
 *  i. THE SCANNER'S OWN BLIND SPOTS ARE PINNED BY HASH — the effective exclude
 *     list, the gate-file list, this file's source and `.gitignore`. All four
 *     make files invisible without touching a single rule, and
 *     `.git/info/exclude` is worse still because it is untracked and shows up in
 *     no diff, so it must be empty.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS SCANNER DOES NOT IMPLEMENT, and where it is enforced instead. An
 * undisclosed gap in an integrity checker is the worst possible place for one.
 * ---------------------------------------------------------------------------
 *
 *   · Suppressed OUTPUT (`2>/dev/null`) is checked only against the manifest's
 *     `cmd` strings, where it is unambiguously a neutered gate. In ordinary
 *     source it has too many legitimate uses to gate on.
 *   · THRESHOLD and coverage/mutation SCOPE edits cannot be judged from one
 *     revision — the difference between a legitimate and a narrowed scope is
 *     direction, not syntax. They belong to `audit:ratchet`, which compares the
 *     absolute denominators and the measured file set in `baseline.json`.
 *   · ASSERTION-FREE TESTS need test-function boundaries, so they need the
 *     runner's enumeration or an AST pass rather than a line scan. Not
 *     implemented here; `test:mutation` (Phase 16) is the real oracle for it.
 *
 * ---------------------------------------------------------------------------
 * PORT NOTES — where this file deliberately differs from the reference
 * implementation it was ported from, and why. Every one of these was measured
 * against this repository, not assumed.
 * ---------------------------------------------------------------------------
 *
 *  1. RULES CARRY A `scope`. A pattern that fires everywhere produces false
 *     positives, a false positive forces a blanket ledger entry, and a blanket
 *     entry hides the real hits — the exact failure this gate exists to avoid.
 *     Three rules are scoped, each from a measured false positive in this tree:
 *       · `SKIP-JS` → test files only. Mongoose's `.skip(skip)` pagination in
 *         four server controllers and the string "fit (limit " in
 *         BackupCodesEditor.tsx are not skipped tests. Scoping removes all five
 *         false positives and loses nothing: a skipped test lives in a test file
 *         by definition. The anchor is deliberately shape-based
 *         (`tests/`, `e2e/`, `*.test.*`, `*.spec.*`, `__tests__/`) rather than a
 *         list of today's directories, so the directories later work creates are
 *         covered the moment they exist.
 *       · `FLAKE-HIDE`'s retry-count form → runner configs and gate files only.
 *         A container `HEALTHCHECK --retries=3`, a word in a passphrase
 *         dictionary and a `retries:` option passed to an application API are
 *         not concealed flakiness. Its runner-level forms (`test.retry`,
 *         `retryTimes(`, `--reruns`) stay live in test files.
 *       · `SLEEP-SYNC`'s bare `setTimeout(fn, >=300)` form → test files only. In
 *         production UI code a 300 ms timer is a toast dismissal, not
 *         synchronisation. `waitForTimeout`/`time.sleep`/`Thread.sleep` stay
 *         global; they have no non-test meaning.
 *  2. `LINT-SUPPRESS` IS ANCHORED TO A DIRECTIVE. ESLint only honours
 *     `eslint-disable*` at the START of a comment, so anchoring there is what
 *     the linter itself does. It removed two false positives in this tree, both
 *     comments *about* suppressions ("rather than four separate eslint-disable
 *     comments…"), and it keeps every real directive.
 *  3. `SWALLOW` IGNORES LINE COMMENTS AND NEVER DOUBLE-REPORTS. A test comment
 *     reading "…makes a silent `catch {}` regression turn this test red" is
 *     prose, not a swallow. And when a line matches on its own, the two-line
 *     window starting one line ABOVE it matched too, reporting one marker at two
 *     positions; the window is now only used when neither line matches alone,
 *     which is the case it exists for.
 *  4. `policy.exemptFromTotal` IS HONOURED, and the exempt ids are left out of
 *     BOTH counts. The reference hard-codes one exempt id for the entry ceiling
 *     and still counts every entry's capacity, so adding a sanctioned
 *     `DEFERRED-ROW` would trip the capacity ratchet — the escape valve blocked
 *     by the ceiling it exists to lower.
 *  5. THE LEDGER FILE IS SELF-DESCRIBING. `suppressions.json` quotes the very
 *     text it excuses in its `symbol` anchors, so scanning it reports every
 *     ledgered marker a second time, in a file no entry names. It is data, not
 *     code: nothing executes it, and its own contents are validated field by
 *     field below.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync, existsSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = process.cwd();
const TF = join(ROOT, '.testfortress');
const LEDGER = join(TF, 'suppressions.json');
const BASELINE = join(TF, 'baseline.json');
const MANIFEST = join(TF, 'verify.json');
const REPORT_DIR = join(TF, 'reports');
const CONFIG = join(TF, 'integrity.config.json');
const SELF = fileURLToPath(import.meta.url);

const MAX_FILE_BYTES = 5_000_000;
/** Long lines are TRUNCATED and scanned, never skipped: `|| true` appended to a minified line is still `|| true`. */
const SCAN_LINE_CHARS = 4000;
const PROSE_EXT = ['.md', '.mdx', '.rst', '.txt', '.adoc'];

/**
 * Vendored, generated and machine-written trees. These apply to EVERY rule;
 * they hold no first-party gate definition and walking them would blow the T0
 * budget. Operator additions live in `integrity.config.json` and are weaker on
 * purpose — see (d).
 */
const DEFAULT_EXCLUDE = [
  '**/node_modules/**',
  '**/dist/**',
  '**/build/**',
  '**/coverage/**',
  '**/.git/**',
  '**/*.min.js',
  '**/*.map',
  '**/*.lock',
  '**/package-lock.json',
  '**/*.snap',
  '.testfortress/reports/**',
];

/**
 * Files where a forbidden pattern means a defeated gate, so no exception
 * exists. Project additions go in `integrity.config.json → gateFiles` (a
 * tightening, so it needs no ledger entry). Deliberately exact-ish: a glob like
 * `**\/integrity-scan*` would silently exempt any real source file whose name
 * happens to start the same way.
 */
const DEFAULT_GATE_FILES = [
  '.testfortress/verify.json',
  'package.json',
  '**/package.json',
  'Makefile',
  'makefile',
  'GNUmakefile',
  '**/Makefile',
  'justfile',
  'Justfile',
  'Taskfile.yml',
  'Taskfile.yaml',
  '.github/workflows/**',
  '.gitlab-ci.yml',
  'azure-pipelines.yml',
  '.githooks/**',
  '.pre-commit-config.yaml',
];

/**
 * Files that necessarily contain the patterns they describe: this scanner, its
 * ratchet sibling, the scan configuration, and the ledger (port note 5). Exact
 * paths only — a glob here is a blind spot with a wildcard on it.
 */
const SELF_DESCRIBING = [
  'scripts/ci/integrity-scan.mjs',
  '.testfortress/integrity.config.json',
  '.testfortress/suppressions.json',
];
// `ratchet-check.mjs` is deliberately NOT on that list, although it is this
// file's sibling. It contains no marker (it describes DIRECTIONS, not patterns),
// and `integrity.config.json` declares `scripts/ci/**` a gate-file zone — so
// exempting it would mean a `|| true`, an empty `catch {}` or a `--no-verify`
// inserted into the ratchet was neither reported nor hashed. The exemption
// bought nothing and cost a blind spot in the one file pair the doctrine already
// says a judge has to stand in for.

/** Where a marker means what the rule says it means. See port note 1. */
const isTestPath = (p) =>
  /(?:^|\/)(?:tests?|__tests__|e2e|spec|specs)\//.test(p) ||
  /\.(?:test|spec)\.[cm]?[jt]sx?$/.test(p);
const isRunnerConfigPath = (p) =>
  /(?:^|\/)(?:vitest\.config|vitest\.workspace|playwright\.config|jest\.config|karma\.conf|\.mocharc)\./.test(
    p,
  );

// ---------------------------------------------------------------------------
// The detection table. `id` is what a ledger entry must name; `kind` is DERIVED
// from it and validated. `forbidden` decides (c); `scope`, when present, is the
// measured answer to "where does this pattern mean what the rule claims".
// Several entries may share an id (a rule with one global and one scoped form);
// they must agree on kind, severity and forbidden — `integrity-scan.test.ts`
// asserts that, because a disagreement would make adjudication depend on table
// order.
// ---------------------------------------------------------------------------
const RULES = [
  // --- always ledgerable: a dated, capacity-bounded exception can exist ------
  {
    id: 'SKIP-JS',
    kind: 'conditional-skip',
    severity: 'high',
    forbidden: false,
    scope: isTestPath,
    // `fit(`/`fdescribe(` are `.only` under another name and are WORSE than
    // `.skip`: they silently drop every other test in the file. Do not delete
    // the alternation.
    re: /\b(?:xit|xdescribe|xtest|fit|fdescribe)\s*\(|\.(?:skip|only|todo|failing)\s*\(/,
    msg: 'skipped, focused, or todo test',
  },
  {
    id: 'SKIP-PY',
    kind: 'conditional-skip',
    severity: 'high',
    forbidden: false,
    re: /@pytest\.mark\.(?:skip|skipif|xfail)|pytest\.skip\(|@unittest\.skip/,
    msg: 'skipped or xfail test',
  },
  {
    id: 'SKIP-OTHER',
    kind: 'conditional-skip',
    severity: 'high',
    forbidden: false,
    re: /\bt\.Skip(?:Now)?\(|#\[ignore\]|@Disabled\b|@Ignore\b|\[Ignore[\](]/,
    msg: 'skipped test (Go/Rust/JVM/.NET)',
  },
  {
    id: 'TYPE-SUPPRESS',
    kind: 'type-suppression',
    severity: 'medium',
    forbidden: false,
    // The DIRECTIVE forms live in comments by definition, so this half must not
    // strip them.
    re: /@ts-(?:ignore|nocheck|expect-error)\b|#\s*type:\s*ignore|@SuppressWarnings|#\[allow\(/,
    msg: 'type checker silenced',
  },
  {
    id: 'TYPE-SUPPRESS',
    kind: 'type-suppression',
    severity: 'medium',
    forbidden: false,
    // `as any` is CODE, so a comment explaining why the cast below is necessary
    // ("`as any` is required here because Mongoose's typings…") is documentation
    // of a suppression, not a second one. Measured: it produced a duplicate hit
    // one line above the real cast in authController.ts.
    ignoreLineComments: true,
    re: /\bas\s+any\b/,
    msg: 'type checker silenced',
  },
  {
    id: 'LINT-SUPPRESS',
    kind: 'lint-suppression',
    severity: 'medium',
    forbidden: false,
    // Anchored to a real directive — see port note 2.
    re: /(?:^|\s)(?:\/\/|\/\*|#)\s*(?:eslint-disable(?:-next-line|-line)?\b|nolint\b|noqa(?!:\s*S\d)\b|pylint:\s*disable|ruff:\s*noqa|@formatter:off)/,
    msg: 'linter silenced',
  },
  {
    id: 'COV-EXCLUDE',
    kind: 'coverage-exclusion',
    severity: 'high',
    forbidden: false,
    re: /pragma:\s*no cover|istanbul ignore|c8 ignore|coverage:\s*ignore|LCOV_EXCL/,
    msg: 'code excluded from coverage',
  },
  {
    id: 'VULN-MUTE',
    kind: 'vulnerability-acceptance',
    severity: 'high',
    forbidden: false,
    re: /audit-level\s*=\s*(?:high|critical)|--ignore-vuln|audit-ci\s+--skip|#\s*nosec|#\s*noqa:\s*S\d/,
    msg: 'vulnerability muted',
  },
  {
    id: 'FLAKE-HIDE',
    kind: 'quarantine',
    severity: 'high',
    forbidden: false,
    // A retry COUNT means concealed flakiness where a test runner or a gate
    // command reads it, and nowhere else. See port note 1.
    //
    // `workers: 1` is here beside `maxWorkers: 1` because the doctrine's row
    // names the JEST spelling, and pinning a suite to one worker is the same
    // cheat whatever the runner calls it — it hides shared state instead of
    // fixing it. Measured: this repository's Playwright config uses the form the
    // doctrine's pattern does not name, so without this the rule missed the one
    // live instance of the thing it forbids.
    scope: (p) => isRunnerConfigPath(p) || isGateFile(p),
    re: /\bretr(?:y|ies)\s*[:=]\s*\{?\s*(?:count\s*[:=]\s*)?[1-9]|--reruns\b|\b(?:max)?[Ww]orkers\s*[:=]\s*1\b|-p\s+no:randomly/,
    msg: 'flakiness concealed rather than fixed',
  },
  {
    id: 'FLAKE-HIDE',
    kind: 'quarantine',
    severity: 'high',
    forbidden: false,
    scope: isTestPath,
    // The runner-level forms have no meaning outside a test: each one asks the
    // runner to re-run a test that failed. A BARE `flaky` is deliberately not
    // here — measured, it matched a comment explaining why a generated password
    // assertion would be flaky, which is a test being FIXED rather than a flake
    // being hidden. Only the decorator and quarantine-helper forms remain.
    //
    // The two PER-SPEC forms are what this stack actually offers: Vitest's
    // `it('x', { retry: 2 }, fn)` and Playwright's
    // `test.describe.configure({ retries: 2 })`. Neither is a retry COUNT the
    // rule above would see, because neither lives in a runner config, and they
    // are the cheapest place to hide a race in a suite this plan is about to
    // grow. `retries:` alone is deliberately NOT matched in a test file: an
    // application API legitimately takes one (the breach seeder does).
    re: /retryTimes\s*\(\s*[1-9]|\b(?:test|it|describe)\.retry\b|@RepeatedTest|@flaky\b|\.flaky\s*\(|\bretry\s*:\s*[1-9]|configure\s*\(\s*\{[^}]*\bretries\s*:\s*[1-9]/,
    msg: 'flakiness concealed rather than fixed',
  },
  {
    id: 'SLEEP-SYNC',
    kind: 'sleep-sync',
    severity: 'medium',
    forbidden: false,
    re: /\b(?:time\.sleep|Thread\.sleep|waitForTimeout)\s*\(/,
    msg: 'sleep used as synchronization',
  },
  {
    id: 'SLEEP-SYNC',
    kind: 'sleep-sync',
    severity: 'medium',
    forbidden: false,
    scope: isTestPath,
    // The doctrine's row names a bare `sleep(` too. It is scoped here rather
    // than global because `sleep`/`delay` helpers are legitimate production
    // code in this repository — the progressive login delay, the breach-seed
    // backoff and the HIBP retry all call one — while in a test the same call
    // is a wait standing in for a condition.
    re: /setTimeout\([^,]*,\s*\d{3,}\s*\)|\b(?:sleep|delay)\s*\(/,
    msg: 'sleep used as synchronization',
  },

  // --- forbidden in gate files, ledgerable-with-a-symbol elsewhere, ---------
  // --- report-only in prose: see (c) ---------------------------------------
  {
    id: 'EXIT-NEUTER',
    kind: 'gate-neutered',
    severity: 'critical',
    forbidden: true,
    re: /\|\|\s*true\b|;\s*exit\s+0\b|set\s+\+e\b|--exit-zero\b|continue-on-error|allow_failure/,
    msg: 'command result neutered, the gate can never fail',
  },
  {
    id: 'NO-TESTS-OK',
    kind: 'gate-neutered',
    severity: 'critical',
    forbidden: true,
    re: /--passWithNoTests|--allowNoTests|--if-present\b/,
    msg: 'an empty or missing suite would pass silently',
  },
  {
    id: 'TEST-FILTER',
    kind: 'gate-narrowed',
    severity: 'high',
    forbidden: true,
    // Anchored to a runner invocation on purpose: a bare `--filter` is
    // legitimate and ubiquitous in monorepo build scripts, and that false
    // positive forces a blanket entry which then hides the real hits.
    re: /(?:vitest|jest|pytest|go\s+test|cargo\s+test|dotnet\s+test|mvn\b|gradle\b)[^\n]*(?:--testNamePattern|--grep\b|\s-k[\s=]|-run[\s=]|--filter\b)/,
    msg: 'a test filter is committed into a test-runner command',
  },
  {
    id: 'STRICT-DOWN',
    kind: 'strictness-downgrade',
    severity: 'critical',
    forbidden: true,
    // The optional quote before the colon is load-bearing here, and its absence
    // was a real hole: `tsconfig.json` is JSON, so the downgrade this project
    // would actually suffer is written `"strict": false`, and a pattern that
    // only accepts the unquoted JS form (`strict: false`) cannot see the one
    // file where TypeScript strictness is configured.
    re: /(?:strict|noImplicitAny|checkJs)"?\s*[:=]\s*false|--no-strict\b/,
    msg: 'strictness downgraded',
  },
  {
    id: 'SNAPSHOT-UPD',
    kind: 'gate-neutered',
    severity: 'critical',
    forbidden: true,
    // A bare `--accept` is deliberately NOT here: it collides with this
    // project's own sanctioned `audit:ratchet --accept --reason=...`, and
    // package.json is a gate file, so the project would report its own ratchet
    // as an unledgerable FORBIDDEN hit. Anchor to the tool if insta's form is
    // ever needed.
    re: /--update-snapshots?\b|--updateSnapshot\b|--snapshot-update\b|UPDATE_SNAPSHOTS|INSTA_UPDATE\b/,
    msg: 'blanket snapshot update committed into a command',
  },
  {
    id: 'HOOK-BYPASS',
    kind: 'gate-neutered',
    severity: 'critical',
    forbidden: true,
    re: /--no-verify\b|HUSKY\s*=\s*0|LEFTHOOK\s*=\s*0|SKIP_SIMPLE_GIT_HOOKS|PRE_COMMIT_ALLOW_NO_CONFIG/,
    msg: 'git hook bypass',
  },
  {
    id: 'TAUTOLOGY',
    kind: 'tautology',
    severity: 'critical',
    forbidden: true,
    // The back-referenced form (`expect(x).toBe(x)`) is the one that survives
    // review: it looks like an assertion, reads like an assertion, and can
    // never fail.
    re: /expect\(\s*true\s*\)\s*\.\s*to|assert\s+True\s*$|assertTrue\(\s*true\s*\)|assert\s+1\s*==\s*1|expect\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\.\s*(?:toBe|toEqual|toStrictEqual)\(\s*\1\s*\)/,
    msg: 'tautological assertion, the test cannot fail',
  },
];

/**
 * Matched against the current line joined to the next non-blank line, because
 * the idiomatic swallow puts the body on the following line. See port note 3
 * for why a line that matches alone is never also reported from the window
 * above it.
 */
const MULTILINE_RULES = [
  {
    id: 'SWALLOW',
    kind: 'swallowed-failure',
    severity: 'high',
    forbidden: true,
    ignoreLineComments: true,
    re: /catch\s*(?:\([^)]*\))?\s*\{\s*\}|except[^:\n]*:\s*(?:pass|\.\.\.)\s*$/,
    msg: 'failure swallowed',
  },
];

/** Checked against the verify manifest's `cmd` strings only. */
const MANIFEST_RULES = [
  {
    id: 'CMD-SILENCED',
    kind: 'gate-neutered',
    severity: 'critical',
    forbidden: true,
    re: /2>\s*(?:\/dev\/null|\$null|NUL)|>\s*\/dev\/null\s+2>&1/,
    msg: 'gate command discards its own error output',
  },
];

/** Markers by EXISTENCE: a file whose whole purpose is suppressing findings. */
const IGNORE_FILES = [
  { path: '.trivyignore', rule: 'IGNORE-FILE-TRIVY', kind: 'vulnerability-acceptance' },
  { path: '.semgrepignore', rule: 'IGNORE-FILE-SEMGREP', kind: 'known-gap' },
  { path: '.nsprc', rule: 'IGNORE-FILE-NSP', kind: 'vulnerability-acceptance' },
  { path: '.snyk', rule: 'IGNORE-FILE-SNYK', kind: 'vulnerability-acceptance' },
  { path: '.gitleaksignore', rule: 'IGNORE-FILE-GITLEAKS', kind: 'known-gap' },
];

/**
 * Rule ids with NO marker in the tree. These are the ONLY staleness-exempt ids
 * — see (g) — and they are what makes a marker-less debt writable at all: a
 * manifest gap, a deferred applicability row, an equivalent surviving mutant,
 * an accepted advisory, a justified baseline reduction.
 */
const MARKERLESS = {
  'KNOWN-GAP': 'known-gap',
  'VULN-ACCEPT': 'vulnerability-acceptance',
  'DEFERRED-ROW': 'known-gap',
  'EQUIV-MUTANT': 'known-gap',
  'BASELINE-REDUCTION': 'known-gap',
  // An uncovered line in a change, excused by `coverage-check.mjs`. It has its
  // OWN id rather than reusing `KNOWN-GAP` because matching is by exact rule id:
  // a bare `KNOWN-GAP` on a file would otherwise excuse its patch coverage as a
  // side effect of having been written about something else entirely, which is
  // the cross-talk the exact-id rule exists to prevent.
  'COV-DIFF-EXEMPT': 'known-gap',
};

const PATTERN_RULES = [...RULES, ...MULTILINE_RULES, ...MANIFEST_RULES];
const RULE_BY_ID = {};
for (const rule of PATTERN_RULES) RULE_BY_ID[rule.id] ??= rule;
const KNOWN_RULE_IDS = new Set([
  ...PATTERN_RULES.map((r) => r.id),
  ...IGNORE_FILES.map((f) => f.rule),
  ...Object.keys(MARKERLESS),
  'SCAN-EXCLUDE',
]);
/** Entries for these must pin the exact occurrence, or one entry covers anything. */
const REQUIRE_SYMBOL = new Set(['SCAN-EXCLUDE', ...IGNORE_FILES.map((f) => f.rule)]);
const EXTRA_KIND = {
  ...Object.fromEntries(IGNORE_FILES.map((f) => [f.rule, f.kind])),
  'SCAN-EXCLUDE': 'known-gap',
};
/** Keyed on the RULE ID so mislabelling `kind` cannot dodge the skip requirement. */
const SKIP_RULES = new Set(['SKIP-JS', 'SKIP-PY', 'SKIP-OTHER']);
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
const fail = (msg) => {
  console.error(`integrity-scan: ${msg}`);
  process.exit(2);
};
const posix = (p) => p.split(sep).join('/');
const today = () => new Date().toISOString().slice(0, 10);
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const daysBetween = (a, b) => (Date.parse(b) - Date.parse(a)) / 86_400_000;
const sha = (s) => createHash('sha256').update(s).digest('hex').slice(0, 16);

function globToRe(glob) {
  let out = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        out += '.*';
        i++;
        if (glob[i + 1] === '/') i++;
      } else out += '[^/]*';
    } else if (c === '?') out += '[^/]';
    else out += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${out}$`);
}

function loadJson(path, fallback) {
  if (!existsSync(path)) return fallback;
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (e) {
    fail(`${path} is not valid JSON: ${e.message}`);
  }
}

function candidateFiles() {
  try {
    const out = execFileSync(
      'git',
      ['ls-files', '-z', '--cached', '--others', '--exclude-standard'],
      {
        cwd: ROOT,
        maxBuffer: 128 << 20,
      },
    ).toString('utf8');
    return [...new Set(out.split('\0').filter(Boolean))];
  } catch (e) {
    fail(`git ls-files failed, not a repository? (${e.message})`);
  }
}

function isScannableText(abs) {
  try {
    if (statSync(abs).size > MAX_FILE_BYTES) return false;
    return !readFileSync(abs).subarray(0, 8000).includes(0);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// config, ledger, baseline, manifest
// ---------------------------------------------------------------------------
const config = loadJson(CONFIG, {});
const configExcludes = config.exclude ?? [];
const gateFileGlobs = [...DEFAULT_GATE_FILES, ...(config.gateFiles ?? [])];
const ledger = loadJson(LEDGER, { version: 1, policy: {}, entries: [] });
const policy = {
  maxTotal: 12,
  maxAgeDays: 90,
  maxAgeDaysStrict: 30,
  maxHitsPerEntry: 3,
  requireApproval: true,
  // `COV-DIFF-EXEMPT` joins the three sanctioned escape valves for the reason
  // they are exempt at all: `suppressions.count` ratchets DOWN and `--accept`
  // moves no field upward, so a COUNTED new entry can never be added without
  // baseline surgery. For a marker in the tree that is the point — fix the code.
  // For a dated, owned, expiring, judge-approved record of a line that genuinely
  // cannot be covered, it would mean the escape valve is blocked by the very
  // ceiling it exists to work within, and the cheapest way out becomes deleting
  // the gate or writing a tautological test. The debt is still bounded: the
  // entry expires, and `coverage:check` goes red again by itself when it does.
  exemptFromTotal: ['DEFERRED-ROW', 'EQUIV-MUTANT', 'BASELINE-REDUCTION', 'COV-DIFF-EXEMPT'],
  ...(ledger.policy ?? {}),
};
const entries = ledger.entries ?? [];
const baseline = loadJson(BASELINE, null);
const manifest = loadJson(MANIFEST, null);

const hardExcludeRes = DEFAULT_EXCLUDE.map(globToRe);
const softExcludeRes = configExcludes.map(globToRe);
const selfDescribingRes = SELF_DESCRIBING.map(globToRe);
const gateFileRes = gateFileGlobs.map(globToRe);

const isHardExcluded = (p) => hardExcludeRes.some((re) => re.test(p));
const isSoftExcluded = (p) => softExcludeRes.some((re) => re.test(p));
const isSelfDescribing = (p) => selfDescribingRes.some((re) => re.test(p));
function isGateFile(p) {
  return gateFileRes.some((re) => re.test(p));
}
const isProse = (p) => PROSE_EXT.some((e) => p.toLowerCase().endsWith(e));

/**
 * Where a rule is unexcusable, ledgerable, or report-only — see (c).
 *
 * Prose and self-describing files are report-only for EVERY rule family, not
 * only the forbidden one. A CONTRIBUTING.md sentence saying "add `# noqa` only
 * with a reason" discusses the convention rather than using it, and making a
 * project's own documentation of its own gates carry renewable ledger entries
 * is a treadmill nobody walks. A gate a correct codebase cannot pass is the
 * pressure that gets the gate bypassed.
 */
function disposition(rule, file) {
  // A SYNTHESIZED marker is not text that happens to appear in a file; it IS the
  // configuration, or the existence of a suppression file. The self-describing
  // carve-out exists because a file that documents these patterns necessarily
  // contains them — it was never meant to excuse the config's own content, and
  // letting it do so means one line (`"exclude": ["src/**"]`) voids the entire
  // scan with nothing left to review. Measured: with the carve-out applied to
  // these, the exclude-needs-its-own-entry rule could never fire at all.
  if (!rule.synthesized && (isProse(file) || isSelfDescribing(file))) return 'report-only';
  if (!rule.forbidden) return 'ledgerable';
  return isGateFile(file) ? 'forbidden' : 'ledgerable-strict';
}

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------
const hits = [];
const seenHit = new Set();
/**
 * `occurrence` distinguishes several markers of one rule ON ONE LINE.
 *
 * Without it, `middleware(req as any, res as any, next)` counted as a single
 * hit and consumed a single unit of a ledger entry's `maxHits` — which is the
 * blanket-entry effect capacity accounting exists to prevent, reproduced at line
 * granularity, with `suppressions.totalHits` under-stating the real debt by the
 * difference. Two table entries sharing a rule id (a global form and a scoped
 * one) still collapse onto the same occurrence index, so one marker stays one
 * hit.
 */
const record = (rule, file, line, text, occurrence = 0) => {
  const disp = disposition(rule, file);
  if (disp === 'ledgerable' && isSoftExcluded(file)) return; // (d)
  const key = `${file}:${line}:${rule.id}:${occurrence}`;
  if (seenHit.has(key)) return;
  seenHit.add(key);
  hits.push({
    file,
    line,
    rule: rule.id,
    kind: rule.kind,
    severity: rule.severity,
    message: rule.msg,
    disposition: disp,
    text: (text ?? '').trim().slice(0, 200),
  });
};

/**
 * Port note 3: prose inside a `//` comment is not a swallowed failure.
 *
 * A `//` preceded by `:` is a URL scheme, not a comment. Stripping from there
 * would truncate the line and hide anything after it — so
 * `try { get('https://host') } catch {}` inside a gate-defining file, where
 * SWALLOW admits no exception, would have been invisible.
 */
const stripLineComment = (line) => line.replace(/(^|[^:])\/\/.*$/, '$1');

/** How many times a rule matches one line. See `record`'s `occurrence`. */
function countMatches(re, text) {
  const global = new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`);
  let count = 0;
  let match;
  while ((match = global.exec(text)) !== null) {
    count++;
    if (match[0] === '') break; // a zero-length match would never advance
  }
  return count;
}

for (const rel of candidateFiles()) {
  const rl = posix(rel);
  if (isHardExcluded(rl)) continue;
  const abs = join(ROOT, rel);
  if (!existsSync(abs) || !isScannableText(abs)) continue;

  const applicable = RULES.filter((rule) => !rule.scope || rule.scope(rl));
  const lines = readFileSync(abs, 'utf8').split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].slice(0, SCAN_LINE_CHARS);
    for (const rule of applicable) {
      const subject = rule.ignoreLineComments ? stripLineComment(line) : line;
      const occurrences = countMatches(rule.re, subject);
      for (let k = 0; k < occurrences; k++) record(rule, rl, i + 1, line, k);
    }

    let j = i + 1;
    while (j < lines.length && lines[j].trim() === '') j++;
    const next = (lines[j] ?? '').slice(0, SCAN_LINE_CHARS).trim();
    for (const rule of MULTILINE_RULES) {
      if (rule.scope && !rule.scope(rl)) continue;
      const here = rule.ignoreLineComments ? stripLineComment(line) : line;
      const there = rule.ignoreLineComments ? stripLineComment(next) : next;
      if (rule.re.test(here)) {
        record(rule, rl, i + 1, line);
      } else if (!rule.re.test(there) && rule.re.test(`${here} ${there}`)) {
        record(rule, rl, i + 1, `${line} ${next}`);
      }
    }
  }
}

for (const f of IGNORE_FILES) {
  if (existsSync(join(ROOT, f.path))) {
    record(
      {
        id: f.rule,
        kind: f.kind,
        severity: 'high',
        forbidden: false,
        synthesized: true,
        msg: `${f.path} suppresses findings`,
      },
      f.path,
      0,
      f.path,
    );
  }
}

for (const g of configExcludes) {
  record(
    {
      id: 'SCAN-EXCLUDE',
      kind: 'known-gap',
      severity: 'critical',
      forbidden: false,
      synthesized: true,
      msg: `integrity scan excludes "${g}"`,
    },
    '.testfortress/integrity.config.json',
    0,
    g,
  );
}

if (manifest?.tasks) {
  for (const [name, t] of Object.entries(manifest.tasks)) {
    const cmd = String(t?.cmd ?? '');
    for (const rule of MANIFEST_RULES) {
      if (rule.re.test(cmd)) record(rule, '.testfortress/verify.json', 0, `${name}: ${cmd}`);
    }
  }
}

// ---------------------------------------------------------------------------
// adjudicate
// ---------------------------------------------------------------------------
const violations = [];
const consumed = new Map();
const touched = new Set();
const reportedEntries = new Set();
const anchorMatches = (e, hit) => !e.symbol || (hit.text ?? '').includes(e.symbol);

for (const hit of hits) {
  if (hit.disposition === 'report-only') continue;

  if (hit.disposition === 'forbidden') {
    violations.push({
      ...hit,
      violation: 'FORBIDDEN',
      detail:
        'a gate-defining file may not contain this pattern; fix the gate, it cannot be ledgered',
    });
    continue;
  }

  // MOST-SPECIFIC-FIRST. A greedy first-fit in line order is not sound: with a
  // general entry (no symbol) and a specific one (symbol) covering the same
  // file+rule, consuming the general entry first makes the specific hit report
  // a spurious LEDGER-CAPACITY even though a valid assignment existed. Full
  // correctness is bipartite matching; symbol-bearing (longest symbol) first
  // resolves every realistic case and is the deliberate approximation.
  const candidates = entries
    .filter((e) => posix(e.file ?? '') === hit.file && e.rule === hit.rule && anchorMatches(e, hit))
    .sort((a, b) => (b.symbol?.length ?? 0) - (a.symbol?.length ?? 0));

  if (candidates.length === 0) {
    violations.push({
      ...hit,
      violation: 'UNLEDGERED',
      detail: `no suppressions.json entry names rule ${hit.rule} for this file`,
    });
    continue;
  }

  if (hit.disposition === 'ledgerable-strict' && !candidates.some((e) => e.symbol)) {
    violations.push({
      ...hit,
      violation: 'ANCHOR-REQUIRED',
      entry: candidates.map((e) => e.id).join(','),
      detail: `${hit.rule} outside a gate file needs an entry with a \`symbol\` pinning the exact occurrence`,
    });
  }

  const usable = candidates.find((e) => (consumed.get(e.id) ?? 0) < (e.maxHits ?? 1));
  if (!usable) {
    const cap = candidates.reduce((n, e) => n + (e.maxHits ?? 1), 0);
    candidates.forEach((e) => touched.add(e.id));
    violations.push({
      ...hit,
      violation: 'LEDGER-CAPACITY',
      detail: `entries for ${hit.rule} in this file cover ${cap} occurrence(s) but more exist; fix the extras (raising maxHits is a ratcheted change, not a remedy)`,
    });
  } else {
    // Touched only when actually CONSUMED, so an entry provisioning capacity
    // nobody uses still shows up as unused rather than hiding behind a sibling.
    consumed.set(usable.id, (consumed.get(usable.id) ?? 0) + 1);
    touched.add(usable.id);
  }
}

// ledger hygiene and policy
for (const e of entries) {
  const at = { file: e.file, entry: e.id };
  const flag = (violation, detail) => {
    violations.push({ ...at, violation, detail });
    reportedEntries.add(e.id);
  };

  if (!e.id) {
    violations.push({
      violation: 'LEDGER-MALFORMED',
      detail: 'entry without an id',
      entry: JSON.stringify(e).slice(0, 120),
    });
    continue;
  }
  if (!e.rule) {
    flag(
      'LEDGER-MALFORMED',
      'entry has no `rule`; matching is by exact rule id, so a ruleless entry covers nothing. For a debt with no marker in the tree use KNOWN-GAP, VULN-ACCEPT, DEFERRED-ROW, EQUIV-MUTANT or BASELINE-REDUCTION',
    );
  } else if (!KNOWN_RULE_IDS.has(e.rule)) {
    flag('LEDGER-UNKNOWN-RULE', `rule "${e.rule}" is not a known rule id`);
  } else {
    // `kind` IS DERIVED FROM `rule`, never chosen by the author. Leaving it
    // free-form is the same class of mistake as kind-based matching, one layer
    // in: `kind` reads as documentation, but a SKIP-PY entry labelled
    // `known-gap` would dodge the unconditional-skip check below and fully
    // ledger a bare skip with no condition and no tier where it runs — a
    // permanent, self-approved test deletion produced by a one-word edit.
    const expected = MARKERLESS[e.rule] ?? RULE_BY_ID[e.rule]?.kind ?? EXTRA_KIND[e.rule];
    if (expected && e.kind !== expected) {
      flag(
        'LEDGER-KIND-MISMATCH',
        `rule ${e.rule} implies kind "${expected}" but the entry says "${e.kind ?? '(missing)'}"; kind is derived from the rule, not chosen`,
      );
    }
  }
  if (e.rule && REQUIRE_SYMBOL.has(e.rule) && !e.symbol) {
    flag(
      'ANCHOR-REQUIRED',
      `${e.rule} entries must set \`symbol\` to the exact glob or path they excuse`,
    );
  }
  if ((e.maxHits ?? 1) > policy.maxHitsPerEntry) {
    flag(
      'LEDGER-CAPACITY-CEILING',
      `maxHits=${e.maxHits} exceeds policy.maxHitsPerEntry=${policy.maxHitsPerEntry}; split it into individually justified entries`,
    );
  }
  if (!DATE_RE.test(e.created ?? '')) {
    flag('LEDGER-BAD-DATE', `created "${e.created ?? '(missing)'}" is not YYYY-MM-DD`);
  } else if (e.created > today()) {
    flag('LEDGER-FUTURE-DATED', `created "${e.created}" is in the future`);
  }

  if (!DATE_RE.test(e.expires ?? '')) {
    flag('LEDGER-BAD-DATE', `expires "${e.expires ?? '(missing)'}" is not YYYY-MM-DD`);
  } else {
    if (DATE_RE.test(e.created ?? '') && e.expires < e.created) {
      flag('LEDGER-BAD-DATE', `expires ${e.expires} precedes created ${e.created}`);
    }
    if (e.expires < today()) flag('LEDGER-EXPIRED', `expired ${e.expires}; re-justify or remove`);
    // (f): measured from TODAY, so future-dating `created` buys nothing.
    const strict = e.rule && RULE_BY_ID[e.rule]?.forbidden;
    const cap = strict ? policy.maxAgeDaysStrict : policy.maxAgeDays;
    if (daysBetween(today(), e.expires) > cap) {
      flag(
        'LEDGER-TOO-LONG',
        `expires ${Math.round(daysBetween(today(), e.expires))} days from today, over the ${cap}-day cap for this rule`,
      );
    }
  }
  if (policy.requireApproval && !e.approvedBy?.length) {
    flag('LEDGER-UNAPPROVED', 'policy.requireApproval is true but approvedBy is empty');
  }
  if (SKIP_RULES.has(e.rule) && !(e.condition && e.satisfiedIn)) {
    flag(
      'UNCONDITIONAL-SKIP',
      'a skip needs a machine-evaluable `condition` and a `satisfiedIn` tier where the condition IS met; a test that never runs anywhere is a deleted test wearing a disguise',
    );
  }
}

// (g): staleness is exempted per RULE, not per kind.
for (const e of entries) {
  if (!e.id || reportedEntries.has(e.id)) continue;
  if (e.rule in MARKERLESS) continue;
  if (!touched.has(e.id)) {
    violations.push({
      file: e.file,
      violation: 'LEDGER-STALE',
      entry: e.id,
      detail: 'no matching marker found; prune this entry (this is the good outcome)',
    });
  }
}

// Capacity provisioned but never consumed is debt nobody is paying down.
for (const e of entries) {
  if (!e.id || reportedEntries.has(e.id) || e.rule in MARKERLESS) continue;
  const used = consumed.get(e.id) ?? 0;
  const cap = e.maxHits ?? 1;
  if (used > 0 && used < cap) {
    violations.push({
      file: e.file,
      violation: 'LEDGER-UNUSED-CAPACITY',
      entry: e.id,
      detail: `covers ${cap} occurrence(s) but only ${used} exist; lower maxHits to ${used} so the ledger states the real debt`,
    });
  }
}

// counts and ratchets — port note 4: the exempt ids are outside BOTH counts, or
// the sanctioned escape valve would trip the ceiling it exists to lower.
const exempt = new Set(policy.exemptFromTotal ?? []);
const countedEntries = entries.filter((e) => !exempt.has(e.rule));
const countable = countedEntries.length;
const totalHits = countedEntries.reduce((n, e) => n + (e.maxHits ?? 1), 0);

if (countable > policy.maxTotal) {
  violations.push({
    violation: 'LEDGER-OVER-POLICY',
    detail: `${countable} entries exceeds policy.maxTotal=${policy.maxTotal}`,
  });
}
if (baseline?.suppressions?.count !== undefined && countable > baseline.suppressions.count) {
  violations.push({
    violation: 'LEDGER-RATCHET',
    detail: `${countable} entries exceeds the ${baseline.suppressions.count} in baseline.json; suppressions ratchet down`,
  });
}
if (
  baseline?.suppressions?.totalHits !== undefined &&
  totalHits > baseline.suppressions.totalHits
) {
  violations.push({
    violation: 'LEDGER-RATCHET',
    detail: `covered occurrences ${totalHits} exceeds the ${baseline.suppressions.totalHits} in baseline.json; capacity ratchets down`,
  });
}
if (!baseline) {
  violations.push({
    violation: 'BASELINE-MISSING',
    detail: '.testfortress/baseline.json not found; no ratchet can be enforced without it',
  });
}

// (i): pin the four ways to make files invisible without touching a rule.
const gitignorePath = join(ROOT, '.gitignore');
const fingerprints = {
  excludeHash: sha(JSON.stringify([...DEFAULT_EXCLUDE, ...configExcludes].sort())),
  gateFilesHash: sha(JSON.stringify([...gateFileGlobs].sort())),
  selfHash: sha(readFileSync(SELF, 'utf8')),
  gitignoreHash: existsSync(gitignorePath) ? sha(readFileSync(gitignorePath, 'utf8')) : 'absent',
};
if (!baseline?.integrity) {
  violations.push({
    violation: 'FINGERPRINT-UNPINNED',
    detail: `baseline.json has no \`integrity\` block; record ${JSON.stringify(fingerprints)} so widening the scan's blind spots is detectable`,
  });
} else {
  // Iterate over what MUST be pinned, not over what happens to be pinned: a
  // partial `integrity` block would otherwise silently disable the fingerprints
  // it omits, reopening the defence by omission rather than by edit.
  for (const [k, v] of Object.entries(fingerprints)) {
    if (baseline.integrity[k] === undefined) {
      violations.push({
        violation: 'FINGERPRINT-UNPINNED',
        detail: `baseline.integrity.${k} is not pinned; record "${v}" or this blind spot can be widened undetected`,
      });
    } else if (baseline.integrity[k] !== v) {
      violations.push({
        violation: 'FINGERPRINT-CHANGED',
        detail: `integrity.${k} changed (baseline ${baseline.integrity[k]}, now ${v}); a wider exclude list, an edited scanner or a new .gitignore rule all hide files from this gate`,
      });
    }
  }
}

// `.git/info/exclude` is untracked and appears in no diff, so it must be empty.
const infoExclude = join(ROOT, '.git', 'info', 'exclude');
if (existsSync(infoExclude)) {
  const effective = readFileSync(infoExclude, 'utf8')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
  if (effective.length) {
    violations.push({
      file: '.git/info/exclude',
      violation: 'UNTRACKED-EXCLUDE',
      detail: `.git/info/exclude has ${effective.length} active rule(s) (${effective.slice(0, 3).join(', ')}); it is untracked and invisible in every diff, so it must be empty`,
    });
  }
}

// ---------------------------------------------------------------------------
// report
// ---------------------------------------------------------------------------
violations.sort(
  (a, b) =>
    (SEVERITY_ORDER[RULE_BY_ID[a.rule]?.severity] ?? 1) -
    (SEVERITY_ORDER[RULE_BY_ID[b.rule]?.severity] ?? 1),
);

const summary = {
  scannedAt: new Date().toISOString(),
  filesWithHits: new Set(hits.map((h) => h.file)).size,
  hits: hits.length,
  reportOnly: hits.filter((h) => h.disposition === 'report-only').length,
  ledgerEntries: countable,
  coveredOccurrences: totalHits,
  // The shape `audit:ratchet` reads. Named explicitly rather than left to be
  // inferred from the two fields above, which count non-exempt entries only.
  suppressions: { count: countable, totalHits, entriesTotal: entries.length },
  violations: violations.length,
  ruleIds: [...new Set(violations.map((v) => v.rule).filter(Boolean))].sort(),
  fingerprints,
  effectiveExclude: [...DEFAULT_EXCLUDE, ...configExcludes],
  gateFiles: gateFileGlobs,
  byRule: hits.reduce((a, h) => ((a[h.rule] = (a[h.rule] ?? 0) + 1), a), {}),
};

mkdirSync(REPORT_DIR, { recursive: true });
writeFileSync(
  join(REPORT_DIR, 'integrity.json'),
  `${JSON.stringify({ summary, violations, hits }, null, 2)}\n`,
);

const argv = process.argv.slice(2);
if (argv.includes('--json')) {
  console.log(JSON.stringify({ summary, violations }, null, 2));
} else if (!argv.includes('--quiet')) {
  for (const v of violations) {
    const loc = v.file ? `${v.file}${v.line ? `:${v.line}` : ''}` : '(ledger)';
    console.error(`${loc}  ${v.violation}  ${v.rule ?? v.entry ?? ''}  ${v.detail}`);
    if (v.text) console.error(`    ${v.text}`);
  }
  console.error(
    `\nintegrity: ${hits.length} marker(s) in ${summary.filesWithHits} file(s), ` +
      `${countable} ledger entr(ies) covering ${totalHits} occurrence(s), ` +
      `${violations.length} violation(s).`,
  );
  console.error(`report: ${relative(ROOT, join(REPORT_DIR, 'integrity.json'))}`);
}

// Every violation fails the gate regardless of severity; severity only orders
// the report so the worst thing is read first.
process.exit(violations.length === 0 ? 0 : 1);
