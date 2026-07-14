#!/usr/bin/env node
/**
 * Static analysis gate — the local stand-in for the old `sast` CodeQL job.
 *
 * Runs the same query suite the workflow ran (`security-and-quality` for
 * javascript-typescript) and fails on error-severity findings.
 *
 * Note what GitHub actually did with those findings: it uploaded them to the
 * Security tab, and the job passed either way. On a private repository that tab
 * needs GitHub Advanced Security to even display them — so on a private repo
 * without GHAS, that job was burning minutes to produce a result nobody could
 * read. Here the findings are printed, and an error-severity one stops the push.
 *
 * CodeQL is the one gate whose tool does not come with the repository. When the
 * CLI is absent this exits 78 — reported as SKIPPED, never as passed — and the
 * ESLint gate (with eslint-plugin-security and the type-checked strict rules)
 * remains the always-on static-analysis baseline.
 *
 * To enable it, unpack the CodeQL bundle into .cache/codeql (gitignored):
 *
 *   gh release download -R github/codeql-action <latest> \
 *     -p 'codeql-bundle-<platform>.tar.gz' -D .cache/codeql
 *   tar -xzf .cache/codeql/codeql-bundle-<platform>.tar.gz -C .cache/codeql
 *
 * The CodeQL CLI is free to use on codebases under an OSI-approved open-source
 * licence, which this repository (MIT) is.
 */
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { runExe, hasExe, repoRoot } from './lib/proc.mjs';
import { color, symbol, note, warn } from './lib/ui.mjs';

const SKIP_EXIT = 78;

const DB_DIR = path.join(repoRoot, '.cache', 'codeql-db');
const SARIF = path.join(repoRoot, '.cache', 'codeql-results.sarif');
const CONFIG = path.join('scripts', 'ci', 'codeql-config.yml');
const BASELINE = path.join(repoRoot, 'scripts', 'ci', 'codeql-baseline.json');
const SUITE = 'codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls';

const updatingBaseline = process.argv.includes('--update-baseline');

/**
 * Identifies a finding across edits that move it.
 *
 * CodeQL's own `primaryLocationLineHash` hashes the offending line's *content*,
 * so inserting an import above a finding does not resurrect it as "new" — which
 * a rule+file+line key would, on every unrelated edit, until the baseline was
 * noise and the gate was worthless.
 */
const fingerprint = (result) =>
  [
    result.ruleId,
    result.locations?.[0]?.physicalLocation?.artifactLocation?.uri ?? '?',
    result.partialFingerprints?.primaryLocationLineHash ?? 'no-hash',
  ].join('::');

/** Explicit path → PATH → the bundle a developer unpacked into .cache. */
function findCodeql() {
  const configured = process.env['HVAULT_CODEQL'];
  if (configured && existsSync(configured)) return configured;

  if (hasExe('codeql', ['version', '--format=terse'])) return 'codeql';

  const bundled = path.join(
    repoRoot,
    '.cache',
    'codeql',
    'codeql',
    process.platform === 'win32' ? 'codeql.exe' : 'codeql',
  );
  return existsSync(bundled) ? bundled : null;
}

const codeql = findCodeql();

if (!codeql) {
  console.log(color.yellow(`      CodeQL CLI not found — SAST gate skipped.`));
  note(
    'ESLint (eslint-plugin-security + strict type-checked rules) still ran as the SAST baseline.',
  );
  note(
    'Enable full CodeQL: see the header of scripts/ci/sast-gate.mjs, or set HVAULT_CODEQL=/path/to/codeql',
  );
  process.exit(SKIP_EXIT);
}

note(`using ${codeql === 'codeql' ? 'codeql (PATH)' : path.relative(repoRoot, codeql)}`);

/** maxRetries is what makes this work on Windows, where a lingering handle (a
 *  virus scanner, an editor) makes rm of a large tree fail with EPERM. */
const removeDatabase = () => {
  rmSync(DB_DIR, { recursive: true, force: true, maxRetries: 5, retryDelay: 250 });
};

const createDatabase = () =>
  runExe(codeql, [
    'database',
    'create',
    DB_DIR,
    '--language=javascript-typescript',
    '--overwrite',
    '--source-root=.',
    `--codescanning-config=${CONFIG}`,
  ]);

console.log(color.cyan('\n  building the CodeQL database'));
let created = await createDatabase();

// Self-heal a half-written database. Interrupting a push (Ctrl-C during the
// 20 minutes this pipeline takes) can leave .cache/codeql-db as a directory that
// is neither absent nor a valid CodeQL database — and `--overwrite` refuses it:
// "the directory does not appear to be a CodeQL database". Left alone, that
// state fails EVERY later push with an error that says nothing about its cause.
// Deleting the remnant and building once more costs a minute and ends it.
if (created !== 0 && existsSync(DB_DIR)) {
  warn('the existing CodeQL database is unusable — removing it and rebuilding once');
  try {
    removeDatabase();
  } catch {
    console.error(
      color.red(
        `\n${symbol.fail} could not remove ${path.relative(repoRoot, DB_DIR)} — delete it and retry`,
      ),
    );
    process.exit(1);
  }
  created = await createDatabase();
}

if (created !== 0) {
  console.error(
    color.red(`\n${symbol.fail} codeql database create failed (exit ${String(created)})`),
  );
  process.exit(1);
}

console.log(color.cyan('\n  running the security-and-quality suite'));
const analyzed = await runExe(codeql, [
  'database',
  'analyze',
  DB_DIR,
  SUITE,
  '--format=sarif-latest',
  `--output=${SARIF}`,
  '--sarif-category=/language:javascript-typescript',
]);
if (analyzed !== 0) {
  console.error(
    color.red(`\n${symbol.fail} codeql database analyze failed (exit ${String(analyzed)})`),
  );
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

const sarif = JSON.parse(readFileSync(SARIF, 'utf8'));
const run = sarif.runs?.[0];
const rules = new Map((run?.tool?.driver?.rules ?? []).map((rule) => [rule.id, rule]));

const buckets = { error: [], warning: [], recommendation: [] };

for (const result of run?.results ?? []) {
  const rule = rules.get(result.ruleId);
  const severity = rule?.properties?.['problem.severity'] ?? result.level ?? 'recommendation';
  const location = result.locations?.[0]?.physicalLocation;
  const finding = {
    rule: result.ruleId,
    message: result.message?.text ?? '',
    file: location?.artifactLocation?.uri ?? '?',
    line: location?.region?.startLine ?? 0,
    fingerprint: fingerprint(result),
  };
  (buckets[severity] ?? buckets.recommendation).push(finding);
}

const print = (findings, label, paint) => {
  if (findings.length === 0) return;
  console.log(paint(`\n  ${label} (${String(findings.length)})`));
  for (const finding of findings) {
    console.log(
      `    ${color.cyan(`${finding.file}:${String(finding.line)}`)}  ${color.gray(finding.rule)}`,
    );
    console.log(`      ${finding.message.split('\n')[0]}`);
  }
};

// ---------------------------------------------------------------------------
// Baseline
// ---------------------------------------------------------------------------
// A first CodeQL run against an existing codebase is never clean, and this one
// is not either — the suite reports every request value that reaches a Mongoose
// query as `js/sql-injection`, because it cannot see the Zod schema, the
// $-key-stripping middleware or the field allowlist standing in front of it.
//
// Failing on those would block the very first push and the gate would be
// switched off within a day. Failing on NOTHING would make it decoration. So
// the pre-existing findings are recorded, and the gate fails on what is NEW —
// which is the only thing the author of a push can actually act on.
//
//   npm run ci:sast -- --update-baseline    after reviewing / fixing findings

if (updatingBaseline) {
  writeFileSync(
    BASELINE,
    `${JSON.stringify(
      {
        note: 'Pre-existing CodeQL error-severity findings, accepted so the gate fails only on NEW ones. Regenerate with: npm run ci:sast -- --update-baseline',
        suite: SUITE,
        findings: buckets.error
          .map((finding) => ({
            fingerprint: finding.fingerprint,
            rule: finding.rule,
            file: finding.file,
          }))
          .sort((a, b) => a.fingerprint.localeCompare(b.fingerprint)),
      },
      null,
      2,
    )}\n`,
  );
  console.log(
    color.green(
      `\n${symbol.pass} baseline written: ${String(buckets.error.length)} error-severity finding(s) accepted`,
    ),
  );
  process.exit(0);
}

/** @type {Set<string>} */
const baseline = new Set(
  existsSync(BASELINE)
    ? JSON.parse(readFileSync(BASELINE, 'utf8')).findings.map((entry) => entry.fingerprint)
    : [],
);

const newErrors = buckets.error.filter((finding) => !baseline.has(finding.fingerprint));
const knownErrors = buckets.error.filter((finding) => baseline.has(finding.fingerprint));

print(newErrors, 'NEW error-severity findings', color.red);
print(buckets.warning, 'warning', color.yellow);
print(buckets.recommendation, 'recommendation', color.gray);

const total = buckets.error.length + buckets.warning.length + buckets.recommendation.length;
note(`${String(total)} finding(s) total — full SARIF: ${path.relative(repoRoot, SARIF)}`);
if (knownErrors.length > 0) {
  note(
    `${String(knownErrors.length)} error-severity finding(s) baselined (see scripts/ci/codeql-baseline.json)`,
  );
}

// A baselined finding that no longer appears was fixed — say so, so the baseline
// does not quietly accumulate entries that suppress nothing.
const fixed = baseline.size - knownErrors.length;
if (fixed > 0) {
  warn(
    `${String(fixed)} baselined finding(s) no longer occur — refresh with: npm run ci:sast -- --update-baseline`,
  );
}

if (newErrors.length > 0) {
  console.error(
    color.red(
      `\n${symbol.fail} CodeQL found ${String(newErrors.length)} NEW error-severity issue(s) — fix them, or accept them with: npm run ci:sast -- --update-baseline`,
    ),
  );
  process.exit(1);
}

if (buckets.warning.length > 0) {
  warn(
    `${String(buckets.warning.length)} warning-severity finding(s) — not fatal, but worth reading.`,
  );
}

console.log(color.green(`\n${symbol.pass} CodeQL: no new error-severity findings`));
