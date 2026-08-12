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
 * CodeQL is the one gate whose tool does not come with the repository, so this
 * gate has to answer a question no other gate does: is the analyser ABSENT, or
 * is it BROKEN? Those are different verdicts and they were not distinguished.
 * The CLI used to be located by `existsSync`, and the bundle ships `codeql` as a
 * shell script that a `umask 077` extraction leaves at mode 0600 — present,
 * found, and not executable. `codeql database create` then exited 127 and the
 * gate reported "codeql database create failed (exit 127)", which reads like a
 * defect in this repository and says nothing about the actual cause.
 *
 * The order is now: probe CodeQL for USABILITY (run it, don't stat it) → fall
 * back to Semgrep CE / OpenGrep when CodeQL cannot run → exit 78 (SKIPPED, never
 * passed) only when NEITHER is available, naming which was looked for and why
 * each was rejected. The ESLint gate (eslint-plugin-security plus the strict
 * type-checked rules) remains the always-on static-analysis baseline underneath
 * all three outcomes.
 *
 * The fallback is a DIFFERENT ENGINE with a different rule corpus, so a green
 * fallback run is recorded as reduced fidelity and never as equivalent to a
 * CodeQL run. It exists so an unusable CodeQL degrades to less analysis rather
 * than to none.
 *
 * To enable CodeQL, unpack the bundle into .cache/codeql (gitignored):
 *
 *   gh release download -R github/codeql-action <latest> \
 *     -p 'codeql-bundle-<platform>.tar.gz' -D .cache/codeql
 *   tar -xzf .cache/codeql/codeql-bundle-<platform>.tar.gz -C .cache/codeql
 *
 * If the extraction dropped the execute bit, `chmod +x .cache/codeql/codeql/codeql`
 * is the whole fix — which is what this gate now tells you instead of exit 127.
 *
 * The CodeQL CLI is free to use on codebases under an OSI-approved open-source
 * licence, which this repository (MIT) is.
 */
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { runExe, hasExe, captureExe, repoRoot } from './lib/proc.mjs';
import { color, symbol, note, warn } from './lib/ui.mjs';

const SKIP_EXIT = 78;

const DB_DIR = path.join(repoRoot, '.cache', 'codeql-db');
const SARIF = path.join(repoRoot, '.cache', 'codeql-results.sarif');
const CONFIG = path.join('scripts', 'ci', 'codeql-config.yml');
const BASELINE = path.join(repoRoot, 'scripts', 'ci', 'codeql-baseline.json');
const SUITE = 'codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls';

/**
 * The fallback engine's inputs, named here so tuning them is one edit.
 *
 * The targets are the SOURCE trees rather than `.`: the fallback resolves its
 * rulesets from the registry and then walks what it is given, and pointing it at
 * the repository root buys nothing but a slower scan over fixtures, build output
 * and configuration.
 */
const FALLBACK_RULESETS = ['p/javascript', 'p/typescript', 'p/nodejs'];
const FALLBACK_TARGETS = [
  'packages/shared/src',
  'packages/server/src',
  'packages/client/src',
  'scripts',
];
const FALLBACK_SARIF = path.join(repoRoot, '.cache', 'semgrep-results.sarif');

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

/**
 * Ask a candidate CodeQL CLI whether it can RUN, by running it.
 *
 * `existsSync` answers a question nobody has: a path that exists but cannot be
 * executed produces exit 127 from the first real command, half a minute later,
 * attributed to whatever that command was. `codeql version` costs a fraction of
 * a second and gives the answer up front.
 *
 * The returned `detail` is what turns a skip into an actionable one, so it
 * distinguishes the two failure modes worth telling apart: the file is not
 * executable (spawn fails outright, or the shim exits 126/127), versus the CLI
 * runs but reports itself broken.
 */
function probeCodeql(candidate) {
  if (candidate !== 'codeql' && !existsSync(candidate)) {
    return { usable: false, detail: 'not found' };
  }
  const probe = captureExe(candidate, ['version', '--format=terse']);
  if (probe.ok) return { usable: true, detail: probe.stdout.trim() };

  // Diagnose from the EVIDENCE, not from the exit status. Both host-state
  // failures this repository has actually hit report 127, and they need
  // opposite fixes:
  //
  //   - the bundle was extracted without execute bits, so the OS refuses to
  //     spawn it at all. captureExe surfaces the spawn error's own message
  //     (`spawnSync … EACCES`) and `chmod +x` is the entire fix.
  //   - a bundle for the WRONG PLATFORM was unpacked here — a win64 bundle on
  //     Linux, whose /bin/sh shim starts fine and then cannot find
  //     `tools/linux64/java/bin/java`, so the SHELL exits 127. `chmod +x` does
  //     nothing for that, and recommending it sends the reader down a dead end.
  //
  // So the executability claim is made only where the spawn itself was refused,
  // and every other failure quotes what the CLI actually said.
  const spawnRefused = /EACCES|ENOEXEC|permission denied|not executable|spawnSync/i.test(
    probe.stderr,
  );
  const firstLine = probe.stderr.trim().split('\n')[0] || 'no output';
  return {
    usable: false,
    detail: spawnRefused
      ? `present but not executable (${firstLine}) — try: chmod +x ${candidate}`
      : `present but unusable (exit ${String(probe.status)}): ${firstLine}`,
  };
}

/** Explicit path → PATH → the bundle a developer unpacked into .cache. */
function resolveCodeql() {
  const rejected = [];
  const candidates = [];

  const configured = process.env['HVAULT_CODEQL'];
  if (configured) candidates.push({ label: 'HVAULT_CODEQL', command: configured });
  if (hasExe('codeql', ['version', '--format=terse'])) {
    candidates.push({ label: 'PATH', command: 'codeql' });
  }
  candidates.push({
    label: '.cache bundle',
    command: path.join(
      repoRoot,
      '.cache',
      'codeql',
      'codeql',
      process.platform === 'win32' ? 'codeql.exe' : 'codeql',
    ),
  });

  for (const candidate of candidates) {
    const probe = probeCodeql(candidate.command);
    if (probe.usable) return { command: candidate.command, rejected };
    // "not found" is the ordinary absent case and is not worth a line each; a
    // candidate that IS there and still cannot run is the whole point of this.
    if (probe.detail !== 'not found') {
      rejected.push(
        `${candidate.label} (${path.relative(repoRoot, candidate.command) || candidate.command}): ${probe.detail}`,
      );
    }
  }
  return { command: null, rejected };
}

/**
 * The fallback engine: Semgrep CE, or OpenGrep — its LGPL-2.1-throughout fork,
 * which is CLI-compatible and carries no proprietary rule licence.
 *
 * Preference order is `semgrep`, then `opengrep`, then an explicit override, and
 * the choice is printed, because which engine produced a green run is part of
 * the result rather than an implementation detail.
 */
function resolveFallback() {
  const configured = process.env['HVAULT_SEMGREP'];
  if (configured && captureExe(configured, ['--version']).ok) {
    return { command: configured, name: path.basename(configured) };
  }
  for (const name of ['semgrep', 'opengrep']) {
    if (hasExe(name, ['--version'])) return { command: name, name };
  }
  return null;
}

/**
 * Run the fallback engine and exit with the gate's verdict.
 *
 * Gates on ERROR severity only, matching the CodeQL path's contract, and judges
 * from the SARIF rather than from the process exit code so that "the analyser
 * could not run" stays distinguishable from "the analyser found something" —
 * which is the same distinction this whole gate exists to make.
 */
async function runFallbackAndExit(engine) {
  console.log(color.cyan(`\n  running ${engine.name} (${FALLBACK_RULESETS.join(', ')})`));
  note('reduced fidelity: a different engine and rule corpus, not a CodeQL equivalent');

  rmSync(FALLBACK_SARIF, { force: true });
  const status = await runExe(engine.command, [
    'scan',
    ...FALLBACK_RULESETS.flatMap((ruleset) => ['--config', ruleset]),
    `--sarif-output=${FALLBACK_SARIF}`,
    '--quiet',
    ...FALLBACK_TARGETS,
  ]);

  if (status !== 0 || !existsSync(FALLBACK_SARIF)) {
    console.error(
      color.red(
        `\n${symbol.fail} ${engine.name} could not complete the scan (exit ${String(status)}) — this is a broken analyser, not a clean codebase`,
      ),
    );
    process.exit(1);
  }

  const report = JSON.parse(readFileSync(FALLBACK_SARIF, 'utf8'));
  const scan = report.runs?.[0];
  const levels = new Map((scan?.tool?.driver?.rules ?? []).map((rule) => [rule.id, rule]));
  const errors = [];
  for (const result of scan?.results ?? []) {
    const level =
      levels.get(result.ruleId)?.defaultConfiguration?.level ?? result.level ?? 'warning';
    if (level !== 'error') continue;
    const location = result.locations?.[0]?.physicalLocation;
    errors.push({
      rule: result.ruleId,
      message: result.message?.text ?? '',
      file: location?.artifactLocation?.uri ?? '?',
      line: location?.region?.startLine ?? 0,
    });
  }

  print(errors, 'error-severity findings', color.red);
  note(
    `${String(scan?.results?.length ?? 0)} finding(s) total from ${String(levels.size)} rule(s) — full SARIF: ${path.relative(repoRoot, FALLBACK_SARIF)}`,
  );

  if (errors.length > 0) {
    console.error(
      color.red(
        `\n${symbol.fail} ${engine.name} found ${String(errors.length)} error-severity issue(s)`,
      ),
    );
    process.exit(1);
  }

  console.log(
    color.green(`\n${symbol.pass} ${engine.name}: no error-severity findings (CodeQL unavailable)`),
  );
  process.exit(0);
}

const { command: codeql, rejected: codeqlRejected } = resolveCodeql();

if (!codeql) {
  // Say WHY before deciding what to do about it. A candidate that was present
  // and rejected is the difference between "install CodeQL" and "chmod +x".
  for (const reason of codeqlRejected) warn(`CodeQL ${reason}`);

  const fallback = resolveFallback();
  if (fallback) {
    note(`CodeQL unusable — falling back to ${fallback.name}`);
    await runFallbackAndExit(fallback);
  }

  // Neither engine is available. Name both, so the skip is a shopping list
  // rather than a shrug.
  console.log(color.yellow('      No usable SAST engine — gate skipped.'));
  note(
    codeqlRejected.length > 0
      ? 'CodeQL: found but unusable (see above).'
      : 'CodeQL: not installed (PATH, .cache/codeql bundle, HVAULT_CODEQL all empty).',
  );
  note('Semgrep CE / OpenGrep: not installed (PATH, HVAULT_SEMGREP both empty).');
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

// A function declaration, not a `const` arrow: the fallback path runs before
// this point in the module and would otherwise hit the temporal dead zone.
function print(findings, label, paint) {
  if (findings.length === 0) return;
  console.log(paint(`\n  ${label} (${String(findings.length)})`));
  for (const finding of findings) {
    console.log(
      `    ${color.cyan(`${finding.file}:${String(finding.line)}`)}  ${color.gray(finding.rule)}`,
    );
    console.log(`      ${finding.message.split('\n')[0]}`);
  }
}

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
