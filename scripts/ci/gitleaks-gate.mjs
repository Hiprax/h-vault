#!/usr/bin/env node
/**
 * `audit:secrets:gitleaks` — the gitleaks rule corpus over the whole history.
 *
 *   node scripts/ci/gitleaks-gate.mjs
 *
 * `audit:secrets`/`audit:secrets:full` (`secret-scan.mjs`) run this project's
 * own eleven rules. This gate adds gitleaks' default corpus (a few hundred
 * provider-specific rules plus a generic high-entropy key rule) over every
 * commit reachable from any ref, so a credential shape the project rules do
 * not know is still caught, including one that was committed and later deleted.
 *
 * Exit codes: 0 = no unignored finding · 1 = a finding, or an allowlist that is
 * not allowed · 2 = could not run. Never 78: `sast` is the ONLY gate allowed to
 * report itself skipped (`local-pipeline.test.ts`, `gate-surface.test.ts`), so
 * an absent scanner is "could not run", which fails the pipeline.
 *
 * ---------------------------------------------------------------------------
 * THE ALLOWLIST IS `.gitleaksignore`. Every other way this gate knows of to make
 * a finding disappear would bypass the suppression ledger (`audit:integrity`
 * gives every `.gitleaksignore` line its own marker, rule `IGNORE-FILE-GITLEAKS`,
 * which needs a dated, owned, judge-approved entry in
 * `.testfortress/suppressions.json`). Each one below is closed here; (e) lists
 * the ones found by measurement, and (k) what remains open:
 * ---------------------------------------------------------------------------
 *
 *  a. INLINE `gitleaks:allow` COMMENTS are ignored (`--ignore-gitleaks-allow`).
 *     Without the flag, one comment on the line of a real key silences it with
 *     no entry anywhere.
 *  b. A `.gitleaks.toml` AT THE SOURCE ROOT replaces the default rules, and can
 *     carry `[allowlist]` paths and regexes; this gate REFUSES to run over one
 *     (exit 1). A project rule set belongs in `secret-scan.mjs`.
 *  c. `GITLEAKS_CONFIG` / `GITLEAKS_CONFIG_TOML` in the ENVIRONMENT do the same
 *     thing invisibly; both are blanked for the child (an empty value is the
 *     same as unset to gitleaks, measured 2026-09-28 with 8.30.1).
 *  d. A GLOBAL fingerprint (`file:rule:line`, three parts) in `.gitleaksignore`
 *     ignores that line in EVERY commit, including ones not written yet, so a
 *     real key later committed at the same line of the same file would be
 *     silently allowed. Only commit-pinned fingerprints
 *     (`<40-hex commit>:file:rule:line`) are accepted: a commit is immutable, so
 *     such a line can only ever excuse the one historical blob a reviewer saw.
 *     A line gitleaks itself would reject as malformed is refused too.
 *
 * ---------------------------------------------------------------------------
 * OTHER DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  e. THE HISTORY IS READ WITH GIT'S OWN FILTERS OFF. gitleaks scans the output
 *     of `git -C <source> log -p -U0 <log-opts>` (its `sources/git.go`; with no
 *     `--log-opts` it appends `--full-history --all --diff-filter=tuxdb`, and a
 *     `--log-opts` value REPLACES those, so they are restated first). What that
 *     output shows is decided by state no diff reveals: `.git/info/attributes`
 *     and the untracked `.git/config` both live outside the tree. Measured
 *     2026-09-28 in a throwaway clone, each of these alone took the scan from 17
 *     findings to 0, exit 0, with the default options: `* -diff` in
 *     `.git/info/attributes` (every path becomes "Binary files differ"); a
 *     `diff=<driver>` attribute whose `textconv` is `true` (every blob becomes
 *     empty); `color.ui=always` or `color.diff=always` in the local config
 *     (gitleaks can no longer parse the coloured patch); and `log.showRoot=false`
 *     dropped the root commit's diff (17 → 13). `--text --no-textconv
 *     --no-ext-diff --no-color --root` restore all 17 with ALL of those applied
 *     at once, the same 17 fingerprints and no new finding from the files `--text`
 *     now reads (the lockfile, which `.gitattributes` marks `-diff`, is scanned as
 *     a result). `GIT_NO_REPLACE_OBJECTS=1` stops a `refs/replace/*` object from
 *     standing in for a commit's real content.
 *  f. A SHALLOW CLONE IS "COULD NOT RUN" (exit 2): its history ends at the graft
 *     point, so a clean scan of it says nothing about the commits it lacks.
 *  g. `--redact`: the SARIF report and the log never carry a secret's value.
 *     Fingerprints do not depend on it.
 *  h. `--platform none`: gitleaks otherwise tries to build web links from the
 *     `origin` URL and logs an ERROR for an SSH host alias, which reads as a
 *     scanner failure in a transcript and is not one.
 *  i. THE VERDICT COMES FROM THE REPORT AND THE EXIT CODE TOGETHER. gitleaks
 *     exits 1 both for "leaks found" (`--exit-code 1`) and on a fatal error,
 *     so exit 1 with no finding in a freshly written report is "could not run",
 *     and a finding in the report is red whatever the exit code said. The
 *     report is deleted before the run, so a stale one is never read.
 *  j. NOT DETECTED HERE: a `.gitleaksignore` line matching no finding (a dead
 *     line). gitleaks always applies `<source>/.gitleaksignore`, whatever
 *     `--gitleaks-ignore-path` names (measured), so this gate cannot see the
 *     raw set. History is immutable, so a line goes dead only after a history
 *     rewrite; a MISTYPED line leaves its real finding unignored, which is red.
 *  k. KNOWN GAPS, stated so they are not mistaken for coverage:
 *       · `git log -p` prints no diff for a MERGE commit, so content introduced
 *         by a merge itself (an "evil merge", or a stash's work-tree commit,
 *         which is a merge) is not scanned; the content of every non-merge
 *         commit, including a stash's index commit, is. 6 of the 193 commits
 *         were merges on 2026-09-28. A blob a merge introduced is still read
 *         by `audit:secrets:full` (`git rev-list --objects --all`, every blob
 *         outside its excluded paths), but only with this project's own eleven
 *         rules, not gitleaks' corpus.
 *       · Only the state named in (e) was measured. Another git setting or
 *         environment variable that reshapes `git log -p` output could hide
 *         content the same way; the untracked `.git/info/exclude` is already
 *         required empty by `audit:integrity` for the same reason.
 */
import { existsSync, readFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { captureExe, hasExe, repoRoot, runExe } from './lib/proc.mjs';
import { ensureReportDir, reportPath } from './lib/reports.mjs';
import { color, note, symbol } from './lib/ui.mjs';

export const REPORT_NAME = 'gitleaks.sarif';
const IGNORE_FILE = '.gitleaksignore';
const CONFIG_FILE = '.gitleaks.toml';
/** gitleaks splits this on spaces and appends it to `git log -p -U0`; see (e). */
export const LOG_OPTS = [
  '--full-history',
  '--all',
  '--diff-filter=tuxdb',
  '--text',
  '--no-textconv',
  '--no-ext-diff',
  '--no-color',
  '--root',
].join(' ');
/** Generous for the history (measured 4.3-4.6 s); a hang must end as "could not run". */
const SCAN_TIMEOUT_MS = 10 * 60_000;
const INSTALL_HINT =
  'install gitleaks 8.x (https://github.com/gitleaks/gitleaks#installing), e.g. ' +
  '`go install github.com/zricethezav/gitleaks/v8@v8.30.1`, and put it on PATH';

/**
 * `<commit>:<file>:<rule>:<line>`, the only line shape accepted; see (d).
 * gitleaks splits the line on `:`, so a path containing one is malformed to it too.
 */
export const COMMIT_FINGERPRINT = /^[0-9a-f]{40}:[^:]+:[A-Za-z0-9._-]+:[1-9]\d*$/;

/** Thrown when a report does not have the shape this gate can read. */
export class GitleaksReportError extends Error {
  constructor(message) {
    super(message);
    this.name = 'GitleaksReportError';
  }
}

const isObject = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);

/**
 * The lines gitleaks reads from `.gitleaksignore`, exactly as it reads them
 * (`detect.go` `AddGitleaksIgnore`: trim, skip blank lines and `#` comments),
 * split into accepted fingerprints and refused lines.
 *
 * @param {string} text
 * @returns {{ fingerprints: { line: number, value: string }[], refused: { line: number, value: string, reason: string }[] }}
 */
export function parseIgnoreFile(text) {
  const fingerprints = [];
  const refused = [];
  for (const [index, raw] of text.split('\n').entries()) {
    const value = raw.trim();
    if (value === '' || value.startsWith('#')) continue;
    const line = index + 1;
    if (COMMIT_FINGERPRINT.test(value)) {
      fingerprints.push({ line, value });
    } else if (value.split(':').length === 3) {
      refused.push({
        line,
        value,
        reason:
          'a global fingerprint ignores this line in every commit, including future ones; pin the commit',
      });
    } else {
      refused.push({ line, value, reason: 'not a `<commit>:<file>:<rule>:<line>` fingerprint' });
    }
  }
  return { fingerprints, refused };
}

/**
 * Reads a gitleaks `--report-format sarif` report into findings, each with the
 * fingerprint gitleaks itself matches `.gitleaksignore` against. Accepts the
 * JSON text or the parsed value. Strict: an unexpected shape throws rather than
 * reading as "no findings".
 *
 * @param {unknown} input
 * @returns {{ rule: string, file: string, line: number, commit: string, fingerprint: string }[]}
 */
export function parseGitleaksSarif(input) {
  let sarif = input;
  if (typeof input === 'string') {
    try {
      sarif = JSON.parse(input);
    } catch (error) {
      throw new GitleaksReportError(`report is not JSON: ${error.message}`);
    }
  }
  const runs = isObject(sarif) ? sarif.runs : undefined;
  if (!Array.isArray(runs) || runs.length === 0) {
    throw new GitleaksReportError('report has no `runs`');
  }
  const findings = [];
  for (const [r, run] of runs.entries()) {
    if (!isObject(run) || !Array.isArray(run.results)) {
      throw new GitleaksReportError(`runs[${r}] has no \`results\` array`);
    }
    for (const [i, result] of run.results.entries()) {
      const where = `runs[${r}].results[${i}]`;
      const location = isObject(result) ? result.locations?.[0]?.physicalLocation : undefined;
      const file = location?.artifactLocation?.uri;
      const line = location?.region?.startLine;
      const commit = result?.partialFingerprints?.commitSha;
      const rule = result?.ruleId;
      if (typeof rule !== 'string' || typeof file !== 'string' || !Number.isInteger(line)) {
        throw new GitleaksReportError(`${where} names no rule, file and line`);
      }
      if (typeof commit !== 'string' || commit === '') {
        throw new GitleaksReportError(`${where} names no commit (was the history scanned?)`);
      }
      findings.push({ rule, file, line, commit, fingerprint: `${commit}:${file}:${rule}:${line}` });
    }
  }
  return findings;
}

/**
 * The gate's exit code; see (b), (d) and (i).
 *
 * @param {number} toolExit gitleaks' own exit code
 * @param {unknown[] | null} findings the parsed report, `null` when there is no readable report
 * @param {number} refusedAllowlist refused `.gitleaksignore` lines plus a present `.gitleaks.toml`
 * @returns {0 | 1 | 2}
 */
export function exitCodeFor(toolExit, findings, refusedAllowlist) {
  if (refusedAllowlist > 0) return 1;
  if (findings === null) return 2;
  if (findings.length > 0) return 1;
  if (toolExit !== 0) return 2;
  return 0;
}

/** `rule | file:line | commit`, then the fingerprint that would allowlist it. */
export function formatFinding(finding) {
  return (
    `${finding.rule} | ${finding.file}:${String(finding.line)} | ${finding.commit}\n` +
    `    fingerprint: ${finding.fingerprint}`
  );
}

async function main() {
  if (!hasExe('gitleaks', ['version'])) {
    console.error(color.red(`${symbol.fail} gitleaks is not installed: ${INSTALL_HINT}`));
    return 2;
  }
  const shallow = captureExe('git', ['rev-parse', '--is-shallow-repository']);
  if (!shallow.ok || shallow.stdout.trim() !== 'false') {
    console.error(
      color.red(
        `${symbol.fail} gitleaks: could not run: ${shallow.ok ? 'this is a shallow clone, so its history is incomplete (git fetch --unshallow)' : 'git rev-parse failed'}`,
      ),
    );
    return 2;
  }

  let refusedAllowlist = 0;
  if (existsSync(path.join(repoRoot, CONFIG_FILE))) {
    refusedAllowlist++;
    console.error(
      color.red(
        `${symbol.fail} ${CONFIG_FILE} would replace gitleaks' default rules and allowlist outside the suppression ledger; remove it`,
      ),
    );
  }
  const ignorePath = path.join(repoRoot, IGNORE_FILE);
  if (existsSync(ignorePath)) {
    const { fingerprints, refused } = parseIgnoreFile(readFileSync(ignorePath, 'utf8'));
    for (const line of refused) {
      console.error(
        color.red(
          `${symbol.fail} ${IGNORE_FILE}:${String(line.line)} ${line.reason}: ${line.value}`,
        ),
      );
    }
    refusedAllowlist += refused.length;
    note(`${IGNORE_FILE}: ${String(fingerprints.length)} commit-pinned fingerprint(s)`);
  }

  ensureReportDir();
  const report = reportPath(REPORT_NAME);
  rmSync(report, { force: true });

  const toolExit = await runExe(
    'gitleaks',
    [
      'detect',
      '--source',
      '.',
      `--log-opts=${LOG_OPTS}`,
      '--gitleaks-ignore-path',
      IGNORE_FILE,
      '--ignore-gitleaks-allow',
      '--redact',
      '--platform',
      'none',
      '--report-format',
      'sarif',
      '--report-path',
      report,
      '--exit-code',
      '1',
      '--no-banner',
      '--no-color',
    ],
    {
      env: { GITLEAKS_CONFIG: '', GITLEAKS_CONFIG_TOML: '', GIT_NO_REPLACE_OBJECTS: '1' },
      timeoutMs: SCAN_TIMEOUT_MS,
    },
  );

  let findings = null;
  if (existsSync(report)) {
    try {
      findings = parseGitleaksSarif(readFileSync(report, 'utf8'));
    } catch (error) {
      console.error(color.red(`${symbol.fail} ${error.message}`));
    }
  }
  for (const finding of findings ?? []) console.error(`  ${formatFinding(finding)}`);

  const code = exitCodeFor(toolExit, findings, refusedAllowlist);
  if (code === 0) {
    console.log(color.green(`${symbol.pass} gitleaks: 0 unignored findings in the history`));
  } else if (code === 1) {
    const reasons = [];
    if (findings !== null && findings.length > 0) {
      reasons.push(`${String(findings.length)} unignored finding(s)`);
    }
    if (refusedAllowlist > 0) {
      reasons.push(`${String(refusedAllowlist)} allowlist item(s) this gate may not use (above)`);
    }
    console.error(color.red(`${symbol.fail} gitleaks: ${reasons.join('; ')}`));
  } else {
    console.error(
      color.red(
        `${symbol.fail} gitleaks: could not run (exit ${String(toolExit)}, ` +
          `${findings === null ? 'no readable report' : 'no finding in the report'}); ` +
          'a scan that did not complete is never reported clean',
      ),
    );
  }
  note(`report: ${path.relative(repoRoot, report)}`);
  return code;
}

/** True when this module was started as a program rather than imported. */
function isEntryPoint() {
  const invoked = process.argv[1];
  if (invoked === undefined) return false;
  return path.resolve(invoked) === path.resolve(fileURLToPath(import.meta.url));
}

if (isEntryPoint()) {
  let code;
  try {
    code = await main();
  } catch (error) {
    // An unexpected throw is a gate that did not finish, never a red verdict
    // about the history (Node's own exit for an uncaught error is 1).
    console.error(
      color.red(`${symbol.fail} gitleaks: could not run: ${error?.message ?? String(error)}`),
    );
    code = 2;
  }
  process.exit(code);
}
