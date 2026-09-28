#!/usr/bin/env node
/**
 * `audit:deps:osv` — the lockfile against the OSV advisory database.
 *
 *   node scripts/ci/osv-gate.mjs
 *
 * `audit:deps` (`npm audit --omit=dev`) reads npm's own advisory feed for the
 * PRODUCTION tree. This gate reads OSV (which aggregates the GitHub Advisory
 * Database and others) for EVERY package in `package-lock.json`, dev tooling
 * included, because a compromised build or test dependency runs on the same
 * machine that holds the release credentials.
 *
 * Exit codes: 0 = scanned, no vulnerability · 1 = at least one vulnerability ·
 * 2 = could not run. Never 78: `sast` is the ONLY gate allowed to report itself
 * skipped (`local-pipeline.test.ts`, `gate-surface.test.ts`), so an absent
 * scanner is "could not run", which fails the pipeline rather than passing it.
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. THE VERDICT COMES FROM THE REPORT AND THE EXIT CODE TOGETHER. The tool's
 *     documented return codes (osv-scanner "Output" documentation, "Return
 *     codes", read 2026-09-28 for 2.4.0; `scan source --help` prints none):
 *       0        packages found, none matches a known vulnerability
 *       1        packages found, and there are vulnerabilities
 *       1-126    reserved for vulnerability-result related errors
 *       127      general error
 *       128      no packages found
 *       129-255  reserved for non-result related errors
 *     So exit 1 alone is ambiguous, and exit 0 with an empty report can mean a
 *     scan of nothing. A vulnerability in the report is red whatever the exit
 *     code said; green needs exit 0 AND a parseable report AND at least one
 *     package scanned; everything else is "could not run" — a failed fetch of
 *     the advisory database included, which must never read as clean.
 *
 *  b. THE CONFIG IS PINNED TO AN EMPTY FILE. osv-scanner loads an
 *     `osv-scanner.toml` from the lockfile's directory on its own, and its
 *     `[[IgnoredVulns]]` table turns a vulnerable lockfile into exit 0 (measured
 *     2026-09-28: minimist 1.2.5 went from exit 1 to exit 0). That would be an
 *     accepted advisory outside the suppression ledger, where no expiry, owner
 *     or reviewer applies. `--config` with an empty file overrides the discovery
 *     (measured: exit 1 again), so no file in the tree can quiet this gate. An
 *     advisory that genuinely has to be accepted is a `VULN-ACCEPT` ledger entry
 *     and a change to this gate, reviewed as one.
 *
 *  c. `--all-packages` IS WHAT MAKES THE PACKAGE COUNT A MEASUREMENT. Without it
 *     a clean report lists no packages at all, so "0 vulnerabilities across N
 *     packages" could only be printed from a hard-coded N, and a lockfile the
 *     scanner silently failed to read would look identical to a clean one.
 *
 *  d. `--all-vulns` BECAUSE THE GATE CONDITION IS "ANY SEVERITY". The default
 *     hides advisories the database marks unimportant; a gate that is meant to
 *     be zero should not start from a filtered zero.
 *
 *  e. NO `-r`. With `--lockfile` and no directory argument it has nothing to
 *     recurse into (measured: "0 dirs visited, 1 inodes visited"), and a flag
 *     that reads as "scan the tree" when it does not would mislead a reviewer.
 *     The workspaces share the one root lockfile.
 */
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { hasExe, repoRoot, runExe } from './lib/proc.mjs';
import { ensureReportDir, reportPath } from './lib/reports.mjs';
import { color, note, symbol } from './lib/ui.mjs';

export const REPORT_NAME = 'osv.json';
const LOCKFILE = 'package-lock.json';
/** Generous for one lockfile (measured 2.7 s end to end); a hung fetch must end as "could not run". */
const SCAN_TIMEOUT_MS = 5 * 60_000;
const INSTALL_HINT =
  'install osv-scanner 2.x (https://google.github.io/osv-scanner/installation/), e.g. ' +
  '`go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.4.0`, and put it on PATH';

/** osv-scanner's documented return codes; see decision (a). */
export const OSV_EXIT = Object.freeze({
  CLEAN: 0,
  VULNERABLE: 1,
  GENERAL_ERROR: 127,
  NO_PACKAGES: 128,
});

/** Thrown when a report does not have the shape this gate can read. */
export class OsvReportError extends Error {
  constructor(message) {
    super(message);
    this.name = 'OsvReportError';
  }
}

const isObject = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);

/**
 * Reads an `osv-scanner --format json` report into the two numbers the gate
 * decides on. Accepts the JSON text or the already-parsed value.
 *
 * Strict on purpose: an unexpected shape is an error, never "no findings",
 * because a report this function misread as empty would be a green gate over
 * a scan nobody looked at.
 *
 * @param {unknown} input
 * @returns {{ packages: number, vulnerabilities: { package: string, version: string, id: string, summary: string }[] }}
 */
export function parseOsvReport(input) {
  let report = input;
  if (typeof input === 'string') {
    try {
      report = JSON.parse(input);
    } catch (error) {
      throw new OsvReportError(`report is not JSON: ${error.message}`);
    }
  }
  if (!isObject(report) || !Array.isArray(report.results)) {
    throw new OsvReportError('report has no `results` array');
  }

  let packages = 0;
  const vulnerabilities = [];
  for (const [r, result] of report.results.entries()) {
    if (!isObject(result) || !Array.isArray(result.packages)) {
      throw new OsvReportError(`results[${r}] has no \`packages\` array`);
    }
    for (const [p, entry] of result.packages.entries()) {
      const pkg = isObject(entry) ? entry.package : undefined;
      if (!isObject(pkg) || typeof pkg.name !== 'string' || typeof pkg.version !== 'string') {
        throw new OsvReportError(`results[${r}].packages[${p}] names no package and version`);
      }
      packages++;
      const found = entry.vulnerabilities ?? [];
      if (!Array.isArray(found)) {
        throw new OsvReportError(`${pkg.name}@${pkg.version}: \`vulnerabilities\` is not an array`);
      }
      for (const vulnerability of found) {
        if (!isObject(vulnerability) || typeof vulnerability.id !== 'string') {
          throw new OsvReportError(`${pkg.name}@${pkg.version}: a vulnerability has no id`);
        }
        vulnerabilities.push({
          package: pkg.name,
          version: pkg.version,
          id: vulnerability.id,
          summary: typeof vulnerability.summary === 'string' ? vulnerability.summary : '',
        });
      }
    }
  }
  return { packages, vulnerabilities };
}

/**
 * The gate's exit code from the tool's exit code and the parsed report (`null`
 * when there is no readable report). See decision (a).
 *
 * @param {number} toolExit
 * @param {{ packages: number, vulnerabilities: unknown[] } | null} report
 * @returns {0 | 1 | 2}
 */
export function exitCodeFor(toolExit, report) {
  if (report === null) return 2;
  if (report.vulnerabilities.length > 0) return 1;
  if (toolExit !== OSV_EXIT.CLEAN) return 2;
  if (report.packages === 0) return 2;
  return 0;
}

/**
 * The count line the gate prints, from the report alone (decision (c)): never
 * a hard-coded package total.
 *
 * @param {{ packages: number, vulnerabilities: unknown[] }} report
 */
export function summarizeReport(report) {
  const found = report.vulnerabilities.length;
  const packages = report.packages;
  return (
    `${found.toLocaleString('en-US')} ${found === 1 ? 'vulnerability' : 'vulnerabilities'} across ` +
    `${packages.toLocaleString('en-US')} ${packages === 1 ? 'package' : 'packages'}`
  );
}

/** One line per finding: `package@version  id  summary`. */
export function formatFinding(finding) {
  const summary = finding.summary ? `  ${finding.summary}` : '';
  return `${finding.package}@${finding.version}  ${finding.id}${summary}`;
}

async function main() {
  if (!hasExe('osv-scanner', ['--version'])) {
    console.error(color.red(`${symbol.fail} osv-scanner is not installed: ${INSTALL_HINT}`));
    return 2;
  }
  if (!existsSync(path.join(repoRoot, LOCKFILE))) {
    console.error(color.red(`${symbol.fail} ${LOCKFILE} not found at the repository root`));
    return 2;
  }
  if (existsSync(path.join(repoRoot, 'osv-scanner.toml'))) {
    note('osv-scanner.toml is present and deliberately NOT honoured (see decision (b))');
  }

  ensureReportDir();
  const report = reportPath(REPORT_NAME);
  // A report left by an earlier run must never be read as this run's verdict.
  rmSync(report, { force: true });

  const scratch = mkdtempSync(path.join(tmpdir(), 'hv-osv-'));
  const emptyConfig = path.join(scratch, 'osv-scanner.toml');
  writeFileSync(emptyConfig, '', 'utf8');

  let toolExit;
  try {
    toolExit = await runExe(
      'osv-scanner',
      [
        'scan',
        'source',
        '--lockfile',
        LOCKFILE,
        '--config',
        emptyConfig,
        '--format',
        'json',
        '--all-packages',
        '--all-vulns',
        '--output-file',
        report,
      ],
      { timeoutMs: SCAN_TIMEOUT_MS },
    );
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }

  let parsed = null;
  if (existsSync(report)) {
    try {
      parsed = parseOsvReport(readFileSync(report, 'utf8'));
    } catch (error) {
      console.error(color.red(`${symbol.fail} ${error.message}`));
    }
  }

  const code = exitCodeFor(toolExit, parsed);
  if (parsed) {
    for (const finding of parsed.vulnerabilities) console.error(`  ${formatFinding(finding)}`);
  }
  const counted = parsed ? summarizeReport(parsed) : 'no readable report';
  if (code === 0) {
    console.log(color.green(`${symbol.pass} osv: ${counted}`));
  } else if (code === 1) {
    console.error(color.red(`${symbol.fail} osv: ${counted}`));
  } else {
    console.error(
      color.red(
        `${symbol.fail} osv: could not run (osv-scanner exit ${String(toolExit)}, ${counted}); ` +
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
    // about the lockfile (Node's own exit for an uncaught error is 1).
    console.error(
      color.red(`${symbol.fail} osv: could not run: ${error?.message ?? String(error)}`),
    );
    code = 2;
  }
  process.exit(code);
}
