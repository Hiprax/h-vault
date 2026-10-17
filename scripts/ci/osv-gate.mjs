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
 * Exit codes: 0 = scanned, no unaccepted vulnerability (see (f)) · 1 = at least one
 * unaccepted vulnerability, or an acceptance this gate refuses ·
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
 *     advisory that genuinely has to be accepted is a `VULN-ACCEPT` ledger entry,
 *     which this gate re-validates itself — see (f).
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
 *
 *  f. AN ADVISORY WITH NO FIXED RELEASE IS ACCEPTED, NEVER IGNORED, and only
 *     through `.testfortress/suppressions.json`. An entry counts only when it is
 *     rule `VULN-ACCEPT`, kind `vulnerability-acceptance`, file
 *     `package-lock.json`, symbol EXACTLY `<advisory id> <name>@<version>` (no
 *     alias, range or wildcard), a positive integer `maxHits`, a reason, a
 *     non-empty `approvedBy`, `created` not after today, today not after
 *     `expires`, and `expires` at most thirty days out. The integrity scan only
 *     holds marker-less rules to its ninety-day cap and exempts them from its
 *     staleness and unused-capacity checks, so this gate does all of it again,
 *     and runs alone under `--only` and in the self-test as well:
 *       - an entry that breaks any of those rules is RED (exit 1), named, even
 *         when the scan found nothing it could have matched;
 *       - an entry whose id is missing or names more than one ledger entry
 *         accepts nothing and is red, because every verdict below is keyed
 *         by id; a date the calendar does not have (`2099-13-01`) is refused
 *         like any other malformed date;
 *       - matching is equality on the report's own id, package name and
 *         version, and an entry that would excuse more findings than its
 *         `maxHits`, or fewer, is red: unused capacity is room to excuse a
 *         finding nobody reviewed;
 *       - an entry that excuses NOTHING in a completed scan is red: a fix
 *         shipped, the package left the tree, or the advisory was re-keyed, and
 *         the acceptance must be pruned rather than left to excuse a future one;
 *       - the report is never rewritten: `osv.json` keeps the accepted finding,
 *         and the summary names every acceptance and its expiry;
 *       - the exit code still comes from the RAW report and the tool's exit:
 *         osv-scanner exits 1 whenever it found anything, so "every finding
 *         accepted" is green only with exit 1, and "nothing found" only with 0.
 *     `audit:ratchet:full` classifies the same report through the same
 *     functions, so the gate and the ratchet cannot disagree about what was
 *     accepted.
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
const LEDGER = '.testfortress/suppressions.json';
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

/** Thrown when the suppression ledger does not have the shape this gate can read. */
export class OsvLedgerError extends Error {
  constructor(message) {
    super(message);
    this.name = 'OsvLedgerError';
  }
}

/** What a ledger entry must be to accept an advisory; see decision (f). */
export const VULN_ACCEPT = Object.freeze({
  rule: 'VULN-ACCEPT',
  kind: 'vulnerability-acceptance',
  file: LOCKFILE,
  maxDays: 30,
});

const DATE = /^\d{4}-\d{2}-\d{2}$/;
/**
 * A date the calendar has. The shape alone admits `2099-13-01`, which compares
 * as a string after every real date and makes the day arithmetic NaN, so the
 * thirty-day cap (`NaN > 30`) would never refuse it.
 */
const isCalendarDate = (value) => {
  if (typeof value !== 'string' || !DATE.test(value)) return false;
  const time = Date.parse(`${value}T00:00:00Z`);
  return !Number.isNaN(time) && new Date(time).toISOString().slice(0, 10) === value;
};
/**
 * `<advisory id> <name>@<version>`: one space, a name that may be scoped
 * (`@scope/pkg`), and a version made of the characters a published npm version
 * uses — so no range, wildcard or second token can stand in for one.
 */
const SYMBOL =
  /^([A-Za-z0-9][A-Za-z0-9._:-]*) ((?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*)@([0-9A-Za-z][0-9A-Za-z.+-]*)$/;

/** `YYYY-MM-DD` in UTC, the calendar the ledger's dates are written in. */
export const utcToday = () => new Date().toISOString().slice(0, 10);
const daysFrom = (from, to) => (Date.parse(to) - Date.parse(from)) / 86_400_000;

/**
 * An acceptance symbol, or `null` when it is not exactly
 * `<advisory id> <name>@<version>`.
 *
 * @param {unknown} symbol
 * @returns {{ id: string, name: string, version: string } | null}
 */
export function parseAcceptanceSymbol(symbol) {
  if (typeof symbol !== 'string') return null;
  const match = SYMBOL.exec(symbol);
  if (!match) return null;
  return { id: match[1], name: match[2], version: match[3] };
}

/**
 * The ledger's `VULN-ACCEPT` entries, split into the ones that accept an
 * advisory today and the ones this gate refuses (each refusal is red). Every
 * other rule in the ledger is ignored. Strict on the ledger's own shape: one
 * this function cannot read throws, and is never "nothing accepted".
 *
 * @param {unknown} ledger the parsed `.testfortress/suppressions.json`
 * @param {string} today `YYYY-MM-DD`
 * @returns {{ acceptances: { entryId: string, id: string, name: string, version: string, maxHits: number, expires: string }[], problems: { entryId: string, reason: string }[] }}
 */
export function readAcceptances(ledger, today) {
  if (!isObject(ledger) || !Array.isArray(ledger.entries)) {
    throw new OsvLedgerError(`${LEDGER} has no \`entries\` array`);
  }
  const acceptances = [];
  const problems = [];
  // Every id in the ledger, not only the acceptances': the verdict keys dead and
  // over- or under-used entries by id, so a shared one would let a live entry
  // hide a dead one.
  const idUses = new Map();
  for (const entry of ledger.entries) {
    if (isObject(entry) && typeof entry.id === 'string') {
      idUses.set(entry.id, (idUses.get(entry.id) ?? 0) + 1);
    }
  }
  for (const entry of ledger.entries) {
    if (!isObject(entry) || entry.rule !== VULN_ACCEPT.rule) continue;
    const entryId = typeof entry.id === 'string' && entry.id !== '' ? entry.id : '(no id)';
    const refuse = (reason) => problems.push({ entryId, reason });
    const target = parseAcceptanceSymbol(entry.symbol);
    if (typeof entry.id !== 'string' || entry.id === '' || idUses.get(entry.id) !== 1) {
      refuse(
        `id ${entryId} must name exactly one ledger entry, and it names more than one entry or none`,
      );
    } else if (entry.kind !== VULN_ACCEPT.kind) {
      refuse(`kind must be "${VULN_ACCEPT.kind}"`);
    } else if (entry.file !== VULN_ACCEPT.file) {
      refuse(`file must be "${VULN_ACCEPT.file}", the only file this gate reads`);
    } else if (target === null) {
      refuse('symbol must be exactly "<advisory id> <name>@<version>"');
    } else if (!Number.isInteger(entry.maxHits) || entry.maxHits < 1) {
      refuse('maxHits must be a positive integer');
    } else if (typeof entry.reason !== 'string' || entry.reason.trim() === '') {
      refuse('reason is empty');
    } else if (
      !Array.isArray(entry.approvedBy) ||
      entry.approvedBy.length === 0 ||
      !entry.approvedBy.every((who) => typeof who === 'string' && who.trim() !== '')
    ) {
      refuse('approvedBy must name the reviewer(s) who accepted it');
    } else if (!isCalendarDate(entry.created) || entry.created > today) {
      refuse(
        `created "${String(entry.created)}" must be a YYYY-MM-DD calendar date no later than ${today}`,
      );
    } else if (!isCalendarDate(entry.expires)) {
      refuse(`expires "${String(entry.expires)}" must be a YYYY-MM-DD calendar date`);
    } else if (entry.expires < today) {
      refuse(
        `expired ${entry.expires}; re-check the advisory and the registry, then renew or remove it`,
      );
    } else if (daysFrom(today, entry.expires) > VULN_ACCEPT.maxDays) {
      refuse(
        `expires ${entry.expires}, more than ${String(VULN_ACCEPT.maxDays)} days from today; an acceptance is re-reviewed at least monthly`,
      );
    } else {
      acceptances.push({ entryId, ...target, maxHits: entry.maxHits, expires: entry.expires });
    }
  }
  return { acceptances, problems };
}

/**
 * Splits the report's findings into accepted and unaccepted, and names each
 * acceptance that excused nothing (`dead`) or more than its capacity
 * (`overused`). Matching is equality on id, package name and version.
 *
 * @param {{ package: string, version: string, id: string, summary: string }[]} vulnerabilities
 * @param {{ entryId: string, id: string, name: string, version: string, maxHits: number, expires: string }[]} acceptances
 */
export function classifyFindings(vulnerabilities, acceptances) {
  const accepted = [];
  const unaccepted = [];
  const hits = new Map(acceptances.map((acceptance) => [acceptance.entryId, 0]));
  for (const finding of vulnerabilities) {
    const acceptance = acceptances.find(
      (candidate) =>
        candidate.id === finding.id &&
        candidate.name === finding.package &&
        candidate.version === finding.version,
    );
    if (acceptance === undefined) {
      unaccepted.push(finding);
      continue;
    }
    hits.set(acceptance.entryId, (hits.get(acceptance.entryId) ?? 0) + 1);
    accepted.push({ finding, entryId: acceptance.entryId, expires: acceptance.expires });
  }
  const dead = acceptances.filter((a) => hits.get(a.entryId) === 0).map((a) => a.entryId);
  const usage = (a) => ({ entryId: a.entryId, hits: hits.get(a.entryId) ?? 0, maxHits: a.maxHits });
  const overused = acceptances.filter((a) => (hits.get(a.entryId) ?? 0) > a.maxHits).map(usage);
  // Capacity it did not use is capacity ready to excuse a finding nobody
  // reviewed; zero hits is `dead`, reported on its own.
  const underused = acceptances
    .filter((a) => {
      const used = hits.get(a.entryId) ?? 0;
      return used > 0 && used < a.maxHits;
    })
    .map(usage);
  return { accepted, unaccepted, dead, overused, underused };
}

/**
 * The gate's exit code once acceptances are taken into account; see decision
 * (f). With no acceptance in play it answers exactly as `exitCodeFor` does.
 *
 * @param {number} toolExit
 * @param {{ packages: number, vulnerabilities: unknown[] } | null} report
 * @param {ReturnType<typeof classifyFindings>} verdict
 * @param {{ entryId: string, reason: string }[]} problems
 * @returns {0 | 1 | 2}
 */
export function acceptanceExitCode(toolExit, report, verdict, problems) {
  if (problems.length > 0) return 1;
  if (report === null) return 2;
  if (verdict.unaccepted.length > 0) return 1;
  if (verdict.overused.length > 0) return 1;
  if (report.packages === 0) return 2;
  const expected = verdict.accepted.length > 0 ? OSV_EXIT.VULNERABLE : OSV_EXIT.CLEAN;
  if (toolExit !== expected) return 2;
  if (verdict.dead.length > 0 || verdict.underused.length > 0) return 1;
  return 0;
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

/**
 * The count line once acceptances are taken into account. With none in play it
 * is `summarizeReport`'s line, unchanged; with any, it can never read as a bare
 * "0 vulnerabilities".
 *
 * @param {{ packages: number, vulnerabilities: unknown[] }} report
 * @param {ReturnType<typeof classifyFindings>} verdict
 */
export function summarizeVerdict(report, verdict) {
  if (verdict.accepted.length === 0) return summarizeReport(report);
  const open = verdict.unaccepted.length;
  const packages = report.packages;
  const entries = [...new Set(verdict.accepted.map((accepted) => accepted.entryId))].join(', ');
  return (
    `${open.toLocaleString('en-US')} unaccepted ${open === 1 ? 'vulnerability' : 'vulnerabilities'} ` +
    `and ${verdict.accepted.length.toLocaleString('en-US')} accepted (${entries}) across ` +
    `${packages.toLocaleString('en-US')} ${packages === 1 ? 'package' : 'packages'}`
  );
}

/** One line per accepted finding, never in an unaccepted finding's shape. */
export function formatAccepted(accepted) {
  const { finding } = accepted;
  return `accepted  ${finding.package}@${finding.version}  ${finding.id}  (${accepted.entryId}, until ${accepted.expires})`;
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

  // The acceptances are read BEFORE the scan, so a ledger this gate cannot read
  // is "could not run" without a scan whose verdict nobody could interpret.
  let acceptances = [];
  let problems = [];
  const ledgerPath = path.join(repoRoot, LEDGER);
  if (existsSync(ledgerPath)) {
    try {
      ({ acceptances, problems } = readAcceptances(
        JSON.parse(readFileSync(ledgerPath, 'utf8')),
        utcToday(),
      ));
    } catch (error) {
      console.error(color.red(`${symbol.fail} osv: could not read ${LEDGER}: ${error.message}`));
      return 2;
    }
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

  const verdict = classifyFindings(parsed?.vulnerabilities ?? [], acceptances);
  const code = acceptanceExitCode(toolExit, parsed, verdict, problems);
  for (const problem of problems) {
    console.error(
      color.red(
        `${symbol.fail} ${LEDGER} ${problem.entryId} cannot accept anything: ${problem.reason}`,
      ),
    );
  }
  for (const finding of verdict.unaccepted) console.error(`  ${formatFinding(finding)}`);
  for (const accepted of verdict.accepted) note(formatAccepted(accepted));
  for (const overused of verdict.overused) {
    console.error(
      color.red(
        `${symbol.fail} ${overused.entryId} would excuse ${String(overused.hits)} findings; its maxHits is ${String(overused.maxHits)}`,
      ),
    );
  }
  if (parsed && code !== 2) {
    for (const underused of verdict.underused) {
      console.error(
        color.red(
          `${symbol.fail} ${underused.entryId} excuses ${String(underused.hits)} finding(s) of its maxHits ${String(underused.maxHits)}; lower maxHits to what it excuses`,
        ),
      );
    }
    for (const entryId of verdict.dead) {
      console.error(
        color.red(
          `${symbol.fail} ${entryId} accepts an advisory this scan no longer reports; remove it from ${LEDGER}`,
        ),
      );
    }
  }
  const counted = parsed ? summarizeVerdict(parsed, verdict) : 'no readable report';
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
