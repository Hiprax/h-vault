#!/usr/bin/env node
/**
 * `audit:openapi` — a breaking change to the HTTP contract requires a MAJOR
 * version bump.
 *
 *   node scripts/ci/openapi-gate.mjs           check, write openapi-compat.json
 *   node scripts/ci/openapi-gate.mjs --json    the summary on stdout as well
 *
 * Exit codes: 0 = no breaking change, or one carried by a MAJOR bump · 1 = a
 * breaking change at the same MAJOR · 2 = could not run (oasdiff absent, the
 * snapshot missing, the document unbuildable).
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. THIS IS RELEASE POLICY, NOT CONFIG LINTING, WHICH IS WHY IT IS ITS OWN
 *     GATE. `audit:config` asks whether the OpenAPI document is well-formed;
 *     this asks whether shipping it would break somebody's client. Those are
 *     different questions with different failure modes, and they need separate
 *     defect-injection cases: `verify:selftest` plants ONE defect per registered
 *     task, so folding this into `audit:config` would have meant proving either
 *     the actionlint leg or this one, never both.
 *
 *  b. THE COMPARISON IS AGAINST A COMMITTED SNAPSHOT, AND THE SNAPSHOT RECORDS
 *     ITS OWN VERSION. `packages/server/openapi.snapshot.json` is an OpenAPI
 *     document, so `info.version` already names the release it describes — no
 *     sidecar, and nothing to keep in step by hand. The snapshot moves only in
 *     the same commit as the version it describes; refreshing it on its own
 *     erases the evidence of whatever it was about to be compared against.
 *
 *  c. THE REVISION IS GENERATED FROM SOURCE, EVERY RUN. `swaggerSpec` is a
 *     TypeScript object literal and it is what the server serves; a checked-in
 *     copy of the current document could drift from it, and then this gate would
 *     be comparing two stale files. It is generated here rather than read from
 *     the artifact `audit:config` happens to leave behind, so that running this
 *     gate alone (`--only=openapi`) checks the same thing as running it in a
 *     full pipeline.
 *
 *  d. `--fail-on WARN`, NOT `ERR`. oasdiff's ERR/WARN split grades how CERTAINLY
 *     a change breaks a client: removing an endpoint is ERR, removing an
 *     optional property from a response is WARN. For this application the WARN
 *     half is not advisory — the SPA reads response properties directly, and the
 *     one whose removal oasdiff grades WARN includes `encryptedVaultKey`, without
 *     which a client cannot open the vault at all. Measured: at `--fail-on ERR`
 *     a deleted response property produced three findings and exit 0.
 *
 *  e. A MISSING `oasdiff` IS "COULD NOT RUN", NEVER A SKIP. Exit 78 is this
 *     pipeline's SKIPPED sentinel and it is honoured from ONE gate (`sast`). The
 *     binary is declared in `local-ci.mjs`'s PREREQUISITES table so the runner
 *     says "oasdiff is not on PATH" before the gate runs; the check here is the
 *     backstop for anyone invoking this script directly.
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { captureExe, repoRoot } from './lib/proc.mjs';
import { ensureReportDir, reportPath, writeJsonReport } from './lib/reports.mjs';
import { color, symbol } from './lib/ui.mjs';
import { majorBumpAccountsForBreaking, majorOf } from './lib/version.mjs';

const EXIT_OK = 0;
const EXIT_FINDINGS = 1;
const EXIT_CANNOT_RUN = 2;

const asJson = process.argv.includes('--json');
const SNAPSHOT_REL = 'packages/server/openapi.snapshot.json';

const fatal = (message) => {
  console.error(color.red(`${symbol.fail} openapi-gate: ${message}`));
  process.exit(EXIT_CANNOT_RUN);
};

const readJson = (file, label) => {
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch (error) {
    return fatal(`${label} could not be read as JSON: ${error.message}`);
  }
};

// ---------------------------------------------------------------------------
// (e) the tool
// ---------------------------------------------------------------------------
const version = captureExe('oasdiff', ['--version']);
if (!version.ok) {
  fatal('oasdiff is not on PATH — install it (https://github.com/oasdiff/oasdiff/releases)');
}
const oasdiffVersion = version.stdout.trim().split('\n')[0] ?? 'unknown';

// ---------------------------------------------------------------------------
// (b) the base
// ---------------------------------------------------------------------------
const snapshotPath = path.join(repoRoot, SNAPSHOT_REL);
if (!existsSync(snapshotPath)) {
  fatal(
    `${SNAPSHOT_REL} is missing. It is the committed base this gate compares against; ` +
      'regenerate it with `node scripts/ci/emit-openapi.mjs` only in the same commit as the ' +
      'version bump it describes.',
  );
}
const snapshot = readJson(snapshotPath, SNAPSHOT_REL);
const snapshotVersion = String(snapshot?.info?.version ?? '');
const snapshotMajor = majorOf(snapshotVersion);
if (snapshotMajor === null) {
  fatal(`${SNAPSHOT_REL} has no semver info.version (found ${JSON.stringify(snapshotVersion)})`);
}

// ---------------------------------------------------------------------------
// (c) the revision
// ---------------------------------------------------------------------------
// `node --import tsx`, never `npx`: npx is a `.cmd` shim on Windows and Node
// refuses to spawn one without a shell, which would make this gate report "could
// not build the OpenAPI document" on a platform where nothing is wrong.
const emitted = captureExe(process.execPath, ['--import', 'tsx', 'scripts/ci/emit-openapi.mjs']);
if (!emitted.ok || !emitted.stdout.trim().startsWith('{')) {
  fatal(
    'could not build the OpenAPI document from packages/server/src/config/swagger.ts ' +
      `(is @hvault/shared built?): ${emitted.stderr.trim().slice(0, 300)}`,
  );
}
ensureReportDir();
const generatedPath = reportPath('openapi-generated.json');
writeFileSync(generatedPath, `${emitted.stdout.trim()}\n`, 'utf8');

const generated = readJson(generatedPath, 'the generated OpenAPI document');
const currentVersion = String(generated?.info?.version ?? '');
const currentMajor = majorOf(currentVersion);
if (currentMajor === null) {
  fatal(
    `the generated document has no semver info.version (found ${JSON.stringify(currentVersion)})`,
  );
}

// The document's version comes from APP_VERSION, which `scripts/inject-version.js`
// compiles out of the root package.json. When the two disagree the shared package
// on disk is stale, and every comparison below would be made against the wrong
// version — a "could not run", not a finding.
const pkg = readJson(path.join(repoRoot, 'package.json'), 'package.json');
if (currentVersion !== String(pkg.version)) {
  fatal(
    `the generated document reports version ${currentVersion} but package.json says ${String(pkg.version)} — ` +
      'packages/shared/dist is stale; run `npm run build:shared`',
  );
}

// ---------------------------------------------------------------------------
// (d) the comparison
// ---------------------------------------------------------------------------
const run = captureExe('oasdiff', [
  'breaking',
  snapshotPath,
  generatedPath,
  '--fail-on',
  'WARN',
  '--format',
  'json',
]);
// No `--color`: oasdiff rejects it for the json format ("only relevant with
// 'text' or 'singleline'") and exits 100 with a usage message, which this gate
// correctly reports as unparseable rather than as a clean contract.

let changes;
try {
  changes = JSON.parse(run.stdout.trim() || '[]');
} catch (error) {
  // Exit status and parseability are judged together: an oasdiff that exited
  // non-zero having written nothing a parser can use is a broken gate, and
  // `JSON.parse(stdout || '[]')` alone would read it as a clean contract.
  fatal(
    `oasdiff produced output this gate cannot parse (exit ${String(run.status)}): ` +
      `${error.message}: ${(run.stderr || run.stdout || '').trim().slice(0, 300)}`,
  );
}
if (!Array.isArray(changes)) {
  fatal(`oasdiff returned ${typeof changes}, expected an array of changes`);
}
// oasdiff exits 1 when it has findings at or above --fail-on; anything else with
// nothing to show for it is a comparison that never happened.
if (run.status !== 0 && run.status !== 1 && changes.length === 0) {
  fatal(
    `oasdiff exited ${String(run.status)} with no findings: ` +
      `${(run.stderr || run.stdout || '').trim().slice(0, 300)}`,
  );
}

/** oasdiff severity levels: 1 INFO, 2 WARN, 3 ERR. */
const LEVELS = { 1: 'info', 2: 'warning', 3: 'error' };
const findings = changes.map((change) => ({
  id: String(change.id ?? 'unknown'),
  level: LEVELS[Number(change.level)] ?? 'error',
  operation: String(change.operation ?? ''),
  path: String(change.path ?? ''),
  text: String(change.text ?? ''),
}));

// The exemption is tied to THE bump that earned it, and expires with it. The
// predicate is in `lib/version.mjs` because it is pure release policy and is
// unit-tested there; see its docblock for why `current > snapshot` is a hole.
const majorBumped = majorBumpAccountsForBreaking(snapshotVersion, currentVersion);
const breaking = findings.length > 0;
const passed = !breaking || majorBumped;

// The size of the BASE, recorded so the ratchet can hold it. A snapshot that
// shrank — truncated by a botched regeneration, or emptied deliberately — makes
// every comparison against it vacuous, because an addition is never a breaking
// change: the gate would report "0 breaking changes" having compared the served
// contract against almost nothing. `.testfortress/baseline.json` ratchets these
// upward, so shrinking the base costs a written `--accept` reason rather than
// passing silently. Same idea as `config.inputsExamined.*`.
const snapshotPaths = Object.keys(snapshot?.paths ?? {});
const snapshotOperations = snapshotPaths.reduce(
  (total, key) => total + Object.keys(snapshot.paths[key] ?? {}).length,
  0,
);

/**
 * A fingerprint of the committed snapshot, pinned in `baseline.json`.
 *
 * The size ratchet above catches a snapshot that SHRANK. It cannot catch the
 * other regeneration: delete a response property from `swagger.ts` and refresh
 * the snapshot in the same commit at the same version, and oasdiff compares the
 * new contract against a base that already agrees with it — zero findings, the
 * path and operation counts unchanged, and a breaking change ships under a
 * version that promises none. That is the golden-file regeneration the doctrine
 * forbids, and nothing here could see it.
 *
 * Direction `pin`, so ANY edit to the snapshot — refresh, truncation, hand
 * edit — fails `audit:ratchet:full` until it is accepted with a written reason,
 * exactly like the integrity fingerprints. Refreshing the base becomes a
 * deliberate, recorded act rather than a silent one.
 */
const snapshotHash = createHash('sha256')
  .update(readFileSync(snapshotPath, 'utf8'))
  .digest('hex')
  .slice(0, 16);

writeJsonReport('openapi-compat.json', {
  version: 1,
  checkedAt: new Date().toISOString(),
  tool: oasdiffVersion,
  failOn: 'WARN',
  snapshot: {
    file: SNAPSHOT_REL,
    version: snapshotVersion,
    major: snapshotMajor,
    paths: snapshotPaths.length,
    operations: snapshotOperations,
    hash: snapshotHash,
  },
  current: { version: currentVersion, major: currentMajor },
  majorBumped,
  breakingChanges: findings.length,
  passed,
  findings,
});

if (asJson) {
  process.stdout.write(
    `${JSON.stringify({ passed, majorBumped, breakingChanges: findings.length, findings }, null, 2)}\n`,
  );
}

for (const finding of findings) {
  console.error(
    `  ${color.cyan(`${finding.operation} ${finding.path}`.trim() || 'document')}  ` +
      `${color.yellow(`[${finding.id}]`)} ${finding.text}`,
  );
}

if (!passed) {
  console.error(
    color.red(
      `\n${symbol.fail} audit:openapi: ${String(findings.length)} breaking change(s) to the HTTP ` +
        `contract at version ${currentVersion}, which no MAJOR bump accounts for — the committed ` +
        `snapshot describes ${snapshotVersion}.\n\n` +
        '  A breaking change needs a MAJOR bump. Either restore the contract, or set the root\n' +
        `  package.json version to ${String(snapshotMajor + 1)}.0.0 and refresh ${SNAPSHOT_REL}\n` +
        '  in that same commit, so the snapshot always names the version it describes. The\n' +
        '  exemption is granted to that release alone; it does not carry into the rest of the line.\n',
    ),
  );
  process.exit(EXIT_FINDINGS);
}

console.log(
  color.green(
    breaking
      ? `${symbol.pass} audit:openapi: ${String(findings.length)} breaking change(s), carried by the ` +
          `MAJOR bump from ${snapshotVersion} to ${currentVersion}`
      : `${symbol.pass} audit:openapi: 0 breaking changes against ${SNAPSHOT_REL} (${snapshotVersion})`,
  ),
);
process.exit(EXIT_OK);
