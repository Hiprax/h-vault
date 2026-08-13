#!/usr/bin/env node
/**
 * `test:upgrade` — the previous release's data and configuration, read by this one.
 *
 * Eight minor releases of encrypted user data have shipped with nothing checking
 * that an upgrade can still read what the release before it wrote. Two halves,
 * both against release 0.7.0:
 *
 *   DATA    a vault generated inside a detached worktree at the v0.7.0 tag, by
 *           that release's own crypto and validated by its own schemas. The
 *           SERVER leg re-validates it against the current schemas and reads it
 *           back through the current models and routes; the CLIENT leg opens the
 *           same frozen ciphertext with the crypto this release actually ships,
 *           which is the gate's headline claim and which a server test cannot
 *           make, because `cryptoService.ts` lives in the client package.
 *
 *   CONFIG  that release's `.env`, loading the current server's environment
 *           configuration in a real child process at a temporary repository
 *           root, with the variables since removed proved inert and every
 *           required one proved to fail by name.
 *
 *   node scripts/ci/upgrade-gate.mjs     the gate (this is what the pipeline runs)
 *   npm run test:upgrade                 the same thing
 *
 * While iterating, a plain vitest invocation runs the same suite:
 *
 *   npm run test:upgrade -w packages/server
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. THE DEADLINE IS THE GATE'S OWN. The configuration half spawns a real
 *     process per case, and "an operator sees a reason rather than a restart
 *     loop" is one of the things it asserts — so a boot that WAITS on something
 *     is a failure this gate has to be able to report. Each probe carries its
 *     own 10-second budget; this is the backstop for the case where the runner
 *     itself is stuck, and it is a FAILURE, never a skip.
 *
 *  b. THE JUNIT REPORTS ARE WRITTEN BUT NOT DECLARED. Each leg writes its own
 *     (`junit-upgrade.xml`, `junit-upgrade-client.xml`) and both are read here
 *     for the test counts; the manifest declares only `upgrade.json`. `ratchet-check.mjs` requires every DECLARED JUnit artifact
 *     to be fresh, and this gate is Tier 2 — it does not run during
 *     `npm run ci` — so declaring it would make `tests.count` UNMEASURED on every
 *     push. The same rule `fuzz-gate.mjs` and `resource-gate.mjs` record.
 *
 *  c. A RUN THAT EXITS 0 WITHOUT WRITING ITS REPORT IS A FAILURE. That shape is
 *     real: passing `--reporter=default` on the command line silently suppresses
 *     the JUnit reporter, and a run with no evidence is indistinguishable from a
 *     run that did not happen. The report is deleted before the run so a stale
 *     file cannot stand in for it.
 *
 *  d. THE FIXTURES ARE CHECKED FOR PROVENANCE HERE, NOT ONLY IN THE SUITE. Both
 *     fixtures are goldens, and a golden with no provenance note is an assertion
 *     nobody can check. The suite asserts the fields; this asserts the files are
 *     present and non-trivial before the suite runs, so a deleted fixture reports
 *     itself rather than surfacing as a confusing module-load error.
 */
import { existsSync, readFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { TIMEOUT_EXIT, repoRoot, runNpm } from './lib/proc.mjs';
import { color, note, warn } from './lib/ui.mjs';
import { ensureReportDir, reportPath, writeJsonReport } from './lib/reports.mjs';

/**
 * The wall-clock deadline for the suite.
 *
 * Measured on the reference machine at ~9 s end to end: twelve child-process
 * boots at ~0.4 s each plus one 600,000-iteration key derivation. Five minutes
 * is far too coarse to fire on a loaded machine and far too tight for a
 * genuinely wedged boot to hide behind.
 */
const LEG_DEADLINE_MS = 300_000;

/**
 * The committed N-1 artefacts. Each is a golden: recorded from the previous
 * release, never regenerated from the current tree.
 */
const FIXTURES = [
  {
    file: 'packages/server/tests/fixtures/v0.7.0-vault.json',
    subject: "a vault as release 0.7.0 persisted it, sealed by that release's own crypto",
  },
  {
    file: 'packages/server/tests/fixtures/v0.7.0.env',
    subject: 'the configuration template release 0.7.0 shipped',
  },
];

/**
 * The legs, in the order they run. The server leg first, because a fixture that
 * no longer parses is a more fundamental failure than one that no longer
 * decrypts, and reading that first makes a combined failure easier to read.
 */
const LEGS = [
  {
    package: 'packages/server',
    report: 'junit-upgrade.xml',
    subject: "the previous release's documents, schemas, models, routes and .env",
  },
  {
    package: 'packages/client',
    report: 'junit-upgrade-client.xml',
    subject: "the previous release's ciphertext, opened by the crypto this one ships",
  },
];

/** The `tests="N"` attribute of a JUnit document, or null when it cannot be read. */
function testCount(file) {
  if (!existsSync(file)) return null;
  const xml = readFileSync(file, 'utf8');
  const outer = /<testsuites[^>]*\btests="(\d+)"/.exec(xml);
  if (outer) return Number(outer[1]);
  const suites = [...xml.matchAll(/<testsuite[^>]*\btests="(\d+)"/g)].map((m) => Number(m[1]));
  return suites.length > 0 ? suites.reduce((a, b) => a + b, 0) : null;
}

ensureReportDir();

const problems = [];

// (d) Before anything runs: the goldens are on disk and they say where they came
// from. A fixture that lost its provenance block is a fixture nobody can trust.
for (const fixture of FIXTURES) {
  const full = path.join(repoRoot, fixture.file);
  if (!existsSync(full)) {
    problems.push(`${fixture.file} is missing — ${fixture.subject}`);
    continue;
  }
  const text = readFileSync(full, 'utf8');
  if (!text.includes('v0.7.0')) {
    problems.push(`${fixture.file} no longer names the tag it was generated from`);
  }
}

const started = Date.now();
const legs = [];

for (const leg of LEGS) {
  console.log(color.bold(`\n  upgrade: ${leg.package} — ${leg.subject}`));

  // (c) Nothing from a previous run may stand in for this one.
  rmSync(reportPath(leg.report), { force: true });

  const legStarted = Date.now();
  const code = await runNpm(['run', 'test:upgrade', '-w', leg.package], {
    // (a) On expiry `proc.mjs` SIGKILLs the npm child and resolves with
    // TIMEOUT_EXIT immediately, so a wedged grandchild is orphaned rather than
    // reaped — which leaks a process but can never leave this gate hanging on
    // the deadline meant to end it.
    timeoutMs: LEG_DEADLINE_MS,
  });
  const legDuration = Date.now() - legStarted;
  const timedOut = code === TIMEOUT_EXIT;
  const tests = testCount(reportPath(leg.report));

  legs.push({
    package: leg.package,
    subject: leg.subject,
    report: leg.report,
    exitCode: code,
    durationMs: legDuration,
    timedOut,
    tests,
    status: code === 0 && tests !== null && !timedOut ? 'pass' : 'fail',
  });

  if (timedOut) {
    console.error(
      color.red(
        `  ✖ ${leg.package} exceeded the ${String(LEG_DEADLINE_MS)}ms deadline — treat this as a hang, not a slow machine`,
      ),
    );
  } else if (code !== 0) {
    console.error(color.red(`  ✖ ${leg.package} failed — exit ${String(code)}`));
  } else if (tests === null) {
    console.error(color.red(`  ✖ ${leg.package} exited 0 but wrote no ${leg.report}`));
  } else {
    console.log(
      color.green(`  ✔ ${leg.package} — ${String(tests)} tests in ${String(legDuration)}ms`),
    );
  }
}

const durationMs = Date.now() - started;
for (const problem of problems) console.error(color.red(`      ${problem}`));

// (d) BOTH LEGS RUN, EVEN AFTER ONE FAILS. They are independent — a schema that
// stopped accepting an old document says nothing about whether the ciphertext
// still opens — and knowing about both in one run is worth the seconds.
const failedLegs = legs.filter((leg) => leg.status !== 'pass');
const failed = failedLegs.length > 0 || problems.length > 0;
const tests = legs.reduce((sum, leg) => sum + (leg.tests ?? 0), 0);

writeJsonReport('upgrade.json', {
  version: 1,
  task: 'test:upgrade',
  checkedAt: new Date().toISOString(),
  durationMs,
  seed: process.env['SEED'] ?? '1337',
  deadlineMs: LEG_DEADLINE_MS,
  // The previous release this gate compares against. Recorded so the report
  // says which upgrade was actually exercised rather than "an upgrade".
  previousRelease: 'v0.7.0',
  fixtures: FIXTURES,
  legs,
  // Every file in both legs also runs inside `test:integration` / `test:unit`,
  // and the task carries `countsTests: false` in the manifest, so this total is
  // reporting only — it never enters the ratchet's headcount.
  tests,
  problems,
  status: failed ? 'fail' : 'pass',
});

if (failed) {
  warn('the previous release’s data or configuration is no longer readable by this one');
  process.exit(1);
}

note(
  `upgrade.json — v0.7.0 → HEAD, ${String(legs.length)} legs, ${String(tests)} tests in ${String(durationMs)}ms, the previous release's vault, ciphertext and .env all still readable`,
);
