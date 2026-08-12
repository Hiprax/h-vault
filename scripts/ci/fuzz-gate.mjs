#!/usr/bin/env node
/**
 * `test:fuzz` — the untrusted-file suites, run under a wall-clock deadline.
 *
 * Two legs: the seven import parsers (client) and the backup-restore folder
 * graph (server). Both consume files a user supplies, which is the one place
 * this application turns attacker-chosen bytes into vault data.
 *
 *   node scripts/ci/fuzz-gate.mjs        the gate (this is what the pipeline runs)
 *   npm run test:fuzz                    the same thing
 *
 * A single leg, while iterating, is a plain vitest invocation:
 *
 *   npm run test:fuzz -w packages/client
 *   npm run test:fuzz -w packages/server
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. THE DEADLINE IS THE GATE'S OWN, NOT VITEST'S. "It never hangs" is one of
 *     the three clauses these suites exist to prove, and a hang is precisely the
 *     failure a test framework reports worst: a wedged parser inside a worker can
 *     take the reporter down with it, and a hook that never returns looks like a
 *     slow machine until someone kills it. So each leg is killed at
 *     `LEG_DEADLINE_MS` and that is a FAILURE, never a skip. The per-case budgets
 *     inside the suites are the fine-grained assertion; this is the backstop that
 *     still fires when the process itself is stuck.
 *
 *  b. THE JUNIT REPORTS ARE WRITTEN BUT NOT DECLARED. Each leg writes its own
 *     `junit-fuzz-<pkg>.xml`, and the manifest declares only `fuzz.json`. That is
 *     deliberate: `ratchet-check.mjs` requires every DECLARED JUnit artifact to be
 *     fresh, and `test:fuzz` is Tier 2 — it does not run during `npm run ci`. A
 *     declared-but-absent report would make `tests.count` UNMEASURED on every
 *     push, which turns a green pipeline red for a reason that has nothing to do
 *     with the code. The reports are still produced, still cleared before each
 *     run, and still read here for the per-leg test counts.
 *
 *  c. A LEG THAT EXITS 0 WITHOUT WRITING ITS REPORT IS A FAILURE. That shape is
 *     real: passing `--reporter=default` on the command line silently suppresses
 *     the JUnit reporter, and a run with no evidence is indistinguishable from a
 *     run that did not happen. The same rule `property-gate.mjs` records.
 *
 *  d. BOTH LEGS RUN, EVEN AFTER ONE FAILS. Aggregating matches the pipeline's own
 *     default, and the two legs are independent: a parser crash says nothing about
 *     the restore path, and knowing about both in one run is worth the seconds.
 */
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { TIMEOUT_EXIT, runNpm } from './lib/proc.mjs';
import { color, note, warn } from './lib/ui.mjs';
import { ensureReportDir, reportPath, writeJsonReport } from './lib/reports.mjs';

/**
 * The wall-clock deadline for one leg.
 *
 * Measured on the reference machine: the client leg is ~33 s (dominated by the
 * million-column row, seven parsers over) and the server leg ~5 s. Five minutes
 * is an order of magnitude of headroom — far too coarse to fire on a loaded
 * machine, and far too tight for a genuinely wedged parser to hide behind.
 */
const LEG_DEADLINE_MS = 300_000;

/** The legs, in the order they run. */
const LEGS = [
  {
    package: 'packages/client',
    report: 'junit-fuzz-client.xml',
    subject: 'the seven import parsers',
  },
  {
    package: 'packages/server',
    report: 'junit-fuzz-server.xml',
    subject: 'the backup-restore folder graph',
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

const legs = [];
const started = Date.now();

for (const leg of LEGS) {
  console.log(color.bold(`\n  fuzz: ${leg.package} — ${leg.subject}`));

  // (c) A stale report from an earlier run would satisfy the "did this leg write
  // its evidence?" check for a leg that wrote nothing.
  rmSync(reportPath(leg.report), { force: true });

  const legStarted = Date.now();
  const code = await runNpm(['run', 'test:fuzz', '-w', leg.package], {
    // (a) The deadline. On expiry `proc.mjs` SIGKILLs the npm child and resolves
    // with TIMEOUT_EXIT immediately, without waiting for it — a wedged
    // grandchild is orphaned rather than reaped, which leaks a process but can
    // never leave this gate itself hanging on the deadline meant to end it.
    timeoutMs: LEG_DEADLINE_MS,
  });
  const durationMs = Date.now() - legStarted;
  const tests = testCount(reportPath(leg.report));
  // The runner reports the deadline through the exit code rather than through
  // the clock: a duration comparison would call a leg that finished in 299.9 s
  // a pass and one that finished in 300.1 s a hang, which is a race with the
  // machine's load rather than a verdict about the code.
  const timedOut = code === TIMEOUT_EXIT;

  legs.push({
    package: leg.package,
    subject: leg.subject,
    report: leg.report,
    exitCode: code,
    durationMs,
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
      color.green(`  ✔ ${leg.package} — ${String(tests)} tests in ${String(durationMs)}ms`),
    );
  }
}

const failed = legs.filter((leg) => leg.status !== 'pass');
const payload = {
  version: 1,
  task: 'test:fuzz',
  checkedAt: new Date().toISOString(),
  durationMs: Date.now() - started,
  seed: process.env['SEED'] ?? '1337',
  deadlineMs: LEG_DEADLINE_MS,
  // Every fuzz file also runs inside `test:unit` / `test:integration`, and the
  // task carries `countsTests: false` in the manifest, so this total is
  // reporting only — it never enters the ratchet's headcount.
  totalLegTests: legs.reduce((sum, leg) => sum + (leg.tests ?? 0), 0),
  crashes: failed.length,
  hangs: legs.filter((leg) => leg.timedOut).length,
  legs,
};
writeJsonReport('fuzz.json', payload);

if (failed.length > 0) {
  warn(`${String(failed.length)} of ${String(legs.length)} fuzz legs failed`);
  for (const leg of failed) {
    console.error(
      color.red(
        `      ${leg.package} — exit ${String(leg.exitCode)}${leg.timedOut ? ' (deadline exceeded)' : ''}`,
      ),
    );
  }
  process.exit(1);
}

note(
  `fuzz.json — ${String(legs.length)} legs, ${String(payload.totalLegTests)} leg-tests, 0 crashes, 0 hangs, seed ${payload.seed}`,
);
