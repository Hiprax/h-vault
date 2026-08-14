#!/usr/bin/env node
/**
 * `test:recovery` — the two disasters this application is built to survive.
 *
 * Graceful shutdown is the case that works, and it already has a suite. These
 * are the cases that do not:
 *
 *   RESTORE  a backup file leaves one database and arrives in another, on a
 *            SECOND mongod, into an account that has never seen it. Every item
 *            must decrypt to the bytes that were sealed and stay paired with its
 *            own name, and the document this server emits must survive the round
 *            trip the browser's signature is computed over — because the
 *            signature can only ever verify while it does. (The shipped verifier
 *            itself lives in the client package and is covered by its own suite;
 *            this leg proves the bytes it is given are signable.)
 *
 *   CRASH    a real server process, killed by SIGKILL mid-write at six points
 *            around the rotation write-fence and the import's write boundary, on
 *            both topologies. The stored vault key must always still be the OLD
 *            one, the fence must survive the crash, a login must clear it only
 *            when the dead rotation's lock is genuinely gone, the interrupted
 *            rotation must complete on retry, and no crash may leave a partial
 *            insert.
 *
 *   node scripts/ci/recovery-gate.mjs     the gate (this is what the pipeline runs)
 *   npm run test:recovery                 the same thing
 *
 * While iterating, a plain vitest invocation runs the same suite:
 *
 *   npm run test:recovery -w packages/server
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. THE DEADLINE IS THE GATE'S OWN, AND IT IS A FAILURE RATHER THAN A SKIP.
 *     The crash half spawns a real child process per case and expects it to die;
 *     the ways that go wrong are a child that never reaches its injection point
 *     and a mongod holding locks for an abandoned transaction. Both present as a
 *     HANG rather than as a red assertion, and a gate that can hang is a gate
 *     someone eventually disables. `crashProbe.ts` bounds each child at 30 s and
 *     this bounds the whole leg; anything past it is reported as a hang.
 *
 *  b. THE JUNIT REPORT IS WRITTEN BUT NOT DECLARED. The suite writes
 *     `junit-recovery.xml` and it is read here for the test count; the manifest
 *     declares only `recovery.json`. `ratchet-check.mjs` requires every DECLARED
 *     JUnit artifact to be fresh, and this gate is Tier 2 — it does not run
 *     during `npm run ci` — so declaring it would make `tests.count` UNMEASURED
 *     on every push. The same rule `fuzz-gate.mjs`, `resource-gate.mjs` and
 *     `upgrade-gate.mjs` record.
 *
 *  c. A RUN THAT EXITS 0 WITHOUT WRITING ITS REPORT IS A FAILURE. That shape is
 *     real: passing `--reporter=default` on the command line silently suppresses
 *     the JUnit reporter, and a run with no evidence is indistinguishable from a
 *     run that did not happen. The report is deleted before the run so a stale
 *     file cannot stand in for it.
 *
 *  d. IT IS ONE LEG, NOT TWO. Everything under test here is server-side: the
 *     backup collector, the restore executor, the rotation fence, the import
 *     transaction. The client's own crypto is exercised by its own suite and by
 *     the client leg of `test:upgrade`; the format is stated independently in
 *     `tests/recovery/vaultFormat.ts`, which explains why a server test cannot
 *     simply import `cryptoService.ts` (it is typed against the DOM lib, and
 *     this package compiles with `lib: ["ES2022"]`).
 */
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { TIMEOUT_EXIT, runNpm } from './lib/proc.mjs';
import { color, note, warn } from './lib/ui.mjs';
import { ensureReportDir, reportPath, writeJsonReport } from './lib/reports.mjs';

/**
 * The wall-clock deadline for the suite.
 *
 * Measured on the reference machine at ~10 s end to end: two mongod instances,
 * a single-node replica set, three 600,000-iteration key derivations and six
 * child processes that each import the server and then die. Five minutes is far
 * too coarse to fire on a loaded machine and far too tight for a probe that has
 * started waiting on a lock it will never get.
 */
const LEG_DEADLINE_MS = 300_000;

/** The suite's own JUnit artifact — written, read here, deliberately undeclared. */
const JUNIT_REPORT = 'junit-recovery.xml';

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

console.log(
  color.bold(
    '\n  recovery: a backup restored onto another database, and a process killed mid-write',
  ),
);

// (c) Nothing from a previous run may stand in for this one.
rmSync(reportPath(JUNIT_REPORT), { force: true });

const started = Date.now();
const code = await runNpm(['run', 'test:recovery', '-w', 'packages/server'], {
  // (a) On expiry `proc.mjs` SIGKILLs the npm child and resolves with
  // TIMEOUT_EXIT immediately, so a wedged grandchild is orphaned rather than
  // reaped — which leaks a process but can never leave this gate hanging on the
  // deadline meant to end it.
  timeoutMs: LEG_DEADLINE_MS,
});
const durationMs = Date.now() - started;
const timedOut = code === TIMEOUT_EXIT;
const tests = testCount(reportPath(JUNIT_REPORT));
const failed = code !== 0 || timedOut || tests === null;

if (timedOut) {
  console.error(
    color.red(
      `  ✖ the recovery suite exceeded the ${String(LEG_DEADLINE_MS)}ms deadline — treat this as a hang, not a slow machine`,
    ),
  );
} else if (code !== 0) {
  console.error(color.red(`  ✖ the recovery suite failed — exit ${String(code)}`));
} else if (tests === null) {
  console.error(color.red(`  ✖ the recovery suite exited 0 but wrote no ${JUNIT_REPORT}`));
} else {
  console.log(color.green(`  ✔ ${String(tests)} tests in ${String(durationMs)}ms`));
}

writeJsonReport('recovery.json', {
  version: 1,
  task: 'test:recovery',
  checkedAt: new Date().toISOString(),
  durationMs,
  seed: process.env['SEED'] ?? '1337',
  deadlineMs: LEG_DEADLINE_MS,
  exitCode: code,
  timedOut,
  report: JUNIT_REPORT,
  // What the run actually covers, so the report says which disasters were
  // rehearsed rather than "recovery passed".
  drills: [
    'a downloaded backup restored into an empty account on a SECOND mongod, every item byte-identical and still paired with its own name',
    'the downloaded document surviving the round trip its signature is computed over, and an altered one failing that signature',
    'a backup opening for nobody without its backup password',
    'a crash between the write-fence commit and the vault-key update, at both ends of that window and on both topologies',
    'login recovery firing only once the dead rotation’s lock has expired, and the interrupted rotation completing on retry',
    'a crash before, inside and after the import write, and while holding the per-user lock',
  ],
  // Both files also run inside `test:integration`, and the task carries
  // `countsTests: false` in the manifest, so this total is reporting only — it
  // never enters the ratchet's headcount.
  tests,
  status: failed ? 'fail' : 'pass',
});

if (failed) {
  warn('this application did not survive one of the disasters it is built to survive');
  process.exit(1);
}

note(
  `recovery.json — ${String(tests)} tests in ${String(durationMs)}ms: a backup restored across two mongod instances byte for byte, and five crash points that left no partial write behind`,
);
