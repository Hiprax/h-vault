#!/usr/bin/env node
/**
 * `test:storage` — the storage port against the engine this stack actually ships.
 *
 * Everywhere else in the push tier, object storage is an in-memory double, which
 * is the right seam for a unit tier and has one blind spot: a double agrees with
 * whatever we believed when we wrote it. This gate starts the pinned engine in a
 * container on a loopback port and runs the SAME `StorageProvider` contract
 * against it, plus the cases that are properties of the engine rather than of the
 * port.
 *
 *   node scripts/ci/storage-gate.mjs      the gate (this is what the pipeline runs)
 *   npm run test:storage                  the same thing
 *
 * While iterating, a plain vitest invocation runs the same suite:
 *
 *   npm run test:storage -w packages/server
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. IT IS TIER 1, NOT TIER 2, AND THAT IS THE DECISION THIS FILE EXISTS TO
 *     RECORD. Its most valuable assertion is that the engine STORES a short
 *     middle part and the server is the only thing refusing one — a silent
 *     total-data-loss class, invisible to every other kind of test, and therefore
 *     one that belongs on every push rather than before a release. It costs a
 *     single 6 MiB container and a handful of API calls (measured: ~5 s end to
 *     end, of which ~1 s is the engine becoming ready), and Docker was ALREADY a
 *     push-tier prerequisite because `audit:image` is Tier 1 and declares it. A
 *     missing daemon is reported by the runner as COULD NOT RUN (exit 2), never
 *     as a failure.
 *
 *  b. THE JUNIT REPORT IS WRITTEN BUT NOT DECLARED, and here the reason is the
 *     mirror image of the one `fuzz-gate.mjs`, `resource-gate.mjs` and
 *     `recovery-gate.mjs` record. Theirs is that a Tier 2 report would be
 *     permanently unmeasured on a push. This gate does run on a push — but its
 *     tests are its OWN (the base server config excludes `tests/storage/**`), so
 *     a declared JUnit would put them in `tests.count`, and the headcount would
 *     then rise and fall with whether a Docker daemon happened to be running.
 *     `storage.json` is the declared artifact and the task carries
 *     `countsTests: false`.
 *
 *  c. A RUN THAT EXITS 0 WITHOUT WRITING ITS REPORT IS A FAILURE. That shape is
 *     real — passing `--reporter=default` on the command line silently suppresses
 *     the JUnit reporter — and a run with no evidence is indistinguishable from a
 *     run that did not happen. The report is deleted before the run so a stale
 *     file cannot stand in for it.
 *
 *  d. THE DEADLINE IS THE GATE'S OWN. The suite starts a container and waits for
 *     it by POLLING, never by sleeping, because `test:flake` runs everything ten
 *     times and a fixed sleep is either ten times too long or a race that
 *     surfaces as an unexplained failure in run seven. The harness bounds its own
 *     wait and dies with the container's log tail; this bounds the whole leg, so
 *     a daemon that accepts `docker run` and then never answers is a failure with
 *     a name rather than a hook someone eventually kills.
 */
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { TIMEOUT_EXIT, runNpm } from './lib/proc.mjs';
import { color, note, warn } from './lib/ui.mjs';
import { ensureReportDir, reportPath, writeJsonReport } from './lib/reports.mjs';

/**
 * The wall-clock deadline for the suite.
 *
 * Measured on the reference machine at ~5 s end to end: one container, one
 * mongod, 48 MiB of parts over loopback. Five minutes is far too coarse to fire
 * on a loaded machine or on the first run of a day that has to pull the image,
 * and far too tight for a container that has stopped answering to hide behind.
 */
const LEG_DEADLINE_MS = 300_000;

/** The suite's own JUnit artifact — written, read here, deliberately undeclared. */
const JUNIT_REPORT = 'junit-storage.xml';

/** The compose service whose image and configuration the harness reuses. */
const ENGINE_SERVICE = 'hvault-s3';

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

console.log(color.bold('\n  storage: the storage port against the real engine, in a container'));

// (c) Nothing from a previous run may stand in for this one.
rmSync(reportPath(JUNIT_REPORT), { force: true });

const started = Date.now();
const code = await runNpm(['run', 'test:storage', '-w', 'packages/server'], {
  // (d) On expiry `proc.mjs` SIGKILLs the npm child and resolves with
  // TIMEOUT_EXIT immediately, so a wedged grandchild is orphaned rather than
  // reaped — which leaks a process but can never leave this gate hanging on the
  // deadline meant to end it. The harness registers its own `process.on('exit')`
  // removal, so the ORDINARY failure paths still reclaim the container; a SIGKILL
  // is the one path that cannot, and it leaves a labelled container behind
  // (`docker ps --filter label=hvault-test=storage-harness`).
  timeoutMs: LEG_DEADLINE_MS,
});
const durationMs = Date.now() - started;
const timedOut = code === TIMEOUT_EXIT;
const tests = testCount(reportPath(JUNIT_REPORT));
const failed = code !== 0 || timedOut || tests === null;

if (timedOut) {
  console.error(
    color.red(
      `  ✖ the storage conformance suite exceeded the ${String(LEG_DEADLINE_MS)}ms deadline — treat this as a hang, not a slow machine`,
    ),
  );
} else if (code !== 0) {
  console.error(color.red(`  ✖ the storage conformance suite failed — exit ${String(code)}`));
} else if (tests === null) {
  console.error(
    color.red(`  ✖ the storage conformance suite exited 0 but wrote no ${JUNIT_REPORT}`),
  );
} else {
  console.log(color.green(`  ✔ ${String(tests)} tests in ${String(durationMs)}ms`));
}

writeJsonReport('storage.json', {
  version: 1,
  task: 'test:storage',
  checkedAt: new Date().toISOString(),
  durationMs,
  seed: process.env['SEED'] ?? '1337',
  deadlineMs: LEG_DEADLINE_MS,
  exitCode: code,
  timedOut,
  report: JUNIT_REPORT,
  // The engine is whatever `docker-compose.yml` pins for this service, by tag AND
  // by digest, read out of that file by the harness. Naming the service rather
  // than the image is deliberate: a second copy of the image reference here is
  // exactly the drift the single-source read exists to prevent.
  engineService: ENGINE_SERVICE,
  // What the run actually covers, so the report says what was checked against a
  // real engine rather than "storage passed".
  checks: [
    'the shared StorageProvider contract, unchanged, against the real engine — the same cases the in-memory double passes',
    'the engine STORES a short middle part, and the server refuses that same part through the real route while leaving nothing in the bucket',
    'segments at the real 8 MiB framing size read back at exactly the offsets the framing predicts, against an engine whose block size matches them',
    'an open upload carries a real initiation date, which is the only thing the garbage collector may abort on',
    'a missing bucket is named on every operation that can carry an error body, so it reads as 503 rather than as a missing file',
    'a missing key, a missing upload and an already-deleted object are told apart, and a repeat delete is not an error',
  ],
  // (b) The suite's tests are its own, but the task carries `countsTests: false`
  // so this total is reporting only: it never enters the ratchet's headcount,
  // which must not depend on whether a Docker daemon was running.
  tests,
  status: failed ? 'fail' : 'pass',
});

if (failed) {
  warn('the storage port does not behave as this application requires against the real engine');
  process.exit(1);
}

note(
  `storage.json — ${String(tests)} tests in ${String(durationMs)}ms: the port contract against the pinned engine, and the short middle part it accepts and the server refuses`,
);
