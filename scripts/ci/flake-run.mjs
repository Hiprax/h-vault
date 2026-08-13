#!/usr/bin/env node
/**
 * `test:flake` — the same suite, ten times, in ten different orders.
 *
 *   node scripts/ci/flake-run.mjs        the gate (this is what verify:full runs)
 *   npm run test:flake                   the same thing
 *
 * Dev flags, for iterating. Both REFUSE to write `flake.json`, because a
 * shortened sample recorded as the gate's evidence is exactly the lie this gate
 * exists to make impossible:
 *
 *   node scripts/ci/flake-run.mjs --runs=2 --no-report
 *   node scripts/ci/flake-run.mjs --only=e2e --no-report
 *
 * ---------------------------------------------------------------------------
 * WHAT TEN CLEAN RUNS PROVE, AND WHAT THEY DO NOT
 * ---------------------------------------------------------------------------
 *
 * They bound the per-run flake rate. Ten independent runs with no failure put
 * the 95% upper bound on the per-run failure probability at roughly 26% by the
 * rule of three (3/n), and the point ESTIMATE at 0 — which is a bound of about
 * one in ten before you get to any confidence level at all. They do NOT
 * establish that the rate is zero, and no finite number of runs can. This gate
 * therefore RECORDS the number of runs and the number of failures and ratchets
 * both — `flake.runs` upward so the sample can never quietly shrink, and
 * `flake.failures` downward so a failure can never quietly be normalised. It
 * does not claim a property it has not measured.
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. EVERY RUN GETS A DIFFERENT ORDER SEED, AND THE SAME DATA SEED. Ten runs at
 *     one seed is one run repeated ten times: the suites already shuffle, so a
 *     fixed seed means a fixed ORDER, and the risk this gate owns (R2 — "the
 *     suite's verdict depends on ordering") would go entirely unmeasured. The
 *     order seed is therefore `SEED + i`, passed as `--sequence.seed`, which
 *     overrides the config (measured; an `outputFile` inside a configured
 *     reporter tuple, by contrast, does NOT — which is why the JUnit redirect
 *     needed a config file).
 *
 *     The DATA seed stays at `SEED` for every run, and that is the other half of
 *     the decision. Varying it too would change what the property and fuzz
 *     suites generate, so a red run could be an order dependence or an input
 *     nobody had drawn before — two different bug reports, indistinguishable in
 *     the report. Generating fresh inputs is `test:property` and `test:fuzz`'s
 *     job; this gate holds the inputs still and moves the order.
 *
 *     Both are derived from the one pinned `SEED`, so the ten-run SEQUENCE is
 *     itself reproducible and every failure names an order you can replay.
 *
 *  b. PARALLELISM IS INHERITED, NEVER REDUCED. No `--no-file-parallelism`, no
 *     pool override, no worker cap: each package's flake config spreads its base
 *     config untouched. Pinning the suite to one worker is how shared state gets
 *     hidden rather than found (Forbidden Action 7), and it would make this gate
 *     measure the opposite of what it claims.
 *
 *  c. EVERY RUN COMPLETES, EVEN AFTER ONE FAILS. Stopping at the first red would
 *     turn a RATE into a yes/no, and one-in-ten and nine-in-ten are wildly
 *     different bug reports that would look identical. The same reasoning covers
 *     the three package legs inside one run: a client failure says nothing about
 *     the server, and both are worth knowing in one pass.
 *
 *  d. A FAILING RUN IS NAMED, NOT COUNTED. The gate parses each leg's JUnit
 *     immediately after the leg finishes — before the next run overwrites it —
 *     and records the failing test names alongside the order seed that produced
 *     them. "Run 7 failed" is not a bug report; "run 7, order seed 1343,
 *     packages/server, `acquireJobLock` holds under contention" is.
 *
 *  e. THE JUNIT REPORTS ARE WRITTEN BUT NOT DECLARED. `flake.json` is the only
 *     report the manifest names. `ratchet-check.mjs` requires every DECLARED
 *     JUnit artifact to be FRESH, and this is a Tier 2 gate that does not run on
 *     a push — a declared-but-stale report would make `tests.count` UNMEASURED
 *     on every push, turning the pipeline red for a reason unrelated to the
 *     code. The same rule shaped `test:fuzz`, `test:resource`, `test:upgrade`
 *     and `test:recovery`.
 *
 *  f. A HANG IS A FAILURE. Every leg carries a wall-clock deadline, because the
 *     failure mode a repeated run is most likely to expose — a race that
 *     deadlocks rather than asserts — produces no exit code at all. On expiry
 *     `proc.mjs` SIGKILLs the child and returns TIMEOUT_EXIT, and this gate
 *     counts that as a failed run, never as a skip.
 */
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { TIMEOUT_EXIT, runNpm } from './lib/proc.mjs';
import { color, note, warn } from './lib/ui.mjs';
import { ensureReportDir, reportPath, writeJsonReport } from './lib/reports.mjs';

/** The sample size. Ten is what §1.7 of the plan records as the gate. */
const DEFAULT_RUNS = 10;

/**
 * The wall-clock deadline for ONE package leg of ONE run.
 *
 * Measured on the reference machine: shared 2.8 s, client 103 s, server 132 s
 * with coverage off — so thirty minutes is roughly thirteen times the slowest
 * healthy leg. That looks absurdly generous and it is not, because the first
 * draft set it at five times and was nearly wrong.
 *
 * WHAT THE FIRST DRAFT MEASURED, recorded because the number is otherwise
 * unjustifiable: with 1.2 GB of orphaned `mongodb-memory-server` dbPaths left in
 * RAM-backed `/tmp` by earlier INTERRUPTED runs, the server leg took 780 s — a
 * six-fold degradation, against a 900 s deadline. Clearing them restored 132 s
 * immediately. A normally-terminating run strands nothing (`mongoServer.stop()`
 * removes its own dbPath), so this is an operator condition rather than a defect
 * in the suite; but this gate is precisely the one that runs the suite ten times
 * in a row, so it is the one most likely to meet a machine in that state, and a
 * gate that reports a HANG because /tmp is full is a gate someone deletes.
 *
 * If you interrupt this gate, `rm -rf /tmp/mongo-mem-*` before running it again.
 */
const LEG_DEADLINE_MS = 1_800_000;

/**
 * Executions per test in the end-to-end leg.
 *
 * MIRRORS `FLAKE_REPEAT_EACH` in `playwright.flake.config.ts`, which is where
 * the value is actually applied; `gate-surface.test.ts` asserts the two agree.
 * Restated rather than imported because this is a `.mjs` runner and that is a
 * TypeScript module — an `await import` of it fails at run time, which would
 * turn the gate's own report into the thing that broke it.
 */
const E2E_REPEAT_EACH = 3;

/**
 * The wall-clock deadline for the end-to-end leg.
 *
 * That leg is the whole Playwright suite at `repeatEach: 3`, and that suite runs
 * single-worker (a constraint its config records and ledgers), so it is three
 * sequential passes of a six-minute suite. Ninety minutes is roughly four times
 * the measured cost; it is a backstop against a browser or a dev server that
 * never comes back, not a performance budget.
 */
const E2E_DEADLINE_MS = 5_400_000;

/** The packages whose suites make up one run, in the order they execute. */
const PACKAGES = ['shared', 'client', 'server'];

const args = process.argv.slice(2);
const flag = (name) => args.includes(`--${name}`);
const value = (name) => {
  const found = args.find((arg) => arg.startsWith(`--${name}=`));
  return found ? found.slice(name.length + 3) : '';
};

const runsRequested = value('runs') ? Number(value('runs')) : DEFAULT_RUNS;
if (!Number.isInteger(runsRequested) || runsRequested < 1) {
  console.error(color.red(`flake: --runs must be a positive integer; received "${value('runs')}"`));
  process.exit(2);
}
const only = value('only');
if (only && only !== 'unit' && only !== 'e2e') {
  console.error(color.red(`flake: --only must be "unit" or "e2e"; received "${only}"`));
  process.exit(2);
}

/**
 * A shortened or partial invocation must not leave an artifact behind that a
 * later reader would take for the gate's evidence. `--no-report` makes that
 * explicit; using a dev flag without it is refused rather than silently honoured.
 */
const partial = runsRequested !== DEFAULT_RUNS || only !== '';
if (partial && !flag('no-report')) {
  console.error(
    color.red(
      'flake: --runs/--only shorten the sample, so they require --no-report. ' +
        'A partial run recorded as flake.json is a smaller sample wearing the full one’s name.',
    ),
  );
  process.exit(2);
}
const writeReport = !flag('no-report');

/** The pinned DATA seed. The ORDER seed is derived from it, per run — see (a). */
const dataSeed = Number(process.env['SEED'] ?? 1337);
if (!Number.isInteger(dataSeed) || dataSeed < 0) {
  console.error(color.red(`flake: SEED must be a non-negative integer; received "${dataSeed}"`));
  process.exit(2);
}

/**
 * Reads a JUnit document for what this gate reports: how many tests ran, how
 * many failed, and WHICH ones (decision d).
 *
 * Returns `null` when the file is absent, which the caller treats as a failed
 * leg rather than as zero failures — a run that wrote no evidence did not
 * demonstrably happen, the same rule `property-gate.mjs` records.
 */
function readJunit(file) {
  if (!existsSync(file)) return null;
  const xml = readFileSync(file, 'utf8');

  const attr = (source, name) => {
    const found = new RegExp(`\\b${name}="(\\d+)"`).exec(source);
    return found ? Number(found[1]) : 0;
  };

  const outer = /<testsuites[^>]*>/.exec(xml);
  const suites = [...xml.matchAll(/<testsuite[^>]*>/g)].map((match) => match[0]);
  const sum = (name) => suites.reduce((total, suite) => total + attr(suite, name), 0);

  const tests = outer ? attr(outer[0], 'tests') : sum('tests');
  const failures = outer ? attr(outer[0], 'failures') : sum('failures');
  const errors = outer ? attr(outer[0], 'errors') : sum('errors');

  // The failing testcases by name. A `<testcase>` carrying a `<failure>` or an
  // `<error>` child is the only shape either runner emits for a red test, and a
  // self-closing `<testcase … />` is by construction not one.
  const failed = [];
  for (const match of xml.matchAll(/<testcase\b([^>]*)>([\s\S]*?)<\/testcase>/g)) {
    if (!/<(failure|error)\b/.test(match[2])) continue;
    const name = /\bname="([^"]*)"/.exec(match[1])?.[1] ?? '(unnamed)';
    const suite = /\bclassname="([^"]*)"/.exec(match[1])?.[1] ?? '';
    failed.push(suite ? `${suite} › ${name}` : name);
  }

  return { tests, failures: failures + errors, failed };
}

/**
 * The order seed for run `index`.
 *
 * Derived from the one pinned data seed so the whole sequence is reproducible,
 * and DISTINCT per run so ten runs are ten samples — see (a). Extracted into a
 * named function rather than inlined because the pre-flight below has to be able
 * to check it, and because collapsing it to a constant is the single edit that
 * would turn this gate into one run repeated ten times while every message it
 * prints stayed true.
 */
const orderSeedFor = (index) => dataSeed + index;

/**
 * PRE-FLIGHT: ten runs must be ten ORDERS.
 *
 * This costs milliseconds and it guards the gate's whole premise. The suites
 * already shuffle on every push, with `sequence.seed` pinned — so a run at a
 * fixed seed is a run in a FIXED order, and a flake gate that used one seed for
 * all ten runs would execute the identical order ten times and report the result
 * as a measurement of order independence. Nothing downstream could tell:
 * `flake.json` would still say ten runs, zero failures, and `flake.runs` would
 * still ratchet.
 *
 * Checked before the first suite starts rather than after the last, because the
 * alternative is discovering it an hour later.
 */
const plannedSeeds = Array.from({ length: runsRequested }, (_, index) => orderSeedFor(index));
if (new Set(plannedSeeds).size !== plannedSeeds.length) {
  console.error(
    color.red(
      `flake: the ${String(runsRequested)} planned runs do not use ${String(runsRequested)} distinct order seeds ` +
        `(${plannedSeeds.join(', ')}). Ten runs in ONE order is one run repeated ten times: ` +
        'the suites shuffle from `sequence.seed`, so a fixed seed is a fixed order, and this gate ' +
        'would then measure nothing it claims to measure.',
    ),
  );
  process.exit(1);
}

ensureReportDir();

const started = Date.now();
/** One entry per package leg of every run. */
const legs = [];
/** One entry per complete run. */
const runs = [];

if (only !== 'e2e') {
  for (let index = 0; index < runsRequested; index += 1) {
    // (a) A DIFFERENT order, derived from the one pinned seed. Distinctness is
    // checked in the pre-flight above, before any suite runs.
    const orderSeed = orderSeedFor(index);
    console.log(
      color.bold(
        `\n  flake run ${String(index + 1)}/${String(runsRequested)} — order seed ${String(orderSeed)}, data seed ${String(dataSeed)}`,
      ),
    );

    const runLegs = [];
    for (const pkg of PACKAGES) {
      const report = `junit-flake-${pkg}.xml`;
      // (d) The previous run's document would otherwise be parsed as this one's.
      rmSync(reportPath(report), { force: true });

      const legStarted = Date.now();
      const code = await runNpm(
        [
          'run',
          'test:flake',
          '-w',
          `packages/${pkg}`,
          '--',
          `--sequence.seed=${String(orderSeed)}`,
        ],
        { timeoutMs: LEG_DEADLINE_MS },
      );
      const durationMs = Date.now() - legStarted;
      const timedOut = code === TIMEOUT_EXIT;
      const junit = readJunit(reportPath(report));

      const leg = {
        run: index + 1,
        orderSeed,
        package: `packages/${pkg}`,
        exitCode: code,
        durationMs,
        timedOut,
        tests: junit?.tests ?? null,
        failedTests: junit?.failed ?? [],
        // A leg that exits 0 without evidence is a failure, not a pass: that is
        // what a suppressed reporter looks like from the outside.
        status: code === 0 && !timedOut && junit !== null ? 'pass' : 'fail',
      };
      runLegs.push(leg);
      legs.push(leg);

      if (timedOut) {
        console.error(
          color.red(
            `  ✖ packages/${pkg} exceeded the ${String(LEG_DEADLINE_MS)}ms deadline — a hang, not a slow machine`,
          ),
        );
      } else if (leg.status === 'fail') {
        console.error(
          color.red(
            `  ✖ packages/${pkg} failed — exit ${String(code)}${junit === null ? ', and wrote no JUnit report' : ''}`,
          ),
        );
        for (const name of leg.failedTests.slice(0, 10)) {
          console.error(color.red(`      ${name}`));
        }
      } else {
        console.log(
          color.green(
            `  ✔ packages/${pkg} — ${String(leg.tests)} tests in ${String(durationMs)}ms`,
          ),
        );
      }
    }

    const failedLegs = runLegs.filter((leg) => leg.status !== 'pass');
    runs.push({
      run: index + 1,
      orderSeed,
      durationMs: runLegs.reduce((total, leg) => total + leg.durationMs, 0),
      status: failedLegs.length === 0 ? 'pass' : 'fail',
      failedPackages: failedLegs.map((leg) => leg.package),
    });
  }
}

/** The end-to-end leg: the whole Playwright suite, three executions per test. */
let e2e = null;
if (only !== 'unit') {
  console.log(color.bold(`\n  flake e2e — the Playwright suite, 3 executions per test, retries 0`));
  const report = 'junit-flake-e2e.xml';
  rmSync(reportPath(report), { force: true });

  const legStarted = Date.now();
  const code = await runNpm(['run', 'test:flake:e2e'], { timeoutMs: E2E_DEADLINE_MS });
  const durationMs = Date.now() - legStarted;
  const timedOut = code === TIMEOUT_EXIT;
  const junit = readJunit(reportPath(report));

  e2e = {
    repeatEach: E2E_REPEAT_EACH,
    exitCode: code,
    durationMs,
    timedOut,
    executions: junit?.tests ?? null,
    failedTests: junit?.failed ?? [],
    status: code === 0 && !timedOut && junit !== null ? 'pass' : 'fail',
  };

  if (e2e.status === 'pass') {
    console.log(
      color.green(`  ✔ e2e — ${String(e2e.executions)} executions in ${String(durationMs)}ms`),
    );
  } else {
    console.error(
      color.red(
        `  ✖ e2e failed — exit ${String(code)}${timedOut ? ' (deadline exceeded)' : ''}${junit === null ? ', and wrote no JUnit report' : ''}`,
      ),
    );
    for (const name of e2e.failedTests.slice(0, 20)) console.error(color.red(`      ${name}`));
  }
}

/**
 * `failures` spans BOTH halves, and it has to: a gate whose headline number
 * counted only the unit runs could report zero while the end-to-end leg was red,
 * which is the half the pipeline's former committed retry count used to conceal.
 * One failed run counts once,
 * however many of its three package legs failed; the end-to-end leg counts once.
 */
const failedRuns = runs.filter((run) => run.status !== 'pass').length;
const failures = failedRuns + (e2e && e2e.status !== 'pass' ? 1 : 0);

const payloadE2eExecutions = e2e?.executions ?? 0;

const payload = {
  version: 1,
  task: 'test:flake',
  checkedAt: new Date().toISOString(),
  durationMs: Date.now() - started,
  // The two seeds, named separately, because conflating them is how a report
  // starts describing a run that did not happen — see (a).
  dataSeed,
  orderSeeds: runs.map((run) => run.orderSeed),
  runs: runs.length,
  failures,
  failedRuns,
  // The SIZE of the end-to-end sample, recorded and ratcheted separately.
  // Without it, deleting the e2e half entirely would LOWER `failures` (an
  // apparent improvement), leave `runs` at ten, and pass — the half that a
  // committed retry count used to conceal, removed by a different route.
  e2eExecutions: e2e?.executions ?? 0,
  // What the number above does and does not license anyone to say, stated IN the
  // artifact so a reader of `flake.json` alone cannot overstate it.
  // `failures` spans BOTH halves while `runs` counts only the shuffled full-suite
  // runs, so the sentence names each separately rather than implying one sample.
  bound:
    runs.length > 0
      ? `${String(failedRuns)} failing run(s) in ${String(runs.length)} shuffled parallel run(s), plus ${String(failures - failedRuns)} failing end-to-end leg(s) over ${String(payloadE2eExecutions)} executions. With 0 failures this bounds the per-run flake rate near 1-in-${String(runs.length)} (95% upper bound ~${(300 / runs.length).toFixed(0)}% by the rule of three). It does not establish zero, and no finite number of runs can.`
      : 'no full-suite runs were performed',
  e2e,
  perRun: runs,
  legs,
};

if (writeReport) writeJsonReport('flake.json', payload);
else note('flake.json NOT written — this was a partial run (--no-report)');

if (failures > 0) {
  warn(`${String(failures)} failing execution(s) across ${String(runs.length)} run(s) plus e2e`);
  for (const run of runs.filter((entry) => entry.status !== 'pass')) {
    console.error(
      color.red(
        `      run ${String(run.run)} (order seed ${String(run.orderSeed)}) — ${run.failedPackages.join(', ')}`,
      ),
    );
  }
  console.error(
    color.red(
      '      A flake is a bug report about the code or the harness. Fix it at its cause, ' +
        'or quarantine it in its own task with a dated, expiring ledger entry. Never retry it away.',
    ),
  );
  process.exit(1);
}

note(
  `flake.json — ${String(runs.length)} shuffled runs, ${String(legs.length)} package legs` +
    `${e2e ? `, ${String(e2e.executions ?? 0)} e2e executions` : ''}, 0 failures, data seed ${String(dataSeed)}`,
);
