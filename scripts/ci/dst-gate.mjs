#!/usr/bin/env node
/**
 * `test:dst` — the whole suite, once, in a timezone that observes DST.
 *
 *   node scripts/ci/dst-gate.mjs        the gate (this is what verify:full runs)
 *   npm run test:dst                    the same thing
 *
 * A single package's leg, while iterating:
 *
 *   HVAULT_TZ=America/New_York npm run test:flake -w packages/client
 *
 * ---------------------------------------------------------------------------
 * WHY IT EXISTS WHEN `test:property` ALREADY RUNS TWO ZONES
 * ---------------------------------------------------------------------------
 *
 * The property gate runs the three PROPERTY suites in `America/New_York`,
 * because `combineExpiry`'s repeated-hour branch is structurally unreachable in
 * a zone with no transition. That is the narrow claim, and it is the only one
 * anything checked: `vitest.property.config.ts` includes `tests/property/**` and
 * nothing else, so ~7,400 of this repository's ~7,600 tests had never been
 * executed anywhere but UTC.
 *
 * That gap is not hypothetical. Everything this application renders about time
 * is computed in local time by design — a secret's expiry countdown, the
 * vault-health "last checked" label, `combineExpiry`'s two local-time controls,
 * `formatDate` — and an assertion written against a UTC machine that happens to
 * agree with local time is indistinguishable from one that is correct. This gate
 * runs the whole suite, once, where those two disagree by four or five hours and
 * change by an hour twice a year.
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. IT NARROWS NOTHING. Every leg runs the package's flake config, which
 *     spreads the base config untouched — the same include set `test:unit` and
 *     `test:integration` run on every push. A `DST_SUITE` naming "the date-ish
 *     files" was the obvious cheaper design and it is the wrong one: which files
 *     are date-sensitive is exactly what nobody knows in advance, and a curated
 *     list would have to be maintained by the same person who did not notice the
 *     dependency.
 *
 *  b. THE ZONE COMES FROM THE HARNESS ALLOWLIST, NOT FROM THIS FILE.
 *     `HVAULT_TZ` is resolved by `tests/harness/determinism.ts` against exactly
 *     two permitted zones and THROWS on anything else, so this is still a pin
 *     rather than a machine-dependent read — and a typo here fails loudly at the
 *     first import rather than quietly running in UTC and reporting a green DST
 *     leg. It is passed as an env var and never as a `TZ=… npm run` prefix,
 *     which is not valid syntax on Windows, where this project is also
 *     developed.
 *
 *  c. IT REUSES THE FLAKE CONFIGS RATHER THAN ADDING THREE MORE. Those configs
 *     exist to run the whole suite while writing somewhere other than the
 *     canonical JUnit and coverage artifacts, which is precisely what a second
 *     out-of-band run of the same suite needs. Sharing them means one fewer
 *     place for an `include` to drift, and `gate-surface.test.ts` already
 *     asserts they narrow nothing. The reports are re-read here BEFORE the next
 *     leg overwrites them.
 *
 *  d. EVERY LEG RUNS, EVEN AFTER ONE FAILS, and a leg that exits 0 without
 *     writing its JUnit is a FAILURE — the shape a suppressed reporter produces,
 *     and the rule `property-gate.mjs` records.
 */
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { TIMEOUT_EXIT, captureExe, runNpm } from './lib/proc.mjs';
import { color, note, warn } from './lib/ui.mjs';
import { ensureReportDir, reportPath, writeJsonReport } from './lib/reports.mjs';

/**
 * The zone. MIRRORS `DST_TZ` in `tests/harness/determinism.ts`, which is where
 * it is validated; `gate-surface.test.ts` asserts the two agree. Restated rather
 * than imported because this is a `.mjs` runner and that is a TypeScript module.
 */
const DST_TZ = 'America/New_York';

/**
 * The wall-clock deadline for one package leg.
 *
 * Half of `flake-run.mjs`'s, deliberately: that gate runs the suite ten times in
 * a row and is the one likely to meet a machine whose RAM disk is full of
 * orphaned dbPaths (the six-fold degradation measured there), while this one runs
 * each suite once. Fifteen minutes is still roughly seven times the slowest
 * measured leg.
 */
const LEG_DEADLINE_MS = 900_000;

const PACKAGES = ['shared', 'client', 'server'];

/** The `tests`/`failures` attributes of a JUnit document, or null when absent. */
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

  const failed = [];
  for (const match of xml.matchAll(/<testcase\b([^>]*)>([\s\S]*?)<\/testcase>/g)) {
    if (!/<(failure|error)\b/.test(match[2])) continue;
    const name = /\bname="([^"]*)"/.exec(match[1])?.[1] ?? '(unnamed)';
    const suite = /\bclassname="([^"]*)"/.exec(match[1])?.[1] ?? '';
    failed.push(suite ? `${suite} › ${name}` : name);
  }
  // Only the count and the NAMES. A separate `failures` total was computed here
  // and consumed by nothing, which is a number nobody checks pretending to be a
  // measurement: the verdict comes from the exit code, and `failed` is what makes
  // the report actionable.
  return { tests: outer ? attr(outer[0], 'tests') : sum('tests'), failed };
}

/**
 * Prove the zone actually REACHES a child, before spending four minutes claiming
 * it did.
 *
 * `dst.json` would otherwise record `timezone: 'America/New_York'` as an
 * assertion by this file rather than as an observation. The harness allowlist
 * throws on a WRONG `HVAULT_TZ`, never on a LOST one — so if propagation broke,
 * `RUN_TZ` would fall back to UTC, all three legs would pass, and the gate would
 * report three green legs "in America/New_York" having run none. That is exactly
 * the coincidence-passes-for-correctness class this gate exists to kill, so it
 * must not be the shape of the gate itself.
 *
 * What this proves and what it does not: it proves the variable survives the
 * spawn AND that ICU in this Node build can resolve the zone (a real failure on a
 * small-icu build, where an unknown zone silently resolves to UTC). It does not
 * prove vitest's own config re-read it — that half is covered inside the suite,
 * by the assertion in `packages/server/tests/determinism.test.ts` that a present
 * `HVAULT_TZ` equals the resolved `RUN_TZ`.
 */
function observedZone() {
  const probe = captureExe(
    process.execPath,
    [
      '-e',
      "process.stdout.write(new Intl.DateTimeFormat('en-US',{timeZone:process.env.HVAULT_TZ}).resolvedOptions().timeZone)",
    ],
    { env: { HVAULT_TZ: DST_TZ } },
  );
  return probe.ok ? probe.stdout.trim() : null;
}

ensureReportDir();

const zoneSeen = observedZone();
if (zoneSeen !== DST_TZ) {
  console.error(
    color.red(
      `dst: the zone did not reach a child process — expected ${DST_TZ}, observed ${String(zoneSeen)}. ` +
        'Running the suite now would report a DST leg it did not perform.',
    ),
  );
  process.exit(1);
}

const legs = [];
const started = Date.now();

for (const pkg of PACKAGES) {
  console.log(color.bold(`\n  dst: packages/${pkg} in TZ=${DST_TZ}`));
  const report = `junit-flake-${pkg}.xml`;
  // (c) A stale document from the flake gate — or from this gate's previous leg
  // — would otherwise be read as this leg's evidence.
  rmSync(reportPath(report), { force: true });

  const legStarted = Date.now();
  const code = await runNpm(['run', 'test:flake', '-w', `packages/${pkg}`], {
    // (b) Read by `tests/harness/determinism.ts`, validated against its
    // allowlist, and applied inside the harness rather than as a shell prefix.
    env: { HVAULT_TZ: DST_TZ },
    timeoutMs: LEG_DEADLINE_MS,
  });
  const durationMs = Date.now() - legStarted;
  const timedOut = code === TIMEOUT_EXIT;
  const junit = readJunit(reportPath(report));

  const leg = {
    package: `packages/${pkg}`,
    timezone: DST_TZ,
    exitCode: code,
    durationMs,
    timedOut,
    tests: junit?.tests ?? null,
    failedTests: junit?.failed ?? [],
    status: code === 0 && !timedOut && junit !== null ? 'pass' : 'fail',
  };
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
        `  ✖ packages/${pkg} (TZ=${DST_TZ}) failed — exit ${String(code)}${junit === null ? ', and wrote no JUnit report' : ''}`,
      ),
    );
    for (const name of leg.failedTests.slice(0, 20)) console.error(color.red(`      ${name}`));
  } else {
    console.log(
      color.green(`  ✔ packages/${pkg} — ${String(leg.tests)} tests in ${String(durationMs)}ms`),
    );
  }
}

const failed = legs.filter((leg) => leg.status !== 'pass');
const payload = {
  version: 1,
  task: 'test:dst',
  checkedAt: new Date().toISOString(),
  durationMs: Date.now() - started,
  timezone: DST_TZ,
  // OBSERVED, not asserted — see `observedZone`.
  timezoneObserved: zoneSeen,
  seed: process.env['SEED'] ?? '1337',
  // Reporting only: every one of these tests also runs on the push tier in UTC,
  // and the task carries `countsTests: false` so the same tests are never
  // ratcheted twice.
  totalLegTests: legs.reduce((sum, leg) => sum + (leg.tests ?? 0), 0),
  failures: failed.length,
  legs,
};
writeJsonReport('dst.json', payload);

if (failed.length > 0) {
  warn(`${String(failed.length)} of ${String(legs.length)} DST legs failed`);
  for (const leg of failed) {
    console.error(color.red(`      ${leg.package} — exit ${String(leg.exitCode)}`));
  }
  console.error(
    color.red(
      `      A test that passes in UTC and fails in ${DST_TZ} has an undeclared dependency on ` +
        "the machine's timezone. Fix the assertion to state the zone it means; never pin the gate back to UTC.",
    ),
  );
  process.exit(1);
}

note(
  `dst.json — ${String(legs.length)} legs in ${DST_TZ}, ${String(payload.totalLegTests)} leg-tests, 0 failures`,
);
