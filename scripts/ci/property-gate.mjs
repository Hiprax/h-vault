#!/usr/bin/env node
/**
 * `test:property` — the property-based suites, run once per timezone.
 *
 * Six legs: the three packages that carry a property suite, each in `UTC` and
 * again in `America/New_York`.
 *
 *   node scripts/ci/property-gate.mjs        the gate (this is what the pipeline runs)
 *   npm run test:property                    the same thing
 *
 * A single package's leg, while iterating, is a plain vitest invocation:
 *
 *   npm run test:property -w packages/client
 *   HVAULT_TZ=America/New_York npm run test:property -w packages/client
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. TWO TIMEZONES, NOT ONE. `combineExpiry` (VaultItemForm) decides "did the
 *     user move either control?" by comparing the rendered control STRINGS rather
 *     than the instants, because during the repeated hour of a fall-back DST
 *     transition two distinct instants render to the same date and time pair. In
 *     UTC that branch cannot be reached at all — there is no transition — so a
 *     suite that only ever runs in UTC cannot tell the fixed implementation from
 *     the broken one. Measured: replacing the string comparison with a
 *     minute-floored instant comparison leaves the UTC leg fully GREEN and turns
 *     the DST leg red on `2026-11-01T06:30:00.000Z`, rewritten an hour earlier.
 *     The zone is applied through `HVAULT_TZ`, which
 *     `tests/harness/determinism.ts` resolves against an ALLOWLIST of exactly
 *     those two zones — so this is still a pin, not a machine-dependent read.
 *
 *  b. EVERY LEG WRITES ITS OWN JUNIT REPORT. Six runs sharing one report name
 *     would leave the LAST leg's result standing in for all six, which is a gate
 *     that has quietly stopped covering five of them. The names come from
 *     `tests/harness/propertyReport.ts`, and `gate-surface.test.ts` compares that
 *     list against what `.testfortress/verify.json` declares, in both directions.
 *
 *  c. EVERY LEG RUNS, EVEN AFTER ONE FAILS. Aggregating matches the pipeline's own
 *     default and costs nothing here: the legs are seconds each, and a property
 *     that fails in one zone and not the other is the single most informative
 *     thing this gate can report.
 *
 *  d. A MISSING REPORT IS A FAILURE. A leg that exits 0 without writing its JUnit
 *     did not run the suite it claims to have run — the shape a `--reporter`
 *     override on the command line produces, which is exactly how this was
 *     observed during development.
 */
import { existsSync, readFileSync } from 'node:fs';
import { runNpm } from './lib/proc.mjs';
import { color, note, warn } from './lib/ui.mjs';
import { ensureReportDir, reportPath, writeJsonReport } from './lib/reports.mjs';

/** The two zones, and the packages, in the order the legs run. */
const ZONES = ['UTC', 'America/New_York'];
const PACKAGES = ['shared', 'server', 'client'];

/** Mirrors `zoneSuffix` in tests/harness/propertyReport.ts. */
const suffix = (zone) => (zone === 'America/New_York' ? 'dst' : 'utc');
const junitName = (pkg, zone) => `junit-property-${pkg}-${suffix(zone)}.xml`;

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

for (const zone of ZONES) {
  for (const pkg of PACKAGES) {
    const report = junitName(pkg, zone);
    console.log(color.bold(`\n  property: packages/${pkg} in TZ=${zone}`));

    const legStarted = Date.now();
    const code = await runNpm(['run', 'test:property', '-w', `packages/${pkg}`], {
      // The suite reads this and pins `process.env.TZ` from it, inside the
      // harness — never as a `TZ=… npm run` prefix, which is not valid syntax on
      // Windows, where this project is also developed.
      env: { HVAULT_TZ: zone },
    });
    const durationMs = Date.now() - legStarted;
    const tests = testCount(reportPath(report));

    legs.push({
      package: `packages/${pkg}`,
      timezone: zone,
      report,
      exitCode: code,
      durationMs,
      tests,
      status: code === 0 && tests !== null ? 'pass' : 'fail',
    });

    if (code !== 0) {
      console.error(color.red(`  ✖ packages/${pkg} (TZ=${zone}) failed — exit ${String(code)}`));
    } else if (tests === null) {
      // (d) Exit 0 with no report means the suite did not actually run.
      console.error(color.red(`  ✖ packages/${pkg} (TZ=${zone}) exited 0 but wrote no ${report}`));
    } else {
      console.log(
        color.green(
          `  ✔ packages/${pkg} (TZ=${zone}) — ${String(tests)} tests in ${String(durationMs)}ms`,
        ),
      );
    }
  }
}

const failed = legs.filter((leg) => leg.status !== 'pass');
const payload = {
  version: 1,
  task: 'test:property',
  checkedAt: new Date().toISOString(),
  durationMs: Date.now() - started,
  seed: process.env['SEED'] ?? '1337',
  zones: ZONES,
  // The total is per LEG, so the same suite counted in two zones appears twice.
  // Deliberate: the number that matters here is "did all six legs run", and the
  // task carries `countsTests: false` in the manifest so this never enters the
  // ratchet's headcount (which `test:unit` and `test:integration` already own —
  // every property file also runs there).
  totalLegTests: legs.reduce((sum, leg) => sum + (leg.tests ?? 0), 0),
  legs,
};
writeJsonReport('property.json', payload);

if (failed.length > 0) {
  warn(`${String(failed.length)} of ${String(legs.length)} property legs failed`);
  for (const leg of failed) {
    console.error(
      color.red(`      ${leg.package} TZ=${leg.timezone} — exit ${String(leg.exitCode)}`),
    );
  }
  process.exit(1);
}

note(
  `property.json — ${String(legs.length)} legs, ${String(payload.totalLegTests)} leg-tests, seed ${payload.seed}`,
);
