/**
 * The gate surface: `.testfortress/verify.json` and the runner that drives it.
 *
 * The manifest exists so that a person or a tool can enumerate this project's
 * gates without reading package.json and guessing. That only holds while the
 * manifest and the runner agree, so the interesting failures here are all
 * DRIFT failures:
 *
 *   1. A task registered in the manifest whose command does not exist. An empty
 *      stub exits 0 and reports green forever; a task pointing at a missing npm
 *      script is the same thing with extra steps.
 *   2. A gate the manifest does not declare, or a declared task no gate runs.
 *      Either way one of the two is lying about what this repository checks.
 *   3. A slow gate promoted into T0. T0 runs on every commit under a 90-second
 *      budget; a tier over budget gets bypassed, and a bypassed hook gates
 *      nothing.
 *   4. The exit-code contract collapsing "could not run" into "passed".
 *
 * The gate registry is read by RUNNING the runner (`--list --json`) rather than
 * by regexing its source, so these assertions are about what the pipeline does,
 * not about how it is written.
 */
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  blockingDependency,
  resolveExitCode,
  resolveTiers,
  selectGates,
} from '../../../scripts/ci/lib/tiers.mjs';
import { toSarif, countLevels } from '../../../scripts/ci/lib/sarif.mjs';
import sharedVitestConfig from '../../shared/vitest.config';
import serverVitestConfig from '../vitest.config';
import securityVitestConfig, { SECURITY_SUITE } from '../vitest.security.config';
import observabilityVitestConfig, { OBSERVABILITY_SUITE } from '../vitest.observability.config';
import serverPropertyConfig, { SERVER_PROPERTY_SUITE } from '../vitest.property.config';
import sharedPropertyConfig, { SHARED_PROPERTY_SUITE } from '../../shared/vitest.property.config';
import clientPropertyConfig, { CLIENT_PROPERTY_SUITE } from '../../client/vitest.property.config';
import clientVitestConfig from '../../client/vitest.config';
import clientFuzzConfig, { CLIENT_FUZZ_SUITE } from '../../client/vitest.fuzz.config';
import serverFuzzConfig, { SERVER_FUZZ_SUITE } from '../vitest.fuzz.config';
import resourceVitestConfig, { RESOURCE_SUITE } from '../vitest.resource.config';
import upgradeVitestConfig, { UPGRADE_SUITE } from '../vitest.upgrade.config';
import recoveryVitestConfig, { RECOVERY_SUITE } from '../vitest.recovery.config';
import clientUpgradeConfig, { CLIENT_UPGRADE_SUITE } from '../../client/vitest.upgrade.config';
import { RESOURCE_SCENARIOS } from '../../../scripts/ci/lib/resource-budgets.mjs';
import { chunkBaseName } from '../../../scripts/ci/bundle-gate.mjs';
import clientSnapshotConfig, { CLIENT_SNAPSHOT_SUITE } from '../../client/vitest.snapshot.config';
import sharedMutationConfig from '../../shared/vitest.mutation.config';
import serverMutationConfig from '../vitest.mutation.config';
import clientMutationConfig from '../../client/vitest.mutation.config';
import sharedFlakeConfig from '../../shared/vitest.flake.config';
import serverFlakeConfig from '../vitest.flake.config';
import clientFlakeConfig from '../../client/vitest.flake.config';
import { CORE_MODULES, MUTATION_LEGS } from '../../../scripts/ci/lib/mutation-scope.mjs';
import playwrightConfig from '../../../playwright.config';
import a11yPlaywrightConfig, { A11Y_SUITE } from '../../../playwright.a11y.config';
import flakePlaywrightConfig, { FLAKE_REPEAT_EACH } from '../../../playwright.flake.config';
import { A11Y_BLOCKING_IMPACTS, A11Y_VIEWS, A11Y_VIEW_IDS } from '../../../e2e/a11yViews';
import { DST_TZ, PINNED_TZ, RUN_TZ, resolveRunTz } from '../../../tests/harness/determinism';
import {
  allPropertyJunitReports,
  propertyJunitReport,
} from '../../../tests/harness/propertyReport';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..', '..', '..');

interface ManifestTask {
  cmd: string;
  tier: number;
  gate: string;
  report: string | string[];
  composite?: boolean;
  requires?: string[];
  canSkip?: boolean;
  /** `false` keeps a re-run of tests another gate already counted out of `tests.count`. */
  countsTests?: boolean;
}

interface Manifest {
  version: number;
  runner: string;
  reportDir: string;
  env: Record<string, string>;
  tiers: Record<string, string>;
  tasks: Record<string, ManifestTask>;
  gaps: unknown[];
}

interface GateEntry {
  id: string;
  task: string;
  tier: number;
  title: string;
  ci: string;
  canSkip: boolean;
  dependsOn: string[];
  requires: string[];
  log: string;
}

const manifest = JSON.parse(
  readFileSync(path.join(repoRoot, '.testfortress', 'verify.json'), 'utf-8'),
) as Manifest;

const pkg = JSON.parse(readFileSync(path.join(repoRoot, 'package.json'), 'utf-8')) as {
  scripts: Record<string, string>;
};

/**
 * The runner's own view of its gates — obtained by asking it, not by parsing it,
 * and deliberately built without reading the manifest. Two independent sources
 * are what makes the comparison below a real check rather than the manifest
 * being compared with itself.
 */
const gates = JSON.parse(
  execFileSync(
    process.execPath,
    [path.join(repoRoot, 'scripts', 'ci', 'local-ci.mjs'), '--list', '--json'],
    { encoding: 'utf-8' },
  ),
) as GateEntry[];

const nonComposite = Object.entries(manifest.tasks).filter(([, task]) => task.composite !== true);
const composite = Object.entries(manifest.tasks).filter(([, task]) => task.composite === true);
const reportsOf = (task: ManifestTask): string[] =>
  Array.isArray(task.report) ? task.report : [task.report];

describe('verify.json manifest', () => {
  it('declares the contract version, the report directory and the tier map', () => {
    expect(manifest.version).toBe(1);
    expect(manifest.reportDir).toBe('.testfortress/reports');
    expect(manifest.tiers).toEqual({ 0: 'verify:fast', 1: 'verify', 2: 'verify:full' });
  });

  it('declares the determinism environment the harness runs under', () => {
    // `scripts/ci` still does not read this block: the values are APPLIED inside
    // each runner (`packages/*/vitest.config.ts` `test.env` plus
    // `tests/harness/determinism.ts`, and `playwright.config.ts`), which is what
    // makes them hold for an IDE run or a bare `npx vitest` too — a shell prefix
    // would not, and `TZ=x cmd` is not valid syntax on Windows, where this project
    // is also developed. So this pins the DECLARATION and the two must agree:
    // every key here is one the harness actually sets.
    expect(manifest.env['TZ']).toBe('UTC');
    expect(manifest.env['LANG']).toBe('C.UTF-8');
    // `LC_ALL` as well as `LANG`, because glibc and ICU resolve `LC_ALL` FIRST: on
    // a machine that exports `LC_ALL=en_US.UTF-8` — as the reference machine does
    // — a `LANG`-only pin is inert.
    expect(manifest.env['LC_ALL']).toBe('C.UTF-8');
    expect(manifest.env['SEED']).toBeTruthy();
  });

  it('marks every aggregator composite, and runs none of them as a gate', () => {
    // Without this, verify:full (T0+T1+T2) would contain a T2 aggregator that
    // runs verify:full, and the tier would recurse into itself. verify:selftest
    // is one for the same reason twice over: it would plant a defect for itself,
    // and a defect for the container drill, on every gate it checks. `ci:local`
    // is the same recursion wearing a clean-room hat: it runs `verify:full`
    // inside a temporary worktree, so a tier that ran it as a member would run
    // itself again, one `npm ci` deeper, without bound.
    expect(composite.map(([name]) => name).sort()).toEqual([
      'ci:local',
      'verify',
      'verify:fast',
      'verify:full',
      'verify:selftest',
    ]);
    for (const [name] of composite) {
      expect(gates.some((gate) => gate.task === name)).toBe(false);
    }
  });

  it('gives every real task a command, a tier, a gate criterion and a report', () => {
    for (const [name, task] of nonComposite) {
      expect(task.cmd, `${name}.cmd`).toBeTruthy();
      expect([0, 1, 2], `${name}.tier`).toContain(task.tier);
      expect(task.gate, `${name}.gate`).toBeTruthy();
      expect(reportsOf(task).length, `${name}.report`).toBeGreaterThan(0);
    }
  });

  it('registers no task whose command does not exist today', () => {
    // A registered task pointing at a missing npm script or a missing file is a
    // gate that can only ever error — the same lie as a stub that exits 0.
    for (const [name, task] of nonComposite) {
      const npmScript = /^npm run ([\w:-]+)/.exec(task.cmd);
      const nodeScript = /^node ([\w./-]+)/.exec(task.cmd);
      if (npmScript) {
        expect(Object.keys(pkg.scripts), `${name} → ${task.cmd}`).toContain(npmScript[1]);
      } else if (nodeScript) {
        expect(existsSync(path.join(repoRoot, nodeScript[1]!)), `${name} → ${task.cmd}`).toBe(true);
      } else {
        throw new Error(`${name}: cmd "${task.cmd}" is neither an npm script nor a node script`);
      }
    }
  });

  it('gives every aggregator a runnable command too', () => {
    for (const [name, task] of composite) {
      const npmScript = /^npm run ([\w:-]+)/.exec(task.cmd);
      expect(npmScript, `${name} → ${task.cmd}`).not.toBeNull();
      expect(Object.keys(pkg.scripts), `${name} → ${task.cmd}`).toContain(npmScript![1]);
    }
  });

  it('never lets two tasks write the same report file', () => {
    // Shared report names mean one gate's evidence silently overwrites another's.
    const declared = nonComposite.flatMap(([, task]) => reportsOf(task));
    expect(declared).toHaveLength(new Set(declared).size);
  });
});

describe('manifest and runner agree', () => {
  it('implements every declared task with exactly one gate', () => {
    for (const [name] of nonComposite) {
      const implementing = gates.filter((gate) => gate.task === name);
      expect(implementing, `task ${name}`).toHaveLength(1);
    }
  });

  it('declares every gate the runner would run', () => {
    for (const gate of gates) {
      expect(Object.keys(manifest.tasks), `gate ${gate.id}`).toContain(gate.task);
    }
  });

  it('agrees on the tier of every gate', () => {
    for (const gate of gates) {
      expect(manifest.tasks[gate.task]!.tier, `gate ${gate.id}`).toBe(gate.tier);
    }
  });

  it('points a gate whose report IS its transcript at the file it actually writes', () => {
    // The runner tees each gate into `<log>`. When a gate's declared report is
    // that transcript, the two names must be the same file — otherwise the gate
    // writes one file and the manifest promises another, and the promised one is
    // what every later tool goes looking for.
    for (const gate of gates) {
      const declared = reportsOf(manifest.tasks[gate.task]!);
      const logReports = declared.filter((report) => report.endsWith('.log'));
      if (logReports.length > 0) {
        expect(logReports, `gate ${gate.id}`).toEqual([gate.log]);
      }
    }
  });
});

describe('tiers', () => {
  it('keeps T0 to the seven gates that fit a 90-second pre-commit budget', () => {
    // Measured end to end on the reference machine: engines 0.0s, secrets 0.1s,
    // lint 30.7s, format 15.1s, type-check 36.4s, integrity 2.3s, ratchet 0.1s —
    // 85 seconds against a 90-second budget. The two anti-cheat gates cost 2.4s
    // between them; the unit suite alone is 105 seconds and the server suite
    // 125, which is why both are T1. A tier over budget gets bypassed, and a
    // bypassed hook gates nothing, so ADDING ANYTHING HERE REQUIRES RE-MEASURING.
    // 5 seconds of headroom is the tightest this has been: the next thing added
    // to T0 almost certainly has to buy its time back somewhere else (ESLint's
    // --cache, or running the independent T0 gates in parallel).
    //
    // The order matters as much as the membership: `ratchet` reads the report
    // `integrity` writes, so it must come after it. Running the cheap ratchet
    // before the scan would compare against the PREVIOUS run's artifact, which
    // it would then reject as stale — correctly, and confusingly.
    const t0 = gates.filter((gate) => gate.tier === 0).map((gate) => gate.id);
    expect(t0).toEqual([
      'engines',
      'secrets',
      'lint',
      'format',
      'type-check',
      'integrity',
      'ratchet',
    ]);
  });

  it('names every gate the push gate does NOT run, so parking one there is deliberate', () => {
    // `npm run ci` is T0+T1. A gate moved to T2 still appears in `--list` and
    // still looks registered, but stops running on every push — the quietest way
    // to retire a gate without deleting it. So the T2 membership is pinned as an
    // exact list rather than merely counted: adding to it is a visible edit here,
    // and moving an existing gate into it fails until someone changes this line.
    //
    // Three members, and each one has to justify its place:
    //
    //   `fuzz` — both of its suites ALSO run inside `test` and
    //   `test-integration` on every push, because neither package narrows its
    //   include set, so the assertions are on the push gate and only the named,
    //   deadline-bounded RUN is held back for `verify:full`.
    //
    //   `resource` — the volume budgets. Unlike `fuzz` these files run HERE and
    //   nowhere else, because the base server config excludes them: each builds a
    //   vault at MAX_ITEMS_PER_USER and times an operation over it, so the suite
    //   is a minute of wall clock, and its numbers are only meaningful in a
    //   process running nothing else — while the push tier runs three workers at
    //   once. Measured under that contention a budget is a coin toss.
    //
    //   `upgrade` — the previous release's vault and .env, read by this one. Like
    //   `fuzz` and unlike `resource`, both of its files also run inside
    //   `test-integration` on every push; what T2 buys is the named,
    //   separately-reported run and a wall-clock deadline over a half that boots a
    //   real child process per case, where a HANG is a distinct defect from a
    //   refusal.
    //
    //   `recovery` — the disaster drills: a backup restored onto a second
    //   mongod, and a real process SIGKILLed mid-write. Like `fuzz` and
    //   `upgrade`, both of its files also run inside `test-integration` on every
    //   push; T2 buys the named run and a deadline, which this gate needs more
    //   than any other because it spawns processes in order to kill them and the
    //   two ways that goes wrong both present as a hang.
    //
    //   `deploy` — the deployment clean room builds four images, stands five
    //   containers up from nothing, restarts them and rotates a database
    //   credential. There is no version of that which belongs in a hook someone
    //   is waiting on, and its fast sibling `smoke` (T1) covers the artifact on
    //   every push.
    //
    //   `mutation` — the oracle, and the longest-running gate in the repository
    //   by an order of magnitude: it re-runs the suite once per mutant over
    //   ~53,000 lines of source. Unlike every other member it has no cheap
    //   sibling on the push tier, and that is stated rather than hidden: what
    //   guards it between runs is `ratchet-check.mjs`'s DEFERRABLE rule, which
    //   keeps `mutation.*` in the baseline as a floor the gate enforces itself
    //   and turns the fields back into hard failures the moment this task stops
    //   being a registered tier-2 gate.
    //
    //   `dst` — the whole suite, once, in America/New_York. Like `fuzz`,
    //   `upgrade` and `recovery` it narrows nothing and every one of its tests
    //   also runs on every push; what T2 buys is the one thing the push tier
    //   structurally cannot, which is a different clock. `test:property` already
    //   runs two zones, but only over `tests/property/**`, so ~7,400 tests had
    //   never been executed anywhere local time and UTC disagree.
    //
    //   `flake` — ten complete runs of all three suites in ten different
    //   shuffled orders, plus the Playwright suite three times over: about an
    //   hour, and the second-longest gate here after the oracle. It measures the
    //   property every other gate assumes, which is that the suite's verdict does
    //   not depend on the order it happened to run in.
    const t2 = gates.filter((gate) => gate.tier === 2).map((gate) => gate.id);
    expect(t2).toEqual([
      'fuzz',
      'resource',
      'upgrade',
      'recovery',
      'dst',
      'deploy',
      'flake',
      'mutation',
    ]);
  });

  it('treats tiers as cumulative, so verify is a superset of verify:fast', () => {
    expect(resolveTiers('0')).toEqual([0]);
    expect(resolveTiers('1')).toEqual([0, 1]);
    expect(resolveTiers('2')).toEqual([0, 1, 2]);
    expect(resolveTiers('full')).toEqual([0, 1, 2]);
    expect(resolveTiers('nope')).toBeNull();
  });

  it('selects by tier, and lets an explicit --only override the tier', () => {
    const table = [
      { id: 'fast', tier: 0 },
      { id: 'slow', tier: 1 },
      { id: 'release', tier: 2 },
    ];
    expect(selectGates(table, { tiers: [0] }).map((gate) => gate.id)).toEqual(['fast']);
    expect(selectGates(table, { tiers: [0, 1] }).map((gate) => gate.id)).toEqual(['fast', 'slow']);
    // Without the override, `--only=release` under the default tier would select
    // nothing and exit 0 — a request to run a gate answered by running none.
    expect(selectGates(table, { only: ['release'], tiers: [0] }).map((gate) => gate.id)).toEqual([
      'release',
    ]);
  });
});

describe('exit-code contract', () => {
  it('reports a failing gate as 1 and a gate that could not run as 2', () => {
    expect(resolveExitCode([{ status: 'pass' }, { status: 'skip' }])).toBe(0);
    expect(resolveExitCode([{ status: 'pass' }, { status: 'fail' }])).toBe(1);
    expect(resolveExitCode([{ status: 'pass' }, { status: 'error' }])).toBe(2);
  });

  it('lets a real failure outrank a broken gate, because it is the actionable one', () => {
    expect(resolveExitCode([{ status: 'error' }, { status: 'fail' }])).toBe(1);
  });

  it('never reports success for a run that contains a non-pass', () => {
    for (const status of ['fail', 'error']) {
      expect(resolveExitCode([{ status: 'pass' }, { status }])).not.toBe(0);
    }
  });
});

describe('the skip sentinel stays bound to one gate', () => {
  it('lets exactly one gate report itself SKIPPED, and it is sast', () => {
    // Exit 78 means "the tooling is genuinely absent". Honouring it from any
    // other gate would let a real failure masquerade as a skip.
    const skippable = gates.filter((gate) => gate.canSkip);
    expect(skippable.map((gate) => gate.id)).toEqual(['sast']);
  });
});

describe('prerequisites are declared, not discovered', () => {
  it('declares docker on the image gate and a built shared package on the rest', () => {
    const byId = new Map(gates.map((gate) => [gate.id, gate]));
    expect(byId.get('docker')?.requires).toContain('docker');
    for (const id of ['type-check', 'test', 'test-integration', 'security', 'e2e']) {
      expect(byId.get(id)?.requires, `gate ${id}`).toContain('build:shared');
    }
  });

  it('stops a failed build from dragging the gates that consume it into failure', () => {
    const byId = new Map(gates.map((gate) => [gate.id, gate]));
    for (const id of ['type-check', 'test', 'test-integration', 'security', 'e2e']) {
      expect(byId.get(id)?.dependsOn, `gate ${id}`).toContain('build');
    }
  });

  it('cascades a BROKEN dependency, and never a deliberately skipped one', () => {
    // `HVAULT_SKIP_GATES=build` means "I already built". Treating that skip as a
    // broken dependency would turn one requested skip into five silent ones, and
    // the run would report green for gates that never ran.
    const statuses: Record<string, string> = {
      broke: 'fail',
      unrunnable: 'error',
      skipped: 'skip',
      fine: 'pass',
    };
    const statusOf = (id: string): string | undefined => statuses[id];

    expect(blockingDependency(['broke'], statusOf)).toBe('broke');
    expect(blockingDependency(['unrunnable'], statusOf)).toBe('unrunnable');
    expect(blockingDependency(['skipped'], statusOf)).toBeUndefined();
    expect(blockingDependency(['fine'], statusOf)).toBeUndefined();
    // A dependency outside the current selection never ran at all.
    expect(blockingDependency(['not-selected'], statusOf)).toBeUndefined();
    expect(blockingDependency(['fine', 'skipped', 'broke'], statusOf)).toBe('broke');
  });
});

describe('machine-readable reports', () => {
  const junitOutputFile = (reporters: unknown): string | undefined => {
    if (!Array.isArray(reporters)) return undefined;
    for (const entry of reporters as unknown[]) {
      if (Array.isArray(entry) && entry[0] === 'junit') {
        return (entry[1] as { outputFile?: string } | undefined)?.outputFile;
      }
    }
    return undefined;
  };

  it.each([
    ['shared', sharedVitestConfig, 'junit-shared.xml'],
    ['server', serverVitestConfig, 'junit-server.xml'],
    ['client', clientVitestConfig, 'junit-client.xml'],
  ])('writes JUnit XML from the %s suite', (_name, config, file) => {
    const output = junitOutputFile(config.test?.reporters);
    expect(output).toBeDefined();
    expect(path.resolve(output!)).toBe(path.join(repoRoot, '.testfortress', 'reports', file));
  });

  it('writes the security suite to its OWN JUnit report, not the server one', () => {
    // The security gate re-runs a named subset of the server suite. Pointed at
    // `junit-server.xml`, it would overwrite the artifact `audit:ratchet:full`
    // reads the server package's test count from — measured: driving the same
    // files from the command line did exactly that, because the base config's
    // inline `outputFile` outranks `--outputFile.junit`. Both halves are
    // asserted: the file it writes, and that it is a different file.
    const security = junitOutputFile(securityVitestConfig.test?.reporters);
    const server = junitOutputFile(serverVitestConfig.test?.reporters);
    expect(security).toBeDefined();
    expect(path.resolve(security!)).toBe(
      path.join(repoRoot, '.testfortress', 'reports', 'junit-security.xml'),
    );
    expect(security).not.toBe(server);
    // And it runs a REAL subset: named files, none of them invented.
    expect(SECURITY_SUITE.length).toBeGreaterThan(0);
    for (const file of SECURITY_SUITE) {
      expect(existsSync(path.join(repoRoot, 'packages', 'server', file)), file).toBe(true);
    }
    expect(securityVitestConfig.test?.include).toEqual(SECURITY_SUITE);
  });

  it('writes the observability suite to its OWN JUnit report, from files that exist', () => {
    // Same contract as the security suite above, and the same two failure modes
    // it is defending against: a subset run overwriting the whole suite's test
    // count, and a named file that has been renamed away — which vitest reports
    // only when NOTHING matches, so a list that is stale in part silently shrinks
    // the gate instead of failing it.
    const observability = junitOutputFile(observabilityVitestConfig.test?.reporters);
    const server = junitOutputFile(serverVitestConfig.test?.reporters);
    expect(observability).toBeDefined();
    expect(path.resolve(observability!)).toBe(
      path.join(repoRoot, '.testfortress', 'reports', 'junit-observability.xml'),
    );
    expect(observability).not.toBe(server);
    expect(OBSERVABILITY_SUITE.length).toBeGreaterThan(0);
    for (const file of OBSERVABILITY_SUITE) {
      expect(existsSync(path.join(repoRoot, 'packages', 'server', file)), file).toBe(true);
    }
    expect(observabilityVitestConfig.test?.include).toEqual(OBSERVABILITY_SUITE);
  });

  it('pins WHICH files each named subset runs, not merely that they exist', () => {
    // The two assertions above check that every named file is real and that the
    // config runs exactly the named list. Neither says anything about the list
    // itself, so DELETING a line from `SECURITY_SUITE` shrinks the gate by a
    // quarter and every check still passes: the remaining files exist, the
    // config still equals its own constant, and the deleted file keeps running
    // inside `test:integration`, so no test disappears and `tests.count` does
    // not move either. What is lost is the gate's MEANING — "this is the suite a
    // reviewer points at when an endpoint is added" — and nothing but this
    // assertion notices.
    //
    // Pinned as exact, sorted sets: adding a file to either suite is a
    // deliberate act that updates this list in the same change, which is the
    // review this is asking for.
    expect([...SECURITY_SUITE].sort()).toEqual([
      'tests/authz-matrix.test.ts',
      'tests/cross-user-isolation.test.ts',
      'tests/phase7-cross-user-edge-cases.test.ts',
      'tests/route-table.test.ts',
    ]);
    expect([...OBSERVABILITY_SUITE].sort()).toEqual([
      'tests/audit-logging.test.ts',
      'tests/error-message-leakage.test.ts',
      'tests/phase2-topology-and-log-pii.test.ts',
      'tests/request-logger-masking.test.ts',
    ]);
  });

  it.each([
    ['shared', sharedPropertyConfig, SHARED_PROPERTY_SUITE, 'shared'],
    ['server', serverPropertyConfig, SERVER_PROPERTY_SUITE, 'server'],
    ['client', clientPropertyConfig, CLIENT_PROPERTY_SUITE, 'client'],
  ] as const)(
    'writes the %s property suite to its own per-zone JUnit report, from files that exist',
    (name, config, suite, pkg) => {
      // Same contract as the security and observability subsets, plus a second
      // axis: the `test:property` gate runs each of these suites TWICE, once per
      // timezone, so each leg needs its own report name. Six legs writing one file
      // would leave the last one standing in for all six.
      const output = junitOutputFile(config.test?.reporters);
      expect(output).toBeDefined();
      // The name carries the suffix for whichever zone THIS run resolved.
      // Asserted through the helper rather than as a literal, so the two cannot
      // drift.
      expect(path.resolve(output!)).toBe(
        path.join(repoRoot, '.testfortress', 'reports', propertyJunitReport(pkg, RUN_TZ)),
      );
      // What used to be asserted here was `RUN_TZ === PINNED_TZ`, i.e. "the
      // ordinary suite runs in UTC". That was true until `test:dst` existed, and
      // it is now false BY DESIGN in that gate's leg — this whole file is one of
      // the suites it runs in America/New_York. The invariant worth keeping is
      // the one about the RESOLVER: an unset `HVAULT_TZ` yields the pin, never
      // the machine's zone.
      expect(resolveRunTz(undefined), 'an unset HVAULT_TZ must resolve to the pin').toBe(PINNED_TZ);
      expect(propertyJunitReport(pkg, DST_TZ)).not.toBe(propertyJunitReport(pkg, PINNED_TZ));

      expect(suite.length, `${name} property suite`).toBeGreaterThan(0);
      for (const file of suite) {
        expect(existsSync(path.join(repoRoot, 'packages', pkg, file)), file).toBe(true);
      }
      expect(config.test?.include).toEqual(suite);
    },
  );

  it('declares exactly the six property reports the gate produces, in both directions', () => {
    // A leg that stops writing its report and a declared report no leg writes are
    // the same defect seen from two sides. The manifest is compared against the
    // helper the CONFIGS use, so neither can quietly change alone.
    const declared = reportsOf(manifest.tasks['test:property']!);
    expect(declared).toContain('property.json');
    expect([...declared].sort()).toEqual([...allPropertyJunitReports(), 'property.json'].sort());
    expect(allPropertyJunitReports()).toHaveLength(6);
    expect(new Set(allPropertyJunitReports()).size).toBe(6);
  });

  it.each([
    ['client fuzz', clientFuzzConfig, CLIENT_FUZZ_SUITE, 'client', 'junit-fuzz-client.xml'],
    ['server fuzz', serverFuzzConfig, SERVER_FUZZ_SUITE, 'server', 'junit-fuzz-server.xml'],
    ['export golden', clientSnapshotConfig, CLIENT_SNAPSHOT_SUITE, 'client', 'junit-export.xml'],
  ] as const)(
    'writes the %s suite to its OWN JUnit report, from files that exist',
    (name, config, suite, pkg, report) => {
      // The same contract as every other named subset: its own report name, and
      // a membership list whose every entry is on disk. Vitest errors only on an
      // EMPTY match, so a list that has gone stale in part would shrink the gate
      // in silence.
      const output = junitOutputFile(config.test?.reporters);
      expect(output, `${name}: no JUnit reporter`).toBeDefined();
      expect(path.resolve(output!)).toBe(path.join(repoRoot, '.testfortress', 'reports', report));
      expect(output).not.toBe(junitOutputFile(clientVitestConfig.test?.reporters));
      expect(output).not.toBe(junitOutputFile(serverVitestConfig.test?.reporters));

      expect(suite.length, `${name} suite`).toBeGreaterThan(0);
      for (const file of suite) {
        expect(existsSync(path.join(repoRoot, 'packages', pkg, file)), file).toBe(true);
      }
      expect(config.test?.include).toEqual(suite);
    },
  );

  it('runs every resource scenario, and leaves none of them to no gate at all', () => {
    // `test:resource` is the one suite the push tier does NOT also run: the base
    // server config excludes `tests/resource/**` outright, because these
    // scenarios build 10,000-item vaults and their numbers are only meaningful in
    // a process running nothing else. That exclusion is exactly the shape a
    // quietly retired suite has, so both halves are pinned here — the base config
    // excludes the directory, and the resource config claims every file in it.
    expect(serverVitestConfig.test?.exclude).toContain('tests/resource/**');

    const declared = RESOURCE_SCENARIOS.map((scenario) => scenario.file);
    expect(resourceVitestConfig.test?.include).toEqual(declared);
    expect(RESOURCE_SUITE).toEqual(declared);
    expect(declared.length).toBeGreaterThan(0);

    // Both directions. A file on disk that no scenario declares would be run by
    // NOTHING — excluded from the push tier and never included here — which is a
    // test that exists and cannot fail.
    const dir = path.join(repoRoot, 'packages', 'server', 'tests', 'resource');
    const onDisk = readdirSync(dir)
      .filter((entry) => entry.endsWith('.test.ts'))
      .map((entry) => `tests/resource/${entry}`)
      .sort();
    expect(onDisk).toEqual([...declared].sort());

    // Its own JUnit report, never the server suite's — pointed there it would
    // overwrite the artifact `audit:ratchet:full` reads the headcount from.
    const output = junitOutputFile(resourceVitestConfig.test?.reporters);
    expect(path.resolve(output!)).toBe(
      path.join(repoRoot, '.testfortress', 'reports', 'junit-resource.xml'),
    );
    expect(output).not.toBe(junitOutputFile(serverVitestConfig.test?.reporters));

    // And, like `test:fuzz`, only the JSON report is DECLARED: a Tier 2 JUnit in
    // the manifest makes `tests.count` UNMEASURED on every push.
    expect(reportsOf(manifest.tasks['test:resource']!)).toEqual(['resource.json']);
    const declaredReports = nonComposite.flatMap(([, task]) => reportsOf(task));
    expect(declaredReports).not.toContain('junit-resource.xml');
  });

  it('runs the upgrade suite from its own config, its own report and its own files', () => {
    // The same contract as every other named subset, plus one thing only this
    // gate has: two committed GOLDENS. A vault and a `.env` recorded from the
    // v0.7.0 tag are the entire basis of the claim "the previous release's data
    // is still readable", so their existence is pinned here rather than left to
    // surface as a module-load error inside the suite.
    const output = junitOutputFile(upgradeVitestConfig.test?.reporters);
    expect(output).toBeDefined();
    expect(path.resolve(output!)).toBe(
      path.join(repoRoot, '.testfortress', 'reports', 'junit-upgrade.xml'),
    );
    expect(output).not.toBe(junitOutputFile(serverVitestConfig.test?.reporters));

    expect(UPGRADE_SUITE.length).toBeGreaterThan(0);
    for (const file of UPGRADE_SUITE) {
      expect(existsSync(path.join(repoRoot, 'packages', 'server', file)), file).toBe(true);
    }
    expect(upgradeVitestConfig.test?.include).toEqual(UPGRADE_SUITE);

    // Both directions, as for `test:resource`: a file on disk that the gate does
    // not claim would still run inside `test:integration`, so no test would
    // disappear and `tests.count` would not move — the gate would simply be
    // smaller than it says it is, and nothing but this would notice.
    const dir = path.join(repoRoot, 'packages', 'server', 'tests', 'upgrade');
    const onDisk = readdirSync(dir)
      .filter((entry) => entry.endsWith('.test.ts'))
      .map((entry) => `tests/upgrade/${entry}`)
      .sort();
    expect(onDisk).toEqual([...UPGRADE_SUITE].sort());

    // Pinned as an exact set, for the reason the security and observability
    // suites are: deleting a line here shrinks the gate by half while every
    // other check in this test still passes.
    expect([...UPGRADE_SUITE].sort()).toEqual([
      'tests/upgrade/config-compat.test.ts',
      'tests/upgrade/n-minus-1.test.ts',
    ]);

    // The CLIENT leg, and it is not decoration. `cryptoService.ts` lives in that
    // package, so a server test structurally cannot make this gate's headline
    // claim — that a vault written by the previous release DECRYPTS under this
    // one. Deleting this leg would leave the gate asserting only that a 0.7.0
    // document still parses, while its name and its report still promised more.
    const clientOutput = junitOutputFile(clientUpgradeConfig.test?.reporters);
    expect(path.resolve(clientOutput!)).toBe(
      path.join(repoRoot, '.testfortress', 'reports', 'junit-upgrade-client.xml'),
    );
    expect(clientOutput).not.toBe(junitOutputFile(clientVitestConfig.test?.reporters));
    expect(clientOutput).not.toBe(output);
    expect(clientUpgradeConfig.test?.include).toEqual(CLIENT_UPGRADE_SUITE);
    expect([...CLIENT_UPGRADE_SUITE].sort()).toEqual(['tests/upgrade/n-minus-1-crypto.test.ts']);
    const clientDir = path.join(repoRoot, 'packages', 'client', 'tests', 'upgrade');
    expect(
      readdirSync(clientDir)
        .filter((entry) => entry.endsWith('.test.ts'))
        .map((entry) => `tests/upgrade/${entry}`)
        .sort(),
    ).toEqual([...CLIENT_UPGRADE_SUITE].sort());

    // The goldens, and the tag they came from. A fixture regenerated from the
    // current tree — the one edit that turns this whole gate into a tautology —
    // would no longer name v0.7.0.
    for (const fixture of ['v0.7.0-vault.json', 'v0.7.0.env']) {
      const full = path.join(repoRoot, 'packages', 'server', 'tests', 'fixtures', fixture);
      expect(existsSync(full), fixture).toBe(true);
      expect(readFileSync(full, 'utf-8'), fixture).toContain('v0.7.0');
    }

    // And, like `test:fuzz` and `test:resource`, only the JSON report is
    // DECLARED: a Tier 2 JUnit in the manifest makes `tests.count` UNMEASURED on
    // every push.
    expect(reportsOf(manifest.tasks['test:upgrade']!)).toEqual(['upgrade.json']);
    const declaredReports = nonComposite.flatMap(([, task]) => reportsOf(task));
    expect(declaredReports).not.toContain('junit-upgrade.xml');
    expect(declaredReports).not.toContain('junit-upgrade-client.xml');
  });

  it('runs the recovery drills from their own config, their own report and their own files', () => {
    // The same contract as every other named subset. What is specific to this
    // gate is the SHAPE of the thing it protects: the two files spawn real child
    // processes and kill them, so a membership list that lost one would quietly
    // stop rehearsing an entire disaster while the gate kept reporting green.
    const output = junitOutputFile(recoveryVitestConfig.test?.reporters);
    expect(output).toBeDefined();
    expect(path.resolve(output!)).toBe(
      path.join(repoRoot, '.testfortress', 'reports', 'junit-recovery.xml'),
    );
    expect(output).not.toBe(junitOutputFile(serverVitestConfig.test?.reporters));

    expect(RECOVERY_SUITE.length).toBeGreaterThan(0);
    for (const file of RECOVERY_SUITE) {
      expect(existsSync(path.join(repoRoot, 'packages', 'server', file)), file).toBe(true);
    }
    expect(recoveryVitestConfig.test?.include).toEqual(RECOVERY_SUITE);

    // Both directions, as for `test:resource` and `test:upgrade`: a file on disk
    // this gate does not claim would still run inside `test:integration`, so no
    // test would disappear and `tests.count` would not move — the gate would
    // simply be smaller than it says it is, and nothing but this would notice.
    const dir = path.join(repoRoot, 'packages', 'server', 'tests', 'recovery');
    const onDisk = readdirSync(dir)
      .filter((entry) => entry.endsWith('.test.ts'))
      .map((entry) => `tests/recovery/${entry}`)
      .sort();
    expect(onDisk).toEqual([...RECOVERY_SUITE].sort());

    // Pinned as an exact set, for the reason the security and observability
    // suites are: deleting a line here halves the gate while every other check
    // in this test still passes.
    expect([...RECOVERY_SUITE].sort()).toEqual([
      'tests/recovery/crash-consistency.test.ts',
      'tests/recovery/restore-drill.test.ts',
    ]);

    // And, like `test:fuzz`, `test:resource` and `test:upgrade`, only the JSON
    // report is DECLARED: a Tier 2 JUnit in the manifest makes `tests.count`
    // UNMEASURED on every push.
    expect(reportsOf(manifest.tasks['test:recovery']!)).toEqual(['recovery.json']);
    const declaredReports = nonComposite.flatMap(([, task]) => reportsOf(task));
    expect(declaredReports).not.toContain('junit-recovery.xml');
  });

  it('reads a chunk budget by base name, with the content hash stripped exactly', () => {
    // The budgets in `lib/bundle-budgets.mjs` are keyed by chunk base name
    // because the filenames carry a content hash that changes on every
    // meaningful edit. Getting that strip wrong is silent: an over-greedy
    // pattern collapsed `vendor-core` and `vendor-react` into one `vendor`
    // bucket, which put both over a budget meant for neither. The hash alphabet
    // is base64url, so it contains `-` — that is what made the greedy form
    // wrong, and it is why these two cases are here rather than one.
    expect(chunkBaseName('main-4aSwR9SA.js')).toBe('main');
    expect(chunkBaseName('vendor-core-1-AcZIh1.js')).toBe('vendor-core');
    expect(chunkBaseName('vendor-react-BP6A0-cs.js')).toBe('vendor-react');
    expect(chunkBaseName('passwordStrength.worker-BZCvnOAA.js')).toBe('passwordStrength.worker');
    expect(chunkBaseName('index-Tp2RFl97.css')).toBe('index');
  });

  it('mutates every core module the plan names, and nothing has fallen out of the tree', () => {
    // A core module is a PATH PREFIX matched against the measured file set, and
    // a typo in one is SILENT in both directions that matter: the gate never
    // writes a score for it, so the baseline never gains a floor for it, and the
    // "core modules carry the higher threshold" claim quietly applies to
    // nothing. Existence on disk is what makes the six real.
    expect(CORE_MODULES).toEqual([
      'packages/client/src/services/crypto/',
      'packages/shared/src/schemas/',
      'packages/server/src/middleware/rateLimiter.ts',
      'packages/server/src/controllers/vaultController.ts',
      'packages/client/src/services/import/',
      'packages/server/src/utils/folderGraph.ts',
    ]);
    for (const modulePath of CORE_MODULES) {
      expect(existsSync(path.join(repoRoot, modulePath)), modulePath).toBe(true);
    }
  });

  it('keeps every core module inside the declared scope, so a threshold cannot be dodged', () => {
    // The failure this forbids: excluding a core module from `mutate` while
    // leaving it in `CORE_MODULES`. The per-module score then disappears rather
    // than dropping, and a floor with no measurement is not a floor. Directory
    // modules are probed through a real file inside them, because a glob matches
    // files rather than directories.
    const probes: Record<string, string> = {
      'packages/client/src/services/crypto/':
        'packages/client/src/services/crypto/cryptoService.ts',
      'packages/shared/src/schemas/': 'packages/shared/src/schemas/vault.ts',
      'packages/client/src/services/import/': 'packages/client/src/services/import/identity.ts',
    };
    for (const modulePath of CORE_MODULES) {
      const file = probes[modulePath] ?? modulePath;
      expect(existsSync(path.join(repoRoot, file)), file).toBe(true);
      const selected = MUTATION_LEGS.some((leg) => {
        let hit = false;
        for (const glob of leg.mutate) {
          if (glob.startsWith('!')) {
            if (path.matchesGlob(file, glob.slice(1))) hit = false;
          } else if (path.matchesGlob(file, glob)) {
            hit = true;
          }
        }
        return hit;
      });
      expect(selected, `${file} must be inside the declared mutation scope`).toBe(true);
    }
  });

  it('excludes from mutation exactly what coverage excludes, plus the UI primitives', () => {
    // The two denominators describe the same body of code on purpose: a file
    // that is measured for coverage but not for mutation is a file whose
    // execution is proven and whose assertions are not, and the discrepancy
    // would be invisible in either report on its own. Each entry below is a
    // NEGATION in the declared scope, and the list is pinned so adding a
    // seventh is a deliberate, reviewable act rather than a config edit.
    const negations = MUTATION_LEGS.flatMap((leg) =>
      leg.mutate.filter((glob) => glob.startsWith('!')),
    ).sort();
    expect(negations).toEqual([
      '!packages/client/src/**/*.d.ts',
      '!packages/client/src/**/*.worker.ts',
      '!packages/client/src/components/ui/**',
      '!packages/client/src/main.tsx',
      '!packages/server/src/**/*.d.ts',
      '!packages/server/src/cli/seedBreaches.ts',
      '!packages/server/src/server.ts',
      '!packages/shared/src/**/*.d.ts',
      '!packages/shared/src/generated/**',
      '!packages/shared/src/types/**',
    ]);
  });

  it.each([
    ['shared', sharedMutationConfig, sharedVitestConfig],
    ['server', serverMutationConfig, serverVitestConfig],
    ['client', clientMutationConfig, clientVitestConfig],
  ])(
    'runs the %s mutation leg against the WHOLE suite, writing no JUnit',
    (name, mutation, base) => {
      // Two failures, and they pull in opposite directions.
      //
      // A NARROWED include would hand the oracle a subset of the suite and report
      // the result as if the whole suite had been asked — the mutation-testing
      // equivalent of a committed test filter. So the include and exclude sets
      // must be exactly the base suite's.
      expect(mutation.test?.include).toEqual(base.test?.include);
      expect(mutation.test?.exclude).toEqual(base.test?.exclude);
      // A JUnit reporter here would rewrite the artifact `audit:ratchet:full`
      // reads the package's test count from — once per mutant, leaving the LAST
      // MUTANT'S run behind as the headcount for the whole repository.
      const reporters = (mutation.test?.reporters ?? []) as unknown[];
      for (const reporter of reporters) {
        const named = Array.isArray(reporter) ? reporter[0] : reporter;
        expect(named, `${name} mutation reporters`).not.toBe('junit');
      }
      // Vitest resolves `root` from the CWD, and Stryker runs from the repository
      // root. Unpinned, the runner scanned the whole sandbox with the default
      // include, matched nothing, and Stryker exited before testing one mutant.
      expect(mutation.test?.root).toBe(path.join(repoRoot, 'packages', name));
    },
  );

  it("declares only the mutation gate's merged report, and defers it to its own tier", () => {
    // `mutation.json` and nothing else. There is no JUnit here to declare — the
    // legs are Stryker runs, not vitest runs with a reporter — but the rule that
    // shaped `test:fuzz` still applies to the JSON: `test:mutation` is tier 2 and
    // does not run during `npm run ci`, so the ratchet must be able to defer the
    // fields it supplies rather than reporting them stale on every push.
    expect(reportsOf(manifest.tasks['test:mutation']!)).toEqual(['mutation.json']);
    expect(manifest.tasks['test:mutation']!.tier).toBe(2);
    // The deferral is conditional on exactly that tier, which is what stops a
    // gate being retired by moving it somewhere it never runs.
    const ratchet = readFileSync(
      path.join(repoRoot, 'scripts', 'ci', 'ratchet-check.mjs'),
      'utf-8',
    );
    expect(ratchet).toContain("owner: 'test:mutation', tier: 2");
    expect(ratchet).toContain("'mutation.overall'");
    expect(ratchet).toContain("'mutation.filesMutated'");
  });

  it("declares only the fuzz gate's JSON report, never its per-leg JUnit", () => {
    // Load-bearing, and counter-intuitive enough to need stating. `test:fuzz` is
    // Tier 2, so it does not run during `npm run ci` — and `ratchet-check.mjs`
    // requires every DECLARED JUnit artifact to be FRESH before it will report
    // `tests.count` at all. Declaring `junit-fuzz-*.xml` would therefore make the
    // headcount UNMEASURED on every push, turning the ratchet red for a reason
    // that has nothing to do with the code. The reports are still written and
    // still read by the gate; they are simply not part of the every-push
    // freshness contract.
    expect(reportsOf(manifest.tasks['test:fuzz']!)).toEqual(['fuzz.json']);
    const declared = nonComposite.flatMap(([, task]) => reportsOf(task));
    expect(declared).not.toContain('junit-fuzz-client.xml');
    expect(declared).not.toContain('junit-fuzz-server.xml');
  });

  it.each([
    ['shared', sharedFlakeConfig, sharedVitestConfig],
    ['server', serverFlakeConfig, serverVitestConfig],
    ['client', clientFlakeConfig, clientVitestConfig],
  ])('runs the %s flake leg against the WHOLE suite, into its own report', (name, flake, base) => {
    // The same contract as the mutation configs, and it matters more here for one
    // reason: `test:flake` and `test:dst` BOTH drive these configs, so a narrowed
    // include would silently shrink two gates at once. Nothing about a flake hunt
    // or a timezone re-run justifies asking a subset of the suite.
    expect(flake.test?.include).toEqual(base.test?.include);
    expect(flake.test?.exclude).toEqual(base.test?.exclude);

    // Its own JUnit, and it must NOT be the canonical one: `test:flake` runs this
    // suite ten times, so pointed at `junit-<pkg>.xml` it would leave the tenth
    // run standing in for `test:unit`/`test:integration`'s evidence, which is
    // what `audit:ratchet:full` reads the headcount from.
    const output = junitOutputFile(flake.test?.reporters);
    expect(output, `${name} flake JUnit`).toBeDefined();
    expect(path.resolve(output!)).toBe(
      path.join(repoRoot, '.testfortress', 'reports', `junit-flake-${name}.xml`),
    );

    // Coverage OFF, and this is correctness rather than speed: ten instrumented
    // runs would race the real run's `coverage/.tmp` directory and overwrite the
    // LCOV document the measured-file-set defence is computed from.
    expect(flake.test?.coverage?.enabled).toBe(false);
    // Vitest resolves `root` from the CWD, so an invocation from the repository
    // root would otherwise scan the wrong tree.
    expect(flake.test?.root).toBe(path.join(repoRoot, 'packages', name));
    // Shuffling is what makes a differently-seeded run a different ORDER. It is
    // inherited rather than restated, so assert it survived the spread.
    expect(flake.test?.sequence?.shuffle).toBe(true);
    // And the parallelism the gate claims to inherit. `flake-run.mjs` states
    // "parallelism is inherited, never reduced" as a load-bearing decision, and
    // until this line nothing enforced it: pinning either config to one worker
    // would hide exactly the shared state ten shuffled runs exist to find, while
    // every message the gate prints stayed true.
    expect(flake.test?.fileParallelism).not.toBe(false);
    // The runner names TWO more ways to reduce it — "no pool override, no worker
    // cap" — and in Vitest 4 they are the same key. `poolOptions.forks.singleFork`
    // was the Vitest 3 spelling and it is GONE from this version's config surface
    // entirely (the base config carries a note about the same removal), so a line
    // asserting it stayed undefined guarded a key nothing reads. `maxWorkers` is
    // what caps workers here, and it is pinned to the BASE config's value rather
    // than to `undefined`: that is the "inherited, never reduced" claim stated
    // literally, and it still fails if this leg halves a cap the base config sets.
    expect(flake.test?.maxWorkers).toBe(base.test?.maxWorkers);
    // And never one, which the equality check alone would wave through if the
    // base config were ever pinned and this leg faithfully inherited it.
    expect(flake.test?.maxWorkers).not.toBe(1);
  });

  it('runs the end-to-end flake leg three times per test, with retries pinned off', () => {
    // `repeatEach` is the SAMPLE and `retries: 0` is the verdict: a retried run
    // reports that a test passed eventually, which is precisely what this gate
    // exists to stop anyone claiming. Both are pinned in the config rather than
    // passed as flags, so a future edit of the runner cannot drop them while the
    // gate keeps printing a flake rate.
    expect(flakePlaywrightConfig.repeatEach).toBe(FLAKE_REPEAT_EACH);
    expect(FLAKE_REPEAT_EACH).toBeGreaterThan(1);
    expect(flakePlaywrightConfig.retries).toBe(0);
    // Unconditionally, not `!!process.env.CI`: a stray `.only` would shrink the
    // suite to one test, and three green executions of one test would be reported
    // as a clean sample of two hundred.
    expect(flakePlaywrightConfig.forbidOnly).toBe(true);
    // No `testMatch`: unlike the a11y config, this leg's whole claim is about the
    // suite `test:e2e` runs.
    expect(flakePlaywrightConfig.testMatch).toBeUndefined();

    // Its own JUnit — `junit-e2e.xml` would overwrite the E2E gate's evidence —
    // and no HTML reporter, which would replace `playwright-report/` with this
    // run and send an investigation to the wrong artifact.
    const junit = playwrightReporter('junit', flakePlaywrightConfig);
    expect(junit).toBeDefined();
    expect((junit as { outputFile: string }).outputFile).toBe(
      '.testfortress/reports/junit-flake-e2e.xml',
    );
    expect(playwrightReporter('html', flakePlaywrightConfig)).toBeUndefined();

    // The runner restates the count because it is a `.mjs` file and this is a
    // TypeScript module; the two must agree or the report claims a sample the run
    // did not take.
    const runner = readFileSync(path.join(repoRoot, 'scripts', 'ci', 'flake-run.mjs'), 'utf-8');
    expect(runner).toContain(`const E2E_REPEAT_EACH = ${String(FLAKE_REPEAT_EACH)};`);
  });

  it('actually varies the order it runs in, and actually runs the end-to-end leg', () => {
    const runner = readFileSync(path.join(repoRoot, 'scripts', 'ci', 'flake-run.mjs'), 'utf-8');

    // The pre-flight checks the PLANNED seeds; it cannot see whether they reach
    // vitest. Delete the argument and all ten runs fall back to the config-pinned
    // `sequence.seed` — ten identical orders, a green pre-flight, a green
    // `flake.json`, and the gate measuring one order ten times. This is the line
    // that notices, and it is the same shape as the `E2E_REPEAT_EACH` check below:
    // a constant restated in a `.mjs` runner needs something pinning it.
    expect(runner).toContain('`--sequence.seed=${String(orderSeed)}`');
    expect(runner).toContain('const orderSeedFor = (index) => dataSeed + index;');

    // And the end-to-end half. `failures` spans both halves while `runs` counts
    // only the unit half, so deleting the e2e leg would LOWER `failures` — an
    // apparent improvement — leave `runs` at ten, and pass.
    expect(runner).toContain("runNpm(['run', 'test:flake:e2e']");
    expect(Object.keys(pkg.scripts)).toContain('test:flake:e2e');
  });

  it('measures a flake RATE, and records the sample size beside it', () => {
    // Both fields, in opposite directions, and neither is optional. Without
    // `flake.runs` ratcheting UP, a gate quietly reduced to three runs would
    // report a cleaner bound over less evidence and nothing would object; without
    // `flake.failures` ratcheting DOWN, an observed flake could be accepted into
    // the baseline and stop being a failure at all.
    const ratchet = readFileSync(
      path.join(repoRoot, 'scripts', 'ci', 'ratchet-check.mjs'),
      'utf-8',
    );
    expect(ratchet).toContain("'flake.runs': 'higher'");
    expect(ratchet).toContain("'flake.failures': 'lower'");
    expect(ratchet).toContain("'flake.e2eExecutions': 'higher'");

    // The direction table is necessary and NOT sufficient, and asserting only it
    // would certify a ratchet that guards nothing: `ratchet-check.mjs` iterates
    // the BASELINE's fields, so a direction declared for a field the baseline does
    // not carry is never compared and never even reported as unmeasured.
    //
    // That requirement is asserted HERE as source text and enforced THERE at run
    // time, and the split is load-bearing rather than stylistic. This file is part
    // of the server suite, and `test:flake` runs that suite ten times — so an
    // assertion here that the baseline already carries a flake record would be a
    // postcondition of the run asserting itself mid-run. It would fail in all ten
    // runs, `flake.json` would report ten failures, and `--accept` refuses a
    // failing report: the record could never be written and no change to
    // production code could ever make the gate green. `FLAKE_REQUIRED_FIELDS` is
    // the mutation oracle's answer to the identical bootstrap, and it binds from
    // the first real run: the moment a baseline carries a `flake` block, all three
    // fields are mandatory, and `meta.fields` makes deleting the block a
    // regression in its own right.
    expect(ratchet).toContain('const FLAKE_REQUIRED_FIELDS = [');
    expect(ratchet).toContain("'flake.runs', 'flake.failures', 'flake.e2eExecutions'");
    expect(ratchet).toContain('...(baselineRaw.flake ? FLAKE_REQUIRED_FIELDS : []),');

    // And once the record does exist, its CONTENT is checked — this half is
    // conditional on presence only, never on the numbers, so a sample that shrank
    // or a failure that got normalised into the baseline still turns this red.
    const baseline = JSON.parse(
      readFileSync(path.join(repoRoot, '.testfortress', 'baseline.json'), 'utf-8'),
    ) as { flake?: { runs?: number; failures?: number; e2eExecutions?: number } };
    if (baseline.flake) {
      expect(baseline.flake.runs).toBeGreaterThanOrEqual(10);
      expect(baseline.flake.failures).toBe(0);
      expect(baseline.flake.e2eExecutions).toBeGreaterThan(0);
    }
    // Deferred, conditional on this exact tier — the rule that stops a gate being
    // retired by moving it somewhere it never runs.
    expect(ratchet).toContain("owner: 'test:flake', tier: 2");
    expect(manifest.tasks['test:flake']!.tier).toBe(2);

    // Only the JSON is declared. The per-run JUnit documents are written and read
    // by the gate, but declaring them would make `tests.count` UNMEASURED on
    // every push — the rule that shaped `test:fuzz`.
    expect(reportsOf(manifest.tasks['test:flake']!)).toEqual(['flake.json']);
    const declared = nonComposite.flatMap(([, task]) => reportsOf(task));
    for (const name of ['shared', 'client', 'server', 'e2e']) {
      expect(declared).not.toContain(`junit-flake-${name}.xml`);
    }
    // Its tests all run elsewhere too, so counting them here would ratchet the
    // same suite eleven times over.
    expect(manifest.tasks['test:flake']!.countsTests).toBe(false);
  });

  it('runs the DST gate in the harness-allowlisted zone, and only there', () => {
    // The zone is restated in a `.mjs` runner because it cannot import this
    // TypeScript module; if the two ever disagree the gate reports a zone it did
    // not run in. The harness itself THROWS on any zone outside its allowlist, so
    // a typo fails at the first import rather than quietly running in UTC and
    // reporting a green DST leg.
    const runner = readFileSync(path.join(repoRoot, 'scripts', 'ci', 'dst-gate.mjs'), 'utf-8');
    expect(runner).toContain(`const DST_TZ = '${DST_TZ}';`);
    expect(DST_TZ).not.toBe(PINNED_TZ);
    expect(() => resolveRunTz(DST_TZ)).not.toThrow();

    expect(reportsOf(manifest.tasks['test:dst']!)).toEqual(['dst.json']);
    expect(manifest.tasks['test:dst']!.tier).toBe(2);
    // Every one of its tests also runs on the push tier in UTC.
    expect(manifest.tasks['test:dst']!.countsTests).toBe(false);
  });

  it('runs the accessibility suite from its own config, its own report and its own files', () => {
    // The same contract as every other named subset, in the other runner. Three
    // failure modes are covered together, because they are indistinguishable
    // from the outside: a config that has stopped naming both specs (Playwright
    // errors only when NOTHING matches, so a half-stale `testMatch` shrinks the
    // gate in silence), a config pointed at the E2E gate's JUnit report (which
    // would overwrite the artifact `audit:ratchet:full` reads the headcount
    // from), and an HTML reporter that would overwrite `playwright-report/` with
    // a two-test run.
    expect([...A11Y_SUITE].sort()).toEqual(['a11y-keyboard.spec.ts', 'a11y.spec.ts']);
    for (const file of A11Y_SUITE) {
      expect(existsSync(path.join(repoRoot, 'e2e', file)), file).toBe(true);
    }
    expect(a11yPlaywrightConfig.testMatch).toEqual([...A11Y_SUITE]);

    const junit = playwrightReporter('junit', a11yPlaywrightConfig);
    expect(junit).toBeDefined();
    expect(path.resolve(repoRoot, String(junit!['outputFile']))).toBe(
      path.join(repoRoot, '.testfortress', 'reports', 'junit-a11y.xml'),
    );
    expect(junit!['outputFile']).not.toBe(
      (playwrightReporter('junit', playwrightConfig) ?? {})['outputFile'],
    );
    expect(playwrightReporter('html', a11yPlaywrightConfig)).toBeUndefined();

    // It inherits the E2E harness rather than restating it: the same dev server,
    // the same pinned timezone and locale, the same single worker. A config that
    // quietly grew its own `use` block would be testing a different application
    // from the one every other spec drives.
    expect(a11yPlaywrightConfig.use).toEqual(playwrightConfig.use);
    expect(a11yPlaywrightConfig.webServer).toEqual(playwrightConfig.webServer);
  });

  it('pins WHICH views the accessibility gate scans, and what fails it', () => {
    // The reason this list is pinned rather than merely counted: an axe run over
    // NOTHING reports zero violations, exactly like an axe run over a clean page.
    // Deleting a view therefore makes the gate greener and quieter at the same
    // time, and neither the spec's own completeness check nor the gate's
    // (both of which read this same list) would notice — they would simply agree
    // about a smaller surface. Adding one here is a deliberate act; so is
    // removing one.
    expect([...A11Y_VIEW_IDS]).toEqual([
      'login',
      'register',
      'vault-list',
      'item-detail',
      'item-form-login',
      'item-form-secret',
      'item-form-note',
      'item-form-card',
      'item-form-card-billing',
      'item-form-address-picker',
      'item-form-identity',
      'settings',
      'vault-health',
      'file-encryption',
      'unlock-screen',
    ]);
    // Every id is unique and every view says what state the page is in — the
    // description is what makes a report readable a year later.
    expect(new Set(A11Y_VIEW_IDS).size).toBe(A11Y_VIEW_IDS.length);
    for (const view of A11Y_VIEWS) expect(view.description, view.id).toBeTruthy();
    // The threshold is the gate. Widening it to `moderate` would be a stricter
    // gate; narrowing it to `critical` alone would silently drop colour contrast,
    // missing labels and broken ARIA relationships, which are all `serious`.
    expect([...A11Y_BLOCKING_IMPACTS]).toEqual(['serious', 'critical']);
  });

  it('keeps every re-run subset out of the test headcount, because its files run twice elsewhere', () => {
    // `test:snapshot` and `test:fuzz` join `test:security`, `test:observability`
    // and `test:property` here: every file they name also runs inside
    // `test:unit` / `test:integration`, so counting them would ratchet the same
    // tests twice — and because the field is higher-is-better, nothing would ever
    // complain.
    for (const name of [
      'test:snapshot',
      'test:fuzz',
      'test:a11y',
      'test:upgrade',
      'test:recovery',
    ]) {
      expect(manifest.tasks[name]!.countsTests, `${name}`).toBe(false);
    }
  });

  it('keeps the property gate out of the test headcount, because its files run twice elsewhere', () => {
    // Every property file also runs inside `test:unit` / `test:integration`, and
    // the gate itself runs each of them once per zone. Counting any of that into
    // `tests.count` would ratchet the same tests three times over — and because
    // the field is higher-is-better, nothing would ever complain.
    expect(manifest.tasks['test:property']!.countsTests).toBe(false);
    for (const [name, task] of nonComposite) {
      if (name === 'test:unit' || name === 'test:integration') {
        expect(task.countsTests, `${name} must be counted`).not.toBe(false);
      }
    }
  });

  it.each([
    ['shared', sharedVitestConfig],
    ['server', serverVitestConfig],
    ['client', clientVitestConfig],
  ])('writes Cobertura coverage from the %s suite, beside lcov', (_name, config) => {
    // Patch-coverage tooling reads Cobertura; lcov stays for everything that
    // already consumes it.
    const reporter = config.test?.coverage?.reporter;
    expect(reporter).toContain('cobertura');
    expect(reporter).toContain('lcov');
  });

  it.each([
    ['shared', sharedVitestConfig],
    ['server', serverVitestConfig],
    ['client', clientVitestConfig],
  ])('keeps the human reporter on the %s suite', (_name, config) => {
    // The JUnit reporter replaces vitest's console output when it is the only
    // one configured, which would leave a developer watching a blank terminal.
    expect(config.test?.reporters).toContain('default');
  });

  /**
   * A Playwright reporter entry is either `'html'` or `['html', options]`. Both
   * shapes must be recognised: matching only the array form would make the
   * assertions below pass on a bare `'html'`, which is exactly the configuration
   * that reintroduces the hazard they exist to forbid.
   */
  const playwrightReporter = (
    name: string,
    config: { reporter?: unknown } = playwrightConfig,
  ): Record<string, unknown> | undefined => {
    const configured: unknown = config.reporter;
    const entries: unknown[] = Array.isArray(configured) ? configured : [configured];
    for (const entry of entries) {
      if (entry === name) return {};
      if (Array.isArray(entry) && entry[0] === name) {
        return (entry[1] as Record<string, unknown> | undefined) ?? {};
      }
    }
    return undefined;
  };

  it('writes JUnit XML from the E2E run', () => {
    const junit = playwrightReporter('junit');
    expect(junit).toBeDefined();
    // Playwright resolves a reporter's outputFile against the config directory,
    // so a relative path here is anchored to the repo root, not to the cwd.
    expect(path.resolve(repoRoot, String(junit!['outputFile']))).toBe(
      path.join(repoRoot, '.testfortress', 'reports', 'junit-e2e.xml'),
    );
  });

  it('never lets the E2E HTML reporter open a browser', () => {
    // The default is `on-failure`, which launches a browser and hangs a git hook
    // forever — the reason the gate used to override the reporters on the CLI.
    // This must NOT be written as `if (html) expect(...)`: a bare `'html'` entry,
    // or a rename, would then satisfy it while the hazard is fully restored.
    // `process.env.CI` is the only legitimate condition, because the config
    // selects a different reporter set there (and this suite runs with it unset).
    const html = playwrightReporter('html');
    if (process.env['CI']) {
      expect(html, 'the CI branch configures no HTML reporter').toBeUndefined();
    } else {
      expect(html, 'the local branch must still configure an HTML reporter').toBeDefined();
      expect(html!['open']).toBe('never');
    }
  });
});

describe('ESLint SARIF conversion', () => {
  const results = [
    {
      filePath: path.join(repoRoot, 'packages/shared/src/example.ts'),
      messages: [
        {
          ruleId: '@typescript-eslint/no-explicit-any',
          severity: 2,
          message: 'Unexpected any.',
          line: 1,
          column: 21,
          endLine: 1,
          endColumn: 24,
        },
        {
          ruleId: '@typescript-eslint/no-unused-vars',
          severity: 1,
          message: 'Unused.',
          line: 2,
          column: 7,
        },
      ],
    },
  ];

  const onlyRun = (log: ReturnType<typeof toSarif>) => log.runs[0]!;

  it('maps ESLint severities onto SARIF levels', () => {
    const sarif = toSarif(results, { rootDir: repoRoot });
    expect(onlyRun(sarif).results.map((entry) => entry.level)).toEqual(['error', 'warning']);
    expect(countLevels(sarif)).toEqual({ error: 1, warning: 1, note: 0 });
  });

  it('records repo-relative locations, because an absolute one resolves nowhere else', () => {
    const sarif = toSarif(results, { rootDir: repoRoot });
    const location = onlyRun(sarif).results[0]!.locations[0]!.physicalLocation;
    expect(location.artifactLocation.uri).toBe('packages/shared/src/example.ts');
    expect(location.artifactLocation.uriBaseId).toBe('%SRCROOT%');
    expect(location.region).toEqual({
      startLine: 1,
      startColumn: 21,
      endLine: 1,
      endColumn: 24,
    });
  });

  it('lists each rule once and indexes every result at it', () => {
    const twice = [results[0]!, results[0]!];
    const run = onlyRun(toSarif(twice, { rootDir: repoRoot }));
    expect(run.tool.driver.rules.map((rule) => rule.id)).toEqual([
      '@typescript-eslint/no-explicit-any',
      '@typescript-eslint/no-unused-vars',
    ]);
    // Four findings over two rules: the index must still point at the rule that
    // produced each one, or a consumer attributes findings to the wrong rule.
    expect(run.results).toHaveLength(4);
    for (const entry of run.results) {
      expect(run.tool.driver.rules[entry.ruleIndex!]!.id).toBe(entry.ruleId);
    }
  });

  it('keeps a fatal parse error, which carries no rule at all', () => {
    const run = onlyRun(
      toSarif(
        [
          {
            filePath: path.join(repoRoot, 'packages/shared/src/broken.ts'),
            messages: [{ ruleId: null, severity: 2, message: 'Parsing error: x', fatal: true }],
          },
        ],
        { rootDir: repoRoot },
      ),
    );
    expect(run.results[0]!.level).toBe('error');
    // A ruleIndex pointing into an empty rule list is invalid SARIF, so both are
    // omitted together rather than one of them being invented.
    expect(run.results[0]!.ruleId).toBeUndefined();
    expect(run.results[0]!.ruleIndex).toBeUndefined();
    expect(run.tool.driver.rules).toHaveLength(0);
  });
});
