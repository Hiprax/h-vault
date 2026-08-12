#!/usr/bin/env node
/**
 * The pipeline. It runs on this machine, before `git push`, instead of on a
 * hosted runner after it.
 *
 * Every gate below is one job or step from the GitHub Actions workflow this
 * replaced, and each carries a `ci:` note naming what it stands in for — so the
 * next person can see at a glance that nothing was quietly dropped when the
 * workflow was deleted. Two gates (`secrets`, `format`) have no CI ancestor at
 * all; they are cheap, they catch things the old pipeline did not, and running
 * locally is what made them affordable.
 *
 *   npm run ci                      run everything (this is what pre-push runs)
 *   npm run ci -- --list            show the gates and what each replaces
 *   npm run ci -- --only=lint,test  run a subset
 *   npm run ci -- --bail            stop at the first failure
 *
 * Three escape hatches exist, and they are documented in CONTRIBUTING.md under
 * "Escape hatches" rather than here. That is deliberate: this file DEFINES the
 * gates, and a ready-to-paste bypass command sitting in it is indistinguishable
 * — to a reader and to the integrity scan alike — from a gate documenting how to
 * defeat itself. The hatches themselves are unchanged; only the copy moved.
 *
 * A gate exits 78 to report itself SKIPPED rather than passed — used when the
 * tooling it needs is genuinely absent (see sast-gate.mjs). A skip is always
 * printed in the summary; the one thing this runner will not do is quietly
 * pretend a check ran.
 *
 * ---------------------------------------------------------------------------
 * Tiers, aggregation, reports
 * ---------------------------------------------------------------------------
 *
 *   npm run verify:fast             T0 only — under 90 seconds
 *   npm run ci                      T0 + T1 — the whole push gate
 *   npm run verify:full             T0 + T1 + T2 — before a release
 *
 * Every gate carries a `tier`, and the same tier is declared for the same task
 * in `.testfortress/verify.json`. The two are cross-checked on every run and a
 * disagreement is a hard "could not run": a manifest that has stopped describing
 * reality is worse than none, because everything reading it still believes it.
 *
 * The runner AGGREGATES by default: every selected gate runs, every failure is
 * reported, and only then does it exit non-zero. Stopping at the first failure
 * costs a round trip per failure. `--bail` restores fail-fast. A gate whose
 * `dependsOn` gate failed is reported SKIPPED rather than run, because a broken
 * build cannot teach anyone anything new by also failing the type-check, the
 * tests and six minutes of E2E.
 *
 * Exit codes are a contract, not decoration:
 *
 *   0   every selected gate passed (or legitimately skipped)
 *   1   at least one gate FAILED — the code is broken
 *   2   no gate failed, but at least one COULD NOT RUN (missing prerequisite,
 *       manifest drift, an unknown gate id, a gate that passed without writing
 *       the report it declares). The verdict is unknown, which is a different
 *       problem from a known-bad one, and an agent must be able to tell them
 *       apart.
 *
 *   npm run ci -- --json            one JSON document on stdout, nothing else
 *
 * Note that `npm run` prints its own two-line banner to stdout before the script
 * starts, so a machine consumer wants `npm run --silent ci -- --json`, or
 * `node scripts/ci/local-ci.mjs --json`, or simply
 * `.testfortress/reports/summary.json`, which every run writes regardless.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { runNpm, runExe, repoRoot, hasExe } from './lib/proc.mjs';
import {
  color,
  symbol,
  heading,
  stepStart,
  note,
  warn,
  summary,
  formatDuration,
} from './lib/ui.mjs';
import {
  TIER_SELECTOR,
  blockingDependency,
  resolveExitCode,
  resolveTiers,
  selectGates,
} from './lib/tiers.mjs';
import {
  MANIFEST_REL,
  clearReports,
  ensureReportDir,
  loadManifest,
  missingReports,
  reportList,
  reportPath,
  validateManifest,
  writeJsonReport,
} from './lib/reports.mjs';

const SKIP_EXIT = 78;
const EXIT_FAILED = 1;
const EXIT_CANNOT_RUN = 2;

const pkg = JSON.parse(readFileSync(path.join(repoRoot, 'package.json'), 'utf8'));

/**
 * Enforces the Node floor the project actually supports.
 *
 * This is what remains of the old Node 22 + 24 CI matrix. The matrix itself is
 * not reproduced: the repo pins Node 24 (.nvmrc, `node:24-alpine3.23` in every
 * production image), and `engines.node` was tightened to `>=24` to match — so the
 * old 22 leg tested a runtime nothing here ships on, and standing a second
 * toolchain up on every push would cost more than it defends. Enforcing `engines`
 * keeps the floor honest.
 *
 * It returns its transcript as well as its exit code: this gate runs in-process,
 * so there is no child output to tee, and without the transcript it would be the
 * one gate that declares a report it cannot write.
 */
function checkEngines() {
  const lines = [];
  const record = (text, render) => {
    lines.push(text);
    render(text);
  };

  const range = pkg.engines?.node ?? '';
  const required = /^>=\s*(\d+)\.(\d+)\.(\d+)$/.exec(range);
  if (!required) {
    record(`cannot interpret engines.node (${range}) — skipping the version check`, warn);
    return { code: 0, output: lines.join('\n') };
  }

  const current = process.versions.node.split('.').map(Number);
  const floor = [Number(required[1]), Number(required[2]), Number(required[3])];
  const below =
    current[0] < floor[0] ||
    (current[0] === floor[0] && current[1] < floor[1]) ||
    (current[0] === floor[0] && current[1] === floor[1] && current[2] < floor[2]);

  if (below) {
    const message = `Node ${process.versions.node} is below the required ${range}`;
    lines.push(message);
    console.error(color.red(`      ${message}`));
    return { code: 1, output: lines.join('\n') };
  }
  record(`Node ${process.versions.node} satisfies ${range}`, note);

  try {
    const pinned = readFileSync(path.join(repoRoot, '.nvmrc'), 'utf8').trim();
    if (pinned && Number(pinned.split('.')[0]) !== current[0]) {
      record(
        `.nvmrc pins Node ${pinned}, you are on ${process.versions.node} — production images use Node ${pinned}`,
        warn,
      );
    }
  } catch {
    // No .nvmrc is not an error.
  }
  return { code: 0, output: lines.join('\n') };
}

/**
 * Prerequisites a gate needs from the WORLD rather than from the code.
 *
 * Declared per gate and checked immediately before it runs, so the runner can
 * say "docker is not on PATH" instead of letting the gate fail with a connection
 * error that reads like a code bug — the failure mode that gets a gate deleted.
 */
const PREREQUISITES = {
  docker: {
    label: 'the docker CLI',
    ok: () => hasExe('docker', ['version', '--format', '{{.Client.Version}}']),
    fix: 'start Docker — or, if you cannot, see "Escape hatches" in CONTRIBUTING.md',
  },
  'build:shared': {
    label: 'a built @hvault/shared (packages/shared/dist)',
    ok: () => {
      try {
        readFileSync(path.join(repoRoot, 'packages', 'shared', 'dist', 'index.d.ts'));
        return true;
      } catch {
        return false;
      }
    },
    // T0 deliberately excludes `build` (18 s of an 82 s budget), so verify:fast
    // consumes the shared build rather than producing it. `npm run ci` runs the
    // build gate first and satisfies this on its own.
    fix: 'npm run build:shared',
  },
};

// `canSkip` marks the only gate allowed to report itself SKIPPED via exit 78.
// The sentinel is honoured from that gate ALONE: if some other tool (npm,
// vitest, eslint) ever happened to exit 78 (EX_CONFIG), an unmarked gate treats
// it as the failure it is, not as a skip — so a real failure can never
// masquerade as "tooling unavailable" and let a broken push through.
//
// `task` is the canonical name this gate implements, and it is the key that ties
// the gate to its entry in `.testfortress/verify.json`. `log` is where the gate's
// transcript is teed; when a gate's declared report IS that transcript, the two
// names are the same file.
/** @type {{id: string, task: string, tier: 0|1|2, title: string, ci: string, log?: string,
 *          dependsOn?: string[], requires?: string[], canSkip?: boolean,
 *          run: (options: {logFile: string, sink: NodeJS.WritableStream}) =>
 *            Promise<number|{code: number, output: string}> | number | {code: number, output: string}}[]} */
const GATES = [
  {
    id: 'engines',
    task: 'engines',
    tier: 0,
    title: 'Node version',
    ci: 'replaces the Node 22/24 matrix floor',
    run: checkEngines,
  },
  {
    id: 'secrets',
    task: 'audit:secrets',
    tier: 0,
    title: 'Secret scan (all tracked files)',
    ci: 'new — the old pipeline never scanned the repo',
    run: (options) => runExe(process.execPath, ['scripts/ci/secret-scan.mjs', '--report'], options),
  },
  {
    id: 'build',
    task: 'build',
    tier: 1,
    title: 'Build (shared → server → client)',
    ci: 'ci job · Build',
    run: (options) => runNpm(['run', 'build'], options),
  },
  {
    id: 'lint',
    task: 'lint',
    tier: 0,
    title: 'Lint (ESLint + eslint-plugin-security)',
    ci: 'ci job · Lint  +  sast job (static analysis baseline)',
    run: (options) => runNpm(['run', 'lint:report'], options),
  },
  {
    id: 'format',
    task: 'format:check',
    tier: 0,
    title: 'Format check (Prettier)',
    ci: 'new — pre-commit only formatted files it happened to see',
    log: 'format.log',
    run: (options) => runNpm(['run', 'format:check'], options),
  },
  {
    id: 'type-check',
    task: 'typecheck',
    tier: 0,
    title: 'Type check (all packages)',
    ci: 'ci job · Type check',
    log: 'tsc.log',
    dependsOn: ['build'],
    requires: ['build:shared'],
    run: (options) => runNpm(['run', 'type-check'], options),
  },
  {
    id: 'integrity',
    task: 'audit:integrity',
    tier: 0,
    title: 'Integrity scan (markers vs the suppression ledger)',
    ci: 'new — no hosted pipeline ever checked whether a gate had been weakened',
    run: (options) => runExe(process.execPath, ['scripts/ci/integrity-scan.mjs'], options),
  },
  {
    id: 'ratchet',
    task: 'audit:ratchet',
    tier: 0,
    // Registered immediately after `integrity`, and that position in this array
    // is load-bearing rather than cosmetic: gates run in array order, the cheap
    // tier's numbers come from the report the scan has just written, and moving
    // this above `integrity` would have it read the PREVIOUS run's artifact —
    // which the ratchet would then reject as stale, correctly but confusingly.
    title: 'Ratchet (cheap fields: suppressions, fingerprints, task list)',
    ci: 'new — nothing stopped a threshold from being lowered to reach green',
    run: (options) =>
      runExe(process.execPath, ['scripts/ci/ratchet-check.mjs', '--tier', '0'], options),
  },
  {
    id: 'test',
    task: 'test:unit',
    tier: 1,
    title: 'Unit tests + coverage thresholds (shared, client)',
    ci: 'ci job · Test (the hermetic half)',
    dependsOn: ['build'],
    requires: ['build:shared'],
    run: (options) => runNpm(['run', 'test:unit'], options),
  },
  {
    id: 'test-integration',
    task: 'test:integration',
    tier: 1,
    title: 'Integration tests + coverage thresholds (server, real mongod)',
    ci: 'ci job · Test (the half that spawns a database)',
    dependsOn: ['build'],
    requires: ['build:shared'],
    run: (options) => runNpm(['run', 'test:integration'], options),
  },
  {
    id: 'audit',
    task: 'audit:deps',
    tier: 1,
    title: 'Dependency audit (production)',
    ci: 'ci job · Audit production dependencies',
    log: 'deps.log',
    run: (options) => runNpm(['run', 'audit:prod'], options),
  },
  {
    id: 'e2e',
    task: 'test:e2e',
    tier: 1,
    title: 'E2E (Playwright, Chromium)',
    ci: 'e2e job',
    dependsOn: ['build'],
    requires: ['build:shared'],
    // --forbid-only mirrors the CI config's `forbidOnly: !!process.env.CI`, but CI
    // is deliberately NOT set: that would also flip `reuseExistingServer` off and
    // make the gate fail outright whenever a dev server already holds the client
    // dev port (5173 by default — see vite.config.helpers' resolveDevPort).
    // The reporters come from playwright.config.ts, which pairs `list` with the
    // JUnit report this gate declares and pins the HTML reporter to `open:
    // 'never'` — the default would launch a browser on failure and hang the hook.
    //
    // There is deliberately NO `--retries` flag here. A retry turns a flaky test
    // into a green one, which is the same as deleting the bug report it was: the
    // two genuine failures this gate's former retry count concealed are recorded
    // in e2e/helpers.ts. A spec that only passes on the second attempt is telling
    // you something about the code or the harness, and the gate's job is to let
    // it.
    run: (options) => runNpm(['run', 'test:e2e', '--', '--forbid-only'], options),
  },
  {
    id: 'docker',
    task: 'audit:image',
    tier: 1,
    title: 'Container build + compose + Nginx config',
    ci: 'docker-build job · image builds, nginx -t, compose config',
    requires: ['docker'],
    run: (options) => runExe(process.execPath, ['scripts/ci/docker-gate.mjs'], options),
  },
  {
    id: 'sast',
    task: 'audit:sast',
    tier: 1,
    title: 'SAST (CodeQL security-and-quality)',
    ci: 'sast job · CodeQL',
    canSkip: true, // exits 78 when the CodeQL CLI is not installed
    run: (options) => runExe(process.execPath, ['scripts/ci/sast-gate.mjs'], options),
  },
  {
    id: 'ratchet-full',
    task: 'audit:ratchet:full',
    tier: 1,
    // LAST on purpose. It compares every measured field — coverage
    // denominators, the measured file set, test counts, warning counts — and
    // every one of those artifacts is produced by a gate above it. Run earlier,
    // it would be reading the previous run's numbers about a tree that has since
    // changed, which is precisely what its own freshness rule exists to reject.
    title: 'Ratchet (every measured field, against baseline.json)',
    ci: 'new — a percentage whose denominator can shrink is not a gate',
    dependsOn: ['build', 'test', 'test-integration'],
    run: (options) => runNpm(['run', 'audit:ratchet:full'], options),
  },
];

// ---------------------------------------------------------------------------
// Argument / environment handling
// ---------------------------------------------------------------------------

const args = process.argv.slice(2);
const flag = (name) => args.some((arg) => arg === `--${name}`);
const value = (name) => {
  const found = args.find((arg) => arg.startsWith(`--${name}=`));
  return found ? found.slice(name.length + 3) : '';
};

const asList = (raw) =>
  raw
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);

const only = asList(value('only'));
const skip = new Set([...asList(value('skip')), ...asList(process.env['HVAULT_SKIP_GATES'] ?? '')]);
// Aggregation is now the default, so the old `--continue` asks for what already
// happens. It is still accepted and ignored rather than rejected, because it is
// in people's shell history and failing a run over a redundant flag helps nobody.
const bail = flag('bail');
const asJson = flag('json');
const isHook = value('hook') !== '';

// In --json mode stdout carries exactly one thing: the JSON document. Every
// human line — this runner's own and every child's — is redirected to stderr,
// which keeps the run watchable without corrupting the payload.
const sink = asJson ? process.stderr : process.stdout;
if (asJson) {
  console.log = console.error;
}

const tierArg = value('tier') || '1';
const tiers = resolveTiers(tierArg);

const fatal = (lines) => {
  for (const line of lines) console.error(color.red(line));
  process.exit(EXIT_CANNOT_RUN);
};

if (!tiers) {
  fatal([`Unknown tier: ${tierArg}`, `Known tiers: ${Object.keys(TIER_SELECTOR).join(', ')}`]);
}

const unknown = [...only, ...skip].filter((id) => !GATES.some((gate) => gate.id === id));
if (unknown.length > 0) {
  fatal([
    `Unknown gate(s): ${unknown.join(', ')}`,
    color.gray(`Known gates: ${GATES.map((gate) => gate.id).join(', ')}`),
  ]);
}

// `--list --json` reports the runner's OWN gate table and reads no manifest.
// That independence is the point: it is the other half of the drift check, so
// whatever compares the two — a person, a test — is comparing two sources and
// not one source with itself.
if (flag('list') && asJson) {
  process.stdout.write(
    `${JSON.stringify(
      GATES.map((gate) => ({
        id: gate.id,
        task: gate.task,
        tier: gate.tier,
        title: gate.title,
        ci: gate.ci,
        canSkip: gate.canSkip === true,
        dependsOn: gate.dependsOn ?? [],
        requires: gate.requires ?? [],
        log: gate.log ?? `${gate.id}.log`,
      })),
      null,
      2,
    )}\n`,
  );
  process.exit(0);
}

// ---------------------------------------------------------------------------
// The manifest is load-bearing: it is checked, not merely shipped
// ---------------------------------------------------------------------------

const { manifest, error: manifestError } = loadManifest();
if (manifestError) fatal([`${symbol.fail} ${manifestError}`]);

const manifestProblems = validateManifest(manifest, GATES);
if (manifestProblems.length > 0) {
  fatal([
    `${symbol.fail} ${MANIFEST_REL} and the gate table disagree:`,
    ...manifestProblems.map((problem) => `  - ${problem}`),
  ]);
}

/** The manifest owns the gate criterion and the declared report; the gate owns how to run it. */
const taskOf = (gate) => manifest.tasks[gate.task];
const reportsOf = (gate) => reportList(taskOf(gate).report);
const logOf = (gate) => gate.log ?? `${gate.id}.log`;

if (flag('list')) {
  console.log(color.bold('\n  Local pipeline gates\n'));
  for (const gate of GATES) {
    console.log(
      `  ${color.cyan(gate.id.padEnd(17))} ${color.gray(`T${String(gate.tier)}`)}  ${gate.title}`,
    );
    console.log(`  ${' '.repeat(17)}     ${color.gray(gate.ci)}`);
    console.log(
      `  ${' '.repeat(17)}     ${color.gray(`${gate.task} → ${reportsOf(gate).join(', ')}`)}\n`,
    );
  }
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

const selected = selectGates(GATES, { only, tiers });

ensureReportDir();
for (const gate of selected) {
  // Reports from an earlier run would make "did this gate write its report?"
  // pass for a gate that wrote nothing.
  clearReports([...reportsOf(gate), logOf(gate)]);
}

heading(
  isHook
    ? 'Local pipeline (pre-push) — this replaces GitHub Actions CI'
    : 'Local pipeline — this replaces GitHub Actions CI',
);
note(
  `${only.length > 0 ? `only ${only.join(', ')}` : `tier ${tiers.map((tier) => `T${String(tier)}`).join(' + ')}`} · ${bail ? 'bail' : 'aggregate'}`,
);
if (isHook) {
  // A pointer, not a paste-ready bypass. Someone who genuinely cannot run a gate
  // will read three lines of CONTRIBUTING.md; someone looking for the quickest
  // way past a red gate should not be handed it by the gate runner itself.
  note('a gate you genuinely cannot run: see "Escape hatches" in CONTRIBUTING.md');
}

const results = [];
const started = Date.now();
const statusOf = (id) => results.find((result) => result.id === id)?.status;

/** Canonical task names whose artifacts this run has produced, in order. */
const completed = [];

const record = (gate, status, durationMs, detail) => {
  results.push({ id: gate.id, task: gate.task, status, durationMs, detail });
  // A gate that ran and FAILED measured its subject just as truly as one that
  // passed; a skipped or unrunnable one measured nothing.
  if (status === 'pass' || status === 'fail') completed.push(gate.task);
};

for (const [index, gate] of selected.entries()) {
  if (skip.has(gate.id)) {
    record(gate, 'skip', 0, 'HVAULT_SKIP_GATES');
    continue;
  }

  // Only a dependency that actually BROKE cascades. A dependency the operator
  // skipped on purpose (`HVAULT_SKIP_GATES=build`, because they just built) must
  // not silently take four more gates down with it — the `requires` check below
  // is what catches a build that is genuinely missing.
  const brokenDependency = blockingDependency(gate.dependsOn ?? [], statusOf);
  if (brokenDependency) {
    record(gate, 'skip', 0, `not reached — ${brokenDependency} did not pass`);
    continue;
  }

  const unmet = (gate.requires ?? []).filter((name) => !PREREQUISITES[name]?.ok());
  if (unmet.length > 0) {
    const first = PREREQUISITES[unmet[0]];
    stepStart(index + 1, selected.length, gate.title);
    console.error(color.red(`      cannot run: ${gate.id} needs ${first.label}`));
    note(`fix: ${first.fix}`);
    record(gate, 'error', 0, `missing prerequisite: ${unmet.join(', ')}`);
    if (bail) break;
    continue;
  }

  stepStart(index + 1, selected.length, gate.title);
  note(gate.ci);

  const gateStarted = Date.now();
  const outcome = await gate.run({
    logFile: reportPath(logOf(gate)),
    sink,
    // Which canonical tasks have already produced an artifact IN THIS RUN.
    // `report.mjs` needs it because it decides "was this measured?" from
    // `summary.json`, which is only written once the run has finished — so a
    // gate that runs report generation mid-run (`audit:ratchet:full`) would
    // otherwise be judging this run's fresh artifacts against the PREVIOUS
    // run's list of what ran, and on a first-ever run against no list at all.
    env: { HVAULT_COMPLETED_TASKS: completed.join(',') },
  });
  const durationMs = Date.now() - gateStarted;
  const code = typeof outcome === 'number' ? outcome : outcome.code;
  // An in-process gate has no child to tee, so it hands back its transcript.
  if (typeof outcome === 'object') {
    writeTranscript(gate, outcome.output);
  }

  if (code === SKIP_EXIT && gate.canSkip) {
    record(gate, 'skip', durationMs, 'tooling unavailable');
    continue;
  }

  const missing = missingReports(reportsOf(gate));

  if (code !== 0) {
    record(gate, 'fail', durationMs, `exit ${String(code)}`);
    console.log(
      color.red(`\n  ${symbol.fail} ${gate.id} failed after ${formatDuration(durationMs)}`),
    );
    if (missing.length > 0)
      note(`(no ${missing.join(', ')} written — the gate did not get that far)`);
    if (bail) break;
    continue;
  }

  // A gate that passes without leaving the evidence it declares is not a gate
  // anything downstream can check, so it is "could not run", never a pass.
  if (missing.length > 0) {
    record(gate, 'error', durationMs, `passed but wrote no ${missing.join(', ')}`);
    console.error(
      color.red(
        `\n  ${symbol.fail} ${gate.id} passed but wrote no ${missing.join(', ')} — its report contract is broken`,
      ),
    );
    if (bail) break;
    continue;
  }

  record(gate, 'pass', durationMs);
  console.log(color.green(`  ${symbol.pass} ${gate.id} passed in ${formatDuration(durationMs)}`));
}

// Gates never reached because an earlier one failed are reported, not omitted.
for (const gate of selected) {
  if (!results.some((result) => result.id === gate.id)) {
    results.push({
      id: gate.id,
      task: gate.task,
      status: 'skip',
      durationMs: 0,
      detail: 'not reached',
    });
  }
}

const durationMs = Date.now() - started;
const exitCode = resolveExitCode(results);

const payload = {
  version: 1,
  runner: 'scripts/ci/local-ci.mjs',
  startedAt: new Date(started).toISOString(),
  durationMs,
  tiers,
  bail,
  exitCode,
  counts: {
    pass: results.filter((result) => result.status === 'pass').length,
    fail: results.filter((result) => result.status === 'fail').length,
    skip: results.filter((result) => result.status === 'skip').length,
    error: results.filter((result) => result.status === 'error').length,
  },
  tasks: selected.map((gate) => {
    const result = results.find((entry) => entry.id === gate.id);
    return {
      task: gate.task,
      id: gate.id,
      status: result.status,
      durationMs: result.durationMs,
      gate: taskOf(gate).gate,
      report: reportsOf(gate).map((name) => `${manifest.reportDir}/${name}`),
      summary: result.detail ?? `exit 0 in ${formatDuration(result.durationMs)}`,
    };
  }),
};

writeJsonReport('summary.json', payload);
// The warning counts are derived from the artifacts this run just produced, so
// they are generated after it, not by it.
await import('./report.mjs');

summary(results);
console.log(color.gray(`  total ${formatDuration(durationMs)}\n`));

if (asJson) {
  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
}

if (exitCode === EXIT_FAILED) {
  console.error(color.red(`${symbol.fail} Pipeline failed — push aborted.\n`));
  process.exit(EXIT_FAILED);
}
if (exitCode === EXIT_CANNOT_RUN) {
  console.error(color.red(`${symbol.fail} Pipeline could not run every gate — verdict unknown.\n`));
  process.exit(EXIT_CANNOT_RUN);
}

console.log(color.green(`${symbol.pass} Pipeline passed.\n`));

/** In-process gates hand back their output; give it the same transcript file a child would get. */
function writeTranscript(gate, output) {
  writeFileSync(reportPath(logOf(gate)), `${output}\n`, 'utf8');
}
