#!/usr/bin/env node
/**
 * `verify:selftest` — proves that every registered gate can still FAIL.
 *
 * A gate nobody has seen fail is indistinguishable from a gate that cannot.
 * This runner plants exactly one defect per task in `.testfortress/verify.json`,
 * runs that task's real command against the planted tree, and requires a
 * non-zero exit that is ATTRIBUTABLE to the defect. Then it restores.
 *
 *   node scripts/ci/selftest.mjs                    every registered task
 *   node scripts/ci/selftest.mjs --only=lint,build  a subset
 *   node scripts/ci/selftest.mjs --json             the report on stdout
 *   node scripts/ci/selftest.mjs --list             what would be planted
 *
 * Exit codes: 0 = every case proved · 1 = a gate did not fail when it should
 * have · 2 = could not run (a task with no defect case, a missing prerequisite,
 * a workspace that could not be prepared).
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. THE CATALOG IS A PER-TASK REGISTRY, NOT A LIST INSIDE THIS FILE. It lives
 *     in `lib/selftest-defects.mjs`, and a registered task with no entry is a
 *     hard error that names the task. Nine later phases register new gate types;
 *     without this rule the final "every gate can fail" check would either fail
 *     mysteriously or silently shrink to the subset that existed on the day this
 *     was written, reporting confidence it did not earn.
 *
 *  b. THE DEFECT IS PLANTED IN A TEMPORARY COPY, NEVER IN THE WORKING TREE. The
 *     copy is built from `git ls-files --cached --others --exclude-standard`,
 *     the same enumeration the integrity scanner uses, because nothing here is
 *     ever staged: a `git worktree` of HEAD would be missing every uncommitted
 *     file, which is most of the gate surface itself. `node_modules` is
 *     symlinked (it is 600 MB and read-only for these purposes) while
 *     `packages/shared/dist` is COPIED, because the `build` gate writes into it
 *     and a symlink would carry that write back into the real checkout.
 *
 *  c. A NON-ZERO EXIT IS NOT ENOUGH; the failure must be attributable. A gate
 *     that is already red for an unrelated reason would otherwise "prove" itself
 *     while proving nothing, so each case declares an `evidence` predicate over
 *     the gate's own report or transcript.
 *
 *  d. EXIT 78 IS NOT A FAILURE. It is this pipeline's SKIPPED sentinel, so a
 *     gate that skips has not been shown to fail, and the case is unproven.
 */
import { execFileSync, spawnSync } from 'node:child_process';
import {
  copyFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, sep } from 'node:path';
import { hasExe } from './lib/proc.mjs';
import { DEFECTS } from './lib/selftest-defects.mjs';

const ROOT = process.cwd();
const MANIFEST = join(ROOT, '.testfortress', 'verify.json');
const REPORT_DIR = join(ROOT, '.testfortress', 'reports');

const EXIT_PROVEN = 0;
const EXIT_UNPROVEN = 1;
const EXIT_CANNOT_RUN = 2;
const SKIP_EXIT = 78;

const argv = process.argv.slice(2);
const flag = (name) => argv.includes(`--${name}`);
const value = (name) => {
  const found = argv.find((a) => a.startsWith(`--${name}=`));
  return found ? found.slice(name.length + 3) : '';
};
const only = value('only')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
const asJson = flag('json');
const log = (...args) => {
  if (!asJson) console.log(...args);
  else console.error(...args);
};

const fatal = (msg) => {
  console.error(`selftest: ${msg}`);
  process.exit(EXIT_CANNOT_RUN);
};

const posix = (p) => p.split(sep).join('/');

// ---------------------------------------------------------------------------
// prerequisites a case needs from the world
//
// Host binaries are probed through `hasExe`, the same helper `local-ci.mjs`'s
// own PREREQUISITES table uses. One idiom for "is this tool on the machine?",
// in one place that knows how spawning differs on Windows — and the three
// probes below no longer restate it three times.
// ---------------------------------------------------------------------------
const PREREQUISITES = {
  docker: {
    label: 'the docker CLI',
    ok: () => hasExe('docker', ['version']),
  },
  actionlint: {
    label: 'the actionlint binary',
    ok: () => hasExe('actionlint', ['-version']),
  },
  hadolint: {
    label: 'the hadolint binary',
    ok: () => hasExe('hadolint', ['--version']),
  },
  codeql: {
    label: 'a usable CodeQL CLI',
    ok: () => {
      const cli = join(ROOT, '.cache', 'codeql', 'codeql', 'codeql');
      if (!existsSync(cli)) return false;
      return spawnSync(cli, ['version'], { stdio: 'ignore' }).status === 0;
    },
  },
};

// ---------------------------------------------------------------------------
// the tasks under test
// ---------------------------------------------------------------------------
if (!existsSync(MANIFEST)) fatal(`${relative(ROOT, MANIFEST)} is missing`);
const manifest = JSON.parse(readFileSync(MANIFEST, 'utf8'));
const registered = Object.entries(manifest.tasks ?? {})
  .filter(([, task]) => task?.composite !== true)
  .map(([name, task]) => ({ name, ...task }));

// (a) A registered gate with no defect case is a hard error naming it. This is
// the check Phase 20 relies on, and it must fire before anything is planted.
const uncovered = registered.filter((t) => !DEFECTS[t.name]).map((t) => t.name);
if (uncovered.length > 0) {
  fatal(
    `no defect-injection case for registered task(s): ${uncovered.join(', ')}. ` +
      'Add one to scripts/ci/lib/selftest-defects.mjs beside the gate it proves — ' +
      'a gate nobody has seen fail is indistinguishable from a gate that cannot.',
  );
}

const selected = registered.filter((t) => only.length === 0 || only.includes(t.name));
const unknown = only.filter((n) => !registered.some((t) => t.name === n));
if (unknown.length > 0) fatal(`unknown task(s): ${unknown.join(', ')}`);

if (flag('list')) {
  for (const task of selected) {
    console.log(`${task.name.padEnd(22)} ${DEFECTS[task.name].title}`);
  }
  process.exit(0);
}

// ---------------------------------------------------------------------------
// (b) the temp copy
// ---------------------------------------------------------------------------
function trackedAndUntracked() {
  return execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], {
    cwd: ROOT,
    maxBuffer: 128 << 20,
  })
    .toString('utf8')
    .split('\0')
    .filter(Boolean);
}

function prepareWorkspace() {
  const dir = mkdtempSync(join(tmpdir(), 'hvault-selftest-'));
  for (const rel of trackedAndUntracked()) {
    const from = join(ROOT, rel);
    if (!existsSync(from)) continue;
    const to = join(dir, rel);
    mkdirSync(dirname(to), { recursive: true });
    copyFileSync(from, to);
  }
  // Dependencies are shared by symlink; they are large and nothing here writes
  // to them. Build OUTPUT is copied instead, because `build` writes into it.
  for (const rel of [
    'node_modules',
    'packages/shared/node_modules',
    'packages/server/node_modules',
    'packages/client/node_modules',
  ]) {
    const from = join(ROOT, rel);
    if (existsSync(from) && !existsSync(join(dir, rel))) {
      mkdirSync(dirname(join(dir, rel)), { recursive: true });
      symlinkSync(from, join(dir, rel), 'dir');
    }
  }
  // Build OUTPUT, copied for two different reasons. `packages/shared/dist` is
  // written by the `build` gate, so a symlink would carry that write back into
  // the real checkout. The server and client bundles are the SUBJECT of
  // `test:smoke`, which runs the emitted JavaScript rather than the sources: a
  // workspace without them makes that gate exit "no built artifact", which is a
  // non-zero exit that has nothing to do with the planted defect — and a case
  // that cannot be attributed proves nothing. All three are gitignored, so the
  // `git ls-files` enumeration above never sees them.
  for (const rel of [
    join('packages', 'shared', 'dist'),
    join('packages', 'server', 'dist'),
    join('packages', 'client', 'dist'),
  ]) {
    const from = join(ROOT, rel);
    if (existsSync(from)) cpSync(from, join(dir, rel), { recursive: true });
  }
  // The gate surface's own artifacts are gitignored, so the enumeration above
  // does not carry them — and two gates COMPARE against them (`audit:ratchet`
  // reads the integrity report, `audit:ratchet:full` reads coverage and JUnit).
  // A workspace without them would fail both for a reason that has nothing to
  // do with the planted defect, which is the opposite of what this proves.
  // Copied LAST so they are the newest files in the tree, which is what the
  // ratchet's freshness rule requires of a report.
  for (const rel of [
    '.testfortress/reports',
    'packages/shared/coverage',
    'packages/server/coverage',
    'packages/client/coverage',
  ]) {
    const from = join(ROOT, rel);
    if (existsSync(from)) cpSync(from, join(dir, rel), { recursive: true });
  }
  // A repository, because two gates enumerate through git and one of them reads
  // the INDEX (`secret-scan` scans tracked files), so the copy needs one.
  const git = (args) => execFileSync('git', args, { cwd: dir, stdio: 'ignore' });
  git(['init', '-q']);
  git(['-c', 'user.email=selftest@localhost', '-c', 'user.name=selftest', 'add', '-A']);
  mkdirSync(join(dir, '.testfortress', 'reports'), { recursive: true });
  return dir;
}

/** Reads whatever the gate declared as its evidence: report first, transcript second. */
function reportText(dir, task) {
  const names = Array.isArray(task.report) ? task.report : task.report ? [task.report] : [];
  const reportDir = join(dir, manifest.reportDir ?? '.testfortress/reports');
  let text = '';
  for (const name of [...names, `${task.name.replace(/[:]/g, '-')}.log`]) {
    const p = join(reportDir, name);
    if (existsSync(p)) text += `\n${readFileSync(p, 'utf8')}`;
  }
  return text;
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------
const workspace = prepareWorkspace();
const results = [];
let cannotRun = false;

log(`selftest: workspace ${workspace}`);
log(`selftest: ${selected.length} registered gate(s) to prove\n`);

for (const task of selected) {
  const defect = DEFECTS[task.name];
  const unmet = (defect.requires ?? []).filter((r) => !PREREQUISITES[r]?.ok());
  if (unmet.length > 0) {
    // Deliberately NOT a pass. A gate whose failability could not be exercised
    // is an unknown, and the exit code says "could not run" rather than "fine".
    results.push({
      task: task.name,
      status: 'blocked',
      defect: defect.title,
      detail: `missing prerequisite: ${unmet.map((u) => PREREQUISITES[u]?.label ?? u).join(', ')}`,
    });
    cannotRun = true;
    log(`  ⚠ ${task.name} — blocked: ${unmet.join(', ')}`);
    continue;
  }

  // plant
  const saved = new Map();
  const created = [];
  for (const [rel, contents] of Object.entries(defect.create ?? {})) {
    const p = join(workspace, rel);
    if (existsSync(p)) saved.set(rel, readFileSync(p, 'utf8'));
    else created.push(rel);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, contents, 'utf8');
  }
  for (const [rel, mutate] of Object.entries(defect.mutate ?? {})) {
    const p = join(workspace, rel);
    if (!existsSync(p)) {
      results.push({
        task: task.name,
        status: 'error',
        defect: defect.title,
        detail: `cannot plant: ${rel} does not exist in the workspace`,
      });
      cannotRun = true;
      continue;
    }
    const original = readFileSync(p, 'utf8');
    saved.set(rel, original);
    writeFileSync(p, mutate(original), 'utf8');
  }

  // A planted file must be STAGED before the gate runs. `secret-scan` reads
  // tracked files only — deliberately, because an untracked `.env` holding real
  // credentials is the intended way to hold them — so a brand-new file left
  // untracked is invisible to it, and the case would report "this gate cannot
  // fail" about a gate that is working exactly as designed. Staging makes the
  // planted defect what it claims to be: a change about to be committed.
  try {
    execFileSync('git', ['add', '-A'], { cwd: workspace, stdio: 'ignore' });
  } catch {
    /* a gate that does not read the index does not care */
  }

  // `buryInHistory` COMMITS the planted files and then deletes them, so the
  // defect exists ONLY in git history and the working tree is genuinely clean.
  // Without it a history-scanning gate is "proved" by a defect its working-tree
  // sibling would have caught anyway — the two would be indistinguishable, which
  // is the same as not having proved the history leg at all.
  if (defect.buryInHistory) {
    // Plain `git commit`, with no hook-skipping flag: such a flag inside a
    // gate-defining file is a HOOK-BYPASS marker that the integrity scan treats
    // as non-ledgerable — it caught the first draft of this very helper — and it
    // is not needed anyway. The temp workspace is a bare `git init` with no hooks
    // installed, because husky wires those through `npm run prepare`, which never
    // runs there.
    const commit = (message) => {
      execFileSync(
        'git',
        [
          '-c',
          'user.email=selftest@localhost',
          '-c',
          'user.name=selftest',
          'commit',
          '-q',
          '-m',
          message,
        ],
        { cwd: workspace, stdio: 'ignore' },
      );
    };
    try {
      commit('selftest: plant');
      for (const rel of Object.keys(defect.create ?? {})) {
        rmSync(join(workspace, rel), { force: true });
      }
      execFileSync('git', ['add', '-A'], { cwd: workspace, stdio: 'ignore' });
      commit('selftest: remove the planted file');
    } catch (error) {
      results.push({
        task: task.name,
        status: 'error',
        defect: defect.title,
        detail: `could not bury the defect in history: ${error.message}`,
      });
      cannotRun = true;
      continue;
    }
  }

  const started = Date.now();
  const run = spawnSync(task.cmd, {
    cwd: workspace,
    shell: true,
    encoding: 'utf8',
    env: { ...process.env, ...(manifest.env ?? {}), FORCE_COLOR: '0' },
    maxBuffer: 64 << 20,
    // Optional, and declared per case rather than globally. One gate needs it:
    // `test:mutation` fails its planted defect in a PRE-FLIGHT that costs
    // milliseconds, but if that plant ever drifted into a no-op the gate would
    // instead do the thing it actually does — mutate ~53,000 lines of source,
    // for hours, while this harness waited. A killed child reports no exit
    // status, which lands as a non-zero code with no matching evidence, so the
    // case is reported `unproven` (the honest verdict for a run that proved
    // nothing) rather than as a pass.
    ...(defect.timeoutMs ? { timeout: defect.timeoutMs } : {}),
  });
  const durationMs = Date.now() - started;
  const code = run.status ?? 1;
  const output = `${run.stdout ?? ''}\n${run.stderr ?? ''}${reportText(workspace, task)}`;

  // restore, always, before judging
  for (const [rel, contents] of saved) writeFileSync(join(workspace, rel), contents, 'utf8');
  for (const rel of created) rmSync(join(workspace, rel), { force: true });
  try {
    execFileSync('git', ['add', '-A'], { cwd: workspace, stdio: 'ignore' });
  } catch {
    /* the working tree is restored either way; the index only mirrors it */
  }

  // (c) + (d)
  const failed = code !== 0 && code !== SKIP_EXIT;
  const attributed = defect.evidence ? defect.evidence(output) : true;
  const status = failed && attributed ? 'proven' : 'unproven';
  const detail = !failed
    ? code === SKIP_EXIT
      ? 'the gate reported SKIPPED (78); a skip is not a failure'
      : `the gate exited 0 with the defect planted — it cannot fail`
    : attributed
      ? `exit ${code}`
      : `exit ${code}, but its report never mentions the planted defect, so the failure is not attributable to it`;

  results.push({
    task: task.name,
    status,
    defect: defect.title,
    exitCode: code,
    durationMs,
    detail,
  });
  log(`  ${status === 'proven' ? '✔' : '✖'} ${task.name} — ${detail}`);
}

rmSync(workspace, { recursive: true, force: true });

const payload = {
  version: 1,
  checkedAt: new Date().toISOString(),
  registered: registered.map((t) => t.name),
  counts: {
    proven: results.filter((r) => r.status === 'proven').length,
    unproven: results.filter((r) => r.status === 'unproven').length,
    blocked: results.filter((r) => r.status === 'blocked').length,
    error: results.filter((r) => r.status === 'error').length,
  },
  results,
};
mkdirSync(REPORT_DIR, { recursive: true });
writeFileSync(join(REPORT_DIR, 'selftest.json'), `${JSON.stringify(payload, null, 2)}\n`);

if (asJson) process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);

const unproven = payload.counts.unproven;
log(
  `\nselftest: ${payload.counts.proven} proven, ${unproven} unproven, ` +
    `${payload.counts.blocked} blocked, ${payload.counts.error} error.`,
);

if (unproven > 0) process.exit(EXIT_UNPROVEN);
if (cannotRun) process.exit(EXIT_CANNOT_RUN);
process.exit(EXIT_PROVEN);
