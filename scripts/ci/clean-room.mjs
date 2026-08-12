#!/usr/bin/env node
/**
 * `ci:local` — the whole gauntlet, run against a checkout of HEAD that has never
 * met this machine.
 *
 * Every other gate runs inside the working tree, and therefore inside whatever
 * state the working tree has accumulated: an installed `node_modules` from
 * another platform, a cache from another version of a tool, a file mode from
 * another umask. This gate distrusts all of it. It creates a git worktree at
 * HEAD in a temporary directory, installs from the lockfile alone, and runs
 * `verify:full` there.
 *
 *   node scripts/ci/clean-room.mjs              the gate
 *   npm run ci:local                            the same thing
 *   npm run ci:local -- --keep                  leave the worktree for inspection
 *
 * It is not hypothetical. The audit that produced this project's hardening plan
 * hit THREE defects that no gate here could catch, all of them host state:
 *
 *   1. a `node_modules` installed on Windows and carried onto Linux, where every
 *      `.bin` shim was non-executable and every native binary was a win32 build;
 *   2. a Playwright browser cache that no longer matched the pinned
 *      `@playwright/test`;
 *   3. host file modes leaking into the Docker image through `COPY`, so the
 *      image a `umask 077` checkout produced could not boot at all.
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. THE TEMPORARY PATH IS RESOLVED IN THIS RUNNER, never in a shell one-liner.
 *     `mktemp -d` does not exist on Windows and `%TEMP%` does not exist on
 *     POSIX; `os.tmpdir()` is the one answer that is right on both, and this
 *     repository is developed on both.
 *
 *  b. IT IS A `git worktree`, SO IT IS EXACTLY HEAD. Not a copy of the working
 *     tree — that is what `verify:selftest` needs, and it is the opposite of
 *     what this gate is for. The claim being made is "the commit that is about
 *     to be pushed builds and passes from nothing", and uncommitted work is
 *     precisely what must NOT be in it. A dirty tree is therefore reported
 *     loudly and the report names the commit, so nobody reads a green run as a
 *     verdict on work that was never in it.
 *
 *     It also writes nothing a person owns: a worktree touches the temporary
 *     directory and `.git/worktrees` bookkeeping, no tracked file and no remote.
 *
 *  c. THE INSTALL IS FROZEN (`npm ci`) AND ITS LIFECYCLE SCRIPTS RUN. `npm ci`
 *     deletes any existing tree and installs the lockfile exactly, which is what
 *     makes defect 1 above visible. The scripts are deliberately NOT skipped:
 *     they are how several dependencies land their platform binaries, and a
 *     clean room that skipped them would install a tree no user ever gets.
 *
 *  d. THE PLAYWRIGHT BROWSER CACHE IS NOT REINSTALLED, and that is the point.
 *     It lives in the user's home directory, keyed by browser build, and it is
 *     shared with the working tree. If it does not match the pinned
 *     `@playwright/test`, the E2E gate fails inside the clean room — which is
 *     defect 2 being caught, not a flake. A runner that quietly ran `playwright
 *     install` first would repair the one thing it exists to detect.
 *
 *  e. `verify:full` RUNS INSIDE THE WORKTREE, WITH ITS OWN cwd. Every gate here
 *     resolves the repository root from the runner's own file location, so a
 *     child started with `cwd` set to the worktree measures the worktree — and
 *     `ci:local` is `composite` in the manifest and absent from the gate table,
 *     so the tier that would contain it can never run it as a member of itself.
 *     Without that, `verify:full` (T0+T1+T2) would include a T2 gate that runs
 *     `verify:full`.
 *
 *  f. THE WORKTREE IS REMOVED EVEN WHEN THE RUN FAILS, and its removal is
 *     `--force`d: `npm ci` leaves ~600 MB of untracked `node_modules` there, and
 *     `git worktree remove` refuses a dirty worktree. A gate that leaves a
 *     gigabyte behind on every failure is a gate people delete. `process.exit`
 *     is therefore never called from inside the block that owns the worktree —
 *     it does not run `finally` handlers.
 */
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { captureExe, repoRoot, runNpm } from './lib/proc.mjs';
import { color, formatDuration, note, symbol, warn } from './lib/ui.mjs';
import { ensureReportDir, writeJsonReport } from './lib/reports.mjs';

const EXIT_PASS = 0;
const EXIT_FAILED = 1;
const EXIT_CANNOT_RUN = 2;

const argv = process.argv.slice(2);
const keep = argv.includes('--keep');

/** Always `-C` the real repository: this runner's own cwd is irrelevant to it. */
const git = (...args) => captureExe('git', ['-C', repoRoot, ...args]);

const started = Date.now();
const steps = [];
const record = (name, ok, detail, extra = {}) => {
  steps.push({ name, ok, detail, ...extra });
  if (ok) console.log(color.green(`  ${symbol.pass} ${name} — ${detail}`));
  else console.error(color.red(`  ${symbol.fail} ${name} — ${detail}`));
  return ok;
};

const finish = ({ code, summary }) => {
  writeJsonReport('cleanroom.json', {
    version: 1,
    task: 'ci:local',
    checkedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    exitCode: code,
    summary,
    steps,
  });
  if (code === EXIT_PASS) console.log(color.green(`\n${symbol.pass} clean room: ${summary}`));
  else console.error(color.red(`\n${symbol.fail} clean room: ${summary}`));
  process.exit(code);
};

ensureReportDir();
console.log(color.bold('\n  clean room — HEAD, a frozen install, and the full gauntlet\n'));

// ---------------------------------------------------------------------------
// 1. What exactly is being verified
// ---------------------------------------------------------------------------
const head = git('rev-parse', 'HEAD');
if (!head.ok) {
  record('head', false, 'git rev-parse HEAD failed — not a repository, or no commit yet');
  finish({ code: EXIT_CANNOT_RUN, summary: 'there is no HEAD to check out' });
}
const commit = head.stdout.trim();
const shortCommit = commit.slice(0, 12);
record('head', true, `verifying ${shortCommit}`, { commit });

// (b) A dirty tree is not an error — the gate's subject is HEAD either way — but
// reading a green run as a verdict on uncommitted work would be wrong, so it is
// stated rather than implied.
const dirtyPaths = git('status', '--porcelain')
  .stdout.split('\n')
  .filter((line) => line.trim().length > 0);
if (dirtyPaths.length > 0) {
  warn(
    `${String(dirtyPaths.length)} uncommitted change(s) are NOT in this run — a clean room verifies the commit, not the desk`,
  );
  for (const line of dirtyPaths.slice(0, 10)) note(line);
  steps.push({
    name: 'working-tree',
    ok: true,
    detail: `${String(dirtyPaths.length)} uncommitted path(s) excluded`,
    dirtyPaths: dirtyPaths.slice(0, 50),
  });
}

// ---------------------------------------------------------------------------
// 2. The worktree (a)
// ---------------------------------------------------------------------------
const parent = mkdtempSync(path.join(tmpdir(), 'hvault-cleanroom-'));
const worktree = path.join(parent, 'repo');

const cleanup = () => {
  if (keep) {
    warn(`--keep: the worktree is still at ${worktree}`);
    warn(`remove it with: git -C ${repoRoot} worktree remove --force ${worktree}`);
    return;
  }
  // (f) `--force`, because `npm ci` made it dirty by design.
  const removed = git('worktree', 'remove', '--force', worktree);
  rmSync(parent, { recursive: true, force: true });
  if (!removed.ok) {
    // Prune the bookkeeping regardless: a stale registration under
    // .git/worktrees would make the NEXT run fail on a path that no longer
    // exists — a failure about this gate rather than about the code.
    git('worktree', 'prune');
  }
};

const added = git('worktree', 'add', '--detach', worktree, commit);
if (!added.ok) {
  rmSync(parent, { recursive: true, force: true });
  record('worktree', false, `git worktree add failed: ${added.stderr.trim().slice(0, 300)}`);
  finish({ code: EXIT_CANNOT_RUN, summary: 'could not create the clean-room worktree' });
}
record('worktree', true, `HEAD checked out at ${worktree}`);

/** @type {{code: number, summary: string}} */
let outcome = { code: EXIT_CANNOT_RUN, summary: 'the clean room did not finish' };

try {
  // -------------------------------------------------------------------------
  // 3. The frozen install (c)
  // -------------------------------------------------------------------------
  const installStarted = Date.now();
  const install = await runNpm(['ci'], { cwd: worktree });
  const installOk = record(
    'npm-ci',
    install === 0,
    install === 0
      ? `lockfile installed from scratch in ${formatDuration(Date.now() - installStarted)}`
      : `npm ci exited ${String(install)} — the lockfile does not install cleanly on this platform`,
  );

  if (installOk) {
    // A tree that installed but produced no runnable binaries is defect 1
    // exactly, and it is worth naming here rather than letting it surface three
    // gates later as "tsc: not found".
    const shim = process.platform === 'win32' ? 'tsc.cmd' : 'tsc';
    const tsc = path.join(worktree, 'node_modules', '.bin', shim);
    record(
      'toolchain',
      existsSync(tsc),
      existsSync(tsc)
        ? 'the installed tree carries its executables'
        : `no runnable ${shim} in node_modules/.bin`,
    );

    // -----------------------------------------------------------------------
    // 4. The gauntlet, inside the worktree (e)
    // -----------------------------------------------------------------------
    note('running verify:full inside the worktree — every tier, nothing inherited');
    const verifyStarted = Date.now();
    const verify = await runNpm(['run', 'verify:full'], { cwd: worktree });
    const verifyOk = record(
      'verify:full',
      verify === 0,
      verify === 0
        ? `every tier passed in ${formatDuration(Date.now() - verifyStarted)}`
        : `verify:full exited ${String(verify)} in the clean room`,
    );

    // The clean room's own summary is copied out BEFORE the worktree goes, or
    // the evidence for a failure would be deleted along with it.
    const summaryPath = path.join(worktree, '.testfortress', 'reports', 'summary.json');
    if (existsSync(summaryPath)) {
      try {
        writeJsonReport('cleanroom-summary.json', JSON.parse(readFileSync(summaryPath, 'utf8')));
        note('gate-by-gate result: .testfortress/reports/cleanroom-summary.json');
      } catch (error) {
        warn(
          `could not copy the clean room summary: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }

    outcome = verifyOk
      ? {
          code: EXIT_PASS,
          summary: `${shortCommit} builds and passes every gate from a frozen install`,
        }
      : {
          code: EXIT_FAILED,
          summary: `${shortCommit} does not pass the gauntlet from a clean checkout — see cleanroom-summary.json`,
        };
  } else {
    outcome = {
      code: EXIT_FAILED,
      summary: 'the frozen install failed, so nothing downstream could be measured',
    };
  }
} catch (error) {
  outcome = {
    code: EXIT_CANNOT_RUN,
    summary: `the clean room could not run: ${error instanceof Error ? error.message : String(error)}`,
  };
} finally {
  cleanup();
}

finish(outcome);
