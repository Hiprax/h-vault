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
 *   npm run ci -- --continue        do not stop at the first failure
 *
 * Escape hatches, in increasing order of bluntness:
 *
 *   HVAULT_SKIP_GATES=docker,e2e git push    skip named gates for one push
 *   git push --no-verify                     skip the hook entirely
 *
 * A gate exits 78 to report itself SKIPPED rather than passed — used when the
 * tooling it needs is genuinely absent (see sast-gate.mjs). A skip is always
 * printed in the summary; the one thing this runner will not do is quietly
 * pretend a check ran.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { runNpm, runExe, repoRoot } from './lib/proc.mjs';
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

const SKIP_EXIT = 78;

const pkg = JSON.parse(readFileSync(path.join(repoRoot, 'package.json'), 'utf8'));

/**
 * Enforces the Node floor the project actually supports.
 *
 * This is what remains of the old Node 22 + 24 CI matrix. The matrix itself is
 * not reproduced: the repo pins Node 24 (.nvmrc, `node:24-alpine` in every
 * production image), and `engines.node` was tightened to `>=24` to match — so the
 * old 22 leg tested a runtime nothing here ships on, and standing a second
 * toolchain up on every push would cost more than it defends. Enforcing `engines`
 * keeps the floor honest.
 */
function checkEngines() {
  const range = pkg.engines?.node ?? '';
  const required = /^>=\s*(\d+)\.(\d+)\.(\d+)$/.exec(range);
  if (!required) {
    warn(`cannot interpret engines.node (${range}) — skipping the version check`);
    return 0;
  }

  const current = process.versions.node.split('.').map(Number);
  const floor = [Number(required[1]), Number(required[2]), Number(required[3])];
  const below =
    current[0] < floor[0] ||
    (current[0] === floor[0] && current[1] < floor[1]) ||
    (current[0] === floor[0] && current[1] === floor[1] && current[2] < floor[2]);

  if (below) {
    console.error(color.red(`      Node ${process.versions.node} is below the required ${range}`));
    return 1;
  }
  note(`Node ${process.versions.node} satisfies ${range}`);

  try {
    const pinned = readFileSync(path.join(repoRoot, '.nvmrc'), 'utf8').trim();
    if (pinned && Number(pinned.split('.')[0]) !== current[0]) {
      warn(
        `.nvmrc pins Node ${pinned}, you are on ${process.versions.node} — production images use Node ${pinned}`,
      );
    }
  } catch {
    // No .nvmrc is not an error.
  }
  return 0;
}

// `canSkip` marks the only gate allowed to report itself SKIPPED via exit 78.
// The sentinel is honoured from that gate ALONE: if some other tool (npm,
// vitest, eslint) ever happened to exit 78 (EX_CONFIG), an unmarked gate treats
// it as the failure it is, not as a skip — so a real failure can never
// masquerade as "tooling unavailable" and let a broken push through.
/** @type {{id: string, title: string, ci: string, canSkip?: boolean, run: () => Promise<number> | number}[]} */
const GATES = [
  {
    id: 'engines',
    title: 'Node version',
    ci: 'replaces the Node 22/24 matrix floor',
    run: checkEngines,
  },
  {
    id: 'secrets',
    title: 'Secret scan (all tracked files)',
    ci: 'new — the old pipeline never scanned the repo',
    run: () => runExe(process.execPath, ['scripts/ci/secret-scan.mjs']),
  },
  {
    id: 'build',
    title: 'Build (shared → server → client)',
    ci: 'ci job · Build',
    run: () => runNpm(['run', 'build']),
  },
  {
    id: 'lint',
    title: 'Lint (ESLint + eslint-plugin-security)',
    ci: 'ci job · Lint  +  sast job (static analysis baseline)',
    run: () => runNpm(['run', 'lint']),
  },
  {
    id: 'format',
    title: 'Format check (Prettier)',
    ci: 'new — pre-commit only formatted files it happened to see',
    run: () => runNpm(['run', 'format:check']),
  },
  {
    id: 'type-check',
    title: 'Type check (all packages)',
    ci: 'ci job · Type check',
    run: () => runNpm(['run', 'type-check']),
  },
  {
    id: 'test',
    title: 'Unit tests + coverage thresholds',
    ci: 'ci job · Test',
    run: () => runNpm(['test']),
  },
  {
    id: 'audit',
    title: 'Dependency audit (production)',
    ci: 'ci job · Audit production dependencies',
    run: () => runNpm(['run', 'audit:prod']),
  },
  {
    id: 'e2e',
    title: 'E2E (Playwright, Chromium)',
    ci: 'e2e job',
    // --forbid-only mirrors the CI config's `forbidOnly: !!process.env.CI`, but CI
    // is deliberately NOT set: that would also flip `reuseExistingServer` off and
    // make the gate fail outright whenever a dev server already holds port 3000.
    // The list reporter matters just as much — the default HTML reporter opens a
    // browser on failure, which would hang a git hook forever.
    run: () => runNpm(['run', 'test:e2e', '--', '--forbid-only', '--retries=2', '--reporter=list']),
  },
  {
    id: 'docker',
    title: 'Container build + compose + Nginx config',
    ci: 'docker-build job · image builds, nginx -t, compose config',
    run: () => runExe(process.execPath, ['scripts/ci/docker-gate.mjs']),
  },
  {
    id: 'sast',
    title: 'SAST (CodeQL security-and-quality)',
    ci: 'sast job · CodeQL',
    canSkip: true, // exits 78 when the CodeQL CLI is not installed
    run: () => runExe(process.execPath, ['scripts/ci/sast-gate.mjs']),
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
const continueOnFailure = flag('continue');
const isHook = value('hook') !== '';

const unknown = [...only, ...skip].filter((id) => !GATES.some((gate) => gate.id === id));
if (unknown.length > 0) {
  console.error(color.red(`Unknown gate(s): ${unknown.join(', ')}`));
  console.error(color.gray(`Known gates: ${GATES.map((gate) => gate.id).join(', ')}`));
  process.exit(1);
}

if (flag('list')) {
  console.log(color.bold('\n  Local pipeline gates\n'));
  for (const gate of GATES) {
    console.log(`  ${color.cyan(gate.id.padEnd(12))} ${gate.title}`);
    console.log(`  ${' '.repeat(12)} ${color.gray(gate.ci)}\n`);
  }
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

const selected = GATES.filter((gate) => only.length === 0 || only.includes(gate.id));

heading(
  isHook
    ? 'Local pipeline (pre-push) — this replaces GitHub Actions CI'
    : 'Local pipeline — this replaces GitHub Actions CI',
);
if (isHook) {
  note('bypass once with:  git push --no-verify');
  note('skip a gate with:  HVAULT_SKIP_GATES=docker,e2e git push');
}

const results = [];
const started = Date.now();
let failed = false;

for (const [index, gate] of selected.entries()) {
  if (skip.has(gate.id)) {
    results.push({ id: gate.id, status: 'skip', durationMs: 0, detail: 'HVAULT_SKIP_GATES' });
    continue;
  }

  stepStart(index + 1, selected.length, gate.title);
  note(gate.ci);

  const gateStarted = Date.now();
  const code = await gate.run();
  const durationMs = Date.now() - gateStarted;

  if (code === SKIP_EXIT && gate.canSkip) {
    results.push({ id: gate.id, status: 'skip', durationMs, detail: 'tooling unavailable' });
    continue;
  }

  if (code !== 0) {
    results.push({
      id: gate.id,
      status: 'fail',
      durationMs,
      detail: `exit ${String(code)}`,
    });
    failed = true;
    console.log(
      color.red(`\n  ${symbol.fail} ${gate.id} failed after ${formatDuration(durationMs)}`),
    );
    if (!continueOnFailure) break;
    continue;
  }

  results.push({ id: gate.id, status: 'pass', durationMs });
  console.log(color.green(`  ${symbol.pass} ${gate.id} passed in ${formatDuration(durationMs)}`));
}

// Gates never reached because an earlier one failed are reported, not omitted.
for (const gate of selected) {
  if (!results.some((result) => result.id === gate.id)) {
    results.push({ id: gate.id, status: 'skip', durationMs: 0, detail: 'not reached' });
  }
}

summary(results);
console.log(color.gray(`  total ${formatDuration(Date.now() - started)}\n`));

if (failed) {
  console.error(color.red(`${symbol.fail} Pipeline failed — push aborted.\n`));
  process.exit(1);
}

console.log(color.green(`${symbol.pass} Pipeline passed.\n`));
