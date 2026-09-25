/**
 * `mutation-diff-gate.mjs`, run as a process against a real git repository.
 *
 * What is under test is everything the gate decides: which change it measures,
 * that it plans and verifies the mutant set, the floor, the one excuse (an
 * in-date `EQUIV-MUTANT` ledger entry), that an `Ignored` mutant on a changed
 * line counts against the change, and the three exit codes.
 *
 * Stryker is replaced at the PROCESS boundary by a stand-in that does what
 * Stryker's project reader and instrumenter do with a plan — it reads the
 * plan's `file:line:col-line:col` ranges, converts them exactly as Stryker does
 * (one subtracted from each line, none from each column) and asks the REAL
 * instrumenter which mutants they select — and then decides each mutant's fate
 * from a marker on its source line instead of running a suite. A real run takes
 * minutes per leg; the selection logic, which is what the plan check exists to
 * police, is Stryker's own.
 */
import { afterAll, describe, expect, it } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import {
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
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { MUTATION_DIFF_FLOOR } from '../../../scripts/ci/lib/mutation-scope.mjs';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

const dirs: string[] = [];
afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

/**
 * The stand-in. A mutant whose first line carries `SURVIVES` survives, one
 * carrying `IGNORED` is reported Ignored, every other one is killed.
 * `HVAULT_FAKE_EXTRA=1` makes it report one mutant nobody planned, and
 * `HVAULT_FAKE_EXIT` makes it exit with that code without writing a report.
 */
const FAKE_STRYKER = `
import fs from 'node:fs';
import { Instrumenter } from '@stryker-mutator/instrumenter';
const log = fs.readFileSync(process.env.HVAULT_FAKE_LOG, 'utf8');
fs.writeFileSync(process.env.HVAULT_FAKE_LOG, log + process.env.HVAULT_MUTATION_LEG + '\\n');
if (process.env.HVAULT_FAKE_EXIT) process.exit(Number(process.env.HVAULT_FAKE_EXIT));
const leg = process.env.HVAULT_MUTATION_LEG;
const plan = JSON.parse(fs.readFileSync(process.env.HVAULT_MUTATION_DIFF_PLAN, 'utf8'));
const byFile = new Map();
for (const range of plan.mutate) {
  const m = /^(.*):(\\d+):(\\d+)-(\\d+):(\\d+)$/.exec(range);
  const ranges = byFile.get(m[1]) ?? [];
  ranges.push({ start: { line: Number(m[2]) - 1, column: Number(m[3]) }, end: { line: Number(m[4]) - 1, column: Number(m[5]) } });
  byFile.set(m[1], ranges);
}
const quiet = () => {};
const logger = { trace: quiet, debug: quiet, info: quiet, warn: quiet, error: quiet, fatal: quiet,
  isTraceEnabled: () => false, isDebugEnabled: () => false, isInfoEnabled: () => false,
  isWarnEnabled: () => false, isErrorEnabled: () => false, isFatalEnabled: () => false };
const files = [...byFile].map(([name, mutate]) => ({ name, content: fs.readFileSync(name, 'utf8'), mutate }));
const { mutants } = await new Instrumenter(logger).instrument(files, { plugins: null, excludedMutations: [], ignorers: [] });
const report = { files: {} };
for (const mutant of mutants) {
  const source = fs.readFileSync(mutant.fileName, 'utf8');
  const line = source.split('\\n')[mutant.location.start.line];
  const status = line.includes('SURVIVES') ? 'Survived' : line.includes('IGNORED') ? 'Ignored' : 'Killed';
  const entry = report.files[mutant.fileName] ?? { source, mutants: [] };
  entry.mutants.push({
    id: String(entry.mutants.length), mutatorName: mutant.mutatorName, replacement: mutant.replacement, status,
    location: {
      start: { line: mutant.location.start.line + 1, column: mutant.location.start.column + 1 },
      end: { line: mutant.location.end.line + 1, column: mutant.location.end.column + 1 },
    },
  });
  report.files[mutant.fileName] = entry;
}
if (process.env.HVAULT_FAKE_EXTRA === '1') {
  const first = Object.values(report.files)[0];
  first.mutants.push({ id: 'x', mutatorName: 'BooleanLiteral', replacement: 'nobody-planned-me', status: 'Killed',
    location: { start: { line: 1, column: 1 }, end: { line: 1, column: 2 } } });
}
fs.mkdirSync('.stryker-tmp', { recursive: true });
fs.writeFileSync('.stryker-tmp/diff-report-' + leg + '.json', JSON.stringify(report));
`;

const LIBS = [
  'proc',
  'ui',
  'reports',
  'changed-diff',
  'diff-base',
  'mutation-scope',
  'mutation-evidence',
  'mutation-diff',
  'stryker-config',
];

const git = (cwd: string, ...args: string[]): string =>
  execFileSync('git', args, { cwd, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();

/** A repository whose `main` holds `base`, with `change` applied in the working tree. */
function workspace(options: {
  base: Record<string, string>;
  change?: Record<string, string>;
  ledger?: unknown[];
  branch?: string | null;
}): string {
  const dir = mkdtempSync(path.join(tmpdir(), 'hv-mutation-diff-gate-'));
  dirs.push(dir);
  mkdirSync(path.join(dir, 'scripts', 'ci', 'lib'), { recursive: true });
  cpSync(
    path.join(repoRoot, 'scripts', 'ci', 'mutation-diff-gate.mjs'),
    path.join(dir, 'scripts', 'ci', 'mutation-diff-gate.mjs'),
  );
  for (const lib of LIBS) {
    cpSync(
      path.join(repoRoot, 'scripts', 'ci', 'lib', `${lib}.mjs`),
      path.join(dir, 'scripts', 'ci', 'lib', `${lib}.mjs`),
    );
  }
  const scope = path.join(dir, 'node_modules', '@stryker-mutator');
  mkdirSync(path.join(scope, 'core', 'bin'), { recursive: true });
  writeFileSync(path.join(scope, 'core', 'package.json'), '{"type":"module"}\n');
  writeFileSync(path.join(scope, 'core', 'bin', 'stryker.js'), FAKE_STRYKER);
  symlinkSync(
    path.join(repoRoot, 'node_modules', '@stryker-mutator', 'instrumenter'),
    path.join(scope, 'instrumenter'),
    'dir',
  );
  mkdirSync(path.join(dir, '.testfortress'), { recursive: true });
  if (options.ledger) {
    writeFileSync(
      path.join(dir, '.testfortress', 'suppressions.json'),
      JSON.stringify({ version: 1, entries: options.ledger }),
    );
  }
  writeFileSync(
    path.join(dir, '.gitignore'),
    'node_modules/\n.stryker-tmp/\n.testfortress/reports/\n',
  );
  for (const [rel, text] of Object.entries(options.base)) {
    mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    writeFileSync(path.join(dir, rel), text);
  }
  git(dir, 'init', '-q', '-b', options.branch === null ? 'trunk' : 'main');
  git(dir, 'config', 'user.email', 'test@localhost');
  git(dir, 'config', 'user.name', 'test');
  git(dir, 'config', 'commit.gpgsign', 'false');
  git(dir, 'add', '-A');
  git(dir, 'commit', '-q', '-m', 'base');
  for (const [rel, text] of Object.entries(options.change ?? {})) {
    mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    writeFileSync(path.join(dir, rel), text);
  }
  return dir;
}

interface GateRun {
  code: number;
  output: string;
  strykerRuns: string[];
  report: Record<string, unknown> | null;
}

function runGate(dir: string, env: Record<string, string> = {}): GateRun {
  const log = path.join(dir, 'stryker-calls.log');
  writeFileSync(log, '');
  const proc = spawnSync(
    process.execPath,
    [path.join(dir, 'scripts', 'ci', 'mutation-diff-gate.mjs')],
    {
      cwd: dir,
      encoding: 'utf-8',
      env: { ...process.env, FORCE_COLOR: '0', HVAULT_FAKE_LOG: log, ...env },
    },
  );
  const reportFile = path.join(dir, '.testfortress', 'reports', 'mutation-diff.json');
  return {
    code: proc.status ?? -1,
    output: `${proc.stdout}\n${proc.stderr}`,
    strykerRuns: readFileSync(log, 'utf-8').split('\n').filter(Boolean),
    report: existsSync(reportFile)
      ? (JSON.parse(readFileSync(reportFile, 'utf-8')) as Record<string, unknown>)
      : null,
  };
}

const BASE = {
  'packages/shared/src/util.ts': 'export const one = 1;\n',
  'packages/shared/README.md': 'docs\n',
};
const clamp = (marker = ''): string =>
  [
    'export const one = 1;',
    'export function clamp(n: number): number {',
    `  if (n > 10) return 10; ${marker}`,
    '  return n < 0 ? 0 : n;',
    '}',
    '',
  ].join('\n');

describe('mutation-diff-gate.mjs', () => {
  it('passes a change that touches no production line, without starting Stryker', () => {
    const dir = workspace({ base: BASE, change: { 'packages/shared/README.md': 'more docs\n' } });
    const run = runGate(dir);
    expect(run.code).toBe(0);
    expect(run.strykerRuns).toEqual([]);
    expect(run.report).toMatchObject({ score: null, passed: true, changedFiles: [] });
  });

  it('passes a change whose mutants are all killed, having planned and tested every one', () => {
    const dir = workspace({ base: BASE, change: { 'packages/shared/src/util.ts': clamp() } });
    const run = runGate(dir);
    expect(run.code).toBe(0);
    expect(run.strykerRuns).toEqual(['shared']);
    const legs = run.report!['legs'] as {
      id: string;
      candidates: number;
      planned: number;
      sampled?: boolean;
      deadlineMs?: number;
    }[];
    const shared = legs.find((leg) => leg.id === 'shared')!;
    expect(shared.candidates).toBeGreaterThan(5);
    expect(shared.planned).toBe(shared.candidates);
    expect(shared.sampled).toBe(false);
    // The hang guard the leg actually ran under is recorded, and a plan this
    // small keeps the hour.
    expect(shared.deadlineMs).toBe(60 * 60 * 1000);
    // Only the shared leg had anything to test; the others started nothing.
    expect(legs.filter((leg) => leg.id !== 'shared').every((leg) => leg.planned === 0)).toBe(true);
    expect(run.report).toMatchObject({
      score: 100,
      passed: true,
      floor: MUTATION_DIFF_FLOOR,
      incremental: false,
      changedFiles: ['packages/shared/src/util.ts'],
    });
  });

  it('measures a brand-new module nobody has committed yet', () => {
    // Untracked files are folded into the diff by hand (`lib/changed-diff.mjs`),
    // because a new module is exactly the case a per-change gate exists for.
    const dir = workspace({
      base: BASE,
      change: {
        'packages/shared/src/fresh.ts': clamp('// SURVIVES').replace('export const one = 1;\n', ''),
      },
    });
    const run = runGate(dir);
    expect(run.report!['changedFiles']).toEqual(['packages/shared/src/fresh.ts']);
    expect(run.code).toBe(1);
    expect(run.output).toMatch(/packages\/shared\/src\/fresh\.ts:2 /);
  });

  it('fails a change whose survivors take it below the floor, naming each one', () => {
    const dir = workspace({
      base: BASE,
      change: { 'packages/shared/src/util.ts': clamp('// SURVIVES') },
    });
    const run = runGate(dir);
    expect(run.code).toBe(1);
    expect(run.output).toMatch(/is below the floor of 85%/);
    expect(run.output).toMatch(/packages\/shared\/src\/util\.ts:3 /);
    // The unchanged first line owns nothing, so nothing there is listed.
    expect(run.output).not.toMatch(/util\.ts:1 /);
    expect(run.report).toMatchObject({ passed: false });
    expect((run.report!['score'] as number) < MUTATION_DIFF_FLOOR).toBe(true);
  });

  it('counts an Ignored mutant on a changed line AGAINST the change', () => {
    const dir = workspace({
      base: BASE,
      change: { 'packages/shared/src/util.ts': clamp('// IGNORED') },
    });
    const run = runGate(dir);
    expect(run.code).toBe(1);
    expect(run.output).toMatch(/\(Ignored\)/);
  });

  it('excuses survivors only through an in-date EQUIV-MUTANT entry for that file, up to its maxHits', () => {
    const entry = (overrides: Record<string, unknown>): Record<string, unknown> => ({
      id: 'SUP-9001',
      rule: 'EQUIV-MUTANT',
      kind: 'known-gap',
      file: 'packages/shared/src/util.ts',
      maxHits: 50,
      expires: '2999-01-01',
      ...overrides,
    });
    const change = { 'packages/shared/src/util.ts': clamp('// SURVIVES') };
    const excused = runGate(workspace({ base: BASE, change, ledger: [entry({})] }));
    expect(excused.code).toBe(0);
    expect((excused.report!['excused'] as unknown[]).length).toBeGreaterThan(0);
    // An expired entry, one for another file, and one whose capacity is too
    // small to cover the survivors all leave the change failing.
    for (const overrides of [
      { expires: '2000-01-01' },
      { file: 'packages/shared/src/other.ts' },
      { maxHits: 1 },
      { rule: 'KNOWN-GAP' },
    ]) {
      const run = runGate(workspace({ base: BASE, change, ledger: [entry(overrides)] }));
      expect(run.code, JSON.stringify(overrides)).toBe(1);
    }
  });

  it('refuses a run in which Stryker tested a mutant nobody planned', () => {
    const dir = workspace({ base: BASE, change: { 'packages/shared/src/util.ts': clamp() } });
    const run = runGate(dir, { HVAULT_FAKE_EXTRA: '1' });
    expect(run.code).toBe(2);
    expect(run.output).toMatch(/tested a different set from the plan/);
    expect(run.report).toBeNull();
  });

  it('reports a Stryker failure as could-not-run, never as a verdict', () => {
    const dir = workspace({ base: BASE, change: { 'packages/shared/src/util.ts': clamp() } });
    const run = runGate(dir, { HVAULT_FAKE_EXIT: '1' });
    expect(run.code).toBe(2);
    expect(run.output).toMatch(/stryker exited 1 and wrote no report/);
    expect(run.report).toBeNull();
  });

  it('cannot run without a trunk to compare against', () => {
    const dir = workspace({ base: BASE, branch: null });
    const run = runGate(dir);
    expect(run.code).toBe(2);
    expect(run.output).toMatch(/none of main, origin\/main resolves/);
    expect(run.strykerRuns).toEqual([]);
  });
});
