/**
 * `test:mutation` — banking and holding a floor PER LEG.
 *
 * The campaign's merged floor is all-or-nothing across three legs, and one leg
 * is measured in days, so for as long as the merged figures were the only floor
 * the oracle held none. These tests pin the two halves of the repair:
 *
 *   1. The arithmetic (`lib/mutation-evidence.mjs`): what a score is, and the
 *      four ways a unit falls short of its floor. Pure, so it is driven directly.
 *   2. The gate itself (`mutation-gate.mjs`), run as a real process in a
 *      throw-away copy of the scripts with Stryker replaced at the PROCESS
 *      boundary. Stryker is a third-party tool that takes minutes to hours per
 *      leg; what is under test here is everything the gate does with the report
 *      Stryker writes — which report it writes back, which floor it compares
 *      against, and above all that a leg with no floor never passes silently.
 */
import { afterAll, describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createTally,
  evidenceFiles,
  floorFailures,
  isBanked,
  pct,
  sortedSurvivors,
  summariseTally,
  tallyReport,
} from '../../../scripts/ci/lib/mutation-evidence.mjs';
import {
  MUTATION_LEGS,
  legForFile,
  legOfReport,
  legReportFor,
  legSelects,
} from '../../../scripts/ci/lib/mutation-scope.mjs';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

type Status = 'Killed' | 'Timeout' | 'Survived' | 'NoCoverage' | 'Ignored' | 'CompileError';

/** A Stryker-shaped report: per file, mutants with a status, a mutator and a line. */
function strykerReport(files: Record<string, Status[]>): {
  files: Record<
    string,
    {
      mutants: {
        status: Status;
        mutatorName: string;
        replacement: string;
        location: { start: { line: number } };
      }[];
    }
  >;
} {
  return {
    files: Object.fromEntries(
      Object.entries(files).map(([file, statuses]) => [
        file,
        {
          mutants: statuses.map((status, index) => ({
            status,
            mutatorName: 'EqualityOperator',
            replacement: `x >= ${String(index)}`,
            location: { start: { line: index + 1 } },
          })),
        },
      ]),
    ),
  };
}

describe('the mutation evidence arithmetic', () => {
  it('counts Killed and Timeout as detected, Survived and NoCoverage against, and nothing else at all', () => {
    const tally = tallyReport(
      strykerReport({
        'packages/shared/src/a.ts': ['Killed', 'Timeout', 'Survived', 'NoCoverage', 'Ignored'],
        'packages/shared/src/b.ts': ['Killed', 'CompileError'],
      }),
    );
    const summary = summariseTally(tally, []);
    // 3 detected over 5 scored. `Ignored` and `CompileError` are in NEITHER half:
    // counting them against would punish a configuration choice, counting them
    // for would let `ignoreStatic` raise the score.
    expect(summary.killed).toBe(3);
    expect(summary.totalMutants).toBe(5);
    expect(summary.overall).toBe(60);
    expect(summary.filesMutated).toEqual(['packages/shared/src/a.ts', 'packages/shared/src/b.ts']);
    expect(tally.byStatus).toEqual({
      Killed: 2,
      Timeout: 1,
      Survived: 1,
      NoCoverage: 1,
      Ignored: 1,
      CompileError: 1,
    });
    // The survivors are the two ALIVE mutants and never the ignored one.
    expect(sortedSurvivors(tally).map((s) => [s.file, s.line, s.status])).toEqual([
      ['packages/shared/src/a.ts', 3, 'Survived'],
      ['packages/shared/src/a.ts', 4, 'NoCoverage'],
    ]);
  });

  it('reports 0, never NaN, over an empty denominator', () => {
    expect(pct(0, 0)).toBe(0);
    expect(summariseTally(createTally(), []).overall).toBe(0);
    expect(pct(2, 3)).toBe(66.67);
  });

  it('accumulates several reports into one tally, which is how the merged figure is built', () => {
    const merged = createTally();
    tallyReport(strykerReport({ 'packages/shared/src/a.ts': ['Killed', 'Survived'] }), merged);
    tallyReport(strykerReport({ 'packages/client/src/b.ts': ['Killed', 'Killed'] }), merged);
    const summary = summariseTally(merged, []);
    expect(summary.totalMutants).toBe(4);
    expect(summary.overall).toBe(75);
    expect(summary.filesMutated).toHaveLength(2);
  });

  it('scores a core module by path prefix, and omits a module with nothing measured', () => {
    const tally = tallyReport(
      strykerReport({
        'packages/shared/src/schemas/vault.ts': ['Killed', 'Killed', 'Killed', 'Survived'],
        'packages/shared/src/utils/index.ts': ['Survived'],
      }),
    );
    const summary = summariseTally(tally, [
      'packages/shared/src/schemas/',
      'packages/server/src/utils/folderGraph.ts',
    ]);
    // Absent, not 0: "not measured here" and "measured, nothing killed" differ.
    expect(summary.modules).toEqual({ 'packages/shared/src/schemas/': 75 });
  });

  it('writes the evidence as statuses the ratchet can recount, ignored ones included', () => {
    const tally = tallyReport(
      strykerReport({ 'packages/shared/src/a.ts': ['Killed', 'Survived', 'Ignored'] }),
    );
    const files = evidenceFiles(tally);
    expect(files['packages/shared/src/a.ts']!.mutants.map((m) => m.status)).toEqual([
      'Killed',
      'Survived',
      'Ignored',
    ]);
  });

  it('treats a unit as banked only when it records BOTH the score and the measured file set', () => {
    expect(isBanked(undefined)).toBe(false);
    expect(isBanked({})).toBe(false);
    expect(isBanked({ overall: 80 })).toBe(false);
    expect(isBanked({ filesMutated: [] })).toBe(false);
    expect(isBanked({ overall: 80, filesMutated: ['a.ts'] })).toBe(true);
  });

  describe('holding a unit to its floor', () => {
    const recorded = {
      overall: 80,
      totalMutants: 10,
      filesMutated: ['a.ts', 'b.ts'],
      modules: { 'a.ts': 90 },
    };
    const holding = {
      overall: 80,
      totalMutants: 10,
      filesMutated: ['a.ts', 'b.ts'],
      modules: { 'a.ts': 90 },
    };

    it('passes a unit measured exactly at its floor', () => {
      expect(floorFailures('shared', recorded, holding)).toEqual([]);
    });

    it('fails a lost file even while the score rises', () => {
      const failures = floorFailures('shared', recorded, {
        ...holding,
        overall: 95,
        filesMutated: ['a.ts'],
      });
      expect(failures).toEqual([
        'shared: scope narrowed: 1 file(s) are no longer mutated, e.g. b.ts',
      ]);
    });

    it('fails a smaller denominator, one below the floor and nothing at the floor', () => {
      expect(floorFailures('client', recorded, { ...holding, totalMutants: 9 })).toEqual([
        'client: denominator shrank: 9 mutants tested, baseline 10',
      ]);
      expect(floorFailures('client', recorded, { ...holding, totalMutants: 11 })).toEqual([]);
    });

    it('fails a score one hundredth below the floor', () => {
      expect(floorFailures('merged', recorded, { ...holding, overall: 79.99 })).toEqual([
        'merged: overall 79.99% is below the recorded 80%',
      ]);
    });

    it('fails a core module that fell, and one that stopped being measured', () => {
      expect(floorFailures('shared', recorded, { ...holding, modules: { 'a.ts': 89 } })).toEqual([
        'shared: core module a.ts: 89% is below the recorded 90%',
      ]);
      expect(floorFailures('shared', recorded, { ...holding, modules: {} })).toEqual([
        'shared: core module a.ts was not measured at all',
      ]);
    });
  });
});

describe('the per-leg scope helpers', () => {
  it('applies the LAST matching pattern, which is the rule Stryker itself applies', () => {
    const client = MUTATION_LEGS.find((leg) => leg.id === 'client')!;
    expect(legSelects(client, 'packages/client/src/lib/utils.ts')).toBe(true);
    // Selected by `**/*.tsx`, then removed by the presentational negation after it.
    expect(legSelects(client, 'packages/client/src/components/ui/button.tsx')).toBe(false);
    expect(legSelects(client, 'packages/client/src/main.tsx')).toBe(false);
    expect(legSelects(client, 'packages/server/src/app.ts')).toBe(false);
  });

  it('assigns every in-scope file to exactly the leg of its own package', () => {
    expect(legForFile('packages/shared/src/utils/rowId.ts')?.id).toBe('shared');
    expect(legForFile('packages/server/src/utils/rowIds.ts')?.id).toBe('server');
    expect(legForFile('packages/client/src/services/crypto/vaultField.ts')?.id).toBe('client');
    expect(legForFile('packages/shared/src/types/index.ts')).toBeUndefined();
    expect(legForFile('scripts/ci/mutation-gate.mjs')).toBeUndefined();
  });

  it('names each leg a report the merged report can never be mistaken for, and maps it back', () => {
    for (const leg of MUTATION_LEGS) {
      expect(legReportFor(leg.id)).not.toBe('mutation.json');
      expect(legOfReport(legReportFor(leg.id))).toBe(leg.id);
    }
    expect(legOfReport('mutation.json')).toBeUndefined();
    expect(legOfReport('mutation-ghost.json')).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// the gate, run as a process against a stand-in for Stryker
// ---------------------------------------------------------------------------

const dirs: string[] = [];
afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

/**
 * Stryker, replaced at the process boundary. It records that it was asked to
 * run, copies the fixture report for the leg it was asked about into the place
 * the real Stryker writes it, and exits with the fixture's code. CommonJS on
 * purpose: nothing above it in the temp tree declares `"type": "module"`.
 */
const FAKE_STRYKER = `
const fs = require('node:fs');
const leg = process.env.HVAULT_MUTATION_LEG;
const dir = process.env.HVAULT_FAKE_STRYKER_FIXTURES;
fs.appendFileSync(dir + '/calls.log', leg + ' ' + process.argv.slice(2).join(' ') + '\\n');
const spec = JSON.parse(fs.readFileSync(dir + '/' + leg + '.json', 'utf8'));
if (spec.report) {
  fs.mkdirSync('.stryker-tmp', { recursive: true });
  fs.writeFileSync('.stryker-tmp/report-' + leg + '.json', JSON.stringify(spec.report));
}
process.exit(spec.exitCode ?? 0);
`;

interface LegSpec {
  report?: ReturnType<typeof strykerReport>;
  exitCode?: number;
}

interface GateRun {
  dir: string;
  code: number;
  output: string;
  calls: string[];
  report: (name: string) => Record<string, unknown> | null;
}

function runGate(options: {
  legs: Partial<Record<'shared' | 'client' | 'server', LegSpec>>;
  baseline: Record<string, unknown>;
  args?: string[];
  /** Files that must exist on disk, for the pre-flight's "still exists" rule. */
  files?: string[];
}): GateRun {
  const dir = mkdtempSync(path.join(tmpdir(), 'hv-mutation-gate-'));
  dirs.push(dir);
  mkdirSync(path.join(dir, 'scripts', 'ci', 'lib'), { recursive: true });
  cpSync(
    path.join(repoRoot, 'scripts', 'ci', 'mutation-gate.mjs'),
    path.join(dir, 'scripts', 'ci', 'mutation-gate.mjs'),
  );
  for (const lib of ['proc', 'ui', 'reports', 'mutation-scope', 'mutation-evidence']) {
    cpSync(
      path.join(repoRoot, 'scripts', 'ci', 'lib', `${lib}.mjs`),
      path.join(dir, 'scripts', 'ci', 'lib', `${lib}.mjs`),
    );
  }
  const bin = path.join(dir, 'node_modules', '@stryker-mutator', 'core', 'bin');
  mkdirSync(bin, { recursive: true });
  writeFileSync(path.join(bin, 'stryker.js'), FAKE_STRYKER);
  const fixtures = path.join(dir, 'fixtures');
  mkdirSync(fixtures);
  writeFileSync(path.join(fixtures, 'calls.log'), '');
  for (const [leg, spec] of Object.entries(options.legs)) {
    writeFileSync(path.join(fixtures, `${leg}.json`), JSON.stringify(spec));
  }
  mkdirSync(path.join(dir, '.testfortress', 'reports'), { recursive: true });
  writeFileSync(
    path.join(dir, '.testfortress', 'baseline.json'),
    JSON.stringify(options.baseline, null, 2),
  );
  for (const file of options.files ?? []) {
    mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
    writeFileSync(path.join(dir, file), 'export {};\n');
  }

  const proc = spawnSync(
    process.execPath,
    [path.join(dir, 'scripts', 'ci', 'mutation-gate.mjs'), ...(options.args ?? [])],
    {
      cwd: dir,
      encoding: 'utf-8',
      env: { ...process.env, FORCE_COLOR: '0', HVAULT_FAKE_STRYKER_FIXTURES: fixtures },
    },
  );
  return {
    dir,
    code: proc.status ?? -1,
    output: `${proc.stdout}\n${proc.stderr}`,
    calls: readFileSync(path.join(fixtures, 'calls.log'), 'utf-8').split('\n').filter(Boolean),
    report: (name) => {
      const file = path.join(dir, '.testfortress', 'reports', name);
      return existsSync(file)
        ? (JSON.parse(readFileSync(file, 'utf-8')) as Record<string, unknown>)
        : null;
    },
  };
}

const SHARED_FILES = {
  'packages/shared/src/utils/a.ts': ['Killed', 'Killed', 'Killed', 'Survived'] as Status[],
};
const CLIENT_FILES = { 'packages/client/src/lib/b.ts': ['Killed', 'Survived'] as Status[] };
const SERVER_FILES = { 'packages/server/src/utils/c.ts': ['Killed', 'Killed'] as Status[] };

const SHARED_FLOOR = {
  overall: 75,
  totalMutants: 4,
  filesMutated: ['packages/shared/src/utils/a.ts'],
};
const CLIENT_FLOOR = {
  overall: 50,
  totalMutants: 2,
  filesMutated: ['packages/client/src/lib/b.ts'],
};
const SERVER_FLOOR = {
  overall: 100,
  totalMutants: 2,
  filesMutated: ['packages/server/src/utils/c.ts'],
};

describe('mutation-gate.mjs, per leg', () => {
  it('fails an UNBANKED leg, names the seed that records it, and still writes its evidence', () => {
    const run = runGate({
      legs: { shared: { report: strykerReport(SHARED_FILES) } },
      baseline: { version: 1 },
      args: ['--leg=shared'],
    });
    expect(run.code).toBe(1);
    expect(run.output).toContain('shared: UNBANKED');
    // Nothing is recorded yet, so the whole `mutation` family is the seed.
    expect(run.output).toContain('--accept --seed mutation --reason');
    const evidence = run.report('mutation-shared.json');
    expect(evidence).toMatchObject({
      task: 'test:mutation',
      leg: 'shared',
      overall: 75,
      totalMutants: 4,
      filesMutated: ['packages/shared/src/utils/a.ts'],
    });
    // A partial run NEVER writes the merged report.
    expect(run.report('mutation.json')).toBeNull();
    expect(run.calls).toEqual(['shared run']);
  });

  it("passes a --leg run that holds the leg's own floor, without writing the merged report", () => {
    const run = runGate({
      legs: { shared: { report: strykerReport(SHARED_FILES) } },
      baseline: { mutation: { legs: { shared: SHARED_FLOOR } } },
      args: ['--leg=shared'],
    });
    expect(run.code).toBe(0);
    expect(run.output).not.toContain('UNBANKED');
    expect(run.report('mutation-shared.json')).not.toBeNull();
    expect(run.report('mutation.json')).toBeNull();
  });

  it("fails a --leg run whose score fell below the leg's floor", () => {
    const run = runGate({
      legs: { shared: { report: strykerReport(SHARED_FILES) } },
      baseline: { mutation: { legs: { shared: { ...SHARED_FLOOR, overall: 75.01 } } } },
      args: ['--leg=shared'],
    });
    expect(run.code).toBe(1);
    expect(run.output).toContain('shared: overall 75% is below the recorded 75.01%');
  });

  it('fails a leg that stopped mutating a file its floor recorded', () => {
    const run = runGate({
      legs: { shared: { report: strykerReport(SHARED_FILES) } },
      baseline: {
        mutation: {
          legs: {
            shared: {
              ...SHARED_FLOOR,
              filesMutated: [...SHARED_FLOOR.filesMutated, 'packages/shared/src/utils/gone.ts'],
            },
          },
        },
      },
      args: ['--leg=shared'],
    });
    expect(run.code).toBe(1);
    expect(run.output).toContain('shared: scope narrowed: 1 file(s) are no longer mutated');
  });

  it('records whether a run was from scratch, which is what the ratchet banks from', () => {
    const cache = '.stryker-tmp/incremental-shared.json';
    // A warm run: Stryker reuses results, the cache survives, the evidence says
    // so, and the hint re-runs from scratch before seeding.
    const warm = runGate({
      legs: { shared: { report: strykerReport(SHARED_FILES) } },
      baseline: { version: 1 },
      args: ['--leg=shared'],
      files: [cache],
    });
    expect(warm.calls).toEqual(['shared run']);
    expect(warm.report('mutation-shared.json')?.['incremental']).toBe(true);
    expect(warm.output).toContain('1. npm run test:mutation -- --leg=shared --full');
    // Separate steps, never an `&&` chain: an unbanked leg's re-run exits 1, so a
    // chain would stop before the accept that records it.
    expect(warm.output).not.toMatch(/--full &&/);
    expect(warm.output).toContain(
      '3. node scripts/ci/ratchet-check.mjs --accept --seed mutation --reason',
    );
    expect(existsSync(path.join(warm.dir, cache))).toBe(true);
    // A --full run: Stryker is forced, the cache is deleted first, and the
    // evidence is marked bankable — so the hint needs no re-run.
    const cold = runGate({
      legs: { shared: { report: strykerReport(SHARED_FILES) } },
      baseline: { version: 1 },
      args: ['--leg=shared', '--full'],
      files: [cache],
    });
    expect(cold.calls).toEqual(['shared run --force']);
    expect(cold.report('mutation-shared.json')?.['incremental']).toBe(false);
    expect(cold.output).not.toContain('npm run test:mutation -- --leg=shared --full');
    expect(cold.output).toContain(
      '2. node scripts/ci/ratchet-check.mjs --accept --seed mutation --reason',
    );
    expect(existsSync(path.join(cold.dir, cache))).toBe(false);
  });

  it('names the leg alone as the seed once another leg is banked', () => {
    const run = runGate({
      legs: { client: { report: strykerReport(CLIENT_FILES) } },
      baseline: { mutation: { legs: { shared: SHARED_FLOOR } } },
      args: ['--leg=client'],
    });
    expect(run.code).toBe(1);
    // `--seed mutation` would be refused: the family is partly present.
    expect(run.output).toContain('--accept --seed mutation.legs.client --reason');
  });

  it("refuses a narrowed scope in the pre-flight, before Stryker is ever started, from ANY leg's record", () => {
    // A file the CLIENT leg's floor recorded that the declared globs no longer
    // select. There is no merged floor at all, which is exactly the state in which
    // a pre-flight reading only the merged set would have checked nothing.
    const excluded = 'packages/client/src/components/ui/button.tsx';
    const run = runGate({
      legs: { shared: { report: strykerReport(SHARED_FILES) } },
      baseline: {
        mutation: { legs: { client: { ...CLIENT_FLOOR, filesMutated: [excluded] } } },
      },
      files: [excluded],
    });
    expect(run.code).toBe(1);
    expect(run.output).toContain('scope narrowed');
    expect(run.output).toContain(excluded);
    expect(run.calls).toEqual([]);
  });

  it('holds every completed leg to its own floor in a full run, and fails the unbanked leg and the absent merged floor', () => {
    const run = runGate({
      legs: {
        shared: { report: strykerReport(SHARED_FILES) },
        client: { report: strykerReport(CLIENT_FILES) },
        server: { report: strykerReport(SERVER_FILES) },
      },
      baseline: { mutation: { legs: { shared: SHARED_FLOOR, client: CLIENT_FLOOR } } },
    });
    expect(run.code).toBe(1);
    expect(run.output).toContain('server: UNBANKED');
    expect(run.output).toContain('merged: no merged mutation floor');
    expect(run.output).not.toContain('shared: UNBANKED');
    expect(run.output).not.toContain('client: UNBANKED');
    // All three legs completed, so the merged report IS written — it is what the
    // merged seed reads — and so is each leg's own.
    expect(run.report('mutation.json')).toMatchObject({ overall: 75, totalMutants: 8 });
    for (const leg of ['shared', 'client', 'server']) {
      expect(run.report(`mutation-${leg}.json`), leg).not.toBeNull();
    }
    expect(run.calls).toEqual(['shared run', 'client run', 'server run']);
  });

  it('passes a full run only when every leg AND the merged figures hold their floors', () => {
    const run = runGate({
      legs: {
        shared: { report: strykerReport(SHARED_FILES) },
        client: { report: strykerReport(CLIENT_FILES) },
        server: { report: strykerReport(SERVER_FILES) },
      },
      baseline: {
        mutation: {
          overall: 75,
          totalMutants: 8,
          filesMutated: [
            ...CLIENT_FLOOR.filesMutated,
            ...SERVER_FLOOR.filesMutated,
            ...SHARED_FLOOR.filesMutated,
          ].sort(),
          legs: { shared: SHARED_FLOOR, client: CLIENT_FLOOR, server: SERVER_FLOOR },
        },
      },
    });
    expect(run.code).toBe(0);
    expect(run.output).not.toContain('mutation failure');
  });

  it('never writes the merged report when a leg breaks, and still holds the legs that completed', () => {
    const run = runGate({
      legs: {
        shared: { report: strykerReport(SHARED_FILES) },
        client: { exitCode: 1 },
        server: { report: strykerReport(SERVER_FILES) },
      },
      baseline: {
        mutation: {
          legs: { shared: { ...SHARED_FLOOR, overall: 90 }, server: SERVER_FLOOR },
        },
      },
    });
    expect(run.code).toBe(1);
    expect(run.report('mutation.json')).toBeNull();
    expect(run.report('mutation-client.json')).toBeNull();
    expect(run.report('mutation-shared.json')).not.toBeNull();
    expect(run.output).toContain('client: stryker exited 1');
    // The shared leg completed, so its own floor was checked even in a broken run.
    expect(run.output).toContain('shared: overall 75% is below the recorded 90%');
  });
});
