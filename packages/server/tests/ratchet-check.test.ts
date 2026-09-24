/**
 * The ratchet's own fixture suite.
 *
 * `audit:ratchet` guards the numbers, and the reason it exists is that the
 * cheapest way to make a percentage go up is to shrink what it measures. So the
 * cases that matter are not "does it compare two numbers" but:
 *
 *   · a coverage percentage that RISES while the denominator falls,
 *   · a percentage that rises while the measured file set loses a file,
 *   · a baseline field whose report stopped being produced,
 *   · a registered gate that disappeared from the manifest,
 *   · a lower-is-better field, which is more than half of them, being ratcheted
 *     the right way round,
 *   · `--accept` refusing to record anything while a regression stands.
 *
 * Each fixture is a throw-away repository with hand-written reports, so the
 * extractors are exercised on the real formats (LCOV, JUnit, the integrity
 * report) rather than on a mock of them.
 */
import { describe, it, expect, afterAll } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  MUTATION_DIFF_BUDGETS,
  MUTATION_DIFF_FLOOR,
} from '../../../scripts/ci/lib/mutation-scope.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..', '..', '..');
const RATCHET = path.join(repoRoot, 'scripts', 'ci', 'ratchet-check.mjs');

interface RatchetResult {
  exitCode: number;
  // `want`/`got`/`dir` are on every regression the script emits; they are typed
  // here because a case that asserts WHICH direction failed is stronger than one
  // asserting only that something did.
  regressions: { path: string; detail: string; want?: unknown; got?: unknown; dir?: string }[];
  missing: { path: string }[];
  absent: { path: string }[];
  undeclared: string[];
  staleReports: string[];
  deferred: { path: string; owner: string }[];
  improvements: { path: string; want: unknown; got: unknown }[];
  /** Only an `--accept` run emits these two. */
  accepted?: { path: string; value: unknown }[];
  seeded?: { path: string; value: unknown; dir: string }[];
  stderr: string;
}

const dirs: string[] = [];
afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

/** LCOV with exactly the counters the extractor reads. */
function lcov(
  files: { name: string; lines: number; hit: number; branches?: number; branchHit?: number }[],
): string {
  return files
    .map(
      (f) =>
        `TN:\nSF:${f.name}\nFNF:0\nFNH:0\nBRF:${f.branches ?? 0}\nBRH:${f.branchHit ?? 0}\n` +
        `LF:${f.lines}\nLH:${f.hit}\nend_of_record\n`,
    )
    .join('');
}

const junit = (tests: number): string =>
  `<?xml version="1.0" encoding="UTF-8" ?>\n<testsuites name="vitest" tests="${tests}" failures="0">\n</testsuites>\n`;

const MANIFEST = {
  version: 1,
  reportDir: '.testfortress/reports',
  tasks: {
    lint: { cmd: 'eslint .', tier: 0, gate: 'clean', report: 'lint.log' },
    'test:unit': {
      cmd: 'vitest run',
      tier: 1,
      gate: 'all pass',
      report: 'junit-app.xml',
      coverage: ['packages/app/coverage/cobertura-coverage.xml'],
    },
    // TIER 2, which is what makes its fields DEFERRABLE rather than required to
    // be fresh on every run. The cases at the end of this file are about
    // exactly that distinction.
    'test:mutation': {
      cmd: 'stryker run',
      tier: 2,
      gate: 'the suite kills at least the recorded share of mutants',
      report: 'mutation.json',
    },
  },
};

/**
 * A Stryker-shaped report: per file, a list of mutants with a status.
 *
 * `Ignored` is present on purpose. It is the status a CONFIGURATION produces
 * (`ignoreStatic: true`), and it must stay out of both halves of the score —
 * otherwise turning that option on would raise the percentage while testing
 * hundreds fewer mutants.
 */
function mutationReport(
  files: { name: string; killed: number; survived: number; ignored?: number }[],
  extra: Record<string, unknown> = {},
): string {
  return JSON.stringify({
    // What `mutation-gate.mjs --full` writes. The ratchet refuses to RAISE a
    // mutation floor from anything else, so a fixture that omitted the flag would
    // be a report too old to say, and every accept case below would be refused.
    incremental: false,
    ...extra,
    files: Object.fromEntries(
      files.map((f) => [
        f.name,
        {
          mutants: [
            ...Array.from({ length: f.killed }, () => ({ status: 'Killed' })),
            ...Array.from({ length: f.survived }, () => ({ status: 'Survived' })),
            ...Array.from({ length: f.ignored ?? 0 }, () => ({ status: 'Ignored' })),
          ],
        },
      ]),
    ),
  });
}

/** 14 of 20 scored mutants killed = 70%, with five ignored ones that must not count. */
const HEALTHY_MUTATION = [
  { name: 'packages/app/src/index.ts', killed: 8, survived: 2, ignored: 5 },
  { name: 'packages/app/src/other.ts', killed: 6, survived: 4 },
];

interface Fixture {
  baseline: Record<string, unknown>;
  reports?: Record<string, string>;
  manifest?: Record<string, unknown>;
  /** Report paths whose mtime is pushed into the past, so they describe another tree. */
  stale?: string[];
  args?: string[];
}

function ratchet(fixture: Fixture): RatchetResult & { dir: string } {
  const dir = mkdtempSync(path.join(tmpdir(), 'hv-ratchet-'));
  dirs.push(dir);
  execFileSync('git', ['init', '-q'], { cwd: dir });

  const write = (rel: string, contents: string): void => {
    const p = path.join(dir, rel);
    mkdirSync(path.dirname(p), { recursive: true });
    writeFileSync(p, contents, 'utf-8');
  };

  // A source file, so the freshness rule has something to compare against.
  write('packages/app/src/index.ts', 'export const a = 1;\n');
  write('.testfortress/verify.json', JSON.stringify(fixture.manifest ?? MANIFEST, null, 2));
  write('.testfortress/baseline.json', JSON.stringify(fixture.baseline, null, 2));
  for (const [rel, contents] of Object.entries(fixture.reports ?? {})) write(rel, contents);

  // Reports describe the tree as it is NOW. mtimes are set explicitly rather
  // than relying on write order, because the source and the report are written
  // in the same millisecond on a fast disk.
  const future = Date.now() / 1000 + 60;
  const past = Date.now() / 1000 - 3600;
  for (const rel of Object.keys(fixture.reports ?? {})) {
    const when = fixture.stale?.includes(rel) ? past : future;
    utimesSync(path.join(dir, rel), when, when);
  }

  const proc = spawnSync(process.execPath, [RATCHET, '--json', ...(fixture.args ?? [])], {
    cwd: dir,
    encoding: 'utf-8',
  });
  const parsed = proc.stdout.trim()
    ? (JSON.parse(proc.stdout) as Omit<RatchetResult, 'exitCode' | 'stderr'>)
    : ({
        regressions: [],
        missing: [],
        absent: [],
        undeclared: [],
        staleReports: [],
        deferred: [],
        improvements: [],
      } as Omit<RatchetResult, 'exitCode' | 'stderr'>);
  return { ...parsed, exitCode: proc.status ?? -1, stderr: proc.stderr, dir };
}

/** The shape a healthy run produces: 90% of 100 lines over two files, 500 tests. */
const HEALTHY_REPORTS = {
  'packages/app/coverage/lcov.info': lcov([
    { name: 'src/index.ts', lines: 60, hit: 54 },
    { name: 'src/other.ts', lines: 40, hit: 36 },
  ]),
  '.testfortress/reports/junit-app.xml': junit(500),
  '.testfortress/reports/integrity.json': JSON.stringify({
    summary: {
      suppressions: { count: 3, totalHits: 5 },
      fingerprints: {
        excludeHash: 'aaaa',
        gateFilesHash: 'bbbb',
        selfHash: 'cccc',
        gitignoreHash: 'dddd',
      },
    },
  }),
  '.testfortress/reports/warnings.json': JSON.stringify({ lint: 0, typecheck: 0, compiler: 0 }),
  '.testfortress/reports/mutation.json': mutationReport(HEALTHY_MUTATION),
};

const HEALTHY_BASELINE = {
  version: 1,
  tests: { count: 500 },
  warnings: { lint: 0, typecheck: 0, compiler: 0 },
  suppressions: { count: 3, totalHits: 5 },
  packages: {
    'packages/app': {
      coverage: {
        line: 90,
        linesTotal: 100,
        filesMeasured: ['src/index.ts', 'src/other.ts'],
      },
      tests: { count: 500 },
    },
  },
  mutation: {
    overall: 70,
    totalMutants: 20,
    filesMutated: ['packages/app/src/index.ts', 'packages/app/src/other.ts'],
    // A module key may not contain a dot: the baseline is flattened on `.`, and
    // a field's direction is resolved through a wildcard over its LAST segment.
    modules: { 'packages/app/src/index_ts': 80 },
    scopeGlobs: ['packages/app/src/**'],
  },
  tasks: ['lint', 'test:mutation', 'test:unit'],
  // Read from SOURCE on every full run, like the bundle budgets, so the fixture
  // carries the real committed values: anything else would be a regression or an
  // improvement in every case below that is not about them.
  mutationDiff: { floor: MUTATION_DIFF_FLOOR, budget: { ...MUTATION_DIFF_BUDGETS } },
  integrity: {
    excludeHash: 'aaaa',
    gateFilesHash: 'bbbb',
    selfHash: 'cccc',
    gitignoreHash: 'dddd',
  },
  meta: {
    fields: [
      'integrity.excludeHash',
      'integrity.gateFilesHash',
      'integrity.gitignoreHash',
      'integrity.selfHash',
      'mutation.filesMutated',
      'mutation.modules.packages/app/src/index_ts',
      'mutation.overall',
      'mutation.scopeGlobs',
      'mutation.totalMutants',
      ...Object.keys(MUTATION_DIFF_BUDGETS).map((leg) => `mutationDiff.budget.${leg}`),
      'mutationDiff.floor',
      'packages.packages/app.coverage.filesMeasured',
      'packages.packages/app.coverage.line',
      'packages.packages/app.coverage.linesTotal',
      'packages.packages/app.tests.count',
      'suppressions.count',
      'suppressions.totalHits',
      'tasks',
      'tests.count',
      'warnings.compiler',
      'warnings.lint',
      'warnings.typecheck',
    ],
  },
};

describe('audit:ratchet', () => {
  it('passes when every measured field matches the baseline', () => {
    const result = ratchet({ baseline: HEALTHY_BASELINE, reports: HEALTHY_REPORTS });
    expect(result.regressions).toEqual([]);
    expect(result.missing).toEqual([]);
    expect(result.absent).toEqual([]);
    expect(result.exitCode).toBe(0);
  });

  describe('a task that re-runs tests another gate already counted', () => {
    /** A second task whose JUnit report covers a SUBSET of `test:unit`'s tests. */
    const withRerun = (countsTests: boolean | undefined): Record<string, unknown> => ({
      ...MANIFEST,
      tasks: {
        ...MANIFEST.tasks,
        'test:subset': {
          cmd: 'vitest run --config subset',
          tier: 1,
          gate: 'the subset passes',
          report: 'junit-subset.xml',
          ...(countsTests === undefined ? {} : { countsTests }),
        },
      },
    });
    const reports = {
      ...HEALTHY_REPORTS,
      '.testfortress/reports/junit-subset.xml': junit(40),
    };

    it('leaves tests.count a headcount when the task declares countsTests: false', () => {
      // 500, not 540: the 40 are 40 of the 500, re-executed. Ratcheting them
      // twice would make the number meaningless in the improving direction,
      // where nothing ever complains.
      const result = ratchet({
        baseline: HEALTHY_BASELINE,
        reports,
        manifest: withRerun(false),
      });
      expect(result.regressions).toEqual([]);
      expect(result.missing).toEqual([]);
      expect(result.improvements.map((entry) => entry.path)).not.toContain('tests.count');
      expect(result.exitCode).toBe(0);
    });

    it('still requires that report to be present and fresh', () => {
      // The flag excuses the task from the SUM, never from the evidence: a gate
      // that writes nothing must still make the count unmeasurable, or
      // `countsTests: false` becomes a way to register a gate that need not run.
      const { '.testfortress/reports/junit-subset.xml': _absent, ...withoutSubset } = reports;
      const result = ratchet({
        baseline: HEALTHY_BASELINE,
        reports: withoutSubset,
        manifest: withRerun(false),
      });
      expect(result.missing.map((entry) => entry.path)).toContain('tests.count');
      expect(result.exitCode).not.toBe(0);
    });

    it('counts the report by default, so the flag has to be asked for', () => {
      const result = ratchet({
        baseline: HEALTHY_BASELINE,
        reports,
        manifest: withRerun(undefined),
      });
      expect(result.improvements).toContainEqual(
        expect.objectContaining({ path: 'tests.count', got: 540 }),
      );
    });
  });

  /**
   * The flagship case. 54 of 60 lines is 90%, and dropping the second file
   * raises the percentage to 90% over 60 lines instead of 100 — the same number
   * over less code. A ratchet that only compares percentages calls this a pass.
   */
  it('fails when the coverage percentage holds but the denominator falls', () => {
    const result = ratchet({
      baseline: HEALTHY_BASELINE,
      reports: {
        ...HEALTHY_REPORTS,
        'packages/app/coverage/lcov.info': lcov([{ name: 'src/index.ts', lines: 60, hit: 57 }]),
      },
    });
    const paths = result.regressions.map((r) => r.path);
    expect(paths).toContain('packages.packages/app.coverage.linesTotal');
    expect(paths).toContain('packages.packages/app.coverage.filesMeasured');
    expect(result.regressions.find((r) => r.path.endsWith('filesMeasured'))?.detail).toMatch(
      /src\/other\.ts/,
    );
    expect(result.exitCode).toBe(1);
  });

  it('fails when the percentage RISES while the measured file set loses a file', () => {
    const result = ratchet({
      baseline: HEALTHY_BASELINE,
      reports: {
        ...HEALTHY_REPORTS,
        // 100% line coverage, and a smaller world.
        'packages/app/coverage/lcov.info': lcov([{ name: 'src/index.ts', lines: 100, hit: 100 }]),
      },
    });
    expect(result.improvements.map((i) => i.path)).toContain('packages.packages/app.coverage.line');
    expect(result.regressions.map((r) => r.path)).toContain(
      'packages.packages/app.coverage.filesMeasured',
    );
    expect(result.exitCode).toBe(1);
  });

  it('fails when the percentage RISES while linesTotal falls and the file set is intact', () => {
    // The purest form of the cheat, and the one the measured-file-set defence
    // cannot see: both files are still there, so `filesMeasured` is unchanged
    // and its superset check passes. What moved is the DENOMINATOR — 40 lines
    // deleted, of which the deleted ones happened to be the uncovered ones — so
    // the percentage climbs from 90% to 100% while ten fewer lines are covered
    // than before. Only the absolute `linesTotal` catches it, which is why the
    // field is ratcheted in absolute terms rather than left as a denominator
    // nobody watches.
    const result = ratchet({
      baseline: HEALTHY_BASELINE,
      reports: {
        ...HEALTHY_REPORTS,
        'packages/app/coverage/lcov.info': lcov([
          { name: 'src/index.ts', lines: 40, hit: 40 },
          { name: 'src/other.ts', lines: 20, hit: 20 },
        ]),
      },
    });
    expect(result.improvements.map((i) => i.path)).toContain('packages.packages/app.coverage.line');
    expect(result.regressions.map((r) => r.path)).toContain(
      'packages.packages/app.coverage.linesTotal',
    );
    // The file set is genuinely untouched, so nothing else is masking the catch.
    expect(result.regressions.map((r) => r.path)).not.toContain(
      'packages.packages/app.coverage.filesMeasured',
    );
    expect(result.exitCode).toBe(1);
  });

  it('fails when the BRANCH percentage rises while the branch denominator falls', () => {
    // The same cheat as the line case above, on the metric that has the least
    // headroom in this repository — and it was invisible until the denominator
    // was recorded: `parseLcov` computed BRF and threw it away, so `coverage.branch`
    // was the one percentage in the baseline with nothing behind it. Here twelve
    // branches are deleted, all of them uncovered, and the ratio climbs from 80%
    // to 100% while four fewer branches are exercised than before.
    const before = {
      ...HEALTHY_BASELINE,
      packages: {
        'packages/app': {
          ...HEALTHY_BASELINE.packages['packages/app'],
          coverage: {
            ...HEALTHY_BASELINE.packages['packages/app'].coverage,
            branch: 80,
            branchesTotal: 20,
          },
        },
      },
      meta: {
        fields: [
          ...HEALTHY_BASELINE.meta.fields,
          'packages.packages/app.coverage.branch',
          'packages.packages/app.coverage.branchesTotal',
        ].sort(),
      },
    };
    const result = ratchet({
      baseline: before,
      reports: {
        ...HEALTHY_REPORTS,
        'packages/app/coverage/lcov.info': lcov([
          { name: 'src/index.ts', lines: 60, hit: 54, branches: 8, branchHit: 8 },
          { name: 'src/other.ts', lines: 40, hit: 36, branches: 0, branchHit: 0 },
        ]),
      },
    });
    expect(result.improvements.map((i) => i.path)).toContain(
      'packages.packages/app.coverage.branch',
    );
    expect(result.regressions.map((r) => r.path)).toContain(
      'packages.packages/app.coverage.branchesTotal',
    );
    expect(result.exitCode).toBe(1);
  });

  it('pins the committed OpenAPI snapshot by content, so a same-version refresh is a regression', () => {
    // The path/operation counts catch a snapshot that SHRANK. They cannot catch
    // the regeneration that keeps its shape: delete a response property from the
    // served contract and refresh the snapshot in the same commit, and oasdiff
    // compares the new document against a base that already agrees with it —
    // zero findings, unchanged counts, a breaking change shipped under a version
    // that promises none.
    const baseline = {
      ...HEALTHY_BASELINE,
      openapi: { snapshotPaths: 47, snapshotOperations: 53, snapshotHash: 'abcdef0123456789' },
      meta: {
        fields: [
          ...HEALTHY_BASELINE.meta.fields,
          'openapi.snapshotHash',
          'openapi.snapshotOperations',
          'openapi.snapshotPaths',
        ].sort(),
      },
    };
    const report = (hash: string): string =>
      JSON.stringify({ snapshot: { paths: 47, operations: 53, hash } });

    const unchanged = ratchet({
      baseline,
      reports: {
        ...HEALTHY_REPORTS,
        '.testfortress/reports/openapi-compat.json': report('abcdef0123456789'),
      },
    });
    expect(unchanged.regressions).toEqual([]);
    expect(unchanged.exitCode).toBe(0);

    const refreshed = ratchet({
      baseline,
      reports: {
        ...HEALTHY_REPORTS,
        // Same 47 paths, same 53 operations, different bytes.
        '.testfortress/reports/openapi-compat.json': report('0000000000000000'),
      },
    });
    const pinned = refreshed.regressions.find((r) => r.path === 'openapi.snapshotHash');
    expect(pinned?.dir).toBe('pin');
    expect(refreshed.exitCode).toBe(1);
  });

  describe('patch coverage, which is measured by a gate rather than by a suite', () => {
    const withDiff = (diff: number): Record<string, string> => ({
      ...HEALTHY_REPORTS,
      '.testfortress/reports/coverage.json': JSON.stringify({ coverage: { diff } }),
    });
    const baselineWithDiff = {
      ...HEALTHY_BASELINE,
      coverage: { diff: 100 },
      meta: { fields: [...HEALTHY_BASELINE.meta.fields, 'coverage.diff'].sort() },
    };

    it('reads coverage.diff from the gate report and passes when it holds at 100', () => {
      const result = ratchet({ baseline: baselineWithDiff, reports: withDiff(100) });
      expect(result.regressions).toEqual([]);
      expect(result.missing).toEqual([]);
      expect(result.exitCode).toBe(0);
    });

    it('fails when patch coverage drops below the pinned 100', () => {
      const result = ratchet({ baseline: baselineWithDiff, reports: withDiff(97.5) });
      expect(result.regressions.map((r) => r.path)).toContain('coverage.diff');
      expect(result.exitCode).toBe(1);
    });

    it('treats a missing coverage report as unmeasured, never as a pass', () => {
      // `coverage:check` is TIER 1: it runs on every push, so unlike the
      // mutation fields there is nothing to defer to. A run that produced no
      // report has not measured patch coverage, and saying so is the only
      // honest answer — the alternative is a gate that disappears quietly.
      const result = ratchet({ baseline: baselineWithDiff, reports: HEALTHY_REPORTS });
      expect(result.missing.map((m) => m.path)).toContain('coverage.diff');
      expect(result.deferred.map((d) => d.path)).not.toContain('coverage.diff');
      expect(result.exitCode).toBe(1);
    });
  });

  it('fails when a baseline field has no fresh report at all', () => {
    const { 'packages/app/coverage/lcov.info': _dropped, ...withoutCoverage } = HEALTHY_REPORTS;
    const result = ratchet({ baseline: HEALTHY_BASELINE, reports: withoutCoverage });
    expect(result.missing.map((m) => m.path)).toEqual(
      expect.arrayContaining([
        'packages.packages/app.coverage.line',
        'packages.packages/app.coverage.linesTotal',
        'packages.packages/app.coverage.filesMeasured',
      ]),
    );
    expect(result.exitCode).toBe(1);
  });

  it('fails when a report is older than the newest source file', () => {
    const result = ratchet({
      baseline: HEALTHY_BASELINE,
      reports: HEALTHY_REPORTS,
      stale: ['.testfortress/reports/junit-app.xml'],
    });
    expect(result.staleReports).toContain('.testfortress/reports/junit-app.xml');
    expect(result.exitCode).toBe(1);
  });

  it('fails when a registered gate disappears from the manifest', () => {
    const result = ratchet({
      baseline: HEALTHY_BASELINE,
      reports: HEALTHY_REPORTS,
      manifest: { ...MANIFEST, tasks: { 'test:unit': MANIFEST.tasks['test:unit'] } },
    });
    const gone = result.regressions.find((r) => r.path === 'tasks');
    expect(gone?.detail).toMatch(/lint.*can no longer fail/s);
    expect(result.exitCode).toBe(1);
  });

  it('fails when a baseline field is deleted, because a deleted field is a deleted gate', () => {
    const baseline = JSON.parse(JSON.stringify(HEALTHY_BASELINE)) as typeof HEALTHY_BASELINE;
    delete (baseline.packages['packages/app'].coverage as Record<string, unknown>).filesMeasured;
    const result = ratchet({ baseline, reports: HEALTHY_REPORTS });
    expect(result.regressions.map((r) => r.path)).toContain('meta.fields');
    expect(result.absent.map((a) => a.path)).toContain('coverage.filesMeasured');
    expect(result.exitCode).toBe(1);
  });

  it('treats a required field that never entered the baseline as an absent gate', () => {
    const result = ratchet({
      baseline: { version: 1, tests: { count: 1 }, meta: { fields: ['tests.count'] } },
      reports: HEALTHY_REPORTS,
    });
    expect(result.absent.map((a) => a.path)).toEqual(
      expect.arrayContaining(['coverage.filesMeasured', 'suppressions.count', 'integrity']),
    );
    expect(result.exitCode).toBe(1);
  });

  describe('direction, which is wrong for more than half the fields', () => {
    it('fails when a lower-is-better field RISES', () => {
      const result = ratchet({
        baseline: HEALTHY_BASELINE,
        reports: {
          ...HEALTHY_REPORTS,
          '.testfortress/reports/warnings.json': JSON.stringify({
            lint: 4,
            typecheck: 0,
            compiler: 0,
          }),
        },
      });
      expect(result.regressions.find((r) => r.path === 'warnings.lint')?.detail).toBe(
        'lower-is-better',
      );
      expect(result.exitCode).toBe(1);
    });

    it('records a lower-is-better field FALLING as an improvement, never as a regression', () => {
      const result = ratchet({
        baseline: HEALTHY_BASELINE,
        reports: {
          ...HEALTHY_REPORTS,
          '.testfortress/reports/integrity.json': JSON.stringify({
            summary: {
              suppressions: { count: 1, totalHits: 1 },
              fingerprints: HEALTHY_BASELINE.integrity,
            },
          }),
        },
      });
      expect(result.regressions).toEqual([]);
      expect(result.improvements.map((i) => i.path)).toEqual(
        expect.arrayContaining(['suppressions.count', 'suppressions.totalHits']),
      );
      expect(result.exitCode).toBe(0);
    });

    it('fails when a pinned fingerprint changes', () => {
      const result = ratchet({
        baseline: HEALTHY_BASELINE,
        reports: {
          ...HEALTHY_REPORTS,
          '.testfortress/reports/integrity.json': JSON.stringify({
            summary: {
              suppressions: { count: 3, totalHits: 5 },
              fingerprints: { ...HEALTHY_BASELINE.integrity, gitignoreHash: 'WIDENED' },
            },
          }),
        },
      });
      expect(result.regressions.find((r) => r.path === 'integrity.gitignoreHash')?.detail).toBe(
        'pinned value changed',
      );
      expect(result.exitCode).toBe(1);
    });

    it('refuses to guess a direction for a field nobody declared one for', () => {
      const result = ratchet({
        baseline: { ...HEALTHY_BASELINE, invented: { metric: 5 } },
        reports: HEALTHY_REPORTS,
      });
      expect(result.undeclared).toContain('invented.metric');
      expect(result.exitCode).toBe(1);
    });
  });

  describe('the mutation oracle, whose gate runs in a tier the push never reaches', () => {
    it('requires BOTH fields as soon as the baseline carries a mutation block, and neither before', () => {
      // The requirement is conditional, so both directions have to hold. A
      // baseline with no block at all is a repository that has not run the
      // oracle yet, and demanding a number nobody measured would leave a
      // permanently red gate whose cheapest cure is deleting baseline fields.
      const { mutation: _none, ...withoutMutation } = HEALTHY_BASELINE;
      const { '.testfortress/reports/mutation.json': _report, ...reportsWithout } = HEALTHY_REPORTS;
      const unmeasured = ratchet({
        baseline: {
          ...withoutMutation,
          meta: { fields: HEALTHY_BASELINE.meta.fields.filter((f) => !f.startsWith('mutation.')) },
        },
        reports: reportsWithout,
      });
      expect(unmeasured.absent).toEqual([]);
      expect(unmeasured.exitCode).toBe(0);

      // …but a block that carries the score WITHOUT the measured file set reads
      // as a gate while the scope-narrowing defence is silently off.
      const { filesMutated: _dropped, ...partialMutation } = HEALTHY_BASELINE.mutation;
      const partial = ratchet({
        baseline: {
          ...HEALTHY_BASELINE,
          mutation: partialMutation,
          meta: {
            fields: HEALTHY_BASELINE.meta.fields.filter((f) => f !== 'mutation.filesMutated'),
          },
        },
        reports: HEALTHY_REPORTS,
      });
      expect(partial.absent.map((a) => a.path)).toContain('mutation.filesMutated');
      expect(partial.exitCode).toBe(1);
    });

    it('scores from the per-mutant statuses, and never from a headline the report states itself', () => {
      // A gate that reports a number it did not measure is precisely what this
      // file exists to catch, so the `overall` in the report is IGNORED and the
      // score is recomputed. The fixture claims 99; the mutants say 70.
      const result = ratchet({
        baseline: { ...HEALTHY_BASELINE, mutation: { ...HEALTHY_BASELINE.mutation, overall: 60 } },
        reports: {
          ...HEALTHY_REPORTS,
          '.testfortress/reports/mutation.json': mutationReport(HEALTHY_MUTATION, {
            overall: 99,
            mutationScore: 99,
          }),
        },
      });
      const improved = result.improvements.find((i) => i.path === 'mutation.overall');
      expect(improved?.got).toBe(70);
      expect(result.exitCode).toBe(0);
    });

    it('keeps Ignored mutants out of the denominator, so skipping them cannot raise the score', () => {
      // `ignoreStatic: true` turns tested mutants into ignored ones. If they
      // counted, the same report would read 14/25 = 56%; if they were dropped
      // from BOTH halves silently, the denominator would stop being a gate. It
      // is the denominator that catches it: 20, not 25.
      const result = ratchet({
        baseline: {
          ...HEALTHY_BASELINE,
          mutation: { ...HEALTHY_BASELINE.mutation, totalMutants: 15, overall: 60 },
        },
        reports: HEALTHY_REPORTS,
      });
      expect(result.improvements.find((i) => i.path === 'mutation.totalMutants')?.got).toBe(20);
      expect(result.improvements.find((i) => i.path === 'mutation.overall')?.got).toBe(70);
    });

    it('fails when the score rises while a file drops out of the mutated set', () => {
      // The mutation-side twin of the coverage case above, and the reason the
      // measured file set is ratcheted rather than the config globs: narrowing
      // a scope normally GROWS the glob list, so a superset check on globs
      // passes the exact cheat it was meant to catch.
      const result = ratchet({
        baseline: HEALTHY_BASELINE,
        reports: {
          ...HEALTHY_REPORTS,
          '.testfortress/reports/mutation.json': mutationReport([
            { name: 'packages/app/src/index.ts', killed: 10, survived: 0 },
          ]),
        },
      });
      expect(result.improvements.map((i) => i.path)).toContain('mutation.overall');
      expect(result.regressions.map((r) => r.path)).toContain('mutation.filesMutated');
      expect(result.regressions.map((r) => r.path)).toContain('mutation.totalMutants');
      expect(result.exitCode).toBe(1);
    });

    it('fails when a core module falls, even while the overall score holds', () => {
      // The whole point of a per-module threshold: an average over 20 mutants
      // hides a crypto module going from 80% to 50%.
      const result = ratchet({
        baseline: HEALTHY_BASELINE,
        reports: {
          ...HEALTHY_REPORTS,
          '.testfortress/reports/mutation.json': mutationReport([
            { name: 'packages/app/src/index.ts', killed: 5, survived: 5, ignored: 5 },
            { name: 'packages/app/src/other.ts', killed: 9, survived: 1 },
          ]),
        },
      });
      expect(result.regressions.map((r) => r.path)).toContain(
        'mutation.modules.packages/app/src/index_ts',
      );
      expect(result.exitCode).toBe(1);
    });

    it('DEFERS the fields when the tier-2 gate has not run, rather than reporting them unmeasured', () => {
      // The push tier does not run `test:mutation`, so requiring a fresh report
      // on every run would make this gate permanently red — and the cheapest
      // escape from a permanently red gate is deleting the baseline fields,
      // which is the pressure this whole file exists to remove.
      const { '.testfortress/reports/mutation.json': _absent, ...withoutMutation } =
        HEALTHY_REPORTS;
      const result = ratchet({ baseline: HEALTHY_BASELINE, reports: withoutMutation });
      expect(result.deferred.map((d) => d.path)).toContain('mutation.overall');
      expect(result.deferred.map((d) => d.path)).toContain('mutation.filesMutated');
      expect(result.missing.map((m) => m.path)).not.toContain('mutation.overall');
      expect(result.exitCode).toBe(0);
    });

    it('defers a STALE mutation report too, because its gate did not run in this invocation', () => {
      const result = ratchet({
        baseline: HEALTHY_BASELINE,
        reports: HEALTHY_REPORTS,
        stale: ['.testfortress/reports/mutation.json'],
      });
      // Deferred, and NOT counted as a stale report — a stale artifact from a
      // gate that only runs on demand is the expected state, not a finding.
      expect(result.deferred.map((d) => d.path)).toContain('mutation.overall');
      expect(result.staleReports).not.toContain('.testfortress/reports/mutation.json');
      expect(result.exitCode).toBe(0);
    });

    it('stops deferring the moment the gate is no longer registered at that tier', () => {
      // The condition that keeps deferral from being a hole: retire the gate,
      // or move it to a tier that never runs it, and every field it supplied
      // becomes the hard failure it would have been all along.
      const { '.testfortress/reports/mutation.json': _absent, ...withoutMutation } =
        HEALTHY_REPORTS;
      const { 'test:mutation': _gone, ...tasksWithoutMutation } = MANIFEST.tasks;
      const result = ratchet({
        baseline: HEALTHY_BASELINE,
        reports: withoutMutation,
        manifest: { ...MANIFEST, tasks: tasksWithoutMutation },
      });
      expect(result.missing.map((m) => m.path)).toContain('mutation.overall');
      expect(result.deferred).toEqual([]);
      // …and the disappearance is ALSO caught as a registered gate that vanished.
      expect(result.regressions.map((r) => r.path)).toContain('tasks');
      expect(result.exitCode).toBe(1);
    });

    it('stops deferring when the gate is moved to a tier the push DOES run', () => {
      // A gate promoted to T1 has no excuse for an absent report: it ran, or it
      // did not, and either way the number is measurable in this invocation.
      const { '.testfortress/reports/mutation.json': _absent, ...withoutMutation } =
        HEALTHY_REPORTS;
      const result = ratchet({
        baseline: HEALTHY_BASELINE,
        reports: withoutMutation,
        manifest: {
          ...MANIFEST,
          tasks: {
            ...MANIFEST.tasks,
            'test:mutation': { ...MANIFEST.tasks['test:mutation'], tier: 1 },
          },
        },
      });
      expect(result.missing.map((m) => m.path)).toContain('mutation.overall');
      expect(result.exitCode).toBe(1);
    });
  });

  describe('a floor per mutation leg, banked before the slowest leg ever completes', () => {
    const LEG_REPORT = '.testfortress/reports/mutation-shared.json';
    const SHARED_LEG = [
      { name: 'packages/shared/src/utils/a.ts', killed: 8, survived: 2, ignored: 3 },
      { name: 'packages/shared/src/schemas/vault.ts', killed: 3, survived: 1 },
    ];
    const SHARED_FLOOR = {
      overall: 70,
      totalMutants: 14,
      filesMutated: ['packages/shared/src/schemas/vault.ts', 'packages/shared/src/utils/a.ts'],
    };
    const read = (dir: string): Record<string, unknown> =>
      JSON.parse(readFileSync(path.join(dir, '.testfortress', 'baseline.json'), 'utf-8')) as Record<
        string,
        unknown
      >;
    const metaFor = (mutation: Record<string, unknown>): string[] => {
      const flat: string[] = [];
      const walk = (value: unknown, prefix: string): void => {
        if (value && typeof value === 'object' && !Array.isArray(value)) {
          for (const [key, inner] of Object.entries(value)) walk(inner, `${prefix}.${key}`);
        } else flat.push(prefix);
      };
      walk(mutation, 'mutation');
      return [
        ...HEALTHY_BASELINE.meta.fields.filter((f) => !f.startsWith('mutation.')),
        ...flat,
      ].sort();
    };
    /** HEALTHY_BASELINE with `mutation` replaced wholesale and meta.fields to match. */
    const withMutation = (
      mutation: Record<string, unknown> | undefined,
    ): Record<string, unknown> => {
      const { mutation: _dropped, ...rest } = HEALTHY_BASELINE;
      return mutation === undefined
        ? { ...rest, meta: { fields: metaFor({}) } }
        : { ...rest, mutation, meta: { fields: metaFor(mutation) } };
    };
    const { '.testfortress/reports/mutation.json': _merged, ...NO_MERGED_REPORT } = HEALTHY_REPORTS;
    const WITH_LEG_REPORT = { ...NO_MERGED_REPORT, [LEG_REPORT]: mutationReport(SHARED_LEG) };

    it("reads a leg's own report into that leg's fields, and never into the merged ones", () => {
      const result = ratchet({
        baseline: withMutation({ legs: { shared: { ...SHARED_FLOOR, overall: 60 } } }),
        reports: WITH_LEG_REPORT,
      });
      // 11 of 14 scored, the three Ignored ones in neither half.
      expect(result.improvements.find((i) => i.path === 'mutation.legs.shared.overall')?.got).toBe(
        78.57,
      );
      // The substring dispatch this replaced would have read `mutation-shared.json`
      // as the MERGED campaign. Nothing merged may be measured from it.
      expect(result.improvements.filter((i) => !i.path.startsWith('mutation.legs.'))).toEqual([]);
      expect(result.regressions).toEqual([]);
      // A block holding ONLY legs does not owe the merged pair: its slowest leg has
      // never completed, and demanding the merged figures would be demanding a
      // number nobody can yet measure.
      expect(result.absent).toEqual([]);
      expect(result.exitCode).toBe(0);
    });

    it("moves a banked leg's floor through the ordinary --accept, and records nothing it was not asked to", () => {
      const result = ratchet({
        baseline: withMutation({ legs: { shared: SHARED_FLOOR } }),
        reports: WITH_LEG_REPORT,
        args: ['--accept', '--reason', 'the shared leg improved'],
      });
      expect(result.exitCode).toBe(0);
      const after = read(result.dir) as { mutation: { legs: { shared: Record<string, unknown> } } };
      expect(after.mutation.legs.shared['overall']).toBe(78.57);
      // The leg's core module IS measured, but the comparison loop is driven by
      // the baseline's own keys, so a plain accept cannot bring it into existence:
      // that takes a seed, exactly as for the merged modules.
      expect(after.mutation.legs.shared['modules']).toBeUndefined();
    });

    it('requires BOTH fields of every banked leg', () => {
      const result = ratchet({
        baseline: withMutation({ legs: { shared: { overall: 70 } } }),
        reports: WITH_LEG_REPORT,
      });
      expect(result.absent.map((a) => a.path)).toEqual(['mutation.legs.shared.filesMutated']);
      expect(result.exitCode).toBe(1);
    });

    it('still owes the merged pair from an empty mutation block, as it always did', () => {
      const result = ratchet({ baseline: withMutation({}), reports: HEALTHY_REPORTS });
      expect(result.absent.map((a) => a.path).sort()).toEqual([
        'mutation.filesMutated',
        'mutation.overall',
      ]);
      expect(result.exitCode).toBe(1);
    });

    it('fails a leg whose score rises while it loses a file', () => {
      const result = ratchet({
        baseline: withMutation({ legs: { shared: { ...SHARED_FLOOR, overall: 50 } } }),
        reports: {
          ...NO_MERGED_REPORT,
          [LEG_REPORT]: mutationReport([
            { name: 'packages/shared/src/utils/a.ts', killed: 14, survived: 0 },
          ]),
        },
      });
      expect(result.improvements.map((i) => i.path)).toContain('mutation.legs.shared.overall');
      expect(result.regressions.map((r) => r.path)).toContain('mutation.legs.shared.filesMutated');
      expect(result.exitCode).toBe(1);
    });

    it('defers a banked leg whose report is absent or stale, exactly like the merged floor', () => {
      for (const fixture of [
        { reports: NO_MERGED_REPORT },
        { reports: WITH_LEG_REPORT, stale: [LEG_REPORT] },
      ]) {
        const result = ratchet({
          baseline: withMutation({ legs: { shared: SHARED_FLOOR } }),
          ...fixture,
        });
        expect(result.deferred.map((d) => d.path)).toContain('mutation.legs.shared.overall');
        expect(result.deferred.find((d) => d.path === 'mutation.legs.shared.overall')?.owner).toBe(
          'test:mutation',
        );
        expect(result.missing).toEqual([]);
        expect(result.staleReports).not.toContain(LEG_REPORT);
        expect(result.exitCode).toBe(0);
      }
    });

    it('stops deferring a leg the moment the campaign is no longer a registered tier-2 gate', () => {
      const { 'test:mutation': _gone, ...tasksWithoutMutation } = MANIFEST.tasks;
      const result = ratchet({
        baseline: withMutation({ legs: { shared: SHARED_FLOOR } }),
        reports: NO_MERGED_REPORT,
        manifest: { ...MANIFEST, tasks: tasksWithoutMutation },
      });
      expect(result.missing.map((m) => m.path)).toContain('mutation.legs.shared.overall');
      expect(result.deferred).toEqual([]);
      expect(result.exitCode).toBe(1);
    });

    it('refuses a leg the declaration no longer knows, rather than guessing its direction', () => {
      const result = ratchet({
        baseline: withMutation({ legs: { ghost: { overall: 70, filesMutated: ['x.ts'] } } }),
        reports: NO_MERGED_REPORT,
      });
      expect(result.undeclared).toContain('mutation.legs.ghost.overall');
      expect(result.exitCode).toBe(1);
    });

    it('fails, rather than defers, a floor field its FRESH report does not measure', () => {
      // Deferral means "the tier-2 gate has not run"; a fresh report means it has.
      // A core module the leg's floor records that the fresh run scored no mutants
      // in has not been deferred — it has disappeared.
      const result = ratchet({
        baseline: withMutation({
          legs: {
            shared: {
              ...SHARED_FLOOR,
              modules: { 'packages/shared/src/utils/gone/': 90 },
            },
          },
        }),
        reports: WITH_LEG_REPORT,
      });
      const missing = result.missing.find(
        (m) => m.path === 'mutation.legs.shared.modules.packages/shared/src/utils/gone/',
      );
      expect(missing).toBeDefined();
      expect(result.deferred.map((d) => d.path)).not.toContain(
        'mutation.legs.shared.modules.packages/shared/src/utils/gone/',
      );
      expect(result.exitCode).toBe(1);
    });

    it('refuses to raise, or to seed, a floor from evidence that was not measured from scratch', () => {
      const incremental = {
        ...NO_MERGED_REPORT,
        [LEG_REPORT]: mutationReport(SHARED_LEG, { incremental: true }),
      };
      // A seed from incremental evidence…
      const seed = ratchet({
        baseline: withMutation(undefined),
        reports: incremental,
        args: ['--accept', '--seed', 'mutation', '--reason', 'bank from a warm cache'],
      });
      expect(seed.exitCode).toBe(2);
      expect(seed.stderr).toMatch(/not measured from scratch/);
      expect(seed.stderr).toMatch(/--full/);
      expect(read(seed.dir)['mutation']).toBeUndefined();
      // …and an ordinary improvement from it, alike.
      const raise = ratchet({
        baseline: withMutation({ legs: { shared: { ...SHARED_FLOOR, overall: 60 } } }),
        reports: incremental,
        args: ['--accept', '--reason', 'raise from a warm cache'],
      });
      expect(raise.exitCode).toBe(2);
      const after = read(raise.dir) as { mutation: { legs: { shared: { overall: number } } } };
      expect(after.mutation.legs.shared.overall).toBe(60);
      // A report too old to say is treated exactly as an incremental one.
      const { incremental: _flag, ...silent } = JSON.parse(mutationReport(SHARED_LEG)) as Record<
        string,
        unknown
      >;
      const unknown = ratchet({
        baseline: withMutation(undefined),
        reports: { ...NO_MERGED_REPORT, [LEG_REPORT]: JSON.stringify(silent) },
        args: ['--accept', '--seed', 'mutation', '--reason', 'no provenance'],
      });
      expect(unknown.exitCode).toBe(2);
    });

    it("banks a leg measured from scratch even while the merged campaign's report is incremental", () => {
      // Each field is judged by its OWN evidence. The merged report's prefix is
      // `mutation.`, which every leg path also starts with; letting it claim them
      // would make a warm campaign run block the one from-scratch leg run that
      // is exactly what the refusal asks for.
      const result = ratchet({
        baseline: withMutation(undefined),
        reports: {
          ...WITH_LEG_REPORT,
          '.testfortress/reports/mutation.json': mutationReport(HEALTHY_MUTATION, {
            incremental: true,
          }),
        },
        args: ['--accept', '--seed', 'mutation.legs.shared', '--reason', 'bank the shared leg'],
      });
      expect(result.exitCode).toBe(0);
      const after = read(result.dir) as { mutation: Record<string, unknown> };
      expect(Object.keys(after.mutation)).toEqual(['legs']);
    });

    it('still COMPARES incremental evidence, because comparing is not banking', () => {
      const result = ratchet({
        baseline: withMutation({ legs: { shared: { ...SHARED_FLOOR, overall: 90 } } }),
        reports: {
          ...NO_MERGED_REPORT,
          [LEG_REPORT]: mutationReport(SHARED_LEG, { incremental: true }),
        },
      });
      expect(result.regressions.map((r) => r.path)).toContain('mutation.legs.shared.overall');
      expect(result.exitCode).toBe(1);
    });

    describe('seeding a leg', () => {
      it('seeds only what a leg run measured when the whole family is absent', () => {
        const result = ratchet({
          baseline: withMutation(undefined),
          reports: WITH_LEG_REPORT,
          args: ['--accept', '--seed', 'mutation', '--reason', 'bank the shared leg'],
        });
        expect(result.exitCode).toBe(0);
        const after = read(result.dir) as {
          mutation: Record<string, unknown> & { legs: { shared: Record<string, unknown> } };
          meta: { fields: string[] };
        };
        expect(after.mutation.legs.shared).toEqual({
          overall: 78.57,
          totalMutants: 14,
          filesMutated: SHARED_FLOOR.filesMutated,
          modules: { 'packages/shared/src/schemas/': 75 },
        });
        // No merged figure was measured, so none may be written.
        expect(Object.keys(after.mutation)).toEqual(['legs']);
        expect(after.meta.fields).toContain('mutation.legs.shared.filesMutated');
        expect((result.seeded ?? []).every((s) => s.path.startsWith('mutation.legs.shared.'))).toBe(
          true,
        );
      });

      it('refuses the whole family once one leg is banked, and accepts the next leg by name', () => {
        const baseline = withMutation({ legs: { shared: SHARED_FLOOR } });
        const clientReport = {
          ...WITH_LEG_REPORT,
          '.testfortress/reports/mutation-client.json': mutationReport([
            { name: 'packages/client/src/lib/b.ts', killed: 3, survived: 1 },
          ]),
        };
        const whole = ratchet({
          baseline,
          reports: clientReport,
          args: ['--accept', '--seed', 'mutation', '--reason', 'bank the client leg'],
        });
        expect(whole.exitCode).toBe(2);
        expect(whole.stderr).toMatch(/already records/);

        const byName = ratchet({
          baseline,
          reports: clientReport,
          args: ['--accept', '--seed', 'mutation.legs.client', '--reason', 'bank the client leg'],
        });
        expect(byName.exitCode).toBe(0);
        const after = read(byName.dir) as {
          mutation: { legs: Record<string, Record<string, unknown>> };
        };
        expect(after.mutation.legs['client']).toMatchObject({
          overall: 75,
          totalMutants: 4,
          filesMutated: ['packages/client/src/lib/b.ts'],
        });
        // The banked leg moved only through the improving direction, as any
        // existing floor does: 70 -> 78.57.
        expect(after.mutation.legs['shared']!['overall']).toBe(78.57);
      });

      it('refuses a seed that would write a score without its measured file set', () => {
        const result = ratchet({
          baseline: withMutation({ legs: { shared: SHARED_FLOOR } }),
          reports: {
            ...WITH_LEG_REPORT,
            '.testfortress/reports/mutation-client.json': mutationReport([
              { name: 'packages/client/src/lib/b.ts', killed: 3, survived: 1 },
            ]),
          },
          args: [
            '--accept',
            '--seed',
            'mutation.legs.client.overall',
            '--reason',
            'the score, but not the scope',
          ],
        });
        expect(result.exitCode).toBe(2);
        expect(result.stderr).toMatch(
          /missing required field\(s\) mutation\.legs\.client\.filesMutated/,
        );
        const after = read(result.dir) as { mutation: { legs: Record<string, unknown> } };
        expect(after.mutation.legs['client']).toBeUndefined();
      });
    });
  });

  describe('the per-change mutation floor and budgets, which are read from source', () => {
    const read = (dir: string): Record<string, unknown> =>
      JSON.parse(readFileSync(path.join(dir, '.testfortress', 'baseline.json'), 'utf-8')) as Record<
        string,
        unknown
      >;
    const { mutationDiff: _none, ...withoutDiff } = HEALTHY_BASELINE;
    const withoutDiffBaseline = {
      ...withoutDiff,
      meta: {
        fields: HEALTHY_BASELINE.meta.fields.filter((f) => !f.startsWith('mutationDiff.')),
      },
    };

    it('holds the committed values, and fails a baseline whose floor is higher than the source', () => {
      // The production change that turns this red is LOWERING the floor in
      // `mutation-scope.mjs`: the baseline remembers the old, higher value.
      const result = ratchet({
        baseline: {
          ...HEALTHY_BASELINE,
          mutationDiff: { ...HEALTHY_BASELINE.mutationDiff, floor: MUTATION_DIFF_FLOOR + 1 },
        },
        reports: HEALTHY_REPORTS,
      });
      expect(result.regressions.map((r) => r.path)).toEqual(['mutationDiff.floor']);
      expect(result.exitCode).toBe(1);
    });

    it('fails a leg whose committed sample budget shrank, because the budget is the denominator', () => {
      const result = ratchet({
        baseline: {
          ...HEALTHY_BASELINE,
          mutationDiff: {
            floor: MUTATION_DIFF_FLOOR,
            budget: { ...MUTATION_DIFF_BUDGETS, server: MUTATION_DIFF_BUDGETS.server + 1 },
          },
        },
        reports: HEALTHY_REPORTS,
      });
      expect(result.regressions.map((r) => r.path)).toEqual(['mutationDiff.budget.server']);
      expect(result.exitCode).toBe(1);
    });

    it('requires the family unconditionally, since source can always measure it', () => {
      const result = ratchet({ baseline: withoutDiffBaseline, reports: HEALTHY_REPORTS });
      expect(result.absent.map((a) => a.path).sort()).toEqual([
        'mutationDiff.budget',
        'mutationDiff.floor',
      ]);
      expect(result.exitCode).toBe(1);
    });

    it('seeds the family from source, which is the one cure for its absence', () => {
      const result = ratchet({
        baseline: withoutDiffBaseline,
        reports: HEALTHY_REPORTS,
        args: ['--accept', '--seed', 'mutationDiff', '--reason', 'register the per-change leg'],
      });
      expect(result.exitCode).toBe(0);
      const after = read(result.dir) as {
        mutationDiff: { floor: number; budget: Record<string, number> };
        meta: { fields: string[] };
      };
      expect(after.mutationDiff).toEqual({
        floor: MUTATION_DIFF_FLOOR,
        budget: MUTATION_DIFF_BUDGETS,
      });
      expect(after.meta.fields).toContain('mutationDiff.floor');
      expect((result.seeded ?? []).map((x) => x.path)).toContain('mutationDiff.floor');
    });

    it('refuses to seed half the family, so the absent half still blocks', () => {
      const result = ratchet({
        baseline: withoutDiffBaseline,
        reports: HEALTHY_REPORTS,
        args: ['--accept', '--seed', 'mutationDiff.floor', '--reason', 'only the floor'],
      });
      expect(result.exitCode).toBe(1);
      expect(result.stderr).toMatch(/ABSENT {5}mutationDiff\.budget/);
      expect(read(result.dir)['mutationDiff']).toBeUndefined();
    });
  });

  describe('--accept', () => {
    it('refuses without a reason', () => {
      const result = ratchet({
        baseline: HEALTHY_BASELINE,
        reports: HEALTHY_REPORTS,
        args: ['--accept'],
      });
      expect(result.exitCode).toBe(2);
      expect(result.stderr).toMatch(/--accept requires --reason/);
    });

    it('refuses while a regression stands, and leaves the baseline untouched', () => {
      const result = ratchet({
        baseline: HEALTHY_BASELINE,
        reports: {
          ...HEALTHY_REPORTS,
          '.testfortress/reports/junit-app.xml': junit(400),
        },
        args: ['--accept', '--reason', 'consolidated the suite'],
      });
      expect(result.exitCode).toBe(1);
      const after = JSON.parse(
        readFileSync(path.join(result.dir, '.testfortress', 'baseline.json'), 'utf-8'),
      ) as typeof HEALTHY_BASELINE;
      expect(after.tests.count).toBe(500);
    });

    it('refuses when only a subset of the fields was compared', () => {
      // `--tier 0` never looks at coverage, the measured file set or the test
      // count, so accepting from that position would write a baseline while a
      // regression it did not examine still stands.
      const result = ratchet({
        baseline: HEALTHY_BASELINE,
        reports: HEALTHY_REPORTS,
        args: ['--tier', '0', '--accept', '--reason', 'cheap fields only'],
      });
      expect(result.exitCode).toBe(2);
      expect(result.stderr).toMatch(/requires the FULL comparison/);
      const after = JSON.parse(
        readFileSync(path.join(result.dir, '.testfortress', 'baseline.json'), 'utf-8'),
      ) as typeof HEALTHY_BASELINE & { reason?: string };
      expect(after.reason).toBeUndefined();
    });

    it('records improvements only, in the improving direction', () => {
      const result = ratchet({
        baseline: HEALTHY_BASELINE,
        reports: { ...HEALTHY_REPORTS, '.testfortress/reports/junit-app.xml': junit(560) },
        args: ['--accept', '--reason', 'added property tests'],
      });
      expect(result.exitCode).toBe(0);
      const after = JSON.parse(
        readFileSync(path.join(result.dir, '.testfortress', 'baseline.json'), 'utf-8'),
      ) as typeof HEALTHY_BASELINE & { reason: string };
      expect(after.tests.count).toBe(560);
      expect(after.reason).toBe('added property tests');
      expect(after.meta.fields).toContain('tests.count');
    });
  });

  /**
   * Seeding, which is the ONE operation in this file that writes a floor without
   * comparing it to anything.
   *
   * The gap it closes was real and shipped: the comparison loop is driven by the
   * BASELINE's keys, so a family the baseline has never carried is measured into
   * `cur` and then never looked at, and `--accept` — which writes only
   * `improvements` — could not bring one into existence. `test:mutation` is
   * exactly that case: its gate fails by design until `mutation.overall` exists,
   * and the two-command procedure README and the gate's own failure message
   * prescribed for recording it could not work. Every case below is about the
   * price of closing that: seeding must not become a second, unpoliced way into
   * the baseline.
   */
  describe('--seed, a family the baseline has never recorded', () => {
    const read = (dir: string): Record<string, unknown> =>
      JSON.parse(readFileSync(path.join(dir, '.testfortress', 'baseline.json'), 'utf-8')) as Record<
        string,
        unknown
      >;

    /** HEALTHY_BASELINE with the whole mutation family gone, `meta.fields` included. */
    function withoutMutation(metaFields?: string[]): Record<string, unknown> {
      const { mutation: _dropped, ...rest } = HEALTHY_BASELINE;
      return {
        ...rest,
        meta: {
          fields:
            metaFields ?? HEALTHY_BASELINE.meta.fields.filter((f) => !f.startsWith('mutation.')),
        },
      };
    }

    it('is not applied by a bare --accept, so a floor is never recorded unasked', () => {
      // The other half of the contract. Seeding has to be deliberate: a blanket
      // "record whatever is measured and absent" would make the first run after
      // any extractor change write floors nobody asked for, and a floor nobody
      // asked for is one nobody reviewed.
      const result = ratchet({
        baseline: withoutMutation(),
        reports: HEALTHY_REPORTS,
        args: ['--accept', '--reason', 'ordinary accept'],
      });
      expect(result.exitCode).toBe(0);
      const after = read(result.dir);
      expect(after['mutation']).toBeUndefined();
      expect((after['meta'] as unknown as { fields: string[] }).fields).not.toContain(
        'mutation.overall',
      );
      expect(result.seeded ?? []).toEqual([]);
    });

    it('records the whole family from the report when it is named', () => {
      const result = ratchet({
        baseline: withoutMutation(),
        reports: HEALTHY_REPORTS,
        args: ['--accept', '--seed', 'mutation', '--reason', 'first mutation baseline'],
      });
      expect(result.exitCode).toBe(0);
      const after = read(result.dir) as unknown as {
        mutation: { overall: number; totalMutants: number; filesMutated: string[] };
        meta: { fields: string[] };
        reason: string;
      };
      // 14 of 20 scored mutants, with the five Ignored ones out of both halves.
      expect(after.mutation.overall).toBe(70);
      expect(after.mutation.totalMutants).toBe(20);
      expect(after.mutation.filesMutated).toEqual([
        'packages/app/src/index.ts',
        'packages/app/src/other.ts',
      ]);
      expect(after.reason).toBe('first mutation baseline');
      // (d): the seeded fields join the pinned field list, so deleting one later
      // is a regression in its own right.
      expect(after.meta.fields).toContain('mutation.overall');
      expect(after.meta.fields).toContain('mutation.totalMutants');
      expect(after.meta.fields).toContain('mutation.filesMutated');
    });

    it('reports a seeded field as seeded and never as an improvement', () => {
      // A floor compared against nothing and a floor that moved up are different
      // claims. Folding the first into `improvements` would tell a reader of the
      // accept output that a number went UP when nothing was there to go up from.
      const result = ratchet({
        baseline: withoutMutation(),
        reports: HEALTHY_REPORTS,
        args: ['--accept', '--seed', 'mutation', '--reason', 'first mutation baseline'],
      });
      expect((result.seeded ?? []).map((entry) => entry.path).sort()).toEqual([
        'mutation.filesMutated',
        'mutation.overall',
        'mutation.totalMutants',
      ]);
      expect(result.improvements.filter((i) => i.path.startsWith('mutation.'))).toEqual([]);
      expect((result.accepted ?? []).filter((a) => a.path.startsWith('mutation.'))).toEqual([]);
    });

    it('measures a core module the baseline has never carried, from the declaration', () => {
      // The second chicken-and-egg, independent of the first: per-module scores
      // used to be computed only for modules the BASELINE already listed, so a
      // bootstrap measured none of them and a module newly added to CORE_MODULES
      // could never be seeded either. The union with the declaration is what
      // makes this row exist; `packages/shared/src/schemas/` is a real entry in
      // `CORE_MODULES`, which is why this file and not `packages/app/**` proves it.
      const result = ratchet({
        baseline: withoutMutation(),
        reports: {
          ...HEALTHY_REPORTS,
          '.testfortress/reports/mutation.json': mutationReport([
            ...HEALTHY_MUTATION,
            { name: 'packages/shared/src/schemas/vault.ts', killed: 9, survived: 1 },
          ]),
        },
        args: ['--accept', '--seed', 'mutation', '--reason', 'first mutation baseline'],
      });
      expect(result.exitCode).toBe(0);
      const after = read(result.dir) as unknown as {
        mutation: { modules: Record<string, number>; overall: number };
      };
      expect(after.mutation.modules['packages/shared/src/schemas/']).toBe(90);
      // and the overall is still computed over EVERY file, not just the module
      expect(after.mutation.overall).toBe(76.67);
    });

    it('refuses without --accept, because there is nothing to compare on a read-only run', () => {
      const result = ratchet({
        baseline: withoutMutation(),
        reports: HEALTHY_REPORTS,
        args: ['--seed', 'mutation'],
      });
      expect(result.exitCode).toBe(2);
      expect(result.stderr).toMatch(/--seed only applies to --accept/);
      expect(read(result.dir)['mutation']).toBeUndefined();
    });

    it('refuses to re-seed a field meta.fields still names, which is the laundering path', () => {
      // The sharp one. `meta.fields` is this file's only memory that a field
      // once existed. Delete `mutation.overall`'s VALUE but leave the memory,
      // hand the run a worse report, and without this refusal the seed would
      // write the worse number as a brand-new floor: a reduction with no
      // comparison, no BASELINE-REDUCTION entry and no sign-off — the one
      // manoeuvre decision (g) refuses to give a flag to.
      const result = ratchet({
        baseline: withoutMutation(HEALTHY_BASELINE.meta.fields),
        reports: {
          ...HEALTHY_REPORTS,
          '.testfortress/reports/mutation.json': mutationReport([
            { name: 'packages/app/src/index.ts', killed: 4, survived: 16 },
          ]),
        },
        args: ['--accept', '--seed', 'mutation', '--reason', 'looks like a first baseline'],
      });
      expect(result.exitCode).toBe(2);
      expect(result.stderr).toMatch(/meta\.fields still names/);
      expect(result.stderr).toMatch(/BASELINE-REDUCTION/);
      expect(read(result.dir)['mutation']).toBeUndefined();
    });

    it('refuses a family that is only half there, so seeding cannot walk around a required field', () => {
      // `mutation.filesMutated` is a REQUIRED field once the block exists. If a
      // partially-present family could be seeded key by key, the missing half
      // could be added without the required-field check ever seeing the family
      // as incomplete.
      const result = ratchet({
        baseline: {
          ...withoutMutation(),
          mutation: { overall: 70 },
        },
        reports: HEALTHY_REPORTS,
        args: ['--accept', '--seed', 'mutation', '--reason', 'topping the family up'],
      });
      expect(result.exitCode).toBe(2);
      expect(result.stderr).toMatch(/already records/);
      expect(result.stderr).toMatch(/mutation\.overall/);
    });

    it('refuses to seed the merged family from a campaign that ran incrementally', () => {
      // The registered command runs incrementally, and that is right for ENFORCING
      // a floor. It is wrong for RECORDING one: a reused result can be a busy
      // machine's Timeout, counted as a kill, carried forward indefinitely.
      const { incremental: _flag, ...silent } = JSON.parse(
        mutationReport(HEALTHY_MUTATION),
      ) as Record<string, unknown>;
      // Explicitly incremental, and a report too old to say: both are refused.
      for (const evidence of [
        mutationReport(HEALTHY_MUTATION, { incremental: true }),
        JSON.stringify(silent),
      ]) {
        const result = ratchet({
          baseline: withoutMutation(),
          reports: { ...HEALTHY_REPORTS, '.testfortress/reports/mutation.json': evidence },
          args: ['--accept', '--seed', 'mutation', '--reason', 'first mutation baseline'],
        });
        expect(result.exitCode).toBe(2);
        expect(result.stderr).toMatch(/mutation\.json, which was not measured from scratch/);
        expect(read(result.dir)['mutation']).toBeUndefined();
      }
    });

    it('refuses a family nothing measured, rather than recording an empty one', () => {
      const { '.testfortress/reports/mutation.json': _dropped, ...withoutReport } = HEALTHY_REPORTS;
      const result = ratchet({
        baseline: withoutMutation(),
        reports: withoutReport,
        args: ['--accept', '--seed', 'mutation', '--reason', 'no evidence at all'],
      });
      expect(result.exitCode).toBe(2);
      expect(result.stderr).toMatch(/nothing under "mutation" was measured/);
      expect(read(result.dir)['mutation']).toBeUndefined();
    });

    it('blocks when a seeded family carries a field with no declared direction', () => {
      // (b) applies to a seeded field exactly as it applies to a baselined one.
      // `duplication.*` is deliberately NOT a wildcard in the direction map, and
      // the deadcode extractor copies whatever keys the report carries, so an
      // unrecognised one has to fail rather than be written with a direction
      // this file guessed.
      const result = ratchet({
        baseline: withoutMutation(),
        reports: {
          ...HEALTHY_REPORTS,
          '.testfortress/reports/deadcode.json': JSON.stringify({
            duplication: { percentage: 1.5, unratcheted: 7 },
          }),
        },
        args: ['--accept', '--seed', 'duplication', '--reason', 'recording duplication'],
      });
      expect(result.exitCode).toBe(1);
      expect(result.stderr).toMatch(/UNDECLARED duplication\.unratcheted/);
      expect(read(result.dir)['duplication']).toBeUndefined();
    });
  });

  describe('the flake sample, whose SIZE is as gated as its failure count', () => {
    /** A baseline carrying the flake trio, and a manifest that registers the gate. */
    const flakeBaseline = (over: Record<string, number> = {}) => ({
      ...HEALTHY_BASELINE,
      flake: { runs: 10, failures: 0, e2eExecutions: 600, ...over },
      meta: {
        fields: [
          ...HEALTHY_BASELINE.meta.fields,
          'flake.e2eExecutions',
          'flake.failures',
          'flake.runs',
        ].sort(),
      },
    });
    const flakeManifest = {
      ...MANIFEST,
      tasks: {
        ...MANIFEST.tasks,
        'test:flake': {
          cmd: 'node scripts/ci/flake-run.mjs',
          tier: 2,
          gate: 'ten shuffled runs and the e2e suite, zero failures',
          report: 'flake.json',
        },
      },
    };
    const flakeReport = (over: Record<string, number> = {}) =>
      JSON.stringify({ runs: 10, failures: 0, e2eExecutions: 600, ...over });

    it('measures the end-to-end sample size, and does not merely declare it', () => {
      // `flake.e2eExecutions` exists because dropping the end-to-end leg LOWERS
      // `failures` — an apparent improvement — while leaving `runs` at ten. The
      // field was declared `higher` and named in the required set, and the
      // extractor never read it: a baseline carrying it would have reported it
      // UNMEASURED on the one run that produces the report, which is a red gate
      // rather than a defence.
      const result = ratchet({
        baseline: flakeBaseline(),
        manifest: flakeManifest,
        reports: { ...HEALTHY_REPORTS, '.testfortress/reports/flake.json': flakeReport() },
      });
      expect(result.missing.map((m) => m.path)).not.toContain('flake.e2eExecutions');
      expect(result.deferred.map((d) => d.path)).not.toContain('flake.e2eExecutions');
      expect(result.exitCode).toBe(0);
    });

    it('fails a run that kept its ten shuffled passes and quietly shrank the e2e leg', () => {
      const result = ratchet({
        baseline: flakeBaseline(),
        manifest: flakeManifest,
        reports: {
          ...HEALTHY_REPORTS,
          // Ten clean runs, zero failures — and a third of the end-to-end
          // executions. Nothing else in the report moves.
          '.testfortress/reports/flake.json': flakeReport({ e2eExecutions: 200 }),
        },
      });
      const shrunk = result.regressions.find((r) => r.path === 'flake.e2eExecutions');
      expect(shrunk).toBeDefined();
      expect(shrunk?.got).toBe(200);
      expect(shrunk?.dir).toBe('higher');
      expect(result.exitCode).toBe(1);
    });

    it('defers all three when the tier-2 gate did not run, rather than reporting them unmeasured', () => {
      const result = ratchet({
        baseline: flakeBaseline(),
        manifest: flakeManifest,
        reports: HEALTHY_REPORTS,
      });
      expect(result.deferred.map((d) => d.path).sort()).toEqual([
        'flake.e2eExecutions',
        'flake.failures',
        'flake.runs',
      ]);
      expect(result.missing.map((m) => m.path)).not.toContain('flake.runs');
      expect(result.exitCode).toBe(0);
    });
  });

  it('ignores the undeclared JUnit files a tier-2 gate leaves behind', () => {
    // `test:flake` and `test:dst` both write `junit-flake-<pkg>.xml` beside the
    // report they declare. Nothing here reads them — the headcount comes from the
    // DECLARED artifacts — but a substring match on "flake" made them known, so
    // the freshness rule reported three STALE reports on the next push and failed
    // a gate over an artifact from a run that had already passed. The cure for a
    // gate that is red for the wrong reason is usually deleting the check.
    const result = ratchet({
      baseline: HEALTHY_BASELINE,
      reports: {
        ...HEALTHY_REPORTS,
        '.testfortress/reports/junit-flake-shared.xml': junit(996),
        '.testfortress/reports/junit-flake-server.xml': junit(2994),
      },
      stale: [
        '.testfortress/reports/junit-flake-shared.xml',
        '.testfortress/reports/junit-flake-server.xml',
      ],
    });
    expect(result.staleReports).toEqual([]);
    expect(result.exitCode).toBe(0);
    // And the headcount still comes from the DECLARED report alone, so those
    // 3,990 tests cannot inflate it.
    expect(result.improvements.map((i) => i.path)).not.toContain('tests.count');
  });

  describe('the cheap tier', () => {
    it('reads only the reports that supply its own fields, so a stale JUnit cannot make it red', () => {
      const result = ratchet({
        baseline: HEALTHY_BASELINE,
        reports: HEALTHY_REPORTS,
        stale: ['.testfortress/reports/junit-app.xml', 'packages/app/coverage/lcov.info'],
        args: ['--tier', '0'],
      });
      expect(result.staleReports).toEqual([]);
      expect(result.missing).toEqual([]);
      expect(result.exitCode).toBe(0);
    });

    it('still catches a suppression count that grew', () => {
      const result = ratchet({
        baseline: HEALTHY_BASELINE,
        reports: {
          ...HEALTHY_REPORTS,
          '.testfortress/reports/integrity.json': JSON.stringify({
            summary: {
              suppressions: { count: 9, totalHits: 12 },
              fingerprints: HEALTHY_BASELINE.integrity,
            },
          }),
        },
        args: ['--tier', '0'],
      });
      expect(result.regressions.map((r) => r.path)).toEqual(
        expect.arrayContaining(['suppressions.count', 'suppressions.totalHits']),
      );
      expect(result.exitCode).toBe(1);
    });
  });
});
