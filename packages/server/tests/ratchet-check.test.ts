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

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..', '..', '..');
const RATCHET = path.join(repoRoot, 'scripts', 'ci', 'ratchet-check.mjs');

interface RatchetResult {
  exitCode: number;
  regressions: { path: string; detail: string }[];
  missing: { path: string }[];
  absent: { path: string }[];
  undeclared: string[];
  staleReports: string[];
  improvements: { path: string }[];
  stderr: string;
}

const dirs: string[] = [];
afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

/** LCOV with exactly the counters the extractor reads. */
function lcov(files: { name: string; lines: number; hit: number }[]): string {
  return files
    .map(
      (f) =>
        `TN:\nSF:${f.name}\nFNF:0\nFNH:0\nBRF:0\nBRH:0\nLF:${f.lines}\nLH:${f.hit}\nend_of_record\n`,
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
  },
};

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
  tasks: ['lint', 'test:unit'],
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
