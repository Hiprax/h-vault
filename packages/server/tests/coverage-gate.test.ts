/**
 * `coverage:check` — the declared coverage scope and the ledger that excuses it.
 *
 * The gate's own arithmetic is diff-cover's, and re-testing that here would be
 * testing someone else's tool. What is OURS, and what these tests pin, is the
 * pair of decisions diff-cover cannot make:
 *
 *   1. WHICH files are production code this project measures. A path the scope
 *      matcher silently drops is a file whose changed lines are never checked,
 *      and the report looks identical either way — there is no "0 files matched"
 *      warning, because a diff legitimately contains files that are not
 *      production code. That silence is the whole hazard, and it is not
 *      hypothetical: the first implementation of `globToRegExp` substituted
 *      `**​/` and then re-scanned its own output, turning `(?:.*​/)?` into
 *      `(?:.[^/]*​/)?` — which matches at most ONE path segment. Every file two
 *      or more directories below `src/` fell out of scope: measured against this
 *      branch, 19 of the 50 changed production files, and the gate reported
 *      green over the 31 survivors.
 *   2. WHEN an uncovered changed line is excused. Only a dated, in-date
 *      `COV-DIFF-EXEMPT` ledger entry does it, bounded by `maxHits`.
 */
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  COVERAGE_SCOPE_GLOBS,
  globToRegExp,
  inCoverageScope,
  packageOfPath,
} from '../../../scripts/ci/lib/coverage-scope.mjs';
import { parseLcov, pct } from '../../../scripts/ci/lib/lcov.mjs';
import { MUTATION_LEGS, PRESENTATIONAL_EXCLUDE } from '../../../scripts/ci/lib/mutation-scope.mjs';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

describe('the coverage scope matcher', () => {
  it('matches a file at any depth below src/, not merely one directory down', () => {
    // The regression that shipped in the first draft. Each of these is a real
    // measured file in this repository, at depth 0, 1, 2 and 3 respectively.
    expect(inCoverageScope('packages/client/src/App.tsx')).toBe(true);
    expect(inCoverageScope('packages/client/src/lib/vaultSearch.ts')).toBe(true);
    expect(inCoverageScope('packages/client/src/services/import/identity.ts')).toBe(true);
    expect(inCoverageScope('packages/client/src/services/import/parsers/bitwarden.ts')).toBe(true);
    expect(inCoverageScope('packages/server/src/controllers/vaultController.ts')).toBe(true);
    expect(inCoverageScope('packages/shared/src/schemas/vault.ts')).toBe(true);
  });

  it('expands ** across separators and * within one segment', () => {
    // `globToRegExp` is a single pass on purpose: a two-pass implementation
    // rewrites its own output, which is exactly how the depth bug happened.
    const deep = globToRegExp('a/**/*.ts');
    expect(deep.test('a/b.ts')).toBe(true);
    expect(deep.test('a/b/c.ts')).toBe(true);
    expect(deep.test('a/b/c/d.ts')).toBe(true);
    expect(deep.test('a/b/c/d.tsx')).toBe(false);

    const single = globToRegExp('a/*.ts');
    expect(single.test('a/b.ts')).toBe(true);
    expect(single.test('a/b/c.ts')).toBe(false);

    // A dot is a literal, never "any character": `a/xbts` must not match.
    expect(globToRegExp('a/*.ts').test('a/xbts')).toBe(false);
  });

  it('excludes exactly the process entry points the coverage configs exclude', () => {
    expect(inCoverageScope('packages/server/src/server.ts')).toBe(false);
    expect(inCoverageScope('packages/server/src/cli/seedBreaches.ts')).toBe(false);
    expect(inCoverageScope('packages/client/src/main.tsx')).toBe(false);
    expect(inCoverageScope('packages/client/src/workers/passwordStrength.worker.ts')).toBe(false);
    expect(inCoverageScope('packages/shared/src/types/index.ts')).toBe(false);
    expect(inCoverageScope('packages/shared/src/generated/version.ts')).toBe(false);
    // Its testable half stays in scope, which is why the exclusion is that one file.
    expect(inCoverageScope('packages/server/src/cli/seedBreachesArgs.ts')).toBe(true);
  });

  it('keeps the presentational primitives IN scope, unlike the mutation oracle', () => {
    // Mutation excludes them because a class-name mutant is cosmetic; coverage
    // has always measured them. Excluding them here would let a changed UI
    // primitive through unmeasured, so the divergence is asserted rather than
    // assumed.
    expect(inCoverageScope('packages/client/src/components/ui/Button.tsx')).toBe(true);
    expect(COVERAGE_SCOPE_GLOBS).not.toContain(PRESENTATIONAL_EXCLUDE);
    const mutationGlobs = MUTATION_LEGS.flatMap((leg) => leg.mutate);
    expect(mutationGlobs).toContain(PRESENTATIONAL_EXCLUDE);
  });

  it('claims nothing outside packages/*/src', () => {
    for (const outside of [
      'scripts/ci/local-ci.mjs',
      'packages/server/tests/gate-surface.test.ts',
      'packages/client/src/styles/globals.css',
      'e2e/helpers.ts',
      'README.md',
      'packages/client/package.json',
    ]) {
      expect(inCoverageScope(outside), outside).toBe(false);
    }
  });

  it('derives every exclusion from the mutation scope rather than restating it', () => {
    // The two denominators must describe the same body of code. `gate-surface`
    // pins the mutation negations against the three vitest configs; this pins
    // that this module is a projection of THAT list, so a coverage exclusion
    // cannot be widened here alone.
    const derived = COVERAGE_SCOPE_GLOBS.filter((glob) => glob.startsWith('!'));
    const fromMutation = MUTATION_LEGS.flatMap((leg) => leg.mutate)
      .filter((glob) => glob.startsWith('!') && glob !== PRESENTATIONAL_EXCLUDE)
      .sort();
    for (const negation of fromMutation) {
      expect(derived, `${negation} must be carried into the coverage scope`).toContain(negation);
    }
    // The only additions are the colocated-test exclusions the coverage configs
    // declare and the mutation legs do not need.
    const extra = derived.filter((glob) => !fromMutation.includes(glob)).sort();
    expect(extra).toEqual([
      '!packages/client/src/**/*.test.ts',
      '!packages/client/src/**/*.test.tsx',
      '!packages/server/src/**/*.test.ts',
      '!packages/shared/src/**/*.test.ts',
    ]);
  });

  it('names the owning package, because the floors are recorded per package', () => {
    expect(packageOfPath('packages/server/src/app.ts')).toBe('packages/server');
    expect(packageOfPath('packages/client/coverage/cobertura-coverage.xml')).toBe(
      'packages/client',
    );
    expect(packageOfPath('scripts/ci/local-ci.mjs')).toBeNull();
  });

  it('agrees with the measured file set, so no measured file is out of scope', () => {
    // The two-way check the depth bug would have failed in one direction: every
    // file the suites actually instrumented must be a file this matcher claims.
    // A file that is measured but out of scope is one whose changed lines the
    // gate would never look at.
    for (const pkg of ['packages/shared', 'packages/server', 'packages/client']) {
      const lcov = path.join(repoRoot, pkg, 'coverage', 'lcov.info');
      if (!existsSync(lcov)) continue;
      const { filesMeasured = [] } = parseLcov(readFileSync(lcov, 'utf8'));
      expect(filesMeasured.length).toBeGreaterThan(0);
      for (const rel of filesMeasured) {
        expect(inCoverageScope(`${pkg}/${rel}`), `${pkg}/${rel} is measured but out of scope`).toBe(
          true,
        );
      }
    }
  });
});

describe('LCOV totals', () => {
  const sample = [
    'SF:src/b.ts',
    'FNF:2',
    'FNH:1',
    'BRF:4',
    'BRH:3',
    'LF:10',
    'LH:9',
    'end_of_record',
    'SF:src/a.ts',
    'FNF:0',
    'FNH:0',
    'BRF:0',
    'BRH:0',
    'LF:10',
    'LH:10',
    'end_of_record',
    '',
  ].join('\n');

  it('sums every record and reports the file set sorted and deduplicated', () => {
    const parsed = parseLcov(sample);
    expect(parsed.line).toBe(95); // 19 of 20
    expect(parsed.branch).toBe(75); // 3 of 4
    expect(parsed.function).toBe(50); // 1 of 2
    expect(parsed.linesTotal).toBe(20);
    expect(parsed.filesMeasured).toEqual(['src/a.ts', 'src/b.ts']);
  });

  it('applies the caller’s path normalisation to every SF record', () => {
    const parsed = parseLcov(sample, (p) => `packages/shared/${p}`);
    expect(parsed.filesMeasured).toEqual(['packages/shared/src/a.ts', 'packages/shared/src/b.ts']);
  });

  it('reports an empty report as unmeasured rather than as 100%', () => {
    // The difference that matters: a zero denominator is "nothing was measured",
    // and returning 100 there would let a gate pass over an empty artifact.
    const parsed = parseLcov('');
    expect(parsed.line).toBeUndefined();
    expect(parsed.branch).toBeUndefined();
    expect(parsed.linesTotal).toBeUndefined();
    expect(parsed.filesMeasured).toBeUndefined();
    expect(pct(0, 0)).toBeUndefined();
    expect(pct(1, 3)).toBe(33.33);
  });
});

describe('the coverage gate is registered like every other gate', () => {
  const manifest = JSON.parse(
    readFileSync(path.join(repoRoot, '.testfortress', 'verify.json'), 'utf8'),
  ) as { tasks: Record<string, { tier: number; report: string | string[]; coverage?: string[] }> };

  it('declares coverage:check at tier 1, writing its own report', () => {
    const task = manifest.tasks['coverage:check'];
    expect(task).toBeDefined();
    expect(task!.tier).toBe(1);
    expect(task!.report).toBe('coverage.json');
  });

  it('runs after the suites that produce the artifacts it reads', () => {
    // Ordering is the gate's only defence against reading a report from a
    // previous run: `dependsOn` is what makes the runner refuse to run it when
    // either suite broke, and array order is what makes the artifacts exist.
    const gates = JSON.parse(
      execFileSync(process.execPath, ['scripts/ci/local-ci.mjs', '--list', '--json'], {
        cwd: repoRoot,
        encoding: 'utf8',
        maxBuffer: 8 << 20,
      }),
    ) as { id: string; task: string; dependsOn: string[]; requires: string[] }[];

    const ids = gates.map((gate) => gate.id);
    const coverage = gates.find((gate) => gate.task === 'coverage:check');
    expect(coverage).toBeDefined();
    expect(coverage!.dependsOn).toEqual(expect.arrayContaining(['test', 'test-integration']));
    // diff-cover is a host binary; an absent one must read as "could not run".
    expect(coverage!.requires).toContain('diff-cover');
    expect(ids.indexOf(coverage!.id)).toBeGreaterThan(ids.indexOf('test'));
    expect(ids.indexOf(coverage!.id)).toBeGreaterThan(ids.indexOf('test-integration'));
    // Before the ratchet, which reads the `coverage.diff` this gate measures.
    expect(ids.indexOf(coverage!.id)).toBeLessThan(ids.indexOf('ratchet-full'));
  });

  it('reads its inputs from the manifest, so a fourth package could not be missed', () => {
    const declared = Object.values(manifest.tasks).flatMap((task) => task.coverage ?? []);
    expect(declared.sort()).toEqual([
      'packages/client/coverage/cobertura-coverage.xml',
      'packages/server/coverage/cobertura-coverage.xml',
      'packages/shared/coverage/cobertura-coverage.xml',
    ]);
  });
});
