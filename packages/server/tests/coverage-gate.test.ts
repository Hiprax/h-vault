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
import { describe, it, expect, afterEach } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildChangedDiff } from '../../../scripts/ci/lib/changed-diff.mjs';
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

/**
 * The changed-line diff the gate measures, and the one property that makes its
 * verdict mean anything: every line number in it belongs to the SAME file the
 * coverage report describes — the working tree.
 *
 * diff-cover, driving git itself, unions three diffs — `<base>...HEAD`,
 * `git diff` and `git diff --cached` — whose `+` line numbers belong to three
 * DIFFERENT files: HEAD, the working tree and the index. These cases run against
 * a real throwaway repository rather than a stubbed `git`, because what is being
 * pinned is git's own numbering; a stub would only prove that the assertions
 * agree with the fixture.
 */
describe('the changed-line diff the coverage gate measures', () => {
  const scratch: string[] = [];

  afterEach(() => {
    while (scratch.length > 0) rmSync(scratch.pop()!, { recursive: true, force: true });
  });

  /** A GitResult-shaped runner bound to one directory, as the gate injects. */
  function gitIn(dir: string) {
    return (args: string[]) => {
      const result = spawnSync('git', args, { cwd: dir, encoding: 'utf8', maxBuffer: 64 << 20 });
      return {
        status: result.error ? 127 : (result.status ?? 1),
        stdout: result.stdout ?? '',
        stderr: result.stderr ?? (result.error ? result.error.message : ''),
      };
    };
  }

  /** Setup-only git: a non-zero status here is a broken fixture, not a result. */
  function mustGit(dir: string, args: string[]): string {
    const result = gitIn(dir)(args);
    if (result.status !== 0) {
      throw new Error(`fixture: git ${args.join(' ')} failed — ${result.stderr || result.stdout}`);
    }
    return result.stdout.trim();
  }

  /**
   * A commit that does not depend on the machine's git identity or signing
   * config — a developer with `commit.gpgsign` on would otherwise fail every
   * fixture here with an error about a missing key.
   */
  function commitAll(dir: string, message: string): void {
    mustGit(dir, [
      '-c',
      'user.email=fixture@localhost',
      '-c',
      'user.name=fixture',
      '-c',
      'commit.gpgsign=false',
      'commit',
      '-qam',
      message,
    ]);
  }

  /**
   * A repository whose committed and uncommitted changes DISAGREE about where
   * every line is — the smallest fixture that exhibits both failure directions.
   *
   * `src/a.ts` starts with six lines. One commit appends a seventh. The working
   * tree then deletes the first, so the appended line is line SIX in the file the
   * suites would have executed. Measured with git:
   *
   *   `<base>...HEAD`   →  `@@ -6,0 +7 @@`   adds line 7   (HEAD numbering)
   *   `git diff`        →  `@@ -1 +0,0 @@`   adds nothing   (working-tree numbering)
   *   `git diff <base>` →  `@@ -6,0 +6 @@`   adds line 6    (working-tree numbering)
   *
   * So the union reports line SEVEN of a SIX-line file — a line that does not
   * exist, whose coverage lookup lands on whatever the report happens to say — and
   * never mentions line six, the only line that actually changed.
   */
  function repoWithDriftedCoordinates(): { dir: string; base: string } {
    const dir = mkdtempSync(path.join(tmpdir(), 'hvault-changed-diff-'));
    scratch.push(dir);
    mustGit(dir, ['init', '-q', '-b', 'main']);
    mkdirSync(path.join(dir, 'src'), { recursive: true });
    writeFileSync(path.join(dir, 'src', 'a.ts'), 'base1\nbase2\nbase3\nbase4\nbase5\nbase6\n');
    mustGit(dir, ['add', '-A']);
    commitAll(dir, 'base');
    const base = mustGit(dir, ['rev-parse', 'HEAD']);
    writeFileSync(
      path.join(dir, 'src', 'a.ts'),
      'base1\nbase2\nbase3\nbase4\nbase5\nbase6\ncommit-added\n',
    );
    commitAll(dir, 'append a line');
    // Uncommitted, and above the appended line, so every later line moves.
    writeFileSync(
      path.join(dir, 'src', 'a.ts'),
      'base2\nbase3\nbase4\nbase5\nbase6\ncommit-added\n',
    );
    return { dir, base };
  }

  /** The `+` line numbers a unified diff claims for one path. */
  function addedLines(diff: string, file: string): number[] {
    const sections = diff.split(/^diff --git /m);
    const section = sections.find((part) => part.includes(`+++ b/${file}\n`));
    if (section === undefined) return [];
    const lines: number[] = [];
    for (const match of section.matchAll(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm)) {
      const start = Number(match[1]);
      const count = match[2] === undefined ? 1 : Number(match[2]);
      for (let i = 0; i < count; i++) lines.push(start + i);
    }
    return lines;
  }

  it('numbers every changed line in the working tree, never in HEAD', () => {
    const { dir, base } = repoWithDriftedCoordinates();

    const diff = buildChangedDiff({ mergeBase: base, untracked: [], git: gitIn(dir) });

    // Six, because that is where the changed line IS in the file the suites run.
    expect(addedLines(diff, 'src/a.ts')).toEqual([6]);
    // Seven is what unioning the three diffs reports, and the file has six lines.
    // Spelled out as its own assertion because it is the regression: a `toEqual`
    // that happened to be rewritten around a wider set would stop saying this.
    expect(addedLines(diff, 'src/a.ts')).not.toContain(7);
  });

  it('folds an untracked file in as a whole new file, since --diff-file hides it from diff-cover', () => {
    const { dir, base } = repoWithDriftedCoordinates();
    writeFileSync(path.join(dir, 'src', 'new.ts'), 'one\ntwo\nthree\n');

    const diff = buildChangedDiff({
      mergeBase: base,
      untracked: ['src/new.ts'],
      git: gitIn(dir),
    });

    expect(addedLines(diff, 'src/new.ts')).toEqual([1, 2, 3]);
    // The tracked half is still there: the untracked pass appends, never replaces.
    expect(addedLines(diff, 'src/a.ts')).toEqual([6]);
  });

  it('folds a STAGED change in, which is how the selftest plants its defect', () => {
    const { dir, base } = repoWithDriftedCoordinates();
    writeFileSync(path.join(dir, 'src', 'staged.ts'), 'first\nsecond\n');
    mustGit(dir, ['add', 'src/staged.ts']);

    const diff = buildChangedDiff({ mergeBase: base, untracked: [], git: gitIn(dir) });

    // `git diff <commit>` reaches the working tree THROUGH the index, so a
    // staged addition needs no separate pass — which is what lets the untracked
    // pass above stay a pass over genuinely untracked files. `selftest.mjs`
    // stages every planted file before running a gate, so a build that measured
    // only committed and unstaged changes would report nothing about it.
    expect(addedLines(diff, 'src/staged.ts')).toEqual([1, 2]);
    expect(addedLines(diff, 'src/a.ts')).toEqual([6]);
  });

  it('numbers a renamed-and-edited file under its NEW path', () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'hvault-changed-diff-'));
    scratch.push(dir);
    mustGit(dir, ['init', '-q', '-b', 'main']);
    mkdirSync(path.join(dir, 'src'), { recursive: true });
    writeFileSync(path.join(dir, 'src', 'old.ts'), 'one\ntwo\nthree\n');
    mustGit(dir, ['add', '-A']);
    commitAll(dir, 'base');
    const base = mustGit(dir, ['rev-parse', 'HEAD']);
    mustGit(dir, ['mv', 'src/old.ts', 'src/new.ts']);
    writeFileSync(path.join(dir, 'src', 'new.ts'), 'one\ntwo\nthree\nfour\n');

    const diff = buildChangedDiff({ mergeBase: base, untracked: [], git: gitIn(dir) });

    // Rename detection turns this into one section headed `a/src/old.ts
    // b/src/new.ts`, and diff-cover reads the path from the `+++` line alone.
    // Reported under the OLD path, the added line would be attributed to a file
    // no coverage report can have an entry for, and an unmatched path is
    // silently full coverage over nothing.
    expect(diff).toContain('+++ b/src/new.ts');
    expect(addedLines(diff, 'src/new.ts')).toEqual([4]);
    expect(addedLines(diff, 'src/old.ts')).toEqual([]);
  });

  it('drops an untracked file git cannot diff as text, rather than emitting a headerless section', () => {
    const { dir, base } = repoWithDriftedCoordinates();
    writeFileSync(path.join(dir, 'src', 'blob.bin'), Buffer.from([0, 1, 2, 0, 255, 0]));
    writeFileSync(path.join(dir, 'src', 'empty.ts'), '');

    const diff = buildChangedDiff({
      mergeBase: base,
      untracked: ['src/blob.bin', 'src/empty.ts'],
      git: gitIn(dir),
    });

    // `git diff --no-index` exits 1 for both — the "inputs differ" status, not a
    // failure — and emits no `+++` line for either, so neither may reach the
    // document diff-cover parses.
    expect(diff).not.toContain('blob.bin');
    expect(diff).not.toContain('empty.ts');
    expect(addedLines(diff, 'src/a.ts')).toEqual([6]);
  });

  it('keeps the a/ and b/ prefixes whatever the machine’s git config says', () => {
    const { dir, base } = repoWithDriftedCoordinates();
    // diff-cover anchors on `diff --git a/… b/…` and strips exactly those two
    // prefixes. A path arriving under any other spelling matches no coverage
    // record — and an unmatched path is not an error there, it is silently full
    // coverage over nothing. Every setting that can move it is set here at once,
    // because pinning four of five would look identical in this test.
    mustGit(dir, ['config', 'diff.noprefix', 'true']);
    mustGit(dir, ['config', 'diff.mnemonicprefix', 'true']);
    mustGit(dir, ['config', 'diff.srcPrefix', 'SRC/']);
    mustGit(dir, ['config', 'diff.dstPrefix', 'DST/']);

    const diff = buildChangedDiff({ mergeBase: base, untracked: [], git: gitIn(dir) });

    expect(diff).toContain('diff --git a/src/a.ts b/src/a.ts');
    expect(diff).toContain('+++ b/src/a.ts');
    expect(diff).not.toContain('DST/');
    expect(addedLines(diff, 'src/a.ts')).toEqual([6]);
  });

  it('strips the no-newline marker, which diff-cover would count as a context line', () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'hvault-changed-diff-'));
    scratch.push(dir);
    mustGit(dir, ['init', '-q', '-b', 'main']);
    mkdirSync(path.join(dir, 'src'), { recursive: true });
    // No trailing newline, on purpose: that is what makes git emit the marker.
    writeFileSync(path.join(dir, 'src', 'tail.ts'), 'alpha\nbeta');
    mustGit(dir, ['add', '-A']);
    commitAll(dir, 'base');
    const base = mustGit(dir, ['rev-parse', 'HEAD']);
    writeFileSync(path.join(dir, 'src', 'tail.ts'), 'alpha\ngamma');

    const diff = buildChangedDiff({ mergeBase: base, untracked: [], git: gitIn(dir) });

    // `diff_reporter.py`'s `_parse_lines` counts every line that does not begin
    // with `+`, `-` or `@@` as CONTEXT and advances the line counter for it. With
    // `-U0` the marker lands BETWEEN the `-` and the `+` of this one-line change,
    // so leaving it in makes diff-cover call the changed line 3 in a two-line
    // file. The hunk header alone cannot show that, which is why the marker's
    // absence is asserted directly.
    expect(diff).not.toContain('\\ No newline');
    expect(addedLines(diff, 'src/tail.ts')).toEqual([2]);
  });

  it('throws rather than returning a partial diff when the base does not resolve', () => {
    const { dir } = repoWithDriftedCoordinates();

    expect(() =>
      buildChangedDiff({ mergeBase: 'no-such-ref', untracked: [], git: gitIn(dir) }),
    ).toThrow(/no-such-ref/);
  });

  it('skips an untracked path that vanished after it was enumerated, rather than failing', () => {
    const { dir, base } = repoWithDriftedCoordinates();

    // MEASURED: `--no-index` against a path that is not there exits 1 — the same
    // status as "the inputs differ" — and writes nothing to stdout. So it is
    // dropped by the no-hunk rule, which is the right answer for a file deleted
    // between `git ls-files --others` and this call, and cannot hide an untested
    // module: the gate's other half enumerates the changed production files
    // itself and reports any that no coverage report mentions.
    const diff = buildChangedDiff({
      mergeBase: base,
      untracked: ['src/absent.ts'],
      git: gitIn(dir),
    });

    expect(diff).not.toContain('absent.ts');
    expect(addedLines(diff, 'src/a.ts')).toEqual([6]);
  });

  it('throws when git itself fails on an untracked path, instead of measuring a short diff', () => {
    const { dir, base } = repoWithDriftedCoordinates();
    const real = gitIn(dir);
    // The process boundary, and only that: every call is the real git except the
    // `--no-index` one, which reports the status an unusable git produces. A
    // short diff here would read as "that file changed nothing", which is the
    // silent-pass shape this whole gate exists to remove.
    const brokenOnNoIndex = (args: string[]) =>
      args.includes('--no-index')
        ? { status: 128, stdout: '', stderr: 'fatal: not a git repository' }
        : real(args);

    expect(() =>
      buildChangedDiff({ mergeBase: base, untracked: ['src/new.ts'], git: brokenOnNoIndex }),
    ).toThrow(/src\/new\.ts/);
  });
});
