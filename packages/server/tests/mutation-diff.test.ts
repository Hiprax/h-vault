/**
 * `test:mutation:diff` — which mutants a change owns, which of them a run tests,
 * and which commit "the change" is measured against.
 *
 * The per-change leg is only honest if three things hold, and each is pinned
 * here against the real thing wherever the real thing is cheap:
 *
 *   1. The CANDIDATE rule selects the mutants a change owns — including the ones
 *      Prettier wraps across a changed and an unchanged line — and never the
 *      block of an unchanged function that merely contains a changed line.
 *      Driven through Stryker's OWN instrumenter, because the rule is defined
 *      over the mutant spans that instrumenter produces.
 *   2. The SAMPLE is keyed, line-independent, stratified and monotone, so an
 *      author cannot steer it and a larger budget always tests a superset.
 *   3. The DIFF BASE is the one `coverage:check` uses, resolved against real
 *      throwaway repositories: a branch, the trunk, a root commit, a shallow
 *      clone.
 */
import { afterAll, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Instrumenter } from '@stryker-mutator/instrumenter';
import {
  apiMutantKey,
  candidateMutants,
  changedLinesByFile,
  locationIncluded,
  planSample,
  rankMutants,
  reportMutantKey,
  sliceLocation,
  strykerRange,
} from '../../../scripts/ci/lib/mutation-diff.mjs';
import { resolveDiffBase } from '../../../scripts/ci/lib/diff-base.mjs';
import { buildStrykerConfig } from '../../../scripts/ci/lib/stryker-config.mjs';
import {
  MUTATION_DIFF_REPORT,
  MUTATION_LEGS,
  diffJsonReportFor,
  incrementalFileFor,
  jsonReportFor,
  legOfReport,
  mutationDiffLegDeadlineMs,
} from '../../../scripts/ci/lib/mutation-scope.mjs';

interface Loc {
  start: { line: number; column: number };
  end: { line: number; column: number };
}
interface Mutant {
  fileName: string;
  location: Loc;
  mutatorName: string;
  replacement: string;
}

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const dirs: string[] = [];
afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

const quiet = (): void => {};
const instrumenter = new Instrumenter({
  trace: quiet,
  debug: quiet,
  info: quiet,
  warn: quiet,
  error: quiet,
  fatal: quiet,
  isTraceEnabled: () => false,
  isDebugEnabled: () => false,
  isInfoEnabled: () => false,
  isWarnEnabled: () => false,
  isErrorEnabled: () => false,
  isFatalEnabled: () => false,
} as never);

/** Every mutant Stryker's instrumenter finds in `source`, exactly as the gate asks for them. */
async function mutantsOf(source: string, name = 'packages/shared/src/probe.ts'): Promise<Mutant[]> {
  const { mutants } = await instrumenter.instrument([{ name, content: source, mutate: true }], {
    plugins: null,
    excludedMutations: [],
    ignorers: [],
  } as never);
  return mutants as unknown as Mutant[];
}

/** A synthetic mutant, 0-based lines like Stryker's API. */
const mutant = (
  startLine: number,
  startColumn: number,
  endLine: number,
  endColumn: number,
  mutatorName = 'EqualityOperator',
  replacement = 'x',
  fileName = 'packages/shared/src/a.ts',
): Mutant => ({
  fileName,
  location: {
    start: { line: startLine, column: startColumn },
    end: { line: endLine, column: endColumn },
  },
  mutatorName,
  replacement,
});

describe('changedLinesByFile', () => {
  it('reads the + side of every -U0 hunk, one-line hunks included, in working-tree line numbers', () => {
    const diff = [
      'diff --git a/packages/shared/src/a.ts b/packages/shared/src/a.ts',
      '--- a/packages/shared/src/a.ts',
      '+++ b/packages/shared/src/a.ts',
      '@@ -3,0 +4,2 @@',
      '+one',
      '+two',
      '@@ -10 +12 @@',
      '-old',
      '+new',
      'diff --git a/packages/shared/src/gone.ts b/packages/shared/src/gone.ts',
      '--- a/packages/shared/src/gone.ts',
      '+++ /dev/null',
      '@@ -1,3 +0,0 @@',
      'diff --git a/packages/shared/src/trimmed.ts b/packages/shared/src/trimmed.ts',
      '--- a/packages/shared/src/trimmed.ts',
      '+++ b/packages/shared/src/trimmed.ts',
      '@@ -5,2 +4,0 @@',
      '-deleted',
      '-deleted',
    ].join('\n');
    const changed = changedLinesByFile(diff);
    expect([...changed.keys()]).toEqual(['packages/shared/src/a.ts']);
    expect([...changed.get('packages/shared/src/a.ts')!].sort((a, b) => a - b)).toEqual([4, 5, 12]);
    // A deleted file and a deletion-only hunk own no lines at all.
    expect(changed.has('packages/shared/src/gone.ts')).toBe(false);
    expect(changed.has('packages/shared/src/trimmed.ts')).toBe(false);
  });
});

describe('the candidate rule, over the instrumenter Stryker itself uses', () => {
  it('owns a mutant Prettier wrapped across a changed and an unchanged line', async () => {
    // Line 3 (1-based) is `      b` — the ONLY changed line — and the logical
    // operator `a &&\n b` spans lines 2-3. Exact containment would drop it.
    const source = [
      'export function both(a: boolean, b: boolean): boolean {',
      '  return a &&',
      '    b;',
      '}',
      '',
    ].join('\n');
    const all = await mutantsOf(source);
    const owned = candidateMutants(all, new Set([3]));
    const logical = owned.find((m) => m.mutatorName === 'LogicalOperator');
    expect(logical, 'the wrapped && mutant must belong to the change').toBeDefined();
    expect(logical!.location.start.line).toBe(1);
    expect(logical!.location.end.line).toBe(2);
    // The function's block spans the unchanged signature and brace too, and it IS
    // owned here, because every mutant inside it touches the changed line: rule
    // (a) asks whether a mutant swallows unchanged LOGIC, not unchanged lines. The
    // next case is the contrast, where the body holds an unchanged `if`.
    const block = all.find((m) => m.mutatorName === 'BlockStatement');
    expect(block).toBeDefined();
    expect(owned).toContain(block);
    // Nothing that lies wholly on line 1 or line 4 (0-based 0 and 3) is owned.
    const whollyOn = (m: Mutant, line: number): boolean =>
      m.location.start.line === line && m.location.end.line === line;
    expect(owned.some((m) => whollyOn(m, 0) || whollyOn(m, 3))).toBe(false);
  });

  it('never owns the block of an unchanged function that merely contains a changed line', async () => {
    const source = [
      'export function clamp(n: number): number {',
      '  if (n > 10) return 10;', // unchanged, and it carries mutants of its own
      '  return n < 0 ? 0 : n;', // the changed line
      '}',
      '',
    ].join('\n');
    const all = await mutantsOf(source);
    const owned = candidateMutants(all, new Set([3]));
    expect(owned.length).toBeGreaterThan(0);
    // Every owned mutant lies on the changed line.
    for (const m of owned) {
      expect(m.location.start.line, `${m.mutatorName} ${m.replacement}`).toBe(2);
      expect(m.location.end.line).toBe(2);
    }
    // The body block is a mutant of the file, and it is not the change's.
    const block = all.find(
      (m) => m.mutatorName === 'BlockStatement' && m.location.start.line === 0,
    );
    expect(block).toBeDefined();
    expect(owned).not.toContain(block);
    // Nothing from the unchanged `if` line.
    expect(all.some((m) => m.location.start.line === 1)).toBe(true);
    expect(owned.some((m) => m.location.start.line === 1)).toBe(false);
  });

  it('owns a brand-new function whole, block included, because every line of it changed', async () => {
    const source = [
      'export const x = 1;',
      'export function neg(n: number): number {',
      '  return n > 0 ? -n : n;',
      '}',
      '',
    ].join('\n');
    const all = await mutantsOf(source);
    const owned = candidateMutants(all, new Set([2, 3, 4]));
    expect(owned.some((m) => m.mutatorName === 'BlockStatement')).toBe(true);
    expect(owned.length).toBe(all.filter((m) => m.location.start.line >= 1).length);
  });

  it('owns nothing when no changed line carries a mutant', async () => {
    const all = await mutantsOf('export const x = 1 > 0;\n\n');
    expect(candidateMutants(all, new Set([2]))).toEqual([]);
  });

  it('keeps everything a candidate contains inside the candidate set, which the plan relies on', () => {
    // 0-based lines: the block spans 0-2, the inner mutant sits on 1, and a third
    // mutant sits alone on 3. Lines 1-3 (1-based) — 0-based 0-2 — changed.
    const outer = mutant(0, 0, 2, 1, 'BlockStatement', '{}');
    const inner = mutant(1, 2, 1, 9);
    const untouched = mutant(3, 0, 3, 5);
    const owned = candidateMutants([outer, inner, untouched], new Set([1, 2, 3]));
    // The mutant on the unchanged fourth line is not the change's…
    expect(owned).toEqual([outer, inner]);
    // …and whatever an owned mutant CONTAINS is owned too, so a plan built from
    // owned ranges can never reach outside the change.
    for (const candidate of owned) {
      for (const other of [outer, inner, untouched]) {
        if (locationIncluded(candidate.location, other.location)) expect(owned).toContain(other);
      }
    }
    // Widen the block over line 4 and it swallows the unchanged mutant there:
    // then it is no longer the change's, while the inner one still is.
    const wide = mutant(0, 0, 3, 9, 'BlockStatement', '{}');
    expect(candidateMutants([wide, inner, untouched], new Set([1, 2, 3]))).toEqual([inner]);
  });
});

describe('the sample', () => {
  const source = Array.from(
    { length: 40 },
    (_, i) => `const v${String(i)} = ${String(i)} > 1;`,
  ).join('\n');

  it('ranks by identity, so a cosmetic edit that moves lines does not re-roll it', async () => {
    const before = await mutantsOf(source);
    const shifted = await mutantsOf(`// a comment\n\n${source}`);
    const identity = (m: Mutant, text: string): string =>
      `${m.mutatorName}|${sliceLocation(text.split('\n'), m.location)}|${m.replacement}`;
    const beforeRanks = rankMutants(before, source, 'key');
    const shiftedRanks = rankMutants(shifted, `// a comment\n\n${source}`, 'key');
    const byIdentity = (ranks: Map<Mutant, string>, text: string): string[] =>
      [...ranks.entries()].map(([m, rank]) => `${identity(m, text)}=${rank}`).sort();
    expect(byIdentity(shiftedRanks, `// a comment\n\n${source}`)).toEqual(
      byIdentity(beforeRanks, source),
    );
  });

  it('tells otherwise identical mutants apart by occurrence, and changes with the key', async () => {
    const twin = 'const a = 1 > 0;\nconst b = 1 > 0;\n';
    const all = await mutantsOf(twin);
    const ranks = rankMutants(all, twin, 'key');
    expect(new Set(ranks.values()).size).toBe(all.length);
    const other = rankMutants(all, twin, 'another key');
    expect([...ranks.values()]).not.toEqual([...other.values()]);
  });

  it('tests everything, unsampled, when the change owns no more than the budget', async () => {
    const all = await mutantsOf(source);
    const plan = planSample({
      files: [
        {
          file: 'packages/shared/src/probe.ts',
          candidates: all,
          all,
          ranks: rankMutants(all, source, 'k'),
        },
      ],
      budget: all.length,
      isCore: () => false,
    });
    expect(plan.sampled).toBe(false);
    expect(plan.planned.length).toBe(all.length);
  });

  it('is monotone: a larger budget tests a superset of a smaller one', async () => {
    const all = await mutantsOf(source);
    const files = [
      {
        file: 'packages/shared/src/probe.ts',
        candidates: all,
        all,
        ranks: rankMutants(all, source, 'k'),
      },
    ];
    let previous = new Set<string>();
    for (const budget of [1, 5, 17, 40, 80]) {
      const plan = planSample({ files, budget, isCore: () => false });
      const keys = new Set(plan.planned.map(apiMutantKey));
      for (const key of previous)
        expect(keys.has(key), `budget ${String(budget)} lost ${key}`).toBe(true);
      expect(plan.planned.length).toBeGreaterThanOrEqual(Math.min(budget, all.length));
      previous = keys;
    }
  });

  it('measures EVERY changed file, even when there are more files than budget', async () => {
    const entries = await Promise.all(
      ['a', 'b', 'c'].map(async (name) => {
        const file = `packages/shared/src/${name}.ts`;
        const text = `export const ${name} = 1 > 0;\nexport const ${name}2 = 2 < 3;\n`;
        const all = await mutantsOf(text, file);
        return { file, candidates: all, all, ranks: rankMutants(all, text, 'k') };
      }),
    );
    const plan = planSample({ files: entries, budget: 1, isCore: () => false });
    expect(new Set(plan.planned.map((m) => m.fileName))).toEqual(
      new Set(entries.map((entry) => entry.file)),
    );
    expect(plan.sampled).toBe(true);
  });

  it('prefers the core modules once every file has its one', async () => {
    const make = async (
      file: string,
    ): Promise<{
      file: string;
      candidates: Mutant[];
      all: Mutant[];
      ranks: Map<Mutant, string>;
    }> => {
      const all = await mutantsOf(source, file);
      return { file, candidates: all, all, ranks: rankMutants(all, source, 'k') };
    };
    const core = await make('packages/shared/src/schemas/x.ts');
    const plain = await make('packages/shared/src/utils/y.ts');
    const plan = planSample({
      files: [core, plain],
      budget: 12,
      isCore: (file) => file.startsWith('packages/shared/src/schemas/'),
    });
    // Counted in SEEDS — the ranges handed to Stryker — because one range also
    // selects every mutant sharing its span. Stratification takes one seed from
    // each file; the budget is then spent on the core file alone.
    const seedsIn = (file: string): number => plan.seeds.filter((m) => m.fileName === file).length;
    expect(seedsIn(plain.file)).toBe(1);
    expect(seedsIn(core.file)).toBeGreaterThan(1);
    const plannedPlain = plan.planned.filter((m) => m.fileName === plain.file);
    const plainSeed = plan.seeds.find((m) => m.fileName === plain.file)!;
    for (const m of plannedPlain)
      expect(locationIncluded(plainSeed.location, m.location)).toBe(true);
    expect(plan.planned.length).toBeGreaterThanOrEqual(12);
  });

  it('plans the whole closure of a chosen range, exactly as Stryker will select it', () => {
    const block = mutant(0, 10, 3, 1, 'BlockStatement', '{}');
    const inner = mutant(1, 2, 1, 12);
    const deeper = mutant(2, 4, 2, 8, 'BooleanLiteral', 'false');
    const all = [block, inner, deeper];
    const ranks = new Map<Mutant, string>([
      [block, '0'],
      [inner, '1'],
      [deeper, '2'],
    ]);
    const plan = planSample({
      files: [{ file: block.fileName, candidates: all, all, ranks }],
      budget: 1,
      isCore: () => false,
    });
    // The lowest rank is the block; its range selects the two nested mutants too.
    expect(plan.seeds).toEqual([block]);
    expect(new Set(plan.planned)).toEqual(new Set(all));
  });
});

describe('the per-leg hang guard', () => {
  const MINUTE = 60_000;

  it('keeps the hour a small change always had', () => {
    expect(mutationDiffLegDeadlineMs(0)).toBe(60 * MINUTE);
    expect(mutationDiffLegDeadlineMs(1)).toBe(60 * MINUTE);
    expect(mutationDiffLegDeadlineMs(14)).toBe(60 * MINUTE);
    expect(mutationDiffLegDeadlineMs(15)).toBe(60 * MINUTE);
  });

  it('grows by two minutes per planned mutant once the plan outgrows the hour', () => {
    expect(mutationDiffLegDeadlineMs(16)).toBe(62 * MINUTE);
    expect(mutationDiffLegDeadlineMs(17)).toBe(64 * MINUTE);
    expect(mutationDiffLegDeadlineMs(81)).toBe(192 * MINUTE);
  });

  it('leaves twice the measured cost of the leg a flat hour stopped at 80 of 81', () => {
    // Measured on the reference machine over a 105-file branch diff: the server
    // leg planned 81 mutants, its dry run took 8m20s and its slowest mutants cost
    // 38 s each. A guard that a healthy run can reach is a coin toss, not a guard.
    const measuredMs = (8 * 60 + 20) * 1000 + 81 * 38_000;
    expect(mutationDiffLegDeadlineMs(81)).toBeGreaterThanOrEqual(2 * measuredMs);
  });

  it('never shrinks as the plan grows', () => {
    let previous = 0;
    for (let planned = 0; planned <= 500; planned++) {
      const deadline = mutationDiffLegDeadlineMs(planned);
      expect(deadline, `planned ${String(planned)}`).toBeGreaterThanOrEqual(previous);
      previous = deadline;
    }
  });

  it('refuses a count no plan can have, rather than guessing a deadline for it', () => {
    for (const planned of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => mutationDiffLegDeadlineMs(planned)).toThrow(RangeError);
      expect(() => mutationDiffLegDeadlineMs(planned)).toThrow(
        /a leg plans a whole, non-negative number of mutants/,
      );
    }
  });
});

describe('talking to Stryker', () => {
  it("plans with EXACTLY the instrumenter Stryker's core runs, pinned by version", () => {
    // The gate predicts which mutants Stryker will test by running the
    // instrumenter itself, and then refuses a run that tested anything else. Two
    // copies at different versions would make that refusal fire on every run, or
    // — worse — agree by accident on today's code. So the direct dependency must
    // be an EXACT pin, equal to what core itself depends on and to what is
    // installed.
    const read = (rel: string): Record<string, Record<string, string> | string> =>
      JSON.parse(readFileSync(path.join(repoRoot, rel), 'utf-8')) as Record<
        string,
        Record<string, string> | string
      >;
    const root = read('package.json');
    const core = read('node_modules/@stryker-mutator/core/package.json');
    const installed = read('node_modules/@stryker-mutator/instrumenter/package.json');
    const pinned = (root['devDependencies'] as Record<string, string>)[
      '@stryker-mutator/instrumenter'
    ];
    expect(pinned).toMatch(/^\d+\.\d+\.\d+$/);
    expect(pinned).toBe(
      (core['dependencies'] as Record<string, string>)['@stryker-mutator/instrumenter'],
    );
    expect(pinned).toBe(installed['version']);
    expect(pinned).toBe(
      (root['devDependencies'] as Record<string, string>)['@stryker-mutator/core'],
    );
  });

  it("writes a range in Stryker's CLI coordinates: 1-based lines, 0-based columns", () => {
    expect(strykerRange('packages/shared/src/a.ts', mutant(0, 4, 2, 9).location)).toBe(
      'packages/shared/src/a.ts:1:4-3:9',
    );
  });

  it("identifies a mutant the same way from the plan and from Stryker's 1-based JSON report", () => {
    const planned = mutant(16, 6, 16, 83, 'ConditionalExpression', 'false');
    const reported = {
      mutatorName: 'ConditionalExpression',
      replacement: 'false',
      location: { start: { line: 17, column: 7 }, end: { line: 17, column: 84 } },
    };
    expect(reportMutantKey('packages/shared/src/a.ts', reported)).toBe(apiMutantKey(planned));
    expect(
      reportMutantKey('packages/shared/src/a.ts', { ...reported, replacement: 'true' }),
    ).not.toBe(apiMutantKey(planned));
  });
});

describe('the Stryker configuration, in both modes', () => {
  it('runs the campaign incrementally, and the per-change leg from scratch in its own files', () => {
    for (const leg of MUTATION_LEGS) {
      const campaign = buildStrykerConfig({ HVAULT_MUTATION_LEG: leg.id });
      expect(campaign.incremental).toBe(true);
      expect(campaign.jsonReporter).toEqual({ fileName: jsonReportFor(leg.id) });
      expect(campaign.mutate).toEqual(leg.mutate);

      const dir = mkdtempSync(path.join(tmpdir(), 'hv-stryker-plan-'));
      dirs.push(dir);
      const planFile = path.join(dir, 'plan.json');
      writeFileSync(
        planFile,
        JSON.stringify({ leg: leg.id, mutate: [`${leg.package}/src/x.ts:1:0-2:3`] }),
      );
      const diff = buildStrykerConfig({
        HVAULT_MUTATION_LEG: leg.id,
        HVAULT_MUTATION_DIFF_PLAN: planFile,
      });
      expect(diff.incremental).toBe(false);
      expect(diff.mutate).toEqual([`${leg.package}/src/x.ts:1:0-2:3`]);
      expect(diff.jsonReporter).toEqual({ fileName: diffJsonReportFor(leg.id) });
      // Never the campaign's evidence, its cache or its sandbox.
      expect(diff.jsonReporter.fileName).not.toBe(campaign.jsonReporter.fileName);
      expect(diff.incrementalFile).not.toBe(incrementalFileFor(leg.id));
      expect(diff.tempDirName).not.toBe(campaign.tempDirName);
      // The SAME oracle: nothing that decides a verdict differs between the modes.
      expect(diff.ignoreStatic).toBe(false);
      expect(diff.ignoreStatic).toBe(campaign.ignoreStatic);
      expect(diff.concurrency).toBe(campaign.concurrency);
      expect(diff.timeoutMS).toBe(campaign.timeoutMS);
      expect(diff.vitest).toEqual(campaign.vitest);
    }
  });

  it('refuses a plan for another leg, an empty plan, and a plan with no leg named', () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'hv-stryker-plan-'));
    dirs.push(dir);
    const write = (plan: unknown): string => {
      const file = path.join(dir, `${String(Math.random()).slice(2)}.json`);
      writeFileSync(file, JSON.stringify(plan));
      return file;
    };
    expect(() =>
      buildStrykerConfig({
        HVAULT_MUTATION_LEG: 'shared',
        HVAULT_MUTATION_DIFF_PLAN: write({ leg: 'client', mutate: ['a.ts:1-2'] }),
      }),
    ).toThrow(/is for "client", not "shared"/);
    // An empty list would fall through to Stryker's default: mutate everything.
    expect(() =>
      buildStrykerConfig({
        HVAULT_MUTATION_LEG: 'shared',
        HVAULT_MUTATION_DIFF_PLAN: write({ leg: 'shared', mutate: [] }),
      }),
    ).toThrow(/names no ranges/);
    expect(() =>
      buildStrykerConfig({
        HVAULT_MUTATION_DIFF_PLAN: write({ leg: 'shared', mutate: ['a.ts:1-2'] }),
      }),
    ).toThrow(/needs HVAULT_MUTATION_LEG/);
  });

  it("names the per-change report so no leg's evidence can ever be mistaken for it", () => {
    expect(legOfReport(MUTATION_DIFF_REPORT)).toBeUndefined();
    expect(MUTATION_LEGS.map((leg) => leg.id)).not.toContain('diff');
  });
});

describe('the diff base, against real repositories', () => {
  const run = (cwd: string, ...args: string[]): string =>
    execFileSync('git', args, {
      cwd,
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
  const gitIn =
    (cwd: string) =>
    (args: string[]): string | null => {
      try {
        return run(cwd, ...args);
      } catch {
        return null;
      }
    };
  function repo(): string {
    const dir = mkdtempSync(path.join(tmpdir(), 'hv-diff-base-'));
    dirs.push(dir);
    run(dir, 'init', '-q', '-b', 'main');
    run(dir, 'config', 'user.email', 'test@localhost');
    run(dir, 'config', 'user.name', 'test');
    run(dir, 'config', 'commit.gpgsign', 'false');
    return dir;
  }
  const commit = (dir: string, file: string, text: string): string => {
    writeFileSync(path.join(dir, file), text);
    run(dir, 'add', '-A');
    run(dir, 'commit', '-q', '-m', file);
    return run(dir, 'rev-parse', 'HEAD');
  };

  it('compares a branch against where it forked from main', () => {
    const dir = repo();
    const fork = commit(dir, 'a.txt', 'a\n');
    run(dir, 'checkout', '-q', '-b', 'feature');
    commit(dir, 'b.txt', 'b\n');
    expect(resolveDiffBase({ git: gitIn(dir) })).toEqual({
      ref: 'main',
      mergeBase: fork,
      onTrunk: false,
    });
  });

  it('compares the trunk against its previous commit, since the change IS the last commit', () => {
    const dir = repo();
    const first = commit(dir, 'a.txt', 'a\n');
    commit(dir, 'b.txt', 'b\n');
    expect(resolveDiffBase({ git: gitIn(dir) })).toEqual({
      ref: 'main',
      mergeBase: first,
      onTrunk: true,
    });
  });

  it('compares a root commit on the trunk against itself, because nothing precedes it', () => {
    const dir = repo();
    const only = commit(dir, 'a.txt', 'a\n');
    expect(resolveDiffBase({ git: gitIn(dir) })).toEqual({
      ref: 'main',
      mergeBase: only,
      onTrunk: true,
    });
  });

  it('honours a requested ref, and refuses when neither it nor the trunk resolves', () => {
    const dir = repo();
    const first = commit(dir, 'a.txt', 'a\n');
    run(dir, 'tag', 'v1');
    commit(dir, 'b.txt', 'b\n');
    expect(resolveDiffBase({ git: gitIn(dir), requested: 'v1' })).toEqual({
      ref: 'v1',
      mergeBase: first,
      onTrunk: false,
    });
    expect(() => resolveDiffBase({ git: gitIn(dir), requested: 'nope' })).toThrow(
      /none of nope resolves/,
    );
    const empty = repo();
    expect(() => resolveDiffBase({ git: gitIn(empty) })).toThrow(/none of main, origin\/main/);
  });

  it('refuses a shallow clone of the trunk, whose empty diff would be a lie', () => {
    const origin = repo();
    commit(origin, 'a.txt', 'a\n');
    commit(origin, 'b.txt', 'b\n');
    const parent = mkdtempSync(path.join(tmpdir(), 'hv-diff-base-shallow-'));
    dirs.push(parent);
    run(parent, 'clone', '-q', '--depth', '1', `file://${origin}`, 'clone');
    const clone = path.join(parent, 'clone');
    expect(() => resolveDiffBase({ git: gitIn(clone), requested: 'HEAD' })).toThrow(
      /shallow clone/,
    );
  });
});
