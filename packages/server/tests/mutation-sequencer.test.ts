/**
 * The order a mutant run visits its test files in (`tests/harness/mutationSequencer.ts`).
 *
 * Under Stryker a mutant run is one vitest worker that bails at the first
 * failure, so the file order is the cost of every killed mutant that has no
 * per-test coverage. Pinned here: each ordering rule, what the ledger learns
 * from a finished run and for which target, how a test file's direct imports
 * are read, the one thing the order must never do (add, drop or duplicate a
 * file — which tests run is the oracle's business, not the sequencer's), and,
 * against a REAL vitest, that the mutation config's `sequence` block actually
 * puts this sequencer in charge and that a kill measured by the reporter leads
 * the next run.
 */
import { afterAll, describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  createVitest,
  type Reporter,
  type TestModule,
  type TestSpecification,
  type Vitest,
} from 'vitest/node';
import {
  MutationRunLedger,
  MutationSequencer,
  createRunLedger,
  importsForReal,
  killSeekingOrder,
  moduleReferences,
  moduleStem,
  mutationSequence,
  recordRun,
  type OrderEntry,
} from '../../../tests/harness/mutationSequencer.js';
import { PROPERTY_RUNS, propertyRun } from '../../../tests/harness/property.js';

const entry = (id: string, overrides: Partial<OrderEntry> = {}): OrderEntry => ({
  id,
  groupOrder: 0,
  project: '',
  isolated: true,
  killedAt: undefined,
  importsTarget: false,
  cost: 100,
  size: 1_000,
  ...overrides,
});
const ids = (entries: readonly OrderEntry[]): string[] => entries.map((e) => e.id);

describe('the kill-seeking order', () => {
  it('runs the cheapest measured file first, not the longest (one worker wants the first failure soonest)', () => {
    const order = killSeekingOrder([
      entry('slow', { cost: 9_000 }),
      entry('fast', { cost: 10 }),
      entry('mid', { cost: 500 }),
    ]);
    expect(ids(order)).toEqual(['fast', 'mid', 'slow']);
  });

  it("puts the target's past killers first, the latest first, whatever they cost", () => {
    const order = killSeekingOrder([
      entry('cheap', { cost: 1, importsTarget: true }),
      entry('old-killer', { cost: 5_000, killedAt: 2 }),
      entry('new-killer', { cost: 9_000, killedAt: 7 }),
    ]);
    expect(ids(order)).toEqual(['new-killer', 'old-killer', 'cheap']);
  });

  it('puts the direct importers of the target ahead of every other file, cheapest first', () => {
    const order = killSeekingOrder([
      entry('unrelated-cheap', { cost: 1 }),
      entry('importer-slow', { cost: 800, importsTarget: true }),
      entry('importer-fast', { cost: 20, importsTarget: true }),
    ]);
    expect(ids(order)).toEqual(['importer-fast', 'importer-slow', 'unrelated-cheap']);
  });

  it('puts unmeasured files after measured ones, the smallest first, and unsized ones last', () => {
    const order = killSeekingOrder([
      entry('unsized', { cost: undefined, size: undefined }),
      entry('big-new', { cost: undefined, size: 9_000 }),
      entry('measured', { cost: 99_999 }),
      entry('small-new', { cost: undefined, size: 10 }),
    ]);
    expect(ids(order)).toEqual(['measured', 'small-new', 'big-new', 'unsized']);
  });

  it("keeps vitest's own grouping ahead of everything: groupOrder, then project, then isolated first", () => {
    const order = killSeekingOrder([
      entry('late-group', { groupOrder: 1, killedAt: 9 }),
      entry('project-b', { project: 'b', importsTarget: true }),
      entry('shared-context', { project: 'a', isolated: false, cost: 1 }),
      entry('isolated', { project: 'a', isolated: true, cost: 9_000 }),
    ]);
    expect(ids(order)).toEqual(['isolated', 'shared-context', 'project-b', 'late-group']);
  });

  it('breaks every tie by module id, so equal files always run in the same order', () => {
    expect(ids(killSeekingOrder([entry('b'), entry('c'), entry('a')]))).toEqual(['a', 'b', 'c']);
    expect(ids(killSeekingOrder([entry('c'), entry('a'), entry('b')]))).toEqual(['a', 'b', 'c']);
  });

  it('returns a permutation of its input — nothing added, dropped or duplicated — and never touches the input', () => {
    const arbitraryEntry = fc.record({
      id: fc.string({ minLength: 1, maxLength: 6 }),
      groupOrder: fc.integer({ min: 0, max: 2 }),
      project: fc.constantFrom('', 'a', 'b'),
      isolated: fc.boolean(),
      killedAt: fc.option(fc.integer({ min: 1, max: 50 }), { nil: undefined }),
      importsTarget: fc.boolean(),
      cost: fc.option(fc.nat({ max: 10_000 }), { nil: undefined }),
      size: fc.option(fc.nat({ max: 10_000 }), { nil: undefined }),
    });
    fc.assert(
      fc.property(
        fc.uniqueArray(arbitraryEntry, { selector: (e) => e.id, maxLength: 30 }),
        (entries) => {
          const before = [...entries];
          const order = killSeekingOrder(entries);
          expect(entries).toEqual(before);
          expect(order).toHaveLength(entries.length);
          expect(new Set(order)).toEqual(new Set(entries));
          // The same files in any input order come out in the same order.
          expect(killSeekingOrder([...entries].reverse())).toEqual(order);
        },
      ),
      propertyRun({ numRuns: PROPERTY_RUNS }),
    );
  });
});

describe('what the ledger learns from a finished run', () => {
  it('records the full cost of a file that passed, and a file with a failed test as a killer of the run target only', () => {
    const ledger = createRunLedger();
    ledger.target = '/sandbox/src/a.ts';
    recordRun(ledger, [
      { id: '/t/one.test.ts', passed: true, killed: false, cost: 12 },
      // Cut short by its own failure: a killer, but its duration is not its cost.
      { id: '/t/two.test.ts', passed: false, killed: true, cost: 3 },
      // Failed without a failing test (it could not be imported): not a kill.
      { id: '/t/three.test.ts', passed: false, killed: false, cost: 1 },
    ]);
    expect(ledger.runs).toBe(1);
    expect([...ledger.costs]).toEqual([['/t/one.test.ts', 12]]);
    expect([...ledger.killers]).toEqual([['/sandbox/src/a.ts', new Map([['/t/two.test.ts', 1]])]]);
  });

  it('keeps each target its own history, and moves a repeat killer to the latest run', () => {
    const ledger = createRunLedger();
    ledger.target = 'A';
    recordRun(ledger, [{ id: 'k', passed: false, killed: true, cost: 5 }]);
    ledger.target = 'B';
    recordRun(ledger, [
      { id: 'k', passed: true, killed: false, cost: 6 },
      { id: 'm', passed: false, killed: true, cost: 7 },
    ]);
    ledger.target = 'A';
    recordRun(ledger, [{ id: 'k', passed: false, killed: true, cost: 8 }]);
    expect(ledger.killers.get('A')).toEqual(new Map([['k', 3]]));
    // `k` passed while B was the target: it is not B's killer.
    expect(ledger.killers.get('B')).toEqual(new Map([['m', 2]]));
    // Its cost is the one from the run it completed, not the truncated ones.
    expect(ledger.costs.get('k')).toBe(6);
  });
});

describe("reading a test file's direct imports", () => {
  it('resolves every relative runtime import against the file, and ignores types, packages, comments and strings', () => {
    const file = '/repo/packages/server/tests/sub/x.test.ts';
    const source = [
      "import { a } from '../../src/models/User.js';",
      // Erased before the file runs, so it can never observe a mutant.
      "import type { B } from '../../src/types';",
      "export type { C } from '../../src/types/more';",
      "export * from './helpers.js';",
      "import '../../src/setup/side-effect.ts';",
      "const lazy = await import('../../src/jobs/cron.js');",
      "vi.mock('../../src/utils/email.js');",
      'vi.doMock("../../src/utils/logger", () => ({}));',
      "const actual = await vi.importActual('../../src/config/index.js');",
      "const legacy = require('../../src/cli/old.cjs');",
      // Neither loads nor replaces a module.
      "vi.unmock('../../src/utils/audit');",
      'import {',
      '  multi,',
      '  line,',
      "} from '../../src/controllers/vaultController.js';",
      'const cast = <string>value; // a `.ts` cast, which a TSX parse would misread',
      "import { describe } from 'vitest';",
      "import mongoose from 'mongoose';",
      // Specifier-SHAPED text that is not an import: a regex would take all three.
      "// import { old } from '../../src/commented/out.js';",
      'const text = "import x from \'../../src/in/a/string.js\'";',
      "const tpl = `vi.mock('../../src/in/a/template.js')`;",
    ].join('\n');
    const references = moduleReferences(file, source);
    expect([...references.imports].sort()).toEqual(
      [
        '/repo/packages/server/src/cli/old',
        '/repo/packages/server/src/config',
        '/repo/packages/server/src/controllers/vaultController',
        '/repo/packages/server/src/jobs/cron',
        '/repo/packages/server/src/models/User',
        '/repo/packages/server/src/setup/side-effect',
        '/repo/packages/server/tests/sub/helpers',
      ].sort(),
    );
    // A mocked module is REPLACED in this file, so the file cannot observe a mutant in it.
    expect([...references.replaces].sort()).toEqual([
      '/repo/packages/server/src/utils/email',
      '/repo/packages/server/src/utils/logger',
    ]);
  });

  it('does not count a file as an importer of a module it mocks, even when it imports it too', () => {
    const file = '/r/tests/t.test.ts';
    const mocksAndImports = moduleReferences(
      file,
      "vi.mock('../src/mailer.js');\nimport { send } from '../src/mailer.js';\nimport { other } from '../src/other.js';",
    );
    expect(importsForReal(mocksAndImports, ['/r/src/mailer'])).toBe(false);
    expect(importsForReal(mocksAndImports, ['/r/src/other'])).toBe(true);
    expect(importsForReal(mocksAndImports, ['/r/src/unrelated', '/r/src/other'])).toBe(true);
    expect(importsForReal(mocksAndImports, [])).toBe(false);
    // The module can also be named through an `import()` inside the mock call.
    const viaImport = moduleReferences(file, "vi.mock(import('../src/mailer.js'), () => ({}));");
    expect(importsForReal(viaImport, ['/r/src/mailer'])).toBe(false);
    expect([...viaImport.replaces]).toEqual(['/r/src/mailer']);
  });

  it('names a module the way an import does: no script extension, no trailing index', () => {
    expect(moduleStem('/r/src/a.ts')).toBe('/r/src/a');
    expect(moduleStem('/r/src/b.tsx')).toBe('/r/src/b');
    expect(moduleStem('/r/src/c.mjs')).toBe('/r/src/c');
    expect(moduleStem('/r/src/config/index.ts')).toBe('/r/src/config');
    // Not a script extension, so not stripped: a data file is its own module.
    expect(moduleStem('/r/src/data.json')).toBe('/r/src/data.json');
  });
});

/** A stand-in for the two things the sequencer reads from vitest: its config and its root. */
function fakeVitest(root: string, related: string[] | undefined): Vitest {
  return { config: { root, related } } as unknown as Vitest;
}

const fakeSpec = (moduleId: string): TestSpecification =>
  ({
    moduleId,
    project: { name: '', config: { sequence: { groupOrder: 0 }, isolate: true } },
  }) as unknown as TestSpecification;

describe('MutationSequencer with its ledger, run after run', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'hv-sequencer-unit-'));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));
  mkdirSync(path.join(dir, 'src'));
  mkdirSync(path.join(dir, 'tests'));
  const write = (rel: string, text: string): string => {
    writeFileSync(path.join(dir, rel), text);
    return path.join(dir, rel);
  };
  const target = write('src/target.ts', 'export const value = 1;\n');
  const other = write('src/other.ts', 'export const other = 2;\n');
  const importer = write('tests/importer.test.ts', "import { value } from '../src/target.js';\n");
  const bystander = write('tests/bystander.test.ts', '// no imports\n'.repeat(4));
  const killer = write('tests/killer.test.ts', '// no imports either\n'.repeat(8));

  const module = (id: string, state: 'passed' | 'failed', cost: number): TestModule =>
    ({
      moduleId: id,
      state: () => state,
      children: {
        *allTests(filter?: string) {
          if (filter === undefined || filter === state) yield { state: () => state };
        },
      },
      diagnostic: () => ({
        duration: cost,
        collectDuration: 0,
        setupDuration: 0,
        prepareDuration: 0,
        environmentSetupDuration: 0,
      }),
    }) as unknown as TestModule;

  it('leads with the direct importer, then the killer it measured, per target', async () => {
    const vitest = fakeVitest(dir, [target]);
    const sequencer = new MutationSequencer(vitest);
    const ledger = new MutationRunLedger();
    ledger.onInit(vitest);
    const ran = (...modules: TestModule[]): void => {
      ledger.onTestRunStart();
      for (const m of modules) ledger.onTestModuleEnd(m);
      ledger.onTestRunEnd();
    };
    const order = async (): Promise<string[]> =>
      (await sequencer.sort([killer, bystander, importer].map(fakeSpec))).map((s) =>
        path.basename(s.moduleId),
      );

    // Nothing measured yet: the importer, then the rest by size.
    expect(await order()).toEqual(['importer.test.ts', 'bystander.test.ts', 'killer.test.ts']);
    ran(
      module(importer, 'passed', 50),
      module(bystander, 'passed', 40),
      module(killer, 'failed', 30),
    );
    // The killer of THIS target now leads, ahead of the importer.
    expect(await order()).toEqual(['killer.test.ts', 'importer.test.ts', 'bystander.test.ts']);

    // Another target has no killer yet, and nobody imports it: measured files
    // cheapest first (the killer's cut-short run measured nothing), then by size.
    (vitest.config as { related: string[] }).related = [other];
    expect(await order()).toEqual(['bystander.test.ts', 'importer.test.ts', 'killer.test.ts']);
    ran(module(bystander, 'passed', 40), module(importer, 'failed', 30));
    expect(await order()).toEqual(['importer.test.ts', 'bystander.test.ts', 'killer.test.ts']);

    // Back on the first target, its own killer still leads.
    (vitest.config as { related: string[] }).related = [target];
    expect((await order())[0]).toBe('killer.test.ts');
  });

  it('does not take a file that failed to IMPORT for a killer: no test failed in it', async () => {
    const vitest = fakeVitest(dir, [other]);
    const sequencer = new MutationSequencer(vitest);
    const ledger = new MutationRunLedger();
    ledger.onInit(vitest);
    // vitest reports such a module as failed with no test inside it failing.
    const brokenImport = {
      moduleId: killer,
      state: () => 'failed',
      children: { *allTests() {} },
      diagnostic: () => ({
        duration: 1,
        collectDuration: 0,
        setupDuration: 0,
        prepareDuration: 0,
        environmentSetupDuration: 0,
      }),
    } as unknown as TestModule;
    const order = async (): Promise<string[]> =>
      (await sequencer.sort([killer, bystander].map(fakeSpec))).map((s) =>
        path.basename(s.moduleId),
      );
    // As in a real run, the order is taken first: that is what names the target.
    expect(await order()).toEqual(['bystander.test.ts', 'killer.test.ts']);
    ledger.onTestRunStart();
    ledger.onTestModuleEnd(brokenImport);
    ledger.onTestRunEnd();
    // Had it been counted, it would now lead; it stays where its size puts it.
    expect(await order()).toEqual(['bystander.test.ts', 'killer.test.ts']);
  });

  it('treats a missing module file as importing nothing, never as an error', async () => {
    const sequencer = new MutationSequencer(fakeVitest(dir, [target]));
    const gone = path.join(dir, 'tests', 'gone.test.ts');
    const sorted = await sequencer.sort([fakeSpec(gone), fakeSpec(importer)]);
    expect(sorted.map((s) => s.moduleId)).toEqual([importer, gone]);
    expect(existsSync(gone)).toBe(false);
  });
});

describe('mutationSequence, the block the mutation configs install', () => {
  it('stops shuffling files, keeps shuffling tests with the base seed and hooks, and installs the sequencer', () => {
    expect(mutationSequence({ shuffle: true, seed: 1337, hooks: 'stack' })).toEqual({
      shuffle: { files: false, tests: true },
      seed: 1337,
      hooks: 'stack',
      sequencer: MutationSequencer,
    });
  });

  it('never turns test shuffling ON where the base had it off', () => {
    expect(mutationSequence(undefined).shuffle).toEqual({ files: false, tests: false });
    expect(mutationSequence({ shuffle: false }).shuffle).toEqual({ files: false, tests: false });
    expect(mutationSequence({ shuffle: { files: true } }).shuffle).toEqual({
      files: false,
      tests: false,
    });
    expect(mutationSequence({ shuffle: { files: true, tests: true } }).shuffle).toEqual({
      files: false,
      tests: true,
    });
  });
});

describe('against a real vitest, configured the way Stryker drives the mutation configs', () => {
  // One worker that bails at the first failure, `related` set to the mutated
  // file before each run and the file list cleared between runs (exactly what
  // Stryker's runner does), the mutation configs' `sequence`, `cache: false` and
  // ledger: the conditions under which the order is the cost.
  const dir = mkdtempSync(path.join(tmpdir(), 'hv-sequencer-real-'));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));
  mkdirSync(path.join(dir, 'src'));
  mkdirSync(path.join(dir, 'tests'));
  // Two switchable "mutants": while one of these files exists, its test fails.
  const flagOne = path.join(dir, 'mutant-one');
  const flagTwo = path.join(dir, 'mutant-two');
  const write = (rel: string, text: string): void => writeFileSync(path.join(dir, rel), text);
  write('src/target.ts', 'export const value = 1;\n');
  write('src/other.ts', 'export const other = 1;\n');
  // Every test file below reaches both modules through `middle`, except the two
  // that import one of them directly. Each file USES what it imports: TypeScript
  // erases an unused import, and a file whose import was erased is not related
  // to anything.
  write(
    'src/middle.ts',
    "export { value } from './target.js';\nexport { other } from './other.js';\n",
  );
  write(
    'tests/a-importer.test.ts',
    "import { value } from '../src/target.js';\ntest('a', () => { expect(value).toBe(1); });\n",
  );
  const viaMiddle = (name: string, body: string, padding: number): void =>
    write(
      `tests/${name}.test.ts`,
      `import { value, other } from '../src/middle.js';\n${'// padding\n'.repeat(padding)}${body}\n`,
    );
  const failsWhile = (flag: string): string => `(existsSync(${JSON.stringify(flag)}) ? 1 : 0)`;
  viaMiddle('b-small', "test('b', () => { expect(value + other).toBe(2); });", 1);
  viaMiddle(
    'c-killer',
    `import { existsSync } from 'node:fs';\ntest('c', () => { expect(value + other + ${failsWhile(flagOne)}).toBe(2); });`,
    20,
  );
  viaMiddle('d-large', "test('d', () => { expect(value + other).toBe(2); });", 60);
  write(
    'tests/j-other.test.ts',
    `import { existsSync } from 'node:fs';\nimport { other } from '../src/other.js';\ntest('j', () => { expect(other + ${failsWhile(flagTwo)}).toBe(1); });\n`,
  );

  const started: string[] = [];
  const recorder: Reporter = {
    onTestModuleStart: (module: TestModule) => {
      started.push(path.basename(module.moduleId));
    },
  };
  let vitest: Vitest | undefined;
  afterAll(async () => {
    await vitest?.close();
  });

  const run = async (target: string): Promise<string[]> => {
    started.length = 0;
    const ctx = vitest as Vitest;
    // Stryker's runner clears the file list before every run and sets `related`
    // to the mutated file; the task registry behind it is NOT cleared.
    ctx.state.filesMap.clear();
    ctx.config.related = [path.join(dir, 'src', target)];
    await ctx.start();
    return [...started];
  };

  it('puts this sequencer in charge, and leads each run with the killer measured for ITS target', async () => {
    vitest = await createVitest(
      'test',
      {
        root: dir,
        config: false,
        include: ['tests/**/*.test.ts'],
        globals: true,
        watch: false,
        pool: 'threads',
        maxWorkers: 1,
        bail: 1,
        cache: false,
        reporters: [new MutationRunLedger(), recorder],
        sequence: mutationSequence({ shuffle: true, seed: 1337 }),
      },
      { logLevel: 'silent' },
    );
    // What vitest's resolver made of the block: this sequencer for the FILES,
    // and the tests inside each file still shuffled with the pinned seed.
    expect(vitest.config.sequence.sequencer).toBe(MutationSequencer);
    expect(vitest.config.sequence.shuffle).toBe(true);
    expect(vitest.config.sequence.seed).toBe(1337);

    // First run, nothing measured: the direct importer, then by size. A seeded
    // shuffle, which is what the base config would have installed, does not
    // produce this order.
    expect(await run('target.ts')).toEqual([
      'a-importer.test.ts',
      'b-small.test.ts',
      'c-killer.test.ts',
      'd-large.test.ts',
    ]);

    // Mutant one is switched on: c fails, so the worker bails there.
    writeFileSync(flagOne, '');
    const killed = await run('target.ts');
    expect(killed.at(-1)).toBe('c-killer.test.ts');
    // The next mutant of the same target starts with its killer.
    expect((await run('target.ts'))[0]).toBe('c-killer.test.ts');

    // Now a mutant of the OTHER module: j imports it directly, so j runs first,
    // fails, and the worker bails before c is reached. c was never run for this
    // target, so it must not be taken for this target's killer — vitest still
    // reports it at the end of the run, with the state it had last time.
    writeFileSync(flagTwo, '');
    expect(await run('other.ts')).toEqual(['j-other.test.ts']);
    const next = await run('other.ts');
    expect(next[0]).toBe('j-other.test.ts');
    expect(next).not.toContain('c-killer.test.ts');
  }, 60_000);
});
