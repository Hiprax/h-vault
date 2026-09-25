/**
 * The order in which a MUTANT run visits its test files: the files most likely
 * to kill the mutant first, the cheapest files next.
 *
 * Installed by the three `vitest.mutation.config.ts` files, which drive both
 * mutation gates (`test:mutation:diff` at T1 and the `test:mutation` campaign at
 * T2), and by nothing else. The suites every other gate runs keep their seeded
 * FILE shuffle untouched, because that shuffle is how order independence is
 * measured (see each package's `vitest.config.ts`, and the ten shuffled runs of
 * `test:flake`); this module changes only the order inside Stryker.
 *
 * ---------------------------------------------------------------------------
 * WHY THE ORDER IS THE COST
 * ---------------------------------------------------------------------------
 *
 * Stryker's vitest runner drives a single vitest worker that bails at the first
 * failing test, so every file visited before the one that kills a mutant is
 * paid for in full. A mutant with per-test coverage visits only its covering
 * tests. A STATIC mutant — module-scope code, which in this codebase is every
 * Zod bound, every route table and every schema — has no per-test coverage, and
 * neither does a HYBRID one (reached at load time and by tests): for both,
 * Stryker runs every test related to the mutated file, and `ignoreStatic: false`
 * is load-bearing (`scripts/ci/lib/stryker-config.mjs`). Stryker also runs all
 * of them LAST, together, which is why a slow tail is what a leg ends with.
 *
 * Inherited from the base config, that walk followed vitest's `RandomSequencer`:
 * the same seeded permutation on every run, blind to what the run was mutating
 * and to which file had just killed a mutant of the same module. MEASURED on the
 * client leg of a 47-file change: 9 static mutants, all killed, completed 8,753
 * tests between them while the other 112 mutants completed 680; four hybrid
 * mutants of one regex, with ten covering tests each, completed about 2,000
 * tests apiece before dying. On the server leg the last 30 of 83 mutants took 38
 * of its 43 minutes, and 27 of those 30 were killed, not survived.
 *
 * ---------------------------------------------------------------------------
 * THE ORDER (`killSeekingOrder`)
 * ---------------------------------------------------------------------------
 *
 * The TARGET of a run is the file Stryker mutated: it hands vitest that file as
 * `related`, which vitest keeps on its config until the run has finished.
 *
 *  1. vitest's own grouping, exactly as `BaseSequencer` has it: `groupOrder`,
 *     then project name, then isolated projects first.
 *  2. Files that killed an earlier mutant OF THE SAME TARGET on this worker, the
 *     latest killer first. Keyed by target on purpose: a history shared by every
 *     target would put every past killer ahead of the cheap files for every later
 *     mutant, and on the server leg each of those files boots a mongod.
 *  3. Files that import the target DIRECTLY. The killer of a module-scope mutant
 *     is usually a test that reads that module's values, and such a test imports
 *     it. This is what makes the FIRST mutant of a target cheap too, which the
 *     history cannot, since Stryker hands a module's static mutants to all of its
 *     workers at once.
 *  4. Everything else.
 *
 * Inside 3 and 4: files whose cost this worker has measured, the cheapest first
 * (with one worker and no idea which file kills, the expected time to the first
 * failure is least when the cheap files go first; vitest's own longest-first
 * rule exists to keep parallel workers busy, which is not the situation here);
 * then unmeasured files, the smallest first. Ties go by module id, so the same
 * inputs always give the same order.
 *
 * ---------------------------------------------------------------------------
 * WHAT IT DOES NOT CHANGE
 * ---------------------------------------------------------------------------
 *
 * Which tests run, or any verdict. The sequencer receives the files vitest
 * selected and returns a permutation of them. A mutant is killed when some test
 * fails under it, and bailing stops only AFTER a failure, so the verdict is the
 * same in every order; a surviving mutant still runs every related test. Tests
 * INSIDE a file are still shuffled with the pinned seed (`mutationSequence`
 * keeps the base config's test shuffle).
 *
 * It keeps no per-machine state. The mutation configs set `cache: false`, so
 * vitest's `results.json` plays no part; the test files themselves are read (for
 * their imports and sizes), never written; and everything the order learns —
 * what each file costs and which files killed which target — is measured in
 * this process by `MutationRunLedger` through vitest's public reporter
 * interface, from the files each run actually ran, and dies with the process.
 */
import { readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
import {
  BaseSequencer,
  type InlineConfig,
  type Reporter,
  type TestModule,
  type TestSpecification,
  type Vitest,
} from 'vitest/node';

type SequenceOptions = NonNullable<InlineConfig['sequence']>;

/** One test file, as the order sees it. */
export interface OrderEntry {
  /** The file's module id (an absolute path); also the final tie-break. */
  readonly id: string;
  readonly groupOrder: number;
  readonly project: string;
  readonly isolated: boolean;
  /** The run in which this file last killed a mutant of the current target, if it ever did. */
  readonly killedAt: number | undefined;
  /** Does the file import the current target directly (and not mock it)? */
  readonly importsTarget: boolean;
  /** Milliseconds this file took the last time this worker ran it to completion. */
  readonly cost: number | undefined;
  /** Its size in bytes, for files not yet measured. */
  readonly size: number | undefined;
}

const compareIds = (a: OrderEntry, b: OrderEntry): number =>
  a.id < b.id ? -1 : a.id > b.id ? 1 : 0;

/** Measured files first, the cheapest first; then unmeasured ones, the smallest first. */
const compareCost = (a: OrderEntry, b: OrderEntry): number => {
  if ((a.cost === undefined) !== (b.cost === undefined)) return a.cost === undefined ? 1 : -1;
  if (a.cost !== undefined && b.cost !== undefined && a.cost !== b.cost) return a.cost - b.cost;
  if ((a.size === undefined) !== (b.size === undefined)) return a.size === undefined ? 1 : -1;
  return (a.size ?? 0) - (b.size ?? 0);
};

const tier = (entry: OrderEntry): number =>
  entry.killedAt !== undefined ? 0 : entry.importsTarget ? 1 : 2;

/**
 * The kill-seeking order, as a pure function of the entries. See the module
 * comment for the rules.
 *
 * @returns a new array holding exactly the given entries
 */
export function killSeekingOrder<T extends OrderEntry>(entries: readonly T[]): T[] {
  return [...entries].sort((a, b) => {
    if (a.groupOrder !== b.groupOrder) return a.groupOrder - b.groupOrder;
    if (a.project !== b.project) return a.project < b.project ? -1 : 1;
    if (a.isolated !== b.isolated) return a.isolated ? -1 : 1;
    const tierDifference = tier(a) - tier(b);
    if (tierDifference !== 0) return tierDifference;
    const within = tier(a) === 0 ? (b.killedAt ?? 0) - (a.killedAt ?? 0) : compareCost(a, b);
    return within !== 0 ? within : compareIds(a, b);
  });
}

// ---------------------------------------------------------------------------
// direct imports
// ---------------------------------------------------------------------------

/** vitest's helpers that load the REAL module, and those that replace it. */
const VI_REAL = new Set(['importActual']);
const VI_REPLACING = new Set(['mock', 'doMock', 'importMock']);

interface Reference {
  readonly specifier: string;
  readonly replaces: boolean;
}

/**
 * The module a node refers to, if it is one of the forms a test file uses to
 * reach a module: an import or re-export declaration, `import x = require()`, a
 * dynamic `import()`, `require()`, or one of vitest's module helpers — and
 * whether the reference REPLACES the module (`vi.mock` and friends), in which
 * case the file sees a stand-in and cannot observe a mutant in the real one.
 */
function referenceOf(node: ts.Node): Reference | undefined {
  const literal = (
    expression: ts.Expression | undefined,
    replaces = false,
  ): Reference | undefined =>
    expression && ts.isStringLiteralLike(expression)
      ? { specifier: expression.text, replaces }
      : undefined;
  // A type-only import or re-export is erased before the file runs, so it can
  // never observe a mutant either.
  if (ts.isImportDeclaration(node)) {
    return node.importClause?.isTypeOnly ? undefined : literal(node.moduleSpecifier);
  }
  if (ts.isExportDeclaration(node)) {
    return node.isTypeOnly ? undefined : literal(node.moduleSpecifier);
  }
  if (ts.isImportEqualsDeclaration(node) && ts.isExternalModuleReference(node.moduleReference)) {
    return literal(node.moduleReference.expression);
  }
  if (!ts.isCallExpression(node)) return undefined;
  const callee = node.expression;
  const first = node.arguments[0];
  if (callee.kind === ts.SyntaxKind.ImportKeyword) return literal(first);
  if (ts.isIdentifier(callee) && callee.text === 'require') return literal(first);
  if (
    ts.isPropertyAccessExpression(callee) &&
    ts.isIdentifier(callee.expression) &&
    callee.expression.text === 'vi'
  ) {
    if (VI_REAL.has(callee.name.text)) return literal(first);
    if (VI_REPLACING.has(callee.name.text)) {
      // `vi.mock(import('../x'))` names the module through an `import()` that is
      // never evaluated as one; the visitor still records that inner call as an
      // import, and `importsForReal` lets the replacement win.
      const named =
        first && ts.isCallExpression(first) && first.expression.kind === ts.SyntaxKind.ImportKeyword
          ? first.arguments[0]
          : first;
      return literal(named, true);
    }
  }
  return undefined;
}

/** A path without its script extension or a trailing `/index`: how an import names a file. */
export const moduleStem = (file: string): string =>
  file.replace(/\.(?:[cm]?[jt]sx?)$/, '').replace(/[/\\]index$/, '');

/** The relative modules a test file reaches at run time, and those it replaces. */
export interface ModuleReferences {
  readonly imports: ReadonlySet<string>;
  readonly replaces: ReadonlySet<string>;
}

/**
 * The stems of every RELATIVE module a test file's source reaches, resolved
 * against the file's directory, and of every module it replaces with a mock.
 * Bare specifiers (packages) are never the target.
 *
 * PARSED, not pattern-matched, for the reason `gate-surface.test.ts` parses the
 * harness for top-level awaits: a specifier-shaped string in a comment or a
 * template would fool a regex, and a real import split over several lines would
 * escape one. A file that does not parse cleanly still yields what the parser
 * recovered; the worst a miss can do is leave a file in the general tier.
 */
export function moduleReferences(testFile: string, source: string): ModuleReferences {
  const imports = new Set<string>();
  const replaces = new Set<string>();
  const visit = (node: ts.Node): void => {
    const reference = referenceOf(node);
    if (reference?.specifier.startsWith('.')) {
      const stem = moduleStem(path.resolve(path.dirname(testFile), reference.specifier));
      (reference.replaces ? replaces : imports).add(stem);
    }
    ts.forEachChild(node, visit);
  };
  // By extension: parsed as TSX, a `.ts` file's `<T>value` cast would be read as an element.
  const kind = /\.[cm]?[jt]sx$/.test(testFile) ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
  visit(ts.createSourceFile(testFile, source, ts.ScriptTarget.Latest, false, kind));
  return { imports, replaces };
}

/** Does a file with these references import one of the targets for real? */
export const importsForReal = (
  references: ModuleReferences,
  targetStems: Iterable<string>,
): boolean =>
  [...targetStems].some((stem) => references.imports.has(stem) && !references.replaces.has(stem));

// ---------------------------------------------------------------------------
// the ledger: what this worker has measured
// ---------------------------------------------------------------------------

/** What one Stryker worker's vitest has learned so far. Never persisted. */
export interface RunLedger {
  /** The target of the run in flight: the sorted `related` files, one per line. */
  target: string;
  /** How many runs have finished. */
  runs: number;
  /** Module id → milliseconds, from the last run in which every one of its tests passed. */
  readonly costs: Map<string, number>;
  /** Target → module id → the run in which that file last killed a mutant of it. */
  readonly killers: Map<string, Map<string, number>>;
}

export const createRunLedger = (): RunLedger => ({
  target: '',
  runs: 0,
  costs: new Map(),
  killers: new Map(),
});

/** One test file that RAN in a run, and what it showed. */
export interface ModuleOutcome {
  readonly id: string;
  /** Every test in it passed: a complete run, so its cost is a full measurement. */
  readonly passed: boolean;
  /** At least one of its TESTS failed, which under a mutant is the kill. */
  readonly killed: boolean;
  readonly cost: number;
}

/**
 * Folds one finished run into the ledger.
 *
 * Only files that ran are given, and only two things are learned from them: the
 * cost of a file whose tests all passed (a file cut short by its own failure
 * would look cheaper than it is), and, for a file with a failed test, that it
 * killed a mutant of the run's target. A file that failed without a failing test
 * — one that could not even be imported, or whose `beforeAll` threw — is
 * neither: vitest does not bail on it, so every related file runs anyway and no
 * order could have reached a verdict sooner.
 */
export function recordRun(ledger: RunLedger, outcomes: readonly ModuleOutcome[]): void {
  ledger.runs += 1;
  for (const outcome of outcomes) {
    if (outcome.passed) ledger.costs.set(outcome.id, outcome.cost);
    if (outcome.killed) {
      const killers = ledger.killers.get(ledger.target) ?? new Map<string, number>();
      killers.set(outcome.id, ledger.runs);
      ledger.killers.set(ledger.target, killers);
    }
  }
}

/** One ledger per vitest instance: the sequencer and the reporter meet here. */
const ledgers = new WeakMap<Vitest, RunLedger>();
const ledgerOf = (vitest: Vitest): RunLedger => {
  let ledger = ledgers.get(vitest);
  if (!ledger) {
    ledger = createRunLedger();
    ledgers.set(vitest, ledger);
  }
  return ledger;
};

/** Everything a test file cost, from vitest's public per-module diagnostic. */
const costOf = (module: TestModule): number => {
  const d = module.diagnostic();
  return (
    d.duration +
    d.collectDuration +
    d.setupDuration +
    d.prepareDuration +
    d.environmentSetupDuration
  );
};

const hasFailedTest = (module: TestModule): boolean => {
  for (const test of module.children.allTests('failed')) if (test) return true;
  return false;
};

/**
 * The reporter half: it measures each run for the sequencer. Install one per
 * config (`reporters: [..., new MutationRunLedger()]`).
 *
 * It learns from `onTestModuleEnd`, which vitest calls for the files that RAN,
 * and never from the module list `onTestRunEnd` is handed: that list names every
 * file the run SELECTED, and one the worker never reached (bail stopped first)
 * appears there still carrying the state of the last run that did reach it — so
 * a file that killed a mutant of one module would be credited with killing the
 * next module's mutant too, and history keyed by target would quietly become one
 * history for all of them.
 */
export class MutationRunLedger implements Reporter {
  #vitest: Vitest | undefined;
  #ran: ModuleOutcome[] = [];

  onInit(vitest: Vitest): void {
    this.#vitest = vitest;
  }

  onTestRunStart(): void {
    this.#ran = [];
  }

  onTestModuleEnd(module: TestModule): void {
    this.#ran.push({
      id: module.moduleId,
      passed: module.state() === 'passed',
      killed: hasFailedTest(module),
      cost: costOf(module),
    });
  }

  onTestRunEnd(): void {
    if (this.#vitest) recordRun(ledgerOf(this.#vitest), this.#ran);
    this.#ran = [];
  }
}

// ---------------------------------------------------------------------------
// the sequencer half
// ---------------------------------------------------------------------------

/** The sequencer the mutation configs install. See the module comment. */
export class MutationSequencer extends BaseSequencer {
  /** Test file → the modules it reaches. Test files are never mutated, so read once. */
  readonly #references = new Map<string, ModuleReferences>();
  readonly #sizes = new Map<string, number | undefined>();

  #referencesOf(file: string): ModuleReferences {
    let references = this.#references.get(file);
    if (!references) {
      // A module id that is not a file on disk names nothing to scan.
      const source = this.#sizeOf(file) === undefined ? '' : readFileSync(file, 'utf8');
      references = moduleReferences(file, source);
      this.#references.set(file, references);
    }
    return references;
  }

  #sizeOf(file: string): number | undefined {
    if (!this.#sizes.has(file))
      this.#sizes.set(file, statSync(file, { throwIfNoEntry: false })?.size);
    return this.#sizes.get(file);
  }

  override sort(files: TestSpecification[]): Promise<TestSpecification[]> {
    const { config } = this.ctx;
    const ledger = ledgerOf(this.ctx);
    const targets = (config.related ?? []).map((file) => path.resolve(config.root, file)).sort();
    ledger.target = targets.join('\n');
    const targetStems = new Set(targets.map(moduleStem));
    const killers = ledger.killers.get(ledger.target);
    const entries = files.map((spec) => ({
      spec,
      id: spec.moduleId,
      groupOrder: spec.project.config.sequence.groupOrder,
      project: spec.project.name,
      isolated: spec.project.config.isolate,
      killedAt: killers?.get(spec.moduleId),
      importsTarget: importsForReal(this.#referencesOf(spec.moduleId), targetStems),
      cost: ledger.costs.get(spec.moduleId),
      size: this.#sizeOf(spec.moduleId),
    }));
    return Promise.resolve(killSeekingOrder(entries).map((entry) => entry.spec));
  }
}

/**
 * The `sequence` block a mutation config installs over its base config's: files
 * in the kill-seeking order, the tests inside each file shuffled exactly as the
 * base shuffles them, with the base seed and hook order.
 */
export function mutationSequence(base: SequenceOptions | undefined): SequenceOptions {
  const shuffle = base?.shuffle;
  const tests = typeof shuffle === 'object' ? (shuffle.tests ?? false) : shuffle === true;
  return { ...base, shuffle: { files: false, tests }, sequencer: MutationSequencer };
}
