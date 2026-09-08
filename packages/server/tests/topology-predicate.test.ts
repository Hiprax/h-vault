/**
 * The replica-set topology predicate has exactly ONE definition.
 *
 * `utils/transactionSupport.ts` answers one question — does the connected
 * topology support multi-document transactions — and every caller that picks
 * between a transactional and a sequential write path depends on getting the
 * SAME answer. Its own docblock says centralizing it "keeps the replica-set
 * detection consistent across call sites", and that sentence was untrue for a
 * long time: the predicate existed in five places — the canonical one and four
 * copies — two of them exported under the same name, and the copies had already
 * begun to diverge
 * (the canonical one is parameterized on a connection so a fabricated one can
 * drive both branches in a test; the copies hard-coded `mongoose.connection`).
 *
 * A copy is not a style problem. Each of these callers writes across several
 * collections, and the copy decides whether that write is atomic. A fix applied
 * to one definition and not the others — a sharded cluster that advertises no
 * `replicaSet` option, a `readyState` that has to be treated as connecting, an
 * upstream driver that moves the option — silently leaves the un-fixed callers
 * on the wrong path, and the wrong path here is a partial write to a vault.
 *
 * ## What each check pins, and why the criterion is what it is
 *
 * The obvious guard, "`options.replicaSet` appears only in the canonical file",
 * is WRONG, and asserting it would have made this file red on arrival:
 * `config/database.ts` reads the same option for a completely different purpose
 * (`verifyTopology` compares what the URI *requests* against what the server's
 * `hello` actually reports, and warns at boot). So the first check is a
 * two-name allowlist with the reason for each name written down, exact in both
 * directions — a new reader of the option is a red test, and deleting either
 * allowed reader is a red test too, so the guard cannot go vacuous.
 *
 * An allowlist alone would then be a hiding place: a predicate re-inlined
 * inside `database.ts` would be allowed. The second check closes that by
 * looking for the predicate's SHAPE — a topology read evaluated together with a
 * `readyState`, within one expression's reach of each other — anywhere outside
 * the canonical module. It deliberately does not key on
 * `ConnectionStates.connected`, because `readyState === 1` spells the same
 * predicate and a copy is just as wrong for being written the short way.
 *
 * ## What a "topology read" is, and what these checks do NOT catch
 *
 * Both checks above run on the SAME set of patterns, and that set is where the
 * honesty of this file lives, so it is spelled out rather than implied. A first
 * draft keyed on the single literal `options.replicaSet`, which was enough for
 * the four historical copies (all of them
 * `mongoose.connection.getClient().options.replicaSet`) and not enough for an
 * ordinary refactor: `const { replicaSet } = connection.getClient().options`
 * contains no such substring and would have sailed through every check here
 * while reintroducing the exact defect. So {@link TOPOLOGY_READS} now covers
 * four spellings — dotted access, bracket access, a destructuring pattern that
 * binds `replicaSet`, and a call to `getClient()` — and the last of those is the
 * one that closes the class, because the option lives on the driver's client and
 * a re-implementation has to reach it somehow. (Ground truth, checked: after the
 * consolidation `getClient()` appears in exactly the two allowed files.)
 *
 * It is still text matching, and text matching has edges. Known ones, stated so
 * that nobody reads more assurance into a green run than it carries: a nested
 * destructure (`const { options: { replicaSet } } = …`) is not matched by the
 * pattern below; `connection.client.options` reaches the same object without
 * `getClient()`, and is caught only by the `replicaSet` patterns beside it; and
 * a copy that launders the value through enough statements to put its
 * `readyState` more than {@link SAME_EXPRESSION_CHARS} away from its topology
 * read defeats the proximity rule. The right tool for full closure is an AST
 * pass, which is a different tier of test; what this file guarantees is that the
 * copies that actually happened, and the idiomatic rewrites nearest to them,
 * cannot come back quietly.
 *
 * The third check catches the copies that keep the name: a second `export
 * function supportsTransactions` (which is what `utils/cascadeDelete.ts` had),
 * and a `const supportsTransactions = <inlined expression>` local to a
 * controller (which is what `userController` and `authController` had). The
 * first two checks catch a copy that renames itself, as `folderController`'s
 * `useTransaction` did.
 *
 * See {@link SCANNED_TREES} for what is scanned and why `tests/` is not.
 */

import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(__dirname, '..');

/**
 * The trees scanned, relative to `packages/server`.
 *
 * `scripts/` is in as well as `src/`, and deliberately: `create-indexes.ts` is
 * PRODUCTION tooling (the compose stack's bootstrap one-shot runs it, and it is
 * required in production), so a topology predicate re-implemented there would be
 * every bit as real as one in a controller and was outside an `src`-only scan.
 *
 * `tests/` is deliberately OUT. Tests fabricate connections on purpose —
 * `{ getClient: () => ({ options: { replicaSet } }) }` is how the predicate's own
 * unit tests drive both of its branches — so scanning them would forbid exactly
 * the thing that proves the canonical predicate works.
 */
const SCANNED_TREES = ['src', 'scripts'] as const;

/** The one module allowed to define the predicate. */
const CANONICAL = 'src/utils/transactionSupport.ts';

/**
 * Every module allowed to read the connection's topology, and why.
 *
 * - `src/utils/transactionSupport.ts` — the predicate itself.
 * - `src/config/database.ts` — `verifyTopology()`, which is not a predicate at all:
 *   it reads what the URI requested so it can compare that against the server's
 *   `hello` response and warn at boot when the two disagree. It answers "is the
 *   deployment configured the way it claims", not "may I open a transaction".
 */
const ALLOWED_TOPOLOGY_READERS = [CANONICAL, 'src/config/database.ts'] as const;

/**
 * Every spelling of "this code reaches the connection's topology", in the four
 * forms described in the header.
 *
 * Declared WITHOUT the global flag on purpose. A `/g` regex carries `lastIndex`
 * across `.test()` calls, so the same pattern reused over a list of files skips
 * every other file — a guard that reads as working and checks half the tree.
 * {@link matchIndexes} compiles its own global copy from `.source` when it needs
 * one.
 *
 * None of these can match ordinary prose, which is deliberate: a bare
 * `/\breplicaSet\b/` would also fire on `toolsController.ts`'s comment about
 * "the URI's `replicaSet` option", and a guard that goes red on documentation is
 * a guard someone deletes.
 */
const TOPOLOGY_READS = [
  /** `options.replicaSet`, `options?.replicaSet` — what all four copies used. */
  /options\s*\??\.\s*replicaSet\b/,
  /** `options['replicaSet']`. */
  /\[\s*['"]replicaSet['"]\s*\]/,
  /** `const { replicaSet } = …options`, including a renamed binding. */
  /\{[^}]*\breplicaSet\b[^}]*\}\s*=/,
  /** The driver client itself — the object the option lives on. */
  /\bgetClient\s*\(\s*\)/,
] as const;

/** Any read of a connection's `readyState`, including the `=== 1` spelling. */
const READY_STATE = /\breadyState\b/;

/**
 * How close a `readyState` read has to be to a `options.replicaSet` read before
 * the two count as one expression. The copies this file exists to prevent were
 * two adjacent lines, ~80 characters apart:
 *
 *     mongoose.connection.readyState === mongoose.ConnectionStates.connected &&
 *     Boolean(mongoose.connection.getClient().options.replicaSet);
 *
 * A whole-file rule ("the option and `readyState` may not both appear") was
 * rejected: it would turn any unrelated future `readyState` read in
 * `config/database.ts` into a false red, and a guard that fires on innocent
 * edits is a guard that gets deleted.
 */
const SAME_EXPRESSION_CHARS = 300;

/** Declares the predicate under its own name, rather than importing it. */
const DECLARES_PREDICATE = /(?:function|const|let|var)\s+supportsTransactions\b/;

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (entry.isFile() && entry.name.endsWith('.ts')) out.push(full);
  }
  return out;
}

interface SourceFile {
  /** Posix-style path relative to `packages/server/src`, e.g. `utils/logger.ts`. */
  rel: string;
  contents: string;
}

const sources: SourceFile[] = SCANNED_TREES.flatMap((tree) =>
  walk(path.join(packageRoot, tree)).map((full) => ({
    rel: path.relative(packageRoot, full).split(path.sep).join('/'),
    contents: readFileSync(full, 'utf-8'),
  })),
).sort((a, b) => a.rel.localeCompare(b.rel));

/** Every match's start index, over EVERY pattern, so proximity is measured. */
function topologyReadIndexes(contents: string): number[] {
  const out: number[] = [];
  for (const pattern of TOPOLOGY_READS) {
    const global = new RegExp(pattern.source, `${pattern.flags}g`);
    for (const match of contents.matchAll(global)) {
      if (typeof match.index === 'number') out.push(match.index);
    }
  }
  return out.sort((a, b) => a - b);
}

/** Every match's start index for one pattern. */
function matchIndexes(contents: string, pattern: RegExp): number[] {
  const global = new RegExp(pattern.source, `${pattern.flags}g`);
  const out: number[] = [];
  for (const match of contents.matchAll(global)) {
    if (typeof match.index === 'number') out.push(match.index);
  }
  return out;
}

describe('the replica-set topology predicate has one definition', () => {
  it('scans a non-empty server source tree', () => {
    // The denominator. Every assertion below is "no file does X"; a broken walk
    // satisfies all of them while proving nothing.
    expect(sources.length).toBeGreaterThan(50);
    expect(sources.map((s) => s.rel)).toContain(CANONICAL);
  });

  it('reaches the connection topology in exactly the two modules allowed to', () => {
    const readers = sources
      .filter((s) => TOPOLOGY_READS.some((pattern) => pattern.test(s.contents)))
      .map((s) => s.rel);

    // Exact, in both directions. A new reader is a copy until proven otherwise
    // and belongs in the list above WITH its reason; a disappeared reader means
    // this guard has stopped watching the thing it was written for.
    expect(readers).toEqual([...ALLOWED_TOPOLOGY_READERS].sort((a, b) => a.localeCompare(b)));
  });

  it('never evaluates a topology read together with readyState outside the canonical module', () => {
    const offenders: string[] = [];

    for (const source of sources) {
      if (source.rel === CANONICAL) continue;
      const optionAt = topologyReadIndexes(source.contents);
      if (optionAt.length === 0) continue;
      const readyAt = matchIndexes(source.contents, READY_STATE);

      for (const option of optionAt) {
        const near = readyAt.some((ready) => Math.abs(ready - option) <= SAME_EXPRESSION_CHARS);
        if (near) {
          const line = source.contents.slice(0, option).split('\n').length;
          // Deduped: two patterns can match at one index (a destructure that
          // also names `getClient()`), and one defect should be reported once.
          const site = `${source.rel}:${String(line)}`;
          if (!offenders.includes(site)) offenders.push(site);
        }
      }
    }

    expect(
      offenders,
      `these modules re-implement the transaction-topology predicate instead of importing ` +
        `supportsTransactions from ${CANONICAL}`,
    ).toEqual([]);
  });

  it('declares supportsTransactions in exactly one module', () => {
    const declarers = sources.filter((s) => DECLARES_PREDICATE.test(s.contents)).map((s) => s.rel);

    expect(declarers).toEqual([CANONICAL]);
  });

  it('exports the canonical predicate parameterized on a connection', () => {
    // The parameter is not decoration: it is what lets the predicate's own unit
    // tests drive BOTH branches from a fabricated connection, and it is the one
    // thing every copy dropped. A copy that reverts to a hard-coded
    // `mongoose.connection` would pass the three checks above by being the only
    // definition, so pin the signature too.
    const canonical = sources.find((s) => s.rel === CANONICAL);
    expect(canonical).toBeDefined();
    expect(canonical?.contents).toMatch(
      /export function supportsTransactions\(\s*connection: mongoose\.Connection = mongoose\.connection,?\s*\)/,
    );
  });
});
