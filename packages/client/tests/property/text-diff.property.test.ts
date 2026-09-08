/**
 * The document diff, as properties.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS FUNCTION DESERVES GENERATED INPUT
 * ---------------------------------------------------------------------------
 *
 * `diffText` is what the upload panel's format-and-repair review shows a user
 * before they replace their own document with a rewrite of it. The transform
 * itself runs inside the isolated sandbox; the COMPARISON is computed here,
 * from the application's own copy of the original, precisely so that the dialog
 * cannot be built from numbers the frame chose. That makes this module's output
 * a security-relevant claim — "these lines, and only these lines, will change" —
 * and a claim of that shape is worth stating as an invariant rather than as a
 * list of examples.
 *
 * The example tests in `tests/document-transform.test.ts` are good and stay:
 * they pin the presentation decisions (a replacement reads `-old` then `+new`)
 * and the named edge cases. What they cannot do is quantify. This file states
 * the algebra:
 *
 *   1. THE ROUND TRIP. Reading the hunks and keeping every non-`added` line
 *      rebuilds `before`; keeping every non-`removed` line rebuilds `after`;
 *      and the regions BETWEEN hunks — the ones the user is never shown — are
 *      identical in the two files. That last clause is the one that matters: a
 *      diff whose hunks are individually correct but which quietly omits a
 *      changed region is a dialog that asks permission for less than it does.
 *   2. THE REPORTED NUMBERS. `linesAdded`/`linesRemoved` count the operations
 *      the hunks actually carry, `identical` is true exactly when the two texts
 *      are equal, and on the bail-out path the numbers are a genuine upper
 *      bound rather than a guess.
 *   3. THE HEADERS. Hunks are ordered, never overlap, carry at most
 *      {@link CONTEXT_LINES} of context beyond a change, and each `@@` header
 *      points at exactly the region of each file the hunk displays.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS DELIBERATELY NOT DONE HERE
 * ---------------------------------------------------------------------------
 *
 * Nothing in this file re-implements the diff. There is no second LCS, no model
 * of the algorithm and no copy of its constants imported from the module: the
 * properties are stated over the PUBLIC output and the arrays the generator
 * chose, and the two constants the implementation keeps private
 * ({@link CONTEXT_LINES} and the cell ceiling) are pinned from OUTSIDE by
 * observed behaviour — see `derives the context window from the diff itself`
 * and the bail-out block. A test that imported them would agree with production
 * by construction, which is the failure mode `storageBreaker`'s module-private
 * threshold exists to avoid, and it is the same failure mode here.
 */
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { diffText, type TextDiff } from '../../src/lib/textDiff';
import {
  propertyBanner,
  propertyRun,
  stringFromAlphabet,
} from '../../../../tests/harness/property.js';

/** One hunk, named through the public type — `DiffHunk` itself is not exported. */
type Hunk = NonNullable<TextDiff['hunks']>[number];

/**
 * The lines of context a hunk keeps on each side of a change.
 *
 * A SPECIFICATION, not an import. `textDiff.ts` keeps its own `CONTEXT_LINES`
 * module-private, and importing it would make every bound below agree with
 * production by construction: widen the window to five and a test that read the
 * constant would still pass. This number is instead pinned against observed
 * behaviour by the first test in the hunk block, so changing the implementation
 * turns that test red and this line has to move with it deliberately.
 */
const CONTEXT_LINES = 3;

/**
 * A middle region big enough that the exact comparison refuses it.
 *
 * The implementation's ceiling is `(n + 1) * (m + 1) > MAX_DIFF_CELLS` over the
 * region that is neither a common prefix nor a common suffix, and
 * `MAX_DIFF_CELLS` is module-private for the reason given above. `1501 * 1501`
 * is 2,253,001, comfortably past the 2,000,000 the module documents. The
 * bail-out property asserts `hunks === null` for this size and `hunks !== null`
 * for {@link EXACT_MIDDLE}, so a change to the ceiling does not silently make
 * this block test nothing — it turns it red, and someone decides.
 */
const BAIL_OUT_MIDDLE = 1_500;

/** A middle region small enough that the exact comparison runs. */
const EXACT_MIDDLE = 40;

/**
 * Latin letters, digits, punctuation — and, load-bearingly, no `\n`.
 *
 * A carriage return IS in the alphabet, and deliberately: `splitLines` splits on
 * `\n` alone, so a `\r` stays on the line it belongs to and cannot change how many
 * lines the generator's array becomes. Including it puts the documented "a
 * rewritten line ending is a change to that line" behaviour inside the counting
 * properties rather than leaving it to a single example test.
 */
const LINE_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789 .,-_/(){}[]"\':;\r';

/**
 * One generated line.
 *
 * Drawn from an explicit alphabet rather than `fc.string()` because a line that
 * contained `\n` would be TWO lines the moment the generator joined its array
 * into a document, and every line-count property below would then be measuring
 * the generator instead of the diff. Short, so that generated documents have
 * repeated lines by chance as real ones do.
 */
const lineArbitrary = stringFromAlphabet(LINE_ALPHABET, { maxLength: 6 });

/**
 * A tiny vocabulary of lines, so that two INDEPENDENTLY generated documents
 * still share long common subsequences.
 *
 * Independent random strings would give the LCS walk nothing to find: every
 * comparison would be a mismatch, every diff would be "delete everything, add
 * everything", and the tie-break, the prefix/suffix trim and the hunk merger
 * would all go unexercised. A six-word vocabulary is what makes the interesting
 * half of the algorithm reachable from an unstructured generator.
 */
const VOCABULARY = ['{', '}', '  "a": 1,', '  "b": 2,', '', 'x'] as const;

/**
 * The canonical form of a generated line array.
 *
 * `split('\n')` is a bijection between strings and NON-EMPTY arrays of
 * newline-free strings: `''` splits to `['']`, and no string splits to `[]`. An
 * empty array therefore describes a document `diffText` can never be handed,
 * and a property that fed it one would be asserting against a line count the
 * function is right to disagree with.
 */
function canonical(lines: readonly string[]): string[] {
  return lines.length === 0 ? [''] : [...lines];
}

/** A generated pair of documents. */
interface Pair {
  readonly before: readonly string[];
  readonly after: readonly string[];
}

/** The document as `diffText` receives it. */
function asText(lines: readonly string[]): string {
  return lines.join('\n');
}

/** One step of an edit script applied to a line of the original. */
type Action =
  | { readonly kind: 'keep' }
  | { readonly kind: 'drop' }
  | { readonly kind: 'replace'; readonly text: string }
  | { readonly kind: 'insert'; readonly text: string };

const actionArbitrary: fc.Arbitrary<Action> = fc.oneof(
  // Weighted towards `keep`, because runs of unchanged lines are what produce
  // context, hunk boundaries and the merge decision. A uniform script rewrites
  // most of the document and collapses every diff into one hunk.
  { arbitrary: fc.constant<Action>({ kind: 'keep' }), weight: 6 },
  { arbitrary: fc.constant<Action>({ kind: 'drop' }), weight: 1 },
  { arbitrary: lineArbitrary.map((text): Action => ({ kind: 'replace', text })), weight: 1 },
  { arbitrary: lineArbitrary.map((text): Action => ({ kind: 'insert', text })), weight: 1 },
);

/** Two documents drawn independently from {@link VOCABULARY}. */
const vocabularyPair: fc.Arbitrary<Pair> = fc
  .tuple(
    fc.array(fc.constantFrom(...VOCABULARY), { minLength: 1, maxLength: 24 }),
    fc.array(fc.constantFrom(...VOCABULARY), { minLength: 1, maxLength: 24 }),
  )
  .map(([before, after]) => ({ before: canonical(before), after: canonical(after) }));

/** A document and the result of running an edit script over it. */
const editedPair: fc.Arbitrary<Pair> = fc
  .tuple(
    fc.array(fc.record({ line: lineArbitrary, action: actionArbitrary }), {
      minLength: 1,
      maxLength: 40,
    }),
    // Appended lines, because an `insert` action sits BEFORE the line it is
    // attached to and can therefore never describe an addition at end of file —
    // which is the single most common real transform outcome (a trailing
    // newline the formatter added).
    fc.array(lineArbitrary, { maxLength: 3 }),
  )
  .map(([entries, appended]) => {
    const before = entries.map((entry) => entry.line);
    const after: string[] = [];
    for (const { line, action } of entries) {
      if (action.kind === 'keep') after.push(line);
      else if (action.kind === 'replace') after.push(action.text);
      else if (action.kind === 'insert') after.push(action.text, line);
      // 'drop' contributes nothing.
    }
    after.push(...appended);
    return { before: canonical(before), after: canonical(after) };
  });

/**
 * A document whose changes sit at CONTROLLED distances from one another.
 *
 * This exists because the other two generators cannot be trusted to reach the
 * hunk-merging boundary. `toHunks` merges two ranges when the second starts no
 * more than one operation past the end of the first, which — for two replaced
 * lines with `gap` unchanged lines between them — puts the decision at exactly
 * `gap === 2 * CONTEXT_LINES`. An edit script weighted towards `keep` reaches
 * that distance only by luck, and MEASURED: with the merge condition mutated
 * from `start <= last.end + 1` to `start <= last.end`, every property in this
 * file stayed green until this generator existed. A boundary that the generator
 * cannot reach is a boundary the suite does not cover.
 *
 * The gaps are drawn across the threshold in both directions, every line is a
 * distinct token so no accidental common subsequence forms, and the document
 * opens and closes with a run long enough that the first and last hunks are not
 * clamped by the edges.
 */
const spacedChangesPair: fc.Arbitrary<Pair> = fc
  .array(fc.integer({ min: 0, max: 2 * CONTEXT_LINES + 4 }), { minLength: 1, maxLength: 5 })
  .map((gaps) => {
    const before: string[] = [];
    const after: string[] = [];
    let next = 0;
    const unchangedRun = (length: number): void => {
      for (let index = 0; index < length; index += 1) {
        const line = `same ${String(next)}`;
        next += 1;
        before.push(line);
        after.push(line);
      }
    };

    unchangedRun(CONTEXT_LINES + 1);
    for (const gap of gaps) {
      before.push(`old ${String(next)}`);
      after.push(`new ${String(next)}`);
      next += 1;
      unchangedRun(gap);
    }
    unchangedRun(CONTEXT_LINES + 1);

    return { before, after };
  });

/** A document compared against a copy of itself. */
const identicalPair: fc.Arbitrary<Pair> = fc
  .array(lineArbitrary, { minLength: 1, maxLength: 20 })
  .map((lines) => ({ before: canonical(lines), after: canonical(lines) }));

/**
 * The generator every structural property runs over.
 *
 * Four shapes rather than one: the vocabulary pair reaches the LCS walk and its
 * tie-break, the edit script reaches the context/hunk machinery, the spaced pair
 * reaches the merge boundary neither of the first two can be relied on to hit,
 * and the identical pair makes `identical === (before === after)` a claim with
 * cases on BOTH sides rather than a one-sided one that two random documents
 * would never falsify.
 */
const documentPair: fc.Arbitrary<Pair> = fc.oneof(
  { arbitrary: vocabularyPair, weight: 2 },
  { arbitrary: editedPair, weight: 3 },
  { arbitrary: spacedChangesPair, weight: 3 },
  { arbitrary: identicalPair, weight: 1 },
);

// ---------------------------------------------------------------------------
// Reading a hunk header
// ---------------------------------------------------------------------------

/**
 * The first line of `before` this hunk covers.
 *
 * NOTE, so a reader does not mistake these for covered cases: the `count === 0`
 * arm of this helper and of the three below it is UNREACHABLE today, and so is
 * the production ternary it mirrors (`textDiff.ts:218`). A hunk's window extends
 * `CONTEXT_LINES` operations past the last change, so a window holding no
 * non-`added` operation would need an operation list that is entirely additions,
 * i.e. a `before` with zero lines — which `split('\n')` never produces. The arms
 * are kept for the same reason production keeps the ternary: both become
 * reachable the moment `CONTEXT_LINES` is 0.
 *
 * `toHunks` writes `beforeStart = beforeAt - 1` when a hunk covers no line of
 * the original at all — the unified-diff convention for an insertion, which
 * names the line the new text goes AFTER. So the first line the hunk actually
 * displays is one past the header in that case, and the header itself in every
 * other.
 */
function firstBeforeLine(hunk: Hunk): number {
  return hunk.beforeCount === 0 ? hunk.beforeStart + 1 : hunk.beforeStart;
}

function firstAfterLine(hunk: Hunk): number {
  return hunk.afterCount === 0 ? hunk.afterStart + 1 : hunk.afterStart;
}

/** The last line of `before` this hunk covers, or the insertion point. */
function lastBeforeLine(hunk: Hunk): number {
  return hunk.beforeCount === 0 ? hunk.beforeStart : hunk.beforeStart + hunk.beforeCount - 1;
}

function lastAfterLine(hunk: Hunk): number {
  return hunk.afterCount === 0 ? hunk.afterStart : hunk.afterStart + hunk.afterCount - 1;
}

/** The run of unchanged lines a hunk opens with. */
function leadingContext(hunk: Hunk): number {
  let count = 0;
  while (count < hunk.lines.length && hunk.lines[count]?.kind === 'context') count += 1;
  return count;
}

/** The run of unchanged lines a hunk closes with. */
function trailingContext(hunk: Hunk): number {
  let count = 0;
  while (
    count < hunk.lines.length &&
    hunk.lines[hunk.lines.length - 1 - count]?.kind === 'context'
  ) {
    count += 1;
  }
  return count;
}

function textsOf(hunk: Hunk, exclude: 'added' | 'removed'): string[] {
  return hunk.lines.filter((line) => line.kind !== exclude).map((line) => line.text);
}

function countOf(hunks: readonly Hunk[], kind: 'added' | 'removed'): number {
  return hunks.reduce(
    (total, hunk) => total + hunk.lines.filter((line) => line.kind === kind).length,
    0,
  );
}

/**
 * Rebuilds BOTH documents from the hunk list and asserts they come back exactly.
 *
 * This is the round trip and the header arithmetic in one walk, and it has to be
 * one walk: a hunk's `@@` header is a claim about where it sits in each FILE,
 * which can only be checked by consuming the file alongside the hunks. The
 * regions between hunks are asserted EQUAL in the two documents before being
 * appended to both reconstructions — that is the clause which makes a diff that
 * silently omits a changed region a failure here rather than a smaller diff.
 */
function expectHunksRebuildBothDocuments(pair: Pair, hunks: readonly Hunk[]): void {
  const rebuiltBefore: string[] = [];
  const rebuiltAfter: string[] = [];
  // 1-based cursors: the next line of each document that has been neither shown
  // by a hunk nor accounted for as an unchanged gap.
  let beforeCursor = 1;
  let afterCursor = 1;

  for (const hunk of hunks) {
    const beforeAt = firstBeforeLine(hunk);
    const afterAt = firstAfterLine(hunk);

    const beforeGap = pair.before.slice(beforeCursor - 1, beforeAt - 1);
    const afterGap = pair.after.slice(afterCursor - 1, afterAt - 1);
    expect(
      afterGap,
      `${propertyBanner()} — a region between hunks is not the same in both documents, so the diff hid a change`,
    ).toEqual(beforeGap);

    const kept = textsOf(hunk, 'added');
    const introduced = textsOf(hunk, 'removed');
    expect(
      kept.length,
      `${propertyBanner()} — beforeCount disagrees with the hunk's own lines`,
    ).toBe(hunk.beforeCount);
    expect(
      introduced.length,
      `${propertyBanner()} — afterCount disagrees with the hunk's own lines`,
    ).toBe(hunk.afterCount);
    expect(
      pair.before.slice(beforeAt - 1, beforeAt - 1 + hunk.beforeCount),
      `${propertyBanner()} — the @@ header does not point at the region of "before" the hunk shows`,
    ).toEqual(kept);
    expect(
      pair.after.slice(afterAt - 1, afterAt - 1 + hunk.afterCount),
      `${propertyBanner()} — the @@ header does not point at the region of "after" the hunk shows`,
    ).toEqual(introduced);

    rebuiltBefore.push(...beforeGap, ...kept);
    rebuiltAfter.push(...afterGap, ...introduced);
    beforeCursor = beforeAt + hunk.beforeCount;
    afterCursor = afterAt + hunk.afterCount;
  }

  const beforeTail = pair.before.slice(beforeCursor - 1);
  const afterTail = pair.after.slice(afterCursor - 1);
  expect(
    afterTail,
    `${propertyBanner()} — the region after the last hunk is not the same in both documents`,
  ).toEqual(beforeTail);
  rebuiltBefore.push(...beforeTail);
  rebuiltAfter.push(...afterTail);

  expect(
    rebuiltBefore,
    `${propertyBanner()} — context + removed does not reconstruct "before"`,
  ).toEqual([...pair.before]);
  expect(
    rebuiltAfter,
    `${propertyBanner()} — context + added does not reconstruct "after"`,
  ).toEqual([...pair.after]);
}

// ---------------------------------------------------------------------------
// 18.1 — the round trip
// ---------------------------------------------------------------------------

describe('diffText reconstructs both documents from what it reports', () => {
  it('rebuilds "before" from context + removed and "after" from context + added', () => {
    fc.assert(
      fc.property(documentPair, (pair) => {
        const diff = diffText(asText(pair.before), asText(pair.after));
        // Every generated pair is small enough for the exact path; a `null` here
        // would mean the ceiling moved and this property stopped running.
        expect(diff.hunks, `${propertyBanner()} — the exact comparison was skipped`).not.toBeNull();
        expectHunksRebuildBothDocuments(pair, diff.hunks ?? []);
      }),
      propertyRun(),
    );
  });

  it('never emits a hunk that shows no change at all', () => {
    // The negative half of the round trip. A hunk of pure context reconstructs
    // both documents perfectly and is still a defect: it asks the user to review
    // a region nothing happened in, and it is what a broken change-index filter
    // in `toHunks` produces.
    fc.assert(
      fc.property(documentPair, (pair) => {
        for (const hunk of diffText(asText(pair.before), asText(pair.after)).hunks ?? []) {
          expect(
            hunk.lines.some((line) => line.kind !== 'context'),
            `${propertyBanner()} — a hunk carries no change`,
          ).toBe(true);
        }
      }),
      propertyRun(),
    );
  });
});

// ---------------------------------------------------------------------------
// 18.2 — the reported numbers
// ---------------------------------------------------------------------------

describe('the numbers diffText reports', () => {
  it('counts the lines of each document exactly, on every path', () => {
    fc.assert(
      fc.property(documentPair, (pair) => {
        const diff = diffText(asText(pair.before), asText(pair.after));
        expect(diff.linesBefore, propertyBanner()).toBe(pair.before.length);
        expect(diff.linesAfter, propertyBanner()).toBe(pair.after.length);
      }),
      propertyRun(),
    );
  });

  it('reports added and removed counts that match the operations in the hunks', () => {
    fc.assert(
      fc.property(documentPair, (pair) => {
        const diff = diffText(asText(pair.before), asText(pair.after));
        const hunks = diff.hunks ?? [];
        expect(
          diff.linesAdded,
          `${propertyBanner()} — linesAdded is not the added operations`,
        ).toBe(countOf(hunks, 'added'));
        expect(
          diff.linesRemoved,
          `${propertyBanner()} — linesRemoved is not the removed operations`,
        ).toBe(countOf(hunks, 'removed'));
        // Neither count may exceed the document it describes.
        expect(diff.linesRemoved, propertyBanner()).toBeLessThanOrEqual(diff.linesBefore);
        expect(diff.linesAdded, propertyBanner()).toBeLessThanOrEqual(diff.linesAfter);
      }),
      propertyRun(),
    );
  });

  it('keeps the two counts in balance with the change in document length', () => {
    // `added - removed` is forced to equal the growth of the document, because
    // both are `length - lcs`. It holds on the bail-out path too, where both
    // counts are the size of the non-common middle. An off-by-one in the LCS
    // fill or in the prefix/suffix trim breaks it while every count still looks
    // individually plausible.
    fc.assert(
      fc.property(documentPair, (pair) => {
        const diff = diffText(asText(pair.before), asText(pair.after));
        expect(diff.linesAdded - diff.linesRemoved, propertyBanner()).toBe(
          diff.linesAfter - diff.linesBefore,
        );
      }),
      propertyRun(),
    );
  });

  it('reports identical exactly when the two texts are equal, and no hunks with it', () => {
    fc.assert(
      fc.property(documentPair, (pair) => {
        const beforeText = asText(pair.before);
        const afterText = asText(pair.after);
        const diff = diffText(beforeText, afterText);
        expect(diff.identical, `${propertyBanner()} — identical disagrees with the texts`).toBe(
          beforeText === afterText,
        );
        if (diff.identical) {
          // `[]` and not `null`: the panel distinguishes "nothing changed" from
          // "the comparison was skipped", and they are not the same sentence.
          expect(diff.hunks, propertyBanner()).toEqual([]);
          expect(diff.linesAdded, propertyBanner()).toBe(0);
          expect(diff.linesRemoved, propertyBanner()).toBe(0);
          expect(diff.linesBefore, propertyBanner()).toBe(diff.linesAfter);
        } else {
          expect(diff.hunks, `${propertyBanner()} — a difference produced no hunk`).not.toEqual([]);
          expect(
            diff.linesAdded + diff.linesRemoved,
            `${propertyBanner()} — a difference was reported as zero lines`,
          ).toBeGreaterThan(0);
        }
      }),
      propertyRun(),
    );
  });

  it('reports an insertion-only edit as insertions and nothing else', () => {
    // The original is a SUBSEQUENCE of the result, so the longest common
    // subsequence is the whole original and the only honest answer is "k added,
    // 0 removed". Known analytically, so this catches an LCS that under-counts —
    // which shows the user spurious deletions of lines that are still there.
    fc.assert(
      fc.property(
        fc.array(lineArbitrary, { minLength: 1, maxLength: 30 }),
        fc.array(fc.tuple(fc.nat(), lineArbitrary), { maxLength: 6 }),
        (base, insertions) => {
          const after = [...base];
          for (const [position, text] of insertions) {
            after.splice(position % (after.length + 1), 0, text);
          }
          const pair: Pair = { before: base, after };
          const diff = diffText(asText(base), asText(after));
          expect(diff.linesRemoved, `${propertyBanner()} — an insertion removed a line`).toBe(0);
          expect(diff.linesAdded, propertyBanner()).toBe(insertions.length);
          expectHunksRebuildBothDocuments(pair, diff.hunks ?? []);
        },
      ),
      propertyRun(),
    );
  });

  it('reports a deletion-only edit as deletions and nothing else', () => {
    fc.assert(
      fc.property(
        fc.array(fc.record({ line: lineArbitrary, keep: fc.boolean() }), {
          minLength: 1,
          maxLength: 30,
        }),
        (entries) => {
          const before = entries.map((entry) => entry.line);
          const kept = entries.filter((entry) => entry.keep).map((entry) => entry.line);
          // A document always has at least one line (see `canonical`), so a
          // script that deleted every one of them keeps the first.
          const after = kept.length === 0 ? [before[0] ?? ''] : kept;
          const diff = diffText(asText(before), asText(after));
          expect(diff.linesAdded, `${propertyBanner()} — a deletion added a line`).toBe(0);
          expect(diff.linesRemoved, propertyBanner()).toBe(before.length - after.length);
          expectHunksRebuildBothDocuments({ before, after }, diff.hunks ?? []);
        },
      ),
      propertyRun(),
    );
  });
});

// ---------------------------------------------------------------------------
// 18.2 — the bail-out path
// ---------------------------------------------------------------------------

/** The shape of a document pair, instantiated at two sizes. */
interface BailOutShape {
  readonly head: number;
  readonly tail: number;
  readonly interior: number[];
}

/**
 * Builds a document pair from a shape at a given middle size.
 *
 * Every token is distinct from every other — `head i`, `mid i`, `MID i`,
 * `tail i` — which is what makes the exact answer knowable without computing an
 * LCS: the two middles agree at exactly the unchanged positions and can match
 * nowhere else, so the exact diff is `changes` removals and `changes` additions
 * whatever the size. Positions `0` and `size - 1` are always changed, so the
 * implementation's common-prefix and common-suffix scans stop precisely at the
 * head and the tail and the middle it measures is `size` on both sides.
 */
function instantiate(
  shape: BailOutShape,
  size: number,
): { readonly pair: Pair; readonly changes: number } {
  const changed = new Set<number>([0, size - 1, ...shape.interior]);
  const head = Array.from({ length: shape.head }, (_, index) => `head ${String(index)}`);
  const tail = Array.from({ length: shape.tail }, (_, index) => `tail ${String(index)}`);
  const beforeMiddle = Array.from({ length: size }, (_, index) => `mid ${String(index)}`);
  const afterMiddle = beforeMiddle.map((line, index) =>
    changed.has(index) ? `MID ${String(index)}` : line,
  );
  return {
    pair: {
      before: [...head, ...beforeMiddle, ...tail],
      after: [...head, ...afterMiddle, ...tail],
    },
    changes: changed.size,
  };
}

describe('the bail-out path, when the exact comparison does not fit', () => {
  /**
   * `interior` is bounded well below {@link EXACT_MIDDLE} so the SAME positions
   * are valid at both sizes; that is what lets the small instance stand as proof
   * of the large one's exact answer.
   */
  const bailOutShape: fc.Arbitrary<BailOutShape> = fc.record({
    head: fc.integer({ min: 0, max: 4 }),
    tail: fc.integer({ min: 0, max: 4 }),
    interior: fc.uniqueArray(fc.integer({ min: 1, max: 30 }), { maxLength: 4 }),
  });

  it('takes the exact path AT the cell ceiling and refuses one row past it', () => {
    // The ceiling itself, pinned from outside — and the reason it is pinned at
    // all: without this, `(midBefore.length + 1) * (midAfter.length + 1) >
    // MAX_DIFF_CELLS` can be mutated to `>=`, or the constant moved by one, and
    // every other test in this file stays green. BAIL_OUT_MIDDLE is three
    // hundred thousand cells clear of the boundary, which is exactly what makes
    // it useless for deciding where the boundary is.
    //
    // 1000 x 2000 is 2,000,000 cells — the largest comparison the module says it
    // will make — and 1001 x 2000 is the smallest one past it. Two documents of
    // 999 and 1999 distinct lines produce the first; one more line on the left
    // produces the second. Nothing here imports the constant: it is read off the
    // behaviour, one row apart.
    const distinct = (prefix: string, count: number): string[] =>
      Array.from({ length: count }, (_, index) => `${prefix}${String(index)}`);
    const right = asText(distinct('b', 1_999));

    const atCeiling = diffText(asText(distinct('a', 999)), right);
    expect(atCeiling.hunks, 'exactly 2,000,000 cells still fits').not.toBeNull();
    // And the exact answer, which is the whole point of it fitting: no line of
    // either document appears in the other.
    expect(atCeiling.linesRemoved).toBe(999);
    expect(atCeiling.linesAdded).toBe(1_999);

    const pastCeiling = diffText(asText(distinct('a', 1_000)), right);
    expect(pastCeiling.hunks, 'one row further is 2,002,000 cells and does not').toBeNull();
    expect(pastCeiling.linesRemoved).toBe(1_000);
    expect(pastCeiling.linesAdded).toBe(1_999);
  });

  it('reports counts that are a genuine upper bound on the exact ones', () => {
    // The honest way to check an upper bound on a number nobody can afford to
    // compute: instantiate ONE shape at two sizes. At {@link EXACT_MIDDLE} the
    // exact path runs, and PRODUCTION ITSELF reports the exact answer for the
    // shape — nothing here re-implements an LCS to predict it. At
    // {@link BAIL_OUT_MIDDLE} the same shape has the same exact answer, by the
    // uniqueness argument in `instantiate`, and the bail-out must not report
    // fewer changes than that.
    //
    // Budget: the full PROPERTY_RUNS. Each case builds, joins and splits four
    // documents — two of ~1,500 lines — which sounds expensive and is not:
    // MEASURED at 97ms for the full 100 cases on an idle 4-core box, because the
    // ceiling is checked before the dynamic-programming table is ever allocated.
    // That is paid three times over — the unit tier plus the two timezone legs of
    // `test:property` — and the fast tier does not notice it.
    fc.assert(
      fc.property(bailOutShape, (shape) => {
        const exact = instantiate(shape, EXACT_MIDDLE);
        const exactDiff = diffText(asText(exact.pair.before), asText(exact.pair.after));
        expect(
          exactDiff.hunks,
          `${propertyBanner()} — the small instance should take the exact path`,
        ).not.toBeNull();
        expect(exactDiff.linesRemoved, propertyBanner()).toBe(exact.changes);
        expect(exactDiff.linesAdded, propertyBanner()).toBe(exact.changes);

        const big = instantiate(shape, BAIL_OUT_MIDDLE);
        const bailed = diffText(asText(big.pair.before), asText(big.pair.after));
        expect(
          bailed.hunks,
          `${propertyBanner()} — the large instance should skip the exact path`,
        ).toBeNull();
        expect(bailed.identical, propertyBanner()).toBe(false);

        // The counts stay exact where the docstring says they do.
        expect(bailed.linesBefore, propertyBanner()).toBe(big.pair.before.length);
        expect(bailed.linesAfter, propertyBanner()).toBe(big.pair.after.length);

        // The bound is the non-common middle: the shared head and tail are
        // excluded, which is what makes the number one a user can act on.
        expect(
          bailed.linesRemoved,
          `${propertyBanner()} — the common ends leaked into the bail-out count`,
        ).toBe(BAIL_OUT_MIDDLE);
        expect(bailed.linesAdded, propertyBanner()).toBe(BAIL_OUT_MIDDLE);
        expect(bailed.linesBefore - bailed.linesRemoved, propertyBanner()).toBe(
          shape.head + shape.tail,
        );

        // And it IS a bound: never below the exact answer, never above the file.
        expect(
          bailed.linesRemoved,
          `${propertyBanner()} — the bail-out under-reported the change`,
        ).toBeGreaterThanOrEqual(exactDiff.linesRemoved);
        expect(bailed.linesAdded, propertyBanner()).toBeGreaterThanOrEqual(exactDiff.linesAdded);
        expect(bailed.linesRemoved, propertyBanner()).toBeLessThanOrEqual(bailed.linesBefore);
        expect(bailed.linesAdded, propertyBanner()).toBeLessThanOrEqual(bailed.linesAfter);
        // Upper, and strictly so for these shapes: at most six positions really
        // changed (`0`, `size - 1`, and up to four interior ones). A bound that happened to be tight everywhere would mean the
        // shape stopped exercising the thing this property is about.
        expect(
          bailed.linesRemoved,
          `${propertyBanner()} — the bound stopped being an over-estimate`,
        ).toBeGreaterThan(exactDiff.linesRemoved);
      }),
      propertyRun(),
    );
  });
});

// ---------------------------------------------------------------------------
// 18.3 — the hunks
// ---------------------------------------------------------------------------

describe('the hunks and their headers', () => {
  it('derives the context window from the diff itself, and it is the one the properties assume', () => {
    // The pin that keeps CONTEXT_LINES above from being a copy nobody checks.
    // One change in the middle of a long file produces one hunk whose leading
    // and trailing runs of unchanged lines ARE the window, so raising or
    // lowering it in `textDiff.ts` turns this red and the constant here has to
    // be moved deliberately.
    const before = Array.from({ length: 40 }, (_, index) => `line ${String(index)}`);
    const after = [...before];
    after[20] = 'CHANGED';
    const hunks = diffText(asText(before), asText(after)).hunks ?? [];
    expect(hunks).toHaveLength(1);
    const [hunk] = hunks;
    expect(hunk).toBeDefined();
    expect(leadingContext(hunk!), 'the leading context run is CONTEXT_LINES').toBe(CONTEXT_LINES);
    expect(trailingContext(hunk!), 'the trailing context run is CONTEXT_LINES').toBe(CONTEXT_LINES);
    // Nothing beyond the window: the removal, the addition, and two full runs.
    expect(hunk!.lines).toHaveLength(2 * CONTEXT_LINES + 2);
  });

  it('merges two changes exactly while their context windows touch, and splits them one line later', () => {
    // The second half of the CONTEXT_LINES pin, and the boundary the property
    // above cannot state on its own. Two replaced lines separated by `gap`
    // unchanged lines share a hunk while their windows meet — which is at
    // `gap === 2 * CONTEXT_LINES`, the last distance where the trailing context
    // of the first change and the leading context of the second leave no line
    // between them. One further line apart and they are two hunks.
    const hunkCountForGap = (gap: number): number => {
      const before: string[] = [];
      const after: string[] = [];
      const run = (from: number, length: number): void => {
        for (let index = 0; index < length; index += 1) {
          before.push(`same ${String(from + index)}`);
          after.push(`same ${String(from + index)}`);
        }
      };
      run(0, CONTEXT_LINES + 1);
      before.push('old A');
      after.push('new A');
      run(100, gap);
      before.push('old B');
      after.push('new B');
      run(200, CONTEXT_LINES + 1);
      return (diffText(asText(before), asText(after)).hunks ?? []).length;
    };

    expect(hunkCountForGap(2 * CONTEXT_LINES - 1), 'inside the window').toBe(1);
    expect(hunkCountForGap(2 * CONTEXT_LINES), 'the windows still touch').toBe(1);
    expect(hunkCountForGap(2 * CONTEXT_LINES + 1), 'one line past the window').toBe(2);
  });

  it('carries at most CONTEXT_LINES of context beyond a change, and cuts it short only at a document edge', () => {
    fc.assert(
      fc.property(documentPair, (pair) => {
        const diff = diffText(asText(pair.before), asText(pair.after));
        for (const hunk of diff.hunks ?? []) {
          const leading = leadingContext(hunk);
          const trailing = trailingContext(hunk);
          expect(leading, `${propertyBanner()} — too much leading context`).toBeLessThanOrEqual(
            CONTEXT_LINES,
          );
          expect(trailing, `${propertyBanner()} — too much trailing context`).toBeLessThanOrEqual(
            CONTEXT_LINES,
          );
          // The other direction, which is what makes the bound TIGHT rather than
          // merely satisfied: the window is only ever short because the document
          // ran out, never because the hunk chose to show less.
          if (leading < CONTEXT_LINES) {
            expect(
              [firstBeforeLine(hunk), firstAfterLine(hunk)],
              `${propertyBanner()} — short leading context away from the top of the document`,
            ).toEqual([1, 1]);
          }
          if (trailing < CONTEXT_LINES) {
            expect(
              [lastBeforeLine(hunk), lastAfterLine(hunk)],
              `${propertyBanner()} — short trailing context away from the end of the document`,
            ).toEqual([diff.linesBefore, diff.linesAfter]);
          }
        }
      }),
      propertyRun(),
    );
  });

  it('emits hunks in order, never overlapping, always separated by an unshown line', () => {
    // Adjacency is the failure this forbids: two hunks that touch are two hunks
    // that should have been merged, and the merge condition in `toHunks`
    // (`start <= last.end + 1`) is one character away from producing them.
    fc.assert(
      fc.property(documentPair, (pair) => {
        const hunks = diffText(asText(pair.before), asText(pair.after)).hunks ?? [];
        for (const [index, hunk] of hunks.entries()) {
          if (index === 0) continue;
          const previous = hunks[index - 1];
          expect(previous).toBeDefined();
          expect(
            firstBeforeLine(hunk),
            `${propertyBanner()} — hunks touch or overlap in "before"`,
          ).toBeGreaterThan(lastBeforeLine(previous!) + 1);
          expect(
            firstAfterLine(hunk),
            `${propertyBanner()} — hunks touch or overlap in "after"`,
          ).toBeGreaterThan(lastAfterLine(previous!) + 1);
        }
      }),
      propertyRun(),
    );
  });

  it('declares start lines that sit inside the documents they number', () => {
    fc.assert(
      fc.property(documentPair, (pair) => {
        const diff = diffText(asText(pair.before), asText(pair.after));
        for (const hunk of diff.hunks ?? []) {
          expect(firstBeforeLine(hunk), propertyBanner()).toBeGreaterThanOrEqual(1);
          expect(firstAfterLine(hunk), propertyBanner()).toBeGreaterThanOrEqual(1);
          expect(lastBeforeLine(hunk), propertyBanner()).toBeLessThanOrEqual(diff.linesBefore);
          expect(lastAfterLine(hunk), propertyBanner()).toBeLessThanOrEqual(diff.linesAfter);
          // A hunk that covers no line of one document still names a real
          // position in it — the line the insertion follows, which is `0` only
          // when the insertion is at the very top.
          if (hunk.beforeCount === 0) {
            expect(hunk.beforeStart, propertyBanner()).toBeLessThanOrEqual(diff.linesBefore);
          }
          if (hunk.afterCount === 0) {
            expect(hunk.afterStart, propertyBanner()).toBeLessThanOrEqual(diff.linesAfter);
          }
        }
      }),
      propertyRun(),
    );
  });
});
