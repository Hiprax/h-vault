/**
 * The per-change mutation leg's arithmetic: which mutants a change owns, which
 * of them a run tests, and how to tell Stryker exactly that set.
 *
 * `test:mutation:diff` is the cheap half of the oracle, split off so it can run
 * on every push while the full campaign keeps its own floor at tier 2. Every
 * decision below is about keeping that split HONEST: the cheap half must be a
 * fair, reproducible, disclosed measurement of the change, never a subset the
 * author can steer toward the mutants that happen to die.
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. A MUTANT BELONGS TO THE CHANGE WHEN IT TOUCHES A CHANGED LINE AND
 *     SWALLOWS NO UNCHANGED CODE. Exact line containment is too narrow: Prettier
 *     wraps at 100 columns, so `a &&` on one line and a changed `b` on the next
 *     is ONE logical-operator mutant spanning both, and containment would drop
 *     it silently. Plain overlap is too wide: the block `{}` mutant of a function
 *     with one changed line overlaps it too, and testing that block tests every
 *     unchanged statement inside it. The rule that separates the two is
 *     "contains no PURELY-unchanged mutant" (one lying entirely on unchanged
 *     lines): the wrapped operator passes, the function body does not. It is
 *     defined over the instrumenter's own mutant list, so it needs no second
 *     parser, and it has the property the plan below relies on: everything a
 *     candidate contains is itself a candidate.
 *
 *  b. THE SAMPLE IS KEYED, LINE-INDEPENDENT AND MONOTONE. When a change owns
 *     more mutants than the committed budget, a subset is tested, chosen by
 *     HMAC-SHA256 over each mutant's IDENTITY — path, mutator, original text,
 *     replacement, and its occurrence index among otherwise identical mutants —
 *     keyed by the merge base. Not by line number, so a cosmetic edit that
 *     shifts lines cannot re-roll it; not by the diff's content, so an author
 *     cannot shop for a sample by editing a comment; and lowest-hash-first, so a
 *     larger budget always tests a SUPERSET of a smaller one, which is what gives
 *     the budget's upward ratchet a meaning.
 *
 *  c. THE SAMPLE IS STRATIFIED: every changed file first, core modules next.
 *     One LOCATION of EVERY file that has a candidate is taken whatever the
 *     budget says, so no changed file can go unmeasured behind a large neighbour;
 *     then the candidates inside the declared core modules; then everything else.
 *
 *     That location is a LEAF — a candidate span with no other candidate
 *     strictly inside it — picked by the lowest hash among the leaf candidates.
 *     It is what keeps the one guaranteed measurement per file at the cost of
 *     one span's mutants, as the budget's own definition promises
 *     (`MUTATION_DIFF_BUDGETS`): a range at a block or an object literal selects
 *     everything nested in it (d), and taking whichever candidate hashed lowest
 *     made the per-file stratum alone 83 mutants on a 32-file server change
 *     whose budget is 20. Everything a candidate contains is itself a candidate
 *     (a), so a leaf among the candidates is a leaf among all of the file's
 *     mutants, and every file with a candidate has one. Mutants that share one
 *     span (`a < b` is replaced more than one way) are one location: they do not
 *     disqualify each other, and the seed's range selects all of them. The
 *     budget phase is untouched, so a container is still sampled, with its whole
 *     closure, whenever its hash comes up there.
 *
 *  d. THE PLAN IS EXACT, AND IT IS VERIFIED. Stryker mutates a node when its
 *     location lies inside a `mutate` range, so the range of a chosen mutant also
 *     selects every mutant nested inside it. The planned set is computed as that
 *     full closure, by the same inclusion rule, BEFORE Stryker runs — and the gate
 *     then requires Stryker to have tested exactly that set. A mismatch means the
 *     instrumenter here and the one inside Stryker disagree, and the run proves
 *     nothing.
 *
 *  e. NOTHING HERE READS THE FILESYSTEM, SPAWNS OR EXITS. The gate owns the
 *     process boundary; this module is pure so each rule can be pinned directly.
 */
import { createHmac } from 'node:crypto';

/**
 * @typedef {{ line: number, column: number }} Position   0-based line (Stryker's API convention), 0-based column
 * @typedef {{ start: Position, end: Position }} Location
 * @typedef {{ fileName: string, location: Location, mutatorName: string, replacement: string, status?: string }} ApiMutant
 */

/**
 * The working-tree line numbers each file's `+` hunks cover, from a `-U0`
 * unified diff (what `lib/changed-diff.mjs` builds). 1-based, like the hunks.
 *
 * @param {string} unifiedDiff
 * @returns {Map<string, Set<number>>}
 */
export function changedLinesByFile(unifiedDiff) {
  /** @type {Map<string, Set<number>>} */
  const changed = new Map();
  /** @type {Set<number> | null} */
  let current = null;
  for (const line of unifiedDiff.split('\n')) {
    if (line.startsWith('+++ ')) {
      const target = line.slice(4);
      // `/dev/null` is the target of a deletion: nothing to measure.
      if (target === '/dev/null') {
        current = null;
        continue;
      }
      const file = target.startsWith('b/') ? target.slice(2) : target;
      current = changed.get(file) ?? new Set();
      changed.set(file, current);
      continue;
    }
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/.exec(line);
    if (hunk && current) {
      const start = Number(hunk[1]);
      const count = hunk[2] === undefined ? 1 : Number(hunk[2]);
      for (let n = start; n < start + count; n++) current.add(n);
    }
  }
  for (const [file, lines] of changed) if (lines.size === 0) changed.delete(file);
  return changed;
}

/** Is `needle` inside `haystack`? Stryker's own `locationIncluded`, verbatim in meaning. */
export function locationIncluded(haystack, needle) {
  const startIncluded =
    haystack.start.line < needle.start.line ||
    (haystack.start.line === needle.start.line && haystack.start.column <= needle.start.column);
  const endIncluded =
    haystack.end.line > needle.end.line ||
    (haystack.end.line === needle.end.line && haystack.end.column >= needle.end.column);
  return startIncluded && endIncluded;
}

/** Do two locations cover exactly the same span? */
const sameSpan = (a, b) =>
  a.start.line === b.start.line &&
  a.start.column === b.start.column &&
  a.end.line === b.end.line &&
  a.end.column === b.end.column;

/**
 * (c) The candidates at LEAF locations: those with no other candidate STRICTLY
 * inside them. Candidates sharing one span do not disqualify each other.
 *
 * @param {readonly ApiMutant[]} candidates of ONE file
 * @returns {ApiMutant[]} in the given order
 */
export function leafCandidates(candidates) {
  return candidates.filter(
    (m) =>
      !candidates.some(
        (other) =>
          locationIncluded(m.location, other.location) && !sameSpan(m.location, other.location),
      ),
  );
}

/** The 1-based lines a mutant spans. */
const spannedLines = (mutant) => {
  const lines = [];
  for (let n = mutant.location.start.line + 1; n <= mutant.location.end.line + 1; n++)
    lines.push(n);
  return lines;
};

/**
 * (a) The mutants of ONE file that belong to its change.
 *
 * @param {readonly ApiMutant[]} mutants every mutant the instrumenter found in the file
 * @param {Set<number>} changedLines 1-based
 * @returns {ApiMutant[]} in the instrumenter's order
 */
export function candidateMutants(mutants, changedLines) {
  const purelyUnchanged = mutants.filter((m) => spannedLines(m).every((n) => !changedLines.has(n)));
  return mutants.filter(
    (m) =>
      spannedLines(m).some((n) => changedLines.has(n)) &&
      !purelyUnchanged.some((u) => locationIncluded(m.location, u.location)),
  );
}

/** The source text a location covers (0-based lines, 0-based columns, end exclusive). */
export function sliceLocation(sourceLines, location) {
  const { start, end } = location;
  if (start.line === end.line)
    return (sourceLines[start.line] ?? '').slice(start.column, end.column);
  const parts = [(sourceLines[start.line] ?? '').slice(start.column)];
  for (let n = start.line + 1; n < end.line; n++) parts.push(sourceLines[n] ?? '');
  parts.push((sourceLines[end.line] ?? '').slice(0, end.column));
  return parts.join('\n');
}

/**
 * (b) Each mutant's line-independent identity, and its keyed rank.
 *
 * @param {readonly ApiMutant[]} mutants of ONE file, in source order
 * @param {string} source that file's text
 * @param {string} key the HMAC key (the merge base)
 * @returns {Map<ApiMutant, string>} mutant -> hex rank (lower is chosen first)
 */
export function rankMutants(mutants, source, key) {
  const lines = source.split('\n');
  /** @type {Map<string, number>} */
  const seen = new Map();
  /** @type {Map<ApiMutant, string>} */
  const ranks = new Map();
  const ordered = [...mutants].sort(
    (a, b) =>
      a.location.start.line - b.location.start.line ||
      a.location.start.column - b.location.start.column ||
      a.location.end.line - b.location.end.line ||
      a.location.end.column - b.location.end.column,
  );
  for (const mutant of ordered) {
    const base = [
      mutant.fileName,
      mutant.mutatorName,
      sliceLocation(lines, mutant.location),
      mutant.replacement,
    ].join('\u0000');
    const occurrence = seen.get(base) ?? 0;
    seen.set(base, occurrence + 1);
    ranks.set(
      mutant,
      createHmac('sha256', key)
        .update(`${base}\u0000${String(occurrence)}`)
        .digest('hex'),
    );
  }
  return ranks;
}

/**
 * (b)+(c)+(d) Which mutants to test, and the ranges that make Stryker test them.
 *
 * @param {object} options
 * @param {{ file: string, candidates: ApiMutant[], all: ApiMutant[], ranks: Map<ApiMutant, string> }[]} options.files
 * @param {number} options.budget the committed planned-mutant budget for this leg
 * @param {(file: string) => boolean} options.isCore
 * @returns {{ seeds: ApiMutant[], planned: ApiMutant[], candidates: number, sampled: boolean }}
 */
export function planSample({ files, budget, isCore }) {
  const byRank = (a, b) => {
    const ra = /** @type {string} */ (rankOf(a));
    const rb = /** @type {string} */ (rankOf(b));
    return ra < rb ? -1 : ra > rb ? 1 : 0;
  };
  /** @type {Map<ApiMutant, string>} */
  const allRanks = new Map();
  /** @type {Map<ApiMutant, ApiMutant[]>} */
  const allOfFile = new Map();
  for (const entry of files) {
    for (const [mutant, rank] of entry.ranks) allRanks.set(mutant, rank);
    for (const mutant of entry.candidates) allOfFile.set(mutant, entry.all);
  }
  const rankOf = (mutant) => allRanks.get(mutant);

  const withCandidates = files.filter((entry) => entry.candidates.length > 0);
  const stratumFiles = [...withCandidates]
    .sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0))
    .map((entry) => /** @type {ApiMutant} */ (leafCandidates(entry.candidates).sort(byRank)[0]));
  const everyCandidate = withCandidates.flatMap((entry) => entry.candidates);
  const stratumCore = everyCandidate.filter((m) => isCore(m.fileName)).sort(byRank);
  const stratumRest = everyCandidate.filter((m) => !isCore(m.fileName)).sort(byRank);

  /** @type {Set<ApiMutant>} */
  const planned = new Set();
  /** @type {ApiMutant[]} */
  const seeds = [];
  const take = (seed) => {
    seeds.push(seed);
    for (const other of allOfFile.get(seed) ?? []) {
      if (locationIncluded(seed.location, other.location)) planned.add(other);
    }
  };
  for (const seed of stratumFiles) if (!planned.has(seed)) take(seed);
  for (const seed of [...stratumCore, ...stratumRest]) {
    if (planned.size >= budget) break;
    if (!planned.has(seed)) take(seed);
  }
  return {
    seeds,
    planned: [...planned],
    candidates: everyCandidate.length,
    sampled: planned.size < everyCandidate.length,
  };
}

/**
 * A Stryker `mutate` entry selecting exactly the nodes inside `location`:
 * `file:startLine:startColumn-endLine:endColumn`, lines 1-based and columns
 * 0-based, which is what Stryker's project reader parses (it subtracts one from
 * each line and none from each column).
 */
export const strykerRange = (file, location) =>
  `${file}:${String(location.start.line + 1)}:${String(location.start.column)}-${String(location.end.line + 1)}:${String(location.end.column)}`;

/** A mutant's identity in the instrumenter's coordinates (0-based lines and columns). */
export const apiMutantKey = (mutant) =>
  [
    mutant.fileName,
    `${String(mutant.location.start.line)}:${String(mutant.location.start.column)}`,
    `${String(mutant.location.end.line)}:${String(mutant.location.end.column)}`,
    mutant.mutatorName,
    mutant.replacement,
  ].join('|');

/**
 * The same identity for a mutant in Stryker's JSON report, which numbers lines
 * AND columns from 1 (`mutation-testing-report-schema`), so both are shifted
 * back before comparison.
 */
export const reportMutantKey = (file, mutant) =>
  [
    file,
    `${String(mutant.location.start.line - 1)}:${String(mutant.location.start.column - 1)}`,
    `${String(mutant.location.end.line - 1)}:${String(mutant.location.end.column - 1)}`,
    mutant.mutatorName,
    mutant.replacement,
  ].join('|');
