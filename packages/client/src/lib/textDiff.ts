/**
 * A line-oriented unified diff, hand-rolled and dependency-free.
 *
 * ---------------------------------------------------------------------------
 * WHY THE HOST COMPUTES THIS AT ALL
 * ---------------------------------------------------------------------------
 *
 * The upload panel's format-and-repair transforms run inside the isolated
 * sandbox document, and that document is the least trusted component in this
 * application: it is where a user's arbitrary file meets Prettier and a JSON
 * repairer. It hands back the transformed TEXT and nothing else. The comparison
 * the user is asked to confirm — how many bytes moved, which lines changed, what
 * the diff looks like — is computed HERE, from the application's own copy of the
 * original, because a confirmation dialog built from numbers the frame chose is a
 * dialog that can lie about what it is asking permission for.
 *
 * ---------------------------------------------------------------------------
 * THE BOUNDARY THIS MODULE SITS ON, WRITTEN DOWN SO IT IS NOT WIDENED
 * ---------------------------------------------------------------------------
 *
 * The application may charset-decode a document and compare its text. It may NOT
 * interpret a document's STRUCTURE. Splitting on newlines and comparing strings
 * is the former; `JSON.parse`, a Markdown parser, a syntax highlighter, Prettier
 * and the JSON repairer are all the latter, and every one of them lives in the
 * sandbox. This module must therefore stay dependency-free — not for size, but
 * because a diff library added here would be a third-party parser running in the
 * origin that holds the unlocked vault.
 */

/** One line of a unified diff. */
interface DiffLine {
  readonly kind: 'context' | 'added' | 'removed';
  readonly text: string;
}

/** One contiguous run of change, with the usual three lines of context. */
interface DiffHunk {
  /** 1-based first line of the hunk in each version, as `@@ -a,b +c,d @@` reports. */
  readonly beforeStart: number;
  readonly beforeCount: number;
  readonly afterStart: number;
  readonly afterCount: number;
  readonly lines: readonly DiffLine[];
}

export interface TextDiff {
  readonly identical: boolean;
  readonly linesBefore: number;
  readonly linesAfter: number;
  readonly linesAdded: number;
  readonly linesRemoved: number;
  /**
   * The hunks, or `null` when the two versions were too large to compare line by
   * line.
   *
   * `null` is a real answer rather than a failure: the byte delta and the line
   * counts are still exact, and the panel says that the detailed comparison was
   * skipped rather than pretending there was nothing to show. When it is `null`,
   * `linesAdded` and `linesRemoved` are the size of the whole changed region —
   * an upper bound, not a count of individually changed lines.
   */
  readonly hunks: readonly DiffHunk[] | null;
}

/**
 * The ceiling on the comparison, in dynamic-programming cells.
 *
 * The exact line diff below is O(n·m) in time and memory, which is the right
 * algorithm for the sizes this feature actually sees — a document is capped at
 * `MAX_FORMATTABLE_SIZE_BYTES` (5 MiB) and a formatted configuration file is
 * hundreds of lines, not hundreds of thousands. Two million cells is a 4-byte
 * table of 8 MB and roughly 1,400 changed lines on each side; past that the
 * panel reports the exact byte and line totals and skips the line-by-line view,
 * which is a far better outcome than a tab that stops responding while
 * somebody's minified 5 MiB JSON is compared against its expansion.
 */
const MAX_DIFF_CELLS = 2_000_000;

/** Lines of unchanged context kept on each side of a change. */
const CONTEXT_LINES = 3;

/**
 * Split into lines the way a diff must: on `\n` ONLY.
 *
 * A carriage return stays on the line it belongs to, so a transform that
 * rewrote CRLF to LF shows up as a change to every line rather than as nothing
 * at all. That is noisy and it is correct — it is a rewrite of every line, and
 * the formatter is configured (`endOfLine: 'auto'`) precisely so that it does not
 * happen.
 */
function splitLines(text: string): string[] {
  return text.split('\n');
}

/**
 * The exact line diff, as a list of operations, or `null` when it was too large.
 *
 * Common leading and trailing lines are removed first. That is not an
 * optimisation for its own sake: an appended line at the end of a 50,000-line
 * file leaves a middle of ONE line, so the cheap step is what makes the ordinary
 * case fit inside the budget at all.
 */
function operations(
  before: readonly string[],
  after: readonly string[],
): readonly DiffLine[] | null {
  let head = 0;
  while (head < before.length && head < after.length && before[head] === after[head]) head += 1;
  let tail = 0;
  while (
    tail < before.length - head &&
    tail < after.length - head &&
    before[before.length - 1 - tail] === after[after.length - 1 - tail]
  ) {
    tail += 1;
  }

  const midBefore = before.slice(head, before.length - tail);
  const midAfter = after.slice(head, after.length - tail);
  if ((midBefore.length + 1) * (midAfter.length + 1) > MAX_DIFF_CELLS) return null;

  // Longest common subsequence over the middle. `lengths` is (n+1)·(m+1) and is
  // filled from the end so the walk below can read it forwards.
  const n = midBefore.length;
  const m = midAfter.length;
  const width = m + 1;
  const lengths = new Uint32Array((n + 1) * width);
  for (let i = n - 1; i >= 0; i -= 1) {
    for (let j = m - 1; j >= 0; j -= 1) {
      lengths[i * width + j] =
        midBefore[i] === midAfter[j]
          ? (lengths[(i + 1) * width + j + 1] ?? 0) + 1
          : Math.max(lengths[(i + 1) * width + j] ?? 0, lengths[i * width + j + 1] ?? 0);
    }
  }

  const result: DiffLine[] = [];
  for (let index = 0; index < head; index += 1) {
    result.push({ kind: 'context', text: before[index] ?? '' });
  }
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (midBefore[i] === midAfter[j]) {
      result.push({ kind: 'context', text: midBefore[i] ?? '' });
      i += 1;
      j += 1;
      continue;
    }
    // A REMOVAL is preferred when the two choices tie, so a replaced line reads
    // as "-old" then "+new" rather than the reverse. It is a presentation
    // decision and it is the one every diff tool makes.
    if ((lengths[(i + 1) * width + j] ?? 0) >= (lengths[i * width + j + 1] ?? 0)) {
      result.push({ kind: 'removed', text: midBefore[i] ?? '' });
      i += 1;
    } else {
      result.push({ kind: 'added', text: midAfter[j] ?? '' });
      j += 1;
    }
  }
  while (i < n) {
    result.push({ kind: 'removed', text: midBefore[i] ?? '' });
    i += 1;
  }
  while (j < m) {
    result.push({ kind: 'added', text: midAfter[j] ?? '' });
    j += 1;
  }
  for (let index = after.length - tail; index < after.length; index += 1) {
    result.push({ kind: 'context', text: after[index] ?? '' });
  }
  return result;
}

/** Group an operation list into unified hunks with {@link CONTEXT_LINES} of context. */
function toHunks(lines: readonly DiffLine[]): DiffHunk[] {
  const changed = lines
    .map((line, index) => (line.kind === 'context' ? -1 : index))
    .filter((index) => index >= 0);
  if (changed.length === 0) return [];

  // Ranges of operation indices to show, merged where their context overlaps.
  const ranges: { start: number; end: number }[] = [];
  for (const index of changed) {
    const start = Math.max(0, index - CONTEXT_LINES);
    const end = Math.min(lines.length - 1, index + CONTEXT_LINES);
    const last = ranges[ranges.length - 1];
    if (last && start <= last.end + 1) {
      last.end = Math.max(last.end, end);
      continue;
    }
    ranges.push({ start, end });
  }

  // Line numbers are accumulated over the WHOLE operation list, because a hunk's
  // header describes where it sits in each file, not where it sits in the diff.
  const beforeNumbers: number[] = [];
  const afterNumbers: number[] = [];
  let beforeLine = 1;
  let afterLine = 1;
  for (const line of lines) {
    beforeNumbers.push(beforeLine);
    afterNumbers.push(afterLine);
    if (line.kind !== 'added') beforeLine += 1;
    if (line.kind !== 'removed') afterLine += 1;
  }

  return ranges.map((range) => {
    const slice = lines.slice(range.start, range.end + 1);
    const beforeCount = slice.filter((line) => line.kind !== 'added').length;
    const afterCount = slice.filter((line) => line.kind !== 'removed').length;
    const beforeAt = beforeNumbers[range.start] ?? 1;
    const afterAt = afterNumbers[range.start] ?? 1;
    return {
      // A hunk that is entirely additions covers no line of the original, and
      // unified diff writes its start as the line BEFORE the insertion — which
      // is what `beforeCount === 0` produces here without a special case.
      beforeStart: beforeCount === 0 ? beforeAt - 1 : beforeAt,
      beforeCount,
      afterStart: afterCount === 0 ? afterAt - 1 : afterAt,
      afterCount,
      lines: slice,
    };
  });
}

/**
 * Compare two versions of a document, line by line.
 *
 * Identical inputs answer `identical: true` with no hunks, which is the case
 * that matters most in practice: repairing an already-valid JSON document is
 * byte-identical, and the panel has to be able to say "nothing changed" rather
 * than asking the user to confirm a rewrite that did not happen.
 */
export function diffText(before: string, after: string): TextDiff {
  const beforeLines = splitLines(before);
  const afterLines = splitLines(after);
  if (before === after) {
    return {
      identical: true,
      linesBefore: beforeLines.length,
      linesAfter: afterLines.length,
      linesAdded: 0,
      linesRemoved: 0,
      hunks: [],
    };
  }

  const ops = operations(beforeLines, afterLines);
  if (ops === null) {
    // The exact comparison did not fit. The counts reported are the size of the
    // region that is not a common prefix or suffix — an upper bound on what
    // changed, and labelled as one by `hunks: null`.
    let head = 0;
    while (
      head < beforeLines.length &&
      head < afterLines.length &&
      beforeLines[head] === afterLines[head]
    ) {
      head += 1;
    }
    let tail = 0;
    while (
      tail < beforeLines.length - head &&
      tail < afterLines.length - head &&
      beforeLines[beforeLines.length - 1 - tail] === afterLines[afterLines.length - 1 - tail]
    ) {
      tail += 1;
    }
    return {
      identical: false,
      linesBefore: beforeLines.length,
      linesAfter: afterLines.length,
      linesRemoved: beforeLines.length - head - tail,
      linesAdded: afterLines.length - head - tail,
      hunks: null,
    };
  }

  return {
    identical: false,
    linesBefore: beforeLines.length,
    linesAfter: afterLines.length,
    linesAdded: ops.filter((line) => line.kind === 'added').length,
    linesRemoved: ops.filter((line) => line.kind === 'removed').length,
    hunks: toHunks(ops),
  };
}
