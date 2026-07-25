/**
 * The "where exactly is the problem" half of a backup-code parse error.
 *
 * `parseBackupCodes` reports a position rather than the offending text, precisely
 * so the message can never carry a secret. This module turns that position back
 * into something a person can act on: a short window of the input the user is
 * already looking at, with the offending run highlighted.
 */
import { cn } from '../../lib/utils';

/** A short, single-line window of the raw input around an offending run. */
export interface ExcerptWindow {
  /** Text immediately before the offending run, inside the window. */
  readonly before: string;
  /** The offending run itself. Empty for an insertion point. */
  readonly bad: string;
  /** Text immediately after the offending run, inside the window. */
  readonly after: string;
  /** 1-based line number of the problem within the raw input. */
  readonly lineNumber: number;
  /** 1-based column of the problem within its line. */
  readonly column: number;
  /** True when the window starts partway through its line. */
  readonly truncatedStart: boolean;
  /** True when the window ends before the end of its line. */
  readonly truncatedEnd: boolean;
}

/** Characters of context to keep on each side of the offending run. */
const DEFAULT_RADIUS = 24;

/**
 * Build the excerpt window for a reported position.
 *
 * The window is always scoped to the single line the problem is on. That is what
 * makes multi-line input work: the excerpt can never span a newline, so it can
 * never appear to point at the wrong line, and `lineNumber`/`column` give the user
 * a coordinate they can find in their own textarea.
 *
 * An issue with `length: 0` is an insertion point (something is MISSING here, such
 * as a closing bracket), so one character of context is highlighted instead of
 * nothing, keeping the marker visible.
 *
 * Every `BackupCodesIssue` carries a position, so there is no "no window" case to
 * return and callers need no null branch.
 */
export function buildExcerptWindow(
  raw: string,
  index: number,
  length: number,
  radius: number = DEFAULT_RADIUS,
): ExcerptWindow {
  const start = Math.min(Math.max(index, 0), raw.length);
  const requested = length;

  // A lone CR counts as a line break here because `segmentNewline` splits on one
  // too; counting only LF would report the wrong line for a classic-Mac-style
  // paste. A CRLF pair advances the count once: the LF is what moves the line on.
  let lineStart = 0;
  let lineNumber = 1;
  for (let i = 0; i < start; i += 1) {
    const ch = raw.charAt(i);
    if (ch === '\n' || (ch === '\r' && raw.charAt(i + 1) !== '\n')) {
      lineStart = i + 1;
      lineNumber += 1;
    }
  }
  let lineEnd = raw.length;
  for (let i = start; i < raw.length; i += 1) {
    const ch = raw.charAt(i);
    if (ch === '\n' || ch === '\r') {
      lineEnd = i;
      break;
    }
  }

  // Never let the highlight cross the line break, and keep it at least one
  // character wide so an insertion point still shows a marker.
  const badEnd = Math.min(start + Math.max(requested, 1), lineEnd);
  const from = Math.max(lineStart, start - radius);
  const to = Math.min(lineEnd, badEnd + radius);

  return {
    before: raw.slice(from, start),
    bad: raw.slice(start, badEnd),
    after: raw.slice(badEnd, to),
    lineNumber,
    column: start - lineStart + 1,
    truncatedStart: from > lineStart,
    truncatedEnd: to < lineEnd,
  };
}

const ELLIPSIS_CLASS = 'text-[hsl(var(--muted-foreground))]';

/**
 * Render an excerpt window as a monospace strip with the offending run underlined.
 *
 * The run is highlighted in place rather than marked with a `^` caret on a second
 * line: a caret row needs exact monospace alignment, which breaks on a wrapped
 * line or a tab in the input, whereas a highlight cannot desynchronise from the
 * text it marks.
 *
 * The strip is `aria-hidden` on purpose. Read aloud it is character salad, and the
 * same information is delivered as prose in the sibling message (which names the
 * problem) plus the line and column. Leading and trailing spaces are preserved
 * (`whitespace-pre`) because a stray space is frequently the bug itself, and the
 * strip scrolls rather than wrapping so a long line cannot reflow the layout.
 *
 * It echoes nothing new: every character shown is already on screen in the
 * textarea above it.
 */
export function BackupCodeExcerpt({ excerpt }: { excerpt: ExcerptWindow }) {
  return (
    <p
      aria-hidden="true"
      className="mt-1.5 overflow-x-auto whitespace-pre rounded border border-[hsl(var(--border))] bg-[hsl(var(--background))] px-2 py-1.5 font-mono text-xs text-[hsl(var(--foreground))]"
    >
      {excerpt.truncatedStart && <span className={ELLIPSIS_CLASS}>{'…'}</span>}
      {excerpt.before}
      <span
        className={cn(
          'rounded-sm bg-[hsl(var(--destructive)/0.2)]',
          'underline decoration-[hsl(var(--destructive))] decoration-wavy underline-offset-2',
        )}
      >
        {excerpt.bad}
      </span>
      {excerpt.after}
      {excerpt.truncatedEnd && <span className={ELLIPSIS_CLASS}>{'…'}</span>}
    </p>
  );
}
