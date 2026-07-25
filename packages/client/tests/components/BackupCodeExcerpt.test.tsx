/**
 * `buildExcerptWindow` is the only genuinely tricky pure logic behind the
 * backup-code error display: it clamps a reported position, scopes the window to a
 * single line, and decides which end was truncated. It is tested directly rather
 * than through the editor so each branch has a named case.
 */
import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/react';
import {
  BackupCodeExcerpt,
  buildExcerptWindow,
} from '../../src/components/vault/BackupCodeExcerpt';

describe('buildExcerptWindow', () => {
  it('windows a long line around the offending run and flags both truncations', () => {
    const excerpt = buildExcerptWindow('a'.repeat(200), 100, 1);
    expect(excerpt.before).toHaveLength(24);
    expect(excerpt.after).toHaveLength(24);
    expect(excerpt.truncatedStart).toBe(true);
    expect(excerpt.truncatedEnd).toBe(true);
  });

  it('flags neither end when the whole line fits in the window', () => {
    const excerpt = buildExcerptWindow('abc', 1, 1);
    expect(excerpt.before).toBe('a');
    expect(excerpt.bad).toBe('b');
    expect(excerpt.after).toBe('c');
    expect(excerpt.truncatedStart).toBe(false);
    expect(excerpt.truncatedEnd).toBe(false);
  });

  it('scopes the window to the offending line and reports a 1-based line and column', () => {
    // Index 7 is the `*` on the second line of 'AAAA\nBB*B\nCCCC'.
    const excerpt = buildExcerptWindow('AAAA\nBB*B\nCCCC', 7, 1);
    expect(excerpt.lineNumber).toBe(2);
    expect(excerpt.column).toBe(3);
    expect(excerpt.before).toBe('BB');
    expect(excerpt.bad).toBe('*');
    // Never crosses the newline, so it can never appear to point at another line.
    expect(excerpt.after).toBe('B');
  });

  it('clamps a run that overshoots the end of its line', () => {
    const excerpt = buildExcerptWindow('AB\nCD', 1, 50);
    expect(excerpt.bad).toBe('B');
    expect(excerpt.after).toBe('');
  });

  it('clamps an index past the end of the input instead of throwing', () => {
    const excerpt = buildExcerptWindow('AB\nCD', 9999, 1);
    expect(excerpt.lineNumber).toBe(2);
    expect(excerpt.bad).toBe('');
  });

  it('still highlights one character for an insertion point reported with length 0', () => {
    // A missing closing bracket has nothing to underline, so the marker borrows the
    // next character rather than collapsing to nothing.
    expect(buildExcerptWindow('["a"', 1, 0).bad).toBe('"');
  });

  it('reports column 1 for a problem at the start of a line', () => {
    const excerpt = buildExcerptWindow(',a', 0, 1);
    expect(excerpt.column).toBe(1);
    expect(excerpt.lineNumber).toBe(1);
    expect(excerpt.before).toBe('');
  });

  it('counts a lone carriage return as a line break, as the parser does', () => {
    // `segmentNewline` splits on a bare CR, so counting only LF would report the
    // wrong line for a classic-Mac-style paste.
    const excerpt = buildExcerptWindow('AAAA\rBB*B', 7, 1);
    expect(excerpt.lineNumber).toBe(2);
    expect(excerpt.column).toBe(3);
    expect(excerpt.bad).toBe('*');
  });

  it('counts a CRLF pair once', () => {
    const excerpt = buildExcerptWindow('AAAA\r\nBB*B', 8, 1);
    expect(excerpt.lineNumber).toBe(2);
    expect(excerpt.column).toBe(3);
  });

  it('stops the window at a carriage return, not just at a newline', () => {
    const excerpt = buildExcerptWindow('AB\rCD', 1, 50);
    expect(excerpt.bad).toBe('B');
    expect(excerpt.after).toBe('');
  });

  it('honours a custom radius', () => {
    const excerpt = buildExcerptWindow('a'.repeat(200), 100, 1, 2);
    expect(excerpt.before).toHaveLength(2);
    expect(excerpt.after).toHaveLength(2);
  });
});

describe('BackupCodeExcerpt', () => {
  it('renders the offending run inside a block hidden from assistive technology', () => {
    const { container } = render(
      <BackupCodeExcerpt excerpt={buildExcerptWindow('AAAA\nBB*B', 7, 1)} />,
    );
    const block = container.querySelector('[aria-hidden="true"]');
    // Read aloud this is character salad; the sibling message carries the meaning.
    expect(block).not.toBeNull();
    expect(block?.textContent).toBe('BB*B');
  });

  it('marks a truncated window with dimmed ellipses at both ends', () => {
    const { container } = render(
      <BackupCodeExcerpt excerpt={buildExcerptWindow('a'.repeat(200), 100, 1)} />,
    );
    const text = container.textContent ?? '';
    expect(text.startsWith('…')).toBe(true);
    expect(text.endsWith('…')).toBe(true);
  });
});
