/**
 * `parseBackupCodes`' DIAGNOSTICS: the message, the position, and the hint.
 *
 * Chosen by the mutation oracle. `backupCodes.ts` is the largest module in the
 * shared package and it carried 210 of the 400 surviving mutants — the highest
 * concentration in the repository — and the reason is a mismatch between what
 * the module is FOR and what `backupCodes.test.ts` asserts. That file proves the
 * parser extracts the right codes and refuses the right inputs, which is the
 * easy half. The hard half is why the module is 1,200 lines instead of twenty:
 * when a user pastes something the parser cannot read, it tells them WHICH
 * character, WHERE, and WHAT TO DO. None of that was asserted, so every
 * message, every hint and every position could be replaced with anything —
 * including nothing — and the suite stayed green.
 *
 * What each block below pins:
 *
 *  - THE NAMED CHARACTER. `PUNCTUATION_NAMES` maps 18 characters to a phrase, so
 *    a message can point at a character without echoing code text back at the
 *    user. Both halves of every entry survived mutation: emptying the KEY makes
 *    the lookup miss (the message degrades to the anonymous form), and emptying
 *    the VALUE produces a sentence with a hole in it. One row per entry, driven
 *    through the real parser.
 *  - THE ESCAPE SEQUENCES. `\xNN` and `\u{…}` are decoded by hand, and the
 *    branches that reject a truncated, empty, non-hex or above-range escape are
 *    reachable only from inputs no existing test wrote.
 *  - THE POSITION. `index` and `length` are what a UI underlines. The arithmetic
 *    that produces them (`brk + 2` for a CRLF, `close + 1 - backslash` for a
 *    braced escape) is invisible to any assertion that only checks the code.
 *  - THE HINT. Three hints are CONDITIONAL, and the condition is the whole
 *    point: the semicolon hint fires only for a trailing semicolon, and the
 *    format hints only when the input looks like a different format. A hint that
 *    always fires is noise, and a mutant that made one always fire changed no
 *    test.
 */
import { describe, it, expect } from 'vitest';
import {
  parseBackupCodes,
  type BackupCodesInputFormat,
  type BackupCodesIssue,
} from '../src/utils/backupCodes.js';

/** The issues of a run that must NOT have succeeded. */
const failureOf = (input: string, format?: BackupCodesInputFormat): readonly BackupCodesIssue[] => {
  const result = parseBackupCodes(input, format === undefined ? undefined : { format });
  expect(result.ok, `expected ${JSON.stringify(input)} to be refused`).toBe(false);
  return result.ok ? [] : result.issues;
};

/** The codes of a run that must have succeeded. */
const codesOf = (input: string, format?: BackupCodesInputFormat): string[] => {
  const result = parseBackupCodes(input, format === undefined ? undefined : { format });
  expect(result.ok, `expected ${JSON.stringify(input)} to parse`).toBe(true);
  return result.ok ? result.codes : [];
};

const SUFFIX = 'Backup codes may only contain letters, digits and - _ . + / =.';

describe('an invalid character is NAMED, not echoed', () => {
  /**
   * Every entry of `PUNCTUATION_NAMES`, driven from the outside. The character
   * is placed in the MIDDLE so the trailing-semicolon hint cannot fire and
   * change the message under test.
   */
  it.each([
    [';', 'a semicolon (;)'],
    [':', 'a colon (:)'],
    ['|', 'a vertical bar (|)'],
    ['\\', 'a backslash (\\)'],
    ['(', 'a parenthesis'],
    [')', 'a parenthesis'],
    ['<', 'an angle bracket'],
    ['>', 'an angle bracket'],
    ['@', 'an at sign (@)'],
    ['#', 'a number sign (#)'],
    ['$', 'a dollar sign ($)'],
    ['%', 'a percent sign (%)'],
    ['^', 'a caret (^)'],
    ['&', 'an ampersand (&)'],
    ['*', 'an asterisk (*)'],
    ['!', 'an exclamation mark (!)'],
    ['?', 'a question mark (?)'],
    ['~', 'a tilde (~)'],
  ])('names %s', (char, phrase) => {
    const [issue] = failureOf(`ab${char}cd`, 'single');
    expect(issue?.code).toBe('CODE_INVALID_CHAR');
    expect(issue?.message).toBe(`The code contains ${phrase}. ${SUFFIX}`);
    // The offending character is pointed AT, not merely reported: `index` is
    // where a UI puts the caret, and every one of these is at offset 2.
    expect(issue?.index).toBe(2);
    expect(issue?.length).toBe(1);
    // And the character itself is never echoed back into the sentence — the
    // reason this map exists at all.
    expect(issue?.message.includes(`"${char}"`)).toBe(false);
  });

  it('falls back to an anonymous phrase for a character it has no name for', () => {
    // The other arm of the same ternary: a character outside the map must still
    // be refused, and the sentence must still read.
    const [issue] = failureOf('ab§cd', 'single');
    expect(issue?.code).toBe('CODE_INVALID_CHAR');
    expect(issue?.message).toBe(`The code contains a character that is not allowed. ${SUFFIX}`);
  });
});

describe('a trailing semicolon gets a hint, an interior one does not', () => {
  it('offers the comma-format remedy only at the end of the value', () => {
    const [trailing] = failureOf('abcd;', 'single');
    expect(trailing?.hint).toBe(
      'Remove the semicolon at the end of the code, or replace your semicolons with commas ' +
        'and choose the comma-separated format.',
    );
    // Interior: the same character, the same code, and deliberately NO hint —
    // "delete the last character" is wrong advice for `ab;cd`.
    const [interior] = failureOf('ab;cd', 'single');
    expect(interior?.code).toBe('CODE_INVALID_CHAR');
    expect(interior?.hint).toBeUndefined();
  });

  it('names the format a stray separator suggests, and only that format', () => {
    const [comma] = failureOf('aaa,bbb', 'single');
    expect(comma?.code).toBe('CODE_CONTAINS_COMMA');
    expect(comma?.hint).toBe(
      'If your codes are separated by commas, choose the comma-separated format.',
    );
    const [space] = failureOf('aaa bbb', 'single');
    expect(space?.code).toBe('CODE_CONTAINS_WHITESPACE');
    expect(space?.hint).toBe(
      'If your codes are separated by spaces, choose the space-separated format.',
    );
    // A non-breaking space is a paste artefact rather than a format signal, so
    // it gets the OTHER hint. Two conditions, two different remedies.
    const [nbsp] = failureOf('aaa bbb', 'newline');
    expect(nbsp?.hint).toBe(
      'That looks like a non-breaking space left behind by copy and paste. Delete it.',
    );
  });
});

describe('escape sequences inside a quoted array item', () => {
  it('decodes the escapes it supports', () => {
    expect(codesOf('["ab\\x41cd"]', 'array')).toEqual(['abAcd']);
    expect(codesOf('["ab\\u0041cd"]', 'array')).toEqual(['abAcd']);
    expect(codesOf('["ab\\u{41}cd"]', 'array')).toEqual(['abAcd']);
  });

  it.each([
    [
      'a truncated \\x',
      '["ab\\x4"]',
      'Item 1 has an incomplete \\x escape. It needs exactly two hex digits, like \\x41.',
      4,
      4,
    ],
    [
      'an empty \\u{}',
      '["ab\\u{}"]',
      'Item 1 has an incomplete \\u escape. It needs four hex digits (\\u0041) or braces (\\u{1F600}).',
      4,
      2,
    ],
    [
      'a non-hex \\u{ZZ}',
      '["ab\\u{ZZ}"]',
      'Item 1 has an incomplete \\u escape. It needs four hex digits (\\u0041) or braces (\\u{1F600}).',
      4,
      2,
    ],
    [
      'a code point above the maximum',
      '["ab\\u{110000}"]',
      'Item 1 has a \\u{ } escape above the largest code point (10FFFF).',
      4,
      10,
    ],
  ])('refuses %s, pointing at it', (_case, input, message, index, length) => {
    const [issue] = failureOf(input, 'array');
    expect(issue?.code).toBe('ARRAY_BAD_ESCAPE');
    expect(issue?.message).toBe(message);
    // The span, not just the offset: `length` is what gets underlined, and the
    // arithmetic behind it (`close + 1 - backslash` for the braced form) is
    // otherwise unasserted.
    expect(issue?.index).toBe(index);
    expect(issue?.length).toBe(length);
    expect(issue?.itemNumber).toBe(1);
  });

  it('refuses a template substitution rather than silently expanding it', () => {
    const [issue] = failureOf('[`ab${x}cd`]', 'array');
    expect(issue?.code).toBe('ARRAY_TEMPLATE_SUBSTITUTION');
    expect(issue?.message).toBe(
      'Item 1 uses a backtick template with a substitution in it, which is not supported. ' +
        'Use plain quotes.',
    );
    expect(issue?.index).toBe(4);
    expect(issue?.length).toBe(2);
  });

  it('decodes an escape whose result is itself an invalid character, and says so', () => {
    // The escape is well-formed, so the escape reader accepts it; the character
    // it produces is then refused by the code validator. Two different rules,
    // and the second one has to win — otherwise `\u{1F600}` is a way to smuggle
    // an emoji into a backup code.
    const [issue] = failureOf('["ab\\u{1F600}"]', 'array');
    expect(issue?.code).toBe('CODE_INVALID_CHAR');
    expect(issue?.message).toBe(`Item 1 contains a character that is not allowed. ${SUFFIX}`);
  });
});

describe('line breaks are counted the way a text editor counts them', () => {
  it('treats CRLF, CR and LF as one separator each', () => {
    expect(codesOf('aaa\r\nbbb', 'newline')).toEqual(['aaa', 'bbb']);
    expect(codesOf('aaa\rbbb', 'newline')).toEqual(['aaa', 'bbb']);
    expect(codesOf('aaa\nbbb', 'newline')).toEqual(['aaa', 'bbb']);
    // The CRLF case is the one that carries arithmetic: advancing by 1 instead
    // of 2 leaves a stray `\n` at the head of the next item, which would then be
    // reported as whitespace inside a code.
    expect(codesOf('aaa\r\nbbb\r\nccc', 'newline')).toEqual(['aaa', 'bbb', 'ccc']);
  });

  it('reports a position that survives a CRLF, so the caret lands on the right line', () => {
    const [issue] = failureOf('aaa\r\nb!b', 'newline');
    expect(issue?.code).toBe('CODE_INVALID_CHAR');
    expect(issue?.itemNumber).toBe(2);
    // 'aaa' + CRLF + 'b' — six characters, which only holds if the CRLF counted
    // as two.
    expect(issue?.index).toBe(6);
  });

  it('treats a backslash before ANY line break as a continuation, producing nothing', () => {
    // JavaScript's line-continuation rule, which is why a list copied out of a
    // wrapped source file still parses. All five terminators are separate
    // branches in `readEscape`, and the two Unicode ones (U+2028, U+2029) arrive
    // from PDFs and word processors — exactly where a printed sheet of backup
    // codes comes from. Written as escapes rather than as literal characters on
    // purpose: as literals they are invisible in a diff, and a review could not
    // tell them from the space they would degrade into.
    expect(codesOf('["aa\\\nbb"]', 'array')).toEqual(['aabb']);
    expect(codesOf('["aa\\\r\nbb"]', 'array')).toEqual(['aabb']);
    expect(codesOf('["aa\\\rbb"]', 'array')).toEqual(['aabb']);
    expect(codesOf('["aa\\\u2028bb"]', 'array')).toEqual(['aabb']);
    expect(codesOf('["aa\\\u2029bb"]', 'array')).toEqual(['aabb']);
  });

  it('drops an unknown escape to its own character, but refuses a legacy octal', () => {
    // `\q` is `q` in a JavaScript string, so a paste containing one is not an
    // error. `\101` is a SyntaxError under strict mode — the mode any module a
    // user copies a list out of actually runs under — so it is refused rather
    // than silently decoded to 'A'.
    expect(codesOf('["aa\\q"]', 'array')).toEqual(['aaq']);
    const [issue] = failureOf('["aa\\101"]', 'array');
    expect(issue?.code).toBe('ARRAY_BAD_ESCAPE');
    expect(issue?.message).toContain('backslash followed by a digit');
  });

  it('reports a line break inside a quoted item as an unterminated string', () => {
    const [issue] = failureOf('["aaa\nbbb"]', 'array');
    expect(issue?.code).toBe('ARRAY_UNTERMINATED_STRING');
    expect(issue?.message).toBe('Item 1 is missing its closing quote before the end of the line.');
    expect(issue?.index).toBe(1);
    expect(issue?.length).toBe(4);
  });
});

describe('auto-detection reports the format it settled on', () => {
  it('falls back to the single-code format and says the choice was automatic', () => {
    const result = parseBackupCodes('!!!', { format: 'auto' });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.format).toBe('single');
    expect(result.detected).toBe(true);
    // An explicitly requested format is NOT auto-detected, and the flag is what
    // a caller uses to decide whether to offer a format picker.
    const explicit = parseBackupCodes('!!!', { format: 'single' });
    expect(explicit.ok).toBe(false);
    if (explicit.ok) return;
    expect(explicit.format).toBe('single');
    expect(explicit.detected).toBe(false);
  });
});
