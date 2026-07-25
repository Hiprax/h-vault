import { describe, it, expect } from 'vitest';
import {
  BACKUP_CODES_FORMATS,
  BACKUP_CODES_INPUT_FORMATS,
  formatBackupCodes,
  isValidBackupCode,
  mergeBackupCodes,
  parseBackupCodes,
} from '../src/utils/backupCodes.js';
import type {
  BackupCodesFormat,
  BackupCodesInputFormat,
  BackupCodesIssue,
} from '../src/utils/backupCodes.js';

// ---------------------------------------------------------------------------
// Helpers
//
// Every fixture uses obviously fake codes. The parse helpers narrow the result
// union so each test asserts on `codes` or on `issue` without a non-null
// assertion.
// ---------------------------------------------------------------------------

function parse(input: string, format?: BackupCodesInputFormat) {
  return format === undefined ? parseBackupCodes(input) : parseBackupCodes(input, { format });
}

/** The parsed codes, failing the test if the parse was rejected. */
function codesOf(input: string, format?: BackupCodesInputFormat): string[] {
  const result = parse(input, format);
  if (!result.ok) {
    throw new Error(
      `expected a successful parse, got ${result.issue.code}: ${result.issue.message}`,
    );
  }
  return result.codes;
}

/** The primary issue, failing the test if the parse succeeded. */
function issueOf(input: string, format?: BackupCodesInputFormat): BackupCodesIssue {
  const result = parse(input, format);
  if (result.ok) throw new Error('expected a rejected parse');
  return result.issue;
}

function issuesOf(input: string, format?: BackupCodesInputFormat): readonly BackupCodesIssue[] {
  const result = parse(input, format);
  if (result.ok) throw new Error('expected a rejected parse');
  return result.issues;
}

// ---------------------------------------------------------------------------
// Format constants
// ---------------------------------------------------------------------------
describe('BACKUP_CODES_FORMATS', () => {
  it('lists the five input shapes in UI order', () => {
    expect(BACKUP_CODES_FORMATS).toEqual(['array', 'comma', 'space', 'newline', 'single']);
  });

  it('offers auto only as a caller-requested format, never as a resolved one', () => {
    expect(BACKUP_CODES_INPUT_FORMATS).toEqual([...BACKUP_CODES_FORMATS, 'auto']);
    expect(BACKUP_CODES_FORMATS).not.toContain('auto');
  });
});

// ---------------------------------------------------------------------------
// isValidBackupCode
// ---------------------------------------------------------------------------
describe('isValidBackupCode', () => {
  it.each([
    ['a Google-style eight-digit code', '12345678'],
    ['a GitHub-style hyphenated code', 'abcde-12345'],
    ['a 25-character recovery key', 'A1B2C3D4E5F6G7H8J9K0LMNPQ'],
    ['base64 with padding', 'dGVzdA=='],
    ['every permitted punctuation character', 'a_b.c+d/e='],
    ['a leading and trailing separator', '-abc-'],
    ['a single character', 'a'],
    ['a code at the length limit', 'a'.repeat(128)],
  ])('accepts %s', (_label, value) => {
    expect(isValidBackupCode(value)).toBe(true);
  });

  it.each([
    ['an empty string', ''],
    ['a space', 'a b'],
    ['a tab', 'a\tb'],
    ['a non-breaking space', 'a\u00a0b'],
    ['a comma', 'a,b'],
    ['brackets', '[a]'],
    ['a double quote', '"a"'],
    ['a single quote', "'a'"],
    ['a semicolon', 'a;b'],
    ['a backslash', 'a\\b'],
    ['only dashes', '---'],
    ['only dots', '...'],
    ['one character over the length limit', 'a'.repeat(129)],
    ['a non-ASCII letter', 'café'],
  ])('rejects %s', (_label, value) => {
    expect(isValidBackupCode(value)).toBe(false);
  });

  it('honours an explicit maxLength', () => {
    expect(isValidBackupCode('a'.repeat(129), 200)).toBe(true);
    expect(isValidBackupCode('abcd', 3)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// The eight worked examples from the feature request
//
// These are the acceptance criteria, so each is asserted on its error CODE and
// its caret POSITION, not merely on being rejected.
// ---------------------------------------------------------------------------
describe('the requested accept/reject examples', () => {
  it('accepts the array example', () => {
    expect(codesOf('["g8sd73h", "324324234","fsdfsdffd", "fds83da"]', 'array')).toEqual([
      'g8sd73h',
      '324324234',
      'fsdfsdffd',
      'fds83da',
    ]);
  });

  it('rejects an array whose first string is missing its closing quote', () => {
    const issue = issueOf('["fdsf3, "fsfd324"]', 'array');
    expect(issue.code).toBe('ARRAY_MISSING_QUOTE');
    expect(issue.itemNumber).toBe(1);
  });

  it('reports only the structural problem, not the comma the broken literal swallowed', () => {
    // The first literal decodes to `fdsf3, `, so per-item validation would report
    // "item 1 contains a comma" and bury the real diagnosis.
    expect(issuesOf('["fdsf3, "fsfd324"]', 'array')).toHaveLength(1);
  });

  it('rejects an array with no closing bracket, pointing at the end of the input', () => {
    const input = '["dsfsdf", "dfs3rg"';
    const issue = issueOf(input, 'array');
    expect(issue.code).toBe('ARRAY_UNCLOSED');
    expect(issue.index).toBe(input.length);
    expect(issue.length).toBe(0);
  });

  it('rejects an array with a missing comma between two strings', () => {
    const issue = issueOf('["gsfdd" "gfdg435"]', 'array');
    expect(issue.code).toBe('ARRAY_MISSING_COMMA');
    expect(issue.index).toBe('["gsfdd" '.length);
  });

  it('accepts the comma-separated example, spaces after commas and all', () => {
    expect(codesOf('sdf23dsfd,sd45hks, jdsfj23', 'comma')).toEqual([
      'sdf23dsfd',
      'sd45hks',
      'jdsfj23',
    ]);
  });

  it('rejects a comma-separated item that contains a space, pointing at the space', () => {
    const issue = issueOf('sdhjfkj hsdjfk, fdsf3', 'comma');
    expect(issue.code).toBe('CODE_CONTAINS_WHITESPACE');
    expect(issue.itemNumber).toBe(1);
    expect(issue.index).toBe(7);
    expect(issue.length).toBe(1);
  });

  it('rejects a trailing comma, pointing at the comma and saying to remove it', () => {
    const input = 'jfdsjkh, dhfsk,fdsf,';
    const issue = issueOf(input, 'comma');
    expect(issue.code).toBe('EMPTY_ITEM');
    expect(issue.itemNumber).toBe(4);
    expect(issue.index).toBe(input.length - 1);
    expect(issue.length).toBe(1);
    expect(issue.hint).toBe('Remove the trailing comma at the end.');
  });

  it('accepts the space-separated example and preserves case exactly', () => {
    expect(codesOf('fds32 JUFSD324 jfds32f', 'space')).toEqual(['fds32', 'JUFSD324', 'jfds32f']);
  });

  it('rejects a comma in space-separated input and points at the comma format', () => {
    const issue = issueOf('dsjfkkj,fdsffs', 'space');
    expect(issue.code).toBe('CODE_CONTAINS_COMMA');
    expect(issue.hint).toContain('comma-separated format');
  });

  it('rejects brackets in space-separated input and points at the array format', () => {
    // A bracket outranks the comma in the same item: telling the user to switch to
    // the array format is more actionable than naming the comma.
    const issue = issueOf('[dsfsdf,dsfsf]', 'space');
    expect(issue.code).toBe('CODE_CONTAINS_BRACKET');
    expect(issue.hint).toContain('array format');
  });

  it('rejects a bare dash used as a separator, because it is not a code', () => {
    const issue = issueOf('fsdjfsd - dsfhkjsdf', 'space');
    expect(issue.code).toBe('CODE_NO_ALPHANUMERIC');
    expect(issue.itemNumber).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// Empty input and the input-length ceiling
// ---------------------------------------------------------------------------
describe('parseBackupCodes empty and oversized input', () => {
  it.each(['', '   ', '\n\n', '\t \r\n'])(
    'treats whitespace-only input (%j) as "no codes", not as invalid',
    (input) => {
      const result = parse(input);
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.codes).toEqual([]);
        expect(result.format).toBe('single');
        expect(result.detected).toBe(true);
      }
    },
  );

  it('reports the requested format for empty input when one was given explicitly', () => {
    const result = parse('', 'array');
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.format).toBe('array');
      expect(result.detected).toBe(false);
    }
  });

  it('rejects input past the raw-length ceiling at the ceiling, as an insertion point', () => {
    const issue = issueOf('a'.repeat(20_001));
    expect(issue.code).toBe('INPUT_TOO_LONG');
    expect(issue.index).toBe(20_000);
    expect(issue.length).toBe(0);
  });

  it('does not blame the raw-length ceiling for input exactly at it', () => {
    // 20,000 identical characters is one absurdly long code, so it is still
    // rejected, but for its length as a CODE rather than as an input.
    expect(issueOf('a'.repeat(20_000)).code).toBe('CODE_TOO_LONG');
  });

  it('honours an explicit maxInputLength', () => {
    // The same input is fine under the default ceiling and rejected under a
    // tighter one, so the option is genuinely read rather than the default reused.
    expect(parse('abcdef', 'single').ok).toBe(true);
    const scoped = parseBackupCodes('abcdef', { format: 'single', maxInputLength: 3 });
    expect(scoped.ok).toBe(false);
    if (!scoped.ok) {
      expect(scoped.issue.code).toBe('INPUT_TOO_LONG');
      expect(scoped.issue.index).toBe(3);
    }
  });
});

// ---------------------------------------------------------------------------
// Code-count and code-length caps
// ---------------------------------------------------------------------------
describe('parseBackupCodes caps', () => {
  const fifty = Array.from({ length: 50 }, (_, i) => `code${i}`);

  it('accepts exactly fifty codes', () => {
    expect(codesOf(fifty.join('\n'), 'newline')).toHaveLength(50);
  });

  it('rejects the fifty-first code and names it', () => {
    const issue = issueOf([...fifty, 'extra'].join('\n'), 'newline');
    expect(issue.code).toBe('TOO_MANY_CODES');
    expect(issue.itemNumber).toBe(51);
  });

  it('honours an explicit max', () => {
    const result = parseBackupCodes('a,b,c', { format: 'comma', max: 2 });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.issue.code).toBe('TOO_MANY_CODES');
      expect(result.issue.itemNumber).toBe(3);
    }
  });

  it('honours the cap under the single format too, so it means the same everywhere', () => {
    const result = parseBackupCodes('abc', { format: 'single', max: 0 });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.issue.code).toBe('TOO_MANY_CODES');
  });

  it.each<BackupCodesFormat>(['comma', 'space', 'newline'])(
    'enforces the cap under the %s format too',
    (format) => {
      const separator = format === 'comma' ? ',' : format === 'space' ? ' ' : '\n';
      const input = Array.from({ length: 51 }, (_, i) => `c${i}`).join(separator);
      const result = parseBackupCodes(input, { format });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.issue.code).toBe('TOO_MANY_CODES');
    },
  );

  it('accepts a code at the length limit and rejects one character more', () => {
    expect(codesOf('a'.repeat(128), 'single')).toEqual(['a'.repeat(128)]);
    expect(issueOf('a'.repeat(129), 'single').code).toBe('CODE_TOO_LONG');
  });

  it('honours an explicit maxCodeLength', () => {
    const result = parseBackupCodes('aaaaa', { format: 'single', maxCodeLength: 4 });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.issue.code).toBe('CODE_TOO_LONG');
  });

  it('calls the item "The code" under the single format, not "Item 1"', () => {
    expect(issueOf('a'.repeat(129), 'single').message).toMatch(/^The code/);
  });
});

// ---------------------------------------------------------------------------
// The newline format
// ---------------------------------------------------------------------------
describe('parseBackupCodes newline format', () => {
  it.each([
    ['LF', 'a1\nb2'],
    ['CRLF', 'a1\r\nb2'],
    ['a lone CR', 'a1\rb2'],
  ])('splits on %s', (_label, input) => {
    expect(codesOf(input, 'newline')).toEqual(['a1', 'b2']);
  });

  it('drops a trailing blank line rather than rejecting it', () => {
    // Every editor and every provider page ends with one; an invisible character
    // must never be a rejection.
    expect(codesOf('a1\nb2\n', 'newline')).toEqual(['a1', 'b2']);
  });

  it('drops blank interior lines', () => {
    expect(codesOf('a1\n\n\nb2', 'newline')).toEqual(['a1', 'b2']);
  });

  it('trims each line', () => {
    expect(codesOf('  a1  \n  b2  ', 'newline')).toEqual(['a1', 'b2']);
  });

  it('accepts a single line', () => {
    expect(codesOf('a1', 'newline')).toEqual(['a1']);
  });

  it('rejects a line holding two codes and numbers the line', () => {
    const issue = issueOf('a1\nb2 c3', 'newline');
    expect(issue.code).toBe('CODE_CONTAINS_WHITESPACE');
    expect(issue.itemNumber).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// The comma format
// ---------------------------------------------------------------------------
describe('parseBackupCodes comma format', () => {
  it('accepts a single item', () => {
    expect(codesOf('a1', 'comma')).toEqual(['a1']);
  });

  it('accepts items with no spaces', () => {
    expect(codesOf('a1,b2', 'comma')).toEqual(['a1', 'b2']);
  });

  it('rejects a leading comma at offset zero, and does not claim there are two', () => {
    const issue = issueOf(',a', 'comma');
    expect(issue.code).toBe('EMPTY_ITEM');
    expect(issue.itemNumber).toBe(1);
    expect(issue.index).toBe(0);
    expect(issue.hint).toBe('The list starts with a comma. Remove it, or put a code before it.');
  });

  it('reports both the leading and the trailing comma of a lone comma, leftmost first', () => {
    const issues = issuesOf(',', 'comma');
    expect(issues).toHaveLength(2);
    expect(issues[0]?.index).toBe(0);
    expect(issues[0]?.hint).toContain('starts with a comma');
    expect(issues[1]?.hint).toBe('Remove the trailing comma at the end.');
  });

  it('rejects two commas in a row and explains which comma to remove', () => {
    const issue = issueOf('a,,b', 'comma');
    expect(issue.code).toBe('EMPTY_ITEM');
    expect(issue.itemNumber).toBe(2);
    expect(issue.hint).toContain('two commas in a row');
  });

  it('rejects a segment that is only whitespace', () => {
    expect(issueOf('a, ,b', 'comma').code).toBe('EMPTY_ITEM');
  });

  it('reports the structural problem alone when items are also invalid', () => {
    // An empty segment changes what the items are, so per-item advice would
    // misdirect. Exactly one issue, and it is the structural one.
    const issues = issuesOf('a b,,c', 'comma');
    expect(issues).toHaveLength(1);
    expect(issues[0]?.code).toBe('EMPTY_ITEM');
  });
});

// ---------------------------------------------------------------------------
// The space format
// ---------------------------------------------------------------------------
describe('parseBackupCodes space format', () => {
  it('collapses runs of spaces', () => {
    expect(codesOf('a1    b2', 'space')).toEqual(['a1', 'b2']);
  });

  it('splits on tabs and newlines too, so a mixed-whitespace paste still works', () => {
    expect(codesOf('a1\tb2\nc3', 'space')).toEqual(['a1', 'b2', 'c3']);
  });

  it('splits on a non-breaking space, so a paste out of a document still works', () => {
    expect(codesOf('a1\u00a0b2', 'space')).toEqual(['a1', 'b2']);
  });

  it('accepts a single token', () => {
    expect(codesOf('a1', 'space')).toEqual(['a1']);
  });

  it('tells the user to delete a comma that only trails one item', () => {
    const issue = issueOf('abc, def', 'space');
    expect(issue.code).toBe('CODE_CONTAINS_COMMA');
    expect(issue.hint).toContain('Remove the comma at the end');
  });
});

// ---------------------------------------------------------------------------
// Per-item classification
// ---------------------------------------------------------------------------
describe('parseBackupCodes per-item classification', () => {
  it('names a semicolon rather than describing it vaguely', () => {
    const issue = issueOf('a;b', 'space');
    expect(issue.code).toBe('CODE_INVALID_CHAR');
    expect(issue.message).toContain('a semicolon (;)');
  });

  it('offers the semicolon-list escape route when a semicolon only trails an item', () => {
    // A semicolon-delimited list is the common near-miss; when the semicolon is at
    // the end of an item, saying "swap them for commas" is more useful than the
    // generic character complaint.
    const issue = issueOf('abc;', 'single');
    expect(issue.code).toBe('CODE_INVALID_CHAR');
    expect(issue.hint).toContain('replace your semicolons with commas');
  });

  it('describes an unnameable character generically and never echoes it', () => {
    const issue = issueOf('café', 'single');
    expect(issue.code).toBe('CODE_INVALID_CHAR');
    expect(issue.message).toContain('a character that is not allowed');
    expect(issue.message).not.toContain('é');
  });

  it('distinguishes an invisible character from an invalid one', () => {
    const issue = issueOf('a\u200bb', 'single');
    expect(issue.code).toBe('CODE_INVISIBLE_CHAR');
    expect(issue.hint).toContain('hidden characters');
  });

  it('recognises a non-breaking space as a paste artefact', () => {
    const issue = issueOf('a\u00a0b', 'single');
    expect(issue.code).toBe('CODE_CONTAINS_WHITESPACE');
    expect(issue.hint).toContain('non-breaking space');
  });

  it('calls a line break a line break, and points at the per-line format', () => {
    // Telling someone to delete an invisible pasted character when what they
    // actually have is a newline sends them looking for the wrong thing.
    const issue = issueOf('a\nb', 'comma');
    expect(issue.code).toBe('CODE_CONTAINS_WHITESPACE');
    expect(issue.message).toContain('line break');
    expect(issue.message).not.toContain('contains a space');
    expect(issue.hint).toContain('one-code-per-line format');
  });

  it('points an ordinary space at the space-separated format', () => {
    const issue = issueOf('a1\nb2 c3', 'newline');
    expect(issue.code).toBe('CODE_CONTAINS_WHITESPACE');
    expect(issue.hint).toContain('space-separated format');
  });

  it('rejects a quote character and points at the array format', () => {
    const issue = issueOf('a"b', 'single');
    expect(issue.code).toBe('CODE_CONTAINS_QUOTE');
    expect(issue.hint).toContain('array format');
  });

  it('rejects a token with no letters or digits', () => {
    const issue = issueOf('---', 'single');
    expect(issue.code).toBe('CODE_NO_ALPHANUMERIC');
    expect(issue.hint).toContain('leftover dash');
  });
});

// ---------------------------------------------------------------------------
// The array format: valid inputs
// ---------------------------------------------------------------------------
describe('parseBackupCodes array format, accepted inputs', () => {
  it('accepts an empty list as "no codes"', () => {
    expect(codesOf('[]', 'array')).toEqual([]);
  });

  it.each([
    ['single quotes', "['a1','b2']", ['a1', 'b2']],
    ['backticks', '[`a1`]', ['a1']],
    ['mixed quote kinds', `["a1", 'b2', \`c3\`]`, ['a1', 'b2', 'c3']],
    ['a trailing comma, which JavaScript allows', '["a1",]', ['a1']],
    ['newlines and indentation', '[\n  "a1",\n  "b2"\n]', ['a1', 'b2']],
    ['surrounding whitespace', '  ["a1"]  ', ['a1']],
    ['a byte-order mark before the bracket', '\ufeff["a1"]', ['a1']],
  ])('accepts %s', (_label, input, expected) => {
    expect(codesOf(input, 'array')).toEqual(expected);
  });

  it('accepts a list at the code limit', () => {
    const fifty = Array.from({ length: 50 }, (_, i) => `"c${i}"`).join(',');
    expect(codesOf(`[${fifty}]`, 'array')).toHaveLength(50);
  });
});

// ---------------------------------------------------------------------------
// The array format: escape decoding
// ---------------------------------------------------------------------------
describe('parseBackupCodes array format, escape decoding', () => {
  it.each([
    ['an identity escape, as JavaScript itself decodes it', '["a\\-b"]', 'a-b'],
    ['an unrecognised identity escape', '["\\q"]', 'q'],
    ['a two-digit hex escape', '["a\\x41b"]', 'aAb'],
    ['a four-digit unicode escape', '["\\u0041BC"]', 'ABC'],
    ['a braced code-point escape', '["a\\u{42}c"]', 'aBc'],
    ['a line continuation', '["a\\\nb"]', 'ab'],
    ['a CRLF line continuation', '["a\\\r\nb"]', 'ab'],
    ['a bare carriage-return line continuation', '["a\\\rb"]', 'ab'],
  ])('decodes %s', (_label, input, expected) => {
    expect(codesOf(input, 'array')).toEqual([expected]);
  });

  it.each([
    ['a decoded backslash', '["a\\\\b"]', 'CODE_INVALID_CHAR'],
    ['a decoded quote', '["a\\"b"]', 'CODE_CONTAINS_QUOTE'],
    ['a decoded newline', '["\\n"]', 'CODE_CONTAINS_WHITESPACE'],
    ['a decoded NUL', '["\\0"]', 'CODE_INVISIBLE_CHAR'],
    ['a raw line separator inside double quotes', '["a\u2028b"]', 'CODE_CONTAINS_WHITESPACE'],
  ])('decodes then rejects %s', (_label, input, code) => {
    expect(issueOf(input, 'array').code).toBe(code);
  });

  it.each([
    ['an incomplete \\x escape', '["\\x4"]', '\\x escape'],
    ['a non-hex \\x escape', '["\\xZZ"]', '\\x escape'],
    ['an incomplete \\u escape', '["\\u12"]', '\\u escape'],
    ['an empty braced escape', '["\\u{}"]', '\\u escape'],
    ['an unclosed braced escape', '["\\u{12"]', '\\u escape'],
    ['a code point above the maximum', '["\\u{110000}"]', '10FFFF'],
  ])('rejects %s', (_label, input, fragment) => {
    const issue = issueOf(input, 'array');
    expect(issue.code).toBe('ARRAY_BAD_ESCAPE');
    expect(issue.message).toContain(fragment);
  });

  it.each(['["\\1"]', '["\\012"]', '["\\08"]', '["\\9"]'])(
    'rejects the legacy octal escape in %s, which strict-mode JavaScript also rejects',
    (input) => {
      const issue = issueOf(input, 'array');
      expect(issue.code).toBe('ARRAY_BAD_ESCAPE');
      expect(issue.message).toContain('followed by a digit');
    },
  );

  it.each([
    ['a tab escape', '["a\\tb"]', 'CODE_CONTAINS_WHITESPACE'],
    ['a carriage-return escape', '["a\\rb"]', 'CODE_CONTAINS_WHITESPACE'],
    ['a form-feed escape', '["a\\fb"]', 'CODE_CONTAINS_WHITESPACE'],
    ['a vertical-tab escape', '["a\\vb"]', 'CODE_CONTAINS_WHITESPACE'],
    ['a backspace escape', '["a\\bb"]', 'CODE_INVISIBLE_CHAR'],
  ])('decodes %s and then rejects what it produced', (_label, input, code) => {
    // Asserting the whitespace/invisible code (rather than CODE_INVALID_CHAR, which
    // is what an UNdecoded backslash would produce) is what proves the decoder ran.
    expect(issueOf(input, 'array').code).toBe(code);
  });

  it('rejects a backslash at the end of the input', () => {
    expect(issueOf('["a\\', 'array').code).toBe('ARRAY_UNTERMINATED_STRING');
  });
});

// ---------------------------------------------------------------------------
// The array format: syntax errors
// ---------------------------------------------------------------------------
describe('parseBackupCodes array format, syntax errors', () => {
  it('rejects text after a completed string that is neither a comma nor a bracket', () => {
    expect(issueOf('["a"x]', 'array').code).toBe('ARRAY_UNEXPECTED_CHAR');
  });

  it.each(['["a",', '['])('reports %j as an unclosed list', (input) => {
    const issue = issueOf(input, 'array');
    expect(issue.code).toBe('ARRAY_UNCLOSED');
    expect(issue.length).toBe(0);
  });

  it('reports a missing opening bracket as an insertion point', () => {
    const issue = issueOf('abc', 'array');
    expect(issue.code).toBe('ARRAY_MISSING_OPEN');
    expect(issue.length).toBe(0);
  });

  it('rejects text after the closing bracket', () => {
    const input = '["a"] junk';
    const issue = issueOf(input, 'array');
    expect(issue.code).toBe('ARRAY_TRAILING_CONTENT');
    // The caret lands on the junk itself, not on the whitespace before it.
    expect(issue.index).toBe(input.indexOf('junk'));
    expect(issue.length).toBe('junk'.length);
  });

  it.each([
    ['a leading comma', '[,"a"]', 1],
    ['an array hole', '["a",,"b"]', 2],
  ])('rejects %s as an empty element', (_label, input, itemNumber) => {
    const issue = issueOf(input, 'array');
    expect(issue.code).toBe('ARRAY_EMPTY_ELEMENT');
    expect(issue.itemNumber).toBe(itemNumber);
  });

  it.each(['[123]', '[true]', '[null]'])(
    'rejects the unquoted value in %s rather than coercing it',
    (input) => {
      // Accepting a bare number would silently corrupt a long numeric code:
      // String(123456789012345678901) is 123456789012345680000.
      expect(issueOf(input, 'array').code).toBe('ARRAY_UNQUOTED_VALUE');
    },
  );

  it('underlines exactly the unquoted token', () => {
    const issue = issueOf('[123]', 'array');
    expect(issue.index).toBe(1);
    expect(issue.length).toBe(3);
  });

  it('rejects a nested list', () => {
    expect(issueOf('[["a"]]', 'array').code).toBe('ARRAY_NESTED_ARRAY');
  });

  it('rejects an object element', () => {
    expect(issueOf('[{"a":1}]', 'array').code).toBe('ARRAY_OBJECT_ELEMENT');
  });

  it('rejects a template literal containing a substitution', () => {
    const issue = issueOf('[`a${b}c`]', 'array');
    expect(issue.code).toBe('ARRAY_TEMPLATE_SUBSTITUTION');
    expect(issue.length).toBe(2);
  });

  it('reports a literal that simply runs out of input as unterminated, not as unclosed', () => {
    const issue = issueOf('["abc', 'array');
    expect(issue.code).toBe('ARRAY_UNTERMINATED_STRING');
    expect(issue.itemNumber).toBe(1);
  });

  it('enforces the code cap inside a list too', () => {
    const fiftyOne = Array.from({ length: 51 }, (_, i) => `"c${i}"`).join(',');
    const issue = issueOf(`[${fiftyOne}]`, 'array');
    expect(issue.code).toBe('TOO_MANY_CODES');
    expect(issue.itemNumber).toBe(51);
  });

  it('rejects a quoted code split across two lines, and says so', () => {
    const issue = issueOf('["a\nb"]', 'array');
    expect(issue.code).toBe('ARRAY_UNTERMINATED_STRING');
    expect(issue.hint).toContain('across two lines');
  });

  it('reports every invalid item, primary first, spanning the whole literal', () => {
    // Escape decoding breaks the mapping from a decoded offset back to the source,
    // so an array item reports its whole literal, quotes included.
    const issues = issuesOf('["a b", "c d"]', 'array');
    expect(issues).toHaveLength(2);
    expect(issues[0]?.itemNumber).toBe(1);
    expect(issues[1]?.itemNumber).toBe(2);
    expect(issues[0]?.index).toBe(1);
    expect(issues[0]?.length).toBe(5);
  });
});

// ---------------------------------------------------------------------------
// auto resolution
// ---------------------------------------------------------------------------
describe('parseBackupCodes auto resolution', () => {
  it.each<[string, BackupCodesFormat, boolean]>([
    ['["a1","b2"]', 'array', true],
    ['[bad', 'array', false],
    ['a1\nb2', 'newline', true],
    ['a1 b2\nc3 d4', 'space', true],
    ['a1,b2', 'comma', true],
    ['dsjfkkj,fdsffs', 'comma', true],
    ['a1 b2', 'space', true],
    ['a1', 'single', true],
    ['jfdsjkh, dhfsk,fdsf,', 'comma', false],
    ['sdhjfkj hsdjfk, fdsf3', 'comma', false],
    ['a,b\nc,d', 'newline', false],
    ['a1\u00a0b2', 'space', true],
  ])('reads %j as %s (accepted: %s)', (input, format, ok) => {
    const result = parse(input);
    expect(result.format).toBe(format);
    expect(result.ok).toBe(ok);
    expect(result.detected).toBe(true);
  });

  it.each<[string, BackupCodesFormat]>([
    ['a,b\nc d', 'newline'],
    ['a1,b2', 'comma'],
    ['a1 b2', 'space'],
    ['a1', 'single'],
  ])('picks a first candidate for %j from the delimiters present', (input, format) => {
    expect(parse(input).format).toBe(format);
  });

  it('falls through to a later candidate when the first one fails', () => {
    // A grid of space-separated codes on several lines fails `newline` (each line
    // holds two codes) and succeeds under `space`.
    const result = parse('a1 b2\nc3 d4');
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.codes).toEqual(['a1', 'b2', 'c3', 'd4']);
  });

  it('returns the failure of the most likely candidate when every candidate fails', () => {
    const issue = issueOf('jfdsjkh, dhfsk,fdsf,');
    expect(issue.code).toBe('EMPTY_ITEM');
  });

  it('commits to the array format on a leading bracket instead of guessing', () => {
    // `[` is not in the code character set, so no real code can start with one.
    // Committing means the user gets an array-specific diagnosis rather than the
    // comma-format complaint the delimiter heuristic would otherwise produce.
    const result = parse('[dsfsdf,dsfsf');
    expect(result.format).toBe('array');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.issue.code).toBe('ARRAY_UNQUOTED_VALUE');
  });

  it('marks an explicitly requested format as not detected', () => {
    const result = parse('a1 b2', 'space');
    expect(result.detected).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Secrecy of error messages
// ---------------------------------------------------------------------------
describe('parseBackupCodes never leaks code text', () => {
  // An error string can reach a log, a toast or a crash report, so it may name a
  // punctuation character but never any of the code itself. Every ERROR FAMILY is
  // exercised — per-item, array-syntax and escape — because a leak introduced into
  // any one message would otherwise slip past a single-shape guard.
  it.each<[string, BackupCodesInputFormat]>([
    ['S3CRET-CODE-XYZ,', 'single'],
    ['S3CRET CODE', 'comma'],
    ['S3CRET;CODE', 'space'],
    ['S3CRETCODE​X', 'single'],
    ['[S3CRET,CODE]', 'space'],
    ['---', 'single'],
    ['S3CRETCODE'.repeat(40), 'single'],
    ['["S3CRET, "CODEXYZ"]', 'array'],
    ['["S3CRETCODE" "OTHERCODE"]', 'array'],
    ['["S3CRETCODE", "OTHERCODE"', 'array'],
    ['[S3CRETCODE]', 'array'],
    ['["S3CRET\\1CODE"]', 'array'],
    ['["S3CRET\\u12CODE"]', 'array'],
    ['[`S3CRET${x}CODE`]', 'array'],
    ['["S3CRETCODE"] TRAILING', 'array'],
    ['S3CRET,,CODE', 'comma'],
  ])('keeps every part of %j out of the message and the hint', (secret, format) => {
    const leaked: string[] = [];
    for (const issue of issuesOf(secret, format)) {
      const text = `${issue.message} ${issue.hint ?? ''}`;
      for (let i = 0; i + 3 <= secret.length; i += 1) {
        const fragment = secret.slice(i, i + 3);
        if (/^[A-Za-z0-9]{3}$/.test(fragment) && text.includes(fragment)) leaked.push(fragment);
      }
    }
    expect(leaked).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Order and case preservation
// ---------------------------------------------------------------------------
describe('parseBackupCodes preserves the input verbatim', () => {
  it('keeps order and case exactly, and never sorts', () => {
    expect(codesOf('ZzAa-1 aAzZ-2', 'space')).toEqual(['ZzAa-1', 'aAzZ-2']);
  });

  it('keeps two codes that differ only in case', () => {
    // Codes are case-sensitive at some providers, so folding case could destroy a
    // distinct code.
    expect(codesOf('ABCD-1\nabcd-1', 'newline')).toHaveLength(2);
  });

  it('does not de-duplicate; mergeBackupCodes owns that so it can report counts', () => {
    expect(codesOf('a1,a1', 'comma')).toEqual(['a1', 'a1']);
  });
});

// ---------------------------------------------------------------------------
// mergeBackupCodes
// ---------------------------------------------------------------------------
describe('mergeBackupCodes', () => {
  it('appends to an empty list', () => {
    expect(mergeBackupCodes([], ['a', 'b'])).toEqual({
      codes: ['a', 'b'],
      addedCount: 2,
      duplicateCount: 0,
      overflowCount: 0,
    });
  });

  it('drops a code that already exists', () => {
    const result = mergeBackupCodes(['a'], ['a', 'b']);
    expect(result.codes).toEqual(['a', 'b']);
    expect(result.addedCount).toBe(1);
    expect(result.duplicateCount).toBe(1);
  });

  it('drops a repeat inside the incoming list, keeping the first', () => {
    const result = mergeBackupCodes([], ['a', 'a']);
    expect(result.codes).toEqual(['a']);
    expect(result.duplicateCount).toBe(1);
  });

  it('treats codes differing only in case as distinct', () => {
    expect(mergeBackupCodes([], ['A', 'a']).addedCount).toBe(2);
  });

  it('preserves order: existing first, then incoming in order', () => {
    expect(mergeBackupCodes(['x'], ['y', 'z']).codes).toEqual(['x', 'y', 'z']);
  });

  it('reports what did not fit once the cap is reached', () => {
    const existing = Array.from({ length: 49 }, (_, i) => `e${i}`);
    const result = mergeBackupCodes(existing, ['x', 'y', 'z']);
    expect(result.addedCount).toBe(1);
    expect(result.overflowCount).toBe(2);
    expect(result.codes).toHaveLength(50);
  });

  it('returns an over-cap existing list untouched instead of truncating it', () => {
    // The stored schema is permissive, so `existing` can legitimately hold values
    // this module would reject; rewriting it would be data loss.
    const existing = Array.from({ length: 60 }, (_, i) => `o${i}`);
    const result = mergeBackupCodes(existing, ['n1']);
    expect(result.codes).toEqual(existing);
    expect(result.overflowCount).toBe(1);
  });

  it('leaves duplicates already inside the existing list alone and uncounted', () => {
    const result = mergeBackupCodes(['d', 'd'], ['q']);
    expect(result.codes).toEqual(['d', 'd', 'q']);
    expect(result.duplicateCount).toBe(0);
  });

  it('counts a duplicate as a duplicate even when the list is full', () => {
    const result = mergeBackupCodes(['a', 'b'], ['a'], 2);
    expect(result.duplicateCount).toBe(1);
    expect(result.overflowCount).toBe(0);
  });

  it('honours an explicit max', () => {
    const result = mergeBackupCodes(['a'], ['b', 'c'], 2);
    expect(result.addedCount).toBe(1);
    expect(result.overflowCount).toBe(1);
  });

  it('never returns the array it was given', () => {
    const existing = ['a'];
    expect(mergeBackupCodes(existing, []).codes).not.toBe(existing);
  });

  it.each([
    [[], ['a', 'a', 'b']],
    [['a'], ['a', 'b', 'c']],
    [Array.from({ length: 50 }, (_, i) => `f${i}`), ['x', 'y']],
  ])('accounts for every incoming code exactly once (%#)', (existing, incoming) => {
    const result = mergeBackupCodes(existing, incoming);
    expect(result.addedCount + result.duplicateCount + result.overflowCount).toBe(incoming.length);
  });
});

// ---------------------------------------------------------------------------
// formatBackupCodes
// ---------------------------------------------------------------------------
describe('formatBackupCodes', () => {
  const sample = ['a1', 'B2-c3', 'd_4.e+f/g='];

  it('defaults to one code per line', () => {
    expect(formatBackupCodes(sample)).toBe('a1\nB2-c3\nd_4.e+f/g=');
  });

  it.each<[BackupCodesFormat, string]>([
    ['comma', 'a1, B2-c3, d_4.e+f/g='],
    ['space', 'a1 B2-c3 d_4.e+f/g='],
    ['array', '["a1", "B2-c3", "d_4.e+f/g="]'],
    ['newline', 'a1\nB2-c3\nd_4.e+f/g='],
    ['single', 'a1\nB2-c3\nd_4.e+f/g='],
  ])('renders the %s format', (format, expected) => {
    expect(formatBackupCodes(sample, format)).toBe(expected);
  });

  it('renders a single code plainly under the single format', () => {
    expect(formatBackupCodes(['a1'], 'single')).toBe('a1');
  });

  it.each(BACKUP_CODES_FORMATS)('renders an empty list as an empty string for %s', (format) => {
    expect(formatBackupCodes([], format)).toBe('');
  });

  it.each<BackupCodesFormat>(['array', 'comma', 'space', 'newline'])(
    'round-trips through the %s format',
    (format) => {
      const result = parseBackupCodes(formatBackupCodes(sample, format), { format });
      expect(result.ok).toBe(true);
      if (result.ok) expect(result.codes).toEqual(sample);
    },
  );
});
