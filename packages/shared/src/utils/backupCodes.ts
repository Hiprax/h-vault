/**
 * Backup-code input parsing for login items.
 *
 * A login's `backupCodes` are stored as a plain `string[]`, and the STORED schema
 * (`loginDataSchema`) caps lengths only: it runs on every decrypt, and a failure
 * there degrades the entire item to the read-only "could not be fully decoded"
 * notice, taking UI access to the item's password with it. All format strictness
 * therefore lives HERE, at input time, where a rejection costs the user a fixable
 * error message instead of access to a working account.
 *
 * Five input formats are supported, each validated exactly, plus `auto`.
 * Everything in this module is pure and dependency-free (three numeric caps
 * aside), so the vault form and the CSV importer share one definition of what a
 * backup code is.
 *
 * The array format is hand-tokenized. `eval` and `new Function` are never used —
 * they are remote-code-execution vectors and the production CSP has no
 * `unsafe-eval` — and neither is `JSON.parse`, which rejects the single quotes
 * JavaScript accepts and whose messages are engine-specific prose we cannot show
 * a user. `JSON.stringify` IS used, but only in `formatBackupCodes`: encoding is
 * not the attack surface, parsing is.
 *
 * Nothing in this file ever puts code text into an error message. A backup code
 * is a secret and an error string can reach a log, a toast or a crash report, so
 * problems are reported with a structural position (`index`/`length`) that the UI
 * turns into a caret over the input the user is already looking at. Naming a
 * single PUNCTUATION character is allowed — a comma is not a secret.
 */
import {
  MAX_LOGIN_BACKUP_CODES,
  MAX_LOGIN_BACKUP_CODE_LENGTH,
  MAX_LOGIN_BACKUP_CODES_INPUT_LENGTH,
} from '../constants/index.js';

/* -------------------------------------------------------------------------- */
/*  Formats                                                                   */
/* -------------------------------------------------------------------------- */

/**
 * The five input shapes, in the order the UI offers them.
 *
 * - `array` — a JS/JSON array-of-strings literal: `["a1b2", "c3d4"]`
 * - `comma` — `a1b2, c3d4`
 * - `space` — `a1b2 c3d4`; splits on ANY whitespace run
 * - `newline` — one code per line
 * - `single` — the whole input is one code
 */
export const BACKUP_CODES_FORMATS = ['array', 'comma', 'space', 'newline', 'single'] as const;
export type BackupCodesFormat = (typeof BACKUP_CODES_FORMATS)[number];

/** A format a caller may ask for. `auto` infers one; see {@link parseBackupCodes}. */
export const BACKUP_CODES_INPUT_FORMATS = [...BACKUP_CODES_FORMATS, 'auto'] as const;
export type BackupCodesInputFormat = (typeof BACKUP_CODES_INPUT_FORMATS)[number];

/* -------------------------------------------------------------------------- */
/*  Issues                                                                    */
/* -------------------------------------------------------------------------- */

/** Every way an input can be rejected, grouped input / per-item / array-syntax. */
export const BACKUP_CODES_ERROR_CODES = [
  'INPUT_TOO_LONG',
  'TOO_MANY_CODES',
  'EMPTY_ITEM',
  'CODE_CONTAINS_WHITESPACE',
  'CODE_INVISIBLE_CHAR',
  'CODE_CONTAINS_BRACKET',
  'CODE_CONTAINS_COMMA',
  'CODE_CONTAINS_QUOTE',
  'CODE_INVALID_CHAR',
  'CODE_NO_ALPHANUMERIC',
  'CODE_TOO_LONG',
  'ARRAY_MISSING_OPEN',
  'ARRAY_UNCLOSED',
  'ARRAY_MISSING_COMMA',
  'ARRAY_MISSING_QUOTE',
  'ARRAY_UNEXPECTED_CHAR',
  'ARRAY_UNTERMINATED_STRING',
  'ARRAY_EMPTY_ELEMENT',
  'ARRAY_UNQUOTED_VALUE',
  'ARRAY_NESTED_ARRAY',
  'ARRAY_OBJECT_ELEMENT',
  'ARRAY_TEMPLATE_SUBSTITUTION',
  'ARRAY_BAD_ESCAPE',
  'ARRAY_TRAILING_CONTENT',
] as const;
export type BackupCodesErrorCode = (typeof BACKUP_CODES_ERROR_CODES)[number];

/**
 * One problem, positioned in the ORIGINAL input.
 *
 * `message` and `hint` never contain any part of a code (see the module header).
 */
export interface BackupCodesIssue {
  readonly code: BackupCodesErrorCode;
  /** One or two plain sentences. Safe to render verbatim. */
  readonly message: string;
  /** Optional next action, e.g. "Remove the trailing comma at the end." */
  readonly hint?: string;
  /** 0-based offset into the original input where the problem starts. */
  readonly index: number;
  /**
   * Length of the offending span. `0` marks an INSERTION point — something is
   * missing at `index`, such as a closing `]`. `>= 1` marks offending text.
   */
  readonly length: number;
  /** 1-based item number, when the problem belongs to one item. */
  readonly itemNumber?: number;
}

/**
 * The outcome of a parse, discriminated on `ok`.
 *
 * On failure `issue` is the primary (left-most) problem and is always present, so
 * the UI never narrows an array index; `issues` holds every problem found, `issue`
 * first, ordered by `index`.
 */
export type BackupCodesParseResult =
  | {
      readonly ok: true;
      /** In input order, trimmed, case untouched, NOT de-duplicated. */
      readonly codes: string[];
      /** The format whose rules were applied. */
      readonly format: BackupCodesFormat;
      /** True when the caller asked for `auto`, so `format` was inferred. */
      readonly detected: boolean;
    }
  | {
      readonly ok: false;
      readonly format: BackupCodesFormat;
      readonly detected: boolean;
      readonly issue: BackupCodesIssue;
      readonly issues: readonly BackupCodesIssue[];
    };

export interface ParseBackupCodesOptions {
  /** Declared input format. Default `'auto'`. */
  readonly format?: BackupCodesInputFormat;
  /** Maximum codes one input may carry. Default {@link MAX_LOGIN_BACKUP_CODES}. */
  readonly max?: number;
  /** Maximum length of one code. Default {@link MAX_LOGIN_BACKUP_CODE_LENGTH}. */
  readonly maxCodeLength?: number;
  /**
   * Maximum raw input length. Default
   * {@link MAX_LOGIN_BACKUP_CODES_INPUT_LENGTH}.
   */
  readonly maxInputLength?: number;
}

interface Limits {
  readonly max: number;
  readonly maxCodeLength: number;
  readonly maxInputLength: number;
}

/* -------------------------------------------------------------------------- */
/*  Character rules                                                           */
/* -------------------------------------------------------------------------- */

/**
 * The non-alphanumeric characters a backup code may contain.
 *
 * Held as a string rather than baked into a character class so that a single
 * character can be tested directly (which is what produces an exact caret
 * position) and so the set reads unambiguously with no regex escaping.
 */
const CODE_PUNCTUATION = '-_.+/=';

const ALPHANUMERIC = /[A-Za-z0-9]/;
const WHITESPACE = /\s/;

/**
 * Characters that are invisible but are NOT matched by `\s`, so `trim()` leaves
 * them behind: C0 and C1 controls, the soft hyphen, the zero-width and
 * directional marks, and the word joiner. A paste out of a PDF or a web page
 * routinely carries one, and it would otherwise be reported as a mysterious
 * "invalid character" the user cannot see.
 */
const INVISIBLE = /[\u0000-\u0008\u000e-\u001f\u007f-\u009f\u00ad\u200b-\u200f\u2060]/;

const BRACKETS = '[]{}';
const QUOTES = '"\'`';

/** Named so a message can point at a character without echoing code text. */
const PUNCTUATION_NAMES = new Map<string, string>([
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
]);

const FORMAT_SWITCH_HINT: Record<BackupCodesFormat, string> = {
  array: 'If your codes are in a list like ["code1", "code2"], choose the array format.',
  comma: 'If your codes are separated by commas, choose the comma-separated format.',
  space: 'If your codes are separated by spaces, choose the space-separated format.',
  newline: 'If each code is on its own line, choose the one-code-per-line format.',
  single: 'If you have only one code, choose the single-code format.',
};

/**
 * Is `value` a well-formed backup code? The single source of truth for every
 * format.
 *
 * A whitespace-free token of `A-Z a-z 0-9 - _ . + / =`, containing at least one
 * letter or digit, 1..`maxLength` characters. Wide enough for every real shape
 * (Google's 8 digits, GitHub's `abcde-12345`, a 25-char Microsoft recovery key,
 * base64 and base64url with `=` padding) and narrow enough to reject exactly the
 * characters that signal a FORMAT mistake: whitespace, commas, brackets, quotes,
 * backslashes.
 *
 * There is deliberately NO rule against a leading or trailing separator.
 * Wrongly rejecting a real code costs the user their account recovery; accepting
 * `-abc-` costs nothing.
 */
export function isValidBackupCode(
  value: string,
  maxLength: number = MAX_LOGIN_BACKUP_CODE_LENGTH,
): boolean {
  if (value.length === 0 || value.length > maxLength) return false;
  let hasAlphanumeric = false;
  for (const ch of value) {
    if (ALPHANUMERIC.test(ch)) {
      hasAlphanumeric = true;
      continue;
    }
    if (!CODE_PUNCTUATION.includes(ch)) return false;
  }
  return hasAlphanumeric;
}

/* -------------------------------------------------------------------------- */
/*  Issue construction                                                        */
/* -------------------------------------------------------------------------- */

function makeIssue(
  code: BackupCodesErrorCode,
  message: string,
  index: number,
  length: number,
  extra: { readonly itemNumber?: number; readonly hint?: string } = {},
): BackupCodesIssue {
  return { code, message, index, length, ...extra };
}

/** "Item 3" for a multi-item format; "The code" when there can only be one. */
function itemLabel(format: BackupCodesFormat, itemNumber: number): string {
  return format === 'single' ? 'The code' : `Item ${itemNumber}`;
}

/* -------------------------------------------------------------------------- */
/*  Segmentation                                                              */
/* -------------------------------------------------------------------------- */

interface ParsedItem {
  readonly value: string;
  /** Offset in the ORIGINAL input. */
  readonly start: number;
  /** Span in the ORIGINAL input. */
  readonly length: number;
  /**
   * False for `array`, where escape decoding breaks the mapping between an
   * offset in the decoded value and an offset in the source, so a per-character
   * caret would point at the wrong place. Such items report the whole literal.
   */
  readonly spanExact: boolean;
  /** 1-based. */
  readonly itemNumber: number;
}

interface Segmentation {
  readonly items: readonly ParsedItem[];
  /** Non-empty means the parse fails and per-item validation is skipped. */
  readonly issues: readonly BackupCodesIssue[];
}

function tooManyCodesIssue(item: ParsedItem, max: number): BackupCodesIssue {
  return makeIssue(
    'TOO_MANY_CODES',
    `You can store at most ${max} backup codes on one login. Item ${max + 1} and anything after it must be removed.`,
    item.start,
    item.length,
    { itemNumber: max + 1 },
  );
}

function segmentSingle(input: string, max: number): Segmentation {
  const start = input.length - input.trimStart().length;
  const value = input.trim();
  const item: ParsedItem = { value, start, length: value.length, spanExact: true, itemNumber: 1 };
  // `max` is honoured here as it is in every other format, so the cap means the same
  // thing whichever way the input was written.
  if (max < 1) return { items: [], issues: [tooManyCodesIssue(item, max)] };
  return { items: [item], issues: [] };
}

/** Index of the next line terminator at or after `from`, or -1. */
function nextLineBreak(input: string, from: number): number {
  for (let i = from; i < input.length; i += 1) {
    const ch = input.charAt(i);
    if (ch === '\n' || ch === '\r') return i;
  }
  return -1;
}

function segmentNewline(input: string, max: number): Segmentation {
  const items: ParsedItem[] = [];
  let pos = 0;
  for (;;) {
    const brk = nextLineBreak(input, pos);
    const end = brk === -1 ? input.length : brk;
    const raw = input.slice(pos, end);
    const lead = raw.length - raw.trimStart().length;
    const value = raw.trim();
    // Blank lines are dropped, not rejected: every editor and every provider page
    // ends with one, and an invisible character must never be a rejection.
    if (value.length > 0) {
      const item: ParsedItem = {
        value,
        start: pos + lead,
        length: value.length,
        spanExact: true,
        itemNumber: items.length + 1,
      };
      if (items.length >= max) return { items, issues: [tooManyCodesIssue(item, max)] };
      items.push(item);
    }
    if (brk === -1) return { items, issues: [] };
    pos = input.charAt(brk) === '\r' && input.charAt(brk + 1) === '\n' ? brk + 2 : brk + 1;
  }
}

function segmentComma(input: string, max: number): Segmentation {
  const items: ParsedItem[] = [];
  const issues: BackupCodesIssue[] = [];
  const trailingComma = input.trimEnd().endsWith(',');
  let pos = 0;
  let itemNumber = 0;
  for (;;) {
    const comma = input.indexOf(',', pos);
    const end = comma === -1 ? input.length : comma;
    const raw = input.slice(pos, end);
    const lead = raw.length - raw.trimStart().length;
    const value = raw.trim();
    itemNumber += 1;
    if (value.length === 0) {
      // Unlike a blank line, an empty segment is REJECTED: a stray comma is a real
      // syntax mistake, and unlike a newline it is visible, so the caret points at
      // something the user can see and delete. The caret goes on the comma
      // adjacent to the empty item.
      const commaIndex = itemNumber === 1 ? end : pos - 1;
      const isTrailing = trailingComma && comma === -1;
      let hint =
        'There are two commas in a row. Remove the extra one, or put the missing code between them.';
      if (isTrailing) {
        hint = 'Remove the trailing comma at the end.';
      } else if (itemNumber === 1) {
        // There is only ONE comma here, at the very start, so the two-in-a-row
        // wording would be plainly wrong.
        hint = 'The list starts with a comma. Remove it, or put a code before it.';
      }
      issues.push(
        makeIssue('EMPTY_ITEM', `Item ${itemNumber} is empty.`, commaIndex, 1, {
          itemNumber,
          hint,
        }),
      );
    } else {
      const item: ParsedItem = {
        value,
        start: pos + lead,
        length: value.length,
        spanExact: true,
        itemNumber,
      };
      if (items.length >= max) {
        issues.push(tooManyCodesIssue(item, max));
        return { items, issues };
      }
      items.push(item);
    }
    if (comma === -1) return { items, issues };
    pos = comma + 1;
  }
}

function segmentSpace(input: string, max: number): Segmentation {
  const items: ParsedItem[] = [];
  let pos = 0;
  while (pos < input.length) {
    if (WHITESPACE.test(input.charAt(pos))) {
      pos += 1;
      continue;
    }
    let end = pos;
    while (end < input.length && !WHITESPACE.test(input.charAt(end))) end += 1;
    const item: ParsedItem = {
      value: input.slice(pos, end),
      start: pos,
      length: end - pos,
      spanExact: true,
      itemNumber: items.length + 1,
    };
    if (items.length >= max) return { items, issues: [tooManyCodesIssue(item, max)] };
    items.push(item);
    pos = end;
  }
  return { items, issues: [] };
}

/* -------------------------------------------------------------------------- */
/*  Array literal tokenizer                                                   */
/* -------------------------------------------------------------------------- */

const HEX = /^[0-9a-fA-F]+$/;
const DIGIT = /^[0-9]$/;

const BAD_ESCAPE_HINT = 'Backup codes do not need escapes. Remove the backslash.';

interface LiteralOk {
  readonly ok: true;
  readonly value: string;
  /** Index just past the closing quote. */
  readonly end: number;
}
interface LiteralFailed {
  readonly ok: false;
  readonly issue: BackupCodesIssue;
}

function unterminated(
  start: number,
  end: number,
  itemNumber: number,
  atLineBreak: boolean,
): LiteralFailed {
  return {
    ok: false,
    issue: makeIssue(
      'ARRAY_UNTERMINATED_STRING',
      atLineBreak
        ? `Item ${itemNumber} is missing its closing quote before the end of the line.`
        : `Item ${itemNumber} is missing its closing quote.`,
      start,
      Math.max(1, end - start),
      {
        itemNumber,
        hint: atLineBreak
          ? 'A quoted code cannot be split across two lines. Add the closing quote at the end of the line.'
          : `Add a quote at the end of item ${itemNumber}, then close the list with ] .`,
      },
    ),
  };
}

function badEscape(
  message: string,
  index: number,
  length: number,
  itemNumber: number,
  hint?: string,
): LiteralFailed {
  return {
    ok: false,
    issue: makeIssue('ARRAY_BAD_ESCAPE', message, index, length, {
      itemNumber,
      ...(hint === undefined ? {} : { hint }),
    }),
  };
}

/**
 * Decode one escape sequence starting at the backslash.
 *
 * Follows JavaScript, including the identity fallback for an unrecognized escape
 * (`\q` really is `q`) and line continuations. Legacy octal escapes are the one
 * deliberate divergence: they are rejected rather than decoded, because they are
 * SyntaxErrors in strict mode — which is what any modern module a user might
 * copy a list out of actually runs under — and no backup code contains one.
 */
function readEscape(
  src: string,
  backslash: number,
  itemNumber: number,
): { readonly ok: true; readonly text: string; readonly next: number } | LiteralFailed {
  const ch = src.charAt(backslash + 1);
  if (ch === '') {
    return unterminated(backslash, src.length, itemNumber, false);
  }
  // Line continuation: produces nothing. CRLF consumes both units.
  if (ch === '\n' || ch === '\u2028' || ch === '\u2029') {
    return { ok: true, text: '', next: backslash + 2 };
  }
  if (ch === '\r') {
    return {
      ok: true,
      text: '',
      next: src.charAt(backslash + 2) === '\n' ? backslash + 3 : backslash + 2,
    };
  }
  if (ch === 'n') return { ok: true, text: '\n', next: backslash + 2 };
  if (ch === 't') return { ok: true, text: '\t', next: backslash + 2 };
  if (ch === 'r') return { ok: true, text: '\r', next: backslash + 2 };
  if (ch === 'b') return { ok: true, text: '\b', next: backslash + 2 };
  if (ch === 'f') return { ok: true, text: '\f', next: backslash + 2 };
  if (ch === 'v') return { ok: true, text: '\v', next: backslash + 2 };
  if (ch === '0' && !DIGIT.test(src.charAt(backslash + 2))) {
    return { ok: true, text: '\u0000', next: backslash + 2 };
  }
  if (DIGIT.test(ch)) {
    return badEscape(
      `Item ${itemNumber} contains a backslash followed by a digit, which is not a valid escape.`,
      backslash,
      2,
      itemNumber,
      BAD_ESCAPE_HINT,
    );
  }
  if (ch === 'x') {
    const digits = src.slice(backslash + 2, backslash + 4);
    if (digits.length < 2 || !HEX.test(digits)) {
      return badEscape(
        `Item ${itemNumber} has an incomplete \\x escape. It needs exactly two hex digits, like \\x41.`,
        backslash,
        2 + digits.length,
        itemNumber,
      );
    }
    return { ok: true, text: String.fromCharCode(parseInt(digits, 16)), next: backslash + 4 };
  }
  if (ch === 'u') {
    if (src.charAt(backslash + 2) === '{') {
      const close = src.indexOf('}', backslash + 3);
      const digits = close === -1 ? '' : src.slice(backslash + 3, close);
      if (close === -1 || digits.length === 0 || digits.length > 6 || !HEX.test(digits)) {
        return badEscape(
          `Item ${itemNumber} has an incomplete \\u escape. It needs four hex digits (\\u0041) or braces (\\u{1F600}).`,
          backslash,
          2,
          itemNumber,
        );
      }
      const point = parseInt(digits, 16);
      if (point > 0x10ffff) {
        return badEscape(
          `Item ${itemNumber} has a \\u{ } escape above the largest code point (10FFFF).`,
          backslash,
          close + 1 - backslash,
          itemNumber,
        );
      }
      return { ok: true, text: String.fromCodePoint(point), next: close + 1 };
    }
    const digits = src.slice(backslash + 2, backslash + 6);
    if (digits.length < 4 || !HEX.test(digits)) {
      return badEscape(
        `Item ${itemNumber} has an incomplete \\u escape. It needs four hex digits (\\u0041) or braces (\\u{1F600}).`,
        backslash,
        2 + digits.length,
        itemNumber,
      );
    }
    return { ok: true, text: String.fromCharCode(parseInt(digits, 16)), next: backslash + 6 };
  }
  // Identity escape — what JavaScript itself does for any other character.
  return { ok: true, text: ch, next: backslash + 2 };
}

function readStringLiteral(
  src: string,
  start: number,
  itemNumber: number,
): LiteralOk | LiteralFailed {
  const quote = src.charAt(start);
  const isTemplate = quote === '`';
  let out = '';
  let i = start + 1;
  for (;;) {
    const ch = src.charAt(i);
    if (ch === '') return unterminated(start, src.length, itemNumber, false);
    if (ch === quote) return { ok: true, value: out, end: i + 1 };
    if (ch === '\\') {
      const esc = readEscape(src, i, itemNumber);
      if (!esc.ok) return esc;
      out += esc.text;
      i = esc.next;
      continue;
    }
    if (!isTemplate && (ch === '\n' || ch === '\r')) {
      return unterminated(start, i, itemNumber, true);
    }
    if (isTemplate && ch === '$' && src.charAt(i + 1) === '{') {
      return {
        ok: false,
        issue: makeIssue(
          'ARRAY_TEMPLATE_SUBSTITUTION',
          `Item ${itemNumber} uses a backtick template with a substitution in it, which is not supported. Use plain quotes.`,
          i,
          2,
          { itemNumber },
        ),
      };
    }
    out += ch;
    i += 1;
  }
}

/** Length of the bare token at `pos`: up to the next `,`, `]`, whitespace or EOF. */
function bareTokenLength(src: string, pos: number): number {
  let end = pos;
  while (end < src.length) {
    const ch = src.charAt(end);
    if (ch === ',' || ch === ']' || WHITESPACE.test(ch)) break;
    end += 1;
  }
  return Math.max(1, end - pos);
}

function skipWhitespace(src: string, from: number): number {
  let i = from;
  while (i < src.length && WHITESPACE.test(src.charAt(i))) i += 1;
  return i;
}

function segmentArray(input: string, max: number): Segmentation {
  const items: ParsedItem[] = [];
  let pos = skipWhitespace(input, 0);
  if (input.charAt(pos) !== '[') {
    return {
      items,
      issues: [
        makeIssue(
          'ARRAY_MISSING_OPEN',
          'A list must start with [ , like ["code1", "code2"].',
          pos,
          0,
          { hint: 'If your codes are not in a list, choose a different format.' },
        ),
      ],
    };
  }
  pos += 1;
  let expectElement = true;
  let previousHeldSeparator = false;
  for (;;) {
    pos = skipWhitespace(input, pos);
    const ch = input.charAt(pos);
    if (ch === '') {
      return {
        items,
        issues: [
          makeIssue(
            'ARRAY_UNCLOSED',
            'The list is missing its closing ] . Add ] at the end.',
            input.length,
            0,
          ),
        ],
      };
    }
    if (ch === ']') {
      pos += 1;
      break;
    }
    if (!expectElement) {
      if (ch === ',') {
        pos += 1;
        expectElement = true;
        continue;
      }
      const n = items.length;
      if (QUOTES.includes(ch)) {
        return {
          items,
          issues: [
            makeIssue(
              'ARRAY_MISSING_COMMA',
              `Items ${n} and ${n + 1} are not separated. Put a comma (,) between them.`,
              pos,
              1,
              { itemNumber: n },
            ),
          ],
        };
      }
      if (previousHeldSeparator) {
        return {
          items,
          issues: [
            makeIssue(
              'ARRAY_MISSING_QUOTE',
              `Item ${n} is missing its closing quote, so the text after it was read as part of item ${n}.`,
              pos,
              1,
              { itemNumber: n, hint: `Add the missing quote at the end of item ${n}.` },
            ),
          ],
        };
      }
      return {
        items,
        issues: [
          makeIssue(
            'ARRAY_UNEXPECTED_CHAR',
            `Unexpected text after item ${n}. Items must be separated by a comma (,) and the list must end with ] .`,
            pos,
            1,
            { itemNumber: n },
          ),
        ],
      };
    }
    const itemNumber = items.length + 1;
    if (ch === ',') {
      return {
        items,
        issues: [
          makeIssue(
            'ARRAY_EMPTY_ELEMENT',
            `Item ${itemNumber} is empty (two commas in a row).`,
            pos,
            1,
            { itemNumber, hint: 'Remove the extra comma.' },
          ),
        ],
      };
    }
    if (ch === '[') {
      return {
        items,
        issues: [
          makeIssue(
            'ARRAY_NESTED_ARRAY',
            `Item ${itemNumber} is a list inside the list. Use one flat list of quoted codes.`,
            pos,
            1,
            { itemNumber },
          ),
        ],
      };
    }
    if (ch === '{') {
      return {
        items,
        issues: [
          makeIssue(
            'ARRAY_OBJECT_ELEMENT',
            `Item ${itemNumber} is an object. Use one flat list of quoted codes.`,
            pos,
            1,
            { itemNumber },
          ),
        ],
      };
    }
    if (!QUOTES.includes(ch)) {
      return {
        items,
        issues: [
          makeIssue(
            'ARRAY_UNQUOTED_VALUE',
            `Item ${itemNumber} is not wrapped in quotes. Every code must be quoted, like "a1b2c3".`,
            pos,
            bareTokenLength(input, pos),
            {
              itemNumber,
              hint: 'Values such as 123 or true are not accepted. Put quotes around the value.',
            },
          ),
        ],
      };
    }
    const literal = readStringLiteral(input, pos, itemNumber);
    if (!literal.ok) return { items, issues: [literal.issue] };
    const item: ParsedItem = {
      value: literal.value,
      start: pos,
      length: literal.end - pos,
      spanExact: false,
      itemNumber,
    };
    if (items.length >= max) return { items, issues: [tooManyCodesIssue(item, max)] };
    items.push(item);
    previousHeldSeparator = literal.value.includes(',') || WHITESPACE.test(literal.value);
    pos = literal.end;
    expectElement = false;
  }
  pos = skipWhitespace(input, pos);
  if (pos < input.length) {
    return {
      items,
      issues: [
        makeIssue(
          'ARRAY_TRAILING_CONTENT',
          'There is extra text after the closing ] . Remove anything after ] .',
          pos,
          input.length - pos,
        ),
      ],
    };
  }
  return { items, issues: [] };
}

function segment(input: string, format: BackupCodesFormat, limits: Limits): Segmentation {
  switch (format) {
    case 'array':
      return segmentArray(input, limits.max);
    case 'comma':
      return segmentComma(input, limits.max);
    case 'space':
      return segmentSpace(input, limits.max);
    case 'newline':
      return segmentNewline(input, limits.max);
    case 'single':
      return segmentSingle(input, limits.max);
  }
}

/* -------------------------------------------------------------------------- */
/*  Per-item validation                                                       */
/* -------------------------------------------------------------------------- */

/** Index of the first character of `value` matching `test`, or -1. */
function findChar(value: string, test: (ch: string) => boolean): number {
  for (let i = 0; i < value.length; i += 1) {
    if (test(value.charAt(i))) return i;
  }
  return -1;
}

/**
 * The one problem worth telling the user about for this item, or `undefined`.
 *
 * Categories are checked in order of how actionable the diagnosis is, not in
 * positional order, so `[a,b]` is reported as a bracket problem (which tells the
 * user to switch to the array format) rather than as a comma problem.
 */
function classifyItem(
  item: ParsedItem,
  format: BackupCodesFormat,
  limits: Limits,
): BackupCodesIssue | undefined {
  const { value, itemNumber } = item;
  const label = itemLabel(format, itemNumber);
  const span = (offset: number, length: number): { index: number; length: number } =>
    item.spanExact
      ? { index: item.start + offset, length }
      : { index: item.start, length: item.length };

  const whitespace = findChar(value, (ch) => WHITESPACE.test(ch));
  if (whitespace !== -1) {
    const ch = value.charAt(whitespace);
    const isLineBreak = ch === '\n' || ch === '\r';
    // Name the whitespace accurately: a line break and a non-breaking space need
    // completely different remedies, and telling someone to delete an invisible
    // character that is actually a newline sends them looking for the wrong thing.
    // There is deliberately no `format === 'space'` arm: the space format splits on
    // every whitespace run, so whitespace can never survive inside one of its items
    // and such an arm would be unreachable.
    let hint = FORMAT_SWITCH_HINT.space;
    if (isLineBreak) {
      hint = FORMAT_SWITCH_HINT.newline;
    } else if (ch !== ' ' && ch !== '\t') {
      hint = 'That looks like a non-breaking space left behind by copy and paste. Delete it.';
    }
    const { index, length } = span(whitespace, 1);
    return makeIssue(
      'CODE_CONTAINS_WHITESPACE',
      isLineBreak
        ? `${label} contains a line break. A backup code cannot span two lines.`
        : `${label} contains a space. A backup code cannot contain spaces.`,
      index,
      length,
      { itemNumber, hint },
    );
  }

  const invisible = findChar(value, (ch) => INVISIBLE.test(ch));
  if (invisible !== -1) {
    const { index, length } = span(invisible, 1);
    return makeIssue(
      'CODE_INVISIBLE_CHAR',
      `${label} contains an invisible character.`,
      index,
      length,
      {
        itemNumber,
        hint: `Copy and paste often carries hidden characters. Retype ${label.toLowerCase()} by hand.`,
      },
    );
  }

  const bracket = findChar(value, (ch) => BRACKETS.includes(ch));
  if (bracket !== -1) {
    const { index, length } = span(bracket, 1);
    return makeIssue(
      'CODE_CONTAINS_BRACKET',
      `${label} contains a bracket. Brackets are not part of a backup code.`,
      index,
      length,
      { itemNumber, hint: FORMAT_SWITCH_HINT.array },
    );
  }

  const comma = value.indexOf(',');
  if (comma !== -1) {
    const { index, length } = span(comma, 1);
    return makeIssue(
      'CODE_CONTAINS_COMMA',
      `${label} contains a comma (,). A backup code cannot contain a comma.`,
      index,
      length,
      {
        itemNumber,
        hint:
          comma === value.length - 1
            ? `Remove the comma at the end of ${label.toLowerCase()}.`
            : FORMAT_SWITCH_HINT.comma,
      },
    );
  }

  const quote = findChar(value, (ch) => QUOTES.includes(ch));
  if (quote !== -1) {
    const { index, length } = span(quote, 1);
    return makeIssue(
      'CODE_CONTAINS_QUOTE',
      `${label} contains a quote character. Quotes are not part of a backup code.`,
      index,
      length,
      { itemNumber, hint: FORMAT_SWITCH_HINT.array },
    );
  }

  const invalid = findChar(value, (ch) => !ALPHANUMERIC.test(ch) && !CODE_PUNCTUATION.includes(ch));
  if (invalid !== -1) {
    const ch = value.charAt(invalid);
    const named = PUNCTUATION_NAMES.get(ch);
    const { index, length } = span(invalid, 1);
    return makeIssue(
      'CODE_INVALID_CHAR',
      named === undefined
        ? `${label} contains a character that is not allowed. Backup codes may only contain letters, digits and - _ . + / =.`
        : `${label} contains ${named}. Backup codes may only contain letters, digits and - _ . + / =.`,
      index,
      length,
      {
        itemNumber,
        ...(ch === ';' && invalid === value.length - 1
          ? {
              hint: `Remove the semicolon at the end of ${label.toLowerCase()}, or replace your semicolons with commas and choose the comma-separated format.`,
            }
          : {}),
      },
    );
  }

  if (!ALPHANUMERIC.test(value)) {
    return makeIssue(
      'CODE_NO_ALPHANUMERIC',
      `${label} is not a backup code: it has no letters or digits.`,
      item.start,
      item.length,
      { itemNumber, hint: 'If that is a leftover dash or separator, delete it.' },
    );
  }

  if (value.length > limits.maxCodeLength) {
    return makeIssue(
      'CODE_TOO_LONG',
      `${label} is longer than ${limits.maxCodeLength} characters, which is longer than any backup code.`,
      item.start,
      item.length,
      {
        itemNumber,
        hint: 'Check that two codes did not run together, and that nothing extra was pasted.',
      },
    );
  }

  return undefined;
}

/* -------------------------------------------------------------------------- */
/*  Entry points                                                              */
/* -------------------------------------------------------------------------- */

function failure(
  format: BackupCodesFormat,
  detected: boolean,
  issues: readonly BackupCodesIssue[],
  primary: BackupCodesIssue,
): BackupCodesParseResult {
  return { ok: false, format, detected, issue: primary, issues };
}

function parseWithFormat(
  input: string,
  format: BackupCodesFormat,
  detected: boolean,
  limits: Limits,
): BackupCodesParseResult {
  // Clearing the field means "no codes", not "invalid".
  if (input.trim() === '') return { ok: true, codes: [], format, detected };

  const seg = segment(input, format, limits);

  // A structural problem changes what the items even ARE, so advice derived from
  // them misleads: in `["fdsf3, "fsfd324"]` the first literal decodes to
  // `fdsf3, `, and validating it would report "item 1 contains a comma" and bury
  // the real diagnosis, "item 1 is missing its closing quote".
  const issues =
    seg.issues.length > 0
      ? [...seg.issues]
      : seg.items
          .map((item) => classifyItem(item, format, limits))
          .filter((issue): issue is BackupCodesIssue => issue !== undefined);

  issues.sort((a, b) => a.index - b.index);
  const primary = issues[0];
  if (primary !== undefined) return failure(format, detected, issues, primary);
  return { ok: true, codes: seg.items.map((item) => item.value), format, detected };
}

/**
 * Candidate formats for `auto`, most likely first. Never empty, so the caller
 * needs no fallback.
 */
function detectFormats(trimmed: string): [BackupCodesFormat, ...BackupCodesFormat[]] {
  const rest: BackupCodesFormat[] = [];
  const hasNewline = /[\n\r]/.test(trimmed);
  const hasComma = trimmed.includes(',');
  // Horizontal whitespace only — a line break is the `newline` signal.
  const hasSpace = /[^\S\n\r]/.test(trimmed);
  if (hasNewline) {
    if (hasComma) rest.push('comma');
    if (hasSpace) rest.push('space');
    return ['newline', ...rest];
  }
  if (hasComma) {
    if (hasSpace) rest.push('space');
    return ['comma', ...rest];
  }
  if (hasSpace) return ['space'];
  return ['single'];
}

/**
 * Parse pasted backup codes.
 *
 * Empty or whitespace-only input SUCCEEDS with `codes: []`. Codes are trimmed of
 * surrounding whitespace and otherwise returned verbatim: case is never changed
 * (codes are case-sensitive at some providers) and exact duplicates are NOT
 * removed — {@link mergeBackupCodes} owns de-duplication so it can report how
 * many were dropped.
 *
 * With `format: 'auto'` (the default), input starting with `[` commits to
 * `array`, since `[` is not in the code character set and no real code can start
 * with one. Otherwise candidates are tried in order — `newline` if a line break
 * is present, `comma` if a comma is, `space` if horizontal whitespace is, else
 * `single` — and the FIRST success wins. When every candidate fails, the failure
 * of the first (most likely) candidate is returned, because it is the most useful
 * diagnosis.
 *
 * A lone token is accepted under `comma`, `space` and `newline`: nothing is wrong
 * with it, and `auto` would classify the same text as `single` and accept it
 * anyway, so rejecting it only when the user happened to pick a multi-item format
 * would be arbitrary.
 */
export function parseBackupCodes(
  input: string,
  options: ParseBackupCodesOptions = {},
): BackupCodesParseResult {
  const requested = options.format ?? 'auto';
  const limits: Limits = {
    max: options.max ?? MAX_LOGIN_BACKUP_CODES,
    maxCodeLength: options.maxCodeLength ?? MAX_LOGIN_BACKUP_CODE_LENGTH,
    maxInputLength: options.maxInputLength ?? MAX_LOGIN_BACKUP_CODES_INPUT_LENGTH,
  };

  if (input.length > limits.maxInputLength) {
    const issue = makeIssue(
      'INPUT_TOO_LONG',
      `This is too long to be a list of backup codes. Keep it under ${limits.maxInputLength} characters.`,
      limits.maxInputLength,
      0,
      { hint: 'Paste only the codes, not the whole page they came from.' },
    );
    const format: BackupCodesFormat = requested === 'auto' ? 'single' : requested;
    return failure(format, requested === 'auto', [issue], issue);
  }

  if (requested !== 'auto') return parseWithFormat(input, requested, false, limits);

  const trimmed = input.trim();
  if (trimmed === '') return { ok: true, codes: [], format: 'single', detected: true };
  if (trimmed.startsWith('[')) return parseWithFormat(input, 'array', true, limits);

  const [first, ...others] = detectFormats(trimmed);
  const firstResult = parseWithFormat(input, first, true, limits);
  if (firstResult.ok) return firstResult;
  for (const candidate of others) {
    const next = parseWithFormat(input, candidate, true, limits);
    if (next.ok) return next;
  }
  return firstResult;
}

export interface MergeBackupCodesResult {
  /** Always a NEW array, safe to hand straight to a state setter. */
  readonly codes: string[];
  /** How many of `incoming` were appended. */
  readonly addedCount: number;
  /** How many of `incoming` were dropped as exact duplicates. */
  readonly duplicateCount: number;
  /** How many of `incoming` were dropped because the list was full. */
  readonly overflowCount: number;
}

/**
 * Append `incoming` to `existing`, dropping exact duplicates and enforcing `max`.
 *
 * `existing` is copied VERBATIM, order intact, including any duplicates it
 * already carries and even when it is already at or over `max`. The stored schema
 * is permissive, so `existing` can legitimately hold values this module would
 * reject on input; silently rewriting or truncating it would be data loss. The
 * cap therefore bounds ADDITIONS only.
 *
 * Duplicate detection is exact and case-SENSITIVE, against both `existing` and
 * the codes already appended from `incoming`; the first occurrence wins. It is
 * checked before the cap, so a duplicate is reported as a duplicate rather than
 * as overflow even when the list is full.
 *
 * `addedCount + duplicateCount + overflowCount === incoming.length`, always.
 */
export function mergeBackupCodes(
  existing: readonly string[],
  incoming: readonly string[],
  max: number = MAX_LOGIN_BACKUP_CODES,
): MergeBackupCodesResult {
  const codes = [...existing];
  const seen = new Set(existing);
  let addedCount = 0;
  let duplicateCount = 0;
  let overflowCount = 0;
  for (const code of incoming) {
    if (seen.has(code)) {
      duplicateCount += 1;
      continue;
    }
    if (codes.length >= max) {
      overflowCount += 1;
      continue;
    }
    codes.push(code);
    seen.add(code);
    addedCount += 1;
  }
  return { codes, addedCount, duplicateCount, overflowCount };
}

/**
 * Render codes back into text: the inverse of {@link parseBackupCodes} for any
 * list of valid codes.
 *
 * `newline` (the default) is one per line, `comma` joins with `', '`, `space`
 * with `' '`, `array` produces `["a", "b"]`. `single` cannot hold a list, so it
 * falls back to one per line.
 */
export function formatBackupCodes(
  codes: readonly string[],
  format: BackupCodesFormat = 'newline',
): string {
  if (codes.length === 0) return '';
  switch (format) {
    case 'array':
      return `[${codes.map((code) => JSON.stringify(code)).join(', ')}]`;
    case 'comma':
      return codes.join(', ');
    case 'space':
      return codes.join(' ');
    case 'newline':
    case 'single':
      return codes.join('\n');
  }
}
