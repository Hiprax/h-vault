import { describe, it, expect } from 'vitest';
import { toCsv } from '../../src/services/export/csvWriter';
import { parseCsv } from '../../src/services/import/csv';

/**
 * A field is quoted when it contains a `"`, `,`, CR or LF, or has
 * leading/trailing whitespace; `"` is doubled; rows are CRLF-joined.
 */
describe('toCsv (RFC 4180 writer)', () => {
  it('emits a plain header and row, comma-separated and CRLF-joined', () => {
    expect(toCsv(['a', 'b', 'c'], [['1', '2', '3']])).toBe('a,b,c\r\n1,2,3');
  });

  it('joins multiple rows with CRLF and adds no trailing newline', () => {
    expect(toCsv(['a'], [['1'], ['2']])).toBe('a\r\n1\r\n2');
  });

  it('emits only the header when there are no rows', () => {
    expect(toCsv(['a', 'b'], [])).toBe('a,b');
  });

  it('quotes a field containing a comma', () => {
    expect(toCsv(['name'], [['Doe, John']])).toBe('name\r\n"Doe, John"');
  });

  it('quotes and doubles an embedded double-quote', () => {
    expect(toCsv(['a'], [['she said "hi"']])).toBe('a\r\n"she said ""hi"""');
  });

  it('quotes a field containing an embedded LF or CRLF', () => {
    expect(toCsv(['note'], [['multi\nline']])).toBe('note\r\n"multi\nline"');
    expect(toCsv(['note'], [['second\r\nrow']])).toBe('note\r\n"second\r\nrow"');
  });

  it('quotes a field containing a lone CR', () => {
    expect(toCsv(['a'], [['x\ry']])).toBe('a\r\n"x\ry"');
  });

  it('quotes a field with leading or trailing whitespace (fidelity for passwords)', () => {
    expect(toCsv(['password'], [[' secret ']])).toBe('password\r\n" secret "');
    expect(toCsv(['password'], [['\ttab']])).toBe('password\r\n"\ttab"');
  });

  it('does not quote a field with no special characters', () => {
    expect(toCsv(['a'], [['plain-value_123']])).toBe('a\r\nplain-value_123');
  });

  it('leaves an empty middle field unquoted', () => {
    expect(toCsv(['a', 'b', 'c'], [['1', '', '3']])).toBe('a,b,c\r\n1,,3');
  });

  it('NEVER mutates a value that begins with a formula character', () => {
    // §1.7: fidelity over a half-working spreadsheet mitigation.
    expect(toCsv(['password'], [['=1+2']])).toBe('password\r\n=1+2');
    expect(toCsv(['password'], [['+cmd']])).toBe('password\r\n+cmd');
    expect(toCsv(['password'], [['-42']])).toBe('password\r\n-42');
    expect(toCsv(['password'], [['@here']])).toBe('password\r\n@here');
    // A formula that also needs quoting stays verbatim inside the quotes.
    expect(toCsv(['password'], [['=SUM(A1,A2)']])).toBe('password\r\n"=SUM(A1,A2)"');
  });
});

/**
 * The load-bearing acceptance criterion (§ Phase 4): output must parse back
 * through the project's OWN tokenizer to the exact input matrix.
 */
describe('toCsv round-trips through parseCsv', () => {
  const matrices: { label: string; headers: string[]; rows: string[][] }[] = [
    {
      label: 'plain values',
      headers: ['name', 'username', 'password'],
      rows: [
        ['GitHub', 'octocat', 'hunter2'],
        ['Email', 'me@example.com', 'p@ss'],
      ],
    },
    {
      label: 'commas, quotes and embedded newlines',
      headers: ['name', 'notes'],
      rows: [
        ['Doe, John', 'line one\nline two'],
        ['quote "test"', 'crlf\r\ninside'],
      ],
    },
    {
      label: 'leading/trailing whitespace and empty cells',
      headers: ['a', 'b', 'c'],
      rows: [
        [' leading', 'trailing ', ''],
        ['', ' \t ', 'x'],
      ],
    },
    {
      label: 'formula-like and Unicode values',
      headers: ['password', 'note'],
      rows: [
        ['=1+2', 'café ☕ — naïve'],
        ['@handle', '日本語, テスト'],
        ['-negative', '👩‍💻 emoji'],
      ],
    },
    {
      label: 'the exact Bitwarden individual-vault CSV header',
      headers: [
        'folder',
        'favorite',
        'type',
        'name',
        'notes',
        'fields',
        'reprompt',
        'login_uri',
        'login_username',
        'login_password',
        'login_totp',
      ],
      rows: [
        [
          'Personal',
          '1',
          'login',
          'Bank',
          'careful',
          '',
          '0',
          'https://bank.example',
          'me',
          's,e"c\nret',
          '',
        ],
      ],
    },
  ];

  for (const { label, headers, rows } of matrices) {
    it(`reproduces [${label}] exactly`, () => {
      const csv = toCsv(headers, rows);
      expect(parseCsv(csv)).toEqual([headers, ...rows]);
    });
  }

  it('property-style: a generated matrix survives the round-trip', () => {
    // A spread of characters that stress every quoting branch, plus Unicode.
    const alphabet = [
      'a',
      'Z',
      '0',
      ' ',
      '\t',
      ',',
      '"',
      '\n',
      '\r',
      '=',
      '+',
      '-',
      '@',
      'é',
      '☕',
      '语',
    ];
    const cell = (r: number, c: number): string => {
      // Deterministic pseudo-content: pick a few characters by position.
      const len = ((r * 7 + c * 3) % 5) + 1;
      let s = '';
      for (let k = 0; k < len; k++) {
        s += alphabet[(r * 13 + c * 5 + k * 11) % alphabet.length] ?? '';
      }
      return s;
    };

    const headers = ['h0', 'h1', 'h2', 'h3'];
    const rows: string[][] = [];
    for (let r = 0; r < 20; r++) {
      const row: string[] = [];
      for (let c = 0; c < headers.length; c++) row.push(cell(r, c));
      rows.push(row);
    }

    expect(parseCsv(toCsv(headers, rows))).toEqual([headers, ...rows]);
  });
});
