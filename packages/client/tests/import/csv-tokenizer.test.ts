import { describe, it, expect } from 'vitest';
import { parseCsv, rowsToRecords, toLowerKeyed, pick } from '../../src/services/import/csv';
import { toUriEntry, hostFromUrl } from '../../src/services/import/uri';

describe('parseCsv (RFC-4180)', () => {
  it('parses simple rows', () => {
    expect(parseCsv('a,b,c\n1,2,3')).toEqual([
      ['a', 'b', 'c'],
      ['1', '2', '3'],
    ]);
  });

  it('handles quoted fields containing commas', () => {
    expect(parseCsv('name,note\n"Doe, John","hi, there"')).toEqual([
      ['name', 'note'],
      ['Doe, John', 'hi, there'],
    ]);
  });

  it('handles quoted fields containing embedded newlines (the bug a line-split parser has)', () => {
    const rows = parseCsv('name,note\n"multi\nline","second\r\nrow"');
    expect(rows).toEqual([
      ['name', 'note'],
      ['multi\nline', 'second\r\nrow'],
    ]);
  });

  it('handles escaped double-quotes', () => {
    expect(parseCsv('a\n"she said ""hi"""')).toEqual([['a'], ['she said "hi"']]);
  });

  it('handles CRLF line endings', () => {
    expect(parseCsv('a,b\r\n1,2\r\n')).toEqual([
      ['a', 'b'],
      ['1', '2'],
    ]);
  });

  it('strips a leading UTF-8 BOM', () => {
    expect(parseCsv('﻿a,b\n1,2')[0]).toEqual(['a', 'b']);
  });

  it('drops blank lines but preserves empty trailing cells', () => {
    expect(parseCsv('a,b\n\n1,\n')).toEqual([
      ['a', 'b'],
      ['1', ''],
    ]);
  });

  it('preserves field whitespace verbatim (does not corrupt passwords)', () => {
    // Password with a trailing space, quoted.
    expect(parseCsv('password\n" secret "')).toEqual([['password'], [' secret ']]);
  });

  it('returns an empty array for empty input', () => {
    expect(parseCsv('')).toEqual([]);
  });
});

describe('rowsToRecords', () => {
  it('keys cells by trimmed header and tolerates ragged rows', () => {
    const { headers, records } = rowsToRecords(' A , B , C \n1,2\n4,5,6,7');
    expect(headers).toEqual(['A', 'B', 'C']);
    expect(records[0]).toEqual({ A: '1', B: '2', C: '' }); // missing trailing cell
    expect(records[1]).toEqual({ A: '4', B: '5', C: '6' }); // extra cell ignored
  });
});

describe('toLowerKeyed / pick', () => {
  it('looks up columns case-insensitively, first non-empty wins', () => {
    const lc = toLowerKeyed({ URL: 'https://x', Username: '', User: 'bob' });
    expect(pick(lc, 'url')).toBe('https://x');
    expect(pick(lc, 'username', 'user')).toBe('bob');
    expect(pick(lc, 'missing')).toBe('');
  });
});

describe('toUriEntry', () => {
  it('accepts http/https/mailto and bare domains', () => {
    expect(toUriEntry('https://example.com')).toEqual({
      uri: 'https://example.com',
      match: 'domain',
    });
    expect(toUriEntry('example.com')).toEqual({ uri: 'example.com', match: 'domain' });
    expect(toUriEntry('mailto:a@b.com')).toEqual({ uri: 'mailto:a@b.com', match: 'domain' });
  });

  it('rejects unsafe schemes', () => {
    expect(toUriEntry('javascript:alert(1)')).toBeNull();
    expect(toUriEntry('android://com.example')).toBeNull();
    expect(toUriEntry('ftp://host')).toBeNull();
    expect(toUriEntry('')).toBeNull();
  });
});

describe('hostFromUrl', () => {
  it('extracts a hostname for name derivation', () => {
    expect(hostFromUrl('https://accounts.google.com/signin')).toBe('accounts.google.com');
    expect(hostFromUrl('example.com/path')).toBe('example.com');
    expect(hostFromUrl('')).toBe('');
  });
});
