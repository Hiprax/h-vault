import { describe, it, expect } from 'vitest';
import { parseImportData, detectCsvFormat } from '../../src/services/import';
import type { ParsedImportItem } from '../../src/services/import';
import { toChromeCsv, CHROME_CSV_HEADER } from '../../src/services/export/formats/chromeCsv';
import type { PortableItem } from '../../src/services/export/portableItem';

/**
 * `toChromeCsv` serializes logins into Chrome/Edge's exact password CSV. It is
 * validated by round-tripping through the repo's own importer and by asserting
 * `detectCsvFormat` recognizes the header. Every non-login item type is not
 * representable in this browser-password format and is counted in `omittedCount`.
 */

function login(over: Partial<PortableItem> = {}): PortableItem {
  return {
    type: 'login',
    name: 'Login',
    folderPath: '',
    favorite: false,
    notes: '',
    tags: [],
    login: { username: 'user', password: 'pass' },
    ...over,
  };
}

function note(over: Partial<PortableItem> = {}): PortableItem {
  return {
    type: 'note',
    name: 'Note',
    folderPath: '',
    favorite: false,
    notes: 'note body',
    tags: [],
    ...over,
  };
}

function card(over: Partial<PortableItem> = {}): PortableItem {
  return {
    type: 'card',
    name: 'Card',
    folderPath: '',
    favorite: false,
    notes: '',
    tags: [],
    card: {
      cardholderName: 'A',
      number: '4111111111111111',
      expMonth: '12',
      expYear: '2030',
      cvv: '123',
    },
    ...over,
  };
}

function identity(over: Partial<PortableItem> = {}): PortableItem {
  return {
    type: 'identity',
    name: 'Identity',
    folderPath: '',
    favorite: false,
    notes: '',
    tags: [],
    identity: { firstName: 'A', lastName: 'B' },
    ...over,
  };
}

function secret(over: Partial<PortableItem> = {}): PortableItem {
  return {
    type: 'secret',
    name: 'Secret',
    folderPath: '',
    favorite: false,
    notes: '',
    tags: [],
    secret: { value: 'v' },
    ...over,
  };
}

function byType(items: ParsedImportItem[], type: string): ParsedImportItem {
  const found = items.find((i) => i.itemType === type);
  expect(found, `expected a ${type} item`).toBeDefined();
  return found!;
}

describe('toChromeCsv — header and detection', () => {
  it('emits exactly the verified Chrome header, in order', () => {
    const { content } = toChromeCsv([login()]);
    const firstLine = content.split('\r\n')[0];
    expect(firstLine).toBe('name,url,username,password,note');
    // …and the exported constant matches that string.
    expect(CHROME_CSV_HEADER.join(',')).toBe(firstLine);
  });

  it('is recognized by detectCsvFormat as chrome', () => {
    const { content } = toChromeCsv([login()]);
    expect(detectCsvFormat(content)).toBe('chrome');
  });

  it('uses CRLF line endings (RFC 4180)', () => {
    const { content } = toChromeCsv([login()]);
    expect(content).toContain('\r\n');
  });
});

describe('toChromeCsv — round-trip', () => {
  it('round-trips a login through the importer, using the first URI', () => {
    const { content } = toChromeCsv([
      login({
        name: 'GitHub',
        login: { username: 'octocat', password: 'hunter2' },
        uris: ['https://github.com', 'https://gist.github.com'],
        notes: 'my secret note',
      }),
    ]);
    const { items } = parseImportData('chrome', content);
    const l = byType(items, 'login');
    expect(l.name).toBe('GitHub');
    expect(l.data.username).toBe('octocat');
    expect(l.data.password).toBe('hunter2');
    const uris = l.data.uris as { uri: string }[];
    // Only the FIRST URI is emitted by Chrome CSV.
    expect(uris).toHaveLength(1);
    expect(new URL(uris[0]!.uri).hostname).toBe('github.com');
    expect(String(l.data.notes)).toContain('my secret note');
  });

  it('preserves values needing quotes (comma, quote, newline) verbatim', () => {
    const { content } = toChromeCsv([
      login({
        name: 'Weird, "name"',
        login: { username: 'a\nb', password: 'p,q' },
      }),
    ]);
    const { items } = parseImportData('chrome', content);
    const l = byType(items, 'login');
    expect(l.name).toBe('Weird, "name"');
    expect(l.data.username).toBe('a\nb');
    expect(l.data.password).toBe('p,q');
  });

  it('preserves a password beginning with `=` verbatim (no formula-injection mutation)', () => {
    const { content } = toChromeCsv([
      login({ name: 'Formula', login: { username: 'u', password: '=1+2' } }),
    ]);
    // The raw CSV must contain the unaltered value (quoted or bare).
    expect(content).toContain('=1+2');
    const { items } = parseImportData('chrome', content);
    expect(byType(items, 'login').data.password).toBe('=1+2');
  });

  it('emits an empty url cell for a login with no URIs, and still round-trips', () => {
    const { content } = toChromeCsv([
      login({ name: 'NoUrl', uris: undefined, login: { username: 'solo', password: 'pw' } }),
    ]);
    const { items } = parseImportData('chrome', content);
    const l = byType(items, 'login');
    expect(l.data.username).toBe('solo');
    expect(l.data.uris).toEqual([]);
  });

  it('falls back to empty username/password when the login sub-object is absent', () => {
    // A malformed portable login with no `login` payload must not throw; the
    // `?.`/`?? ''` fallbacks emit blanks and the name keeps the row importable.
    const { content } = toChromeCsv([login({ name: 'Bare', login: undefined })]);
    const rows = content.split('\r\n');
    expect(rows).toHaveLength(2);
    expect(rows[1]).toBe('Bare,,,,');
    const { items } = parseImportData('chrome', content);
    const l = byType(items, 'login');
    expect(l.data.username).toBe('');
    expect(l.data.password).toBe('');
  });
});

describe('toChromeCsv — omitted (non-login) types', () => {
  it('emits login rows only and counts every non-login item as omitted', () => {
    const { content, omittedCount } = toChromeCsv([login(), note(), card(), identity(), secret()]);
    // Four non-login items omitted.
    expect(omittedCount).toBe(4);
    // One data row (the login) plus the header line.
    expect(content.split('\r\n')).toHaveLength(2);
  });

  it('a vault of 3 logins + 2 cards yields 3 rows and omittedCount === 2', () => {
    const { content, omittedCount } = toChromeCsv([
      login({ name: 'A' }),
      login({ name: 'B' }),
      login({ name: 'C' }),
      card(),
      card(),
    ]);
    expect(omittedCount).toBe(2);
    // Header + three login rows.
    expect(content.split('\r\n')).toHaveLength(4);
  });

  it('emits a header-only document (no rows) when the vault has no logins', () => {
    const { content, omittedCount } = toChromeCsv([card(), identity(), note()]);
    expect(omittedCount).toBe(3);
    expect(content.split('\r\n')).toHaveLength(1);
    expect(content).toBe('name,url,username,password,note');
    // The importer yields nothing from a header-only file.
    expect(parseImportData('chrome', content).items).toHaveLength(0);
  });
});
