import { describe, it, expect } from 'vitest';
import { parseImportData, detectCsvFormat } from '../../src/services/import';
import type { ParsedImportItem } from '../../src/services/import';
import {
  toBitwardenCsv,
  BITWARDEN_CSV_HEADER,
} from '../../src/services/export/formats/bitwardenCsv';
import type { PortableItem } from '../../src/services/export/portableItem';

/**
 * `toBitwardenCsv` serializes logins and secure notes into Bitwarden's exact
 * individual-vault CSV. It is validated by round-tripping through the repo's own
 * importer and by asserting `detectCsvFormat` recognizes the header. Cards,
 * identities and secrets are not representable in this format and are counted in
 * `omittedCount`.
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

describe('toBitwardenCsv — header and detection', () => {
  it('emits exactly the verified Bitwarden header, in order', () => {
    const { content } = toBitwardenCsv([login()]);
    const firstLine = content.split('\r\n')[0];
    expect(firstLine).toBe(
      'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp',
    );
    // …and the exported constant matches that string.
    expect(BITWARDEN_CSV_HEADER.join(',')).toBe(firstLine);
  });

  it('is recognized by detectCsvFormat as bitwarden', () => {
    const { content } = toBitwardenCsv([login()]);
    expect(detectCsvFormat(content)).toBe('bitwarden');
  });

  it('uses CRLF line endings (RFC 4180)', () => {
    const { content } = toBitwardenCsv([login()]);
    expect(content).toContain('\r\n');
  });
});

describe('toBitwardenCsv — round-trip', () => {
  it('round-trips a login through the importer', () => {
    const totp = 'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP';
    const { content } = toBitwardenCsv([
      login({
        name: 'GitHub',
        favorite: true,
        folderPath: 'Work',
        login: { username: 'octocat', password: 'hunter2' },
        uris: ['https://github.com'],
        totp,
      }),
    ]);
    const { items } = parseImportData('bitwarden', content);
    const l = byType(items, 'login');
    expect(l.name).toBe('GitHub');
    expect(l.favorite).toBe(true);
    expect(l.tags).toEqual(['Work']);
    expect(l.data.username).toBe('octocat');
    expect(l.data.password).toBe('hunter2');
    const uris = l.data.uris as { uri: string }[];
    expect(new URL(uris[0]!.uri).hostname).toBe('github.com');
    expect(l.data.totp).toBe(totp);
  });

  it('round-trips a note through the importer', () => {
    const { content } = toBitwardenCsv([note({ name: 'My Note', notes: 'secret text' })]);
    const { items } = parseImportData('bitwarden', content);
    const n = byType(items, 'note');
    expect(n.name).toBe('My Note');
    expect(String(n.data.content)).toContain('secret text');
  });

  it('writes custom fields into the fields cell and folds them into notes on re-import', () => {
    const { content } = toBitwardenCsv([
      login({
        name: 'WithFields',
        customFields: [
          { name: 'PIN', value: '1234', type: 'hidden' },
          { name: 'Q', value: 'A', type: 'text' },
        ],
      }),
    ]);
    expect(content).toContain('PIN: 1234');
    const { items } = parseImportData('bitwarden', content);
    const l = byType(items, 'login');
    expect(String(l.data.notes)).toContain('PIN: 1234');
  });

  it('preserves values needing quotes (comma, quote, newline) verbatim', () => {
    const { content } = toBitwardenCsv([
      login({
        name: 'Weird, "name"',
        login: { username: 'a\nb', password: 'p,q' },
      }),
    ]);
    const { items } = parseImportData('bitwarden', content);
    const l = byType(items, 'login');
    expect(l.name).toBe('Weird, "name"');
    expect(l.data.username).toBe('a\nb');
    expect(l.data.password).toBe('p,q');
  });
});

describe('toBitwardenCsv — omitted types', () => {
  it('counts cards, identities and secrets in omittedCount and emits no rows for them', () => {
    const { content, omittedCount } = toBitwardenCsv([
      login(),
      note(),
      card(),
      identity(),
      secret(),
    ]);
    expect(omittedCount).toBe(3);
    // Two data rows (login + note) plus the header line.
    expect(content.split('\r\n')).toHaveLength(3);
  });

  it('omits everything when the vault has no logins or notes', () => {
    const { content, omittedCount } = toBitwardenCsv([card(), identity()]);
    expect(omittedCount).toBe(2);
    // Header only, no data rows.
    expect(content.split('\r\n')).toHaveLength(1);
    expect(parseImportData('bitwarden', content).items).toHaveLength(0);
  });
});
