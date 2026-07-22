import { describe, it, expect } from 'vitest';
import { parseImportData } from '../../src/services/import';
import type { ParsedImportItem } from '../../src/services/import';

const BW_JSON = JSON.stringify({
  folders: [{ id: 'f1', name: 'Work' }],
  items: [
    {
      type: 1,
      name: 'GitHub',
      favorite: true,
      folderId: 'f1',
      notes: 'login note',
      login: {
        username: 'octocat',
        password: 'hunter2',
        totp: 'JBSWY3DPEHPK3PXP',
        uris: [{ match: null, uri: 'https://github.com' }, { uri: 'android://com.github' }],
      },
      fields: [{ name: 'PIN', value: '1234', type: 1 }],
    },
    {
      type: 2,
      name: 'My Note',
      notes: 'secret text',
      fields: [{ name: 'k', value: 'v', type: 0 }],
    },
    {
      type: 3,
      name: 'My Card',
      card: {
        cardholderName: 'Alice A',
        brand: 'Visa',
        number: '4111111111111111',
        expMonth: '12',
        expYear: '2030',
        code: '123',
      },
    },
    {
      type: 4,
      name: 'My Identity',
      identity: {
        firstName: 'Alice',
        lastName: 'Anderson',
        email: 'alice@example.com',
        phone: '+1 555 123 4567',
        address1: '1 Main St',
        city: 'Town',
        state: 'CA',
        postalCode: '90001',
        country: 'US',
        passportNumber: 'X123',
      },
    },
  ],
});

function byType(items: ParsedImportItem[], type: string): ParsedImportItem {
  const found = items.find((i) => i.itemType === type);
  expect(found, `expected a ${type} item`).toBeDefined();
  return found!;
}

describe('Bitwarden JSON', () => {
  it('maps all four item types', () => {
    const { items } = parseImportData('bitwarden', BW_JSON);
    expect(items).toHaveLength(4);
  });

  it('maps a login: folder→tag, favorite, totp, custom fields, and drops the unsafe app URI', () => {
    const login = byType(parseImportData('bitwarden', BW_JSON).items, 'login');
    expect(login.name).toBe('GitHub');
    expect(login.favorite).toBe(true);
    expect(login.tags).toEqual(['Work']);
    expect(login.data.username).toBe('octocat');
    expect(login.data.totp).toBe('JBSWY3DPEHPK3PXP');
    // The https URI is kept; the android:// URI is dropped from `uris`.
    expect(login.data.uris).toEqual([{ uri: 'https://github.com', match: 'domain' }]);
    expect(String(login.data.notes)).toContain('android://com.github');
    expect(login.data.customFields).toEqual([{ name: 'PIN', value: '1234', type: 'hidden' }]);
  });

  it('maps a secure note', () => {
    const note = byType(parseImportData('bitwarden', BW_JSON).items, 'note');
    expect(note.name).toBe('My Note');
    expect(String(note.data.content)).toContain('secret text');
    expect(String(note.data.content)).toContain('k: v'); // custom field folded into content
  });

  it('maps a card', () => {
    const card = byType(parseImportData('bitwarden', BW_JSON).items, 'card');
    expect(card.data.cardholderName).toBe('Alice A');
    expect(card.data.number).toBe('4111111111111111');
    expect(card.data.cvv).toBe('123');
    expect(card.data.brand).toBe('Visa');
  });

  it('maps an identity with a nested address', () => {
    const id = byType(parseImportData('bitwarden', BW_JSON).items, 'identity');
    expect(id.data.firstName).toBe('Alice');
    expect(id.data.email).toBe('alice@example.com');
    expect(id.data.passport).toBe('X123');
    expect(id.data.address).toMatchObject({ street: '1 Main St', city: 'Town', zip: '90001' });
  });

  it('throws a friendly ImportParseError on malformed JSON', () => {
    expect(() => parseImportData('bitwarden', '{not json')).toThrowError(/Bitwarden/);
  });
});

describe('Bitwarden CSV', () => {
  const csv =
    'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n' +
    'Work,1,login,GitHub,a note,,0,https://github.com,octocat,hunter2,\n' +
    'Personal,0,note,My Note,note body,,0,,,,';

  it('parses login and note rows', () => {
    const { items } = parseImportData('bitwarden', csv);
    expect(items).toHaveLength(2);
    expect(items[0]?.itemType).toBe('login');
    expect(items[0]?.tags).toEqual(['Work']);
    expect(items[0]?.favorite).toBe(true);
    expect(items[0]?.data.username).toBe('octocat');
    expect(items[1]?.itemType).toBe('note');
    expect(items[1]?.data.content).toBe('note body');
  });
});

describe('Bitwarden identity extra fields', () => {
  const BW_IDENTITY_EXTRAS = JSON.stringify({
    items: [
      {
        type: 4,
        name: 'Full Identity',
        identity: {
          title: 'Dr',
          firstName: 'Alice',
          middleName: 'Quinn',
          lastName: 'Anderson',
          username: 'aq_anderson',
          licenseNumber: 'DL-99887766',
        },
      },
    ],
  });

  it('preserves title, middleName, username and licenseNumber somewhere retrievable', () => {
    const id = byType(parseImportData('bitwarden', BW_IDENTITY_EXTRAS).items, 'identity');
    // The real schema fields are still mapped directly.
    expect(id.data.firstName).toBe('Alice');
    expect(id.data.lastName).toBe('Anderson');
    // The four fields with no schema home are folded into notes under clear labels.
    const notes = String(id.data.notes);
    expect(notes).toContain('Title: Dr');
    expect(notes).toContain('Middle name: Quinn');
    expect(notes).toContain('Username: aq_anderson');
    expect(notes).toContain('License number: DL-99887766');
  });
});

describe('Bitwarden SSH keys (type 5)', () => {
  const PRIVATE_KEY =
    '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1r\n-----END OPENSSH PRIVATE KEY-----';
  const PUBLIC_KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 alice@laptop';
  const FINGERPRINT = 'SHA256:abc123def456';
  const BW_SSH = JSON.stringify({
    items: [
      {
        type: 5,
        name: 'Prod Server Key',
        favorite: true,
        notes: 'the box in the closet',
        sshKey: {
          privateKey: PRIVATE_KEY,
          publicKey: PUBLIC_KEY,
          keyFingerprint: FINGERPRINT,
        },
        fields: [{ name: 'Env', value: 'prod', type: 0 }],
      },
    ],
  });

  it('preserves the key material in clearly-labelled custom fields instead of dropping it', () => {
    const { items } = parseImportData('bitwarden', BW_SSH);
    expect(items).toHaveLength(1);
    const item = items[0]!;
    expect(item.itemType).toBe('login');
    expect(item.name).toBe('Prod Server Key');
    expect(item.favorite).toBe(true);

    const fields = item.data.customFields as { name: string; value: string; type: string }[];
    const byName = (n: string): { name: string; value: string; type: string } | undefined =>
      fields.find((f) => f.name === n);

    expect(byName('SSH Private Key')?.value).toBe(PRIVATE_KEY);
    // The private key is masked as a hidden field.
    expect(byName('SSH Private Key')?.type).toBe('hidden');
    expect(byName('SSH Public Key')?.value).toBe(PUBLIC_KEY);
    expect(byName('SSH Key Fingerprint')?.value).toBe(FINGERPRINT);
    // The item's own Bitwarden custom fields are preserved alongside the key parts.
    expect(byName('Env')?.value).toBe('prod');
    // Notes survive too.
    expect(String(item.data.notes)).toContain('the box in the closet');
  });
});
