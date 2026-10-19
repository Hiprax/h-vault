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
        address2: 'Apt 4B',
        address3: 'Building C',
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

  it('maps a secure note, carrying its fields as custom fields rather than folding them', () => {
    // Specification change (0.18.0): notes hold custom fields now, so a Bitwarden
    // secure note's `fields` import as fields, as a login's and an identity's
    // always have. Folding them into the content wrote hidden values in clear.
    const note = byType(parseImportData('bitwarden', BW_JSON).items, 'note');
    expect(note.name).toBe('My Note');
    expect(note.data.content).toBe('secret text');
    expect(note.data.customFields).toEqual([{ name: 'k', value: 'v', type: 'text' }]);
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
    // address1 is the first line; address2 and address3 are joined into the SECOND line
    // rather than all three being concatenated into `street`. That is what makes an
    // export-then-import round trip preserve both of H-Vault's street lines, and it also
    // removes the unbounded three-way join that could exceed the street cap on its own.
    expect(id.data.address).toMatchObject({ street2: 'Apt 4B, Building C' });
  });

  describe('Bitwarden identity address lines', () => {
    function parseIdentity(identity: Record<string, unknown>): Record<string, unknown> {
      const json = JSON.stringify({ items: [{ type: 4, name: 'Id', identity }] });
      return byType(parseImportData('bitwarden', json).items, 'identity').data;
    }

    it('maps address2 alone to the second line, leaving the first empty', () => {
      expect(parseIdentity({ address1: '1 Main St', address2: 'Apt 4B' }).address).toMatchObject({
        street: '1 Main St',
        street2: 'Apt 4B',
      });
    });

    it('emits an address when address2 is the ONLY line present', () => {
      // The presence guard is a disjunction. Before street2 joined it, an export whose
      // only address content sat in address2 produced an identity with no address.
      expect(parseIdentity({ address2: 'Apt 4B' }).address).toMatchObject({
        street: '',
        street2: 'Apt 4B',
      });
    });

    it('emits no address at all when every line and locality field is empty', () => {
      expect(parseIdentity({ firstName: 'A' }).address).toBeUndefined();
    });

    it('never invents delivery notes: no Bitwarden field maps to them', () => {
      // Stated as a test so a future "helpful" mapping has to argue with it. Folding an
      // unrelated column into courier instructions would be silent data corruption.
      const address = parseIdentity({ address1: '1 Main St' }).address as Record<string, unknown>;
      expect(address).not.toHaveProperty('deliveryNotes');
    });
  });

  it('throws a friendly ImportParseError on malformed JSON', () => {
    expect(() => parseImportData('bitwarden', '{not json')).toThrowError(/Bitwarden/);
  });
});

describe('Bitwarden JSON note and card fields (0.18.0)', () => {
  /** A value no other input here contains, so finding it anywhere proves a leak. */
  const PIN = '\uE000card-pin\uE001';
  const ALARM = '\uE000alarm-code\uE001';

  const parseOne = (item: Record<string, unknown>): ParsedImportItem => {
    const { items } = parseImportData('bitwarden', JSON.stringify({ items: [item] }));
    expect(items).toHaveLength(1);
    return items[0]!;
  };

  it('maps a card’s fields to custom fields, types intact, and leaves its notes alone', () => {
    const card = parseOne({
      type: 3,
      name: 'Card',
      notes: 'card note',
      card: { cardholderName: 'A', number: '4111111111111111' },
      fields: [
        { name: 'PIN', value: PIN, type: 1 },
        { name: 'Bank', value: 'Acme', type: 0 },
        { name: 'Contactless', value: 'true', type: 2 },
        { name: '   ', value: 'nameless', type: 0 },
      ],
    });

    expect(card.itemType).toBe('card');
    expect(card.data.customFields).toEqual([
      { name: 'PIN', value: PIN, type: 'hidden' },
      { name: 'Bank', value: 'Acme', type: 'text' },
      { name: 'Contactless', value: 'true', type: 'boolean' },
    ]);
    // Nothing is folded any more: the notes are exactly the source's.
    expect(card.data.notes).toBe('card note');
    expect(String(card.data.notes)).not.toContain('\uE000');
  });

  it('emits neither customFields nor notes for a card that has neither', () => {
    const card = parseOne({
      type: 3,
      name: 'Bare card',
      card: { number: '4111111111111111' },
      fields: [{ name: '', value: 'x', type: 0 }],
    });

    expect('customFields' in card.data).toBe(false);
    expect('notes' in card.data).toBe(false);
  });

  it('keeps a hidden note field hidden, its value out of the content', () => {
    const note = parseOne({
      type: 2,
      name: 'House',
      notes: 'keys under the mat',
      fields: [
        { name: 'Alarm', value: ALARM, type: 1 },
        { name: 'Wi-Fi', value: 'house-net', type: 0 },
      ],
    });

    expect(note.data.content).toBe('keys under the mat');
    expect(note.data.customFields).toEqual([
      { name: 'Alarm', value: ALARM, type: 'hidden' },
      { name: 'Wi-Fi', value: 'house-net', type: 'text' },
    ]);
  });

  it('imports an unknown item type as a note carrying its fields the same way', () => {
    const note = parseOne({
      type: 99,
      name: 'Future type',
      fields: [{ name: 'k', value: 'v', type: 0 }],
    });

    expect(note.itemType).toBe('note');
    expect(note.data.content).toBe('');
    expect(note.data.customFields).toEqual([{ name: 'k', value: 'v', type: 'text' }]);
  });

  it('keeps folding a CSV note’s fields column, which carries no field types', () => {
    const csv =
      'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n' +
      ',0,note,My Note,note body,k: v,0,,,,';
    const [note] = parseImportData('bitwarden', csv).items;
    expect(note?.data.content).toBe('note body\n\nk: v');
    expect(note && 'customFields' in note.data).toBe(false);
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
