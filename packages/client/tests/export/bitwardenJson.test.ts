import { describe, it, expect } from 'vitest';
import { parseImportData } from '../../src/services/import';
import type { ParsedImportItem } from '../../src/services/import';
import { toBitwardenJson } from '../../src/services/export/formats/bitwardenJson';
import type { PortableItem } from '../../src/services/export/portableItem';

/**
 * `toBitwardenJson` serializes normalized portable items into Bitwarden's
 * unencrypted-JSON export shape. The proof is a round-trip through the repo's
 * OWN importer (`parseImportData('bitwarden', …)`): if a field survives that,
 * the emitted key is the one Bitwarden reads. Because the importer maps folders
 * to a single tag and never reads `passwordHistory`, the acceptance is
 * per-field, and the two documented losses are asserted AS losses.
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
      cardholderName: 'Alice Q',
      number: '4111111111111111',
      expMonth: '12',
      expYear: '2030',
      cvv: '123',
      brand: 'Visa',
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
    identity: {
      firstName: 'Alice',
      lastName: 'Quinn',
      email: 'alice@example.com',
      phone: '+15551234567',
      address: { street: '1 Main St', city: 'Town', state: 'CA', zip: '90210', country: 'US' },
      company: 'Acme',
      ssn: '000-00-0000',
      passport: 'X1234567',
    },
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
    secret: { value: 'topsecret', description: 'the desc' },
    ...over,
  };
}

/** Re-import the serialized content and return the parsed item of a given type. */
function roundTrip(portable: PortableItem[]): ParsedImportItem[] {
  const { content, omittedCount } = toBitwardenJson(portable);
  expect(omittedCount).toBe(0);
  return parseImportData('bitwarden', content).items;
}

function byType(items: ParsedImportItem[], type: string): ParsedImportItem {
  const found = items.find((i) => i.itemType === type);
  expect(found, `expected a ${type} item`).toBeDefined();
  return found!;
}

describe('toBitwardenJson — document shape', () => {
  it('emits { folders, items } and NEVER a collections key', () => {
    const { content } = toBitwardenJson([login()]);
    const doc = JSON.parse(content) as Record<string, unknown>;
    expect(Object.keys(doc).sort()).toEqual(['folders', 'items']);
    expect('collections' in doc).toBe(false);
  });

  it('reports omittedCount 0 (every type is representable)', () => {
    const { omittedCount } = toBitwardenJson([login(), note(), card(), identity(), secret()]);
    expect(omittedCount).toBe(0);
  });

  it('uses numeric item type codes (1/2/3/4)', () => {
    const { content } = toBitwardenJson([login(), note(), card(), identity()]);
    const doc = JSON.parse(content) as { items: { type: number }[] };
    expect(doc.items.map((i) => i.type)).toEqual([1, 2, 3, 4]);
  });

  it("names the card CVV field 'code', not 'cvv'", () => {
    const { content } = toBitwardenJson([card()]);
    const doc = JSON.parse(content) as { items: { card: Record<string, unknown> }[] };
    const emitted = doc.items[0]?.card ?? {};
    expect(emitted.code).toBe('123');
    expect('cvv' in emitted).toBe(false);
  });

  it('uses address1/postalCode/passportNumber for identity, not address/zip/passport', () => {
    const { content } = toBitwardenJson([identity()]);
    const doc = JSON.parse(content) as { items: { identity: Record<string, unknown> }[] };
    const emitted = doc.items[0]?.identity ?? {};
    expect(emitted.address1).toBe('1 Main St');
    expect(emitted.postalCode).toBe('90210');
    expect(emitted.passportNumber).toBe('X1234567');
    for (const wrong of ['address', 'zip', 'passport']) {
      expect(wrong in emitted, `must not emit ${wrong}`).toBe(false);
    }
  });

  it('emits fields[] with numeric type codes (text→0, hidden→1, boolean→2)', () => {
    const item = login({
      customFields: [
        { name: 't', value: 'a', type: 'text' },
        { name: 'h', value: 'b', type: 'hidden' },
        { name: 'b', value: 'c', type: 'boolean' },
      ],
    });
    const { content } = toBitwardenJson([item]);
    const doc = JSON.parse(content) as { items: { fields: { type: number }[] }[] };
    expect(doc.items[0]?.fields.map((f) => f.type)).toEqual([0, 1, 2]);
  });
});

describe('toBitwardenJson — per-field round-trip', () => {
  it('round-trips itemType, name and favorite for login/note/card/identity', () => {
    const items = roundTrip([
      login({ name: 'GitHub', favorite: true }),
      note({ name: 'My Note' }),
      card({ name: 'My Card' }),
      identity({ name: 'My Identity' }),
    ]);
    expect(items).toHaveLength(4);
    expect(byType(items, 'login').name).toBe('GitHub');
    expect(byType(items, 'login').favorite).toBe(true);
    expect(byType(items, 'note').name).toBe('My Note');
    expect(byType(items, 'card').name).toBe('My Card');
    expect(byType(items, 'identity').name).toBe('My Identity');
  });

  it("round-trips a login's username, password, first uri host and totp", () => {
    const totp = 'otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&issuer=Acme';
    const items = roundTrip([
      login({
        login: { username: 'octocat', password: 'hunter2' },
        uris: ['https://github.com', 'https://www.github.com'],
        totp,
      }),
    ]);
    const l = byType(items, 'login');
    expect(l.data.username).toBe('octocat');
    expect(l.data.password).toBe('hunter2');
    const uris = l.data.uris as { uri: string }[];
    expect(new URL(uris[0]!.uri).hostname).toBe('github.com');
    expect(l.data.totp).toBe(totp);
  });

  it("round-trips a card's number and code→cvv", () => {
    const items = roundTrip([
      card({
        card: {
          cardholderName: 'A',
          number: '5555444433332222',
          expMonth: '01',
          expYear: '2029',
          cvv: '999',
          brand: 'Mastercard',
        },
      }),
    ]);
    const c = byType(items, 'card');
    expect(c.data.number).toBe('5555444433332222');
    expect(c.data.cvv).toBe('999');
  });

  it("round-trips an identity's firstName/lastName and mapped address fields", () => {
    const items = roundTrip([identity()]);
    const id = byType(items, 'identity');
    expect(id.data.firstName).toBe('Alice');
    expect(id.data.lastName).toBe('Quinn');
    const addr = id.data.address as { street: string; zip: string; country: string };
    expect(addr.street).toBe('1 Main St');
    expect(addr.zip).toBe('90210');
    expect(addr.country).toBe('US');
    expect(id.data.passport).toBe('X1234567');
  });
});

describe('toBitwardenJson — documented losses', () => {
  it('re-imports a folder path as a single tag (folder→tag loss)', () => {
    const items = roundTrip([login({ folderPath: 'Work/Clients' })]);
    const l = byType(items, 'login');
    // The path is emitted as a Bitwarden folder name and re-imports as a tag,
    // never as a folder — the original hierarchy is flattened.
    expect(l.tags).toEqual(['Work/Clients']);
  });

  it('emits passwordHistory in the file, but the importer drops it (dropped-by-importer loss)', () => {
    const item = login({
      login: { username: 'u', password: 'newpass' },
      passwordHistory: [{ password: 'oldpass', changedAt: '2024-06-01T00:00:00.000Z' }],
    });
    const { content } = toBitwardenJson([item]);

    // The password history IS present in the emitted file (a different
    // Bitwarden instance would keep it)…
    const doc = JSON.parse(content) as {
      items: { passwordHistory?: { lastUsedDate: string; password: string }[] }[];
    };
    expect(doc.items[0]?.passwordHistory).toEqual([
      { lastUsedDate: '2024-06-01T00:00:00.000Z', password: 'oldpass' },
    ]);

    // …but the repo's own importer never reads it, so the old password does not
    // survive the round-trip anywhere on the imported item.
    const [imported] = parseImportData('bitwarden', content).items;
    expect(JSON.stringify(imported)).not.toContain('oldpass');
  });
});

describe('toBitwardenJson — secret mapping', () => {
  it('maps a secret to a secure note (type 2) carrying value and description in notes', () => {
    const { content } = toBitwardenJson([secret()]);
    const doc = JSON.parse(content) as { items: { type: number; notes: string }[] };
    expect(doc.items[0]?.type).toBe(2);
    expect(doc.items[0]?.notes).toContain('topsecret');
    expect(doc.items[0]?.notes).toContain('the desc');

    const [imported] = parseImportData('bitwarden', content).items;
    expect(imported?.itemType).toBe('note');
    expect(String(imported?.data.content)).toContain('topsecret');
  });

  it('folds a secret expiry into the note body and omits an absent description', () => {
    const item = secret({ secret: { value: 'v', expiresAt: '2030-01-01' } });
    const { content } = toBitwardenJson([item]);
    const doc = JSON.parse(content) as { items: { notes: string }[] };
    expect(doc.items[0]?.notes).toContain('v');
    expect(doc.items[0]?.notes).toContain('Expires: 2030-01-01');
    // No description was set, so no stray blank section precedes the value.
    expect(doc.items[0]?.notes.startsWith('v')).toBe(true);
  });
});

describe('toBitwardenJson — optional-field edges', () => {
  it('emits null address fields and no round-trip address for an identity with no address', () => {
    const item = identity({ identity: { firstName: 'No', lastName: 'Address' } });
    const { content } = toBitwardenJson([item]);
    const doc = JSON.parse(content) as { items: { identity: Record<string, unknown> }[] };
    const emitted = doc.items[0]?.identity ?? {};
    expect(emitted.address1).toBeNull();
    expect(emitted.postalCode).toBeNull();
    expect(emitted.company).toBeNull();

    const [imported] = parseImportData('bitwarden', content).items;
    expect(imported?.data.address).toBeUndefined();
  });

  it("folds a card's billing address into notes (Bitwarden cards have no address field)", () => {
    const item = card({
      card: {
        cardholderName: 'A',
        number: '4111111111111111',
        expMonth: '12',
        expYear: '2030',
        cvv: '123',
        billingAddress: {
          street: '1 Main',
          city: 'Town',
          state: 'CA',
          zip: '90210',
          country: 'US',
        },
      },
      notes: 'existing note',
    });
    const { content } = toBitwardenJson([item]);
    const doc = JSON.parse(content) as { items: { notes: string }[] };
    expect(doc.items[0]?.notes).toContain('existing note');
    expect(doc.items[0]?.notes).toContain('Billing address: 1 Main, Town, CA, 90210, US');
  });

  it('deduplicates a shared folder path to a single Bitwarden folder', () => {
    const { content } = toBitwardenJson([
      login({ name: 'A', folderPath: 'Work' }),
      login({ name: 'B', folderPath: 'Work' }),
    ]);
    const doc = JSON.parse(content) as {
      folders: { id: string; name: string }[];
      items: { folderId: string }[];
    };
    expect(doc.folders).toHaveLength(1);
    expect(doc.folders[0]?.name).toBe('Work');
    // Both items point at the same folder id.
    expect(doc.items[0]?.folderId).toBe(doc.items[1]?.folderId);
    expect(doc.items[0]?.folderId).toBe(doc.folders[0]?.id);
  });
});
