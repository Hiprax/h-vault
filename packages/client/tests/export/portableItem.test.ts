import { describe, it, expect, beforeAll } from 'vitest';
import type { ItemType, IPasswordHistoryEntry, IVaultItemResponse } from '@hvault/shared';
import { cryptoService } from '../../src/services/crypto/cryptoService';
import type { DecryptedVaultItem, DecryptedFolder } from '../../src/stores/vaultStore';
import {
  toPortableItems,
  toOtpauthUri,
  type PortableItem,
} from '../../src/services/export/portableItem';

/**
 * `toPortableItems` flattens decrypted vault items into a format-agnostic shape,
 * validating each item through its data schema, decrypting password history, and
 * reporting — never silently dropping — anything it cannot represent. Uses the
 * REAL Web Crypto vault key (installed in tests/setup.ts) so password-history
 * round-trips prove the decrypt path, not just the shape.
 */

function mkItem(
  itemType: ItemType,
  data: Record<string, unknown>,
  opts: {
    id?: string;
    name?: string;
    folderId?: string;
    favorite?: boolean;
    tags?: string[];
    passwordHistory?: IPasswordHistoryEntry[];
  } = {},
): DecryptedVaultItem {
  const raw: IVaultItemResponse = {
    _id: opts.id ?? 'id1',
    itemType,
    tags: opts.tags ?? [],
    favorite: opts.favorite ?? false,
    encryptedData: 'enc',
    dataIv: 'iv',
    dataTag: 'tag',
    encryptedName: 'enc',
    nameIv: 'iv',
    nameTag: 'tag',
    passwordHistory: opts.passwordHistory,
    createdAt: '2024-01-01T00:00:00.000Z',
    updatedAt: '2024-01-01T00:00:00.000Z',
  };
  return {
    id: opts.id ?? 'id1',
    itemType,
    folderId: opts.folderId,
    tags: opts.tags ?? [],
    favorite: opts.favorite ?? false,
    name: opts.name ?? 'Item',
    data,
    createdAt: '2024-01-01T00:00:00.000Z',
    updatedAt: '2024-01-01T00:00:00.000Z',
    _raw: raw,
  };
}

function mkFolder(id: string, name: string, parentId?: string): DecryptedFolder {
  return {
    id,
    name,
    parentId,
    sortOrder: 0,
    createdAt: '2024-01-01T00:00:00.000Z',
    updatedAt: '2024-01-01T00:00:00.000Z',
    _raw: {
      _id: id,
      encryptedName: 'enc',
      nameIv: 'iv',
      nameTag: 'tag',
      sortOrder: 0,
      createdAt: '2024-01-01T00:00:00.000Z',
      updatedAt: '2024-01-01T00:00:00.000Z',
    },
  };
}

async function run(
  items: DecryptedVaultItem[],
  folders: DecryptedFolder[] = [],
): Promise<{ portable: PortableItem[]; skipped: { id: string; name: string; reason: string }[] }> {
  return toPortableItems({ items, folders, vaultKey });
}

let vaultKey: CryptoKey;

beforeAll(async () => {
  const rawVk = cryptoService.generateVaultKey();
  vaultKey = await cryptoService.importVaultKey(rawVk);
});

describe('toOtpauthUri', () => {
  it('passes an existing otpauth:// URI through unchanged', () => {
    const uri = 'otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&issuer=Acme';
    expect(toOtpauthUri(uri, 'Anything')).toBe(uri);
  });

  it('is case-insensitive about the otpauth scheme', () => {
    const uri = 'OTPAUTH://totp/x?secret=ABC';
    expect(toOtpauthUri(uri, 'x')).toBe(uri);
  });

  it('wraps a bare base32 secret into a standard otpauth URI', () => {
    const out = toOtpauthUri('jbswy3dpehpk3pxp', 'My Login');
    expect(out).toMatch(/^otpauth:\/\/totp\//);
    expect(out).toContain('secret=JBSWY3DPEHPK3PXP');
    expect(out).toContain('issuer=My+Login');
    expect(out).toContain('algorithm=SHA1');
    expect(out).toContain('digits=6');
    expect(out).toContain('period=30');
  });

  it('strips whitespace from a bare secret', () => {
    expect(toOtpauthUri('jbsw y3dp ehpk 3pxp', 'x')).toContain('secret=JBSWY3DPEHPK3PXP');
  });

  it('falls back to an H-Vault issuer when the name is blank', () => {
    expect(toOtpauthUri('ABC', '   ')).toContain('issuer=H-Vault');
  });
});

describe('toPortableItems — per type', () => {
  it('flattens a login with uris, bare totp, notes and custom fields', async () => {
    const item = mkItem(
      'login',
      {
        username: 'alice',
        password: 's3cret',
        uris: [{ uri: 'https://example.com', match: 'exact' }],
        totp: 'JBSWY3DPEHPK3PXP',
        notes: 'a note',
        customFields: [{ name: 'PIN', value: '1234', type: 'hidden' }],
      },
      { name: 'Example', favorite: true, tags: ['work'] },
    );
    const { portable, skipped } = await run([item]);
    expect(skipped).toHaveLength(0);
    const [rec] = portable;
    expect(rec).toBeDefined();
    expect(rec?.type).toBe('login');
    expect(rec?.name).toBe('Example');
    expect(rec?.favorite).toBe(true);
    expect(rec?.tags).toEqual(['work']);
    expect(rec?.login).toEqual({ username: 'alice', password: 's3cret' });
    expect(rec?.uris).toEqual(['https://example.com']);
    expect(rec?.totp).toContain('secret=JBSWY3DPEHPK3PXP');
    expect(rec?.notes).toBe('a note');
    expect(rec?.customFields).toEqual([{ name: 'PIN', value: '1234', type: 'hidden' }]);
  });

  it('passes an already-otpauth totp through unchanged', async () => {
    const uri = 'otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&issuer=Acme';
    const item = mkItem('login', {
      username: 'a',
      password: 'b',
      totp: uri,
    });
    const { portable } = await run([item]);
    expect(portable[0]?.totp).toBe(uri);
  });

  it('omits uris, totp and customFields when the login has none', async () => {
    const item = mkItem('login', { username: 'a', password: 'b' });
    const { portable } = await run([item]);
    const rec = portable[0];
    expect(rec?.uris).toBeUndefined();
    expect(rec?.totp).toBeUndefined();
    expect(rec?.customFields).toBeUndefined();
    expect(rec?.notes).toBe('');
  });

  it('drops empty-string uris from a login', async () => {
    const item = mkItem('login', {
      username: 'a',
      password: 'b',
      uris: [{ uri: '', match: 'exact' }],
    });
    const { portable } = await run([item]);
    expect(portable[0]?.uris).toBeUndefined();
  });

  it('flattens a secret with description, expiry and custom fields', async () => {
    const item = mkItem('secret', {
      value: 'top-secret',
      description: 'the desc',
      expiresAt: '2030-01-01',
      customFields: [{ name: 'k', value: 'v', type: 'text' }],
    });
    const { portable } = await run([item]);
    const rec = portable[0];
    expect(rec?.type).toBe('secret');
    expect(rec?.secret).toEqual({
      value: 'top-secret',
      description: 'the desc',
      expiresAt: '2030-01-01',
    });
    expect(rec?.customFields).toEqual([{ name: 'k', value: 'v', type: 'text' }]);
  });

  it('omits customFields when a secret has none', async () => {
    const item = mkItem('secret', { value: 'v', description: 'd' });
    const { portable } = await run([item]);
    expect(portable[0]?.customFields).toBeUndefined();
  });

  it('does not emit a totp for a whitespace-only value', async () => {
    const item = mkItem('login', { username: 'a', password: 'b', totp: '   ' });
    const { portable } = await run([item]);
    expect(portable[0]?.totp).toBeUndefined();
  });

  it('flattens a note, using content as notes', async () => {
    const item = mkItem('note', { content: '# Heading\nbody', format: 'markdown' });
    const { portable } = await run([item]);
    expect(portable[0]?.type).toBe('note');
    expect(portable[0]?.notes).toBe('# Heading\nbody');
  });

  it('flattens a card, carrying cvv, brand and billing address', async () => {
    const item = mkItem('card', {
      cardholderName: 'Alice Q',
      number: '4111111111111111',
      expMonth: '12',
      expYear: '2030',
      cvv: '123',
      brand: 'Visa',
      notes: 'card note',
      billingAddress: { street: '1 Main', city: 'Town', state: 'CA', zip: '90210', country: 'US' },
    });
    const { portable } = await run([item]);
    const rec = portable[0];
    expect(rec?.type).toBe('card');
    expect(rec?.card?.number).toBe('4111111111111111');
    expect(rec?.card?.cvv).toBe('123');
    expect(rec?.card?.brand).toBe('Visa');
    expect(rec?.card?.billingAddress).toEqual({
      street: '1 Main',
      city: 'Town',
      state: 'CA',
      zip: '90210',
      country: 'US',
    });
    expect(rec?.notes).toBe('card note');
  });

  it('omits an absent card billing address', async () => {
    const item = mkItem('card', { cardholderName: 'A', number: '4111111111111111' });
    const { portable } = await run([item]);
    expect(portable[0]?.card?.billingAddress).toBeUndefined();
    expect(portable[0]?.notes).toBe('');
  });

  it('flattens an identity, carrying address, ssn and passport', async () => {
    const item = mkItem('identity', {
      firstName: 'Alice',
      lastName: 'Quinn',
      email: 'alice@example.com',
      phone: '+15551234567',
      address: { street: '1 Main', city: 'Town', state: 'CA', zip: '90210', country: 'US' },
      company: 'Acme',
      ssn: '000-00-0000',
      passport: 'X1234567',
      notes: 'id note',
      customFields: [{ name: 'k', value: 'v', type: 'text' }],
    });
    const { portable } = await run([item]);
    const rec = portable[0];
    expect(rec?.type).toBe('identity');
    expect(rec?.identity?.firstName).toBe('Alice');
    expect(rec?.identity?.lastName).toBe('Quinn');
    expect(rec?.identity?.email).toBe('alice@example.com');
    expect(rec?.identity?.address?.zip).toBe('90210');
    expect(rec?.identity?.ssn).toBe('000-00-0000');
    expect(rec?.identity?.passport).toBe('X1234567');
    expect(rec?.notes).toBe('id note');
    expect(rec?.customFields).toEqual([{ name: 'k', value: 'v', type: 'text' }]);
  });

  it('omits an absent identity address', async () => {
    const item = mkItem('identity', { firstName: 'A', lastName: 'B' });
    const { portable } = await run([item]);
    expect(portable[0]?.identity?.address).toBeUndefined();
  });
});

describe('toPortableItems — folder paths', () => {
  it('resolves a nested folder path for an item', async () => {
    const folders = [mkFolder('f1', 'Work'), mkFolder('f2', 'Clients', 'f1')];
    const item = mkItem('login', { username: 'a', password: 'b' }, { folderId: 'f2' });
    const { portable } = await run([item], folders);
    expect(portable[0]?.folderPath).toBe('Work/Clients');
  });

  it('uses an empty path for an item with no folder', async () => {
    const item = mkItem('login', { username: 'a', password: 'b' });
    const { portable } = await run([item]);
    expect(portable[0]?.folderPath).toBe('');
  });

  it('uses an empty path when the folder id is unknown', async () => {
    const item = mkItem('login', { username: 'a', password: 'b' }, { folderId: 'ghost' });
    const { portable } = await run([item]);
    expect(portable[0]?.folderPath).toBe('');
  });
});

describe('toPortableItems — skipping', () => {
  it('reports an undecodable placeholder (`_raw`) instead of exporting it', async () => {
    const item = mkItem('login', { _raw: { anything: 'x' } }, { id: 'bad', name: 'Broken' });
    const { portable, skipped } = await run([item]);
    expect(portable).toHaveLength(0);
    expect(skipped).toEqual([
      { id: 'bad', name: 'Broken', reason: 'Item data could not be decoded' },
    ]);
  });

  it('reports a `_validationError` placeholder', async () => {
    const item = mkItem('login', { _validationError: true }, { id: 'bad2', name: 'Bad2' });
    const { portable, skipped } = await run([item]);
    expect(portable).toHaveLength(0);
    expect(skipped[0]?.reason).toBe('Item data could not be decoded');
  });

  it('reports an item whose data fails schema validation', async () => {
    // A card number longer than the schema max (30) is not an undecodable
    // placeholder, but still fails `cardDataSchema.safeParse`.
    const item = mkItem('card', { number: 'x'.repeat(31) }, { id: 'bad3', name: 'Bad3' });
    const { portable, skipped } = await run([item]);
    expect(portable).toHaveLength(0);
    expect(skipped[0]).toEqual({ id: 'bad3', name: 'Bad3', reason: 'Item data failed validation' });
  });

  it('guarantees portable.length + skipped.length === items.length', async () => {
    const items = [
      mkItem('login', { username: 'a', password: 'b' }, { id: 'ok1' }),
      mkItem('login', { _raw: {} }, { id: 'bad1' }),
      mkItem('note', { content: 'hi' }, { id: 'ok2' }),
      mkItem('card', { number: 'x'.repeat(31) }, { id: 'bad2' }),
    ];
    const { portable, skipped } = await run(items);
    expect(portable.length + skipped.length).toBe(items.length);
    expect(portable).toHaveLength(2);
    expect(skipped).toHaveLength(2);
  });
});

describe('toPortableItems — password history', () => {
  it('decrypts password-history entries onto the portable record', async () => {
    const older = await cryptoService.encryptData('oldpass', vaultKey);
    const item = mkItem(
      'login',
      { username: 'a', password: 'new' },
      {
        passwordHistory: [
          {
            encryptedPassword: older.encrypted,
            iv: older.iv,
            tag: older.tag,
            changedAt: '2024-06-01T00:00:00.000Z',
          },
        ],
      },
    );
    const { portable } = await run([item]);
    expect(portable[0]?.passwordHistory).toEqual([
      { password: 'oldpass', changedAt: '2024-06-01T00:00:00.000Z' },
    ]);
  });

  it('drops an undecryptable history entry but keeps the item and the good ones', async () => {
    const good = await cryptoService.encryptData('goodpass', vaultKey);
    const item = mkItem(
      'login',
      { username: 'a', password: 'new' },
      {
        passwordHistory: [
          {
            encryptedPassword: good.encrypted,
            iv: good.iv,
            tag: good.tag,
            changedAt: '2024-06-01T00:00:00.000Z',
          },
          {
            // Garbage ciphertext — decrypt throws, entry is dropped, not the item.
            encryptedPassword: 'AAAA',
            iv: 'AAAAAAAAAAAAAAAA',
            tag: 'AAAAAAAAAAAAAAAAAAAAAA==',
            changedAt: '2024-07-01T00:00:00.000Z',
          },
        ],
      },
    );
    const { portable, skipped } = await run([item]);
    expect(skipped).toHaveLength(0);
    expect(portable).toHaveLength(1);
    expect(portable[0]?.passwordHistory).toEqual([
      { password: 'goodpass', changedAt: '2024-06-01T00:00:00.000Z' },
    ]);
  });

  it('sets no passwordHistory when the item has none', async () => {
    const item = mkItem('login', { username: 'a', password: 'b' });
    const { portable } = await run([item]);
    expect(portable[0]?.passwordHistory).toBeUndefined();
  });
});
