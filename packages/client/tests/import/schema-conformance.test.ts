import { describe, it, expect } from 'vitest';
import { parseImportData } from '../../src/services/import';
import type { CsvFieldMapping, ImportSourceFormat } from '../../src/services/import';
import { vaultItemDataSchemas } from '@hvault/shared';

/**
 * The load-bearing guard: whatever a parser emits as an item's decrypted `data`
 * MUST pass the shared `vaultItemDataSchemas[itemType]`. If it does not,
 * the validation step drops the entire item — counted and reported, but still
 * lost — so a parser that produces almost-valid data becomes data loss. This runs a representative
 * record for every format + item type through the real schema.
 */

interface Case {
  format: Exclude<ImportSourceFormat, 'json'>;
  text: string;
  mapping?: CsvFieldMapping;
  minItems: number;
}

const BITWARDEN = JSON.stringify({
  folders: [{ id: 'f', name: 'Work' }],
  items: [
    {
      type: 1,
      name: 'Login',
      folderId: 'f',
      login: {
        username: 'u',
        password: 'p',
        totp: 'JBSWY3DPEHPK3PXP',
        uris: [{ uri: 'https://a.com' }, { uri: 'android://x' }],
      },
      fields: [{ name: 'PIN', value: '1234', type: 1 }],
    },
    { type: 2, name: 'Note', notes: 'body' },
    {
      type: 3,
      name: 'Card',
      card: {
        cardholderName: 'A',
        number: '4111',
        expMonth: '12',
        expYear: '2030',
        code: '123',
        brand: 'Visa',
      },
    },
    {
      type: 4,
      name: 'Identity',
      // email + phone that pass a naive check but fail the shared schema refines;
      // Fix requires the parser to fold them into notes so the item stays valid.
      identity: {
        title: 'Dr',
        firstName: 'A',
        middleName: 'M',
        lastName: 'B',
        username: 'ab_user',
        licenseNumber: 'DL-1',
        email: 'a@b..c',
        phone: '+1 555 CALL-NOW',
        address1: '1 Main St',
        city: 'Town',
        state: 'CA',
        postalCode: '90001',
        country: 'US',
        passportNumber: 'X1',
      },
    },
    {
      type: 5,
      name: 'SSH Key',
      sshKey: {
        privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----',
        publicKey: 'ssh-ed25519 AAAA key@host',
        keyFingerprint: 'SHA256:zzz',
      },
    },
  ],
});

const cases: Case[] = [
  { format: 'firefox', text: 'url,username,password\nhttps://a.com,u,p', minItems: 1 },
  {
    format: 'chrome',
    text: 'name,url,username,password,note\nA,https://a.com,u,p,note',
    minItems: 1,
  },
  {
    format: 'lastpass',
    text:
      'url,username,password,totp,extra,name,grouping,fav\n' +
      'https://a.com,u,p,SEC,notes,X,G\\H,1\n' +
      'http://sn,,,,body,SecureNote,Personal,0',
    minItems: 2,
  },
  {
    format: 'keepass',
    text: '"Group","Title","Username","Password","URL","Notes"\n"G","T","u","p","https://a.com","n"',
    minItems: 1,
  },
  {
    format: 'onepassword',
    text: 'title,website,username,password,otpauth,notes,tags\nX,https://a.com,u,p,otpauth://x,n,a;b',
    minItems: 1,
  },
  {
    format: 'csv',
    text: 'Name,User,Pass,Site\nAcme,u,p,https://a.com',
    mapping: { Name: 'name', User: 'username', Pass: 'password', Site: 'url' },
    minItems: 1,
  },
  { format: 'bitwarden', text: BITWARDEN, minItems: 5 },
];

describe('every parser emits schema-conformant decrypted data', () => {
  for (const c of cases) {
    it(`${c.format}: all parsed items pass vaultItemDataSchemas`, () => {
      const { items } = parseImportData(c.format, c.text, c.mapping);
      expect(items.length).toBeGreaterThanOrEqual(c.minItems);
      for (const item of items) {
        const result = vaultItemDataSchemas[item.itemType].safeParse(item.data);
        expect(
          result.success,
          `${c.format} ${item.itemType} "${item.name}" failed schema: ${
            result.success ? '' : JSON.stringify(result.error.issues)
          }`,
        ).toBe(true);
      }
    });
  }
});
