import { describe, it, expect } from 'vitest';
import { vaultItemDataSchemas } from '@hvault/shared';
import { parseImportData } from '../../src/services/import';
import {
  firstNonEmpty,
  toTags,
  makeItem,
  clampName,
  normalizeCustomFieldType,
} from '../../src/services/import/itemBuilders';
import { hostFromUrl, toUriEntry } from '../../src/services/import/uri';
import { rowsToRecords } from '../../src/services/import/csv';

// Targeted coverage of parser/helper fallback + skip branches.

describe('itemBuilders helpers', () => {
  it('firstNonEmpty returns the first trimmed non-empty value, else empty', () => {
    expect(firstNonEmpty('', '  ', 'x', 'y')).toBe('x');
    expect(firstNonEmpty(undefined, null, '   ')).toBe('');
  });

  it('clampName trims and bounds length', () => {
    expect(clampName('  hi  ')).toBe('hi');
    expect(clampName('a'.repeat(400)).length).toBe(255);
  });

  it('toTags de-duplicates and caps at the tag limit', () => {
    expect(toTags(['a', 'a', 'b', '  ', null])).toEqual(['a', 'b']);
    expect(toTags(Array.from({ length: 25 }, (_, i) => `t${String(i)}`))).toHaveLength(20);
  });

  it('normalizeCustomFieldType maps numeric and string variants', () => {
    expect(normalizeCustomFieldType(0)).toBe('text');
    expect(normalizeCustomFieldType(1)).toBe('hidden');
    expect(normalizeCustomFieldType(2)).toBe('boolean');
    expect(normalizeCustomFieldType('boolean')).toBe('boolean');
    expect(normalizeCustomFieldType(99)).toBe('text');
    expect(normalizeCustomFieldType(undefined)).toBe('text');
  });

  it('makeItem falls back to a per-type default name when the name is empty', () => {
    expect(makeItem('card', '', {}).name).toBe('Untitled card');
    expect(makeItem('identity', '   ', {}).name).toBe('Untitled identity');
  });
});

describe('uri helpers', () => {
  it('hostFromUrl falls back gracefully on an unparseable value', () => {
    expect(hostFromUrl('not a url with spaces')).toBe('not a url with spaces');
    expect(hostFromUrl('   ')).toBe('');
  });

  it('toUriEntry keeps a mailto and rejects a data: URI', () => {
    expect(toUriEntry('mailto:a@b.com')).not.toBeNull();
    expect(toUriEntry('data:text/plain,hi')).toBeNull();
  });
});

describe('csv rowsToRecords edge cases', () => {
  it('returns empty for empty input', () => {
    expect(rowsToRecords('')).toEqual({ headers: [], records: [] });
  });

  it('skips empty header columns and tolerates ragged widths', () => {
    const { headers, records } = rowsToRecords('a,,c\n1,2,3,4\n9');
    expect(headers).toEqual(['a', '', 'c']);
    // The empty-named column is not keyed; the 4th cell (no header) is ignored.
    expect(records[0]).toEqual({ a: '1', c: '3' });
    expect(records[1]).toEqual({ a: '9', c: '' });
  });
});

describe('parser skip + fallback branches', () => {
  it('Firefox: derives the name from the username when there is no URL', () => {
    const { items } = parseImportData('firefox', 'url,username,password\n,onlyuser,pw');
    expect(items).toHaveLength(1);
    expect(items[0]?.name).toBe('onlyuser');
  });

  it('Chrome: skips a fully blank data row', () => {
    const { items } = parseImportData(
      'chrome',
      'name,url,username,password,note\n,,,,\nGH,https://x,u,p',
    );
    expect(items).toHaveLength(1);
  });

  it('LastPass: skips a blank row and maps a backslash grouping to its last segment', () => {
    const csv =
      'url,username,password,totp,extra,name,grouping,fav\n,,,,,,,\nhttps://x,u,p,,,X,A\\B\\C,0';
    const { items } = parseImportData('lastpass', csv);
    expect(items).toHaveLength(1);
    expect(items[0]?.tags).toEqual(['C']);
  });

  it('KeePass: skips a blank row', () => {
    const csv =
      '"Group","Title","Username","Password","URL","Notes"\n"","","","","",""\n"G","T","u","p","https://x","n"';
    const { items } = parseImportData('keepass', csv);
    expect(items).toHaveLength(1);
  });

  it('1Password: skips a blank row and splits tags', () => {
    const csv = 'title,website,username,password,otpauth,notes,tags\n,,,,,,\nX,https://x,u,p,,,a;b';
    const { items } = parseImportData('onepassword', csv);
    expect(items).toHaveLength(1);
    expect(items[0]?.tags).toEqual(['a', 'b']);
  });

  it('Generic CSV: skips rows with no mapped content and collects multiple URL columns', () => {
    const csv = 'A,B,C\n,,\nName1,https://x,https://y';
    const { items } = parseImportData('csv', csv, { A: 'name', B: 'url', C: 'url' });
    expect(items).toHaveLength(1);
    expect(items[0]?.data.uris).toHaveLength(2);
  });

  it('Bitwarden JSON identity: folds a SCHEMA-invalid email/phone into notes and keeps the item', () => {
    // These values pass a naive check (email has @ and a dot; phone has a digit)
    // but FAIL the shared identityDataSchema refinements (double-dot domain; a
    // phone containing letters). The parser must validate against the real schema
    // and fold them into notes, otherwise the whole identity is dropped downstream.
    const bw = JSON.stringify({
      items: [
        {
          type: 4,
          name: 'Weird Identity',
          identity: { firstName: 'A', ssn: '123', email: 'a@b..c', phone: '+1 555 CALL-NOW' },
        },
      ],
    });
    const { items } = parseImportData('bitwarden', bw);
    expect(items).toHaveLength(1);
    const id = items[0]!;
    expect(id.data.email).toBeUndefined();
    expect(id.data.phone).toBeUndefined();
    expect(id.data.ssn).toBe('123'); // the rest of the identity survives intact
    expect(String(id.data.notes)).toContain('Email: a@b..c');
    expect(String(id.data.notes)).toContain('Phone: +1 555 CALL-NOW');
  });

  it('Bitwarden JSON identity: keeps a schema-VALID email/phone on the item', () => {
    const bw = JSON.stringify({
      items: [
        {
          type: 4,
          name: 'Good Identity',
          identity: { firstName: 'A', email: 'alice@example.com', phone: '+1 (555) 123-4567' },
        },
      ],
    });
    const id = parseImportData('bitwarden', bw).items[0]!;
    expect(id.data.email).toBe('alice@example.com');
    expect(id.data.phone).toBe('+1 (555) 123-4567');
  });

  it('Bitwarden JSON card: uses the default name when none is given', () => {
    const bw = JSON.stringify({ items: [{ type: 3, card: { number: '4111' } }] });
    const { items } = parseImportData('bitwarden', bw);
    expect(items[0]?.name).toBe('Untitled card');
  });

  it('Bitwarden CSV: skips an empty secure-note row', () => {
    const csv =
      'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n' +
      ',,note,,,,,,,,';
    const { items } = parseImportData('bitwarden', csv);
    expect(items).toHaveLength(0);
  });

  // A JSON export may put a number in a custom field. `customFieldSchema.value`
  // is a z.string(), so an uncoerced number fails safeParse and discards the
  // ENTIRE login — password included — not merely that field.
  it('Bitwarden JSON login: coerces a numeric custom-field value instead of dropping the item', () => {
    const bw = JSON.stringify({
      items: [
        {
          type: 1,
          name: 'Bank',
          login: { username: 'alice', password: 'hunter2' },
          fields: [{ name: 'PIN', value: 1234, type: 0 }],
        },
      ],
    });

    const { items } = parseImportData('bitwarden', bw);

    expect(items).toHaveLength(1);
    expect(items[0]?.data.password).toBe('hunter2');
    const fields = items[0]?.data.customFields as { name: string; value: string }[];
    expect(fields[0]?.value).toBe('1234');
    // And the result actually satisfies the shared schema it will be validated by.
    expect(vaultItemDataSchemas.login.safeParse(items[0]?.data).success).toBe(true);
  });

  // A column header literally named `__proto__` resolves to Object.prototype on
  // the lower-keyed record rather than to a cell value, and `?? ''` does not fire
  // because an object is not nullish. Nothing is polluted (the assignment that
  // built the record used a string value, a silent no-op), but calling a string
  // method on it used to throw and take the WHOLE file down with a misleading
  // "unable to parse" error. The remaining columns must still import.
  it('generic CSV: a __proto__ column is ignored instead of aborting the import', () => {
    // Built via JSON.parse so `__proto__` is an OWN property — mirroring the
    // computed-key assignment the mapping UI performs. An object literal would
    // set the prototype instead.
    const mapping = JSON.parse('{"__proto__":"name","User":"username"}') as Record<string, string>;
    const csv = '__proto__,User\nignored,alice';

    const { items } = parseImportData('csv', csv, mapping);

    expect(items).toHaveLength(1);
    expect(items[0]?.data.username).toBe('alice');
    // The bogus column contributed no name, so the username fallback names it.
    expect(items[0]?.name).toBe('alice');
    // Sanity: the prototype was never written to.
    expect(({} as Record<string, unknown>).name).toBeUndefined();
  });
});
