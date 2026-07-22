import { describe, it, expect } from 'vitest';
import { parseImportData, detectCsvFormat } from '../../src/services/import';
import { computeItemIdentity } from '../../src/services/import/identity';

describe('LastPass CSV', () => {
  const csv =
    'url,username,password,totp,extra,name,grouping,fav\n' +
    'https://example.com,alice,pw1,JBSWY3DPEHPK3PXP,my notes,Example,Work\\Sites,1\n' +
    'http://sn,,,,"Secret body text",My Secure Note,Personal,0';

  it('parses logins with totp, grouping→tag, fav→favorite', () => {
    const { items } = parseImportData('lastpass', csv);
    expect(items).toHaveLength(2);
    const loginItem = items[0]!;
    expect(loginItem.itemType).toBe('login');
    expect(loginItem.name).toBe('Example');
    expect(loginItem.favorite).toBe(true);
    expect(loginItem.tags).toEqual(['Sites']); // last path segment
    expect(loginItem.data.totp).toBe('JBSWY3DPEHPK3PXP');
    expect(loginItem.data.notes).toBe('my notes');
  });

  it('maps the http://sn sentinel to a secure note', () => {
    const { items } = parseImportData('lastpass', csv);
    const note = items[1]!;
    expect(note.itemType).toBe('note');
    expect(note.name).toBe('My Secure Note');
    expect(note.data.content).toBe('Secret body text');
    expect(note.tags).toEqual(['Personal']);
  });

  it('is auto-detected', () => {
    expect(detectCsvFormat(csv)).toBe('lastpass');
  });
});

describe('KeePass 2.x CSV', () => {
  const csv =
    '"Group","Title","Username","Password","URL","Notes"\n' +
    '"Root/Internet","GitHub","octocat","hunter2","https://github.com","note text"';

  it('parses a login and maps the group last-segment to a tag', () => {
    const { items } = parseImportData('keepass', csv);
    expect(items).toHaveLength(1);
    const item = items[0]!;
    expect(item.itemType).toBe('login');
    expect(item.name).toBe('GitHub');
    expect(item.tags).toEqual(['Internet']);
    expect(item.data.username).toBe('octocat');
    expect(item.data.notes).toBe('note text');
    expect(item.data.uris).toEqual([{ uri: 'https://github.com', match: 'domain' }]);
  });

  it('is auto-detected', () => {
    expect(detectCsvFormat(csv)).toBe('keepass');
  });
});

describe('1Password CSV', () => {
  const csv =
    'title,website,username,password,otpauth,notes,tags\n' +
    'My Login,https://example.com,alice,pw,otpauth://totp/x?secret=ABC,some notes,"work,personal"';

  it('parses a login with totp and tags', () => {
    const { items } = parseImportData('onepassword', csv);
    expect(items).toHaveLength(1);
    const item = items[0]!;
    expect(item.name).toBe('My Login');
    expect(item.tags).toEqual(['work', 'personal']);
    expect(item.data.totp).toBe('otpauth://totp/x?secret=ABC');
  });
});

describe('Generic CSV with column mapping', () => {
  it('maps user columns and derives name from URL + username when name is unmapped', () => {
    const csv = 'Website,Login,Secret\nhttps://foo.com,user@foo.com,p@ss';
    const mapping = { Website: 'url', Login: 'username', Secret: 'password' };
    const { items } = parseImportData('csv', csv, mapping);
    expect(items).toHaveLength(1);
    const item = items[0]!;
    expect(item.itemType).toBe('login');
    // Derived from the URL host, with the username appended so several accounts
    // on one site do not all land under the same name.
    expect(item.name).toBe('foo.com (user@foo.com)');
    expect(item.data.username).toBe('user@foo.com');
    expect(item.data.password).toBe('p@ss');
  });

  it('leaves a mapped name column verbatim, username or not', () => {
    // Only a DERIVED name is disambiguated; a title the source supplied is the
    // user's own label and is never rewritten.
    const csv = 'Title,Website,Login\nWork Google,https://accounts.google.com,alice@example.com';
    const { items } = parseImportData('csv', csv, {
      Title: 'name',
      Website: 'url',
      Login: 'username',
    });
    expect(items[0]?.name).toBe('Work Google');
  });

  it('names an unsafe-scheme row from its host but keys it on exact content', async () => {
    // The realistic member of the "host-NAMED but exact-content-KEYED" class: a
    // mobile export's `android://` URI. `toUriEntry` drops it from `uris`, so the
    // strict `normalizeHost` has nothing to read and the row falls back to
    // exact-content matching — while the permissive `hostFromUrl` still names it.
    // Appending the username therefore moves this row's key, which splits it from
    // a copy imported before the rename rather than merging it with anything: a
    // visible duplicate, never a silent overwrite of a different account.
    const csv = 'URL,User\nandroid://com.example,alice';
    const { items } = parseImportData('csv', csv, { URL: 'url', User: 'username' });
    const item = items[0]!;

    expect(item.name).toBe('com.example (alice)');
    expect(item.data.uris).toEqual([]);
    const key = await computeItemIdentity(item);
    expect(key).toMatch(/^login\u0000[0-9a-f]{64}$/);
    expect(key).not.toBe(await computeItemIdentity({ ...item, name: 'com.example' }));
  });

  it('drops unsafe-scheme URLs but keeps the item (preserved in notes)', () => {
    const csv = 'Name,URL,User\nApp,android://com.example,alice';
    const mapping = { Name: 'name', URL: 'url', User: 'username' };
    const { items } = parseImportData('csv', csv, mapping);
    expect(items).toHaveLength(1);
    expect(items[0]?.data.uris).toEqual([]);
    expect(String(items[0]?.data.notes)).toContain('android://com.example');
  });

  it('maps a folder column to a tag', () => {
    const csv = 'name,folder\nItem,Finance';
    const { items } = parseImportData('csv', csv, { name: 'name', folder: 'folder' });
    expect(items[0]?.tags).toEqual(['Finance']);
  });
});
