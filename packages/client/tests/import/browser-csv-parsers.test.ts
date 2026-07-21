import { describe, it, expect } from 'vitest';
import { parseImportData, detectCsvFormat } from '../../src/services/import';
import type { ParsedImportItem } from '../../src/services/import';

function login(item: ParsedImportItem): Record<string, unknown> {
  expect(item.itemType).toBe('login');
  return item.data;
}

describe('Firefox CSV', () => {
  const csv =
    'url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\n' +
    'https://accounts.google.com/signin,alice@example.com,s3cret,,https://accounts.google.com,{guid-1},1,2,3\n' +
    'https://github.com,bob,"p,w",,,{guid-2},1,2,3';

  it('parses logins and derives the name from the URL host', () => {
    const { items } = parseImportData('firefox', csv);
    expect(items).toHaveLength(2);
    expect(items[0]?.name).toBe('accounts.google.com');
    const d0 = login(items[0]!);
    expect(d0.username).toBe('alice@example.com');
    expect(d0.password).toBe('s3cret');
    expect(d0.uris).toEqual([{ uri: 'https://accounts.google.com/signin', match: 'domain' }]);
    // Quoted password with a comma survives.
    expect(login(items[1]!).password).toBe('p,w');
    expect(items[1]?.name).toBe('github.com');
  });

  it('is auto-detected from its header signature', () => {
    expect(detectCsvFormat(csv)).toBe('firefox');
  });

  it('skips fully empty rows', () => {
    const { items } = parseImportData('firefox', 'url,username,password\n,,\nhttps://x.com,u,p');
    expect(items).toHaveLength(1);
  });

  it('preserves a populated httpRealm column in notes', () => {
    const withRealm =
      'url,username,password,httpRealm,formActionOrigin,guid\n' +
      'https://intranet.example.com,alice,pw,Corp Intranet,,{guid-1}';
    const { items } = parseImportData('firefox', withRealm);
    expect(items).toHaveLength(1);
    const d = login(items[0]!);
    expect(String(d.notes)).toContain('HTTP realm: Corp Intranet');
    // The dropped internal columns never leak into the item.
    expect(String(d.notes)).not.toContain('guid-1');
  });

  it('adds no notes when httpRealm is empty', () => {
    // The two base fixture rows both leave httpRealm empty; neither gains notes.
    const { items } = parseImportData('firefox', csv);
    expect(login(items[0]!).notes).toBeUndefined();
    expect(login(items[1]!).notes).toBeUndefined();
  });
});

describe('Chrome/Edge CSV', () => {
  const csv = 'name,url,username,password,note\nGitHub,https://github.com,octocat,hunter2,my note';

  it('parses a login with note', () => {
    const { items } = parseImportData('chrome', csv);
    expect(items).toHaveLength(1);
    expect(items[0]?.name).toBe('GitHub');
    const d = login(items[0]!);
    expect(d.username).toBe('octocat');
    expect(d.password).toBe('hunter2');
    expect(d.notes).toBe('my note');
    expect(d.uris).toEqual([{ uri: 'https://github.com', match: 'domain' }]);
  });

  it('is auto-detected', () => {
    expect(detectCsvFormat(csv)).toBe('chrome');
  });
});
