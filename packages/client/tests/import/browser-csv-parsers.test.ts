import { describe, it, expect } from 'vitest';
import { parseImportData, detectCsvFormat } from '../../src/services/import';
import { computeItemIdentity } from '../../src/services/import/identity';
import type { ParsedImportItem } from '../../src/services/import';

function login(item: ParsedImportItem): Record<string, unknown> {
  expect(item.itemType).toBe('login');
  return item.data;
}

/** The identity-key field separator documented in `identity.ts`. */
const SEP = '\u0000';
/** An exact-content key (`<itemType>\0<sha256hex>`), as opposed to a logical one. */
const EXACT_CONTENT_KEY = new RegExp(`^login${SEP}[0-9a-f]{64}$`);

/** Build a Firefox export from `url,username,password` triples. */
function firefoxCsv(...rows: [url: string, username: string, password: string][]): string {
  return ['url,username,password', ...rows.map((r) => r.join(','))].join('\n');
}

describe('Firefox CSV', () => {
  const csv =
    'url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\n' +
    'https://accounts.google.com/signin,alice@example.com,s3cret,,https://accounts.google.com,{guid-1},1,2,3\n' +
    'https://github.com,bob,"p,w",,,{guid-2},1,2,3';

  it('parses logins and derives the name from the URL host and username', () => {
    const { items } = parseImportData('firefox', csv);
    expect(items).toHaveLength(2);
    expect(items[0]?.name).toBe('accounts.google.com (alice@example.com)');
    const d0 = login(items[0]!);
    expect(d0.username).toBe('alice@example.com');
    expect(d0.password).toBe('s3cret');
    expect(d0.uris).toEqual([{ uri: 'https://accounts.google.com/signin', match: 'domain' }]);
    // Quoted password with a comma survives.
    expect(login(items[1]!).password).toBe('p,w');
    expect(items[1]?.name).toBe('github.com (bob)');
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

/**
 * Firefox has no title column, so EVERY row takes the host-derived naming path —
 * which is why several accounts on one site used to arrive as visually identical
 * rows. The username is appended to tell them apart.
 *
 * The rename is a DISPLAY change and must not move any match key: a login with a
 * resolvable host and a username is keyed on host+username, so re-importing the
 * same file stays a no-op. The one row where that does not hold is covered
 * explicitly at the end of this block.
 */
describe('Firefox CSV — host-derived names disambiguate without moving identity', () => {
  it('gives ten accounts on one host ten distinct names', () => {
    const csv = firefoxCsv(
      ...Array.from(
        { length: 10 },
        (_, i) =>
          [
            'https://accounts.google.com/signin',
            `user${String(i)}@gmail.com`,
            `pw${String(i)}`,
          ] as [string, string, string],
      ),
    );

    const { items } = parseImportData('firefox', csv);
    expect(items).toHaveLength(10);
    const names = items.map((i) => i.name);
    expect(new Set(names).size).toBe(10);
    expect(names[0]).toBe('accounts.google.com (user0@gmail.com)');
    expect(names[9]).toBe('accounts.google.com (user9@gmail.com)');
  });

  it('keeps the bare host when the row has no username to add', () => {
    const { items } = parseImportData('firefox', firefoxCsv(['https://example.com', '', 'pw']));
    expect(items[0]?.name).toBe('example.com');
  });

  it('names a row with neither host nor username by the type default', () => {
    const { items } = parseImportData('firefox', firefoxCsv(['', '', 'pw']));
    expect(items).toHaveLength(1);
    expect(items[0]?.name).toBe('Untitled login');
  });

  it('leaves the identity key of a renamed login exactly where it was', async () => {
    const { items } = parseImportData(
      'firefox',
      firefoxCsv(['https://accounts.google.com/signin', 'alice@example.com', 's3cret']),
    );
    const item = items[0]!;
    expect(item.name).toBe('accounts.google.com (alice@example.com)');

    // Matching keys off host+username, never the display name, so the row keys
    // identically to the bare-host name it would have carried before the rename.
    const beforeRename = await computeItemIdentity({ ...item, name: 'accounts.google.com' });
    const afterRename = await computeItemIdentity(item);
    expect(afterRename).toBe(beforeRename);
    expect(afterRename).toBe(['login', 'accounts.google.com', 'alice@example.com'].join(SEP));
  });

  it('keeps ten same-host accounts on ten distinct identity keys', async () => {
    const csv = firefoxCsv(
      ...Array.from(
        { length: 10 },
        (_, i) =>
          ['https://accounts.google.com', `user${String(i)}@gmail.com`, 'pw'] as [
            string,
            string,
            string,
          ],
      ),
    );
    const { items } = parseImportData('firefox', csv);
    const keys = await Promise.all(items.map((item) => computeItemIdentity(item)));
    expect(new Set(keys).size).toBe(10);
  });

  it('does move the key of a row that is host-NAMED but exact-content-KEYED', async () => {
    // The two paths use different host extractors, deliberately. The display name
    // comes from the permissive `hostFromUrl`, which falls back to a manual strip
    // and so names very nearly anything; matching uses the strict `normalizeHost`,
    // which yields '' the moment `new URL` fails. A malformed URL therefore lands
    // host-NAMED yet exact-content-KEYED — and an exact-content key hashes
    // `{ name, data }`, so for this row alone the rename does change the key.
    //
    // Accepted deliberately: such a row imported before this change and
    // re-imported after it lands as a duplicate — a false SPLIT, which is visible
    // and loses nothing. Closing the gap by widening `normalizeHost` to match
    // `hostFromUrl` would promote malformed URIs to LOGICAL matching, risking a
    // false MERGE that silently overwrites a different account. A split is
    // recoverable; a merge is not.
    const { items } = parseImportData('firefox', firefoxCsv(['ht tp://foo.com', 'alice', 'pw']));
    const item = items[0]!;
    expect(item.name).toBe('ht tp: (alice)');

    const afterRename = await computeItemIdentity(item);
    expect(afterRename).toMatch(EXACT_CONTENT_KEY);
    expect(afterRename).not.toBe(await computeItemIdentity({ ...item, name: 'ht tp:' }));
  });

  it('bounds a pathological host+username pair at the import name limit', () => {
    // Neither half may crowd the other out: the disambiguator survives a
    // 3000-char host, the host survives a 600-char username, and when BOTH
    // overrun the budget each keeps an equal share of it.
    const { items } = parseImportData(
      'firefox',
      firefoxCsv(
        [`https://${'a'.repeat(3000)}.example.com`, 'octocat', 'pw'],
        ['https://example.com', 'u'.repeat(600), 'pw'],
        [`https://${'b'.repeat(300)}.example.com`, 'u'.repeat(300), 'pw'],
      ),
    );

    const longHost = items[0]!.name;
    expect(longHost).toHaveLength(255);
    expect(longHost.endsWith(' (octocat)')).toBe(true);

    const longUser = items[1]!.name;
    expect(longUser).toHaveLength(255);
    expect(longUser.startsWith('example.com (uuu')).toBe(true);

    // Both halves over their share: 126 + ' (' + 126 + ')' = 255.
    const bothLong = items[2]!.name;
    expect(bothLong).toHaveLength(255);
    expect(bothLong).toBe(`${'b'.repeat(126)} (${'u'.repeat(126)})`);
  });
});

describe('Chrome/Edge CSV', () => {
  const csv = 'name,url,username,password,note\nGitHub,https://github.com,octocat,hunter2,my note';

  it('parses a login with note', () => {
    const { items } = parseImportData('chrome', csv);
    expect(items).toHaveLength(1);
    // An explicit source title is used verbatim: the username is appended only
    // to a name DERIVED from the host, never to one the source (or the user) set.
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
