import { describe, it, expect, vi } from 'vitest';
import { vaultItemDataSchemas } from '@hvault/shared';
import {
  canonicalJson,
  computeItemIdentity,
  normalizeHost,
  normalizeUsername,
  siteUri,
} from '../../src/services/import/identity';

/**
 * Identity decides whether an incoming import row and an item already in the
 * vault are the same item. Every guarantee the importer makes rests on it: ten
 * accounts on one site staying ten items, a re-import of the same file changing
 * nothing, and `overwrite` updating the right row.
 *
 * These tests drive the REAL Web Crypto digest installed by `tests/setup.ts`;
 * `crypto.subtle` is deliberately never mocked.
 */

// The purity guard: if `identity.ts` — or anything it imports, at any depth —
// pulled in the auth store, this factory would run and throw, failing the whole
// file on the static import below. Identity must never touch account key
// material, so this is asserted structurally rather than by a test case (a test
// body could not observe it: the module is already loaded by then).
vi.mock('../../src/stores/authStore', () => {
  throw new Error('identity.ts must not import authStore, directly or transitively');
});

/** The documented field separator (NUL). */
const SEP = '\u0000';
const HEX_64 = /^[0-9a-f]{64}$/;

type Data = Record<string, unknown>;

const login = (name: string, data: Data): Parameters<typeof computeItemIdentity>[0] => ({
  itemType: 'login',
  name,
  data,
});

const uris = (...values: string[]): { uri: string; match: 'domain' }[] =>
  values.map((uri) => ({ uri, match: 'domain' }));

/** Run raw data through the shared schema, exactly as the vault store does on decrypt. */
const stored = (itemType: 'login' | 'card', data: Data): Data =>
  vaultItemDataSchemas[itemType].parse(data) as Data;

describe('normalizeHost', () => {
  it('resolves a bare or protocol-relative domain through the shared normalizeUri', () => {
    expect(normalizeHost('amazon.com')).toBe('amazon.com');
    expect(normalizeHost('//amazon.com')).toBe('amazon.com');
  });

  it('lowercases, strips exactly one leading www. and ignores path/port/credentials', () => {
    expect(normalizeHost('HTTPS://WWW.Amazon.COM/gp/cart?x=1')).toBe('amazon.com');
    expect(normalizeHost('https://user:pass@www.example.com:8443/deep/path')).toBe('example.com');
    expect(normalizeHost('https://www.www.example.com')).toBe('www.example.com');
  });

  it('keeps a meaningful subdomain', () => {
    expect(normalizeHost('https://login.example.com')).toBe('login.example.com');
  });

  it('strips a trailing root dot', () => {
    expect(normalizeHost('https://example.com./account')).toBe('example.com');
  });

  it('returns an empty host for a URI that has none', () => {
    expect(normalizeHost('mailto:someone@example.com')).toBe('');
    expect(normalizeHost('')).toBe('');
    expect(normalizeHost('   ')).toBe('');
  });

  it('returns an empty host for a malformed URI instead of throwing', () => {
    expect(() => normalizeHost('ht tp://not a url')).not.toThrow();
    expect(normalizeHost('ht tp://not a url')).toBe('');
    expect(normalizeHost('^https://.*regex.*$')).toBe('');
  });

  // `new URL` does not reject these — it REWRITES them and hands back a host
  // that looks perfectly ordinary. Left alone, two unrelated logins collapse
  // onto one of those hosts, which is the false merge a logical key must never
  // produce. Asserted on the raw parser behaviour too, so these stay honest if
  // a future runtime changes: each raw host below is non-empty and WRONG.
  it('refuses a host the URL parser truncated at a backslash', () => {
    expect(new URL(String.raw`https://accounts\.google\.com/.*`).hostname).toBe('accounts');
    expect(normalizeHost(String.raw`https://accounts\.google\.com/.*`)).toBe('');
    expect(normalizeHost(String.raw`https://accounts\.okta\.com/.*`)).toBe('');
    // Reachable with no regex at all: every parser stamps `match: 'domain'`,
    // and a backslash-corrupted URL column passes `toUriEntry` untouched.
    expect(normalizeHost(String.raw`https://foo\bar.com`)).toBe('');
    expect(normalizeHost(String.raw`foo\bar.com`)).toBe('');
  });

  it('refuses a host the URL parser spliced together across stripped whitespace', () => {
    expect(new URL('https://ac\tcounts.google.com').hostname).toBe('accounts.google.com');
    expect(normalizeHost('https://ac\tcounts.google.com')).toBe('');
    expect(normalizeHost('https://exa\nmple.com')).toBe('');
    expect(normalizeHost('https://exa\rmple.com')).toBe('');
  });

  it('still resolves a URI whose PATH — not authority — carries a backslash', () => {
    // The host is already decided by then, so demoting these would cost a
    // legitimate match for nothing.
    expect(normalizeHost(String.raw`https://example.com/a\b`)).toBe('example.com');
    expect(normalizeHost(String.raw`https://example.com/?q=a\b`)).toBe('example.com');
  });

  it('leaves an internationalized domain alone', () => {
    // Guards the authority check against over-reach: punycode conversion means
    // the parsed host is NOT a substring of what the user wrote, so any rule
    // phrased as "the host must appear in the authority" would break IDN.
    expect(normalizeHost('https://例え.jp')).toBe('xn--r8jz45g.jp');
  });
});

describe('siteUri', () => {
  it('returns the first URI of an ordinary login', () => {
    expect(siteUri({ uris: uris('https://amazon.com', 'https://a.co') })).toBe(
      'https://amazon.com',
    );
  });

  it('tolerates a bare string entry, which no parser marks as a pattern', () => {
    expect(siteUri({ uris: ['https://amazon.com'] })).toBe('https://amazon.com');
  });

  it('returns nothing when there are no URIs at all', () => {
    expect(siteUri({})).toBe('');
    expect(siteUri({ uris: [] })).toBe('');
    expect(siteUri({ uris: 'not-an-array' })).toBe('');
    expect(siteUri({ uris: [{ match: 'domain' }] })).toBe('');
  });

  it('withholds a regex entry, because a pattern names no single site', () => {
    const pattern = { uri: String.raw`https://accounts\.google\.com/.*`, match: 'regex' };
    expect(siteUri({ uris: [pattern] })).toBe('');
  });
});

describe('computeItemIdentity — a URI that names a pattern cannot forge a logical key', () => {
  /**
   * `uriEntrySchema` stores a `match: 'regex'` URI verbatim and exempts it from
   * the http/https/mailto check, so it is the one value in a schema-valid login
   * that is a PATTERN rather than an address. Feeding one to the URL parser does
   * not fail loudly — it truncates at the first backslash — so without the
   * withholding in `siteUri` two unrelated sites collapse onto one key.
   */
  const regexLogin = (name: string, uri: string, username: string) =>
    login(name, { username, password: 'p', uris: [{ uri, match: 'regex' }] });

  it('keeps two regex logins on different sites apart, same username or not', async () => {
    const google = await computeItemIdentity(
      regexLogin('Google', String.raw`https://accounts\.google\.com/.*`, 'alice@example.com'),
    );
    const okta = await computeItemIdentity(
      regexLogin('Okta', String.raw`https://accounts\.okta\.com/.*`, 'alice@example.com'),
    );

    expect(google).not.toBe(okta);
    // Both fell back to exact content rather than to a truncated `accounts` host.
    for (const key of [google, okta]) {
      expect(key.startsWith(`login${SEP}`)).toBe(true);
      expect(key.split(SEP)).toHaveLength(2);
      expect(key.split(SEP)[1]).toMatch(HEX_64);
    }
  });

  it('never emits a logical key built from a truncated host', async () => {
    const key = await computeItemIdentity(
      regexLogin('Google', String.raw`https://accounts\.google\.com/.*`, 'alice@example.com'),
    );
    expect(key).not.toContain(`${SEP}accounts${SEP}`);
  });

  it('still keys a regex login on exact content, so a re-import stays a no-op', async () => {
    const row = () =>
      regexLogin('Google', String.raw`https://accounts\.google\.com/.*`, 'alice@example.com');
    expect(await computeItemIdentity(row())).toBe(await computeItemIdentity(row()));
  });

  it('applies the same rule to a plain login whose URL was backslash-corrupted', async () => {
    // No regex needed: every parser stamps `match: 'domain'`, and `toUriEntry`
    // passes a backslash straight through.
    const one = await computeItemIdentity(
      login('Intranet', {
        username: 'alice',
        password: 'p',
        uris: uris(String.raw`https://foo\bar.com`),
      }),
    );
    const two = await computeItemIdentity(
      login('Other', {
        username: 'alice',
        password: 'p',
        uris: uris(String.raw`https://foo\baz.com`),
      }),
    );
    expect(one).not.toBe(two);
    expect(one).not.toContain(`${SEP}foo${SEP}`);
  });
});

describe('normalizeUsername', () => {
  it('trims and lowercases', () => {
    expect(normalizeUsername('  Octo.Cat@Gmail.COM ')).toBe('octo.cat@gmail.com');
  });

  it('normalizes to NFC so the two encodings of one name agree', () => {
    const composed = '\u00C5ngstrom'; // U+00C5, precomposed
    const decomposed = 'A\u030Angstrom'; // "A" + U+030A combining ring above
    expect(composed).not.toBe(decomposed);
    expect(normalizeUsername(decomposed)).toBe(normalizeUsername(composed));
    expect(normalizeUsername(decomposed)).toBe('ångstrom');
  });

  it('yields an empty string for a non-string value', () => {
    expect(normalizeUsername(undefined)).toBe('');
    expect(normalizeUsername(null)).toBe('');
    expect(normalizeUsername(42)).toBe('');
  });
});

describe('canonicalJson', () => {
  it('is independent of object key order, at every depth', () => {
    expect(canonicalJson({ a: 1, b: 2 })).toBe(canonicalJson({ b: 2, a: 1 }));
    expect(canonicalJson({ outer: { x: 1, y: 2 }, z: 3 })).toBe(
      canonicalJson({ z: 3, outer: { y: 2, x: 1 } }),
    );
  });

  it('sorts the keys of objects nested INSIDE arrays', () => {
    // Load-bearing: an item stored by an older client may have serialized its
    // `uris` entries as `{ match, uri }` where today's schema output is
    // `{ uri, match }`. Without in-array sorting those hash differently and a
    // re-import silently duplicates the item.
    expect(canonicalJson({ uris: [{ match: 'domain', uri: 'a' }] })).toBe(
      canonicalJson({ uris: [{ uri: 'a', match: 'domain' }] }),
    );
  });

  it('keeps a __proto__ key as data instead of losing it', () => {
    // `JSON.parse` produces an own `__proto__` property, so decrypted data can
    // carry one. Assigning it onto a plain object literal would hit the
    // inherited setter and drop the field, making these two hash identically.
    const a = JSON.parse('{"__proto__":{"secret":"a"}}') as Record<string, unknown>;
    const b = JSON.parse('{"__proto__":{"secret":"b"}}') as Record<string, unknown>;
    expect(canonicalJson(a)).not.toBe(canonicalJson(b));
    expect(canonicalJson(a)).toContain('secret');
  });

  it('preserves array order, so two orderings differ', () => {
    expect(canonicalJson([1, 2])).not.toBe(canonicalJson([2, 1]));
    expect(canonicalJson({ uris: ['a', 'b'] })).not.toBe(canonicalJson({ uris: ['b', 'a'] }));
  });

  it('NFC-normalizes strings so equivalent encodings serialize identically', () => {
    const composed = 'caf\u00E9'; // U+00E9, precomposed
    const decomposed = 'cafe\u0301'; // "e" + U+0301 combining acute
    expect(composed).not.toBe(decomposed);
    expect(canonicalJson({ note: decomposed })).toBe(canonicalJson({ note: composed }));
  });

  it('drops undefined properties and emits null for a top-level undefined', () => {
    expect(canonicalJson({ a: 1, b: undefined })).toBe(canonicalJson({ a: 1 }));
    expect(canonicalJson(undefined)).toBe('null');
  });

  it('emits parseable JSON', () => {
    expect(JSON.parse(canonicalJson({ b: [1, 'x'], a: null }))).toEqual({ a: null, b: [1, 'x'] });
  });
});

describe('computeItemIdentity — logins with a discriminating key', () => {
  it('uses the documented host/username key shape', async () => {
    const key = await computeItemIdentity(
      login('Google', { username: 'Octo.Cat@Gmail.com', uris: uris('accounts.google.com') }),
    );
    expect(key).toBe(['login', 'accounts.google.com', 'octo.cat@gmail.com'].join(SEP));
  });

  it('keeps ten accounts on one host as ten distinct items', async () => {
    const keys = await Promise.all(
      Array.from({ length: 10 }, (_, i) =>
        computeItemIdentity(
          login('accounts.google.com', {
            username: `user${String(i)}@gmail.com`,
            password: 'pw',
            uris: uris('https://accounts.google.com/signin'),
          }),
        ),
      ),
    );
    expect(new Set(keys).size).toBe(10);
  });

  it('matches the same account across case, www. and title differences', async () => {
    const a = await computeItemIdentity(
      login('Work Google', {
        username: 'Octo.Cat@Gmail.com',
        password: 'old',
        uris: uris('https://WWW.Accounts.Google.com/signin?hl=en'),
      }),
    );
    const b = await computeItemIdentity(
      login('accounts.google.com', {
        username: ' octo.cat@gmail.com ',
        password: 'old',
        uris: uris('accounts.google.com'),
      }),
    );
    expect(b).toBe(a);
  });

  it('is unchanged by a password change, so overwrite can update in place', async () => {
    const base = { username: 'octocat', uris: uris('https://github.com') };
    const before = await computeItemIdentity(login('GitHub', { ...base, password: 'old' }));
    const after = await computeItemIdentity(login('GitHub', { ...base, password: 'new' }));
    expect(after).toBe(before);
  });

  it('is deterministic across calls', async () => {
    const item = login('GitHub', { username: 'octocat', uris: uris('https://github.com') });
    expect(await computeItemIdentity(item)).toBe(await computeItemIdentity(item));
  });
});

describe('computeItemIdentity — a weak key falls back to exact content', () => {
  const isExactContentKey = (key: string, itemType: string): boolean => {
    const parts = key.split(SEP);
    return parts.length === 2 && parts[0] === itemType && HEX_64.test(parts[1] ?? '');
  };

  it('falls back when a login has a host but no username', async () => {
    const key = await computeItemIdentity(
      login('Amazon', { username: '', password: 'pw', uris: uris('https://amazon.com') }),
    );
    expect(isExactContentKey(key, 'login')).toBe(true);
  });

  it('falls back when a login has a username but no resolvable host', async () => {
    const key = await computeItemIdentity(
      login('Router', { username: 'admin', password: 'pw', uris: uris('mailto:a@b.com') }),
    );
    expect(isExactContentKey(key, 'login')).toBe(true);
  });

  it('falls back when a login has neither', async () => {
    const key = await computeItemIdentity(login('Loose login', { password: 'pw' }));
    expect(isExactContentKey(key, 'login')).toBe(true);
  });

  it('never merges two account-less entries on one host that differ in content', async () => {
    const one = await computeItemIdentity(
      login('Amazon', { password: 'first', uris: uris('https://amazon.com') }),
    );
    const two = await computeItemIdentity(
      login('Amazon', { password: 'second', uris: uris('https://amazon.com') }),
    );
    expect(two).not.toBe(one);
  });

  it('still matches two byte-identical account-less entries', async () => {
    const data = (): Data => ({ password: 'same', uris: uris('https://amazon.com') });
    expect(await computeItemIdentity(login('Amazon', data()))).toBe(
      await computeItemIdentity(login('Amazon', data())),
    );
  });
});

describe('computeItemIdentity — non-login types', () => {
  it('distinguishes two notes with the same name but different content', async () => {
    const a = await computeItemIdentity({
      itemType: 'note',
      name: 'Recovery',
      data: { content: 'first' },
    });
    const b = await computeItemIdentity({
      itemType: 'note',
      name: 'Recovery',
      data: { content: 'second' },
    });
    expect(b).not.toBe(a);
    expect(a.startsWith(`note${SEP}`)).toBe(true);
  });

  it('matches two byte-identical notes', async () => {
    const item = (): Parameters<typeof computeItemIdentity>[0] => ({
      itemType: 'note',
      name: 'Recovery',
      data: { content: 'same' },
    });
    expect(await computeItemIdentity(item())).toBe(await computeItemIdentity(item()));
  });

  it('treats note data key order as irrelevant', async () => {
    const a = await computeItemIdentity({
      itemType: 'note',
      name: 'N',
      data: { content: 'c', format: 'markdown' },
    });
    const b = await computeItemIdentity({
      itemType: 'note',
      name: 'N',
      data: { format: 'markdown', content: 'c' },
    });
    expect(b).toBe(a);
  });

  it('distinguishes two notes with identical content but different names', async () => {
    const a = await computeItemIdentity({ itemType: 'note', name: 'A', data: { content: 'c' } });
    const b = await computeItemIdentity({ itemType: 'note', name: 'B', data: { content: 'c' } });
    expect(b).not.toBe(a);
  });

  it('never matches across item types', async () => {
    const noteKey = await computeItemIdentity({ itemType: 'note', name: 'X', data: {} });
    const secretKey = await computeItemIdentity({ itemType: 'secret', name: 'X', data: {} });
    expect(secretKey).not.toBe(noteKey);
    expect(noteKey.startsWith(`note${SEP}`)).toBe(true);
    expect(secretKey.startsWith(`secret${SEP}`)).toBe(true);
  });
});

describe('computeItemIdentity — identity is computed over schema-validated data', () => {
  it('gives a raw parser row and its stored (schema-transformed) form the same key', async () => {
    // A login with no username takes the exact-content path, which is exactly
    // where a pre- vs post-validation difference silently breaks idempotency:
    // the source row carries `amazon.com`, the stored item `https://amazon.com`.
    const raw: Data = { password: 'pw', uris: uris('amazon.com') };
    const parsed = stored('login', raw);

    // Guard against a vacuous pass: the two objects must really differ.
    expect(parsed).not.toEqual(raw);

    expect(await computeItemIdentity(login('Amazon', parsed))).toBe(
      await computeItemIdentity(login('Amazon', raw)),
    );
  });

  it('holds for a non-login type whose schema fills defaults', async () => {
    const raw: Data = { number: '4111111111111111' };
    const parsed = stored('card', raw);
    expect(parsed).not.toEqual(raw);

    expect(await computeItemIdentity({ itemType: 'card', name: 'Visa', data: parsed })).toBe(
      await computeItemIdentity({ itemType: 'card', name: 'Visa', data: raw }),
    );
  });

  it('holds for a login on the logical key path too', async () => {
    const raw: Data = { username: 'octocat', password: 'pw', uris: uris('github.com') };
    expect(await computeItemIdentity(login('GitHub', stored('login', raw)))).toBe(
      await computeItemIdentity(login('GitHub', raw)),
    );
  });

  it('still derives the logical key from raw data the schema rejected', async () => {
    // Bare-string URIs fail `uriEntrySchema`, so the raw object is what gets
    // read — the host must still be recovered rather than the item silently
    // dropping to exact-content matching.
    const raw: Data = { username: 'octocat', password: 'pw', uris: ['github.com'] };
    expect(vaultItemDataSchemas.login.safeParse(raw).success).toBe(false);

    expect(await computeItemIdentity(login('GitHub', raw))).toBe(
      ['login', 'github.com', 'octocat'].join(SEP),
    );
  });

  it('still produces a stable key when the data fails validation', async () => {
    // A username over the 500-char cap: the schema rejects it, so the raw object
    // is hashed rather than the item being left without an identity.
    const bad = (): Data => ({ username: 'x'.repeat(600), password: 'pw' });
    expect(vaultItemDataSchemas.login.safeParse(bad()).success).toBe(false);

    const key = await computeItemIdentity(login('Broken', bad()));
    expect(key).toBe(await computeItemIdentity(login('Broken', bad())));
    expect(key.startsWith(`login${SEP}`)).toBe(true);
  });
});
