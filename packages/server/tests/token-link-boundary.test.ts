import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * No one-time token ever rides in a query string (F-27), and the four token links
 * are built in ONE place.
 *
 * A query string is part of the request line that both Nginx tiers write to their
 * access logs (`$request_uri`, `$request`), and a browser forwards it in `Referer`.
 * A verification, reset, unlock or recipient-confirmation JWT there is a working
 * credential in a log file for as long as it is valid. The fragment is never sent to
 * any server, so `utils/email.ts` `tokenLink(path, token)` is the ONE builder, and
 * its output is `${APP_URL}${path}#token=…`; the pages read it from `location.hash`.
 *
 * `email.test.ts` pins each link's exact shape. This file pins the CLASS: no module
 * under `src/` spells a token parameter into a query (`?token=`, `&token=`, the
 * same for `invite`, or `searchParams.set('token', …)`), and each of the four page
 * paths is named only where it is handed to `tokenLink`, so a fifth sender that
 * rebuilt the URL by hand would be caught before it shipped.
 *
 * What it cannot see, stated: a token URL assembled from pieces none of which
 * names the parameter or the page (a parameter name or a path held in a constant
 * or in configuration, say), and, because comments are stripped by pattern rather
 * than by a parser, a line on which a string holds `//` not preceded by `:` is
 * blanked after that point. Those are deliberate detours, not the one-keystroke
 * template this exists to stop.
 */

const serverRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const srcDir = path.join(serverRoot, 'src');

/** Every `.ts` file under a directory. */
function sourceFiles(dir: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(dir)) {
    const absolute = path.join(dir, entry);
    if (statSync(absolute).isDirectory()) {
      found.push(...sourceFiles(absolute));
      continue;
    }
    if (entry.endsWith('.ts')) found.push(absolute);
  }
  return found;
}

/**
 * Source with comments blanked (same length, newlines kept), so a docblock that
 * NAMES the forbidden spelling is not a violation and every reported line is the
 * real one. A `//` preceded by `:` is a URL scheme, not a comment.
 */
function withoutComments(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, (comment) => comment.replace(/[^\n]/g, ' '))
    .replace(/(^|[^:])\/\/.*$/gm, (_match, before: string) => before);
}

/** A token parameter written into a query string, in any of the spellings code reaches for. */
const QUERY_TOKEN =
  /[?&](?:token|invite)=|searchParams\s*\.\s*(?:set|append)\(\s*['"`](?:token|invite)['"`]|URLSearchParams\(\s*\{[^}]*\b(?:token|invite)\b|querystring\s*\.\s*stringify\(\s*\{[^}]*\b(?:token|invite)\b/g;

/** The four application pages a one-time token opens. */
const TOKEN_PAGES = [
  '/verify-email',
  '/reset-password',
  '/unlock-account',
  '/backup/confirm-recipient',
];

/**
 * An occurrence of a token page as a URL path: a whole string literal, or the
 * text straight after `APP_URL}` in a template. The API routes (`/auth/verify-email`
 * in the OpenAPI document) are different strings and are not matched.
 */
function pageMentions(source: string, page: string): number[] {
  const escaped = page.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
  const pattern = new RegExp(`(['"\`])${escaped}\\1|APP_URL\\}${escaped}\\b|\`${escaped}[?#]`, 'g');
  return [...source.matchAll(pattern)].map((m) => m.index);
}

/** `file:line text` for a match. */
function located(file: string, source: string, index: number, text: string): string {
  const line = source.slice(0, index).split('\n').length;
  return `${path.relative(serverRoot, file)}:${String(line)} ${text.replace(/\s+/g, ' ').trim()}`;
}

function queryTokenViolations(file: string): string[] {
  const source = withoutComments(readFileSync(file, 'utf8'));
  QUERY_TOKEN.lastIndex = 0;
  return [...source.matchAll(QUERY_TOKEN)].map((m) => located(file, source, m.index, m[0]));
}

/**
 * Each mention of a token page must be the first argument of `tokenLink(`, either
 * directly or through a module constant that is itself passed to `tokenLink(`.
 */
function pageViolations(file: string): string[] {
  return pageViolationsIn(withoutComments(readFileSync(file, 'utf8')), file);
}

/** {@link pageViolations} over already comment-stripped `source`. */
function pageViolationsIn(source: string, file = path.join(srcDir, 'inline.ts')): string[] {
  const found: string[] = [];
  for (const page of TOKEN_PAGES) {
    for (const index of pageMentions(source, page)) {
      const before = source.slice(Math.max(0, index - 40), index);
      if (/tokenLink\(\s*$/.test(before)) continue;
      // The API routes the pages POST to (`router.post('/verify-email', …)` under
      // `/api/v1/auth`) share the tail but are not links.
      if (/router\s*\.\s*(?:get|post|put|patch|delete)\(\s*$/.test(before)) continue;
      const constant = /const\s+(\w+)\s*=\s*$/.exec(source.slice(Math.max(0, index - 80), index));
      if (constant && new RegExp(`tokenLink\\(\\s*${constant[1]!}\\b`).test(source)) continue;
      found.push(located(file, source, index, source.slice(index, index + page.length + 2)));
    }
  }
  return found;
}

describe('one-time tokens never enter a query string', () => {
  it('finds the server sources to scan', () => {
    const files = sourceFiles(srcDir);
    expect(files.length).toBeGreaterThan(80);
    expect(files).toContain(path.join(srcDir, 'utils', 'email.ts'));
  });

  it('no server module writes a token or invite parameter into a query string', () => {
    expect(sourceFiles(srcDir).flatMap(queryTokenViolations)).toEqual([]);
  });

  it('utils/email.ts contains no `?token=` at all, and writes `#token=` exactly once, in tokenLink', () => {
    const file = path.join(srcDir, 'utils', 'email.ts');
    const source = withoutComments(readFileSync(file, 'utf8'));

    expect(source).not.toContain('?token=');
    const fragments = [...source.matchAll(/#token=/g)];
    expect(fragments).toHaveLength(1);
    // The builder's body: from its signature to the closing brace at column 0.
    const start = source.indexOf('export function tokenLink(');
    const end = source.indexOf('\n}\n', start);
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    const at = fragments[0]!.index;
    expect(at).toBeGreaterThan(start);
    expect(at).toBeLessThan(end);
  });

  it('names each token page only where it is handed to tokenLink', () => {
    const files = sourceFiles(srcDir);
    expect(files.flatMap(pageViolations)).toEqual([]);
    // And every page IS linked from somewhere: a page nothing links to would make
    // the assertion above pass over nothing.
    const everything = files.map((f) => withoutComments(readFileSync(f, 'utf8'))).join('\n');
    for (const page of TOKEN_PAGES) {
      expect(pageMentions(everything, page).length, page).toBeGreaterThan(0);
    }
  });

  it('the patterns recognise the spellings they forbid, and pass the ones they allow', () => {
    const query = (text: string): boolean => {
      QUERY_TOKEN.lastIndex = 0;
      return QUERY_TOKEN.test(text);
    };
    // Forbidden: every shape a hand-built link or a helper could take.
    expect(
      query('const u = `${config.APP_URL}/verify-email?token=${encodeURIComponent(t)}`;'),
    ).toBe(true);
    expect(query("const u = base + '&token=' + t;")).toBe(true);
    expect(query('url.searchParams.set("token", t);')).toBe(true);
    expect(query("url.searchParams.append('invite', t);")).toBe(true);
    expect(query('const q = new URLSearchParams({ token });')).toBe(true);
    expect(query('const q = new URLSearchParams({ email, token: t });')).toBe(true);
    expect(query('const q = querystring.stringify({ token: t });')).toBe(true);
    // Allowed: the fragment form and an unrelated query parameter.
    expect(query('return `${config.APP_URL}${path}#token=${encodeURIComponent(token)}`;')).toBe(
      false,
    );
    expect(query('`${base}/items?page=2&limit=50`')).toBe(false);

    // Page mentions: a hand-built link is caught; `tokenLink('/…'` and a constant
    // passed to it are not; an API route with the same tail is not a page.
    const pages = (text: string): number => pageMentions(text, '/reset-password').length;
    expect(pages('const u = `${config.APP_URL}/reset-password#token=${t}`;')).toBe(1);
    expect(pages("const u = tokenLink('/reset-password', t);")).toBe(1);
    expect(pages("'/auth/reset-password': { post: {} }")).toBe(0);
    expect(pages('const u = `/reset-password#token=${t}`;')).toBe(1);
    expect(pageViolationsIn("router.post('/reset-password', handler);")).toEqual([]);
    expect(
      pageViolationsIn('const u = `${config.APP_URL}/reset-password#token=${t}`;'),
    ).toHaveLength(1);
    expect(pageViolationsIn("const P = '/reset-password';\nconst u = tokenLink(P, t);")).toEqual(
      [],
    );
    expect(pageViolationsIn("const P = '/reset-password';\nconst u = `${base}${P}`;")).toHaveLength(
      1,
    );
    expect(withoutComments('// see ?token= in the old links\nconst a = 1;')).not.toContain(
      '?token=',
    );
  });
});
