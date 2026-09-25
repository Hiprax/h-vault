// @vitest-environment node
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * The API's error envelope is FLAT, and no client module may read it as nested.
 *
 * ## The defect this exists to stop coming back
 *
 * `createErrorMiddleware` (`@hiprax/errors`, mounted at `server/src/app.ts`)
 * writes exactly one refusal shape:
 *
 *     { success: false, message, statusCode, statusText }
 *
 * `message` carries the machine-readable `ERROR_CODES` constant. There is no
 * `error` object on the wire and there never has been — but `ApiResponse` and
 * `PaginatedResponse` still DECLARE a nested `error: { code, message }`, so the
 * wrong read type-checks, lints clean, and is one autocomplete away at every
 * call site.
 *
 * `authStore.verify2fa` made that read. `response.data.error.code` was always
 * `undefined`, so its classification always came out "retryable", so its MEK
 * teardown was unreachable for every Axios failure: a dead 2FA session left the
 * master-password-derived key resident until the five-minute abandon timer. The
 * three tests covering it fabricated the nested body, which is why nothing went
 * red for as long as it shipped.
 *
 * Neither the type system nor the linter can catch that — `data` is `any`, and
 * the nested field exists in the declared type. A source-graph assertion is the
 * only thing that fires on the edit itself, so this is the same one-definition
 * discipline `sandbox-boundary.test.ts` applies to `qr`: one place decides
 * (`services/auth/sessionFailure.ts`), and it reads `data.message`.
 *
 * ## What is deliberately NOT flagged
 *
 * `.data.error` on anything that is not an HTTP response body — a domain object
 * with an `error` field, a `Result`-shaped value — would be a false positive, so
 * the pattern is anchored on the property chain rather than on the identifier:
 * only a `data` (optionally through a cast) whose very next property access is
 * `error` is reported. `errors`, `errorCode` and `errorMessage` are untouched,
 * because the boundary is `\berror\b`.
 *
 * ## What it therefore CANNOT see, stated rather than implied
 *
 * Anchoring on the chain means two spellings escape by construction, and a guard
 * that does not say where it stops is one a reader will over-trust:
 *
 *  - indirection through a local — `const body = err.response?.data;` and then
 *    `body?.error?.code` — because the second line has no `data` in it;
 *  - destructuring — `const { error } = response.data;` — for the same reason.
 *
 * Widening to either would mean tracking an identifier across statements, which
 * is a type-aware analysis rather than a pattern, and both spellings would be a
 * deliberate detour rather than the autocomplete this exists to catch. The
 * spelling that IS one keystroke away is `response.data.error`, and it is
 * covered — including after `npm run format` has wrapped it, which is the gap
 * this guard shipped with.
 */

const clientRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const srcDir = path.join(clientRoot, 'src');

/** Every `.ts`/`.tsx` file under a directory. */
function sourceFiles(dir: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(dir)) {
    const absolute = path.join(dir, entry);
    if (statSync(absolute).isDirectory()) {
      found.push(...sourceFiles(absolute));
      continue;
    }
    if (entry.endsWith('.ts') || entry.endsWith('.tsx')) found.push(absolute);
  }
  return found;
}

/**
 * Source with comments blanked, so a docblock that NAMES the forbidden read (as
 * several deliberately do, including the one above) is not itself a violation.
 *
 * Every removed character is replaced by a SPACE rather than by nothing, and the
 * newlines inside a block comment are kept. Deleting them collapsed the file, so
 * every `file:line` this test reported after the first docblock named a line that
 * was not the one at fault — in a codebase this comment-dense, usually by
 * hundreds. Blanking preserves both the line and the column.
 *
 * The line-comment strip requires the `//` not to be preceded by `:`, so a URL
 * in a string literal (`otpauth://`, `https://`) does not swallow the rest of
 * its line and hide a real violation sitting after it.
 */
function withoutComments(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, (comment) => comment.replace(/[^\n]/g, ' '))
    .replace(/(^|[^:])\/\/.*$/gm, (_match, before: string) => before);
}

/**
 * A `data` — bare, optional-chained, or reached through a cast — whose next
 * property access is `error`, in dot or bracket form.
 *
 * Matches `res.data.error`, `error.response?.data?.error`,
 * `(err.response?.data as Record<string, unknown> | undefined)?.error`,
 * `data['error']`, and — the spelling that matters most — any of those broken
 * across two lines by Prettier.
 *
 * ## Why the cast body stops at a newline and the rest does not
 *
 * `[^)\n]*` for the `as` clause, so a cast can never run past the end of its own
 * line looking for a closing paren several statements away; the surrounding
 * `\s*` runs deliberately DO cross newlines, because that is where
 * `printWidth: 100` actually breaks this expression:
 *
 * ```ts
 * const serverMessage: unknown = (error.response?.data as Record<string, unknown> | undefined)
 *   ?.message;
 * ```
 *
 * That exact shape is already in the tree at `src/lib/utils.ts`, for `?.message`.
 * Its `?.error` twin is therefore not a hypothetical spelling but the one a
 * reintroduction would take after a single `npm run format`.
 */
const NESTED_ENVELOPE_READ =
  /\bdata\b(?:\s+as\s+[^)\n]*)?\s*\)?\s*\??\s*(?:\.\s*error\b|\[\s*['"]error['"]\s*\])/g;

/**
 * Whether `source` — one line, one file, or anything in between — makes the read.
 *
 * Shared by the recognition table and the file scan below so the two
 * cannot be testing two different things, which is precisely how the line-by-line
 * scan survived: its table only ever fed it single lines.
 */
function matchesNestedEnvelopeRead(source: string): boolean {
  // `NESTED_ENVELOPE_READ` is global, so it carries `lastIndex` between calls.
  NESTED_ENVELOPE_READ.lastIndex = 0;
  return NESTED_ENVELOPE_READ.test(source);
}

/**
 * `file:line` for every forbidden read in `file`.
 *
 * Scans the WHOLE comment-stripped text rather than each line in turn, and
 * derives the line number from `match.index`. A per-line scan cannot see an
 * expression Prettier has wrapped, which is the formatting this repository
 * enforces on every commit.
 */
function violations(file: string): string[] {
  const relative = path.relative(clientRoot, file);
  const source = withoutComments(readFileSync(file, 'utf8'));
  NESTED_ENVELOPE_READ.lastIndex = 0;
  return [...source.matchAll(NESTED_ENVELOPE_READ)].map((match) => {
    const line = source.slice(0, match.index).split('\n').length;
    return `${relative}:${String(line)} ${match[0].replace(/\s+/g, ' ').trim()}`;
  });
}

describe('the client never reads the nested error envelope', () => {
  it('finds files to scan at all', () => {
    // Guards the guard: a moved `src/` or a broken walker would make every
    // assertion below pass vacuously, which is exactly the failure mode this
    // whole file exists to prevent.
    // 182 files at the time of writing; the floor is a broken-walker tripwire,
    // not a census, so it sits well below that and does not need maintaining.
    const files = sourceFiles(srcDir);
    expect(files.length).toBeGreaterThan(150);
    expect(files.some((f) => f.endsWith(path.join('stores', 'authStore.ts')))).toBe(true);
  });

  it('no module under src/ reads `response.data.error`', () => {
    const found = sourceFiles(srcDir).flatMap(violations);
    expect(found).toEqual([]);
  });

  it('the pattern actually recognises the read it forbids', () => {
    // Red-before-green for the guard itself: if this ever passes vacuously, the
    // assertion above is decoration. Every spelling here is one a future edit
    // could plausibly reach for, including the exact line `verify2fa` shipped.
    for (const spelling of [
      'const code = response.data.error.code;',
      'const code = err.response?.data?.error?.code;',
      'const errorCode = (error.response?.data as Record<string, unknown> | undefined)?.error;',
      "const code = data['error'];",
      // The spelling Prettier PRODUCES. `printWidth: 100` breaks that cast after
      // the closing paren — `src/lib/utils.ts:65-66` already carries the
      // `?.message` twin — so this is the shape a reintroduction would actually
      // take in this codebase, and a scanner that reads one line at a time
      // cannot see it.
      'const c: unknown = (error.response?.data as Record<string, unknown> | undefined)\n  ?.error;',
    ]) {
      expect(matchesNestedEnvelopeRead(spelling)).toBe(true);
    }
  });

  it('the pattern leaves the legitimate reads alone', () => {
    // The flat envelope, the `data` payload of a SUCCESS response, and any
    // identifier that merely starts with `error`.
    for (const spelling of [
      'const message = (error.response?.data as Record<string, unknown> | undefined)?.message;',
      'const items = response.data.data.items;',
      'const code = response.data.errorCode;',
      'const list = response.data.errors;',
      'items.push({ ...item, data: result.data as Record<string, unknown> });',
      // The wrapped shape of a LEGITIMATE read. Scanning whole files rather than
      // single lines is what makes this one worth pinning: the cast body is
      // bounded to its own line precisely so this cannot run forward to a `)`
      // several statements away and find an unrelated `?.error` behind it.
      'const m: unknown = (error.response?.data as Record<string, unknown> | undefined)\n  ?.message;',
    ]) {
      expect(matchesNestedEnvelopeRead(spelling)).toBe(false);
    }
  });

  it('the SCANNER sees a wrapped read in a real file, not just the pattern', () => {
    // The gap the per-line scan actually left. Asserting the regex alone was not
    // enough: the regex was always capable of matching across a newline, and the
    // scanner never handed it one. This drives `violations()` — the function the
    // guard assertion above calls — over a file on disk, so the two can never
    // diverge again.
    const scratch = mkdtempSync(path.join(tmpdir(), 'envelope-guard-'));
    try {
      const file = path.join(scratch, 'wrapped.ts');
      writeFileSync(
        file,
        [
          '/**',
          ' * A docblock naming response.data.error, which must NOT count.',
          ' */',
          'export function read(error: unknown): unknown {',
          '  const code: unknown = (error.response?.data as Record<string, unknown> | undefined)',
          '    ?.error;',
          '  return code;',
          '}',
          '',
        ].join('\n'),
        'utf8',
      );

      const found = violations(file);

      expect(found).toHaveLength(1);
      // The line number is the one a human would point at — proof that blanking
      // comments rather than deleting them kept the offsets honest. The docblock
      // above occupies lines 1-3 and contributes nothing.
      expect(found[0]).toMatch(/wrapped\.ts:5 /);
      // And the docblock really was scanned and really was ignored: exactly one
      // finding, from the code, never from the prose describing it.
      expect(found[0]).not.toMatch(/docblock/);
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });
});
