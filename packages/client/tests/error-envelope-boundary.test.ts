// @vitest-environment node
import { readFileSync, readdirSync, statSync } from 'node:fs';
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
 * Source with comments removed, so a docblock that NAMES the forbidden read (as
 * several deliberately do, including the one above) is not itself a violation.
 *
 * The line-comment strip requires the `//` not to be preceded by `:`, so a URL
 * in a string literal (`otpauth://`, `https://`) does not swallow the rest of
 * its line and hide a real violation sitting after it.
 */
function withoutComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
}

/**
 * A `data` — bare, optional-chained, or reached through a cast — whose next
 * property access is `error`, in dot or bracket form.
 *
 * Matches `res.data.error`, `error.response?.data?.error`,
 * `(err.response?.data as Record<string, unknown> | undefined)?.error` and
 * `data['error']`.
 */
const NESTED_ENVELOPE_READ =
  /\bdata\b(?:\s+as\s+[^)]*)?\)?\s*\??\s*(?:\.\s*error\b|\[\s*['"]error['"]\s*\])/;

/** `file:line` for every line of `file` that makes the forbidden read. */
function violations(file: string): string[] {
  const relative = path.relative(clientRoot, file);
  return withoutComments(readFileSync(file, 'utf8'))
    .split('\n')
    .flatMap((line, index) =>
      NESTED_ENVELOPE_READ.test(line) ? [`${relative}:${String(index + 1)} ${line.trim()}`] : [],
    );
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
    ]) {
      expect(NESTED_ENVELOPE_READ.test(spelling)).toBe(true);
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
    ]) {
      expect(NESTED_ENVELOPE_READ.test(spelling)).toBe(false);
    }
  });
});
