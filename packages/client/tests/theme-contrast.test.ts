/**
 * Dark-theme readability of the palette classes the light theme darkens.
 *
 * ## The defect this exists to catch
 *
 * Tailwind's `700`/`800`/`900` text shades are chosen for a LIGHT surface. The
 * dark theme paints on `--card: 222.2 84% 4.9%` (near-black, `#020817`), where
 * those same shades collapse: `text-green-800` (`#166534`) measures 2.80:1 there
 * and `text-yellow-800` (`#854d0e`) 2.92:1, against the 4.5:1 WCAG 1.4.3 floor
 * for text under 18pt. The `400` shades that belong on that surface measure
 * 11.5:1 and 13.1:1.
 *
 * So a class at one of those shades is only safe when the SAME class string also
 * carries a `dark:text-` override. Every one of them in this application does —
 * that is the invariant, and it was breached exactly once, by an accessibility
 * fix. Raising the sidebar's status text from `text-green-600` to
 * `text-green-800` repaired a real 2.92:1 light-theme failure and was written
 * with its `dark:text-green-400` partner; the identical repair to the settings
 * page's "Email Verified" status was written without one, which took that text
 * from 6.07:1 to 2.80:1 in the theme it did not measure. The change made the
 * light theme pass and the dark theme fail harder than the light theme ever had.
 *
 * ## Why this is a source assertion rather than a rendered one
 *
 * The application's own accessibility gate (`test:a11y`, axe over fifteen views)
 * runs one theme: Playwright's default colour scheme is `light` and the walk
 * does not override it, so it is structurally blind to this. jsdom cannot help
 * either — it performs no layout and computes no colour, so a rendered
 * assertion in this package could only inspect the same class string this file
 * reads, with a browser's worth of setup in front of it. The honest form is to
 * read the source, state the rule, and say plainly what it does not prove: this
 * checks that a dark-mode override EXISTS, never that the colour it names is the
 * right one.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative, resolve } from 'node:path';
import { describe, it, expect } from 'vitest';

// Anchored on this module, never on `process.cwd()`: the suite is run both as
// `npm run test -w packages/client` and as `vitest --root packages/client` from
// the repository root, and a cwd-relative path resolves differently under the
// two.
const clientRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const srcDir = join(clientRoot, 'src');

/**
 * The shades that are unreadable on the dark theme's surfaces.
 *
 * `600` and lighter are excluded deliberately: they are the shades that pass on
 * near-black and fail on white, which is the opposite defect and the one the
 * accessibility phase was fixing. Listing the palette explicitly rather than
 * matching `text-\w+-800` keeps `text-card-foreground` and friends out.
 */
const DARK_UNREADABLE_SHADE =
  /\btext-(?:slate|gray|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)-(?:700|800|900)\b/g;

interface Occurrence {
  readonly file: string;
  readonly line: number;
  readonly className: string;
  readonly shade: string;
  readonly hasDarkOverride: boolean;
}

/** Every `.ts`/`.tsx` file under `packages/client/src`. */
function sourceFiles(dir: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) found.push(...sourceFiles(full));
    else if (/\.tsx?$/.test(full)) found.push(full);
  }
  return found;
}

/**
 * Extracts the quoted run a match sits inside, bounded by its own LINE.
 *
 * Deliberately local rather than a scan of the file's string literals. A
 * whole-file literal scanner desynchronises on the first apostrophe in a
 * comment — `the card's white surface` opens a string that swallows everything
 * to the next quote — and the first version of this check did exactly that,
 * reporting a clean tree while the defect below sat in it. A class utility
 * always lives inside a quoted string on one line (a JavaScript string literal
 * cannot contain a raw newline, and Prettier cannot break one), so the nearest
 * quote to the left and the next of the same kind to the right are its real
 * delimiters, and nothing that happens elsewhere in the file can move them.
 */
function enclosingClassName(line: string, at: number): string | null {
  const before = line.slice(0, at);
  const open = Math.max(before.lastIndexOf("'"), before.lastIndexOf('"'), before.lastIndexOf('`'));
  if (open < 0) return null;
  // `charAt`, not `line[open]`: the index is provably in range (it came from a
  // `lastIndexOf` on a prefix of this same line), but `noUncheckedIndexedAccess`
  // types the subscript as `string | undefined` and this package's test config
  // inherits that strictness deliberately. `charAt` is total, so the fact is
  // expressed in the type system rather than asserted past it.
  const quote = line.charAt(open);
  const close = line.indexOf(quote, at);
  return line.slice(open + 1, close < 0 ? line.length : close);
}

/** Every occurrence of a dark-unreadable shade, with whether it is overridden. */
function collectOccurrences(): Occurrence[] {
  const occurrences: Occurrence[] = [];
  for (const file of sourceFiles(srcDir)) {
    const lines = readFileSync(file, 'utf8').split('\n');
    lines.forEach((line, index) => {
      DARK_UNREADABLE_SHADE.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = DARK_UNREADABLE_SHADE.exec(line)) !== null) {
        const className = enclosingClassName(line, match.index);
        if (className === null) continue;
        occurrences.push({
          file: relative(clientRoot, file),
          line: index + 1,
          className,
          shade: match[0],
          hasDarkOverride: /dark:text-/.test(className),
        });
      }
    });
  }
  return occurrences;
}

describe('dark-theme text contrast', () => {
  const occurrences = collectOccurrences();

  it('pairs every dark-unreadable text shade with a dark-mode override', () => {
    const unpaired = occurrences
      .filter((occurrence) => !occurrence.hasDarkOverride)
      .map(
        (occurrence) =>
          `${occurrence.file}:${String(occurrence.line)} — ${occurrence.shade} in "${occurrence.className}" has no dark:text-* override`,
      );
    expect(unpaired).toEqual([]);
  });

  it('actually scanned the application, so a clean result means something', () => {
    // The lesson the accessibility gate records in its own words: a scan over
    // NOTHING reports zero violations, exactly like a scan over a clean tree. A
    // broken walker, a renamed directory or a regex that stopped matching would
    // all turn the assertion above green while checking nothing at all.
    expect(sourceFiles(srcDir).length).toBeGreaterThan(50);
    expect(occurrences.length).toBeGreaterThan(20);
    // A known-good pairing must be among them: the sidebar's connectivity
    // indicator, which is the fix the settings page's status was supposed to
    // mirror.
    expect(
      occurrences.some(
        (occurrence) =>
          occurrence.file === 'src/components/layout/AppLayout.tsx' &&
          occurrence.className.includes('text-green-800') &&
          occurrence.hasDarkOverride,
      ),
    ).toBe(true);
  });

  it('detects an unpaired shade, and is not fooled by one paired on the same line', () => {
    // The checker's own red/green, on strings rather than on the tree — so the
    // rule keeps its teeth on the day the tree is clean and every other
    // assertion here would pass whatever the extractor did.
    const paired = `className={cn('text-green-800 dark:text-green-400')}`;
    const unpaired = `className={cn('text-green-800')}`;
    const indexOf = (line: string): number => line.indexOf('text-green-800');

    expect(enclosingClassName(paired, indexOf(paired))).toBe('text-green-800 dark:text-green-400');
    expect(enclosingClassName(unpaired, indexOf(unpaired))).toBe('text-green-800');
    // A ternary puts two independent class strings on one line: each arm is its
    // own literal and each needs its own override. Reading past the arm's
    // closing quote would let the first arm's override excuse the second's
    // absence — the exact shape of the defect this file was written for.
    const ternary = `cond ? 'text-green-800 dark:text-green-400' : 'text-yellow-800'`;
    expect(enclosingClassName(ternary, ternary.indexOf('text-yellow-800'))).toBe('text-yellow-800');
  });
});
