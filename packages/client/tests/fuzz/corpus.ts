/**
 * The committed fuzz corpus: hostile import files, kept as bytes on disk.
 *
 * A generated property draws a fresh sample every run; a corpus entry is a
 * specific input somebody decided was worth keeping forever. The two do
 * different jobs and this suite uses both:
 *
 *   - `parsers.fuzz.test.ts` runs EVERY entry through EVERY parser, because a
 *     user picks the format from a dropdown and can pick the wrong one. A
 *     Bitwarden JSON file handed to the KeePass parser is an ordinary mistake,
 *     not an attack, and it must still land on the contract: valid items, or a
 *     typed `ImportParseError`.
 *   - each entry that came from an observed crash is ALSO pinned by its own
 *     named regression test, so the reason it exists survives the file.
 *
 * Two deliberate omissions, both stated rather than left to be noticed:
 *
 *   1. The million-column row and the repeated-row bomb are GENERATED in the
 *      test rather than committed. At roughly 8 MB and 3 MB they would be the
 *      two largest files in the repository, no reviewer could read either, and
 *      generation is exact — `'v,'.repeat(n)` has no ambiguity a fixture would
 *      resolve.
 *   2. Nothing here is minimized by a tool. Each file is hand-written down to
 *      the smallest input that still reproduces what it is named for, which is
 *      what makes it readable in a diff five years from now.
 *
 * The files are read through `readCorpus`, which anchors on this module's own
 * URL. Resolving from `process.cwd()` is the defect this repository already
 * hit once: the suite passed under `npm run test -w packages/client` and failed
 * with a misleading ENOENT under `npx vitest --root packages/client` from the
 * repository root.
 *
 * `.gitattributes` marks this directory `-text` and `.prettierignore` excludes
 * it. Both are load-bearing: the blanket `* text=auto eol=lf` would rewrite the
 * CRLF and bare-CR terminators that `bom-crlf-lf.csv` exists to exercise, and
 * Prettier cannot even parse `bitwarden-truncated.json` — which is the point of
 * that file.
 */
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ImportSourceFormat } from '../../src/services/import';

const CORPUS_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'corpus');

/** The parsers a corpus entry is run through: every non-native format. */
export const FUZZ_FORMATS: readonly Exclude<ImportSourceFormat, 'json'>[] = [
  'bitwarden',
  'lastpass',
  'keepass',
  'chrome',
  'firefox',
  'onepassword',
  'csv',
] as const;

export interface CorpusEntry {
  /** File name inside `tests/fuzz/corpus/`. */
  file: string;
  /** The parser it was written against. It is still run through all of them. */
  origin: Exclude<ImportSourceFormat, 'json'>;
  /** What this input is for — the sentence a reviewer needs and the file cannot carry. */
  why: string;
  /**
   * Set only on an entry that DELIBERATELY violates clause 2 of the parser
   * contract because of a recorded, deferred defect.
   *
   * The value is the exhaustive list of `vaultItemDataSchemas` paths that may
   * fail for it. The corpus loop still runs the entry and still asserts the
   * other clauses; it just checks the failures against this list instead of
   * requiring none — so an ELEVENTH field joining the defect turns the run red
   * rather than hiding inside a blanket exemption.
   */
  knownInvalidPaths?: readonly string[];
}

export const CORPUS: readonly CorpusEntry[] = [
  {
    file: 'empty.csv',
    origin: 'chrome',
    why: 'A zero-byte file. The tokenizer must produce no rows rather than one empty row, and no parser may index into a header list that does not exist.',
  },
  {
    file: 'bom-crlf-lf.csv',
    origin: 'chrome',
    why: 'A UTF-8 BOM followed by CRLF, LF and a bare CR as row terminators, and a final row with no terminator at all. Every one of those four shapes appears in a real browser export.',
  },
  {
    file: 'duplicate-headers.csv',
    origin: 'chrome',
    why: 'The same header name four times over. Records are built by assignment, so a later column silently wins; the contract is only that the result is a valid item, never which duplicate is kept.',
  },
  {
    file: 'ragged-blank-rows.csv',
    origin: 'chrome',
    why: 'Rows shorter and longer than the header, an all-empty row, and blank lines between records — the shape a hand-edited export has.',
  },
  {
    file: 'quote-chaos.csv',
    origin: 'keepass',
    why: 'Doubled quotes, a comma and a newline inside quoted fields, and an unterminated quote that swallows the rest of the file. The unterminated case is the one that used to be a whole-file abort in naive tokenizers.',
  },
  {
    file: 'unicode-surrogates.csv',
    origin: 'firefox',
    why: "A lone high surrogate, a lone low surrogate, an embedded NUL, an RTL override, a combining-mark stack and an astral-plane pair. Names and usernames reach `normalize('NFC')` and the identity hash, so an unpaired surrogate must not throw there.",
  },
  {
    file: 'header-edge.csv',
    origin: 'onepassword',
    why: "Headers named `__proto__`, `constructor` and `toString`, plus an empty and a whitespace-only header. Records are plain objects, so `record['__proto__'] = value' resolves to the inherited accessor and the cell reads back as an object rather than a string.",
  },
  {
    file: 'one-past-bounds.csv',
    origin: 'lastpass',
    why: 'Every bound a CSV path can reach, exceeded by exactly one character in one row: the URI cap (measured before the scheme the schema prepends), username, password, TOTP, notes, the display name and a tag. Each has a clamp; this is what proves each clamp is still there.',
  },
  {
    file: 'uri-schemes.csv',
    origin: 'keepass',
    why: '`javascript:`, an app scheme, a browser-extension scheme, `mailto:`, protocol-relative, a bare domain, a value padded with spaces, and a backslash in the authority. Only http/https/mailto may survive into `uris`; the rest must be dropped into notes rather than sink the login.',
  },
  {
    file: 'bitwarden-null-item.json',
    origin: 'bitwarden',
    why: 'REGRESSION: `{"items":[null, …]}`. The raw parser dereferences the member and throws a TypeError; the contract is that `parseImportData` converts it into a typed ImportParseError, and that no half-built item escapes.',
  },
  {
    file: 'bitwarden-wrong-types.json',
    origin: 'bitwarden',
    why: 'A number, an array, an object and null in every place the format documents a string, plus an unknown item type and a null `fields` member. Each has to be coerced or ignored — a value of the wrong type must never reach the schema.',
  },
  {
    file: 'bitwarden-scalar-bounds.json',
    origin: 'bitwarden',
    why: 'One character past every card and identity scalar on the JSON path. It witnessed the deferred defect that those eleven were unclamped, and now witnesses the clamp that fixed it: it carries no knownInvalidPaths, so the corpus loop holds it to the unconditional schema clause.',
  },
  {
    file: 'bitwarden-overfull-lists.json',
    origin: 'bitwarden',
    why: 'One login carrying one more URI and one more custom field than an item may hold. Both caps live in the parser, and each is the difference between an item arriving trimmed and the whole login — password included — being discarded at validation.',
  },
  {
    file: 'bitwarden-truncated.json',
    origin: 'bitwarden',
    why: 'A JSON document cut off mid-object — a half-written download. `JSON.parse` throws a SyntaxError, which must reach the user as a typed ImportParseError naming the format.',
  },
  {
    file: 'bitwarden-deep-nesting.json',
    origin: 'bitwarden',
    why: 'Two thousand levels of nesting under a key no parser reads. `JSON.parse` is iterative in V8 so this is not a stack overflow today, but a hand-rolled recursive walk added later would blow the stack on it.',
  },
];

/** The bytes of one corpus entry, verbatim. */
export function readCorpus(file: string): string {
  return readFileSync(path.join(CORPUS_DIR, file), 'utf8');
}

/**
 * What is actually on disk in `corpus/`.
 *
 * Read from the filesystem rather than derived from {@link CORPUS}, so the suite
 * can compare the two in BOTH directions: an entry naming a deleted file fails
 * loudly on its own, but a file dropped into the directory and never listed is
 * SILENT — nothing runs it, and the reason it was added is lost.
 */
export const CORPUS_FILES: readonly string[] = readdirSync(CORPUS_DIR);
