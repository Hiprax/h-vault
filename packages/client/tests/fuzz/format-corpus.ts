/**
 * The committed format-and-repair corpus: hostile documents, kept as bytes on
 * disk.
 *
 * A generated property draws a fresh sample every run; a corpus entry is a
 * specific input somebody decided was worth keeping forever. The two do
 * different jobs, and this suite uses a corpus because the inputs that matter
 * here are not random at all — they are the shapes a real editor, a real
 * download and a real half-finished save produce.
 *
 * Every entry is run through EVERY combination of the two transforms, because a
 * user can tick either box for any file the panel offers them for, and through
 * the DECODER first, because a document that is not plain UTF-8 must be refused
 * before any of it reaches a parser.
 *
 * Two deliberate omissions, both stated rather than left to be noticed:
 *
 *   1. The oversized JSON Lines record is GENERATED in the test rather than
 *      committed. At roughly a megabyte it would be the largest file in this
 *      repository, no reviewer could read it, and generation is exact —
 *      `'0,'.repeat(n)` has no ambiguity a fixture would resolve. The same
 *      decision `tests/fuzz/corpus.ts` records for the million-column row.
 *   2. Nothing here is minimized by a tool. Each file is hand-written down to
 *      the smallest input that still reproduces what it is named for, which is
 *      what makes it readable in a diff five years from now.
 *
 * The files are read through {@link readFormatCorpus}, which anchors on this
 * module's own URL. Resolving from `process.cwd()` is the defect this repository
 * already hit once: a suite passed under `npm run test -w packages/client` and
 * failed with a misleading ENOENT under `npx vitest --root packages/client` from
 * the repository root.
 *
 * The directory holds NOTHING but corpus files: the reason each one exists is
 * here, in {@link FORMAT_CORPUS}, and the note covering the set as a whole is
 * `format-corpus.provenance.md` BESIDE this module rather than inside the
 * directory — {@link FORMAT_CORPUS_FILES} reads that directory back and compares
 * it against the index, so anything else in there would read as an unexplained
 * fixture.
 *
 * `.gitattributes` marks the directory `-text` and `.prettierignore` excludes
 * it. Both are load-bearing: the blanket `* text=auto eol=lf` would rewrite the
 * CRLF terminators that `crlf.jsonl` exists to exercise and would corrupt
 * `utf16.json` outright, and Prettier cannot parse `truncated-array.json` — which
 * is the point of that file.
 */
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const CORPUS_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'format-corpus');

/** One combination of the two checkboxes, spelled the way an entry lists it. */
export type TransformCombination = 'format' | 'repair' | 'format+repair';

/** Every combination the panel can produce, in the order the suites run them. */
export const TRANSFORM_COMBINATIONS: readonly TransformCombination[] = [
  'format',
  'repair',
  'format+repair',
];

export interface FormatCorpusEntry {
  /** File name inside `tests/fuzz/format-corpus/`. */
  readonly file: string;
  /** What this input is for — the sentence a reviewer needs and the file cannot carry. */
  readonly why: string;
  /**
   * Set on an entry whose BYTES are not plain UTF-8, and which the application
   * must therefore refuse before any parser sees it.
   *
   * Listed rather than inferred, so a file that stops being refused — because
   * the decoder was loosened, say — turns the run red instead of quietly moving
   * into the other half of the suite.
   */
  readonly refusedByDecoder?: true;
  /**
   * The combinations that MUST fail for this entry. Every other combination must
   * succeed.
   *
   * A truth table rather than a single "this one is broken" flag, and the
   * difference is what makes the suite able to fail in both directions.
   * "It failed" is what a broken engine reports for everything, so an entry that
   * is expected to fail has to be distinguishable from one that has started
   * failing — and an entry that is expected to SUCCEED and quietly stopped is the
   * regression nobody would otherwise notice. Every value below was MEASURED
   * against the real Prettier and the real repairer rather than predicted.
   */
  readonly failing?: readonly TransformCombination[];
}

/** The two flags a combination stands for. */
export function flagsOf(combination: TransformCombination): { format: boolean; repair: boolean } {
  return {
    format: combination !== 'repair',
    repair: combination !== 'format',
  };
}

export const FORMAT_CORPUS: readonly FormatCorpusEntry[] = [
  {
    file: 'valid-compact.json',
    why: 'Ordinary, already-valid, minified JSON. Repairing it must be byte-identical and formatting it must be idempotent — the two properties every other entry is measured against.',
  },
  {
    file: 'trailing-comma.json',
    why: 'A trailing comma in both an object and an array. Prettier ACCEPTS this on its own, which is why the panel must not claim repair is the only thing that can fix a file.',
  },
  {
    file: 'single-quotes.json',
    why: 'Single-quoted keys and values, which is what a JavaScript object literal pasted into a `.json` file looks like. Only the repairer can read it.',
  },
  {
    file: 'comments.jsonc',
    why: 'A line comment and a block comment. Formatting KEEPS them (the jsonc parser); repairing STRIPS them, because strict JSON has none — a loss the diff shows and the user confirms.',
  },
  {
    file: 'unquoted-keys.json5',
    why: 'Unquoted keys and a trailing comma, read by the json5 parser rather than by the strict one. Formatting must not refuse a file the extension declares to be JSON5.',
  },
  {
    file: 'truncated-array.json',
    failing: ['format'],
    why: 'A download cut off mid-array. The repairer closes it; the formatter alone cannot, and must report a position rather than throwing something the panel cannot describe.',
  },
  {
    file: 'unterminated-string.json',
    failing: ['format'],
    why: 'A string that never closes — the other half of a half-written file. The repairer closes it, which is a guess, and the diff is what makes that guess something the user agrees to.',
  },
  {
    file: 'concatenated.json',
    failing: ['format', 'repair', 'format+repair'],
    why: 'REGRESSION: two whole JSON documents in one file. The repairer refuses it rather than picking one, and the failure must name the line and the column of the second document.',
  },
  {
    file: 'empty.json',
    // MEASURED: formatting an empty document succeeds and yields an empty
    // document, which is the honest answer — an empty file is a legal upload.
    // Repairing one does not: there is no document to repair, and the refusal is
    // what stops an empty success being presented as a fix.
    failing: ['repair', 'format+repair'],
    why: 'A zero-byte file. Formatting it is a no-op and must stay one; repairing it has nothing to work on, and the answer must be a refusal rather than an empty success.',
  },
  {
    file: 'deep-nesting.json',
    why: 'Two hundred levels of nesting. `JSON.parse` is iterative in V8, but a recursive-descent parser and a recursive PRINTER are two more chances to blow the stack, and both run here.',
  },
  {
    file: 'unicode.json',
    why: 'An astral-plane pair, a right-to-left override, a combining-mark stack, an escaped NUL and an escaped surrogate pair. Every one of them survives a round trip through the decoder, and none may be normalised away.',
  },
  {
    file: 'crlf.jsonl',
    why: 'CRLF-terminated JSON Lines. Every line ending must come back a CRLF: rewriting them would show as a change to every line of a Windows-authored file, which is a rewrite nobody asked for.',
  },
  {
    file: 'blank-lines.ndjson',
    why: 'Blank lines between records, and a trailing newline that leaves an empty final line. Neither is a record, and parsing either as one would make every well-formed JSON Lines file fail on its last line.',
  },
  {
    file: 'broken-record.jsonl',
    failing: ['format', 'repair', 'format+repair'],
    why: 'Two concatenated documents on line THREE. The reported line number must be 3 — a whole-file character offset is useless against a format that is defined line by line.',
  },
  {
    file: 'hostile.md',
    // Markdown has no repairer by design, so any combination asking for one is
    // refused. The panel never offers it; this pins the engine's own answer.
    failing: ['repair', 'format+repair'],
    why: 'Markdown carrying a `<script>` tag, a table, a fenced code block and a loose list. The formatter must rewrite the layout and leave the script tag exactly as the text it is: this is DATA on its way to being encrypted, never markup.',
  },
  {
    file: 'anchors.yaml',
    failing: ['repair', 'format+repair'],
    why: 'YAML anchors, a merge key, a literal block and a flow sequence — the four constructs whose meaning depends on indentation, and therefore the four a formatter could silently change.',
  },
  {
    file: 'broken-flow.yaml',
    // All three, and for two different reasons: the formatter cannot parse it,
    // and YAML has no repairer at all, so every combination that asks for one is
    // refused before a byte is read.
    failing: ['format', 'repair', 'format+repair'],
    why: 'A flow sequence that never closes. YAML has no repairer by design, so the formatter is the only parse check it gets, and its `loc` is what the panel shows.',
  },
  {
    file: 'bom.json',
    refusedByDecoder: true,
    why: 'Valid UTF-8 behind a byte-order mark — an ordinary Windows-authored file. It is refused BY NAME, because `TextDecoder` strips the mark and the upload would otherwise lose three bytes while the diff reported no change.',
  },
  {
    file: 'utf16.json',
    refusedByDecoder: true,
    why: 'UTF-16LE with no byte-order mark, which is the case the round-trip check CANNOT see: every byte is under 0x80, so it decodes and re-encodes byte-for-byte. Its NUL characters are what refuse it, and without that rule it would reach Prettier and fail with a syntax error about a character nobody can see.',
  },
];

/** The RAW BYTES of one corpus entry, which is what the decoder is handed. */
export function readFormatCorpus(file: string): ArrayBuffer {
  const bytes = readFileSync(path.join(CORPUS_DIR, file));
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

/**
 * What is actually on disk in `format-corpus/`.
 *
 * Read from the filesystem rather than derived from {@link FORMAT_CORPUS}, so
 * the suite can compare the two in BOTH directions: an entry naming a deleted
 * file fails loudly on its own, but a file dropped into the directory and never
 * listed is SILENT — nothing runs it, and the reason it was added is lost.
 */
export const FORMAT_CORPUS_FILES: readonly string[] = readdirSync(CORPUS_DIR);
