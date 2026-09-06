import { MAX_PREVIEW_TEXT_LINES, extensionTable } from '@hvault/shared';
import { decodeDocumentText } from '../decode';
import { documentShell, el, notice, viewToggle } from '../dom';
import { delimiterFor, parseDelimited, renderTable } from './table';

/**
 * The renderer for the `text` and `code` modes: plain text, source code,
 * delimited data and the JSON family.
 *
 * ---------------------------------------------------------------------------
 * THE ONE RULE EVERY RENDERER IN THIS DIRECTORY FOLLOWS
 * ---------------------------------------------------------------------------
 *
 * It returns DOM NODES, and a document's own bytes only ever arrive as TEXT
 * NODES. Nothing here builds a markup string, and nothing here is ever assigned
 * to `innerHTML`. That is not caution about these particular formats — a `.txt`
 * file cannot be "malicious markup" until something parses it as markup, and the
 * point is that nothing ever does. Serialising a tree back to a string and
 * re-parsing it is the mutation-XSS shape, and the way not to have it is to
 * never produce the string in the first place.
 *
 * The isolation around this document is defence in depth for the renderers that
 * genuinely must parse. This one earns its safety structurally.
 *
 * ---------------------------------------------------------------------------
 * WHY THE HIGHLIGHTER IS A DYNAMIC IMPORT
 * ---------------------------------------------------------------------------
 *
 * `lowlight` carries highlight.js's whole common language set, which is by a
 * wide margin the largest thing this document can download. A `.txt`, a `.log`
 * and a `.csv` need none of it, and the extension-to-language table below is
 * what lets that be decided WITHOUT loading it: the table names only languages
 * the common set actually registers, an extension absent from it renders as
 * plain text, and the import happens only on the branch that will use it.
 *
 * `packages/client/tests/sandbox-renderers.test.ts` asserts every value in the
 * table is really registered, so the table cannot drift into promising a
 * language the bundle does not carry — which would degrade silently to plain
 * text and look like a styling bug.
 */

/**
 * Extension to highlight.js language, for the languages `lowlight`'s COMMON set
 * registers.
 *
 * Deliberately incomplete. `powershell` is not in the common set, so `.ps1`,
 * `.bat` and `.cmd` render as plain text, and `fish` has no grammar there
 * either. That is the intended graceful degradation rather than a gap: an
 * unhighlighted preview is a small loss, while registering an extra language
 * enlarges the highlighter chunk that `scripts/ci/lib/bundle-budgets.mjs`
 * bounds — so adding one means re-measuring that budget, not assuming it still
 * holds.
 */
export const HIGHLIGHT_LANGUAGES: Readonly<Record<string, string>> = extensionTable({
  sh: 'bash',
  bash: 'bash',
  zsh: 'bash',
  py: 'python',
  rb: 'ruby',
  pl: 'perl',
  lua: 'lua',
  sql: 'sql',
  r: 'r',
  js: 'javascript',
  mjs: 'javascript',
  cjs: 'javascript',
  jsx: 'javascript',
  ts: 'typescript',
  tsx: 'typescript',
  c: 'c',
  h: 'c',
  cpp: 'cpp',
  hpp: 'cpp',
  cs: 'csharp',
  java: 'java',
  kt: 'kotlin',
  go: 'go',
  rs: 'rust',
  php: 'php',
  swift: 'swift',
  diff: 'diff',
  patch: 'diff',
  // systemd units, `.env` files and Java properties are all key/value with `#`
  // comments, which is what highlight.js's `ini` grammar is.
  ini: 'ini',
  conf: 'ini',
  cfg: 'ini',
  properties: 'ini',
  env: 'ini',
  service: 'ini',
  toml: 'ini',
  json: 'json',
  jsonc: 'json',
  json5: 'json',
  jsonl: 'json',
  ndjson: 'json',
  yaml: 'yaml',
  yml: 'yaml',
  xml: 'xml',
});

/** The extensions whose contents are worth pretty-printing as JSON. */
const JSON_EXTENSIONS = new Set(['json', 'jsonc', 'json5']);
/** One JSON document per line. */
const JSON_LINES_EXTENSIONS = new Set(['jsonl', 'ndjson']);

/** How many spaces a pretty-printed JSON document is indented by. */
const JSON_INDENT = 2;

/** Byte counts in a notice, in the units a person reads. */
function describeBytes(bytes: number): string {
  if (bytes < 1024) return `${String(bytes)} bytes`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** Split into lines without a trailing empty one for a file ending in a newline. */
function toLines(text: string): string[] {
  const lines = text.split('\n');
  if (lines.length > 1 && lines[lines.length - 1] === '') lines.pop();
  return lines;
}

/**
 * The gutter, as ONE text node rather than one element per line.
 *
 * 50,000 lines is 50,000 `<span>`s under the obvious implementation, and it is
 * the node count rather than the byte count that stops a tab responding — which
 * is the whole reason `MAX_PREVIEW_TEXT_LINES` exists. A second `<pre>` beside
 * the source, laid out as a flex row with identical line metrics, costs exactly
 * two text nodes for any file.
 *
 * `aria-hidden`, because line numbers are a visual affordance: a screen reader
 * announcing "one two three four" between every line of a shell script makes the
 * script unreadable.
 */
function gutter(doc: Document, lineCount: number): HTMLPreElement {
  const node = el(doc, 'pre', 'hv-gutter');
  node.setAttribute('aria-hidden', 'true');
  const numbers: string[] = [];
  for (let line = 1; line <= lineCount; line += 1) numbers.push(String(line));
  node.textContent = numbers.join('\n');
  return node;
}

/**
 * Source text with line numbers, highlighted when the language is one the bundle
 * carries.
 *
 * Highlighting is best-effort in the strongest sense: any failure inside
 * `lowlight` leaves the plain text node already in place, because the text is
 * written FIRST and the highlighted tree replaces it only once it exists. A
 * highlighter that threw on a pathological file would otherwise take the whole
 * preview with it.
 */
async function sourceView(doc: Document, text: string, ext: string): Promise<HTMLElement> {
  const lines = toLines(text);
  const wrapper = el(doc, 'div', 'hv-source');
  const code = el(doc, 'code');
  code.textContent = text;
  const pre = el(doc, 'pre', 'hv-lines');
  pre.append(code);
  wrapper.append(gutter(doc, lines.length), pre);

  const language = HIGHLIGHT_LANGUAGES[ext];
  if (language === undefined) return wrapper;

  try {
    const [{ createLowlight, common }, { toDom }] = await Promise.all([
      import('lowlight'),
      import('hast-util-to-dom'),
    ]);
    const tree = createLowlight(common).highlight(language, text);
    const highlighted = toDom(tree, { fragment: true, document: doc });
    // `fragment: true` is a REQUEST, not a guarantee. `hast-util-to-dom` decides
    // the root's shape from the TREE, and for a root with NO CHILDREN it builds
    // a `Document`, which `replaceChildren` refuses with
    // `HierarchyRequestError`. `renderers/pipeline.ts` holds the measurement and
    // the library's line numbers; the handling is repeated here rather than
    // imported from there because that module pulls `unified` and
    // `rehype-sanitize`, and this one is the chunk that has to stay small enough
    // for a `.log` file to be worth opening.
    //
    // An empty file is the whole of the reachable case: lowlight returns a
    // childless root for `''` and for nothing else (measured — a single space
    // returns one child). Until this, the throw landed in the catch below and an
    // empty `.js` quietly lost its code styling, recorded as a highlighter
    // failure when the highlighter had worked perfectly.
    //
    // Spreading the CHILDREN rather than handing over the root is the one form
    // correct for both shapes, and it needs no branch — so there is no arm a
    // test could miss. It is exactly equivalent for a fragment, which
    // `replaceChildren` empties into the target either way. `childNodes` is
    // live, and the spread reads it before anything moves.
    code.replaceChildren(...highlighted.childNodes);
    code.className = 'hljs';
  } catch {
    // The plain text node is already rendered. A highlighter that could not run
    // costs colour and nothing else, and reporting it would turn a cosmetic
    // outcome into a failed preview.
  }
  return wrapper;
}

/** Pretty-print, or `null` when the text is not JSON this can re-serialise. */
function prettyJson(text: string, ext: string): string | null {
  try {
    if (JSON_LINES_EXTENSIONS.has(ext)) {
      const lines = toLines(text).filter((line) => line.trim() !== '');
      if (lines.length === 0) return null;
      return lines.map((line) => JSON.stringify(JSON.parse(line), null, JSON_INDENT)).join('\n\n');
    }
    if (!JSON_EXTENSIONS.has(ext)) return null;
    return JSON.stringify(JSON.parse(text), null, JSON_INDENT);
  } catch {
    // `.json5` and `.jsonc` are the expected failures here — comments and
    // trailing commas are not JSON — and a file that simply is not valid JSON
    // is the other. Both fall back to the source view, which is the honest
    // rendering of a document that does not parse. Repairing it is Phase 20's
    // job, on the UPLOAD path, with the user's confirmation.
    return null;
  }
}

/**
 * Two renderings of one document, with a toggle between them.
 *
 * The alternative rendering is built LAZILY and then cached, so a table of ten
 * thousand rows is not built for a reader who never presses the button and is
 * not rebuilt for one who presses it twice.
 */
function togglePair(
  doc: Document,
  labels: readonly [string, string],
  first: HTMLElement,
  buildSecond: () => HTMLElement,
): { toolbar: HTMLElement; body: HTMLElement } {
  const body = el(doc, 'div', 'hv-body');
  body.append(first);
  let second: HTMLElement | null = null;
  const toolbar = viewToggle(doc, labels, (showingSecond) => {
    if (!showingSecond) {
      body.replaceChildren(first);
      return;
    }
    second ??= buildSecond();
    body.replaceChildren(second);
  });
  return { toolbar, body };
}

/**
 * A plain, unhighlighted view of some text, with a truncation notice when the
 * file has more lines than the cap.
 *
 * The "original" half of both toggles: a reader who asks to see a CSV as text,
 * or a JSON document as it was actually stored, is asking for the bytes rather
 * than for an interpretation of them, so no grammar is consulted here.
 */
function plainView(doc: Document, text: string, byteLength: number): HTMLElement {
  const view = el(doc, 'div', 'hv-plain');
  const kept = truncate(text);
  if (kept.truncated) {
    view.append(
      notice(
        doc,
        `Showing the first ${String(MAX_PREVIEW_TEXT_LINES)} of ${String(kept.totalLines)} lines (${describeBytes(byteLength)}). Download the file to see all of it.`,
      ),
    );
  }
  const code = el(doc, 'code');
  code.textContent = kept.text;
  const pre = el(doc, 'pre', 'hv-lines');
  pre.append(code);
  view.append(pre);
  return view;
}

/**
 * Render a `text` or `code` document.
 *
 * One entry point for both modes because the difference between them is which
 * extensions each carries, not how a file is put on screen: every branch below
 * ends in text nodes, and the mode only decides whether a language grammar is
 * consulted on the way.
 */
export async function renderText(
  doc: Document,
  bytes: ArrayBuffer,
  ext: string,
): Promise<HTMLElement> {
  const decoded = decodeDocumentText(bytes);
  const shell = documentShell(doc, 'text');
  if (decoded.warning !== null) shell.append(notice(doc, decoded.warning));

  const delimiter = delimiterFor(ext);
  if (delimiter !== null) {
    const parsed = parseDelimited(decoded.text, delimiter);
    if (parsed.truncated) {
      shell.append(
        notice(
          doc,
          `Showing the first ${String(MAX_PREVIEW_TEXT_LINES)} of ${String(parsed.totalRows)} rows (${describeBytes(bytes.byteLength)}). Download the file to see all of it.`,
        ),
      );
    }
    const { toolbar, body } = togglePair(
      doc,
      ['Show table', 'Show raw text'],
      renderTable(doc, parsed),
      () => plainView(doc, decoded.text, bytes.byteLength),
    );
    shell.append(toolbar, body);
    return shell;
  }

  const pretty = prettyJson(decoded.text, ext);
  if (pretty !== null) {
    // The FORMATTED text is what the cap is applied to, and it is the longer of
    // the two: pretty-printing a one-line JSON document is exactly what turns a
    // file that fits into one that does not. Its notice therefore has to be
    // raised here rather than borrowed from the raw view behind the toggle,
    // which measures a different string — without this a 60,000-line
    // pretty-printed document was silently cut while the view one click away
    // said nothing was missing.
    const formatted = truncate(pretty);
    if (formatted.truncated) {
      shell.append(
        notice(
          doc,
          `Showing the first ${String(MAX_PREVIEW_TEXT_LINES)} of ${String(formatted.totalLines)} formatted lines (${describeBytes(bytes.byteLength)}). Download the file to see all of it.`,
        ),
      );
    }
    const { toolbar, body } = togglePair(
      doc,
      ['Show formatted', 'Show original'],
      await sourceView(doc, formatted.text, ext),
      () => plainView(doc, decoded.text, bytes.byteLength),
    );
    shell.append(toolbar, body);
    return shell;
  }

  const kept = truncate(decoded.text);
  if (kept.truncated) {
    shell.append(
      notice(
        doc,
        `Showing the first ${String(MAX_PREVIEW_TEXT_LINES)} of ${String(kept.totalLines)} lines (${describeBytes(bytes.byteLength)}). Download the file to see all of it.`,
      ),
    );
  }
  shell.append(await sourceView(doc, kept.text, ext));
  return shell;
}

/** Keep at most {@link MAX_PREVIEW_TEXT_LINES} lines, and say how many there were. */
function truncate(text: string): { text: string; truncated: boolean; totalLines: number } {
  const lines = toLines(text);
  if (lines.length <= MAX_PREVIEW_TEXT_LINES) {
    return { text, truncated: false, totalLines: lines.length };
  }
  return {
    text: lines.slice(0, MAX_PREVIEW_TEXT_LINES).join('\n'),
    truncated: true,
    totalLines: lines.length,
  };
}
