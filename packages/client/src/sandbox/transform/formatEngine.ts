import {
  canRepairSyntax,
  extensionTable,
  transformExcerpt,
  transformSyntaxForExtension,
  transformToolLabels,
  type SandboxRepairDetailCode,
  type SandboxTransformFailedMessage,
  type SandboxTransformFailureCode,
  type SandboxTransformRequest,
  type SandboxTransformedMessage,
  type TransformSyntax,
} from '@hvault/shared';

/**
 * The format-and-repair engine — the only code in this application that hands a
 * user's document to a third-party parser.
 *
 * ---------------------------------------------------------------------------
 * WHY IT LIVES HERE AND NOT IN A WEB WORKER
 * ---------------------------------------------------------------------------
 *
 * A dedicated worker is the obvious home for a CPU-bound text transform, and it
 * is the wrong one. A worker is SAME-ORIGIN. A vulnerability in Prettier or in
 * the JSON repairer running inside one could `fetch` this application's own API
 * with the httpOnly refresh cookie attached, read an access token out of the
 * response body, and hand it to whoever supplied the file. A worker has no DOM,
 * but it has the origin, and the origin is what a token is bound to.
 *
 * Inside the isolated document the same vulnerability lands somewhere with an
 * opaque origin, no cookies, no storage, and `connect-src 'none'` — it cannot
 * open a socket at all. That is also what makes the rule in Section 1.2 of the
 * design absolute rather than nearly true: NO untrusted document byte is parsed
 * in the application's origin, at view time or at upload time.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS MODULE IS AND IS NOT
 * ---------------------------------------------------------------------------
 *
 * It is PURE in the sense that matters here: text in, text or a positioned
 * failure out. It touches no DOM, no channel and no key, so every case below is
 * exercised directly in the test suite rather than through an iframe.
 *
 * It does NOT compute the diff the user confirms. That is deliberate and it is a
 * security decision rather than a layering one: a confirmation dialog built from
 * numbers this document chose is a dialog that can lie about what it is asking
 * permission for. The host recomputes the whole comparison from its own copy of
 * the original (`src/lib/textDiff.ts`), and the only thing it takes from here is
 * the transformed TEXT, which it treats strictly as data.
 *
 * ---------------------------------------------------------------------------
 * EVERY IMPORT OF A FORMATTER IS DYNAMIC, AND THAT IS A BUILD INSTRUCTION
 * ---------------------------------------------------------------------------
 *
 * Rollup emits a separate chunk at a dynamic-import boundary and nowhere else,
 * so a static `import` of Prettier here would put ~1 MB of formatter into the
 * chunk that a plain text PREVIEW downloads. The per-type split below is what
 * produces `vendor-prettier-core`, `-json`, `-markdown` and `-yaml`, and their
 * ceilings in `scripts/ci/lib/bundle-budgets.mjs` are keyed to exactly this
 * shape: formatting a README must not fetch the YAML grammar.
 *
 * This module must NEVER be imported by application-side code, not even for a
 * type. `packages/client/tests/sandbox-boundary.test.ts` asserts that no module
 * outside `src/sandbox/` reaches into it at runtime; a static import from the
 * host would put Prettier into the APPLICATION's Rollup graph, where its chunks
 * would be named by Rollup's defaults, land in `dist/assets/`, and breach
 * `DEFAULT_CHUNK_BUDGET_KB` on size.
 */

/*
 * The two tool versions this engine records as provenance, and the labels built
 * from them, live in `@hvault/shared` (`JSONREPAIR_VERSION`, `PRETTIER_VERSION`,
 * `transformToolLabels`) rather than here, because the APPLICATION must compute
 * the same pair: it refuses any reply whose labels are not exactly the ones its
 * own request can produce, since they are shown beside the upload button and
 * sealed into the document. They are still hand-written, and
 * `packages/client/tests/document-format.test.ts` still pins them to the
 * installed packages.
 */

/**
 * The Prettier parser for each extension in the JSON family.
 *
 * Keyed by EXTENSION rather than by syntax, because this is the one place where
 * the three JSON dialects genuinely differ: `.jsonc` keeps its comments and may
 * carry a trailing comma, `.json5` keeps unquoted keys and single quotes, and
 * `.json` is strict. Collapsing them onto one parser would silently strip a
 * comment from a `.jsonc` file that had no syntax error at all.
 *
 * Every key here must be an extension `TRANSFORM_SYNTAXES` maps to `json`, which
 * the test suite asserts in both directions — an extension added there and
 * forgotten here would fall back to the strict parser and lose comments.
 */
const JSON_PARSERS: Readonly<Record<string, 'json' | 'jsonc' | 'json5'>> = extensionTable({
  json: 'json',
  jsonc: 'jsonc',
  json5: 'json5',
});

/**
 * The print width used for ONE JSONL record.
 *
 * A JSONL record is a whole JSON document that must stay on ONE line, and
 * Prettier's only lever for that is the width it is allowed to fill. Measured
 * against Prettier 3.9.5: at this width a record of roughly 900 KB still prints
 * flat, and a ~940 KB one breaks — which is why {@link formatRecord} verifies
 * the result rather than assuming it. A broken record is refused, never written:
 * a formatter that silently turns one JSONL row into three has corrupted the
 * file in a way no diff summary would describe as an error.
 */
const JSONL_PRINT_WIDTH = 1_000_000;

/**
 * Prettier's module and plugin shapes, named WITHOUT importing anything at
 * runtime: `typeof import(...)` and `import type` are both erased at build, so
 * this file's only real reference to Prettier is the dynamic `import()` below.
 */
type PrettierStandalone = typeof import('prettier/standalone');
type PrettierPlugin = import('prettier').Plugin;

/** A positioned failure, before it is dressed as a message. */
interface EnginePosition {
  line: number | null;
  column: number | null;
}

/**
 * Convert a character OFFSET into a 1-based line and column.
 *
 * `jsonrepair` reports an offset and nothing else, so this is what turns
 * "position 7" into "line 1, column 8" — the difference between a failure a user
 * can find in their file and one they can only be told about. Prettier reports a
 * `loc` and needs no conversion.
 *
 * An offset past the end of the text answers the position of the end, which is
 * the honest answer for "the document stopped before it should have" and is the
 * shape a truncated file produces.
 */
export function positionAt(text: string, offset: number): EnginePosition {
  const bounded = Math.max(0, Math.min(offset, text.length));
  // The number of newlines BEFORE the offset is the number of completed lines,
  // so the line is that count plus one. `lastIndexOf` then finds where the
  // current line starts; -1 (no newline at all) makes the column the offset plus
  // one, which is correct for a single-line document.
  let line = 1;
  for (let index = 0; index < bounded; index += 1) {
    if (text[index] === '\n') line += 1;
  }
  // `lastIndexOf` clamps a negative `fromIndex` to 0 rather than answering -1,
  // so offset 0 in a document that STARTS with a newline would otherwise report
  // column 0. Answering the start of the document directly is both correct and
  // the only case that needs saying.
  const lineStart = bounded === 0 ? 0 : text.lastIndexOf('\n', bounded - 1) + 1;
  return { line, column: bounded - lineStart + 1 };
}

// `Invalid character` is not a prefix of `Invalid unicode character`, so the
// order of this list decides nothing; it follows `jsonrepair`'s own source.
const REPAIR_DETAIL_PREFIXES: readonly (readonly [string, SandboxRepairDetailCode])[] = [
  ['Invalid character', 'invalidCharacter'],
  ['Unexpected character', 'unexpectedCharacter'],
  ['Unexpected end of json string', 'unexpectedEnd'],
  ['Object key expected', 'objectKeyExpected'],
  ['Colon expected', 'colonExpected'],
  ['Invalid unicode character', 'invalidUnicode'],
];

/**
 * Which of `jsonrepair`'s six complaints this is, as a code, or `undefined`.
 *
 * The repairer's wording is not sent: the application words every refusal it
 * shows, because the words land in its chrome. But WHICH complaint it was is
 * worth keeping — "a colon was expected" beside a line and a column is the whole
 * diagnosis — and `jsonrepair` has exactly six things it can say, each thrown
 * from one helper with a fixed prefix. Matched by prefix because three of them
 * append the offending text. A message this does not recognise (a future
 * release, a plugin) sends no detail, and the host's general sentence stands.
 *
 * Exported so the table can be held to each prefix directly: not every one of
 * the six can be provoked through `jsonrepair` with an input small enough to
 * keep in a test.
 */
export function repairDetailOf(error: unknown): SandboxRepairDetailCode | undefined {
  if (!(error instanceof Error)) return undefined;
  for (const [prefix, code] of REPAIR_DETAIL_PREFIXES) {
    if (error.message.startsWith(prefix)) return code;
  }
  return undefined;
}

/**
 * Prettier throws a `SyntaxError` carrying a `loc`; read it without asserting it.
 *
 * Every step is guarded because this reads a THIRD PARTY's error object, and the
 * shape is a convention rather than a contract: a plugin may throw an ordinary
 * `Error`, a future version may move the field, and one of the two paths that
 * calls this can be reached by anything the loaded chunk decides to raise. An
 * unguarded `error.loc.start.line` would turn "your YAML has a syntax error" into
 * a `TypeError` the frame answers with its generic refusal, losing the position
 * that made the message useful.
 *
 * Exported for the same reason {@link positionAt} is: the malformed shapes
 * cannot be produced by asking Prettier for them, so they are constructed
 * directly in the test.
 */
export function locOf(error: unknown): EnginePosition {
  if (typeof error !== 'object' || error === null || !('loc' in error)) {
    return { line: null, column: null };
  }
  const loc = (error as { loc?: unknown }).loc;
  if (typeof loc !== 'object' || loc === null || !('start' in loc)) {
    return { line: null, column: null };
  }
  const start = (loc as { start?: unknown }).start;
  if (typeof start !== 'object' || start === null) return { line: null, column: null };
  const { line, column } = start as { line?: unknown; column?: unknown };
  return {
    line: typeof line === 'number' ? line : null,
    column: typeof column === 'number' ? column : null,
  };
}

/** `jsonrepair` throws a `JSONRepairError` carrying `position`, a character offset. */
function offsetOf(error: unknown): number | null {
  if (typeof error !== 'object' || error === null || !('position' in error)) return null;
  const position = (error as { position?: unknown }).position;
  return typeof position === 'number' ? position : null;
}

/**
 * The message every failure path goes through, so its shape is decided once.
 *
 * A CODE, never a sentence: the application words the refusal. `detail` is
 * added only when there is one, so an ordinary failure carries no empty field.
 */
function failure(
  stage: SandboxTransformFailedMessage['stage'],
  code: SandboxTransformFailureCode,
  position: EnginePosition,
  excerpt: string,
  detail?: SandboxRepairDetailCode,
): SandboxTransformFailedMessage {
  const base = {
    kind: 'transformFailed',
    stage,
    code,
    line: position.line,
    column: position.column,
    excerpt,
  } as const;
  return detail === undefined ? base : { ...base, detail };
}

/**
 * A tool that threw WITH a position is reporting a problem in the document; one
 * that threw without one is reporting a problem in itself, and saying "syntax
 * error" about the reader's file then would be a claim nothing supports.
 */
function syntaxOrEngine(located: boolean): SandboxTransformFailureCode {
  return located ? 'syntaxError' : 'engineFailed';
}

/**
 * Load Prettier and exactly the plugins one syntax needs.
 *
 * FOUR chunks rather than one, because the alternative is that formatting a
 * README downloads the YAML grammar and the JavaScript parser. `estree` is the
 * PRINTER for everything the `babel` parser produces, so the JSON family needs
 * both and neither is useful alone.
 */
async function loadPrettier(
  syntax: TransformSyntax,
): Promise<{ prettier: PrettierStandalone; plugins: PrettierPlugin[] }> {
  const prettier = await import('prettier/standalone');
  if (syntax === 'markdown') {
    const markdown = await import('prettier/plugins/markdown');
    return { prettier, plugins: [markdown as PrettierPlugin] };
  }
  if (syntax === 'yaml') {
    const yaml = await import('prettier/plugins/yaml');
    return { prettier, plugins: [yaml as PrettierPlugin] };
  }
  const [babel, estree] = await Promise.all([
    import('prettier/plugins/babel'),
    import('prettier/plugins/estree'),
  ]);
  return { prettier, plugins: [babel as PrettierPlugin, estree as PrettierPlugin] };
}

/**
 * The Prettier options every call shares.
 *
 * `endOfLine: 'auto'` is the one that is not a default and it is load-bearing.
 * Prettier's default rewrites every line ending to LF, so a Windows-authored
 * document would come back with every single line changed — a diff the user
 * cannot read, describing a rewrite they did not ask for. `auto` keeps whatever
 * the file's first line ending is.
 *
 * `embeddedLanguageFormatting: 'off'` is explicit rather than incidental. With
 * only the Markdown plugin loaded, Prettier already leaves a fenced ```js block
 * alone because it has no parser for it; saying so out loud means that adding a
 * plugin here later cannot silently start rewriting the code inside somebody's
 * document.
 *
 * Nothing else is set. This repository's own Prettier settings govern this
 * repository's source, and imposing them on a user's YAML would be a rewrite
 * they never asked for; Prettier's own defaults are the neutral choice, and the
 * exact version that produced them is recorded in the provenance.
 */
const BASE_OPTIONS = {
  endOfLine: 'auto',
  embeddedLanguageFormatting: 'off',
} as const;

/**
 * Which Prettier parser reads this document.
 *
 * The JSON family is the only one that consults the EXTENSION, for the reason
 * {@link JSON_PARSERS} records. `jsonl` never reaches here: its records are
 * formatted one at a time, always as strict JSON.
 */
function parserFor(syntax: TransformSyntax, ext: string): string {
  if (syntax === 'markdown') return 'markdown';
  if (syntax === 'yaml') return 'yaml';
  return JSON_PARSERS[ext] ?? 'json';
}

/**
 * Format ONE JSONL record, and prove it is still one line.
 *
 * Prettier always terminates its output with a newline, so the trailing one is
 * removed; a newline anywhere else means the formatter broke the record across
 * lines and the result would no longer be JSONL. That is refused rather than
 * written, because the corruption is invisible afterwards: every downstream
 * reader would see three malformed records where there was one good one.
 */
async function formatRecord(
  record: string,
  prettier: PrettierStandalone,
  plugins: PrettierPlugin[],
): Promise<string | null> {
  const formatted = await prettier.format(record, {
    ...BASE_OPTIONS,
    parser: 'json',
    plugins,
    printWidth: JSONL_PRINT_WIDTH,
  });
  const body = formatted.replace(/\n$/, '');
  return body.includes('\n') ? null : body;
}

/**
 * Split a document into lines, keeping each line's own terminator information.
 *
 * Splitting on `\n` alone rather than on `\r?\n` is what lets a CRLF file come
 * back a CRLF file: the carriage return is carried on the line it belongs to and
 * put back afterwards. Splitting on both and re-joining with `\n` would rewrite
 * every line ending in the file while reporting a transform of the content.
 */
interface SourceLine {
  body: string;
  carriageReturn: boolean;
}

function splitLines(text: string): SourceLine[] {
  return text.split('\n').map((line) => ({
    body: line.endsWith('\r') ? line.slice(0, -1) : line,
    carriageReturn: line.endsWith('\r'),
  }));
}

function joinLines(lines: readonly SourceLine[]): string {
  return lines.map((line) => `${line.body}${line.carriageReturn ? '\r' : ''}`).join('\n');
}

/**
 * Is this line a record, or the blank space around one?
 *
 * A blank line is passed through untouched rather than repaired or formatted.
 * The alternative is worse in both directions: a file ending in a newline has an
 * empty final line, which every JSON tool rejects as an empty document, so
 * treating it as a record would make every well-formed JSONL file fail on its
 * last line.
 */
function isBlank(line: SourceLine): boolean {
  return line.body.trim() === '';
}

/**
 * Repair a JSONL document line by line, reporting the LINE that failed.
 *
 * Per line rather than whole-document, because that is what JSONL is: a sequence
 * of independent documents. Repairing the concatenation would turn two adjacent
 * records into one error, and the error a user needs is "line 4", not "position
 * 8,213".
 *
 * Unlike {@link formatLines} this does NOT re-check that the result is still one
 * line, and the asymmetry is a measured fact rather than an oversight.
 * {@link splitLines} guarantees the body it hands over contains no `\n` and no
 * trailing `\r`, and `jsonrepair` echoes the whitespace it was given rather than
 * introducing any: measured against 3.15.0, it escapes a literal newline inside
 * a string, strips a Markdown code fence without adding one, and preserves a
 * trailing CRLF it was handed. It has no path that turns a one-line input into a
 * multi-line output. The formatter genuinely does have one — its printer BREAKS
 * a long record on purpose — which is why only that half is checked.
 */
async function repairLines(text: string): Promise<string | SandboxTransformFailedMessage> {
  const { jsonrepair } = await import('jsonrepair');
  const lines = splitLines(text);
  const out: SourceLine[] = [];
  for (const [index, line] of lines.entries()) {
    if (isBlank(line)) {
      out.push(line);
      continue;
    }
    try {
      out.push({ body: jsonrepair(line.body), carriageReturn: line.carriageReturn });
    } catch (error) {
      const offset = offsetOf(error);
      const column = offset === null ? null : positionAt(line.body, offset).column;
      const lineNumber = index + 1;
      return failure(
        'repair',
        syntaxOrEngine(offset !== null),
        { line: lineNumber, column },
        transformExcerpt(text, lineNumber),
        repairDetailOf(error),
      );
    }
  }
  return joinLines(out);
}

/** Format a JSONL document line by line, keeping every record on its own line. */
async function formatLines(
  text: string,
  prettier: PrettierStandalone,
  plugins: PrettierPlugin[],
): Promise<string | SandboxTransformFailedMessage> {
  const lines = splitLines(text);
  const out: SourceLine[] = [];
  for (const [index, line] of lines.entries()) {
    if (isBlank(line)) {
      out.push(line);
      continue;
    }
    const lineNumber = index + 1;
    try {
      const body = await formatRecord(line.body, prettier, plugins);
      if (body === null) {
        return failure(
          'format',
          'recordTooLong',
          { line: lineNumber, column: 1 },
          transformExcerpt(text, lineNumber),
        );
      }
      out.push({ body, carriageReturn: line.carriageReturn });
    } catch (error) {
      const loc = locOf(error);
      return failure(
        'format',
        syntaxOrEngine(loc.line !== null || loc.column !== null),
        // Prettier saw ONE line, so its own line number is always 1 and would be
        // a lie about the file; the column it reports is the one that matters.
        { line: lineNumber, column: loc.column },
        transformExcerpt(text, lineNumber),
      );
    }
  }
  return joinLines(out);
}

/** Repair a whole JSON document. */
async function repairWhole(text: string): Promise<string | SandboxTransformFailedMessage> {
  const { jsonrepair } = await import('jsonrepair');
  try {
    return jsonrepair(text);
  } catch (error) {
    const offset = offsetOf(error);
    const position = offset === null ? { line: null, column: null } : positionAt(text, offset);
    return failure(
      'repair',
      syntaxOrEngine(offset !== null),
      position,
      transformExcerpt(text, position.line),
      repairDetailOf(error),
    );
  }
}

/**
 * Run the requested transforms over one document.
 *
 * REPAIR THEN FORMAT, and the order is not interchangeable. The repairer turns
 * something that is not JSON into something that is; the formatter can only read
 * a document that already parses. Reversed, every file worth repairing would
 * fail at the first step.
 *
 * A failure at either step STOPS: nothing half-transformed is ever returned, and
 * the panel's answer to a failure is to offer the original bytes unchanged. That
 * is the whole contract — a document is uploaded exactly as it was, or exactly
 * as the user confirmed, and never as something in between.
 */
export async function runTransform(
  request: Omit<SandboxTransformRequest, 'kind'>,
): Promise<SandboxTransformedMessage | SandboxTransformFailedMessage> {
  const { text, ext, format, repair } = request;
  // A request asking for NEITHER transform is refused HERE as well as at the
  // message boundary, and the duplication is deliberate: `parseTransformRequest`
  // protects the port, this protects the function. Answering "here is your text
  // back" would return `{formatted: false, repaired: false}` with a tool label
  // beside it — a provenance record naming software that never touched the
  // bytes, which is exactly the lie the record exists to prevent.
  if (!format && !repair) {
    return failure('format', 'nothingRequested', { line: null, column: null }, '');
  }
  const syntax = transformSyntaxForExtension(ext);
  if (syntax === null) {
    return failure('format', 'unsupportedType', { line: null, column: null }, '');
  }
  if (repair && !canRepairSyntax(syntax)) {
    return failure('repair', 'repairUnsupported', { line: null, column: null }, '');
  }

  let current = text;
  if (repair) {
    const repaired = syntax === 'jsonl' ? await repairLines(current) : await repairWhole(current);
    if (typeof repaired !== 'string') return repaired;
    current = repaired;
  }

  if (format) {
    // Loaded ONCE, here, and passed down. A repair-only run never reaches this
    // line and therefore never downloads a formatter at all.
    const { prettier, plugins } = await loadPrettier(syntax);
    if (syntax === 'jsonl') {
      const formatted = await formatLines(current, prettier, plugins);
      if (typeof formatted !== 'string') return formatted;
      current = formatted;
    } else {
      try {
        current = await prettier.format(current, {
          ...BASE_OPTIONS,
          parser: parserFor(syntax, ext),
          plugins,
        });
      } catch (error) {
        const position = locOf(error);
        return failure(
          'format',
          syntaxOrEngine(position.line !== null || position.column !== null),
          position,
          // The excerpt comes from the text the FORMATTER saw, which is the
          // repaired text when a repair ran — quoting the original would point
          // at a line the reported number no longer describes.
          transformExcerpt(current, position.line),
        );
      }
    }
  }

  return {
    kind: 'transformed',
    text: current,
    formatted: format,
    repaired: repair,
    ...transformToolLabels(repair, format),
  };
}
