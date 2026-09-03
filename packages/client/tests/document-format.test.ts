// @vitest-environment jsdom
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  MAX_DOCUMENT_TRANSFORM_LABEL_LENGTH,
  MAX_TRANSFORM_EXCERPT_LENGTH,
  MAX_TRANSFORM_MESSAGE_LENGTH,
  REPAIRABLE_TRANSFORM_SYNTAXES,
  TRANSFORM_SYNTAXES,
  canRepairSyntax,
  transformSyntaxForExtension,
  transformSyntaxForName,
} from '@hvault/shared';
import {
  JSONREPAIR_VERSION,
  PRETTIER_VERSION,
  excerptFor,
  firstLine,
  locOf,
  positionAt,
  runTransform,
} from '../src/sandbox/transform/formatEngine';
import { parseTransformRequest } from '../src/sandbox/protocol';
import { transformReplySchema } from '../src/services/documents/transform';
import { diffText } from '../src/lib/textDiff';
import { DOCUMENT_PLAINTEXT_CHUNK_BYTES, documentMetaSchema } from '@hvault/shared';

/**
 * The in-browser format-and-repair engine.
 *
 * These run against the REAL Prettier and the REAL `jsonrepair`, in the tier
 * where that is honest: the engine is a pure function from text to text, and the
 * whole point of the module is what those two libraries do to a document. Mocking
 * either would leave a suite that pins the engine's plumbing and nothing a user
 * would notice.
 *
 * The iframe, the port and the deadlines belong to `document-transform.test.ts`;
 * the panel belongs to `components/documents-upload.test.tsx`.
 */

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

/** Ask for both transforms, which is the combination the panel offers first. */
function request(
  text: string,
  ext: string,
  overrides: { format?: boolean; repair?: boolean } = {},
) {
  return { text, ext, format: overrides.format ?? true, repair: overrides.repair ?? false };
}

describe('the transform vocabulary', () => {
  it('maps every JSON dialect, JSON Lines, Markdown and YAML, and nothing else', () => {
    expect(transformSyntaxForName('a.json')).toBe('json');
    expect(transformSyntaxForName('a.jsonc')).toBe('json');
    expect(transformSyntaxForName('a.json5')).toBe('json');
    expect(transformSyntaxForName('a.jsonl')).toBe('jsonl');
    expect(transformSyntaxForName('a.ndjson')).toBe('jsonl');
    expect(transformSyntaxForName('README.md')).toBe('markdown');
    expect(transformSyntaxForName('a.markdown')).toBe('markdown');
    expect(transformSyntaxForName('a.yaml')).toBe('yaml');
    expect(transformSyntaxForName('a.yml')).toBe('yaml');
    // The negatives are the point: a formatter offered for a type it cannot read
    // is a checkbox that fails after the user has ticked it.
    expect(transformSyntaxForName('a.txt')).toBeNull();
    expect(transformSyntaxForName('a.png')).toBeNull();
    expect(transformSyntaxForName('a.ts')).toBeNull();
    // No extension at all, and a leading-dot name, which has none by the rule
    // `documentExtension` applies everywhere in this application.
    expect(transformSyntaxForName('Dockerfile')).toBeNull();
    expect(transformSyntaxForName('.bashrc')).toBeNull();
    expect(transformSyntaxForExtension('')).toBeNull();
  });

  it('is case-insensitive through the extension rule, not through a second entry', () => {
    expect(transformSyntaxForName('A.JSON')).toBe('json');
    expect(transformSyntaxForName('A.YML')).toBe('yaml');
    // …but the MAP itself is lowercase-only, so nothing looks up an upper-case
    // key directly and finds one.
    expect(transformSyntaxForExtension('JSON')).toBeNull();
  });

  it('offers repair for the JSON family only', () => {
    expect(canRepairSyntax('json')).toBe(true);
    expect(canRepairSyntax('jsonl')).toBe(true);
    expect(canRepairSyntax('markdown')).toBe(false);
    expect(canRepairSyntax('yaml')).toBe(false);
    expect([...REPAIRABLE_TRANSFORM_SYNTAXES].sort()).toEqual(['json', 'jsonl']);
  });

  it('records tool versions that match the packages actually installed', () => {
    // The provenance is sealed into the encrypted metadata and is the only
    // record of what rewrote a user's bytes. A dependency bump that forgets these
    // constants makes that record describe software that never ran.
    const read = (pkg: string): string =>
      (
        JSON.parse(
          readFileSync(path.join(repoRoot, 'node_modules', pkg, 'package.json'), 'utf8'),
        ) as { version: string }
      ).version;
    expect(JSONREPAIR_VERSION).toBe(read('jsonrepair'));
    expect(PRETTIER_VERSION).toBe(read('prettier'));
  });
});

describe('positions and excerpts', () => {
  it('converts a character offset into a 1-based line and column', () => {
    const text = 'one\ntwo\nthree';
    expect(positionAt(text, 0)).toEqual({ line: 1, column: 1 });
    expect(positionAt(text, 3)).toEqual({ line: 1, column: 4 });
    // The newline itself belongs to the line it terminates; the character after
    // it starts the next one.
    expect(positionAt(text, 4)).toEqual({ line: 2, column: 1 });
    expect(positionAt(text, 8)).toEqual({ line: 3, column: 1 });
  });

  it('answers the start of a document that begins with a newline', () => {
    // `lastIndexOf` clamps a negative `fromIndex` to 0 rather than answering -1,
    // so this is the case that reports column 0 without its guard.
    expect(positionAt('\nx', 0)).toEqual({ line: 1, column: 1 });
  });

  it('clamps an offset past the end rather than inventing a position', () => {
    expect(positionAt('ab', 99)).toEqual({ line: 1, column: 3 });
    expect(positionAt('ab', -5)).toEqual({ line: 1, column: 1 });
  });

  it('quotes the offending line, without its carriage return, and marks a cut', () => {
    expect(excerptFor('one\r\ntwo', 1)).toBe('one');
    expect(excerptFor('one\ntwo', 2)).toBe('two');
    // Out of range in both directions answers nothing rather than a wrong line.
    expect(excerptFor('one', 0)).toBe('');
    expect(excerptFor('one', 9)).toBe('');
    expect(excerptFor('one', null)).toBe('');

    const long = 'x'.repeat(MAX_TRANSFORM_EXCERPT_LENGTH + 50);
    const cut = excerptFor(long, 1);
    expect(cut).toHaveLength(MAX_TRANSFORM_EXCERPT_LENGTH);
    expect(cut.endsWith('…')).toBe(true);
  });

  it('reads a position out of a third-party error, or answers null rather than throwing', () => {
    // Prettier's `loc` is a CONVENTION, not a contract: a plugin may throw a
    // plain `Error`, and one of the two call sites can be reached by anything
    // the dynamically-loaded chunk decides to raise. Each shape below is a step
    // of that walk failing, and every one of them must degrade to "no position"
    // — an unguarded `error.loc.start.line` would turn "your YAML has a syntax
    // error on line 3" into a `TypeError` answered by the frame's generic
    // refusal, which is a worse message about a different problem.
    const none = { line: null, column: null };
    expect(locOf(new Error('no loc at all'))).toEqual(none);
    expect(locOf(null)).toEqual(none);
    expect(locOf('a thrown string')).toEqual(none);
    expect(locOf({ loc: 'not an object' })).toEqual(none);
    expect(locOf({ loc: null })).toEqual(none);
    expect(locOf({ loc: {} })).toEqual(none);
    expect(locOf({ loc: { start: null } })).toEqual(none);
    expect(locOf({ loc: { start: 'nope' } })).toEqual(none);
    // A partially-populated `start`: each field is read independently, so a
    // line without a column is still a usable position.
    expect(locOf({ loc: { start: { line: '3', column: 5 } } })).toEqual({ line: null, column: 5 });
    expect(locOf({ loc: { start: { line: 3 } } })).toEqual({ line: 3, column: null });
    // And the shape Prettier actually throws.
    expect(locOf({ loc: { start: { line: 3, column: 1 }, end: { line: 3, column: 2 } } })).toEqual({
      line: 3,
      column: 1,
    });
  });

  it('takes a tool message down to its first line, trimmed, and bounds it', () => {
    // The code frame Prettier appends is dropped: the panel draws its own
    // excerpt, from its own copy of the text, in its own font.
    expect(firstLine('  Unexpected token (1:5)  \n> 1 | {\n    |     ^')).toBe(
      'Unexpected token (1:5)',
    );
    expect(firstLine('')).toBe('');

    // And the bound, which is what stops an over-long sentence taking a
    // positioned failure down with it: the host's reply schema declares
    // `message: z.string().max(MAX_TRANSFORM_MESSAGE_LENGTH)` and REJECTS the
    // whole message past it, so an unbounded one here would turn "line 4,
    // column 12" into "the formatter sent something unexpected".
    const shout = 'e'.repeat(MAX_TRANSFORM_MESSAGE_LENGTH + 500);
    const bounded = firstLine(shout);
    expect(bounded).toHaveLength(MAX_TRANSFORM_MESSAGE_LENGTH);
    expect(bounded.endsWith('…')).toBe(true);
    // The bound is the schema's, not a number invented here — a message this
    // module trimmed must still be one the host will accept.
    expect(
      transformReplySchema.safeParse({
        kind: 'transformFailed',
        stage: 'format',
        message: bounded,
        line: 1,
        column: 1,
        excerpt: '',
      }).success,
    ).toBe(true);
  });
});

describe('repair', () => {
  it('leaves already-valid JSON byte-identical', async () => {
    const text = '{"a":1,"b":[1,2]}';
    const result = await runTransform(request(text, 'json', { format: false, repair: true }));
    expect(result.kind).toBe('transformed');
    if (result.kind !== 'transformed') return;
    expect(result.text).toBe(text);
    expect(result.repaired).toBe(true);
    expect(result.formatted).toBe(false);
    expect(result.tool).toBe('jsonrepair');
    expect(result.toolVersion).toBe(JSONREPAIR_VERSION);
  });

  it('repairs a trailing comma, a single-quoted key, a comment and a truncated array', async () => {
    const broken = `{
  // a note
  'name': "value",
  "list": [1, 2,
}`;
    const result = await runTransform(request(broken, 'json', { format: false, repair: true }));
    expect(result.kind).toBe('transformed');
    if (result.kind !== 'transformed') return;
    // The whole point: what comes out is JSON, and it is the same DATA.
    expect(JSON.parse(result.text)).toEqual({ name: 'value', list: [1, 2] });
    expect(result.text).not.toContain('//');
    expect(result.text).not.toContain("'name'");
  });

  it('stops on two concatenated documents, naming the line and the column', async () => {
    const result = await runTransform(
      request('{"a":1}{"b":2}', 'json', { format: false, repair: true }),
    );
    expect(result.kind).toBe('transformFailed');
    if (result.kind !== 'transformFailed') return;
    expect(result.stage).toBe('repair');
    expect(result.line).toBe(1);
    // Position 7 is the second `{`; a 1-based column is one more than that.
    expect(result.column).toBe(8);
    expect(result.excerpt).toBe('{"a":1}{"b":2}');
    expect(result.message).toContain('position 7');
    // And NOTHING partially repaired escapes: a failure carries no text at all.
    expect(result).not.toHaveProperty('text');
  });

  it('refuses to repair a syntax it has no repairer for', async () => {
    const result = await runTransform(request('# title\n', 'md', { format: false, repair: true }));
    expect(result.kind).toBe('transformFailed');
    if (result.kind !== 'transformFailed') return;
    expect(result.stage).toBe('repair');
    expect(result.message).toContain('JSON family');
    expect(result.line).toBeNull();
  });
});

describe('format', () => {
  it('is idempotent for JSON and for Markdown', async () => {
    for (const [text, ext] of [
      ['{"a":1,"b":{"c":[1,2,3]},"d":"x"}', 'json'],
      ['#  Title\n\n*  one\n*  two\n\n|a|b|\n|-|-|\n|1|2|\n', 'md'],
    ] as const) {
      const once = await runTransform(request(text, ext));
      expect(once.kind).toBe('transformed');
      if (once.kind !== 'transformed') return;
      const twice = await runTransform(request(once.text, ext));
      expect(twice.kind).toBe('transformed');
      if (twice.kind !== 'transformed') return;
      expect(twice.text).toBe(once.text);
    }
  });

  it('normalises a trailing comma without any repair being asked for', async () => {
    // Recorded because the UI copy depends on it: formatting ALONE already
    // accepts some syntax a user would call broken, so the panel must not claim
    // that repair is the only thing that can fix a file.
    const result = await runTransform(request('{"a":1,}', 'json'));
    expect(result.kind).toBe('transformed');
    if (result.kind !== 'transformed') return;
    expect(result.text).toBe('{ "a": 1 }\n');
    expect(result.tool).toBe('prettier');
    expect(result.toolVersion).toBe(PRETTIER_VERSION);
  });

  it('keeps a JSONC comment and reads JSON5 with their own parsers', async () => {
    const jsonc = await runTransform(request('{//keep\n"a":1}', 'jsonc'));
    expect(jsonc.kind).toBe('transformed');
    if (jsonc.kind !== 'transformed') return;
    expect(jsonc.text).toContain('//keep');

    // Strict JSON would reject an unquoted key outright; the json5 parser does not.
    const json5 = await runTransform(request("{a:1,'b':2}", 'json5'));
    expect(json5.kind).toBe('transformed');
    if (json5.kind !== 'transformed') return;
    expect(json5.text.trimEnd()).toBe('{ a: 1, b: 2 }');
  });

  it('reports a broken YAML at the line and column Prettier found it', async () => {
    const result = await runTransform(request('a: 1\nb: [1, 2\n', 'yaml'));
    expect(result.kind).toBe('transformFailed');
    if (result.kind !== 'transformFailed') return;
    expect(result.stage).toBe('format');
    expect(result.line).toBe(3);
    expect(result.column).toBe(1);
    // The tool's own sentence, WITHOUT the code frame it appends: the panel
    // draws its own excerpt from its own copy of the text.
    expect(result.message).toContain('Flow sequence');
    expect(result.message).not.toContain('\n');
  });

  it('preserves CRLF line endings rather than rewriting every line', async () => {
    // Prettier's default rewrites them to LF, which would show up as a diff
    // touching every line of a Windows-authored file — a rewrite the user never
    // asked for, presented as noise they cannot read.
    const result = await runTransform(request('{"a":1,"b":2}\r\n', 'json'));
    expect(result.kind).toBe('transformed');
    if (result.kind !== 'transformed') return;
    expect(result.text).toBe('{ "a": 1, "b": 2 }\r\n');
  });

  it('refuses a file type it cannot read', async () => {
    const result = await runTransform(request('x', 'png'));
    expect(result.kind).toBe('transformFailed');
    if (result.kind !== 'transformFailed') return;
    expect(result.message).toContain('cannot be formatted');
    expect(result.line).toBeNull();
    expect(result.excerpt).toBe('');
  });
});

describe('JSON Lines', () => {
  it('keeps every record on its own line and passes blank lines through', async () => {
    const result = await runTransform(request('{"a":1}\n\n{"b":2}\n', 'jsonl'));
    expect(result.kind).toBe('transformed');
    if (result.kind !== 'transformed') return;
    // A trailing newline leaves an empty final line, which is not a record and
    // must not be parsed as one — every well-formed JSONL file ends that way.
    expect(result.text).toBe('{ "a": 1 }\n\n{ "b": 2 }\n');
  });

  it('reports the failing LINE of a JSON Lines document, not a whole-file offset', async () => {
    const text = '{"a":1}\n{"b":2}{"c":3}\n{"d":4}\n';
    const result = await runTransform(request(text, 'jsonl', { format: false, repair: true }));
    expect(result.kind).toBe('transformFailed');
    if (result.kind !== 'transformFailed') return;
    expect(result.line).toBe(2);
    expect(result.excerpt).toBe('{"b":2}{"c":3}');
    // The column is relative to the LINE. Whole-file offset 15 would be
    // meaningless against a line number.
    expect(result.column).toBe(8);
  });

  it('repairs each record independently', async () => {
    const result = await runTransform(
      request("{'a':1,}\n{b:2}\n", 'ndjson', { format: false, repair: true }),
    );
    expect(result.kind).toBe('transformed');
    if (result.kind !== 'transformed') return;
    expect(result.text).toBe('{"a":1}\n{"b":2}\n');
  });

  it('reports a record the formatter could not read, at its own line', async () => {
    const result = await runTransform(request('{"a":1}\n{"b":}\n', 'jsonl'));
    expect(result.kind).toBe('transformFailed');
    if (result.kind !== 'transformFailed') return;
    expect(result.stage).toBe('format');
    expect(result.line).toBe(2);
    expect(result.excerpt).toBe('{"b":}');
  });
});

describe('repair then format, in that order', () => {
  it('runs both and records both in the provenance', async () => {
    const result = await runTransform(
      request("{'a':1,/*c*/}", 'json', { format: true, repair: true }),
    );
    expect(result.kind).toBe('transformed');
    if (result.kind !== 'transformed') return;
    expect(result.text).toBe('{ "a": 1 }\n');
    expect(result.formatted).toBe(true);
    expect(result.repaired).toBe(true);
    expect(result.tool).toBe('jsonrepair+prettier');
    expect(result.toolVersion).toBe(`${JSONREPAIR_VERSION}+${PRETTIER_VERSION}`);
  });

  it.each([
    ['both', { format: true, repair: true }],
    ['format alone', { format: true, repair: false }],
    ['repair alone', { format: false, repair: true }],
  ])('seals a provenance block the metadata schema accepts, having run %s', async (_l, flags) => {
    // Driven through `runTransform` and validated against the REAL
    // `documentMetaSchema`, not against arithmetic on two string literals: the
    // labels are built by `toolLabels`, both fields are
    // `.max(MAX_DOCUMENT_TRANSFORM_LABEL_LENGTH)` in the schema, and a record
    // that will not seal is a document that cannot be uploaded WITH its
    // provenance — discovered after the user has chosen the file and confirmed
    // the diff. Widen either label past the bound and this goes red.
    const result = await runTransform(request('{"a":1}', 'json', flags));
    expect(result.kind).toBe('transformed');
    if (result.kind !== 'transformed') return;

    const meta = {
      name: 'a.json',
      mime: 'application/json',
      ext: 'json',
      plaintextBytes: 7,
      sha256: 'a'.repeat(64),
      chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
      chunkCount: 1,
      tags: [],
      capturedAt: new Date(0).toISOString(),
      transform: {
        formatted: result.formatted,
        repaired: result.repaired,
        tool: result.tool,
        toolVersion: result.toolVersion,
        originalSha256: 'b'.repeat(64),
      },
    };
    const parsed = documentMetaSchema.safeParse(meta);
    expect(
      parsed.success,
      `${result.tool} ${result.toolVersion}: ${JSON.stringify(parsed.error?.issues ?? [])}`,
    ).toBe(true);
    // And the labels are inside the bound with room to spare, which is what
    // makes a future third tool safe to name here rather than a coin toss.
    expect(result.tool.length).toBeLessThanOrEqual(MAX_DOCUMENT_TRANSFORM_LABEL_LENGTH);
    expect(result.toolVersion.length).toBeLessThanOrEqual(MAX_DOCUMENT_TRANSFORM_LABEL_LENGTH);
  });

  it('stops at the repair stage without ever reaching the formatter', async () => {
    const result = await runTransform(
      request('{"a":1}{"b":2}', 'json', { format: true, repair: true }),
    );
    expect(result.kind).toBe('transformFailed');
    if (result.kind !== 'transformFailed') return;
    expect(result.stage).toBe('repair');
  });

  it('formats a document only the repairer could read, which is what the order buys', async () => {
    // Reversed, the formatter would see `{'a':` and stop, and every file worth
    // repairing would fail at the first step. The success IS the ordering
    // assertion: strict JSON came out of something that was not JSON.
    const result = await runTransform(request("{'a':\n}", 'json', { format: true, repair: true }));
    expect(result.kind).toBe('transformed');
    if (result.kind !== 'transformed') return;
    expect(JSON.parse(result.text)).toEqual({ a: null });
    // And the formatter ran on the REPAIRED text rather than on the original,
    // which is the other half of the order: the original has a newline in the
    // middle and no closing quote, and neither survives.
    expect(result.text).toBe('{ "a": null }\n');
  });
});

describe('the frame validator for a transform request', () => {
  it('accepts a well-formed request', () => {
    expect(
      parseTransformRequest({
        kind: 'transform',
        text: 'x',
        ext: 'json',
        format: true,
        repair: false,
      }),
    ).toEqual({ kind: 'transform', text: 'x', ext: 'json', format: true, repair: false });
  });

  it('refuses a request that asks for neither transform, in the ENGINE too', async () => {
    // The same refusal in both places, because they protect different things:
    // the validator protects the port, the engine protects the function. A
    // "success" here would carry `{formatted: false, repaired: false}` and a
    // tool label — a provenance record naming software that never ran.
    const result = await runTransform({
      text: '{"a":1}',
      ext: 'json',
      format: false,
      repair: false,
    });
    expect(result.kind).toBe('transformFailed');
    if (result.kind !== 'transformFailed') return;
    expect(result.message).toContain('No transform was requested');
    expect(result).not.toHaveProperty('tool');
  });

  it('refuses a request that asks for neither transform', () => {
    // Nothing in the application produces one, so it is a bug or a message from
    // somebody else. Answering "here is your text back" would attach a
    // provenance record describing a transform that never happened.
    expect(
      parseTransformRequest({
        kind: 'transform',
        text: 'x',
        ext: 'json',
        format: false,
        repair: false,
      }),
    ).toBeNull();
  });

  it('refuses anything malformed rather than coercing it', () => {
    expect(parseTransformRequest(null)).toBeNull();
    expect(parseTransformRequest('transform')).toBeNull();
    expect(parseTransformRequest({ kind: 'render' })).toBeNull();
    expect(
      parseTransformRequest({
        kind: 'transform',
        text: 1,
        ext: 'json',
        format: true,
        repair: false,
      }),
    ).toBeNull();
    expect(
      parseTransformRequest({ kind: 'transform', text: 'x', ext: 2, format: true, repair: false }),
    ).toBeNull();
    expect(
      parseTransformRequest({
        kind: 'transform',
        text: 'x',
        ext: 'json',
        format: 'yes',
        repair: false,
      }),
    ).toBeNull();
    expect(
      parseTransformRequest({ kind: 'transform', text: 'x', ext: 'json', format: true, repair: 1 }),
    ).toBeNull();
  });

  it('accepts an empty extension and lets the engine refuse it', () => {
    // The validator does not carry the list of formattable types, which is what
    // keeps that list in ONE place.
    expect(
      parseTransformRequest({ kind: 'transform', text: 'x', ext: '', format: true, repair: false }),
    ).not.toBeNull();
  });
});

describe('every extension the JSON family names has a parser', () => {
  it('formats each of them without falling back to the strict parser silently', async () => {
    const jsonExtensions = Object.entries(TRANSFORM_SYNTAXES)
      .filter(([, syntax]) => syntax === 'json')
      .map(([extension]) => extension);
    expect(jsonExtensions.sort()).toEqual(['json', 'json5', 'jsonc']);
    for (const extension of jsonExtensions) {
      const result = await runTransform(request('{"a":1}', extension));
      expect(result.kind, extension).toBe('transformed');
    }
  });
});

describe('the diff the host computes over the engine output', () => {
  it('describes a formatted document the panel would show', async () => {
    const original = '{"a":1,"b":2}';
    const result = await runTransform(request(original, 'json'));
    expect(result.kind).toBe('transformed');
    if (result.kind !== 'transformed') return;
    const diff = diffText(original, result.text);
    expect(diff.identical).toBe(false);
    expect(diff.linesRemoved).toBe(1);
    expect(diff.hunks).not.toBeNull();
  });

  it('reports "nothing changed" when a repair was a no-op', async () => {
    const original = '{"a":1}';
    const result = await runTransform(request(original, 'json', { format: false, repair: true }));
    expect(result.kind).toBe('transformed');
    if (result.kind !== 'transformed') return;
    expect(diffText(original, result.text).identical).toBe(true);
  });
});
