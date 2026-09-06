/**
 * The document sandbox's renderers, and the two checks that run before any of
 * them: the decoder and the magic-byte sniffer.
 *
 * ## Why these are tested directly, with no iframe
 *
 * Every renderer here is a pure function from bytes to DOM nodes, so jsdom is
 * the honest tier for them: the isolation, the handshake and the port belong to
 * `document-sandbox.test.tsx`, and a real `/sandbox.html` rendering a real
 * document belongs to Playwright. Mixing the three would produce a suite that
 * looked thorough and pinned nothing precisely.
 *
 * ## The rule every case here is ultimately about
 *
 * A document's own bytes reach the page as TEXT NODES and never as markup.
 * Several assertions below are therefore negatives — no element appeared, the
 * source was not re-parsed — because "the right text is on screen" is satisfied
 * equally well by a renderer that built the markup and by one that did not.
 */
import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import {
  MAX_PREVIEW_TABLE_CELLS,
  MAX_PREVIEW_TABLE_COLUMNS,
  MAX_PREVIEW_TEXT_LINES,
  PREVIEW_MAGIC_BYTES,
  PREVIEW_MODES,
  previewModeForName,
} from '@hvault/shared';
import { decodeDocumentText } from '../src/sandbox/decode';
import { previewRefusal } from '../src/sandbox/sniff';
import {
  delimiterFor,
  describeTableTruncation,
  parseDelimited,
  renderTable,
} from '../src/sandbox/renderers/table';
import { HIGHLIGHT_LANGUAGES, renderText } from '../src/sandbox/renderers/text';
import {
  IMAGE_MEDIA_TYPES,
  IMAGE_UNDECODABLE_NOTICE,
  renderImage,
} from '../src/sandbox/renderers/image';
import { MEDIA_TYPES, MEDIA_UNPLAYABLE_NOTICE, renderMedia } from '../src/sandbox/renderers/media';

/** A buffer allocated in THIS realm, the way a structured clone would arrive. */
function bytesOf(text: string): ArrayBuffer {
  const encoded = new TextEncoder().encode(text);
  const buffer = new ArrayBuffer(encoded.byteLength);
  new Uint8Array(buffer).set(encoded);
  return buffer;
}

function rawBytes(values: readonly number[]): ArrayBuffer {
  const buffer = new ArrayBuffer(values.length);
  new Uint8Array(buffer).set(values);
  return buffer;
}

/**
 * A file that opens like `ext` and is otherwise nothing.
 *
 * Built from the table itself rather than from a second copy of each signature,
 * so a test cannot pass against a signature the table no longer carries. A
 * wildcard position is filled with a byte that is not a valid signature byte
 * anywhere, which keeps the fixture honest about what is being matched.
 */
function filesLookingLike(ext: string, extra = 16): ArrayBuffer[] {
  const alternatives = PREVIEW_MAGIC_BYTES[ext];
  if (!alternatives?.length) throw new Error(`${ext} has no signature to build a fixture from`);
  return alternatives.map((signature) =>
    rawBytes([...signature.bytes.map((byte) => byte ?? 0x2a), ...Array<number>(extra).fill(0x41)]),
  );
}

/** The first alternative, for a case that only needs one specimen. */
function fileLookingLike(ext: string, extra = 16): ArrayBuffer {
  return filesLookingLike(ext, extra)[0]!;
}

beforeEach(() => {
  document.body.replaceChildren();
});

afterEach(() => {
  vi.restoreAllMocks();
  document.body.replaceChildren();
});

// ---------------------------------------------------------------------------
// decode.ts
// ---------------------------------------------------------------------------

describe('decoding a document as text', () => {
  it('honours a UTF-8 byte-order mark and leaves no U+FEFF behind', () => {
    const decoded = decodeDocumentText(rawBytes([0xef, 0xbb, 0xbf, 0x68, 0x69]));
    expect(decoded).toMatchObject({ text: 'hi', encoding: 'utf-8', declared: true, warning: null });
    // The mark must not survive as a zero-width character at the head of the
    // first line: it is invisible on screen and enough to make a diff against
    // the same file elsewhere report a difference nobody can see. `TextDecoder`
    // removes it for each of these encodings, and `ignoreBOM: true` is the one
    // option that would put it back — which is what this line fails on.
    expect(decoded.text).not.toContain('\uFEFF');
  });

  it('honours both UTF-16 byte-order marks', () => {
    // 'hi' little-endian and big-endian, each behind its own mark.
    const le = decodeDocumentText(rawBytes([0xff, 0xfe, 0x68, 0x00, 0x69, 0x00]));
    expect(le).toMatchObject({ text: 'hi', encoding: 'utf-16le', declared: true });
    expect(le.text).not.toContain('\uFEFF');
    const be = decodeDocumentText(rawBytes([0xfe, 0xff, 0x00, 0x68, 0x00, 0x69]));
    expect(be).toMatchObject({ text: 'hi', encoding: 'utf-16be', declared: true });
    expect(be.text).not.toContain('\uFEFF');
  });

  it('assumes UTF-8 without a mark, and says the encoding was assumed', () => {
    const decoded = decodeDocumentText(bytesOf('plain ascii'));
    expect(decoded).toMatchObject({ text: 'plain ascii', encoding: 'utf-8', declared: false });
    expect(decoded.warning).toBeNull();
  });

  it('shows a nearly-UTF-8 file rather than refusing it', () => {
    // One truncated multi-byte sequence in a long line of real text. Someone
    // opening this wants to see the file, with a replacement character where
    // the damage is — and one bad byte in a hundred is not "mostly damaged", so
    // no warning is raised either.
    const damaged = new Uint8Array([...new TextEncoder().encode('a'.repeat(120)), 0xe2, 0x82]);
    const buffer = new ArrayBuffer(damaged.byteLength);
    new Uint8Array(buffer).set(damaged);
    const decoded = decodeDocumentText(buffer);
    expect(decoded.text.startsWith('a'.repeat(120))).toBe(true);
    expect(decoded.text).toContain('�');
    expect(decoded.warning).toBeNull();
  });

  it('warns when most of the file did not decode, and still returns the text', () => {
    // Bytes no UTF-8 sequence can begin with. This is what a file that is not
    // text at all looks like through the decoder, and the answer is a warning
    // rather than a refusal: refusing on the bytes' own evidence is `sniff.ts`'s
    // job, and it can name the format instead of guessing.
    const decoded = decodeDocumentText(rawBytes([0xff, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8]));
    expect(decoded.warning).toContain('not valid UTF-8');
    expect(decoded.text.length).toBeGreaterThan(0);
  });

  it('warns when a DECLARED encoding does not decode, naming the declaration', () => {
    // A UTF-8 mark followed by bytes that are not UTF-8: the writer said what
    // this was and was wrong, which is a different sentence from "no mark, and
    // it does not look like text".
    const decoded = decodeDocumentText(rawBytes([0xef, 0xbb, 0xbf, 0xff, 0xfe, 0xfd, 0xfc]));
    expect(decoded.warning).toContain('utf-8');
    expect(decoded.warning).toContain('byte-order mark');
    expect(decoded.declared).toBe(true);
  });

  it('reports an empty file as empty text and no warning', () => {
    expect(decodeDocumentText(new ArrayBuffer(0))).toMatchObject({ text: '', warning: null });
  });
});

// ---------------------------------------------------------------------------
// sniff.ts
// ---------------------------------------------------------------------------

describe('comparing a document’s bytes with what its name claims', () => {
  it('recognises every signature the shared table carries', () => {
    // Built from the table, so this cannot drift into testing a signature that
    // was removed. `%PDF-` is the interesting member: a PDF is never previewed,
    // and its row exists so that a PDF wearing another extension can be NAMED.
    for (const ext of Object.keys(PREVIEW_MAGIC_BYTES)) {
      const mode = PREVIEW_MODES[ext];
      expect(mode, `${ext} has a signature but no mode`).toBeDefined();
      // EVERY alternative, not just the first. A format may have more than one
      // legal opening — `GIF87a` and `GIF89a`, an MP3 with an ID3 tag and six
      // frame-sync variants without one — and testing only the first would let
      // any of the others be deleted with the whole suite still green.
      const specimens = filesLookingLike(ext);
      expect(specimens.length).toBe(PREVIEW_MAGIC_BYTES[ext]?.length);
      specimens.forEach((specimen, index) => {
        expect(
          previewRefusal(mode!, ext, specimen),
          `${ext} alternative ${String(index)}`,
        ).toBeNull();
      });
    }
    expect(PREVIEW_MAGIC_BYTES['pdf']).toBeDefined();
    // The two formats whose alternatives exist for real-world variants rather
    // than for decoration, named so that dropping one is a visible edit.
    expect(PREVIEW_MAGIC_BYTES['gif']).toHaveLength(2);
    expect(PREVIEW_MAGIC_BYTES['mp3']).toHaveLength(7);
  });

  it('refuses a file whose bytes disagree with an extension that has a signature', () => {
    const refusal = previewRefusal('image', 'png', bytesOf('this is plainly not a PNG'));
    expect(refusal).toContain('.png');
    expect(refusal).toContain('PNG');
    expect(refusal).toContain('Download it');
  });

  it('refuses a PDF renamed .md, and says what it actually is', () => {
    // The case Rule A alone cannot reach: `md` has no signature of its own, so a
    // check that only ever validated the CLAIM would hand a PDF to the markdown
    // parser.
    const refusal = previewRefusal('markdown', 'md', fileLookingLike('pdf'));
    expect(refusal).toContain('PDF');
    expect(refusal).toContain('.md');
  });

  it('refuses a JPEG renamed .txt, which no length-based guard would catch', () => {
    // `FF D8 FF` is three bytes, so a ">= 4 bytes to contradict" rule would let
    // the single commonest real-world mislabelling there is fall through to the
    // text renderer as mojibake. `0xFF` cannot begin valid UTF-8, which is what
    // makes the signature decisive despite its length.
    expect(previewRefusal('text', 'txt', fileLookingLike('jpg'))).toContain('JPG');
  });

  it('lets a four-byte printable signature contradict, which is the threshold’s other side', () => {
    // The guard is "a byte that cannot begin text, OR at least four constrained
    // bytes". `OggS` and `fLaC` are FOUR printable bytes and no more, so they sit
    // exactly on that boundary and are the only formats whose refusal depends on
    // it. Without this the threshold could be raised from four to five and
    // nothing would notice; the `n-1` side is pinned by the `ID3,name,album`
    // case below.
    expect(previewRefusal('text', 'txt', fileLookingLike('ogg'))).toContain('OGG');
    expect(previewRefusal('markdown', 'md', fileLookingLike('flac'))).toContain('FLAC');
  });

  it('lets a text file that merely BEGINS like a short signature through', () => {
    // `BM` (bmp) and `ID3` (a tagged MP3) are short PRINTABLE words, and a
    // spreadsheet header or an ordinary sentence can start with either. They may
    // confirm a claim and must never contradict one.
    expect(previewRefusal('text', 'csv', bytesOf('BM,width,height\n1,2,3\n'))).toBeNull();
    expect(previewRefusal('text', 'csv', bytesOf('ID3,name,album\n1,a,b\n'))).toBeNull();
    expect(previewRefusal('markdown', 'md', bytesOf('BMW cars are made in Munich.'))).toBeNull();
  });

  it('lets a CSV whose fifth byte begins "ftyp" through', () => {
    // The ISO base-media signature is anchored at byte 0 by the box size's top
    // octet, which is `0x00` for every conformant file. Written as "ftyp at
    // offset 4" instead, this exact CSV would be reported as a video.
    expect(previewRefusal('text', 'csv', bytesOf('col,ftyp,name\n1,2,3\n'))).toBeNull();
  });

  it('passes every extension that has no signature at all, which is most of them', () => {
    // The one-directional rule. Implemented the other way round — refuse
    // anything matching no known signature — this would reject every shell
    // script and every configuration file in the store while looking like a
    // security feature.
    expect(previewRefusal('code', 'sh', bytesOf('#!/bin/sh\necho hi\n'))).toBeNull();
    expect(previewRefusal('code', 'conf', bytesOf('[unit]\nDescription=x\n'))).toBeNull();
    expect(previewRefusal('markdown', 'md', bytesOf('# Title\n'))).toBeNull();
    expect(previewRefusal('html', 'html', bytesOf('<p>hi</p>'))).toBeNull();
  });

  it('does not refuse a mislabelling that changes nothing about the rendering', () => {
    // A PNG named `.svg` is still an image and still renders. Refusing it would
    // be pedantry with a download button attached.
    expect(previewRefusal('image', 'svg', fileLookingLike('png'))).toBeNull();
  });

  it('reports an empty file as empty rather than as a mismatch', () => {
    // Ahead of every other check: an empty file matches no signature, so without
    // this it would be refused with a sentence about its contents disagreeing
    // with its name — true, and useless.
    const refusal = previewRefusal('image', 'png', new ArrayBuffer(0));
    expect(refusal).toContain('empty');
    expect(refusal).not.toContain('PNG');
  });

  it('names the more specific format when a file satisfies two signatures', () => {
    // An AVIF satisfies the generic ISO base-media signature that `mp4` carries
    // as well as its own; nine constrained bytes beat five.
    expect(previewRefusal('markdown', 'md', fileLookingLike('avif'))).toContain('AVIF');
  });

  it('is not fooled by an extension that names an inherited property', () => {
    // Every table in this document is indexed by an extension taken from a name
    // somebody else chose, so an ordinary object literal would answer
    // `PREVIEW_MAGIC_BYTES['constructor']` with the `Object` FUNCTION and this
    // sniffer would call `.some` on it. The tables are built with no prototype
    // instead, which is what makes the `undefined` branch reachable for these two
    // names — asserted here on the READER, because the shared suite pins the data.
    for (const ext of ['constructor', '__proto__']) {
      expect(() => previewRefusal('text', ext, bytesOf('#!/bin/sh\n'))).not.toThrow();
      expect(previewRefusal('text', ext, bytesOf('#!/bin/sh\n')), ext).toBeNull();
    }
  });

  it('builds every extension-keyed table in this document without a prototype', () => {
    // The structural half, and it is what a future map added with `Object.freeze`
    // would fail. `formatEngine`'s `JSON_PARSERS` is not exported and is not
    // listed here; it is also not reachable with an inherited name, because
    // `parserFor` is only called for an extension that already answered a real
    // syntax through `TRANSFORM_SYNTAXES`, which the shared suite pins.
    for (const table of [HIGHLIGHT_LANGUAGES, IMAGE_MEDIA_TYPES, MEDIA_TYPES]) {
      expect(Object.getPrototypeOf(table)).toBeNull();
    }
  });
});

// ---------------------------------------------------------------------------
// table.ts
// ---------------------------------------------------------------------------

describe('parsing delimited data', () => {
  it('knows which extensions are tabular and which are not', () => {
    expect(delimiterFor('csv')).toBe(',');
    expect(delimiterFor('tsv')).toBe('\t');
    expect(delimiterFor('txt')).toBeNull();
    expect(delimiterFor('json')).toBeNull();
  });

  it('reads quoted fields containing the delimiter, a newline and a doubled quote', () => {
    const parsed = parseDelimited('a,"b,c","d\ne","f""g"\n', ',');
    expect(parsed.rows).toEqual([['a', 'b,c', 'd\ne', 'f"g']]);
    expect(parsed.totalRows).toBe(1);
  });

  it('ends a row at LF and at CRLF, and adds no phantom row for a trailing newline', () => {
    expect(parseDelimited('a,b\r\nc,d\n', ',').rows).toEqual([
      ['a', 'b'],
      ['c', 'd'],
    ]);
    // A file that does NOT end in a newline still has its last row.
    expect(parseDelimited('a,b\nc,d', ',').rows).toHaveLength(2);
  });

  it('counts rows past the cap even though it keeps none of them', () => {
    const rows = Array.from({ length: MAX_PREVIEW_TEXT_LINES + 5 }, (_, i) => `${String(i)},x`);
    const parsed = parseDelimited(`${rows.join('\n')}\n`, ',');
    expect(parsed.rows).toHaveLength(MAX_PREVIEW_TEXT_LINES);
    expect(parsed.truncated).toBe(true);
    // The real size, so the notice can say how much is missing rather than "some".
    expect(parsed.totalRows).toBe(MAX_PREVIEW_TEXT_LINES + 5);
  });

  it('reports an empty document as no rows at all', () => {
    expect(parseDelimited('', ',')).toMatchObject({ rows: [], truncated: false, totalRows: 0 });
  });

  it('counts the columns past the ceiling even though it keeps none of them', () => {
    // The row cap is not a node budget: a table's node count is rows TIMES
    // columns, and the width comes from the file. `MAX_PREVIEW_BYTES` is 25 MiB,
    // so a single line of nothing but commas asks for twenty-six million cells
    // in one row — and the array of empty strings is a quarter of a gigabyte
    // before one element exists, which is why the cap is applied HERE and not
    // only at render time.
    const fields = MAX_PREVIEW_TABLE_COLUMNS + 6;
    const parsed = parseDelimited(`${'x,'.repeat(fields - 1)}x\n`, ',');

    expect(parsed.rows[0]).toHaveLength(MAX_PREVIEW_TABLE_COLUMNS);
    expect(parsed.columns).toBe(MAX_PREVIEW_TABLE_COLUMNS);
    expect(parsed.columnsTruncated).toBe(true);
    // The real width, so the notice can name it rather than saying "some".
    expect(parsed.totalColumns).toBe(fields);
    // And the negative that keeps the two dimensions apart: nothing was cut
    // vertically, so nothing may claim it was.
    expect(parsed.truncated).toBe(false);
    expect(parsed.totalRows).toBe(1);
  });

  it('leaves a row EXACTLY at the column ceiling alone', () => {
    // The other side of the bound. `n + 6` above proves the cap fires; this
    // proves it does not fire one column early, which is the edit that would
    // quietly cut a real file's last column and report it as truncated.
    const atBound = parseDelimited(`${'x,'.repeat(MAX_PREVIEW_TABLE_COLUMNS - 1)}x\n`, ',');
    expect(atBound.rows[0]).toHaveLength(MAX_PREVIEW_TABLE_COLUMNS);
    expect(atBound.columns).toBe(MAX_PREVIEW_TABLE_COLUMNS);
    expect(atBound.totalColumns).toBe(MAX_PREVIEW_TABLE_COLUMNS);
    expect(atBound.columnsTruncated).toBe(false);

    // And one past it, which is the same file with a single extra comma.
    const overBound = parseDelimited(`${'x,'.repeat(MAX_PREVIEW_TABLE_COLUMNS)}x\n`, ',');
    expect(overBound.rows[0]).toHaveLength(MAX_PREVIEW_TABLE_COLUMNS);
    expect(overBound.totalColumns).toBe(MAX_PREVIEW_TABLE_COLUMNS + 1);
    expect(overBound.columnsTruncated).toBe(true);
  });

  it('drops rows once the CELL budget is spent, at a height the row cap never reaches', () => {
    // The column ceiling alone still permits 50,000 x 1,000, which is fifty
    // million cells. The budget that bites here is the PRODUCT, and it bites
    // 400 rows into a file the row cap would have waved through whole.
    const columns = 700;
    const row = Array.from({ length: columns }, () => 'x').join(',');
    const rowCount = 400;
    const parsed = parseDelimited(
      `${Array.from({ length: rowCount }, () => row).join('\n')}\n`,
      ',',
    );

    // floor(250,000 / 700). Written as the number rather than as the division,
    // so this cannot pass by re-implementing the code it is checking.
    expect(parsed.rows).toHaveLength(357);
    expect(parsed.columns).toBe(columns);
    expect(parsed.rows.length * parsed.columns).toBeLessThanOrEqual(MAX_PREVIEW_TABLE_CELLS);
    expect(rowCount).toBeLessThan(MAX_PREVIEW_TEXT_LINES);
    expect(parsed.truncated).toBe(true);
    expect(parsed.totalRows).toBe(rowCount);
    // Nothing was cut horizontally: 700 is under the ceiling.
    expect(parsed.columnsTruncated).toBe(false);
  });

  it('counts a late wide row rather than throwing away the rows already kept', () => {
    // ONE pathological row is enough to blow the budget, because every other row
    // is PADDED out to the widest one. The choice made here is to keep the rows
    // a reader is already looking at — a file reads in order — and to count the
    // row that would have widened them.
    const wide = Array.from({ length: 1_200 }, (_, index) => `w${String(index)}`).join(',');
    const narrow = Array.from({ length: 300 }, (_, index) => `a${String(index)},b,c`).join('\n');
    const parsed = parseDelimited(`${narrow}\n${wide}\n`, ',');

    expect(parsed.rows).toHaveLength(300);
    expect(parsed.columns).toBe(3);
    expect(parsed.truncated).toBe(true);
    expect(parsed.totalRows).toBe(301);
    expect(parsed.columnsTruncated).toBe(true);
    expect(parsed.totalColumns).toBe(1_200);
    // Had the wide row been kept, the table would be 301 x 1,200 = 361,200 cells.
    expect(parsed.rows.length * parsed.columns).toBeLessThanOrEqual(MAX_PREVIEW_TABLE_CELLS);
  });
});

describe('describing what a table preview cut', () => {
  /** A table of the given shape, with no cells: only the counts are read. */
  const shaped = (
    rows: number,
    totalRows: number,
    columns: number,
    totalColumns: number,
  ): Parameters<typeof describeTableTruncation>[0] => ({
    rows: Array.from({ length: rows }, () => []),
    truncated: totalRows > rows,
    totalRows,
    columns,
    columnsTruncated: totalColumns > columns,
    totalColumns,
  });

  it('says nothing at all about a table that fitted', () => {
    // The negative that keeps the notice meaningful: a banner on every CSV is a
    // banner nobody reads.
    expect(describeTableTruncation(shaped(3, 3, 4, 4))).toBeNull();
  });

  it('names the ROW count kept, not the row cap, because the cell budget cuts rows too', () => {
    // The bug this replaces: the sentence quoted `MAX_PREVIEW_TEXT_LINES`
    // verbatim, so a file cut by the cell budget was told "the first 50000"
    // while 357 rows were on screen.
    expect(describeTableTruncation(shaped(357, 400, 700, 700))).toBe(
      'Showing the first 357 of 400 rows',
    );
  });

  it('names the columns when only the width was cut', () => {
    expect(describeTableTruncation(shaped(1, 1, 1_000, 26_001))).toBe(
      'Showing the first 1000 of 26001 columns',
    );
  });

  it('names BOTH dimensions when both were cut, because either alone is a lie', () => {
    // A reader told only about the rows has no way to know the columns they can
    // see are not all of them, and vice versa.
    expect(describeTableTruncation(shaped(300, 301, 3, 1_200))).toBe(
      'Showing the first 300 of 301 rows and the first 3 of 1200 columns',
    );
  });
});

// ---------------------------------------------------------------------------
// text.ts
// ---------------------------------------------------------------------------

describe('rendering text and code', () => {
  it('puts the file in a single text node and never in markup', async () => {
    const rendered = await renderText(document, bytesOf('<script>alert(1)</script>\nplain'), 'txt');
    const code = rendered.querySelector('.hv-lines code');

    expect(code?.childNodes).toHaveLength(1);
    expect(code?.childNodes[0]?.nodeType).toBe(Node.TEXT_NODE);
    expect(code?.textContent).toBe('<script>alert(1)</script>\nplain');
    // The negative that is the assertion: had this built a markup string, the
    // file would have contributed an element to the tree.
    expect(rendered.querySelector('script')).toBeNull();
    expect(code?.children).toHaveLength(0);
  });

  it('numbers the lines with one text node rather than one element per line', async () => {
    const rendered = await renderText(document, bytesOf('one\ntwo\nthree\n'), 'txt');
    const gutter = rendered.querySelector('.hv-gutter');

    expect(gutter?.textContent).toBe('1\n2\n3');
    expect(gutter?.childNodes).toHaveLength(1);
    // 50,000 lines is 50,000 elements under the obvious implementation, and it
    // is the node count rather than the byte count that stops a tab responding.
    expect(gutter?.children).toHaveLength(0);
    // A visual affordance, not content: announcing "one two three" between the
    // lines of a shell script makes the script unreadable.
    expect(gutter?.getAttribute('aria-hidden')).toBe('true');
  });

  it('truncates past the line cap, with the count and the byte size', async () => {
    const text = `${Array.from({ length: MAX_PREVIEW_TEXT_LINES + 7 }, (_, i) => `line ${String(i)}`).join('\n')}\n`;
    const rendered = await renderText(document, bytesOf(text), 'txt');

    const notice = rendered.querySelector('.hv-notice');
    expect(notice?.textContent).toContain(String(MAX_PREVIEW_TEXT_LINES));
    expect(notice?.textContent).toContain(String(MAX_PREVIEW_TEXT_LINES + 7));
    expect(notice?.textContent).toContain('Download the file');
    // Kept exactly at the cap, not one line either side of it.
    expect(rendered.querySelector('.hv-gutter')?.textContent?.split('\n')).toHaveLength(
      MAX_PREVIEW_TEXT_LINES,
    );
  });

  it('says nothing about truncation for a file that fits', async () => {
    const rendered = await renderText(document, bytesOf('one\ntwo\n'), 'txt');
    expect(rendered.querySelector('.hv-notice')).toBeNull();
  });

  it('shows the encoding warning above a file that barely decoded', async () => {
    const rendered = await renderText(document, rawBytes([0xff, 0xfd, 0xfc, 0xfb]), 'txt');
    expect(rendered.querySelector('.hv-notice')?.textContent).toContain('not valid UTF-8');
    // And still shows the file, because refusing is the sniffer's job.
    expect(rendered.querySelector('.hv-lines')).not.toBeNull();
  });

  it('highlights a language the bundle carries', async () => {
    const rendered = await renderText(document, bytesOf('const x = 1;\n'), 'js');
    const code = rendered.querySelector('.hv-lines code');
    expect(code?.className).toBe('hljs');
    expect(code?.querySelector('.hljs-keyword')?.textContent).toBe('const');
  });

  it('falls back to plain text for an extension with no grammar', async () => {
    // `.ps1` is the documented case: `powershell` is not in lowlight's common
    // set, so a PowerShell script renders unhighlighted rather than not at all.
    const rendered = await renderText(document, bytesOf('Get-ChildItem\n'), 'ps1');
    const code = rendered.querySelector('.hv-lines code');
    expect(code?.textContent).toBe('Get-ChildItem\n');
    expect(code?.querySelector('span')).toBeNull();
    expect(code?.className).toBe('');
  });

  it('names only languages the bundle actually registers', async () => {
    // The table decides whether the highlighter is downloaded AT ALL, without
    // loading it, so a value it names that lowlight does not register would
    // degrade silently to plain text and read as a styling bug.
    const { createLowlight, common } = await import('lowlight');
    const lowlight = createLowlight(common);
    for (const [ext, language] of Object.entries(HIGHLIGHT_LANGUAGES)) {
      expect(lowlight.registered(language), `${ext} claims ${language}`).toBe(true);
    }
    // And every key is an extension the map actually offers as `code`.
    for (const ext of Object.keys(HIGHLIGHT_LANGUAGES)) {
      expect(PREVIEW_MODES[ext], `${ext} has a grammar but no mode`).toBeDefined();
    }
  });

  it('renders a CSV as a table of text nodes, never as a formula', async () => {
    // `=cmd|' /C calc'!A0` is the classic CSV-injection payload: a formula to
    // Excel, Numbers and Sheets. It is a string here, shown EXACTLY as stored —
    // not escaped, not prefixed, not stripped — because the reader is looking at
    // this to find out what the file contains, and the danger belongs to the
    // spreadsheet it is opened in after it is downloaded.
    const payload = "=cmd|' /C calc'!A0";
    // A second cell that IS markup, and it is the one that makes the negative
    // discriminate. The formula payload contains no tags, so `textContent` and
    // `innerHTML` produce an identical tree for it — a renderer that built the
    // cell as markup would pass every assertion about the formula alone.
    // No double quotes in the payload: inside a quoted CSV field they would have
    // to be doubled, and the fixture would then be testing the parser's escaping
    // rather than the renderer's node building.
    const markup = '<img src=x onerror=alert(1)>';
    const rendered = await renderText(
      document,
      bytesOf(`name,value,markup\nrow,"${payload}","${markup}"\n`),
      'csv',
    );
    document.body.append(rendered);

    const cells = rendered.querySelectorAll('td');
    expect(rendered.querySelectorAll('th')).toHaveLength(3);
    expect(cells[1]?.textContent).toBe(payload);
    expect(cells[1]?.childNodes[0]?.nodeType).toBe(Node.TEXT_NODE);
    expect(cells[2]?.textContent).toBe(markup);
    expect(cells[2]?.children).toHaveLength(0);
    expect(rendered.querySelector('img')).toBeNull();
  });

  it('pads a ragged row instead of dropping it', async () => {
    const rendered = await renderText(document, bytesOf('a,b,c\n1,2\n'), 'csv');
    expect(rendered.querySelectorAll('tbody tr')).toHaveLength(1);
    expect(rendered.querySelectorAll('tbody td')).toHaveLength(3);
  });

  it('puts no notice at all above a CSV that fitted, and none above an empty one', async () => {
    // The negative that keeps the notice meaningful. Without it, a notice built
    // unconditionally reads `null (12 bytes). Download the file to see all of
    // it.` above every spreadsheet in the vault, and every assertion that only
    // looks for text INSIDE a notice still passes.
    const fitted = await renderText(document, bytesOf('a,b\n1,2\n'), 'csv');
    expect(fitted.querySelector('.hv-notice')).toBeNull();
    expect(fitted.querySelectorAll('th')).toHaveLength(2);

    // And a `.csv` with no bytes at all, which reaches `renderTable` with no
    // header row and must render an empty table rather than throw.
    const empty = await renderText(document, new ArrayBuffer(0), 'csv');
    expect(empty.querySelector('.hv-notice')).toBeNull();
    expect(empty.querySelector('table')).not.toBeNull();
    expect(empty.querySelectorAll('th')).toHaveLength(0);
    expect(empty.querySelectorAll('tr')).toHaveLength(0);
  });

  it('clamps a single unbounded row to the column ceiling and says so', async () => {
    // The shape of the defect: 26,001 empty fields on ONE line is well under
    // MAX_PREVIEW_BYTES, and the table was built EAGERLY — not behind the view
    // toggle — so the tab died on opening the document, with no notice, because
    // no ROW had been dropped and the notice only ever counted rows.
    const rendered = await renderText(document, bytesOf(`${','.repeat(26_000)}\n`), 'csv');

    expect(rendered.querySelectorAll('th')).toHaveLength(MAX_PREVIEW_TABLE_COLUMNS);
    expect(rendered.querySelectorAll('td')).toHaveLength(0);

    const said = rendered.querySelector('.hv-notice')?.textContent ?? '';
    expect(said).toContain(`the first ${String(MAX_PREVIEW_TABLE_COLUMNS)} of 26001 columns`);
    expect(said).toContain('Download the file to see all of it.');
    // The file is one row and all of it is on screen, so the notice must not
    // claim rows are missing.
    expect(said).not.toContain('rows');
  });

  it('bounds the CELL count of a file one wide row would blow up, and names both cuts', async () => {
    // 300 ordinary three-column rows and one 1,200-field row. Every row is
    // padded out to the widest, so this asked for 361,200 cells and reported
    // nothing missing — the row count and the total row count agreed, because
    // the row that broke it was a WIDTH.
    const wide = Array.from({ length: 1_200 }, (_, index) => `w${String(index)}`).join(',');
    const narrow = Array.from({ length: 300 }, (_, index) => `a${String(index)},b,c`).join('\n');
    const rendered = await renderText(document, bytesOf(`${narrow}\n${wide}\n`), 'csv');

    const cells = rendered.querySelectorAll('th').length + rendered.querySelectorAll('td').length;
    expect(cells).toBeLessThanOrEqual(MAX_PREVIEW_TABLE_CELLS);
    // Exactly, not merely under: the first row is the header, the other 299 are
    // body rows, and every one is three cells wide.
    expect(rendered.querySelectorAll('th')).toHaveLength(3);
    expect(rendered.querySelectorAll('td')).toHaveLength(299 * 3);

    const said = rendered.querySelector('.hv-notice')?.textContent ?? '';
    expect(said).toContain('the first 300 of 301 rows');
    expect(said).toContain('the first 3 of 1200 columns');
  });

  it('re-applies the budget in renderTable, which is where the elements are made', async () => {
    // `renderText` builds the table on FIRST render rather than behind the view
    // toggle, so this function is the last place before the elements exist. A
    // caller assembling a DelimitedTable itself would otherwise decide how many
    // this document creates — and the row budget is spent at the width the
    // caller DECLARED, so a table claiming a hundred thousand columns buys one
    // row rather than 250 of them at a width it never had.
    const table = renderTable(document, {
      rows: Array.from({ length: 3 }, () => ['a', 'b', 'c', 'd']),
      truncated: false,
      totalRows: 3,
      columns: MAX_PREVIEW_TABLE_CELLS,
      columnsTruncated: false,
      totalColumns: MAX_PREVIEW_TABLE_CELLS,
    });

    expect(table.querySelectorAll('th')).toHaveLength(MAX_PREVIEW_TABLE_COLUMNS);
    expect(table.querySelectorAll('tbody tr')).toHaveLength(0);
    expect(table.querySelectorAll('td')).toHaveLength(0);
  });

  it('builds no rows for a table that declares no columns', async () => {
    // A width of zero prices a row at nothing, so the cell budget buys every
    // row in the array and each renders as an empty `<tr>`. The parser never
    // produces that shape — a kept row always has at least one field — but this
    // function is the defensive boundary, and a boundary that answers "250,000
    // empty rows" to a degenerate input is not defending anything.
    const table = renderTable(document, {
      rows: Array.from({ length: 5 }, () => ['a']),
      truncated: false,
      totalRows: 5,
      columns: 0,
      columnsTruncated: false,
      totalColumns: 0,
    });

    expect(table.querySelectorAll('tr')).toHaveLength(0);
    expect(table.querySelectorAll('th')).toHaveLength(0);
    expect(table.querySelectorAll('td')).toHaveLength(0);
  });

  it('offers the raw text behind a CSV, and builds it only when asked', async () => {
    const rendered = await renderText(document, bytesOf('a,b\n1,2\n'), 'csv');
    document.body.append(rendered);
    const toggle = rendered.querySelector<HTMLButtonElement>('.hv-toggle');

    expect(toggle?.textContent).toBe('Show raw text');
    expect(toggle?.getAttribute('aria-pressed')).toBe('false');
    expect(rendered.querySelector('table')).not.toBeNull();

    toggle?.click();
    expect(toggle?.getAttribute('aria-pressed')).toBe('true');
    expect(toggle?.textContent).toBe('Show table');
    expect(rendered.querySelector('table')).toBeNull();
    expect(rendered.querySelector('.hv-lines code')?.textContent).toBe('a,b\n1,2\n');

    toggle?.click();
    expect(rendered.querySelector('table')).not.toBeNull();
  });

  it('pretty-prints JSON and keeps the original a click away', async () => {
    const original = '{"b":1,"a":[2,3]}';
    const rendered = await renderText(document, bytesOf(original), 'json');
    document.body.append(rendered);

    const formatted = rendered.querySelector('.hv-lines code')?.textContent;
    expect(formatted).toBe('{\n  "b": 1,\n  "a": [\n    2,\n    3\n  ]\n}');
    // Key order is PRESERVED. Re-ordering would be a silent edit to a document
    // the reader is looking at precisely to see what is in it.
    expect(formatted?.indexOf('"b"')).toBeLessThan(formatted?.indexOf('"a"') ?? 0);

    rendered.querySelector<HTMLButtonElement>('.hv-toggle')?.click();
    expect(rendered.querySelector('.hv-lines code')?.textContent).toBe(original);
  });

  it('raises the line-cap notice against the FORMATTED text, not the source', async () => {
    // The case the notice exists for, and the one an intuition gets backwards:
    // this document is ONE line as stored and cannot trip a line cap, while
    // pretty-printing it produces four lines per element. Measuring the raw view
    // instead would cut a 60,000-line formatted document silently while the view
    // one click away reported nothing missing.
    // A flat array of numbers: compact it is ONE line, and pretty-printed it is
    // one line per element plus the two brackets — so the cap is crossed by
    // exactly five lines, which is the smallest input that reaches this branch.
    const source = JSON.stringify(
      Array.from({ length: MAX_PREVIEW_TEXT_LINES + 3 }, (_, index) => index),
    );
    expect(source.split('\n')).toHaveLength(1);

    const rendered = await renderText(document, bytesOf(source), 'json');
    const notice = rendered.querySelector('.hv-notice');
    expect(notice?.textContent).toContain('formatted lines');
    expect(notice?.textContent).toContain(String(MAX_PREVIEW_TEXT_LINES));
    expect(notice?.textContent).toContain('Download the file');
    // Cut exactly at the cap, and the notice is about the view being shown.
    expect(rendered.querySelector('.hv-lines code')?.textContent?.split('\n')).toHaveLength(
      MAX_PREVIEW_TEXT_LINES,
    );
  });

  it('says nothing about truncation for a JSON document whose formatted form fits', async () => {
    // The negative, without which the assertion above passes on a renderer that
    // shows the notice unconditionally.
    const rendered = await renderText(document, bytesOf('{"a":1}'), 'json');
    expect(rendered.querySelector('.hv-notice')).toBeNull();
  });

  it('pretty-prints one JSON document per line for JSONL', async () => {
    const rendered = await renderText(document, bytesOf('{"a":1}\n{"b":2}\n'), 'jsonl');
    expect(rendered.querySelector('.hv-lines code')?.textContent).toBe(
      '{\n  "a": 1\n}\n\n{\n  "b": 2\n}',
    );
  });

  it('shows a JSON document that does not parse as its own source, with no toggle', async () => {
    // `.json5` and `.jsonc` are the expected failures — comments and trailing
    // commas are not JSON — and so is a file that is simply broken. Showing the
    // source is the honest rendering; repairing it is the upload path's job,
    // with the user's confirmation.
    const rendered = await renderText(document, bytesOf('{"a":1,}\n'), 'json');
    expect(rendered.querySelector('.hv-toggle')).toBeNull();
    expect(rendered.querySelector('.hv-lines code')?.textContent).toBe('{"a":1,}\n');
  });

  it('reports a truncated file in the units a person reads', async () => {
    // The notice carries the file's SIZE as well as its line count, and the size
    // is what tells a reader whether "the first 50,000 lines" is most of the
    // document or a hundredth of it. Megabytes, kilobytes and bytes are three
    // branches; a file large enough to truncate is the megabyte one.
    const line = `${'x'.repeat(30)}\n`;
    const text = line.repeat(MAX_PREVIEW_TEXT_LINES + 3);
    const rendered = await renderText(document, bytesOf(text), 'txt');
    expect(rendered.querySelector('.hv-notice')?.textContent).toMatch(/\d+\.\d MB/);
  });

  it('keeps the truncation notice on the raw view behind a CSV toggle', async () => {
    // The two views truncate independently: a reader who switches to the raw
    // text of a very long CSV must be told there too, or the table said the file
    // was cut and the text silently pretends otherwise.
    const rows = Array.from({ length: MAX_PREVIEW_TEXT_LINES + 4 }, (_, i) => `${String(i)},x`);
    const rendered = await renderText(document, bytesOf(`${rows.join('\n')}\n`), 'csv');
    document.body.append(rendered);

    rendered.querySelector<HTMLButtonElement>('.hv-toggle')?.click();
    const notices = [...rendered.querySelectorAll('.hv-notice')].map((n) => n.textContent ?? '');
    expect(notices.some((text) => text.includes('Download the file'))).toBe(true);
    expect(rendered.querySelector('.hv-plain .hv-notice')).not.toBeNull();
    // Two columns at the row cap is 100,000 cells, comfortably inside the cell
    // budget, so ROWS are the only thing cut and the notice says only that.
    expect(
      notices.some(
        (text) =>
          text.includes(`the first ${String(MAX_PREVIEW_TEXT_LINES)} of 50004 rows`) &&
          !text.includes('columns'),
      ),
    ).toBe(true);
  });

  it('renders an empty file as an empty preview rather than a failure', async () => {
    const rendered = await renderText(document, new ArrayBuffer(0), 'txt');
    expect(rendered.querySelector('.hv-lines code')?.textContent).toBe('');
  });

  it('renders an empty file whose extension DOES have a grammar, highlighter and all', async () => {
    // `.txt` above never reaches the highlighter, so it cannot cover this. An
    // empty `.js` does, and it is the one input for which lowlight returns a
    // root with NO CHILDREN (measured: `''` -> 0 children, `' '` -> 1). An empty
    // hast root is exactly the tree for which `hast-util-to-dom` builds a
    // `Document` instead of a fragment regardless of `fragment: true`, and
    // `replaceChildren` on a `Document` throws `HierarchyRequestError` — which
    // `sourceView`'s best-effort catch swallowed, silently downgrading the file
    // to the unhighlighted presentation.
    const rendered = await renderText(document, new ArrayBuffer(0), 'js');
    const code = rendered.querySelector('.hv-lines code');
    expect(code?.textContent).toBe('');
    // The SAME presentation an empty file gets in every other highlightable
    // language, rather than one that silently lost its code styling.
    expect(code?.className).toBe('hljs');
  });
});

// ---------------------------------------------------------------------------
// image.ts and media.ts
// ---------------------------------------------------------------------------

/**
 * `URL.createObjectURL`, which jsdom does not implement.
 *
 * Installed as a PROPERTY on the real `URL` rather than through
 * `vi.stubGlobal('URL', ...)`: replacing the global with an object literal takes
 * the CONSTRUCTOR with it, and anything under test that calls `new URL(...)`
 * then fails with "URL is not a constructor" from a line nowhere near the stub.
 */
interface BlobUrlMinting {
  createObjectURL?: (blob: Blob) => string;
  revokeObjectURL?: (url: string) => void;
}

describe('rendering images and media', () => {
  let created: { readonly type: string }[];
  const urlGlobal = URL as unknown as BlobUrlMinting;

  beforeEach(() => {
    created = [];
    // The MEDIA TYPE the seam is handed is what gets asserted — it is the part
    // production depends on, and the part a wrong table breaks.
    urlGlobal.createObjectURL = (blob: Blob) => {
      created.push({ type: blob.type });
      return `blob:test/${String(created.length)}`;
    };
    urlGlobal.revokeObjectURL = () => undefined;
  });

  afterEach(() => {
    delete urlGlobal.createObjectURL;
    delete urlGlobal.revokeObjectURL;
  });

  it('renders an image from a blob URL it minted itself', async () => {
    const rendered = renderImage(document, bytesOf('not really a png'), 'png');
    const image = rendered.querySelector('img');

    expect(image?.getAttribute('src')).toBe('blob:test/1');
    expect(created[0]?.type).toBe('image/png');
    // A generic, non-empty alternative text: the document's NAME is never sent
    // to this frame, and an EMPTY alt would declare the image decorative when
    // the image is the entire document.
    expect(image?.getAttribute('alt')).not.toBe('');
    expect(image?.getAttribute('alt')).toBeTruthy();
  });

  it('renders SVG through <img> and never as markup', async () => {
    const svg = '<svg xmlns="http://www.w3.org/2000/svg" onload="window.__pwned=1"></svg>';
    const rendered = renderImage(document, bytesOf(svg), 'svg');
    document.body.append(rendered);

    expect(created[0]?.type).toBe('image/svg+xml');
    expect(rendered.querySelector('img')).not.toBeNull();
    // An `<img>` renders an SVG's graphics and does not run its scripts; the
    // same bytes inserted as markup would run everything they contain.
    expect(rendered.querySelector('svg')).toBeNull();
    expect(rendered.innerHTML).not.toContain('onload');
    expect(rendered.innerHTML).not.toContain('<svg');
  });

  it('labels a blob it has no media type for as opaque bytes rather than guessing', async () => {
    // Reachable only through drift — a new `image` extension the table was not
    // taught about — and the answer is a type the browser will refuse rather
    // than a plausible-looking lie. The negative matters more than the value:
    // labelling unknown bytes `image/png` is how a decoder gets handed something
    // it was never meant to parse.
    const rendered = renderImage(document, bytesOf('bytes'), 'zzz');
    expect(created[0]?.type).toBe('application/octet-stream');
    expect(rendered.querySelector('img')).not.toBeNull();
  });

  it('explains a file that will not decode instead of showing a broken glyph', async () => {
    const rendered = renderImage(document, bytesOf('junk'), 'png');
    rendered.querySelector('img')?.dispatchEvent(new Event('error'));

    expect(rendered.querySelector('img')).toBeNull();
    expect(rendered.textContent).toBe(IMAGE_UNDECODABLE_NOTICE);
  });

  it('plays audio and video with controls and never with autoplay', async () => {
    const video = renderMedia(document, bytesOf('x'), 'mp4');
    expect(video.querySelector('video')?.controls).toBe(true);
    expect(video.querySelector('video')?.autoplay).toBe(false);
    expect(created[0]?.type).toBe('video/mp4');

    const audio = renderMedia(document, bytesOf('x'), 'mp3');
    expect(audio.querySelector('audio')?.controls).toBe(true);
    expect(audio.querySelector('audio')?.autoplay).toBe(false);
    expect(created[1]?.type).toBe('audio/mpeg');
  });

  it('explains a recording this browser cannot play', async () => {
    const rendered = renderMedia(document, bytesOf('x'), 'mp4');
    rendered.querySelector('video')?.dispatchEvent(new Event('error'));
    expect(rendered.querySelector('video')).toBeNull();
    expect(rendered.textContent).toBe(MEDIA_UNPLAYABLE_NOTICE);
  });

  it('knows a media type for every extension the shared map offers', () => {
    // The drift this catches is silent: a new `media` extension with no entry
    // here would be handed to a `<video>` inside an `application/octet-stream`
    // blob, and the failure would look like an unplayable file.
    for (const [ext, mode] of Object.entries(PREVIEW_MODES)) {
      if (mode === 'image') expect(IMAGE_MEDIA_TYPES[ext], ext).toBeDefined();
      if (mode === 'media') expect(MEDIA_TYPES[ext], ext).toBeDefined();
    }
    // And neither table claims an extension the map does not offer in that mode.
    for (const ext of Object.keys(IMAGE_MEDIA_TYPES)) expect(PREVIEW_MODES[ext]).toBe('image');
    for (const ext of Object.keys(MEDIA_TYPES)) expect(PREVIEW_MODES[ext]).toBe('media');
  });

  it('says so rather than guessing when a media extension has no entry', () => {
    // Reachable only through drift, which is exactly why it must not present as
    // a silent `<video>` with an octet-stream blob.
    const rendered = renderMedia(document, bytesOf('x'), 'zzz');
    expect(rendered.textContent).toBe(MEDIA_UNPLAYABLE_NOTICE);
    expect(rendered.querySelector('video')).toBeNull();
    expect(rendered.querySelector('audio')).toBeNull();
  });

  it('agrees with the shared map about what each fixture extension is', () => {
    // Ties this suite's fixtures back to the one definition of the rule, so a
    // change to `PREVIEW_MODES` that this file was not updated for fails here
    // rather than passing against a stale local assumption.
    expect(previewModeForName('photo.png')).toBe('image');
    expect(previewModeForName('clip.mp4')).toBe('media');
    expect(previewModeForName('notes.md')).toBe('markdown');
    expect(previewModeForName('deploy.sh')).toBe('code');
    expect(previewModeForName('statement.pdf')).toBe('none');
  });
});
