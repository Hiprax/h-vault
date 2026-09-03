/**
 * Turning a document's bytes into text, and being honest when they are not text.
 *
 * Every renderer in the `text`, `code`, `markdown` and `html` family starts
 * here, so the encoding decision is made ONCE rather than four times with three
 * different answers.
 *
 * ---------------------------------------------------------------------------
 * WHY A BOM CHECK AND NOTHING CLEVERER
 * ---------------------------------------------------------------------------
 *
 * Charset detection from content is a heuristic that is wrong often enough to be
 * dangerous on a file the reader stored precisely because they could not
 * remember what was in it. A byte-order mark is not a heuristic: it is a
 * declaration the writer made. So three declarations are honoured (UTF-8,
 * UTF-16LE, UTF-16BE) and everything else is decoded as UTF-8, which is what
 * essentially every text file written this century is.
 *
 * The fallback is NON-FATAL on purpose. A file that is ALMOST UTF-8 — one
 * truncated multi-byte sequence, one stray byte from another encoding — should
 * be shown with a replacement character where the damage is, because the person
 * looking at it wants to know what is in it. Refusing outright would tell them
 * nothing.
 *
 * What that costs is a file which is not text at all rendering as a screenful of
 * U+FFFD, so the ratio below turns that case into a stated warning rather than a
 * silent mess. The warning is advisory: it never stops the render, because the
 * caller may well be looking at a file it knows is damaged. A file whose bytes
 * positively identify it as some OTHER format is refused earlier and elsewhere,
 * by `sniff.ts`, which is where a refusal belongs.
 */

/** The three byte-order marks worth honouring, longest first. */
const BYTE_ORDER_MARKS = [
  { label: 'utf-8', bytes: [0xef, 0xbb, 0xbf] },
  // Checked BEFORE utf-16be for no reason other than declaration order; the two
  // marks are byte-reversed, so no input can match both.
  { label: 'utf-16le', bytes: [0xff, 0xfe] },
  { label: 'utf-16be', bytes: [0xfe, 0xff] },
] as const;

/** Not exported: `DecodedText.encoding` is the only consumer, and it is in this file. */
type TextEncodingLabel = (typeof BYTE_ORDER_MARKS)[number]['label'];

/**
 * The share of decoded characters that may be U+FFFD before the reader is
 * warned.
 *
 * A tenth, and the number is not arbitrary: real text is either valid or damaged
 * in a few places, while a JPEG decoded as UTF-8 is roughly half replacement
 * characters. Ten percent sits far above the first kind and far below the
 * second, so a file with one broken sequence in a thousand lines does not carry
 * a warning it does not deserve.
 */
const REPLACEMENT_RATIO_THRESHOLD = 0.1;

/** U+FFFD, what a decoder emits where it could not make sense of the bytes. */
const REPLACEMENT_CHARACTER = '�';

export interface DecodedText {
  /** The decoded text, with any byte-order mark removed. */
  readonly text: string;
  /** Which encoding was used, so the interface can say so. */
  readonly encoding: TextEncodingLabel;
  /** Whether the encoding was DECLARED by a byte-order mark or assumed. */
  readonly declared: boolean;
  /**
   * A sentence to show the reader, or `null` when the bytes decoded cleanly.
   *
   * Advisory. It never stops a render — see the note at the top of this file.
   */
  readonly warning: string | null;
}

/** Does `bytes` open with this mark? */
function startsWith(bytes: Uint8Array, mark: readonly number[]): boolean {
  if (bytes.length < mark.length) return false;
  return mark.every((byte, index) => bytes[index] === byte);
}

/** How many of `text`'s characters are the decoder's "I could not read this". */
function replacementRatio(text: string): number {
  if (text.length === 0) return 0;
  let seen = 0;
  for (const character of text) {
    if (character === REPLACEMENT_CHARACTER) seen += 1;
  }
  return seen / text.length;
}

/**
 * Decode a document's bytes as text.
 *
 * Never throws and never rejects: every input decodes to something, and the
 * caller learns from {@link DecodedText.warning} whether the result is
 * trustworthy. A renderer that could refuse here would be duplicating
 * `sniff.ts`, which refuses on the bytes' own evidence rather than on how badly
 * they decoded.
 */
export function decodeDocumentText(bytes: ArrayBuffer): DecodedText {
  const view = new Uint8Array(bytes);

  for (const mark of BYTE_ORDER_MARKS) {
    if (!startsWith(view, mark.bytes)) continue;
    // The WHOLE view, mark included, and no slice. `TextDecoder` removes a
    // leading byte-order mark itself for each of these three encodings (measured
    // for all three), and slicing first would be a line no test could ever fail
    // on. What the decoder must NOT be given is `ignoreBOM: true`, which turns
    // the mark into a U+FEFF at the head of the first line — invisible on screen,
    // and enough to make a diff against the same file elsewhere report a
    // difference nobody can see. The test that pins this asserts the decoded
    // text has no U+FEFF, which is what would fail if that option were added.
    const text = new TextDecoder(mark.label, { fatal: false }).decode(view);
    return {
      text,
      encoding: mark.label,
      declared: true,
      warning:
        replacementRatio(text) > REPLACEMENT_RATIO_THRESHOLD
          ? `This file declares ${mark.label} with a byte-order mark, but much of it did not decode. It is shown with a replacement character where the bytes could not be read.`
          : null,
    };
  }

  const text = new TextDecoder('utf-8', { fatal: false }).decode(view);
  return {
    text,
    encoding: 'utf-8',
    declared: false,
    warning:
      replacementRatio(text) > REPLACEMENT_RATIO_THRESHOLD
        ? 'This file has no byte-order mark and much of it is not valid UTF-8, so it may not be a text file at all. It is shown with a replacement character where the bytes could not be read.'
        : null,
  };
}
