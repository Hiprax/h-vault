import { PREVIEW_MAGIC_BYTES, PREVIEW_MODES } from '@hvault/shared';
import type { PreviewMode, PreviewSignature, SandboxRenderFailureCode } from '@hvault/shared';

/**
 * Comparing a document's first bytes with what its name claims, before any
 * renderer is handed it.
 *
 * This is both a safety property and an honest answer to "why does my `.md` not
 * render". A file's extension is a label anyone can change; its opening bytes
 * are what it is.
 *
 * ---------------------------------------------------------------------------
 * THE RULE IS ONE-DIRECTIONAL, AND GETTING THAT BACKWARDS BREAKS EVERYTHING
 * ---------------------------------------------------------------------------
 *
 * Most of what this viewer renders has NO magic number at all: every `text`,
 * `code`, `markdown` and `html` extension, which after the `code` list in
 * `PREVIEW_MODES` is the majority of the map. So the absence of a signature is
 * NEVER a refusal. Implemented the other way round — "refuse anything whose
 * bytes match no known signature" — this would reject every shell script and
 * every configuration file in the store, and it would do it while looking like a
 * security feature.
 *
 * ---------------------------------------------------------------------------
 * TWO RULES, AND WHY THE SECOND ONE HAS TO EXIST
 * ---------------------------------------------------------------------------
 *
 * **Rule A, the claim.** If the claimed extension HAS signatures and none of
 * them matches, refuse. A `.png` that is not a PNG is not going to render.
 *
 * **Rule B, the impostor.** If the claimed extension has NO signature, but the
 * bytes positively match some other format's, and that format is presented in a
 * different way, refuse. Rule A alone cannot do this — `md` has no signature, so
 * a PDF renamed `.md` would sail through to the markdown parser — and refusing
 * that case is a requirement rather than an embellishment.
 *
 * Rule B is where a careless implementation invents false refusals, because its
 * whole reachable surface is TEXT-family claims: it is the only place a
 * signature is compared against a file nobody said was binary. See
 * {@link mayContradict} for the guard, and for the residual risk it does not
 * remove.
 *
 * Everything here only ever DECLINES A PREVIEW. It is not an authorization
 * decision, nothing is deleted, and the download button beside the frame still
 * works — which is what makes the residual false-refusal risk acceptable rather
 * than merely regrettable.
 */

/** Bytes that can legitimately begin a text file: tab, LF, CR and printable ASCII. */
function couldBeginText(byte: number): boolean {
  return byte === 0x09 || byte === 0x0a || byte === 0x0d || (byte >= 0x20 && byte <= 0x7e);
}

/** How many positions a signature actually constrains. */
function concreteBytes(signature: PreviewSignature): number {
  return signature.bytes.filter((byte) => byte !== null).length;
}

/**
 * May this signature be used to CONTRADICT a claim, or only to confirm one?
 *
 * The property that matters is "could a legitimate text file plausibly begin
 * with these bytes", and length alone is the wrong proxy for it in both
 * directions. `FF D8 FF` is only three bytes, yet `0xFF` cannot begin valid
 * UTF-8 at all and `FF D8` is not a byte-order mark, so a JPEG can never be
 * confused with prose — and excluding it on length would let the single
 * commonest real-world mislabelling there is (a photo saved as `.txt`) fall
 * through to the text renderer as mojibake. Meanwhile `BM` and `ID3` are
 * dangerous precisely BECAUSE they are short printable words that a spreadsheet
 * header or a sentence can begin with.
 *
 * So: a signature may contradict when it constrains a byte no text file can
 * begin with, OR when it is long enough that the coincidence stops being
 * plausible. `bmp` (`BM`) and the MP3 `ID3` tag qualify under neither and are
 * confirm-only.
 *
 * THE RESIDUAL RISK, STATED RATHER THAN IMPLIED: this does not eliminate false
 * refusals, and no formulation of Rule B could. A document ABOUT file formats
 * whose very first characters are a magic string — a `magic-numbers.md` opening
 * `%PDF-1.7 marks a PDF`, or `GIF89a is the newer header` — clears the
 * four-byte bar and is refused. That is contrived, it costs a preview rather
 * than the file, and the download button is right there.
 */
function mayContradict(signature: PreviewSignature): boolean {
  const CONTRADICTION_BYTES = 4;
  const hasNonTextByte = signature.bytes.some((byte) => byte !== null && !couldBeginText(byte));
  return hasNonTextByte || concreteBytes(signature) >= CONTRADICTION_BYTES;
}

/** Does this run of bytes, anchored at byte 0, match the file? */
function matches(signature: PreviewSignature, view: Uint8Array): boolean {
  if (view.length < signature.bytes.length) return false;
  return signature.bytes.every((byte, index) => byte === null || view[index] === byte);
}

/** A format the bytes positively identify as, and how specific the evidence was. */
interface Identification {
  readonly ext: string;
  readonly concrete: number;
}

/**
 * What these bytes actually look like, judged only on evidence strong enough to
 * contradict a claim.
 *
 * The most SPECIFIC match wins, which is what makes an overlap decisive: an AVIF
 * matches both the `avif` signature and the generic ISO base-media one that
 * `mp4` carries, and the nine constrained bytes beat the five. A tie between two
 * formats that are PRESENTED differently is impossible by construction —
 * `packages/shared/tests/constants.test.ts` refuses one — so this never has to
 * choose arbitrarily between an image and a video.
 */
function identify(view: Uint8Array): Identification | null {
  let best: Identification | null = null;
  for (const [ext, alternatives] of Object.entries(PREVIEW_MAGIC_BYTES)) {
    for (const signature of alternatives) {
      if (!mayContradict(signature)) continue;
      if (!matches(signature, view)) continue;
      const concrete = concreteBytes(signature);
      if (best === null || concrete > best.concrete) best = { ext, concrete };
    }
  }
  return best;
}

/**
 * Why a document must not be previewed: WHICH rule refused it, and what the bytes
 * looked like instead when that is known.
 *
 * A code and an extension, never a sentence. The refusal is shown in the
 * application's chrome, so the application words it
 * (`src/lib/sandboxRefusals.ts`); this document only reports what it found.
 * `detectedFormat` is always a key of `PREVIEW_MAGIC_BYTES`, which is the only
 * shape the application will honour.
 */
interface PreviewRefusal {
  readonly code: Extract<
    SandboxRenderFailureCode,
    'emptyFile' | 'contentMismatch' | 'contentImpostor'
  >;
  readonly detectedFormat?: string;
}

/**
 * Why this document must not be previewed, or `null` when it may be.
 *
 * Called once, before a renderer is chosen, so a refusal costs nothing but the
 * comparison. The answer names what was expected (the host already knows: it
 * sent the extension) and what was found, so the application can say that
 * rather than report that "validation failed".
 */
export function previewRefusal(
  mode: PreviewMode,
  ext: string,
  bytes: ArrayBuffer,
): PreviewRefusal | null {
  if (bytes.byteLength === 0) {
    // Ahead of everything else: an empty file matches no signature, so without
    // this it would be refused by Rule A as contents disagreeing with a name —
    // which is true and useless. It is also what stops an `<img>` or a `<video>`
    // being handed nothing and rendering as a broken glyph with no explanation.
    return { code: 'emptyFile' };
  }

  const view = new Uint8Array(bytes);
  const claimed = PREVIEW_MAGIC_BYTES[ext];

  if (claimed !== undefined) {
    if (claimed.some((signature) => matches(signature, view))) return null;
    const actual = identify(view);
    return actual === null
      ? { code: 'contentMismatch' }
      : { code: 'contentMismatch', detectedFormat: actual.ext };
  }

  // Rule B. Only reachable for a claim with no signature of its own, which after
  // the `code` list is almost always a text-family document.
  const actual = identify(view);
  if (actual === null) return null;
  // Same presentation, no conflict: a PNG named `.svg` is still an image and
  // still renders, and refusing it would be pedantry with a download button
  // attached.
  if (PREVIEW_MODES[actual.ext] === mode) return null;
  return { code: 'contentImpostor', detectedFormat: actual.ext };
}
