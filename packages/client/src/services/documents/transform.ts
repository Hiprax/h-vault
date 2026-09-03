import type { DocumentMeta } from '@hvault/shared';
import { z } from 'zod';
import {
  MAX_DOCUMENT_TRANSFORM_LABEL_LENGTH,
  MAX_TRANSFORM_EXCERPT_LENGTH,
  MAX_TRANSFORM_MESSAGE_LENGTH,
} from '@hvault/shared';
import { connectSandbox } from '../../lib/sandboxHandshake';
import { diffText, type TextDiff } from '../../lib/textDiff';

/**
 * The application's half of the format-and-repair protocol.
 *
 * The transforms themselves run inside the isolated sandbox document, for the
 * reason its own source spells out: a Web Worker would have been the obvious
 * home and is same-origin, so a bug in Prettier or in the JSON repairer could
 * `fetch` this application's API with the httpOnly refresh cookie attached and
 * read an access token out of the response. This module is what stands on the
 * safe side of that boundary.
 *
 * ---------------------------------------------------------------------------
 * WHAT IT OWNS, AND WHY EACH PIECE IS HERE RATHER THAN IN THE FRAME
 * ---------------------------------------------------------------------------
 *
 *  a. THE DECODE. The frame is handed TEXT, not bytes, and this module produces
 *     it — because it also has to keep the original in order to compare against
 *     what comes back. The boundary that governs this file is narrow and worth
 *     stating: the application may CHARSET-DECODE a document and compare its
 *     text; it may not interpret the document's STRUCTURE. `JSON.parse` belongs
 *     on the other side of that line just as much as Prettier does.
 *  b. THE ROUND-TRIP REFUSAL. A document is only transformed when its bytes
 *     decode as UTF-8 and re-encode to EXACTLY those bytes. That is what makes
 *     the two numbers the user is shown mean something: the diff and
 *     `originalSha256` then provably describe the same bytes. Without it, a
 *     byte-order-marked file would be silently re-encoded on upload while the
 *     diff reported no change at all. One case the round trip CANNOT see is
 *     handled beside it — UTF-16 whose characters are all ASCII decodes and
 *     re-encodes byte-for-byte, and is caught by its NUL characters instead.
 *  c. THE DIFF. Computed here from the ORIGINAL text and the returned text, never
 *     from a summary the frame sent, because a confirmation dialog built from
 *     numbers the least-trusted component chose is a dialog that can lie about
 *     what it is asking permission for.
 *  d. A FRESH FRAME PER TRANSFORM, destroyed afterwards. One document can never
 *     observe the next, and a frame that has answered is never asked again.
 */

/** The provenance block sealed into the encrypted metadata. */
type DocumentTransformProvenance = NonNullable<DocumentMeta['transform']>;

/** Why a transform could not be completed, in the terms the panel displays. */
export interface TransformFailure {
  /** The tool's own sentence, or this module's when the document never reached one. */
  readonly message: string;
  /** 1-based, or `null` when nothing reported a position. */
  readonly line: number | null;
  readonly column: number | null;
  /** The offending source line, bounded, or `''` when there is none to quote. */
  readonly excerpt: string;
}

/** A completed transform, ready to be confirmed and uploaded. */
export interface TransformReview {
  /**
   * The bytes that would be uploaded.
   *
   * Encoded ONCE, here, so the digest, the byte count the user is shown and the
   * bytes the store seals are the same buffer. Encoding again at upload time
   * would be a second chance for them to disagree.
   */
  readonly blob: Blob;
  readonly transform: DocumentTransformProvenance;
  readonly diff: TextDiff;
  readonly bytesBefore: number;
  readonly bytesAfter: number;
}

export type TransformAttempt =
  | { readonly status: 'ready'; readonly review: TransformReview }
  | { readonly status: 'failed'; readonly failure: TransformFailure };

/**
 * How long to wait for the frame's handshake, and then for its answer.
 *
 * TWO deadlines, not one, and the split is deliberate. A CSP or CORS mistake
 * leaves the frame blank forever and should be reported in seconds; a formatter
 * working through a five-megabyte document legitimately takes far longer. One
 * combined deadline would make the first failure take the second's budget to
 * report — the user would stare at a spinner for half a minute to be told the
 * frame never loaded.
 *
 * The reply bound is generous rather than tight because the cost of being wrong
 * is asymmetric: too short discards a transform that was about to succeed, while
 * too long costs a user who is already watching a spinner a few more seconds
 * before being offered their original file back. Measured for scale: Prettier
 * formats a one-megabyte JSON document in about 1.5 s on the reference machine,
 * and `MAX_FORMATTABLE_SIZE_BYTES` caps the input at five.
 */
const HANDSHAKE_TIMEOUT_MS = 10_000;
const REPLY_TIMEOUT_MS = 30_000;

/**
 * What the frame may say in answer to a transform request.
 *
 * Its OWN union, not the viewer's. A shared schema would give a render frame the
 * right to send a transform result and this frame the right to send a link
 * capability, and each host would then have to ignore messages it should be
 * tearing the frame down for.
 *
 * Every string is bounded, because every one of them is built by the frame from
 * the document's own bytes.
 *
 * Exported so the fuzz suite can hold the ENGINE to it directly. That is the
 * contract that actually matters: an engine output this schema rejects is a
 * transform that dies at the message boundary, and it would die there for every
 * user without a single line of the engine having thrown.
 */
export const transformReplySchema = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('transformed'),
    // The transformed document itself. Bounded only by what the browser could
    // hold: it is DATA on its way to being encrypted, and a formatter that
    // legitimately doubles a five-megabyte file must not be refused by a bound
    // invented here. The store's own pre-flight is what decides whether the
    // result can be stored.
    text: z.string(),
    formatted: z.boolean(),
    repaired: z.boolean(),
    // Bounded by the METADATA schema's own limit, because that is where these
    // two end up: `documentMetaSchema.transform` caps both at
    // `MAX_DOCUMENT_TRANSFORM_LABEL_LENGTH`. Without the bound here a frame
    // could return a 10,000-character `tool`, survive this boundary, survive the
    // review dialog, and die in the store's meta pre-flight as "the upload could
    // not be started" — a message about the upload for a fault in the FRAME.
    // Refused here it is what it is: the formatter sent something unexpected and
    // was stopped.
    tool: z.string().min(1).max(MAX_DOCUMENT_TRANSFORM_LABEL_LENGTH),
    toolVersion: z.string().min(1).max(MAX_DOCUMENT_TRANSFORM_LABEL_LENGTH),
  }),
  z.object({
    kind: z.literal('transformFailed'),
    stage: z.enum(['repair', 'format']),
    message: z.string().max(MAX_TRANSFORM_MESSAGE_LENGTH),
    line: z.number().int().positive().nullable(),
    column: z.number().int().positive().nullable(),
    excerpt: z.string().max(MAX_TRANSFORM_EXCERPT_LENGTH),
  }),
  // The protocol-level refusal, which either job may answer with: the frame
  // could not parse the request at all.
  z.object({ kind: z.literal('failed'), reason: z.string().max(MAX_TRANSFORM_MESSAGE_LENGTH) }),
]);

/** A failure with no position, which is every failure that never reached a parser. */
function plainFailure(message: string): TransformAttempt {
  return { status: 'failed', failure: { message, line: null, column: null, excerpt: '' } };
}

/**
 * Decode a document as UTF-8, or say why it cannot be transformed.
 *
 * The three refusals are distinguished because the remedy differs and because
 * one of them is an ordinary file: "starts with a byte-order mark" is a
 * perfectly good Windows-authored `.json`, and telling its owner it is "not
 * valid UTF-8" would be false. The asymmetry with the VIEWER is worth naming
 * where a user meets it: the viewer decodes UTF-16 and byte-order marks happily,
 * because displaying a document changes nothing, while rewriting one has to be
 * able to prove that what was shown and what was hashed are the same bytes.
 */
export function decodeTransformSource(bytes: ArrayBuffer): { text: string } | { refusal: string } {
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return {
      refusal:
        'This file is not UTF-8 text, so it cannot be formatted or repaired here. It can still be uploaded exactly as it is.',
    };
  }
  // A NUL is the one CHARACTER, rather than byte sequence, that says these bytes
  // are not text in the encoding they were just decoded as. It is what UTF-16
  // ASCII looks like read as UTF-8 — `{\0"\0a\0` — and, measured, such a file
  // decodes cleanly AND re-encodes byte-for-byte, so the round trip below cannot
  // see it. Without this the file would reach Prettier and come back with a
  // syntax error about a character the user cannot see, instead of the one
  // sentence that tells them what is actually wrong. No document any of these
  // formatters can read may contain one: JSON forbids a literal control
  // character in a string, and YAML forbids a NUL outright. Markdown does not,
  // which is why the sentence names UTF-16 as the LIKELY cause rather than
  // asserting it — a `.md` holding a NUL is refused honestly, as a file these
  // tools cannot read, rather than mislabelled.
  if (text.includes('\u0000')) {
    return {
      refusal:
        'This file contains NUL characters, so it is not the plain UTF-8 text these tools read — most often it is UTF-16. It cannot be formatted or repaired here, and can still be uploaded exactly as it is.',
    };
  }
  // The round trip. With a FATAL decoder this is a bijection on everything it
  // accepts, so the ONLY difference it can actually find today is the leading
  // byte-order mark `TextDecoder` strips — which the length check finds first.
  // The per-byte comparison below and `byteOrderMarkOrMismatch`'s non-BOM
  // branch are therefore both DELIBERATELY UNREACHABLE and stay uncovered
  // rather than being mocked into coverage. They are kept because this is the
  // check that lets the panel promise that the diff the user confirmed and the
  // digest sealed into the metadata describe the same bytes, and a promise of
  // that shape should not rest on one `byteLength` comparison and an argument
  // about a decoder's internals.
  const reencoded = new TextEncoder().encode(text);
  const original = new Uint8Array(bytes);
  if (reencoded.byteLength !== original.byteLength) {
    return { refusal: byteOrderMarkOrMismatch(original) };
  }
  for (let index = 0; index < original.length; index += 1) {
    if (reencoded[index] !== original[index]) return { refusal: byteOrderMarkOrMismatch(original) };
  }
  return { text };
}

/**
 * Name the one cause of a round-trip mismatch that a user can act on.
 *
 * `TextDecoder` strips a leading UTF-8 byte-order mark and there is no option
 * that both keeps it and rejects malformed input, so a BOM is the mismatch this
 * check actually finds. The other branch exists because "the bytes did not come
 * back" is the honest thing to say when they did not, rather than asserting a
 * cause that was not checked.
 */
function byteOrderMarkOrMismatch(original: Uint8Array): string {
  const hasBom = original[0] === 0xef && original[1] === 0xbb && original[2] === 0xbf;
  return hasBom
    ? 'This file starts with a byte-order mark, so formatting it would change bytes outside the part being formatted. It can still be uploaded exactly as it is.'
    : 'This file did not survive a round trip through UTF-8 unchanged, so it cannot be formatted or repaired here. It can still be uploaded exactly as it is.';
}

/** The SHA-256 of a buffer, as the lowercase hex the metadata schema requires. */
async function sha256Hex(bytes: ArrayBuffer): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Build the hidden frame one transform runs in.
 *
 * Exactly the attributes the viewer's frame carries, because they are the
 * containment rather than presentation: `allow-scripts` WITHOUT
 * `allow-same-origin` is what gives the document an opaque origin, and the two
 * must never appear together. It is hidden with `display: none` rather than by
 * being left unattached — an unattached iframe never loads a document at all.
 */
function createTransformFrame(): HTMLIFrameElement {
  const frame = document.createElement('iframe');
  frame.src = '/sandbox.html';
  frame.setAttribute('sandbox', 'allow-scripts');
  frame.referrerPolicy = 'no-referrer';
  frame.setAttribute('allow', '');
  frame.setAttribute('aria-hidden', 'true');
  frame.title = 'Document formatter';
  frame.style.display = 'none';
  return frame;
}

/**
 * Ask the isolated document to format and/or repair one file.
 *
 * Resolves, never rejects: every failure — a frame that never loaded, a frame
 * that answered with nonsense, a syntax error in the document, a deadline — is a
 * `failed` outcome the panel turns into "upload the original unchanged". A
 * rejection here would leave the panel choosing between a spinner and a stack
 * trace.
 */
export async function transformDocument(
  source: Blob,
  options: { readonly ext: string; readonly format: boolean; readonly repair: boolean },
): Promise<TransformAttempt> {
  const bytes = await source.arrayBuffer();
  const decoded = decodeTransformSource(bytes);
  if ('refusal' in decoded) return plainFailure(decoded.refusal);
  const originalText = decoded.text;
  const originalSha256 = await sha256Hex(bytes);

  const reply = await requestTransform(originalText, options);
  if (reply.kind === 'failed') return plainFailure(reply.reason);
  if (reply.kind === 'transformFailed') {
    return {
      status: 'failed',
      failure: {
        message: reply.message,
        line: reply.line,
        column: reply.column,
        excerpt: reply.excerpt,
      },
    };
  }

  const blob = new Blob([new TextEncoder().encode(reply.text)]);
  return {
    status: 'ready',
    review: {
      blob,
      transform: {
        formatted: reply.formatted,
        repaired: reply.repaired,
        tool: reply.tool,
        toolVersion: reply.toolVersion,
        originalSha256,
      },
      // From THIS module's copy of the original, which is the whole point.
      diff: diffText(originalText, reply.text),
      bytesBefore: bytes.byteLength,
      bytesAfter: blob.size,
    },
  };
}

type TransformReply = z.infer<typeof transformReplySchema>;

/**
 * One frame, one request, one answer, then nothing.
 *
 * The window listener is registered BEFORE the frame is attached, because
 * attaching it is what starts the document loading and the handshake is the
 * first thing that document does. The reverse order is a race this loses on a
 * fast machine and wins on a slow one, which is the worst kind.
 */
function requestTransform(
  text: string,
  options: { readonly ext: string; readonly format: boolean; readonly repair: boolean },
): Promise<TransformReply> {
  return new Promise<TransformReply>((resolve) => {
    const frame = createTransformFrame();
    let replyTimer: ReturnType<typeof setTimeout> | null = null;
    let settled = false;

    const finish = (reply: TransformReply): void => {
      if (settled) return;
      settled = true;
      if (replyTimer !== null) clearTimeout(replyTimer);
      session.close();
      frame.remove();
      resolve(reply);
    };

    const session = connectSandbox({
      getFrame: () => frame,
      handshakeTimeoutMs: HANDSHAKE_TIMEOUT_MS,
      reasons: {
        timeout:
          'The formatter did not load, so this file was not changed. You can upload it exactly as it is.',
        spokeEarly:
          'The formatter did not start correctly and was stopped, so this file was not changed.',
      },
      onOpen: ({ post }) => {
        // The SECOND deadline, armed only once the channel is live: from here on
        // the frame is working, and the thing being bounded is the work.
        replyTimer = setTimeout(() => {
          finish({
            kind: 'failed',
            reason:
              'Formatting this file took too long and was stopped, so it was not changed. You can upload it exactly as it is.',
          });
        }, REPLY_TIMEOUT_MS);
        post({
          kind: 'transform',
          text,
          ext: options.ext,
          format: options.format,
          repair: options.repair,
        });
      },
      onMessage: (data, { fail }) => {
        const parsed = transformReplySchema.safeParse(data);
        if (!parsed.success) {
          // Anything outside this frame's own reply set — a `ready`-shaped
          // message, a render result, a malformed one — is a frame that has gone
          // wrong. `fail` tears the channel down and reports through
          // `onUnavailable` below.
          fail(
            'The formatter sent something unexpected and was stopped, so this file was not changed.',
          );
          return;
        }
        finish(parsed.data);
      },
      onUnavailable: (reason) => {
        finish({ kind: 'failed', reason });
      },
    });

    document.body.append(frame);
  });
}
