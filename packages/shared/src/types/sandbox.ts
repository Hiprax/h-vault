/**
 * The messages that cross between the application and its isolated render
 * document — TYPES, the closed CODE LISTS its refusals are drawn from, and a few
 * bounds, with no runtime schema.
 *
 * ---------------------------------------------------------------------------
 * WHY THERE IS NO ZOD SCHEMA HERE, WHICH IS THE POINT OF THE FILE
 * ---------------------------------------------------------------------------
 *
 * The sandbox is built as its OWN Rollup graph, and `manualChunks` puts `zod` in
 * `vendor-core` next to AXIOS. A shared runtime schema would therefore drag an
 * HTTP client into a document served under `connect-src 'none'`, where every
 * call it could make is dead code waiting on a policy change, and it would do so
 * silently: the document would still work, and nothing in the pipeline would
 * report it.
 *
 * So the two sides validate with different tools and share only the SHAPE, which
 * is erased at build time. The host uses Zod, as the application does
 * everywhere. The frame hand-rolls a structural validator over the handful of
 * shapes it accepts (`packages/client/src/sandbox/protocol.ts`) — a few `typeof`
 * checks, which is genuinely all the frame needs, because it dispatches on the
 * mode with a `switch` whose `default` is "unsupported" and therefore never
 * needs the list of valid modes at runtime.
 *
 * ---------------------------------------------------------------------------
 * THE DIRECTIONS, AND WHAT TRAVELS ON WHICH CHANNEL
 * ---------------------------------------------------------------------------
 *
 * On the WINDOW, exactly once, frame to host: `{ kind: 'ready' }`. Nothing else
 * is ever sent or accepted there, and the host removes its window listener the
 * moment it accepts one. Posting INTO an opaque origin requires
 * `targetOrigin: '*'`, which is the other reason nothing of value travels here.
 *
 * On a transferred `MessagePort`, everything else. A port dies with the document
 * that held it, so a frame that navigates itself away loses the channel instead
 * of continuing as a trusted peer.
 *
 * ---------------------------------------------------------------------------
 * TWO JOBS, TWO REQUEST KINDS, TWO DISJOINT REPLY SETS
 * ---------------------------------------------------------------------------
 *
 * The same isolated document does both of the things this application must never
 * do in its own origin: it RENDERS a stored file, and it FORMATS or REPAIRS one
 * before it is encrypted. They share the document for one reason — a Web Worker
 * would have been the obvious home for the second, and a worker is SAME-ORIGIN,
 * so a bug in Prettier or in the repairer could `fetch` this application's own
 * API with the httpOnly refresh cookie attached and read an access token out of
 * the response. A worker has no DOM, but it has the origin, and the origin is
 * what matters here.
 *
 * Each job has its own request kind and its own replies, and the two reply sets
 * are DISJOINT apart from `failed`, which either job may answer with. That is a
 * containment property rather than a naming convention: each host validates only
 * the replies ITS request can produce, so a frame answering a render request with
 * a transform result is a frame that has gone wrong, and it is torn down.
 *
 * ---------------------------------------------------------------------------
 * THE FRAME NAMES A REFUSAL; THE APPLICATION WORDS IT
 * ---------------------------------------------------------------------------
 *
 * Every refusal the frame can report is a CODE from one of the closed lists
 * below, never a sentence, and every sentence a reader sees is the host's own
 * (`packages/client/src/lib/sandboxRefusals.ts`). The reason is where the
 * sentence lands. A render refusal is shown beside the real Download button, a
 * transform refusal in the upload panel, a scan refusal in the import tool's
 * status line — all in the application's own chrome, in the application's
 * voice. A frame that could choose that text could put up to a paragraph of
 * anything there, which turns "code execution inside a contained origin" into
 * "arbitrary words in the trusted interface": a phishing primitive, and a direct
 * contradiction of the rule that the application draws the chrome so a renderer
 * cannot forge it.
 *
 * Codes select SENTENCES and nothing else. No host branches its control flow on
 * one: which failures end a session and which end one image is still carried by
 * the reply's KIND (see `SandboxQrReply`), because a value the untrusted side
 * chooses must not decide what the trusted side does. A code a host does not
 * recognise — a newer frame, a cached older host, or a hostile one — is answered
 * with that host's generic sentence, and is never shown.
 *
 * The ONE free-text field left on any REFUSAL is a transform failure's
 * `excerpt`: the offending line of the user's own document, bounded and shown in
 * a `<pre>` as a quotation of it. The host re-derives even that from its own copy
 * wherever it holds the text the line refers to. (A frame's RESULTS — a
 * transformed document, a decoded QR string — are data, not refusals, and are
 * validated as such by the host that asked for them.)
 */
import type { PreviewMode } from '../constants/index.js';

/**
 * The RESOLVED theme, never the user's `'system'` preference.
 *
 * The sandbox cannot resolve `'system'` for itself in any way the application
 * would agree with, and a document that disagreed with its own chrome about
 * light or dark would look broken rather than themed.
 */
export type SandboxTheme = 'light' | 'dark';

/**
 * Host to frame: render these bytes.
 *
 * FOUR fields, and the list is exhaustive by design. It carries no document key,
 * no vault key, no access token, no document id and no document name. The
 * chrome around the frame — the title, the toolbar, the download button — is
 * drawn by the application OUTSIDE the rectangle, so a renderer cannot forge it
 * and does not need the name in order to draw it.
 *
 * `bytes` is COPIED by structured clone, never transferred. Transferring would
 * detach the host's buffer, and that buffer is a PROP the host was lent rather
 * than given: the second post of the same document — a remount, a StrictMode
 * double-effect — would then throw on a detached buffer and kill the preview
 * with no message to explain it. The extra copy is already inside
 * `MAX_PREVIEW_BYTES`, which is sized as "a small multiple of the file" for
 * exactly this reason.
 */
export interface SandboxRenderRequest {
  readonly kind: 'render';
  /** Which renderer to use. Resolved by the host from the document's name. */
  readonly mode: PreviewMode;
  /** The lowercased extension, as a hint for highlighting — never as a claim. */
  readonly ext: string;
  readonly theme: SandboxTheme;
  readonly bytes: ArrayBuffer;
}

/** Frame to host: the document was rendered. */
export interface SandboxRenderedMessage {
  readonly kind: 'rendered';
}

/**
 * Why a RENDER request was refused. The host words each one.
 *
 * `contentMismatch` and `contentImpostor` are the two outcomes of the frame's
 * magic-byte comparison (`packages/client/src/sandbox/sniff.ts`): a name whose
 * format has a signature the bytes do not carry, and a name with no signature
 * whose bytes positively are some other format.
 */
export const SANDBOX_RENDER_FAILURE_CODES = [
  'requestNotUnderstood',
  'emptyFile',
  'contentMismatch',
  'contentImpostor',
  'noRenderer',
  'renderFailed',
] as const;
export type SandboxRenderFailureCode = (typeof SANDBOX_RENDER_FAILURE_CODES)[number];

/**
 * Why a SCAN SESSION cannot go on. Each of these ends the session, and each is
 * answered with the unattributable `failed` for exactly that reason: the frame
 * could not parse the request, its decoder will not load, or this browser gives
 * it nothing to read pixels with. No later image improves any of them.
 */
export const SANDBOX_QR_SESSION_FAILURE_CODES = [
  'requestNotUnderstood',
  'scannerUnavailable',
  'engineUnavailable',
] as const;
export type SandboxQrSessionFailureCode = (typeof SANDBOX_QR_SESSION_FAILURE_CODES)[number];

/**
 * Every code a `failed` message may carry, across the three jobs.
 *
 * A TRANSFORM host receives `failed` only for `requestNotUnderstood`, which is a
 * member of both lists above; its own refusals travel as
 * `SandboxTransformFailedMessage` instead.
 */
export type SandboxFailureCode = SandboxRenderFailureCode | SandboxQrSessionFailureCode;

/**
 * The longest code, or format name, a host reads off the port.
 *
 * Generous on purpose: a host maps an UNRECOGNISED code to its generic sentence
 * rather than tearing the frame down, so a newer frame talking to a cached older
 * host degrades to a plainer sentence instead of to "the preview sent something
 * unexpected". The bound only stops a frame handing the host an unbounded string
 * to compare.
 */
export const MAX_SANDBOX_CODE_LENGTH = 64;

/**
 * Frame to host: it could not do what it was asked, and which refusal that was.
 *
 * A CODE, never a sentence — see the file header for why. `detectedFormat` rides
 * along only with the two content-comparison codes: the extension the bytes
 * actually matched, so the host can say "they look like a JPG file". It is drawn
 * from `PREVIEW_MAGIC_BYTES`'s own keys and a host honours it only when it IS
 * one of them, so the most a hostile frame can do with it is name the wrong
 * format out of a fixed list.
 */
export interface SandboxFailedMessage {
  readonly kind: 'failed';
  readonly code: SandboxFailureCode;
  readonly detectedFormat?: string;
}

/**
 * Frame to host: the user clicked a link inside the rendered document.
 *
 * A CAPABILITY, not data. The host validates the scheme with the repository's
 * existing `isSafeUrl` AT THE MESSAGE BOUNDARY — before any dialog and before it
 * reaches any presentation code — because a `javascript:` URL opened by the
 * application runs in the application's origin, with the vault key in it. That
 * is the entire compromise in one message.
 */
export interface SandboxLinkMessage {
  readonly kind: 'link';
  readonly href: string;
}

/**
 * Everything the frame may say IN ANSWER TO A RENDER REQUEST.
 *
 * A message outside this union — including one shaped like the window handshake,
 * which is how a compromised renderer would try to obtain a second channel, and
 * including a transform reply, which this request did not ask for — tears the
 * frame down and falls back to "download to view".
 */
export type SandboxFrameMessage =
  SandboxRenderedMessage | SandboxFailedMessage | SandboxLinkMessage;

/**
 * Host to frame: run the optional in-browser transforms over this text.
 *
 * FIVE fields, and what is absent matters as much as what is here. It carries no
 * key, no token, no document id and no file name — the document does not exist
 * yet, because this runs BEFORE anything is encrypted or uploaded.
 *
 * `text`, not bytes. The host decodes the file itself, and refuses the transform
 * outright unless the decoded string re-encodes to the ORIGINAL bytes exactly, so
 * that the string posted here and the digest recorded in
 * `transform.originalSha256` provably describe the same file. Decoding is a
 * browser primitive rather than one of the parsers this design keeps out of the
 * application's origin (Markdown, HTML, the highlighter, Prettier, the JSON
 * repairer), and the host has to hold the original anyway: it computes the diff
 * the user confirms from its OWN copy, never from a summary the frame chose.
 *
 * At least one of `format` and `repair` is true. A request asking for neither is
 * a bug in the host — nothing offers that path — and the frame refuses it rather
 * than answering "here is your text back", because a provenance record naming no
 * transform records nothing.
 */
export interface SandboxTransformRequest {
  readonly kind: 'transform';
  readonly text: string;
  /** The lowercased extension, which decides the syntax and therefore the parser. */
  readonly ext: string;
  readonly format: boolean;
  readonly repair: boolean;
}

/**
 * Frame to host: the transforms ran, and this is the result.
 *
 * `formatted` and `repaired` report which transforms RAN. On this message they
 * necessarily equal what was asked for — the host REFUSES the reply when they do
 * not — and that is a property of the design
 * rather than a coincidence: the engine never silently drops half a request. A
 * repair asked for on a syntax with no repairer is a FAILURE, not a document
 * quietly formatted alone, because a provenance record that overstated or
 * understated what happened to the bytes would be worse than no record. What the
 * two flags do NOT claim is that anything changed: a repair of already-valid
 * JSON is byte-identical and still reports `repaired: true`, which is why the
 * host shows the user a diff instead of these booleans. They, and the tool
 * labels beside them, become the `transform` block of the encrypted metadata.
 *
 * `text` is DATA and is treated as such by everything downstream: it is encoded,
 * hashed, encrypted and uploaded, and it is never rendered as markup. The host
 * does not trust it to describe itself either — the byte delta and the diff the
 * user confirms are computed by the host from its own original and this text.
 */
export interface SandboxTransformedMessage {
  readonly kind: 'transformed';
  readonly text: string;
  readonly formatted: boolean;
  readonly repaired: boolean;
  /**
   * The package that rewrote the bytes, e.g. `prettier` or `jsonrepair+prettier`,
   * and its version.
   *
   * Both are FIXED by the request: `transformToolLabels(repaired, formatted)` in
   * this package is the only thing that produces them, on either side. The host
   * refuses a reply whose labels are not exactly that pair, because they are shown
   * beside the button that uploads the result and sealed into the document for
   * good, and a label the frame chose would be up to 128 characters of its own
   * words in both places.
   */
  readonly tool: string;
  readonly toolVersion: string;
}

/**
 * Why a TRANSFORM stopped. The host words each one, per stage.
 *
 * `syntaxError` means the tool reported a POSITION — the document itself is
 * where the problem is. A tool that threw without one is `engineFailed`, so a
 * plugin crash is never presented to the user as a mistake in their file.
 */
export const SANDBOX_TRANSFORM_FAILURE_CODES = [
  'nothingRequested',
  'unsupportedType',
  'repairUnsupported',
  'syntaxError',
  'recordTooLong',
  'engineFailed',
] as const;
export type SandboxTransformFailureCode = (typeof SANDBOX_TRANSFORM_FAILURE_CODES)[number];

/**
 * What the JSON repairer said was wrong, as a code.
 *
 * `jsonrepair` has exactly six things it can say, and naming which one is the
 * difference between "Line 3, column 21" and "a colon was expected at line 3,
 * column 21". Prettier's messages are open-ended and are not carried at all.
 * Optional: a repairer message the frame does not recognise simply sends none.
 */
export const SANDBOX_REPAIR_DETAIL_CODES = [
  'invalidCharacter',
  'unexpectedCharacter',
  'unexpectedEnd',
  'objectKeyExpected',
  'colonExpected',
  'invalidUnicode',
] as const;
export type SandboxRepairDetailCode = (typeof SANDBOX_REPAIR_DETAIL_CODES)[number];

/**
 * Frame to host: the document could not be repaired or formatted, and where.
 *
 * A structured failure rather than a sentence, because the panel has to name the
 * line, the column and the offending text: "the upload STOPS and says where" is
 * the behaviour this feature is specified by, and a host that received only a
 * message could not offer it. The SENTENCE is the host's, chosen by `stage`,
 * `code` and `detail`.
 *
 * `line` and `column` are 1-BASED and `null` when the underlying tool reported no
 * position — the JSON repairer reports a character OFFSET, which the frame
 * converts, and Prettier reports a `loc`, but neither is guaranteed for every
 * error. `excerpt` is the offending source line, bounded, and empty when there is
 * no line to quote. It is the ONE free-text field left on any refusal, and the
 * host uses it only when it cannot quote the line itself: a failure in the
 * formatter AFTER a repair points into the repaired text, which only the frame
 * holds.
 */
export interface SandboxTransformFailedMessage {
  readonly kind: 'transformFailed';
  /** Which half stopped: the repairer, or the formatter that ran after it. */
  readonly stage: 'repair' | 'format';
  readonly code: SandboxTransformFailureCode;
  readonly detail?: SandboxRepairDetailCode;
  readonly line: number | null;
  readonly column: number | null;
  readonly excerpt: string;
}

/**
 * Everything the frame may say IN ANSWER TO A TRANSFORM REQUEST.
 *
 * `SandboxFailedMessage` is a member of BOTH unions, and deliberately: it is the
 * answer to a request the frame could not even parse, which is a state that
 * belongs to the protocol rather than to either job. The host treats it the way
 * it treats every other failure here — the upload falls back to the original,
 * untransformed bytes.
 */
export type SandboxTransformReply =
  SandboxTransformedMessage | SandboxTransformFailedMessage | SandboxFailedMessage;

/**
 * Host to frame: find a QR code in this image.
 *
 * ---------------------------------------------------------------------------
 * A THIRD REQUEST KIND, AND WHY THE BOUNDARY IS DRAWN HERE
 * ---------------------------------------------------------------------------
 *
 * The frame runs the QR decoder, and NOTHING else about the import happens
 * there. It is handed pixels and answers with one short string. The migration
 * link it finds is then parsed in the application's own origin.
 *
 * That split is deliberate, and the reasoning is the opposite of the obvious
 * one. Moving the parser into the frame as well would not reduce what the frame
 * can see: the decoded string IS the export, base64 and all, so the frame holds
 * every secret either way the moment it decodes anything. What the split changes
 * is where the THIRD-PARTY code sits. The decoder is a dependency; the parser is
 * this repository's own, fuzzed and covered. So the dependency goes where a
 * compromised release can reach nothing, and the first-party parser stays where
 * it can be measured.
 *
 * `image` is typed `unknown` because this package is compiled without the DOM
 * library, being shared with the server. It is an `ImageBitmap` or a `Blob`, and
 * the frame narrows it before touching it, which it would have to do regardless:
 * nothing arriving on the port is trusted, whatever a type here claims.
 *
 * TWO DEPARTURES from the render contract above, both deliberate:
 *
 *  1. A CAMERA FRAME is TRANSFERRED, where `SandboxRenderRequest.bytes` is
 *     copied. The render request is copied because its buffer is a prop the host
 *     was lent and must still own afterwards. A camera frame is a bitmap the
 *     host mints for this one request and never looks at again, so transferring
 *     is free and avoids moving megabytes per frame across a process boundary.
 *     AN UPLOADED PHOTO IS COPIED INSTEAD, and the host has no choice: a `Blob`
 *     is serializable but NOT transferable, so naming one in a transfer list
 *     throws `DataCloneError` before the message is queued. The frame cannot
 *     tell the two apart and does not need to.
 *  2. One frame answers MANY requests, where a render frame answers one. A
 *     scanning session is a stream of camera frames, and standing a new
 *     document up per frame would cost a handshake each time. `requestId` is
 *     what keeps that honest: a reply that matches no outstanding request is a
 *     frame that has gone wrong, and the host tears it down.
 */
export interface SandboxQrRequest {
  readonly kind: 'qrScan';
  /** Echoed back, so a late or invented reply can be told apart from an answer. */
  readonly requestId: number;
  /** An `ImageBitmap` or a `Blob`. See above for why this is not typed. */
  readonly image: unknown;
}

/**
 * Frame to host: a code was read.
 *
 * `text` is bounded and is checked by the frame to begin with an `otpauth:` or
 * `otpauth-migration:` scheme, so the host is never handed an arbitrary string
 * scraped off a poster. It is still DATA: the host parses it, validates it and
 * never renders it as markup.
 */
export interface SandboxQrFoundMessage {
  readonly kind: 'qrFound';
  readonly requestId: number;
  readonly text: string;
}

/** Frame to host: no code in this image. The ordinary answer while aiming. */
export interface SandboxQrMissMessage {
  readonly kind: 'qrMiss';
  readonly requestId: number;
}

/**
 * Why ONE image was refused. The host words each one.
 *
 * `imageTooLarge` covers both bounds, the file's bytes and its decoded sides,
 * and the host's sentence claims neither in particular. Everything else about an
 * image the frame could not read — a format the engine will not decode, an
 * object that is neither a bitmap nor a file — is `imageUnreadable`.
 */
export const SANDBOX_QR_IMAGE_FAILURE_CODES = ['imageTooLarge', 'imageUnreadable'] as const;
export type SandboxQrImageFailureCode = (typeof SANDBOX_QR_IMAGE_FAILURE_CODES)[number];

/**
 * Frame to host: THIS ONE IMAGE could not be read, and why.
 *
 * It exists for the same reason `SandboxTransformFailedMessage` does, and the
 * distinction it draws is the load-bearing part. `SandboxFailedMessage` answers
 * a request the frame could not even parse, or a decoder that will never load:
 * states that belong to the PROTOCOL, that the next image cannot improve, and
 * that therefore end the session. This one answers a particular image the frame
 * looked at and refused — too many bytes, too many pixels, a format the engine
 * cannot decode — and carries the `requestId` that says which.
 *
 * MEASURED CONSEQUENCE OF NOT HAVING IT. Every one of those refusals used to
 * arrive as an unattributable `failed`, so the host had no honest choice but to
 * treat it as the session dying: picking one 8000 x 6000 photograph, or one HEIC
 * a non-Safari engine cannot decode, stopped a running camera mid-aim and said
 * nothing about why. With a `requestId` the host rejects that one scan, shows
 * its own sentence for the code, and keeps scanning.
 */
export interface SandboxQrFailedMessage {
  readonly kind: 'qrFailed';
  readonly requestId: number;
  readonly code: SandboxQrImageFailureCode;
}

/**
 * Everything the frame may say IN ANSWER TO A SCAN REQUEST.
 *
 * Disjoint from the render and transform replies, like those two are from each
 * other. A frame answering a scan with a `rendered` message is a frame that has
 * gone wrong, and the host tears it down rather than guessing.
 *
 * THREE of the four members name a request and one does not, and that is the
 * whole design: `SandboxFailedMessage` is a member of this union and of the
 * other two for the same reason it is a member of theirs — it is the answer to a
 * request the frame could not even parse, which belongs to the protocol rather
 * than to any one image, and the host ends the session on it. Everything that IS
 * about one image carries its `requestId`.
 */
export type SandboxQrReply =
  SandboxQrFoundMessage | SandboxQrMissMessage | SandboxQrFailedMessage | SandboxFailedMessage;

/** The longest decoded string the frame will hand back. */
export const MAX_SANDBOX_QR_TEXT_LENGTH = 8192;

/** The largest image side the frame will decode, in pixels. */
export const MAX_SANDBOX_QR_IMAGE_SIDE = 4096;

/**
 * The largest uploaded image the frame will decode, in bytes.
 *
 * This is the only bound standing between a decompression bomb and the tab: a
 * 64000 x 64000 PNG is a few hundred kilobytes on the wire and about 16 GB
 * decoded. The frame also refuses on the decoded dimensions, because a small
 * file can still declare a huge canvas.
 */
export const MAX_SANDBOX_QR_IMAGE_BYTES = 12 * 1024 * 1024;
