import {
  PREVIEW_MAGIC_BYTES,
  SANDBOX_QR_IMAGE_FAILURE_CODES,
  SANDBOX_QR_SESSION_FAILURE_CODES,
  SANDBOX_RENDER_FAILURE_CODES,
  SANDBOX_REPAIR_DETAIL_CODES,
  SANDBOX_TRANSFORM_FAILURE_CODES,
  type SandboxQrImageFailureCode,
  type SandboxQrSessionFailureCode,
  type SandboxRenderFailureCode,
  type SandboxRepairDetailCode,
  type SandboxTransformFailureCode,
} from '@hvault/shared';

/**
 * Every sentence the application shows for something the isolated document
 * refused — the ONE place they are written.
 *
 * ---------------------------------------------------------------------------
 * WHY THE FRAME SENDS A CODE AND THIS FILE SENDS THE WORDS
 * ---------------------------------------------------------------------------
 *
 * The frame is the least-trusted component in the system: it runs third-party
 * parsers over bytes nobody vouched for. Every refusal it reports is displayed
 * OUTSIDE its rectangle, in the application's own chrome — beside the real
 * Download button, in the upload panel, in the import tool's status line. When
 * the frame chose that sentence, a compromised renderer could write up to a
 * paragraph of anything there in the application's voice ("re-enter your master
 * password at …"), which turned contained code execution into a phishing
 * primitive and contradicted the one rule the chrome exists for: the application
 * draws it, so a renderer cannot forge it.
 *
 * So the frame names WHICH refusal it is, from a closed list in
 * `@hvault/shared`, and the application decides what that means to a reader.
 *
 * ---------------------------------------------------------------------------
 * THE TWO RULES EVERY FUNCTION HERE FOLLOWS
 * ---------------------------------------------------------------------------
 *
 *  1. MEMBERSHIP IS TESTED AGAINST THE LIST, NEVER BY LOOKING THE CODE UP. A
 *     plain object indexed by a frame-chosen string resolves `toString`,
 *     `constructor` and `__proto__` through its prototype, so a code of
 *     `'toString'` would fetch a function where a sentence was expected. The
 *     tables below are only ever indexed AFTER {@link isOneOf} has narrowed the
 *     value to a declared code.
 *  2. AN UNRECOGNISED CODE GETS THE GENERIC SENTENCE, and is never shown. That
 *     covers a hostile frame and an honest one alike — a cached older host
 *     talking to a newer frame should degrade to a plainer sentence, not to "the
 *     preview sent something unexpected".
 *
 * A code selects a SENTENCE and nothing else. No caller branches on one: which
 * failures end a scanning session is decided by the reply's kind, and the tables
 * being typed `Record<Code, …>` is what makes a code added to a list without a
 * sentence here a type error rather than a silent fallback.
 *
 * Nothing here may be imported by `src/sandbox/`, and nothing here imports from
 * it (`tests/sandbox-boundary.test.ts`): the frame must not be able to read the
 * words it is being denied.
 */

/** Is this value one of these codes? The only way a table below is ever indexed. */
function isOneOf<T extends string>(codes: readonly T[], value: unknown): value is T {
  return typeof value === 'string' && (codes as readonly string[]).includes(value);
}

/** `png` becomes `PNG`, which is how a person names a format. */
function formatName(ext: string): string {
  return ext.toUpperCase();
}

/**
 * A format the frame says the bytes matched, but ONLY if it is one of the formats
 * the magic-byte table actually knows. `Object.hasOwn`, because
 * `PREVIEW_MAGIC_BYTES` is a null-prototype table and `in` would still be the
 * wrong question to ask of a string the frame chose.
 */
function knownFormat(detectedFormat: unknown): string | null {
  return typeof detectedFormat === 'string' && Object.hasOwn(PREVIEW_MAGIC_BYTES, detectedFormat)
    ? detectedFormat
    : null;
}

/** The sentence appended to every content refusal, because a refusal needs a next step. */
const DOWNLOAD_ADVICE = 'Download it to open it with something that understands it.';

/** What the viewer says when the frame's refusal is one it does not recognise. */
export const RENDER_FAILURE_FALLBACK =
  'The document preview could not be shown. You can download the file instead.';

const RENDER_FAILURES: Record<
  SandboxRenderFailureCode,
  (ext: string, detected: string | null) => string
> = {
  requestNotUnderstood: () =>
    'The preview could not be started, so nothing was shown. You can download the file instead.',
  // Ahead of the content rules in the frame: an empty file matches no signature,
  // and "its contents disagree with its name" would be true and useless.
  emptyFile: () => 'This file is empty. There is nothing to show.',
  contentMismatch: (ext, detected) => {
    const looksLike =
      detected === null ? '' : ` They look like a ${formatName(detected)} file instead.`;
    return `This file is named ".${ext}", but its contents are not a ${formatName(ext)} file.${looksLike} ${DOWNLOAD_ADVICE}`;
  },
  contentImpostor: (ext, detected) =>
    detected === null
      ? `This file is named ".${ext}", but its contents are a different kind of file. ${DOWNLOAD_ADVICE}`
      : `This file is named ".${ext}", but its contents are a ${formatName(detected)} file. ${DOWNLOAD_ADVICE}`,
  noRenderer: () =>
    'There is no viewer here for this kind of document. You can download the file instead.',
  // No detail from the error, on either side of the boundary: it would have been
  // built from the document's own bytes.
  renderFailed: () => 'The document could not be displayed. You can download the file instead.',
};

/**
 * Why a preview was refused, in the viewer's words.
 *
 * `ext` is the extension the HOST sent — the application already knows what the
 * document claims to be, and it is the reader's own file name, shown in the title
 * above. `detectedFormat` is honoured only for the two content codes, and only
 * when it names a format the magic-byte table knows.
 */
export function describeRenderFailure(code: unknown, detectedFormat: unknown, ext: string): string {
  if (!isOneOf(SANDBOX_RENDER_FAILURE_CODES, code)) return RENDER_FAILURE_FALLBACK;
  return RENDER_FAILURES[code](ext, knownFormat(detectedFormat));
}

/** What the upload panel says for a transform refusal it does not recognise. */
export const TRANSFORM_FAILURE_FALLBACK = 'This file could not be repaired or formatted.';

const REPAIR_DETAILS: Record<SandboxRepairDetailCode, string> = {
  invalidCharacter: 'The repairer found a character it cannot accept.',
  unexpectedCharacter: 'The repairer found a character it did not expect.',
  unexpectedEnd: 'The file ends before the repairer could finish reading it.',
  objectKeyExpected: 'The repairer expected an object key.',
  colonExpected: 'The repairer expected a colon.',
  invalidUnicode: 'The repairer found an invalid unicode escape.',
};

const TRANSFORM_FAILURES: Record<
  SandboxTransformFailureCode,
  (stage: 'repair' | 'format', detail: string | null) => string
> = {
  nothingRequested: () => 'No transform was requested, so nothing was done to this file.',
  unsupportedType: () => 'This file type cannot be formatted or repaired in your browser.',
  repairUnsupported: () => 'Repair covers the JSON family only.',
  // The tool's own wording is NOT carried: Prettier's messages are open-ended,
  // and a sentence the frame chose is the defect this file exists to close. The
  // position and the quoted line beside this are what the reader acts on.
  syntaxError: (stage, detail) =>
    stage === 'repair'
      ? (detail ?? 'The repairer could not make sense of this file.')
      : 'The formatter found a syntax error in this file.',
  recordTooLong: () =>
    'This record is too long to keep on one line, and a JSON Lines record may not be split across lines.',
  // A tool that threw WITHOUT reporting a position. Worded as the tool stopping,
  // never as a mistake in the reader's file, because nothing says it was one.
  engineFailed: (stage) =>
    stage === 'repair'
      ? 'The repairer stopped unexpectedly, so this file was not changed.'
      : 'The formatter stopped unexpectedly, so this file was not changed.',
};

/** Why a transform stopped, in the upload panel's words. */
export function describeTransformFailure(
  stage: 'repair' | 'format',
  code: unknown,
  detail: unknown,
): string {
  if (!isOneOf(SANDBOX_TRANSFORM_FAILURE_CODES, code)) return TRANSFORM_FAILURE_FALLBACK;
  const detailSentence = isOneOf(SANDBOX_REPAIR_DETAIL_CODES, detail)
    ? REPAIR_DETAILS[detail]
    : null;
  return TRANSFORM_FAILURES[code](stage, detailSentence);
}

/**
 * Why the formatter refused the REQUEST itself — the protocol-level `failed`,
 * which the transform frame sends only when it could not parse what it was sent.
 */
export function describeTransformRequestFailure(code: unknown): string {
  return code === 'requestNotUnderstood'
    ? 'The formatter did not understand the request, so this file was not changed. You can upload it exactly as it is.'
    : 'The formatter failed, so this file was not changed. You can upload it exactly as it is.';
}

/** What the import tool says when a session ends for a reason it does not recognise. */
export const QR_SESSION_FAILURE_FALLBACK = 'The scanner failed. Paste your export link instead.';

const QR_SESSION_FAILURES: Record<SandboxQrSessionFailureCode, string> = {
  requestNotUnderstood:
    'The scanner could not understand the request. Paste your export link instead.',
  scannerUnavailable: 'The scanner could not be loaded. Paste your export link instead.',
  engineUnavailable: 'This browser cannot read images here. Paste your export link instead.',
};

/** Why a scanning session ended, in the import tool's words. */
export function describeQrSessionFailure(code: unknown): string {
  return isOneOf(SANDBOX_QR_SESSION_FAILURE_CODES, code)
    ? QR_SESSION_FAILURES[code]
    : QR_SESSION_FAILURE_FALLBACK;
}

/** What the import tool says when one image was refused for a reason it does not recognise. */
export const QR_IMAGE_FAILURE_FALLBACK = 'That image could not be read.';

const QR_IMAGE_FAILURES: Record<SandboxQrImageFailureCode, string> = {
  // Both bounds — bytes and decoded sides — and it claims neither in particular.
  imageTooLarge: 'That image is too large to read.',
  imageUnreadable: QR_IMAGE_FAILURE_FALLBACK,
};

/** Why ONE image was refused, in the import tool's words. */
export function describeQrImageFailure(code: unknown): string {
  return isOneOf(SANDBOX_QR_IMAGE_FAILURE_CODES, code)
    ? QR_IMAGE_FAILURES[code]
    : QR_IMAGE_FAILURE_FALLBACK;
}
