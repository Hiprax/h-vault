import { describe, expect, it } from 'vitest';
import {
  SANDBOX_QR_IMAGE_FAILURE_CODES,
  SANDBOX_QR_SESSION_FAILURE_CODES,
  SANDBOX_RENDER_FAILURE_CODES,
  SANDBOX_REPAIR_DETAIL_CODES,
  SANDBOX_TRANSFORM_FAILURE_CODES,
} from '@hvault/shared';
import {
  QR_IMAGE_FAILURE_FALLBACK,
  QR_SESSION_FAILURE_FALLBACK,
  RENDER_FAILURE_FALLBACK,
  TRANSFORM_FAILURE_FALLBACK,
  describeQrImageFailure,
  describeQrSessionFailure,
  describeRenderFailure,
  describeTransformFailure,
  describeTransformRequestFailure,
} from '../src/lib/sandboxRefusals';

/**
 * The application's own words for every refusal the isolated document can
 * report — and the proof that nothing the document sends is ever among them.
 *
 * Each host is also driven end to end in its own suite
 * (`document-sandbox.test.tsx`, `document-transform.test.ts`,
 * `totpImport/qrSandbox.test.ts`). What belongs here is the property that holds
 * for the MODULE: every code in every closed list has a sentence of its own, and
 * every value outside a list gets that host's fallback, including the values an
 * object lookup would have answered through its prototype.
 */

/**
 * Values a hostile or merely newer frame might send in place of a code. The last
 * four are the reason membership is tested against the list: each resolves to
 * something on a plain object literal.
 */
const NOT_CODES: readonly unknown[] = [
  undefined,
  null,
  7,
  {},
  '',
  'aCodeFromTheFuture',
  'Session expired. Re-enter your master password at https://evil.example',
  'toString',
  'constructor',
  '__proto__',
  'hasOwnProperty',
];

describe('render refusals', () => {
  it('words every render code with a sentence of its own, and none with the fallback', () => {
    const sentences = SANDBOX_RENDER_FAILURE_CODES.map((code) =>
      describeRenderFailure(code, 'jpg', 'png'),
    );
    for (const [index, sentence] of sentences.entries()) {
      const code = SANDBOX_RENDER_FAILURE_CODES[index] ?? '';
      expect(sentence, code).not.toBe(RENDER_FAILURE_FALLBACK);
      // A code is an identifier for the host to look up, never text to show.
      expect(sentence, code).not.toContain(code);
    }
    expect(new Set(sentences).size).toBe(SANDBOX_RENDER_FAILURE_CODES.length);
  });

  it.each(NOT_CODES)('answers %p with the fallback, and never shows it', (code) => {
    const sentence = describeRenderFailure(code, 'jpg', 'png');
    expect(sentence).toBe(RENDER_FAILURE_FALLBACK);
    if (typeof code === 'string' && code !== '') expect(sentence).not.toContain(code);
  });

  it('names a detected format only when the magic-byte table knows it', () => {
    expect(describeRenderFailure('contentMismatch', 'jpg', 'png')).toBe(
      'This file is named ".png", but its contents are not a PNG file. They look like a JPG file instead. Download it to open it with something that understands it.',
    );
    // Absent, and each kind of value that is not a known format: the sentence
    // simply does not name one.
    for (const detected of [undefined, 'exe', '__proto__', 'toString', 'PNG', 42]) {
      expect(describeRenderFailure('contentMismatch', detected, 'png'), String(detected)).toBe(
        'This file is named ".png", but its contents are not a PNG file. Download it to open it with something that understands it.',
      );
      expect(describeRenderFailure('contentImpostor', detected, 'md'), String(detected)).toBe(
        'This file is named ".md", but its contents are a different kind of file. Download it to open it with something that understands it.',
      );
    }
    expect(describeRenderFailure('contentImpostor', 'pdf', 'md')).toBe(
      'This file is named ".md", but its contents are a PDF file. Download it to open it with something that understands it.',
    );
  });

  it('ignores a detected format on every code that is not a content comparison', () => {
    expect(describeRenderFailure('emptyFile', 'pdf', 'png')).toBe(
      'This file is empty. There is nothing to show.',
    );
    expect(describeRenderFailure('renderFailed', 'pdf', 'png')).not.toContain('PDF');
  });
});

describe('transform refusals', () => {
  it('words every transform code, at both stages, without the fallback', () => {
    for (const code of SANDBOX_TRANSFORM_FAILURE_CODES) {
      for (const stage of ['repair', 'format'] as const) {
        const sentence = describeTransformFailure(stage, code, undefined);
        expect(sentence, `${stage}/${code}`).not.toBe(TRANSFORM_FAILURE_FALLBACK);
        expect(sentence, `${stage}/${code}`).not.toContain(code);
      }
    }
  });

  it('gives every repairer complaint its own sentence, for a repair only', () => {
    const sentences = SANDBOX_REPAIR_DETAIL_CODES.map((detail) =>
      describeTransformFailure('repair', 'syntaxError', detail),
    );
    expect(new Set(sentences).size).toBe(SANDBOX_REPAIR_DETAIL_CODES.length);
    expect(sentences).not.toContain('The repairer could not make sense of this file.');
    expect(describeTransformFailure('repair', 'syntaxError', 'colonExpected')).toBe(
      'The repairer expected a colon.',
    );
    // A repairer's complaint says nothing about the FORMATTER, which reads the
    // repaired text; a detail arriving with a format-stage failure is ignored.
    expect(describeTransformFailure('format', 'syntaxError', 'colonExpected')).toBe(
      'The formatter found a syntax error in this file.',
    );
  });

  it.each(NOT_CODES)('answers a detail of %p with the general sentence', (detail) => {
    expect(describeTransformFailure('repair', 'syntaxError', detail)).toBe(
      'The repairer could not make sense of this file.',
    );
  });

  it.each(NOT_CODES)('answers a code of %p with the fallback', (code) => {
    expect(describeTransformFailure('repair', code, 'colonExpected')).toBe(
      TRANSFORM_FAILURE_FALLBACK,
    );
  });

  it('never words a tool that failed without a position as a fault in the file', () => {
    for (const stage of ['repair', 'format'] as const) {
      expect(describeTransformFailure(stage, 'engineFailed', undefined)).toMatch(
        /stopped unexpectedly, so this file was not changed\.$/,
      );
      expect(describeTransformFailure(stage, 'engineFailed', undefined)).not.toMatch(/syntax/i);
    }
  });

  it.each(NOT_CODES)('words a protocol refusal of %p generically, with the remedy', (code) => {
    const sentence = describeTransformRequestFailure(code);
    expect(sentence).toBe(
      'The formatter failed, so this file was not changed. You can upload it exactly as it is.',
    );
  });

  it('words the one protocol refusal a transform frame sends', () => {
    expect(describeTransformRequestFailure('requestNotUnderstood')).toBe(
      'The formatter did not understand the request, so this file was not changed. You can upload it exactly as it is.',
    );
  });
});

describe('scan refusals', () => {
  it('words every session code with its own sentence and the paste-a-link remedy', () => {
    const sentences = SANDBOX_QR_SESSION_FAILURE_CODES.map(describeQrSessionFailure);
    for (const sentence of sentences) {
      expect(sentence).not.toBe(QR_SESSION_FAILURE_FALLBACK);
      expect(sentence).toMatch(/Paste your export link instead\.$/);
    }
    // The fallback carries the same remedy: a session that ended for a reason
    // this host does not recognise still leaves the reader somewhere to go.
    expect(QR_SESSION_FAILURE_FALLBACK).toMatch(/Paste your export link instead\.$/);
    expect(new Set(sentences).size).toBe(SANDBOX_QR_SESSION_FAILURE_CODES.length);
  });

  it('words every image code, and only imageUnreadable is the generic sentence', () => {
    expect(SANDBOX_QR_IMAGE_FAILURE_CODES.map(describeQrImageFailure)).toEqual([
      'That image is too large to read.',
      QR_IMAGE_FAILURE_FALLBACK,
    ]);
  });

  it.each(NOT_CODES)('answers %p with the fallbacks of both kinds', (code) => {
    expect(describeQrSessionFailure(code)).toBe(QR_SESSION_FAILURE_FALLBACK);
    expect(describeQrImageFailure(code)).toBe(QR_IMAGE_FAILURE_FALLBACK);
  });

  it('keeps the two kinds apart: a code of one is not a code of the other', () => {
    expect(describeQrSessionFailure('imageTooLarge')).toBe(QR_SESSION_FAILURE_FALLBACK);
    expect(describeQrImageFailure('scannerUnavailable')).toBe(QR_IMAGE_FAILURE_FALLBACK);
  });
});
