// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  JSONREPAIR_VERSION,
  MAX_SANDBOX_CODE_LENGTH,
  MAX_TRANSFORM_EXCERPT_LENGTH,
  PRETTIER_VERSION,
} from '@hvault/shared';
import { diffText } from '../src/lib/textDiff';
import { decodeTransformSource, transformDocument } from '../src/services/documents/transform';

/**
 * The application's half of the transform: the diff it computes for itself, the
 * decode it refuses on, and the frame it drives.
 *
 * The engine is exercised for real in `document-format.test.ts`. What is
 * exercised HERE is everything the application does around it, and the two
 * properties that matter most are both negatives: the application never trusts
 * the frame's account of what changed, and a frame that misbehaves cannot leave
 * the upload waiting for ever.
 */

// ---------------------------------------------------------------------------
// The diff
// ---------------------------------------------------------------------------

describe('diffText', () => {
  it('reports identical texts as identical, with no hunks to confirm', () => {
    const diff = diffText('a\nb\n', 'a\nb\n');
    expect(diff.identical).toBe(true);
    expect(diff.hunks).toEqual([]);
    expect(diff.linesAdded).toBe(0);
    expect(diff.linesRemoved).toBe(0);
  });

  it('counts one changed line as one removal and one addition', () => {
    const diff = diffText('a\nb\nc\n', 'a\nB\nc\n');
    expect(diff.identical).toBe(false);
    expect(diff.linesAdded).toBe(1);
    expect(diff.linesRemoved).toBe(1);
    expect(diff.hunks).toHaveLength(1);
    const [hunk] = diff.hunks ?? [];
    expect(hunk?.lines.map((line) => `${line.kind}:${line.text}`)).toEqual([
      'context:a',
      'removed:b',
      'added:B',
      'context:c',
      'context:',
    ]);
  });

  it('puts the removal before the addition when a line was replaced', () => {
    // A presentation decision, and the one every diff tool makes. Reversed, a
    // replacement reads as an insertion followed by an unrelated deletion.
    const diff = diffText('x\n', 'y\n');
    const kinds = (diff.hunks ?? [])[0]?.lines.map((line) => line.kind);
    expect(kinds?.indexOf('removed')).toBeLessThan(kinds?.indexOf('added') ?? -1);
  });

  it('reports a pure insertion without claiming a line was removed', () => {
    const diff = diffText('a\nb\n', 'a\nnew\nb\n');
    expect(diff.linesAdded).toBe(1);
    expect(diff.linesRemoved).toBe(0);
  });

  it('reports a pure deletion without claiming a line was added', () => {
    const diff = diffText('a\ngone\nb\n', 'a\nb\n');
    expect(diff.linesAdded).toBe(0);
    expect(diff.linesRemoved).toBe(1);
  });

  it('splits distant changes into separate hunks and merges adjacent ones', () => {
    const before = Array.from({ length: 40 }, (_, index) => `line ${String(index)}`).join('\n');
    const after = before.replace('line 1', 'LINE 1').replace('line 35', 'LINE 35');
    const diff = diffText(before, after);
    expect(diff.hunks).toHaveLength(2);

    const near = before.replace('line 10', 'LINE 10').replace('line 11', 'LINE 11');
    expect(diffText(before, near).hunks).toHaveLength(1);
  });

  it('numbers each hunk against the files rather than against the diff', () => {
    const before = Array.from({ length: 20 }, (_, index) => `l${String(index)}`).join('\n');
    const after = before.replace('l15', 'L15');
    const [hunk] = diffText(before, after).hunks ?? [];
    // l15 is the sixteenth line, so a hunk with three lines of leading context
    // starts at line 13 in BOTH files.
    expect(hunk?.beforeStart).toBe(13);
    expect(hunk?.afterStart).toBe(13);
    expect(hunk?.beforeCount).toBe(hunk?.afterCount);
  });

  it('treats a rewritten line ending as a change to that line', () => {
    // Splitting on `\r?\n` would report "no change" for a transform that
    // rewrote every line ending in the file, which is a rewrite the user is
    // entitled to see. The formatter is configured not to do it; this is what
    // would report it if that ever changed.
    const diff = diffText('a\r\nb\r\n', 'a\nb\n');
    expect(diff.identical).toBe(false);
    expect(diff.linesRemoved).toBeGreaterThan(0);
  });

  it('skips the line-by-line comparison when the two versions are too large', () => {
    // The exact comparison is quadratic, so past its budget it answers `null`
    // hunks rather than freezing the tab. The totals stay exact and the panel
    // says the detailed view was skipped.
    const before = Array.from({ length: 2_000 }, (_, index) => `a${String(index)}`).join('\n');
    const after = Array.from({ length: 2_000 }, (_, index) => `b${String(index)}`).join('\n');
    const diff = diffText(before, after);
    expect(diff.hunks).toBeNull();
    expect(diff.identical).toBe(false);
    expect(diff.linesBefore).toBe(2_000);
    expect(diff.linesAfter).toBe(2_000);
    expect(diff.linesRemoved).toBe(2_000);
    expect(diff.linesAdded).toBe(2_000);
  });

  it('trims the common ends even when it then gives up on the middle', () => {
    // The bail-out path re-derives the common prefix and suffix for itself, so
    // the totals it reports describe the region that actually differs rather
    // than the whole file. Without that, a 4,000-line document with a shared
    // header and footer and a rewritten middle would be reported as 4,000 lines
    // removed and 4,000 added — a number the user cannot act on.
    const header = Array.from({ length: 10 }, (_, index) => `head ${String(index)}`);
    const footer = Array.from({ length: 10 }, (_, index) => `foot ${String(index)}`);
    const before = [
      ...header,
      ...Array.from({ length: 2_000 }, (_, i) => `a${String(i)}`),
      ...footer,
    ];
    const after = [
      ...header,
      ...Array.from({ length: 2_000 }, (_, i) => `b${String(i)}`),
      ...footer,
    ];
    const diff = diffText(before.join('\n'), after.join('\n'));

    expect(diff.hunks).toBeNull();
    expect(diff.linesBefore).toBe(2_020);
    expect(diff.linesAfter).toBe(2_020);
    // The twenty shared lines are excluded from both counts.
    expect(diff.linesRemoved).toBe(2_000);
    expect(diff.linesAdded).toBe(2_000);
  });

  it('still compares a huge file whose change is small, because of the common ends', () => {
    // The cheap prefix/suffix trim is what makes the ordinary case — one line
    // appended to a very long file — fit inside the budget at all.
    const lines = Array.from({ length: 50_000 }, (_, index) => `line ${String(index)}`);
    const before = lines.join('\n');
    const after = `${before}\nappended`;
    const diff = diffText(before, after);
    expect(diff.hunks).not.toBeNull();
    expect(diff.linesAdded).toBe(1);
    expect(diff.linesRemoved).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// The decode
// ---------------------------------------------------------------------------

/** A buffer allocated in THIS realm, as a `Blob.arrayBuffer()` would produce. */
function bufferOf(bytes: readonly number[]): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.length);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

function utf8(text: string): ArrayBuffer {
  return bufferOf([...new TextEncoder().encode(text)]);
}

describe('decodeTransformSource', () => {
  it('accepts ordinary UTF-8, including characters outside ASCII', () => {
    expect(decodeTransformSource(utf8('{"a":"héllo 😀"}'))).toEqual({ text: '{"a":"héllo 😀"}' });
  });

  it('accepts an empty document', () => {
    expect(decodeTransformSource(utf8(''))).toEqual({ text: '' });
  });

  it('refuses bytes that are not valid UTF-8, and says so', () => {
    // A lone continuation byte: valid in no UTF-8 sequence.
    const result = decodeTransformSource(bufferOf([0x7b, 0x80, 0x7d]));
    expect(result).toHaveProperty('refusal');
    if (!('refusal' in result)) return;
    expect(result.refusal).toContain('not UTF-8 text');
    expect(result.refusal).toContain('uploaded exactly as it is');
  });

  it('refuses a byte-order mark BY NAME, because it is an ordinary Windows file', () => {
    // `TextDecoder` strips it, so the text would re-encode three bytes shorter:
    // the upload would silently lose them while the diff reported no change at
    // all, and `originalSha256` would digest bytes the user was never shown.
    const result = decodeTransformSource(bufferOf([0xef, 0xbb, 0xbf, 0x7b, 0x7d]));
    expect(result).toHaveProperty('refusal');
    if (!('refusal' in result)) return;
    expect(result.refusal).toContain('byte-order mark');
    // NOT the "not valid UTF-8" wording: it is perfectly valid UTF-8, and
    // telling its owner otherwise would be false.
    expect(result.refusal).not.toContain('not UTF-8 text');
  });

  it('refuses UTF-16 with a byte-order mark, which no UTF-8 decoder can read at all', () => {
    // `0xff` is not a valid UTF-8 byte in any position, so this one is refused
    // by the decode itself.
    const result = decodeTransformSource(bufferOf([0xff, 0xfe, 0x7b, 0x00, 0x7d, 0x00]));
    expect(result).toHaveProperty('refusal');
    if (!('refusal' in result)) return;
    expect(result.refusal).toContain('not UTF-8 text');
  });

  it('refuses UTF-16 WITHOUT a byte-order mark, which the round trip cannot see', () => {
    // MEASURED, and the reason a second rule exists: `{"a":1}` in UTF-16LE is
    // every byte under 0x80 interleaved with NULs, so it decodes cleanly under
    // `{fatal:true}` AND re-encodes byte-for-byte identically. The round trip is
    // satisfied and the document is still not text. Without this it would reach
    // Prettier and come back with a syntax error about a character the user
    // cannot see.
    const utf16 = [...new TextEncoder().encode('{"a":1}')].flatMap((byte) => [byte, 0x00]);
    const result = decodeTransformSource(bufferOf(utf16));
    expect(result).toHaveProperty('refusal');
    if (!('refusal' in result)) return;
    expect(result.refusal).toContain('NUL characters');
    expect(result.refusal).toContain('UTF-16');
  });

  it('accepts an escaped NUL, which is an ordinary six-character JSON escape', () => {
    // The rule is about the CHARACTER, not about the two-letter sequence that
    // denotes it. Refusing `\u0000` in a string would refuse a perfectly
    // ordinary document.
    expect(decodeTransformSource(utf8(String.raw`{"a":"\u0000"}`))).toHaveProperty('text');
  });
});

// ---------------------------------------------------------------------------
// The frame
// ---------------------------------------------------------------------------

/**
 * The harness: stub `MessageChannel` so the test holds the frame's end of the
 * port directly.
 *
 * The real `/sandbox.html` never loads under jsdom, and the host transfers
 * `port2` through a `postMessage` on a window object that does not exist here.
 * Replacing the constructor is the smallest intervention that leaves every line
 * of the production path — the handshake checks, the listener removal, both
 * deadlines, the reply validation — running exactly as it does in a browser. The
 * frame's own side is exercised for real in `document-format.test.ts`.
 */
interface FramePort {
  postToHost: (data: unknown) => void;
  received: unknown[];
}

function installFrame(): { frameReplies: FramePort; restore: () => void } {
  const received: unknown[] = [];
  const listeners: ((event: MessageEvent) => void)[] = [];
  const port1 = {
    addEventListener: (_type: string, handler: (event: MessageEvent) => void) => {
      listeners.push(handler);
    },
    start: () => undefined,
    close: () => undefined,
    postMessage: (data: unknown) => {
      received.push(data);
    },
  };
  const OriginalChannel = globalThis.MessageChannel;
  // A stand-in for the browser's channel, cast at the ASSIGNMENT rather than
  // silenced with a compiler directive. `typeof MessageChannel` demands a
  // `prototype` and two real `MessagePort`s, none of which this test is about,
  // and a directive would suppress every FUTURE type error on that line as well
  // as this one — which is why `audit:integrity` makes each of them a ledger
  // entry. A cast is narrow and visible; the same double cast stands in for a
  // `Window` below.
  const StubChannel = class {
    port1 = port1;
    port2 = {} as MessagePort;
  };
  globalThis.MessageChannel = StubChannel as unknown as typeof MessageChannel;
  return {
    frameReplies: {
      received,
      postToHost: (data: unknown) => {
        for (const handler of listeners) handler({ data } as MessageEvent);
      },
    },
    restore: () => {
      globalThis.MessageChannel = OriginalChannel;
    },
  };
}

/** Complete the handshake for whatever hidden frame the driver just attached. */
function completeHandshake(origin = 'null'): void {
  const frame = document.querySelector<HTMLIFrameElement>('iframe[title="Document formatter"]');
  if (!frame) throw new Error('no transform frame was attached');
  const source = {
    postMessage: () => undefined,
  } as unknown as Window;
  Object.defineProperty(frame, 'contentWindow', { configurable: true, get: () => source });
  const event = new MessageEvent('message', { data: { kind: 'ready' }, origin });
  Object.defineProperty(event, 'source', { configurable: true, get: () => source });
  window.dispatchEvent(event);
}

describe('transformDocument', () => {
  let harness: ReturnType<typeof installFrame>;

  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    harness = installFrame();
  });

  afterEach(() => {
    harness.restore();
    vi.runOnlyPendingTimers();
    vi.useRealTimers();
    for (const frame of document.querySelectorAll('iframe')) frame.remove();
  });

  it('posts the text and the two flags, and nothing else, then removes the frame', async () => {
    const pending = transformDocument(new Blob(['{"a":1}']), {
      ext: 'json',
      format: true,
      repair: false,
    });
    await vi.waitFor(() => {
      expect(document.querySelector('iframe[title="Document formatter"]')).not.toBeNull();
    });
    completeHandshake();

    // FIVE fields. No key, no token, no document id, no file name — the
    // document does not exist yet, and the frame is never told what it is called.
    expect(harness.frameReplies.received).toEqual([
      { kind: 'transform', text: '{"a":1}', ext: 'json', format: true, repair: false },
    ]);

    harness.frameReplies.postToHost({
      kind: 'transformed',
      text: '{ "a": 1 }\n',
      formatted: true,
      repaired: false,
      tool: 'prettier',
      toolVersion: PRETTIER_VERSION,
    });
    const attempt = await pending;
    expect(attempt.status).toBe('ready');
    // The frame is destroyed afterwards, so one document can never observe the
    // next and a frame that has answered is never asked again.
    expect(document.querySelector('iframe[title="Document formatter"]')).toBeNull();
  });

  it('creates the frame with an opaque origin and no delegated permission', async () => {
    const pending = transformDocument(new Blob(['{}']), {
      ext: 'json',
      format: true,
      repair: false,
    });
    await vi.waitFor(() => {
      expect(document.querySelector('iframe[title="Document formatter"]')).not.toBeNull();
    });
    const frame = document.querySelector<HTMLIFrameElement>('iframe[title="Document formatter"]');
    // `allow-scripts` WITHOUT `allow-same-origin`. The two together let the
    // framed document remove its own sandbox attribute and are worth nothing.
    expect(frame?.getAttribute('sandbox')).toBe('allow-scripts');
    expect(frame?.getAttribute('sandbox')).not.toContain('allow-same-origin');
    expect(frame?.referrerPolicy).toBe('no-referrer');
    expect(frame?.getAttribute('allow')).toBe('');
    expect(frame?.getAttribute('src')).toBe('/sandbox.html');

    completeHandshake();
    harness.frameReplies.postToHost({ kind: 'failed', code: 'requestNotUnderstood' });
    await pending;
  });

  it('computes the diff and the byte delta ITSELF, ignoring what the frame claims', async () => {
    const original = '{"a":1}';
    const pending = transformDocument(new Blob([original]), {
      ext: 'json',
      format: true,
      repair: false,
    });
    await vi.waitFor(() => {
      expect(document.querySelector('iframe[title="Document formatter"]')).not.toBeNull();
    });
    completeHandshake();
    harness.frameReplies.postToHost({
      kind: 'transformed',
      text: '{ "a": 1 }\n',
      formatted: true,
      repaired: false,
      tool: 'prettier',
      toolVersion: PRETTIER_VERSION,
      // A frame that also sent a flattering summary would get nowhere: the
      // schema strips it and nothing reads it.
      linesAdded: 0,
      bytesAfter: 7,
    });
    const attempt = await pending;
    expect(attempt.status).toBe('ready');
    if (attempt.status !== 'ready') return;
    expect(attempt.review.bytesBefore).toBe(7);
    expect(attempt.review.bytesAfter).toBe(11);
    expect(attempt.review.diff.identical).toBe(false);
    expect(attempt.review.diff.linesAdded).toBeGreaterThan(0);
    expect(attempt.review.blob.size).toBe(11);
  });

  it('records the provenance its OWN request determines, with the digest of the ORIGINAL bytes', async () => {
    const pending = transformDocument(new Blob(['{"a":1}']), {
      ext: 'json',
      format: true,
      repair: true,
    });
    await vi.waitFor(() => {
      expect(document.querySelector('iframe[title="Document formatter"]')).not.toBeNull();
    });
    completeHandshake();
    harness.frameReplies.postToHost({
      kind: 'transformed',
      text: '{ "a": 1 }\n',
      formatted: true,
      repaired: true,
      tool: 'jsonrepair+prettier',
      toolVersion: `${JSONREPAIR_VERSION}+${PRETTIER_VERSION}`,
    });
    const attempt = await pending;
    if (attempt.status !== 'ready') throw new Error('expected a review');
    expect(attempt.review.transform).toEqual({
      formatted: true,
      repaired: true,
      tool: 'jsonrepair+prettier',
      toolVersion: `${JSONREPAIR_VERSION}+${PRETTIER_VERSION}`,
      // SHA-256 of `{"a":1}`, verified independently with `sha256sum` rather
      // than recorded from this code's own output — the bytes BEFORE the
      // transform, which is the whole point of the field.
      originalSha256: '015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862',
    });
  });

  it('passes a positioned failure through with its line, column and excerpt', async () => {
    const pending = transformDocument(new Blob(['{"a":1}{"b":2}']), {
      ext: 'json',
      format: false,
      repair: true,
    });
    await vi.waitFor(() => {
      expect(document.querySelector('iframe[title="Document formatter"]')).not.toBeNull();
    });
    completeHandshake();
    harness.frameReplies.postToHost({
      kind: 'transformFailed',
      stage: 'repair',
      code: 'syntaxError',
      detail: 'unexpectedCharacter',
      line: 1,
      column: 8,
      excerpt: '{"a":1}{"b":2}',
    });
    const attempt = await pending;
    // The sentence is the HOST's for that code and detail; the position is the
    // frame's two integers; the excerpt is quoted from the host's own copy.
    expect(attempt).toEqual({
      status: 'failed',
      failure: {
        message: 'The repairer found a character it did not expect.',
        line: 1,
        column: 8,
        excerpt: '{"a":1}{"b":2}',
      },
    });
  });

  /** Run one transform against a frame that answers with `reply`. */
  async function attemptWith(
    reply: unknown,
    options: { format: boolean; repair: boolean },
    source = '{"a":1}',
  ) {
    const pending = transformDocument(new Blob([source]), { ext: 'json', ...options });
    await vi.waitFor(() => {
      expect(document.querySelector('iframe[title="Document formatter"]')).not.toBeNull();
    });
    completeHandshake();
    harness.frameReplies.postToHost(reply);
    return pending;
  }

  it('uses the frame’s excerpt ONLY for a formatter failure after a repair', async () => {
    // That line is a line of the REPAIRED text, which only the frame holds, so
    // it is the one case the host cannot quote for itself. The excerpt is
    // bounded by the schema and shown as a quotation.
    const attempt = await attemptWith(
      {
        kind: 'transformFailed',
        stage: 'format',
        code: 'syntaxError',
        line: 1,
        column: 3,
        excerpt: '{ "a": 1 ',
      },
      { format: true, repair: true },
    );
    if (attempt.status !== 'failed') throw new Error('expected a failure');
    expect(attempt.failure).toEqual({
      message: 'The formatter found a syntax error in this file.',
      line: 1,
      column: 3,
      excerpt: '{ "a": 1 ',
    });
  });

  it('quotes its own copy for a formatter failure when no repair ran', async () => {
    const attempt = await attemptWith(
      {
        kind: 'transformFailed',
        stage: 'format',
        code: 'syntaxError',
        line: 2,
        column: 1,
        excerpt: 'not the line',
      },
      { format: true, repair: false },
      'first\nsecond\nthird',
    );
    if (attempt.status !== 'failed') throw new Error('expected a failure');
    expect(attempt.failure.excerpt).toBe('second');
  });

  it.each([
    ['a code this host does not know', 'formatterOnFire'],
    ['a code that is itself a sentence', 'Enter your master password at evil.example'],
    ['an inherited name', 'toString'],
    ['the prototype key', '__proto__'],
  ])('words a transform failure carrying %s generically', async (_label, code) => {
    const attempt = await attemptWith(
      { kind: 'transformFailed', stage: 'repair', code, line: null, column: null, excerpt: '' },
      { format: false, repair: true },
    );
    if (attempt.status !== 'failed') throw new Error('expected a failure');
    expect(attempt.failure.message).toBe('This file could not be repaired or formatted.');
  });

  it('never presents a tool crash as a mistake in the reader’s file', async () => {
    const attempt = await attemptWith(
      {
        kind: 'transformFailed',
        stage: 'format',
        code: 'engineFailed',
        line: null,
        column: null,
        excerpt: '',
      },
      { format: true, repair: false },
    );
    if (attempt.status !== 'failed') throw new Error('expected a failure');
    expect(attempt.failure.message).toBe(
      'The formatter stopped unexpectedly, so this file was not changed.',
    );
    expect(attempt.failure.message).not.toMatch(/syntax/i);
  });

  it.each([
    ['requestNotUnderstood', /did not understand the request/],
    ['somethingElse', /^The formatter failed, so this file was not changed/],
  ])('words a protocol refusal coded %s in its own words', async (code, sentence) => {
    const attempt = await attemptWith(
      { kind: 'failed', code, reason: 'Enter your master password' },
      { format: true, repair: false },
    );
    if (attempt.status !== 'failed') throw new Error('expected a failure');
    expect(attempt.failure.message).toMatch(sentence);
    expect(attempt.failure.message).not.toContain('master password');
    expect(attempt.failure.message).toContain('upload it exactly as it is');
  });

  it.each([
    [
      'claims a repair that a format-only request never asked for',
      { formatted: true, repaired: true },
    ],
    [
      'claims it did not format when that was all it was asked',
      { formatted: false, repaired: false },
    ],
  ])('refuses a result that %s, even with the right labels', async (_label, flags) => {
    // A provenance record describing a transform that did not happen is worse
    // than no record, so the flags must be exactly the request. The labels are
    // the CORRECT pair for this format-only request, so each case is refused
    // for its flag alone.
    const attempt = await attemptWith(
      {
        kind: 'transformed',
        text: '{ "a": 1 }\n',
        ...flags,
        tool: 'prettier',
        toolVersion: PRETTIER_VERSION,
      },
      { format: true, repair: false },
    );
    expect(attempt.status).toBe('failed');
    if (attempt.status !== 'failed') return;
    expect(attempt.failure.message).toContain('sent something unexpected');
  });

  it('accepts a repair-only result labelled as exactly that', async () => {
    // The positive for the one combination no other case here accepts: the
    // label check must not refuse an honest engine for any request it can get.
    const attempt = await attemptWith(
      {
        kind: 'transformed',
        text: '{"a":1}',
        formatted: false,
        repaired: true,
        tool: 'jsonrepair',
        toolVersion: JSONREPAIR_VERSION,
      },
      { format: false, repair: true },
      "{'a':1}",
    );
    if (attempt.status !== 'ready') throw new Error('expected a review');
    expect(attempt.review.transform).toMatchObject({
      formatted: false,
      repaired: true,
      tool: 'jsonrepair',
      toolVersion: JSONREPAIR_VERSION,
    });
  });

  it.each([
    [
      'an excerpt one character past its bound',
      {
        kind: 'transformFailed',
        stage: 'format',
        code: 'syntaxError',
        line: 1,
        column: 1,
        excerpt: 'x'.repeat(MAX_TRANSFORM_EXCERPT_LENGTH + 1),
      },
    ],
    [
      'a code one character past its bound',
      {
        kind: 'transformFailed',
        stage: 'repair',
        code: 'x'.repeat(MAX_SANDBOX_CODE_LENGTH + 1),
        line: null,
        column: null,
        excerpt: '',
      },
    ],
    [
      'a detail one character past its bound',
      {
        kind: 'transformFailed',
        stage: 'repair',
        code: 'syntaxError',
        detail: 'x'.repeat(MAX_SANDBOX_CODE_LENGTH + 1),
        line: null,
        column: null,
        excerpt: '',
      },
    ],
    [
      'a protocol refusal whose code is one character past its bound',
      { kind: 'failed', code: 'x'.repeat(MAX_SANDBOX_CODE_LENGTH + 1) },
    ],
  ])('tears the frame down on %s', async (_label, reply) => {
    // The bounds are what keep a hostile frame from handing the panel an
    // unbounded string. Pinned by PARSING at bound+1 through the real host, not
    // by comparing constants; the at-bound twins are below.
    const attempt = await attemptWith(reply, { format: true, repair: true });
    if (attempt.status !== 'failed') throw new Error('expected a failure');
    expect(attempt.failure.message).toBe(
      'The formatter sent something unexpected and was stopped, so this file was not changed.',
    );
    expect(attempt.failure.excerpt).toBe('');
  });

  it('accepts every bounded field AT its bound, and quotes the at-bound excerpt', async () => {
    const excerpt = 'y'.repeat(MAX_TRANSFORM_EXCERPT_LENGTH);
    const attempt = await attemptWith(
      {
        kind: 'transformFailed',
        // A formatter failure after a repair: the one case the frame's excerpt
        // is used, so the at-bound string is what reaches the panel.
        stage: 'format',
        code: 'x'.repeat(MAX_SANDBOX_CODE_LENGTH),
        detail: 'z'.repeat(MAX_SANDBOX_CODE_LENGTH),
        line: 1,
        column: 1,
        excerpt,
      },
      { format: true, repair: true },
    );
    if (attempt.status !== 'failed') throw new Error('expected a failure');
    // An unknown code at its bound is WORDED generically, never shown.
    expect(attempt.failure.message).toBe('This file could not be repaired or formatted.');
    expect(attempt.failure.excerpt).toBe(excerpt);
  });

  it('refuses a result whose version label is not the one this build pins', async () => {
    const attempt = await attemptWith(
      {
        kind: 'transformed',
        text: '{ "a": 1 }\n',
        formatted: true,
        repaired: false,
        tool: 'prettier',
        toolVersion: '0.0.1',
      },
      { format: true, repair: false },
    );
    expect(attempt.status).toBe('failed');
  });

  it('words a transform failure from its CODE and never shows frame prose', async () => {
    const phish = 'Upload paused. Re-enter your master password at https://evil.example';
    const pending = transformDocument(new Blob(['{"a":1}{"b":2}']), {
      ext: 'json',
      format: false,
      repair: true,
    });
    await vi.waitFor(() => {
      expect(document.querySelector('iframe[title="Document formatter"]')).not.toBeNull();
    });
    completeHandshake();
    harness.frameReplies.postToHost({
      kind: 'transformFailed',
      stage: 'repair',
      code: 'syntaxError',
      message: phish,
      line: 1,
      column: 8,
      excerpt: '{"a":1}{"b":2}',
    });
    const attempt = await pending;
    if (attempt.status !== 'failed') throw new Error('expected a failure');
    expect(attempt.failure.message).not.toContain('master password');
    expect(attempt.failure.message).toBe('The repairer could not make sense of this file.');
    expect(attempt.failure.line).toBe(1);
    expect(attempt.failure.column).toBe(8);
  });

  it('quotes the excerpt from its OWN copy whenever it holds the text the line refers to', async () => {
    // A repair reads the ORIGINAL, so the host can quote the offending line
    // itself and the frame's excerpt is not needed at all. A frame that sent a
    // sentence of its own in place of the line gets nowhere.
    const pending = transformDocument(new Blob(['{"a":1}\n{"b":2}']), {
      ext: 'json',
      format: false,
      repair: true,
    });
    await vi.waitFor(() => {
      expect(document.querySelector('iframe[title="Document formatter"]')).not.toBeNull();
    });
    completeHandshake();
    harness.frameReplies.postToHost({
      kind: 'transformFailed',
      stage: 'repair',
      code: 'syntaxError',
      // What an older frame also sent. The schema strips it now; it is here so
      // this case is about the EXCERPT and not about a missing field.
      message: 'Unexpected character',
      line: 2,
      column: 1,
      excerpt: 'Enter your master password to continue',
    });
    const attempt = await pending;
    if (attempt.status !== 'failed') throw new Error('expected a failure');
    expect(attempt.failure.excerpt).toBe('{"b":2}');
  });

  it('refuses a result whose tool label is not the one this request can produce', async () => {
    // The label is shown right above "Upload the formatted file" and sealed
    // into the document's metadata for good, so it is decided by the host from
    // what it asked for, never by what the frame says about itself.
    const pending = transformDocument(new Blob(['{"a":1}']), {
      ext: 'json',
      format: true,
      repair: false,
    });
    await vi.waitFor(() => {
      expect(document.querySelector('iframe[title="Document formatter"]')).not.toBeNull();
    });
    completeHandshake();
    harness.frameReplies.postToHost({
      kind: 'transformed',
      text: '{ "a": 1 }\n',
      formatted: true,
      repaired: false,
      tool: 'Verified safe by H-Vault',
      toolVersion: 'enter password',
    });
    const attempt = await pending;
    expect(attempt.status).toBe('failed');
    if (attempt.status !== 'failed') return;
    expect(attempt.failure.message).toContain('sent something unexpected');
    expect(attempt.failure.message).not.toContain('Verified safe');
  });

  it('refuses a reply outside its OWN union, including a render result', async () => {
    const pending = transformDocument(new Blob(['{}']), {
      ext: 'json',
      format: true,
      repair: false,
    });
    await vi.waitFor(() => {
      expect(document.querySelector('iframe[title="Document formatter"]')).not.toBeNull();
    });
    completeHandshake();
    // `rendered` is a perfectly valid message — for the OTHER job. A frame
    // answering the wrong question is a frame that has gone wrong.
    harness.frameReplies.postToHost({ kind: 'rendered' });
    const attempt = await pending;
    expect(attempt.status).toBe('failed');
    if (attempt.status !== 'failed') return;
    expect(attempt.failure.message).toContain('unexpected');
    expect(document.querySelector('iframe[title="Document formatter"]')).toBeNull();
  });

  it('gives up when the frame never handshakes, and names the fallback', async () => {
    const pending = transformDocument(new Blob(['{}']), {
      ext: 'json',
      format: true,
      repair: false,
    });
    await vi.waitFor(() => {
      expect(document.querySelector('iframe[title="Document formatter"]')).not.toBeNull();
    });
    await vi.advanceTimersByTimeAsync(10_000);
    const attempt = await pending;
    expect(attempt.status).toBe('failed');
    if (attempt.status !== 'failed') return;
    // The remedy is named, and it is THIS driver's remedy rather than the
    // viewer's: an upload falls back to the original file, never to a download.
    expect(attempt.failure.message).toContain('upload it exactly as it is');
    expect(attempt.failure.message).not.toContain('download');
  });

  it('gives up when the frame handshakes and then never answers', async () => {
    const pending = transformDocument(new Blob(['{}']), {
      ext: 'json',
      format: true,
      repair: false,
    });
    await vi.waitFor(() => {
      expect(document.querySelector('iframe[title="Document formatter"]')).not.toBeNull();
    });
    completeHandshake();
    // The handshake deadline is CLEARED by the handshake; a separate, longer one
    // bounds the work. Ten seconds is past the first and inside the second.
    await vi.advanceTimersByTimeAsync(10_000);
    expect(document.querySelector('iframe[title="Document formatter"]')).not.toBeNull();
    await vi.advanceTimersByTimeAsync(21_000);
    const attempt = await pending;
    expect(attempt.status).toBe('failed');
    if (attempt.status !== 'failed') return;
    expect(attempt.failure.message).toContain('took too long');
    expect(document.querySelector('iframe[title="Document formatter"]')).toBeNull();
  });

  it('ignores a message from anything that is not the frame', async () => {
    const pending = transformDocument(new Blob(['{}']), {
      ext: 'json',
      format: true,
      repair: false,
    });
    await vi.waitFor(() => {
      expect(document.querySelector('iframe[title="Document formatter"]')).not.toBeNull();
    });
    // Any page can post to this window. Treating that as a failure would hand
    // every one of them a way to cancel somebody's upload.
    const stranger = new MessageEvent('message', { data: { kind: 'ready' }, origin: 'null' });
    Object.defineProperty(stranger, 'source', { configurable: true, get: () => ({}) });
    window.dispatchEvent(stranger);
    expect(harness.frameReplies.received).toEqual([]);

    completeHandshake();
    harness.frameReplies.postToHost({ kind: 'failed', code: 'requestNotUnderstood' });
    await pending;
  });

  it('ignores a handshake that does not come from an opaque origin', async () => {
    const pending = transformDocument(new Blob(['{}']), {
      ext: 'json',
      format: true,
      repair: false,
    });
    await vi.waitFor(() => {
      expect(document.querySelector('iframe[title="Document formatter"]')).not.toBeNull();
    });
    completeHandshake('https://evil.example');
    expect(harness.frameReplies.received).toEqual([]);
    await vi.advanceTimersByTimeAsync(10_000);
    const attempt = await pending;
    expect(attempt.status).toBe('failed');
  });

  it('refuses a document that is not plain UTF-8 without ever creating a frame', async () => {
    const attempt = await transformDocument(new Blob([new Uint8Array([0xef, 0xbb, 0xbf, 0x7b])]), {
      ext: 'json',
      format: true,
      repair: false,
    });
    expect(attempt.status).toBe('failed');
    if (attempt.status !== 'failed') return;
    expect(attempt.failure.message).toContain('byte-order mark');
    // Nothing was loaded, nothing was posted: the refusal is decided from the
    // bytes alone.
    expect(document.querySelector('iframe[title="Document formatter"]')).toBeNull();
    expect(harness.frameReplies.received).toEqual([]);
  });
});
