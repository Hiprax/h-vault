import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

/**
 * The driver's own contract, driven through a stubbed handshake.
 *
 * `connectSandbox` is a COLLABORATOR here, not the unit: what it guarantees (a
 * one-shot handshake, a transferred port, a listener removed before anything is
 * created) is pinned against the real thing in its own suite. What belongs here
 * is the property only this driver decides, and the one that replaces
 * "one frame, one payload" for a streaming session: a reply is an answer only
 * when it matches an OUTSTANDING request, and anything else tears the session
 * down rather than being guessed at.
 */

const connectSandbox = vi.fn();
vi.mock('../../src/lib/sandboxHandshake', () => ({
  connectSandbox: (options: unknown) => connectSandbox(options),
}));

const { openQrScanner } = await import('../../src/services/totpImport/qrSandbox');

type PostFn = (message: unknown, transfer?: Transferable[]) => void;
type FailFn = (reason: string) => void;

interface Captured {
  onMessage: (data: unknown, connection: { post: PostFn; fail: FailFn }) => void;
  onUnavailable: (reason: string) => void;
  post: ReturnType<typeof vi.fn<PostFn>>;
  fail: ReturnType<typeof vi.fn<FailFn>>;
  close: ReturnType<typeof vi.fn<() => void>>;
}

function openWithStub(): {
  captured: Captured;
  unavailable: string[];
  scanner: ReturnType<typeof openQrScanner>;
} {
  const post = vi.fn<PostFn>();
  const fail = vi.fn<FailFn>();
  const close = vi.fn<() => void>();
  let captured: Captured | null = null;

  connectSandbox.mockImplementation((options: Record<string, never>) => {
    const opts = options as unknown as {
      onOpen: (c: unknown) => void;
      onMessage: Captured['onMessage'];
      onUnavailable: (reason: string) => void;
    };
    const connection = { post, fail };
    captured = { onMessage: opts.onMessage, onUnavailable: opts.onUnavailable, post, fail, close };
    opts.onOpen(connection);
    return { close };
  });

  const unavailable: string[] = [];
  const scanner = openQrScanner((reason) => unavailable.push(reason));
  if (captured === null) throw new Error('connectSandbox was not called');
  return { captured, unavailable, scanner };
}

/** A stand-in for the transferable image; the driver never inspects it. */
const image = {} as ImageBitmap;

beforeEach(() => {
  connectSandbox.mockReset();
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  document.body.innerHTML = '';
});

describe('openQrScanner', () => {
  it('transfers the image rather than copying it', async () => {
    const { captured, scanner } = openWithStub();
    const pending = scanner.scan(image);

    const [message, transfer] = captured.post.mock.calls[0] ?? [];
    expect((message as { kind: string }).kind).toBe('qrScan');
    // Copying would move megabytes per camera frame across what is, in
    // Chromium, a separate process.
    expect(transfer).toEqual([image]);

    const requestId = (message as { requestId: number }).requestId;
    captured.onMessage({ kind: 'qrMiss', requestId }, { post: captured.post, fail: captured.fail });
    await expect(pending).resolves.toBeNull();
  });

  it('resolves a found code with its text', async () => {
    const { captured, scanner } = openWithStub();
    const pending = scanner.scan(image);
    const requestId = (captured.post.mock.calls[0]?.[0] as { requestId: number }).requestId;

    captured.onMessage(
      { kind: 'qrFound', requestId, text: 'otpauth-migration://offline?data=AA' },
      { post: captured.post, fail: captured.fail },
    );
    await expect(pending).resolves.toBe('otpauth-migration://offline?data=AA');
  });

  it('answers each request with its own reply, even out of order', async () => {
    const { captured, scanner } = openWithStub();
    const first = scanner.scan(image);
    const second = scanner.scan(image);
    const ids = captured.post.mock.calls.map(
      (call) => (call[0] as { requestId: number }).requestId,
    );

    captured.onMessage(
      { kind: 'qrFound', requestId: ids[1], text: 'otpauth://totp/b?secret=AA' },
      { post: captured.post, fail: captured.fail },
    );
    captured.onMessage(
      { kind: 'qrFound', requestId: ids[0], text: 'otpauth://totp/a?secret=AA' },
      { post: captured.post, fail: captured.fail },
    );

    await expect(first).resolves.toContain('/a?');
    await expect(second).resolves.toContain('/b?');
  });

  // A uniform tuple type, so the table does not widen into a union that
  // `it.each` cannot line up with the callback.
  const unexpectedReplies: [unknown, string][] = [
    [{ kind: 'rendered' }, 'a render reply'],
    [{ kind: 'transformed', text: 'x' }, 'a transform reply'],
    [{ kind: 'ready' }, 'a second handshake'],
    ['not an object', 'a bare string'],
  ];

  it.each(unexpectedReplies)('tears the session down on %s', (reply) => {
    const { captured } = openWithStub();
    captured.onMessage(reply, { post: captured.post, fail: captured.fail });
    expect(captured.fail).toHaveBeenCalled();
  });

  it('tears the session down on a reply to a request that was never made', () => {
    const { captured } = openWithStub();
    captured.onMessage(
      { kind: 'qrFound', requestId: 999, text: 'otpauth://totp/a?secret=AA' },
      { post: captured.post, fail: captured.fail },
    );
    expect(captured.fail).toHaveBeenCalledWith(expect.stringContaining('not made'));
  });

  it('tears the session down on a SECOND reply to the same request', async () => {
    const { captured, scanner } = openWithStub();
    const pending = scanner.scan(image);
    const requestId = (captured.post.mock.calls[0]?.[0] as { requestId: number }).requestId;
    const connection = { post: captured.post, fail: captured.fail };

    captured.onMessage({ kind: 'qrMiss', requestId }, connection);
    await expect(pending).resolves.toBeNull();

    captured.onMessage({ kind: 'qrMiss', requestId }, connection);
    expect(captured.fail).toHaveBeenCalled();
  });

  it('refuses an oversized decoded string rather than handing it on', () => {
    const { captured, scanner } = openWithStub();
    void scanner.scan(image);
    const requestId = (captured.post.mock.calls[0]?.[0] as { requestId: number }).requestId;
    captured.onMessage(
      { kind: 'qrFound', requestId, text: 'o'.repeat(20_000) },
      { post: captured.post, fail: captured.fail },
    );
    expect(captured.fail).toHaveBeenCalled();
  });

  it('treats one slow image as a miss, not as a dead session', async () => {
    // A camera produces another frame in about 120 ms, so the useful answer to a
    // slow decode is "try the next one" rather than "stop scanning".
    const { captured, scanner } = openWithStub();
    const pending = scanner.scan(image);
    vi.advanceTimersByTime(5000);
    await expect(pending).resolves.toBeNull();
    expect(captured.fail).not.toHaveBeenCalled();
  });

  it('rejects every outstanding scan when the session dies, rather than hanging them', async () => {
    const { captured, scanner } = openWithStub();
    const first = scanner.scan(image);
    const second = scanner.scan(image);

    captured.onUnavailable('the frame is gone');

    await expect(first).rejects.toThrow(/the frame is gone/);
    await expect(second).rejects.toThrow(/the frame is gone/);
  });

  it('resolves every outstanding scan as a miss when closed deliberately', async () => {
    // Closing is not a failure: the caller stopped the camera, and a pending
    // frame is simply a frame nobody is waiting for any more.
    const { scanner } = openWithStub();
    const pending = scanner.scan(image);
    scanner.close();
    await expect(pending).resolves.toBeNull();
  });

  it('ends the session on a failure the frame reported for itself', async () => {
    const { captured } = openWithStub();
    captured.onMessage(
      { kind: 'failed', reason: 'the scanner could not be loaded' },
      { post: captured.post, fail: captured.fail },
    );
    expect(captured.fail).toHaveBeenCalledWith('the scanner could not be loaded');
  });

  it('falls back to its own wording when the frame gives no reason', () => {
    const { captured } = openWithStub();
    captured.onMessage({ kind: 'failed' }, { post: captured.post, fail: captured.fail });
    expect(captured.fail).toHaveBeenCalledWith('The scanner failed.');
  });

  it('tears the session down on a reply that names no request at all', () => {
    const { captured, scanner } = openWithStub();
    void scanner.scan(image);
    captured.onMessage({ kind: 'qrMiss' }, { post: captured.post, fail: captured.fail });
    expect(captured.fail).toHaveBeenCalledWith(expect.stringContaining('without saying to what'));
  });

  it('reports the frame as unavailable at most once, however it dies', () => {
    const { captured, unavailable } = openWithStub();
    captured.onUnavailable('first');
    captured.onUnavailable('second');
    expect(unavailable).toEqual(['first']);
  });

  it('reports a frame that never started, with a remedy rather than a failure', () => {
    const { captured, unavailable } = openWithStub();
    captured.onUnavailable('The scanner could not start. Paste your export link instead.');
    expect(unavailable[0]).toContain('Paste your export link');
  });

  it('rejects a scan once the session is gone', async () => {
    const { captured, scanner } = openWithStub();
    captured.onUnavailable('gone');
    await expect(scanner.scan(image)).rejects.toThrow(/not running/);
  });

  it('removes its frame when closed, and closing twice is harmless', () => {
    const { captured, scanner } = openWithStub();
    expect(document.querySelectorAll('iframe')).toHaveLength(1);
    scanner.close();
    scanner.close();
    expect(document.querySelectorAll('iframe')).toHaveLength(0);
    expect(captured.close).toHaveBeenCalled();
  });

  it('builds a frame with an opaque origin and no delegated permission', () => {
    openWithStub();
    const frame = document.querySelector('iframe');
    // `allow-scripts` WITHOUT `allow-same-origin` is the containment itself.
    expect(frame?.getAttribute('sandbox')).toBe('allow-scripts');
    expect(frame?.getAttribute('sandbox')).not.toContain('allow-same-origin');
    // The camera belongs to this origin and must never be handed to the frame.
    expect(frame?.getAttribute('allow')).toBe('');
    // Asserted here rather than only where the constructor lives, because the
    // attributes are shared with the formatter's frame now: this is what makes a
    // change to the shared builder fail at BOTH boundaries rather than one.
    expect(frame?.referrerPolicy).toBe('no-referrer');
  });
});
