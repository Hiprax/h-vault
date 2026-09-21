import { describe, it, expect, vi, afterEach } from 'vitest';
import { openQrScanner } from '../../src/services/totpImport/qrSandbox';

/**
 * The scanner driver over the REAL handshake.
 *
 * Its own suite stubs `connectSandbox` in order to drive reply handling without
 * a frame. This one does the opposite: it runs the genuine handshake, so the
 * parts only the real thing exercises are covered, above all the TRANSFER. An
 * image posted by copy rather than by transfer would move megabytes per camera
 * frame across what is, in Chromium, a process boundary, and nothing else in the
 * suite would notice.
 */

interface StubWindow {
  postMessage: ReturnType<typeof vi.fn>;
}

/**
 * What a real `contentWindow` gives the host, and nothing more. jsdom leaves
 * `iframe.contentWindow` as a real about:blank Window that never loads the
 * document, and a `MessageEvent` built in a test cannot name a cross-document
 * window, so the identity has to be substituted.
 */
function stubFrameWindow(frame: HTMLIFrameElement): StubWindow {
  const stub: StubWindow = { postMessage: vi.fn() };
  Object.defineProperty(frame, 'contentWindow', { configurable: true, get: () => stub });
  return stub;
}

function handshake(): { host: MessagePort; stub: StubWindow } {
  const frame = document.querySelector('iframe');
  if (frame === null) throw new Error('the driver did not attach a frame');
  const stub = stubFrameWindow(frame);

  const event = new MessageEvent('message', { data: { kind: 'ready' }, origin: 'null' });
  Object.defineProperty(event, 'source', { configurable: true, get: () => stub });
  window.dispatchEvent(event);

  const port = stub.postMessage.mock.calls[0]?.[2]?.[0] as MessagePort | undefined;
  if (port === undefined) throw new Error('the host transferred no port');
  port.start();
  return { host: port, stub };
}

afterEach(() => {
  document.body.innerHTML = '';
});

describe('the scanner over the real handshake', () => {
  it('transfers the image on the port, rather than copying it', async () => {
    const scanner = openQrScanner(vi.fn());
    const { host } = handshake();

    const received = new Promise<MessageEvent>((resolve) => {
      host.addEventListener('message', (event) => resolve(event as MessageEvent), { once: true });
    });

    // A transferable the environment actually has. An `ImageBitmap` does not
    // exist in jsdom, and what is being pinned is the transfer itself.
    const image = new ArrayBuffer(8);
    const pending = scanner.scan(image as unknown as ImageBitmap);

    const event = await received;
    const message = event.data as { kind: string; requestId: number };
    expect(message.kind).toBe('qrScan');
    // Transferred, so the sender's buffer is detached. That is the observable
    // difference between a transfer and a copy.
    expect(image.byteLength).toBe(0);

    host.postMessage({ kind: 'qrMiss', requestId: message.requestId });
    await expect(pending).resolves.toBeNull();
    scanner.close();
  });

  it('gives up on a frame that never completes its handshake', () => {
    vi.useFakeTimers();
    try {
      const unavailable = vi.fn();
      openQrScanner(unavailable);
      // A CSP or CORS mistake makes a frame blank with no error anyone can read,
      // so the deadline is what turns "nothing happened" into a verdict.
      vi.advanceTimersByTime(11_000);
      expect(unavailable).toHaveBeenCalledWith(expect.stringContaining('Paste your export link'));
    } finally {
      vi.useRealTimers();
    }
  });

  it('refuses a frame that speaks before its handshake', () => {
    const unavailable = vi.fn();
    openQrScanner(unavailable);
    const frame = document.querySelector('iframe');
    const stub = stubFrameWindow(frame!);

    const event = new MessageEvent('message', { data: { kind: 'qrFound' }, origin: 'null' });
    Object.defineProperty(event, 'source', { configurable: true, get: () => stub });
    window.dispatchEvent(event);

    expect(unavailable).toHaveBeenCalledWith(expect.stringContaining('behaved unexpectedly'));
  });
});
