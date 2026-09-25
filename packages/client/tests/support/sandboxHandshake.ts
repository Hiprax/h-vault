import { vi } from 'vitest';

/**
 * Complete a sandbox frame's handshake under jsdom, for the two QR suites.
 *
 * NOT yet the one definition in the repository, and the difference matters in a
 * codebase where "ONE definition" is a load-bearing phrase: three other suites
 * still hand-roll this — `tests/document-sandbox.test.tsx`,
 * `tests/components/DocumentDetail.preview.test.tsx` and
 * `tests/document-transform.test.ts`. Folding those in is worth doing and is not
 * this file's claim to have done.
 *
 * What it IS, is the single definition for the two suites that need a REAL
 * `connectSandbox` driving a REAL `MessagePort`: the QR driver's own integration
 * test, and the scan panel's frame-lifetime test. Both have to solve the same
 * two jsdom problems, and a second copy of the solution is a second place for it
 * to drift.
 *
 * The problems, both of them properties of the harness rather than of the code
 * under test:
 *
 *  1. jsdom leaves `iframe.contentWindow` as a real `about:blank` window that
 *     never loads the document, so the frame never posts anything. The host
 *     accepts a handshake only when `event.source === frame.contentWindow`, and
 *     a `MessageEvent` constructed in a test cannot name a cross-document
 *     window, so the identity has to be substituted on both sides at once.
 *  2. `event.origin` has to read `'null'`, which is what a sandboxed document
 *     with an opaque origin reports.
 *
 * What comes back is the port the HOST transferred, already started, so a test
 * speaks as the frame does: post a reply on it, read the request off it.
 */

interface StubWindow {
  postMessage: ReturnType<typeof vi.fn>;
}

/** Give a frame a `contentWindow` a test can both name and observe. */
export function stubFrameWindow(frame: HTMLIFrameElement): StubWindow {
  const stub: StubWindow = { postMessage: vi.fn() };
  Object.defineProperty(frame, 'contentWindow', { configurable: true, get: () => stub });
  return stub;
}

/** Post one window message AS the frame, with the source and origin the host requires. */
export function postAsFrame(stub: StubWindow, data: unknown): void {
  const event = new MessageEvent('message', { data, origin: 'null' });
  Object.defineProperty(event, 'source', { configurable: true, get: () => stub });
  window.dispatchEvent(event);
}

/**
 * Drive the handshake of the one sandbox frame attached to the document, and
 * return the port the host transferred.
 */
export function completeSandboxHandshake(): { host: MessagePort; stub: StubWindow } {
  const frame = document.querySelector('iframe');
  if (frame === null) throw new Error('the driver did not attach a frame');
  const stub = stubFrameWindow(frame);

  postAsFrame(stub, { kind: 'ready' });

  const host = stub.postMessage.mock.calls[0]?.[2]?.[0] as MessagePort | undefined;
  if (host === undefined) throw new Error('the host transferred no port');
  host.start();
  return { host, stub };
}

/** The next message the host posts on `port`, as a typed payload. */
export function nextHostMessage<T>(port: MessagePort): Promise<T> {
  return new Promise<T>((resolve) => {
    port.addEventListener('message', (event) => resolve((event as MessageEvent).data as T), {
      once: true,
    });
  });
}
