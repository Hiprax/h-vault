import { describe, it, expect, vi, afterEach } from 'vitest';
import { openQrScanner } from '../../src/services/totpImport/qrSandbox';
import {
  completeSandboxHandshake,
  postAsFrame,
  stubFrameWindow,
} from '../support/sandboxHandshake';

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

afterEach(() => {
  document.body.innerHTML = '';
});

describe('the scanner over the real handshake', () => {
  it('transfers the image on the port, rather than copying it', async () => {
    const scanner = openQrScanner(vi.fn());
    const { host } = completeSandboxHandshake();

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

  it('posts an uploaded photo BY COPY, because a Blob is not transferable', async () => {
    // THE DEFECT THIS PINS. `scan` accepts `ImageBitmap | Blob`, and a `Blob` is
    // SERIALIZABLE but not TRANSFERABLE. Naming one in a transfer list throws
    // `DataCloneError: Found invalid value in transferList.` synchronously,
    // inside the promise executor, so before this was fixed EVERY "upload a
    // photo" attempt failed and the feature could never have worked once.
    //
    // The type checker cannot catch it: `Transferable` is a union that includes
    // `MediaSourceHandle`, which is an EMPTY interface, so every object is
    // structurally assignable to it.
    const scanner = openQrScanner(vi.fn());
    const { host } = completeSandboxHandshake();

    const received = new Promise<MessageEvent>((resolve) => {
      host.addEventListener('message', (event) => resolve(event as MessageEvent), { once: true });
    });

    const photo = new File([new Uint8Array([1, 2, 3, 4])], 'export.png', { type: 'image/png' });
    const pending = scanner.scan(photo);

    const event = await received;
    const message = event.data as { kind: string; requestId: number; image: unknown };
    // Arriving at all IS the assertion: before the fix the post threw inside the
    // promise executor and no message was ever queued, so this `await` timed out.
    expect(message.kind).toBe('qrScan');
    expect(typeof message.requestId).toBe('number');
    // The negative that makes this a transfer-list test rather than a plumbing
    // test: the sender's own Blob is NOT detached, because nothing was moved.
    // Transferring it would have thrown; transferring the ArrayBuffer above
    // empties it, and that contrast is the point of running both cases here.
    expect(photo.size).toBe(4);
    // MEASURED, and the reason the far side's TYPE is not asserted here: jsdom's
    // structured clone flattens a Blob to a plain `{}` with no keys. Whether a
    // real engine delivers a readable Blob to the frame is a question only a real
    // engine can answer, and `e2e/totp-import.spec.ts` asks it by uploading an
    // actual PNG and expecting the accounts inside it to appear.

    host.postMessage({ kind: 'qrFound', requestId: message.requestId, text: 'otpauth://totp/a' });
    await expect(pending).resolves.toBe('otpauth://totp/a');
    scanner.close();
  });

  it('sends a photo uploaded BEFORE the handshake, which is the real upload order', async () => {
    // The order every real upload actually happens in: the scanner is created
    // and scanned in the same breath, long before the frame has loaded its
    // document and posted its handshake. Refusing at that moment reported "That
    // image could not be read." for every photograph, and the camera hid it by
    // simply trying again 120 ms later.
    const scanner = openQrScanner(vi.fn());
    const photo = new File([new Uint8Array([1, 2, 3, 4])], 'export.png', { type: 'image/png' });
    const pending = scanner.scan(photo);

    const { host } = completeSandboxHandshake();
    const received = new Promise<MessageEvent>((resolve) => {
      host.addEventListener('message', (event) => resolve(event as MessageEvent), { once: true });
    });

    const message = (await received).data as { kind: string; requestId: number };
    expect(message.kind).toBe('qrScan');

    host.postMessage({ kind: 'qrFound', requestId: message.requestId, text: 'otpauth://totp/a' });
    await expect(pending).resolves.toBe('otpauth://totp/a');
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
    if (frame === null) throw new Error('the driver did not attach a frame');
    postAsFrame(stubFrameWindow(frame), { kind: 'qrFound' });

    expect(unavailable).toHaveBeenCalledWith(expect.stringContaining('behaved unexpectedly'));
  });
});
