import { MAX_SANDBOX_QR_TEXT_LENGTH } from '@hvault/shared';
import { createHiddenSandboxFrame } from '../../lib/sandboxFrame';
import { connectSandbox, type SandboxSession } from '../../lib/sandboxHandshake';

/**
 * The application's half of the QR-scanning protocol.
 *
 * The decoder runs inside the isolated document for the reason its own source
 * gives: it is third-party code fed pixels from outside the machine, and in this
 * origin it would sit beside an unlocked vault key. This module stands on the
 * safe side of that boundary and owns everything the frame must not: the camera,
 * the capture, the pacing, and the parsing of whatever comes back.
 *
 * ---------------------------------------------------------------------------
 * ONE FRAME, MANY REQUESTS, AND WHY THAT IS SAFE HERE
 * ---------------------------------------------------------------------------
 *
 * Both existing drivers hold "one frame, one payload": the viewer remounts per
 * document and the transform driver destroys its frame after a single answer. A
 * scanning session cannot work that way, because it is a stream of camera frames
 * and a handshake per frame would cost more than the decode.
 *
 * What replaces that property is `requestId`. Every request carries one, every
 * reply must echo one that is still outstanding, and anything else tears the
 * session down: a reply to a request that was never made, a second reply to the
 * same request, a reply shaped like a render or a transform, or a `ready`
 * message arriving on the port. The frame is also single-purpose for its whole
 * life, because nothing else is ever sent to it.
 *
 * ---------------------------------------------------------------------------
 * WHAT CROSSES, IN EACH DIRECTION
 * ---------------------------------------------------------------------------
 *
 * Out: one image, TRANSFERRED rather than copied. The host mints it for this one
 * request and never looks at it again, so transferring avoids moving megabytes
 * per frame across what is, in Chromium, a process boundary.
 *
 * Back: one bounded string, or a miss. Never a pixel.
 */

/** A live scanning channel. */
export interface QrScanner {
  /**
   * Decode one image. Resolves with the text, or `null` when nothing was found.
   *
   * Never rejects for an ordinary miss, because while aiming a camera a miss is
   * the common case rather than an error. It rejects only when the channel is
   * gone, which the caller answers by stopping.
   */
  readonly scan: (image: ImageBitmap | Blob) => Promise<string | null>;
  readonly close: () => void;
}

/** How long one image may take before the host stops waiting for it. */
const REPLY_TIMEOUT_MS = 4000;
const HANDSHAKE_TIMEOUT_MS = 10_000;

interface Pending {
  readonly resolve: (text: string | null) => void;
  readonly reject: (error: Error) => void;
  readonly timer: ReturnType<typeof setTimeout>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

/**
 * Stand up a scanning channel.
 *
 * `onUnavailable` is called at most once, with a sentence for the user; after it
 * the session is dead and every outstanding and future `scan` rejects. The
 * caller's remedy is the point of the wording: scanning degrades to pasting a
 * link, not to nothing.
 */
export function openQrScanner(onUnavailable: (reason: string) => void): QrScanner {
  const frame = createHiddenSandboxFrame('QR scanner');
  const pending = new Map<number, Pending>();
  let post: ((message: unknown, transfer?: Transferable[]) => void) | null = null;
  let dead = false;
  let nextRequestId = 0;

  const die = (reason: string): void => {
    if (dead) return;
    dead = true;
    for (const entry of pending.values()) {
      clearTimeout(entry.timer);
      entry.reject(new Error(reason));
    }
    pending.clear();
    session.close();
    frame.remove();
    onUnavailable(reason);
  };

  const session: SandboxSession = connectSandbox({
    getFrame: () => frame,
    handshakeTimeoutMs: HANDSHAKE_TIMEOUT_MS,
    reasons: {
      timeout: 'The scanner could not start. Paste your export link instead.',
      spokeEarly: 'The scanner behaved unexpectedly. Paste your export link instead.',
    },
    onOpen: (connection) => {
      // The port is the channel, and the image rides it TRANSFERRED. See the
      // module header for why this one is transferred where a render's bytes
      // are copied.
      post = connection.post;
    },
    onMessage: (data, connection) => {
      if (!isRecord(data)) {
        connection.fail('The scanner sent something unreadable.');
        return;
      }
      const kind = data.kind;
      if (kind === 'failed') {
        // A failure the frame could name. It belongs to no single request, so it
        // ends the session rather than one scan.
        connection.fail(typeof data.reason === 'string' ? data.reason : 'The scanner failed.');
        return;
      }
      if (kind !== 'qrFound' && kind !== 'qrMiss') {
        // Including a `rendered`, `transformed` or `ready` message: a frame
        // answering a question nobody asked is a frame that has gone wrong.
        connection.fail('The scanner sent an unexpected reply.');
        return;
      }

      const requestId = data.requestId;
      if (typeof requestId !== 'number') {
        connection.fail('The scanner replied without saying to what.');
        return;
      }
      const entry = pending.get(requestId);
      if (entry === undefined) {
        // A reply to nothing, or a second reply to one request.
        connection.fail('The scanner replied to a request that was not made.');
        return;
      }
      pending.delete(requestId);
      clearTimeout(entry.timer);

      if (kind === 'qrMiss') {
        entry.resolve(null);
        return;
      }
      const text = data.text;
      if (typeof text !== 'string' || text.length > MAX_SANDBOX_QR_TEXT_LENGTH) {
        connection.fail('The scanner sent an unreadable result.');
        return;
      }
      entry.resolve(text);
    },
    onUnavailable: die,
  });

  document.body.append(frame);

  return {
    scan: (image) =>
      new Promise<string | null>((resolve, reject) => {
        if (dead || post === null) {
          reject(new Error('The scanner is not running.'));
          return;
        }
        const requestId = (nextRequestId += 1);
        const timer = setTimeout(() => {
          pending.delete(requestId);
          // One slow image is not a dead session: resolve it as a miss and let
          // the next frame try. A camera produces another one in about 120 ms.
          resolve(null);
        }, REPLY_TIMEOUT_MS);
        pending.set(requestId, { resolve, reject, timer });
        post({ kind: 'qrScan', requestId, image }, [image]);
      }),
    close: () => {
      if (dead) return;
      dead = true;
      for (const entry of pending.values()) {
        clearTimeout(entry.timer);
        entry.resolve(null);
      }
      pending.clear();
      session.close();
      frame.remove();
    },
  };
}
