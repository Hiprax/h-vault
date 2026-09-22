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
 * WHICH FAILURES END THE SESSION, AND WHICH END ONE IMAGE
 * ---------------------------------------------------------------------------
 *
 * The distinction is carried by the reply's SHAPE, not by its wording, because
 * wording cannot be reasoned about. `qrFailed` names a `requestId` and refuses
 * one image; `failed` names none and ends the session. The frame decides which
 * it is, and it can only do so honestly: it sends `failed` when it could not
 * parse the request or could not load its decoder, and `qrFailed` for anything
 * it refused after it knew which request it was answering.
 *
 * Collapsing the two is what one oversized photograph used to cost: an
 * unattributable failure left the host no honest reading but "the session is
 * gone", so a running camera stopped mid-aim because somebody picked a big file.
 *
 * ---------------------------------------------------------------------------
 * WHAT CROSSES, IN EACH DIRECTION
 * ---------------------------------------------------------------------------
 *
 * Out: one image. A CAMERA FRAME is TRANSFERRED rather than copied: the host
 * mints the bitmap for this one request and never looks at it again, so
 * transferring avoids moving megabytes per frame across what is, in Chromium, a
 * process boundary. AN UPLOADED PHOTO IS COPIED, and that is not a preference:
 * a `Blob` is serializable but NOT transferable, so naming one in a transfer
 * list throws. See {@link transferableImage}.
 *
 * Back: one bounded string, or a miss. Never a pixel.
 */

/**
 * The frame looked at ONE image and refused it, in its own words.
 *
 * A TYPE rather than a sentence for the caller to recognise, because `scan`
 * rejects for several reasons and only this one carries a message written FOR A
 * USER: it names which limit the image crossed, where the caller's own fallback
 * can say only that something went wrong. Matching on the text instead would
 * make every one of those sentences load-bearing, and they are meant to be free
 * to change.
 *
 * It is NOT a dead channel. The session is still good and the next image is
 * worth trying, which is the distinction `SandboxQrFailedMessage` exists to
 * carry across the boundary.
 */
export class QrImageRefusedError extends Error {
  constructor(reason: string) {
    super(reason);
    this.name = 'QrImageRefusedError';
  }
}

/** A live scanning channel. */
export interface QrScanner {
  /**
   * Decode one image. Resolves with the text, or `null` when nothing was found.
   *
   * Never rejects for an ordinary miss, because while aiming a camera a miss is
   * the common case rather than an error. It rejects for exactly two reasons,
   * and they call for opposite answers:
   *
   *  - THE CHANNEL IS GONE — the frame never started, or it failed, or the
   *    caller closed. The session is over and the caller stops; every
   *    outstanding and future `scan` rejects the same way.
   *  - THIS ONE IMAGE COULD NOT BE HANDED OVER. The channel is untouched and
   *    the session is still good, so a camera simply takes the next frame.
   *
   * A caller that cannot tell them apart and stops on either is correct but
   * pessimistic; one that continues on either will loop on a dead channel. The
   * two shipped callers stop on neither: the camera pump swallows both and is
   * ended by `onUnavailable` instead, and an uploaded photo has one shot and
   * reports the failure either way.
   *
   * Requests made before the frame has finished its handshake are QUEUED, not
   * refused. That is not a nicety: see `parked` in the implementation.
   */
  readonly scan: (image: ImageBitmap | Blob) => Promise<string | null>;
  readonly close: () => void;
}

/** How long one image may take before the host stops waiting for it. */
const REPLY_TIMEOUT_MS = 4000;
const HANDSHAKE_TIMEOUT_MS = 10_000;

/**
 * How many timed-out request ids are remembered, so that a LATE reply can be
 * told apart from an INVENTED one.
 *
 * The rule this bound serves is the session's central one: a reply that matches
 * no outstanding request tears the whole session down, camera and all. That rule
 * is load-bearing and stays — but a reply the frame sends at 4.1 s for a request
 * the host gave up on at 4.0 s is a SLOW frame, not a hostile one, and killing
 * the camera for it turns one slow decode into "scanning stopped for no visible
 * reason". So a timed-out id is forgiven EXACTLY ONCE and then forgotten, which
 * keeps the second reply to any one request a teardown, exactly as before.
 *
 * Sixteen, and bounded because the alternative grows for the life of a scanning
 * session. Two callers share one session at most — the camera pump, which holds
 * one request in flight and paces at about 120 ms, and an uploaded photo, which
 * rides the camera's session when one is running and is gated to one at a time
 * by the panel — so sixteen ids is far more slack than a frame that is merely
 * slow can use, while an id older than that is indistinguishable from an
 * invented one and is treated as one. The bound holds whatever a caller does,
 * which is the point of having one: it is sized from that reasoning rather than
 * dependent on it.
 *
 * An array rather than a `Set`: at sixteen entries a linear scan is cheaper than
 * the bookkeeping an insertion-ordered eviction needs, and it evicts without
 * having to reason about an iterator that may yield nothing.
 */
const MAX_REMEMBERED_TIMEOUTS = 16;

/**
 * The transfer list for one image, or nothing at all.
 *
 * ONLY an `ImageBitmap` may be named in a transfer list. A `Blob` — which is
 * what the "upload a photo" path produces, `File` being a `Blob` — is
 * SERIALIZABLE but NOT TRANSFERABLE, and naming one throws
 * `DataCloneError: Found invalid value in transferList.` SYNCHRONOUSLY, before
 * the message is queued. MEASURED: it threw on every single upload, so that path
 * could never have worked once, and the throw jumped past the caller's cleanup
 * and leaked one hidden sandbox iframe per attempt.
 *
 * THE TYPE CHECKER CANNOT CATCH THIS and must never be relied on to. The DOM
 * library's `Transferable` union includes `MediaSourceHandle`, which is declared
 * as an EMPTY interface, so every object is structurally assignable to it and
 * `[blob]` type-checks perfectly clean.
 *
 * The test is `instanceof Blob` rather than `instanceof ImageBitmap`, and that
 * is not stylistic either: `ImageBitmap` is absent from some environments this
 * module is driven in (jsdom has no such global, so the check would silently
 * answer "not a bitmap" for everything), while `Blob` exists everywhere. The two
 * named types are the whole of `scan`'s input, so testing the one that always
 * exists is what keeps the rule enforceable rather than accidentally inverted.
 */
function transferableImage(image: ImageBitmap | Blob): Transferable[] | undefined {
  return image instanceof Blob ? undefined : [image];
}

interface Pending {
  readonly resolve: (text: string | null) => void;
  readonly reject: (error: Error) => void;
  readonly timer: ReturnType<typeof setTimeout>;
}

/** What a caller asked for, before it is known whether it can be sent yet. */
interface Request {
  readonly image: ImageBitmap | Blob;
  readonly resolve: (text: string | null) => void;
  readonly reject: (error: Error) => void;
}

type Post = (message: unknown, transfer?: Transferable[]) => void;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

/**
 * The longest sentence this host will repeat from the frame.
 *
 * Every `reason` is the frame's own words, and the frame is the untrusted side
 * of this boundary: it is rendered as TEXT and never as markup, so the risk is
 * not injection but a message long enough to bury the page. The document viewer
 * bounds its own `reason` for exactly this, and this is the same rule at the
 * same boundary.
 */
const MAX_REASON_LENGTH = 200;

/** A frame-supplied sentence, or the host's own words when it is not usable. */
function reasonOrDefault(value: unknown, fallback: string): string {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_REASON_LENGTH
    ? value
    : fallback;
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
  /** Ids this host stopped waiting for; see {@link MAX_REMEMBERED_TIMEOUTS}. */
  const timedOut: number[] = [];
  /**
   * Requests made BEFORE the frame finished its handshake.
   *
   * WITHOUT THIS QUEUE, "upload a photo" CANNOT WORK, and the reason is timing
   * rather than anything about images. A channel is not open the instant it is
   * asked for: the frame has to load its document and post its handshake first,
   * which is tens of milliseconds at best. The camera survives refusal because
   * it is a LOOP — a frame refused now is retried 120 ms later, and the caller
   * swallows the refusal — but an upload stands a scanner up and scans ONCE, so
   * a refusal is the whole feature failing, reported to the user as "That image
   * could not be read." however good the photograph was.
   *
   * Parking rather than refusing is also what the handshake deadline is already
   * for: a parked request is answered when the channel opens, or refused with
   * the same sentence every other caller gets when the frame never arrives.
   *
   * It needs no bound, and the reason is its LIFETIME rather than its width: it
   * exists only between a frame being created and its handshake landing or
   * timing out, and every way that can end drains this completely —
   * {@link dispatch} on success, a rejection in `die`, a resolution in `close`.
   * A caller cannot make it grow without bound either, since both shipped ones
   * await each scan before asking for the next.
   */
  const parked: Request[] = [];
  let post: Post | null = null;
  let dead = false;
  let nextRequestId = 0;

  const rememberTimedOut = (requestId: number): void => {
    timedOut.push(requestId);
    if (timedOut.length > MAX_REMEMBERED_TIMEOUTS) timedOut.shift();
  };

  /**
   * Was this a reply to a request the host already gave up on? Forgiving it
   * CONSUMES the id, so a SECOND reply to the same request is still a teardown.
   */
  const forgiveLateReply = (requestId: number): boolean => {
    const at = timedOut.indexOf(requestId);
    if (at === -1) return false;
    timedOut.splice(at, 1);
    return true;
  };

  /**
   * Send one request on an OPEN channel, and arm its deadline.
   *
   * `send` is passed in rather than read from `post`, so this cannot be called
   * on a channel that is not open: the one caller that has to prove the channel
   * is open is the one holding the reference.
   */
  const dispatch = (request: Request, send: Post): void => {
    const requestId = (nextRequestId += 1);
    try {
      send({ kind: 'qrScan', requestId, image: request.image }, transferableImage(request.image));
    } catch {
      // NOTHING IS REGISTERED UNTIL THE POST HAS SUCCEEDED, which is why the
      // request is sent before the map entry and the timer exist. A throw here
      // used to leave a pending entry and a live 4 s timer behind for a message
      // that was never sent, and the reply that would have cleared them could
      // never arrive. Ordering it this way means the failed request simply never
      // happened; there is no state to unwind.
      //
      // A refused image is one lost frame, NOT a dead channel: the port is
      // untouched, so the session stays up and the next frame is 120 ms away.
      // `scan` still rejects, because the caller asked for an answer and there
      // is none.
      request.reject(new Error('That image could not be handed to the scanner.'));
      return;
    }
    const timer = setTimeout(() => {
      pending.delete(requestId);
      rememberTimedOut(requestId);
      // One slow image is not a dead session: resolve it as a miss and let the
      // next frame try. A camera produces another one in about 120 ms.
      request.resolve(null);
    }, REPLY_TIMEOUT_MS);
    pending.set(requestId, { resolve: request.resolve, reject: request.reject, timer });
  };

  const die = (reason: string): void => {
    if (dead) return;
    dead = true;
    for (const entry of pending.values()) {
      clearTimeout(entry.timer);
      entry.reject(new Error(reason));
    }
    pending.clear();
    // A request that never went out is refused with the same sentence as one
    // that did: from the caller's side there is no difference, and the remedy
    // the wording carries is the same either way.
    for (const request of parked.splice(0)) request.reject(new Error(reason));
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
      // The port is the channel. A camera frame rides it TRANSFERRED, an
      // uploaded photo COPIED; see the module header and
      // {@link transferableImage} for why the two differ.
      post = connection.post;
      // Whatever was asked for while the frame was still loading goes out now,
      // in the order it was asked for.
      for (const request of parked.splice(0)) dispatch(request, connection.post);
    },
    onMessage: (data, connection) => {
      if (!isRecord(data)) {
        connection.fail('The scanner sent something unreadable.');
        return;
      }
      const kind = data.kind;
      if (kind === 'failed') {
        // A failure that names NO request: the frame could not parse what it was
        // sent, or its decoder will not load. Neither improves with the next
        // image, so it ends the session rather than one scan. A failure that IS
        // about one image arrives as `qrFailed` below and is answered there.
        connection.fail(reasonOrDefault(data.reason, 'The scanner failed.'));
        return;
      }
      if (kind !== 'qrFound' && kind !== 'qrMiss' && kind !== 'qrFailed') {
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
        if (forgiveLateReply(requestId)) {
          // A slow answer to a request already resolved as a miss. The caller
          // has its answer and the camera has moved on several frames, so there
          // is nothing to deliver and nothing wrong: drop it and keep scanning.
          return;
        }
        // A reply to nothing, or a second reply to one request.
        connection.fail('The scanner replied to a request that was not made.');
        return;
      }
      pending.delete(requestId);
      clearTimeout(entry.timer);

      if (kind === 'qrFailed') {
        // ONE image refused, by a frame that is still perfectly healthy. The
        // session stays up, the camera keeps going, and the caller is handed the
        // frame's own sentence because it says WHICH limit the image crossed —
        // which "That image could not be read." cannot.
        entry.reject(
          new QrImageRefusedError(reasonOrDefault(data.reason, 'That image could not be read.')),
        );
        return;
      }
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
        if (dead) {
          reject(new Error('The scanner is not running.'));
          return;
        }
        const request: Request = { image, resolve, reject };
        const send = post;
        if (send === null) {
          // The handshake has not finished. See {@link parked}: refusing here
          // is what made an uploaded photo fail every time.
          parked.push(request);
          return;
        }
        dispatch(request, send);
      }),
    close: () => {
      if (dead) return;
      dead = true;
      for (const entry of pending.values()) {
        clearTimeout(entry.timer);
        entry.resolve(null);
      }
      pending.clear();
      // Closing is not a failure: the caller stopped, and a request nobody is
      // waiting for any more is answered the same way an unanswered one is.
      for (const request of parked.splice(0)) request.resolve(null);
      session.close();
      frame.remove();
    },
  };
}
