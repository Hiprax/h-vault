/**
 * The application's half of the sandbox handshake — ONE definition, used by
 * every driver that speaks to the isolated document.
 *
 * ---------------------------------------------------------------------------
 * THE ONE-SHOT HANDSHAKE, WHICH IS THE ACTUAL CONTAINMENT
 * ---------------------------------------------------------------------------
 *
 * The frame posts `{kind:'ready'}` on the window exactly once. This host accepts
 * it only when BOTH `event.source === frame.contentWindow` AND `event.origin ===
 * 'null'` hold, and then REMOVES THE WINDOW LISTENER. The removal is the
 * load-bearing half, and the intuitive argument for why is WRONG, so it is
 * written down here rather than left to be re-derived:
 *
 * An iframe's sandboxing flag set is re-applied to EVERY document created in
 * that nested browsing context. A compromised renderer that sets `location =
 * 'https://evil.example'` therefore does NOT escape the sandbox. Its document is
 * still sandboxed, still has an opaque origin, and so still reports
 * `event.origin === 'null'`; and `iframe.contentWindow` is the same WindowProxy
 * across navigations, so the source check passes too. BOTH halves pass for an
 * attacker-controlled document. What that document does NOT have is a CSP — a
 * policy is per-response and does not survive a navigation — so it has full
 * network access and would be an exfiltration endpoint if this host ever spoke
 * to it again.
 *
 * So the host must never speak to it again. Once the listener is gone, a second
 * window `ready` reaches nobody. That is the intended outcome and NOT a case
 * this host detects: there is deliberately no handler looking for a second
 * handshake, because a listener that stayed registered in order to detect one
 * would be the very thing being defended against. Detection lives on the PORT
 * instead, where a `ready`-shaped or otherwise unexpected message tears the
 * frame down — and each caller decides that for itself, because each one accepts
 * a different set of replies.
 *
 * `event.origin === 'null'` is retained, but only as a defence against a frame
 * that somehow lost its sandbox attribute entirely. It does NOT distinguish
 * "still the sandbox" from "navigated away", and must never be described as
 * though it did.
 *
 * ---------------------------------------------------------------------------
 * FOUR RULES FOR ANYONE EDITING THIS FILE
 * ---------------------------------------------------------------------------
 *
 *  1. THERE IS NO `accepted` BOOLEAN AND THERE MUST NEVER BE ONE. Removing the
 *     listener IS the one-shot property. A redundant flag beside it makes the
 *     property something a later branch must remember to check instead of
 *     something the code cannot express twice — and it makes the property
 *     UNTESTABLE, because deleting the `removeEventListener` line would then
 *     change no observable behaviour and the test that defends the containment
 *     would pass against a build that has lost it. Measured: that is exactly
 *     what happened here before this rule was written down.
 *  2. THE ORDER INSIDE THE ACCEPT PATH IS FIXED. Remove the listener, clear the
 *     timer, and only THEN create the channel, start it and transfer it. The
 *     suite proves the null-guard below ran by observing that no `MessageChannel`
 *     was constructed, so constructing one earlier makes that test unable to
 *     fail.
 *  3. A WRONG SOURCE OR A WRONG ORIGIN IS IGNORED, NEVER A TEARDOWN. Any page
 *     on the internet can post to this window; treating that as a failure would
 *     hand every one of them a way to cancel a preview.
 *  4. TEARDOWN NEVER TOUCHES THE FRAME ELEMENT. It removes listeners, clears the
 *     timer and closes the port. One caller renders its iframe declaratively and
 *     React owns that node; the other creates one imperatively and removes it
 *     itself. A module that removed the element would break the first and
 *     duplicate the second.
 */

/** What a caller may do with a live channel. */
interface SandboxConnection {
  /**
   * Post a payload to the frame on the transferred port.
   *
   * The port, never the window: posting INTO an opaque origin requires
   * `targetOrigin: '*'`, so nothing of value may travel there. The port is the
   * channel precisely because it dies with the document that held it.
   *
   * `transfer` is OPTIONAL and every caller but one leaves it out, deliberately.
   * A render request's bytes are COPIED, because that buffer is a prop the host
   * was lent and must still own afterwards; transferring would detach it and the
   * second post of the same document would throw. The scanner is the exception:
   * it mints one image per request, never looks at it again, and moves megabytes
   * per camera frame across what is in Chromium a separate process, so there the
   * copy is the thing worth avoiding.
   */
  readonly post: (message: unknown, transfer?: Transferable[]) => void;
  /**
   * Give up on this frame, reporting why. Tears the channel down and calls
   * `onUnavailable` AT MOST ONCE, however many times it is called.
   */
  readonly fail: (reason: string) => void;
}

export interface ConnectSandboxOptions {
  /**
   * The frame, read LIVE at every message rather than captured once.
   *
   * An accessor rather than an element, and the difference is not cosmetic:
   * `contentWindow` becomes `null` when an iframe is detached, and the source
   * check below is only meaningful if it reads the CURRENT element. A snapshot
   * taken at connect time would keep comparing against a window that no longer
   * exists.
   */
  readonly getFrame: () => HTMLIFrameElement | null;
  /**
   * How long to wait for the handshake before giving up on the frame.
   *
   * A CSP or CORS mistake makes the frame blank with no error anyone can read,
   * so this is what turns "nothing happened" into a verdict the caller can act
   * on. It covers the HANDSHAKE only; a caller that also needs a bound on the
   * REPLY arms its own timer in {@link onOpen}, because stretching this one to
   * cover both would make a blank frame take the whole reply budget to report.
   */
  readonly handshakeTimeoutMs: number;
  /** Called once, when the channel is live. This is where the payload is posted. */
  readonly onOpen: (connection: SandboxConnection) => void;
  /**
   * Called for every message on the port, with the RAW value.
   *
   * Raw and unvalidated on purpose: each driver accepts a different set of
   * replies, and a shared schema would hand a render frame the right to send a
   * transform result. The caller validates and calls `fail` on anything outside
   * its own set.
   */
  readonly onMessage: (data: unknown, connection: SandboxConnection) => void;
  /** Called at most once, with a sentence the caller can show a user. */
  readonly onUnavailable: (reason: string) => void;
  /**
   * The two sentences this module itself has to produce, supplied by the caller.
   *
   * They are the caller's words rather than this module's because the FALLBACK
   * differs per driver and the sentence has to name it: a preview that never
   * loads degrades to "download the file instead", while a transform that never
   * loads degrades to "upload the original unchanged". A single neutral wording
   * would be accurate for neither, and a module that guessed would put the wrong
   * remedy in front of the user at exactly the moment they need the right one.
   */
  readonly reasons: {
    /** No handshake arrived inside {@link handshakeTimeoutMs}. */
    readonly timeout: string;
    /** The frame posted something on the window before its handshake. */
    readonly spokeEarly: string;
  };
}

export interface SandboxSession {
  /** Tear down listeners, timer and port. Idempotent, and it never reports. */
  readonly close: () => void;
}

/** Narrow an unknown to an indexable object without asserting anything about it. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

/**
 * Wait for one frame's handshake, then hand its channel to the caller.
 *
 * Registers the window listener immediately, so an imperative caller must call
 * this BEFORE it attaches its frame to the document; a declarative one calls it
 * from an effect, by which point the element is committed.
 */
export function connectSandbox(options: ConnectSandboxOptions): SandboxSession {
  const { getFrame, handshakeTimeoutMs, onOpen, onMessage, onUnavailable, reasons } = options;

  let port: MessagePort | null = null;
  // The ONLY flag, and it guards the giving-up path alone: it stops the caller
  // being told twice that the frame is unavailable. It is NOT, and must never
  // become, a record of whether the handshake was accepted — see rule 1 above.
  let dead = false;

  const teardown = (): void => {
    window.removeEventListener('message', onWindowMessage);
    clearTimeout(timer);
    // Closing the port is what actually severs the channel: a port outlives the
    // element unless it is closed, and a frame that still holds a live one is
    // still a peer.
    port?.close();
    port = null;
  };

  const fail = (reason: string): void => {
    if (dead) return;
    dead = true;
    teardown();
    onUnavailable(reason);
  };

  const connection: SandboxConnection = {
    post: (message: unknown, transfer?: Transferable[]) => {
      if (transfer === undefined) {
        port?.postMessage(message);
        return;
      }
      port?.postMessage(message, transfer);
    },
    fail,
  };

  const onPortMessage = (event: MessageEvent): void => {
    onMessage(event.data, connection);
  };

  function onWindowMessage(event: MessageEvent): void {
    const source = event.source;
    const target = getFrame()?.contentWindow ?? null;
    // REJECT BEFORE COMPARING when either side is null. `contentWindow` is null
    // for a detached iframe and `event.source` is null for a message from a
    // closed window, so a bare `source === target` evaluates TRUE after teardown
    // and would accept anything at all. That single line is how this design gets
    // undone.
    if (!source || !target || source !== target) return;
    // Retained as a defence against a frame that lost its sandbox attribute
    // entirely. It does NOT distinguish the sandbox from a document that
    // navigated itself away — see the note at the top of this file.
    if (event.origin !== 'null') return;

    if (!isRecord(event.data) || event.data.kind !== 'ready') {
      // A frame that speaks before its handshake is not trusted with one.
      fail(reasons.spokeEarly);
      return;
    }
    // ONE-SHOT, and this line IS the control. Removed BEFORE anything is created
    // or posted, so there is no window in which a second handshake could be
    // accepted — not even a synchronous re-entrant one.
    window.removeEventListener('message', onWindowMessage);
    clearTimeout(timer);

    const channel = new MessageChannel();
    port = channel.port1;
    port.addEventListener('message', onPortMessage);
    port.start();
    // `targetOrigin: '*'` is forced, not chosen: an opaque origin cannot be
    // named. It is why the port exists at all — everything of value travels on
    // it, and is never posted to a window.
    target.postMessage({ kind: 'channel' }, '*', [channel.port2]);
    onOpen(connection);
  }

  const timer = setTimeout(() => {
    fail(reasons.timeout);
  }, handshakeTimeoutMs);

  window.addEventListener('message', onWindowMessage);
  return { close: teardown };
}
