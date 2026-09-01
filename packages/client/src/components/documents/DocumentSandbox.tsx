import { useCallback, useEffect, useRef, useState } from 'react';
import { z } from 'zod';
import type { PreviewMode, SandboxTheme } from '@hvault/shared';
import { isSafeUrl } from '../../lib/utils';

/**
 * The application's half of the document-preview protocol.
 *
 * It owns the frame element, the handshake, the channel, and the validation of
 * everything that comes back. It owns NO chrome: the title, the toolbar and the
 * download button are drawn by the caller, OUTSIDE the rectangle, so a renderer
 * cannot forge them.
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
 * frame down.
 *
 * `event.origin === 'null'` is retained, but only as a defence against a frame
 * that somehow lost its sandbox attribute entirely. It does NOT distinguish
 * "still the sandbox" from "navigated away", and must never be described as
 * though it did.
 */

/** How long to wait for the frame's handshake before giving up on it. */
const HANDSHAKE_TIMEOUT_MS = 10_000;

/**
 * What the frame may say on the port, validated with Zod because this is the
 * application, which validates with Zod everywhere.
 *
 * The frame validates with a hand-rolled checker instead
 * (`src/sandbox/protocol.ts`), and that asymmetry is deliberate rather than
 * untidy: `manualChunks` puts `zod` in `vendor-core` next to axios, so a schema
 * shared with the sandbox would put an HTTP client inside a document that is
 * forbidden to make requests.
 *
 * A STRICT union: `z.discriminatedUnion` over `kind`, with each member a plain
 * `z.object()` (which strips unknown keys by default in this codebase). A
 * message that does not parse is not merely ignored — it is treated as the frame
 * having gone wrong, which is the only safe reading when the peer is untrusted.
 */
const frameMessageSchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('rendered') }),
  z.object({ kind: z.literal('failed'), reason: z.string().max(500) }),
  z.object({ kind: z.literal('link'), href: z.string().max(4096) }),
]);

export interface DocumentSandboxProps {
  /**
   * The verified plaintext, COPIED to the frame rather than transferred, so the
   * caller keeps its own usable reference. Changing this prop to a different
   * buffer is what makes a NEW frame element.
   */
  readonly bytes: ArrayBuffer;
  readonly mode: PreviewMode;
  /** The lowercased extension, as a highlighting hint — never as a claim. */
  readonly ext: string;
  readonly theme: SandboxTheme;
  /**
   * Called with an href whose scheme has ALREADY passed `isSafeUrl`.
   *
   * Validation happens here, at the message boundary, and not in whatever
   * renders the confirmation dialog. An arrangement where this host forwarded a
   * raw href and the presentation layer decided would be the entire compromise
   * in one message: a `javascript:` URL opened by the application runs in the
   * application's origin, with the vault key in it.
   */
  readonly onLink: (href: string) => void;
  /**
   * Called when the preview cannot be shown — a handshake that never arrived, a
   * frame that spoke out of turn, or a renderer that reported failure. The
   * caller degrades to its download affordance; an empty rectangle forever is
   * the one outcome that is never acceptable.
   */
  readonly onUnavailable: (reason: string) => void;
  readonly title?: string;
  readonly className?: string;
}

export function DocumentSandbox({
  bytes,
  mode,
  ext,
  theme,
  onLink,
  onUnavailable,
  title = 'Document preview',
  className,
}: DocumentSandboxProps) {
  const frameRef = useRef<HTMLIFrameElement | null>(null);
  const [torn, setTorn] = useState(false);

  // ONE FRAME PER DOCUMENT. A new buffer means a new element, a new listener and
  // exactly one accepted handshake — never a listener that outlives the frame it
  // was registered for. Derived during render (React's documented
  // adjust-state-when-a-prop-changes pattern) rather than in an effect, so the
  // remount happens in the same commit as the new bytes and the previous
  // document's frame is never handed the next document's plaintext.
  const [seenBytes, setSeenBytes] = useState(bytes);
  const [generation, setGeneration] = useState(0);
  if (seenBytes !== bytes) {
    setSeenBytes(bytes);
    setGeneration((value) => value + 1);
    setTorn(false);
  }

  // The callbacks are held in refs so the protocol effect depends only on the
  // frame's identity and the payload. A caller passing an inline arrow would
  // otherwise re-run the effect on every render, which would tear down a healthy
  // frame and re-handshake mid-preview.
  const onLinkRef = useRef(onLink);
  const onUnavailableRef = useRef(onUnavailable);
  useEffect(() => {
    onLinkRef.current = onLink;
    onUnavailableRef.current = onUnavailable;
  }, [onLink, onUnavailable]);

  const giveUp = useCallback((reason: string) => {
    setTorn(true);
    onUnavailableRef.current(reason);
  }, []);

  useEffect(() => {
    const frame = frameRef.current;
    if (!frame) return;

    let port: MessagePort | null = null;
    // The ONLY flag, and it guards the giving-up path alone: it stops the caller
    // being told twice that the preview is unavailable.
    //
    // There is deliberately NO `handshakeAccepted` boolean. The one-shot rule is
    // enforced by REMOVING THE LISTENER and by nothing else, because a boolean
    // makes the property something a later branch must remember to check while
    // the removal makes it structural. It also makes the property TESTABLE: with
    // a redundant flag in place, deleting the `removeEventListener` line changes
    // no observable behaviour, so the test that is supposed to defend the
    // containment passes against a build that has lost it. Measured — that is
    // exactly what happened here before this comment was written.
    let dead = false;

    const teardown = (): void => {
      window.removeEventListener('message', onWindowMessage);
      clearTimeout(timer);
      // Closing the port is what actually severs the channel: a port outlives
      // the element unless it is closed, and a frame that still holds a live one
      // is still a peer.
      port?.close();
      port = null;
    };

    const fail = (reason: string): void => {
      if (dead) return;
      dead = true;
      teardown();
      giveUp(reason);
    };

    const onPortMessage = (event: MessageEvent): void => {
      const parsed = frameMessageSchema.safeParse(event.data);
      if (!parsed.success) {
        // Anything unexpected — INCLUDING a `ready`-shaped message, which is how
        // a compromised renderer would try to obtain a second channel — is a
        // frame that has gone wrong. Detection lives here rather than on the
        // window precisely because the window listener is gone by now.
        fail('The document preview sent something unexpected and was stopped.');
        return;
      }
      const message = parsed.data;
      if (message.kind === 'failed') {
        fail(message.reason);
        return;
      }
      if (message.kind === 'link') {
        // AT THE MESSAGE BOUNDARY, before any dialog and before this reaches any
        // presentation code. `isSafeUrl` admits http, https and mailto only; a
        // `javascript:`, `data:` or `blob:` href opens nothing and shows
        // nothing, silently, because there is no user intent worth confirming
        // for a scheme the application will never open.
        if (!isSafeUrl(message.href)) return;
        onLinkRef.current(message.href);
      }
      // 'rendered' needs no action: the frame is visible either way, and the
      // host draws no "loading" state a renderer could keep hostage.
    };

    function onWindowMessage(event: MessageEvent): void {
      const source = event.source;
      const target = frameRef.current?.contentWindow ?? null;
      // REJECT BEFORE COMPARING when either side is null. `contentWindow` is
      // null for a detached iframe and `event.source` is null for a message from
      // a closed window, so a bare `source === target` evaluates TRUE after
      // teardown and would accept anything at all. That single line is how this
      // design gets undone.
      if (!source || !target || source !== target) return;
      // Retained as a defence against a frame that lost its sandbox attribute
      // entirely. It does NOT distinguish the sandbox from a document that
      // navigated itself away — see the note at the top of this file.
      if (event.origin !== 'null') return;

      if (!isRecord(event.data) || event.data.kind !== 'ready') {
        // A frame that speaks before its handshake is not trusted with one.
        fail('The document preview did not start correctly and was stopped.');
        return;
      }
      // ONE-SHOT, and this line IS the control. Removed BEFORE anything is
      // created or posted, so there is no window in which a second handshake
      // could be accepted — not even a synchronous re-entrant one.
      window.removeEventListener('message', onWindowMessage);
      clearTimeout(timer);

      const channel = new MessageChannel();
      port = channel.port1;
      port.addEventListener('message', onPortMessage);
      port.start();
      // `targetOrigin: '*'` is forced, not chosen: an opaque origin cannot be
      // named. It is why the port exists at all — the plaintext below travels on
      // it, and is never posted to a window.
      target.postMessage({ kind: 'channel' }, '*', [channel.port2]);
      // FOUR fields and no more: no document key, no vault key, no access token,
      // no document id, no document name.
      //
      // COPIED, not transferred, and that is a decision rather than an
      // oversight. Transferring would detach `bytes` — which is a PROP, owned by
      // the caller — so the second post of the same document (a remount on a
      // theme change, a React StrictMode double-effect, any re-render that
      // re-runs this) would throw `DataCloneError` on a detached buffer, and the
      // preview would die for a reason no message would explain. A component
      // must not consume a prop it was lent. The extra copy is already inside
      // the budget: `MAX_PREVIEW_BYTES` is sized as "a small multiple of the
      // file", precisely because the app holds the plaintext, the frame receives
      // it, and a renderer then builds its own representation on top.
      port.postMessage({ kind: 'render', mode, ext, theme, bytes });
    }

    const timer = setTimeout(() => {
      // A CSP or CORS mistake makes the frame blank with no error anyone can
      // read, so the timeout is what turns "nothing happened" into a verdict the
      // caller can act on. Degrading to a download is always better than an
      // empty rectangle that never resolves.
      fail('The document preview did not load. You can download the file instead.');
    }, HANDSHAKE_TIMEOUT_MS);

    window.addEventListener('message', onWindowMessage);
    return teardown;
    // `generation` is in the list because it is what identifies the ELEMENT: a
    // new document remounts the iframe, and this effect must bind to the new one.
  }, [bytes, mode, ext, theme, generation, giveUp]);

  if (torn) return null;

  return (
    <iframe
      // A NEW element per document, so one document can never observe the next.
      //
      // The theme is part of the key for a reason that is easy to get wrong: the
      // protocol effect re-runs when the theme changes, but a frame that has
      // ALREADY handshaked never posts `ready` again, so a re-run against the
      // same element would register a listener nothing ever speaks to and end in
      // the ten-second timeout — a preview that vanishes when the user toggles
      // dark mode. Remounting is the honest answer: a new element, a new
      // handshake, and no stale channel to reason about.
      key={`${String(generation)}:${theme}`}
      ref={frameRef}
      src="/sandbox.html"
      title={title}
      className={className}
      // `allow-scripts` WITHOUT `allow-same-origin`, which is what gives the
      // framed document an opaque origin. The two must NEVER appear together:
      // that pair lets the framed document remove its own sandbox attribute and
      // is worth nothing at all. No other flag is granted — no `allow-popups`,
      // `allow-forms`, `allow-modals`, `allow-downloads` or
      // `allow-top-navigation`.
      sandbox="allow-scripts"
      // Not decoration. This host is rendered at `/documents/<id>`, and without
      // this the frame reads that id out of `document.referrer` — the one piece
      // of identifying information the protocol deliberately never sends.
      // helmet's default `Referrer-Policy: no-referrer` covers it in production,
      // but that is an undocumented load-bearing dependency and it is absent on
      // the Vite dev server the end-to-end suite drives.
      referrerPolicy="no-referrer"
      // Deny every delegated permission rather than trusting each feature's
      // default.
      allow=""
    />
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
