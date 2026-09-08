import { useCallback, useEffect, useRef, useState } from 'react';
import { z } from 'zod';
import type { PreviewMode, SandboxTheme } from '@hvault/shared';
import { isSafeUrl } from '../../lib/utils';
import { connectSandbox } from '../../lib/sandboxHandshake';

/**
 * The application's half of the document-preview protocol.
 *
 * It owns the frame element, the handshake, the channel, and the validation of
 * everything that comes back. It owns NO chrome: the title, the toolbar and the
 * download button are drawn by the caller, OUTSIDE the rectangle, so a renderer
 * cannot forge them.
 *
 * ---------------------------------------------------------------------------
 * THE HANDSHAKE LIVES IN ONE PLACE, AND IT IS NOT THIS FILE
 * ---------------------------------------------------------------------------
 *
 * `src/lib/sandboxHandshake.ts` owns the one-shot handshake, the port, the
 * deadline and the teardown, and its docblock is where the reasoning lives.
 * That is not tidiness: this application speaks to the isolated document from
 * TWO places — the viewer here, and the upload panel's format-and-repair
 * transform — under the same threat model, and the containment is a REMOVED
 * LISTENER rather than a flag. A control whose whole nature is "there is exactly
 * one of it" cannot be written down twice.
 *
 * What stays here is what is specific to a preview: which replies are accepted,
 * what the frame is handed, and when the element is remounted.
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

  // `torn` is cleared HERE and nowhere else — on a new document, never on a
  // rename or a theme change — and that asymmetry with the element key below is
  // deliberate. A torn component renders no iframe at all, so the key cannot
  // revive it; what revives it is the caller. `DocumentDetail` records the
  // reason `giveUp` reported, which makes its own `previewRefusal` non-null and
  // takes the refusal branch, so this component is not rendered at all while it
  // is torn and never sees the changed prop. Clearing `torn` on `mode`/`ext`
  // would therefore be dead code today — but if this component ever gains a
  // second caller that keeps it mounted through a failure, that is the line to
  // revisit, and it belongs to the caller's decision about when a failed preview
  // is worth retrying rather than to this component's.

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

    // Every handler is created INSIDE the effect, and the callbacks it needs are
    // read from refs. A handler built from the props directly would put them in
    // the dependency list, and an inline arrow at the call site would then tear
    // down a healthy frame and re-handshake on every render.
    const session = connectSandbox({
      // The frame is read LIVE rather than captured: `contentWindow` is null on
      // a detached iframe, and the source check is only meaningful against the
      // current element.
      getFrame: () => frameRef.current,
      handshakeTimeoutMs: HANDSHAKE_TIMEOUT_MS,
      reasons: {
        // A CSP or CORS mistake makes the frame blank with no error anyone can
        // read, so the deadline is what turns "nothing happened" into a verdict
        // the caller can act on. Degrading to a download is always better than
        // an empty rectangle that never resolves.
        timeout: 'The document preview did not load. You can download the file instead.',
        spokeEarly: 'The document preview did not start correctly and was stopped.',
      },
      onOpen: ({ post }) => {
        // FOUR fields and no more: no document key, no vault key, no access
        // token, no document id, no document name.
        //
        // COPIED, not transferred, and that is a decision rather than an
        // oversight. Transferring would detach `bytes` — which is a PROP, owned
        // by the caller — so the second post of the same document (a remount on
        // a theme change, a React StrictMode double-effect, any re-render that
        // re-runs this) would throw `DataCloneError` on a detached buffer, and
        // the preview would die for a reason no message would explain. A
        // component must not consume a prop it was lent. The extra copy is
        // already inside the budget: `MAX_PREVIEW_BYTES` is sized as "a small
        // multiple of the file", precisely because the app holds the plaintext,
        // the frame receives it, and a renderer then builds its own
        // representation on top.
        post({ kind: 'render', mode, ext, theme, bytes });
      },
      onMessage: (data, { fail }) => {
        const parsed = frameMessageSchema.safeParse(data);
        if (!parsed.success) {
          // Anything unexpected — INCLUDING a `ready`-shaped message, which is
          // how a compromised renderer would try to obtain a second channel, and
          // including a TRANSFORM reply, which a render request never asked for
          // — is a frame that has gone wrong. Detection lives here rather than
          // on the window precisely because the window listener is gone by now.
          fail('The document preview sent something unexpected and was stopped.');
          return;
        }
        const message = parsed.data;
        if (message.kind === 'failed') {
          fail(message.reason);
          return;
        }
        if (message.kind === 'link') {
          // AT THE MESSAGE BOUNDARY, before any dialog and before this reaches
          // any presentation code. `isSafeUrl` admits http, https and mailto
          // only; a `javascript:`, `data:` or `blob:` href opens nothing and
          // shows nothing, silently, because there is no user intent worth
          // confirming for a scheme the application will never open.
          if (!isSafeUrl(message.href)) return;
          onLinkRef.current(message.href);
        }
        // 'rendered' needs no action: the frame is visible either way, and the
        // host draws no "loading" state a renderer could keep hostage.
      },
      onUnavailable: giveUp,
    });

    return session.close;
    // `generation` is in the list because it is what identifies the ELEMENT: a
    // new document remounts the iframe, and this effect must bind to the new one.
    //
    // EVERY OTHER ENTRY HERE MUST BE ACCOUNTED FOR IN THE ELEMENT KEY BELOW,
    // and exactly two are accounted for without appearing in it. `bytes` is
    // represented by `generation`, which is bumped during render in the same
    // commit the new buffer arrives, so it cannot move without the key moving;
    // putting a buffer in a string key would say nothing anyway. `giveUp` is
    // `useCallback(..., [])` and is stable for this component's life, so it
    // never triggers a re-run at all — if it ever gains a dependency, it needs
    // one of those two treatments and not a third. Everything else belongs in
    // the key; see the key's own comment for why re-running this effect against
    // a frame that has already handshaked can only ever end in the timeout.
  }, [bytes, mode, ext, theme, generation, giveUp]);

  if (torn) return null;

  return (
    <iframe
      // A NEW element per document, so one document can never observe the next.
      //
      // THE RULE, WHICH IS GENERAL AND NOT ABOUT ANY ONE PROP: every input the
      // protocol effect above reads is part of this key. A frame that has
      // ALREADY handshaked never posts `ready` again — that is the whole shape
      // of the one-shot protocol — so re-running the effect against the same
      // element registers a listener nothing will ever speak to, and the only
      // possible outcome is the ten-second timeout. The reader watches a working
      // preview be replaced by "The document preview did not load."
      //
      // Remounting is the honest answer: a new element, a new document, a new
      // handshake, and no stale channel to reason about. It is also the ONLY
      // answer available, because the payload — the mode and the extension
      // among it — crosses exactly once, in `onOpen`, so a frame cannot be told
      // it is now rendering something else.
      //
      // Both of the props that are not `bytes` have reached this the hard way.
      // The theme is the obvious one: toggling dark mode killed the preview.
      // `mode` and `ext` are the pair that reads like a rename and is not.
      // Renaming `notes.md` to `notes.markdown`, or a `.txt` to a `.log`, moves
      // `ext` (and often `mode` with it) while the plaintext stays the SAME
      // BUFFER — `DocumentDetail`'s read effect depends on the document's id and
      // not on its metadata, deliberately, so that a rename does not re-download
      // the file. `generation` therefore does not move, and before this neither
      // did anything else in the key. A key listing only the props someone
      // happened to think of is a key that will be wrong again; list what the
      // effect reads.
      key={`${String(generation)}:${mode}:${ext}:${theme}`}
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
      // In the tab order, DECLARED. An iframe is sequentially focusable anyway,
      // but the application's own focus trap works from a selector list that has
      // no `iframe` in it — so while the viewer's expanded panel is trapping
      // focus, a keyboard user would be cycled between its two header buttons and
      // could never reach the document itself. This changes no security property:
      // it makes an existing capability visible to the trap, and grants nothing.
      tabIndex={0}
    />
  );
}
