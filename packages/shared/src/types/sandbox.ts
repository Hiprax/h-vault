/**
 * The messages that cross between the application and its isolated render
 * document — TYPES ONLY, with no runtime schema.
 *
 * ---------------------------------------------------------------------------
 * WHY THERE IS NO ZOD SCHEMA HERE, WHICH IS THE POINT OF THE FILE
 * ---------------------------------------------------------------------------
 *
 * The sandbox is built as its OWN Rollup graph, and `manualChunks` puts `zod` in
 * `vendor-core` next to AXIOS. A shared runtime schema would therefore drag an
 * HTTP client into a document whose entire premise is that it can issue no
 * request at all (`connect-src 'none'`), and it would do so silently: the
 * document would still work, and nothing in the pipeline would report it.
 *
 * So the two sides validate with different tools and share only the SHAPE, which
 * is erased at build time. The host uses Zod, as the application does
 * everywhere. The frame hand-rolls a structural validator over the handful of
 * shapes it accepts (`packages/client/src/sandbox/protocol.ts`) — a few `typeof`
 * checks, which is genuinely all the frame needs, because it dispatches on the
 * mode with a `switch` whose `default` is "unsupported" and therefore never
 * needs the list of valid modes at runtime.
 *
 * ---------------------------------------------------------------------------
 * THE DIRECTIONS, AND WHAT TRAVELS ON WHICH CHANNEL
 * ---------------------------------------------------------------------------
 *
 * On the WINDOW, exactly once, frame to host: `{ kind: 'ready' }`. Nothing else
 * is ever sent or accepted there, and the host removes its window listener the
 * moment it accepts one. Posting INTO an opaque origin requires
 * `targetOrigin: '*'`, which is the other reason nothing of value travels here.
 *
 * On a transferred `MessagePort`, everything else. A port dies with the document
 * that held it, so a frame that navigates itself away loses the channel instead
 * of continuing as a trusted peer.
 */
import type { PreviewMode } from '../constants/index.js';

/**
 * The RESOLVED theme, never the user's `'system'` preference.
 *
 * The sandbox cannot resolve `'system'` for itself in any way the application
 * would agree with, and a document that disagreed with its own chrome about
 * light or dark would look broken rather than themed.
 */
export type SandboxTheme = 'light' | 'dark';

/**
 * Host to frame: render these bytes.
 *
 * FOUR fields, and the list is exhaustive by design. It carries no document key,
 * no vault key, no access token, no document id and no document name. The
 * chrome around the frame — the title, the toolbar, the download button — is
 * drawn by the application OUTSIDE the rectangle, so a renderer cannot forge it
 * and does not need the name in order to draw it.
 *
 * `bytes` is COPIED by structured clone, never transferred. Transferring would
 * detach the host's buffer, and that buffer is a PROP the host was lent rather
 * than given: the second post of the same document — a remount, a StrictMode
 * double-effect — would then throw on a detached buffer and kill the preview
 * with no message to explain it. The extra copy is already inside
 * `MAX_PREVIEW_BYTES`, which is sized as "a small multiple of the file" for
 * exactly this reason.
 */
export interface SandboxRenderRequest {
  readonly kind: 'render';
  /** Which renderer to use. Resolved by the host from the document's name. */
  readonly mode: PreviewMode;
  /** The lowercased extension, as a hint for highlighting — never as a claim. */
  readonly ext: string;
  readonly theme: SandboxTheme;
  readonly bytes: ArrayBuffer;
}

/** Frame to host: the document was rendered. */
export interface SandboxRenderedMessage {
  readonly kind: 'rendered';
}

/**
 * Frame to host: it could not render, and why.
 *
 * `reason` is displayed by the application's chrome, so it is treated as
 * untrusted text: shown, never interpreted, and never used to build markup.
 */
export interface SandboxFailedMessage {
  readonly kind: 'failed';
  readonly reason: string;
}

/**
 * Frame to host: the user clicked a link inside the rendered document.
 *
 * A CAPABILITY, not data. The host validates the scheme with the repository's
 * existing `isSafeUrl` AT THE MESSAGE BOUNDARY — before any dialog and before it
 * reaches any presentation code — because a `javascript:` URL opened by the
 * application runs in the application's origin, with the vault key in it. That
 * is the entire compromise in one message.
 */
export interface SandboxLinkMessage {
  readonly kind: 'link';
  readonly href: string;
}

/**
 * Everything the frame may say on the port.
 *
 * A message outside this union — including one shaped like the window handshake,
 * which is how a compromised renderer would try to obtain a second channel —
 * tears the frame down and falls back to "download to view".
 */
export type SandboxFrameMessage =
  SandboxRenderedMessage | SandboxFailedMessage | SandboxLinkMessage;
