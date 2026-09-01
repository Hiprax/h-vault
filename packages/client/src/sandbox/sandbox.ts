import { frameMessage, parseRenderRequest } from './protocol';
import { renderText } from './renderers/text';

/**
 * The document sandbox's entry point — the frame side of the render protocol.
 *
 * Named `sandbox.ts` and NOT `main.ts`: the application's entry is
 * `src/main.tsx`, and two entries claiming the chunk base name `main` would
 * leave the loser with a numeric suffix that resolves to no budget entry and
 * fails the `bundle` gate for a reason nobody would connect to a filename.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS DOCUMENT IS
 * ---------------------------------------------------------------------------
 *
 * It is embedded by the application as
 * `<iframe src="/sandbox.html" sandbox="allow-scripts" referrerpolicy="no-referrer" allow="">`.
 * Without `allow-same-origin` it holds an OPAQUE origin: every same-origin check
 * against the embedder fails, so it can read neither the app's DOM nor its
 * `sessionStorage`, IndexedDB, cookies, nor any key in the app's memory. Its own
 * Content-Security-Policy — attached by the Express route that serves it, and
 * NOT inherited from the embedder, because a document fetched from an http(s)
 * URL never inherits one — denies it every network capability, `connect-src`
 * included.
 *
 * So a vulnerability in any parser this document runs lands somewhere holding no
 * key, no token, no cookie and no storage, that can open no socket. That is the
 * whole point of the isolation, and it is why every renderer lives here rather
 * than in the page that holds the unlocked vault.
 *
 * ---------------------------------------------------------------------------
 * TWO TRAPS THE POLICY SETS, WRITTEN DOWN WHERE A RENDERER AUTHOR WILL READ THEM
 * ---------------------------------------------------------------------------
 *
 *  1. `connect-src 'none'` blocks `fetch()` and `XMLHttpRequest` against a
 *     `blob:` URL just as it blocks them against the network. A renderer must
 *     therefore read its bytes from the `ArrayBuffer` it was handed, and mint a
 *     blob URL ONLY to put in a `src` attribute — which `img-src` and
 *     `media-src` govern, and which do not involve `connect-src` at all.
 *  2. `img-src` carries no http/https source. That is what stops a markdown
 *     document pulling a remote image, which is INTENDED (a remote fetch is a
 *     read receipt for a private file) and is shown to the user as a
 *     disabled-remote-content notice — never repaired by widening `img-src`.
 *
 * ---------------------------------------------------------------------------
 * THE HANDSHAKE, FROM THIS SIDE
 * ---------------------------------------------------------------------------
 *
 * `{kind:'ready'}` is the only message this document ever posts on the WINDOW.
 * The host answers by transferring a `MessagePort`, and everything after that
 * travels on the port. There is deliberately no check on the host's
 * `event.origin` here: this document cannot know the embedder's origin (it is
 * framed with `referrerpolicy="no-referrer"`, and its own origin is opaque), and
 * the trust direction runs the other way — the HOST is what must not trust this
 * document. What stops an arbitrary page from framing it and speaking to it is
 * `frame-ancestors 'self'` in its policy, not a check written here.
 */

/**
 * The port the host transferred, or `null` before the handshake completes.
 *
 * Module-level rather than passed around, because there is exactly one per
 * document for the life of the document: a port dies with the document that
 * held it, which is precisely why the protocol puts everything after the
 * handshake on one.
 */
let channel: MessagePort | null = null;

/** Where a renderer's output goes. Created by `sandbox.html`. */
function renderTarget(doc: Document): HTMLElement {
  const existing = doc.getElementById('root');
  if (existing) return existing;
  // A document served without its root element is a build mistake, not a
  // runtime condition; recreating it is cheaper than a blank frame with no
  // explanation, and costs nothing when the element is there.
  const created = doc.createElement('div');
  created.id = 'root';
  doc.body.append(created);
  return created;
}

/**
 * Render one request, or say why it could not be rendered.
 *
 * Every branch answers on the port. Silence is the one thing this must never
 * do: the host times out on a frame that never speaks, and degrades to
 * "download to view", so a swallowed error costs the user a working preview and
 * tells nobody why.
 */
function renderRequest(doc: Document, port: MessagePort, data: unknown): void {
  const request = parseRenderRequest(data);
  if (!request) {
    port.postMessage(frameMessage.failed('The preview request was not understood.'));
    return;
  }
  // The resolved theme, never the user's `'system'` preference — the sandbox
  // cannot resolve that in any way the application would agree with, and a frame
  // that disagreed with its own chrome would look broken rather than themed.
  doc.documentElement.dataset.theme = request.theme;

  const target = renderTarget(doc);
  try {
    switch (request.mode) {
      case 'text':
        target.replaceChildren(renderText(doc, request.bytes));
        port.postMessage(frameMessage.rendered());
        return;
      default:
        // 19.1-19.3 add the rest. An unrecognised mode and an unimplemented one
        // take the SAME branch on purpose, which is why the frame never needs
        // the list of valid modes at runtime.
        target.replaceChildren();
        port.postMessage(frameMessage.failed('No renderer for this document type.'));
        return;
    }
  } catch {
    // A renderer that threw has left the target in an unknown state, so it is
    // emptied before the host is told. The message carries NO detail from the
    // error: it would be built from the document's own bytes, and it is
    // displayed by the application's chrome.
    target.replaceChildren();
    port.postMessage(frameMessage.failed('The document could not be displayed.'));
  }
}

/**
 * A click on a link inside a rendered document, delegated from the root.
 *
 * The frame opens NOTHING itself — `allow-popups` and `allow-top-navigation` are
 * both withheld, so it could not — and instead reports the href as a capability
 * request. The host validates the scheme at the message boundary and asks the
 * user before opening anything. Reported rather than silently dropped, because a
 * link in a README that does nothing at all reads as a broken viewer.
 */
function onRootClick(event: MouseEvent): void {
  const target = event.target;
  if (!(target instanceof Element)) return;
  const anchor = target.closest('a[href]');
  if (!anchor) return;
  event.preventDefault();
  const href = anchor.getAttribute('href');
  if (href === null || href === '') return;
  channel?.postMessage(frameMessage.link(href));
}

/**
 * Boot the frame side: listen for the port, then announce readiness.
 *
 * Exported so it can be driven directly in jsdom, and CALLED at module scope
 * because that is what an entry point does. The listener is registered BEFORE
 * `ready` is posted: the host transfers the port synchronously from its own
 * handler, and a listener registered afterwards would be a race this document
 * loses on a fast machine and wins on a slow one.
 *
 * The window listener is removed the moment a port arrives — the mirror of the
 * host's one-shot rule, and for a related reason: with the listener gone, a
 * second attempt to hand this document a channel reaches nobody, so there is
 * exactly one channel per document and no way to acquire another.
 */
export function startSandbox(win: Window): void {
  const doc = win.document;

  const onWindowMessage = (event: MessageEvent): void => {
    const port = event.ports[0];
    // The handshake reply is IDENTIFIED BY ITS PORT, not by its payload: a
    // transferred port is a capability the embedder alone can create, whereas
    // a payload is something any framing document could imitate.
    if (!port) return;
    win.removeEventListener('message', onWindowMessage);
    channel = port;
    port.addEventListener('message', (message: MessageEvent) => {
      renderRequest(doc, port, message.data);
    });
    port.start();
  };

  win.addEventListener('message', onWindowMessage);
  renderTarget(doc).addEventListener('click', onRootClick);
  // `targetOrigin: '*'` is forced rather than chosen: an opaque origin cannot
  // name its embedder, and the embedder cannot be named by this document
  // either. It is safe HERE because the payload is a constant with no secret in
  // it — which is also why the plaintext never travels on the window.
  win.parent.postMessage({ kind: 'ready' }, '*');
}

/** The transferred port. Exported for the isolation suite. */
export function sandboxChannel(): MessagePort | null {
  return channel;
}

startSandbox(window);
