import type { SandboxRenderRequest } from '@hvault/shared';
import {
  frameMessage,
  parseQrScanRequest,
  parseRenderRequest,
  parseTransformRequest,
} from './protocol';
import { previewRefusal } from './sniff';
import './sandbox.css';

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
 * URL never inherits one — carries `connect-src 'none'`, so nothing running here
 * can READ a response, and names no external host, so nothing it emits leaves
 * this server.
 *
 * So a vulnerability in any parser this document runs lands somewhere holding no
 * key, no token, no cookie and no storage, that can reach no host but this one
 * and read no answer back from it. (Not "no socket at all": `script-src`,
 * `style-src`, `img-src` and `font-src` allow `'self'`, which a sandboxed
 * document resolves from the response URL — see the same-origin note in
 * `packages/server/src/config/sandboxCsp.ts`.) That is the whole point of the
 * isolation, and it is why every renderer lives here rather than in the page
 * that holds the unlocked vault.
 *
 * It does TWO jobs, for that one reason. It RENDERS a stored document, and it
 * FORMATS or REPAIRS one on its way IN, before a byte of it is encrypted. The
 * second could have been a Web Worker and must not be: a worker is same-origin,
 * so a bug in Prettier or in the JSON repairer running inside one could `fetch`
 * this application's own API with the httpOnly refresh cookie attached and read
 * an access token out of the response. A worker has no DOM, but it has the
 * origin, and the origin is what a token is bound to.
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
 * Which of the document's three jobs a port message is asking for.
 *
 * A one-field peek, deliberately: the full validation belongs to the parser for
 * whichever kind this names, and a message whose `kind` is none of them takes
 * the render path and is refused there. That keeps ONE place where an
 * unparseable message is answered, rather than three that could drift.
 */
function requestKind(data: unknown): 'transform' | 'qrScan' | 'render' {
  if (typeof data !== 'object' || data === null) return 'render';
  const kind = (data as { kind?: unknown }).kind;
  if (kind === 'transform') return 'transform';
  if (kind === 'qrScan') return 'qrScan';
  return 'render';
}

/**
 * Find a QR code in one image and answer on the port.
 *
 * The decoder is imported ON DEMAND, so a document opened for a preview never
 * downloads it, and it is the import boundary that gives the decoder its own
 * chunk. Everything is answered on the port, including failure, because the
 * host arms a deadline per request and a silent path would hold it open.
 */
async function qrScanRequest(port: MessagePort, data: unknown): Promise<void> {
  const request = parseQrScanRequest(data);
  if (!request) {
    // BOTH failures here stay `failed` rather than `qrFailed`, and both are
    // meant to end the session. A request this frame cannot parse names no
    // `requestId` to answer with, and a decoder chunk that will not load will
    // not load for the next image either — so there is nothing for the host to
    // retry, and pretending otherwise would leave a camera running against a
    // frame that can never answer. Everything that IS about one image is
    // answered by `scanImage` with a `qrFailed` that says which.
    port.postMessage(frameMessage.failed('The scan request was not understood.'));
    return;
  }
  try {
    const { scanImage } = await import('./qrScan');
    port.postMessage(
      await scanImage(request.requestId, request.image, QR_EFFORT, QR_TIME_LIMIT_MS),
    );
  } catch {
    port.postMessage(frameMessage.failed('The scanner could not be loaded.'));
  }
}

/**
 * How hard the decoder tries, per image.
 *
 * Tuned for a live camera rather than a photograph: a frame that does not read
 * quickly is better dropped for the next one, since the next one is about 120 ms
 * away and is very likely better aimed. The host escalates by sending the same
 * frame again only when it has been missing for a while.
 */
const QR_EFFORT = 2;
const QR_TIME_LIMIT_MS = 120;

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
 * Load the renderer for one mode and build its DOM.
 *
 * Every branch is a DYNAMIC import, and that is a build instruction as much as a
 * runtime one: Rollup emits a separate chunk at a dynamic-import boundary and
 * nowhere else, so a static import here would put the markdown pipeline and the
 * syntax highlighter into the chunk that a plain `.txt` preview downloads. The
 * per-chunk ceilings in `scripts/ci/lib/bundle-budgets.mjs` are keyed to the
 * split this switch produces.
 *
 * `text` and `code` share a renderer because the difference between them is
 * which extensions each carries, not how a file is put on screen.
 *
 * The `default` branch answers `none` — the modes this project has DECIDED not
 * to render, PDF among them — and any mode string the host might send that this
 * document does not know. Both deserve the same answer, which is why the frame
 * never needs the list of valid modes at runtime.
 */
async function renderFor(doc: Document, request: SandboxRenderRequest): Promise<Node | null> {
  switch (request.mode) {
    case 'text':
    case 'code': {
      const { renderText } = await import('./renderers/text');
      return renderText(doc, request.bytes, request.ext);
    }
    case 'markdown': {
      const { renderMarkdown } = await import('./renderers/markdown');
      return renderMarkdown(doc, request.bytes);
    }
    case 'html': {
      const { renderHtml } = await import('./renderers/html');
      return renderHtml(doc, request.bytes);
    }
    case 'image': {
      const { renderImage } = await import('./renderers/image');
      return renderImage(doc, request.bytes, request.ext);
    }
    case 'media': {
      const { renderMedia } = await import('./renderers/media');
      return renderMedia(doc, request.bytes, request.ext);
    }
    default:
      return null;
  }
}

/**
 * Render one request, or say why it could not be rendered.
 *
 * Every branch answers on the port. Silence is the one thing this must never
 * do: the host times out on a frame that never speaks, and degrades to
 * "download to view", so a swallowed error costs the user a working preview and
 * tells nobody why.
 */
async function renderRequest(doc: Document, port: MessagePort, data: unknown): Promise<void> {
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
    // BEFORE a renderer is chosen, so a file whose bytes disagree with its name
    // never reaches a parser that was picked on the strength of that name.
    const refusal = previewRefusal(request.mode, request.ext, request.bytes);
    if (refusal !== null) {
      target.replaceChildren();
      port.postMessage(frameMessage.failed(refusal));
      return;
    }
    const rendered = await renderFor(doc, request);
    if (rendered === null) {
      target.replaceChildren();
      port.postMessage(frameMessage.failed('No renderer for this document type.'));
      return;
    }
    target.replaceChildren(rendered);
    port.postMessage(frameMessage.rendered());
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
 * Run the format-and-repair engine over one document, and answer on the port.
 *
 * The SECOND job this document does, and it renders NOTHING: the frame that
 * carries a transform is hidden, has no theme to apply and no target to fill, so
 * this path deliberately touches neither `dataset.theme` nor the render target.
 * Touching either would be harmless today and would be the first step towards a
 * transform that draws something a user might read and act on.
 *
 * The engine's chunk is loaded on demand, like every renderer, and for the same
 * reason: Prettier and the JSON repairer are around a megabyte between them, and
 * nobody previewing a `.png` should download either.
 *
 * Every branch answers on the port, including the one where the request did not
 * parse. Silence is the one thing this must never do — the host's own deadline
 * is the only other outcome, and a swallowed error costs the user a transform
 * and tells nobody why.
 */
async function transformRequest(port: MessagePort, data: unknown): Promise<void> {
  const request = parseTransformRequest(data);
  if (!request) {
    port.postMessage(frameMessage.failed('The transform request was not understood.'));
    return;
  }
  try {
    const { runTransform } = await import('./transform/formatEngine');
    port.postMessage(await runTransform(request));
  } catch {
    // A formatter that threw something the engine could not classify — a chunk
    // that failed to load, an out-of-memory on a pathological document. The
    // message carries NO detail from the error, exactly as the render path's
    // does: it would be built from the document's own bytes.
    port.postMessage(
      frameMessage.transformFailed({
        stage: 'format',
        message: 'The document could not be formatted.',
        line: null,
        column: null,
        excerpt: '',
      }),
    );
  }
}

/**
 * Is this an ABSOLUTE URL — the only kind the host is ever asked to open?
 *
 * `new URL(href)` with no base throws for anything relative, which is exactly
 * the question being asked and is why there is no regular expression here.
 */
function isAbsoluteUrl(href: string): boolean {
  try {
    new URL(href);
    return true;
  } catch {
    return false;
  }
}

/**
 * Scroll to a same-document target, resolving the id the SANITIZER wrote.
 *
 * `hast-util-sanitize`'s default schema clobbers every `id` and `name` with the
 * prefix `user-content-`, and it does NOT rewrite the hrefs that point at them.
 * So a heading anchor written `#intro` has to be looked up as
 * `user-content-intro`, and a GFM footnote reference is prefixed TWICE — once by
 * `remark-rehype`, which already emits `user-content-fn-1`, and once by the
 * sanitizer, which makes the element's id `user-content-user-content-fn-1` while
 * the link still says `#user-content-fn-1`. Trying the literal id first and the
 * prefixed one second resolves both without either being a special case.
 *
 * A fragment that resolves to nothing scrolls nowhere and is not reported. That
 * is the honest outcome for a link into a document that has no such anchor.
 *
 * The decode is GUARDED because the fragment is a stored document's bytes.
 * `decodeURIComponent` throws `URIError` on a malformed escape, and `<a
 * href="#%">` is a perfectly ordinary href to write — so an unguarded decode
 * threw out of a DELEGATED click handler. The listener survives that (a throwing
 * listener is reported, not removed), so the cost is narrower than "links stop
 * working" and worse than it sounds: the rest of THAT dispatch is abandoned, the
 * click does nothing, and the report goes to a document with no error surface,
 * so the frame's own program never learns it happened and the reader is given no
 * reason. Falling back to the RAW fragment rather than returning early is what
 * keeps an id that genuinely contains a stray `%` resolvable; a fragment that
 * names nothing then does nothing, which is the same outcome this function
 * already gives every anchor it cannot find.
 */
function decodeFragment(fragment: string): string {
  try {
    return decodeURIComponent(fragment);
  } catch {
    return fragment;
  }
}

function scrollToFragment(doc: Document, fragment: string): void {
  const id = decodeFragment(fragment);
  const target = doc.getElementById(id) ?? doc.getElementById(`user-content-${id}`);
  target?.scrollIntoView();
}

/**
 * A click on a link inside a rendered document, delegated from the root.
 *
 * Three outcomes, and the split matters.
 *
 * A SAME-DOCUMENT FRAGMENT — a heading anchor, a table-of-contents entry, a GFM
 * footnote — is handled entirely in here. Posting it to the host would be worse
 * than useless: the host validates with `isSafeUrl`, which admits http, https
 * and mailto only, so every fragment would be silently dropped and heading and
 * footnote navigation would simply stop working with nothing to explain it.
 *
 * An ABSOLUTE URL is reported as a capability request. The frame opens NOTHING
 * itself — `allow-popups` and `allow-top-navigation` are both withheld, so it
 * could not — and the host validates the scheme at the message boundary and asks
 * the user before opening anything. Reported rather than silently dropped,
 * because a link in a README that does nothing at all reads as a broken viewer.
 *
 * Anything else — a relative path — resolves to nothing meaningful for a file
 * that was stored on its own, and is dropped. `preventDefault` runs first in
 * every case, so no branch can leave the frame following a link.
 */
function onRootClick(event: MouseEvent): void {
  const target = event.target;
  if (!(target instanceof Element)) return;
  const anchor = target.closest('a[href]');
  if (!anchor) return;
  event.preventDefault();
  const href = anchor.getAttribute('href');
  if (href === null || href === '') return;
  if (href.startsWith('#')) {
    scrollToFragment(anchor.ownerDocument, href.slice(1));
    return;
  }
  if (!isAbsoluteUrl(href)) return;
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
      // DISPATCHED ON `kind` BEFORE either validator runs. Funnelling everything
      // through the render parser would answer a perfectly good transform
      // request with "the preview request was not understood", which is a
      // transform that fails for a reason that is not true.
      //
      // `void`, because both handlers are async only so that they can load a
      // chunk, and both resolve rather than reject on every path — every failure
      // inside them is answered ON THE PORT, which is the contract the host's
      // deadline depends on.
      const kind = requestKind(message.data);
      void (kind === 'transform'
        ? transformRequest(port, message.data)
        : kind === 'qrScan'
          ? qrScanRequest(port, message.data)
          : renderRequest(doc, port, message.data));
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
