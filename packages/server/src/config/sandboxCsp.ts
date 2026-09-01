import path from 'node:path';

/**
 * The Content-Security-Policy carried by `/sandbox.html`, the isolated document
 * every stored file is rendered inside.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS A POLICY OF ITS OWN, AND WHY IT LIVES HERE
 * ---------------------------------------------------------------------------
 *
 * The application renders no byte of a stored document in its own origin. It
 * decrypts, verifies, and hands the plaintext to an `<iframe sandbox=
 * "allow-scripts">` — no `allow-same-origin`, so the framed document holds an
 * OPAQUE origin and fails every same-origin check against the page that holds
 * the unlocked vault key. A vulnerability in any parser that document runs (the
 * markdown pipeline, the HTML sanitizer, the highlighter) therefore lands
 * somewhere with no key, no token, no cookie and no storage.
 *
 * A document fetched from an `http(s)` URL does NOT inherit its embedder's CSP
 * — only `about:blank`, `blob:`, `data:`, `javascript:` and `srcdoc` documents
 * do. That is precisely what makes a tailored, far stricter policy possible
 * here instead of the application's own, and it is why this policy is attached
 * by the route that serves the document rather than by helmet.
 *
 * It has ONE home because it is pinned in three places that cannot import each
 * other: a unit test over this constant, `scripts/ci/smoke-gate.mjs` over the
 * header the built artifact actually sends, and the deploy drill over the
 * header that reaches a client through Nginx. A constant test alone would pass
 * while the route sent something else; a served-header test alone would leave
 * the constant free to drift. Both pin it DIRECTIVE BY DIRECTIVE rather than by
 * substring, because `connect-src 'none'` and `worker-src 'none'` are each one
 * appended word away from being widened and `toContain("connect-src 'none'")`
 * stays green through `connect-src 'none' https:`.
 *
 * ---------------------------------------------------------------------------
 * THE THREE LOAD-BEARING DIRECTIVES
 * ---------------------------------------------------------------------------
 *
 *  1. `script-src 'self'` DOES resolve inside a sandboxed document. CSP takes
 *     its `self`-origin from the RESPONSE's URL, not from the document's opaque
 *     origin, so `'self'` still names this server. Write that down, because it
 *     is the first thing a reader doubts. What blocks a module script fetched
 *     by an opaque origin is CORS, not CSP: a module script is fetched in CORS
 *     mode unconditionally, sends `Origin: null`, and needs an
 *     `Access-Control-Allow-Origin` header — which is why `sandbox-assets/` is
 *     served with one and `assets/` is not.
 *
 *  2. `connect-src 'none'` is the containment. The sandbox opens no socket of
 *     any kind: it receives bytes over a `MessagePort` and renders them. A
 *     renderer that cannot open a socket cannot exfiltrate a document to
 *     anyone, cannot reach this application's own API, and cannot burn a user's
 *     rate-limit budget into a login lockout. It is only affordable because
 *     there is no PDF renderer — pdf.js needs a worker and a WebAssembly
 *     decoder fetched by URL, and carrying it would have forced `connect-src`
 *     and `worker-src` open for every other format too.
 *
 *  3. The `sandbox allow-scripts` DIRECTIVE repeats the iframe attribute inside
 *     the policy, so the document sandboxes ITSELF even if a future embedder
 *     forgets the attribute.
 *
 * `frame-ancestors 'self'` is what permits our own framing while refusing
 * anyone else's; helmet's default `X-Frame-Options: SAMEORIGIN` agrees with it
 * on the response for the application shell and needs no change.
 */

/**
 * The policy, as data: directive name to its source list, in the order the
 * header serializes them.
 *
 * A record rather than a string, because that is what makes the pins
 * directive-by-directive on both sides — the unit test compares this object
 * WHOLE (so an added directive fails as loudly as a widened one), and the smoke
 * gate parses the served header back into the same shape before comparing.
 *
 * `sandbox` carries a single token that is not a source expression, which is
 * why the values are plain strings rather than a source-list type.
 */
export const SANDBOX_CSP_DIRECTIVES = Object.freeze({
  'default-src': ["'none'"],
  'script-src': ["'self'"],
  'style-src': ["'self'"],
  // `blob:` for media the sandbox mints itself from bytes it was handed;
  // `data:` for inline images in a rendered markdown or HTML document. There is
  // deliberately NO http/https source: that is what stops a markdown file
  // reaching out for a remote `<img>`, which is shown to the user as a
  // disabled-remote-content notice rather than repaired by widening this.
  'img-src': ["'self'", 'blob:', 'data:'],
  'font-src': ["'self'", 'data:'],
  // Audio and video play from a blob URL the sandbox mints itself. A blob URL
  // minted by the application would not resolve in an opaque origin.
  'media-src': ['blob:'],
  'connect-src': ["'none'"],
  'worker-src': ["'none'"],
  'frame-src': ["'none'"],
  'child-src': ["'none'"],
  'object-src': ["'none'"],
  'base-uri': ["'none'"],
  'form-action': ["'none'"],
  'frame-ancestors': ["'self'"],
  sandbox: ['allow-scripts'],
} as const);

/**
 * The header value, derived from {@link SANDBOX_CSP_DIRECTIVES} so the two can
 * never disagree.
 *
 * Serialized once at module load: the policy is per-response but identical for
 * every response, and nothing in it is request-dependent (there is no nonce —
 * the sandbox document carries no inline script, and `script-src 'self'` is
 * what admits its bundle).
 */
export const SANDBOX_CSP_HEADER: string = Object.entries(SANDBOX_CSP_DIRECTIVES)
  .map(([directive, sources]) => `${directive} ${sources.join(' ')}`)
  .join('; ');

/**
 * How long a client may hold the sandbox document.
 *
 * `no-cache` means "revalidate", not "never store": the document names
 * content-hashed `/sandbox-assets/` URLs that change on every deploy, so a
 * held copy is a frame that requests assets which no longer exist. Exactly the
 * reasoning `/sw.js` already carries, and named rather than inlined so the
 * smoke gate can pin the served value against this one number.
 */
export const SANDBOX_DOCUMENT_CACHE_CONTROL = 'no-cache';

/**
 * The two headers `sandbox-assets/` must carry, and `assets/` must not.
 *
 * A module script is fetched in CORS mode UNCONDITIONALLY, and Vite emits
 * `<script type="module" crossorigin>` for every HTML entry. From the sandbox's
 * opaque origin that request carries `Origin: null`, which matches no allowlist,
 * so it needs `Access-Control-Allow-Origin: *` or the fetch is a network error
 * and the frame is silently blank. Separately, helmet's default
 * `Cross-Origin-Resource-Policy: same-origin` blocks the no-cors subresources
 * (the stylesheet) wherever Express serves them — which is the path a pm2
 * deployment and the smoke gate use.
 *
 * Scoped to that ONE directory. These are public build artefacts with no secret
 * in them, and any page could already execute them with a `<script>` tag; what
 * changes is only that an opaque origin may now READ them, which is what its own
 * document needs. Widening `/assets/` to match would hand every sandboxed
 * document on the internet read access to the application's own bundle, and is
 * the "obvious fix" a blank frame invites.
 */
export const SANDBOX_ASSET_HEADERS = Object.freeze({
  'Access-Control-Allow-Origin': '*',
  'Cross-Origin-Resource-Policy': 'cross-origin',
} as const);

/** Anything that can take a response header — a real `res`, or a test double. */
interface HeaderSink {
  setHeader(name: string, value: string): unknown;
}

/** A response that can also send a body; the sandbox route needs nothing more. */
interface DocumentResponse extends HeaderSink {
  send(body: string): unknown;
}

/**
 * Does this on-disk path lie inside the sandbox's asset directory?
 *
 * Separator-delimited on BOTH sides, which is what keeps it from firing on a
 * sibling directory called `sandbox-assets-old` or on a FILE named
 * `sandbox-assets`. `path.sep` rather than `/`, because `send` builds the path
 * it hands to `setHeaders` with `path.join`, so on Windows it arrives with
 * backslashes.
 */
export function isSandboxAssetPath(filePath: string): boolean {
  return filePath.includes(`${path.sep}sandbox-assets${path.sep}`);
}

/**
 * `express.static`'s `setHeaders` hook: add {@link SANDBOX_ASSET_HEADERS} to a
 * sandbox asset and touch nothing else.
 *
 * Extracted from `app.ts` rather than written inline there because the
 * production static mount is unreachable under test — `app.ts` is imported with
 * `NODE_ENV=test` and cannot be imported any other way (the production block
 * reads a client build that does not exist in a checkout). Inline, this
 * predicate and its two `setHeader` calls would be permanently uncovered
 * production code AND would have no fast-tier pin at all; here, both halves are
 * asserted directly.
 */
export function applySandboxAssetHeaders(res: HeaderSink, filePath: string): void {
  if (!isSandboxAssetPath(filePath)) return;
  for (const [name, value] of Object.entries(SANDBOX_ASSET_HEADERS)) {
    res.setHeader(name, value);
  }
}

/**
 * The handler that serves the isolated document, built once over the HTML read
 * at startup.
 *
 * `setHeader` REPLACES rather than appends, which is what makes exactly one
 * `Content-Security-Policy` reach the client even though helmet already set the
 * application's. That matters: two policies on one response are INTERSECTED by
 * the browser, which would kill `blob:` media and `data:` images in one stroke.
 *
 * No nonce is injected, unlike the SPA shell. The document carries no inline
 * script — its bundle is a `<script type="module" crossorigin
 * src="/sandbox-assets/…">`, admitted by `script-src 'self'` — and a per-request
 * value has no business in a response the client is told it may revalidate.
 */
export function createSandboxDocumentHandler(
  html: string,
): (req: unknown, res: DocumentResponse) => void {
  return (_req, res) => {
    res.setHeader('Content-Security-Policy', SANDBOX_CSP_HEADER);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', SANDBOX_DOCUMENT_CACHE_CONTROL);
    res.send(html);
  };
}
