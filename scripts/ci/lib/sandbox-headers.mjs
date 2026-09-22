/**
 * The isolated render document's serving contract, as a gate script sees it.
 *
 * `packages/server/src/config/sandboxCsp.ts` is the single HOME of this policy and
 * of the two headers `sandbox-assets/` carries. This file is the gate-side
 * RESTATEMENT of it, and it exists because a gate runner is plain JavaScript with
 * no build step in front of it and cannot import a TypeScript module.
 *
 * The restatement is therefore structural rather than a choice — but a second copy
 * that nothing compares is a second copy that drifts, so it is pinned from the
 * other end: `packages/server/tests/clean-room.test.ts` imports BOTH this module
 * and `SANDBOX_CSP_DIRECTIVES` and asserts they describe the same policy. That is
 * what makes "the drill and the constant cannot drift apart" a check rather than a
 * hope, and it runs on the push tier rather than only when someone stands six
 * containers up.
 *
 * Two gates read it, and neither may keep its own copy:
 *
 *   * `test:smoke` boots the BUILT artifact in production mode and reads the
 *     header Express itself sends;
 *   * `test:deploy` reads the header that reaches a client through the real Nginx,
 *     which is the only place the `web-root` stage's deletion of `sandbox.html`
 *     is actually proven — with the file left on the Nginx document root,
 *     `try_files` would answer from disk with the doc-root's `default-src 'self'`
 *     and none of the sandbox's own directives.
 *
 * Every failure mode here is SILENT in a browser: a blank rectangle, or a viewer
 * that ships unstyled, with no console error worth reporting.
 */

/**
 * The policy, directive to its source list as one normalised string.
 *
 * Compared DIRECTIVE BY DIRECTIVE and in BOTH directions, never by substring.
 * `connect-src 'none'` and `worker-src 'none'` are the containment, and the bound
 * they buy is worth stating exactly rather than as a slogan: nothing the isolated
 * document runs can READ a response (no `fetch`, `XMLHttpRequest`, WebSocket,
 * `EventSource` or `sendBeacon`), and no directive here names an external host, so
 * nothing it emits reaches a third party. It is NOT "opens no socket of any kind"
 * — `script-src`, `style-src`, `img-src` and `font-src` all allow `'self'`, which
 * a sandboxed document resolves from the response URL, so an `<img src="/api/v1/…">`
 * is a GET this server would see. `packages/server/src/config/sandboxCsp.ts` names
 * that wording as the one not to write. Each of the two is one appended word away
 * from being widened, which a `.includes("connect-src 'none'")` check stays green
 * through.
 * An ADDED directive matters as much as a widened one, which is why
 * {@link cspProblems} sweeps the served header's own keys as well.
 */
export const SANDBOX_CSP_EXPECTED = Object.freeze({
  'default-src': "'none'",
  'script-src': "'self'",
  'style-src': "'self'",
  'img-src': "'self' blob: data:",
  'font-src': "'self' data:",
  'media-src': 'blob:',
  'connect-src': "'none'",
  'worker-src': "'none'",
  'frame-src': "'none'",
  'child-src': "'none'",
  'object-src': "'none'",
  'base-uri': "'none'",
  'form-action': "'none'",
  'frame-ancestors': "'self'",
  sandbox: 'allow-scripts',
});

/**
 * `Cache-Control` on the document itself.
 *
 * `no-cache` means "revalidate", not "never store": the document names
 * content-hashed `/sandbox-assets/` URLs that change on every deploy, so a held
 * copy is a frame asking for assets that no longer exist — a dead viewer for
 * every returning user, one deploy late. It is also the second half of the
 * off-the-disk check: Nginx's `location /` sends
 * `public, max-age=0, must-revalidate`.
 */
export const SANDBOX_DOCUMENT_CACHE_CONTROL = 'no-cache';

/**
 * The two headers every file under `sandbox-assets/` must carry, keyed by the
 * lower-cased header name `Headers.get` takes.
 *
 * A module script is fetched in CORS mode UNCONDITIONALLY, and Vite emits
 * `<script type="module" crossorigin>` for every HTML entry, so from the frame's
 * opaque origin the request carries `Origin: null`, matches no allowlist, and
 * needs `Access-Control-Allow-Origin: *` or the fetch is a network error.
 * Separately, the stylesheet is a no-cors subresource, which
 * `Cross-Origin-Resource-Policy` governs — and an opaque origin is cross-origin
 * to everything, including us.
 */
export const SANDBOX_ASSET_HEADERS_EXPECTED = Object.freeze({
  'access-control-allow-origin': '*',
  'cross-origin-resource-policy': 'cross-origin',
});

/** `"a 'b'; c 'd'"` -> `{ a: "'b'", c: "'d'" }`, whitespace normalised. */
export function parseCsp(header) {
  const directives = {};
  for (const part of String(header ?? '').split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    const [name, ...sources] = tokens;
    if (name) directives[name.toLowerCase()] = sources.join(' ');
  }
  return directives;
}

/**
 * Everything wrong with the `Content-Security-Policy` a client received for
 * `/sandbox.html`, as a list of sentences. Empty means the policy is exactly the
 * one above.
 *
 * The comma test is not pedantry. `Headers.get` joins REPEATED headers with
 * `", "`, and a CSP source list never contains a comma, so its presence means two
 * policies reached the client — which a browser INTERSECTS, killing `blob:` media
 * and `data:` images in one stroke. It is also what catches helmet's application
 * policy surviving beside the sandbox's own.
 *
 * @param {string | null | undefined} raw the value of the header, as received
 * @returns {string[]}
 */
export function cspProblems(raw) {
  const header = String(raw ?? '');
  if (header.trim().length === 0) {
    return ['no Content-Security-Policy header reached the client'];
  }
  const problems = [];
  if (header.includes(',')) {
    problems.push(
      'two Content-Security-Policy headers reached the client (a browser INTERSECTS them, ' +
        `which would kill blob: media and data: images): ${header}`,
    );
  }
  const served = parseCsp(header);
  for (const [directive, sources] of Object.entries(SANDBOX_CSP_EXPECTED)) {
    if (served[directive] !== sources) {
      problems.push(
        `${directive}: expected "${sources}", got "${served[directive] ?? '(absent)'}"`,
      );
    }
  }
  for (const directive of Object.keys(served)) {
    if (!(directive in SANDBOX_CSP_EXPECTED)) {
      problems.push(`unexpected directive ${directive} in the served policy`);
    }
  }
  return problems;
}

/**
 * Everything wrong with the RESPONSE that answered an asset probe, judged BEFORE
 * a single header is compared.
 *
 * Every header check below is a claim about a named file, and each one is
 * satisfiable by a response that is not that file at all — which makes this the
 * half that can pass on nothing. Both gates need it, for two different reasons,
 * and neither reason is hypothetical:
 *
 *   * Under EXPRESS (`test:smoke`) a missing asset is not a 404. `express.static`
 *     falls through, and `app.ts`'s SPA catch-all — every path that does not
 *     begin `/api/` — answers `/assets/main-abc.js` with 200 and index.html,
 *     carrying exactly the CORS origin and the same-origin CORP that
 *     {@link appAssetProblems} expects. A status check alone therefore closes
 *     nothing there; the CONTENT TYPE is the only thing that tells the bundle
 *     from the shell.
 *   * Under NGINX (`test:deploy`) `/assets/` is served from disk, so a missing
 *     file can be a real 404 — and a 404 carries neither header, which is a clean
 *     pass for the same negative. There the STATUS is what tells them apart.
 *
 * So both are asserted, for both gates, in one place. A non-200 is reported alone
 * rather than beside a content-type complaint, because "it answered 404" already
 * says everything there is to say about the body.
 *
 * @param {string} label the URL, so a failure names which asset was not served
 * @param {{ status: number, headers: { get: (name: string) => string | null } }} res
 * @returns {string[]}
 */
export function assetResponseProblems(label, res) {
  if (res.status !== 200) {
    return [`${label} answered ${String(res.status)}, not 200`];
  }
  const type = (res.headers.get('content-type') ?? '').toLowerCase();
  if (type.startsWith('text/html')) {
    return [
      `${label} answered 200 with an HTML document (content-type "${type}") rather than the ` +
        'asset — a path with no file behind it is answered by the SPA fallback, whose headers ' +
        "are the application's own and satisfy every header check on this response",
    ];
  }
  return [];
}

/**
 * Everything wrong with the CORS and CORP headers on one file under
 * `sandbox-assets/`.
 *
 * `label` names the URL, because the interesting failure is one asset carrying
 * them and another not: `build.assetsDir` routes the entry script, the chunks AND
 * the stylesheet through the same setting today, so they cannot diverge — but a
 * later switch to explicit `entryFileNames`/`chunkFileNames` that forgets
 * `assetFileNames` would leave the stylesheet in `/assets/` and ship the viewer
 * unstyled while every script-only assertion still passed.
 *
 * @param {string} label
 * @param {(name: string) => string | null} get
 * @returns {string[]}
 */
export function sandboxAssetProblems(label, get) {
  const problems = [];
  for (const [name, expected] of Object.entries(SANDBOX_ASSET_HEADERS_EXPECTED)) {
    const actual = get(name);
    if (actual !== expected) {
      problems.push(`${label} ${name}=${String(actual)}, expected ${expected}`);
    }
  }
  return problems;
}

/**
 * Everything wrong with the same two headers on one file under `assets/`, where
 * the widening must NOT have reached.
 *
 * Phrased as the exact values the application's own bundle carries rather than as
 * their ABSENCE, and the difference is measured rather than stylistic: every
 * Express response already carries both header NAMES, because the `cors`
 * middleware is configured with a fixed string origin and emits
 * `Access-Control-Allow-Origin: <CORS_ORIGIN>` unconditionally, and helmet's
 * default emits `Cross-Origin-Resource-Policy: same-origin`. A "must not be
 * present" assertion is therefore false on a correct build, and the tempting way
 * to make it pass is to delete the negative — which is the whole check.
 *
 * Nginx serves `/assets/` from its own document root, so under the deploy drill
 * the values come from that block rather than from Express; both spellings are
 * the caller's to declare, which is why `expected` is a parameter.
 *
 * @param {string} label
 * @param {(name: string) => string | null} get
 * @param {{ acao: string | null, corp: string | null }} expected
 * @returns {string[]}
 */
export function appAssetProblems(label, get, expected) {
  const problems = [];
  const acao = get('access-control-allow-origin');
  const corp = get('cross-origin-resource-policy');
  if (acao !== expected.acao) {
    problems.push(
      `${label} Access-Control-Allow-Origin=${String(acao)}, expected ${String(expected.acao)} — ` +
        'the sandbox widening must stay inside sandbox-assets/',
    );
  }
  if (corp !== expected.corp) {
    problems.push(
      `${label} Cross-Origin-Resource-Policy=${String(corp)}, expected ${String(expected.corp)} — ` +
        'the sandbox widening must stay inside sandbox-assets/',
    );
  }
  return problems;
}

/**
 * The module script and the stylesheet `/sandbox.html` names, out of the document
 * itself rather than from a guessed filename.
 *
 * Both are content-hashed, so there is nothing to hard-code; and both must be
 * probed, which is the assertion the `assetsDir` comment in
 * `packages/client/vite.config.sandbox.ts` asks for by name.
 *
 * @param {string} html
 * @returns {{ script: string | null, stylesheet: string | null }}
 */
export function sandboxAssetUrls(html) {
  const source = String(html ?? '');
  return {
    script: /<script[^>]+src="(\/sandbox-assets\/[^"]+\.js)"/.exec(source)?.[1] ?? null,
    stylesheet: /<link[^>]+href="(\/sandbox-assets\/[^"]+\.css)"/.exec(source)?.[1] ?? null,
  };
}

/**
 * The four URL spellings that reach the isolated render document past the
 * Express route registered to claim it.
 *
 * Express 5 matches the RAW, undecoded pathname; `send` (inside
 * `express.static`) decodes and normalises before touching the filesystem. So
 * while `sandbox.html` sat in the static root, each of these was answered off
 * disk carrying helmet's APPLICATION policy — `connect-src 'self'`, a nonce'd
 * script, `frame-src 'self'` — instead of the sandbox's own, which is the whole
 * containment. Every renderer kept working; only the isolation stopped
 * existing. The fix is the LAYOUT (the document is emitted outside every static
 * root), so these probes are what proves the layout, not a filter.
 *
 * `/./sandbox.html` and `/foo/../sandbox.html` are deliberately absent: Express
 * normalises dot segments before matching, so both reach the route and carry the
 * full policy. Measured, both directions.
 *
 * Kept here rather than in either gate because BOTH must ask, and for different
 * reasons: `test:smoke` asks Express directly, `test:deploy` asks through Nginx,
 * whose `try_files $uri @app` normalises `$uri` before the proxy hop — so the
 * pair also answers whether the raw or the normalised URI reaches the app.
 */
export const SANDBOX_BYPASS_SPELLINGS = Object.freeze([
  '/sandbox%2Ehtml',
  '//sandbox.html',
  '/sandbox.htm%6C',
  '/%73andbox.html',
  // The fifth is not one of the four measured spellings; it is here because the
  // FIX introduced the dependency it probes. The document now sits exactly one
  // `..` outside the static root, so containment also leans on `send`'s
  // traversal guard — it decodes the path first, then refuses any `..` segment
  // with a 403, with or without a `root`. That is a library property this
  // repository does not own, so it is asserted rather than assumed. The 403 is
  // not what a client sees: `serve-static` runs with `fallthrough` on and turns
  // any sub-500 stream error into a bare `next()`, so the SPA catch-all answers
  // it 200 with the shell. The judgement below is on the BODY for exactly this
  // reason — a status check would have to encode which of the two layers
  // answered, and neither answer is wrong.
  '/..%2fsandbox-document%2fsandbox.html',
]);

/**
 * Join a bypass spelling onto a base URL WITHOUT letting the URL parser repair
 * it.
 *
 * `new URL('//sandbox.html', 'http://127.0.0.1:5000')` is a protocol-relative
 * reference and resolves to `http://sandbox.html/` — a different host, silently.
 * The percent-encoded spellings survive `new URL` intact, but they are built the
 * same way so no reader has to remember which of the four is the dangerous one.
 *
 * @param {string} baseUrl origin, with no trailing slash
 * @param {string} spelling one of {@link SANDBOX_BYPASS_SPELLINGS}
 * @returns {string}
 */
export function bypassUrl(baseUrl, spelling) {
  return `${String(baseUrl).replace(/\/+$/, '')}${spelling}`;
}

/**
 * Everything wrong with the answer to one bypass spelling.
 *
 * The judgement is stated the way the defect broke it, not as a fixed status:
 * whatever answers, EITHER it is not the isolated document, OR it carries that
 * document's complete policy. A 404 passes. The SPA shell passes — it is what
 * every other unknown path gets, and it carries helmet's policy honestly. The
 * document under helmet's policy is the only thing that fails.
 *
 * The document is recognised by the `sandbox-assets/` module script it names,
 * which is the same marker `test:deploy` already uses to tell it from the shell.
 * A body check rather than a status check, because under Express a miss is not a
 * 404 at all: the SPA catch-all answers every non-`/api/` path with 200.
 *
 * @param {string} spelling the spelling probed, so a failure names it
 * @param {{ headers: { get: (name: string) => string | null } }} res
 * @param {string} body the response body, already read
 * @returns {string[]}
 */
export function sandboxBypassProblems(spelling, res, body) {
  if (!/<script[^>]+src="\/sandbox-assets\//.test(String(body ?? ''))) return [];
  const diff = cspProblems(res.headers.get('content-security-policy'));
  if (diff.length === 0) return [];
  return [
    `${spelling} served the isolated render document WITHOUT its own policy ` +
      `(${diff.join('; ')}) — the containment is the policy, so this spelling is the ` +
      'isolation not existing',
  ];
}
