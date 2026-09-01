/**
 * The document sandbox, from the server's side.
 *
 * This is the ORDINARY server suite on purpose, NOT `test:security`'s
 * `SECURITY_SUITE`: that gate is pinned to four files about cross-user row
 * ownership, and adding CSP assertions to it would pass mechanically while
 * quietly widening what the gate claims to cover.
 *
 * ---------------------------------------------------------------------------
 * WHAT CAN BE PINNED HERE, AND WHAT CANNOT
 * ---------------------------------------------------------------------------
 *
 * `GET /sandbox.html` is registered inside `if (config.NODE_ENV ===
 * 'production')`, and this file imports `app` under `NODE_ENV=test`. Forcing
 * production mode is not an option either: the production block reads
 * `packages/server/public/index.html`, which does not exist in a checkout, so
 * the import would throw. (`security-headers.test.ts` records the same
 * constraint for the SPA shell.)
 *
 * So the SERVED header is pinned twice, elsewhere and over the wire —
 * `scripts/ci/smoke-gate.mjs` boots the built artifact in production mode, and
 * the deploy drill reads the header that reaches a client through Nginx. What
 * is pinned HERE is the POLICY ITSELF, directive by directive, and the two
 * things about the application that make the frame possible. A constant test
 * alone would pass while the route sent something else; a served-header test
 * alone would leave the constant free to drift. Both halves are needed and
 * neither substitutes for the other.
 */
import { describe, it, expect } from 'vitest';
import request from 'supertest';
import path from 'node:path';
import app from '../src/app.js';
import {
  SANDBOX_ASSET_HEADERS,
  SANDBOX_CSP_DIRECTIVES,
  SANDBOX_CSP_HEADER,
  SANDBOX_DOCUMENT_CACHE_CONTROL,
  applySandboxAssetHeaders,
  createSandboxDocumentHandler,
  isSandboxAssetPath,
} from '../src/config/sandboxCsp.js';

/** A response double that records what a handler did to it, and nothing else. */
function recordingResponse() {
  const headers = new Map<string, string>();
  const sent: string[] = [];
  return {
    headers,
    sent,
    setHeader(name: string, value: string) {
      headers.set(name.toLowerCase(), value);
    },
    send(body: string) {
      sent.push(body);
    },
  };
}

/** `"a 'b'; c 'd'"` -> `{ a: ["'b'"], c: ["'d'"] }`. */
function parseCsp(header: string): Record<string, string[]> {
  const directives: Record<string, string[]> = {};
  for (const part of header.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    const [name, ...sources] = tokens;
    if (name !== undefined) directives[name.toLowerCase()] = sources;
  }
  return directives;
}

describe('the document sandbox policy', () => {
  it('is exactly the fifteen directives the isolation is built from, and nothing else', () => {
    // Compared WHOLE rather than directive by directive with `toContain`, so
    // this fails in both directions: a widened source list AND an added
    // directive. `toContain("connect-src 'none'")` would stay green through
    // `connect-src 'none' https:`, which is the exact edit this guards against.
    expect(SANDBOX_CSP_DIRECTIVES).toEqual({
      'default-src': ["'none'"],
      'script-src': ["'self'"],
      'style-src': ["'self'"],
      'img-src': ["'self'", 'blob:', 'data:'],
      'font-src': ["'self'", 'data:'],
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
    });
  });

  it('denies the sandbox every network capability, which is what containment means', () => {
    // Named separately from the whole-policy comparison above because these
    // three are the reason the design is affordable at all, and because a
    // future change is likeliest to arrive here: a renderer that "just needs to
    // fetch one thing" widens `connect-src`, and a parser moved off the main
    // thread widens `worker-src`. The sandbox issues no request of any kind —
    // it receives bytes over a MessagePort and renders them — so a
    // vulnerability in any parser it runs cannot exfiltrate the document, reach
    // this application's own API, or burn a user's rate-limit budget into a
    // login lockout.
    expect(SANDBOX_CSP_DIRECTIVES['connect-src']).toEqual(["'none'"]);
    expect(SANDBOX_CSP_DIRECTIVES['worker-src']).toEqual(["'none'"]);
    // `connect-src 'none'` also blocks fetch() and XMLHttpRequest against a
    // `blob:` URL, not just against the network — a renderer must read its
    // bytes from the ArrayBuffer it was handed and mint a blob URL only to put
    // in a `src` attribute, which `img-src`/`media-src` govern instead.
    expect(SANDBOX_CSP_DIRECTIVES['img-src']).toContain('blob:');
    expect(SANDBOX_CSP_DIRECTIVES['media-src']).toContain('blob:');
    // No http/https source anywhere: a markdown file cannot pull a remote
    // image, which is intended and is surfaced to the user rather than repaired
    // by widening this.
    for (const sources of Object.values(SANDBOX_CSP_DIRECTIVES)) {
      for (const source of sources) {
        expect(source).not.toMatch(/^https?:/);
      }
    }
    // 'unsafe-inline' and 'unsafe-eval' would each undo the script isolation.
    expect(SANDBOX_CSP_HEADER).not.toContain('unsafe-inline');
    expect(SANDBOX_CSP_HEADER).not.toContain('unsafe-eval');
  });

  it('sandboxes itself through the policy, not only through the iframe attribute', () => {
    // The `sandbox` DIRECTIVE repeats the embedder's attribute inside the
    // response, so the document holds an opaque origin even if a future
    // embedder forgets `sandbox="allow-scripts"`. `allow-same-origin` must
    // never appear beside it: the pair is documented as worth nothing, because
    // a document granted both can remove its own sandbox attribute.
    expect(SANDBOX_CSP_DIRECTIVES.sandbox).toEqual(['allow-scripts']);
    expect(SANDBOX_CSP_HEADER).not.toContain('allow-same-origin');
  });

  it('serializes to a header that parses back to exactly those directives', () => {
    // The header is DERIVED from the record, so this is not a restatement: it
    // is the check that the derivation is lossless and that a browser reading
    // the string sees what the record says. A missing separator or a stray
    // comma (which would read as a SECOND policy, and two policies are
    // intersected) shows up here.
    expect(SANDBOX_CSP_HEADER).not.toContain(',');
    expect(parseCsp(SANDBOX_CSP_HEADER)).toEqual(
      Object.fromEntries(
        Object.entries(SANDBOX_CSP_DIRECTIVES).map(([name, sources]) => [name, [...sources]]),
      ),
    );
  });

  it('is strictly tighter than the application policy on every capability that matters', () => {
    // A real cross-file invariant rather than a restatement of either policy:
    // the whole point of serving this document from its own route is that it
    // does NOT inherit the embedder's CSP, so the two are free to diverge — and
    // the direction of the divergence is what the design depends on. The
    // application must run scripts with a nonce, talk to its own API, load its
    // Vault Health worker and compile WebAssembly. The sandbox may do none of
    // those. If a future edit ever relaxed the sandbox to match the app, this
    // is what would notice.
    expect(SANDBOX_CSP_DIRECTIVES['default-src']).toEqual(["'none'"]);
    expect(SANDBOX_CSP_DIRECTIVES['script-src']).not.toContain("'wasm-unsafe-eval'");
    expect(SANDBOX_CSP_DIRECTIVES['script-src']?.some((s) => s.startsWith("'nonce-"))).toBe(false);
  });
});

describe('the route that serves the sandbox document', () => {
  it('sends the document under its own policy and nothing else', () => {
    const res = recordingResponse();
    createSandboxDocumentHandler('<!doctype html><html></html>')({}, res);

    // The body is the HTML read at startup, verbatim — no nonce injection,
    // unlike the SPA shell. The document carries no inline script (its bundle
    // is a `<script type="module" crossorigin src="/sandbox-assets/…">`,
    // admitted by `script-src 'self'`), and a per-request value has no business
    // in a response the client may revalidate.
    expect(res.sent).toEqual(['<!doctype html><html></html>']);
    expect(res.sent[0]).not.toContain('nonce');

    // Exactly three headers, and the policy is THE constant rather than a copy
    // of it. This is the pin that would fail if the route were ever pointed at
    // a second, hand-written policy string.
    expect([...res.headers.keys()].sort()).toEqual([
      'cache-control',
      'content-security-policy',
      'content-type',
    ]);
    expect(res.headers.get('content-security-policy')).toBe(SANDBOX_CSP_HEADER);
    expect(res.headers.get('content-type')).toBe('text/html; charset=utf-8');
    // Revalidated, never held: the document names content-hashed
    // `/sandbox-assets/` URLs that change on every deploy, so a cached copy is a
    // frame requesting assets that no longer exist.
    expect(res.headers.get('cache-control')).toBe(SANDBOX_DOCUMENT_CACHE_CONTROL);
    expect(SANDBOX_DOCUMENT_CACHE_CONTROL).toBe('no-cache');
  });

  it('sets the header rather than adding one, so two policies cannot be intersected', () => {
    // helmet has already set the application's policy by the time this handler
    // runs. Node's `setHeader` REPLACES; an `append` would leave two policies on
    // one response, and a browser INTERSECTS those — killing `blob:` media and
    // `data:` images in one stroke while every renderer looked correct in dev.
    // Simulated by pre-seeding the sink with helmet's value and asserting one
    // entry survives with the sandbox's.
    const res = recordingResponse();
    res.setHeader('Content-Security-Policy', "default-src 'self'");
    createSandboxDocumentHandler('<html></html>')({}, res);
    expect(res.headers.get('content-security-policy')).toBe(SANDBOX_CSP_HEADER);
    expect([...res.headers.keys()].filter((k) => k === 'content-security-policy')).toHaveLength(1);
  });
});

describe('the headers an opaque origin needs from sandbox-assets/', () => {
  const under = (...segments: string[]) => path.join(path.sep, 'srv', 'hvault', ...segments);

  it('fires for anything under sandbox-assets/ and for nothing under assets/', () => {
    expect(isSandboxAssetPath(under('sandbox-assets', 'sandbox-B-ZR7ZQC.js'))).toBe(true);
    // Nested, because a future build may emit sub-directories.
    expect(isSandboxAssetPath(under('sandbox-assets', 'chunks', 'markdown-abc.js'))).toBe(true);

    // The negatives are the whole scope of the widening. The application's own
    // bundle must stay unreadable to an opaque origin: widening `/assets/` is
    // the obvious "fix" for a blank frame and would hand every sandboxed
    // document on the internet read access to it.
    expect(isSandboxAssetPath(under('assets', 'main-4aSwR9SA.js'))).toBe(false);
    expect(isSandboxAssetPath(under('index.html'))).toBe(false);
    expect(isSandboxAssetPath(under('sw.js'))).toBe(false);
    // Separator-delimited on both sides: neither a FILE with that name nor a
    // sibling directory whose name merely starts with it may match.
    expect(isSandboxAssetPath(under('sandbox-assets'))).toBe(false);
    expect(isSandboxAssetPath(under('sandbox-assets-old', 'main.js'))).toBe(false);
  });

  it('adds exactly the two CORS headers, and only to a sandbox asset', () => {
    const asset = recordingResponse();
    applySandboxAssetHeaders(asset, under('sandbox-assets', 'sandbox-B-ZR7ZQC.js'));
    expect(Object.fromEntries(asset.headers)).toEqual({
      'access-control-allow-origin': '*',
      'cross-origin-resource-policy': 'cross-origin',
    });
    expect(SANDBOX_ASSET_HEADERS).toEqual({
      'Access-Control-Allow-Origin': '*',
      'Cross-Origin-Resource-Policy': 'cross-origin',
    });

    // The negative that matters: an application asset passes through this same
    // hook on every request and must leave it untouched.
    const appAsset = recordingResponse();
    applySandboxAssetHeaders(appAsset, under('assets', 'main-4aSwR9SA.js'));
    expect([...appAsset.headers.keys()]).toEqual([]);
  });
});

describe('the application, as the sandbox document’s embedder', () => {
  it('permits framing its own document and nothing else', async () => {
    const res = await request(app).get('/api/v1/health');
    const csp = res.headers['content-security-policy'] as string;

    // `frame-src 'self'` is the ONE directive this feature opens in the app's
    // own policy. `frame-ancestors 'self'` in the sandbox's policy is the other
    // half of the same handshake, and helmet's `X-Frame-Options: SAMEORIGIN`
    // agrees with both — asserted here because an inconsistency between the two
    // framing mechanisms shows up as a blank frame, not as an error.
    expect(parseCsp(csp)['frame-src']).toEqual(["'self'"]);
    expect(SANDBOX_CSP_DIRECTIVES['frame-ancestors']).toEqual(["'self'"]);
    expect(res.headers['x-frame-options']).toMatch(/SAMEORIGIN/i);
  });

  it('does not mount the sandbox route outside production', async () => {
    // The route lives inside `if (config.NODE_ENV === 'production')` beside the
    // SPA fallback, and both are absent under test — `routeTable.ts` classifies
    // it `when: 'production'` and `route-table.test.ts` asserts that absence
    // against the real router stack. This is the same claim from the outside:
    // the URL answers nothing here, so no test in this suite can be fooled into
    // believing it exercised the production serving path.
    const res = await request(app).get('/sandbox.html');
    expect(res.status).toBe(404);
    // And it certainly does not answer with the sandbox policy.
    expect(res.headers['content-security-policy']).not.toContain('sandbox allow-scripts');
  });
});
