import { describe, it, expect, beforeEach, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import request from 'supertest';
import type { Request, Response, NextFunction } from 'express';
import { bulkReEncryptSchema, loginSchema, restoreBackupSchema } from '@hvault/shared';
import app from '../src/app.js';
import { authHeader, createTestUser, getCsrf } from './helpers.js';

/**
 * What each route's `validate` middleware was handed, recorded on the way through.
 *
 * The sanitizer's work is invisible at the controller: every body schema is a plain
 * `z.object()`, whose strip mode drops an unknown key such as `$gt` or `__proto__`
 * whether or not the sanitizer ran. So the only place its absence can be observed is
 * the input to validation, which is what this records. The wrapper calls straight
 * through, so every route under test behaves exactly as it does in production.
 */
const { validatedBodies } = vi.hoisted(() => ({
  validatedBodies: [] as { schema: unknown; body: unknown }[],
}));

vi.mock('../src/middleware/validate.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/middleware/validate.js')>();
  return {
    ...actual,
    validate: (...args: Parameters<typeof actual.validate>) => {
      const inner = actual.validate(...args);
      const [schema, location = 'body'] = args;
      return (req: Request, res: Response, next: NextFunction): void => {
        if (location === 'body') validatedBodies.push({ schema, body: req.body as unknown });
        inner(req, res, next);
      };
    },
  };
});

/**
 * Split a `Content-Security-Policy` header into `directive -> source list`.
 *
 * helmet joins directives with `;` and no surrounding space (`helmet/index.cjs`,
 * `getHeaderValue`), and a valueless directive such as
 * `upgrade-insecure-requests` is emitted as a bare name — which parses here to
 * an empty source array, deliberately distinct from an absent directive
 * (`undefined`). Order is not preserved because CSP attaches no meaning to it.
 */
function parseCspHeader(header: string): Record<string, string[]> {
  const directives: Record<string, string[]> = {};
  for (const part of header.split(';')) {
    const [name, ...sources] = part.trim().split(/\s+/).filter(Boolean);
    if (name !== undefined) directives[name.toLowerCase()] = sources;
  }
  return directives;
}

/**
 * Fetch a real app response and hand back both the raw policy and its parse.
 *
 * The status and header assertions live here so that a broken `/health` or a
 * missing CSP surfaces as its own loud failure in every caller rather than as a
 * directive quietly reading `undefined`.
 */
async function appCsp(): Promise<{ header: string; directives: Record<string, string[]> }> {
  const res = await request(app).get('/api/v1/health');
  expect(res.status).toBe(200);
  const header = res.headers['content-security-policy'] as string | undefined;
  expect(header).toBeDefined();
  return { header: header!, directives: parseCspHeader(header!) };
}

describe('Security Headers & Middleware', () => {
  // ── Helmet Security Headers ────────────────────────────────────────

  describe('Helmet security headers', () => {
    it('should set Content-Security-Policy header with nonce for scripts and unsafe-inline for styles', async () => {
      const res = await request(app).get('/api/v1/health');

      expect(res.status).toBe(200);
      const csp = res.headers['content-security-policy'];
      expect(csp).toBeDefined();
      expect(csp).toContain("default-src 'self'");
      expect(csp).toContain("object-src 'none'");
      expect(csp).toContain("frame-src 'self'");
      // Script directive should contain a nonce
      expect(csp).toMatch(/script-src[^;]*'nonce-[A-Za-z0-9+/=]+'[^;]*/);
      // Style directive should use 'unsafe-inline' instead of nonce (SPA trade-off)
      expect(csp).toMatch(/style-src[^;]*'self'[^;]*'unsafe-inline'/);
      expect(csp).not.toMatch(/style-src[^;]*'nonce-/);
    });

    it("should allow 'wasm-unsafe-eval' in script-src (for hash-wasm Argon2id) but not 'unsafe-eval'", async () => {
      const res = await request(app).get('/api/v1/health');

      expect(res.status).toBe(200);
      const csp = res.headers['content-security-policy'] as string;
      expect(csp).toBeDefined();

      // Isolate the script-src directive so assertions don't leak into other directives
      const scriptSrcMatch = csp.match(/script-src([^;]*)/);
      expect(scriptSrcMatch).not.toBeNull();
      const scriptSrc = scriptSrcMatch![1]!;

      // WASM compilation must be permitted (required by @hiprax/crypto browser Argon2id)
      expect(scriptSrc).toContain("'wasm-unsafe-eval'");
      // The broader, more dangerous 'unsafe-eval' (JS eval/new Function) must NOT be present
      expect(scriptSrc).not.toContain("'unsafe-eval'");
      // Defense-in-depth: no directive anywhere in the CSP may grant the broad 'unsafe-eval'.
      // Match it as a standalone token so the 'wasm-unsafe-eval' substring never trips this.
      expect(csp).not.toMatch(/(^|[\s;])'unsafe-eval'/);
    });

    it("restricts frame-src to 'self' (the document sandbox) and never blob:, data: or a wildcard", async () => {
      const res = await request(app).get('/api/v1/health');

      expect(res.status).toBe(200);
      const csp = res.headers['content-security-policy'] as string;
      expect(csp).toBeDefined();

      const frameSrcMatch = csp.match(/frame-src([^;]*)/);
      expect(frameSrcMatch).not.toBeNull();
      const frameSrc = frameSrcMatch![1]!;

      // The application frames exactly one document — `/sandbox.html`, which is
      // same-origin BY URL; its opaque origin comes from the iframe's `sandbox`
      // attribute, not from where it was fetched. So 'self' is the whole of it.
      expect(frameSrc.trim()).toBe("'self'");
      // The negatives are the point. `blob:` or `data:` would let an injected
      // iframe carry its own contents — and such a document DOES inherit its
      // embedder's CSP, so it would run inside this page's policy rather than
      // inside the sandbox's far stricter one. A wildcard would frame anything.
      expect(frameSrc).not.toContain('blob:');
      expect(frameSrc).not.toContain('data:');
      expect(frameSrc).not.toContain('*');
    });

    it("restricts worker-src to 'self' (Vault Health password-strength worker) and never blob:", async () => {
      const res = await request(app).get('/api/v1/health');

      expect(res.status).toBe(200);
      const csp = res.headers['content-security-policy'] as string;
      expect(csp).toBeDefined();

      const workerSrcMatch = csp.match(/worker-src([^;]*)/);
      expect(workerSrcMatch).not.toBeNull();
      const workerSrc = workerSrcMatch![1]!;
      expect(workerSrc).toContain("'self'");
      // The worker is a same-origin bundled file — a blob: worker would be an
      // XSS-amplification vector and is deliberately NOT permitted.
      expect(workerSrc).not.toContain('blob:');
    });

    // ── The five directives that come from helmet's defaults, not from app.ts ──
    //
    // `app.ts` passes `contentSecurityPolicy: { directives }` and never sets
    // `useDefaults`, which helmet defaults to `true`. Everything the app names
    // explicitly is pinned by the tests above; the five below are supplied
    // ENTIRELY by `helmet.contentSecurityPolicy.getDefaultDirectives()` and were
    // asserted by nothing on this response, so `useDefaults: false` — one word —
    // removed all five while the twenty-six tests that existed before these did
    // stayed green. These tests are the pin, and `app.ts` carries a comment
    // pointing back at them.
    //
    // Each asserts the whole parsed source list rather than a substring, so it
    // fails on removal (`undefined`), on a widening and on a swap; the second
    // assertion in each re-reads the RAW header, so a bug in `parseCspHeader`
    // cannot make the TEST pass vacuously. Those raw assertions are coupled to
    // helmet joining directives with `;` and no space: a helmet that emitted
    // `; ` would redden all five, which is the correct direction to fail.
    //
    // They run against `/api/v1/health` because that is the cheapest response
    // that carries this policy, and the SPA shell carries the same one — no
    // route sets a CSP of its own except `/sandbox.html`, and
    // `app-production-client.test.ts` asserts the shell's policy and the
    // sandbox's are different objects.

    it("pins base-uri to 'self', which comes from helmet's implicit useDefaults and not from app.ts", async () => {
      const { header, directives } = await appCsp();

      // `base-uri` has NO fallback to `default-src`, so if `useDefaults` ever
      // goes false this directive is simply gone and an injected
      // `<base href="https://attacker.example">` re-points every relative URL on
      // the page — including the ones that carry the CSRF token.
      expect(directives['base-uri']).toEqual(["'self'"]);
      expect(header).toMatch(/(^|;)base-uri 'self'(;|$)/);
    });

    it("pins form-action to 'self', which comes from helmet's implicit useDefaults and not from app.ts", async () => {
      const { header, directives } = await appCsp();

      // Also without a `default-src` fallback. Losing it lets an injected or
      // DOM-clobbered <form> POST the master-password form's fields to a
      // third-party origin, which is precisely the class of exfiltration a
      // nonce-based `script-src` does not cover — no script is involved.
      expect(directives['form-action']).toEqual(["'self'"]);
      expect(header).toMatch(/(^|;)form-action 'self'(;|$)/);
    });

    it("pins frame-ancestors to 'self', which comes from helmet's implicit useDefaults and not from app.ts", async () => {
      const { header, directives } = await appCsp();

      // The clickjacking bound, and the modern half of it: `X-Frame-Options`
      // (asserted below) is the legacy header, `frame-ancestors` is what current
      // browsers enforce, and it too has no `default-src` fallback.
      //
      // It governs who may EMBED this response. It is NOT what lets the
      // application frame its own `/sandbox.html` — that is `frame-src 'self'`
      // (asserted above) on this side, plus the sandbox response's own
      // `frame-ancestors 'self'` in `config/sandboxCsp.ts` on the other. Reading
      // the two as one directive is the mistake this note exists to prevent.
      // 'self' is helmet's untouched default and agrees with the
      // `X-Frame-Options: SAMEORIGIN` this same response carries; nothing here
      // is meant to be framed by anyone, so this value is a floor to hold.
      expect(directives['frame-ancestors']).toEqual(["'self'"]);
      expect(header).toMatch(/(^|;)frame-ancestors 'self'(;|$)/);
    });

    it("pins script-src-attr to 'none', which comes from helmet's implicit useDefaults and not from app.ts", async () => {
      const { header, directives } = await appCsp();

      // Inline event handlers (`onclick="..."`) are governed by
      // `script-src-attr`, which DOES fall back to `script-src`. Today that
      // fallback would still block them: `script-src` carries a nonce, and a
      // source list holding any nonce refuses inline behaviour of every kind
      // regardless of 'unsafe-inline'. Stating 'none' unconditionally is what
      // makes the block independent of `script-src` — the day someone drops the
      // nonce in favour of 'unsafe-inline' for a legacy widget, or adds
      // 'unsafe-hashes' with a handler hash, attribute handlers must stay dead.
      expect(directives['script-src-attr']).toEqual(["'none'"]);
      expect(header).toMatch(/(^|;)script-src-attr 'none'(;|$)/);
    });

    it("pins upgrade-insecure-requests, which comes from helmet's implicit useDefaults and not from app.ts", async () => {
      const { header, directives } = await appCsp();

      // A valueless directive: present with an EMPTY source list, which is what
      // distinguishes it from an absent one (`undefined`). It rewrites the
      // http:// sub-resources and same-origin navigations a mixed-content asset
      // or an in-page link would otherwise fetch in the clear. It is NOT a
      // substitute for HSTS: the upgrade set is scoped to a browsing context and
      // is not persisted across browser sessions, so a top-level navigation
      // arriving from outside — the first of a fresh session above all — is
      // what it does not cover.
      expect(directives['upgrade-insecure-requests']).toEqual([]);
      // And it must stay valueless: a source list here is a malformed directive
      // that browsers discard, which a presence check alone would not notice.
      expect(header).toMatch(/(^|;)upgrade-insecure-requests(;|$)/);
    });

    it('pins the policy as one whole set, so no directive can appear, vanish, or revert to a looser helmet default unnoticed', async () => {
      const { header } = await appCsp();
      // The one value that legitimately differs per request.
      const normalised = header.replace(/'nonce-[A-Za-z0-9+/=]+'/, "'nonce-<per-request>'");

      // Compared WHOLE, and in both directions, for the same reason
      // `sandbox-document.test.ts` compares the sandbox policy whole. Every
      // assertion above names one directive, so between them they catch a
      // directive that disappears and a named source list that is widened — but
      // none of them catches a directive that is ADDED, nor one the app names
      // today being DELETED and silently replaced by helmet's looser default.
      // Removing `fontSrc: ["'self'"]` from app.ts is exactly that shape:
      // `font-src` reverts to helmet's `'self' https: data:`, admitting every
      // https origin as a font source, and nothing else in this repository
      // notices. A deliberate policy change updates this literal and says why.
      expect(parseCspHeader(normalised)).toEqual({
        'default-src': ["'self'"],
        'base-uri': ["'self'"],
        'font-src': ["'self'"],
        'form-action': ["'self'"],
        'frame-ancestors': ["'self'"],
        'img-src': ["'self'", 'data:', 'blob:'],
        'object-src': ["'none'"],
        'script-src': ["'self'", "'nonce-<per-request>'", "'wasm-unsafe-eval'"],
        'script-src-attr': ["'none'"],
        'style-src': ["'self'", "'unsafe-inline'"],
        'upgrade-insecure-requests': [],
        'connect-src': ["'self'"],
        'worker-src': ["'self'"],
        'media-src': ["'none'"],
        'frame-src': ["'self'"],
      });
    });

    it('should generate unique CSP nonce per request', async () => {
      const res1 = await request(app).get('/api/v1/health');
      const res2 = await request(app).get('/api/v1/health');

      const csp1 = res1.headers['content-security-policy'] as string;
      const csp2 = res2.headers['content-security-policy'] as string;

      const nonceMatch1 = csp1.match(/'nonce-([A-Za-z0-9+/=]+)'/);
      const nonceMatch2 = csp2.match(/'nonce-([A-Za-z0-9+/=]+)'/);

      expect(nonceMatch1).toBeDefined();
      expect(nonceMatch2).toBeDefined();
      expect(nonceMatch1![1]).not.toBe(nonceMatch2![1]);
    });

    it('should set X-Content-Type-Options to nosniff', async () => {
      const res = await request(app).get('/api/v1/health');

      expect(res.headers['x-content-type-options']).toBe('nosniff');
    });

    it('should set X-DNS-Prefetch-Control header', async () => {
      const res = await request(app).get('/api/v1/health');

      expect(res.headers['x-dns-prefetch-control']).toBeDefined();
    });

    it('should set X-Download-Options header', async () => {
      const res = await request(app).get('/api/v1/health');

      expect(res.headers['x-download-options']).toBe('noopen');
    });

    it('should set Referrer-Policy header', async () => {
      const res = await request(app).get('/api/v1/health');

      expect(res.headers['referrer-policy']).toBeDefined();
    });

    it('should set X-Frame-Options header', async () => {
      const res = await request(app).get('/api/v1/health');

      const xfo = res.headers['x-frame-options'];
      expect(xfo).toBeDefined();
      // Helmet defaults to SAMEORIGIN
      expect(xfo).toMatch(/DENY|SAMEORIGIN/i);
    });

    it('should not expose X-Powered-By header', async () => {
      const res = await request(app).get('/api/v1/health');

      expect(res.headers['x-powered-by']).toBeUndefined();
    });
  });

  // ── Production HTML CSP nonce injection ────────────────────────────

  describe('Production HTML CSP nonce injection', () => {
    // NOTE: two tests that copied the `/<script(?=[\s>])/gi` regex from app.ts into
    // the test body and ran it against a string literal were removed. They never
    // imported or invoked app.ts's production HTML handler — they asserted that
    // `String.prototype.replace` behaves like `String.prototype.replace`, i.e. they
    // tested the JS engine, and the "Mirrors the regex used in app.ts" comment meant
    // the clone silently drifted from the real code. The production handler runs only
    // under NODE_ENV=production against a built client dist, which the test app (loaded
    // in NODE_ENV=test) cannot reach, so there is no way to exercise it here. The live
    // CSP nonce in the response header IS asserted behaviorally below and in
    // "should generate unique CSP nonce per request" above.

    it('should not contain a CSP meta tag in the source index.html', () => {
      const __dirname = path.dirname(fileURLToPath(import.meta.url));
      const clientIndexPath = path.resolve(__dirname, '..', '..', 'client', 'index.html');
      const html = readFileSync(clientIndexPath, 'utf-8');
      expect(html).not.toContain('Content-Security-Policy');
    });

    it('should include nonce in CSP header for script-src and unsafe-inline for style-src', async () => {
      const res = await request(app).get('/api/v1/health');
      const csp = res.headers['content-security-policy'] as string;
      expect(csp).toMatch(/script-src[^;]*'nonce-[A-Za-z0-9+/=]+'/);
      expect(csp).toContain("style-src 'self' 'unsafe-inline'");
    });
  });

  // ── MongoDB Injection Prevention ───────────────────────────────────

  describe('MongoDB injection prevention', () => {
    /**
     * The three routes the sanitizer must cover, and the schema each validates with.
     *
     * `/auth/login` is parsed by the GLOBAL 2 MB parser, so the app-level sanitizer
     * sees its body. The other two are the custom-limit routes: the global parser
     * skips them (`CUSTOM_BODY_LIMIT_PATHS`), so their body is still `undefined` when
     * the app-level sanitizer runs and is parsed later, by the route's own 30 MB
     * parser. They are covered only if the route sanitizes after that parser, which
     * is the defect these cases pin. Login is the control: the two paths must agree.
     */
    const SANITIZED_ROUTES = [
      { path: '/api/v1/auth/login', schema: loginSchema },
      { path: '/api/v1/backup/restore', schema: restoreBackupSchema },
      { path: '/api/v1/vault/items/bulk-reencrypt', schema: bulkReEncryptSchema },
    ] as const;

    /**
     * Each planted body is RAW JSON on purpose. Written as an object literal,
     * `{ __proto__: {...} }` sets the literal's prototype rather than creating a key,
     * and `JSON.stringify` then sends nothing at all, so a test built that way passes
     * against a server with no sanitizer. `JSON.parse` is what creates `__proto__` as
     * an own key, exactly as the body parser does.
     *
     * Every body also carries `keep` fields, so a sanitizer that blanked the whole
     * body, or stripped a `$`-prefixed VALUE instead of a key, fails too. None of them
     * satisfies the route's schema, so every request stops at validation with a 400
     * and no handler runs.
     */
    const INJECTION_CASES = [
      {
        name: 'a top-level $-prefixed key',
        raw: '{"$gt":"1","keep":"$value-not-a-key"}',
        expected: { keep: '$value-not-a-key' },
      },
      {
        name: 'a nested $-prefixed key, in an object and inside an array',
        raw: '{"nested":{"$gt":"","keep":"v"},"list":[{"$where":"this.owner == 1","keep":1}]}',
        expected: { nested: { keep: 'v' }, list: [{ keep: 1 }] },
      },
      {
        name: 'a __proto__ key',
        raw: '{"__proto__":{"isAdmin":true},"keep":"v"}',
        expected: { keep: 'v' },
      },
      {
        name: 'a constructor key',
        raw: '{"constructor":{"prototype":{"isAdmin":true}},"keep":"v"}',
        expected: { keep: 'v' },
      },
      {
        name: 'a prototype key, top-level and nested',
        raw: '{"prototype":{"polluted":true},"nested":{"prototype":{"polluted":true},"keep":2}}',
        expected: { nested: { keep: 2 } },
      },
    ] as const;

    let accessToken = '';

    beforeEach(async () => {
      validatedBodies.length = 0;
      ({ accessToken } = await createTestUser());
    });

    /** POSTs a raw JSON body as a signed-in user with a valid CSRF pair. */
    async function postRaw(route: string, raw: string): Promise<request.Response> {
      const agent = request.agent(app);
      const csrf = await getCsrf(agent);
      return agent
        .post(route)
        .set('Authorization', authHeader(accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .set('Content-Type', 'application/json')
        .send(raw);
    }

    for (const route of SANITIZED_ROUTES) {
      describe(`on ${route.path}`, () => {
        for (const injection of INJECTION_CASES) {
          it(`strips ${injection.name} before validation sees the body`, async () => {
            const res = await postRaw(route.path, injection.raw);

            // Stopped at validation, and by the flat error envelope: no handler ran.
            expect(res.status).toBe(400);
            expect(res.body).toMatchObject({ success: false, statusCode: 400 });

            // Exactly one body reached validation, and it was THIS route's schema.
            expect(validatedBodies).toHaveLength(1);
            const [seen] = validatedBodies;
            expect(seen!.schema).toBe(route.schema);

            // The whole sanitized body, not a spot check: every dangerous key gone at
            // every depth, every legitimate one intact.
            expect(seen!.body).toStrictEqual(injection.expected);
            expect(Object.hasOwn(seen!.body as object, '__proto__')).toBe(false);
            // A `__proto__` copied by assignment would not be an own key at all; it
            // would have become the body's prototype, and this is what catches that.
            expect(Object.getPrototypeOf(seen!.body)).toBe(Object.prototype);
          });
        }

        it('refuses a body nested past the depth bound with 400, before validation', async () => {
          // 10,000 levels is 20 KB, well inside every parser limit, and deep enough
          // to overflow the stack of a recursive walk. That overflow used to surface
          // as a 500; a malformed body is the client's error.
          const depth = 10_000;
          const raw = `${'{"a":'.repeat(depth)}1${'}'.repeat(depth)}`;

          const res = await postRaw(route.path, raw);

          expect(res.status).toBe(400);
          expect(res.body).toMatchObject({
            success: false,
            statusCode: 400,
            message: 'Request body is nested too deeply',
          });
          expect(validatedBodies).toHaveLength(0);
        });
      });
    }

    it('sanitizes an array element by element, keeping it an array and every valid element', async () => {
      // Observed at the input to validation, like the cases above: the registration
      // schema strips the unknown `probe` key afterwards whatever the sanitizer did.
      // A walk that rebuilt an array as an object of indices, dropped an element, or
      // stopped at the array instead of entering it, fails here.
      const csrf = await getCsrf(request.agent(app));
      const res = await request(app)
        .post('/api/v1/auth/register')
        .set('x-csrf-token', csrf.token)
        .set('Cookie', csrf.cookie)
        .send({
          email: 'test@example.com',
          authHash: 'my-hash',
          encryptedVaultKey: 'evk',
          vaultKeyIv: 'iv',
          vaultKeyTag: 'tag',
          kdfIterations: 600000,
          kdfAlgorithm: 'PBKDF2-SHA256',
          encryptionVersion: 1,
          probe: ['plain', 7, { $gt: '', keep: 'x' }, ['nested', { $where: '1', keep: 2 }]],
        });

      expect(res.status, JSON.stringify(res.body)).toBe(201);
      expect(validatedBodies).toHaveLength(1);
      const seen = validatedBodies[0]!.body as Record<string, unknown>;
      expect(Array.isArray(seen.probe)).toBe(true);
      expect(seen.probe).toStrictEqual(['plain', 7, { keep: 'x' }, ['nested', { keep: 2 }]]);
      expect(seen).toMatchObject({ email: 'test@example.com', kdfIterations: 600000 });
    });
  });

  // ── HPP Protection ─────────────────────────────────────────────────

  describe('HPP (HTTP Parameter Pollution) protection', () => {
    it('should keep last value for non-whitelisted duplicate query params', async () => {
      // hppx with keepLast strategy — non-whitelisted params keep only last value
      // For a GET request, duplicate params like ?page=1&page=2 should use page=2
      const res = await request(app).get('/api/v1/health?extra=first&extra=second');

      // The request should process successfully regardless
      expect(res.status).toBe(200);
    });

    it('should allow whitelisted duplicate query params (tags)', async () => {
      // 'tags' is whitelisted in hppx config, so it should allow arrays
      // This just verifies the middleware doesn't crash on whitelisted params
      const res = await request(app).get('/api/v1/health?tags=a&tags=b');

      expect(res.status).toBe(200);
    });
  });

  // ── CSRF Double-Submit Mismatch ──────────────────────────────────

  describe('CSRF token mismatch rejection', () => {
    it('should reject a state-changing request with a corrupted CSRF token', async () => {
      // Get a valid CSRF token
      const csrfRes = await request(app).get('/api/v1/csrf-token');
      const validToken: string = csrfRes.body.data.csrfToken;
      const setCookies: string[] = (csrfRes.headers['set-cookie'] as string[] | undefined) ?? [];
      const csrfCookieRaw = setCookies.find((c: string) => c.startsWith('__csrf='));
      const csrfCookie = csrfCookieRaw ? csrfCookieRaw.split(';')[0]! : '';

      // Corrupt the token by flipping a character in the HMAC portion
      const corruptedToken = (validToken[0] === 'a' ? 'b' : 'a') + validToken.slice(1);

      const res = await request(app)
        .post('/api/v1/auth/login')
        .set('x-csrf-token', corruptedToken)
        .set('Cookie', csrfCookie)
        .send({ email: 'test@example.com', authHash: 'some-hash' });

      expect(res.status).toBe(403);
    });

    it('should reject a state-changing request with a completely fabricated CSRF token', async () => {
      const res = await request(app)
        .post('/api/v1/auth/login')
        .set('x-csrf-token', 'fabricated-token-value.not-a-real-hmac')
        .send({ email: 'test@example.com', authHash: 'some-hash' });

      expect(res.status).toBe(403);
    });

    it('should reject a request with a valid-format but wrong-secret CSRF token', async () => {
      // Craft a token with the correct format but signed with a different secret
      const crypto = await import('node:crypto');
      const timestamp = Date.now().toString(36);
      const randomValue = crypto.randomBytes(32).toString('hex');
      const payload = `${timestamp}:${randomValue}`;
      const hmac = crypto
        .createHmac('sha256', 'wrong-secret-key-that-is-32-chars!')
        .update(payload)
        .digest('hex');
      const forgedToken = `${hmac}.${payload}`;

      const res = await request(app)
        .post('/api/v1/auth/login')
        .set('x-csrf-token', forgedToken)
        .send({ email: 'test@example.com', authHash: 'some-hash' });

      expect(res.status).toBe(403);
    });
  });

  // ── CORS ───────────────────────────────────────────────────────────

  describe('CORS headers', () => {
    it('should include Access-Control-Allow-Credentials header', async () => {
      const res = await request(app).get('/api/v1/health').set('Origin', 'http://localhost:5173');

      expect(res.headers['access-control-allow-credentials']).toBe('true');
    });

    it('should respond to OPTIONS preflight with allowed methods', async () => {
      const res = await request(app)
        .options('/api/v1/health')
        .set('Origin', 'http://localhost:5173')
        .set('Access-Control-Request-Method', 'POST')
        .set('Access-Control-Request-Headers', 'Content-Type, Authorization, x-csrf-token');

      // Should return 204 or 200 for preflight
      expect([200, 204]).toContain(res.status);
      expect(res.headers['access-control-allow-methods']).toBeDefined();
      expect(res.headers['access-control-allow-headers']).toBeDefined();
    });
  });
});
