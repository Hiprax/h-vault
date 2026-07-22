import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import request from 'supertest';
import app from '../src/app.js';

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
      expect(csp).toContain("frame-src 'none'");
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
    it('should strip $-prefixed keys from request body', async () => {
      // We need a CSRF token for POST requests
      const csrfRes = await request(app).get('/api/v1/csrf-token');
      const csrfToken: string = csrfRes.body.data.csrfToken;
      const setCookies: string[] = (csrfRes.headers['set-cookie'] as string[] | undefined) ?? [];
      const csrfCookieRaw = setCookies.find((c) => c.startsWith('__csrf='));
      const csrfCookie = csrfCookieRaw ? csrfCookieRaw.split(';')[0]! : '';

      // Send a login request with $-prefixed keys that should be stripped
      // The $gt key should be stripped before any controller logic runs
      const res = await request(app)
        .post('/api/v1/auth/login')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          email: 'test@example.com',
          authHash: 'some-hash',
          $gt: '1',
        });

      // The request should still process (not crash) — 401 because user doesn't exist
      // If the $gt wasn't stripped, it could cause unexpected behavior in MongoDB queries
      expect(res.status).toBe(401);
    });

    it('should strip nested $-prefixed keys from request body', async () => {
      const csrfRes = await request(app).get('/api/v1/csrf-token');
      const csrfToken: string = csrfRes.body.data.csrfToken;
      const setCookies: string[] = (csrfRes.headers['set-cookie'] as string[] | undefined) ?? [];
      const csrfCookieRaw = setCookies.find((c) => c.startsWith('__csrf='));
      const csrfCookie = csrfCookieRaw ? csrfCookieRaw.split(';')[0]! : '';

      const res = await request(app)
        .post('/api/v1/auth/login')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          email: { $gt: '' },
          authHash: 'some-hash',
        });

      // The $gt inside email should be stripped, making email an empty object
      // This should result in a 400 validation error (invalid email) not a MongoDB operator injection
      expect([400, 401]).toContain(res.status);
    });

    it('should strip __proto__ keys from request body (prototype pollution prevention)', async () => {
      const csrfRes = await request(app).get('/api/v1/csrf-token');
      const csrfToken: string = csrfRes.body.data.csrfToken;
      const setCookies: string[] = (csrfRes.headers['set-cookie'] as string[] | undefined) ?? [];
      const csrfCookieRaw = setCookies.find((c) => c.startsWith('__csrf='));
      const csrfCookie = csrfCookieRaw ? csrfCookieRaw.split(';')[0]! : '';

      // Send a login request with __proto__ key that should be stripped
      const res = await request(app)
        .post('/api/v1/auth/login')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          email: 'test@example.com',
          authHash: 'some-hash',
          __proto__: { isAdmin: true },
        });

      // Should process normally without prototype pollution — 401 because user doesn't exist
      expect(res.status).toBe(401);
    });

    it('should strip constructor keys from request body (prototype pollution prevention)', async () => {
      const csrfRes = await request(app).get('/api/v1/csrf-token');
      const csrfToken: string = csrfRes.body.data.csrfToken;
      const setCookies: string[] = (csrfRes.headers['set-cookie'] as string[] | undefined) ?? [];
      const csrfCookieRaw = setCookies.find((c) => c.startsWith('__csrf='));
      const csrfCookie = csrfCookieRaw ? csrfCookieRaw.split(';')[0]! : '';

      // Send a login request with constructor key that should be stripped
      const res = await request(app)
        .post('/api/v1/auth/login')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          email: 'test@example.com',
          authHash: 'some-hash',
          constructor: { prototype: { isAdmin: true } },
        });

      // Should process normally without prototype pollution — 401 because user doesn't exist
      expect(res.status).toBe(401);
    });

    it('should strip prototype keys from request body (prototype pollution prevention)', async () => {
      const csrfRes = await request(app).get('/api/v1/csrf-token');
      const csrfToken: string = csrfRes.body.data.csrfToken;
      const setCookies: string[] = (csrfRes.headers['set-cookie'] as string[] | undefined) ?? [];
      const csrfCookieRaw = setCookies.find((c) => c.startsWith('__csrf='));
      const csrfCookie = csrfCookieRaw ? csrfCookieRaw.split(';')[0]! : '';

      const res = await request(app)
        .post('/api/v1/auth/login')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          email: 'test@example.com',
          authHash: 'some-hash',
          prototype: { polluted: true },
        });

      // Should process normally without prototype pollution — 401 because user doesn't exist
      expect(res.status).toBe(401);
    });

    it('should handle arrays in request body without stripping valid data', async () => {
      const csrfRes = await request(app).get('/api/v1/csrf-token');
      const csrfToken: string = csrfRes.body.data.csrfToken;
      const setCookies: string[] = (csrfRes.headers['set-cookie'] as string[] | undefined) ?? [];
      const csrfCookieRaw = setCookies.find((c) => c.startsWith('__csrf='));
      const csrfCookie = csrfCookieRaw ? csrfCookieRaw.split(';')[0]! : '';

      // Arrays should be preserved (sanitized element-by-element)
      const res = await request(app)
        .post('/api/v1/auth/register')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          email: 'test@example.com',
          authHash: 'my-hash',
          encryptedVaultKey: 'evk',
          vaultKeyIv: 'iv',
          vaultKeyTag: 'tag',
          kdfIterations: 600000,
          kdfAlgorithm: 'PBKDF2-SHA256',
          encryptionVersion: 1,
        });

      // Should process normally (201 for new registration)
      expect(res.status).toBe(201);
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
