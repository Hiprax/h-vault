import { describe, it, expect, beforeEach } from 'vitest';
import { Types } from 'mongoose';
import request from 'supertest';
import app from '../src/app.js';
import {
  authLimiter,
  refreshLimiter,
  accountLimiter,
  tokenVerifyLimiter,
  heavyOpLimiter,
  passwordVerifyLimiter,
  healthLimiter,
} from '../src/middleware/rateLimiter.js';
import { createTestUser, authHeader, sampleVaultItem, getCsrf as getCsrfBase } from './helpers.js';
import type { TestUser } from './helpers.js';

// Re-export with { csrfToken, csrfCookie } naming used throughout this file
async function getCsrf(
  agent: request.SuperTest<request.Test>,
  extraCookies?: string,
): Promise<{ csrfToken: string; csrfCookie: string }> {
  const { token, cookie } = await getCsrfBase(agent, extraCookies);
  return { csrfToken: token, csrfCookie: cookie };
}

// ── BWK setup data ───────────────────────────────────────────────────

const bwkSetupData = {
  authHash: 'test-auth-hash-value',
  encryptedBWK: 'test-encrypted-bwk-data',
  bwkIv: 'test-bwk-iv-value',
  bwkTag: 'test-bwk-tag-value',
  bwkSalt: 'test-bwk-salt-value',
};

// ── Tests ────────────────────────────────────────────────────────────
// Rate limiters are pass-through in test mode (NODE_ENV=test).
// These tests verify that adding strictLimiter / tokenVerifyLimiter
// middleware to routes does not break the middleware chain — requests
// still reach the controller and return expected responses.

describe('Rate limiting middleware chain (Phase 7 fixes)', () => {
  let user: TestUser;
  let agent: request.SuperTest<request.Test>;

  beforeEach(async () => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    user = await createTestUser();
  });

  // ── 7.1 — Backup restore has strictLimiter ──────────────────────

  describe('7.1 — POST /api/v1/backup/restore (strictLimiter)', () => {
    it('should accept restore requests through rate limiter middleware', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const itemId = new Types.ObjectId().toString();

      const backupData = JSON.stringify({
        items: [{ _id: itemId, ...sampleVaultItem({ encryptedName: 'rate-limit-test-item' }) }],
        folders: [],
      });

      const res = await agent
        .post('/api/v1/backup/restore')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ conflictStrategy: 'skip', data: backupData });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.itemsRestored).toBe(1);
    });

    it('should still enforce auth before rate limiter', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/backup/restore')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ conflictStrategy: 'skip', data: '{}' });

      expect(res.status).toBe(401);
    });
  });

  // ── 7.2 — Backup setup and change-password have strictLimiter ───

  describe('7.2 — POST /api/v1/backup/setup (strictLimiter)', () => {
    it('should accept setup requests through rate limiter middleware', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/backup/setup')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send(bwkSetupData);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('should still enforce auth before rate limiter on setup', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/backup/setup')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send(bwkSetupData);

      expect(res.status).toBe(401);
    });
  });

  describe('7.2 — PUT /api/v1/backup/change-password (strictLimiter)', () => {
    it('should accept change-password requests through rate limiter middleware', async () => {
      // Setup backup first
      const { csrfToken: csrf1, csrfCookie: cookie1 } = await getCsrf(agent);
      await agent
        .post('/api/v1/backup/setup')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf1)
        .set('Cookie', cookie1)
        .send(bwkSetupData);

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .put('/api/v1/backup/change-password')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          password: user.rawPassword,
          newEncryptedBWK: 'new-encrypted-bwk-data',
          newBwkIv: 'new-bwk-iv-value',
          newBwkTag: 'new-bwk-tag-value',
          newBwkSalt: 'new-bwk-salt-value',
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('should still enforce auth before rate limiter on change-password', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .put('/api/v1/backup/change-password')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          password: 'some-password',
          newEncryptedBWK: 'new-encrypted-bwk-data',
          newBwkIv: 'new-bwk-iv-value',
          newBwkTag: 'new-bwk-tag-value',
          newBwkSalt: 'new-bwk-salt-value',
        });

      expect(res.status).toBe(401);
    });
  });

  // ── 7.3 — Import has strictLimiter ──────────────────────────────

  describe('7.3 — POST /api/v1/tools/import (strictLimiter)', () => {
    it('should accept import requests through rate limiter middleware', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const importData = JSON.stringify({
        items: [sampleVaultItem({ encryptedName: 'rate-limit-import-test' })],
      });

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'json', data: importData });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.importedCount).toBe(1);
    });

    it('should still enforce auth before rate limiter on import', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/import')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'json', data: '{}' });

      expect(res.status).toBe(401);
    });
  });

  // ── 7.4 — 2FA login has tokenVerifyLimiter ─────────────────────

  describe('7.4 — POST /api/v1/auth/login/2fa (tokenVerifyLimiter)', () => {
    it('should still process 2FA login requests through rate limiter middleware', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      // Send an invalid tempToken — the request should pass through rate
      // limiters and reach the controller, which rejects it as unauthorized.
      const res = await agent
        .post('/api/v1/auth/login/2fa')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ tempToken: 'invalid-token', code: '123456' });

      // Should reach controller (not blocked by middleware chain) and
      // return 401 because the tempToken is invalid.
      expect(res.status).toBe(401);
    });
  });

  // ── 7.5 — 2FA disable has strictLimiter ────────────────────────

  describe('7.5 — DELETE /api/v1/user/2fa (strictLimiter)', () => {
    it('should accept 2FA disable requests through rate limiter middleware', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      // 2FA is not enabled for the test user, so the controller returns 400.
      // This verifies the middleware chain (strictLimiter) does not block.
      const res = await agent
        .delete('/api/v1/user/2fa')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ code: '123456', password: user.rawPassword });

      expect(res.status).toBe(400);
    });

    it('should still enforce auth before rate limiter on 2FA disable', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .delete('/api/v1/user/2fa')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ code: '123456', password: 'test' });

      expect(res.status).toBe(401);
    });
  });

  // ── 7.6 — Token-based endpoints use tokenVerifyLimiter ──────────

  describe('7.6 — Token-based verification endpoints (tokenVerifyLimiter)', () => {
    it('should process verify-email requests through tokenVerifyLimiter', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/auth/verify-email')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ token: 'invalid-token' });

      // Should reach controller (not blocked by rate limiter middleware).
      // Returns 400 because the JWT token is malformed.
      expect(res.status).toBe(400);
    });

    it('should process reset-password requests through tokenVerifyLimiter', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/auth/reset-password')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          token: 'invalid-token',
          email: 'test@example.com',
          newAuthHash: 'new-hash',
          newEncryptedVaultKey: 'new-key',
          newVaultKeyIv: 'new-iv',
          newVaultKeyTag: 'new-tag',
        });

      // Should reach controller (not blocked by rate limiter middleware).
      // Returns 400 because the JWT token is malformed.
      expect(res.status).toBe(400);
    });

    it('should process unlock-account requests through tokenVerifyLimiter', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/auth/unlock-account')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ token: 'invalid-token' });

      // Should reach controller (not blocked by rate limiter middleware).
      // Returns 400 because the JWT token is malformed.
      expect(res.status).toBe(400);
    });
  });

  // ── 7.7 — accountLimiter skips when email missing ─────────────

  describe('7.7 — accountLimiter email-missing fallback', () => {
    it('should still process login without email (validation rejects it)', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      // Send login without email — accountLimiter skips, request reaches
      // validation middleware which rejects it with 400.
      const res = await agent
        .post('/api/v1/auth/login')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ authHash: 'some-hash' });

      // Validation error because email is required
      expect(res.status).toBe(400);
    });

    it('should still process login with valid email through accountLimiter', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/auth/login')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ email: 'test@example.com', authHash: 'invalid-hash' });

      // Reaches controller — returns 401 because credentials are wrong
      expect(res.status).toBe(401);
    });
  });

  // ── L8 — Empty trash has heavyOpLimiter ──────────────────────────

  describe('L8 — DELETE /api/v1/vault/items/trash/empty (heavyOpLimiter)', () => {
    it('should accept empty trash requests through rate limiter middleware', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .delete('/api/v1/vault/items/trash/empty')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie);

      // Reaches controller — returns 200 (empty trash succeeds even with no items)
      expect(res.status).toBe(200);
    });
  });

  // ── L9 — Backup download has heavyOpLimiter ──────────────────────

  describe('L9 — GET /api/v1/backup/download (heavyOpLimiter)', () => {
    it('should accept download requests through rate limiter middleware', async () => {
      const res = await agent
        .get('/api/v1/backup/download')
        .set('Authorization', authHeader(user.accessToken));

      // Reaches controller — may return 400 (backup not configured) but not 403
      expect([200, 400]).toContain(res.status);
    });
  });

  // ── 3.5 — POST /auth/refresh has authLimiter ────────────────────

  describe('3.5 — POST /api/v1/auth/refresh (authLimiter)', () => {
    it('should accept refresh requests through rate limiter middleware', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent, `refreshToken=${user.refreshToken}`);

      const res = await agent
        .post('/api/v1/auth/refresh')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', `${csrfCookie}; refreshToken=${user.refreshToken}`);

      // Reaches controller — returns 200 with new tokens
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.accessToken).toBeDefined();
    });

    it('should reject refresh without a token (reaches controller, not blocked by limiter)', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/auth/refresh')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie);

      // Reaches controller — returns 401 because no refreshToken cookie
      expect(res.status).toBe(401);
    });
  });

  // ── 3.6 — POST /backup/trigger has heavyOpLimiter ──────────────

  describe('3.6 — POST /api/v1/backup/trigger (heavyOpLimiter)', () => {
    it('should accept trigger requests through rate limiter middleware', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/backup/trigger')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie);

      // Reaches controller — may return 400 (backup not configured) but passes limiter
      expect([200, 400]).toContain(res.status);
    });

    it('should still enforce auth before rate limiter on trigger', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/backup/trigger')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie);

      expect(res.status).toBe(401);
    });
  });

  // ── 3.7 — POST /tools/export has heavyOpLimiter + passwordVerifyLimiter ──

  describe('3.7 — POST /api/v1/tools/export (heavyOpLimiter + passwordVerifyLimiter)', () => {
    it('should accept export requests through the stacked rate limiter middleware', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/export')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ authHash: user.rawPassword });

      // Reaches controller — returns 200 (export data)
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('should still enforce auth before rate limiter on export', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/export')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ authHash: 'some-password' });

      expect(res.status).toBe(401);
    });

    it('should reject export requests with an invalid authHash (Task 2.2 chain still validates)', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/export')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ authHash: 'wrong-password' });

      // Reaches controller — bcrypt mismatch returns 401
      expect(res.status).toBe(401);
    });
  });

  // ── MISSING-4 — POST /user/2fa/verify has tokenVerifyLimiter ────

  describe('MISSING-4 — POST /api/v1/user/2fa/verify (tokenVerifyLimiter)', () => {
    it('should accept 2FA verify requests through rate limiter middleware', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      // 2FA is not set up for the test user, so the controller returns 409.
      // This verifies the middleware chain (tokenVerifyLimiter) does not block.
      const res = await agent
        .post('/api/v1/user/2fa/verify')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ code: '123456', secret: 'some-secret' });

      // Reaches controller — returns 400 or 409 (no pending 2FA setup / already enabled)
      expect([400, 409]).toContain(res.status);
    });

    it('should still enforce auth before rate limiter on 2FA verify', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/user/2fa/verify')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ code: '123456', secret: 'some-secret' });

      expect(res.status).toBe(401);
    });
  });

  // ── CSRF token endpoint has csrfLimiter ──────────────────────────

  describe('GET /api/v1/csrf-token (csrfLimiter)', () => {
    it('should return CSRF token through rate limiter middleware', async () => {
      const res = await agent.get('/api/v1/csrf-token');

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.csrfToken).toBeDefined();
    });

    it('should return multiple CSRF tokens successfully (no-op limiter in test)', async () => {
      // Rate limiters are pass-through in test mode; verify the endpoint
      // still responds correctly when called multiple times.
      for (let i = 0; i < 5; i++) {
        const res = await agent.get('/api/v1/csrf-token');
        expect(res.status).toBe(200);
        expect(res.body.data.csrfToken).toBeDefined();
      }
    });
  });

  // ── Health endpoint has healthLimiter ────────────────────────────

  describe('GET /api/v1/health (healthLimiter)', () => {
    it('should accept health requests through the rate limiter middleware', async () => {
      const res = await agent.get('/api/v1/health');

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.status).toBeDefined();
    });

    it('should keep responding to repeated health probes (no-op limiter in test)', async () => {
      for (let i = 0; i < 10; i++) {
        const res = await agent.get('/api/v1/health');
        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
      }
    });
  });
});

// ---------------------------------------------------------------------------
// Structural wiring: the named limiter is actually MOUNTED on the route.
//
// The round-trip tests above only prove the middleware chain doesn't BREAK the
// endpoint — and because every limiter is a pass-through no-op under
// NODE_ENV=test, removing one from a route leaves those tests green. Each
// limiter is nonetheless a distinct exported function reference (a per-limiter
// no-op closure in non-production), so we can assert the exact reference is
// present in the route's Express layer stack. This is the assertion that turns
// RED the moment a limiter is unwired from its route.
// ---------------------------------------------------------------------------

interface RouteLayer {
  path: string;
  methods: Record<string, boolean>;
  stack: { handle: unknown }[];
}
interface StackLayer {
  route?: RouteLayer;
  handle?: { stack?: StackLayer[] };
}

function collectRouteLayers(): RouteLayer[] {
  const expressApp = app as unknown as {
    router?: { stack: StackLayer[] };
    _router?: { stack: StackLayer[] };
  };
  const rootStack = expressApp.router?.stack ?? expressApp._router?.stack ?? [];
  const routes: RouteLayer[] = [];
  const walk = (layers: StackLayer[]): void => {
    for (const layer of layers) {
      if (layer.route) {
        routes.push(layer.route);
      } else if (layer.handle?.stack) {
        walk(layer.handle.stack);
      }
    }
  };
  walk(rootStack);
  return routes;
}

describe('Rate limiter route wiring (structural)', () => {
  const routeLayers = collectRouteLayers();

  function isLimiterMounted(method: string, subPath: string, limiter: unknown): boolean {
    return routeLayers.some(
      (r) =>
        r.methods[method] === true &&
        r.path === subPath &&
        r.stack.some((l) => l.handle === limiter),
    );
  }

  // [describe-label, HTTP method, router-relative path, limiter reference]
  const wirings: [string, string, string, unknown][] = [
    ['authLimiter on POST /auth/login', 'post', '/login', authLimiter],
    ['accountLimiter on POST /auth/login', 'post', '/login', accountLimiter],
    ['authLimiter on POST /auth/refresh', 'post', '/refresh', authLimiter],
    ['refreshLimiter on POST /auth/refresh', 'post', '/refresh', refreshLimiter],
    ['authLimiter on POST /auth/login/2fa', 'post', '/login/2fa', authLimiter],
    ['tokenVerifyLimiter on POST /auth/login/2fa', 'post', '/login/2fa', tokenVerifyLimiter],
    ['tokenVerifyLimiter on POST /auth/verify-email', 'post', '/verify-email', tokenVerifyLimiter],
    [
      'tokenVerifyLimiter on POST /auth/reset-password',
      'post',
      '/reset-password',
      tokenVerifyLimiter,
    ],
    [
      'tokenVerifyLimiter on POST /auth/unlock-account',
      'post',
      '/unlock-account',
      tokenVerifyLimiter,
    ],
    [
      'heavyOpLimiter on DELETE /vault/items/trash/empty',
      'delete',
      '/items/trash/empty',
      heavyOpLimiter,
    ],
    ['heavyOpLimiter on POST /tools/export', 'post', '/export', heavyOpLimiter],
    ['passwordVerifyLimiter on POST /tools/export', 'post', '/export', passwordVerifyLimiter],
    ['heavyOpLimiter on POST /tools/import', 'post', '/import', heavyOpLimiter],
    ['heavyOpLimiter on POST /backup/trigger', 'post', '/trigger', heavyOpLimiter],
    ['heavyOpLimiter on GET /backup/download', 'get', '/download', heavyOpLimiter],
    ['passwordVerifyLimiter on POST /backup/setup', 'post', '/setup', passwordVerifyLimiter],
    ['passwordVerifyLimiter on POST /backup/restore', 'post', '/restore', passwordVerifyLimiter],
    ['tokenVerifyLimiter on POST /user/2fa/verify', 'post', '/2fa/verify', tokenVerifyLimiter],
    ['passwordVerifyLimiter on DELETE /user/2fa', 'delete', '/2fa', passwordVerifyLimiter],
    ['healthLimiter on GET /health', 'get', '/health', healthLimiter],
    ['healthLimiter on GET /config', 'get', '/config', healthLimiter],
  ];

  it.each(wirings)('%s', (_label, method, path, limiter) => {
    expect(isLimiterMounted(method, path, limiter)).toBe(true);
  });
});
