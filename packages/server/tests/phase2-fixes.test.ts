import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import type { RequestHandler, Router } from 'express';
import app from '../src/app.js';
import authRouter from '../src/routes/auth.js';
import { refreshLimiter } from '../src/middleware/rateLimiter.js';
import { Folder } from '../src/models/Folder.js';
import { createTestUser, authHeader, sampleFolder, getCsrf, type TestUser } from './helpers.js';

/**
 * Return the ordered list of handler functions mounted on the route matching
 * `method` + `path` in an Express Router. Used to assert middleware *presence*
 * structurally, since rate limiters are pass-through no-ops outside production
 * and cannot be observed behaviourally in the test environment.
 */
function routeHandlers(router: Router, method: string, path: string): RequestHandler[] {
  const stack = (router as unknown as { stack: RouteLayer[] }).stack;
  for (const layer of stack) {
    if (layer.route && layer.route.path === path && layer.route.methods[method]) {
      return layer.route.stack.map((l) => l.handle);
    }
  }
  return [];
}

interface RouteLayer {
  route?: {
    path: string;
    methods: Record<string, boolean>;
    stack: { handle: RequestHandler }[];
  };
}

// ── Constants ──────────────────────────────────────────────────────────

const AUTH_BASE = '/api/v1/auth';
const FOLDER_BASE = '/api/v1/folders';

// ── Test Suite ─────────────────────────────────────────────────────────

describe('Phase 2 Fixes', () => {
  let user: TestUser;
  let agent: request.Agent;
  let csrf: { cookie: string; token: string };

  beforeEach(async () => {
    user = await createTestUser();
    agent = request.agent(app);
    csrf = await getCsrf(agent);
  });

  // ── Helpers ────────────────────────────────────────────────────────

  async function apiCreateFolder(overrides: Record<string, unknown> = {}) {
    const res = await agent
      .post(FOLDER_BASE)
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', csrf.cookie)
      .set('x-csrf-token', csrf.token)
      .send(sampleFolder(overrides));
    expect(res.status).toBe(201);
    return res.body.data;
  }

  // ── 2.1 — Refresh Token Rate Limiter ──────────────────────────────
  // Rate limiters are pass-through in test mode. These tests verify that
  // the refreshLimiter middleware added to the route does not break the
  // middleware chain — requests still reach the controller and return
  // expected responses.

  describe('Task 2.1 — Refresh endpoint with refreshLimiter', () => {
    it('mounts refreshLimiter on POST /auth/refresh', () => {
      // Rate limiters are pass-through no-ops outside production, so the limit
      // itself cannot be exercised here. The regression this guards is the
      // limiter being *dropped from the route entirely* — assert its presence
      // structurally on the middleware chain (the exported binding is the exact
      // instance mounted on the route, even as a test-mode no-op).
      const handlers = routeHandlers(authRouter, 'post', '/refresh');
      expect(handlers).toContain(refreshLimiter);
    });

    it('should process refresh requests through the rate limiter middleware', async () => {
      // Attempt refresh with CSRF but no refresh cookie — should reach
      // the controller and return 401 (missing refresh token).
      const res = await agent
        .post(`${AUTH_BASE}/refresh`)
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token);

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('should accept a valid refresh token through the rate limiter', async () => {
      // CSRF token must be bound to the same refresh-token family the
      // request will use; otherwise the session-bound CSRF check fails.
      const csrfBound = await getCsrf(agent, `refreshToken=${user.refreshToken}`);
      const res = await agent
        .post(`${AUTH_BASE}/refresh`)
        .set('Cookie', `${csrfBound.cookie}; refreshToken=${user.refreshToken}`)
        .set('x-csrf-token', csrfBound.token);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('accessToken');
    });

    it('should still work under normal usage (sequential refreshes)', async () => {
      // First refresh
      const csrfBound = await getCsrf(agent, `refreshToken=${user.refreshToken}`);
      const res1 = await agent
        .post(`${AUTH_BASE}/refresh`)
        .set('Cookie', `${csrfBound.cookie}; refreshToken=${user.refreshToken}`)
        .set('x-csrf-token', csrfBound.token);
      expect(res1.status).toBe(200);

      // A successful refresh MUST rotate the refresh-token cookie. Asserting it
      // exists (rather than guarding the second refresh behind `if`) is what
      // gives this test teeth: if the handler stops issuing a rotated cookie the
      // test now fails here instead of silently degrading to a no-op.
      const cookies = res1.headers['set-cookie'] as string[] | undefined;
      const newRefreshCookie = cookies?.find((c: string) => c.startsWith('refreshToken='));
      expect(newRefreshCookie).toBeDefined();

      const newRefreshValue = newRefreshCookie!.split(';')[0]!.split('=')[1] ?? '';
      expect(newRefreshValue.length).toBeGreaterThan(0);

      const csrf2 = await getCsrf(agent, `refreshToken=${newRefreshValue}`);
      const res2 = await agent
        .post(`${AUTH_BASE}/refresh`)
        .set('Cookie', `${csrf2.cookie}; ${newRefreshCookie!}`)
        .set('x-csrf-token', csrf2.token);
      expect(res2.status).toBe(200);
      expect(res2.body.data).toHaveProperty('accessToken');
    });
  });

  // ── 2.3 — Folder $graphLookup Optimization ────────────────────────

  describe('Task 2.3 — Folder depth and circular reference via $graphLookup', () => {
    it('should detect direct circular reference (A → B → A) via $graphLookup', async () => {
      const folderA = await apiCreateFolder({ encryptedName: 'gql-a' });
      const folderB = await apiCreateFolder({ encryptedName: 'gql-b', parentId: folderA._id });

      const res = await agent
        .put(`${FOLDER_BASE}/${folderA._id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ parentId: folderB._id });

      expect(res.status).toBe(400);
    });

    it('should detect 3-level circular reference (A → B → C → A) via $graphLookup', async () => {
      const folderA = await apiCreateFolder({ encryptedName: 'gql-3a' });
      const folderB = await apiCreateFolder({ encryptedName: 'gql-3b', parentId: folderA._id });
      const folderC = await apiCreateFolder({ encryptedName: 'gql-3c', parentId: folderB._id });

      const res = await agent
        .put(`${FOLDER_BASE}/${folderA._id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ parentId: folderC._id });

      expect(res.status).toBe(400);
    });

    it('should allow valid reparenting (no cycle)', async () => {
      const folderA = await apiCreateFolder({ encryptedName: 'gql-va' });
      const folderB = await apiCreateFolder({ encryptedName: 'gql-vb' });

      const res = await agent
        .put(`${FOLDER_BASE}/${folderB._id}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ parentId: folderA._id });

      expect(res.status).toBe(200);
      expect(res.body.data.parentId).toBe(folderA._id);
    });

    it('should reject deeply nested folder chain exceeding MAX_FOLDER_NESTING_DEPTH via $graphLookup', async () => {
      // Create a chain of 51 folders directly in DB
      const folderIds: string[] = [];
      for (let i = 0; i < 51; i++) {
        const folder = await Folder.create({
          userId: user.id,
          encryptedName: `gql-deep-${i}`,
          nameIv: `iv-${i}`,
          nameTag: `tag-${i}`,
          parentId: i > 0 ? folderIds[i - 1] : undefined,
        });
        folderIds.push(folder._id.toString());
      }

      // Try to create a new folder under the deepest folder
      const res = await agent
        .post(FOLDER_BASE)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({
          encryptedName: 'gql-too-deep',
          nameIv: 'iv',
          nameTag: 'tag',
          parentId: folderIds[folderIds.length - 1],
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should allow creating a folder at a valid nesting depth', async () => {
      const parent = await apiCreateFolder({ encryptedName: 'gql-vp' });
      const child = await apiCreateFolder({ encryptedName: 'gql-vc', parentId: parent._id });

      // Create grandchild — depth 3, well within limit
      const res = await agent
        .post(FOLDER_BASE)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({
          encryptedName: 'gql-grandchild',
          nameIv: 'iv',
          nameTag: 'tag',
          parentId: child._id,
        });

      expect(res.status).toBe(201);
    });
  });

  // ── 2.3b — updateFolder must bound the MOVED SUBTREE's depth ─────────
  // Re-parenting relocates a folder's entire descendant subtree, so the
  // deepest descendant lands at (parentDepth + subtreeHeight). Creation is
  // naturally bounded (a new folder has no descendants); a move is not — the
  // depth check must account for the moved folder's own subtree height.

  describe('Task 2.3b — updateFolder subtree-move depth', () => {
    /** Creates a parent→child chain of `length` folders; returns ids (root first). */
    async function buildChain(length: number, prefix: string): Promise<string[]> {
      const ids: string[] = [];
      for (let i = 0; i < length; i++) {
        const folder = await Folder.create({
          userId: user.id,
          encryptedName: `${prefix}-${String(i)}`,
          nameIv: `iv-${prefix}-${String(i)}`,
          nameTag: `tag-${prefix}-${String(i)}`,
          parentId: i > 0 ? ids[i - 1] : undefined,
        });
        ids.push(folder._id.toString());
      }
      return ids;
    }

    function putParent(folderId: string, parentId: string) {
      return agent
        .put(`${FOLDER_BASE}/${folderId}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({ parentId });
    }

    it('rejects moving a tall subtree under a mid-depth parent (parentDepth + subtreeHeight > MAX)', async () => {
      // Subtree of 31 levels rooted at sub[0] (sub[0] is a root) → height 31.
      const sub = await buildChain(31, 'sub');
      // Independent parent chain; parent[24] sits at depth 25.
      const parent = await buildChain(25, 'par');

      const res = await putParent(sub[0]!, parent[24]!);

      // 25 + 31 = 56 > 50 → must be rejected.
      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toContain('Maximum folder nesting depth exceeded');

      // The move must NOT have been applied — sub[0] stays a root.
      const moved = await Folder.findById(sub[0]!).lean();
      expect(moved!.parentId).toBeUndefined();
    });

    it('allows moving a tall subtree under a shallow parent (within MAX)', async () => {
      const sub = await buildChain(31, 'ok-sub'); // height 31
      const root = await buildChain(1, 'ok-root'); // depth 1

      const res = await putParent(sub[0]!, root[0]!);

      // 1 + 31 = 32 ≤ 50 → allowed.
      expect(res.status).toBe(200);
      expect(res.body.data.parentId).toBe(root[0]!);
    });

    it('enforces the exact depth cap on a subtree move (50 allowed, 51 rejected)', async () => {
      // Parent chain p[0..48]: p[47] at depth 48, p[48] at depth 49.
      const p = await buildChain(49, 'cap');
      // Two-level subtree (height 2) rooted at s[0].
      const s = await buildChain(2, 'leaf');

      // 48 + 2 = 50 → boundary allowed (deepest leaf lands exactly at depth 50).
      const allowRes = await putParent(s[0]!, p[47]!);
      expect(allowRes.status).toBe(200);

      // 49 + 2 = 51 → boundary rejected.
      const rejectRes = await putParent(s[0]!, p[48]!);
      expect(rejectRes.status).toBe(400);
      expect(rejectRes.body.message).toContain('Maximum folder nesting depth exceeded');
    });
  });
});
