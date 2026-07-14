import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import type { RequestHandler, Router } from 'express';
import app from '../src/app.js';
import userRouter from '../src/routes/user.js';
import folderRouter from '../src/routes/folders.js';
import authRouter from '../src/routes/auth.js';
import { generalAuthLimiter } from '../src/middleware/rateLimiter.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { BackupLog } from '../src/models/BackupLog.js';
import { createTestUser, authHeader, sampleVaultItem, getCsrf as getCsrfBase } from './helpers.js';
import type { TestUser } from './helpers.js';

interface RouteLayer {
  route?: {
    path: string;
    methods: Record<string, boolean>;
    stack: { handle: RequestHandler }[];
  };
}

/**
 * Ordered handler functions mounted on the `method` + `path` route of a Router.
 * Rate limiters are pass-through no-ops outside production, so their presence
 * cannot be observed behaviourally in the test env — assert it structurally on
 * the middleware chain instead. The exported limiter binding is the exact
 * instance mounted on the route (even as a test-mode no-op), so an identity
 * check catches its removal from the route.
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

async function getCsrf(
  agent: request.SuperTest<request.Test>,
): Promise<{ csrfToken: string; csrfCookie: string }> {
  const { token, cookie } = await getCsrfBase(agent);
  return { csrfToken: token, csrfCookie: cookie };
}

const bwkSetupData = {
  encryptedBWK: 'test-encrypted-bwk-data',
  bwkIv: 'test-bwk-iv-value',
  bwkTag: 'test-bwk-tag-value',
  bwkSalt: 'test-bwk-salt-value',
};

async function setupBackupForUser(
  agent: request.SuperTest<request.Test>,
  token: string,
  rawAuthHash = 'test-auth-hash-value',
) {
  const { csrfToken, csrfCookie } = await getCsrf(agent);
  await agent
    .post('/api/v1/backup/setup')
    .set('Authorization', authHeader(token))
    .set('x-csrf-token', csrfToken)
    .set('Cookie', csrfCookie)
    .send({ ...bwkSetupData, authHash: rawAuthHash });
}

// ── Tests ────────────────────────────────────────────────────────────

describe('Phase 2: Security Hardening', () => {
  let user: TestUser;
  let agent: request.SuperTest<request.Test>;

  beforeEach(async () => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    user = await createTestUser();
  });

  // ── Task 2.1: Validate Import Data Field Formats ──────────────────

  describe('Task 2.1: Import field format validation', () => {
    describe('searchHash validation', () => {
      it('should strip malformed searchHash (not 64-char hex)', async () => {
        const { csrfToken, csrfCookie } = await getCsrf(agent);

        const importData = JSON.stringify({
          items: [sampleVaultItem({ searchHash: 'not-a-valid-hash!' })],
        });

        const res = await agent
          .post('/api/v1/tools/import')
          .set('Authorization', authHeader(user.accessToken))
          .set('x-csrf-token', csrfToken)
          .set('Cookie', csrfCookie)
          .send({ format: 'json', data: importData });

        expect(res.status).toBe(201);
        expect(res.body.data.importedCount).toBe(1);

        const item = await VaultItem.findOne({ userId: user.id });
        expect(item?.searchHash).toBeUndefined();
      });

      it('should accept valid 64-char lowercase hex searchHash', async () => {
        const { csrfToken, csrfCookie } = await getCsrf(agent);
        const validHash = 'a'.repeat(64);

        const importData = JSON.stringify({
          items: [sampleVaultItem({ searchHash: validHash })],
        });

        const res = await agent
          .post('/api/v1/tools/import')
          .set('Authorization', authHeader(user.accessToken))
          .set('x-csrf-token', csrfToken)
          .set('Cookie', csrfCookie)
          .send({ format: 'json', data: importData });

        expect(res.status).toBe(201);

        const item = await VaultItem.findOne({ userId: user.id });
        expect(item?.searchHash).toBe(validHash);
      });

      it('should strip searchHash with uppercase chars', async () => {
        const { csrfToken, csrfCookie } = await getCsrf(agent);
        // The regex requires lowercase: /^[a-f0-9]{64}$/
        const upperHash = 'A'.repeat(64);

        const importData = JSON.stringify({
          items: [sampleVaultItem({ searchHash: upperHash })],
        });

        const res = await agent
          .post('/api/v1/tools/import')
          .set('Authorization', authHeader(user.accessToken))
          .set('x-csrf-token', csrfToken)
          .set('Cookie', csrfCookie)
          .send({ format: 'json', data: importData });

        expect(res.status).toBe(201);

        const item = await VaultItem.findOne({ userId: user.id });
        expect(item?.searchHash).toBeUndefined();
      });

      it('should strip searchHash that is too short', async () => {
        const { csrfToken, csrfCookie } = await getCsrf(agent);

        const importData = JSON.stringify({
          items: [sampleVaultItem({ searchHash: 'abcdef' })],
        });

        const res = await agent
          .post('/api/v1/tools/import')
          .set('Authorization', authHeader(user.accessToken))
          .set('x-csrf-token', csrfToken)
          .set('Cookie', csrfCookie)
          .send({ format: 'json', data: importData });

        expect(res.status).toBe(201);

        const item = await VaultItem.findOne({ userId: user.id });
        expect(item?.searchHash).toBeUndefined();
      });
    });

    describe('tags validation', () => {
      it('should strip tags longer than 50 characters', async () => {
        const { csrfToken, csrfCookie } = await getCsrf(agent);
        const longTag = 'x'.repeat(51);

        const importData = JSON.stringify({
          items: [sampleVaultItem({ tags: ['valid-tag', longTag] })],
        });

        const res = await agent
          .post('/api/v1/tools/import')
          .set('Authorization', authHeader(user.accessToken))
          .set('x-csrf-token', csrfToken)
          .set('Cookie', csrfCookie)
          .send({ format: 'json', data: importData });

        expect(res.status).toBe(201);

        const item = await VaultItem.findOne({ userId: user.id });
        expect(item?.tags).toEqual(['valid-tag']);
      });

      it('should limit tags array to 20 items', async () => {
        const { csrfToken, csrfCookie } = await getCsrf(agent);
        const tags = Array.from({ length: 25 }, (_, i) => `tag-${String(i)}`);

        const importData = JSON.stringify({
          items: [sampleVaultItem({ tags })],
        });

        const res = await agent
          .post('/api/v1/tools/import')
          .set('Authorization', authHeader(user.accessToken))
          .set('x-csrf-token', csrfToken)
          .set('Cookie', csrfCookie)
          .send({ format: 'json', data: importData });

        expect(res.status).toBe(201);

        const item = await VaultItem.findOne({ userId: user.id });
        expect(item?.tags).toHaveLength(20);
      });

      it('should strip empty tags after trimming', async () => {
        const { csrfToken, csrfCookie } = await getCsrf(agent);

        const importData = JSON.stringify({
          items: [sampleVaultItem({ tags: ['valid', '   ', ''] })],
        });

        const res = await agent
          .post('/api/v1/tools/import')
          .set('Authorization', authHeader(user.accessToken))
          .set('x-csrf-token', csrfToken)
          .set('Cookie', csrfCookie)
          .send({ format: 'json', data: importData });

        expect(res.status).toBe(201);

        const item = await VaultItem.findOne({ userId: user.id });
        expect(item?.tags).toEqual(['valid']);
      });

      it('should filter non-string tags', async () => {
        const { csrfToken, csrfCookie } = await getCsrf(agent);

        const importData = JSON.stringify({
          items: [sampleVaultItem({ tags: ['valid', 123, null, true] })],
        });

        const res = await agent
          .post('/api/v1/tools/import')
          .set('Authorization', authHeader(user.accessToken))
          .set('x-csrf-token', csrfToken)
          .set('Cookie', csrfCookie)
          .send({ format: 'json', data: importData });

        expect(res.status).toBe(201);

        const item = await VaultItem.findOne({ userId: user.id });
        expect(item?.tags).toEqual(['valid']);
      });
    });

    describe('folderId validation', () => {
      it('should strip folderId that is not a valid ObjectId format', async () => {
        const { csrfToken, csrfCookie } = await getCsrf(agent);

        const importData = JSON.stringify({
          items: [sampleVaultItem({ folderId: 'not-an-objectid' })],
        });

        const res = await agent
          .post('/api/v1/tools/import')
          .set('Authorization', authHeader(user.accessToken))
          .set('x-csrf-token', csrfToken)
          .set('Cookie', csrfCookie)
          .send({ format: 'json', data: importData });

        expect(res.status).toBe(201);

        const item = await VaultItem.findOne({ userId: user.id });
        expect(item?.folderId).toBeUndefined();
      });

      it('should strip folderId with valid format but not belonging to user', async () => {
        const { csrfToken, csrfCookie } = await getCsrf(agent);
        // Valid ObjectId format but doesn't exist in DB
        const fakeFolderId = 'aabbccddeeff112233445566';

        const importData = JSON.stringify({
          items: [sampleVaultItem({ folderId: fakeFolderId })],
        });

        const res = await agent
          .post('/api/v1/tools/import')
          .set('Authorization', authHeader(user.accessToken))
          .set('x-csrf-token', csrfToken)
          .set('Cookie', csrfCookie)
          .send({ format: 'json', data: importData });

        expect(res.status).toBe(201);

        const item = await VaultItem.findOne({ userId: user.id });
        expect(item?.folderId).toBeUndefined();
      });

      it('should accept folderId with valid format belonging to user', async () => {
        const { csrfToken, csrfCookie } = await getCsrf(agent);

        // Create a folder for this user
        const folder = await Folder.create({
          userId: user.id,
          encryptedName: 'test-folder',
          nameIv: 'iv',
          nameTag: 'tag',
        });
        const folderId = folder._id.toString();

        const importData = JSON.stringify({
          items: [sampleVaultItem({ folderId })],
        });

        const res = await agent
          .post('/api/v1/tools/import')
          .set('Authorization', authHeader(user.accessToken))
          .set('x-csrf-token', csrfToken)
          .set('Cookie', csrfCookie)
          .send({ format: 'json', data: importData });

        expect(res.status).toBe(201);

        const item = await VaultItem.findOne({ userId: user.id });
        expect(String(item?.folderId)).toBe(folderId);
      });
    });

    describe('non-JSON format validation', () => {
      it('should sanitize fields for bitwarden format imports', async () => {
        const { csrfToken, csrfCookie } = await getCsrf(agent);

        const importData = JSON.stringify({
          items: [
            sampleVaultItem({
              searchHash: 'INVALID',
              tags: ['x'.repeat(51), 'valid'],
              folderId: 'bad-id',
            }),
          ],
        });

        const res = await agent
          .post('/api/v1/tools/import')
          .set('Authorization', authHeader(user.accessToken))
          .set('x-csrf-token', csrfToken)
          .set('Cookie', csrfCookie)
          .send({ format: 'bitwarden', data: importData });

        expect(res.status).toBe(201);

        const item = await VaultItem.findOne({ userId: user.id });
        expect(item?.searchHash).toBeUndefined();
        expect(item?.tags).toEqual(['valid']);
        expect(item?.folderId).toBeUndefined();
      });
    });
  });

  // ── Task 2.2: BackupLog Entry for Downloads ───────────────────────

  describe('Task 2.2: Backup download creates BackupLog', () => {
    it('should create a BackupLog entry on download', async () => {
      await setupBackupForUser(agent, user.accessToken);

      const res = await agent
        .get('/api/v1/backup/download')
        .set('Authorization', authHeader(user.accessToken));

      expect(res.status).toBe(200);

      const logs = await BackupLog.find({ userId: user.id });
      expect(logs).toHaveLength(1);
      expect(logs[0]!.status).toBe('success');
      expect(logs[0]!.sentTo).toEqual(['download']);
      expect(logs[0]!.fileSizeBytes).toBeGreaterThan(0);
      expect(logs[0]!.itemCount).toBeDefined();
    });

    it('should include download BackupLog in backup history', async () => {
      await setupBackupForUser(agent, user.accessToken);

      // Trigger a download
      await agent.get('/api/v1/backup/download').set('Authorization', authHeader(user.accessToken));

      // Check history
      const res = await agent
        .get('/api/v1/backup/history?page=1&limit=10')
        .set('Authorization', authHeader(user.accessToken));

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(1);
      expect(res.body.data[0].sentTo).toEqual(['download']);
    });

    it('should include item count in download BackupLog', async () => {
      await setupBackupForUser(agent, user.accessToken);

      // Create some items
      const { csrfToken, csrfCookie } = await getCsrf(agent);
      await agent
        .post('/api/v1/vault/items')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send(sampleVaultItem());

      await agent.get('/api/v1/backup/download').set('Authorization', authHeader(user.accessToken));

      const log = await BackupLog.findOne({ userId: user.id });
      expect(log?.itemCount).toBe(1);
    });
  });

  // ── Task 2.3: Rate Limiting on Read-Heavy Endpoints ───────────────

  describe('Task 2.3: generalAuthLimiter middleware presence', () => {
    // Rate limiters are pass-through no-ops outside production, so a 200 in the
    // test env proves only that the (no-op) chain does not break the route — it
    // CANNOT detect the limiter being removed from the route (a removed limiter
    // is also a no-op in test). Each test therefore pairs the behavioural 200
    // smoke with a STRUCTURAL assertion that `generalAuthLimiter` is actually
    // mounted on the route's middleware chain.

    it('should have generalAuthLimiter on GET /user/profile', async () => {
      expect(routeHandlers(userRouter, 'get', '/profile')).toContain(generalAuthLimiter);

      const res = await agent
        .get('/api/v1/user/profile')
        .set('Authorization', authHeader(user.accessToken));
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('should have generalAuthLimiter on GET /user/sessions', async () => {
      expect(routeHandlers(userRouter, 'get', '/sessions')).toContain(generalAuthLimiter);

      const res = await agent
        .get('/api/v1/user/sessions')
        .set('Authorization', authHeader(user.accessToken));
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('should have generalAuthLimiter on GET /user/audit-log', async () => {
      expect(routeHandlers(userRouter, 'get', '/audit-log')).toContain(generalAuthLimiter);

      const res = await agent
        .get('/api/v1/user/audit-log?page=1&limit=20')
        .set('Authorization', authHeader(user.accessToken));
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('should have generalAuthLimiter on GET /folders', async () => {
      expect(routeHandlers(folderRouter, 'get', '/')).toContain(generalAuthLimiter);

      const res = await agent
        .get('/api/v1/folders')
        .set('Authorization', authHeader(user.accessToken));
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('should have generalAuthLimiter on POST /auth/lock, /logout, /logout-all (previously unlimited)', async () => {
      // These state-changing routes run generalAuthLimiter AFTER authenticate
      // (which supplies the per-user key). Assert it is mounted on all three.
      for (const path of ['/lock', '/logout', '/logout-all']) {
        expect(routeHandlers(authRouter, 'post', path)).toContain(generalAuthLimiter);
      }

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/auth/lock')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie);
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('mounts generalAuthLimiter AFTER authenticate on POST /auth/lock (userId-keyed order)', () => {
      // The limiter is keyed by userId, so it must run after `authenticate`
      // populates req.user. Verify the relative order in the chain.
      const handlers = routeHandlers(authRouter, 'post', '/lock');
      const limiterIdx = handlers.indexOf(generalAuthLimiter);
      expect(limiterIdx).toBeGreaterThan(0); // something (authenticate) precedes it
      expect(handlers.length).toBeGreaterThanOrEqual(2);
    });
  });
});
