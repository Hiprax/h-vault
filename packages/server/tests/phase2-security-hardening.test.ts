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
import {
  createTestUser,
  authHeader,
  sampleVaultItem,
  seedItem,
  getCsrf as getCsrfBase,
} from './helpers.js';
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

/** A well-formed 64-char lowercase-hex searchHash — required on every import row. */
const VALID_SEARCH_HASH = 'a'.repeat(64);

/**
 * One `operations.inserts` row: the shared sample item plus the `searchHash`
 * the import contract requires on every insert.
 */
function importInsert(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return sampleVaultItem({ searchHash: VALID_SEARCH_HASH, ...overrides });
}

/** A structured import body carrying only inserts. */
function importBody(
  inserts: Record<string, unknown>[],
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return { format: 'json', operations: { inserts }, ...overrides };
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
    /** POSTs a structured import body with auth + a fresh CSRF pair. */
    async function postImport(body: Record<string, unknown>): Promise<request.Response> {
      const { csrfToken, csrfCookie } = await getCsrf(agent);
      return agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send(body);
    }

    describe('searchHash validation', () => {
      it('should reject a malformed searchHash (not 64-char hex) and write nothing', async () => {
        const res = await postImport(
          importBody([importInsert({ searchHash: 'not-a-valid-hash!' })]),
        );

        expect(res.status).toBe(400);
        expect(res.body.success).toBe(false);
        expect(res.body.message).toContain('searchHash');
        expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
      });

      it('should accept valid 64-char lowercase hex searchHash', async () => {
        const res = await postImport(importBody([importInsert()]));

        expect(res.status).toBe(201);
        expect(res.body.data).toEqual({ insertedCount: 1, updatedCount: 0 });

        const item = await VaultItem.findOne({ userId: user.id });
        expect(item).not.toBeNull();
        expect(item!.searchHash).toBe(VALID_SEARCH_HASH);
      });

      it('should reject a searchHash with uppercase chars', async () => {
        // The regex requires lowercase: /^[a-f0-9]{64}$/
        const res = await postImport(importBody([importInsert({ searchHash: 'A'.repeat(64) })]));

        expect(res.status).toBe(400);
        expect(res.body.message).toContain('searchHash');
        expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
      });

      it('should reject a searchHash that is too short', async () => {
        const res = await postImport(importBody([importInsert({ searchHash: 'abcdef' })]));

        expect(res.status).toBe(400);
        expect(res.body.message).toContain('searchHash');
        expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
      });

      it('should reject an insert that carries no searchHash at all', async () => {
        const insert = importInsert();
        delete insert.searchHash;

        const res = await postImport(importBody([insert]));

        expect(res.status).toBe(400);
        expect(res.body.message).toContain('searchHash');
        expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
      });

      it('should reject an update whose searchHash is malformed, leaving the target untouched', async () => {
        // An overwrite replaces `encryptedName`, so the stored hash must be
        // refreshed alongside it — a malformed one fails the whole request
        // rather than stranding the row against its old name.
        const existing = await seedItem(user.id, {
          encryptedName: 'update-target',
          searchHash: VALID_SEARCH_HASH,
        });

        const res = await postImport({
          format: 'json',
          operations: {
            updates: [
              {
                ...sampleVaultItem({ encryptedName: 'rewritten' }),
                id: String(existing._id),
                searchHash: 'nope',
              },
            ],
          },
        });

        expect(res.status).toBe(400);
        expect(res.body.message).toContain('searchHash');

        const persisted = await VaultItem.findById(String(existing._id));
        expect(persisted).not.toBeNull();
        expect(persisted!.encryptedName).toBe('update-target');
      });
    });

    describe('tags validation', () => {
      it('should reject a tag longer than 50 characters', async () => {
        const res = await postImport(
          importBody([importInsert({ tags: ['valid-tag', 'x'.repeat(51)] })]),
        );

        expect(res.status).toBe(400);
        expect(res.body.message).toContain('tags');
        expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
      });

      it('should reject more than 20 tags on one item', async () => {
        const tags = Array.from({ length: 25 }, (_, i) => `tag-${String(i)}`);

        const res = await postImport(importBody([importInsert({ tags })]));

        expect(res.status).toBe(400);
        expect(res.body.message).toContain('tags');
        expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
      });

      it('should reject a tag that is empty after trimming', async () => {
        const res = await postImport(importBody([importInsert({ tags: ['valid', '   '] })]));

        expect(res.status).toBe(400);
        expect(res.body.message).toContain('tags');
        expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
      });

      it('should reject a non-string tag', async () => {
        const res = await postImport(importBody([importInsert({ tags: ['valid', 123] })]));

        expect(res.status).toBe(400);
        expect(res.body.message).toContain('tags');
        expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
      });

      it('should trim surrounding whitespace off accepted tags', async () => {
        const res = await postImport(importBody([importInsert({ tags: ['  spaced  ', 'plain'] })]));

        expect(res.status).toBe(201);

        const item = await VaultItem.findOne({ userId: user.id });
        expect(item).not.toBeNull();
        expect(item!.tags).toEqual(['spaced', 'plain']);
      });
    });

    describe('folderId validation', () => {
      it('should reject a folderId that is not a valid ObjectId', async () => {
        const res = await postImport(importBody([importInsert({ folderId: 'not-an-objectid' })]));

        expect(res.status).toBe(400);
        expect(res.body.message).toContain('folderId');
        expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
      });

      it('should import at the vault root when the folderId belongs to another user', async () => {
        const other = await createTestUser();
        const foreignFolder = await Folder.create({
          userId: other.id,
          encryptedName: 'foreign-folder',
          nameIv: 'iv',
          nameTag: 'tag',
        });

        const res = await postImport(
          importBody([importInsert({ folderId: foreignFolder._id.toString() })]),
        );

        expect(res.status).toBe(201);

        const item = await VaultItem.findOne({ userId: user.id });
        expect(item).not.toBeNull();
        expect(item!.folderId).toBeUndefined();
        // Nothing landed in the other account's folder either.
        expect(await VaultItem.countDocuments({ folderId: foreignFolder._id })).toBe(0);
      });

      it('should accept a folderId belonging to the caller', async () => {
        const folder = await Folder.create({
          userId: user.id,
          encryptedName: 'test-folder',
          nameIv: 'iv',
          nameTag: 'tag',
        });
        const folderId = folder._id.toString();

        const res = await postImport(importBody([importInsert({ folderId })]));

        expect(res.status).toBe(201);

        const item = await VaultItem.findOne({ userId: user.id });
        expect(item).not.toBeNull();
        expect(String(item!.folderId)).toBe(folderId);
      });
    });

    describe('source-format independence', () => {
      it('should apply the same field validation to a bitwarden import', async () => {
        // `format` is audit metadata only: it never relaxes validation, so the
        // same malformed row is rejected whichever source it claims to be from.
        const res = await postImport(
          importBody([importInsert({ searchHash: 'INVALID', folderId: 'bad-id' })], {
            format: 'bitwarden',
          }),
        );

        expect(res.status).toBe(400);
        expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
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
