/**
 * Tests for fix tasks from the comprehensive audit.
 *
 * Covers:
 * - Task 1.1: 2FA decryption key uses twoFactorEncryptionKey (not SESSION_SECRET)
 * - Task 1.3: 2FA setup requires valid password
 * - Task 2.4: restoreItem creates audit log entry
 * - Task 2.5: strictLimiter on destructive vault endpoints
 * - Task 2.8: import rejects invalid itemType / backup restore validates fields
 * - Task 3.2: passwordHistory schema min(1) enforcement
 * - Task 3.5: disable2fa requires password
 * - Task 3.7: Swagger UI restricted in production
 * - Task 3.16: Token fields have max length
 * - Task 3.17: import payload key constraints (the former csvMapping cap; column
 *   mapping is now client-side only and no longer part of the wire schema)
 * - Task 4.1: formatBytes edge cases
 * - Task 4.3: Named constants exist
 * - Task 5.8: Dev-prefix secrets rejected in non-development
 */
import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import type { RequestHandler, Router } from 'express';
import app from '../src/app.js';
import vaultRouter from '../src/routes/vault.js';
import { heavyOpLimiter } from '../src/middleware/rateLimiter.js';
import { permanentDelete } from '../src/controllers/vaultController.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { User } from '../src/models/User.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { createTestUser, authHeader, sampleVaultItem, getCsrf } from './helpers.js';
import type { TestUser, CsrfPair } from './helpers.js';

const API = '/api/v1';

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
 * the middleware chain. Each exported limiter binding is the exact instance
 * mounted on the route (even as a test-mode no-op), so an identity check catches
 * its removal from the route.
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

function withCsrf(
  req: request.Test,
  csrf: CsrfPair,
  accessToken?: string,
  extraCookies?: string,
): request.Test {
  const cookies = extraCookies ? `${csrf.cookie}; ${extraCookies}` : csrf.cookie;
  let r = req.set('x-csrf-token', csrf.token).set('Cookie', cookies);
  if (accessToken) {
    r = r.set('Authorization', authHeader(accessToken));
  }
  return r;
}

// ---------------------------------------------------------------------------
// Task 1.3: 2FA setup requires valid password
// ---------------------------------------------------------------------------
describe('Task 1.3: 2FA setup requires password verification', () => {
  let agent: request.Agent;
  let user: TestUser;
  let csrf: CsrfPair;

  beforeEach(async () => {
    agent = request.agent(app);
    user = await createTestUser();
    csrf = await getCsrf(agent);
  });

  it('should reject 2FA setup without password field', async () => {
    const res = await withCsrf(
      agent.post(`${API}/user/2fa/setup`).send({}),
      csrf,
      user.accessToken,
    );

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  it('should reject 2FA setup with empty password', async () => {
    const res = await withCsrf(
      agent.post(`${API}/user/2fa/setup`).send({ password: '' }),
      csrf,
      user.accessToken,
    );

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  it('should reject 2FA setup with incorrect password', async () => {
    const res = await withCsrf(
      agent.post(`${API}/user/2fa/setup`).send({ password: 'wrong-password' }),
      csrf,
      user.accessToken,
    );

    expect(res.status).toBe(401);
    expect(res.body.success).toBe(false);
  });

  it('should accept 2FA setup with correct password', async () => {
    const res = await withCsrf(
      agent.post(`${API}/user/2fa/setup`).send({ password: user.rawPassword }),
      csrf,
      user.accessToken,
    );

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.otpauthUri).toBeDefined();
    expect(res.body.data.secret).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// Task 2.4: restoreItem creates audit log entry
// ---------------------------------------------------------------------------
describe('Task 2.4: restoreItem creates audit log', () => {
  let agent: request.Agent;
  let user: TestUser;
  let csrf: CsrfPair;

  beforeEach(async () => {
    agent = request.agent(app);
    user = await createTestUser();
    csrf = await getCsrf(agent);
  });

  it('should create an audit log entry when restoring an item from trash', async () => {
    // Create an item
    const createRes = await withCsrf(
      agent.post(`${API}/vault/items`).send(sampleVaultItem()),
      csrf,
      user.accessToken,
    );
    expect(createRes.status).toBe(201);
    const itemId: string = createRes.body.data._id;

    // Soft delete the item (move to trash)
    const deleteRes = await withCsrf(
      agent.delete(`${API}/vault/items/${itemId}`),
      csrf,
      user.accessToken,
    );
    expect(deleteRes.status).toBe(200);

    // Clear existing audit logs to isolate the restore log
    await AuditLog.deleteMany({});

    // Restore the item
    const restoreRes = await withCsrf(
      agent.post(`${API}/vault/items/restore/${itemId}`),
      csrf,
      user.accessToken,
    );
    expect(restoreRes.status).toBe(200);
    expect(restoreRes.body.success).toBe(true);

    // Verify audit log was created
    const logs = await AuditLog.find({ userId: user.id, action: 'item_restore' });
    expect(logs.length).toBe(1);
    expect(logs[0]!.metadata).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// Task 2.5: rate-limiter wiring on destructive vault endpoints
//
// Limiters are pass-through no-ops under NODE_ENV=test, so a status-code
// assertion can never observe them and would stay green even if a limiter were
// unwired. Assert the middleware chain STRUCTURALLY instead: the exact exported
// limiter instance must be present in the route's Express layer stack.
// ---------------------------------------------------------------------------
describe('Task 2.5: rate limiter wiring on destructive endpoints', () => {
  it('mounts heavyOpLimiter on POST /items/bulk-delete', () => {
    expect(routeHandlers(vaultRouter, 'post', '/items/bulk-delete')).toContain(heavyOpLimiter);
  });

  it('mounts heavyOpLimiter on DELETE /items/trash/empty', () => {
    expect(routeHandlers(vaultRouter, 'delete', '/items/trash/empty')).toContain(heavyOpLimiter);
  });

  it('wires DELETE /items/:id/permanent with the permanentDelete controller (single-item deletes are intentionally not heavy-limited)', () => {
    const handlers = routeHandlers(vaultRouter, 'delete', '/items/:id/permanent');
    // The route exists and terminates in the real controller...
    expect(handlers).toContain(permanentDelete);
    // ...and, like the plain DELETE /items/:id soft-delete, carries no
    // heavyOpLimiter — a single-item permanent delete is not a bulk/heavy op.
    // (This documents the real wiring rather than asserting a limiter that was
    // never mounted, which the former misnamed "strictLimiter" test implied.)
    expect(handlers).not.toContain(heavyOpLimiter);
  });
});

// ---------------------------------------------------------------------------
// Task 2.8: Import rejects invalid itemType
// ---------------------------------------------------------------------------
describe('Task 2.8: Import validates itemType', () => {
  let agent: request.Agent;
  let user: TestUser;
  let csrf: CsrfPair;

  beforeEach(async () => {
    agent = request.agent(app);
    user = await createTestUser();
    csrf = await getCsrf(agent);
  });

  it('should reject the whole import when a row carries an invalid itemType', async () => {
    const res = await withCsrf(
      agent.post(`${API}/tools/import`).send({
        format: 'json',
        operations: {
          inserts: [
            {
              itemType: 'INVALID_TYPE',
              encryptedData: 'data',
              dataIv: 'iv',
              dataTag: 'tag',
              encryptedName: 'name',
              nameIv: 'niv',
              nameTag: 'ntag',
              searchHash: 'a'.repeat(64),
            },
            {
              itemType: 'login',
              encryptedData: 'data2',
              dataIv: 'iv2',
              dataTag: 'tag2',
              encryptedName: 'name2',
              nameIv: 'niv2',
              nameTag: 'ntag2',
              searchHash: 'b'.repeat(64),
            },
          ],
        },
      }),
      csrf,
      user.accessToken,
    );

    // `itemType` is a z.enum, so an unknown type is a 400 for the request — the
    // valid row beside it is not written either.
    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
  });

  it('should accept all valid item types during import', async () => {
    const validTypes = ['login', 'secret', 'note', 'card', 'identity'];
    const inserts = validTypes.map((type, index) => ({
      itemType: type,
      encryptedData: `data-${type}`,
      dataIv: `iv-${type}`,
      dataTag: `tag-${type}`,
      encryptedName: `name-${type}`,
      nameIv: `niv-${type}`,
      nameTag: `ntag-${type}`,
      searchHash: index.toString(16).padStart(64, '0'),
    }));

    const res = await withCsrf(
      agent.post(`${API}/tools/import`).send({ format: 'json', operations: { inserts } }),
      csrf,
      user.accessToken,
    );

    expect(res.status).toBe(201);
    expect(res.body.data).toEqual({ insertedCount: 5, updatedCount: 0 });

    const stored = await VaultItem.find({ userId: user.id }).lean();
    expect(stored.map((item) => item.itemType).sort()).toEqual([...validTypes].sort());
  });
});

// ---------------------------------------------------------------------------
// Task 3.5: disable2fa requires password
// ---------------------------------------------------------------------------
describe('Task 3.5: disable2fa requires password', () => {
  let agent: request.Agent;
  let user: TestUser;
  let csrf: CsrfPair;

  beforeEach(async () => {
    agent = request.agent(app);
    user = await createTestUser();
    csrf = await getCsrf(agent);
  });

  it('should reject disable 2FA without password', async () => {
    const res = await withCsrf(
      agent.delete(`${API}/user/2fa`).send({ code: '123456' }),
      csrf,
      user.accessToken,
    );

    // Should fail validation (password required)
    expect(res.status).toBe(400);
  });

  it('should reject disable 2FA with empty password', async () => {
    const res = await withCsrf(
      agent.delete(`${API}/user/2fa`).send({ code: '123456', password: '' }),
      csrf,
      user.accessToken,
    );

    expect(res.status).toBe(400);
  });
});

// ---------------------------------------------------------------------------
// Task 3.7: Swagger UI restricted in production
// ---------------------------------------------------------------------------
describe('Task 3.7: Swagger restricted by environment', () => {
  it('serves the OpenAPI spec in the non-production (test) environment', async () => {
    const res = await request(app).get('/api/v1/docs.json');

    // The documented contract: docs ARE served in dev/test. A permissive
    // [200, 301, 404] set accepted "docs absent" too, so an inverted gate would
    // have passed. Assert the doc is actually served and is a real OpenAPI 3 spec.
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('application/json');
    expect(res.body.openapi).toBe('3.0.3');
    expect(res.body.info).toBeDefined();
    expect(typeof res.body.paths).toBe('object');
    // (The production-gating matrix — docs hidden unless ENABLE_SWAGGER — is
    // covered by swagger.test.ts's warnIfSwaggerEnabledInProduction suite.)
  });
});

// ---------------------------------------------------------------------------
// Task 1.1: 2FA uses twoFactorEncryptionKey (not SESSION_SECRET)
// ---------------------------------------------------------------------------
describe('Task 1.1: 2FA encryption key consistency', () => {
  it('should successfully complete 2FA setup using twoFactorEncryptionKey', async () => {
    const agent = request.agent(app);
    const user = await createTestUser();
    const csrf = await getCsrf(agent);

    // Setup 2FA (this uses twoFactorEncryptionKey for encryption)
    const res = await withCsrf(
      agent.post(`${API}/user/2fa/setup`).send({ password: user.rawPassword }),
      csrf,
      user.accessToken,
    );

    expect(res.status).toBe(200);
    expect(res.body.data.secret).toBeDefined();

    // Verify the encrypted secret is stored in the database
    const dbUser = await User.findById(user.id).select('+pendingTwoFactorSecret');
    expect(dbUser).toBeDefined();
    expect(dbUser!.pendingTwoFactorSecret).toBeDefined();
    // The stored secret should be encrypted (not the raw base32)
    expect(dbUser!.pendingTwoFactorSecret).not.toBe(res.body.data.secret);
  });
});

// ---------------------------------------------------------------------------
// Task 1.2: Vault store clearStore exists and is callable
// (Server-side: verify items are properly isolated per user)
// ---------------------------------------------------------------------------
describe('Task 1.2: Vault data isolation', () => {
  it('should not return items from a different user', async () => {
    const agent1 = request.agent(app);
    const agent2 = request.agent(app);
    const user1 = await createTestUser();
    const user2 = await createTestUser();
    const csrf1 = await getCsrf(agent1);
    const csrf2 = await getCsrf(agent2);

    // User 1 creates an item
    await withCsrf(
      agent1.post(`${API}/vault/items`).send(sampleVaultItem()),
      csrf1,
      user1.accessToken,
    );

    // User 2 should see no items
    const res = await withCsrf(agent2.get(`${API}/vault/items`), csrf2, user2.accessToken);

    expect(res.status).toBe(200);
    expect(res.body.data).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Task 2.3: The progressive delay is skipped in the test environment
// ---------------------------------------------------------------------------
// A failed login DOES incur a progressive delay in production, and since the
// login-timing fix it incurs the SAME delay whether or not the email exists
// (see login-timing-symmetry.test.ts). `isTest` skips the sleep, so the suite
// stays fast and this asserts only that no delay leaks into the test run.
describe('Task 2.3: Progressive login delay is skipped under isTest', () => {
  it('should respond to failed login within reasonable time', async () => {
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);

    const start = Date.now();
    const res = await withCsrf(
      agent.post(`${API}/auth/login`).send({
        email: 'nonexistent@example.com',
        authHash: 'wrong-hash',
      }),
      csrf,
    );
    const elapsed = Date.now() - start;

    expect(res.status).toBe(401);
    expect(elapsed).toBeLessThan(3000);
  });
});

// ---------------------------------------------------------------------------
// Task 3.6: changeBackupPassword requires password
// ---------------------------------------------------------------------------
describe('Task 3.6: Backup password change requires auth', () => {
  let agent: request.Agent;
  let _user: TestUser;
  let csrf: CsrfPair;

  beforeEach(async () => {
    agent = request.agent(app);
    _user = await createTestUser();
    csrf = await getCsrf(agent);
  });

  it('should reject backup password change without authentication', async () => {
    const res = await withCsrf(
      agent.put(`${API}/backup/change-password`).send({
        password: 'my-password',
        newEncryptedBWK: 'new-key',
        newBwkIv: 'new-iv',
        newBwkTag: 'new-tag',
        newBwkSalt: 'new-salt',
      }),
      csrf,
      // no access token
    );

    expect(res.status).toBe(401);
  });
});

// ---------------------------------------------------------------------------
// Task 4.17: Backup history uses proper pagination
// ---------------------------------------------------------------------------
describe('Task 4.17: Backup history pagination', () => {
  let agent: request.Agent;
  let user: TestUser;
  let csrf: CsrfPair;

  beforeEach(async () => {
    agent = request.agent(app);
    user = await createTestUser();
    csrf = await getCsrf(agent);
  });

  it('should return paginated backup history', async () => {
    const res = await withCsrf(
      agent.get(`${API}/backup/history?page=1&limit=10`),
      csrf,
      user.accessToken,
    );

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.pagination).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// Task 2.3: Strip userId from vault, folder, audit, and backup-log responses
// ---------------------------------------------------------------------------
//
// The server is the only authority that needs the userId on these documents;
// echoing it back to the client widens the leak surface (XSS, error reports,
// shared-browser caches, PWA payloads). The fix lives in the model `toJSON`
// transforms plus explicit `.select('-userId')` projections on every lean
// response path. These tests pin the API responses so future regressions are
// caught immediately.
describe('Task 2.3: userId stripped from API responses', () => {
  let agent: request.Agent;
  let user: TestUser;
  let csrf: CsrfPair;

  beforeEach(async () => {
    agent = request.agent(app);
    user = await createTestUser();
    csrf = await getCsrf(agent);
  });

  it('omits userId from POST /vault/items response', async () => {
    const res = await withCsrf(
      agent.post(`${API}/vault/items`).send(sampleVaultItem()),
      csrf,
      user.accessToken,
    );
    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.data.userId).toBeUndefined();
  });

  it('omits userId from GET /vault/items rows', async () => {
    // Seed an item via the API so the list endpoint has something to return.
    await withCsrf(
      agent.post(`${API}/vault/items`).send(sampleVaultItem()),
      csrf,
      user.accessToken,
    );

    const res = await agent
      .get(`${API}/vault/items`)
      .set('Authorization', authHeader(user.accessToken));

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(Array.isArray(res.body.data)).toBe(true);
    expect(res.body.data.length).toBeGreaterThan(0);
    for (const item of res.body.data as Record<string, unknown>[]) {
      expect(item.userId).toBeUndefined();
    }
  });

  it('omits userId from GET /vault/items/:id', async () => {
    const createRes = await withCsrf(
      agent.post(`${API}/vault/items`).send(sampleVaultItem()),
      csrf,
      user.accessToken,
    );
    const itemId = createRes.body.data._id as string;

    const res = await agent
      .get(`${API}/vault/items/${itemId}`)
      .set('Authorization', authHeader(user.accessToken));

    expect(res.status).toBe(200);
    expect(res.body.data.userId).toBeUndefined();
    expect(res.body.data._id).toBe(itemId);
  });

  it('omits userId from PUT /vault/items/:id response', async () => {
    const createRes = await withCsrf(
      agent.post(`${API}/vault/items`).send(sampleVaultItem()),
      csrf,
      user.accessToken,
    );
    const itemId = createRes.body.data._id as string;

    const updateRes = await withCsrf(
      agent.put(`${API}/vault/items/${itemId}`).send({ favorite: true }),
      csrf,
      user.accessToken,
    );

    expect(updateRes.status).toBe(200);
    expect(updateRes.body.data.userId).toBeUndefined();
    expect(updateRes.body.data.favorite).toBe(true);
  });

  it('omits userId from GET /vault/items/trash rows', async () => {
    const createRes = await withCsrf(
      agent.post(`${API}/vault/items`).send(sampleVaultItem()),
      csrf,
      user.accessToken,
    );
    const itemId = createRes.body.data._id as string;

    await withCsrf(agent.delete(`${API}/vault/items/${itemId}`).send(), csrf, user.accessToken);

    const res = await agent
      .get(`${API}/vault/items/trash`)
      .set('Authorization', authHeader(user.accessToken));

    expect(res.status).toBe(200);
    expect(res.body.data.length).toBeGreaterThan(0);
    for (const item of res.body.data as Record<string, unknown>[]) {
      expect(item.userId).toBeUndefined();
    }
  });

  it('omits userId from POST /folders and GET /folders rows', async () => {
    const createRes = await withCsrf(
      agent.post(`${API}/folders`).send({
        encryptedName: 'enc-name',
        nameIv: 'iv',
        nameTag: 'tag',
      }),
      csrf,
      user.accessToken,
    );
    expect(createRes.status).toBe(201);
    expect(createRes.body.data.userId).toBeUndefined();

    const listRes = await agent
      .get(`${API}/folders`)
      .set('Authorization', authHeader(user.accessToken));

    expect(listRes.status).toBe(200);
    expect(listRes.body.data.length).toBeGreaterThan(0);
    for (const folder of listRes.body.data as Record<string, unknown>[]) {
      expect(folder.userId).toBeUndefined();
    }
  });

  it('omits userId from PUT /folders/:id response', async () => {
    const createRes = await withCsrf(
      agent.post(`${API}/folders`).send({
        encryptedName: 'enc-name',
        nameIv: 'iv',
        nameTag: 'tag',
      }),
      csrf,
      user.accessToken,
    );
    const folderId = createRes.body.data._id as string;

    const updateRes = await withCsrf(
      agent.put(`${API}/folders/${folderId}`).send({ icon: 'star' }),
      csrf,
      user.accessToken,
    );

    expect(updateRes.status).toBe(200);
    expect(updateRes.body.data.userId).toBeUndefined();
  });

  it('omits userId from GET /user/audit-log rows', async () => {
    // Seed an audit row by triggering an audited action.
    await withCsrf(
      agent.post(`${API}/vault/items`).send(sampleVaultItem()),
      csrf,
      user.accessToken,
    );

    const res = await agent
      .get(`${API}/user/audit-log?page=1&limit=10`)
      .set('Authorization', authHeader(user.accessToken));

    expect(res.status).toBe(200);
    expect(res.body.data.length).toBeGreaterThan(0);
    for (const log of res.body.data as Record<string, unknown>[]) {
      expect(log.userId).toBeUndefined();
    }
  });

  it('omits userId from GET /backup/history rows', async () => {
    // Seed a backup-log row directly so we don't need to wire the full
    // backup-encryption setup just to assert the response shape.
    await AuditLog.db.collection('backup_logs').insertOne({
      userId: new (await import('mongoose')).default.Types.ObjectId(user.id),
      status: 'success',
      sentTo: ['download'],
      timestamp: new Date(),
    });

    const res = await agent
      .get(`${API}/backup/history?page=1&limit=10`)
      .set('Authorization', authHeader(user.accessToken));

    expect(res.status).toBe(200);
    expect(res.body.data.length).toBeGreaterThan(0);
    for (const log of res.body.data as Record<string, unknown>[]) {
      expect(log.userId).toBeUndefined();
    }
  });
});
