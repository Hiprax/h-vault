import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import mongoose, { Types } from 'mongoose';
import express from 'express';
import request from 'supertest';

/**
 * Coverage-driven suite for `app.ts` wiring, the backup e-mail delivery paths,
 * the folder duplicate-name (E11000 → 409) catches, and the migration runner's
 * un-exercised branches.
 *
 * Two production modules are substituted here, both for dependencies that are
 * genuinely external to the unit under test:
 *
 *  • `config/index.js` — only `emailConfigured` / `isProduction` are turned into
 *    live getters backed by mutable state. Everything else (including the
 *    `config` object identity) is the real module. `emailConfigured` is `false`
 *    in the test env, which is precisely why `triggerBackup`'s entire e-mail
 *    delivery block (partial failures, all-failed status, the per-recipient
 *    BackupLog error message) has never been executed by any suite.
 *  • `utils/email.js` — `sendEmail` is the SMTP boundary. Stubbing it lets us
 *    drive a deterministic partial-delivery failure; every assertion below is
 *    made against the HTTP response, the persisted BackupLog, the User document
 *    and the audit log — never against the stub alone.
 */

const cfgState = vi.hoisted(() => ({
  emailConfigured: false,
  isProduction: false,
}));

const { mockSendEmail } = vi.hoisted(() => ({
  mockSendEmail: vi.fn<(...args: unknown[]) => Promise<{ success: boolean; message: string }>>(),
}));

vi.mock('../src/config/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/config/index.js')>();
  cfgState.emailConfigured = actual.emailConfigured;
  cfgState.isProduction = actual.isProduction;
  return {
    ...actual,
    get emailConfigured() {
      return cfgState.emailConfigured;
    },
    get isProduction() {
      return cfgState.isProduction;
    },
  };
});

vi.mock('../src/utils/email.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/utils/email.js')>();
  return { ...actual, sendEmail: mockSendEmail };
});

import app from '../src/app.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { BackupLog } from '../src/models/BackupLog.js';
import { Folder } from '../src/models/Folder.js';
import { JobLock } from '../src/models/JobLock.js';
import { Migration } from '../src/models/Migration.js';
import { User } from '../src/models/User.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { getMetrics } from '../src/controllers/metricsController.js';
import { runMigrations, type MigrationDefinition } from '../src/utils/migrations.js';
import {
  authHeader,
  createTestUser,
  getCsrf,
  sampleFolder,
  sampleVaultItem,
  seedFolder,
  seedItem,
  type TestUser,
} from './helpers.js';

const BWK_SETUP = {
  encryptedBWK: 'test-encrypted-bwk-data',
  bwkIv: 'test-bwk-iv-value',
  bwkTag: 'test-bwk-tag-value',
  bwkSalt: 'test-bwk-salt-value',
};

/** 64 lowercase hex chars — the shape both Zod and the Folder model require. */
const hexHash = (seed: string): string =>
  seed
    .repeat(Math.ceil(64 / seed.length))
    .slice(0, 64)
    .toLowerCase();

const HASH_A = hexHash('a1b2c3d4');
const HASH_B = hexHash('9f8e7d6c');

type Agent = request.SuperTest<request.Test>;

async function post(
  agent: Agent,
  url: string,
  token: string,
  body: unknown,
): Promise<request.Response> {
  const { token: csrfToken, cookie } = await getCsrf(agent);
  return agent
    .post(url)
    .set('Authorization', authHeader(token))
    .set('x-csrf-token', csrfToken)
    .set('Cookie', cookie)
    .send(body as object);
}

async function put(
  agent: Agent,
  url: string,
  token: string,
  body: unknown,
): Promise<request.Response> {
  const { token: csrfToken, cookie } = await getCsrf(agent);
  return agent
    .put(url)
    .set('Authorization', authHeader(token))
    .set('x-csrf-token', csrfToken)
    .set('Cookie', cookie)
    .send(body as object);
}

async function del(agent: Agent, url: string, token: string): Promise<request.Response> {
  const { token: csrfToken, cookie } = await getCsrf(agent);
  return agent
    .delete(url)
    .set('Authorization', authHeader(token))
    .set('x-csrf-token', csrfToken)
    .set('Cookie', cookie);
}

async function configureBackup(agent: Agent, user: TestUser): Promise<void> {
  const res = await post(agent, '/api/v1/backup/setup', user.accessToken, {
    ...BWK_SETUP,
    authHash: user.rawPassword,
  });
  expect(res.status).toBe(200);
}

describe('app.ts / backup / folder / migrations — uncovered behaviour', () => {
  let agent: Agent;
  let user: TestUser;

  beforeEach(async () => {
    agent = request(app) as unknown as Agent;
    user = await createTestUser();
    cfgState.emailConfigured = false;
    cfgState.isProduction = false;
    mockSendEmail.mockReset();
    mockSendEmail.mockResolvedValue({ success: true, message: 'sent' });
  });

  // ── app.ts: CUSTOM_BODY_LIMIT_PATHS 30 MB override ────────────────────

  describe('body-size limits (app.ts CUSTOM_BODY_LIMIT_PATHS)', () => {
    it('rejects a >2 MB body on an ordinary route with 413 and writes nothing', async () => {
      const res = await post(agent, '/api/v1/vault/items', user.accessToken, {
        ...sampleVaultItem({ encryptedData: 'a'.repeat(2_500_000) }),
      });

      expect(res.status).toBe(413);
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
    });

    it('accepts the same >2 MB body on /backup/restore and actually restores it', async () => {
      // 7 × 400 KB ≈ 2.8 MB on the wire — comfortably over the global 2 MB
      // parser limit and comfortably under the route-level 30 MB one. Each row
      // is individually within MAX_ENCRYPTED_DATA_LENGTH (500 000).
      const items = Array.from({ length: 7 }, () => ({
        _id: new Types.ObjectId().toString(),
        itemType: 'login',
        encryptedData: 'b'.repeat(400_000),
        dataIv: 'test-data-iv',
        dataTag: 'test-data-tag',
        encryptedName: 'test-encrypted-name',
        nameIv: 'test-name-iv',
        nameTag: 'test-name-tag',
      }));
      const data = JSON.stringify({ items, folders: [] });
      expect(data.length).toBeGreaterThan(2 * 1024 * 1024);

      const res = await post(agent, '/api/v1/backup/restore', user.accessToken, {
        conflictStrategy: 'skip',
        data,
      });

      expect(res.status).toBe(200);
      expect(res.body.data.itemsRestored).toBe(7);
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(7);
    });
  });

  // ── app.ts: unknown route ─────────────────────────────────────────────

  it('returns 404 for an unmounted API path', async () => {
    const res = await agent.get('/api/v1/definitely-not-a-route');
    expect(res.status).toBe(404);
  });

  // ── app.ts: MongoDB operator-injection stripping ───────────────────────

  it('cannot be authenticated with a MongoDB operator-injection login body', async () => {
    const before = await AuditLog.countDocuments({ userId: user.id, action: 'login' });

    const res = await post(agent, '/api/v1/auth/login', '', {
      email: { $ne: null },
      authHash: { $ne: null },
    });

    // Operator keys are stripped from req.body before validation, so the body
    // can never reach Mongo as a query operator. It must never authenticate.
    expect(res.status).not.toBe(200);
    expect(res.body.success).toBe(false);
    const setCookie = res.headers['set-cookie'] as string[] | undefined;
    expect((setCookie ?? []).some((c) => c.toLowerCase().includes('refresh'))).toBe(false);
    expect(await AuditLog.countDocuments({ userId: user.id, action: 'login' })).toBe(before);
  });

  // ── healthController: the disconnected + production branches ───────────

  describe('healthController branches', () => {
    it('reports 503 / error / disconnected when mongoose is not connected', async () => {
      Object.defineProperty(mongoose.connection, 'readyState', {
        value: mongoose.ConnectionStates.disconnected,
        configurable: true,
      });
      try {
        const res = await agent.get('/api/v1/health');

        expect(res.status).toBe(503);
        expect(res.body.success).toBe(false);
        expect(res.body.data.status).toBe('error');
        expect(res.body.data.database).toBe('disconnected');
      } finally {
        // Remove the shadowing own-property; the prototype getter takes over.
        delete (mongoose.connection as unknown as Record<string, unknown>).readyState;
      }
      expect(mongoose.connection.readyState).toBe(mongoose.ConnectionStates.connected);
    });

    it('omits uptime and version from the health payload in production', async () => {
      cfgState.isProduction = true;
      try {
        const res = await agent.get('/api/v1/health');

        expect(res.status).toBe(200);
        expect(res.body.data.status).toBe('ok');
        // Build/runtime fingerprinting must not be handed to anonymous callers.
        expect(res.body.data.uptime).toBeUndefined();
        expect(res.body.data.version).toBeUndefined();
      } finally {
        cfgState.isProduction = false;
      }
    });
  });

  // ── metricsController: the disconnected branch ─────────────────────────

  it('reports database.state=disconnected in /metrics when mongoose is down', async () => {
    const { errorMiddleware } = await import('@hiprax/errors');
    const metricsApp = express();
    metricsApp.get('/metrics', getMetrics);
    metricsApp.use(errorMiddleware);

    Object.defineProperty(mongoose.connection, 'readyState', {
      value: mongoose.ConnectionStates.disconnected,
      configurable: true,
    });
    try {
      const res = await request(metricsApp).get('/metrics');

      expect(res.status).toBe(200);
      expect(res.body.data.database.state).toBe('disconnected');
      expect(res.body.data.database.readyState).toBe(0);
    } finally {
      delete (mongoose.connection as unknown as Record<string, unknown>).readyState;
    }
  });

  // ── backupController: e-mail delivery outcomes ─────────────────────────

  describe('POST /api/v1/backup/trigger — e-mail delivery', () => {
    it('records a partial delivery failure in the response, the BackupLog and the audit log', async () => {
      await configureBackup(agent, user);
      await put(agent, '/api/v1/backup/settings', user.accessToken, {
        backupEmails: ['good@example.com', 'bad@example.com'],
      });
      await seedItem(user.id);

      cfgState.emailConfigured = true;
      mockSendEmail.mockImplementation((to: unknown) =>
        Promise.resolve(
          to === 'bad@example.com'
            ? { success: false, message: 'smtp_send_failed: mailbox full' }
            : { success: true, message: 'sent' },
        ),
      );

      const res = await post(agent, '/api/v1/backup/trigger', user.accessToken, {});

      expect(res.status).toBe(200);
      expect(res.body.message).toBe('Backup created. Sent to 1/2 recipients');
      expect(res.body.data).toMatchObject({
        emailSent: true,
        emailsSent: 1,
        emailsFailed: 1,
        failedEmails: ['bad@example.com'],
        itemCount: 1,
      });

      const log = await BackupLog.findOne({ userId: user.id }).lean();
      expect(log?.status).toBe('success');
      expect(log?.sentTo).toEqual(['good@example.com', 'bad@example.com']);
      expect(log?.errorMessage).toBe('Email delivery failed for: bad@example.com');

      const dbUser = await User.findById(user.id).lean();
      expect(dbUser?.settings.backup.lastBackupStatus).toBe('success');
      expect(dbUser?.settings.backup.lastBackupAt).toBeInstanceOf(Date);

      const audit = await AuditLog.findOne({ userId: user.id, action: 'backup_triggered' }).lean();
      expect(audit?.metadata).toMatchObject({ emailSent: true, emailsSent: 1, emailsFailed: 1 });
    });

    it('marks the backup failed when every recipient delivery fails', async () => {
      await configureBackup(agent, user);
      await put(agent, '/api/v1/backup/settings', user.accessToken, {
        backupEmails: ['a@example.com', 'b@example.com'],
      });

      cfgState.emailConfigured = true;
      mockSendEmail.mockResolvedValue({ success: false, message: 'transporter_not_configured' });

      const res = await post(agent, '/api/v1/backup/trigger', user.accessToken, {});

      expect(res.status).toBe(200);
      expect(res.body.message).toBe('Backup created but all email deliveries failed');
      expect(res.body.data).toMatchObject({
        emailSent: false,
        emailsSent: 0,
        emailsFailed: 2,
        failedEmails: ['a@example.com', 'b@example.com'],
      });

      const log = await BackupLog.findOne({ userId: user.id }).lean();
      expect(log?.status).toBe('failed');
      expect(log?.errorMessage).toBe('Email delivery failed for: a@example.com, b@example.com');

      const dbUser = await User.findById(user.id).lean();
      expect(dbUser?.settings.backup.lastBackupStatus).toBe('failed');
    });

    it('falls back to the account e-mail when no backup recipients are configured', async () => {
      await configureBackup(agent, user);

      cfgState.emailConfigured = true;

      const res = await post(agent, '/api/v1/backup/trigger', user.accessToken, {});

      expect(res.status).toBe(200);
      expect(res.body.message).toBe('Backup created and sent successfully');
      expect(res.body.data).toMatchObject({ emailsSent: 1, emailsFailed: 0, failedEmails: [] });

      const log = await BackupLog.findOne({ userId: user.id }).lean();
      expect(log?.sentTo).toEqual([user.email]);
      expect(log?.errorMessage).toBeUndefined();
      expect(mockSendEmail).toHaveBeenCalledTimes(1);
      expect(mockSendEmail.mock.calls[0]?.[0]).toBe(user.email);
    });
  });

  // ── backupController: the per-user trigger JobLock ─────────────────────

  describe('POST /api/v1/backup/trigger — distributed dedup lock', () => {
    it('409s while another worker holds the per-user lock, and leaves that lock intact', async () => {
      await configureBackup(agent, user);

      await JobLock.create({
        jobName: `backup:trigger:${user.id}`,
        lockedBy: 'another-worker',
        lockedAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000),
      });

      const res = await post(agent, '/api/v1/backup/trigger', user.accessToken, {});

      expect(res.status).toBe(409);
      expect(res.body.message).toMatch(/already in progress/i);
      // No work was done…
      expect(await BackupLog.countDocuments({ userId: user.id })).toBe(0);
      // …and, crucially, the loser must NOT release the holder's lock.
      const lock = await JobLock.findOne({ jobName: `backup:trigger:${user.id}` }).lean();
      expect(lock?.lockedBy).toBe('another-worker');
    });

    it('releases its own lock on success so a second trigger can run', async () => {
      await configureBackup(agent, user);

      const first = await post(agent, '/api/v1/backup/trigger', user.accessToken, {});
      expect(first.status).toBe(200);
      expect(await JobLock.countDocuments({ jobName: `backup:trigger:${user.id}` })).toBe(0);

      const second = await post(agent, '/api/v1/backup/trigger', user.accessToken, {});
      expect(second.status).toBe(200);
      expect(await BackupLog.countDocuments({ userId: user.id })).toBe(2);
    });

    it("does not block a different user's trigger (the lock is per-user)", async () => {
      const other = await createTestUser();
      await configureBackup(agent, other);

      await JobLock.create({
        jobName: `backup:trigger:${user.id}`,
        lockedBy: 'another-worker',
        lockedAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000),
      });

      const res = await post(agent, '/api/v1/backup/trigger', other.accessToken, {});
      expect(res.status).toBe(200);
      expect(await BackupLog.countDocuments({ userId: other.id })).toBe(1);
    });
  });

  // ── backupController: history pagination ───────────────────────────────

  describe('GET /api/v1/backup/history — pagination', () => {
    it('paginates newest-first, isolates other users, and never leaks userId', async () => {
      const other = await createTestUser();
      const base = Date.now();
      for (let i = 0; i < 5; i++) {
        await BackupLog.create({
          userId: user.id,
          status: 'success',
          itemCount: i,
          fileSizeBytes: 100 + i,
          sentTo: ['download'],
          timestamp: new Date(base + i * 1000),
        });
      }
      await BackupLog.create({
        userId: other.id,
        status: 'success',
        itemCount: 99,
        sentTo: ['download'],
        timestamp: new Date(base + 10_000),
      });

      const res = await agent
        .get('/api/v1/backup/history?page=2&limit=2')
        .set('Authorization', authHeader(user.accessToken));

      expect(res.status).toBe(200);
      expect(res.body.pagination).toEqual({ page: 2, limit: 2, total: 5, totalPages: 3 });
      // Sorted timestamp desc → itemCounts 4,3 | 2,1 | 0. Page 2 is [2, 1].
      expect(res.body.data.map((l: { itemCount: number }) => l.itemCount)).toEqual([2, 1]);
      // The other user's row (itemCount 99) is excluded by `total` and by content.
      expect(res.body.data.some((l: { itemCount: number }) => l.itemCount === 99)).toBe(false);
      expect(res.body.data.every((l: Record<string, unknown>) => !('userId' in l))).toBe(true);
    });
  });

  // ── folderController: E11000 → 409 on create AND update ────────────────

  describe('folder duplicate-name conflicts', () => {
    it('returns 409 (not 500) when creating a second folder with the same searchHash', async () => {
      const first = await post(agent, '/api/v1/folders', user.accessToken, {
        ...sampleFolder({ searchHash: HASH_A }),
      });
      expect(first.status).toBe(201);

      const second = await post(agent, '/api/v1/folders', user.accessToken, {
        ...sampleFolder({ searchHash: HASH_A }),
      });

      expect(second.status).toBe(409);
      expect(second.body.success).toBe(false);
      expect(second.body.message).toMatch(/already exists/i);
      expect(await Folder.countDocuments({ userId: user.id })).toBe(1);
    });

    it('returns 409 (not 500) when RENAMING a folder onto an existing name, leaving it unchanged', async () => {
      const a = await seedFolder(user.id, { searchHash: HASH_A, encryptedName: 'alpha' });
      const b = await seedFolder(user.id, { searchHash: HASH_B, encryptedName: 'beta' });

      const res = await put(agent, `/api/v1/folders/${String(b._id)}`, user.accessToken, {
        searchHash: HASH_A,
      });

      expect(res.status).toBe(409);
      expect(res.body.message).toMatch(/already exists/i);

      // The losing folder must be byte-for-byte untouched.
      const raw = await Folder.findById(String(b._id)).lean();
      expect(raw?.searchHash).toBe(HASH_B);
      expect(raw?.encryptedName).toBe('beta');
      // …and the winner keeps its hash too.
      const rawA = await Folder.findById(String(a._id)).lean();
      expect(rawA?.searchHash).toBe(HASH_A);

      // A failed rename must not be audited as a successful folder_update.
      expect(await AuditLog.countDocuments({ userId: user.id, action: 'folder_update' })).toBe(0);
    });

    it('lets a DIFFERENT user create a folder with the same searchHash (index is per-user)', async () => {
      const other = await createTestUser();
      await seedFolder(user.id, { searchHash: HASH_A });

      const res = await post(agent, '/api/v1/folders', other.accessToken, {
        ...sampleFolder({ searchHash: HASH_A }),
      });

      expect(res.status).toBe(201);
      expect(await Folder.countDocuments({ userId: other.id })).toBe(1);
      expect(await Folder.countDocuments({ userId: user.id })).toBe(1);
    });
  });

  // ── folderController: parentId IDOR guard on create AND update ─────────

  describe('folder parentId must belong to the caller', () => {
    it("404s when CREATING a folder under another user's folder, and writes nothing", async () => {
      const other = await createTestUser();
      const foreignParent = await seedFolder(other.id, { encryptedName: 'foreign' });

      const res = await post(agent, '/api/v1/folders', user.accessToken, {
        ...sampleFolder({ parentId: String(foreignParent._id) }),
      });

      expect(res.status).toBe(404);
      expect(res.body.message).toMatch(/parent folder not found/i);
      expect(await Folder.countDocuments({ userId: user.id })).toBe(0);
      // The victim's tree is untouched.
      expect(await Folder.countDocuments({ userId: other.id })).toBe(1);
    });

    it("404s when RE-PARENTING onto another user's folder, leaving the folder where it was", async () => {
      const other = await createTestUser();
      const foreignParent = await seedFolder(other.id, { encryptedName: 'foreign' });
      const mine = await seedFolder(user.id, { encryptedName: 'mine' });

      const res = await put(agent, `/api/v1/folders/${String(mine._id)}`, user.accessToken, {
        parentId: String(foreignParent._id),
      });

      expect(res.status).toBe(404);
      expect(res.body.message).toMatch(/parent folder not found/i);

      const raw = await Folder.findById(String(mine._id)).lean();
      expect(raw?.parentId).toBeUndefined();
      expect(await AuditLog.countDocuments({ userId: user.id, action: 'folder_update' })).toBe(0);
    });
  });

  // ── folderController: delete action=move re-homes to the PARENT ────────

  it('DELETE /folders/:id?action=move re-homes items and child folders onto the parent', async () => {
    const parent = await seedFolder(user.id, { encryptedName: 'parent' });
    const target = await seedFolder(user.id, {
      encryptedName: 'target',
      parentId: parent._id,
    });
    const child = await seedFolder(user.id, { encryptedName: 'child', parentId: target._id });
    const item = await seedItem(user.id, { folderId: target._id });
    const otherUsersItem = await seedItem((await createTestUser()).id);

    const res = await del(
      agent,
      `/api/v1/folders/${String(target._id)}?action=move`,
      user.accessToken,
    );

    expect(res.status).toBe(200);
    expect(await Folder.findById(String(target._id)).lean()).toBeNull();

    const movedItem = await VaultItem.findById(String(item._id)).lean();
    expect(String(movedItem?.folderId)).toBe(String(parent._id));
    expect(movedItem?.deletedAt).toBeUndefined();

    const movedChild = await Folder.findById(String(child._id)).lean();
    expect(String(movedChild?.parentId)).toBe(String(parent._id));

    // Nothing outside this user's tree is touched.
    const untouched = await VaultItem.findById(String(otherUsersItem._id)).lean();
    expect(untouched).not.toBeNull();
    expect(untouched?.folderId).toBeUndefined();
  });

  // ── migrations.ts ─────────────────────────────────────────────────────

  describe('runMigrations', () => {
    beforeEach(async () => {
      await JobLock.ensureIndexes();
      await Migration.ensureIndexes();
    });

    it('applies the built-in registry (default argument) and records v1', async () => {
      await runMigrations();

      const v1 = await Migration.findOne({ version: 1 }).lean();
      expect(v1?.name).toBe('initial-schema');
      expect(await JobLock.countDocuments({ jobName: 'migrations' })).toBe(0);
    });

    it('tolerates an E11000 on the tracking insert (another process recorded it first)', async () => {
      // `up()` itself writes the tracking row — exactly what a racing worker that
      // recorded the version between our find() and our create() looks like. The
      // subsequent Migration.create must be swallowed as a duplicate, not thrown.
      const up = vi.fn(async () => {
        await Migration.create({ version: 3101, name: 'raced', appliedAt: new Date() });
      });
      const list: MigrationDefinition[] = [{ version: 3101, name: 'raced', up }];

      await expect(runMigrations(list)).resolves.toBeUndefined();

      expect(up).toHaveBeenCalledTimes(1);
      expect(await Migration.countDocuments({ version: 3101 })).toBe(1);
      // The lock is still released on the tolerated-duplicate path.
      expect(await JobLock.countDocuments({ jobName: 'migrations' })).toBe(0);
    });

    it('applies pending migrations in ascending version order regardless of registry order', async () => {
      const order: number[] = [];
      const list: MigrationDefinition[] = [
        {
          version: 3203,
          name: 'third',
          up: () => {
            order.push(3203);
            return Promise.resolve();
          },
        },
        {
          version: 3201,
          name: 'first',
          up: () => {
            order.push(3201);
            return Promise.resolve();
          },
        },
        {
          version: 3202,
          name: 'second',
          up: () => {
            order.push(3202);
            return Promise.resolve();
          },
        },
      ];

      await runMigrations(list);

      // Data migrations are not commutative — v3202 may depend on v3201 having
      // already run, so the registry's declaration order must never leak through.
      expect(order).toEqual([3201, 3202, 3203]);
      expect(await Migration.countDocuments({ version: { $in: [3201, 3202, 3203] } })).toBe(3);
    });

    it('propagates a non-duplicate persistence error from the tracking insert', async () => {
      const spy = vi
        .spyOn(Migration, 'create')
        .mockRejectedValueOnce(new Error('transient write failure') as never);

      const up = vi.fn(() => Promise.resolve());
      const list: MigrationDefinition[] = [{ version: 3103, name: 'infra-error', up }];

      // Only E11000 is tolerated. A genuine infra failure must surface — silently
      // swallowing it would leave the migration applied but un-recorded forever.
      await expect(runMigrations(list)).rejects.toThrow('transient write failure');
      spy.mockRestore();

      expect(await Migration.countDocuments({ version: 3103 })).toBe(0);
      // The lock is still released, so the next boot can retry.
      expect(await JobLock.countDocuments({ jobName: 'migrations' })).toBe(0);
    });

    it('still completes boot when releasing the migration lock fails', async () => {
      const spy = vi
        .spyOn(JobLock, 'deleteOne')
        .mockRejectedValueOnce(new Error('transient mongo failure') as never);

      const up = vi.fn(() => Promise.resolve());
      const list: MigrationDefinition[] = [{ version: 3102, name: 'release-fails', up }];

      // A transient failure releasing the lock must not fail startup — the
      // migration itself already committed and the lock's TTL will reap it.
      await expect(runMigrations(list)).resolves.toBeUndefined();
      expect(up).toHaveBeenCalledTimes(1);
      expect(await Migration.countDocuments({ version: 3102 })).toBe(1);

      spy.mockRestore();
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });
});
