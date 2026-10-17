/**
 * F-25: the heavy responses — a backup download, a backup mailed on demand and a
 * vault export — each build a whole vault's worth of JSON, and nothing bounded how
 * many ran at once (measured: nine concurrent downloads of a 22 MB vault peaked at
 * 564 MB). They are now admitted through one budget: two per process, one per
 * account, released when the response has closed AND the handler has settled.
 *
 * A download is held in flight deterministically by gating the one step every
 * backup takes after admission, the document summary, so what the tests observe
 * is admission rather than timing.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

const gate = vi.hoisted(() => {
  let release: (() => void) | null = null;
  let entered = 0;
  const closed = { value: false };
  return {
    close() {
      closed.value = true;
    },
    open() {
      closed.value = false;
      release?.();
      release = null;
    },
    get entered() {
      return entered;
    },
    reset() {
      entered = 0;
      closed.value = false;
      release = null;
    },
    async pass(): Promise<void> {
      entered += 1;
      if (!closed.value) return;
      await new Promise<void>((resolve) => {
        const previous = release;
        release = () => {
          previous?.();
          resolve();
        };
      });
    },
  };
});

vi.mock('../src/utils/documentSummary.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/utils/documentSummary.js')>();
  return {
    ...actual,
    collectDocumentSummary: async (userId: string) => {
      await gate.pass();
      return actual.collectDocumentSummary(userId);
    },
  };
});

import request from 'supertest';
import app from '../src/app.js';
import { config } from '../src/config/index.js';
import { BackupLog } from '../src/models/BackupLog.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { User } from '../src/models/User.js';
import { heavyResponseSemaphore } from '../src/utils/heavyResponseBudget.js';
import { authHeader, createTestUser, getCsrf, sampleVaultItem, type TestUser } from './helpers.js';

const API = '/api/v1';
const mutableConfig = config as unknown as Record<string, unknown>;
let savedBackupMax: unknown;

async function configureBackup(user: TestUser): Promise<void> {
  await User.updateOne(
    { _id: user.id },
    {
      $set: {
        'settings.backup.isConfigured': true,
        'settings.backup.encryptedBWK': 'test-bwk',
        'settings.backup.bwkIv': 'bwk-iv',
        'settings.backup.bwkTag': 'bwk-tag',
        'settings.backup.bwkSalt': 's'.repeat(32),
      },
    },
  );
}

function download(user: TestUser): request.Test {
  return request(app)
    .get(`${API}/backup/download`)
    .set('Authorization', authHeader(user.accessToken));
}

async function post(user: TestUser, path: string, body?: Record<string, unknown>) {
  const agent = request.agent(app);
  const csrf = await getCsrf(agent);
  return agent
    .post(`${API}${path}`)
    .set('Authorization', authHeader(user.accessToken))
    .set('Cookie', csrf.cookie)
    .set('x-csrf-token', csrf.token)
    .send(body ?? {});
}

/** Waits until `count` requests are inside the gated step. */
async function untilEntered(count: number): Promise<void> {
  await vi.waitFor(() => {
    expect(gate.entered).toBeGreaterThanOrEqual(count);
  });
}

beforeEach(() => {
  gate.reset();
  savedBackupMax = mutableConfig.BACKUP_MAX_SIZE_MB;
});

afterEach(() => {
  gate.open();
  mutableConfig.BACKUP_MAX_SIZE_MB = savedBackupMax;
});

describe('one heavy response per account', () => {
  it('keeps one of three concurrent downloads in flight and refuses the other two with 409', async () => {
    const user = await createTestUser();
    await configureBackup(user);
    await VaultItem.create({ userId: user.id, ...sampleVaultItem() });
    gate.close();

    const settled: number[] = [];
    const pending = [download(user), download(user), download(user)].map((r) =>
      r.then((x) => {
        settled.push(x.status);
        return x;
      }),
    );
    await untilEntered(1);
    // While the admitted download is still held, the other two are ANSWERED, not
    // queued: both settle with 409 before the gate opens.
    await vi.waitFor(() => {
      expect(settled).toHaveLength(2);
    });
    expect(settled).toEqual([409, 409]);
    gate.open();
    const results = await Promise.all(pending);

    const statuses = results.map((r) => r.status).sort();
    expect(statuses).toEqual([200, 409, 409]);
    expect(gate.entered).toBe(1);
    const refusal = results.find((r) => r.status === 409)!;
    expect(refusal.body.message).toMatch(/already in progress/i);
    // No `data`: a 409 carrying `data.vaultKeyVersion` means a stale vault key.
    expect(refusal.body).not.toHaveProperty('data');
    // Only the admitted download is recorded.
    expect(await BackupLog.countDocuments({ userId: user.id })).toBe(1);
  });

  it('shares that one slot between a download, an export and a mailed backup', async () => {
    const user = await createTestUser();
    await configureBackup(user);
    gate.close();

    const inFlight = download(user).then((r) => r);
    await untilEntered(1);

    const exported = await post(user, '/tools/export', { authHash: user.rawPassword });
    const triggered = await post(user, '/backup/trigger');
    expect(exported.status).toBe(409);
    expect(triggered.status).toBe(409);
    expect(await AuditLog.countDocuments({ userId: user.id, action: 'export' })).toBe(0);

    gate.open();
    expect((await inFlight).status).toBe(200);
    // Released once settled: the next one is admitted.
    expect((await post(user, '/tools/export', { authHash: user.rawPassword })).status).toBe(200);
  });
});

describe('two heavy responses per process', () => {
  it('lets two accounts through at once and holds a third until a slot frees, without refusing it', async () => {
    const users = await Promise.all([createTestUser(), createTestUser(), createTestUser()]);
    for (const user of users) await configureBackup(user);
    gate.close();

    const first = download(users[0]!).then((r) => r);
    const second = download(users[1]!).then((r) => r);
    await untilEntered(2);
    const third = download(users[2]!).then((r) => r);

    // The third waits in the process queue, not refused: its handler has not started.
    await vi.waitFor(() => {
      expect(heavyResponseSemaphore.waiting).toBe(1);
    });
    expect(gate.entered).toBe(2);

    gate.open();
    const results = await Promise.all([first, second, third]);
    expect(results.map((r) => r.status)).toEqual([200, 200, 200]);
    expect(gate.entered).toBe(3);
  });
});

describe('the size limit is decided before the first byte', () => {
  it('refuses an oversized backup with a whole 413 envelope and records no download', async () => {
    const user = await createTestUser();
    await configureBackup(user);
    await VaultItem.create({
      userId: user.id,
      ...sampleVaultItem({ encryptedData: 'x'.repeat(4_000) }),
    });
    mutableConfig.BACKUP_MAX_SIZE_MB = 2_000 / (1024 * 1024);

    const res = await download(user);

    expect(res.status).toBe(413);
    // A complete error envelope, not a truncated stream: nothing was sent before it.
    expect(res.body).toMatchObject({ success: false, statusCode: 413 });
    expect(res.headers['content-disposition']).toBeUndefined();
    expect(await BackupLog.countDocuments({ userId: user.id, status: 'success' })).toBe(0);
    expect(await AuditLog.countDocuments({ userId: user.id, action: 'backup_download' })).toBe(0);
  });

  it('streams a backup that fits, byte-for-byte parseable, and records it once it has been sent', async () => {
    const user = await createTestUser();
    await configureBackup(user);
    await VaultItem.create({ userId: user.id, ...sampleVaultItem() });
    await VaultItem.create({ userId: user.id, ...sampleVaultItem(), deletedAt: new Date() });

    const res = await download(user)
      .buffer(true)
      .parse((response, done) => {
        let text = '';
        response.setEncoding('utf8');
        response.on('data', (chunk: string) => (text += chunk));
        response.on('end', () => done(null, text));
      });

    expect(res.status).toBe(200);
    expect(res.headers['content-disposition']).toMatch(/^attachment; filename="hvault-backup-/);
    const parsed = JSON.parse(res.body as string) as {
      items: unknown[];
      folders: unknown[];
      metadata: { itemCount: number; folderCount: number };
      backupEncryption: { encryptedBWK: string };
    };
    // The trashed row is not in a backup; the live one is.
    expect(parsed.items).toHaveLength(1);
    expect(parsed.metadata).toEqual({ itemCount: 1, folderCount: 0 });
    expect(parsed.backupEncryption.encryptedBWK).toBe('test-bwk');
    expect(await BackupLog.countDocuments({ userId: user.id, status: 'success' })).toBe(1);
    const audit = await AuditLog.findOne({ userId: user.id, action: 'backup_download' }).lean();
    expect(audit?.metadata).toMatchObject({ itemCount: 1, completed: true });
  });
});
