/**
 * F-25: a streamed response's two ways of ending badly, over a real listening
 * server and a raw socket, because supertest buffers every body and so can neither
 * stop reading nor see how a connection ended.
 *
 *   - A client that stops reading is cut off at the send deadline, and the slot it
 *     held comes back. An idle timeout would never fire for a reader that takes a
 *     byte now and then; this deadline is absolute.
 *   - A failure after the first byte (here a cursor that dies mid-vault) destroys
 *     the connection. Nothing is appended to the half-sent document: no error
 *     envelope glued to the end of a file.
 *
 * Both are recorded as downloads that did not complete, since what reached the
 * client before the cut still left the server.
 */
import { describe, it, expect, beforeAll, afterAll, afterEach, vi } from 'vitest';
import http from 'node:http';
import net from 'node:net';
import type { AddressInfo } from 'node:net';
import mongoose from 'mongoose';
import app from '../src/app.js';
import { config } from '../src/config/index.js';
import { User } from '../src/models/User.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { BackupLog } from '../src/models/BackupLog.js';
import { AuditLog } from '../src/models/AuditLog.js';
import {
  SEND_DEADLINE_POLICY,
  heavyResponseSemaphore,
  heavyResponseUserQuota,
} from '../src/utils/heavyResponseBudget.js';
import request from 'supertest';
import { authHeader, createTestUser, getCsrf, sampleVaultItem, type TestUser } from './helpers.js';

let server: http.Server;
let port: number;
const savedPolicy = { ...SEND_DEADLINE_POLICY };

beforeAll(async () => {
  server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  port = (server.address() as AddressInfo).port;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

afterEach(() => {
  Object.assign(SEND_DEADLINE_POLICY, savedPolicy);
  vi.restoreAllMocks();
});

async function backupUser(items: number, dataBytes: number): Promise<TestUser> {
  const user = await createTestUser();
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
  await VaultItem.insertMany(
    Array.from({ length: items }, () => ({
      userId: user.id,
      ...sampleVaultItem({ encryptedData: 'e'.repeat(dataBytes) }),
    })),
  );
  return user;
}

/** A raw GET that the test controls: it reads only when told to. */
function rawGet(path: string, token: string, { read }: { read: boolean }) {
  const socket = net.connect(port, '127.0.0.1');
  const received: Buffer[] = [];
  const closed = new Promise<void>((resolve) => socket.once('close', () => resolve()));
  socket.on('error', () => undefined);
  if (read) socket.on('data', (chunk: Buffer) => received.push(chunk));
  else socket.pause();
  socket.write(
    `GET ${path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${token}\r\nConnection: close\r\n\r\n`,
  );
  return { socket, closed, text: () => Buffer.concat(received).toString('utf8') };
}

describe('a client that stops reading', () => {
  it('is cut off at the send deadline, and the slot and the share come back', async () => {
    // ~12 MB: far more than the loopback socket buffers hold, so the server blocks.
    const user = await backupUser(300, 40_000);
    SEND_DEADLINE_POLICY.bytesPerSecond = 1024 * 1024 * 1024;
    SEND_DEADLINE_POLICY.slackMs = 400;

    const started = Date.now();
    const client = rawGet('/api/v1/backup/download', user.accessToken, { read: false });

    // The server gives up on its own: the slot, the share and the record, while the
    // client still has not read a byte.
    await vi.waitFor(
      async () => {
        const log = await BackupLog.findOne({ userId: user.id }).lean();
        expect(log?.status).toBe('failed');
        expect(heavyResponseSemaphore.available).toBe(heavyResponseSemaphore.permits);
      },
      { timeout: 10_000, interval: 50 },
    );
    expect(Date.now() - started).toBeLessThan(10_000);
    expect(heavyResponseUserQuota.heldBy(user.id)).toBe(0);
    const audit = await AuditLog.findOne({ userId: user.id, action: 'backup_download' }).lean();
    expect(audit?.metadata).toMatchObject({ completed: false });

    // What the client can still read is a truncated file: the connection was ended.
    const received: Buffer[] = [];
    client.socket.on('data', (chunk: Buffer) => received.push(chunk));
    client.socket.resume();
    await client.closed;
    const text = Buffer.concat(received).toString('utf8');
    expect(text).toMatch(/^HTTP\/1\.1 200/);
    expect(text).not.toContain('"metadata"');
  }, 30_000);

  it('does not cut off a client that takes the whole file in time', async () => {
    const user = await backupUser(40, 40_000);
    SEND_DEADLINE_POLICY.slackMs = 10_000;

    const client = rawGet('/api/v1/backup/download', user.accessToken, { read: true });
    await client.closed;

    const body = client.text().split('\r\n\r\n').slice(1).join('\r\n\r\n');
    expect(client.text()).toMatch(/^HTTP\/1\.1 200/);
    expect(body).toContain('"metadata":{"itemCount":40,"folderCount":0}');
    expect(await BackupLog.countDocuments({ userId: user.id, status: 'success' })).toBe(1);
  }, 30_000);
});

/** Cursors the server holds open right now, from its own counters. */
async function openCursors(): Promise<number> {
  const status = (await mongoose.connection.db!.command({ serverStatus: 1 })) as {
    metrics: { cursor: { open: { total: number } } };
  };
  return Number(status.metrics.cursor.open.total);
}

describe('an early exit closes the database cursor', () => {
  it('releases the list cursor of a page the client abandoned', async () => {
    // Rows large enough that the page spans several driver batches.
    const user = await backupUser(120, 200_000);
    const baseline = await openCursors();

    const client = rawGet('/api/v1/vault/items?limit=200', user.accessToken, { read: false });
    // The server blocks on backpressure with a cursor open, then the client leaves.
    await vi.waitFor(async () => {
      expect(await openCursors()).toBeGreaterThan(baseline);
    });
    client.socket.destroy();

    await vi.waitFor(
      async () => {
        expect(await openCursors()).toBe(baseline);
      },
      { timeout: 10_000, interval: 50 },
    );
  }, 30_000);

  it('releases the estimate cursor of a backup refused as too large', async () => {
    // More than one driver batch (16 MB), so a cursor is still open on the server
    // when the estimate stops at the size limit.
    const user = await backupUser(200, 200_000);
    const baseline = await openCursors();
    const mutable = config as unknown as Record<string, unknown>;
    const saved = mutable.BACKUP_MAX_SIZE_MB;
    mutable.BACKUP_MAX_SIZE_MB = 1;
    try {
      const client = rawGet('/api/v1/backup/download', user.accessToken, { read: true });
      await client.closed;
      expect(client.text()).toMatch(/^HTTP\/1\.1 413/);
    } finally {
      mutable.BACKUP_MAX_SIZE_MB = saved;
    }
    await vi.waitFor(
      async () => {
        expect(await openCursors()).toBe(baseline);
      },
      { timeout: 10_000, interval: 50 },
    );
  }, 30_000);
});

describe('a failure after the first byte', () => {
  /** Makes the SECOND `VaultItem.find` (the stream pass) yield one row and then fail. */
  function failTheStreamPass(): void {
    const realFind = VaultItem.find.bind(VaultItem) as (...args: unknown[]) => unknown;
    let calls = 0;
    vi.spyOn(VaultItem, 'find').mockImplementation(((...args: unknown[]) => {
      calls += 1;
      if (calls !== 2) return realFind(...args);
      const cursor = (async function* dying() {
        yield { _id: '65a1b2c3d4e5f60718293a4b', encryptedData: 'first-row' };
        throw new Error('the database connection was lost');
      })();
      const chain = {
        select: () => chain,
        sort: () => chain,
        skip: () => chain,
        limit: () => chain,
        batchSize: () => chain,
        lean: () => chain,
        cursor: () => cursor,
      };
      return chain;
    }) as never);
  }

  it('destroys a download mid-file and appends nothing to it', async () => {
    const user = await backupUser(3, 100);
    failTheStreamPass();

    const client = rawGet('/api/v1/backup/download', user.accessToken, { read: true });
    await client.closed;

    const text = client.text();
    expect(text).toMatch(/^HTTP\/1\.1 200/);
    expect(text).toContain('first-row');
    // Truncated, and nothing glued on: no error envelope, no closing brace.
    expect(text).not.toContain('"success":false');
    expect(text).not.toContain('"metadata"');
    // Both, eventually: the audit row is written before the history row, and the
    // slot comes back only once the handler has settled after both.
    await vi.waitFor(async () => {
      const audit = await AuditLog.findOne({ userId: user.id, action: 'backup_download' }).lean();
      expect(audit?.metadata).toMatchObject({ completed: false });
      expect(heavyResponseSemaphore.available).toBe(heavyResponseSemaphore.permits);
    });
  });

  it('ends an export mid-file and records it as not completed', async () => {
    const user = await backupUser(3, 100);
    failTheStreamPass();
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);

    const res = await agent
      .post('/api/v1/tools/export')
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', csrf.cookie)
      .set('x-csrf-token', csrf.token)
      .send({ authHash: user.rawPassword })
      .then(
        (response) => response,
        (error: unknown) => error,
      );

    // Cut off part-way: the connection ends without a complete body.
    expect(res).toBeInstanceOf(Error);
    await vi.waitFor(async () => {
      const audit = await AuditLog.findOne({ userId: user.id, action: 'export' }).lean();
      expect(audit?.metadata).toMatchObject({ completed: false });
      expect(heavyResponseSemaphore.available).toBe(heavyResponseSemaphore.permits);
    });
    expect(await AuditLog.countDocuments({ userId: user.id, action: 'export' })).toBe(1);
  });

  it('destroys a list page mid-page and appends nothing to it', async () => {
    const user = await backupUser(3, 100);
    vi.spyOn(VaultItem, 'find').mockImplementation((() => {
      const cursor = (async function* dying() {
        yield { _id: '65a1b2c3d4e5f60718293a4b', encryptedData: 'first-row' };
        throw new Error('the database connection was lost');
      })();
      const chain = {
        select: () => chain,
        sort: () => chain,
        skip: () => chain,
        limit: () => chain,
        batchSize: () => chain,
        lean: () => chain,
        cursor: () => cursor,
      };
      return chain;
    }) as never);

    const client = rawGet('/api/v1/vault/items', user.accessToken, { read: true });
    await client.closed;

    const text = client.text();
    expect(text).toMatch(/^HTTP\/1\.1 200/);
    expect(text).toContain('first-row');
    expect(text).not.toContain('"success":false');
    expect(text).not.toContain('"pagination"');
  });
});

describe('the download record (F-25)', () => {
  it('a history row that cannot be written at the end of the file truncates nothing and loses no audit row', async () => {
    const user = await backupUser(3, 100);
    const create = vi
      .spyOn(BackupLog, 'create')
      .mockImplementationOnce((() =>
        Promise.reject(new Error('the primary stepped down'))) as never);

    const client = rawGet('/api/v1/backup/download', user.accessToken, { read: true });
    await client.closed;

    expect(create).toHaveBeenCalledTimes(1);
    // The whole file was delivered: the closing members are there.
    const text = client.text();
    expect(text).toMatch(/^HTTP\/1\.1 200/);
    expect(text).toContain('"metadata":{"itemCount":3,"folderCount":0}');
    // The download is on the audit record, as a completed one...
    const audit = await AuditLog.findOne({ userId: user.id, action: 'backup_download' }).lean();
    expect(audit?.metadata).toMatchObject({ completed: true, itemCount: 3 });
    // ...and the history row that failed was not written twice or as a failure.
    expect(await BackupLog.countDocuments({ userId: user.id })).toBe(0);
    expect(heavyResponseSemaphore.available).toBe(heavyResponseSemaphore.permits);
  });
});
