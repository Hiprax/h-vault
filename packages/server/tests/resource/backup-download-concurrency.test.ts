/**
 * Nine concurrent backup downloads of a 22 MB vault, each from its own account,
 * through a real listening server — inside a memory budget.
 *
 * The regression this exists for (F-25): every download built the whole backup as
 * item rows in an array, then a JSON string, then a buffer, and nothing bounded how
 * many ran at once. Measured on the code before the fix (see the budget's docblock)
 * nine of them grew the process by hundreds of megabytes. Now at most two run per
 * process and each streams from the cursors, so the growth is about two rows in
 * flight plus socket buffers, whatever the number of clients.
 *
 * A real server and raw sockets that DISCARD what they read, because supertest
 * would buffer every body in this process and the budget would measure the test
 * client rather than the server.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import app from '../../src/app.js';
import { createTestUser, type TestUser } from '../helpers.js';
import { configureBackupEncryption, seedVault } from './fixtures.js';
import { measure, recordScenarioCase } from './measure.js';
import { RESOURCE_BUDGETS } from '../../../../scripts/ci/lib/resource-budgets.mjs';

/** Accounts downloading at once, and the shape of each one's vault (~22 MB). */
const CLIENTS = 9;
const ITEMS_PER_VAULT = 550;
const DATA_BYTES = 40_000;

const budget = RESOURCE_BUDGETS.backupDownloadConcurrency;

let server: http.Server;
let port: number;
let users: TestUser[];

beforeAll(async () => {
  server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  port = (server.address() as AddressInfo).port;
}, 60_000);

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

/** One download, read and thrown away; resolves to its status and byte count. */
function download(token: string): Promise<{ status: number; bytes: number }> {
  return new Promise((resolve, reject) => {
    const req = http.get(
      {
        host: '127.0.0.1',
        port,
        path: '/api/v1/backup/download',
        headers: { authorization: `Bearer ${token}` },
      },
      (res) => {
        let bytes = 0;
        res.on('data', (chunk: Buffer) => {
          bytes += chunk.length;
        });
        res.on('end', () => resolve({ status: res.statusCode ?? 0, bytes }));
        res.on('error', reject);
      },
    );
    req.on('error', reject);
  });
}

describe('nine concurrent downloads of a 22 MB vault', () => {
  beforeAll(async () => {
    users = [];
    for (let i = 0; i < CLIENTS; i += 1) {
      const user = await createTestUser();
      await configureBackupEncryption(user.id);
      await seedVault(user.id, { count: ITEMS_PER_VAULT, dataBytes: DATA_BYTES });
      users.push(user);
    }
  }, 600_000);

  it('delivers every file within the time and memory budget', async () => {
    const run = await measure(() => Promise.all(users.map((user) => download(user.accessToken))));

    recordScenarioCase('backup-download-concurrency', 'nine-concurrent-downloads', {
      invariant:
        'nine accounts downloading a 22 MB backup at once all get the whole file, and the process grows by far less than nine copies of it',
      clients: CLIENTS,
      itemsPerVault: ITEMS_PER_VAULT,
      dataBytesPerItem: DATA_BYTES,
      statuses: run.result.map((r) => r.status),
      bytesPerDownload: run.result.map((r) => r.bytes),
      durationMs: run.durationMs,
      rssGrowthMb: run.rssGrowthMb,
      peakRssMb: run.peakRssMb,
      rssStartMb: run.rssStartMb,
      processMaxRssMb: run.processMaxRssMb,
      budget,
    });

    expect(run.result.map((r) => r.status)).toEqual(Array(CLIENTS).fill(200));
    // Every file is the whole vault: 22 MB of ciphertext and then some.
    for (const { bytes } of run.result) expect(bytes).toBeGreaterThan(ITEMS_PER_VAULT * DATA_BYTES);
    expect(run.durationMs).toBeLessThan(budget.durationMs);
    expect(run.rssGrowthMb).toBeLessThan(budget.rssGrowthMb);
  }, 600_000);
});
