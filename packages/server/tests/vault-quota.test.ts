/**
 * F-24: a per-account byte quota over the vault's items and folders.
 *
 * Every row an account writes used to be bounded only by a row count, so one
 * account could fill the database. `User.vaultBytes` is a denormalised counter of
 * the bytes the account's rows occupy (trashed rows included, until they are
 * purged), written by ONE conditional reservation before every growing write and
 * corrected after it. These tests hold it to the database's own measurement
 * (`support/vaultBytes.ts`) after every path that writes a vault row, and pin the
 * refusal at the boundary, the inline install of a missing counter, and the rule
 * that a write that does not grow the vault is never refused.
 *
 * Driven through the HTTP API and read through the raw collections, so the
 * assertions do not depend on how the counter is implemented.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

vi.mock('node-cron', () => ({
  default: { schedule: vi.fn().mockReturnValue({ stop: vi.fn() }) },
}));

import request from 'supertest';
import mongoose from 'mongoose';
import cron from 'node-cron';
import { TRASH_AUTO_PURGE_DAYS } from '@hvault/shared';
import app from '../src/app.js';
import { config } from '../src/config/index.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { startTrashCleanupJob } from '../src/jobs/trashCleanup.js';
import {
  authHeader,
  createTestUser,
  getCsrf,
  sampleFolder,
  sampleVaultItem,
  type TestUser,
} from './helpers.js';
import { storedVaultBytes, vaultBytesCounter } from './support/vaultBytes.js';

const API = '/api/v1';
const MB = 1024 * 1024;
const mutableConfig = config as unknown as Record<string, unknown>;
let savedQuota: unknown;

function setQuotaBytes(bytes: number): void {
  mutableConfig.VAULT_STORAGE_QUOTA_MB_PER_USER = bytes / MB;
}

beforeEach(() => {
  savedQuota = mutableConfig.VAULT_STORAGE_QUOTA_MB_PER_USER;
  mutableConfig.VAULT_STORAGE_QUOTA_MB_PER_USER = 512;
});

afterEach(() => {
  mutableConfig.VAULT_STORAGE_QUOTA_MB_PER_USER = savedQuota;
  vi.restoreAllMocks();
});

type Method = 'get' | 'post' | 'put' | 'delete';

async function call(
  user: TestUser,
  method: Method,
  path: string,
  body?: Record<string, unknown>,
): Promise<request.Response> {
  const agent = request.agent(app);
  const csrf = await getCsrf(agent);
  const req = agent[method](`${API}${path}`)
    .set('Authorization', authHeader(user.accessToken))
    .set('Cookie', csrf.cookie)
    .set('x-csrf-token', csrf.token);
  return body === undefined ? req : req.send(body);
}

/** A search hash in the only shape the import schema accepts (64 lower-case hex). */
const SEARCH_HASH = 'a'.repeat(64);

/** An import insert: an item body plus the search hash every import row carries. */
function importInsert(dataBytes: number): Record<string, unknown> {
  return itemBody(dataBytes, { searchHash: SEARCH_HASH });
}

/** An item create body whose ciphertext is `dataBytes` characters long. */
function itemBody(dataBytes: number, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return sampleVaultItem({ encryptedData: 'd'.repeat(dataBytes), ...extra });
}

async function createItem(user: TestUser, dataBytes: number): Promise<string> {
  const res = await call(user, 'post', '/vault/items', itemBody(dataBytes));
  expect(res.status).toBe(201);
  return String(res.body.data._id);
}

/** The counter equals what the database says the account stores. */
async function expectCounterExact(user: TestUser): Promise<number> {
  const stored = await storedVaultBytes(user.id);
  expect(await vaultBytesCounter(user.id)).toBe(stored);
  return stored;
}

function purgeTick(): () => Promise<void> {
  const schedule = vi.mocked(cron.schedule);
  schedule.mockClear();
  startTrashCleanupJob();
  return schedule.mock.calls[0]![1] as () => Promise<void>;
}

describe('an account without a counter', () => {
  it('is installed inline with the true stored bytes on its first write, never refused', async () => {
    const user = await createTestUser();
    // Rows written before the counter existed (an upgraded account).
    await VaultItem.create({ userId: user.id, ...itemBody(4_000) });
    await Folder.create({ userId: user.id, ...sampleFolder() });
    expect(await vaultBytesCounter(user.id)).toBeUndefined();

    await createItem(user, 1_000);

    await expectCounterExact(user);
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(2);
  });

  it('is installed by a delete too, and the delete is counted', async () => {
    const user = await createTestUser();
    const legacy = await VaultItem.create({
      userId: user.id,
      ...itemBody(3_000),
      deletedAt: new Date(),
    });
    await VaultItem.create({ userId: user.id, ...itemBody(2_000) });

    const res = await call(user, 'delete', `/vault/items/${String(legacy._id)}/permanent`);

    expect(res.status).toBe(200);
    const stored = await expectCounterExact(user);
    expect(stored).toBeGreaterThan(0);
  });

  it('reports the counter in the profile, and null before it is installed', async () => {
    const user = await createTestUser();
    const before = await call(user, 'get', '/user/profile');
    expect(before.status).toBe(200);
    expect(before.body.data.vaultBytes).toBeNull();
    expect(before.body.data.vaultQuotaBytes).toBe(512 * MB);

    await createItem(user, 500);
    const after = await call(user, 'get', '/user/profile');
    expect(after.body.data.vaultBytes).toBe(await storedVaultBytes(user.id));
    expect(after.body.data.vaultQuotaBytes).toBe(512 * MB);
    // The bookkeeping fields stay off the wire.
    expect(after.body.data).not.toHaveProperty('quotaEpoch');
    expect(after.body.data).not.toHaveProperty('quotaRecountedAt');
    expect(after.body.data).not.toHaveProperty('vaultBytesWrittenAt');
  });
});

describe('the quota boundary', () => {
  it('refuses the write that would cross the quota with 400, writing nothing', async () => {
    const user = await createTestUser();
    await createItem(user, 1_000);
    const used = await expectCounterExact(user);
    setQuotaBytes(used + 3_000);

    const refused = await call(user, 'post', '/vault/items', itemBody(5_000));

    expect(refused.status).toBe(400);
    expect(refused.body.message).toMatch(/storage limit/i);
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(1);
    expect(await vaultBytesCounter(user.id)).toBe(used);

    // Negative: what still fits is admitted.
    await createItem(user, 1_000);
    await expectCounterExact(user);
  });

  it('refuses an update that would grow the row past the quota and leaves the row as it was', async () => {
    const user = await createTestUser();
    const id = await createItem(user, 1_000);
    const used = await expectCounterExact(user);
    setQuotaBytes(used + 2_000);

    const grown = await call(user, 'put', `/vault/items/${id}`, {
      encryptedData: 'g'.repeat(8_000),
      dataIv: 'test-data-iv',
      dataTag: 'test-data-tag',
    });

    expect(grown.status).toBe(400);
    const row = await VaultItem.findById(id).lean();
    expect(row?.encryptedData).toBe('d'.repeat(1_000));
    expect(await vaultBytesCounter(user.id)).toBe(used);
  });

  it('admits exactly one of fifty concurrent creates when only one fits', async () => {
    const user = await createTestUser();
    const first = await createItem(user, 2_000);
    const used = await expectCounterExact(user);
    const oneItem = used; // one identical row is what the account holds
    expect(first).toBeTruthy();
    // Room for one more identical row, not for two.
    setQuotaBytes(used + oneItem + Math.floor(oneItem / 2));

    const results = await Promise.all(
      Array.from({ length: 50 }, () => call(user, 'post', '/vault/items', itemBody(2_000))),
    );

    const statuses = results.map((r) => r.status);
    expect(statuses.filter((s) => s === 201)).toHaveLength(1);
    expect(statuses.filter((s) => s === 400)).toHaveLength(49);
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(2);
    await expectCounterExact(user);
  });

  it('never refuses a write that does not grow the vault, however far over the quota', async () => {
    const user = await createTestUser();
    const a = await createItem(user, 6_000);
    const b = await createItem(user, 6_000);
    const c = await createItem(user, 6_000);
    const folder = await call(user, 'post', '/folders', sampleFolder());
    expect(folder.status).toBe(201);
    await expectCounterExact(user);
    setQuotaBytes(1); // far below what the account already stores

    // Trash, restore, move, shrink, purge, empty the trash, delete the folder.
    expect((await call(user, 'delete', `/vault/items/${a}`)).status).toBe(200);
    expect((await call(user, 'post', `/vault/items/restore/${a}`)).status).toBe(200);
    expect(
      (
        await call(user, 'post', '/vault/items/bulk-move', {
          ids: [a, b],
          folderId: String(folder.body.data._id),
        })
      ).status,
    ).toBe(200);
    const shrink = await call(user, 'put', `/vault/items/${b}`, {
      encryptedData: 'small',
      dataIv: 'test-data-iv',
      dataTag: 'test-data-tag',
    });
    expect(shrink.status).toBe(200);
    expect((await call(user, 'delete', `/vault/items/${b}`)).status).toBe(200);
    expect((await call(user, 'delete', `/vault/items/${b}/permanent`)).status).toBe(200);
    expect((await call(user, 'delete', `/vault/items/${c}`)).status).toBe(200);
    expect((await call(user, 'delete', '/vault/items/trash/empty')).status).toBe(200);
    expect(
      (await call(user, 'delete', `/folders/${String(folder.body.data._id)}?action=move`)).status,
    ).toBe(200);

    await expectCounterExact(user);
    // And a rotation of what is left, which is never refused either.
    const rotated = await call(user, 'post', '/vault/items/bulk-reencrypt', {
      authHash: user.rawPassword,
      newEncryptedVaultKey: 'rotated-key',
      newVaultKeyIv: 'rotated-iv',
      newVaultKeyTag: 'rotated-tag',
      items: [
        {
          id: a,
          encryptedName: 'rotated-name',
          nameIv: 'rotated-name-iv',
          nameTag: 'rotated-name-tag',
          encryptedData: 'rotated-data',
          dataIv: 'rotated-data-iv',
          dataTag: 'rotated-data-tag',
        },
      ],
      folders: [],
      documents: [],
    });
    expect(rotated.status).toBe(200);
    await expectCounterExact(user);
  });
});

describe('the counter equals the stored bytes after every path that writes a vault row', () => {
  it('create, update, trash, restore, bulk delete and move, folders, purge, empty trash', async () => {
    const user = await createTestUser();
    const a = await createItem(user, 1_200);
    await expectCounterExact(user);
    const b = await createItem(user, 300);
    await expectCounterExact(user);

    // Grow, shrink, tags only, favourite only, a password-history push.
    for (const update of [
      { encryptedData: 'x'.repeat(5_000), dataIv: 'test-data-iv', dataTag: 'test-data-tag' },
      { encryptedData: 'x'.repeat(40), dataIv: 'test-data-iv', dataTag: 'test-data-tag' },
      { tags: ['work', 'personal', 'a-rather-long-tag-name'] },
      { favorite: true },
      {
        passwordHistory: [
          {
            encryptedPassword: 'old-password-ciphertext',
            iv: 'h-iv',
            tag: 'h-tag',
            changedAt: '2026-10-01T12:00:00.000Z',
          },
        ],
      },
    ]) {
      const res = await call(user, 'put', `/vault/items/${a}`, update);
      expect(res.status).toBe(200);
      await expectCounterExact(user);
    }

    const folderRes = await call(user, 'post', '/folders', sampleFolder());
    expect(folderRes.status).toBe(201);
    const folderId = String(folderRes.body.data._id);
    await expectCounterExact(user);
    const renamed = await call(user, 'put', `/folders/${folderId}`, {
      encryptedName: 'a-much-longer-encrypted-folder-name-than-before',
      nameIv: 'new-folder-iv',
      nameTag: 'new-folder-tag',
    });
    expect(renamed.status).toBe(200);
    await expectCounterExact(user);
    const child = await call(user, 'post', '/folders', sampleFolder({ parentId: folderId }));
    expect(child.status).toBe(201);
    await expectCounterExact(user);

    expect(
      (await call(user, 'post', '/vault/items/bulk-move', { ids: [a, b], folderId })).status,
    ).toBe(200);
    await expectCounterExact(user);
    expect((await call(user, 'delete', `/vault/items/${a}`)).status).toBe(200);
    await expectCounterExact(user);
    expect((await call(user, 'post', `/vault/items/restore/${a}`)).status).toBe(200);
    await expectCounterExact(user);
    expect((await call(user, 'post', '/vault/items/bulk-delete', { ids: [a, b] })).status).toBe(
      200,
    );
    await expectCounterExact(user);
    expect((await call(user, 'post', `/vault/items/restore/${b}`)).status).toBe(200);

    expect((await call(user, 'delete', `/folders/${folderId}?action=delete`)).status).toBe(200);
    await expectCounterExact(user);
    expect((await call(user, 'delete', `/vault/items/${a}/permanent`)).status).toBe(200);
    await expectCounterExact(user);

    const c = await createItem(user, 700);
    expect((await call(user, 'delete', `/vault/items/${c}`)).status).toBe(200);
    expect((await call(user, 'delete', '/vault/items/trash/empty')).status).toBe(200);
    // `b` went to the trash with its folder, and the empty-trash took it with `c`:
    // no item is left. The child folder was moved up to the root when its parent
    // went, so it is the one row the account still stores, and all it counts.
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
    const folders = await Folder.find({ userId: user.id }).lean();
    expect(folders.map((f) => String(f._id))).toEqual([String(child.body.data._id)]);
    expect(folders[0]?.parentId ?? null).toBeNull();
    expect(await expectCounterExact(user)).toBeGreaterThan(0);
  });

  it('import: inserts and overwrites', async () => {
    const user = await createTestUser();
    const existing = await createItem(user, 900);
    await expectCounterExact(user);

    const res = await call(user, 'post', '/tools/import', {
      format: 'json',
      conflictStrategy: 'overwrite',
      operations: {
        inserts: [importInsert(2_000), importInsert(10)],
        updates: [
          {
            id: existing,
            encryptedName: 'overwritten-name',
            nameIv: 'o-name-iv',
            nameTag: 'o-name-tag',
            encryptedData: 'o'.repeat(3_333),
            dataIv: 'o-data-iv',
            dataTag: 'o-data-tag',
            searchHash: SEARCH_HASH,
          },
        ],
      },
    });

    expect(res.status).toBe(201);
    expect(res.body.data).toMatchObject({ insertedCount: 2, updatedCount: 1 });
    await expectCounterExact(user);
  });

  it('import: refuses a batch that would cross the quota, whole, before any write', async () => {
    const user = await createTestUser();
    await createItem(user, 900);
    const used = await expectCounterExact(user);
    setQuotaBytes(used + 3_000);

    const res = await call(user, 'post', '/tools/import', {
      format: 'json',
      operations: {
        inserts: [importInsert(1_000), importInsert(1_000), importInsert(1_000)],
        updates: [],
      },
    });

    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/storage limit/i);
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(1);
    expect(await vaultBytesCounter(user.id)).toBe(used);
  });

  it('backup restore: fresh rows, overwrites, keep-both duplicates and a trashed row brought back', async () => {
    const user = await createTestUser();
    const kept = await createItem(user, 800);
    const trashed = await createItem(user, 400);
    expect((await call(user, 'delete', `/vault/items/${trashed}`)).status).toBe(200);
    await expectCounterExact(user);

    const backup = {
      items: [
        { _id: kept, ...itemBody(1_500) },
        { _id: trashed, ...itemBody(2_500) },
        { _id: new mongoose.Types.ObjectId().toString(), ...itemBody(600) },
      ],
      folders: [{ _id: new mongoose.Types.ObjectId().toString(), ...sampleFolder() }],
    };

    for (const conflictStrategy of ['overwrite', 'keep_both', 'skip'] as const) {
      const res = await call(user, 'post', '/backup/restore', {
        conflictStrategy,
        data: JSON.stringify(backup),
      });
      expect(res.status).toBe(200);
      await expectCounterExact(user);
    }
  });

  it('the nightly trash purge', async () => {
    const user = await createTestUser();
    const old = await createItem(user, 1_000);
    await createItem(user, 200);
    expect((await call(user, 'delete', `/vault/items/${old}`)).status).toBe(200);
    // Aged past the purge window: `deletedAt` is placement, so this is byte-neutral.
    await VaultItem.updateOne(
      { _id: old },
      { $set: { deletedAt: new Date(Date.now() - (TRASH_AUTO_PURGE_DAYS + 5) * 86_400_000) } },
    );
    await expectCounterExact(user);

    await purgeTick()();

    expect(await VaultItem.exists({ _id: old })).toBeNull();
    await expectCounterExact(user);
  });

  it('a vault key rotation and a re-seal (sequential branch)', async () => {
    const user = await createTestUser();
    const a = await createItem(user, 1_000);
    const folder = await call(user, 'post', '/folders', sampleFolder());
    const folderId = String(folder.body.data._id);
    await expectCounterExact(user);

    const res = await call(user, 'post', '/vault/items/bulk-reencrypt', {
      authHash: user.rawPassword,
      newEncryptedVaultKey: 'rotated-key',
      newVaultKeyIv: 'rotated-iv',
      newVaultKeyTag: 'rotated-tag',
      items: [
        {
          id: a,
          encryptedName: 'a-longer-rotated-name-than-the-original',
          nameIv: 'v2:rotated-name-iv',
          nameTag: 'rotated-name-tag',
          encryptedData: 'r'.repeat(1_000),
          dataIv: 'v2:rotated-data-iv',
          dataTag: 'rotated-data-tag',
        },
      ],
      folders: [
        {
          id: folderId,
          encryptedName: 'rotated-folder-name',
          nameIv: 'v2:rotated-folder-iv',
          nameTag: 'rotated-folder-tag',
        },
      ],
      documents: [],
      vaultFieldFormat: 2,
    });

    expect(res.status).toBe(200);
    await expectCounterExact(user);

    // The re-seal: the same key, rows rewritten in the bound format (the `v2:`
    // markers lengthen the IVs, so the rows grow), proven by the stored wrapper.
    const rotated = await mongoose.connection
      .collection('users')
      .findOne(
        { _id: new mongoose.Types.ObjectId(user.id) },
        { projection: { vaultKeyVersion: 1 } },
      );
    const resealed = await call(user, 'post', '/vault/items/bulk-reencrypt', {
      authHash: user.rawPassword,
      newEncryptedVaultKey: 'rotated-key',
      newVaultKeyIv: 'rotated-iv',
      newVaultKeyTag: 'rotated-tag',
      reseal: true,
      idempotencyKey: '7b1c5f0e-3d2a-4c8b-9e6f-1a2b3c4d5e6f',
      vaultKeyVersion: rotated?.['vaultKeyVersion'] as number,
      items: [
        {
          id: a,
          encryptedName: 'resealed-name-that-is-longer-again',
          nameIv: 'v2:resealed-name-iv',
          nameTag: 'resealed-name-tag',
          encryptedData: 's'.repeat(1_500),
          dataIv: 'v2:resealed-data-iv',
          dataTag: 'resealed-data-tag',
        },
      ],
      folders: [
        {
          id: folderId,
          encryptedName: 'resealed-folder-name',
          nameIv: 'v2:resealed-folder-iv',
          nameTag: 'resealed-folder-tag',
        },
      ],
      documents: [],
      vaultFieldFormat: 2,
    });

    expect(resealed.status).toBe(200);
    expect((await VaultItem.findById(a).lean())?.encryptedData).toBe('s'.repeat(1_500));
    await expectCounterExact(user);
  });

  it('a sequential rotation that fails part-way and is rolled back', async () => {
    const user = await createTestUser();
    const a = await createItem(user, 1_000);
    const b = await createItem(user, 1_000);
    await expectCounterExact(user);

    // The second item's write fails, after the first was rewritten: the rollback
    // restores the first, and the counter follows both.
    const original = VaultItem.updateOne.bind(VaultItem) as (...args: unknown[]) => unknown;
    let writes = 0;
    vi.spyOn(VaultItem, 'updateOne').mockImplementation(((...args: unknown[]) => {
      const update = args[1] as { $set?: Record<string, unknown> } | undefined;
      if (update?.$set?.encryptedName === 'rotated-b') {
        writes += 1;
        throw new mongoose.mongo.MongoServerError({
          message: 'the database refused the write',
          code: 121,
        });
      }
      return original(...args);
    }) as never);

    const rotatedRow = (id: string, name: string) => ({
      id,
      encryptedName: name,
      nameIv: 'rotated-name-iv',
      nameTag: 'rotated-name-tag',
      encryptedData: 'z'.repeat(4_000),
      dataIv: 'rotated-data-iv',
      dataTag: 'rotated-data-tag',
    });
    const res = await call(user, 'post', '/vault/items/bulk-reencrypt', {
      authHash: user.rawPassword,
      newEncryptedVaultKey: 'rotated-key',
      newVaultKeyIv: 'rotated-iv',
      newVaultKeyTag: 'rotated-tag',
      items: [rotatedRow(a, 'rotated-a'), rotatedRow(b, 'rotated-b')],
      folders: [],
      documents: [],
    });

    expect(res.status).toBe(409);
    expect(writes).toBe(1);
    expect((await VaultItem.findById(a).lean())?.encryptedData).toBe('d'.repeat(1_000));
    await expectCounterExact(user);
  });
});
