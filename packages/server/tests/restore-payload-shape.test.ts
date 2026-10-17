/**
 * F-14: a restore's backup payload is parsed and shape-checked BEFORE the rotation
 * fence and BEFORE the vault-key exclusion lock, and a malformed one is a 400.
 *
 * `data` is validated by the route as a string only. It used to be parsed inside
 * the locked span with no shape check, so a payload whose `items` was a number, an
 * object or an array holding `null` failed as a 500 while holding the lock, and a
 * payload that was not an object at all (`[]`, `"x"`) "restored successfully" with
 * nothing in it.
 *
 * "Before the lock" is proved two ways: with the lock HELD by another holder, a
 * malformed payload is still answered 400 (a request that took the lock first
 * would be told the lock is busy), and no lock acquisition is attempted at all for
 * it. The same is shown for the fence with a raised `rotationInProgress`.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Types } from 'mongoose';
import request from 'supertest';
import app from '../src/app.js';
import { JobLock } from '../src/models/JobLock.js';
import { User } from '../src/models/User.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { MAX_FOLDERS_PER_USER, MAX_ITEMS_PER_USER } from '@hvault/shared';
import {
  authHeader,
  createTestUser,
  getCsrf,
  sampleFolder,
  sampleVaultItem,
  type TestUser,
} from './helpers.js';

const RESTORE = '/api/v1/backup/restore';

let user: TestUser;
let agent: request.Agent;

beforeEach(async () => {
  agent = request.agent(app);
  user = await createTestUser({ emailVerified: true });
});

afterEach(() => {
  vi.restoreAllMocks();
});

async function restore(data: string): Promise<request.Response> {
  const csrf = await getCsrf(agent);
  return agent
    .post(RESTORE)
    .set('Authorization', authHeader(user.accessToken))
    .set('x-csrf-token', csrf.token)
    .set('Cookie', csrf.cookie)
    .send({ conflictStrategy: 'keep_both', data });
}

/** Every lock acquisition attempted for this account's vault-key lock. */
function watchRotationLockAttempts(): () => number {
  const spy = vi.spyOn(JobLock, 'findOneAndUpdate');
  return () =>
    spy.mock.calls.filter(
      ([filter]) => (filter as { jobName?: unknown }).jobName === `vault-rotation:${user.id}`,
    ).length;
}

/** The account's rows and the restore's audit trail, all of which must stay empty. */
async function nothingWritten(): Promise<void> {
  expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
  expect(await Folder.countDocuments({ userId: user.id })).toBe(0);
  expect(await AuditLog.countDocuments({ userId: user.id, action: 'backup_restored' })).toBe(0);
  expect(await JobLock.countDocuments({ jobName: `vault-rotation:${user.id}` })).toBe(0);
}

/** Another holder takes this account's vault-key lock, so a request that took it would be told "busy". */
async function holdLockElsewhere(): Promise<void> {
  await JobLock.create({
    jobName: `vault-rotation:${user.id}`,
    lockedBy: 'another-holder',
    lockedAt: new Date(),
    expiresAt: new Date(Date.now() + 60_000),
  });
}

const MALFORMED: readonly { name: string; data: string; path: string }[] = [
  { name: '`items` is a number', data: '{"items":5}', path: 'items' },
  { name: '`items` holds null', data: '{"items":[null]}', path: 'items.0' },
  { name: '`items` is an object', data: '{"items":{}}', path: 'items' },
  { name: 'the payload is an array', data: '[]', path: '' },
  { name: 'the payload is a string', data: '"x"', path: '' },
  { name: '`folders` is a string', data: '{"folders":"x"}', path: 'folders' },
  { name: '`folders` holds a number', data: '{"items":[],"folders":[1]}', path: 'folders.0' },
  { name: '`items` holds an array', data: '{"items":[[]]}', path: 'items.0' },
  { name: 'the payload is null', data: 'null', path: '' },
  { name: '`version` is an object', data: '{"version":{},"items":[]}', path: 'version' },
  { name: '`exportDate` is a number', data: '{"exportDate":1,"items":[]}', path: 'exportDate' },
  // Accepted as "no items" before F-14; no backup the product writes has it.
  { name: '`items` is null', data: '{"items":null}', path: 'items' },
];

describe('F-14: a malformed backup payload is a 400, decided before the fence and the lock', () => {
  for (const { name, data, path } of MALFORMED) {
    it(`refuses a payload where ${name}, writing nothing and taking no lock`, async () => {
      const lockAttempts = watchRotationLockAttempts();

      const res = await restore(data);

      expect(res.status).toBe(400);
      expect(res.body).toMatchObject({ success: false, statusCode: 400 });
      const message = String(res.body.message);
      expect(message.startsWith('Invalid backup data')).toBe(true);
      if (path !== '') expect(message).toContain(`at ${path}:`);
      else expect(message).not.toContain(' at ');
      expect(lockAttempts()).toBe(0);
      await nothingWritten();
    });
  }

  it('names only the FIRST problem when a file has many', async () => {
    const res = await restore(JSON.stringify({ items: [null, null, null], folders: 'x' }));

    expect(res.status).toBe(400);
    const message = String(res.body.message);
    expect(message.startsWith('Invalid backup data at items.0: ')).toBe(true);
    expect(message).not.toContain('items.1');
    expect(message).not.toContain('folders');
    expect(message.split('Invalid backup data')).toHaveLength(2);
  });

  it('the lock watch sees the acquisition a well-formed restore makes (positive control)', async () => {
    const lockAttempts = watchRotationLockAttempts();

    const res = await restore('{"items":[],"folders":[]}');

    expect(res.status).toBe(200);
    expect(lockAttempts()).toBe(1);
  });

  it('refuses more items than one account can hold before taking the lock', async () => {
    // The item cap and the entry cap are the same number, so the count, which
    // runs first, is what answers; the skeleton's own item bound is pinned in
    // the shared schema tests.
    await holdLockElsewhere();
    const data = JSON.stringify({
      items: Array.from({ length: MAX_ITEMS_PER_USER + 1 }, () => ({})),
    });

    const res = await restore(data);

    expect(res.status).toBe(400);
    expect(String(res.body.message)).toMatch(/^Restore exceeds the maximum allowed item count/);
  });

  it('refuses more folders than one account can hold before taking the lock', async () => {
    await holdLockElsewhere();
    const data = JSON.stringify({
      folders: Array.from({ length: MAX_FOLDERS_PER_USER + 1 }, () => ({})),
    });

    const res = await restore(data);

    expect(res.status).toBe(400);
    expect(String(res.body.message)).toMatch(/^Invalid backup data at folders: /);
  });

  it('counts entries before looking at any row: 10,001 junk rows get the entry-count refusal', async () => {
    await holdLockElsewhere();
    const data = JSON.stringify({ items: Array.from({ length: 10_001 }, () => 0) });

    const res = await restore(data);

    expect(res.status).toBe(400);
    expect(res.body.message).toBe(
      'Restore exceeds the maximum allowed item count (10000). Received 10001 entries.',
    );
  });

  it('refuses more entries in total than one restore may carry before taking the lock', async () => {
    await holdLockElsewhere();
    const data = JSON.stringify({
      items: Array.from({ length: 9_501 }, () => ({})),
      folders: Array.from({ length: 500 }, () => ({})),
    });

    const res = await restore(data);

    expect(res.status).toBe(400);
    expect(String(res.body.message)).toMatch(/^Restore exceeds the maximum allowed item count/);
  });

  it('still refuses malformed JSON with its own 400, taking no lock', async () => {
    const lockAttempts = watchRotationLockAttempts();

    const res = await restore('{"items":[');

    expect(res.status).toBe(400);
    expect(res.body.message).toBe('Invalid backup data: malformed JSON');
    expect(lockAttempts()).toBe(0);
    await nothingWritten();
  });

  it('answers a malformed payload 400 even while another holder has the lock (not "busy")', async () => {
    await holdLockElsewhere();

    const res = await restore('{"items":5}');

    expect(res.status).toBe(400);
    expect(String(res.body.message)).toMatch(/^Invalid backup data at items:/);
    // The other holder's lock is untouched.
    const held = await JobLock.findOne({ jobName: `vault-rotation:${user.id}` }).lean();
    expect(held?.lockedBy).toBe('another-holder');
  });

  it('answers a malformed payload 400 even while a rotation fence is raised (not 409)', async () => {
    await User.updateOne({ _id: user.id }, { $set: { rotationInProgress: true } });

    const res = await restore('[]');

    expect(res.status).toBe(400);
    expect(String(res.body.message)).toMatch(/^Invalid backup data: /);
  });

  it('still answers a WELL-FORMED payload with the fence raised as the 409 it was', async () => {
    await User.updateOne({ _id: user.id }, { $set: { rotationInProgress: true } });

    const res = await restore('{"items":[],"folders":[]}');

    expect(res.status).toBe(409);
    await nothingWritten();
  });
});

describe('F-14: a well-formed backup still restores in full', () => {
  it('restores a backup carrying every top-level block the download writes, rows intact', async () => {
    const itemId = new Types.ObjectId().toString();
    const folderId = new Types.ObjectId().toString();
    const backup = {
      version: '0.15.0',
      exportDate: new Date().toISOString(),
      items: [
        {
          _id: itemId,
          ...sampleVaultItem({ encryptedName: 'kept-name', tags: ['t1', 't2'] }),
          folderId,
        },
      ],
      folders: [{ _id: folderId, ...sampleFolder({ encryptedName: 'kept-folder' }) }],
      encryptedVaultKey: 'evk',
      vaultKeyIv: 'iv',
      vaultKeyTag: 'tag',
      backupEncryption: {
        encryptedBWK: 'bwk',
        bwkIv: 'bwk-iv',
        bwkTag: 'bwk-tag',
        bwkSalt: 'bwk-salt',
        bwkEncryptedVaultKey: 'bwk-evk',
        bwkVaultKeyIv: 'bwk-vk-iv',
        bwkVaultKeyTag: 'bwk-vk-tag',
      },
      metadata: { itemCount: 1, folderCount: 1 },
      documentSummary: { count: 0 },
      integrity: 'f'.repeat(64),
    };

    const res = await restore(JSON.stringify(backup));

    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.data).toMatchObject({ itemsRestored: 1, foldersRestored: 1 });
    // Every field of the row survived the shape check: nothing was stripped.
    const item = await VaultItem.findOne({ userId: user.id }).lean();
    expect(item).toMatchObject({
      itemType: 'login',
      encryptedName: 'kept-name',
      encryptedData: 'test-encrypted-data-base64',
      dataIv: 'test-data-iv',
      dataTag: 'test-data-tag',
      tags: ['t1', 't2'],
    });
    const folder = await Folder.findOne({ userId: user.id }).lean();
    expect(folder).toMatchObject({ encryptedName: 'kept-folder' });
    expect(String(item!.folderId)).toBe(String(folder!._id));
    // A restore never adopts the file's key material.
    const after = await User.findById(user.id).lean();
    expect(after!.encryptedVaultKey).not.toBe('evk');
  });

  it('admits a file exactly at every bound: 9,500 items and 500 folders, 10,000 entries', async () => {
    // Every row here lacks its encrypted fields, so each is SKIPPED by the
    // restore's own row checks: what is pinned is that the skeleton and the
    // count let the file through to them, not that the rows are stored.
    const data = JSON.stringify({
      items: Array.from({ length: MAX_ITEMS_PER_USER - MAX_FOLDERS_PER_USER }, () => ({})),
      folders: Array.from({ length: MAX_FOLDERS_PER_USER }, () => ({})),
    });

    const res = await restore(data);

    expect(res.status, JSON.stringify(res.body).slice(0, 300)).toBe(200);
    expect(res.body.data).toMatchObject({ itemsRestored: 0, foldersRestored: 0 });
  });

  it(`admits ${String(MAX_ITEMS_PER_USER)} items in one array`, async () => {
    const data = JSON.stringify({ items: Array.from({ length: MAX_ITEMS_PER_USER }, () => ({})) });

    const res = await restore(data);

    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({ itemsRestored: 0, itemsSkipped: MAX_ITEMS_PER_USER });
  });

  it('restores a payload with neither items nor folders as an empty restore', async () => {
    const res = await restore('{"version":1}');

    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({ itemsRestored: 0, foldersRestored: 0 });
  });
});

describe('a row identity that is not a string of 24 hex digits is no identity (F-14)', () => {
  // bson's `ObjectId.isValid` (and so `mongoose.isValidObjectId`) accepts an OBJECT
  // whose `id` is 24 hex digits. `String()` of that object is "[object Object]",
  // which the restore then handed to `new ObjectId`: a 500 inside the lock, and on
  // `keep_both` after folders had already been written.
  const HEX = '0123456789abcdef01234567';
  const objectId = { id: HEX };

  async function restoreWith(
    strategy: 'skip' | 'overwrite' | 'keep_both',
    data: Record<string, unknown>,
  ): Promise<request.Response> {
    const csrf = await getCsrf(agent);
    return agent
      .post(RESTORE)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf.token)
      .set('Cookie', csrf.cookie)
      .send({ conflictStrategy: strategy, data: JSON.stringify(data) });
  }

  for (const strategy of ['skip', 'overwrite', 'keep_both'] as const) {
    it(`${strategy}: an object _id, parentId and folderId restore as rows with fresh ids, never a 500`, async () => {
      const res = await restoreWith(strategy, {
        folders: [{ ...sampleFolder(), _id: objectId, parentId: objectId }],
        items: [{ ...sampleVaultItem(), _id: objectId, folderId: { _id: HEX } }],
      });

      expect(res.status).toBe(200);
      expect(res.body.data).toMatchObject({ itemsRestored: 1, foldersRestored: 1 });
      const folders = await Folder.find({ userId: user.id }).lean();
      const items = await VaultItem.find({ userId: user.id }).lean();
      expect(folders).toHaveLength(1);
      expect(items).toHaveLength(1);
      // Fresh ids, never the one the object carried, and no reference to it either.
      expect(String(folders[0]!._id)).not.toBe(HEX);
      expect(String(items[0]!._id)).not.toBe(HEX);
      expect(folders[0]!.parentId).toBeUndefined();
      expect(items[0]!.folderId).toBeUndefined();
      // The restore completed and is on the record.
      expect(await AuditLog.countDocuments({ userId: user.id, action: 'backup_restored' })).toBe(1);
    });
  }
});
