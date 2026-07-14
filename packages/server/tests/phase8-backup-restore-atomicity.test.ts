/**
 * Phase 8 — Task 8.1: Backup Restore Atomicity Tests
 *
 * Tests partial failures, skip reason reporting, trashed item handling
 * across all conflict strategies, and data integrity after partial restore.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { Types } from 'mongoose';
import request from 'supertest';
import app from '../src/app.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { AuditLog } from '../src/models/AuditLog.js';
import {
  createTestUser,
  authHeader,
  sampleVaultItem,
  sampleFolder,
  getCsrf as getCsrfBase,
} from './helpers.js';
import type { TestUser } from './helpers.js';
import { MAX_FOLDERS_PER_USER } from '@hvault/shared';

const API = '/api/v1';

async function getCsrf(
  agent: request.SuperTest<request.Test>,
): Promise<{ csrfToken: string; csrfCookie: string }> {
  const { token, cookie } = await getCsrfBase(agent);
  return { csrfToken: token, csrfCookie: cookie };
}

function restoreRequest(
  agent: request.SuperTest<request.Test>,
  token: string,
  csrfToken: string,
  csrfCookie: string,
  body: Record<string, unknown>,
) {
  return agent
    .post(`${API}/backup/restore`)
    .set('Authorization', authHeader(token))
    .set('x-csrf-token', csrfToken)
    .set('Cookie', csrfCookie)
    .send(body);
}

// ─────────────────────────────────────────────────────────────────────────────
// Partial restore: valid items succeed while invalid items are skipped
// ─────────────────────────────────────────────────────────────────────────────

describe('Backup restore atomicity — partial failures', () => {
  let user: TestUser;
  let agent: request.SuperTest<request.Test>;

  beforeEach(async () => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    user = await createTestUser();
  });

  it('should restore valid items and skip items with missing encryption fields in one request', async () => {
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const validId = new Types.ObjectId().toString();
    const badId = new Types.ObjectId().toString();

    const data = JSON.stringify({
      items: [
        { _id: validId, ...sampleVaultItem({ encryptedName: 'good-item' }) },
        {
          _id: badId,
          itemType: 'login',
          encryptedData: '',
          dataIv: '',
          dataTag: '',
          encryptedName: '',
          nameIv: '',
          nameTag: '',
        },
      ],
      folders: [],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, {
      data,
      conflictStrategy: 'skip',
    });

    expect(res.status).toBe(200);
    expect(res.body.data.itemsRestored).toBe(1);
    expect(res.body.data.itemsSkipped).toBe(1);

    // Valid item persisted correctly (fresh _id -> look up by content)
    const good = await VaultItem.findOne({ userId: user.id, encryptedName: 'good-item' }).lean();
    expect(good).not.toBeNull();
    expect(good!.encryptedName).toBe('good-item');

    // Bad item not persisted
    const bad = await VaultItem.findById(badId).lean();
    expect(bad).toBeNull();
  });

  it('should restore valid items alongside items with invalid item type', async () => {
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const goodId = new Types.ObjectId().toString();
    const badTypeId = new Types.ObjectId().toString();

    const data = JSON.stringify({
      items: [
        { _id: goodId, ...sampleVaultItem({ itemType: 'note' }) },
        { _id: badTypeId, ...sampleVaultItem({ itemType: 'bitcoin_wallet' }) },
      ],
      folders: [],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, {
      data,
      conflictStrategy: 'skip',
    });

    expect(res.status).toBe(200);
    expect(res.body.data.itemsRestored).toBe(1);
    expect(res.body.data.itemsSkipped).toBe(1);
    expect(res.body.data.itemSkipReasons).toContainEqual({
      itemId: badTypeId,
      reason: 'invalid_item_type',
    });

    const good = await VaultItem.findOne({ userId: user.id, itemType: 'note' }).lean();
    expect(good).not.toBeNull();
    expect(good!.itemType).toBe('note');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Trashed items: restored regardless of conflict strategy
// ─────────────────────────────────────────────────────────────────────────────

describe('Backup restore — trashed items across conflict strategies', () => {
  let user: TestUser;
  let agent: request.SuperTest<request.Test>;

  beforeEach(async () => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    user = await createTestUser();
  });

  it('should restore trashed items with overwrite strategy (clears deletedAt)', async () => {
    const itemId = new Types.ObjectId().toString();

    await VaultItem.create({
      _id: itemId,
      userId: user.id,
      itemType: 'login',
      encryptedData: 'trashed-data',
      dataIv: 'iv',
      dataTag: 'tag',
      encryptedName: 'old-name',
      nameIv: 'iv',
      nameTag: 'tag',
      tags: [],
      favorite: false,
      deletedAt: new Date(),
    });

    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const data = JSON.stringify({
      items: [{ _id: itemId, ...sampleVaultItem({ encryptedName: 'restored-overwrite' }) }],
      folders: [],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, {
      data,
      conflictStrategy: 'overwrite',
    });

    expect(res.status).toBe(200);
    expect(res.body.data.itemsRestored).toBe(1);
    expect(res.body.data.itemsSkipped).toBe(0);

    const item = await VaultItem.findById(itemId).lean();
    expect(item!.deletedAt).toBeUndefined();
    expect(item!.encryptedName).toBe('restored-overwrite');
  });

  it('should restore trashed items with keep_both strategy (clears deletedAt)', async () => {
    const itemId = new Types.ObjectId().toString();

    await VaultItem.create({
      _id: itemId,
      userId: user.id,
      itemType: 'secret',
      encryptedData: 'trashed-secret',
      dataIv: 'iv',
      dataTag: 'tag',
      encryptedName: 'trashed-name',
      nameIv: 'iv',
      nameTag: 'tag',
      tags: [],
      favorite: false,
      deletedAt: new Date(),
    });

    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const data = JSON.stringify({
      items: [
        { _id: itemId, ...sampleVaultItem({ itemType: 'secret', encryptedName: 'restored-kb' }) },
      ],
      folders: [],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, {
      data,
      conflictStrategy: 'keep_both',
    });

    expect(res.status).toBe(200);
    expect(res.body.data.itemsRestored).toBe(1);
    expect(res.body.data.itemsSkipped).toBe(0);

    const item = await VaultItem.findById(itemId).lean();
    expect(item!.deletedAt).toBeUndefined();
  });

  it('should restore mixed trashed and non-trashed items in one request', async () => {
    const trashedId = new Types.ObjectId().toString();
    const existingId = new Types.ObjectId().toString();
    const newId = new Types.ObjectId().toString();

    // Trashed item
    await VaultItem.create({
      _id: trashedId,
      userId: user.id,
      itemType: 'login',
      encryptedData: 'trashed',
      dataIv: 'iv',
      dataTag: 'tag',
      encryptedName: 'trashed',
      nameIv: 'iv',
      nameTag: 'tag',
      tags: [],
      favorite: false,
      deletedAt: new Date(),
    });

    // Non-trashed existing item (will be skipped with 'skip' strategy)
    await VaultItem.create({
      _id: existingId,
      userId: user.id,
      itemType: 'login',
      encryptedData: 'existing',
      dataIv: 'iv',
      dataTag: 'tag',
      encryptedName: 'existing',
      nameIv: 'iv',
      nameTag: 'tag',
      tags: [],
      favorite: false,
    });

    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const data = JSON.stringify({
      items: [
        { _id: trashedId, ...sampleVaultItem({ encryptedName: 'un-trashed' }) },
        { _id: existingId, ...sampleVaultItem({ encryptedName: 'conflict' }) },
        { _id: newId, ...sampleVaultItem({ encryptedName: 'brand-new' }) },
      ],
      folders: [],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, {
      data,
      conflictStrategy: 'skip',
    });

    expect(res.status).toBe(200);
    // Trashed restored + new item restored = 2; existing skipped = 1
    expect(res.body.data.itemsRestored).toBe(2);
    expect(res.body.data.itemsSkipped).toBe(1);
    expect(res.body.data.itemSkipReasons).toContainEqual({
      itemId: existingId,
      reason: 'conflict_skipped',
    });

    // Trashed item: deletedAt cleared
    const trashed = await VaultItem.findById(trashedId).lean();
    expect(trashed!.deletedAt).toBeUndefined();
    expect(trashed!.encryptedName).toBe('un-trashed');

    // Existing item: data preserved
    const existing = await VaultItem.findById(existingId).lean();
    expect(existing!.encryptedData).toBe('existing');

    // New item: created (fresh _id -> look up by content)
    const newItem = await VaultItem.findOne({ userId: user.id, encryptedName: 'brand-new' }).lean();
    expect(newItem).not.toBeNull();
    expect(newItem!.encryptedName).toBe('brand-new');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Conflict strategies with folders: overwrite updates data, skip preserves it
// ─────────────────────────────────────────────────────────────────────────────

describe('Backup restore — folder conflict strategies', () => {
  let user: TestUser;
  let agent: request.SuperTest<request.Test>;

  beforeEach(async () => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    user = await createTestUser();
  });

  it('overwrite strategy should update existing folder data', async () => {
    const folderId = new Types.ObjectId().toString();

    await Folder.create({
      _id: folderId,
      userId: user.id,
      encryptedName: 'old-folder-name',
      nameIv: 'old-iv',
      nameTag: 'old-tag',
    });

    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const data = JSON.stringify({
      items: [],
      folders: [
        {
          _id: folderId,
          ...sampleFolder({
            encryptedName: 'new-folder-name',
            nameIv: 'new-iv',
            nameTag: 'new-tag',
          }),
        },
      ],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, {
      data,
      conflictStrategy: 'overwrite',
    });

    expect(res.status).toBe(200);
    expect(res.body.data.foldersRestored).toBe(1);
    expect(res.body.data.foldersSkipped).toBe(0);

    const folder = await Folder.findById(folderId).lean();
    expect(folder!.encryptedName).toBe('new-folder-name');
  });

  it('skip strategy should preserve existing folder data', async () => {
    const folderId = new Types.ObjectId().toString();

    await Folder.create({
      _id: folderId,
      userId: user.id,
      encryptedName: 'keep-this',
      nameIv: 'iv',
      nameTag: 'tag',
    });

    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const data = JSON.stringify({
      items: [],
      folders: [{ _id: folderId, ...sampleFolder({ encryptedName: 'do-not-overwrite' }) }],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, {
      data,
      conflictStrategy: 'skip',
    });

    expect(res.status).toBe(200);
    expect(res.body.data.foldersSkipped).toBe(1);
    expect(res.body.data.folderSkipReasons).toContainEqual({
      folderId,
      reason: 'conflict_skipped',
    });

    const folder = await Folder.findById(folderId).lean();
    expect(folder!.encryptedName).toBe('keep-this');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Skip reasons included in audit log metadata
// ─────────────────────────────────────────────────────────────────────────────

describe('Backup restore — audit log skip reasons', () => {
  let user: TestUser;
  let agent: request.SuperTest<request.Test>;

  beforeEach(async () => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    user = await createTestUser();
  });

  it('should include both item and folder skip reasons in audit log', async () => {
    const existingFolderId = new Types.ObjectId().toString();
    const badItemId = new Types.ObjectId().toString();

    await Folder.create({
      _id: existingFolderId,
      userId: user.id,
      encryptedName: 'existing',
      nameIv: 'iv',
      nameTag: 'tag',
    });

    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const data = JSON.stringify({
      items: [{ _id: badItemId, ...sampleVaultItem({ itemType: 'invalid_type' }) }],
      folders: [{ _id: existingFolderId, ...sampleFolder() }],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, {
      data,
      conflictStrategy: 'skip',
    });

    expect(res.status).toBe(200);

    const audit = await AuditLog.findOne({
      userId: user.id,
      action: 'backup_restored',
    })
      .sort({ timestamp: -1 })
      .lean();

    expect(audit).toBeDefined();
    const meta = audit!.metadata as Record<string, unknown>;
    expect(meta.itemsSkipped).toBe(1);
    expect(meta.foldersSkipped).toBe(1);

    const itemReasons = meta.itemSkipReasons as { itemId: string; reason: string }[];
    expect(itemReasons).toContainEqual({ itemId: badItemId, reason: 'invalid_item_type' });

    const folderReasons = meta.folderSkipReasons as { folderId: string; reason: string }[];
    expect(folderReasons).toContainEqual({
      folderId: existingFolderId,
      reason: 'conflict_skipped',
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Allowed fields safelist: only permitted fields are written
// ─────────────────────────────────────────────────────────────────────────────

describe('Backup restore — field allowlist enforcement', () => {
  let user: TestUser;
  let agent: request.SuperTest<request.Test>;

  beforeEach(async () => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    user = await createTestUser();
  });

  it('should not persist disallowed fields on restored items', async () => {
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const itemId = new Types.ObjectId().toString();
    const spoofedUserId = new Types.ObjectId().toString();
    // `deletedAt` is the load-bearing discriminator: it is NOT on
    // ALLOWED_ITEM_FIELDS, and the restore only marks a row trashed off the
    // EXISTING DB row's deletedAt — never the backup row's. So if the allowlist
    // strips it (correct), the fresh insert lands NOT soft-deleted; if the
    // allowlist were bypassed, the `{ ...sanitizedItem }` spread would carry the
    // future `deletedAt` straight onto the persisted document.
    //
    // (`userId` alone is a poor probe here: the server spreads `userId` LAST in
    // the write, so a spoofed value is overwritten even with no allowlist. And
    // `__proto__` in an object literal sets the prototype rather than an own
    // property and is dropped by JSON.stringify, so it never reaches the server —
    // we use JSON.parse to inject a genuine own `__proto__` property instead.)
    const rawItem = JSON.parse(
      JSON.stringify({
        _id: itemId,
        ...sampleVaultItem({ encryptedName: 'allowlist-probe' }),
        userId: spoofedUserId,
        deletedAt: '2099-01-01T00:00:00.000Z',
      }),
    ) as Record<string, unknown>;

    const data = JSON.stringify({ items: [rawItem], folders: [] });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, { data });

    expect(res.status).toBe(200);
    expect(res.body.data.itemsRestored).toBe(1);

    const item = await VaultItem.findOne({
      userId: user.id,
      encryptedName: 'allowlist-probe',
    }).lean();
    expect(item).not.toBeNull();
    // Item belongs to the authenticated user, not the spoofed userId.
    expect(item!.userId.toString()).toBe(user.id);
    // The non-allowlisted `deletedAt` must NOT have been persisted — the item is
    // live, not soft-deleted. This is what actually breaks if the allowlist is removed.
    expect(item!.deletedAt).toBeUndefined();
  });

  it('should preserve allowed fields like tags and favorite on restored items', async () => {
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const itemId = new Types.ObjectId().toString();
    const data = JSON.stringify({
      items: [
        {
          _id: itemId,
          ...sampleVaultItem({
            tags: ['banking', 'work'],
            favorite: true,
            encryptedName: 'tagged-item',
          }),
        },
      ],
      folders: [],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, { data });

    expect(res.status).toBe(200);
    expect(res.body.data.itemsRestored).toBe(1);

    const item = await VaultItem.findOne({ userId: user.id, encryptedName: 'tagged-item' }).lean();
    expect(item!.tags).toEqual(['banking', 'work']);
    expect(item!.favorite).toBe(true);
  });

  it('should preserve folder icon, color, and sortOrder on restore', async () => {
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const folderId = new Types.ObjectId().toString();
    const data = JSON.stringify({
      items: [],
      folders: [
        {
          _id: folderId,
          ...sampleFolder({
            icon: 'lock',
            color: '#ff0000',
            sortOrder: 5,
          }),
        },
      ],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, { data });

    expect(res.status).toBe(200);
    expect(res.body.data.foldersRestored).toBe(1);

    const folder = await Folder.findOne({ userId: user.id }).lean();
    expect(folder!.icon).toBe('lock');
    expect(folder!.color).toBe('#ff0000');
    expect(folder!.sortOrder).toBe(5);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Phase 3.5: Trashed items auto-restored — surfaced as trashed_auto_restored
//             skip reason regardless of conflictStrategy
// ─────────────────────────────────────────────────────────────────────────────

describe('Backup restore — trashed_auto_restored skip reason', () => {
  let user: TestUser;
  let agent: request.SuperTest<request.Test>;

  beforeEach(async () => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    user = await createTestUser();
  });

  async function seedTrashedItem(itemId: string): Promise<void> {
    await VaultItem.create({
      _id: itemId,
      userId: user.id,
      itemType: 'login',
      encryptedData: 'old-data',
      dataIv: 'iv',
      dataTag: 'tag',
      encryptedName: 'old-name',
      nameIv: 'iv',
      nameTag: 'tag',
      tags: [],
      favorite: false,
      deletedAt: new Date(),
    });
  }

  it('records trashed_auto_restored in itemSkipReasons when conflictStrategy=skip', async () => {
    const itemId = new Types.ObjectId().toString();
    await seedTrashedItem(itemId);

    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const data = JSON.stringify({
      items: [{ _id: itemId, ...sampleVaultItem({ encryptedName: 'restored' }) }],
      folders: [],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, {
      data,
      conflictStrategy: 'skip',
    });

    expect(res.status).toBe(200);
    expect(res.body.data.itemsRestored).toBe(1);
    expect(res.body.data.itemSkipReasons).toContainEqual({
      itemId,
      reason: 'trashed_auto_restored',
    });

    const item = await VaultItem.findById(itemId).lean();
    expect(item!.deletedAt).toBeUndefined();
    expect(item!.encryptedName).toBe('restored');
  });

  it('records trashed_auto_restored in itemSkipReasons when conflictStrategy=keep_both', async () => {
    const itemId = new Types.ObjectId().toString();
    await seedTrashedItem(itemId);

    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const data = JSON.stringify({
      items: [{ _id: itemId, ...sampleVaultItem({ encryptedName: 'restored-kb' }) }],
      folders: [],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, {
      data,
      conflictStrategy: 'keep_both',
    });

    expect(res.status).toBe(200);
    expect(res.body.data.itemSkipReasons).toContainEqual({
      itemId,
      reason: 'trashed_auto_restored',
    });
  });

  it('also records trashed_auto_restored when conflictStrategy=overwrite (still an override of trash semantics)', async () => {
    const itemId = new Types.ObjectId().toString();
    await seedTrashedItem(itemId);

    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const data = JSON.stringify({
      items: [{ _id: itemId, ...sampleVaultItem({ encryptedName: 'restored-ow' }) }],
      folders: [],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, {
      data,
      conflictStrategy: 'overwrite',
    });

    expect(res.status).toBe(200);
    expect(res.body.data.itemSkipReasons).toContainEqual({
      itemId,
      reason: 'trashed_auto_restored',
    });
  });

  it('audit log includes trashed_auto_restored reasons in metadata', async () => {
    const itemId = new Types.ObjectId().toString();
    await seedTrashedItem(itemId);

    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const data = JSON.stringify({
      items: [{ _id: itemId, ...sampleVaultItem() }],
      folders: [],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, {
      data,
      conflictStrategy: 'skip',
    });

    expect(res.status).toBe(200);

    const audit = await AuditLog.findOne({
      userId: user.id,
      action: 'backup_restored',
    })
      .sort({ timestamp: -1 })
      .lean();

    expect(audit).toBeDefined();
    const meta = audit!.metadata as Record<string, unknown>;
    const reasons = meta.itemSkipReasons as { itemId: string; reason: string }[];
    expect(reasons).toContainEqual({ itemId, reason: 'trashed_auto_restored' });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// keep_both: searchHash collision must not crash the restore
// ─────────────────────────────────────────────────────────────────────────────
//
// The Folder model has a unique partial index on (userId, searchHash). When a
// backup contains a folder whose searchHash matches an existing folder and
// the user picks `keep_both`, naively re-using the searchHash on the
// duplicate insert throws E11000 and crashes the entire restore. The
// controller must strip searchHash from the duplicate so the duplicate
// folder is created without it (the user can rename later, which rebuilds
// the searchHash).

describe('Backup restore — keep_both with colliding folder searchHash', () => {
  let user: TestUser;
  let agent: request.SuperTest<request.Test>;

  beforeEach(async () => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    user = await createTestUser();
    // The collision paths under test rely on the unique partial (userId,
    // searchHash) index being live to raise E11000. autoIndex builds it
    // lazily, so await it here to keep these assertions order-independent.
    await Folder.init();
  });

  it('returns 200 and creates a duplicate folder without searchHash on collision', async () => {
    const sharedHash = 'a'.repeat(64);
    const existingFolderId = new Types.ObjectId().toString();

    await Folder.create({
      _id: existingFolderId,
      userId: user.id,
      encryptedName: 'existing',
      nameIv: 'iv',
      nameTag: 'tag',
      searchHash: sharedHash,
    });

    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const data = JSON.stringify({
      items: [],
      folders: [
        {
          _id: existingFolderId,
          ...sampleFolder({
            encryptedName: 'duplicate-from-backup',
            searchHash: sharedHash,
          }),
        },
      ],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, {
      data,
      conflictStrategy: 'keep_both',
    });

    expect(res.status).toBe(200);
    expect(res.body.data.foldersRestored).toBe(1);
    expect(res.body.data.foldersSkipped).toBe(0);

    // Two folders now exist for the user. The original keeps its searchHash;
    // the duplicate must NOT carry the colliding hash (otherwise the unique
    // partial index would have rejected it).
    const folders = await Folder.find({ userId: user.id }).lean();
    expect(folders.length).toBe(2);

    const original = folders.find((f) => String(f._id) === existingFolderId);
    expect(original).toBeDefined();
    expect(original!.searchHash).toBe(sharedHash);

    const duplicate = folders.find((f) => String(f._id) !== existingFolderId);
    expect(duplicate).toBeDefined();
    expect(duplicate!.encryptedName).toBe('duplicate-from-backup');
    expect(duplicate!.searchHash).toBeUndefined();
  });

  it('does not leak a 5xx when the searchHash collides on a fresh _id under keep_both', async () => {
    const sharedHash = 'b'.repeat(64);
    const newBackupId = new Types.ObjectId().toString();

    // Existing folder with the colliding searchHash but a DIFFERENT _id, so
    // the controller goes down the !exists branch and tries to create a new
    // folder with the same searchHash.
    await Folder.create({
      userId: user.id,
      encryptedName: 'sibling',
      nameIv: 'iv',
      nameTag: 'tag',
      searchHash: sharedHash,
    });

    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const data = JSON.stringify({
      items: [],
      folders: [
        {
          _id: newBackupId,
          ...sampleFolder({
            encryptedName: 'colliding-fresh-folder',
            searchHash: sharedHash,
          }),
        },
      ],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, {
      data,
      conflictStrategy: 'keep_both',
    });

    expect(res.status).toBe(200);
    expect(res.body.data.foldersRestored).toBe(1);

    const restored = await Folder.findOne({
      userId: user.id,
      encryptedName: 'colliding-fresh-folder',
    }).lean();
    expect(restored).not.toBeNull();
    // searchHash stripped on collision — defense-in-depth fallback path
    expect(restored!.searchHash).toBeUndefined();
    expect(restored!.encryptedName).toBe('colliding-fresh-folder');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// folderId ownership validation: a tampered backup file may carry an item
// whose folderId points at a non-existent (or another user's) folder. The
// listing/access queries scope by userId so it is not an IDOR escalation,
// but the dangling reference would surface in the UI as "unknown folder".
// The restore flow strips folderId values that don't belong to the user's
// folder set — same defensive pattern used by importVault.
// ─────────────────────────────────────────────────────────────────────────────

describe('Backup restore — folderId ownership validation', () => {
  let user: TestUser;
  let agent: request.SuperTest<request.Test>;

  beforeEach(async () => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    user = await createTestUser();
  });

  it('strips folderId from restored items when it does not belong to the user', async () => {
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const itemId = new Types.ObjectId().toString();
    // A folderId that does not exist in this user's collection at all.
    const forgedFolderId = new Types.ObjectId().toString();

    const data = JSON.stringify({
      items: [
        {
          _id: itemId,
          ...sampleVaultItem({
            encryptedName: 'item-with-forged-folderId',
            folderId: forgedFolderId,
          }),
        },
      ],
      folders: [],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, {
      data,
      conflictStrategy: 'skip',
    });

    expect(res.status).toBe(200);
    expect(res.body.data.itemsRestored).toBe(1);

    const item = await VaultItem.findOne({
      userId: user.id,
      encryptedName: 'item-with-forged-folderId',
    }).lean();
    expect(item).not.toBeNull();
    // folderId stripped because the forged ID doesn't belong to the user
    expect(item!.folderId).toBeUndefined();
  });

  it('preserves folderId when it points at a folder that exists for the user', async () => {
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    // Pre-create a folder owned by the user
    const ownFolderId = new Types.ObjectId().toString();
    await Folder.create({
      _id: ownFolderId,
      userId: user.id,
      encryptedName: 'real-folder',
      nameIv: 'iv',
      nameTag: 'tag',
    });

    const itemId = new Types.ObjectId().toString();
    const data = JSON.stringify({
      items: [
        {
          _id: itemId,
          ...sampleVaultItem({
            encryptedName: 'item-in-real-folder',
            folderId: ownFolderId,
          }),
        },
      ],
      folders: [],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, {
      data,
      conflictStrategy: 'skip',
    });

    expect(res.status).toBe(200);
    expect(res.body.data.itemsRestored).toBe(1);

    const item = await VaultItem.findOne({
      userId: user.id,
      encryptedName: 'item-in-real-folder',
    }).lean();
    expect(item!.folderId?.toString()).toBe(ownFolderId);
  });

  it('preserves folderId when it points at a folder restored from the same backup', async () => {
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const folderId = new Types.ObjectId().toString();
    const itemId = new Types.ObjectId().toString();

    const data = JSON.stringify({
      items: [
        {
          _id: itemId,
          ...sampleVaultItem({
            encryptedName: 'item-in-restored-folder',
            folderId,
          }),
        },
      ],
      folders: [{ _id: folderId, ...sampleFolder({ encryptedName: 'restored-folder' }) }],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, {
      data,
      conflictStrategy: 'skip',
    });

    expect(res.status).toBe(200);
    expect(res.body.data.itemsRestored).toBe(1);
    expect(res.body.data.foldersRestored).toBe(1);

    // The folder was restored with a fresh _id; the item's folderId must be
    // remapped to that new id, not the backup's folderId.
    const restoredFolder = await Folder.findOne({
      userId: user.id,
      encryptedName: 'restored-folder',
    }).lean();
    const item = await VaultItem.findOne({
      userId: user.id,
      encryptedName: 'item-in-restored-folder',
    }).lean();
    expect(item!.folderId?.toString()).toBe(String(restoredFolder!._id));
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// T3 — folder "overwrite" branch must survive a searchHash collision.
//
// The overwrite branch blindly $sets the backup folder's searchHash. Because
// searchHash is in ALLOWED_FOLDER_FIELDS, a backup that carries a hash already
// owned by a DIFFERENT sibling folder (a tampered backup, or two folders
// renamed to the same name after the backup was taken) violates the unique
// partial (userId, searchHash) index → E11000. Previously that bubbled to a 500
// and left a half-applied restore. The branch now retries without the colliding
// hash, mirroring the keep_both / fresh-insert siblings.
// ─────────────────────────────────────────────────────────────────────────────

describe('Backup restore — folder overwrite survives searchHash collisions', () => {
  let user: TestUser;
  let agent: request.SuperTest<request.Test>;

  beforeEach(async () => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    user = await createTestUser();
    // The unique partial (userId, searchHash) index must be live for the
    // collision to raise E11000. autoIndex builds it lazily; await it so the
    // assertion is deterministic regardless of test ordering.
    await Folder.init();
  });

  it('returns 200 (not 500) when overwrite would set a searchHash already owned by a sibling folder', async () => {
    const hashA = 'a'.repeat(64);
    const hashB = 'b'.repeat(64);
    const folderAId = new Types.ObjectId().toString();

    // F_A owns hashA (this is the folder we overwrite); F_B owns hashB.
    await Folder.create({
      _id: folderAId,
      userId: user.id,
      encryptedName: 'folder-A',
      nameIv: 'iv',
      nameTag: 'tag',
      searchHash: hashA,
    });
    await Folder.create({
      userId: user.id,
      encryptedName: 'folder-B',
      nameIv: 'iv',
      nameTag: 'tag',
      searchHash: hashB,
    });

    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const restoredItemId = new Types.ObjectId().toString();
    const data = JSON.stringify({
      // Folders restore before items: if the overwrite threw, the loop would
      // abort before this item — so its presence proves the restore continued.
      items: [{ _id: restoredItemId, ...sampleVaultItem({ encryptedName: 'after-folder' }) }],
      folders: [
        {
          _id: folderAId,
          ...sampleFolder({ encryptedName: 'folder-A-overwritten', searchHash: hashB }),
        },
      ],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, {
      data,
      conflictStrategy: 'overwrite',
    });

    expect(res.status).toBe(200);
    expect(res.body.data.foldersRestored).toBe(1);

    // F_A's content was overwritten; the colliding hash was stripped on retry.
    const folderA = await Folder.findById(folderAId).lean();
    expect(folderA!.encryptedName).toBe('folder-A-overwritten');
    expect(folderA!.searchHash).toBeUndefined();

    // F_B is untouched and keeps its hash — no folder was lost.
    const folderB = await Folder.findOne({ userId: user.id, encryptedName: 'folder-B' }).lean();
    expect(folderB!.searchHash).toBe(hashB);

    // The collision did not abort the restore — the trailing item still landed.
    const item = await VaultItem.findOne({ userId: user.id, encryptedName: 'after-folder' }).lean();
    expect(item).not.toBeNull();
    expect(item!.encryptedName).toBe('after-folder');
  });

  it('returns 200 and ignores a malformed-format searchHash on overwrite (would otherwise be a ValidationError)', async () => {
    const folderId = new Types.ObjectId().toString();
    const originalHash = 'c'.repeat(64);
    await Folder.create({
      _id: folderId,
      userId: user.id,
      encryptedName: 'orig',
      nameIv: 'iv',
      nameTag: 'tag',
      searchHash: originalHash,
    });

    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const data = JSON.stringify({
      items: [],
      folders: [
        {
          _id: folderId,
          // Uppercase hex fails the model's /^[a-f0-9]{64}$/ match validator.
          ...sampleFolder({ encryptedName: 'orig-overwritten', searchHash: 'A'.repeat(64) }),
        },
      ],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, {
      data,
      conflictStrategy: 'overwrite',
    });

    expect(res.status).toBe(200);
    expect(res.body.data.foldersRestored).toBe(1);

    const folder = await Folder.findById(folderId).lean();
    expect(folder!.encryptedName).toBe('orig-overwritten');
    // The garbage hash was dropped before the write, so it never reached the
    // $set; the folder keeps its existing valid hash rather than 500-ing.
    expect(folder!.searchHash).toBe(originalHash);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// T4 — a single malformed item must never abort the whole restore.
//
// The item loop previously wrote each row straight to Mongoose with no
// per-item guard and no searchHash/length sanitization, so one bad row (a
// legacy/tampered backup with an over-length field or a non-hex searchHash)
// raised a ValidationError that 500'd the entire restore mid-flight. Each
// write is now guarded: validation/duplicate-key failures skip just that item
// (reason `invalid_item_data`); an invalid-format searchHash is stripped so a
// salvageable item is still restored.
// ─────────────────────────────────────────────────────────────────────────────

describe('Backup restore — malformed item data is skipped, not fatal', () => {
  let user: TestUser;
  let agent: request.SuperTest<request.Test>;

  beforeEach(async () => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    user = await createTestUser();
  });

  it('skips an item whose encryptedData exceeds the model maxlength and restores the rest', async () => {
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const goodId = new Types.ObjectId().toString();
    const badId = new Types.ObjectId().toString();

    // 500_001 chars exceeds the VaultItem.encryptedData maxlength of 500_000
    // while keeping the whole payload comfortably under the 30 MB body limit.
    const oversized = 'a'.repeat(500_001);

    const data = JSON.stringify({
      items: [
        { _id: goodId, ...sampleVaultItem({ encryptedName: 'good' }) },
        { _id: badId, ...sampleVaultItem({ encryptedName: 'bad', encryptedData: oversized }) },
      ],
      folders: [],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, {
      data,
      conflictStrategy: 'skip',
    });

    expect(res.status).toBe(200);
    expect(res.body.data.itemsRestored).toBe(1);
    expect(res.body.data.itemsSkipped).toBe(1);
    expect(res.body.data.itemSkipReasons).toContainEqual({
      itemId: badId,
      reason: 'invalid_item_data',
    });

    const good = await VaultItem.findOne({ userId: user.id, encryptedName: 'good' }).lean();
    expect(good).not.toBeNull();
    expect(good!.encryptedName).toBe('good');

    const bad = await VaultItem.findById(badId).lean();
    expect(bad).toBeNull();
  });

  it('strips an invalid-format searchHash and still restores the item (no abort)', async () => {
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const itemId = new Types.ObjectId().toString();
    const data = JSON.stringify({
      items: [
        {
          _id: itemId,
          // Non-hex/too-short — fails VaultItem.searchHash /^[a-f0-9]{64}$/.
          ...sampleVaultItem({ encryptedName: 'bad-hash', searchHash: 'ZZZ' }),
        },
      ],
      folders: [],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, {
      data,
      conflictStrategy: 'skip',
    });

    expect(res.status).toBe(200);
    expect(res.body.data.itemsRestored).toBe(1);
    expect(res.body.data.itemsSkipped).toBe(0);

    const item = await VaultItem.findOne({ userId: user.id, encryptedName: 'bad-hash' }).lean();
    expect(item).not.toBeNull();
    expect(item!.searchHash).toBeUndefined();
    expect(item!.encryptedName).toBe('bad-hash');
  });

  it('guards the trashed auto-restore path so a malformed item does not abort and leaves the trashed entry intact', async () => {
    const itemId = new Types.ObjectId().toString();
    // Seed a trashed item. A backup item with the same _id is normally
    // auto-restored regardless of conflictStrategy; with oversized data it must
    // be skipped and the trashed original must stay trashed and unchanged.
    await VaultItem.create({
      _id: itemId,
      userId: user.id,
      ...sampleVaultItem({ encryptedName: 'trashed-original' }),
      deletedAt: new Date(),
    });

    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const oversized = 'a'.repeat(500_001);
    const data = JSON.stringify({
      items: [
        { _id: itemId, ...sampleVaultItem({ encryptedName: 'bad', encryptedData: oversized }) },
      ],
      folders: [],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, {
      data,
      conflictStrategy: 'skip',
    });

    expect(res.status).toBe(200);
    expect(res.body.data.itemsRestored).toBe(0);
    expect(res.body.data.itemsSkipped).toBe(1);
    expect(res.body.data.itemSkipReasons).toContainEqual({
      itemId,
      reason: 'invalid_item_data',
    });

    const item = await VaultItem.findById(itemId).lean();
    expect(item).not.toBeNull();
    // Validation runs before the update is applied, so deletedAt was never
    // cleared and the original ciphertext is untouched.
    expect(item!.deletedAt).toBeTruthy();
    expect(item!.encryptedName).toBe('trashed-original');
  });

  it('includes invalid_item_data in the backup_restored audit metadata', async () => {
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const badId = new Types.ObjectId().toString();
    const oversized = 'a'.repeat(500_001);
    const data = JSON.stringify({
      items: [
        { _id: badId, ...sampleVaultItem({ encryptedName: 'bad', encryptedData: oversized }) },
      ],
      folders: [],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, {
      data,
      conflictStrategy: 'skip',
    });

    expect(res.status).toBe(200);

    const audit = await AuditLog.findOne({
      userId: user.id,
      action: 'backup_restored',
    })
      .sort({ timestamp: -1 })
      .lean();

    expect(audit).toBeDefined();
    const meta = audit!.metadata as Record<string, unknown>;
    const reasons = meta.itemSkipReasons as { itemId: string; reason: string }[];
    expect(reasons).toContainEqual({ itemId: badId, reason: 'invalid_item_data' });
  });

  it('skips an item whose passwordHistory has an un-castable date without aborting (CastError path)', async () => {
    const existingId = new Types.ObjectId().toString();
    const goodId = new Types.ObjectId().toString();

    // Existing (non-trashed) item so the malformed backup row goes down the
    // overwrite -> findOneAndUpdate path, where an un-castable date surfaces as
    // a bare Mongoose CastError rather than a wrapped ValidationError.
    await VaultItem.create({
      _id: existingId,
      userId: user.id,
      ...sampleVaultItem({ encryptedName: 'existing-original' }),
    });

    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const data = JSON.stringify({
      items: [
        {
          _id: existingId,
          ...sampleVaultItem({
            encryptedName: 'existing-overwritten',
            passwordHistory: [
              { encryptedPassword: 'x', iv: 'iv', tag: 'tag', changedAt: 'not-a-real-date' },
            ],
          }),
        },
        { _id: goodId, ...sampleVaultItem({ encryptedName: 'good' }) },
      ],
      folders: [],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, {
      data,
      conflictStrategy: 'overwrite',
    });

    expect(res.status).toBe(200);
    expect(res.body.data.itemSkipReasons).toContainEqual({
      itemId: existingId,
      reason: 'invalid_item_data',
    });

    // The good item still landed — the bad row did not abort the restore.
    const good = await VaultItem.findOne({ userId: user.id, encryptedName: 'good' }).lean();
    expect(good).not.toBeNull();
    expect(good!.encryptedName).toBe('good');

    // The existing item was not overwritten with the malformed payload.
    const existing = await VaultItem.findById(existingId).lean();
    expect(existing!.encryptedName).toBe('existing-original');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Phase 3.1 — per-folder error resilience (mirror the item loop)
// A malformed folder no longer aborts the whole restore: a non-castable
// parentId is sanitized (folder still restores, parent-less), while a folder
// that fails a required-field validator is skipped as invalid_folder_data.
// ─────────────────────────────────────────────────────────────────────────────

describe('Backup restore — malformed folder data is skipped/sanitized, not fatal', () => {
  let user: TestUser;
  let agent: request.SuperTest<request.Test>;

  beforeEach(async () => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    user = await createTestUser();
  });

  it('sanitizes a non-castable parentId, skips a folder missing a required field, and still restores the rest', async () => {
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const goodFolderId = new Types.ObjectId().toString();
    const badParentFolderId = new Types.ObjectId().toString();
    const missingFieldFolderId = new Types.ObjectId().toString();
    const itemId = new Types.ObjectId().toString();

    const data = JSON.stringify({
      items: [{ _id: itemId, ...sampleVaultItem({ encryptedName: 'good-item' }) }],
      folders: [
        // Fully valid — restores normally.
        { _id: goodFolderId, ...sampleFolder({ encryptedName: 'good-folder' }) },
        // Non-castable parentId — sanitized up front so the folder restores
        // WITHOUT a parent rather than throwing a CastError and aborting.
        {
          _id: badParentFolderId,
          ...sampleFolder({ encryptedName: 'bad-parent-folder', parentId: 'not-an-objectid' }),
        },
        // Missing the required encryptedName — a ValidationError that survives
        // sanitization, so the folder is skipped as invalid_folder_data.
        { _id: missingFieldFolderId, nameIv: 'iv', nameTag: 'tag' },
      ],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, {
      data,
      conflictStrategy: 'skip',
    });

    expect(res.status).toBe(200);
    // good-folder + bad-parent-folder both restore; the missing-field one skips.
    expect(res.body.data.foldersRestored).toBe(2);
    expect(res.body.data.foldersSkipped).toBe(1);
    expect(res.body.data.folderSkipReasons).toContainEqual({
      folderId: missingFieldFolderId,
      reason: 'invalid_folder_data',
    });
    // The item still restored — a bad folder no longer aborts the whole request.
    expect(res.body.data.itemsRestored).toBe(1);

    // The sanitized folder persisted, with parentId dropped.
    const badParent = await Folder.findOne({
      userId: user.id,
      encryptedName: 'bad-parent-folder',
    }).lean();
    expect(badParent).not.toBeNull();
    expect(badParent!.parentId).toBeUndefined();
    expect(badParent!.encryptedName).toBe('bad-parent-folder');

    // The good folder and item persisted.
    const goodFolder = await Folder.findOne({
      userId: user.id,
      encryptedName: 'good-folder',
    }).lean();
    expect(goodFolder).not.toBeNull();
    const item = await VaultItem.findOne({ userId: user.id, encryptedName: 'good-item' }).lean();
    expect(item).not.toBeNull();

    // The invalid folder was not persisted.
    const missing = await Folder.findById(missingFieldFolderId).lean();
    expect(missing).toBeNull();

    // The audit log carries the folder skip reason.
    const audit = await AuditLog.findOne({ userId: user.id, action: 'backup_restored' })
      .sort({ timestamp: -1 })
      .lean();
    expect(audit).toBeDefined();
    const meta = audit!.metadata as Record<string, unknown>;
    const folderReasons = meta.folderSkipReasons as { folderId: string; reason: string }[];
    expect(folderReasons).toContainEqual({
      folderId: missingFieldFolderId,
      reason: 'invalid_folder_data',
    });
  });

  it('ignores a malformed parentId when overwriting an existing folder, retaining its current parent', async () => {
    // Existing parent + child (child under parent). Both pre-exist so the
    // backup rows go down the overwrite -> findOneAndUpdate path.
    const parentId = new Types.ObjectId().toString();
    const childId = new Types.ObjectId().toString();
    await Folder.create({
      _id: parentId,
      userId: user.id,
      encryptedName: 'parent',
      nameIv: 'iv',
      nameTag: 'tag',
    });
    await Folder.create({
      _id: childId,
      userId: user.id,
      encryptedName: 'child-old',
      nameIv: 'iv',
      nameTag: 'tag',
      parentId: new Types.ObjectId(parentId),
    });

    const { csrfToken, csrfCookie } = await getCsrf(agent);

    // Overwrite the child with a backup row carrying a NON-CASTABLE parentId.
    // The malformed value is stripped up front (no CastError abort). On the
    // overwrite path the stripped value is ignored, so the child keeps its
    // existing valid parent (mirroring the item loop's folderId behavior) —
    // corrupt backup data must not yank a well-placed folder to the root.
    const data = JSON.stringify({
      items: [],
      folders: [
        {
          _id: childId,
          ...sampleFolder({ encryptedName: 'child-new', parentId: 'not-an-objectid' }),
        },
      ],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, {
      data,
      conflictStrategy: 'overwrite',
    });

    expect(res.status).toBe(200);
    expect(res.body.data.foldersRestored).toBe(1);
    expect(res.body.data.foldersSkipped).toBe(0);

    const child = await Folder.findById(childId).lean();
    expect(child).not.toBeNull();
    // Overwritten fields applied; existing valid parent retained.
    expect(child!.encryptedName).toBe('child-new');
    expect(String(child!.parentId)).toBe(parentId);
  });

  it('skips a folder whose encryptedName exceeds the model maxlength (ValidationError) without aborting', async () => {
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const goodFolderId = new Types.ObjectId().toString();
    const badFolderId = new Types.ObjectId().toString();

    // 1001 chars exceeds the Folder.encryptedName maxlength of 1000.
    const oversized = 'a'.repeat(1001);

    const data = JSON.stringify({
      items: [],
      folders: [
        { _id: goodFolderId, ...sampleFolder({ encryptedName: 'ok' }) },
        { _id: badFolderId, ...sampleFolder({ encryptedName: oversized }) },
      ],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, {
      data,
      conflictStrategy: 'skip',
    });

    expect(res.status).toBe(200);
    expect(res.body.data.foldersRestored).toBe(1);
    expect(res.body.data.foldersSkipped).toBe(1);
    expect(res.body.data.folderSkipReasons).toContainEqual({
      folderId: badFolderId,
      reason: 'invalid_folder_data',
    });

    const good = await Folder.findOne({ userId: user.id, encryptedName: 'ok' }).lean();
    expect(good).not.toBeNull();
    const bad = await Folder.findById(badFolderId).lean();
    expect(bad).toBeNull();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Phase 3.2 — enforce MAX_FOLDERS_PER_USER on restore (parity with the item cap)
// ─────────────────────────────────────────────────────────────────────────────

describe('Backup restore — MAX_FOLDERS_PER_USER enforcement', () => {
  let user: TestUser;
  let agent: request.SuperTest<request.Test>;

  beforeEach(async () => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    user = await createTestUser();
  });

  it('rejects a restore that would exceed the per-user folder limit with 400', async () => {
    // Seed the user right at the cap so a single restored folder would exceed it.
    const seed = Array.from({ length: MAX_FOLDERS_PER_USER }, () => ({
      userId: user.id,
      encryptedName: 'seed',
      nameIv: 'iv',
      nameTag: 'tag',
    }));
    await Folder.insertMany(seed);

    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const data = JSON.stringify({
      items: [],
      folders: [{ _id: new Types.ObjectId().toString(), ...sampleFolder({ encryptedName: 'x' }) }],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, {
      data,
      conflictStrategy: 'keep_both',
    });

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
    expect(String(res.body.message)).toMatch(/folder limit/i);

    // Nothing beyond the seed was created.
    const count = await Folder.countDocuments({ userId: user.id });
    expect(count).toBe(MAX_FOLDERS_PER_USER);
  });

  it('allows a restore that stays within the per-user folder limit', async () => {
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const data = JSON.stringify({
      items: [],
      folders: [
        { _id: new Types.ObjectId().toString(), ...sampleFolder({ encryptedName: 'a' }) },
        { _id: new Types.ObjectId().toString(), ...sampleFolder({ encryptedName: 'b' }) },
      ],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, {
      data,
      conflictStrategy: 'skip',
    });

    expect(res.status).toBe(200);
    expect(res.body.data.foldersRestored).toBe(2);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Phase 3.3 — additive keep_both folder re-parenting
// A restored backup only remaps NEWLY-CREATED duplicates; the pre-existing tree
// is left untouched.
// ─────────────────────────────────────────────────────────────────────────────

describe('Backup restore — additive keep_both re-parenting', () => {
  let user: TestUser;
  let agent: request.SuperTest<request.Test>;

  beforeEach(async () => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    user = await createTestUser();
  });

  it('remaps duplicated children under duplicated parents while leaving the existing tree in place', async () => {
    const parentId = new Types.ObjectId().toString();
    const childId = new Types.ObjectId().toString();

    // Seed an existing parent + child (child under parent).
    await Folder.create({
      _id: parentId,
      userId: user.id,
      encryptedName: 'parent',
      nameIv: 'iv',
      nameTag: 'tag',
    });
    await Folder.create({
      _id: childId,
      userId: user.id,
      encryptedName: 'child',
      nameIv: 'iv',
      nameTag: 'tag',
      parentId: new Types.ObjectId(parentId),
    });

    const { csrfToken, csrfCookie } = await getCsrf(agent);

    // keep_both restore containing BOTH the parent and the child (both conflict,
    // both get duplicated). The duplicated child must land under the duplicated
    // parent; the original child must stay under the original parent.
    const data = JSON.stringify({
      items: [],
      folders: [
        { _id: parentId, ...sampleFolder({ encryptedName: 'parent-dup' }) },
        {
          _id: childId,
          ...sampleFolder({ encryptedName: 'child-dup', parentId }),
        },
      ],
    });

    const res = await restoreRequest(agent, user.accessToken, csrfToken, csrfCookie, {
      data,
      conflictStrategy: 'keep_both',
    });

    expect(res.status).toBe(200);
    expect(res.body.data.foldersRestored).toBe(2);

    const allFolders = await Folder.find({ userId: user.id }).lean();
    const newParent = allFolders.find(
      (f) => String(f._id) !== parentId && f.encryptedName === 'parent-dup',
    );
    const newChild = allFolders.find(
      (f) => String(f._id) !== childId && f.encryptedName === 'child-dup',
    );
    expect(newParent).toBeDefined();
    expect(newChild).toBeDefined();

    // Duplicated child points at the duplicated parent.
    expect(String(newChild!.parentId)).toBe(String(newParent!._id));

    // The ORIGINAL child is untouched — still under the ORIGINAL parent.
    const originalChild = await Folder.findById(childId).lean();
    expect(String(originalChild!.parentId)).toBe(parentId);
    expect(String(originalChild!.parentId)).not.toBe(String(newParent!._id));
  });
});
