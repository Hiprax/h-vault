import { describe, it, expect, beforeEach } from 'vitest';
import { Types } from 'mongoose';
import request from 'supertest';
import app from '../src/app.js';
import {
  MAX_IMPORT_ITEMS,
  MAX_RESTORE_DATA_LENGTH,
  PASSWORD_HISTORY_MAX,
  MAX_TAGS_PER_ITEM,
} from '@hvault/shared';
import { Folder } from '../src/models/Folder.js';
import { VaultItem } from '../src/models/VaultItem.js';
import {
  createTestUser,
  authHeader,
  getCsrf,
  seedFolder,
  seedItem,
  dbBackupPayload,
  sampleVaultItem,
} from './helpers.js';
import type { TestUser } from './helpers.js';

// ─────────────────────────────────────────────────────────────────────────────
// Phase 7 — POST /backup/restore body-limit headroom + narrowed projections.
//
// (a) Body limit. The client posts `{ conflictStrategy, data:
//     JSON.stringify(backupData) }`, so the backup document rides the wire as a
//     JSON *string* and every `"` inside it is escaped to `\"`. A quote-dense
//     backup — thousands of small items, each with a full password history — runs
//     ~6-7% quotes, so a payload whose inner `data` is still inside the 25 MiB
//     `MAX_RESTORE_DATA_LENGTH` cap serializes to well over 26 MB on the wire. The
//     old 26 MB route parser rejected it with a 413 before Zod ever ran: a backup
//     the app itself produced, and would not take back. The parser is now 30 MB.
//
// (b) Projections. `restoreBackup` used to load every existing item and folder in
//     full (`.find({ userId }).lean()`, encrypted blobs and all) purely to read
//     ids. It now projects to exactly the fields the loops touch — `_id`,
//     `sourceRefId`, `deletedAt` for items; `_id`, `sourceRefId` for folders. Each
//     drives a distinct restore behavior, so each gets a test. The `sourceRefId`
//     and `deletedAt` tests fail outright if their field is projected away; `_id`
//     cannot be dropped by a projection, so its tests guard the owned-row match
//     behaviorally instead.
// ─────────────────────────────────────────────────────────────────────────────

async function restore(
  agent: request.SuperTest<request.Test>,
  token: string,
  body: Record<string, unknown>,
) {
  const { token: csrfToken, cookie: csrfCookie } = await getCsrf(agent);
  return agent
    .post('/api/v1/backup/restore')
    .set('Authorization', authHeader(token))
    .set('x-csrf-token', csrfToken)
    .set('Cookie', csrfCookie)
    .send(body);
}

interface SkipReason {
  itemId?: string;
  folderId?: string;
  reason: string;
}

function itemSkipReasons(res: request.Response): SkipReason[] {
  return (res.body.data.itemSkipReasons ?? []) as SkipReason[];
}

// The former route limit. The quote-dense payload below must exceed it, or the
// test would pass against the old 26 MB parser and prove nothing.
const OLD_ROUTE_LIMIT_BYTES = 26 * 1024 * 1024;
const NEW_ROUTE_LIMIT_BYTES = 30 * 1024 * 1024;

/**
 * One realistically-shaped, quote-dense login row: base64-ish ciphertext fields
 * plus the two repeating structures that make a real backup quote-heavy — a full
 * tag list and a full password history. Every field is a fixed length and the
 * only variable part (`_id`) is always 24 hex chars, so the serialized size is
 * deterministic; the size arithmetic below is exact, not approximate.
 */
function quoteDenseBackupItem(): Record<string, unknown> {
  return {
    _id: new Types.ObjectId().toString(),
    itemType: 'login',
    encryptedName: 'n'.repeat(88),
    nameIv: 'i'.repeat(16),
    nameTag: 't'.repeat(24),
    encryptedData: 'd'.repeat(700),
    dataIv: 'v'.repeat(16),
    dataTag: 'g'.repeat(24),
    searchHash: 'a'.repeat(64),
    favorite: false,
    tags: Array.from({ length: MAX_TAGS_PER_ITEM }, (_, t) => `tag-${String(t)}`),
    passwordHistory: Array.from({ length: PASSWORD_HISTORY_MAX }, () => ({
      encryptedPassword: 'p'.repeat(120),
      iv: 'w'.repeat(16),
      tag: 'h'.repeat(24),
      changedAt: '2026-01-01T00:00:00.000Z',
    })),
  };
}

describe('Backup restore — quote-dense near-max payload (body-limit headroom)', () => {
  let user: TestUser;
  let agent: request.SuperTest<request.Test>;

  beforeEach(async () => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    user = await createTestUser();
  });

  it('accepts a backup whose inner data is within the 25 MiB cap but whose escaped wire body exceeds 26 MB', async () => {
    // Fill `data` to just under MAX_RESTORE_DATA_LENGTH with quote-dense rows.
    const perItemBytes = Buffer.byteLength(JSON.stringify(quoteDenseBackupItem()), 'utf8') + 1;
    const itemCount = Math.floor((MAX_RESTORE_DATA_LENGTH - 1_000) / perItemBytes);
    expect(itemCount).toBeLessThanOrEqual(MAX_IMPORT_ITEMS);

    const items = Array.from({ length: itemCount }, () => quoteDenseBackupItem());
    const data = JSON.stringify({ items, folders: [] });

    // The inner document is a legal restore payload: Zod's `.max()` accepts it.
    expect(data.length).toBeLessThanOrEqual(MAX_RESTORE_DATA_LENGTH);

    // …yet escaping it into the request envelope pushes the actual wire body past
    // the old 26 MB parser limit. This is the whole defect: a backup inside the
    // schema cap that the transport layer refused.
    const body = { conflictStrategy: 'skip', data };
    const wireBytes = Buffer.byteLength(JSON.stringify(body), 'utf8');
    expect(wireBytes).toBeGreaterThan(OLD_ROUTE_LIMIT_BYTES);
    expect(wireBytes).toBeLessThan(NEW_ROUTE_LIMIT_BYTES);

    const res = await restore(agent, user.accessToken, body);

    // Parsed and processed, not cut off with 413 Payload Too Large.
    expect(res.status).not.toBe(413);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.itemsRestored).toBe(itemCount);

    // And genuinely persisted — the request ran end to end, it did not merely parse.
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(itemCount);
  }, 180_000);
});

describe('Backup restore — narrowed existing-row projections', () => {
  let userA: TestUser;
  let userB: TestUser;
  let agent: request.SuperTest<request.Test>;

  beforeEach(async () => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    userA = await createTestUser();
    userB = await createTestUser();
  });

  // ── `deletedAt` — the trashed auto-restore branch ─────────────────────────

  it('auto-restores a trashed item regardless of conflictStrategy (deletedAt survives the projection)', async () => {
    const trashed = await seedItem(userA.id, {
      encryptedName: 'trashed-item',
      deletedAt: new Date(),
    });
    const trashedId = String(trashed._id);

    // The backup carries the item's own `_id`, so it matches by owned-`_id`. With
    // `deletedAt` projected away, `isTrashed` would read false and the row would
    // fall into the `skip` branch below — left in the trash, silently.
    const res = await restore(agent, userA.accessToken, {
      conflictStrategy: 'skip',
      data: JSON.stringify({
        items: [
          {
            _id: trashedId,
            ...sampleVaultItem({ encryptedName: 'restored-from-trash' }),
          },
        ],
        folders: [],
      }),
    });

    expect(res.status).toBe(200);
    expect(res.body.data.itemsRestored).toBe(1);
    expect(res.body.data.itemsSkipped).toBe(0);
    expect(itemSkipReasons(res)).toContainEqual({
      itemId: trashedId,
      reason: 'trashed_auto_restored',
    });

    const reloaded = await VaultItem.findById(trashedId).lean();
    expect(reloaded?.deletedAt == null).toBe(true);
    expect(reloaded?.encryptedName).toBe('restored-from-trash');
  });

  // ── `_id` — the owned-row match ───────────────────────────────────────────

  it('overwrites an owned row in place rather than duplicating it (_id match)', async () => {
    const owned = await seedItem(userA.id, { encryptedName: 'before' });
    const ownedId = String(owned._id);

    const res = await restore(agent, userA.accessToken, {
      conflictStrategy: 'overwrite',
      data: JSON.stringify({
        items: [{ _id: ownedId, ...sampleVaultItem({ encryptedName: 'after' }) }],
        folders: [],
      }),
    });

    expect(res.status).toBe(200);
    expect(res.body.data.itemsRestored).toBe(1);
    expect(await VaultItem.countDocuments({ userId: userA.id })).toBe(1);
    expect((await VaultItem.findById(ownedId).lean())?.encryptedName).toBe('after');
  });

  it('skips an owned row and leaves its ciphertext untouched (_id match)', async () => {
    const owned = await seedItem(userA.id, { encryptedName: 'original' });
    const ownedId = String(owned._id);

    const res = await restore(agent, userA.accessToken, {
      conflictStrategy: 'skip',
      data: JSON.stringify({
        items: [{ _id: ownedId, ...sampleVaultItem({ encryptedName: 'incoming' }) }],
        folders: [],
      }),
    });

    expect(res.status).toBe(200);
    expect(res.body.data.itemsSkipped).toBe(1);
    expect(await VaultItem.countDocuments({ userId: userA.id })).toBe(1);
    expect((await VaultItem.findById(ownedId).lean())?.encryptedName).toBe('original');
  });

  // ── `sourceRefId` — repeat-restore provenance idempotency ─────────────────

  it('does not duplicate on a repeat cross-account restore under skip (sourceRefId match)', async () => {
    await seedFolder(userA.id, { encryptedName: 'fA' });
    await seedItem(userA.id, { encryptedName: 'iA1' });
    await seedItem(userA.id, { encryptedName: 'iA2' });
    const payload = await dbBackupPayload(userA.id);
    const data = JSON.stringify(payload);

    const first = await restore(agent, userB.accessToken, { conflictStrategy: 'skip', data });
    expect(first.status).toBe(200);
    expect(first.body.data.itemsRestored).toBe(2);
    expect(first.body.data.foldersRestored).toBe(1);

    // Second pass: none of the backup `_id`s are owned by B, so the match can only
    // come from the `(userId, sourceRefId)` provenance stamped on the first pass.
    // Project `sourceRefId` away and every row would insert again.
    const second = await restore(agent, userB.accessToken, { conflictStrategy: 'skip', data });
    expect(second.status).toBe(200);
    expect(second.body.data.itemsSkipped).toBe(2);
    expect(second.body.data.foldersSkipped).toBe(1);

    expect(await VaultItem.countDocuments({ userId: userB.id })).toBe(2);
    expect(await Folder.countDocuments({ userId: userB.id })).toBe(1);
  });

  it('updates in place on a repeat cross-account restore under overwrite (sourceRefId match)', async () => {
    await seedItem(userA.id, { encryptedName: 'v1' });
    const first = await restore(agent, userB.accessToken, {
      conflictStrategy: 'overwrite',
      data: JSON.stringify(await dbBackupPayload(userA.id)),
    });
    expect(first.status).toBe(200);

    // Same backup rows, edited content: the second restore must find B's
    // previously-restored row by provenance and update it, not insert a second one.
    const payload = await dbBackupPayload(userA.id);
    const [row] = payload.items;
    row!.encryptedName = 'v2';

    const second = await restore(agent, userB.accessToken, {
      conflictStrategy: 'overwrite',
      data: JSON.stringify(payload),
    });
    expect(second.status).toBe(200);
    expect(second.body.data.itemsRestored).toBe(1);

    const rowsB = await VaultItem.find({ userId: userB.id }).lean();
    expect(rowsB).toHaveLength(1);
    expect(rowsB[0]?.encryptedName).toBe('v2');
  });

  it('remaps a restored item onto its restored folder (folder _id/sourceRefId both readable)', async () => {
    const folder = await seedFolder(userA.id, { encryptedName: 'parent-folder' });
    await seedItem(userA.id, { encryptedName: 'child-item', folderId: folder._id });

    const data = JSON.stringify(await dbBackupPayload(userA.id));
    const res = await restore(agent, userB.accessToken, { conflictStrategy: 'skip', data });
    expect(res.status).toBe(200);

    // The folder was minted a fresh `_id` for B; the item's `folderId` must have
    // been rewired to it rather than left dangling (or stripped).
    const [folderB] = await Folder.find({ userId: userB.id }).lean();
    const [itemB] = await VaultItem.find({ userId: userB.id }).lean();
    expect(folderB).toBeDefined();
    expect(String(itemB?.folderId)).toBe(String(folderB?._id));
    expect(String(folderB?._id)).not.toBe(String(folder._id));
  });

  it('keep_both still duplicates a folder + item on repeat restore (contract unchanged)', async () => {
    await seedFolder(userA.id, { encryptedName: 'dup-folder' });
    await seedItem(userA.id, { encryptedName: 'dup-item' });
    const data = JSON.stringify(await dbBackupPayload(userA.id));

    await restore(agent, userB.accessToken, { conflictStrategy: 'keep_both', data });
    await restore(agent, userB.accessToken, { conflictStrategy: 'keep_both', data });

    expect(await VaultItem.countDocuments({ userId: userB.id })).toBe(2);
    expect(await Folder.countDocuments({ userId: userB.id })).toBe(2);
  });
});
