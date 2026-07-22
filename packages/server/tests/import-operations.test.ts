/**
 * Phase 6 — server-executor: `POST /tools/import` with a structured
 * `operations` payload.
 *
 * Conflict resolution moved to the client (the only place the plaintext, and
 * therefore item identity, exists), so the server became a validated EXECUTOR:
 * it applies exactly the `inserts` and `updates` it is handed and makes no
 * matching decisions of its own. These tests pin what it validates and in what
 * order, and that a rejection at any stage writes nothing.
 *
 * Covers:
 *   • inserts-only, updates-only and mixed requests
 *   • an update targeting another user's / an unknown / a trashed id → 400,
 *     nothing written (never a silent skip)
 *   • an update cannot rewrite tags / favorite / folderId / itemType
 *   • an over-count or over-length `passwordHistory` → 400, nothing written
 *   • an over-length ciphertext field → 400 before any write
 *   • a rotation in flight → 409
 *   • a second import while the per-user JobLock is held → 409, and the lock is
 *     released on both the success and the failure path
 *   • the per-user item cap, counted against net-new inserts only
 *   • the `import` audit-log entry and its counts
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import request from 'supertest';
import {
  MAX_ENCRYPTED_NAME_LENGTH,
  MAX_ITEMS_PER_USER,
  PASSWORD_HISTORY_MAX,
} from '@hvault/shared';
import app from '../src/app.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { User } from '../src/models/User.js';
import { acquireJobLock, releaseJobLock } from '../src/utils/jobLock.js';
import { vaultImportLockName } from '../src/utils/controllerHelpers.js';
import {
  createTestUser,
  authHeader,
  sampleVaultItem,
  seedItem,
  seedFolder,
  getCsrf,
  rawItems,
  type TestUser,
} from './helpers.js';

const API = '/api/v1';

/** A distinct, well-formed (lowercase hex, 64-char) searchHash per index. */
function searchHashFor(index: number): string {
  return index.toString(16).padStart(64, '0');
}

/** One `inserts[]` row that satisfies `importInsertItemSchema`. */
function insertRow(
  index: number,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return sampleVaultItem({
    encryptedName: `inserted-name-${String(index)}`,
    encryptedData: `inserted-data-${String(index)}`,
    searchHash: searchHashFor(index),
    ...overrides,
  });
}

/** One `updates[]` row that satisfies `importUpdateItemSchema`. */
function updateRow(id: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id,
    encryptedName: 'updated-name',
    nameIv: 'updated-name-iv',
    nameTag: 'updated-name-tag',
    encryptedData: 'updated-data',
    dataIv: 'updated-data-iv',
    dataTag: 'updated-data-tag',
    searchHash: searchHashFor(999),
    ...overrides,
  };
}

function historyEntry(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    encryptedPassword: 'previous-password-ciphertext',
    iv: 'history-iv',
    tag: 'history-tag',
    changedAt: new Date().toISOString(),
    ...overrides,
  };
}

async function postOperations(
  token: string,
  operations: Record<string, unknown>,
  extra: Record<string, unknown> = {},
): Promise<request.Response> {
  const agent = request.agent(app);
  const csrf = await getCsrf(agent);

  return agent
    .post(`${API}/tools/import`)
    .set('Authorization', authHeader(token))
    .set('x-csrf-token', csrf.token)
    .set('Cookie', csrf.cookie)
    .send({ format: 'json', operations, ...extra });
}

describe('Phase 6 — POST /tools/import executes structured operations', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ── The three request shapes ─────────────────────────────────────────

  it('inserts every row of an inserts-only request', async () => {
    const res = await postOperations(user.accessToken, {
      inserts: [insertRow(1), insertRow(2), insertRow(3)],
    });

    expect(res.status).toBe(201);
    expect(res.body.data).toEqual({ insertedCount: 3, updatedCount: 0 });

    const stored = await rawItems(user.id);
    expect(stored).toHaveLength(3);
    expect(stored.map((item) => item.encryptedName).sort()).toEqual([
      'inserted-name-1',
      'inserted-name-2',
      'inserted-name-3',
    ]);
    // Every row is scoped to the caller, regardless of what the payload claimed.
    expect(stored.every((item) => String(item.userId) === user.id)).toBe(true);
  });

  it('rewrites content in place for an updates-only request and refreshes searchHash', async () => {
    const existing = await seedItem(user.id, {
      encryptedName: 'original-name',
      encryptedData: 'original-data',
      searchHash: searchHashFor(7),
    });

    const res = await postOperations(user.accessToken, {
      updates: [updateRow(String(existing._id))],
    });

    expect(res.status).toBe(201);
    expect(res.body.data).toEqual({ insertedCount: 0, updatedCount: 1 });

    const stored = await rawItems(user.id);
    expect(stored).toHaveLength(1);
    expect(stored[0]!.encryptedName).toBe('updated-name');
    expect(stored[0]!.encryptedData).toBe('updated-data');
    // An overwrite replaces `encryptedName`, so the stored hash must follow it
    // or it strands against the old name.
    expect(stored[0]!.searchHash).toBe(searchHashFor(999));
  });

  it('applies inserts and updates together in one mixed request', async () => {
    const existing = await seedItem(user.id, {
      encryptedName: 'original-name',
      encryptedData: 'original-data',
    });

    const res = await postOperations(user.accessToken, {
      inserts: [insertRow(1), insertRow(2)],
      updates: [updateRow(String(existing._id))],
    });

    expect(res.status).toBe(201);
    expect(res.body.data).toEqual({ insertedCount: 2, updatedCount: 1 });

    const stored = await rawItems(user.id);
    expect(stored).toHaveLength(3);
    expect(stored.filter((item) => item.encryptedData === 'updated-data')).toHaveLength(1);
  });

  it('carries password history onto an updated item', async () => {
    const existing = await seedItem(user.id, { encryptedData: 'original-data' });

    const res = await postOperations(user.accessToken, {
      updates: [updateRow(String(existing._id), { passwordHistory: [historyEntry()] })],
    });

    expect(res.status).toBe(201);

    const stored = await rawItems(user.id);
    const history = stored[0]!.passwordHistory as { encryptedPassword: string }[];
    expect(history).toHaveLength(1);
    expect(history[0]!.encryptedPassword).toBe('previous-password-ciphertext');
  });

  it('carries password history onto an inserted item', async () => {
    // Re-importing a native export recreates items that already had a history.
    // Dropping it would silently lose every previous password of an item
    // restored from a backup export.
    const res = await postOperations(user.accessToken, {
      inserts: [insertRow(1, { passwordHistory: [historyEntry()] })],
    });

    expect(res.status).toBe(201);
    expect(res.body.data).toEqual({ insertedCount: 1, updatedCount: 0 });

    const stored = await rawItems(user.id);
    const history = stored[0]!.passwordHistory as { encryptedPassword: string }[];
    expect(history).toHaveLength(1);
    expect(history[0]!.encryptedPassword).toBe('previous-password-ciphertext');
  });

  it('rejects an over-count passwordHistory on an insert and writes nothing', async () => {
    const res = await postOperations(user.accessToken, {
      inserts: [
        insertRow(1, {
          passwordHistory: Array.from({ length: PASSWORD_HISTORY_MAX + 1 }, () => historyEntry()),
        }),
      ],
    });

    expect(res.status).toBe(400);
    expect(await rawItems(user.id)).toHaveLength(0);
  });

  // ── Update targets are validated, never silently skipped ─────────────

  it('rejects an update naming another user’s item and writes nothing', async () => {
    const other = await createTestUser({ email: 'other-owner@example.com' });
    const foreign = await seedItem(other.id, { encryptedData: 'foreign-data' });

    const res = await postOperations(user.accessToken, {
      inserts: [insertRow(1)],
      updates: [updateRow(String(foreign._id))],
    });

    expect(res.status).toBe(400);
    expect(JSON.stringify(res.body)).toMatch(/update target/i);

    // The foreign row is untouched AND the accompanying insert never landed:
    // validation precedes every write, so the request is all-or-nothing.
    const foreignStored = await rawItems(other.id);
    expect(foreignStored[0]!.encryptedData).toBe('foreign-data');
    expect(await rawItems(user.id)).toHaveLength(0);
  });

  it('rejects an update naming an id that does not exist', async () => {
    const res = await postOperations(user.accessToken, {
      updates: [updateRow('0123456789abcdef01234567')],
    });

    expect(res.status).toBe(400);
    expect(JSON.stringify(res.body)).toMatch(/update target/i);
    expect(await rawItems(user.id)).toHaveLength(0);
  });

  it('rejects an update naming a trashed item and leaves it in the trash unchanged', async () => {
    const trashed = await seedItem(user.id, {
      encryptedData: 'trashed-data',
      deletedAt: new Date(),
    });

    const res = await postOperations(user.accessToken, {
      updates: [updateRow(String(trashed._id))],
    });

    expect(res.status).toBe(400);
    expect(JSON.stringify(res.body)).toMatch(/update target/i);

    const stored = await rawItems(user.id);
    expect(stored).toHaveLength(1);
    expect(stored[0]!.encryptedData).toBe('trashed-data');
    expect(stored[0]!.deletedAt).not.toBeNull();
  });

  // ── An update writes CONTENT only ────────────────────────────────────

  it('cannot rewrite tags, favorite, folderId or itemType through an update', async () => {
    const folder = await seedFolder(user.id);
    const existing = await seedItem(user.id, {
      itemType: 'note',
      tags: ['keep-me'],
      favorite: true,
      folderId: folder._id,
    });

    // Every one of these keys is smuggled onto the update row. `importUpdateItemSchema`
    // strips unknown keys, so they are already gone by the time the controller
    // runs; the narrow `ALLOWED_UPDATE_FIELDS` projection is the second line of
    // defence that keeps this true if the schema is ever widened. The `$set`
    // assertion below pins that projection's actual output, since the end-to-end
    // assertions alone would still pass on the broader insert allowlist.
    const setSpy = vi.spyOn(VaultItem, 'updateOne');

    const res = await postOperations(user.accessToken, {
      updates: [
        updateRow(String(existing._id), {
          itemType: 'login',
          tags: ['injected'],
          favorite: false,
          folderId: null,
        }),
      ],
    });

    expect(res.status).toBe(201);

    const stored = await rawItems(user.id);
    expect(stored[0]!.encryptedData).toBe('updated-data');
    expect(stored[0]!.itemType).toBe('note');
    expect(stored[0]!.tags).toEqual(['keep-me']);
    expect(stored[0]!.favorite).toBe(true);
    expect(String(stored[0]!.folderId)).toBe(String(folder._id));

    const applied = setSpy.mock.calls[0]![1] as { $set: Record<string, unknown> };
    expect(Object.keys(applied.$set).sort()).toEqual([
      'dataIv',
      'dataTag',
      'encryptedData',
      'encryptedName',
      'nameIv',
      'nameTag',
      'searchHash',
    ]);
  });

  it('runs every update with runValidators so the model’s validators fire', async () => {
    // `runValidators: true` is what makes the VaultItem `passwordHistory` count
    // and per-entry length validators apply to an update at all; without it they
    // are silently inert. Asserted through a spy on the real call rather than by
    // reading the source.
    const existing = await seedItem(user.id);
    const updateSpy = vi.spyOn(VaultItem, 'updateOne');

    const res = await postOperations(user.accessToken, {
      updates: [updateRow(String(existing._id))],
    });

    expect(res.status).toBe(201);
    expect(updateSpy).toHaveBeenCalledTimes(1);
    expect(updateSpy.mock.calls[0]![2]).toMatchObject({ runValidators: true });
  });

  it('strips a folderId the caller does not own from an insert but still imports it', async () => {
    const other = await createTestUser({ email: 'folder-owner@example.com' });
    const foreignFolder = await seedFolder(other.id);

    const res = await postOperations(user.accessToken, {
      inserts: [insertRow(1, { folderId: String(foreignFolder._id) })],
    });

    expect(res.status).toBe(201);
    expect(res.body.data.insertedCount).toBe(1);

    const stored = await rawItems(user.id);
    expect(stored).toHaveLength(1);
    expect(stored[0]!.folderId).toBeUndefined();
  });

  it('keeps a folderId the caller does own', async () => {
    const folder = await seedFolder(user.id);

    const res = await postOperations(user.accessToken, {
      inserts: [insertRow(1, { folderId: String(folder._id) })],
    });

    expect(res.status).toBe(201);
    const stored = await rawItems(user.id);
    expect(String(stored[0]!.folderId)).toBe(String(folder._id));
  });

  // ── Bounded payloads ─────────────────────────────────────────────────

  // These two ceilings are enforced by `importPasswordHistoryEntrySchema`
  // on the wire, which is what rejects here — `assertImportFieldLengths` walks
  // only top-level strings and would never see a nested history array, which is
  // precisely why the bound had to live in the schema. What is asserted is the
  // end-to-end outcome: the request is refused and the target row is untouched.
  it('rejects a passwordHistory with more than the allowed number of entries', async () => {
    const existing = await seedItem(user.id, { encryptedData: 'original-data' });

    const res = await postOperations(user.accessToken, {
      updates: [
        updateRow(String(existing._id), {
          passwordHistory: Array.from({ length: PASSWORD_HISTORY_MAX + 1 }, () => historyEntry()),
        }),
      ],
    });

    expect(res.status).toBe(400);
    const stored = await rawItems(user.id);
    expect(stored[0]!.encryptedData).toBe('original-data');
    expect(stored[0]!.passwordHistory).toBeUndefined();
  });

  it('rejects an over-length passwordHistory entry', async () => {
    const existing = await seedItem(user.id, { encryptedData: 'original-data' });

    const res = await postOperations(user.accessToken, {
      updates: [
        updateRow(String(existing._id), {
          passwordHistory: [historyEntry({ encryptedPassword: 'x'.repeat(5_001) })],
        }),
      ],
    });

    expect(res.status).toBe(400);
    const stored = await rawItems(user.id);
    expect(stored[0]!.encryptedData).toBe('original-data');
    expect(stored[0]!.passwordHistory).toBeUndefined();
  });

  it('rejects an over-length encrypted field before any write', async () => {
    // Two layers agree on this ceiling: `importInsertItemSchema` bounds it on the
    // wire (which is what rejects here) and `assertImportFieldLengths` re-checks
    // both arrays in the controller before any DB work. What matters behaviorally
    // is that one bad row takes the whole request down with nothing persisted.
    const existing = await seedItem(user.id, { encryptedData: 'original-data' });

    const res = await postOperations(user.accessToken, {
      inserts: [
        insertRow(1),
        insertRow(2, { encryptedName: 'x'.repeat(MAX_ENCRYPTED_NAME_LENGTH + 1) }),
      ],
      updates: [updateRow(String(existing._id))],
    });

    expect(res.status).toBe(400);

    // Neither the well-formed sibling insert nor the update landed.
    const stored = await rawItems(user.id);
    expect(stored).toHaveLength(1);
    expect(stored[0]!.encryptedData).toBe('original-data');
  });

  // ── Fences: rotation and the per-user import lock ────────────────────

  it('409s while a vault-key rotation is in flight and writes nothing', async () => {
    await User.updateOne({ _id: user.id }, { $set: { rotationInProgress: true } });

    const res = await postOperations(user.accessToken, { inserts: [insertRow(1)] });

    expect(res.status).toBe(409);
    expect(await rawItems(user.id)).toHaveLength(0);
  });

  it('409s when another import already holds the per-user lock, and writes nothing', async () => {
    const lockName = vaultImportLockName(user.id);
    const heldBy = await acquireJobLock(lockName, 60_000);
    expect(heldBy).not.toBeNull();

    try {
      const res = await postOperations(user.accessToken, { inserts: [insertRow(1)] });

      expect(res.status).toBe(409);
      expect(JSON.stringify(res.body)).toMatch(/import is already in progress/i);
      expect(await rawItems(user.id)).toHaveLength(0);
    } finally {
      await releaseJobLock(lockName, heldBy!);
    }
  });

  it('holds the lock only for the duration of one request, so sequential batches all land', async () => {
    // The client splits a large import into several requests sent one after the
    // other. Each must find the lock free, or a legitimate migration dies on its
    // own predecessor.
    const first = await postOperations(user.accessToken, { inserts: [insertRow(1)] });
    const second = await postOperations(user.accessToken, { inserts: [insertRow(2)] });
    const third = await postOperations(user.accessToken, { inserts: [insertRow(3)] });

    expect([first.status, second.status, third.status]).toEqual([201, 201, 201]);
    expect(await rawItems(user.id)).toHaveLength(3);
  });

  it('releases the lock when the import fails AFTER acquiring it, so the retry succeeds', async () => {
    // The rejection must originate INSIDE the locked region or this proves
    // nothing: validation failures (an unknown update id, an over-long field)
    // all fire before the lock is ever taken, so they would pass even with the
    // `finally` release deleted. The cap check is the first step under the lock,
    // so drive the failure through that.
    const countSpy = vi
      .spyOn(VaultItem, 'countDocuments')
      .mockResolvedValue(MAX_ITEMS_PER_USER as never);

    const rejected = await postOperations(user.accessToken, { inserts: [insertRow(1)] });
    expect(rejected.status).toBe(400);
    expect(JSON.stringify(rejected.body)).toMatch(/per-user item limit/i);

    countSpy.mockRestore();

    const retry = await postOperations(user.accessToken, { inserts: [insertRow(1)] });
    expect(retry.status).toBe(201);
    expect(await rawItems(user.id)).toHaveLength(1);
  });

  it('rejects an updates array naming the same item id twice', async () => {
    const existing = await seedItem(user.id, { encryptedData: 'original-data' });

    const res = await postOperations(user.accessToken, {
      updates: [
        updateRow(String(existing._id)),
        updateRow(String(existing._id), { encryptedData: 'second-write' }),
      ],
    });

    expect(res.status).toBe(400);
    expect(JSON.stringify(res.body)).toMatch(/more than once/i);

    const stored = await rawItems(user.id);
    expect(stored).toHaveLength(1);
    expect(stored[0]!.encryptedData).toBe('original-data');
  });

  // ── The per-user item cap ────────────────────────────────────────────

  it('rejects a request whose inserts would breach the per-user cap and writes nothing', async () => {
    const existing = await seedItem(user.id, { encryptedData: 'original-data' });

    // Pinned rather than seeded: minting 10,000 real rows would be far too slow.
    // The stub is persistent because the executor counts twice — once before the
    // lock and once against the state the writes observe.
    vi.spyOn(VaultItem, 'countDocuments').mockResolvedValue((MAX_ITEMS_PER_USER - 1) as never);

    const res = await postOperations(user.accessToken, {
      inserts: [insertRow(1), insertRow(2)],
      updates: [updateRow(String(existing._id))],
    });

    expect(res.status).toBe(400);
    expect(JSON.stringify(res.body)).toMatch(/per-user item limit/i);

    // The cap check precedes every write, so the update in the same request is
    // rolled into the rejection rather than half-applied.
    const stored = await rawItems(user.id);
    expect(stored).toHaveLength(1);
    expect(stored[0]!.encryptedData).toBe('original-data');
  });

  it('counts updates as free: an updates-only request at the cap still succeeds', async () => {
    const existing = await seedItem(user.id, { encryptedData: 'original-data' });

    vi.spyOn(VaultItem, 'countDocuments').mockResolvedValue(MAX_ITEMS_PER_USER as never);

    const res = await postOperations(user.accessToken, {
      updates: [updateRow(String(existing._id))],
    });

    expect(res.status).toBe(201);
    expect(res.body.data).toEqual({ insertedCount: 0, updatedCount: 1 });
    expect((await rawItems(user.id))[0]!.encryptedData).toBe('updated-data');
  });

  it('allows a request that lands exactly on the cap', async () => {
    vi.spyOn(VaultItem, 'countDocuments').mockResolvedValue((MAX_ITEMS_PER_USER - 2) as never);

    const res = await postOperations(user.accessToken, {
      inserts: [insertRow(1), insertRow(2)],
    });

    expect(res.status).toBe(201);
    expect(res.body.data.insertedCount).toBe(2);
    expect(await rawItems(user.id)).toHaveLength(2);
  });

  // ── Audit trail ──────────────────────────────────────────────────────

  it('writes one import audit entry carrying the format, strategy and both counts', async () => {
    const existing = await seedItem(user.id);

    const res = await postOperations(
      user.accessToken,
      {
        inserts: [insertRow(1), insertRow(2)],
        updates: [updateRow(String(existing._id))],
      },
      { format: 'bitwarden', conflictStrategy: 'overwrite' },
    );

    expect(res.status).toBe(201);

    const entry = await AuditLog.findOne({ userId: user.id, action: 'import' }).lean();
    expect(entry).not.toBeNull();
    expect(entry!.metadata).toMatchObject({
      format: 'bitwarden',
      conflictStrategy: 'overwrite',
      insertedCount: 2,
      updatedCount: 1,
    });
  });

  it('writes no import audit entry when the request is rejected', async () => {
    const res = await postOperations(user.accessToken, {
      updates: [updateRow('0123456789abcdef01234567')],
    });

    expect(res.status).toBe(400);
    expect(await AuditLog.countDocuments({ userId: user.id, action: 'import' })).toBe(0);
  });
});
