/**
 * Import validation and edge cases.
 *
 * Covers import scenarios not already exercised by tools.test.ts or
 * import-operations.test.ts:
 *   • One malformed row rejects the whole request — there is no per-item skip.
 *   • Identical rows are never collapsed: the server does no matching at all,
 *     within a batch or across batches.
 *   • A large batch (near the MAX_IMPORT_ITEMS boundary).
 *   • An insert whose folderId belongs to a different user.
 *   • Attacker-supplied keys on an insert row (`_id`, timestamps) and a
 *     malformed searchHash.
 *
 * The former conflict-strategy tests are gone with the behavior they described:
 * the server no longer matches an incoming row against the vault, so it can no
 * longer overwrite, skip or duplicate one. Resolution happens on the client,
 * which is the only place the plaintext identity of an item exists.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../src/app.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { createTestUser, authHeader, sampleVaultItem, getCsrf, type TestUser } from './helpers.js';

const API = '/api/v1';

async function postImport(
  token: string,
  payload: Record<string, unknown>,
): Promise<request.Response> {
  const agent = request.agent(app);
  const csrf = await getCsrf(agent);
  return agent
    .post(`${API}/tools/import`)
    .set('Authorization', authHeader(token))
    .set('x-csrf-token', csrf.token)
    .set('Cookie', csrf.cookie)
    .send(payload);
}

/** One `inserts[]` row that satisfies `importInsertItemSchema`. */
function insertRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return sampleVaultItem({ searchHash: 'a'.repeat(64), ...overrides });
}

describe('Import validation and edge cases', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  // ── One malformed row rejects the whole request ─────────────────────

  describe('mixed valid and malformed rows in one batch', () => {
    it('rejects the whole request and writes nothing when a row lacks its ciphertext', async () => {
      const res = await postImport(user.accessToken, {
        format: 'json',
        operations: {
          inserts: [
            insertRow({ encryptedName: 'valid-1' }),
            // Empty ciphertext fields: every one of them is `min(1)`.
            {
              itemType: 'login',
              encryptedData: '',
              dataIv: '',
              dataTag: '',
              encryptedName: '',
              nameIv: '',
              nameTag: '',
              searchHash: 'b'.repeat(64),
            },
            insertRow({ encryptedName: 'valid-2' }),
          ],
        },
      });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      // Import stays all-or-nothing: the two well-formed rows are not written.
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
    });

    it('rejects a row that omits its searchHash', async () => {
      const { searchHash: _omitted, ...withoutHash } = insertRow({ encryptedName: 'no-hash' });

      const res = await postImport(user.accessToken, {
        format: 'json',
        operations: { inserts: [withoutHash] },
      });

      expect(res.status).toBe(400);
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
    });
  });

  // ── No server-side de-duplication, ever ─────────────────────────────

  describe('identical rows are never collapsed', () => {
    it('inserts every row even when name and searchHash repeat, within and across batches', async () => {
      // The identity of a login is its site and username, both inside the
      // encrypted blob — so the server cannot compute it and must not guess at
      // it. Collapsing rows by `encryptedName` / `searchHash` is exactly the
      // defect this contract removes: ten accounts on one site became one.
      const duplicate = { encryptedName: 'shared-enc-name', searchHash: 'a'.repeat(64) };

      const first = await postImport(user.accessToken, {
        format: 'json',
        operations: { inserts: [insertRow(duplicate), insertRow(duplicate)] },
      });
      expect(first.status).toBe(201);
      expect(first.body.data).toEqual({ insertedCount: 2, updatedCount: 0 });

      const second = await postImport(user.accessToken, {
        format: 'json',
        conflictStrategy: 'skip',
        operations: { inserts: [insertRow(duplicate)] },
      });
      expect(second.status).toBe(201);
      expect(second.body.data).toEqual({ insertedCount: 1, updatedCount: 0 });

      // Three rows, three distinct ids — `conflictStrategy` is audit metadata
      // and changes no outcome here.
      const items = await VaultItem.find({ userId: user.id }).lean();
      expect(items).toHaveLength(3);
      expect(new Set(items.map((item) => String(item._id))).size).toBe(3);
    });
  });

  // ── Import large batch near MAX_IMPORT_ITEMS ────────────────────────

  describe('large batch import', () => {
    it('should accept a batch of 1,000 valid items', async () => {
      // 1,000 items is enough to verify batching works without blowing up test time
      const inserts = Array.from({ length: 1_000 }, (_, i) =>
        insertRow({
          encryptedName: `bulk-${String(i)}`,
          searchHash: i.toString(16).padStart(64, '0'),
        }),
      );

      const res = await postImport(user.accessToken, {
        format: 'json',
        operations: { inserts },
      });

      expect(res.status).toBe(201);
      expect(res.body.data.insertedCount).toBe(1_000);

      const count = await VaultItem.countDocuments({ userId: user.id });
      expect(count).toBe(1_000);
    }, 30_000);
  });

  // ── Cross-user folderId ─────────────────────────────────────────────

  describe('import with folderId belonging to a different user', () => {
    it("should strip folderId when it references a different user's folder", async () => {
      // Create a second user and give them a folder
      const otherUser = await createTestUser({ email: `other-${Date.now()}@example.com` });
      const otherFolder = await Folder.create({
        userId: otherUser.id,
        encryptedName: 'other-user-folder',
        nameIv: 'iv',
        nameTag: 'tag',
      });
      const otherFolderId = otherFolder._id.toString();

      // The first user tries to import an item pointing at the other user's folder
      const res = await postImport(user.accessToken, {
        format: 'json',
        operations: {
          inserts: [insertRow({ folderId: otherFolderId, encryptedName: 'cross-user' })],
        },
      });

      expect(res.status).toBe(201);
      expect(res.body.data.insertedCount).toBe(1);

      // The folderId must NOT have been stored — it's another user's folder
      const item = await VaultItem.findOne({
        userId: user.id,
        encryptedName: 'cross-user',
      });
      expect(item).not.toBeNull();
      expect(item!.folderId).toBeUndefined();

      // And the other user's folder must still exist and be untouched
      const stillThere = await Folder.findById(otherFolderId);
      expect(stillThere).not.toBeNull();
      expect(String(stillThere!.userId)).toBe(otherUser.id);
    });
  });

  // ── Field-injection safety on an insert row ─────────────────────────

  describe('import honours only the safe field projection', () => {
    it('ignores attacker-supplied non-allowlisted fields (_id, timestamps)', async () => {
      // Parsing + encryption are client-side; the server receives native encrypted
      // items and maps ONLY a fixed set of fields. A tampered item that smuggles a
      // chosen _id or timestamps must not have those honoured — the server mints
      // its own id and stamps its own timestamps.
      const before = Date.now();

      const res = await postImport(user.accessToken, {
        format: 'json',
        operations: {
          inserts: [
            {
              itemType: 'login',
              encryptedName: 'safeName',
              nameIv: 'niv1',
              nameTag: 'ntag1',
              encryptedData: 'safeData',
              dataIv: 'iv1',
              dataTag: 'tag1',
              favorite: true,
              tags: ['legit'],
              searchHash: 'a'.repeat(64),
              _id: 'aaaaaaaaaaaaaaaaaaaaaaaa', // attacker-chosen id → must be ignored
              createdAt: '2000-01-01T00:00:00.000Z', // must be ignored
              userId: 'bbbbbbbbbbbbbbbbbbbbbbbb', // must be ignored
            },
          ],
        },
      });
      expect(res.status).toBe(201);
      expect(res.body.data.insertedCount).toBe(1);

      const item = await VaultItem.findOne({ userId: user.id, encryptedName: 'safeName' }).lean();
      expect(item).not.toBeNull();
      // Legitimate fields ARE honoured.
      expect(item!.encryptedData).toBe('safeData');
      expect(item!.itemType).toBe('login');
      expect(item!.favorite).toBe(true);
      expect(item!.tags).toEqual(['legit']);
      expect(item!.searchHash).toBe('a'.repeat(64));
      // The attacker-chosen _id must NOT be honoured (server mints its own).
      expect(String(item!._id)).not.toBe('aaaaaaaaaaaaaaaaaaaaaaaa');
      expect(item!.createdAt.getTime()).toBeGreaterThanOrEqual(before);
    });

    it('rejects an insert whose searchHash is not 64 lowercase hex characters', async () => {
      const res = await postImport(user.accessToken, {
        format: 'json',
        operations: { inserts: [insertRow({ searchHash: 'not-a-valid-hash' })] },
      });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
    });
  });
});
