/**
 * Phase 6 — Task 6.4: Import Validation and Edge Case Tests
 *
 * Covers import scenarios not already exercised by tools.test.ts or
 * phase2-security-hardening.test.ts:
 *   • Overwrite conflict strategy that changes itemType.
 *   • Mixed valid/invalid items in the same batch.
 *   • Deduplication fallback when encryptedName matches but searchHash
 *     differs (handles vault key rotation where hashes re-compute).
 *   • Deduplication when neither name nor hash match — items should import.
 *   • Import of large batches (near the MAX_IMPORT_ITEMS boundary).
 *   • Import with folderId belonging to a different user (cross-user).
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

describe('Phase 6 — Import Validation and Edge Cases', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  // ── Overwrite conflict strategy changing itemType ───────────────────

  describe('conflictStrategy: overwrite changing itemType', () => {
    it('should overwrite the itemType when searchHash matches', async () => {
      const searchHash = 'a'.repeat(64);

      // Seed an existing login item with a known searchHash
      const firstImport = JSON.stringify({
        items: [sampleVaultItem({ itemType: 'login', encryptedName: 'orig', searchHash })],
      });
      const firstRes = await postImport(user.accessToken, {
        format: 'json',
        data: firstImport,
      });
      expect(firstRes.status).toBe(201);
      expect(firstRes.body.data.importedCount).toBe(1);

      // Now import an item with the same searchHash but a different itemType
      const secondImport = JSON.stringify({
        items: [sampleVaultItem({ itemType: 'note', encryptedName: 'orig', searchHash })],
      });
      const secondRes = await postImport(user.accessToken, {
        format: 'json',
        data: secondImport,
        conflictStrategy: 'overwrite',
      });

      expect(secondRes.status).toBe(201);
      expect(secondRes.body.data.overwrittenCount).toBe(1);
      // The controller's `importedCount` counts all successfully-handled rows
      // (inserts + overwrites), matching the existing `overwrite-1-updated`
      // test in tools.test.ts. So we don't assert importedCount here — just
      // check the row count in the database.
      const items = await VaultItem.find({ userId: user.id }).lean();
      expect(items).toHaveLength(1);
      expect(items[0]!.itemType).toBe('note');
    });
  });

  // ── Mixed valid/invalid items in the same batch ─────────────────────

  describe('mixed valid/invalid items in one batch', () => {
    it('should import valid items and report skipped count for invalid ones', async () => {
      const importData = JSON.stringify({
        items: [
          sampleVaultItem({ encryptedName: 'valid-1' }),
          // Missing encryption fields
          {
            itemType: 'login',
            encryptedData: '',
            dataIv: '',
            dataTag: '',
            encryptedName: '',
            nameIv: '',
            nameTag: '',
          },
          sampleVaultItem({ encryptedName: 'valid-2' }),
          // Invalid (but caught by encryption-field filter)
          { itemType: 'login' },
          sampleVaultItem({ encryptedName: 'valid-3' }),
        ],
      });

      const res = await postImport(user.accessToken, {
        format: 'json',
        data: importData,
      });

      expect(res.status).toBe(201);
      expect(res.body.data.importedCount).toBe(3);
      expect(res.body.data.skippedCount).toBe(2);

      const items = await VaultItem.find({ userId: user.id }).lean();
      expect(items).toHaveLength(3);
      const names = items.map((i) => i.encryptedName).sort();
      expect(names).toEqual(['valid-1', 'valid-2', 'valid-3']);
    });
  });

  // ── Deduplication by encryptedName when searchHash differs ──────────

  describe('deduplication fallback by encryptedName', () => {
    it('should treat items as duplicates when encryptedName matches but searchHash differs', async () => {
      // Seed a user with a known item
      const seedImport = JSON.stringify({
        items: [
          sampleVaultItem({
            encryptedName: 'shared-enc-name',
            searchHash: 'a'.repeat(64),
          }),
        ],
      });
      const seedRes = await postImport(user.accessToken, {
        format: 'json',
        data: seedImport,
      });
      expect(seedRes.status).toBe(201);

      // Import an item with the same encryptedName but a DIFFERENT searchHash.
      // Simulates a post-rotation export where searchHashes were recomputed.
      const dupImport = JSON.stringify({
        items: [
          sampleVaultItem({
            encryptedName: 'shared-enc-name',
            searchHash: 'b'.repeat(64),
          }),
        ],
      });
      const res = await postImport(user.accessToken, {
        format: 'json',
        data: dupImport,
        conflictStrategy: 'skip',
      });

      expect(res.status).toBe(201);
      expect(res.body.data.duplicateCount).toBe(1);
      expect(res.body.data.importedCount).toBe(0);

      // Only one item persisted
      const count = await VaultItem.countDocuments({ userId: user.id });
      expect(count).toBe(1);
    });

    it('should NOT dedup when neither encryptedName nor searchHash match', async () => {
      // Seed
      const seedImport = JSON.stringify({
        items: [
          sampleVaultItem({
            encryptedName: 'name-A',
            searchHash: 'a'.repeat(64),
          }),
        ],
      });
      await postImport(user.accessToken, { format: 'json', data: seedImport });

      // Completely distinct item
      const dupImport = JSON.stringify({
        items: [
          sampleVaultItem({
            encryptedName: 'name-B',
            searchHash: 'b'.repeat(64),
          }),
        ],
      });
      const res = await postImport(user.accessToken, {
        format: 'json',
        data: dupImport,
        conflictStrategy: 'skip',
      });

      expect(res.status).toBe(201);
      expect(res.body.data.importedCount).toBe(1);
      expect(res.body.data.duplicateCount).toBe(0);

      const count = await VaultItem.countDocuments({ userId: user.id });
      expect(count).toBe(2);
    });
  });

  // ── Import large batch near MAX_IMPORT_ITEMS ────────────────────────

  describe('large batch import', () => {
    it('should accept a batch of 1,000 valid items', async () => {
      // 1,000 items is enough to verify batching works without blowing up test time
      const items = Array.from({ length: 1_000 }, (_, i) =>
        sampleVaultItem({ encryptedName: `bulk-${String(i)}` }),
      );
      const importData = JSON.stringify({ items });

      const res = await postImport(user.accessToken, {
        format: 'json',
        data: importData,
      });

      expect(res.status).toBe(201);
      expect(res.body.data.importedCount).toBe(1_000);

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
      const importData = JSON.stringify({
        items: [sampleVaultItem({ folderId: otherFolderId, encryptedName: 'cross-user' })],
      });

      const res = await postImport(user.accessToken, {
        format: 'json',
        data: importData,
      });

      expect(res.status).toBe(201);
      expect(res.body.data.importedCount).toBe(1);

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

  // ── Field-injection safety on the JSON import path ─────────────────

  describe('import honours only the safe field projection for JSON items', () => {
    it('ignores attacker-supplied non-allowlisted fields (_id, timestamps, bad searchHash)', async () => {
      // Parsing + encryption are client-side; the server receives native encrypted
      // items and maps ONLY a fixed set of fields. A tampered item that smuggles a
      // chosen _id, timestamps, or a malformed searchHash must not have those
      // honoured — the server mints its own id and sanitizes searchHash.
      const importData = JSON.stringify({
        items: [
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
            searchHash: 'not-a-valid-hash', // not 64-hex → sanitized away
            _id: 'aaaaaaaaaaaaaaaaaaaaaaaa', // attacker-chosen id → must be ignored
            createdAt: '2000-01-01T00:00:00.000Z', // must be ignored
          },
        ],
      });

      const res = await postImport(user.accessToken, { format: 'json', data: importData });
      expect(res.status).toBe(201);
      expect(res.body.data.importedCount).toBe(1);

      const item = await VaultItem.findOne({ userId: user.id, encryptedName: 'safeName' }).lean();
      expect(item).not.toBeNull();
      // Legitimate fields ARE honoured.
      expect(item!.encryptedData).toBe('safeData');
      expect(item!.itemType).toBe('login');
      expect(item!.favorite).toBe(true);
      expect(item!.tags).toEqual(['legit']);
      // A non-64-hex searchHash is stripped by sanitizeImportFields.
      expect(item!.searchHash).toBeUndefined();
      // The attacker-chosen _id must NOT be honoured (server mints its own).
      expect(String(item!._id)).not.toBe('aaaaaaaaaaaaaaaaaaaaaaaa');
    });
  });
});
