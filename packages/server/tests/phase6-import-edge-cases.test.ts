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

  // ── CSV with embedded commas and quotes (real-world edge case) ──────

  describe('CSV import with embedded commas and quotes', () => {
    it('should parse CSV rows with commas inside quoted fields', async () => {
      // Build a CSV row with a comma embedded inside a quoted field — the parser
      // must not split on that comma. Headers map to encryption fields.
      const csvData = [
        'encName,eData,eIv,eTag,nIv,nTag',
        '"name,with,commas","data,with,commas",iv1,tag1,niv1,ntag1',
      ].join('\n');

      const csvMapping: Record<string, string> = {
        encName: 'encryptedName',
        eData: 'encryptedData',
        eIv: 'dataIv',
        eTag: 'dataTag',
        nIv: 'nameIv',
        nTag: 'nameTag',
      };

      const res = await postImport(user.accessToken, {
        format: 'csv',
        data: csvData,
        csvMapping,
      });

      expect(res.status).toBe(201);
      expect(res.body.data.importedCount).toBe(1);

      const item = await VaultItem.findOne({ userId: user.id }).lean();
      expect(item).not.toBeNull();
      expect(item!.encryptedName).toBe('name,with,commas');
      expect(item!.encryptedData).toBe('data,with,commas');
    });

    it('a hostile CSV mapping cannot inject non-encryption fields or pollute the prototype', async () => {
      // A hostile/tampered mapping points columns at high-value NON-encryption
      // targets (itemType, favorite, tags, searchHash) and at a prototype-
      // pollution vector (__proto__). The CSV row builder honours ONLY the six
      // encrypted columns (encryptedData/dataIv/dataTag/encryptedName/nameIv/
      // nameTag) and hardcodes every other field to a server default. This test
      // pins that safe projection: if the builder ever started trusting the raw
      // mapping (e.g. spreading it into the row), the injected itemType/favorite/
      // tags/searchHash would leak and these assertions would go red.
      //
      // Note: CSV_ALLOWED_TARGET_FIELDS is defense-in-depth LAYERED BEHIND that
      // explicit field-picking — removing the allowlist line alone has no
      // observable effect here (a non-read key in the intermediate object is
      // inert, and `obj['__proto__'] = <string>` is a no-op). The observable,
      // regression-catching contract is the safe projection asserted below.
      const csvData = [
        'encName,eData,eIv,eTag,nIv,nTag,evilType,evilFav,evilTags,evilHash,proto',
        'safeName,safeData,iv1,tag1,niv1,ntag1,secret,true,injected-tag,deadbeef,polluted',
      ].join('\n');

      const csvMapping: Record<string, string> = {
        encName: 'encryptedName',
        eData: 'encryptedData',
        eIv: 'dataIv',
        eTag: 'dataTag',
        nIv: 'nameIv',
        nTag: 'nameTag',
        evilType: 'itemType', // non-encryption target -> must be ignored
        evilFav: 'favorite', // non-encryption target -> must be ignored
        evilTags: 'tags', // non-encryption target -> must be ignored
        evilHash: 'searchHash', // non-encryption target -> must be ignored
        proto: '__proto__', // prototype-pollution vector -> must be inert
      };

      const res = await postImport(user.accessToken, {
        format: 'csv',
        data: csvData,
        csvMapping,
      });

      expect(res.status).toBe(201);
      expect(res.body.data.importedCount).toBe(1);

      const item = await VaultItem.findOne({ userId: user.id, encryptedName: 'safeName' }).lean();
      expect(item).not.toBeNull();
      // The six encryption columns ARE honoured.
      expect(item!.encryptedData).toBe('safeData');
      expect(item!.dataIv).toBe('iv1');
      expect(item!.dataTag).toBe('tag1');
      expect(item!.nameIv).toBe('niv1');
      expect(item!.nameTag).toBe('ntag1');
      // Every non-encryption target is dropped — the fields stay at their server
      // defaults instead of the injected 'secret' / 'true' / 'injected-tag' /
      // 'deadbeef' values.
      expect(item!.itemType).toBe('login');
      expect(item!.favorite).toBe(false);
      expect(item!.tags).toEqual([]);
      expect(item!.searchHash).toBeUndefined();
      // The '__proto__' mapping did not pollute Object.prototype.
      expect((Object.prototype as Record<string, unknown>).polluted).toBeUndefined();
      expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    });
  });
});
