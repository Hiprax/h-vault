import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import axios from 'axios';
import {
  MAX_ENCRYPTED_DATA_LENGTH,
  MAX_IMPORT_ITEMS,
  PASSWORD_HISTORY_MAX,
  HIBP_BATCH_MAX_PREFIXES,
} from '@hvault/shared';
import app from '../src/app.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { hibpCache } from '../src/controllers/toolsController.js';
import * as sizeEstimator from '../src/utils/sizeEstimator.js';
import {
  createTestUser,
  authHeader,
  sampleVaultItem,
  sampleFolder,
  seedFolder,
  seedItem,
  rawItems,
  getCsrf as getCsrfBase,
} from './helpers.js';
import type { TestUser } from './helpers.js';

// Re-export with { csrfToken, csrfCookie } naming used throughout this file
async function getCsrf(
  agent: request.SuperTest<request.Test>,
): Promise<{ csrfToken: string; csrfCookie: string }> {
  const { token, cookie } = await getCsrfBase(agent);
  return { csrfToken: token, csrfCookie: cookie };
}

// ── Import payload builders ──────────────────────────────────────────
// An import carries explicit `operations` — `inserts` plus `updates`, each
// update naming the `_id` it targets. Conflict resolution happens on the client
// (the match key lives inside the encrypted blob, so the server cannot compute
// it), which makes the server a validated executor: it applies exactly what it
// is handed. Every row below is built to satisfy the wire schema, so a 400 in
// these tests is always the guard under test and never a malformed payload.

/** A distinct, well-formed (lowercase hex, 64-char) searchHash per index. */
function searchHashFor(index: number): string {
  return index.toString(16).padStart(64, '0');
}

/** One `operations.inserts[]` row satisfying `importInsertItemSchema`. */
function insertRow(
  index: number,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return sampleVaultItem({
    encryptedName: `imported-name-${String(index)}`,
    encryptedData: `imported-data-${String(index)}`,
    searchHash: searchHashFor(index),
    ...overrides,
  });
}

/** One `operations.updates[]` row satisfying `importUpdateItemSchema`. */
function updateRow(id: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id,
    encryptedName: 'updated-encrypted-name',
    nameIv: 'updated-name-iv',
    nameTag: 'updated-name-tag',
    encryptedData: 'updated-encrypted-data',
    dataIv: 'updated-data-iv',
    dataTag: 'updated-data-tag',
    searchHash: searchHashFor(4095),
    ...overrides,
  };
}

/** One bounded `passwordHistory` entry for an update row. */
function historyEntry(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    encryptedPassword: 'previous-password-ciphertext',
    iv: 'history-iv',
    tag: 'history-tag',
    changedAt: new Date().toISOString(),
    ...overrides,
  };
}

// ── Tests ────────────────────────────────────────────────────────────

describe('Tools routes', () => {
  let user: TestUser;
  let agent: request.SuperTest<request.Test>;

  beforeEach(async () => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    user = await createTestUser();
  });

  // ── Generate Password (endpoint removed — generation is client-side only) ──

  describe('POST /api/v1/tools/generate-password (removed)', () => {
    it('should return 404 because the endpoint no longer exists', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/generate-password')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({});

      expect(res.status).toBe(404);
    });
  });

  // ── Check Password Breach ─────────────────────────────────────────

  describe('POST /api/v1/tools/check-password-breach', () => {
    it('proxies the HIBP range response, hits the k-anonymity URL with maxRedirects:0, and caches the second call', async () => {
      // Stub the outbound call so the suite never depends on live internet or a
      // third-party service — and so we can assert the controller's real
      // contract: passthrough, the SSRF-hardened request options, and the
      // in-memory cache serving the second call without a second network hit.
      hibpCache.clear();
      const hibpBody =
        '0018A45C4D1DEF81644B54AB7F969B88D65:12\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:3';
      const getSpy = vi.spyOn(axios, 'get').mockResolvedValue({ data: hibpBody });

      // SHA-1 prefix of "password" is "5BAA6"
      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/tools/check-password-breach')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ hashPrefix: '5BAA6' });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toBe(hibpBody);

      // The request is the k-anonymity range URL, carries the SSRF hardening
      // (maxRedirects:0), and the `Add-Padding` privacy header. A regression that
      // dropped any of these would fail here.
      expect(getSpy).toHaveBeenCalledTimes(1);
      expect(getSpy).toHaveBeenCalledWith(
        'https://api.pwnedpasswords.com/range/5BAA6',
        expect.objectContaining({
          maxRedirects: 0,
          timeout: 10_000,
          headers: expect.objectContaining({ 'Add-Padding': 'true' }),
        }),
      );

      // Second identical request must be served from the module-level cache —
      // axios is NOT called again.
      const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);
      const res2 = await agent
        .post('/api/v1/tools/check-password-breach')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf2)
        .set('Cookie', cookie2)
        .send({ hashPrefix: '5BAA6' });

      expect(res2.status).toBe(200);
      expect(res2.body.data).toBe(hibpBody);
      expect(getSpy).toHaveBeenCalledTimes(1);

      getSpy.mockRestore();
      hibpCache.clear();
    });

    it('requests Add-Padding and strips count-0 padding rows from the response', async () => {
      // Add-Padding returns dummy rows with COUNT === 0 that must be discarded;
      // a high-count row (:100) must NOT be mistaken for a padding row.
      hibpCache.clear();
      const padded =
        'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:2\r\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:0\r\nCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC:100';
      const getSpy = vi.spyOn(axios, 'get').mockResolvedValue({ data: padded });

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/tools/check-password-breach')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ hashPrefix: 'ABCDE' });

      expect(res.status).toBe(200);
      // The :0 padding row is gone; the real and high-count rows survive.
      expect(res.body.data).toBe(
        'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:2\r\nCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC:100',
      );
      expect(getSpy).toHaveBeenCalledWith(
        'https://api.pwnedpasswords.com/range/ABCDE',
        expect.objectContaining({ headers: expect.objectContaining({ 'Add-Padding': 'true' }) }),
      );

      getSpy.mockRestore();
      hibpCache.clear();
    });

    it('should return 401 without auth token', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/check-password-breach')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ hashPrefix: '5BAA6' });

      expect(res.status).toBe(401);
    });

    it('should reject a non-hex hash prefix', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/check-password-breach')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ hashPrefix: 'ZZZZZ' });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should reject a hash prefix with path traversal characters', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/check-password-breach')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ hashPrefix: '../xx' });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should reject a hash prefix with wrong length', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/check-password-breach')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ hashPrefix: 'ABC' });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });
  });

  // ── Check Password Breach (batch) ─────────────────────────────────

  describe('POST /api/v1/tools/check-password-breach/batch', () => {
    it('fans out unique prefixes, dedupes + uppercase-normalizes, and caches', async () => {
      hibpCache.clear();
      const bodies: Record<string, string> = {
        '5BAA6': 'AAA:1\r\nBBB:2',
        ABCDE: 'CCC:3',
      };
      const getSpy = vi
        .spyOn(axios, 'get')
        .mockImplementation((url: string) =>
          Promise.resolve({ data: bodies[url.split('/range/')[1] ?? ''] ?? '' }),
        );

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      // '5baa6' (lowercase) collapses onto '5BAA6'; three inputs -> two lookups.
      const res = await agent
        .post('/api/v1/tools/check-password-breach/batch')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ hashPrefixes: ['5BAA6', '5baa6', 'ABCDE'] });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data['5BAA6']).toBe(bodies['5BAA6']);
      expect(res.body.data.ABCDE).toBe(bodies.ABCDE);
      expect(res.body.errors).toEqual([]);
      expect(getSpy).toHaveBeenCalledTimes(2); // one per unique prefix
      // Uppercase-normalized URL + SSRF hardening preserved.
      expect(getSpy).toHaveBeenCalledWith(
        'https://api.pwnedpasswords.com/range/5BAA6',
        expect.objectContaining({ maxRedirects: 0, timeout: 10_000 }),
      );

      // Second identical request is fully served from cache.
      getSpy.mockClear();
      const { csrfToken: c2, csrfCookie: k2 } = await getCsrf(agent);
      const res2 = await agent
        .post('/api/v1/tools/check-password-breach/batch')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', c2)
        .set('Cookie', k2)
        .send({ hashPrefixes: ['5BAA6', 'ABCDE'] });
      expect(res2.status).toBe(200);
      expect(getSpy).not.toHaveBeenCalled();

      getSpy.mockRestore();
      hibpCache.clear();
    });

    it('reports a failed prefix in errors[] instead of dropping it silently', async () => {
      hibpCache.clear();
      const getSpy = vi.spyOn(axios, 'get').mockImplementation((url: string) => {
        if (url.endsWith('/range/FFFFF')) return Promise.reject(new Error('upstream 500'));
        return Promise.resolve({ data: 'ZZZ:9' });
      });

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/tools/check-password-breach/batch')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ hashPrefixes: ['5BAA6', 'FFFFF'] });

      expect(res.status).toBe(200);
      expect(res.body.data['5BAA6']).toBe('ZZZ:9');
      expect(res.body.data.FFFFF).toBeUndefined();
      expect(res.body.errors).toEqual(['FFFFF']);

      getSpy.mockRestore();
      hibpCache.clear();
    });

    it('rejects an array containing a non-hex prefix', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/tools/check-password-breach/batch')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ hashPrefixes: ['5BAA6', 'ZZZZZ'] });
      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('rejects an empty array', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/tools/check-password-breach/batch')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ hashPrefixes: [] });
      expect(res.status).toBe(400);
    });

    it('rejects an array over the prefix cap', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const tooMany = Array.from({ length: HIBP_BATCH_MAX_PREFIXES + 1 }, (_, i) =>
        i.toString(16).padStart(5, '0'),
      );
      const res = await agent
        .post('/api/v1/tools/check-password-breach/batch')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ hashPrefixes: tooMany });
      expect(res.status).toBe(400);
    });

    it('returns 401 without an auth token', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/tools/check-password-breach/batch')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ hashPrefixes: ['5BAA6'] });
      expect(res.status).toBe(401);
    });
  });

  // ── Export Vault ─────────────────────────────────────────────────

  describe('POST /api/v1/tools/export', () => {
    it('should export empty vault with valid authHash', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/export')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ authHash: user.rawPassword });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.items).toBeDefined();
      expect(Array.isArray(res.body.data.items)).toBe(true);
      expect(res.body.data.items.length).toBe(0);
      expect(res.body.data.folders).toBeDefined();
      expect(Array.isArray(res.body.data.folders)).toBe(true);
      expect(res.body.data.folders.length).toBe(0);
      expect(res.body.data.metadata).toBeDefined();
      expect(res.body.data.metadata.itemCount).toBe(0);
    });

    it('should set Content-Disposition attachment header so browsers download the export', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/export')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ authHash: user.rawPassword });

      expect(res.status).toBe(200);
      const contentDisposition = res.headers['content-disposition'];
      expect(contentDisposition).toBeDefined();
      expect(contentDisposition).toMatch(/^attachment;\s*filename="hvault-export-.+\.enc"$/);
      // Timestamp should use the filesystem-safe format (no colons or dots).
      const filenameMatch = /filename="(.+)"/.exec(contentDisposition as string);
      expect(filenameMatch).not.toBeNull();
      const filename = filenameMatch![1];
      expect(filename).not.toContain(':');
      // The dot before "enc" is the extension; the timestamp itself must not
      // contain colons or periods (they are replaced with hyphens).
      const stem = filename!.replace(/\.enc$/, '');
      expect(stem).not.toContain('.');
      expect(stem).not.toContain(':');

      expect(res.headers['content-type']).toMatch(/^application\/json/);
      expect(res.headers['content-length']).toBeDefined();
      expect(Number(res.headers['content-length'])).toBeGreaterThan(0);
    });

    it('should reject export without authHash', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/export')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({});

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should reject export with a non-json format (export is JSON-only; CSV is import-only)', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/export')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'csv', authHash: user.rawPassword });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should reject export with wrong authHash', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/export')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ authHash: 'wrong-password' });

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('should export vault with items after import', async () => {
      const { csrfToken: csrfToken1, csrfCookie: csrfCookie1 } = await getCsrf(agent);

      // Import some data first
      const importRes = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken1)
        .set('Cookie', csrfCookie1)
        .send({ format: 'json', operations: { inserts: [insertRow(1), insertRow(2)] } });
      expect(importRes.status).toBe(201);

      // Now export (requires re-authentication)
      const { csrfToken: csrfToken2, csrfCookie: csrfCookie2 } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/export')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken2)
        .set('Cookie', csrfCookie2)
        .send({ authHash: user.rawPassword });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.items.length).toBe(2);
      expect(res.body.data.metadata.itemCount).toBe(2);
    });
  });

  // ── Import Vault ─────────────────────────────────────────────────

  describe('POST /api/v1/tools/import', () => {
    it('inserts every row of an inserts-only request', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          format: 'json',
          operations: { inserts: [insertRow(1), insertRow(2), insertRow(3)] },
        });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toEqual({ insertedCount: 3, updatedCount: 0 });

      const stored = await rawItems(user.id);
      expect(stored.map((item) => item.encryptedName).sort()).toEqual([
        'imported-name-1',
        'imported-name-2',
        'imported-name-3',
      ]);
    });

    it('rewrites content in place for an updates-only request and refreshes searchHash', async () => {
      const existing = await seedItem(user.id, {
        encryptedName: 'original-name',
        encryptedData: 'original-data',
        searchHash: searchHashFor(7),
      });

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'json', operations: { updates: [updateRow(String(existing._id))] } });

      expect(res.status).toBe(201);
      expect(res.body.data).toEqual({ insertedCount: 0, updatedCount: 1 });

      const stored = await rawItems(user.id);
      expect(stored).toHaveLength(1);
      expect(stored[0]!.encryptedName).toBe('updated-encrypted-name');
      expect(stored[0]!.encryptedData).toBe('updated-encrypted-data');
      // An update replaces `encryptedName`, so the stored hash must follow it
      // or it strands against the old name.
      expect(stored[0]!.searchHash).toBe(searchHashFor(4095));
    });

    it('applies inserts and updates together in one mixed request', async () => {
      const existing = await seedItem(user.id, { encryptedData: 'original-data' });

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          format: 'json',
          operations: {
            inserts: [insertRow(1), insertRow(2)],
            updates: [updateRow(String(existing._id))],
          },
        });

      expect(res.status).toBe(201);
      expect(res.body.data).toEqual({ insertedCount: 2, updatedCount: 1 });

      const stored = await rawItems(user.id);
      expect(stored).toHaveLength(3);
      expect(stored.filter((item) => item.encryptedData === 'updated-encrypted-data')).toHaveLength(
        1,
      );
    });

    // The "reject invalid JSON data" and "reject JSON without items array" tests
    // went with the `data` envelope they described: an import no longer carries a
    // JSON STRING for the server to parse, so there is no parse step left to
    // fail. The rejection that guards the same ground now is the one below — an
    // old client's body is not the structured shape, so it never reaches the
    // controller at all.
    it('rejects the removed `data` envelope with a 400 and writes nothing', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          format: 'json',
          data: JSON.stringify({ items: [sampleVaultItem({ encryptedName: 'legacy-item' })] }),
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
    });

    it('rejects an insert row without a searchHash', async () => {
      // Every non-import creation path writes a searchHash and the restore flow
      // relies on its presence, so it is required on the wire rather than
      // optional-and-hopefully-present.
      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const { searchHash: _omitted, ...withoutHash } = insertRow(1);

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'json', operations: { inserts: [withoutHash] } });

      expect(res.status).toBe(400);
      expect(res.body.message).toContain('searchHash');
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
    });

    it('executes a schema-valid operations body and persists the insert verbatim', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          format: 'json',
          operations: {
            inserts: [insertRow(9, { tags: ['work'], favorite: true })],
          },
        });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toEqual({ insertedCount: 1, updatedCount: 0 });

      // The row lands under the CALLER's id with its ciphertext and metadata
      // intact — the response counts alone would not prove either.
      const stored = await VaultItem.findOne({ userId: user.id }).lean();
      expect(stored).not.toBeNull();
      expect(stored!.encryptedName).toBe('imported-name-9');
      expect(stored!.encryptedData).toBe('imported-data-9');
      expect(stored!.searchHash).toBe(searchHashFor(9));
      expect(stored!.tags).toEqual(['work']);
      expect(stored!.favorite).toBe(true);
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(1);
    });
  });

  // ── Import Encryption Field Validation ──────────────────────────

  describe('POST /api/v1/tools/import - encryption field validation', () => {
    // The legacy envelope filtered malformed rows out silently and reported them
    // in a `skippedCount`, which meant a client could believe an item had been
    // imported that never was. Silent per-row skipping is gone: the six
    // ciphertext fields are required on the wire, so ONE malformed row rejects
    // the whole request and nothing is written. There is no `skippedCount` left
    // to report — hence the shape assertions below rather than a count.
    it('rejects the whole request when one row has empty encryption fields, writing nothing', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          format: 'json',
          operations: {
            inserts: [
              insertRow(1),
              insertRow(2, { encryptedData: '', dataIv: '', dataTag: '' }),
              insertRow(3),
            ],
          },
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toContain('encryptedData');
      // The well-formed siblings did not land either — import is all-or-nothing.
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
    });

    it('rejects an update row with an empty ciphertext field, leaving the target untouched', async () => {
      const existing = await seedItem(user.id, { encryptedData: 'original-data' });

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          format: 'json',
          operations: { updates: [updateRow(String(existing._id), { nameTag: '' })] },
        });

      expect(res.status).toBe(400);
      const stored = await rawItems(user.id);
      expect(stored).toHaveLength(1);
      expect(stored[0]!.encryptedData).toBe('original-data');
    });

    it('imports every row when all of them carry complete encryption fields', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'json', operations: { inserts: [insertRow(1), insertRow(2)] } });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      // The response reports exactly the two counts and nothing else.
      expect(res.body.data).toEqual({ insertedCount: 2, updatedCount: 0 });
      expect(res.body.message).not.toMatch(/skipped/i);
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(2);
    });
  });

  // ── Source Formats ───────────────────────────────────────────────

  describe('POST /api/v1/tools/import - source formats', () => {
    // The per-format tests (bitwarden / lastpass / keepass / csv, one `it` each)
    // differed only in the string they put in `format` and are folded into the
    // loop below, which now covers ALL eight values instead of four. The two
    // "invalid JSON in bitwarden format" / "bitwarden without items array" tests
    // went with the `data` envelope: there is no server-side parse step left for
    // a format to fail at.
    it('accepts every source format as already-encrypted operations and records it in the audit log', async () => {
      // Import is zero-knowledge: parsing + encryption happen client-side, so
      // every format arrives as the same structured `operations` payload.
      // `format` is audit-only metadata and every value is handled identically.
      const formats = [
        'json',
        'bitwarden',
        'lastpass',
        'keepass',
        'chrome',
        'firefox',
        'onepassword',
        'csv',
      ] as const;

      for (const [index, format] of formats.entries()) {
        const { csrfToken, csrfCookie } = await getCsrf(agent);

        const res = await agent
          .post('/api/v1/tools/import')
          .set('Authorization', authHeader(user.accessToken))
          .set('x-csrf-token', csrfToken)
          .set('Cookie', csrfCookie)
          .send({ format, operations: { inserts: [insertRow(index)] } });

        expect(res.status, format).toBe(201);
        expect(res.body.data, format).toEqual({ insertedCount: 1, updatedCount: 0 });
      }

      // One audit entry per request, each stamped with its own format and the
      // default conflict strategy. Read as a set rather than by `createdAt` sort
      // order, which is not deterministic within a millisecond.
      const entries = await AuditLog.find({ userId: user.id, action: 'import' }).lean();
      const metadata = entries.map((entry) => entry.metadata as Record<string, unknown>);
      expect(metadata.map((meta) => meta.format).sort()).toEqual([...formats].sort());
      expect(
        metadata.every(
          (meta) =>
            meta.conflictStrategy === 'skip' && meta.insertedCount === 1 && meta.updatedCount === 0,
        ),
      ).toBe(true);
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(formats.length);
    });

    it('rejects a raw plaintext CSV payload (the server never parses plaintext)', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const csvData = 'url,username,password\nhttps://example.com,alice,s3cret';

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'csv', data: csvData });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
    });

    it('rejects insert rows carrying plaintext instead of ciphertext', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          format: 'bitwarden',
          operations: {
            inserts: [{ itemType: 'login', name: 'plain', username: 'alice', password: 's3cret' }],
          },
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
    });

    it('rejects a format the enum does not know', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'dashlane', operations: { inserts: [insertRow(1)] } });

      expect(res.status).toBe(400);
      expect(res.body.message).toContain('format');
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
    });
  });

  // ── HIBP API Error Handling ────────────────────────────────────────

  describe('POST /api/v1/tools/check-password-breach - API error handling', () => {
    it('should handle HIBP API timeout gracefully', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      // Mock axios.get to simulate a timeout
      const getSpy = vi.spyOn(axios, 'get').mockRejectedValueOnce(
        Object.assign(new Error('timeout of 10000ms exceeded'), {
          code: 'ECONNABORTED',
          isAxiosError: true,
        }),
      );

      const res = await agent
        .post('/api/v1/tools/check-password-breach')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ hashPrefix: 'ABCDE' });

      expect(res.status).toBe(500);
      expect(res.body.success).toBe(false);

      getSpy.mockRestore();
    });

    it('should handle HIBP API network error gracefully', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const getSpy = vi.spyOn(axios, 'get').mockRejectedValueOnce(
        Object.assign(new Error('getaddrinfo ENOTFOUND api.pwnedpasswords.com'), {
          code: 'ENOTFOUND',
          isAxiosError: true,
        }),
      );

      const res = await agent
        .post('/api/v1/tools/check-password-breach')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ hashPrefix: 'ABCDE' });

      expect(res.status).toBe(500);
      expect(res.body.success).toBe(false);

      getSpy.mockRestore();
    });

    it('should handle HIBP API 429 (rate limited) error', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const getSpy = vi.spyOn(axios, 'get').mockRejectedValueOnce(
        Object.assign(new Error('Request failed with status code 429'), {
          response: { status: 429, data: 'Rate limit exceeded' },
          isAxiosError: true,
        }),
      );

      const res = await agent
        .post('/api/v1/tools/check-password-breach')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ hashPrefix: 'ABCDE' });

      expect(res.status).toBe(500);
      expect(res.body.success).toBe(false);

      getSpy.mockRestore();
    });
  });

  // ── Export Includes Folders ────────────────────────────────────────

  describe('POST /api/v1/tools/export - includes folders', () => {
    it('should include folders in export response', async () => {
      // Create folders directly in DB
      await Folder.create({
        userId: user.id,
        encryptedName: 'folder-1',
        nameIv: 'folder-iv-1',
        nameTag: 'folder-tag-1',
      });
      await Folder.create({
        userId: user.id,
        encryptedName: 'folder-2',
        nameIv: 'folder-iv-2',
        nameTag: 'folder-tag-2',
      });

      // Create an item
      await VaultItem.create({
        userId: user.id,
        ...sampleVaultItem({ encryptedName: 'export-item' }),
      });

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/export')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ authHash: user.rawPassword });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.items.length).toBe(1);
      expect(res.body.data.folders.length).toBe(2);
      expect(res.body.data.metadata.itemCount).toBe(1);
    });

    it('should not include soft-deleted items in export', async () => {
      // Create active and deleted items
      await VaultItem.create({
        userId: user.id,
        ...sampleVaultItem({ encryptedName: 'active-export-item' }),
      });
      await VaultItem.create({
        userId: user.id,
        ...sampleVaultItem({ encryptedName: 'deleted-export-item' }),
        deletedAt: new Date(),
      });

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/export')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ authHash: user.rawPassword });

      expect(res.status).toBe(200);
      expect(res.body.data.items.length).toBe(1);
    });

    it('should create audit log entry on export with folder count', async () => {
      await Folder.create({
        userId: user.id,
        ...sampleFolder({ encryptedName: 'audit-folder' }),
      });

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      await agent
        .post('/api/v1/tools/export')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ authHash: user.rawPassword })
        .expect(200);

      const auditEntry = await AuditLog.findOne({
        userId: user.id,
        action: 'export',
      });

      expect(auditEntry).not.toBeNull();
      const meta = auditEntry!.metadata as Record<string, unknown>;
      expect(typeof meta.itemCount).toBe('number');
      expect(typeof meta.folderCount).toBe('number');
      expect(meta.folderCount).toBe(1);
    });

    it('should isolate export data between users', async () => {
      const user2 = await createTestUser();

      await VaultItem.create({
        userId: user.id,
        ...sampleVaultItem({ encryptedName: 'user1-export-item' }),
      });
      await VaultItem.create({
        userId: user2.id,
        ...sampleVaultItem({ encryptedName: 'user2-export-item' }),
      });

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/export')
        .set('Authorization', authHeader(user2.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ authHash: user2.rawPassword });

      expect(res.status).toBe(200);
      expect(res.body.data.items.length).toBe(1);
      expect(res.body.data.items[0].encryptedName).toBe('user2-export-item');
    });
  });

  // ── Export Size Limit ──────────────────────────────────────────────

  describe('POST /api/v1/tools/export - size limit', () => {
    it('should reject export when payload exceeds EXPORT_MAX_SIZE_MB', async () => {
      // Dynamically import config and temporarily lower the size limit
      const { config: serverConfig } = await import('../src/config/index.js');
      const original = serverConfig.EXPORT_MAX_SIZE_MB;
      (serverConfig as Record<string, unknown>).EXPORT_MAX_SIZE_MB = 0.0001; // ~100 bytes

      try {
        await VaultItem.create({
          userId: user.id,
          ...sampleVaultItem({ encryptedName: 'size-limit-item' }),
        });

        const { csrfToken, csrfCookie } = await getCsrf(agent);

        const res = await agent
          .post('/api/v1/tools/export')
          .set('Authorization', authHeader(user.accessToken))
          .set('x-csrf-token', csrfToken)
          .set('Cookie', csrfCookie)
          .send({ authHash: user.rawPassword });

        expect(res.status).toBe(413);
        expect(res.body.success).toBe(false);
      } finally {
        (serverConfig as Record<string, unknown>).EXPORT_MAX_SIZE_MB = original;
      }
    });

    it('should allow export within size limit', async () => {
      await VaultItem.create({
        userId: user.id,
        ...sampleVaultItem({ encryptedName: 'small-item' }),
      });

      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/export')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ authHash: user.rawPassword });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.items.length).toBe(1);
    });

    it('should short-circuit mid-cursor when streaming estimate exceeds size limit', async () => {
      // Regression test for the double-serialization optimization: verifies the
      // incremental size estimator still short-circuits the cursor loop before
      // loading the entire result set into memory.
      const { config: serverConfig } = await import('../src/config/index.js');
      const original = serverConfig.EXPORT_MAX_SIZE_MB;
      // Set limit to ~3000 bytes. With 600-byte per-item overhead + 1024-byte
      // wrapper overhead, 4 items should trip the guard before the 10th item.
      (serverConfig as Record<string, unknown>).EXPORT_MAX_SIZE_MB = 0.003;

      // Spy on the per-item estimator (calling through) so we can prove the loop
      // aborted MID-cursor rather than loading all 10 items and only tripping the
      // final full-payload size check. Removing the in-loop estimator/throw would
      // leave this spy uncalled (or called 10 times), failing the assertions below
      // — the 413 status alone cannot distinguish the two.
      const estimateSpy = vi.spyOn(sizeEstimator, 'estimateItemJsonSize');

      try {
        // Create 10 items; the estimator should reject before iterating all of them.
        for (let i = 0; i < 10; i++) {
          await VaultItem.create({
            userId: user.id,
            ...sampleVaultItem({ encryptedName: `short-circuit-${String(i)}` }),
          });
        }

        const { csrfToken, csrfCookie } = await getCsrf(agent);
        const res = await agent
          .post('/api/v1/tools/export')
          .set('Authorization', authHeader(user.accessToken))
          .set('x-csrf-token', csrfToken)
          .set('Cookie', csrfCookie)
          .send({ authHash: user.rawPassword });

        expect(res.status).toBe(413);
        expect(res.body.success).toBe(false);

        // The streaming guard ran (proves the in-cursor estimator exists) AND
        // stopped before consuming all 10 items (proves the memory-safety abort).
        expect(estimateSpy).toHaveBeenCalled();
        expect(estimateSpy.mock.calls.length).toBeLessThan(10);
      } finally {
        estimateSpy.mockRestore();
        (serverConfig as Record<string, unknown>).EXPORT_MAX_SIZE_MB = original;
      }
    });

    it('should export many items in a single pass without double serialization', async () => {
      // Regression test: verifies the optimized path correctly handles many
      // items in a single response. Previously each item was JSON.stringify'd
      // once in the loop plus once in the final payload serialization; now the
      // loop uses field-length estimation and only the final response is
      // serialized.
      const itemCount = 50;
      const items = Array.from({ length: itemCount }, (_, i) => ({
        userId: user.id,
        ...sampleVaultItem({ encryptedName: `bulk-${String(i)}` }),
      }));
      await VaultItem.insertMany(items);

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/tools/export')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ authHash: user.rawPassword });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.items.length).toBe(itemCount);
      expect(res.body.data.metadata.itemCount).toBe(itemCount);
    });

    it('should return export payload with application/json content type', async () => {
      // Regression test: after switching from res.json() to res.send(preSerialized),
      // the response must still advertise application/json so clients can parse it.
      await VaultItem.create({
        userId: user.id,
        ...sampleVaultItem({ encryptedName: 'content-type-item' }),
      });

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/tools/export')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ authHash: user.rawPassword });

      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toMatch(/application\/json/);
      expect(res.body.success).toBe(true);
      expect(res.body.data.items.length).toBe(1);
    });

    it('should reject export when large encryptedData fields push the estimated size over the limit', async () => {
      // Targets the per-item estimator specifically: a handful of items with
      // large encryptedData fields should exceed the limit based on the
      // summed field byte lengths.
      const { config: serverConfig } = await import('../src/config/index.js');
      const original = serverConfig.EXPORT_MAX_SIZE_MB;
      // 1 MB limit; two ~500KB items already exceed it, so with 5 seeded the
      // estimator MUST abort mid-cursor (around the 3rd item) rather than
      // consuming all 5 — that mid-cursor abort is the memory-safety property.
      (serverConfig as Record<string, unknown>).EXPORT_MAX_SIZE_MB = 1;

      const estimateSpy = vi.spyOn(sizeEstimator, 'estimateItemJsonSize');

      try {
        const bigPayload = 'a'.repeat(499_000); // Under MAX_ENCRYPTED_DATA_LENGTH (500,000)
        const seeded = 5;
        for (let i = 0; i < seeded; i++) {
          await VaultItem.create({
            userId: user.id,
            ...sampleVaultItem({
              encryptedName: `big-item-${String(i)}`,
              encryptedData: bigPayload,
            }),
          });
        }

        const { csrfToken, csrfCookie } = await getCsrf(agent);
        const res = await agent
          .post('/api/v1/tools/export')
          .set('Authorization', authHeader(user.accessToken))
          .set('x-csrf-token', csrfToken)
          .set('Cookie', csrfCookie)
          .send({ authHash: user.rawPassword });

        expect(res.status).toBe(413);
        expect(res.body.success).toBe(false);

        // The per-item estimator ran and short-circuited before consuming every
        // seeded row — distinguishing the streaming guard from the final
        // full-payload serialization check (which would consume all 5).
        expect(estimateSpy).toHaveBeenCalled();
        expect(estimateSpy.mock.calls.length).toBeLessThan(seeded);
      } finally {
        estimateSpy.mockRestore();
        (serverConfig as Record<string, unknown>).EXPORT_MAX_SIZE_MB = original;
      }
    });
  });

  // ── Import Item Count Limit ────────────────────────────────────────

  describe('POST /api/v1/tools/import - item count limit', () => {
    it('should reject import exceeding the maximum item count with the count-cap error', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      // Build MAX_IMPORT_ITEMS + 1 rows that are otherwise VALID, so the ONLY
      // guard that can reject them is the combined count bound — a malformed row
      // would 400 regardless of whether that bound exists. Each row is kept as
      // small as the schema allows so the body still clears the global 2 MB JSON
      // parser and reaches Zod.
      const minimalRow = {
        itemType: 'login',
        encryptedData: 'a',
        dataIv: 'a',
        dataTag: 'a',
        encryptedName: 'a',
        nameIv: 'a',
        nameTag: 'a',
        searchHash: searchHashFor(1),
      };
      const body = {
        format: 'json',
        operations: { inserts: Array.from({ length: MAX_IMPORT_ITEMS + 1 }, () => minimalRow) },
      };
      // Sanity: the payload must reach the schema, not be rejected by the body
      // parser for the wrong reason.
      expect(Buffer.byteLength(JSON.stringify(body))).toBeLessThan(2 * 1024 * 1024);

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send(body);

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      // Assert the SPECIFIC guard fired. Removing the count refinement would let
      // the per-user cap reject instead, with a DIFFERENT message — so this
      // message match is what turns the mutation red.
      expect(JSON.stringify(res.body)).toMatch(/operations must contain between 1 and/i);
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
    });

    it('should reject an import that carries no operations at all', async () => {
      // The other end of the same bound: a request with nothing to do is a
      // caller defect, not a no-op success.
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'json', operations: { inserts: [], updates: [] } });

      expect(res.status).toBe(400);
      expect(JSON.stringify(res.body)).toMatch(/operations must contain between 1 and/i);
      expect(await AuditLog.countDocuments({ userId: user.id, action: 'import' })).toBe(0);
    });
  });

  // ── Update Targets and Folder Ownership ─────────────────────────
  // The deduplication tests that used to sit here — the `- deduplication`
  // describe (skip / keep_both / overwrite outcomes) and the "export then
  // import" round trip — are gone with the behavior they covered. The server no
  // longer matches an incoming row against the vault by `searchHash` or
  // `encryptedName`: it cannot, because the identity of a login is its site and
  // username, both of which live inside the ciphertext. Resolution happens on
  // the client, which sends the decisions it made as explicit inserts and
  // updates. What replaces those tests is validation of the targets the client
  // names — an update must resolve to a LIVE item the caller owns, or the whole
  // request is refused.

  describe('POST /api/v1/tools/import - update targets and folder ownership', () => {
    it('rejects an update naming another user’s item and writes nothing', async () => {
      const other = await createTestUser();
      const foreign = await seedItem(other.id, { encryptedData: 'foreign-data' });

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          format: 'json',
          operations: {
            inserts: [insertRow(1)],
            updates: [updateRow(String(foreign._id))],
          },
        });

      expect(res.status).toBe(400);
      expect(JSON.stringify(res.body)).toMatch(/update target/i);

      // The foreign row is untouched AND the accompanying insert never landed:
      // validation precedes every write, so the request is all-or-nothing.
      const foreignStored = await rawItems(other.id);
      expect(foreignStored).toHaveLength(1);
      expect(foreignStored[0]!.encryptedData).toBe('foreign-data');
      expect(await rawItems(user.id)).toHaveLength(0);
    });

    it('rejects an update naming an id that does not exist', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          format: 'json',
          operations: { updates: [updateRow('0123456789abcdef01234567')] },
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

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'json', operations: { updates: [updateRow(String(trashed._id))] } });

      expect(res.status).toBe(400);
      expect(JSON.stringify(res.body)).toMatch(/update target/i);

      const stored = await rawItems(user.id);
      expect(stored).toHaveLength(1);
      expect(stored[0]!.encryptedData).toBe('trashed-data');
      expect(stored[0]!.deletedAt).toBeInstanceOf(Date);
    });

    it('strips a folderId the caller does not own from an insert but still imports the row', async () => {
      const other = await createTestUser();
      const foreignFolder = await seedFolder(other.id);

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          format: 'json',
          operations: { inserts: [insertRow(1, { folderId: String(foreignFolder._id) })] },
        });

      expect(res.status).toBe(201);
      expect(res.body.data).toEqual({ insertedCount: 1, updatedCount: 0 });

      // The row lands at the vault root rather than failing the import.
      const stored = await rawItems(user.id);
      expect(stored).toHaveLength(1);
      expect(stored[0]!.folderId).toBeUndefined();
    });

    it('keeps a folderId the caller does own', async () => {
      const folder = await seedFolder(user.id);

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          format: 'json',
          operations: { inserts: [insertRow(1, { folderId: String(folder._id) })] },
        });

      expect(res.status).toBe(201);
      const stored = await rawItems(user.id);
      expect(String(stored[0]!.folderId)).toBe(String(folder._id));
    });
  });

  // ── Auth Guards ──────────────────────────────────────────────────

  describe('Auth guards', () => {
    it('should return 401 for export without token', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/export')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send();

      expect(res.status).toBe(401);
    });

    it('should return 401 for import without token', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      // The body is fully schema-valid, so a 401 here can only come from the
      // auth guard — never from validation rejecting a malformed payload first.
      const res = await agent
        .post('/api/v1/tools/import')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'json', operations: { inserts: [insertRow(1)] } });

      expect(res.status).toBe(401);
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
    });
  });

  // ── Prototype Pollution Protection ──────────────────────────────

  describe('POST /api/v1/tools/import - prototype pollution protection', () => {
    it('drops __proto__ pollution AND non-allowlisted schema fields on the insert path, leaving Object.prototype clean', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      // Two threats in one insert row:
      //   1. `__proto__` (built into the raw JSON body so it survives as an own
      //      property through JSON.parse) carrying isAdmin/role — the
      //      prototype-pollution vector.
      //   2. Top-level `deletedAt` + `sourceRefId`: REAL VaultItem schema paths
      //      that the controller's fixed `ALLOWED_ITEM_FIELDS` projection never
      //      copies. A regression that replaced that projection with a naive
      //      `{ userId, ...item }` spread WOULD persist both (Mongoose casts
      //      deletedAt to a Date and stores sourceRefId), so asserting they are
      //      absent turns that mutation red — asserting only keys no
      //      implementation could ever persist would prove nothing.
      const base = insertRow(1, {
        encryptedName: 'proto-insert-test',
        deletedAt: new Date('2020-01-01T00:00:00.000Z').toISOString(),
        sourceRefId: '0123456789abcdef01234567',
      });
      const rowJson =
        JSON.stringify(base).slice(0, -1) + ',"__proto__":{"isAdmin":true,"role":"superuser"}}';
      const rawBody = `{"format":"json","operations":{"inserts":[${rowJson}]}}`;

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .set('Content-Type', 'application/json')
        .send(rawBody);

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toEqual({ insertedCount: 1, updatedCount: 0 });

      // Object.prototype must be untouched (prototype-pollution guard).
      expect(({} as Record<string, unknown>)['isAdmin']).toBeUndefined();
      expect(({} as Record<string, unknown>)['role']).toBeUndefined();

      // The persisted row carries only the allowlisted fields: neither the
      // pollution keys nor the smuggled schema paths made it in.
      const saved = await VaultItem.findOne({
        userId: user.id,
        encryptedName: 'proto-insert-test',
      }).lean();
      expect(saved).not.toBeNull();
      const savedRecord = saved as unknown as Record<string, unknown>;
      expect(savedRecord['isAdmin']).toBeUndefined();
      expect(savedRecord['role']).toBeUndefined();
      // deletedAt was NOT written (item is a live, non-trashed row)…
      expect(savedRecord['deletedAt']).toBeUndefined();
      // …and the smuggled provenance id was dropped, not persisted verbatim.
      expect(savedRecord['sourceRefId']).toBeUndefined();
    });
  });

  // ── Update path: bounds and the narrow write allowlist ──────────────
  // An import update names the `_id` it rewrites, so these tests target a real
  // pre-created item instead of relying on the server to find a match by name.
  // An update writes CONTENT only: `ALLOWED_UPDATE_FIELDS` is deliberately
  // narrower than the insert allowlist so an import can never silently
  // reorganize or retype a vault the user has already curated.

  describe('POST /api/v1/tools/import - update field enforcement', () => {
    it('should reject an update with encryptedData exceeding the 500k ceiling', async () => {
      const existing = await seedItem(user.id, {
        encryptedName: 'update-validator',
        encryptedData: 'original-data',
        searchHash: searchHashFor(1),
      });

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          format: 'json',
          conflictStrategy: 'overwrite',
          operations: {
            updates: [
              updateRow(String(existing._id), {
                encryptedData: 'A'.repeat(MAX_ENCRYPTED_DATA_LENGTH + 1),
              }),
            ],
          },
        });

      expect(res.status).toBe(400);

      // The existing item must be preserved unchanged — the rejection must abort
      // the write, not silently succeed with truncation.
      const persisted = await VaultItem.findOne({ _id: existing._id }).lean();
      expect(persisted).not.toBeNull();
      expect(persisted!.encryptedData).toBe('original-data');
      expect(persisted!.encryptedName).toBe('update-validator');
    });

    it('should not let an update rewrite userId, tags, favorite or itemType', async () => {
      const folder = await seedFolder(user.id);
      const existing = await seedItem(user.id, {
        itemType: 'note',
        encryptedData: 'original-data',
        tags: ['keep-me'],
        favorite: true,
        folderId: folder._id,
      });
      const spoofedUserId = '0123456789abcdef01234567';

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          format: 'json',
          conflictStrategy: 'overwrite',
          operations: {
            updates: [
              updateRow(String(existing._id), {
                userId: spoofedUserId,
                itemType: 'login',
                tags: ['injected'],
                favorite: false,
                folderId: null,
              }),
            ],
          },
        });

      expect(res.status).toBe(201);
      expect(res.body.data).toEqual({ insertedCount: 0, updatedCount: 1 });

      const persisted = await VaultItem.findOne({ _id: existing._id }).lean();
      expect(persisted).not.toBeNull();
      // The ciphertext WAS rewritten…
      expect(persisted!.encryptedData).toBe('updated-encrypted-data');
      // …but nothing outside the narrow update allowlist was.
      expect(persisted!.userId.toString()).toBe(user.id);
      expect(persisted!.userId.toString()).not.toBe(spoofedUserId);
      expect(persisted!.itemType).toBe('note');
      expect(persisted!.tags).toEqual(['keep-me']);
      expect(persisted!.favorite).toBe(true);
      expect(String(persisted!.folderId)).toBe(String(folder._id));
    });

    it('should reject a passwordHistory with more than the allowed number of entries', async () => {
      const existing = await seedItem(user.id, { encryptedData: 'original-data' });

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          format: 'json',
          operations: {
            updates: [
              updateRow(String(existing._id), {
                passwordHistory: Array.from({ length: PASSWORD_HISTORY_MAX + 1 }, () =>
                  historyEntry(),
                ),
              }),
            ],
          },
        });

      expect(res.status).toBe(400);
      const persisted = await VaultItem.findOne({ _id: existing._id }).lean();
      expect(persisted).not.toBeNull();
      expect(persisted!.encryptedData).toBe('original-data');
      expect(persisted!.passwordHistory).toBeUndefined();
    });

    it('should reject an over-length passwordHistory entry', async () => {
      const existing = await seedItem(user.id, { encryptedData: 'original-data' });

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          format: 'json',
          operations: {
            updates: [
              updateRow(String(existing._id), {
                passwordHistory: [historyEntry({ encryptedPassword: 'x'.repeat(5_001) })],
              }),
            ],
          },
        });

      expect(res.status).toBe(400);
      const persisted = await VaultItem.findOne({ _id: existing._id }).lean();
      expect(persisted).not.toBeNull();
      expect(persisted!.encryptedData).toBe('original-data');
      expect(persisted!.passwordHistory).toBeUndefined();
    });

    it('carries a bounded passwordHistory onto the updated item', async () => {
      const existing = await seedItem(user.id, { encryptedData: 'original-data' });

      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          format: 'json',
          operations: {
            updates: [updateRow(String(existing._id), { passwordHistory: [historyEntry()] })],
          },
        });

      expect(res.status).toBe(201);

      const persisted = await VaultItem.findOne({ _id: existing._id }).lean();
      expect(persisted).not.toBeNull();
      expect(persisted!.passwordHistory).toHaveLength(1);
      expect(persisted!.passwordHistory![0]!.encryptedPassword).toBe(
        'previous-password-ciphertext',
      );
    });
  });

  // ── Import field-length atomicity ───────────────────────────────────
  // Two layers agree on the per-field ceilings: the wire schema bounds each row
  // (which is what rejects here) and `assertImportFieldLengths` re-checks both
  // arrays in the controller before any DB work, so the guarantee survives if
  // those wire bounds are ever loosened. What matters behaviorally is that ONE
  // bad row takes the whole request down with nothing persisted and no audit
  // entry — never a partial, half-applied import.
  describe('POST /api/v1/tools/import - field-length atomicity', () => {
    it('rejects the whole import (400) when one item has over-length encryptedData, inserting nothing and writing no audit log', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          format: 'json',
          operations: {
            inserts: [
              insertRow(1),
              insertRow(2),
              insertRow(3, { encryptedData: 'a'.repeat(MAX_ENCRYPTED_DATA_LENGTH + 1) }),
              insertRow(4),
            ],
          },
        });

      expect(res.status).toBe(400);
      expect(res.body.message).toContain('encryptedData');

      // Nothing persisted — import is all-or-nothing.
      const count = await VaultItem.countDocuments({ userId: user.id });
      expect(count).toBe(0);

      // No success audit log for a rejected import.
      const auditCount = await AuditLog.countDocuments({ userId: user.id, action: 'import' });
      expect(auditCount).toBe(0);
    });

    it('rejects an over-length dataIv (400) before any write', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          format: 'json',
          operations: {
            inserts: [insertRow(1), insertRow(2, { dataIv: 'x'.repeat(100) })], // > 24
          },
        });

      expect(res.status).toBe(400);
      expect(res.body.message).toContain('dataIv');

      const count = await VaultItem.countDocuments({ userId: user.id });
      expect(count).toBe(0);
    });

    it('does not persist an earlier update when a later insert is over-length (mixed requests stay atomic)', async () => {
      // Seed an item the request will update in place.
      const existing = await seedItem(user.id, {
        encryptedName: 'update-target',
        searchHash: searchHashFor(3),
        encryptedData: 'original-data',
      });

      // The updates run AFTER the inserts inside the executor, but the length
      // check runs before either — so an over-length insert must take the whole
      // request down without the update ever being applied.
      const { csrfToken, csrfCookie } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({
          format: 'json',
          conflictStrategy: 'overwrite',
          operations: {
            inserts: [insertRow(4, { encryptedData: 'a'.repeat(MAX_ENCRYPTED_DATA_LENGTH + 1) })],
            updates: [updateRow(String(existing._id))],
          },
        });

      expect(res.status).toBe(400);

      // The pre-existing item must be UNCHANGED — the update must not have been
      // applied ahead of the rejection.
      const persisted = await VaultItem.findOne({ _id: existing._id }).lean();
      expect(persisted).not.toBeNull();
      expect(persisted!.encryptedData).toBe('original-data');
      expect(persisted!.encryptedName).toBe('update-target');

      // The over-length row must not have been inserted, so only the seeded item
      // remains and no `import` audit entry was written.
      const inserted = await VaultItem.findOne({
        userId: user.id,
        searchHash: searchHashFor(4),
      }).lean();
      expect(inserted).toBeNull();
      expect(await VaultItem.countDocuments({ userId: user.id })).toBe(1);
      expect(await AuditLog.countDocuments({ userId: user.id, action: 'import' })).toBe(0);
    });
  });
});
