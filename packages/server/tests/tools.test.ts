import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import axios from 'axios';
import { MAX_IMPORT_ITEMS, MAX_IMPORT_DATA_LENGTH } from '@hvault/shared';
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

      // The request is the k-anonymity range URL and carries the SSRF hardening
      // (maxRedirects:0). A regression that dropped either would fail here.
      expect(getSpy).toHaveBeenCalledTimes(1);
      expect(getSpy).toHaveBeenCalledWith(
        'https://api.pwnedpasswords.com/range/5BAA6',
        expect.objectContaining({ maxRedirects: 0, timeout: 10_000 }),
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
      const importData = JSON.stringify({
        items: [
          sampleVaultItem({ encryptedName: 'item-1' }),
          sampleVaultItem({ encryptedName: 'item-2' }),
        ],
      });

      await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken1)
        .set('Cookie', csrfCookie1)
        .send({ format: 'json', data: importData });

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
    it('should import items in JSON format', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const importData = JSON.stringify({
        items: [
          sampleVaultItem({ encryptedName: 'imported-item-1' }),
          sampleVaultItem({ encryptedName: 'imported-item-2' }),
          sampleVaultItem({ encryptedName: 'imported-item-3' }),
        ],
      });

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'json', data: importData });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.importedCount).toBe(3);
    });

    it('should reject invalid JSON data', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'json', data: 'not-valid-json{{{' });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should reject JSON without items array', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'json', data: JSON.stringify({ notItems: [] }) });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });
  });

  // ── Import Encryption Field Validation ──────────────────────────

  describe('POST /api/v1/tools/import - encryption field validation', () => {
    it('should skip items with missing encryption fields and report skippedCount', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const importData = JSON.stringify({
        items: [
          sampleVaultItem({ encryptedName: 'valid-item' }),
          {
            itemType: 'login',
            encryptedData: '',
            dataIv: '',
            dataTag: '',
            encryptedName: '',
            nameIv: '',
            nameTag: '',
          },
          {
            itemType: 'login',
            encryptedData: 'data',
            dataIv: 'iv',
            dataTag: 'tag',
            encryptedName: '',
            nameIv: '',
            nameTag: '',
          },
        ],
      });

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'json', data: importData });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.importedCount).toBe(1);
      expect(res.body.data.skippedCount).toBe(2);
      expect(res.body.message).toMatch(/skipped/i);
    });

    it('should reject import when all items have missing encryption fields', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const importData = JSON.stringify({
        items: [
          {
            itemType: 'login',
            encryptedData: '',
            dataIv: '',
            dataTag: '',
            encryptedName: '',
            nameIv: '',
            nameTag: '',
          },
        ],
      });

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'json', data: importData });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should import all items when all have valid encryption fields', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const importData = JSON.stringify({
        items: [
          sampleVaultItem({ encryptedName: 'all-valid-1' }),
          sampleVaultItem({ encryptedName: 'all-valid-2' }),
        ],
      });

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'json', data: importData });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.importedCount).toBe(2);
      expect(res.body.data.skippedCount).toBe(0);
      expect(res.body.message).not.toMatch(/skipped/i);
    });
  });

  // ── Non-JSON Import Formats ──────────────────────────────────────

  describe('POST /api/v1/tools/import - non-JSON formats', () => {
    it('should import items in bitwarden format', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const importData = JSON.stringify({
        items: [
          sampleVaultItem({ encryptedName: 'bitwarden-item-1' }),
          sampleVaultItem({ encryptedName: 'bitwarden-item-2' }),
        ],
      });

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'bitwarden', data: importData });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.importedCount).toBe(2);
    });

    it('should import items in lastpass format', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const importData = JSON.stringify({
        items: [sampleVaultItem({ encryptedName: 'lastpass-item-1' })],
      });

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'lastpass', data: importData });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.importedCount).toBe(1);
    });

    it('should import items in keepass format', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const importData = JSON.stringify({
        items: [
          sampleVaultItem({ encryptedName: 'keepass-item-1' }),
          sampleVaultItem({ encryptedName: 'keepass-item-2' }),
          sampleVaultItem({ encryptedName: 'keepass-item-3' }),
        ],
      });

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'keepass', data: importData });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.importedCount).toBe(3);
    });

    it('accepts each source format as already-encrypted items and records it in the audit log', async () => {
      // Import is zero-knowledge: parsing + encryption happen client-side, so every
      // format arrives as the same native `{ items: [...] }` envelope. `format` is
      // audit-only metadata and every value is handled identically.
      for (const format of ['chrome', 'firefox', 'onepassword', 'lastpass'] as const) {
        const { csrfToken, csrfCookie } = await getCsrf(agent);
        const importData = JSON.stringify({
          items: [sampleVaultItem({ encryptedName: `enc-${format}` })],
        });

        const res = await agent
          .post('/api/v1/tools/import')
          .set('Authorization', authHeader(user.accessToken))
          .set('x-csrf-token', csrfToken)
          .set('Cookie', csrfCookie)
          .send({ format, data: importData });

        expect(res.status, format).toBe(201);
        expect(res.body.data.importedCount).toBe(1);

        const auditEntry = await AuditLog.findOne({ userId: user.id, action: 'import' }).sort({
          createdAt: -1,
        });
        expect(auditEntry).not.toBeNull();
        expect((auditEntry!.metadata as Record<string, unknown>).format).toBe(format);
      }
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
    });

    it('rejects a JSON payload whose items carry plaintext instead of ciphertext', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);
      // Items with no encryption fields — a zero-knowledge server drops them all.
      const importData = JSON.stringify({
        items: [{ itemType: 'login', name: 'plain', username: 'alice', password: 's3cret' }],
      });

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'bitwarden', data: importData });

      expect(res.status).toBe(400);
      expect(res.body.message).toContain('No valid items');
    });

    it('should reject invalid JSON in bitwarden format', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'bitwarden', data: 'not-json{{' });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should reject bitwarden format without items array', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'bitwarden', data: JSON.stringify({ folders: [] }) });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('imports a csv-format payload of already-encrypted items via the single server path', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      // The server no longer parses CSV; a `csv` format simply carries encrypted
      // items in the native `{ items: [...] }` envelope like every other format.
      const importData = JSON.stringify({
        items: [sampleVaultItem({ encryptedName: 'csv-fallback-item' })],
      });

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'csv', data: importData });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.importedCount).toBe(1);
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

      expect(auditEntry).toBeDefined();
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

      // Build MAX_IMPORT_ITEMS + 1 items that are VALID (non-empty encrypted
      // fields), so the ONLY guard that can reject them is the MAX_IMPORT_ITEMS
      // request-size cap — not the "no valid items" filter (which would fire on
      // the old empty-`{}` payload regardless of whether the count cap exists).
      // itemType is omitted (defaults to 'login') to keep each row minimal so
      // the serialized `data` blob stays under MAX_IMPORT_DATA_LENGTH (1 MB).
      const minimalItem = {
        encryptedData: 'a',
        dataIv: 'a',
        dataTag: 'a',
        encryptedName: 'a',
        nameIv: 'a',
        nameTag: 'a',
      };
      const items = Array.from({ length: MAX_IMPORT_ITEMS + 1 }, () => minimalItem);
      const importData = JSON.stringify({ items });
      // Sanity: the payload must reach the controller, not be rejected by the
      // schema's data-length cap for the wrong reason.
      expect(importData.length).toBeLessThanOrEqual(MAX_IMPORT_DATA_LENGTH);

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'json', data: importData });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      // Assert the SPECIFIC guard fired. Removing the MAX_IMPORT_ITEMS block
      // would let the per-user cap reject instead, with a DIFFERENT message —
      // so this message match is what turns the mutation red.
      expect(JSON.stringify(res.body)).toMatch(/maximum allowed item count/i);
    });
  });

  // ── Import Deduplication ────────────────────────────────────────

  describe('POST /api/v1/tools/import - deduplication', () => {
    it('should skip duplicates when conflictStrategy is skip', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const items = [
        sampleVaultItem({ encryptedName: 'dedup-1', searchHash: 'a'.repeat(64) }),
        sampleVaultItem({ encryptedName: 'dedup-2', searchHash: 'b'.repeat(64) }),
      ];

      // First import
      const importData1 = JSON.stringify({ items });
      await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'json', data: importData1 });

      // Second import with skip strategy (default)
      const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf2)
        .set('Cookie', cookie2)
        .send({ format: 'json', data: importData1, conflictStrategy: 'skip' });

      expect(res.status).toBe(201);
      expect(res.body.data.duplicateCount).toBe(2);
      expect(res.body.data.importedCount).toBe(0);
    });

    it('should import all when conflictStrategy is keep_both', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const items = [sampleVaultItem({ encryptedName: 'keep-1', searchHash: 'c'.repeat(64) })];
      const importData = JSON.stringify({ items });

      // First import
      await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'json', data: importData });

      // Second import with keep_both
      const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf2)
        .set('Cookie', cookie2)
        .send({ format: 'json', data: importData, conflictStrategy: 'keep_both' });

      expect(res.status).toBe(201);
      expect(res.body.data.importedCount).toBe(1);
    });

    it('should overwrite existing when conflictStrategy is overwrite', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const items = [sampleVaultItem({ encryptedName: 'overwrite-1', searchHash: 'd'.repeat(64) })];
      const importData = JSON.stringify({ items });

      // First import
      await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'json', data: importData });

      // Second import with overwrite and updated data
      const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);
      const updatedItems = [
        sampleVaultItem({ encryptedName: 'overwrite-1-updated', searchHash: 'd'.repeat(64) }),
      ];
      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf2)
        .set('Cookie', cookie2)
        .send({
          format: 'json',
          data: JSON.stringify({ items: updatedItems }),
          conflictStrategy: 'overwrite',
        });

      expect(res.status).toBe(201);
      expect(res.body.data.overwrittenCount).toBe(1);
      expect(res.body.data.importedCount).toBe(1);
    });
  });

  // ── Export then Import Deduplication ─────────────────────────────

  describe('Export then Import deduplication', () => {
    it('should skip duplicates when re-importing an export with default skip strategy', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      // Create items with searchHash via import
      const items = [
        sampleVaultItem({ encryptedName: 'export-test-1', searchHash: 'e'.repeat(64) }),
        sampleVaultItem({ encryptedName: 'export-test-2', searchHash: 'f'.repeat(64) }),
      ];
      await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'json', data: JSON.stringify({ items }) });

      // Export the vault
      const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);
      const exportRes = await agent
        .post('/api/v1/tools/export')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf2)
        .set('Cookie', cookie2)
        .send({ format: 'json', authHash: user.rawPassword });

      expect(exportRes.status).toBe(200);
      const exportedData = exportRes.body.data;

      // Re-import the exported data (format=json, default conflictStrategy=skip)
      const { csrfToken: csrf3, csrfCookie: cookie3 } = await getCsrf(agent);
      const reimportRes = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf3)
        .set('Cookie', cookie3)
        .send({ format: 'json', data: JSON.stringify(exportedData) });

      expect(reimportRes.status).toBe(201);
      // Items with matching searchHash should be skipped
      expect(reimportRes.body.data.duplicateCount).toBeGreaterThanOrEqual(2);
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

      const res = await agent
        .post('/api/v1/tools/import')
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'json', data: '{}' });

      expect(res.status).toBe(401);
    });
  });

  // ── Prototype Pollution Protection ──────────────────────────────

  describe('POST /api/v1/tools/import - prototype pollution protection', () => {
    it('drops __proto__ pollution AND non-allowlisted schema fields on the insert path, leaving Object.prototype clean', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      // Two threats in one row on the fresh-INSERT path (no existing match):
      //   1. `__proto__` (built into the raw JSON string so it survives as an
      //      own property through JSON.parse) carrying isAdmin/role — the
      //      prototype-pollution vector.
      //   2. Top-level `deletedAt` + `sourceRefId`: REAL VaultItem schema paths
      //      that the controller's EXPLICIT field-by-field construction never
      //      copies. A regression that replaced that construction with a naive
      //      `{ userId, ...item }` spread WOULD persist both (Mongoose casts
      //      deletedAt to a Date and stores sourceRefId), so asserting they are
      //      absent turns that mutation red — the earlier tests asserted only
      //      keys that no implementation could ever persist.
      const base = sampleVaultItem({
        encryptedName: 'proto-insert-test',
        deletedAt: new Date('2020-01-01T00:00:00.000Z').toISOString(),
        sourceRefId: '0123456789abcdef01234567',
      });
      const itemJson =
        JSON.stringify(base).slice(0, -1) + ',"__proto__":{"isAdmin":true,"role":"superuser"}}';
      const importData = `{"items":[${itemJson}]}`;

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'json', data: importData });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.importedCount).toBe(1);

      // Object.prototype must be untouched (prototype-pollution guard).
      expect(({} as Record<string, unknown>)['isAdmin']).toBeUndefined();
      expect(({} as Record<string, unknown>)['role']).toBeUndefined();

      // The persisted row carries only the explicitly-constructed fields:
      // neither the pollution keys nor the smuggled schema paths made it in.
      const items = await VaultItem.find({ userId: user.id }).lean();
      const saved = items.find(
        (i) => (i as Record<string, unknown>).encryptedName === 'proto-insert-test',
      );
      expect(saved).not.toBeUndefined();
      const savedRecord = saved as Record<string, unknown>;
      expect(savedRecord['isAdmin']).toBeUndefined();
      expect(savedRecord['role']).toBeUndefined();
      // deletedAt was NOT written (item is a live, non-trashed row)…
      expect(savedRecord['deletedAt']).toBeUndefined();
      // …and the smuggled provenance id was dropped, not persisted verbatim.
      expect(savedRecord['sourceRefId']).toBeUndefined();
    });
  });

  // ── Overwrite Validation: Mongoose validators must run on overwrite path ─

  describe('POST /api/v1/tools/import - overwrite validator enforcement', () => {
    it('should reject overwrite with encryptedData exceeding the 500k maxlength', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      // Seed an existing item that the overwrite path will target
      const initial = [
        sampleVaultItem({
          encryptedName: 'overwrite-validator',
          searchHash: '1'.repeat(64),
        }),
      ];
      const seedRes = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'json', data: JSON.stringify({ items: initial }) });
      expect(seedRes.status).toBe(201);

      // Build an overwrite payload that bumps encryptedData well past the
      // 500_000 character schema limit. The total payload is under the 1MB
      // import body cap so it reaches the controller's overwrite branch.
      const oversized = sampleVaultItem({
        encryptedName: 'overwrite-validator',
        searchHash: '1'.repeat(64),
        encryptedData: 'A'.repeat(600_000),
      });

      const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf2)
        .set('Cookie', cookie2)
        .send({
          format: 'json',
          conflictStrategy: 'overwrite',
          data: JSON.stringify({ items: [oversized] }),
        });

      expect(res.status).toBe(400);

      // Existing item must be preserved unchanged — the failed validator
      // must abort the write, not silently succeed with truncation.
      const persisted = await VaultItem.findOne({
        userId: user.id,
        searchHash: '1'.repeat(64),
      }).lean();
      expect(persisted).not.toBeNull();
      expect(persisted!.encryptedData).toBe(initial[0]!['encryptedData']);
    });

    it('should not persist disallowed fields (e.g. userId) on overwrite', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const initial = [
        sampleVaultItem({
          encryptedName: 'overwrite-allowlist',
          searchHash: '2'.repeat(64),
        }),
      ];
      await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'json', data: JSON.stringify({ items: initial }) });

      // Submit an overwrite with a spoofed userId; the allowlist must drop it.
      const spoofedUserId = '0123456789abcdef01234567';
      const spoofed = {
        ...sampleVaultItem({
          encryptedName: 'overwrite-allowlist',
          searchHash: '2'.repeat(64),
        }),
        userId: spoofedUserId,
      };

      const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf2)
        .set('Cookie', cookie2)
        .send({
          format: 'json',
          conflictStrategy: 'overwrite',
          data: JSON.stringify({ items: [spoofed] }),
        });

      expect(res.status).toBe(201);

      const persisted = await VaultItem.findOne({
        searchHash: '2'.repeat(64),
      }).lean();
      expect(persisted).not.toBeNull();
      expect(persisted!.userId.toString()).toBe(user.id);
      expect(persisted!.userId.toString()).not.toBe(spoofedUserId);
    });
  });

  // ── Import field-length atomicity ───────────────────────────────────
  // The shared importSchema only caps the whole `data` blob (1MB); per-item
  // encrypted-field lengths are enforced by the VaultItem model. Without an
  // up-front controller check, an over-length field trips a Mongoose validator
  // only after the conflict loop has already overwritten earlier items — a
  // partial, unaudited import. The controller now validates field lengths
  // before any DB write so a bad item rejects the whole batch cleanly.
  describe('POST /api/v1/tools/import - field-length atomicity', () => {
    it('rejects the whole import (400) when one item has over-length encryptedData, inserting nothing and writing no audit log', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const data = JSON.stringify({
        items: [
          sampleVaultItem({ encryptedName: 'valid-1' }),
          sampleVaultItem({ encryptedName: 'valid-2' }),
          sampleVaultItem({
            encryptedName: 'oversized-insert',
            encryptedData: 'a'.repeat(500_001), // > MAX_ENCRYPTED_DATA_LENGTH (500_000)
          }),
          sampleVaultItem({ encryptedName: 'valid-3' }),
        ],
      });

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'json', data });

      expect(res.status).toBe(400);
      expect(res.body.message).toContain('encryptedData');
      expect(res.body.message).toContain('exceeds the maximum length');

      // Nothing persisted — import is all-or-nothing.
      const count = await VaultItem.countDocuments({ userId: user.id });
      expect(count).toBe(0);

      // No success audit log for a rejected import.
      const auditCount = await AuditLog.countDocuments({ userId: user.id, action: 'import' });
      expect(auditCount).toBe(0);
    });

    it('rejects an over-length dataIv (400) before any write', async () => {
      const { csrfToken, csrfCookie } = await getCsrf(agent);

      const data = JSON.stringify({
        items: [
          sampleVaultItem({ encryptedName: 'valid-iv' }),
          sampleVaultItem({ encryptedName: 'bad-iv', dataIv: 'x'.repeat(100) }), // > 24
        ],
      });

      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrfToken)
        .set('Cookie', csrfCookie)
        .send({ format: 'json', data });

      expect(res.status).toBe(400);
      expect(res.body.message).toContain('dataIv');
      expect(res.body.message).toContain('exceeds the maximum length');

      const count = await VaultItem.countDocuments({ userId: user.id });
      expect(count).toBe(0);
    });

    it('does not persist an earlier overwrite when a later item is over-length (overwrite path stays atomic)', async () => {
      const targetHash = '3'.repeat(64);
      const otherHash = '4'.repeat(64);

      // Seed an existing item that the overwrite path will target.
      const { csrfToken: seedCsrf, csrfCookie: seedCookie } = await getCsrf(agent);
      const seedRes = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', seedCsrf)
        .set('Cookie', seedCookie)
        .send({
          format: 'json',
          data: JSON.stringify({
            items: [
              sampleVaultItem({
                encryptedName: 'overwrite-target',
                searchHash: targetHash,
                encryptedData: 'original-data',
              }),
            ],
          }),
        });
      expect(seedRes.status).toBe(201);

      // Overwrite batch: the FIRST item matches the seeded item by searchHash
      // (so it is overwritten first); the SECOND is over-length. Without the
      // up-front length check, the first overwrite persists before the throw —
      // a partial import. With it, the whole batch rejects before any write.
      const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/tools/import')
        .set('Authorization', authHeader(user.accessToken))
        .set('x-csrf-token', csrf2)
        .set('Cookie', cookie2)
        .send({
          format: 'json',
          conflictStrategy: 'overwrite',
          data: JSON.stringify({
            items: [
              sampleVaultItem({
                encryptedName: 'overwrite-target',
                searchHash: targetHash,
                encryptedData: 'updated-data',
              }),
              sampleVaultItem({
                encryptedName: 'oversized-insert',
                searchHash: otherHash,
                encryptedData: 'a'.repeat(500_001),
              }),
            ],
          }),
        });

      expect(res.status).toBe(400);

      // The pre-existing item must be UNCHANGED — the earlier overwrite must
      // not have been applied (red before the fix, green after).
      const persisted = await VaultItem.findOne({
        userId: user.id,
        searchHash: targetHash,
      }).lean();
      expect(persisted).not.toBeNull();
      expect(persisted!.encryptedData).toBe('original-data');

      // The over-length item must not have been inserted.
      const inserted = await VaultItem.findOne({
        userId: user.id,
        searchHash: otherHash,
      }).lean();
      expect(inserted).toBeNull();

      // Only the originally-seeded item remains.
      const count = await VaultItem.countDocuments({ userId: user.id });
      expect(count).toBe(1);

      // The seed import wrote one `import` audit log; the failed overwrite
      // import must NOT have written a second one.
      const auditCount = await AuditLog.countDocuments({ userId: user.id, action: 'import' });
      expect(auditCount).toBe(1);
    });
  });
});
