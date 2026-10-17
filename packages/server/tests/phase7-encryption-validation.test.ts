import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import app from '../src/app.js';
import { MAX_ENCRYPTED_DATA_LENGTH, MAX_ENCRYPTED_NAME_LENGTH } from '@hvault/shared';
import { createTestUser, authHeader, sampleVaultItem, getCsrf, type TestUser } from './helpers.js';

// ---------------------------------------------------------------------------
// Phase 7 — Task 7.2: Encryption Field Validation Tests
// ---------------------------------------------------------------------------

describe('Encryption Field Validation', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  // ── Helper ──────────────────────────────────────────────────────────

  async function postItem(overrides: Record<string, unknown>, expectedStatus?: number) {
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);
    const res = await agent
      .post('/api/v1/vault/items')
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', csrf.cookie)
      .set('x-csrf-token', csrf.token)
      .send(sampleVaultItem(overrides));
    if (expectedStatus !== undefined) {
      expect(res.status).toBe(expectedStatus);
    }
    return res;
  }

  // ── Empty string rejection ─────────────────────────────────────────

  describe('Empty string rejection for required encrypted fields', () => {
    it('should reject empty encryptedData', async () => {
      const res = await postItem({ encryptedData: '' });
      expect(res.status).toBe(400);
    });

    it('should reject empty dataIv', async () => {
      const res = await postItem({ dataIv: '' });
      expect(res.status).toBe(400);
    });

    it('should reject empty dataTag', async () => {
      const res = await postItem({ dataTag: '' });
      expect(res.status).toBe(400);
    });

    it('should reject empty encryptedName', async () => {
      const res = await postItem({ encryptedName: '' });
      expect(res.status).toBe(400);
    });

    it('should reject empty nameIv', async () => {
      const res = await postItem({ nameIv: '' });
      expect(res.status).toBe(400);
    });

    it('should reject empty nameTag', async () => {
      const res = await postItem({ nameTag: '' });
      expect(res.status).toBe(400);
    });
  });

  // ── IV length boundary ─────────────────────────────────────────────

  describe('IV field length boundaries', () => {
    it('should accept dataIv at exactly 24 characters', async () => {
      // 24 chars is the max allowed (base64 for 12 bytes = 16 chars, but schema max is 24)
      const res = await postItem({ dataIv: 'a'.repeat(24) });
      expect(res.status).toBe(201);
    });

    it('should reject dataIv exceeding 24 characters', async () => {
      const res = await postItem({ dataIv: 'a'.repeat(25) });
      expect(res.status).toBe(400);
    });

    it('should accept nameIv at exactly 24 characters', async () => {
      const res = await postItem({ nameIv: 'a'.repeat(24) });
      expect(res.status).toBe(201);
    });

    it('should reject nameIv exceeding 24 characters', async () => {
      const res = await postItem({ nameIv: 'a'.repeat(25) });
      expect(res.status).toBe(400);
    });
  });

  // ── Auth tag length boundary ───────────────────────────────────────

  describe('Auth tag field length boundaries', () => {
    it('should accept dataTag at exactly 32 characters', async () => {
      const res = await postItem({ dataTag: 'a'.repeat(32) });
      expect(res.status).toBe(201);
    });

    it('should reject dataTag exceeding 32 characters', async () => {
      const res = await postItem({ dataTag: 'a'.repeat(33) });
      expect(res.status).toBe(400);
    });

    it('should accept nameTag at exactly 32 characters', async () => {
      const res = await postItem({ nameTag: 'a'.repeat(32) });
      expect(res.status).toBe(201);
    });

    it('should reject nameTag exceeding 32 characters', async () => {
      const res = await postItem({ nameTag: 'a'.repeat(33) });
      expect(res.status).toBe(400);
    });
  });

  // ── encryptedData length boundaries ────────────────────────────────

  describe('encryptedData length boundaries', () => {
    it('should accept encryptedData at exactly MAX_ENCRYPTED_DATA_LENGTH', async () => {
      const res = await postItem({ encryptedData: 'a'.repeat(MAX_ENCRYPTED_DATA_LENGTH) });
      expect(res.status).toBe(201);
    });

    it('should reject encryptedData exceeding MAX_ENCRYPTED_DATA_LENGTH', async () => {
      const res = await postItem({ encryptedData: 'a'.repeat(MAX_ENCRYPTED_DATA_LENGTH + 1) });
      expect(res.status).toBe(400);
    });
  });

  // ── encryptedName length boundaries ────────────────────────────────

  describe('encryptedName length boundaries', () => {
    it('should accept encryptedName at exactly MAX_ENCRYPTED_NAME_LENGTH', async () => {
      const res = await postItem({ encryptedName: 'a'.repeat(MAX_ENCRYPTED_NAME_LENGTH) });
      expect(res.status).toBe(201);
    });

    it('should reject encryptedName exceeding MAX_ENCRYPTED_NAME_LENGTH', async () => {
      const res = await postItem({ encryptedName: 'a'.repeat(MAX_ENCRYPTED_NAME_LENGTH + 1) });
      expect(res.status).toBe(400);
    });
  });

  // ── searchHash: accepted and dropped, whatever its shape (F-12) ─────
  //
  // No keyed hash of a name is stored any more, so the schemas no longer
  // validate one: an older client's value is dropped before any handler runs.
  // These used to pin each malformed shape refusing the item with 400.

  describe('searchHash is accepted and dropped, whatever its shape (F-12)', () => {
    const shapes: [string, string][] = [
      ['valid lowercase hex (64 chars)', 'a'.repeat(64)],
      ['uppercase hex characters', 'A'.repeat(64)],
      ['wrong length (too short)', 'a'.repeat(63)],
      ['wrong length (too long)', 'a'.repeat(65)],
      ['non-hex characters', 'g'.repeat(64)],
      [
        'mixed valid/invalid chars',
        ('abcdef1234567890'.repeat(3) + 'zz' + 'ab'.repeat(7)).slice(0, 64),
      ],
    ];

    it.each(shapes)('creates the item and stores no hash: %s', async (_label, searchHash) => {
      const res = await postItem({ searchHash });
      expect(res.status).toBe(201);
      expect(res.body.data.searchHash).toBeUndefined();
      const stored = await mongoose.connection
        .collection('vault_items')
        .findOne({ _id: new mongoose.Types.ObjectId(String(res.body.data._id)) });
      expect(stored).not.toBeNull();
      expect(stored).not.toHaveProperty('searchHash');
    });
  });

  // ── Update schema: partial encrypted field groups ──────────────────

  describe('Update schema encrypted field group validation', () => {
    let itemId: string;

    beforeEach(async () => {
      const agent = request.agent(app);
      const csrf = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/vault/items')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send(sampleVaultItem())
        .expect(201);
      itemId = res.body.data._id as string;
    });

    async function updateItem(body: Record<string, unknown>) {
      const agent = request.agent(app);
      const csrf = await getCsrf(agent);
      return agent
        .put(`/api/v1/vault/items/${itemId}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send(body);
    }

    it('should reject encryptedData without dataIv and dataTag', async () => {
      const res = await updateItem({ encryptedData: 'new-data' });
      expect(res.status).toBe(400);
    });

    it('should reject dataIv without encryptedData and dataTag', async () => {
      const res = await updateItem({ dataIv: 'new-iv' });
      expect(res.status).toBe(400);
    });

    it('should reject dataTag without encryptedData and dataIv', async () => {
      const res = await updateItem({ dataTag: 'new-tag' });
      expect(res.status).toBe(400);
    });

    it('should accept all three data fields together', async () => {
      const res = await updateItem({
        encryptedData: 'new-data',
        dataIv: 'new-iv',
        dataTag: 'new-tag',
      });
      expect(res.status).toBe(200);
    });

    it('should reject encryptedName without nameIv and nameTag', async () => {
      const res = await updateItem({ encryptedName: 'new-name' });
      expect(res.status).toBe(400);
    });

    it('should reject nameIv without encryptedName and nameTag', async () => {
      const res = await updateItem({ nameIv: 'new-iv' });
      expect(res.status).toBe(400);
    });

    it('should accept all three name fields together', async () => {
      const res = await updateItem({
        encryptedName: 'new-name',
        nameIv: 'new-iv',
        nameTag: 'new-tag',
      });
      expect(res.status).toBe(200);
    });

    it('should accept update with only non-encrypted fields', async () => {
      const res = await updateItem({ favorite: true });
      expect(res.status).toBe(200);
    });
  });

  // ── Folder encrypted field validation ──────────────────────────────

  describe('Folder encrypted field validation', () => {
    async function postFolder(overrides: Record<string, unknown>) {
      const agent = request.agent(app);
      const csrf = await getCsrf(agent);
      return agent
        .post('/api/v1/folders')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send({
          encryptedName: 'test-name',
          nameIv: 'test-iv',
          nameTag: 'test-tag',
          ...overrides,
        });
    }

    it('should reject empty encryptedName for folder', async () => {
      const res = await postFolder({ encryptedName: '' });
      expect(res.status).toBe(400);
    });

    it('should reject folder encryptedName exceeding MAX_ENCRYPTED_NAME_LENGTH', async () => {
      const res = await postFolder({ encryptedName: 'a'.repeat(MAX_ENCRYPTED_NAME_LENGTH + 1) });
      expect(res.status).toBe(400);
    });

    it('should accept folder encryptedName at exactly MAX_ENCRYPTED_NAME_LENGTH', async () => {
      const res = await postFolder({ encryptedName: 'a'.repeat(MAX_ENCRYPTED_NAME_LENGTH) });
      expect(res.status).toBe(201);
    });

    it('should reject folder nameIv exceeding 24 characters', async () => {
      const res = await postFolder({ nameIv: 'a'.repeat(25) });
      expect(res.status).toBe(400);
    });

    it('should reject folder nameTag exceeding 32 characters', async () => {
      const res = await postFolder({ nameTag: 'a'.repeat(33) });
      expect(res.status).toBe(400);
    });

    // F-12: these used to pin a malformed folder hash refusing the folder.
    it('accepts a folder whose searchHash is uppercase hex, and stores none', async () => {
      const res = await postFolder({ searchHash: 'A'.repeat(64) });
      expect(res.status).toBe(201);
      expect(res.body.data.searchHash).toBeUndefined();
    });

    it('accepts a folder whose searchHash is the wrong length, and stores none', async () => {
      const res = await postFolder({ searchHash: 'a'.repeat(32) });
      expect(res.status).toBe(201);
      const stored = await mongoose.connection
        .collection('folders')
        .findOne({ _id: new mongoose.Types.ObjectId(String(res.body.data._id)) });
      expect(stored).not.toHaveProperty('searchHash');
    });
  });
});
