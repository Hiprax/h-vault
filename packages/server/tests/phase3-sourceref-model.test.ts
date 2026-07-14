import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import app from '../src/app.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { User } from '../src/models/User.js';
import { createTestUser, authHeader, seedItem, seedFolder, getCsrf } from './helpers.js';
import type { TestUser } from './helpers.js';

// A synthetic origin `_id` string, standing in for the ObjectId of a backup
// row that belonged to ANOTHER account — exactly the value a restore stamps
// onto a freshly-inserted, non-owned row. It must never surface to a client.
const FOREIGN_REF = new mongoose.Types.ObjectId().toString();

describe('Phase 3 — sourceRefId provenance field', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  // ========================================================================
  // 3.1 — model round-trip + toJSON omission
  // ========================================================================

  describe('model persistence + toJSON strip', () => {
    it('persists sourceRefId on a VaultItem but omits it from toJSON()', async () => {
      const created = await VaultItem.create({
        userId: user.id,
        itemType: 'login',
        encryptedData: 'x',
        dataIv: 'x',
        dataTag: 'x',
        encryptedName: 'x',
        nameIv: 'x',
        nameTag: 'x',
        sourceRefId: FOREIGN_REF,
      });

      // Stored value is retained at the persistence layer.
      const reloaded = await VaultItem.findById(created._id).lean();
      expect(reloaded?.sourceRefId).toBe(FOREIGN_REF);

      // toJSON (the hydrated create-path serialization) strips it as
      // defense-in-depth alongside __v and userId.
      const hydrated = await VaultItem.findById(created._id);
      const json = hydrated!.toJSON() as Record<string, unknown>;
      expect(json['sourceRefId']).toBeUndefined();
      expect(json['userId']).toBeUndefined();
      expect(json['__v']).toBeUndefined();
      // Sanity: real content still present.
      expect(json['encryptedData']).toBe('x');
    });

    it('persists sourceRefId on a Folder but omits it from toJSON()', async () => {
      const created = await Folder.create({
        userId: user.id,
        encryptedName: 'x',
        nameIv: 'x',
        nameTag: 'x',
        sourceRefId: FOREIGN_REF,
      });

      const reloaded = await Folder.findById(created._id).lean();
      expect(reloaded?.sourceRefId).toBe(FOREIGN_REF);

      const hydrated = await Folder.findById(created._id);
      const json = hydrated!.toJSON() as Record<string, unknown>;
      expect(json['sourceRefId']).toBeUndefined();
      expect(json['userId']).toBeUndefined();
      expect(json['__v']).toBeUndefined();
      expect(json['encryptedName']).toBe('x');
    });
  });

  // ========================================================================
  // 3.3 — sourceRefId excluded from every client-facing serialization
  // ========================================================================

  describe('response exclusion on lean read paths', () => {
    it('GET /vault/items (list) never returns sourceRefId', async () => {
      await seedItem(user.id, { sourceRefId: FOREIGN_REF });

      const res = await request(app)
        .get('/api/v1/vault/items')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(res.body.data.length).toBeGreaterThan(0);
      for (const item of res.body.data as Record<string, unknown>[]) {
        expect(item).not.toHaveProperty('sourceRefId');
      }
      expect(res.text).not.toContain('sourceRefId');
    });

    it('GET /vault/items/:id (get) never returns sourceRefId', async () => {
      const seeded = await seedItem(user.id, { sourceRefId: FOREIGN_REF });

      const res = await request(app)
        .get(`/api/v1/vault/items/${String(seeded['_id'])}`)
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(res.body.data).not.toHaveProperty('sourceRefId');
      expect(res.text).not.toContain('sourceRefId');
    });

    it('GET /vault/items/trash never returns sourceRefId', async () => {
      await seedItem(user.id, { sourceRefId: FOREIGN_REF, deletedAt: new Date() });

      const res = await request(app)
        .get('/api/v1/vault/items/trash')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(res.body.data.length).toBeGreaterThan(0);
      for (const item of res.body.data as Record<string, unknown>[]) {
        expect(item).not.toHaveProperty('sourceRefId');
      }
      expect(res.text).not.toContain('sourceRefId');
    });

    it('PUT /vault/items/:id (update) never returns sourceRefId', async () => {
      const seeded = await seedItem(user.id, { sourceRefId: FOREIGN_REF });
      const agent = request.agent(app);
      const { token, cookie } = await getCsrf(agent);

      const res = await agent
        .put(`/api/v1/vault/items/${String(seeded['_id'])}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', cookie)
        .set('x-csrf-token', token)
        .send({ favorite: true })
        .expect(200);

      expect(res.body.data).not.toHaveProperty('sourceRefId');
      expect(res.text).not.toContain('sourceRefId');

      // The provenance value itself is untouched at the persistence layer —
      // only the client-facing projection hides it.
      const stored = await VaultItem.findById(seeded['_id']).lean();
      expect(stored?.sourceRefId).toBe(FOREIGN_REF);
    });

    it('POST /vault/items/restore/:id never returns sourceRefId', async () => {
      const seeded = await seedItem(user.id, {
        sourceRefId: FOREIGN_REF,
        deletedAt: new Date(),
      });
      const agent = request.agent(app);
      const { token, cookie } = await getCsrf(agent);

      const res = await agent
        .post(`/api/v1/vault/items/restore/${String(seeded['_id'])}`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', cookie)
        .set('x-csrf-token', token)
        .expect(200);

      expect(res.body.data).not.toHaveProperty('sourceRefId');
      expect(res.text).not.toContain('sourceRefId');
    });

    it('GET /folders (list) never returns sourceRefId', async () => {
      await seedFolder(user.id, { sourceRefId: FOREIGN_REF });

      const res = await request(app)
        .get('/api/v1/folders')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      expect(res.body.data.length).toBeGreaterThan(0);
      for (const folder of res.body.data as Record<string, unknown>[]) {
        expect(folder).not.toHaveProperty('sourceRefId');
      }
      expect(res.text).not.toContain('sourceRefId');
    });

    it('PUT /folders/:id/sort (reorder) never returns sourceRefId', async () => {
      const seeded = await seedFolder(user.id, { sourceRefId: FOREIGN_REF });
      const agent = request.agent(app);
      const { token, cookie } = await getCsrf(agent);

      const res = await agent
        .put(`/api/v1/folders/${String(seeded['_id'])}/sort`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', cookie)
        .set('x-csrf-token', token)
        .send({ sortOrder: 7 })
        .expect(200);

      expect(res.body.data).not.toHaveProperty('sourceRefId');
      expect(res.text).not.toContain('sourceRefId');
    });
  });

  describe('response exclusion on export + backup cursors', () => {
    it('POST /tools/export never emits sourceRefId', async () => {
      await seedItem(user.id, { sourceRefId: FOREIGN_REF });
      await seedFolder(user.id, { sourceRefId: FOREIGN_REF });
      const agent = request.agent(app);
      const { token, cookie } = await getCsrf(agent);

      const res = await agent
        .post('/api/v1/tools/export')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', cookie)
        .set('x-csrf-token', token)
        // helpers store authHash as bcrypt(rawPassword); the endpoint compares
        // the submitted value against that hash, so send the raw password.
        .send({ authHash: user.rawPassword })
        .expect(200);

      expect(res.body.data.items.length).toBeGreaterThan(0);
      expect(res.body.data.folders.length).toBeGreaterThan(0);
      expect(res.text).not.toContain('sourceRefId');
    });

    it('GET /backup/download never emits sourceRefId', async () => {
      await seedItem(user.id, { sourceRefId: FOREIGN_REF });
      await seedFolder(user.id, { sourceRefId: FOREIGN_REF });
      // Downloading requires backup encryption to be configured.
      await User.updateOne({ _id: user.id }, { $set: { 'settings.backup.isConfigured': true } });

      const res = await request(app)
        .get('/api/v1/backup/download')
        .set('Authorization', authHeader(user.accessToken))
        .expect(200);

      // The backup payload embeds the encrypted items/folders; assert the raw
      // serialized body carries no provenance field.
      expect(res.text).toContain('items');
      expect(res.text).not.toContain('sourceRefId');
    });
  });
});
