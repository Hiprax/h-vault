import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import app from '../src/app.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { User } from '../src/models/User.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import {
  createTestUser,
  authHeader,
  sampleVaultItem,
  sampleFolder,
  deriveTestPurposeKey,
  getCsrf,
  type TestUser,
} from './helpers.js';

// ---------------------------------------------------------------------------
// Test Suite: Concurrent Operations
// ---------------------------------------------------------------------------

describe('Concurrent Operations', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  // ── Helpers ─────────────────────────────────────────────────────────

  async function createItemViaApi(token: string, overrides: Record<string, unknown> = {}) {
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);
    const res = await agent
      .post('/api/v1/vault/items')
      .set('Authorization', authHeader(token))
      .set('Cookie', csrf.cookie)
      .set('x-csrf-token', csrf.token)
      .send(sampleVaultItem(overrides))
      .expect(201);
    return res.body.data._id as string;
  }

  async function createFolderViaApi(token: string, overrides: Record<string, unknown> = {}) {
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);
    const res = await agent
      .post('/api/v1/folders')
      .set('Authorization', authHeader(token))
      .set('Cookie', csrf.cookie)
      .set('x-csrf-token', csrf.token)
      .send(sampleFolder(overrides))
      .expect(201);
    return res.body.data._id as string;
  }

  // ── Concurrent Vault Item Creation ──────────────────────────────────

  describe('Concurrent vault item creation', () => {
    it('should handle multiple simultaneous item creations', async () => {
      // Create 5 items concurrently
      const createPromises = Array.from({ length: 5 }, (_, i) =>
        createItemViaApi(user.accessToken, { encryptedName: `concurrent-item-${String(i)}` }),
      );

      const ids = await Promise.all(createPromises);

      // All should succeed with unique IDs
      expect(new Set(ids).size).toBe(5);

      // All items should exist in DB
      const items = await VaultItem.find({ userId: user.id }).lean();
      expect(items).toHaveLength(5);
    });
  });

  // ── Concurrent Delete Operations ────────────────────────────────────

  describe('Concurrent delete operations', () => {
    it('should handle concurrent soft-delete of same item (idempotent)', async () => {
      const itemId = await createItemViaApi(user.accessToken);

      // Send 3 delete requests concurrently for the same item
      const deletePromises = Array.from({ length: 3 }, async () => {
        const agent = request.agent(app);
        const csrf = await getCsrf(agent);
        return agent
          .delete(`/api/v1/vault/items/${itemId}`)
          .set('Authorization', authHeader(user.accessToken))
          .set('Cookie', csrf.cookie)
          .set('x-csrf-token', csrf.token);
      });

      const results = await Promise.all(deletePromises);

      // At least one should succeed; others may get 404 (already deleted)
      const successCount = results.filter((r) => r.status === 200).length;
      const notFoundCount = results.filter((r) => r.status === 404).length;
      expect(successCount + notFoundCount).toBe(3);
      expect(successCount).toBeGreaterThanOrEqual(1);

      // Item should be soft-deleted
      const item = await VaultItem.findById(itemId).lean();
      expect(item?.deletedAt).toBeDefined();
    });
  });

  // ── Concurrent Folder Deletion with Item Move ──────────────────────

  describe('Concurrent folder deletion with item operations', () => {
    it('should handle folder deletion while items are being created in it', async () => {
      const folderId = await createFolderViaApi(user.accessToken);

      // Create an item in the folder
      await createItemViaApi(user.accessToken, { folderId });

      // Concurrently: delete folder (action=move) and create another item in it
      const [deleteResult, _createResult] = await Promise.all([
        (async () => {
          const agent = request.agent(app);
          const csrf = await getCsrf(agent);
          return agent
            .delete(`/api/v1/folders/${folderId}?action=move`)
            .set('Authorization', authHeader(user.accessToken))
            .set('Cookie', csrf.cookie)
            .set('x-csrf-token', csrf.token);
        })(),
        (async () => {
          const agent = request.agent(app);
          const csrf = await getCsrf(agent);
          return agent
            .post('/api/v1/vault/items')
            .set('Authorization', authHeader(user.accessToken))
            .set('Cookie', csrf.cookie)
            .set('x-csrf-token', csrf.token)
            .send(sampleVaultItem({ folderId }));
        })(),
      ]);

      // Folder should be deleted, items should still exist
      const folder = await Folder.findById(folderId).lean();
      expect(folder).toBeNull();

      // All items should exist regardless of creation/deletion order
      const items = await VaultItem.find({ userId: user.id }).lean();
      expect(items.length).toBeGreaterThanOrEqual(1);

      // Delete result should be 200
      expect(deleteResult.status).toBe(200);
    });
  });

  // ── Concurrent Bulk Operations ──────────────────────────────────────

  describe('Concurrent bulk operations', () => {
    it('should handle concurrent bulk-delete and item read', async () => {
      // Create several items
      const ids = await Promise.all(
        Array.from({ length: 5 }, (_, i) =>
          createItemViaApi(user.accessToken, { encryptedName: `bulk-${String(i)}` }),
        ),
      );

      // Concurrently: bulk-delete and list items
      const [deleteResult, listResult] = await Promise.all([
        (async () => {
          const agent = request.agent(app);
          const csrf = await getCsrf(agent);
          return agent
            .post('/api/v1/vault/items/bulk-delete')
            .set('Authorization', authHeader(user.accessToken))
            .set('Cookie', csrf.cookie)
            .set('x-csrf-token', csrf.token)
            .send({ ids: ids.slice(0, 3) });
        })(),
        (async () => {
          return request(app)
            .get('/api/v1/vault/items')
            .set('Authorization', authHeader(user.accessToken));
        })(),
      ]);

      expect(deleteResult.status).toBe(200);
      expect(listResult.status).toBe(200);

      // After both complete, exactly 3 items should be soft-deleted
      const activeItems = await VaultItem.find({
        userId: user.id,
        deletedAt: { $exists: false },
      }).lean();
      const trashedItems = await VaultItem.find({
        userId: user.id,
        deletedAt: { $exists: true, $ne: null },
      }).lean();

      expect(activeItems).toHaveLength(2);
      expect(trashedItems).toHaveLength(3);
    });
  });

  // ── Concurrent Vault Key Rotation (Idempotency) ────────────────────

  describe('Concurrent vault key rotation', () => {
    it('should handle concurrent rotation requests with same idempotency key', async () => {
      const itemId = await createItemViaApi(user.accessToken);
      const idempotencyKey = '550e8400-e29b-41d4-a716-446655440000';

      const rotationBody = {
        authHash: user.rawPassword,
        idempotencyKey,
        items: [
          {
            id: itemId,
            encryptedName: 'rotated-name',
            nameIv: 'rotated-iv',
            nameTag: 'rotated-tag',
            encryptedData: 'rotated-data',
            dataIv: 'rotated-data-iv',
            dataTag: 'rotated-data-tag',
          },
        ],
        folders: [],
        newEncryptedVaultKey: 'new-vault-key',
        newVaultKeyIv: 'new-vk-iv',
        newVaultKeyTag: 'new-vk-tag',
      };

      // Fire two rotation requests concurrently with the same idempotency key
      const [first, second] = await Promise.all([
        (async () => {
          const agent1 = request.agent(app);
          const csrf1 = await getCsrf(agent1);
          return agent1
            .post('/api/v1/vault/items/bulk-reencrypt')
            .set('Authorization', authHeader(user.accessToken))
            .set('Cookie', csrf1.cookie)
            .set('x-csrf-token', csrf1.token)
            .send(rotationBody);
        })(),
        (async () => {
          const agent2 = request.agent(app);
          const csrf2 = await getCsrf(agent2);
          return agent2
            .post('/api/v1/vault/items/bulk-reencrypt')
            .set('Authorization', authHeader(user.accessToken))
            .set('Cookie', csrf2.cookie)
            .set('x-csrf-token', csrf2.token)
            .send(rotationBody);
        })(),
      ]);

      // With the distributed lock, one request acquires the lock and succeeds,
      // the other is rejected with 409 (rotation already in progress).
      // The client can safely retry, which will hit the idempotency check.
      const statuses = [first.status, second.status].sort();
      expect(statuses).toEqual([200, 409]);

      // Item should have the rotated data exactly once
      const item = await VaultItem.findById(itemId).lean();
      expect(item?.encryptedName).toBe('rotated-name');
    });
  });

  // ── Concurrent Backup Code Usage ────────────────────────────────────

  describe('Concurrent backup code usage', () => {
    it('should not allow the same backup code to be used twice concurrently', async () => {
      const bcryptModule = await import('bcryptjs');
      const { CryptoManager } = await import('@hiprax/crypto');
      const { Secret } = await import('otpauth');

      const cm = new CryptoManager();
      const secretObj = new Secret();
      const secret = secretObj.base32;
      const encryptedSecret = cm.encryptTextSync(
        secret,
        process.env['SESSION_SECRET'] ?? 'TestSessionSecret4Testing!!12345',
      );

      const testUser = await createTestUser({ emailVerified: true });

      // Create a known backup code
      const rawBackupCode = 'abcdef1234567890';
      const hashedBackupCode = await bcryptModule.hash(rawBackupCode, 4);

      // Enable 2FA directly in DB
      await User.findByIdAndUpdate(testUser.id, {
        $set: {
          twoFactorEnabled: true,
          twoFactorSecret: encryptedSecret,
          backupCodes: [hashedBackupCode],
        },
      });

      // Create temp tokens for 2FA
      const tempToken1 = jwt.sign(
        { userId: testUser.id, purpose: '2fa_temp' },
        deriveTestPurposeKey('2fa_temp'),
        { expiresIn: '5m' },
      );
      const tempToken2 = jwt.sign(
        { userId: testUser.id, purpose: '2fa_temp' },
        deriveTestPurposeKey('2fa_temp'),
        { expiresIn: '5m' },
      );

      // Fire two concurrent 2FA requests with the same backup code
      const [result1, result2] = await Promise.all([
        (async () => {
          const agent1 = request.agent(app);
          const csrf1 = await getCsrf(agent1);
          return agent1
            .post('/api/v1/auth/login/2fa')
            .set('Cookie', csrf1.cookie)
            .set('x-csrf-token', csrf1.token)
            .send({ tempToken: tempToken1, code: rawBackupCode });
        })(),
        (async () => {
          const agent2 = request.agent(app);
          const csrf2 = await getCsrf(agent2);
          return agent2
            .post('/api/v1/auth/login/2fa')
            .set('Cookie', csrf2.cookie)
            .set('x-csrf-token', csrf2.token)
            .send({ tempToken: tempToken2, code: rawBackupCode });
        })(),
      ]);

      // At most one should succeed — the backup code is single-use
      const successCount = [result1, result2].filter((r) => r.status === 200).length;
      const failCount = [result1, result2].filter((r) => r.status !== 200).length;

      expect(successCount).toBeLessThanOrEqual(1);
      // At least one should fail (code consumed or race lost)
      expect(failCount).toBeGreaterThanOrEqual(1);

      // Verify the backup code was consumed (empty array or length 0)
      const updatedUser = await User.findById(testUser.id).select('+backupCodes');
      expect(updatedUser!.backupCodes!.length).toBeLessThanOrEqual(0);
    });
  });

  // ── Token Refresh During Logout ─────────────────────────────────────

  describe('Token refresh during logout', () => {
    it('should handle concurrent refresh and logout without crashing', async () => {
      const refreshCookie = `refreshToken=${user.refreshToken}`;

      // Fire refresh and logout concurrently
      const [refreshResult, logoutResult] = await Promise.all([
        (async () => {
          const agent1 = request.agent(app);
          const csrf1 = await getCsrf(agent1, refreshCookie);
          return agent1
            .post('/api/v1/auth/refresh')
            .set('Cookie', `${csrf1.cookie}; ${refreshCookie}`)
            .set('x-csrf-token', csrf1.token);
        })(),
        (async () => {
          const agent2 = request.agent(app);
          const csrf2 = await getCsrf(agent2, refreshCookie);
          return agent2
            .post('/api/v1/auth/logout')
            .set('Authorization', authHeader(user.accessToken))
            .set('Cookie', `${csrf2.cookie}; ${refreshCookie}`)
            .set('x-csrf-token', csrf2.token);
        })(),
      ]);

      // Both operations should complete without crashing the server.
      // An authenticated logout always responds 200 (so the old `anySuccess`
      // check was trivially satisfied and asserted nothing about refresh);
      // refresh either wins the rotation race (200) or loses it (401).
      expect(logoutResult.status).toBe(200);
      expect([200, 401]).toContain(refreshResult.status);

      // The load-bearing invariant: the ORIGINAL refresh token must be dead
      // afterward, whoever won. If logout won it deleted the row by hash; if
      // refresh won it rotated (marking the original used). A THIRD refresh
      // presenting the original must therefore 401 — either "not found" or
      // reuse-detected. A rotation regression that left the original usable
      // would turn this red.
      const replayAgent = request.agent(app);
      const replayCsrf = await getCsrf(replayAgent, refreshCookie);
      const replay = await replayAgent
        .post('/api/v1/auth/refresh')
        .set('Cookie', `${replayCsrf.cookie}; ${refreshCookie}`)
        .set('x-csrf-token', replayCsrf.token)
        .send();
      expect(replay.status).toBe(401);

      // No stale duplicate tokens linger: at most one live token remains (the
      // rotated one if refresh won and reuse detection has not yet reaped it,
      // otherwise none).
      const remaining = await RefreshToken.countDocuments({ userId: user.id });
      expect(remaining).toBeLessThanOrEqual(1);
    });
  });

  // ── Concurrent Item Operations ──────────────────────────────────────

  describe('Concurrent item operations', () => {
    it('should handle concurrent item updates without conflict', async () => {
      const itemIds = await Promise.all(
        Array.from({ length: 3 }, (_, i) =>
          createItemViaApi(user.accessToken, { encryptedName: `item-${String(i)}` }),
        ),
      );

      // Update all items concurrently
      const updatePromises = itemIds.map(async (id, i) => {
        const agent = request.agent(app);
        const csrf = await getCsrf(agent);
        return agent
          .put(`/api/v1/vault/items/${id}`)
          .set('Authorization', authHeader(user.accessToken))
          .set('Cookie', csrf.cookie)
          .set('x-csrf-token', csrf.token)
          .send(sampleVaultItem({ encryptedName: `updated-${String(i)}` }));
      });

      const updateResults = await Promise.all(updatePromises);

      for (const result of updateResults) {
        expect(result.status).toBe(200);
      }

      const items = await VaultItem.find({ userId: user.id }).lean();
      expect(items).toHaveLength(3);
      // Concurrent creation + update means ordering by createdAt is non-deterministic.
      // Instead, verify all three expected names exist regardless of order.
      const names = items.map((item) => item.encryptedName).sort();
      expect(names).toEqual(['updated-0', 'updated-1', 'updated-2']);
    });
  });

  // ── Concurrent Session Operations ───────────────────────────────────

  describe('Concurrent session operations', () => {
    it('should handle concurrent session listing and revocation', async () => {
      const otherUser = await createTestUser({ email: 'other@example.com' });

      const [listResult, revokeResult] = await Promise.all([
        request(app)
          .get('/api/v1/user/sessions')
          .set('Authorization', authHeader(user.accessToken)),
        (async () => {
          const sessionsRes = await request(app)
            .get('/api/v1/user/sessions')
            .set('Authorization', authHeader(otherUser.accessToken));

          const sessions = sessionsRes.body.data as { _id: string }[];
          // otherUser was just created with exactly one refresh-token session;
          // the previous `if (sessions.length === 0) return sessionsRes` escape
          // silently degraded to a plain GET (also 200) and let the test pass
          // without ever issuing the delete. Assert the precondition instead.
          expect(sessions).toHaveLength(1);

          const agent = request.agent(app);
          const csrf = await getCsrf(agent);
          return agent
            .delete(`/api/v1/user/sessions/${sessions[0]!._id}`)
            .set('Authorization', authHeader(otherUser.accessToken))
            .set('Cookie', csrf.cookie)
            .set('x-csrf-token', csrf.token);
        })(),
      ]);

      expect(listResult.status).toBe(200);
      expect(revokeResult.status).toBe(200);

      // The revoke must actually DELETE otherUser's session row. Asserting only
      // the 200 status (as before) would pass even if revokeSession stopped
      // deleting and merely responded 200. The previous DB check looked at
      // `user` — the wrong user, whose session was never targeted.
      expect(await RefreshToken.countDocuments({ userId: otherUser.id })).toBe(0);

      // `user` was not touched by the revoke and must still have its session.
      const userSessions = await RefreshToken.find({ userId: user.id }).lean();
      expect(userSessions).toHaveLength(1);
    });
  });
});
