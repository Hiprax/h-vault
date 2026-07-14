import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import crypto from 'node:crypto';
import request from 'supertest';
import app from '../src/app.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { User } from '../src/models/User.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { hashToken } from '../src/utils/token.js';
import {
  createTestUser,
  authHeader,
  sampleVaultItem,
  sampleFolder,
  getCsrf,
  type TestUser,
} from './helpers.js';

/** Seeds an extra refresh token row for a user and returns its raw + hash. */
async function seedRefreshToken(userId: string): Promise<{ raw: string; hash: string }> {
  const raw = crypto.randomBytes(64).toString('hex');
  const hash = hashToken(raw);
  await RefreshToken.create({
    userId,
    tokenHash: hash,
    familyId: crypto.randomUUID(),
    deviceInfo: { userAgent: 'seeded-device', ip: '127.0.0.1', fingerprint: 'seeded-fp' },
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  });
  return { raw, hash };
}

// ---------------------------------------------------------------------------
// Phase 7 — Task 7.1: Concurrent Operations Safety Tests
// ---------------------------------------------------------------------------

describe('Concurrent Operations Safety', () => {
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

  // ── Vault key rotation + item creation ─────────────────────────────

  describe('Concurrent vault key rotation and item creation', () => {
    it('rotation should not lose items created concurrently', async () => {
      // Create a pre-existing item
      const existingItemId = await createItemViaApi(user.accessToken);
      const idempotencyKey = '660e8400-e29b-41d4-a716-446655440001';

      const rotationBody = {
        authHash: user.rawPassword,
        idempotencyKey,
        items: [
          {
            id: existingItemId,
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

      // Concurrently: rotate vault key and create a new item
      const [rotationResult, createResult] = await Promise.all([
        (async () => {
          const agent = request.agent(app);
          const csrf = await getCsrf(agent);
          return agent
            .post('/api/v1/vault/items/bulk-reencrypt')
            .set('Authorization', authHeader(user.accessToken))
            .set('Cookie', csrf.cookie)
            .set('x-csrf-token', csrf.token)
            .send(rotationBody);
        })(),
        (async () => {
          const agent = request.agent(app);
          const csrf = await getCsrf(agent);
          return agent
            .post('/api/v1/vault/items')
            .set('Authorization', authHeader(user.accessToken))
            .set('Cookie', csrf.cookie)
            .set('x-csrf-token', csrf.token)
            .send(sampleVaultItem({ encryptedName: 'new-during-rotation' }));
        })(),
      ]);

      // Both operations should complete without server error
      expect(rotationResult.status).toBeLessThan(500);
      expect(createResult.status).toBeLessThan(500);

      const allItems = await VaultItem.find({ userId: user.id }).lean();
      const existing = allItems.find((i) => String(i._id) === existingItemId);
      expect(existing).toBeDefined();

      // The concurrent create is either accepted (201 → the row MUST be
      // persisted, never silently dropped) or fenced by the rotation
      // write-guard (409 → assertVaultNotRotating). No other outcome is valid.
      if (createResult.status === 201) {
        const created = allItems.find((i) => i.encryptedName === 'new-during-rotation');
        expect(created).toBeDefined();
      } else {
        expect(createResult.status).toBe(409);
      }

      // The rotation either committed the new vault key AND re-encrypted the
      // pre-existing item, or it did neither (leaving the original ciphertext).
      // A 200 that failed to rewrite the item's ciphertext — the data-loss
      // regression this guards — turns the first branch RED.
      if (rotationResult.status === 200) {
        expect(existing?.encryptedName).toBe('rotated-name');
        expect(existing?.encryptedData).toBe('rotated-data');
        const postUser = await User.findById(user.id).select('+encryptedVaultKey').lean();
        expect(postUser?.encryptedVaultKey).toBe('new-vault-key');
      } else {
        expect(existing?.encryptedName).toBe('test-encrypted-name');
      }
    });
  });

  // ── Password change + token refresh ────────────────────────────────

  describe('Concurrent password change and token refresh', () => {
    it('refresh should fail after password change completes', async () => {
      const refreshCookie = `refreshToken=${user.refreshToken}`;
      const newAuthHash = 'new-password-hash-value';

      // Seed an INDEPENDENT refresh token that the concurrent refresh never
      // touches. Its deletion isolates changePassword's own token revocation —
      // the concurrent refresh would rotate/consume `user.refreshToken`
      // regardless, so that token dying proves nothing about changePassword.
      const independent = await seedRefreshToken(user.id);

      // Fire password change and token refresh concurrently. The change carries
      // the CORRECT `currentAuthHash` (the schema field — the old test sent
      // `currentPassword`, which Zod rejected with 400, making the whole test
      // dead), so it succeeds deterministically.
      const [changeResult, refreshResult] = await Promise.all([
        (async () => {
          const agent = request.agent(app);
          const csrf = await getCsrf(agent);
          return agent
            .put('/api/v1/user/change-password')
            .set('Authorization', authHeader(user.accessToken))
            .set('Cookie', csrf.cookie)
            .set('x-csrf-token', csrf.token)
            .send({
              currentAuthHash: user.rawPassword,
              newAuthHash,
              newEncryptedVaultKey: 'new-vault-key',
              newVaultKeyIv: 'new-vk-iv',
              newVaultKeyTag: 'new-vk-tag',
            });
        })(),
        (async () => {
          const agent = request.agent(app);
          const csrf = await getCsrf(agent, refreshCookie);
          return agent
            .post('/api/v1/auth/refresh')
            .set('Cookie', `${csrf.cookie}; ${refreshCookie}`)
            .set('x-csrf-token', csrf.token);
        })(),
      ]);

      // The password change succeeds (correct current auth hash) and the
      // concurrent refresh must not crash the server.
      expect(changeResult.status).toBe(200);
      expect(refreshResult.status).toBeLessThan(500);

      // changePassword revokes EVERY refresh token for the user — including the
      // independent one no request touched. Removing that revocation turns this
      // RED (the concurrent refresh alone cannot account for this token's death).
      expect(await RefreshToken.findOne({ tokenHash: independent.hash })).toBeNull();

      // And the original refresh token can no longer mint access tokens.
      const verifyRefresh = await (async () => {
        const agent = request.agent(app);
        const csrf = await getCsrf(agent, refreshCookie);
        return agent
          .post('/api/v1/auth/refresh')
          .set('Cookie', `${csrf.cookie}; ${refreshCookie}`)
          .set('x-csrf-token', csrf.token);
      })();
      expect(verifyRefresh.status).not.toBe(200);
    });
  });

  // ── Backup restore + vault modification ────────────────────────────

  describe('Concurrent backup restore and vault modification', () => {
    it('should handle concurrent item creation and bulk-delete without crash', async () => {
      // Create items to work with
      const itemIds = await Promise.all(
        Array.from({ length: 4 }, (_, i) =>
          createItemViaApi(user.accessToken, { encryptedName: `item-${String(i)}` }),
        ),
      );

      // Concurrently: bulk-delete first 2 items + create a new item
      const [deleteResult, createResult] = await Promise.all([
        (async () => {
          const agent = request.agent(app);
          const csrf = await getCsrf(agent);
          return agent
            .post('/api/v1/vault/items/bulk-delete')
            .set('Authorization', authHeader(user.accessToken))
            .set('Cookie', csrf.cookie)
            .set('x-csrf-token', csrf.token)
            .send({ ids: itemIds.slice(0, 2) });
        })(),
        createItemViaApi(user.accessToken, { encryptedName: 'new-concurrent' }),
      ]);

      expect(deleteResult.status).toBe(200);
      expect(typeof createResult).toBe('string'); // item ID returned

      // Active items should include the non-deleted ones + the newly created one
      const activeItems = await VaultItem.find({
        userId: user.id,
        deletedAt: { $exists: false },
      }).lean();
      expect(activeItems.length).toBeGreaterThanOrEqual(3); // 2 surviving + 1 new
    });
  });

  // ── Logout-all + token refresh ─────────────────────────────────────

  describe('Concurrent logout-all and token refresh', () => {
    it('refresh should fail after logout-all revokes all sessions', async () => {
      const refreshCookie = `refreshToken=${user.refreshToken}`;

      // Fire logout-all and token refresh concurrently
      const [logoutResult, refreshResult] = await Promise.all([
        (async () => {
          const agent = request.agent(app);
          const csrf = await getCsrf(agent, refreshCookie);
          return agent
            .post('/api/v1/auth/logout-all')
            .set('Authorization', authHeader(user.accessToken))
            .set('Cookie', `${csrf.cookie}; ${refreshCookie}`)
            .set('x-csrf-token', csrf.token);
        })(),
        (async () => {
          const agent = request.agent(app);
          const csrf = await getCsrf(agent, refreshCookie);
          return agent
            .post('/api/v1/auth/refresh')
            .set('Cookie', `${csrf.cookie}; ${refreshCookie}`)
            .set('x-csrf-token', csrf.token);
        })(),
      ]);

      // Neither should crash the server
      expect(logoutResult.status).toBeLessThan(500);
      expect(refreshResult.status).toBeLessThan(500);

      // At least one should succeed
      const anySuccess = logoutResult.status === 200 || refreshResult.status === 200;
      expect(anySuccess).toBe(true);

      // After both complete, verify the old token is no longer valid
      const postLogoutRefresh = await (async () => {
        const agent = request.agent(app);
        const csrf = await getCsrf(agent, refreshCookie);
        return agent
          .post('/api/v1/auth/refresh')
          .set('Cookie', `${csrf.cookie}; ${refreshCookie}`)
          .set('x-csrf-token', csrf.token);
      })();

      // Old refresh token should be consumed or revoked
      expect(postLogoutRefresh.status).not.toBe(200);
    });
  });

  // ── Account deletion + vault operations ────────────────────────────

  describe('Concurrent account deletion and vault operations', () => {
    it('vault operations should fail gracefully during account deletion', async () => {
      // Create a pre-existing item BEFORE the race. Because it exists before
      // deletion begins, the cascade must remove it — a deterministic check
      // (the concurrent create is inherently racy, so we don't hinge on it).
      const preExistingItemId = await createItemViaApi(user.accessToken);

      // Concurrently: delete the account and try to create a new item.
      const [deleteResult, createResult] = await Promise.all([
        (async () => {
          const agent = request.agent(app);
          const csrf = await getCsrf(agent);
          return agent
            .delete('/api/v1/user')
            .set('Authorization', authHeader(user.accessToken))
            .set('Cookie', csrf.cookie)
            .set('x-csrf-token', csrf.token)
            .send({ password: user.rawPassword });
        })(),
        (async () => {
          const agent = request.agent(app);
          const csrf = await getCsrf(agent);
          return agent
            .post('/api/v1/vault/items')
            .set('Authorization', authHeader(user.accessToken))
            .set('Cookie', csrf.cookie)
            .set('x-csrf-token', csrf.token)
            .send(sampleVaultItem({ encryptedName: 'during-deletion' }));
        })(),
      ]);

      // Account deletion succeeds and the user is gone.
      expect(deleteResult.status).toBe(200);
      expect(await User.findById(user.id)).toBeNull();

      // The concurrent create fails gracefully (rejected once the account is
      // gone) or wins the race (201) — never a 5xx crash.
      expect([201, 401, 404]).toContain(createResult.status);

      // The cascade removed the pre-existing item — no orphaned vault row is
      // left pointing at a deleted user.
      expect(await VaultItem.findById(preExistingItemId)).toBeNull();
    });
  });

  // ── Concurrent folder + item creation in same folder ───────────────

  describe('Concurrent folder operations', () => {
    it('creates five distinct folders concurrently and persists exactly five', async () => {
      const createPromises = Array.from({ length: 5 }, (_, i) =>
        createFolderViaApi(user.accessToken, { encryptedName: `concurrent-folder-${String(i)}` }),
      );

      const folderIds = await Promise.all(createPromises);

      // Distinct ids AND exactly five rows actually persisted (the previous test
      // asserted only id-uniqueness, which is true by ObjectId construction even
      // if a create silently failed to persist).
      expect(new Set(folderIds).size).toBe(5);
      expect(await Folder.countDocuments({ userId: user.id })).toBe(5);
    });

    it('deduplicates concurrent folder creates that share a searchHash (one 201, rest 409)', async () => {
      const searchHash = 'a'.repeat(64); // valid /^[a-f0-9]{64}$/
      const attempts = await Promise.all(
        Array.from({ length: 5 }, (_, i) =>
          (async () => {
            const agent = request.agent(app);
            const csrf = await getCsrf(agent);
            return agent
              .post('/api/v1/folders')
              .set('Authorization', authHeader(user.accessToken))
              .set('Cookie', csrf.cookie)
              .set('x-csrf-token', csrf.token)
              .send(sampleFolder({ encryptedName: `dup-folder-${String(i)}`, searchHash }));
          })(),
        ),
      );

      const created = attempts.filter((r) => r.status === 201);
      const conflicts = attempts.filter((r) => r.status === 409);

      // The unique (userId, searchHash) partial index admits exactly one row;
      // the losers surface as 409 (E11000 → conflict), never 500 or a dupe.
      expect(created).toHaveLength(1);
      expect(conflicts).toHaveLength(4);
      expect(await Folder.countDocuments({ userId: user.id })).toBe(1);
    });
  });

  // ── Vault key rotation partial-failure rollback ────────────────────

  describe('Vault key rotation partial-failure rollback', () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    it('rolls back partially-written ciphertext and leaves vault key unchanged when a folder update fails mid-rotation', async () => {
      // Two items + two folders so we can fail the SECOND folder write after
      // the items + first folder have already been written with new ciphertext.
      const item1Id = await createItemViaApi(user.accessToken, {
        encryptedData: 'orig-data-1',
        encryptedName: 'orig-name-1',
        nameIv: 'orig-name-iv-1',
        nameTag: 'orig-name-tag-1',
        dataIv: 'orig-data-iv-1',
        dataTag: 'orig-data-tag-1',
      });
      const item2Id = await createItemViaApi(user.accessToken, {
        encryptedData: 'orig-data-2',
        encryptedName: 'orig-name-2',
        nameIv: 'orig-name-iv-2',
        nameTag: 'orig-name-tag-2',
        dataIv: 'orig-data-iv-2',
        dataTag: 'orig-data-tag-2',
      });
      const folder1Id = await createFolderViaApi(user.accessToken, {
        encryptedName: 'orig-folder-1',
        nameIv: 'orig-folder-iv-1',
        nameTag: 'orig-folder-tag-1',
      });
      const folder2Id = await createFolderViaApi(user.accessToken, {
        encryptedName: 'orig-folder-2',
        nameIv: 'orig-folder-iv-2',
        nameTag: 'orig-folder-tag-2',
      });

      // Capture original user vault key state.
      const originalUser = await User.findById(user.id).select('+encryptedVaultKey').lean();
      expect(originalUser).not.toBeNull();
      const originalEncryptedVaultKey = originalUser!.encryptedVaultKey;

      // Stub Folder.updateOne so the SECOND folder update throws. The first
      // folder + both items will already have been written with new ciphertext
      // by then, so the rollback path must restore them.
      const realFolderUpdateOne = Folder.updateOne.bind(Folder);
      let folderCallCount = 0;
      const spy = vi.spyOn(Folder, 'updateOne').mockImplementation((...args: unknown[]) => {
        folderCallCount++;
        // First call (folder1) succeeds; second call (folder2) throws.
        if (folderCallCount === 2) {
          throw new Error('Simulated DB failure on second folder update');
        }
        return realFolderUpdateOne(...(args as Parameters<typeof Folder.updateOne>));
      });

      const rotationBody = {
        authHash: user.rawPassword,
        items: [
          {
            id: item1Id,
            encryptedName: 'NEW-name-1',
            nameIv: 'NEW-name-iv-1',
            nameTag: 'NEW-name-tag-1',
            encryptedData: 'NEW-data-1',
            dataIv: 'NEW-data-iv-1',
            dataTag: 'NEW-data-tag-1',
          },
          {
            id: item2Id,
            encryptedName: 'NEW-name-2',
            nameIv: 'NEW-name-iv-2',
            nameTag: 'NEW-name-tag-2',
            encryptedData: 'NEW-data-2',
            dataIv: 'NEW-data-iv-2',
            dataTag: 'NEW-data-tag-2',
          },
        ],
        folders: [
          {
            id: folder1Id,
            encryptedName: 'NEW-folder-1',
            nameIv: 'NEW-folder-iv-1',
            nameTag: 'NEW-folder-tag-1',
          },
          {
            id: folder2Id,
            encryptedName: 'NEW-folder-2',
            nameIv: 'NEW-folder-iv-2',
            nameTag: 'NEW-folder-tag-2',
          },
        ],
        newEncryptedVaultKey: 'rotated-vault-key',
        newVaultKeyIv: 'rotated-vk-iv',
        newVaultKeyTag: 'rotated-vk-tag',
      };

      const agent = request.agent(app);
      const csrf = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/vault/items/bulk-reencrypt')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send(rotationBody);

      // Restore the spy BEFORE asserting state so subsequent reads use real DB calls.
      spy.mockRestore();

      // The rotation must fail with a 4xx response (conflict).
      expect(res.status).toBeGreaterThanOrEqual(400);
      expect(res.status).toBeLessThan(500);

      // The user's vault key MUST remain unchanged.
      const postUser = await User.findById(user.id).select('+encryptedVaultKey').lean();
      expect(postUser).not.toBeNull();
      expect(postUser!.encryptedVaultKey).toBe(originalEncryptedVaultKey);
      expect(postUser!.rotationInProgress).not.toBe(true);
      expect(postUser!.pendingEncryptedVaultKey).toBeUndefined();

      // CRITICAL: every item and folder must carry its ORIGINAL ciphertext,
      // not the new one. This is what the rollback guarantees.
      const item1 = await VaultItem.findById(item1Id).lean();
      const item2 = await VaultItem.findById(item2Id).lean();
      const folder1 = await Folder.findById(folder1Id).lean();
      const folder2 = await Folder.findById(folder2Id).lean();

      expect(item1?.encryptedData).toBe('orig-data-1');
      expect(item1?.encryptedName).toBe('orig-name-1');
      expect(item2?.encryptedData).toBe('orig-data-2');
      expect(item2?.encryptedName).toBe('orig-name-2');
      expect(folder1?.encryptedName).toBe('orig-folder-1');
      expect(folder2?.encryptedName).toBe('orig-folder-2');
    });

    it('aborts before any write when a requested item id is missing', async () => {
      const realItemId = await createItemViaApi(user.accessToken, {
        encryptedData: 'real-data',
        encryptedName: 'real-name',
      });
      const fakeItemId = '0000aaaa0000aaaa0000aaaa';

      const originalUser = await User.findById(user.id).select('+encryptedVaultKey').lean();
      const originalEncryptedVaultKey = originalUser!.encryptedVaultKey;

      const rotationBody = {
        authHash: user.rawPassword,
        items: [
          {
            id: realItemId,
            encryptedName: 'NEW-name',
            nameIv: 'NEW-name-iv',
            nameTag: 'NEW-name-tag',
            encryptedData: 'NEW-data',
            dataIv: 'NEW-data-iv',
            dataTag: 'NEW-data-tag',
          },
          {
            id: fakeItemId,
            encryptedName: 'NEW-name-fake',
            nameIv: 'NEW-name-iv-fake',
            nameTag: 'NEW-name-tag-fake',
            encryptedData: 'NEW-data-fake',
            dataIv: 'NEW-data-iv-fake',
            dataTag: 'NEW-data-tag-fake',
          },
        ],
        folders: [],
        newEncryptedVaultKey: 'rotated-vault-key',
        newVaultKeyIv: 'rotated-vk-iv',
        newVaultKeyTag: 'rotated-vk-tag',
      };

      const agent = request.agent(app);
      const csrf = await getCsrf(agent);
      const res = await agent
        .post('/api/v1/vault/items/bulk-reencrypt')
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send(rotationBody);

      expect(res.status).toBeGreaterThanOrEqual(400);
      expect(res.status).toBeLessThan(500);

      // Vault key unchanged.
      const postUser = await User.findById(user.id).select('+encryptedVaultKey').lean();
      expect(postUser!.encryptedVaultKey).toBe(originalEncryptedVaultKey);
      expect(postUser!.rotationInProgress).not.toBe(true);

      // The real item must NOT have been touched (early abort before any write).
      const realItem = await VaultItem.findById(realItemId).lean();
      expect(realItem?.encryptedData).toBe('real-data');
      expect(realItem?.encryptedName).toBe('real-name');
    });
  });

  // ── Concurrent session revocation ──────────────────────────────────

  describe('Concurrent session revocation', () => {
    it('should handle revoking all other sessions concurrently from multiple actors', async () => {
      const refreshCookie = `refreshToken=${user.refreshToken}`;

      // Seed 3 additional sessions. logout-all must revoke every session EXCEPT
      // the caller's own (matched by `tokenHash: { $ne: current }`), so exactly
      // one row — `user.refreshToken` — survives both concurrent calls.
      await seedRefreshToken(user.id);
      await seedRefreshToken(user.id);
      await seedRefreshToken(user.id);
      expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(4);

      // Fire two logout-all requests concurrently
      const [result1, result2] = await Promise.all([
        (async () => {
          const agent = request.agent(app);
          const csrf = await getCsrf(agent, refreshCookie);
          return agent
            .post('/api/v1/auth/logout-all')
            .set('Authorization', authHeader(user.accessToken))
            .set('Cookie', `${csrf.cookie}; ${refreshCookie}`)
            .set('x-csrf-token', csrf.token);
        })(),
        (async () => {
          const agent = request.agent(app);
          const csrf = await getCsrf(agent, refreshCookie);
          return agent
            .post('/api/v1/auth/logout-all')
            .set('Authorization', authHeader(user.accessToken))
            .set('Cookie', `${csrf.cookie}; ${refreshCookie}`)
            .set('x-csrf-token', csrf.token);
        })(),
      ]);

      // Both should complete without crashing and succeed for an authed caller.
      expect(result1.status).toBe(200);
      expect(result2.status).toBe(200);

      // All OTHER sessions were revoked; only the caller's own token remains.
      // Replacing the deleteMany with a no-op leaves 4 rows here → RED.
      expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(1);
      const survivor = await RefreshToken.findOne({ userId: user.id }).lean();
      expect(survivor?.tokenHash).toBe(hashToken(user.refreshToken));
    });
  });
});
