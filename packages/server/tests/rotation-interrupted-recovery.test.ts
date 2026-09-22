import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { AuditLog } from '../src/models/AuditLog.js';
import {
  createTestUser,
  authHeader,
  getCsrf,
  seedItem,
  seedFolder,
  type TestUser,
} from './helpers.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';

// ---------------------------------------------------------------------------
// Crash-recovery for an interrupted vault key rotation.
//
// The sequential rotation path commits `rotationInProgress: true` TOGETHER with
// the new vault key wrapped under the account's MEK
// (`pendingEncryptedVaultKey` / `pendingVaultKeyIv` / `pendingVaultKeyTag`),
// expressly so that a crash mid-rotation is recoverable: some rows are already
// sealed under that key and NOTHING ELSE ANYWHERE stores it. Login recovery
// therefore lowers the fence and must leave the wrapper alone — a flag can be
// recomputed, a key cannot — and `GET /user/profile` must say the rotation is
// outstanding so the account can finish it.
//
// The transactional path never writes the wrapper (it rolls back atomically, so
// there is nothing half-done to finish), and that asymmetry is asserted here
// too: a crashed transactional rotation reports nothing outstanding.
// ---------------------------------------------------------------------------

const API = '/api/v1';

const PENDING = {
  pendingEncryptedVaultKey: 'pending-wrapped-vault-key',
  pendingVaultKeyIv: 'pending-vault-key-iv',
  pendingVaultKeyTag: 'pending-vault-key-tag',
} as const;

/** The fields the User model marks `select: false`; none may ever be serialised. */
const NEVER_SERIALISED = [
  'authHash',
  'twoFactorSecret',
  'pendingTwoFactorSecret',
  'pendingTwoFactorExpiry',
  'backupCodes',
] as const;

describe('Interrupted vault key rotation: recovery and disclosure', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser({ emailVerified: true });
  });

  async function login(): Promise<request.Response> {
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);
    return agent
      .post(`${API}/auth/login`)
      .set('Cookie', csrf.cookie)
      .set('x-csrf-token', csrf.token)
      .send({ email: user.email, authHash: user.rawPassword });
  }

  async function profile(): Promise<request.Response> {
    return request(app)
      .get(`${API}/user/profile`)
      .set('Authorization', authHeader(user.accessToken));
  }

  /** Writes the exact state a crashed SEQUENTIAL rotation leaves behind. */
  async function seedCrashedRotation(withPendingKey = true): Promise<void> {
    await User.updateOne(
      { _id: user.id },
      { $set: { rotationInProgress: true, ...(withPendingKey ? PENDING : {}) } },
    );
  }

  // ── 3.1 recovery keeps the key and lowers only the fence ─────────────

  it('lowers the crashed write fence but KEEPS the pending vault key wrapper', async () => {
    await seedCrashedRotation();

    const res = await login();
    expect(res.status).toBe(200);

    const recovered = await User.findById(user.id).lean();
    // The fence is down: writes are admitted again.
    expect(recovered!.rotationInProgress).toBe(false);
    // ...and the only stored copy of the in-flight key survived, byte for byte.
    expect(recovered!.pendingEncryptedVaultKey).toBe(PENDING.pendingEncryptedVaultKey);
    expect(recovered!.pendingVaultKeyIv).toBe(PENDING.pendingVaultKeyIv);
    expect(recovered!.pendingVaultKeyTag).toBe(PENDING.pendingVaultKeyTag);
    // The LIVE key is untouched: recovery never promotes the pending wrapper.
    expect(recovered!.encryptedVaultKey).toBe('test-encrypted-vault-key');
    expect(recovered!.vaultKeyIv).toBe('test-vault-key-iv');
    expect(recovered!.vaultKeyTag).toBe('test-vault-key-tag');
  });

  it('records the outstanding rotation on the rotation_recovery audit row', async () => {
    await seedCrashedRotation();

    await login();

    const audits = await AuditLog.find({ userId: user.id, action: 'rotation_recovery' }).lean();
    expect(audits).toHaveLength(1);
    const metadata = audits[0]!.metadata as Record<string, unknown>;
    expect(metadata['detail']).toMatch(/interrupted vault key rotation/i);
    expect(metadata['interruptedRotation']).toBe(true);
  });

  it('reports nothing outstanding when a crashed rotation left no pending wrapper', async () => {
    // The transactional path raises the fence without ever writing the wrapper.
    await seedCrashedRotation(false);

    const res = await login();
    expect(res.status).toBe(200);

    const recovered = await User.findById(user.id).lean();
    expect(recovered!.rotationInProgress).toBe(false);
    expect(recovered!.pendingEncryptedVaultKey).toBeUndefined();

    const audits = await AuditLog.find({ userId: user.id, action: 'rotation_recovery' }).lean();
    expect(audits).toHaveLength(1);
    expect((audits[0]!.metadata as Record<string, unknown>)['interruptedRotation']).toBe(false);
  });

  // ── 3.2 the profile says so, and says nothing else ───────────────────

  it('reports interruptedRotation and the pending wrapper on the profile', async () => {
    await seedCrashedRotation();
    await login();

    const res = await profile();
    expect(res.status).toBe(200);
    expect(res.body.data.interruptedRotation).toBe(true);
    // The wrapper itself, so the client can unwrap it with the MEK it holds and
    // finish the rotation rather than mint a third key.
    expect(res.body.data.pendingEncryptedVaultKey).toBe(PENDING.pendingEncryptedVaultKey);
    expect(res.body.data.pendingVaultKeyIv).toBe(PENDING.pendingVaultKeyIv);
    expect(res.body.data.pendingVaultKeyTag).toBe(PENDING.pendingVaultKeyTag);
  });

  it('never serialises a select:false field alongside the new disclosure', async () => {
    await User.updateOne(
      { _id: user.id },
      {
        $set: {
          ...PENDING,
          rotationInProgress: true,
          twoFactorSecret: 'encrypted-totp-secret',
          pendingTwoFactorSecret: 'encrypted-pending-totp-secret',
          pendingTwoFactorExpiry: new Date(Date.now() + 60_000),
          backupCodes: ['hashed-backup-code'],
        },
      },
    );
    await login();

    const res = await profile();
    expect(res.status).toBe(200);
    expect(res.body.data.interruptedRotation).toBe(true);
    for (const field of NEVER_SERIALISED) {
      expect(res.body.data).not.toHaveProperty(field);
    }
  });

  it('reports interruptedRotation false and no pending fields on a clean account', async () => {
    const res = await profile();

    expect(res.status).toBe(200);
    expect(res.body.data.interruptedRotation).toBe(false);
    expect(res.body.data).not.toHaveProperty('pendingEncryptedVaultKey');
    expect(res.body.data).not.toHaveProperty('pendingVaultKeyIv');
    expect(res.body.data).not.toHaveProperty('pendingVaultKeyTag');
    for (const field of NEVER_SERIALISED) {
      expect(res.body.data).not.toHaveProperty(field);
    }
  });

  // ── The outstanding-rotation guard ───────────────────────────────────
  //
  // Keeping the wrapper is only half of the protection. The rows sealed under the
  // key it wraps are ALSO invisible to the client driving the next rotation, which
  // cannot decrypt them and carries them across unchanged — so a rotation to any
  // OTHER key replaces the vault key and leaves them behind for ever, behind a
  // 200. The server is the only place that can see the wrapper and refuse.

  describe('a rotation while one is outstanding', () => {
    let itemId: string;
    let folderId: string;

    beforeEach(async () => {
      itemId = String((await seedItem(user.id, { encryptedName: 'pre-existing-item' }))._id);
      folderId = String((await seedFolder(user.id, { encryptedName: 'pre-existing-folder' }))._id);
      await seedCrashedRotation();
      await login();
    });

    function rotationBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
      return {
        authHash: user.rawPassword,
        items: [
          {
            id: itemId,
            encryptedName: 'rotated-name',
            nameIv: 'rotated-name-iv',
            nameTag: 'rotated-name-tag',
            encryptedData: 'rotated-data',
            dataIv: 'rotated-data-iv',
            dataTag: 'rotated-data-tag',
          },
        ],
        folders: [
          {
            id: folderId,
            encryptedName: 'rotated-folder-name',
            nameIv: 'rotated-folder-iv',
            nameTag: 'rotated-folder-tag',
          },
        ],
        newEncryptedVaultKey: 'a-third-vault-key',
        newVaultKeyIv: 'a-third-iv',
        newVaultKeyTag: 'a-third-tag',
        ...overrides,
      };
    }

    async function rotate(body: Record<string, unknown>): Promise<request.Response> {
      const agent = request.agent(app);
      const csrf = await getCsrf(agent);
      return agent
        .post(`${API}/vault/items/bulk-reencrypt`)
        .set('Authorization', authHeader(user.accessToken))
        .set('Cookie', csrf.cookie)
        .set('x-csrf-token', csrf.token)
        .send(body);
    }

    it('refuses a rotation to a THIRD key, and writes nothing', async () => {
      const res = await rotate(rotationBody());

      expect(res.status).toBe(409);
      expect(res.body.message).toMatch(/interrupted vault key rotation is still outstanding/i);

      const after = await User.findById(user.id).lean();
      // Neither key moved, and the wrapper is still there to finish with.
      expect(after!.encryptedVaultKey).toBe('test-encrypted-vault-key');
      expect(after!.pendingEncryptedVaultKey).toBe(PENDING.pendingEncryptedVaultKey);
      expect(after!.vaultKeyVersion ?? 0).toBe(0);
      // And no row was rewritten on the way to the refusal.
      expect((await VaultItem.findById(itemId).lean())!.encryptedName).toBe('pre-existing-item');
      expect((await Folder.findById(folderId).lean())!.encryptedName).toBe('pre-existing-folder');
      // The fence is down again, so the account is not wedged by the refusal.
      expect(after!.rotationInProgress).toBe(false);
    });

    it('accepts the rotation that ADOPTS the pending wrapper, and clears it on commit', async () => {
      const res = await rotate(
        rotationBody({
          newEncryptedVaultKey: PENDING.pendingEncryptedVaultKey,
          newVaultKeyIv: PENDING.pendingVaultKeyIv,
          newVaultKeyTag: PENDING.pendingVaultKeyTag,
        }),
      );

      expect(res.status, JSON.stringify(res.body)).toBe(200);
      const after = await User.findById(user.id).lean();
      expect(after!.encryptedVaultKey).toBe(PENDING.pendingEncryptedVaultKey);
      // A COMMIT is the one event that makes the wrapper redundant.
      expect(after!.pendingEncryptedVaultKey).toBeUndefined();
      expect(after!.pendingVaultKeyIv).toBeUndefined();
      expect(after!.pendingVaultKeyTag).toBeUndefined();
      expect(after!.vaultKeyVersion).toBe(1);

      // ...and the profile stops offering to finish it.
      const profileRes = await profile();
      expect(profileRes.body.data.interruptedRotation).toBe(false);
    });

    it('accepts a rotation to a third key when it says in so many words that it is discarding', async () => {
      // The escape that stops the guard from wedging an account whose wrapper can
      // no longer be opened — it is sealed under the MEK the rotation ran with, and
      // a master-password change since has replaced that MEK.
      const res = await rotate(rotationBody({ discardPendingVaultKey: true }));

      expect(res.status, JSON.stringify(res.body)).toBe(200);
      const after = await User.findById(user.id).lean();
      expect(after!.encryptedVaultKey).toBe('a-third-vault-key');
      expect(after!.pendingEncryptedVaultKey).toBeUndefined();
      expect(after!.vaultKeyVersion).toBe(1);
    });

    it('still refuses when the flag is explicitly false rather than absent', async () => {
      const res = await rotate(rotationBody({ discardPendingVaultKey: false }));

      expect(res.status).toBe(409);
      expect((await User.findById(user.id).lean())!.encryptedVaultKey).toBe(
        'test-encrypted-vault-key',
      );
    });

    it('leaves an account with no outstanding rotation free to rotate to any key', async () => {
      // The guard must not cost anything to the ordinary case: only an account
      // actually holding a wrapper is constrained.
      await User.updateOne(
        { _id: user.id },
        {
          $unset: {
            pendingEncryptedVaultKey: 1,
            pendingVaultKeyIv: 1,
            pendingVaultKeyTag: 1,
          },
        },
      );

      const res = await rotate(rotationBody());

      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect((await User.findById(user.id).lean())!.encryptedVaultKey).toBe('a-third-vault-key');
    });
  });
});
