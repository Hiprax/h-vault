import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import crypto from 'node:crypto';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { BackupLog } from '../src/models/BackupLog.js';
import {
  createTestUser,
  authHeader,
  sampleVaultItem,
  sampleFolder,
  getCsrf as getCsrfBase,
} from './helpers.js';
import type { TestUser } from './helpers.js';
import { hashToken } from '../src/utils/token.js';

// Re-export with { csrfToken, csrfCookie } naming used throughout this file.
// `extraCookies` mirrors the helper signature so the CSRF token can be issued
// against the same refresh-token family the request will use.
async function getCsrf(
  agent: request.Agent,
  extraCookies?: string,
): Promise<{ csrfToken: string; csrfCookie: string }> {
  const { token, cookie } = await getCsrfBase(agent, extraCookies);
  return { csrfToken: token, csrfCookie: cookie };
}

// ---------------------------------------------------------------------------
// Helper: create an item via the API
// ---------------------------------------------------------------------------

async function createItemViaApi(
  token: string,
  overrides: Record<string, unknown> = {},
): Promise<string> {
  const agent = request.agent(app);
  const { csrfToken, csrfCookie } = await getCsrf(agent);

  const res = await agent
    .post('/api/v1/vault/items')
    .set('Authorization', authHeader(token))
    .set('Cookie', csrfCookie)
    .set('x-csrf-token', csrfToken)
    .send(sampleVaultItem(overrides))
    .expect(201);

  return res.body.data._id as string;
}

// ---------------------------------------------------------------------------
// Helper: create a folder via the API
// ---------------------------------------------------------------------------

async function createFolderViaApi(
  token: string,
  overrides: Record<string, unknown> = {},
): Promise<string> {
  const agent = request.agent(app);
  const { csrfToken, csrfCookie } = await getCsrf(agent);

  const res = await agent
    .post('/api/v1/folders')
    .set('Authorization', authHeader(token))
    .set('Cookie', csrfCookie)
    .set('x-csrf-token', csrfToken)
    .send(sampleFolder(overrides))
    .expect(201);

  return res.body.data._id as string;
}

// ===========================================================================
//  1. Vault Key Rotation (POST /items/bulk-reencrypt)
// ===========================================================================

describe('Vault Key Rotation (POST /api/v1/vault/items/bulk-reencrypt)', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  it('should rotate vault key and re-encrypt items and folders', async () => {
    // Create items and a folder that will be re-encrypted
    const itemId = await createItemViaApi(user.accessToken);
    const folderId = await createFolderViaApi(user.accessToken);

    const agent = request.agent(app);
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const res = await agent
      .post('/api/v1/vault/items/bulk-reencrypt')
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', csrfCookie)
      .set('x-csrf-token', csrfToken)
      .send({
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
        newEncryptedVaultKey: 'new-vault-key',
        newVaultKeyIv: 'new-vault-key-iv',
        newVaultKeyTag: 'new-vault-key-tag',
      })
      .expect(200);

    expect(res.body.success).toBe(true);
    expect(res.body.message).toMatch(/vault key rotated/i);

    // Verify vault item was updated
    const updatedItem = await VaultItem.findById(itemId);
    expect(updatedItem!.encryptedData).toBe('rotated-data');
    expect(updatedItem!.encryptedName).toBe('rotated-name');

    // Verify folder was updated
    const updatedFolder = await Folder.findById(folderId);
    expect(updatedFolder!.encryptedName).toBe('rotated-folder-name');

    // Verify user vault key was updated
    const updatedUser = await User.findById(user.id);
    expect(updatedUser!.encryptedVaultKey).toBe('new-vault-key');
    expect(updatedUser!.vaultKeyIv).toBe('new-vault-key-iv');
    expect(updatedUser!.vaultKeyTag).toBe('new-vault-key-tag');
  });

  it('should reject rotation with wrong password', async () => {
    const agent = request.agent(app);
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const res = await agent
      .post('/api/v1/vault/items/bulk-reencrypt')
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', csrfCookie)
      .set('x-csrf-token', csrfToken)
      .send({
        authHash: 'wrong-password',
        items: [],
        folders: [],
        newEncryptedVaultKey: 'new-vault-key',
        newVaultKeyIv: 'new-vault-key-iv',
        newVaultKeyTag: 'new-vault-key-tag',
      })
      .expect(401);

    expect(res.body.success).toBe(false);
  });

  it('should handle idempotency key — duplicate request returns success without re-processing', async () => {
    const itemId = await createItemViaApi(user.accessToken);
    const idempotencyKey = crypto.randomUUID();

    const payload = {
      authHash: user.rawPassword,
      idempotencyKey,
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
      folders: [],
      newEncryptedVaultKey: 'new-vault-key',
      newVaultKeyIv: 'new-vault-key-iv',
      newVaultKeyTag: 'new-vault-key-tag',
    };

    // First request
    const agent1 = request.agent(app);
    const csrf1 = await getCsrf(agent1);

    const res1 = await agent1
      .post('/api/v1/vault/items/bulk-reencrypt')
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', csrf1.csrfCookie)
      .set('x-csrf-token', csrf1.csrfToken)
      .send(payload)
      .expect(200);

    expect(res1.body.success).toBe(true);

    // Verify idempotency key was stored
    const userAfterFirst = await User.findById(user.id);
    expect(userAfterFirst!.lastRotationKey).toBe(idempotencyKey);

    // Second (duplicate) request with same idempotency key
    const agent2 = request.agent(app);
    const csrf2 = await getCsrf(agent2);

    const res2 = await agent2
      .post('/api/v1/vault/items/bulk-reencrypt')
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', csrf2.csrfCookie)
      .set('x-csrf-token', csrf2.csrfToken)
      .send({
        ...payload,
        // Even with different data, the idempotency key should short-circuit
        newEncryptedVaultKey: 'should-not-be-applied',
      })
      .expect(200);

    expect(res2.body.success).toBe(true);

    // Verify vault key was NOT updated by the duplicate request
    const userAfterSecond = await User.findById(user.id);
    expect(userAfterSecond!.encryptedVaultKey).toBe('new-vault-key');
  });

  it('should set rotationInProgress flag during non-transactional rotation', async () => {
    // In test env (MongoMemoryServer without replica set), the fallback path runs.
    // We verify that the rotation completes and the flag is cleared.
    const itemId = await createItemViaApi(user.accessToken);

    const agent = request.agent(app);
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    await agent
      .post('/api/v1/vault/items/bulk-reencrypt')
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', csrfCookie)
      .set('x-csrf-token', csrfToken)
      .send({
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
        folders: [],
        newEncryptedVaultKey: 'new-vault-key',
        newVaultKeyIv: 'new-vault-key-iv',
        newVaultKeyTag: 'new-vault-key-tag',
      })
      .expect(200);

    // After successful rotation, rotationInProgress should be cleared
    const updatedUser = await User.findById(user.id);
    expect(updatedUser!.get('rotationInProgress')).toBeFalsy();
    // Pending fields should be unset
    expect(updatedUser!.get('pendingEncryptedVaultKey')).toBeUndefined();
    expect(updatedUser!.get('pendingVaultKeyIv')).toBeUndefined();
    expect(updatedUser!.get('pendingVaultKeyTag')).toBeUndefined();
  });

  it('should rotate with empty items and folders arrays', async () => {
    const agent = request.agent(app);
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const res = await agent
      .post('/api/v1/vault/items/bulk-reencrypt')
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', csrfCookie)
      .set('x-csrf-token', csrfToken)
      .send({
        authHash: user.rawPassword,
        items: [],
        folders: [],
        newEncryptedVaultKey: 'new-vault-key',
        newVaultKeyIv: 'new-vault-key-iv',
        newVaultKeyTag: 'new-vault-key-tag',
      })
      .expect(200);

    expect(res.body.success).toBe(true);

    const updatedUser = await User.findById(user.id);
    expect(updatedUser!.encryptedVaultKey).toBe('new-vault-key');
  });
});

// ===========================================================================
//  2. Token Refresh Reuse Detection
// ===========================================================================

describe('Token Refresh Reuse Detection (POST /api/v1/auth/refresh)', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  it('should issue new tokens when refreshing with a valid unused token', async () => {
    const agent = request.agent(app);
    const { csrfToken, csrfCookie } = await getCsrf(agent, `refreshToken=${user.refreshToken}`);

    const res = await agent
      .post('/api/v1/auth/refresh')
      .set('Cookie', `${csrfCookie}; refreshToken=${user.refreshToken}`)
      .set('x-csrf-token', csrfToken)
      .expect(200);

    expect(res.body.success).toBe(true);
    expect(res.body.data.accessToken).toBeDefined();
    expect(typeof res.body.data.accessToken).toBe('string');
  });

  it('should revoke entire token family on refresh token reuse', async () => {
    // First, get the family ID of the user's refresh token
    const tokenHash = hashToken(user.refreshToken);
    const storedToken = await RefreshToken.findOne({ tokenHash });
    expect(storedToken).toBeDefined();
    const familyId = storedToken!.familyId;

    // First refresh — legitimate use (marks original token as used, creates new one)
    const agent1 = request.agent(app);
    const csrf1 = await getCsrf(agent1, `refreshToken=${user.refreshToken}`);

    const res1 = await agent1
      .post('/api/v1/auth/refresh')
      .set('Cookie', `${csrf1.csrfCookie}; refreshToken=${user.refreshToken}`)
      .set('x-csrf-token', csrf1.csrfToken)
      .expect(200);

    expect(res1.body.success).toBe(true);

    // Verify the original token is now marked as used
    const usedToken = await RefreshToken.findOne({ tokenHash });
    expect(usedToken!.usedAt).not.toBeNull();

    // Verify a new token was created in the same family
    const familyTokens = await RefreshToken.countDocuments({ familyId });
    expect(familyTokens).toBe(2);

    // Second refresh — reuse the SAME original token (simulates stolen token attack)
    const agent2 = request.agent(app);
    const csrf2 = await getCsrf(agent2, `refreshToken=${user.refreshToken}`);

    const res2 = await agent2
      .post('/api/v1/auth/refresh')
      .set('Cookie', `${csrf2.csrfCookie}; refreshToken=${user.refreshToken}`)
      .set('x-csrf-token', csrf2.csrfToken)
      .expect(401);

    expect(res2.body.success).toBe(false);
    expect(res2.body.message).toBe('TOKEN_REUSE_DETECTED');

    // Verify entire token family was revoked
    const remainingTokens = await RefreshToken.countDocuments({ familyId });
    expect(remainingTokens).toBe(0);
  });

  it('should reject refresh with an invalid token', async () => {
    const agent = request.agent(app);
    const { csrfToken, csrfCookie } = await getCsrf(agent, 'refreshToken=invalid-token-value');

    const res = await agent
      .post('/api/v1/auth/refresh')
      .set('Cookie', `${csrfCookie}; refreshToken=invalid-token-value`)
      .set('x-csrf-token', csrfToken)
      .expect(401);

    expect(res.body.success).toBe(false);
    expect(res.body.message).toBe('TOKEN_INVALID');
  });

  it('should reject refresh without a refresh token cookie', async () => {
    const agent = request.agent(app);
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const res = await agent
      .post('/api/v1/auth/refresh')
      .set('Cookie', csrfCookie)
      .set('x-csrf-token', csrfToken)
      .expect(401);

    expect(res.body.success).toBe(false);
  });

  it('should reject refresh with an expired token', async () => {
    // Create a token that is already expired
    const expiredToken = crypto.randomBytes(64).toString('hex');
    const expiredHash = hashToken(expiredToken);
    const tokenRecord = await RefreshToken.findOne({ tokenHash: hashToken(user.refreshToken) });

    await RefreshToken.create({
      userId: user.id,
      tokenHash: expiredHash,
      familyId: tokenRecord!.familyId,
      deviceInfo: { userAgent: 'test', ip: '127.0.0.1', fingerprint: 'test' },
      expiresAt: new Date(Date.now() - 1000), // Already expired
    });

    const agent = request.agent(app);
    const { csrfToken, csrfCookie } = await getCsrf(agent, `refreshToken=${expiredToken}`);

    const res = await agent
      .post('/api/v1/auth/refresh')
      .set('Cookie', `${csrfCookie}; refreshToken=${expiredToken}`)
      .set('x-csrf-token', csrfToken)
      .expect(401);

    expect(res.body.success).toBe(false);
    expect(res.body.message).toBe('TOKEN_EXPIRED');
  });
});

// ===========================================================================
//  3. Account Deletion Cascade (DELETE /api/v1/user)
// ===========================================================================

describe('Account Deletion Cascade (DELETE /api/v1/user)', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  it('should delete user and all associated data', async () => {
    // Create vault items, folders, and audit logs for the user
    await createItemViaApi(user.accessToken);
    await createItemViaApi(user.accessToken, { itemType: 'note' });
    await createFolderViaApi(user.accessToken);

    // Create a backup log entry manually
    await BackupLog.create({
      userId: user.id,
      status: 'success',
      fileSize: 1024,
      itemCount: 2,
      recipientEmail: user.email,
    });

    // Verify data exists before deletion
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(2);
    expect(await Folder.countDocuments({ userId: user.id })).toBe(1);
    expect(await RefreshToken.countDocuments({ userId: user.id })).toBeGreaterThanOrEqual(1);
    expect(await BackupLog.countDocuments({ userId: user.id })).toBe(1);

    // Delete account
    const agent = request.agent(app);
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const res = await agent
      .delete('/api/v1/user')
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', csrfCookie)
      .set('x-csrf-token', csrfToken)
      .send({ password: user.rawPassword })
      .expect(200);

    expect(res.body.success).toBe(true);
    expect(res.body.message).toMatch(/account deleted/i);

    // Verify all user data was deleted
    expect(await User.findById(user.id)).toBeNull();
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(0);
    expect(await Folder.countDocuments({ userId: user.id })).toBe(0);
    expect(await RefreshToken.countDocuments({ userId: user.id })).toBe(0);
    expect(await BackupLog.countDocuments({ userId: user.id })).toBe(0);
    expect(await AuditLog.countDocuments({ userId: user.id })).toBe(0);

    // Verify a system-level account_delete audit log was created (userId: null)
    const systemAudit = await AuditLog.findOne({
      action: 'account_delete',
      'metadata.deletedUserId': user.id,
    });
    expect(systemAudit).not.toBeNull();
    expect(systemAudit!.userId).toBeNull();
  });

  it('should reject deletion with wrong password', async () => {
    const agent = request.agent(app);
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const res = await agent
      .delete('/api/v1/user')
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', csrfCookie)
      .set('x-csrf-token', csrfToken)
      .send({ password: 'wrong-password-value' })
      .expect(401);

    expect(res.body.success).toBe(false);

    // User should still exist
    expect(await User.findById(user.id)).not.toBeNull();
  });

  it('should not affect other users data during deletion', async () => {
    const otherUser = await createTestUser();

    // Create data for both users
    await createItemViaApi(user.accessToken);
    await createItemViaApi(otherUser.accessToken);
    await createFolderViaApi(otherUser.accessToken);

    // Delete first user's account
    const agent = request.agent(app);
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    await agent
      .delete('/api/v1/user')
      .set('Authorization', authHeader(user.accessToken))
      .set('Cookie', csrfCookie)
      .set('x-csrf-token', csrfToken)
      .send({ password: user.rawPassword })
      .expect(200);

    // Verify other user's data is intact
    expect(await User.findById(otherUser.id)).not.toBeNull();
    expect(await VaultItem.countDocuments({ userId: otherUser.id })).toBe(1);
    expect(await Folder.countDocuments({ userId: otherUser.id })).toBe(1);
    expect(await RefreshToken.countDocuments({ userId: otherUser.id })).toBeGreaterThanOrEqual(1);
  });
});

// ===========================================================================
//  4. Rotation Recovery on Login After Crash
// ===========================================================================

describe('Rotation Recovery on Login (POST /api/v1/auth/login)', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  it('should recover from interrupted vault key rotation on next login', async () => {
    // Simulate a mid-rotation crash by setting rotationInProgress and pending fields
    await User.updateOne(
      { _id: user.id },
      {
        $set: {
          rotationInProgress: true,
          pendingEncryptedVaultKey: 'pending-key-data',
          pendingVaultKeyIv: 'pending-iv-data',
          pendingVaultKeyTag: 'pending-tag-data',
        },
      },
    );

    // Verify the crash state was set
    const crashedUser = await User.findById(user.id);
    expect(crashedUser!.rotationInProgress).toBe(true);
    expect(crashedUser!.get('pendingEncryptedVaultKey')).toBe('pending-key-data');
    expect(crashedUser!.get('pendingVaultKeyIv')).toBe('pending-iv-data');
    expect(crashedUser!.get('pendingVaultKeyTag')).toBe('pending-tag-data');

    // Log in — this should trigger recovery
    const agent = request.agent(app);
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const loginRes = await agent
      .post('/api/v1/auth/login')
      .set('Cookie', csrfCookie)
      .set('x-csrf-token', csrfToken)
      .send({ email: user.email, authHash: user.rawPassword })
      .expect(200);

    expect(loginRes.body.success).toBe(true);
    expect(loginRes.body.data.accessToken).toBeDefined();

    // Verify rotationInProgress is cleared
    const recoveredUser = await User.findById(user.id);
    expect(recoveredUser!.rotationInProgress).toBe(false);

    // Verify pending fields are unset
    expect(recoveredUser!.get('pendingEncryptedVaultKey')).toBeUndefined();
    expect(recoveredUser!.get('pendingVaultKeyIv')).toBeUndefined();
    expect(recoveredUser!.get('pendingVaultKeyTag')).toBeUndefined();

    // Verify original vault key is preserved (not overwritten by pending data)
    expect(recoveredUser!.encryptedVaultKey).toBe('test-encrypted-vault-key');
    expect(recoveredUser!.vaultKeyIv).toBe('test-vault-key-iv');
    expect(recoveredUser!.vaultKeyTag).toBe('test-vault-key-tag');

    // Verify a rotation_recovery audit log entry was created
    const auditEntry = await AuditLog.findOne({
      userId: user.id,
      action: 'rotation_recovery',
    });
    expect(auditEntry).not.toBeNull();
    expect(auditEntry!.metadata).toBeDefined();
  });

  it('should not trigger recovery when rotationInProgress is false', async () => {
    // Ensure rotationInProgress is false (default)
    const normalUser = await User.findById(user.id);
    expect(normalUser!.rotationInProgress).toBe(false);

    // Log in normally
    const agent = request.agent(app);
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const loginRes = await agent
      .post('/api/v1/auth/login')
      .set('Cookie', csrfCookie)
      .set('x-csrf-token', csrfToken)
      .send({ email: user.email, authHash: user.rawPassword })
      .expect(200);

    expect(loginRes.body.success).toBe(true);

    // No rotation_recovery audit log should exist
    const auditEntry = await AuditLog.findOne({
      userId: user.id,
      action: 'rotation_recovery',
    });
    expect(auditEntry).toBeNull();
  });

  it('should recover rotation state and still proceed with 2FA flow', async () => {
    // Enable 2FA on the user
    await User.updateOne(
      { _id: user.id },
      {
        $set: {
          twoFactorEnabled: true,
          twoFactorSecret: 'encrypted-secret-placeholder',
          rotationInProgress: true,
          pendingEncryptedVaultKey: 'pending-key-2fa',
          pendingVaultKeyIv: 'pending-iv-2fa',
          pendingVaultKeyTag: 'pending-tag-2fa',
        },
      },
    );

    // Log in — should recover AND return twoFactorRequired
    const agent = request.agent(app);
    const { csrfToken, csrfCookie } = await getCsrf(agent);

    const loginRes = await agent
      .post('/api/v1/auth/login')
      .set('Cookie', csrfCookie)
      .set('x-csrf-token', csrfToken)
      .send({ email: user.email, authHash: user.rawPassword })
      .expect(200);

    expect(loginRes.body.success).toBe(true);
    expect(loginRes.body.data.twoFactorRequired).toBe(true);
    expect(loginRes.body.data.tempToken).toBeDefined();

    // Verify rotation recovery happened even with 2FA
    const recoveredUser = await User.findById(user.id);
    expect(recoveredUser!.rotationInProgress).toBe(false);
    expect(recoveredUser!.get('pendingEncryptedVaultKey')).toBeUndefined();

    // Verify audit log
    const auditEntry = await AuditLog.findOne({
      userId: user.id,
      action: 'rotation_recovery',
    });
    expect(auditEntry).not.toBeNull();
  });
});
