import { describe, it, expect, beforeEach } from 'vitest';
import { Types } from 'mongoose';
import request from 'supertest';
import app from '../src/app.js';
import { User } from '../src/models/User.js';
import { Folder } from '../src/models/Folder.js';
import {
  createTestUser,
  authHeader,
  sampleVaultItem,
  sampleFolder,
  getCsrf as getCsrfBase,
} from './helpers.js';
import type { TestUser } from './helpers.js';

async function getCsrf(agent: request.Agent): Promise<{ csrfToken: string; csrfCookie: string }> {
  const { token, cookie } = await getCsrfBase(agent);
  return { csrfToken: token, csrfCookie: cookie };
}

// ── Helper: create an item via the API ──────────────────────────────────────
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

// ── Helper: create a folder via the API ─────────────────────────────────────
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
//  4.1 - Backup Restore keep_both Folder ParentId Remapping
// ===========================================================================

describe('Backup restore keep_both folder parentId remapping', () => {
  let user: TestUser;
  let agent: request.SuperTest<request.Test>;

  beforeEach(async () => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    user = await createTestUser();
  });

  it('should leave an existing non-duplicated child under its original parent (additive keep_both)', async () => {
    // Create a parent folder and a child folder that references it
    const parentId = new Types.ObjectId().toString();
    const childId = new Types.ObjectId().toString();

    // Seed the user's live tree directly (a parent with a child under it).
    // Restore now mints fresh _ids for non-owned rows, so we seed the initial
    // tree with these exact ids rather than "seeding" via a first restore.
    await Folder.create({
      _id: parentId,
      userId: user.id,
      ...sampleFolder({ encryptedName: 'parent-folder' }),
    });
    await Folder.create({
      _id: childId,
      userId: user.id,
      ...sampleFolder({ encryptedName: 'child-folder' }),
      parentId: new Types.ObjectId(parentId),
    });

    // Verify initial state
    const childBefore = await Folder.findById(childId).lean();
    expect(childBefore).not.toBeNull();
    expect(String(childBefore!.parentId)).toBe(parentId);

    // Second restore with keep_both: parent folder conflicts, child does NOT
    // conflict (it is not in this batch). The parent gets duplicated (new ID).
    // Under ADDITIVE keep_both semantics the pre-existing child is left exactly
    // where it is — still under its ORIGINAL parent — because a restored backup
    // must never re-parent live folders that were not part of the duplicated
    // set. Only newly-created duplicate folders are remapped.
    const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);
    const keepBothData = JSON.stringify({
      items: [],
      folders: [{ _id: parentId, ...sampleFolder({ encryptedName: 'parent-folder-dup' }) }],
    });

    const res = await agent
      .post('/api/v1/backup/restore')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf2)
      .set('Cookie', cookie2)
      .send({ conflictStrategy: 'keep_both', data: keepBothData });

    expect(res.status).toBe(200);
    expect(res.body.data.foldersRestored).toBe(1);

    // Find the new duplicate parent folder
    const allFolders = await Folder.find({ userId: user.id }).lean();
    const newParent = allFolders.find(
      (f) => String(f._id) !== parentId && f.encryptedName === 'parent-folder-dup',
    );
    expect(newParent).toBeDefined();

    // The existing child folder's parentId is UNCHANGED — it stays under the
    // original parent, not the freshly-created duplicate.
    const childAfter = await Folder.findById(childId).lean();
    expect(childAfter).not.toBeNull();
    expect(String(childAfter!.parentId)).toBe(parentId);
    expect(String(childAfter!.parentId)).not.toBe(String(newParent!._id));
  });

  it('should remap parentId for child folders that were also duplicated', async () => {
    // Create parent and child folders
    const parentId = new Types.ObjectId().toString();
    const childId = new Types.ObjectId().toString();

    // Seed the user's live tree directly (parent + child under it).
    await Folder.create({
      _id: parentId,
      userId: user.id,
      ...sampleFolder({ encryptedName: 'parent' }),
    });
    await Folder.create({
      _id: childId,
      userId: user.id,
      ...sampleFolder({ encryptedName: 'child' }),
      parentId: new Types.ObjectId(parentId),
    });

    // Restore both parent and child with keep_both — both get duplicated
    const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);
    const keepBothData = JSON.stringify({
      items: [],
      folders: [
        { _id: parentId, ...sampleFolder({ encryptedName: 'parent-dup' }) },
        { _id: childId, ...sampleFolder({ encryptedName: 'child-dup', parentId }) },
      ],
    });

    const res = await agent
      .post('/api/v1/backup/restore')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf2)
      .set('Cookie', cookie2)
      .send({ conflictStrategy: 'keep_both', data: keepBothData });

    expect(res.status).toBe(200);
    expect(res.body.data.foldersRestored).toBe(2);

    // Find the duplicated parent and child
    const allFolders = await Folder.find({ userId: user.id }).lean();
    const newParent = allFolders.find(
      (f) => String(f._id) !== parentId && f.encryptedName === 'parent-dup',
    );
    const newChild = allFolders.find(
      (f) => String(f._id) !== childId && f.encryptedName === 'child-dup',
    );
    expect(newParent).toBeDefined();
    expect(newChild).toBeDefined();

    // The duplicated child's parentId should point to the duplicated parent
    expect(String(newChild!.parentId)).toBe(String(newParent!._id));
  });
});

// ===========================================================================
//  4.2 - Non-Transactional Vault Key Rotation Safety
// ===========================================================================

describe('Non-transactional vault key rotation safety', () => {
  let user: TestUser;

  beforeEach(async () => {
    user = await createTestUser();
  });

  it('should NOT update vault key when an item update fails during rotation', async () => {
    // Create an item
    const itemId1 = await createItemViaApi(user.accessToken);

    // Use a non-existent item ID to simulate a "not found" failure
    const fakeItemId = new Types.ObjectId().toString();

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
            id: itemId1,
            encryptedName: 'rotated-1',
            nameIv: 'rotated-iv-1',
            nameTag: 'rotated-tag-1',
            encryptedData: 'rotated-data-1',
            dataIv: 'rotated-data-iv-1',
            dataTag: 'rotated-data-tag-1',
          },
          {
            id: fakeItemId, // This will fail (not found)
            encryptedName: 'rotated-2',
            nameIv: 'rotated-iv-2',
            nameTag: 'rotated-tag-2',
            encryptedData: 'rotated-data-2',
            dataIv: 'rotated-data-iv-2',
            dataTag: 'rotated-data-tag-2',
          },
        ],
        folders: [],
        newEncryptedVaultKey: 'should-not-be-applied',
        newVaultKeyIv: 'should-not-be-applied-iv',
        newVaultKeyTag: 'should-not-be-applied-tag',
      });

    // The rotation should be aborted with a conflict status
    expect(res.status).toBe(409);
    expect(res.body.success).toBe(false);

    // Verify the vault key was NOT changed
    const updatedUser = await User.findById(user.id);
    expect(updatedUser!.encryptedVaultKey).toBe('test-encrypted-vault-key');
    expect(updatedUser!.vaultKeyIv).toBe('test-vault-key-iv');
    expect(updatedUser!.vaultKeyTag).toBe('test-vault-key-tag');

    // Verify rotation state was cleaned up
    expect(updatedUser!.get('rotationInProgress')).toBeFalsy();
    expect(updatedUser!.get('pendingEncryptedVaultKey')).toBeUndefined();
  });

  it('should NOT update vault key when a folder update fails during rotation', async () => {
    const itemId = await createItemViaApi(user.accessToken);
    const fakeFolderId = new Types.ObjectId().toString();

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
            encryptedName: 'rotated',
            nameIv: 'rotated-iv',
            nameTag: 'rotated-tag',
            encryptedData: 'rotated-data',
            dataIv: 'rotated-data-iv',
            dataTag: 'rotated-data-tag',
          },
        ],
        folders: [
          {
            id: fakeFolderId, // This will fail (not found)
            encryptedName: 'rotated-folder',
            nameIv: 'rotated-folder-iv',
            nameTag: 'rotated-folder-tag',
          },
        ],
        newEncryptedVaultKey: 'should-not-be-applied',
        newVaultKeyIv: 'should-not-be-applied-iv',
        newVaultKeyTag: 'should-not-be-applied-tag',
      });

    expect(res.status).toBe(409);
    expect(res.body.success).toBe(false);

    // Vault key should remain unchanged
    const updatedUser = await User.findById(user.id);
    expect(updatedUser!.encryptedVaultKey).toBe('test-encrypted-vault-key');
  });

  it('should succeed and update vault key when all items and folders update successfully', async () => {
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
            encryptedName: 'rotated',
            nameIv: 'rotated-iv',
            nameTag: 'rotated-tag',
            encryptedData: 'rotated-data',
            dataIv: 'rotated-data-iv',
            dataTag: 'rotated-data-tag',
          },
        ],
        folders: [
          {
            id: folderId,
            encryptedName: 'rotated-folder',
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

    // Vault key should be updated
    const updatedUser = await User.findById(user.id);
    expect(updatedUser!.encryptedVaultKey).toBe('new-vault-key');
    expect(updatedUser!.vaultKeyIv).toBe('new-vault-key-iv');
    expect(updatedUser!.vaultKeyTag).toBe('new-vault-key-tag');
  });
});

// ===========================================================================
//  4.3 - Distributed Backup Deduplication
// ===========================================================================

describe('Distributed backup trigger deduplication', () => {
  let user: TestUser;
  let agent: request.SuperTest<request.Test>;

  beforeEach(async () => {
    agent = request(app) as unknown as request.SuperTest<request.Test>;
    user = await createTestUser();
  });

  // Helper to set up backup for the user
  async function setupBackup() {
    const { csrfToken, csrfCookie } = await getCsrf(agent);
    await agent
      .post('/api/v1/backup/setup')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrfToken)
      .set('Cookie', csrfCookie)
      .send({
        encryptedBWK: 'test-encrypted-bwk-data',
        bwkIv: 'test-bwk-iv-value',
        bwkTag: 'test-bwk-tag-value',
        bwkSalt: 'test-bwk-salt-value',
        authHash: user.rawPassword,
      });
  }

  // NOTE: the "reject a second concurrent trigger via distributed lock" and
  // "release the lock after successful trigger" cases that previously lived
  // here were line-for-line duplicates of backup.test.ts's
  // `POST /api/v1/backup/trigger - concurrent deduplication` block (same
  // JobLock seed, same 409 assertion, same `JobLock.findOne(...) === null`
  // release assertion). They added runtime without incremental signal, so they
  // were removed. The "allow a second trigger after the first completes" case
  // below is unique to this file and is kept.

  it('should allow a second trigger after the first completes', async () => {
    await setupBackup();

    // First trigger
    const { csrfToken: csrf1, csrfCookie: cookie1 } = await getCsrf(agent);
    const res1 = await agent
      .post('/api/v1/backup/trigger')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf1)
      .set('Cookie', cookie1);

    expect(res1.status).toBe(200);

    // Second trigger should succeed since the lock was released
    const { csrfToken: csrf2, csrfCookie: cookie2 } = await getCsrf(agent);
    const res2 = await agent
      .post('/api/v1/backup/trigger')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf2)
      .set('Cookie', cookie2);

    expect(res2.status).toBe(200);
  });
});
