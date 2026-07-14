import { test, expect } from '@playwright/test';
import {
  createAuthenticatedUser,
  authGet,
  authMutate,
  createItem,
  createFolder,
  type AuthenticatedUser,
} from './helpers';

/**
 * Comprehensive backup/restore E2E tests for H-Vault.
 *
 * Covers: backup setup, settings, trigger, download, history, restore
 * (same-account, cross-account, after vault key rotation), backup password
 * change, conflict strategies, edge cases, full round-trip, and isolation.
 *
 * Uses API-level authentication (bypassing client-side PBKDF2). Each test
 * creates its own isolated user(s).
 */

// ─── Shared Fixtures ────────────────────────────────────────────────────────

function backupSetupData(user: AuthenticatedUser) {
  return {
    authHash: user.authHash,
    encryptedBWK: 'e2e-encrypted-bwk-data',
    bwkIv: 'e2e-bwk-iv-value',
    bwkTag: 'e2e-bwk-tag-value',
    bwkSalt: 'e2e-bwk-salt-value',
    bwkEncryptedVaultKey: 'e2e-bwk-enc-vk',
    bwkVaultKeyIv: 'e2e-bwk-vk-iv',
    bwkVaultKeyTag: 'e2e-bwk-vk-tag',
  };
}

/** Sets up backup encryption for a user. Returns the setup response. */
async function setupBackupForUser(
  request: Parameters<typeof authMutate>[0],
  user: AuthenticatedUser,
  overrides: Record<string, unknown> = {},
) {
  const res = await authMutate(request, user, 'post', '/api/v1/backup/setup', {
    ...backupSetupData(user),
    ...overrides,
  });
  expect(res.ok()).toBe(true);
  return res;
}

/** Downloads backup JSON for a user. */
async function downloadBackup(request: Parameters<typeof authGet>[0], user: AuthenticatedUser) {
  const res = await authGet(request, user, '/api/v1/backup/download');
  expect(res.ok()).toBe(true);
  const text = await res.text();
  return JSON.parse(text) as Record<string, unknown>;
}

// ─── 1. Backup Setup ────────────────────────────────────────────────────────

test.describe('Backup Setup', () => {
  test('should setup backup encryption with all required fields', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const res = await authMutate(request, user, 'post', '/api/v1/backup/setup', {
      authHash: user.authHash,
      encryptedBWK: 'e2e-encrypted-bwk-data',
      bwkIv: 'e2e-bwk-iv-value',
      bwkTag: 'e2e-bwk-tag-value',
      bwkSalt: 'e2e-bwk-salt-value',
    });

    expect(res.ok()).toBe(true);
    const body = (await res.json()) as { success: boolean; message: string };
    expect(body.success).toBe(true);
    expect(body.message).toMatch(/configured/i);
  });

  test('should setup backup encryption with optional vault key fields', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const res = await authMutate(
      request,
      user,
      'post',
      '/api/v1/backup/setup',
      backupSetupData(user),
    );

    expect(res.ok()).toBe(true);
    const body = (await res.json()) as { success: boolean };
    expect(body.success).toBe(true);
  });

  test('should reject setup without authHash', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const res = await authMutate(request, user, 'post', '/api/v1/backup/setup', {
      encryptedBWK: 'e2e-encrypted-bwk-data',
      bwkIv: 'e2e-bwk-iv-value',
      bwkTag: 'e2e-bwk-tag-value',
      bwkSalt: 'e2e-bwk-salt-value',
    });

    expect(res.ok()).toBe(false);
    expect(res.status()).toBe(400);
  });

  test('should reject setup with invalid authHash (wrong password)', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const res = await authMutate(request, user, 'post', '/api/v1/backup/setup', {
      ...backupSetupData(user),
      authHash: 'wrong-password-hash',
    });

    expect(res.ok()).toBe(false);
    expect(res.status()).toBe(401);
  });

  test('should reject setup without required encryption fields', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    // Missing encryptedBWK
    const res = await authMutate(request, user, 'post', '/api/v1/backup/setup', {
      authHash: user.authHash,
      bwkIv: 'e2e-bwk-iv-value',
      bwkTag: 'e2e-bwk-tag-value',
      bwkSalt: 'e2e-bwk-salt-value',
    });

    expect(res.ok()).toBe(false);
    expect(res.status()).toBe(400);
  });
});

// ─── 2. Backup Settings ─────────────────────────────────────────────────────

test.describe('Backup Settings', () => {
  test('should update backup settings (enabled, scheduleHour, backupEmails)', async ({
    request,
  }) => {
    const user = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user);

    const res = await authMutate(request, user, 'put', '/api/v1/backup/settings', {
      enabled: true,
      scheduleHour: 3,
      backupEmails: ['backup1@test.local', 'backup2@test.local'],
    });

    expect(res.ok()).toBe(true);
    const body = (await res.json()) as {
      success: boolean;
      data: { enabled: boolean; scheduleHour: number; backupEmails: string[] };
    };
    expect(body.success).toBe(true);
    expect(body.data.enabled).toBe(true);
    expect(body.data.scheduleHour).toBe(3);
    expect(body.data.backupEmails).toEqual(['backup1@test.local', 'backup2@test.local']);
  });

  test('should reject enabling backups without encryption configured', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const res = await authMutate(request, user, 'put', '/api/v1/backup/settings', {
      enabled: true,
    });

    expect(res.ok()).toBe(false);
    expect(res.status()).toBe(400);
    const body = (await res.json()) as { message: string };
    expect(body.message).toMatch(/encryption.*configured/i);
  });

  test('should update backup emails list', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const res = await authMutate(request, user, 'put', '/api/v1/backup/settings', {
      backupEmails: ['a@test.local', 'b@test.local', 'c@test.local'],
    });

    expect(res.ok()).toBe(true);
    const body = (await res.json()) as { data: { backupEmails: string[] } };
    expect(body.data.backupEmails).toHaveLength(3);
  });

  test('should reject more than MAX_BACKUP_EMAILS', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    // MAX_BACKUP_EMAILS = 10; send 11
    const tooManyEmails = Array.from({ length: 11 }, (_, i) => `e${String(i)}@test.local`);

    const res = await authMutate(request, user, 'put', '/api/v1/backup/settings', {
      backupEmails: tooManyEmails,
    });

    expect(res.ok()).toBe(false);
    expect(res.status()).toBe(400);
  });
});

// ─── 3. Backup Trigger ──────────────────────────────────────────────────────

test.describe('Backup Trigger', () => {
  test('should trigger backup with empty vault', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user);

    const res = await authMutate(request, user, 'post', '/api/v1/backup/trigger');

    expect(res.ok()).toBe(true);
    const body = (await res.json()) as {
      success: boolean;
      data: { itemCount: number; fileSizeBytes: number };
    };
    expect(body.success).toBe(true);
    expect(body.data.itemCount).toBe(0);
    expect(body.data.fileSizeBytes).toBeGreaterThan(0);
  });

  test('should trigger backup with items and folders', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user);

    await createItem(request, user, { encryptedName: 'trigger-item-1' });
    await createItem(request, user, { itemType: 'note', encryptedName: 'trigger-item-2' });
    await createFolder(request, user, { encryptedName: 'trigger-folder-1' });

    const res = await authMutate(request, user, 'post', '/api/v1/backup/trigger');

    expect(res.ok()).toBe(true);
    const body = (await res.json()) as {
      success: boolean;
      data: { itemCount: number; fileSizeBytes: number };
    };
    expect(body.data.itemCount).toBe(2);
    expect(body.data.fileSizeBytes).toBeGreaterThan(0);
  });

  test('should reject trigger without encryption configured', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const res = await authMutate(request, user, 'post', '/api/v1/backup/trigger');

    expect(res.ok()).toBe(false);
    expect(res.status()).toBe(400);
    const body = (await res.json()) as { message: string };
    expect(body.message).toMatch(/encryption.*configured/i);
  });
});

// ─── 4. Backup Download ─────────────────────────────────────────────────────

test.describe('Backup Download', () => {
  test('should download backup and verify JSON structure', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user);

    const backup = await downloadBackup(request, user);

    expect(backup.version).toBeDefined();
    expect(backup.exportDate).toBeDefined();
    expect(Array.isArray(backup.items)).toBe(true);
    expect(Array.isArray(backup.folders)).toBe(true);
    expect(backup.encryptedVaultKey).toBeDefined();
    expect(backup.vaultKeyIv).toBeDefined();
    expect(backup.vaultKeyTag).toBeDefined();
    expect(backup.backupEncryption).toBeDefined();
    expect(backup.metadata).toBeDefined();

    const enc = backup.backupEncryption as Record<string, unknown>;
    expect(enc.encryptedBWK).toBe('e2e-encrypted-bwk-data');
    expect(enc.bwkIv).toBe('e2e-bwk-iv-value');
    expect(enc.bwkTag).toBe('e2e-bwk-tag-value');
    expect(enc.bwkSalt).toBe('e2e-bwk-salt-value');
    expect(enc.bwkEncryptedVaultKey).toBe('e2e-bwk-enc-vk');
    expect(enc.bwkVaultKeyIv).toBe('e2e-bwk-vk-iv');
    expect(enc.bwkVaultKeyTag).toBe('e2e-bwk-vk-tag');
  });

  test('should download backup with items and verify all items present', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user);

    await createItem(request, user, { encryptedName: 'dl-item-1', itemType: 'login' });
    await createItem(request, user, { encryptedName: 'dl-item-2', itemType: 'secret' });
    await createItem(request, user, { encryptedName: 'dl-item-3', itemType: 'note' });

    const backup = await downloadBackup(request, user);
    const items = backup.items as { encryptedName: string; itemType: string }[];

    expect(items).toHaveLength(3);
    const names = items.map((i) => i.encryptedName);
    expect(names).toContain('dl-item-1');
    expect(names).toContain('dl-item-2');
    expect(names).toContain('dl-item-3');
  });

  test('should download backup with folders and verify all folders present', async ({
    request,
  }) => {
    const user = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user);

    await createFolder(request, user, { encryptedName: 'dl-folder-1' });
    await createFolder(request, user, { encryptedName: 'dl-folder-2' });

    const backup = await downloadBackup(request, user);
    const folders = backup.folders as { encryptedName: string }[];

    expect(folders).toHaveLength(2);
    const names = folders.map((f) => f.encryptedName);
    expect(names).toContain('dl-folder-1');
    expect(names).toContain('dl-folder-2');
  });

  test('should reject download without encryption configured', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const res = await authGet(request, user, '/api/v1/backup/download');

    expect(res.ok()).toBe(false);
    expect(res.status()).toBe(400);
  });
});

// ─── 5. Backup History ──────────────────────────────────────────────────────

test.describe('Backup History', () => {
  test('should get backup history after trigger', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user);
    await authMutate(request, user, 'post', '/api/v1/backup/trigger');

    const res = await authGet(request, user, '/api/v1/backup/history');

    expect(res.ok()).toBe(true);
    const body = (await res.json()) as {
      success: boolean;
      data: { status: string; itemCount: number; fileSizeBytes: number }[];
      pagination: { total: number; page: number };
    };
    expect(body.success).toBe(true);
    expect(body.pagination.total).toBeGreaterThanOrEqual(1);
    expect(body.data[0]!.status).toBe('success');
    expect(typeof body.data[0]!.itemCount).toBe('number');
    expect(typeof body.data[0]!.fileSizeBytes).toBe('number');
  });

  test('should verify history pagination', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user);

    // Trigger multiple backups
    await authMutate(request, user, 'post', '/api/v1/backup/trigger');
    await authMutate(request, user, 'post', '/api/v1/backup/trigger');
    await authMutate(request, user, 'post', '/api/v1/backup/trigger');

    const res = await authGet(request, user, '/api/v1/backup/history?page=1&limit=2');
    expect(res.ok()).toBe(true);

    const body = (await res.json()) as {
      data: unknown[];
      pagination: { total: number; totalPages: number; page: number; limit: number };
    };
    expect(body.data).toHaveLength(2);
    expect(body.pagination.total).toBe(3);
    expect(body.pagination.totalPages).toBe(2);
    expect(body.pagination.page).toBe(1);

    // Page 2
    const res2 = await authGet(request, user, '/api/v1/backup/history?page=2&limit=2');
    const body2 = (await res2.json()) as { data: unknown[] };
    expect(body2.data).toHaveLength(1);
  });
});

// ─── 6. Restore - Same Account ──────────────────────────────────────────────

test.describe('Restore - Same Account', () => {
  test('should restore deleted items with skip strategy', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user);

    // Create items and download backup
    const id1 = await createItem(request, user, { encryptedName: 'restore-skip-1' });
    const id2 = await createItem(request, user, { encryptedName: 'restore-skip-2' });
    const backup = await downloadBackup(request, user);

    // Permanently delete both items (soft delete, then permanent)
    await authMutate(request, user, 'delete', `/api/v1/vault/items/${id1}`);
    await authMutate(request, user, 'delete', `/api/v1/vault/items/${id1}/permanent`);
    await authMutate(request, user, 'delete', `/api/v1/vault/items/${id2}`);
    await authMutate(request, user, 'delete', `/api/v1/vault/items/${id2}/permanent`);

    // Verify vault is empty
    const emptyList = await authGet(request, user, '/api/v1/vault/items');
    const emptyBody = (await emptyList.json()) as { pagination: { total: number } };
    expect(emptyBody.pagination.total).toBe(0);

    // Restore with skip strategy
    const restoreRes = await authMutate(request, user, 'post', '/api/v1/backup/restore', {
      conflictStrategy: 'skip',
      data: JSON.stringify(backup),
    });

    expect(restoreRes.ok()).toBe(true);
    const restoreBody = (await restoreRes.json()) as {
      success: boolean;
      data: { itemsRestored: number; itemsSkipped: number };
    };
    expect(restoreBody.data.itemsRestored).toBe(2);
    expect(restoreBody.data.itemsSkipped).toBe(0);

    // Verify items are back
    const listRes = await authGet(request, user, '/api/v1/vault/items');
    const listBody = (await listRes.json()) as { pagination: { total: number } };
    expect(listBody.pagination.total).toBe(2);
  });

  test('should restore with keep_both strategy and duplicate items', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user);

    await createItem(request, user, { encryptedName: 'keep-both-item' });
    const backup = await downloadBackup(request, user);

    // Items still exist -- restore with keep_both should create duplicates
    const restoreRes = await authMutate(request, user, 'post', '/api/v1/backup/restore', {
      conflictStrategy: 'keep_both',
      data: JSON.stringify(backup),
    });

    expect(restoreRes.ok()).toBe(true);
    const restoreBody = (await restoreRes.json()) as {
      data: { itemsRestored: number };
    };
    expect(restoreBody.data.itemsRestored).toBe(1);

    // Verify items doubled
    const listRes = await authGet(request, user, '/api/v1/vault/items');
    const listBody = (await listRes.json()) as { pagination: { total: number } };
    expect(listBody.pagination.total).toBe(2);
  });

  test('should restore with overwrite strategy and replace items', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user);

    const itemId = await createItem(request, user, { encryptedName: 'original-name' });
    const backup = await downloadBackup(request, user);

    // Modify the item
    await authMutate(request, user, 'put', `/api/v1/vault/items/${itemId}`, {
      encryptedName: 'modified-name',
      nameIv: 'mod-iv',
      nameTag: 'mod-tag',
    });

    // Verify modification
    const modRes = await authGet(request, user, `/api/v1/vault/items/${itemId}`);
    const modBody = (await modRes.json()) as { data: { encryptedName: string } };
    expect(modBody.data.encryptedName).toBe('modified-name');

    // Restore with overwrite — should restore original name
    const restoreRes = await authMutate(request, user, 'post', '/api/v1/backup/restore', {
      conflictStrategy: 'overwrite',
      data: JSON.stringify(backup),
    });

    expect(restoreRes.ok()).toBe(true);
    const restoreBody = (await restoreRes.json()) as {
      data: { itemsRestored: number; itemsSkipped: number };
    };
    expect(restoreBody.data.itemsRestored).toBe(1);

    // Verify original data restored
    const verifyRes = await authGet(request, user, `/api/v1/vault/items/${itemId}`);
    const verifyBody = (await verifyRes.json()) as { data: { encryptedName: string } };
    expect(verifyBody.data.encryptedName).toBe('original-name');
  });

  test('should restore with items AND folders, preserving folder references', async ({
    request,
  }) => {
    const user = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user);

    const folderId = await createFolder(request, user, { encryptedName: 'restore-folder' });
    await createItem(request, user, { encryptedName: 'folder-item', folderId });

    const backup = await downloadBackup(request, user);

    // Delete everything permanently
    const listRes = await authGet(request, user, '/api/v1/vault/items');
    const items = (await listRes.json()) as { data: { _id: string }[] };
    for (const item of items.data) {
      await authMutate(request, user, 'delete', `/api/v1/vault/items/${item._id}`);
      await authMutate(request, user, 'delete', `/api/v1/vault/items/${item._id}/permanent`);
    }
    await authMutate(request, user, 'delete', `/api/v1/folders/${folderId}?action=delete`);

    // Restore
    const restoreRes = await authMutate(request, user, 'post', '/api/v1/backup/restore', {
      conflictStrategy: 'skip',
      data: JSON.stringify(backup),
    });

    expect(restoreRes.ok()).toBe(true);
    const restoreBody = (await restoreRes.json()) as {
      data: {
        itemsRestored: number;
        foldersRestored: number;
      };
    };
    expect(restoreBody.data.itemsRestored).toBe(1);
    expect(restoreBody.data.foldersRestored).toBe(1);

    // Verify folder references are maintained. The folder was permanently
    // deleted before the restore, so it is re-created with a FRESH server-minted
    // id and the item's folderId is remapped to it — the relationship is
    // preserved even though the literal id differs from the pre-delete one.
    const verifyFolders = await authGet(request, user, '/api/v1/folders');
    const foldersBody = (await verifyFolders.json()) as {
      data: { _id: string; encryptedName: string }[];
    };
    expect(foldersBody.data).toHaveLength(1);
    const newFolderId = foldersBody.data[0]!._id;
    const verifyItems = await authGet(request, user, '/api/v1/vault/items');
    const verifyBody = (await verifyItems.json()) as { data: { folderId: string }[] };
    expect(verifyBody.data[0]!.folderId).toBe(newFolderId);
  });
});

// ─── 7. Restore - Cross Account ─────────────────────────────────────────────

test.describe('Restore - Cross Account', () => {
  test('should restore User1 backup to User2 (cross-account)', async ({ request }) => {
    const user1 = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user1);

    await createItem(request, user1, { encryptedName: 'cross-item-1', itemType: 'login' });
    await createItem(request, user1, { encryptedName: 'cross-item-2', itemType: 'secret' });

    const backup = await downloadBackup(request, user1);

    // User2 restores the backup
    const user2 = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user2);

    const restoreRes = await authMutate(request, user2, 'post', '/api/v1/backup/restore', {
      conflictStrategy: 'skip',
      data: JSON.stringify(backup),
    });

    expect(restoreRes.ok()).toBe(true);
    const restoreBody = (await restoreRes.json()) as {
      data: { itemsRestored: number };
    };
    expect(restoreBody.data.itemsRestored).toBe(2);

    // Verify items in User2's vault
    const listRes = await authGet(request, user2, '/api/v1/vault/items');
    const listBody = (await listRes.json()) as {
      data: { encryptedName: string; itemType: string }[];
      pagination: { total: number };
    };
    expect(listBody.pagination.total).toBe(2);
    const names = listBody.data.map((i) => i.encryptedName);
    expect(names).toContain('cross-item-1');
    expect(names).toContain('cross-item-2');

    // Cross-user isolation: User1's vault is untouched by User2's restore.
    const user1List = await authGet(request, user1, '/api/v1/vault/items');
    const user1Body = (await user1List.json()) as { pagination: { total: number } };
    expect(user1Body.pagination.total).toBe(2);
  });

  test('should cross-account restore with different authHash', async ({ request }) => {
    const user1 = await createAuthenticatedUser(request, { authHash: 'user1-unique-auth-hash' });
    await setupBackupForUser(request, user1);
    await createItem(request, user1, { encryptedName: 'diff-pw-item' });

    const backup = await downloadBackup(request, user1);

    const user2 = await createAuthenticatedUser(request, { authHash: 'user2-different-hash' });
    await setupBackupForUser(request, user2);

    const restoreRes = await authMutate(request, user2, 'post', '/api/v1/backup/restore', {
      conflictStrategy: 'skip',
      data: JSON.stringify(backup),
    });

    expect(restoreRes.ok()).toBe(true);
    const body = (await restoreRes.json()) as { data: { itemsRestored: number } };
    expect(body.data.itemsRestored).toBe(1);
  });

  test('should cross-account restore preserving item types', async ({ request }) => {
    const user1 = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user1);

    // Create one of each type
    const types = ['login', 'secret', 'note', 'card', 'identity'] as const;
    for (const t of types) {
      await createItem(request, user1, { itemType: t, encryptedName: `type-${t}` });
    }

    const backup = await downloadBackup(request, user1);

    const user2 = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user2);

    const restoreRes = await authMutate(request, user2, 'post', '/api/v1/backup/restore', {
      conflictStrategy: 'skip',
      data: JSON.stringify(backup),
    });

    expect(restoreRes.ok()).toBe(true);
    const body = (await restoreRes.json()) as { data: { itemsRestored: number } };
    expect(body.data.itemsRestored).toBe(5);

    // Verify each type
    const listRes = await authGet(request, user2, '/api/v1/vault/items');
    const listBody = (await listRes.json()) as { data: { itemType: string }[] };
    const restoredTypes = listBody.data.map((i) => i.itemType).sort();
    expect(restoredTypes).toEqual([...types].sort());
  });

  test('should cross-account restore with folders and remap references', async ({ request }) => {
    const user1 = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user1);

    const folderId = await createFolder(request, user1, { encryptedName: 'cross-folder' });
    await createItem(request, user1, { encryptedName: 'cross-folder-item', folderId });

    const backup = await downloadBackup(request, user1);

    const user2 = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user2);

    const restoreRes = await authMutate(request, user2, 'post', '/api/v1/backup/restore', {
      conflictStrategy: 'skip',
      data: JSON.stringify(backup),
    });

    expect(restoreRes.ok()).toBe(true);
    const restoreBody = (await restoreRes.json()) as {
      data: { itemsRestored: number; foldersRestored: number };
    };
    expect(restoreBody.data.itemsRestored).toBe(1);
    expect(restoreBody.data.foldersRestored).toBe(1);

    // Verify folder and item exist in user2's vault
    const foldersRes = await authGet(request, user2, '/api/v1/folders');
    const foldersBody = (await foldersRes.json()) as {
      data: { _id: string; encryptedName: string }[];
    };
    expect(foldersBody.data).toHaveLength(1);
    expect(foldersBody.data[0]!.encryptedName).toBe('cross-folder');
    const newFolderId = foldersBody.data[0]!._id;

    const itemsRes = await authGet(request, user2, '/api/v1/vault/items');
    const itemsBody = (await itemsRes.json()) as {
      data: { encryptedName: string; folderId?: string }[];
    };
    // With _ids intact the server mints a fresh folder id and REMAPS the item's
    // folderId to it — the reference is preserved, not dropped.
    expect(itemsBody.data).toHaveLength(1);
    expect(itemsBody.data[0]!.encryptedName).toBe('cross-folder-item');
    expect(itemsBody.data[0]!.folderId).toBe(newFolderId);
  });

  test('should restore the same cross-account backup twice with skip without duplication', async ({
    request,
  }) => {
    const user1 = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user1);

    await createItem(request, user1, { encryptedName: 'idem-item-1', itemType: 'login' });
    await createItem(request, user1, { encryptedName: 'idem-item-2', itemType: 'secret' });
    await createFolder(request, user1, { encryptedName: 'idem-folder' });

    const backup = await downloadBackup(request, user1);

    const user2 = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user2);

    // First restore mints fresh ids stamped with sourceRefId.
    const first = await authMutate(request, user2, 'post', '/api/v1/backup/restore', {
      conflictStrategy: 'skip',
      data: JSON.stringify(backup),
    });
    expect(first.ok()).toBe(true);
    const firstBody = (await first.json()) as {
      data: { itemsRestored: number; foldersRestored: number };
    };
    expect(firstBody.data.itemsRestored).toBe(2);
    expect(firstBody.data.foldersRestored).toBe(1);

    const afterFirstItems = await authGet(request, user2, '/api/v1/vault/items');
    expect(
      ((await afterFirstItems.json()) as { pagination: { total: number } }).pagination.total,
    ).toBe(2);
    const afterFirstFolders = await authGet(request, user2, '/api/v1/folders');
    expect(((await afterFirstFolders.json()) as { data: unknown[] }).data).toHaveLength(1);

    // Second restore of the SAME backup matches the prior rows by
    // (userId, sourceRefId) → everything is skipped, nothing duplicated.
    const second = await authMutate(request, user2, 'post', '/api/v1/backup/restore', {
      conflictStrategy: 'skip',
      data: JSON.stringify(backup),
    });
    expect(second.ok()).toBe(true);
    const secondBody = (await second.json()) as {
      data: {
        itemsRestored: number;
        foldersRestored: number;
        itemsSkipped: number;
        foldersSkipped: number;
      };
    };
    expect(secondBody.data.itemsRestored).toBe(0);
    expect(secondBody.data.foldersRestored).toBe(0);
    expect(secondBody.data.itemsSkipped).toBe(2);
    expect(secondBody.data.foldersSkipped).toBe(1);

    // No duplication — counts are unchanged after the repeat restore.
    const finalItems = await authGet(request, user2, '/api/v1/vault/items');
    const finalItemsBody = (await finalItems.json()) as {
      data: { encryptedName: string }[];
      pagination: { total: number };
    };
    expect(finalItemsBody.pagination.total).toBe(2);
    expect(finalItemsBody.data.map((i) => i.encryptedName).sort()).toEqual([
      'idem-item-1',
      'idem-item-2',
    ]);

    const finalFolders = await authGet(request, user2, '/api/v1/folders');
    const finalFoldersBody = (await finalFolders.json()) as { data: { encryptedName: string }[] };
    expect(finalFoldersBody.data).toHaveLength(1);
    expect(finalFoldersBody.data[0]!.encryptedName).toBe('idem-folder');

    // Cross-user isolation: User1 still has exactly their originals.
    const user1Items = await authGet(request, user1, '/api/v1/vault/items');
    expect(((await user1Items.json()) as { pagination: { total: number } }).pagination.total).toBe(
      2,
    );
  });
});

// ─── 8. Restore - After Vault Key Rotation ──────────────────────────────────

test.describe('Restore - After Vault Key Rotation', () => {
  test('should backup after vault key rotation and restore to new user', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user);

    // Create items and a folder
    const itemId = await createItem(request, user, { encryptedName: 'pre-rotation-item' });
    const folderId = await createFolder(request, user, { encryptedName: 'pre-rotation-folder' });

    // Simulate vault key rotation via bulk-reencrypt
    const rotateRes = await authMutate(
      request,
      user,
      'post',
      '/api/v1/vault/items/bulk-reencrypt',
      {
        authHash: user.authHash,
        items: [
          {
            id: itemId,
            encryptedName: 'rotated-item-name',
            nameIv: 'rotated-name-iv',
            nameTag: 'rotated-name-tag',
            encryptedData: 'rotated-encrypted-data',
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
        newEncryptedVaultKey: 'new-rotated-vault-key',
        newVaultKeyIv: 'new-rotated-vk-iv',
        newVaultKeyTag: 'new-rotated-vk-tag',
      },
    );
    expect(rotateRes.ok()).toBe(true);

    // Download backup after rotation - should contain new vault key
    const backup = await downloadBackup(request, user);
    expect(backup.encryptedVaultKey).toBe('new-rotated-vault-key');
    expect(backup.vaultKeyIv).toBe('new-rotated-vk-iv');
    expect(backup.vaultKeyTag).toBe('new-rotated-vk-tag');

    // Verify the backup contains the rotated item data
    const backupItems = backup.items as { encryptedName: string }[];
    expect(backupItems[0]!.encryptedName).toBe('rotated-item-name');

    // New user restores the post-rotation backup
    const user2 = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user2);

    const restoreRes = await authMutate(request, user2, 'post', '/api/v1/backup/restore', {
      conflictStrategy: 'skip',
      data: JSON.stringify(backup),
    });

    expect(restoreRes.ok()).toBe(true);
    const restoreBody = (await restoreRes.json()) as {
      data: { itemsRestored: number; foldersRestored: number };
    };
    expect(restoreBody.data.itemsRestored).toBe(1);
    expect(restoreBody.data.foldersRestored).toBe(1);

    // Verify user2 has the rotated items
    const listRes = await authGet(request, user2, '/api/v1/vault/items');
    const listBody = (await listRes.json()) as { data: { encryptedName: string }[] };
    expect(listBody.data[0]!.encryptedName).toBe('rotated-item-name');
  });
});

// ─── 9. Backup Password Change ──────────────────────────────────────────────

test.describe('Backup Password Change', () => {
  test('should change backup password and verify new encryption metadata', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user);

    const changeRes = await authMutate(request, user, 'put', '/api/v1/backup/change-password', {
      password: user.authHash,
      newEncryptedBWK: 'new-encrypted-bwk-after-change',
      newBwkIv: 'new-bwk-iv-after-change',
      newBwkTag: 'new-bwk-tag-after-change',
      newBwkSalt: 'new-bwk-salt-after-change',
      newBwkEncryptedVaultKey: 'new-bwk-vk-after-change',
      newBwkVaultKeyIv: 'new-bwk-vk-iv-change',
      newBwkVaultKeyTag: 'new-bwk-vk-tag-change',
    });

    expect(changeRes.ok()).toBe(true);
    const body = (await changeRes.json()) as { success: boolean; message: string };
    expect(body.success).toBe(true);
    expect(body.message).toMatch(/changed/i);

    // Download and verify new encryption metadata
    const backup = await downloadBackup(request, user);
    const enc = backup.backupEncryption as Record<string, unknown>;
    expect(enc.encryptedBWK).toBe('new-encrypted-bwk-after-change');
    expect(enc.bwkIv).toBe('new-bwk-iv-after-change');
    expect(enc.bwkTag).toBe('new-bwk-tag-after-change');
    expect(enc.bwkSalt).toBe('new-bwk-salt-after-change');
  });

  test('should reject change with wrong current password', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user);

    const res = await authMutate(request, user, 'put', '/api/v1/backup/change-password', {
      password: 'wrong-password',
      newEncryptedBWK: 'new-bwk',
      newBwkIv: 'new-iv',
      newBwkTag: 'new-tag',
      newBwkSalt: 'new-salt',
    });

    expect(res.ok()).toBe(false);
    expect(res.status()).toBe(401);
  });

  test('should preserve backup functionality after password change', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user);

    // Change password
    await authMutate(request, user, 'put', '/api/v1/backup/change-password', {
      password: user.authHash,
      newEncryptedBWK: 'changed-bwk',
      newBwkIv: 'changed-iv',
      newBwkTag: 'changed-tag',
      newBwkSalt: 'changed-salt',
    });

    // Trigger should still work
    const triggerRes = await authMutate(request, user, 'post', '/api/v1/backup/trigger');
    expect(triggerRes.ok()).toBe(true);

    // Download should still work
    const backup = await downloadBackup(request, user);
    expect(backup.version).toBeDefined();
    expect(backup.items).toBeDefined();
  });
});

// ─── 10. Restore Conflict Strategies ────────────────────────────────────────

test.describe('Restore Conflict Strategies', () => {
  test('skip: should preserve existing items and add only new ones', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user);

    const existingId = await createItem(request, user, { encryptedName: 'existing-item' });
    const backup = await downloadBackup(request, user);

    // Modify the existing item so we can verify skip preserved it
    await authMutate(request, user, 'put', `/api/v1/vault/items/${existingId}`, {
      encryptedName: 'modified-existing',
      nameIv: 'mod-iv',
      nameTag: 'mod-tag',
    });

    const restoreRes = await authMutate(request, user, 'post', '/api/v1/backup/restore', {
      conflictStrategy: 'skip',
      data: JSON.stringify(backup),
    });

    expect(restoreRes.ok()).toBe(true);
    const body = (await restoreRes.json()) as {
      data: {
        itemsSkipped: number;
        itemsRestored: number;
        itemSkipReasons: { itemId: string; reason: string }[];
      };
    };
    expect(body.data.itemsSkipped).toBe(1);
    expect(body.data.itemsRestored).toBe(0);
    expect(body.data.itemSkipReasons).toHaveLength(1);
    expect(body.data.itemSkipReasons[0]!.reason).toBe('conflict_skipped');

    // Verify the modified name was preserved (not overwritten)
    const getRes = await authGet(request, user, `/api/v1/vault/items/${existingId}`);
    const getBody = (await getRes.json()) as { data: { encryptedName: string } };
    expect(getBody.data.encryptedName).toBe('modified-existing');
  });

  test('overwrite: should replace existing items with backup data', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user);

    const itemId = await createItem(request, user, { encryptedName: 'overwrite-original' });
    const backup = await downloadBackup(request, user);

    // Modify
    await authMutate(request, user, 'put', `/api/v1/vault/items/${itemId}`, {
      encryptedName: 'overwrite-modified',
      nameIv: 'mod-iv',
      nameTag: 'mod-tag',
    });

    const restoreRes = await authMutate(request, user, 'post', '/api/v1/backup/restore', {
      conflictStrategy: 'overwrite',
      data: JSON.stringify(backup),
    });

    expect(restoreRes.ok()).toBe(true);
    const body = (await restoreRes.json()) as {
      data: { itemsRestored: number; itemsSkipped: number };
    };
    expect(body.data.itemsRestored).toBe(1);
    expect(body.data.itemsSkipped).toBe(0);

    // Verify original data restored
    const getRes = await authGet(request, user, `/api/v1/vault/items/${itemId}`);
    const getBody = (await getRes.json()) as { data: { encryptedName: string } };
    expect(getBody.data.encryptedName).toBe('overwrite-original');
  });

  test('keep_both: should keep all items including duplicates', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user);

    await createItem(request, user, { encryptedName: 'duplicate-item' });
    const backup = await downloadBackup(request, user);

    const restoreRes = await authMutate(request, user, 'post', '/api/v1/backup/restore', {
      conflictStrategy: 'keep_both',
      data: JSON.stringify(backup),
    });

    expect(restoreRes.ok()).toBe(true);
    const body = (await restoreRes.json()) as {
      data: { itemsRestored: number; itemsSkipped: number };
    };
    expect(body.data.itemsRestored).toBe(1);
    expect(body.data.itemsSkipped).toBe(0);

    // Two items should exist now
    const listRes = await authGet(request, user, '/api/v1/vault/items');
    const listBody = (await listRes.json()) as { pagination: { total: number } };
    expect(listBody.pagination.total).toBe(2);
  });

  test('skip: should verify folderSkipReasons in response', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user);

    await createFolder(request, user, { encryptedName: 'existing-folder' });
    const backup = await downloadBackup(request, user);

    const restoreRes = await authMutate(request, user, 'post', '/api/v1/backup/restore', {
      conflictStrategy: 'skip',
      data: JSON.stringify(backup),
    });

    expect(restoreRes.ok()).toBe(true);
    const body = (await restoreRes.json()) as {
      data: {
        foldersSkipped: number;
        folderSkipReasons: { folderId: string; reason: string }[];
      };
    };
    expect(body.data.foldersSkipped).toBe(1);
    expect(body.data.folderSkipReasons).toHaveLength(1);
    expect(body.data.folderSkipReasons[0]!.reason).toBe('conflict_skipped');
  });
});

// ─── 11. Restore Edge Cases ─────────────────────────────────────────────────

test.describe('Restore Edge Cases', () => {
  test('should restore with empty backup (no items, no folders)', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user);

    const emptyBackup = { items: [], folders: [] };

    const restoreRes = await authMutate(request, user, 'post', '/api/v1/backup/restore', {
      conflictStrategy: 'skip',
      data: JSON.stringify(emptyBackup),
    });

    expect(restoreRes.ok()).toBe(true);
    const body = (await restoreRes.json()) as {
      data: {
        itemsRestored: number;
        itemsSkipped: number;
        foldersRestored: number;
        foldersSkipped: number;
      };
    };
    expect(body.data.itemsRestored).toBe(0);
    expect(body.data.itemsSkipped).toBe(0);
    expect(body.data.foldersRestored).toBe(0);
    expect(body.data.foldersSkipped).toBe(0);
  });

  test('should skip items with invalid item types and report reason', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const backupWithBadType = {
      items: [
        {
          _id: '507f1f77bcf86cd799439011',
          itemType: 'invalid_type',
          encryptedData: 'data',
          dataIv: 'iv',
          dataTag: 'tag',
          encryptedName: 'name',
          nameIv: 'niv',
          nameTag: 'ntag',
          userId: 'some-user-id',
        },
      ],
      folders: [],
    };

    const restoreRes = await authMutate(request, user, 'post', '/api/v1/backup/restore', {
      conflictStrategy: 'skip',
      data: JSON.stringify(backupWithBadType),
    });

    expect(restoreRes.ok()).toBe(true);
    const body = (await restoreRes.json()) as {
      data: {
        itemsSkipped: number;
        itemsRestored: number;
        itemSkipReasons: { itemId: string; reason: string }[];
      };
    };
    expect(body.data.itemsSkipped).toBe(1);
    expect(body.data.itemsRestored).toBe(0);
    expect(body.data.itemSkipReasons[0]!.reason).toBe('invalid_item_type');
  });

  test('should skip items with missing encryption fields and report reason', async ({
    request,
  }) => {
    const user = await createAuthenticatedUser(request);

    const backupWithMissingFields = {
      items: [
        {
          _id: '507f1f77bcf86cd799439012',
          itemType: 'login',
          encryptedData: 'data',
          dataIv: 'iv',
          dataTag: 'tag',
          // Missing encryptedName, nameIv, nameTag
          userId: 'some-user-id',
        },
      ],
      folders: [],
    };

    const restoreRes = await authMutate(request, user, 'post', '/api/v1/backup/restore', {
      conflictStrategy: 'skip',
      data: JSON.stringify(backupWithMissingFields),
    });

    expect(restoreRes.ok()).toBe(true);
    const body = (await restoreRes.json()) as {
      data: {
        itemsSkipped: number;
        itemSkipReasons: { itemId: string; reason: string }[];
      };
    };
    expect(body.data.itemsSkipped).toBe(1);
    expect(body.data.itemSkipReasons[0]!.reason).toBe('missing_encryption_fields');
  });

  test('should restore trashed items (clear deletedAt)', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user);

    const itemId = await createItem(request, user, { encryptedName: 'will-trash-then-restore' });

    // Soft-delete to put in trash
    await authMutate(request, user, 'delete', `/api/v1/vault/items/${itemId}`);

    // Verify it is in trash
    const trashRes = await authGet(request, user, '/api/v1/vault/items/trash');
    const trashBody = (await trashRes.json()) as { data: { _id: string }[] };
    expect(trashBody.data.some((i) => i._id === itemId)).toBe(true);

    // Download backup that includes the non-trashed version (backup does NOT include trashed)
    // Instead, create a backup payload with the item to restore over the trashed one
    const backupPayload = {
      items: [
        {
          _id: itemId,
          itemType: 'login',
          encryptedData: 'restored-data',
          dataIv: 'restored-iv',
          dataTag: 'restored-tag',
          encryptedName: 'restored-from-trash',
          nameIv: 'r-niv',
          nameTag: 'r-ntag',
          tags: [],
          favorite: false,
        },
      ],
      folders: [],
    };

    const restoreRes = await authMutate(request, user, 'post', '/api/v1/backup/restore', {
      conflictStrategy: 'skip',
      data: JSON.stringify(backupPayload),
    });

    expect(restoreRes.ok()).toBe(true);
    const body = (await restoreRes.json()) as {
      data: { itemsRestored: number };
    };
    // Trashed items should be restored (not skipped)
    expect(body.data.itemsRestored).toBe(1);

    // Verify the item is no longer in trash and is in the active list
    const activeRes = await authGet(request, user, '/api/v1/vault/items');
    const activeBody = (await activeRes.json()) as { data: { _id: string }[] };
    expect(activeBody.data.some((i) => i._id === itemId)).toBe(true);

    const trashRes2 = await authGet(request, user, '/api/v1/vault/items/trash');
    const trashBody2 = (await trashRes2.json()) as { data: { _id: string }[] };
    expect(trashBody2.data.some((i) => i._id === itemId)).toBe(false);
  });
});

// ─── 12. Full Round-Trip ────────────────────────────────────────────────────

test.describe('Full Round-Trip', () => {
  test('should complete full backup/restore cycle across two users', async ({ request }) => {
    // User1: create items + folders, setup backup, trigger, download
    const user1 = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user1);

    const folderId1 = await createFolder(request, user1, { encryptedName: 'rt-folder-1' });
    const folderId2 = await createFolder(request, user1, { encryptedName: 'rt-folder-2' });
    await createItem(request, user1, {
      encryptedName: 'rt-login',
      itemType: 'login',
      folderId: folderId1,
    });
    await createItem(request, user1, {
      encryptedName: 'rt-note',
      itemType: 'note',
      folderId: folderId1,
    });
    await createItem(request, user1, {
      encryptedName: 'rt-secret',
      itemType: 'secret',
      folderId: folderId2,
    });
    await createItem(request, user1, {
      encryptedName: 'rt-card',
      itemType: 'card',
    });
    await createItem(request, user1, {
      encryptedName: 'rt-identity',
      itemType: 'identity',
    });

    // Trigger backup
    const triggerRes = await authMutate(request, user1, 'post', '/api/v1/backup/trigger');
    expect(triggerRes.ok()).toBe(true);
    const triggerBody = (await triggerRes.json()) as {
      data: { itemCount: number };
    };
    expect(triggerBody.data.itemCount).toBe(5);

    // Download backup
    const backup = await downloadBackup(request, user1);
    expect((backup.items as unknown[]).length).toBe(5);
    expect((backup.folders as unknown[]).length).toBe(2);
    expect((backup.metadata as { itemCount: number }).itemCount).toBe(5);
    expect((backup.metadata as { folderCount: number }).folderCount).toBe(2);

    // User2: restore User1's backup with _ids intact — the server mints fresh
    // _ids for the non-owned rows (the real client sends ids verbatim).
    const user2 = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user2);

    const restoreRes = await authMutate(request, user2, 'post', '/api/v1/backup/restore', {
      conflictStrategy: 'skip',
      data: JSON.stringify(backup),
    });

    expect(restoreRes.ok()).toBe(true);
    const restoreBody = (await restoreRes.json()) as {
      data: {
        itemsRestored: number;
        foldersRestored: number;
        itemsSkipped: number;
        foldersSkipped: number;
      };
    };
    expect(restoreBody.data.itemsRestored).toBe(5);
    expect(restoreBody.data.foldersRestored).toBe(2);
    expect(restoreBody.data.itemsSkipped).toBe(0);
    expect(restoreBody.data.foldersSkipped).toBe(0);

    // Verify all items and folders in User2's vault
    const user2Items = await authGet(request, user2, '/api/v1/vault/items');
    const user2ItemsBody = (await user2Items.json()) as {
      data: { encryptedName: string; itemType: string }[];
      pagination: { total: number };
    };
    expect(user2ItemsBody.pagination.total).toBe(5);

    const itemTypes = user2ItemsBody.data.map((i) => i.itemType).sort();
    expect(itemTypes).toEqual(['card', 'identity', 'login', 'note', 'secret']);

    const itemNames = user2ItemsBody.data.map((i) => i.encryptedName).sort();
    expect(itemNames).toEqual(
      ['rt-card', 'rt-identity', 'rt-login', 'rt-note', 'rt-secret'].sort(),
    );

    const user2Folders = await authGet(request, user2, '/api/v1/folders');
    const user2FoldersBody = (await user2Folders.json()) as {
      data: { encryptedName: string }[];
    };
    expect(user2FoldersBody.data).toHaveLength(2);
    const folderNames = user2FoldersBody.data.map((f) => f.encryptedName).sort();
    expect(folderNames).toEqual(['rt-folder-1', 'rt-folder-2']);

    // User2: trigger their own backup, download, verify it matches
    const user2TriggerRes = await authMutate(request, user2, 'post', '/api/v1/backup/trigger');
    expect(user2TriggerRes.ok()).toBe(true);

    const user2Backup = await downloadBackup(request, user2);
    expect((user2Backup.items as unknown[]).length).toBe(5);
    expect((user2Backup.folders as unknown[]).length).toBe(2);
  });
});

// ─── 13. Backup Isolation ───────────────────────────────────────────────────

test.describe('Backup Isolation', () => {
  test('should not include other user items in backup download', async ({ request }) => {
    const user1 = await createAuthenticatedUser(request);
    const user2 = await createAuthenticatedUser(request);

    await setupBackupForUser(request, user1);
    await setupBackupForUser(request, user2);

    // User1 creates items
    await createItem(request, user1, { encryptedName: 'user1-secret-item' });
    await createItem(request, user1, { encryptedName: 'user1-another-item' });
    await createFolder(request, user1, { encryptedName: 'user1-folder' });

    // User2 creates their own items
    await createItem(request, user2, { encryptedName: 'user2-item' });

    // Download both backups
    const backup1 = await downloadBackup(request, user1);
    const backup2 = await downloadBackup(request, user2);

    // User1's backup should have 2 items, 1 folder
    const items1 = backup1.items as { encryptedName: string }[];
    expect(items1).toHaveLength(2);
    expect(items1.every((i) => i.encryptedName.startsWith('user1-'))).toBe(true);

    const folders1 = backup1.folders as { encryptedName: string }[];
    expect(folders1).toHaveLength(1);

    // User2's backup should have 1 item, 0 folders
    const items2 = backup2.items as { encryptedName: string }[];
    expect(items2).toHaveLength(1);
    expect(items2[0]!.encryptedName).toBe('user2-item');

    const folders2 = backup2.folders as unknown[];
    expect(folders2).toHaveLength(0);
  });

  test('should not allow User2 to access User1 backup endpoints with User1 token', async ({
    request,
  }) => {
    const user1 = await createAuthenticatedUser(request);
    await setupBackupForUser(request, user1);
    await createItem(request, user1, { encryptedName: 'isolated-item' });

    const user2 = await createAuthenticatedUser(request);

    // User2 tries to download User1's backup (but uses their own token — gets their own data)
    // This verifies the server scopes backup data to the authenticated user
    await setupBackupForUser(request, user2);
    const backup2 = await downloadBackup(request, user2);
    const items2 = backup2.items as unknown[];
    expect(items2).toHaveLength(0); // User2 has no items

    // User2 triggers backup — only their own data
    const triggerRes = await authMutate(request, user2, 'post', '/api/v1/backup/trigger');
    expect(triggerRes.ok()).toBe(true);
    const triggerBody = (await triggerRes.json()) as { data: { itemCount: number } };
    expect(triggerBody.data.itemCount).toBe(0);
  });
});
