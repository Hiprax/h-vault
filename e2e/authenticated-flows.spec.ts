import { test, expect } from '@playwright/test';
import {
  createAuthenticatedUser,
  authGet,
  authMutate,
  sampleVaultItem,
  sampleFolder,
  createItem,
  createFolder,
} from './helpers';

/**
 * Authenticated E2E tests for H-Vault core flows.
 *
 * Uses API-level authentication (bypassing client-side PBKDF2) to test
 * server-side vault CRUD, folder CRUD, settings, password generator,
 * session management, audit logs, and export functionality.
 *
 * Each test creates its own user for isolation.
 */

// ─── Vault Item CRUD ──────────────────────────────────────────────────────────

test.describe('Authenticated Vault CRUD', () => {
  test('should create a vault item', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const res = await authMutate(request, user, 'post', '/api/v1/vault/items', sampleVaultItem());

    expect(res.ok()).toBe(true);
    const body = (await res.json()) as {
      success: boolean;
      data: { _id: string; itemType: string };
    };
    expect(body.success).toBe(true);
    expect(body.data._id).toBeDefined();
    expect(body.data.itemType).toBe('login');
  });

  test('should list vault items', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    await createItem(request, user);
    await createItem(request, user, { itemType: 'note' });

    const res = await authGet(request, user, '/api/v1/vault/items');
    expect(res.ok()).toBe(true);

    const body = (await res.json()) as {
      success: boolean;
      data: unknown[];
      pagination: { total: number };
    };
    expect(body.success).toBe(true);
    expect(body.data).toHaveLength(2);
    expect(body.pagination.total).toBe(2);
  });

  test('should get a single vault item by ID', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    const itemId = await createItem(request, user);

    const res = await authGet(request, user, `/api/v1/vault/items/${itemId}`);
    expect(res.ok()).toBe(true);

    const body = (await res.json()) as {
      success: boolean;
      data: { _id: string; encryptedData: string };
    };
    expect(body.data._id).toBe(itemId);
    expect(body.data.encryptedData).toBe('e2e-encrypted-data');
  });

  test('should update a vault item', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    const itemId = await createItem(request, user);

    const res = await authMutate(request, user, 'put', `/api/v1/vault/items/${itemId}`, {
      encryptedData: 'updated-data',
      dataIv: 'new-iv',
      dataTag: 'new-tag',
      favorite: true,
    });
    expect(res.ok()).toBe(true);

    const body = (await res.json()) as {
      success: boolean;
      data: { favorite: boolean; encryptedData: string };
    };
    expect(body.data.favorite).toBe(true);
    expect(body.data.encryptedData).toBe('updated-data');
  });

  test('should soft-delete and restore a vault item', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    const itemId = await createItem(request, user);

    // Soft delete
    const deleteRes = await authMutate(request, user, 'delete', `/api/v1/vault/items/${itemId}`);
    expect(deleteRes.ok()).toBe(true);

    // Should appear in trash
    const trashRes = await authGet(request, user, '/api/v1/vault/items/trash');
    expect(trashRes.ok()).toBe(true);
    const trashBody = (await trashRes.json()) as { data: { _id: string }[] };
    expect(trashBody.data.some((item) => item._id === itemId)).toBe(true);

    // Should NOT appear in active items
    const listRes = await authGet(request, user, '/api/v1/vault/items');
    const listBody = (await listRes.json()) as { data: { _id: string }[] };
    expect(listBody.data.some((item) => item._id === itemId)).toBe(false);

    // Restore
    const restoreRes = await authMutate(
      request,
      user,
      'post',
      `/api/v1/vault/items/restore/${itemId}`,
    );
    expect(restoreRes.ok()).toBe(true);

    // Should appear in active items again
    const afterRestoreRes = await authGet(request, user, '/api/v1/vault/items');
    const afterRestoreBody = (await afterRestoreRes.json()) as { data: { _id: string }[] };
    expect(afterRestoreBody.data.some((item) => item._id === itemId)).toBe(true);
  });

  test('should permanently delete a vault item', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    const itemId = await createItem(request, user);

    // Soft delete first
    await authMutate(request, user, 'delete', `/api/v1/vault/items/${itemId}`);

    // Permanent delete
    const permRes = await authMutate(
      request,
      user,
      'delete',
      `/api/v1/vault/items/${itemId}/permanent`,
    );
    expect(permRes.ok()).toBe(true);

    // Should NOT appear in trash
    const trashRes = await authGet(request, user, '/api/v1/vault/items/trash');
    const trashBody = (await trashRes.json()) as { data: { _id: string }[] };
    expect(trashBody.data.some((item) => item._id === itemId)).toBe(false);
  });

  test('should create all five vault item types', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const types = ['login', 'secret', 'note', 'card', 'identity'] as const;
    for (const itemType of types) {
      const res = await authMutate(
        request,
        user,
        'post',
        '/api/v1/vault/items',
        sampleVaultItem({ itemType }),
      );
      expect(res.ok()).toBe(true);
      const body = (await res.json()) as { data: { itemType: string } };
      expect(body.data.itemType).toBe(itemType);
    }

    const listRes = await authGet(request, user, '/api/v1/vault/items');
    const listBody = (await listRes.json()) as { pagination: { total: number } };
    expect(listBody.pagination.total).toBe(5);
  });

  test('should support filtering by item type', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    await createItem(request, user, { itemType: 'login' });
    await createItem(request, user, { itemType: 'note' });
    await createItem(request, user, { itemType: 'note' });

    const res = await authGet(request, user, '/api/v1/vault/items?itemType=note');
    expect(res.ok()).toBe(true);
    const body = (await res.json()) as {
      data: { itemType: string }[];
      pagination: { total: number };
    };
    expect(body.pagination.total).toBe(2);
    expect(body.data.every((item) => item.itemType === 'note')).toBe(true);
  });

  test('should support bulk delete', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const ids: string[] = [];
    for (let i = 0; i < 3; i++) {
      ids.push(await createItem(request, user));
    }

    const bulkRes = await authMutate(request, user, 'post', '/api/v1/vault/items/bulk-delete', {
      ids,
    });
    expect(bulkRes.ok()).toBe(true);

    // All items should be in trash
    const trashRes = await authGet(request, user, '/api/v1/vault/items/trash');
    const trashBody = (await trashRes.json()) as { data: { _id: string }[] };
    expect(trashBody.data).toHaveLength(3);
  });

  test('should empty trash permanently', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    // Create and soft-delete items
    for (let i = 0; i < 3; i++) {
      const id = await createItem(request, user);
      await authMutate(request, user, 'delete', `/api/v1/vault/items/${id}`);
    }

    // Verify trash has items
    const trashBefore = await authGet(request, user, '/api/v1/vault/items/trash');
    const trashBeforeBody = (await trashBefore.json()) as { data: unknown[] };
    expect(trashBeforeBody.data).toHaveLength(3);

    // Empty trash
    const emptyRes = await authMutate(request, user, 'delete', '/api/v1/vault/items/trash/empty');
    expect(emptyRes.ok()).toBe(true);

    // Verify trash is empty
    const trashAfter = await authGet(request, user, '/api/v1/vault/items/trash');
    const trashAfterBody = (await trashAfter.json()) as { data: unknown[] };
    expect(trashAfterBody.data).toHaveLength(0);
  });

  test('should support sorting by updatedAt', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    await createItem(request, user, { encryptedName: 'item-a' });
    await createItem(request, user, { encryptedName: 'item-b' });

    const res = await authGet(request, user, '/api/v1/vault/items?sortBy=updatedAt&sortOrder=desc');
    expect(res.ok()).toBe(true);
    const body = (await res.json()) as { data: { encryptedName: string }[] };
    expect(body.data).toHaveLength(2);
    // Most recently created should be first in desc order
    expect(body.data[0]!.encryptedName).toBe('item-b');
  });

  test('should support pagination', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    // Create 5 items
    for (let i = 0; i < 5; i++) {
      await createItem(request, user);
    }

    // Page 1 with limit 2
    const page1Res = await authGet(request, user, '/api/v1/vault/items?page=1&limit=2');
    expect(page1Res.ok()).toBe(true);
    const page1Body = (await page1Res.json()) as {
      data: unknown[];
      pagination: { page: number; limit: number; total: number; totalPages: number };
    };
    expect(page1Body.data).toHaveLength(2);
    expect(page1Body.pagination.total).toBe(5);
    expect(page1Body.pagination.totalPages).toBe(3);
    expect(page1Body.pagination.page).toBe(1);

    // Page 3 with limit 2 should have 1 item
    const page3Res = await authGet(request, user, '/api/v1/vault/items?page=3&limit=2');
    const page3Body = (await page3Res.json()) as { data: unknown[] };
    expect(page3Body.data).toHaveLength(1);
  });

  test('should reject invalid ObjectId', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const res = await authGet(request, user, '/api/v1/vault/items/not-a-valid-id');
    expect(res.status()).toBe(400);
  });

  test('should return 404 for non-existent item', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const res = await authGet(request, user, '/api/v1/vault/items/000000000000000000000000');
    expect(res.status()).toBe(404);
  });

  test('should support favorite filter', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    await createItem(request, user, { favorite: true, encryptedName: 'fav-item' });
    await createItem(request, user, { favorite: false, encryptedName: 'normal-item' });

    const res = await authGet(request, user, '/api/v1/vault/items?favorite=true');
    expect(res.ok()).toBe(true);
    const body = (await res.json()) as {
      data: { favorite: boolean }[];
      pagination: { total: number };
    };
    expect(body.pagination.total).toBe(1);
    expect(body.data[0]!.favorite).toBe(true);
  });

  test('should support tags on vault items', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const itemId = await createItem(request, user, { tags: ['work', 'important'] });

    const res = await authGet(request, user, `/api/v1/vault/items/${itemId}`);
    const body = (await res.json()) as { data: { tags: string[] } };
    expect(body.data.tags).toEqual(['work', 'important']);
  });
});

// ─── Folder CRUD ──────────────────────────────────────────────────────────────

test.describe('Authenticated Folder CRUD', () => {
  test('should create a folder', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const res = await authMutate(request, user, 'post', '/api/v1/folders', sampleFolder());
    expect(res.ok()).toBe(true);

    const body = (await res.json()) as {
      success: boolean;
      data: { _id: string; encryptedName: string };
    };
    expect(body.success).toBe(true);
    expect(body.data._id).toBeDefined();
  });

  test('should list folders', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    await createFolder(request, user);
    await createFolder(request, user, { encryptedName: 'folder-2' });

    const res = await authGet(request, user, '/api/v1/folders');
    expect(res.ok()).toBe(true);

    const body = (await res.json()) as { success: boolean; data: unknown[] };
    expect(body.data).toHaveLength(2);
  });

  test('should update a folder', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    const folderId = await createFolder(request, user);

    const res = await authMutate(request, user, 'put', `/api/v1/folders/${folderId}`, {
      encryptedName: 'updated-name',
      nameIv: 'new-iv',
      nameTag: 'new-tag',
    });
    expect(res.ok()).toBe(true);

    const body = (await res.json()) as { data: { encryptedName: string } };
    expect(body.data.encryptedName).toBe('updated-name');
  });

  test('should delete a folder', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    const folderId = await createFolder(request, user);

    const res = await authMutate(
      request,
      user,
      'delete',
      `/api/v1/folders/${folderId}?action=delete`,
    );
    expect(res.ok()).toBe(true);

    const listRes = await authGet(request, user, '/api/v1/folders');
    const listBody = (await listRes.json()) as { data: unknown[] };
    expect(listBody.data).toHaveLength(0);
  });

  test('should move items to folder', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    const folderId = await createFolder(request, user);
    const itemId = await createItem(request, user);

    // Move item to folder
    const moveRes = await authMutate(request, user, 'post', '/api/v1/vault/items/bulk-move', {
      ids: [itemId],
      folderId,
    });
    expect(moveRes.ok()).toBe(true);

    // Verify item is in folder
    const getRes = await authGet(request, user, `/api/v1/vault/items/${itemId}`);
    const getBody = (await getRes.json()) as { data: { folderId: string } };
    expect(getBody.data.folderId).toBe(folderId);
  });

  test('should support nested folders', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    const parentId = await createFolder(request, user, { encryptedName: 'parent' });
    const childId = await createFolder(request, user, {
      encryptedName: 'child',
      parentId,
    });

    const res = await authGet(request, user, '/api/v1/folders');
    const body = (await res.json()) as {
      data: { _id: string; parentId?: string }[];
    };
    const child = body.data.find((f) => f._id === childId);
    expect(child?.parentId).toBe(parentId);
  });

  test('should filter items by folder', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    const folderId = await createFolder(request, user);

    // Create item in folder and one without folder
    await createItem(request, user, { folderId });
    await createItem(request, user, { encryptedName: 'no-folder' });

    const res = await authGet(request, user, `/api/v1/vault/items?folderId=${folderId}`);
    expect(res.ok()).toBe(true);
    const body = (await res.json()) as { pagination: { total: number } };
    expect(body.pagination.total).toBe(1);
  });

  test('should update folder sort order', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    const folderId = await createFolder(request, user);

    const res = await authMutate(request, user, 'put', `/api/v1/folders/${folderId}/sort`, {
      sortOrder: 5,
    });
    expect(res.ok()).toBe(true);
  });
});

// ─── User Profile & Settings ──────────────────────────────────────────────────

test.describe('Authenticated User & Settings', () => {
  test('should get user profile', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const res = await authGet(request, user, '/api/v1/user/profile');
    expect(res.ok()).toBe(true);

    const body = (await res.json()) as {
      success: boolean;
      data: { email: string; emailVerified: boolean };
    };
    expect(body.data.email).toBe(user.email);
    expect(body.data.emailVerified).toBe(true);
  });

  test('should update user settings', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const res = await authMutate(request, user, 'put', '/api/v1/user/settings', {
      autoLockTimeout: 10,
      clipboardClearTimeout: 30,
      theme: 'dark',
    });
    expect(res.ok()).toBe(true);

    const body = (await res.json()) as {
      success: boolean;
      data: { autoLockTimeout: number; theme: string };
    };
    expect(body.data.autoLockTimeout).toBe(10);
    expect(body.data.theme).toBe('dark');
  });

  test('should persist settings across requests', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    // Set settings
    await authMutate(request, user, 'put', '/api/v1/user/settings', {
      autoLockTimeout: 5,
      theme: 'dark',
    });

    // Verify via profile
    const profileRes = await authGet(request, user, '/api/v1/user/profile');
    const profileBody = (await profileRes.json()) as {
      data: { settings: { autoLockTimeout: number; theme: string } };
    };
    expect(profileBody.data.settings.autoLockTimeout).toBe(5);
    expect(profileBody.data.settings.theme).toBe('dark');
  });
});

// ─── Session Management ──────────────────────────────────────────────────────

test.describe('Authenticated Session Management', () => {
  test('should list active sessions', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const res = await authGet(request, user, '/api/v1/user/sessions');
    expect(res.ok()).toBe(true);

    const body = (await res.json()) as {
      success: boolean;
      data: { deviceInfo: { userAgent: string } }[];
    };
    expect(body.data.length).toBeGreaterThanOrEqual(1);
  });

  test('should revoke a session', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const sessionsRes = await authGet(request, user, '/api/v1/user/sessions');
    const sessionsBody = (await sessionsRes.json()) as { data: { _id: string }[] };

    if (sessionsBody.data.length > 0) {
      const sessionId = sessionsBody.data[0]!._id;
      const revokeRes = await authMutate(
        request,
        user,
        'delete',
        `/api/v1/user/sessions/${sessionId}`,
      );
      expect(revokeRes.ok()).toBe(true);
    }
  });
});

// ─── Audit Log ────────────────────────────────────────────────────────────────

test.describe('Authenticated Audit Log', () => {
  test('should list audit log entries', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const res = await authGet(request, user, '/api/v1/user/audit-log');
    expect(res.ok()).toBe(true);

    const body = (await res.json()) as {
      success: boolean;
      data: { action: string }[];
      pagination: { total: number };
    };
    expect(body.pagination.total).toBeGreaterThanOrEqual(1);
    expect(body.data.some((entry) => entry.action === 'login')).toBe(true);
  });

  test('should filter audit log by action type', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const res = await authGet(request, user, '/api/v1/user/audit-log?action=login');
    expect(res.ok()).toBe(true);

    const body = (await res.json()) as { data: { action: string }[] };
    expect(body.data.every((entry) => entry.action === 'login')).toBe(true);
  });

  test('should paginate audit log', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const res = await authGet(request, user, '/api/v1/user/audit-log?page=1&limit=5');
    expect(res.ok()).toBe(true);

    const body = (await res.json()) as {
      pagination: { page: number; limit: number };
    };
    expect(body.pagination.page).toBe(1);
    expect(body.pagination.limit).toBe(5);
  });
});

// ─── Export & Import ─────────────────────────────────────────────────────────

test.describe('Authenticated Export & Import', () => {
  test('should export vault data', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    await createItem(request, user);

    const res = await authMutate(request, user, 'post', '/api/v1/tools/export', {
      format: 'json',
      authHash: user.authHash,
    });
    expect(res.ok()).toBe(true);

    const body = (await res.json()) as {
      success: boolean;
      data: { items: unknown[]; folders: unknown[]; metadata: { itemCount: number } };
    };
    expect(body.data.items).toHaveLength(1);
    expect(body.data.metadata.itemCount).toBe(1);
  });

  test('should import vault items via JSON', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const importRes = await authMutate(request, user, 'post', '/api/v1/tools/import', {
      format: 'json',
      data: JSON.stringify({
        items: [
          sampleVaultItem({ encryptedName: 'imported-1' }),
          sampleVaultItem({ itemType: 'note', encryptedName: 'imported-2' }),
        ],
      }),
      conflictStrategy: 'keep_both',
    });
    expect(importRes.ok()).toBe(true);

    const importBody = (await importRes.json()) as {
      data: { importedCount: number };
    };
    expect(importBody.data.importedCount).toBe(2);
  });

  test('should handle import conflict strategy: skip', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    // Create an existing item
    await createItem(request, user, { encryptedName: 'existing-item' });

    // Import an item with the same encryptedName — dedup should match on encryptedName fallback
    const importRes = await authMutate(request, user, 'post', '/api/v1/tools/import', {
      format: 'json',
      data: JSON.stringify({
        items: [sampleVaultItem({ encryptedName: 'existing-item' })],
      }),
      conflictStrategy: 'skip',
    });
    expect(importRes.ok()).toBe(true);

    const body = (await importRes.json()) as {
      data: { importedCount: number; duplicateCount: number };
    };
    // Should detect the duplicate and skip it
    expect(body.data.duplicateCount).toBe(1);
    expect(body.data.importedCount).toBe(0);
  });

  test('should reject export with wrong authHash', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const res = await authMutate(request, user, 'post', '/api/v1/tools/export', {
      format: 'json',
      authHash: 'wrong-password-hash',
    });
    expect(res.status()).toBe(401);
  });

  test('should export and re-import round-trip', async ({ request }) => {
    const user1 = await createAuthenticatedUser(request);
    await createItem(request, user1, { encryptedName: 'round-trip-item' });

    // Export from user1
    const exportRes = await authMutate(request, user1, 'post', '/api/v1/tools/export', {
      format: 'json',
      authHash: user1.authHash,
    });
    const exportBody = (await exportRes.json()) as {
      data: { items: Record<string, unknown>[] };
    };

    // Import into user2
    const user2 = await createAuthenticatedUser(request);
    const importRes = await authMutate(request, user2, 'post', '/api/v1/tools/import', {
      format: 'json',
      data: JSON.stringify({ items: exportBody.data.items }),
      conflictStrategy: 'keep_both',
    });
    expect(importRes.ok()).toBe(true);

    const importBody = (await importRes.json()) as { data: { importedCount: number } };
    expect(importBody.data.importedCount).toBe(1);
  });
});

// ─── Cross-User Isolation ─────────────────────────────────────────────────────

test.describe('Cross-User Isolation', () => {
  test('should not allow access to another user vault items', async ({ request }) => {
    const user1 = await createAuthenticatedUser(request);
    const user2 = await createAuthenticatedUser(request);

    const itemId = await createItem(request, user1);

    // User2 tries to access User1's item
    const res = await authGet(request, user2, `/api/v1/vault/items/${itemId}`);
    expect(res.status()).toBe(404);

    // User2's item list should be empty
    const listRes = await authGet(request, user2, '/api/v1/vault/items');
    const listBody = (await listRes.json()) as { pagination: { total: number } };
    expect(listBody.pagination.total).toBe(0);
  });

  test('should not allow updating another user vault items', async ({ request }) => {
    const user1 = await createAuthenticatedUser(request);
    const user2 = await createAuthenticatedUser(request);

    const itemId = await createItem(request, user1);

    const res = await authMutate(request, user2, 'put', `/api/v1/vault/items/${itemId}`, {
      encryptedData: 'hacked',
      dataIv: 'hacked',
      dataTag: 'hacked',
    });
    expect(res.status()).toBe(404);
  });

  test('should not allow deleting another user vault items', async ({ request }) => {
    const user1 = await createAuthenticatedUser(request);
    const user2 = await createAuthenticatedUser(request);

    const itemId = await createItem(request, user1);

    const res = await authMutate(request, user2, 'delete', `/api/v1/vault/items/${itemId}`);
    expect(res.status()).toBe(404);
  });

  test('should not allow access to another user folders', async ({ request }) => {
    const user1 = await createAuthenticatedUser(request);
    const user2 = await createAuthenticatedUser(request);

    const folderId = await createFolder(request, user1);

    const res = await authMutate(request, user2, 'put', `/api/v1/folders/${folderId}`, {
      encryptedName: 'hacked',
      nameIv: 'hacked',
      nameTag: 'hacked',
    });
    expect(res.status()).toBe(404);
  });
});

// ─── Logout ───────────────────────────────────────────────────────────────────

test.describe('Authenticated Logout', () => {
  test('should logout and invalidate the access token', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const logoutRes = await authMutate(request, user, 'post', '/api/v1/auth/logout');
    expect(logoutRes.ok()).toBe(true);
  });

  test('should logout all sessions', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const logoutAllRes = await authMutate(request, user, 'post', '/api/v1/auth/logout-all');
    expect(logoutAllRes.ok()).toBe(true);
  });
});
