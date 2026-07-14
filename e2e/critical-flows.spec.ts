import { test, expect } from '@playwright/test';
import {
  createAuthenticatedUser,
  authGet,
  authMutate,
  sampleVaultItem,
  getCsrf,
  createItem,
} from './helpers';

/**
 * Critical flow E2E tests for H-Vault.
 *
 * Covers:
 *  1. Authenticated lock/unlock flow
 *  2. Import/Export flow
 *  3. Password change flow
 *  4. Account deletion flow
 *
 * Uses API-level authentication (bypassing client-side PBKDF2) to test
 * server-side flows end-to-end. Each test creates its own user for isolation.
 */

// ---------------------------------------------------------------------------
// 1. Lock/Unlock Flow (API-level)
// ---------------------------------------------------------------------------

test.describe('Lock/Unlock Flow', () => {
  test('should verify vault is accessible, then locked state prevents data creation without auth', async ({
    request,
  }) => {
    const user = await createAuthenticatedUser(request);

    // Verify vault is accessible when authenticated
    const listRes = await authGet(request, user, '/api/v1/vault/items');
    expect(listRes.ok()).toBe(true);
    const listBody = (await listRes.json()) as { success: boolean };
    expect(listBody.success).toBe(true);

    // Simulate "locked" state by making requests without auth token
    const lockedRes = await request.get('/api/v1/vault/items', { headers: {} });
    expect(lockedRes.status()).toBe(401);

    // Verify re-authentication restores access (unlock)
    const unlockListRes = await authGet(request, user, '/api/v1/vault/items');
    expect(unlockListRes.ok()).toBe(true);
  });

  test('should verify lock screen does not appear for unauthenticated users', async ({ page }) => {
    await page.goto('/login');
    await page.waitForLoadState('networkidle');

    const lockScreen = page.getByRole('button', { name: /unlock/i });
    await expect(lockScreen).not.toBeVisible();
  });

  test('should verify no sensitive data is exposed in storage when logged out', async ({
    page,
  }) => {
    await page.goto('/login');
    await page.waitForLoadState('networkidle');

    // Check no vault keys or tokens are in localStorage
    const localStorageKeys = await page.evaluate(() => Object.keys(localStorage));
    const sensitiveLocal = localStorageKeys.filter(
      (key) => key.includes('vaultKey') || key.includes('accessToken') || key.includes('mek'),
    );
    expect(sensitiveLocal).toHaveLength(0);

    // Check sessionStorage as well
    const sessionStorageKeys = await page.evaluate(() => Object.keys(sessionStorage));
    const sensitiveSession = sessionStorageKeys.filter(
      (key) => key.includes('vaultKey') || key.includes('accessToken') || key.includes('mek'),
    );
    expect(sensitiveSession).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// 2. Import/Export Flow (API-level)
// ---------------------------------------------------------------------------

test.describe('Import/Export Flow', () => {
  test('should create items, export them, and verify export content', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    await createItem(request, user, { encryptedName: 'export-item-1' });
    await createItem(request, user, { itemType: 'note', encryptedName: 'export-item-2' });

    // Export vault data
    const exportRes = await authMutate(request, user, 'post', '/api/v1/tools/export', {
      format: 'json',
      authHash: user.authHash,
    });
    expect(exportRes.ok()).toBe(true);

    const exportBody = (await exportRes.json()) as {
      success: boolean;
      data: { items: { encryptedName: string; itemType: string }[]; folders: unknown[] };
    };
    expect(exportBody.success).toBe(true);
    expect(exportBody.data.items).toHaveLength(2);
    expect(exportBody.data.folders).toBeDefined();

    const exportedNames = exportBody.data.items.map((i) => i.encryptedName);
    expect(exportedNames).toContain('export-item-1');
    expect(exportedNames).toContain('export-item-2');
  });

  test('should import vault items via JSON', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const importRes = await authMutate(request, user, 'post', '/api/v1/tools/import', {
      format: 'json',
      data: JSON.stringify({
        items: [
          sampleVaultItem({ encryptedName: 'imported-item-1' }),
          sampleVaultItem({ itemType: 'note', encryptedName: 'imported-item-2' }),
          sampleVaultItem({ itemType: 'secret', encryptedName: 'imported-item-3' }),
        ],
      }),
      conflictStrategy: 'keep_both',
    });
    expect(importRes.ok()).toBe(true);

    const importBody = (await importRes.json()) as {
      success: boolean;
      data: { importedCount: number };
    };
    expect(importBody.success).toBe(true);
    expect(importBody.data.importedCount).toBe(3);

    // Verify items exist in vault
    const listRes = await authGet(request, user, '/api/v1/vault/items');
    const listBody = (await listRes.json()) as { pagination: { total: number } };
    expect(listBody.pagination.total).toBe(3);
  });

  test('should export and then re-import data round-trip', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    await createItem(request, user, { encryptedName: 'round-trip-item' });

    // Export
    const exportRes = await authMutate(request, user, 'post', '/api/v1/tools/export', {
      format: 'json',
      authHash: user.authHash,
    });
    expect(exportRes.ok()).toBe(true);
    const exportBody = (await exportRes.json()) as {
      data: { items: Record<string, unknown>[] };
    };
    expect(exportBody.data.items).toHaveLength(1);

    // Create a second user and import the exported data
    const user2 = await createAuthenticatedUser(request);

    const importRes = await authMutate(request, user2, 'post', '/api/v1/tools/import', {
      format: 'json',
      data: JSON.stringify({ items: exportBody.data.items }),
      conflictStrategy: 'keep_both',
    });
    expect(importRes.ok()).toBe(true);

    const importBody = (await importRes.json()) as { data: { importedCount: number } };
    expect(importBody.data.importedCount).toBe(1);

    // Verify item exists in user2's vault
    const listRes = await authGet(request, user2, '/api/v1/vault/items');
    const listBody = (await listRes.json()) as {
      data: { encryptedName: string }[];
      pagination: { total: number };
    };
    expect(listBody.pagination.total).toBe(1);
    expect(listBody.data[0]!.encryptedName).toBe('round-trip-item');
  });
});

// ---------------------------------------------------------------------------
// 3. Password Change Flow (API-level)
// ---------------------------------------------------------------------------

test.describe('Password Change Flow', () => {
  test('should change password and authenticate with new password', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    const newAuthHash = 'e2e-new-auth-hash-after-change';

    const changeRes = await authMutate(request, user, 'put', '/api/v1/user/change-password', {
      currentAuthHash: user.authHash,
      newAuthHash,
      newEncryptedVaultKey: 'new-encrypted-vault-key',
      newVaultKeyIv: 'new-vault-key-iv',
      newVaultKeyTag: 'new-vault-key-tag',
    });
    expect(changeRes.ok()).toBe(true);

    const changeBody = (await changeRes.json()) as { success: boolean; message: string };
    expect(changeBody.success).toBe(true);
    expect(changeBody.message).toMatch(/password changed|log in again/i);

    // Wait so the new JWT iat is strictly after the ceiled passwordChangedAt.
    await new Promise((r) => setTimeout(r, 1100));

    // Login with the NEW password
    const loginCsrf = await getCsrf(request);
    const loginRes = await request.post('/api/v1/auth/login', {
      data: { email: user.email, authHash: newAuthHash },
      headers: {
        'content-type': 'application/json',
        'x-csrf-token': loginCsrf,
      },
    });
    expect(loginRes.ok()).toBe(true);
  });

  test('should reject login with old password after password change', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    const newAuthHash = 'e2e-changed-password-hash';

    await authMutate(request, user, 'put', '/api/v1/user/change-password', {
      currentAuthHash: user.authHash,
      newAuthHash,
      newEncryptedVaultKey: 'new-encrypted-vault-key',
      newVaultKeyIv: 'new-vault-key-iv',
      newVaultKeyTag: 'new-vault-key-tag',
    });

    // Try login with OLD password
    const loginCsrf = await getCsrf(request);
    const loginRes = await request.post('/api/v1/auth/login', {
      data: { email: user.email, authHash: user.authHash },
      headers: {
        'content-type': 'application/json',
        'x-csrf-token': loginCsrf,
      },
    });
    expect(loginRes.status()).toBe(401);
  });

  test('should reject password change with wrong current password', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const changeRes = await authMutate(request, user, 'put', '/api/v1/user/change-password', {
      currentAuthHash: 'wrong-current-password',
      newAuthHash: 'new-password-hash',
      newEncryptedVaultKey: 'new-encrypted-vault-key',
      newVaultKeyIv: 'new-vault-key-iv',
      newVaultKeyTag: 'new-vault-key-tag',
    });
    expect(changeRes.status()).toBe(401);
  });

  test('should revoke refresh tokens after password change', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    await authMutate(request, user, 'put', '/api/v1/user/change-password', {
      currentAuthHash: user.authHash,
      newAuthHash: 'e2e-revocation-test-hash',
      newEncryptedVaultKey: 'new-encrypted-vault-key',
      newVaultKeyIv: 'new-vault-key-iv',
      newVaultKeyTag: 'new-vault-key-tag',
    });

    // Wait so the new JWT iat is strictly after the ceiled passwordChangedAt.
    await new Promise((r) => setTimeout(r, 1100));

    // Login with new password
    const loginCsrf = await getCsrf(request);
    const loginRes = await request.post('/api/v1/auth/login', {
      data: { email: user.email, authHash: 'e2e-revocation-test-hash' },
      headers: {
        'content-type': 'application/json',
        'x-csrf-token': loginCsrf,
      },
    });
    expect(loginRes.ok()).toBe(true);

    const loginBody = (await loginRes.json()) as { data: { accessToken: string } };

    // Check sessions — should only have the new login session
    const sessionsRes = await request.get('/api/v1/user/sessions', {
      headers: { authorization: `Bearer ${loginBody.data.accessToken}` },
    });
    expect(sessionsRes.ok()).toBe(true);

    const sessionsBody = (await sessionsRes.json()) as { data: unknown[] };
    expect(sessionsBody.data).toHaveLength(1);
  });

  test('should preserve vault items after password change', async ({ request }) => {
    const user = await createAuthenticatedUser(request);
    const newAuthHash = 'e2e-preserve-items-hash';

    // Create items before password change
    await createItem(request, user, { encryptedName: 'pre-change-item' });

    // Change password
    await authMutate(request, user, 'put', '/api/v1/user/change-password', {
      currentAuthHash: user.authHash,
      newAuthHash,
      newEncryptedVaultKey: 'new-encrypted-vault-key',
      newVaultKeyIv: 'new-vault-key-iv',
      newVaultKeyTag: 'new-vault-key-tag',
    });

    // Wait for 1.1s so the new JWT `iat` is strictly after the ceiled
    // `passwordChangedAt` timestamp (JWT iat has second-level precision and
    // the server ceils passwordChangedAt to the next second).
    await new Promise((r) => setTimeout(r, 1100));

    // Login with new password
    const loginCsrf = await getCsrf(request);
    const loginRes = await request.post('/api/v1/auth/login', {
      data: { email: user.email, authHash: newAuthHash },
      headers: {
        'content-type': 'application/json',
        'x-csrf-token': loginCsrf,
      },
    });
    const loginBody = (await loginRes.json()) as { data: { accessToken: string } };

    // Verify items still exist
    const listRes = await request.get('/api/v1/vault/items', {
      headers: { authorization: `Bearer ${loginBody.data.accessToken}` },
    });
    const listBody = (await listRes.json()) as { pagination: { total: number } };
    expect(listBody.pagination.total).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// 4. Account Deletion Flow (API-level)
// ---------------------------------------------------------------------------

test.describe('Account Deletion Flow', () => {
  test('should delete account with correct password', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    // Create some data first
    await createItem(request, user);

    // Delete account
    const deleteRes = await authMutate(request, user, 'delete', '/api/v1/user', {
      password: user.authHash,
    });
    expect(deleteRes.ok()).toBe(true);

    // Login should fail after account deletion
    const loginCsrf = await getCsrf(request);
    const loginRes = await request.post('/api/v1/auth/login', {
      data: { email: user.email, authHash: user.authHash },
      headers: {
        'content-type': 'application/json',
        'x-csrf-token': loginCsrf,
      },
    });
    expect(loginRes.status()).toBe(401);
  });

  test('should reject account deletion with wrong password', async ({ request }) => {
    const user = await createAuthenticatedUser(request);

    const deleteRes = await authMutate(request, user, 'delete', '/api/v1/user', {
      password: 'wrong-password-hash',
    });
    expect(deleteRes.status()).toBe(401);
  });
});
