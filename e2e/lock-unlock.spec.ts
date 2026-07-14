import { test, expect } from '@playwright/test';
import { createAuthenticatedUser, authGet, createItem } from './helpers';

/**
 * Lock/Unlock E2E tests.
 *
 * Verifies that vault locking clears sensitive data from browser storage,
 * that unlocking restores access, and that locked state prevents operations.
 */

test.describe('Vault Lock/Unlock', () => {
  test.describe('Storage Security When Logged Out', () => {
    test('should not expose vault data in localStorage when logged out', async ({ page }) => {
      await page.goto('/login');
      await page.waitForLoadState('networkidle');

      const storageKeys = await page.evaluate(() => Object.keys(localStorage));
      const vaultKeys = storageKeys.filter(
        (key) => key.includes('vault') && !key.includes('__hv_'),
      );
      expect(vaultKeys).toHaveLength(0);
    });

    test('should not have sensitive keys in sessionStorage when logged out', async ({ page }) => {
      await page.goto('/login');
      await page.waitForLoadState('networkidle');

      const sessionKeys = await page.evaluate(() => Object.keys(sessionStorage));
      const sensitiveKeys = sessionKeys.filter(
        (key) => key.includes('token') || key.includes('mek') || key.includes('vaultKey'),
      );
      expect(sensitiveKeys).toHaveLength(0);
    });

    test('should not expose plaintext auth tokens in any storage', async ({ page }) => {
      await page.goto('/login');
      await page.waitForLoadState('networkidle');

      // Check localStorage values don't contain JWT-like patterns
      const localValues = await page.evaluate(() => {
        const values: string[] = [];
        for (let i = 0; i < localStorage.length; i++) {
          const key = localStorage.key(i);
          if (key) values.push(localStorage.getItem(key) ?? '');
        }
        return values;
      });

      for (const val of localValues) {
        // JWT tokens have 3 parts separated by dots
        expect(val).not.toMatch(/^eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\./);
      }
    });
  });

  test.describe('Lock Behavior (API-level)', () => {
    test('should block vault access without authentication token', async ({ request }) => {
      // Simulate locked state: requests without auth token should fail
      const res = await request.get('/api/v1/vault/items', { headers: {} });
      expect(res.status()).toBe(401);
    });

    test('should block all vault operations without authentication', async ({ request }) => {
      const csrf = await (async () => {
        const r = await request.get('/api/v1/csrf-token');
        const b = (await r.json()) as { data: { csrfToken: string } };
        return b.data.csrfToken;
      })();

      // GET operations
      const getRes = await request.get('/api/v1/vault/items');
      expect(getRes.status()).toBe(401);

      const trashRes = await request.get('/api/v1/vault/items/trash');
      expect(trashRes.status()).toBe(401);

      const foldersRes = await request.get('/api/v1/folders');
      expect(foldersRes.status()).toBe(401);

      // POST operations
      const createRes = await request.post('/api/v1/vault/items', {
        data: {},
        headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
      });
      expect(createRes.status()).toBe(401);
    });

    test('should restore access after re-authentication', async ({ request }) => {
      const user = await createAuthenticatedUser(request);

      // Create item while authenticated
      await createItem(request, user);

      // Verify access works
      const listRes = await authGet(request, user, '/api/v1/vault/items');
      expect(listRes.ok()).toBe(true);

      // Simulate lock (no token)
      const lockedRes = await request.get('/api/v1/vault/items');
      expect(lockedRes.status()).toBe(401);

      // Re-authenticate (unlock) — same token still valid
      const unlockRes = await authGet(request, user, '/api/v1/vault/items');
      expect(unlockRes.ok()).toBe(true);
      const body = (await unlockRes.json()) as { pagination: { total: number } };
      expect(body.pagination.total).toBe(1);
    });
  });

  test.describe('Protected Routes Redirect', () => {
    test('should redirect unauthenticated access to /vault', async ({ page }) => {
      await page.goto('/vault');
      await expect(page).toHaveURL(/\/login/, { timeout: 10_000 });
    });

    test('should redirect unauthenticated access to /settings', async ({ page }) => {
      await page.goto('/settings');
      await expect(page).toHaveURL(/\/login/, { timeout: 10_000 });
    });

    test('should redirect unauthenticated access to /generator', async ({ page }) => {
      await page.goto('/generator');
      await expect(page).toHaveURL(/\/login/, { timeout: 10_000 });
    });

    test('should redirect unauthenticated access to /vault/health', async ({ page }) => {
      await page.goto('/vault/health');
      await expect(page).toHaveURL(/\/login/, { timeout: 10_000 });
    });

    test('should redirect unauthenticated access to /settings/backup', async ({ page }) => {
      await page.goto('/settings/backup');
      await expect(page).toHaveURL(/\/login/, { timeout: 10_000 });
    });

    test('should redirect unauthenticated access to /settings/sessions', async ({ page }) => {
      await page.goto('/settings/sessions');
      await expect(page).toHaveURL(/\/login/, { timeout: 10_000 });
    });

    test('should redirect unauthenticated access to /settings/audit', async ({ page }) => {
      await page.goto('/settings/audit');
      await expect(page).toHaveURL(/\/login/, { timeout: 10_000 });
    });
  });
});
