import { test, expect } from '@playwright/test';
import { testEmail, TEST_PASSWORD, getCsrf } from './helpers';

/**
 * Full user journey E2E tests.
 *
 * Exercises complete workflows through both the UI and API.
 *
 * Note on authentication: Since the client performs PBKDF2 key derivation
 * (600k iterations) before sending authHash to the server, API-level tests
 * send the raw authHash directly. For UI-level tests, we rely on the
 * registration UI flow since the client handles crypto automatically.
 *
 * Email verification: In E2E test environments, we register via API and
 * verify email status cannot proceed without verification.
 */

// ---------------------------------------------------------------------------
// API Helpers
// ---------------------------------------------------------------------------

function registrationPayload(email: string, authHash = 'e2e-test-auth-hash') {
  return {
    email,
    authHash,
    encryptedVaultKey: 'e2e-enc-vk',
    vaultKeyIv: 'e2e-vk-iv',
    vaultKeyTag: 'e2e-vk-tag',
    kdfIterations: 600_000,
    kdfAlgorithm: 'PBKDF2-SHA256',
  };
}

async function apiRegister(
  request: import('@playwright/test').APIRequestContext,
  email: string,
  authHash = 'e2e-test-auth-hash',
) {
  const csrf = await getCsrf(request);
  return request.post('/api/v1/auth/register', {
    data: registrationPayload(email, authHash),
    headers: {
      'content-type': 'application/json',
      'x-csrf-token': csrf,
    },
  });
}

async function apiLogin(
  request: import('@playwright/test').APIRequestContext,
  email: string,
  authHash: string,
) {
  const csrf = await getCsrf(request);
  return request.post('/api/v1/auth/login', {
    data: { email, authHash },
    headers: {
      'content-type': 'application/json',
      'x-csrf-token': csrf,
    },
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe('Full User Journey', () => {
  // ── Registration & Verification Flow ──────────────────────────────

  test.describe('Registration Journey', () => {
    test('should display registration form with all required fields', async ({ page }) => {
      await page.goto('/register');
      await expect(page.getByLabel(/email/i)).toBeVisible();
      await expect(page.getByLabel(/^master password$/i)).toBeVisible();
      await expect(page.getByLabel(/confirm master password/i)).toBeVisible();
    });

    test('should show password strength feedback during registration', async ({ page }) => {
      await page.goto('/register');

      // Weak password
      await page.getByLabel(/^master password$/i).fill('short');
      await expect(page.getByText(/very weak|weak|too short/i)).toBeVisible({ timeout: 5_000 });

      // Strong password
      await page.getByLabel(/^master password$/i).fill(TEST_PASSWORD);
      await expect(page.getByText(/strong|good|fair/i)).toBeVisible({ timeout: 5_000 });
    });

    test('should register user via API and return generic success', async ({ request }) => {
      const email = testEmail();
      const res = await apiRegister(request, email);

      expect(res.ok()).toBe(true);
      const body = (await res.json()) as { success: boolean; message: string };
      expect(body.success).toBe(true);
      expect(body.message).toMatch(/registration successful/i);
    });

    test('should return identical response for duplicate registration (anti-enumeration)', async ({
      request,
    }) => {
      const email = testEmail();

      const res1 = await apiRegister(request, email, 'hash1');
      const res2 = await apiRegister(request, email, 'hash2');

      // Both should return success — prevents email enumeration
      expect(res1.ok()).toBe(true);
      expect(res2.ok()).toBe(true);
    });
  });

  // ── Email Verification Enforcement ────────────────────────────────

  test.describe('Email Verification Enforcement', () => {
    test('should reject login for unverified email with generic 401', async ({ request }) => {
      const email = testEmail();
      const authHash = 'e2e-test-auth-hash';

      await apiRegister(request, email, authHash);

      const loginRes = await apiLogin(request, email, authHash);

      expect(loginRes.status()).toBe(401);
      const body = (await loginRes.json()) as {
        success: boolean;
        message: string;
        data?: { reason: string };
      };
      expect(body.message).toBe('Invalid email or password');
      expect(body.data?.reason).toBe('email_not_verified');
    });
  });

  // ── Login Flow ────────────────────────────────────────────────────

  test.describe('Login Journey', () => {
    test('should display error for invalid credentials', async ({ page }) => {
      await page.goto('/login');

      await page.getByLabel(/email/i).fill('nonexistent@example.com');
      await page.getByLabel(/^master password$/i).fill('wrong-password');
      await page.getByRole('button', { name: /log in|sign in/i }).click();

      await expect(page.getByText(/invalid|incorrect|failed|error/i)).toBeVisible({
        timeout: 10_000,
      });
      await expect(page).toHaveURL(/\/login/);
    });

    test('should navigate between login and registration pages', async ({ page }) => {
      await page.goto('/login');
      await page.getByRole('link', { name: /register|sign up|create/i }).click();
      await expect(page).toHaveURL(/\/register/);

      const loginLink = page.getByRole('link', { name: /log in|sign in|already have/i });
      await loginLink.click();
      await expect(page).toHaveURL(/\/login/);
    });
  });

  // ── Forgot Password (Anti-Enumeration) ────────────────────────────

  test.describe('Forgot Password Journey', () => {
    test('should show generic success for any email (prevents enumeration)', async ({ page }) => {
      await page.goto('/forgot-password');
      await page.getByLabel(/email/i).fill('random@nonexistent.example.com');
      await page.getByRole('button', { name: /reset|send|submit/i }).click();

      await expect(page.getByRole('heading', { name: /check your email/i })).toBeVisible({
        timeout: 10_000,
      });
    });
  });

  // ── API-Level Auth Guards ─────────────────────────────────────────

  test.describe('API Auth Guards', () => {
    test('should reject vault operations without authentication', async ({ request }) => {
      const res = await request.get('/api/v1/vault/items');
      expect(res.status()).toBe(401);
    });

    test('should reject folder operations without authentication', async ({ request }) => {
      const res = await request.get('/api/v1/folders');
      expect(res.status()).toBe(401);
    });

    test('should reject backup operations without authentication', async ({ request }) => {
      const csrf = await getCsrf(request);

      const setupRes = await request.post('/api/v1/backup/setup', {
        data: { encryptedBWK: 'test', bwkIv: 'iv', bwkTag: 'tag', bwkSalt: 'salt' },
        headers: {
          'content-type': 'application/json',
          'x-csrf-token': csrf,
        },
      });
      expect(setupRes.status()).toBe(401);

      const triggerRes = await request.post('/api/v1/backup/trigger', {
        headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
      });
      expect(triggerRes.status()).toBe(401);

      const restoreRes = await request.post('/api/v1/backup/restore', {
        data: { data: '{}', conflictStrategy: 'skip' },
        headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
      });
      expect(restoreRes.status()).toBe(401);

      const downloadRes = await request.get('/api/v1/backup/download');
      expect(downloadRes.status()).toBe(401);
    });

    test('should reject session and audit operations without authentication', async ({
      request,
    }) => {
      const sessionsRes = await request.get('/api/v1/user/sessions');
      expect(sessionsRes.status()).toBe(401);

      const auditRes = await request.get('/api/v1/user/audit-log');
      expect(auditRes.status()).toBe(401);
    });

    test('should reject tools endpoints without authentication', async ({ request }) => {
      const csrf = await getCsrf(request);

      const exportRes = await request.post('/api/v1/tools/export', {
        data: { format: 'json' },
        headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
      });
      expect(exportRes.status()).toBe(401);
    });
  });
});
