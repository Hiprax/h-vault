import { test, expect } from '@playwright/test';
import { E2E_STRONG_PASSWORD, PBKDF2_STEP_TIMEOUT_MS, testEmail, TEST_PASSWORD } from './helpers';

test.describe('Authentication Flows', () => {
  test.describe('Registration', () => {
    test('should show registration form with required fields', async ({ page }) => {
      await page.goto('/register');
      await expect(page.getByLabel(/email/i)).toBeVisible();
      await expect(page.getByLabel(/^master password$/i)).toBeVisible();
      await expect(page.getByLabel(/confirm master password/i)).toBeVisible();
    });

    test('should reject registration with mismatched passwords', async ({ page }) => {
      await page.goto('/register');
      await page.getByLabel(/email/i).fill(testEmail());
      await page.getByLabel(/^master password$/i).fill(TEST_PASSWORD);
      await page.getByLabel(/confirm master password/i).fill('DifferentPassword123!');

      // Check terms to allow refine validation to run
      await page.locator('input[type="checkbox"]').check();
      await page.getByRole('button', { name: /create account|register|sign up/i }).click();

      await expect(page.getByText(/do not match|mismatch/i)).toBeVisible({ timeout: 5_000 });
    });

    test('should reject registration with weak password', async ({ page }) => {
      await page.goto('/register');
      await page.getByLabel(/email/i).fill(testEmail());
      await page.getByLabel(/^master password$/i).fill('weak');
      await page.getByLabel(/confirm master password/i).fill('weak');

      // Password strength indicator should appear (zxcvbn returns "Very Weak" or "Weak")
      await expect(page.getByText(/very weak|weak|too short|minimum/i)).toBeVisible({
        timeout: 5_000,
      });
    });

    test('should reject registration with invalid email', async ({ page }) => {
      await page.goto('/register');
      await page.getByLabel(/email/i).fill('not-an-email');
      await page.getByLabel(/^master password$/i).fill(TEST_PASSWORD);
      await page.getByLabel(/confirm master password/i).fill(TEST_PASSWORD);
      await page.getByRole('button', { name: /create account|register|sign up/i }).click();

      // Native HTML5 email validation should prevent submission;
      // verify user stays on the register page (form was not submitted)
      await expect(page).toHaveURL(/\/register/, { timeout: 5_000 });

      // The email input should be marked invalid by the browser
      const isInvalid = await page
        .locator('#register-email')
        .evaluate((el) => !(el as HTMLInputElement).validity.valid);
      expect(isInvalid).toBe(true);
    });
  });

  test.describe('Invitation links', () => {
    // The dev server registers in `open` mode for every spec, so this proves the
    // half only a browser can: the invitation travels in the link's FRAGMENT, the
    // page moves it into the form and replaces the fragment away before anything
    // else happens, and the registration request carries it. That the server then
    // admits exactly that address once is pinned against the real handler by
    // `packages/server/tests/registration-mode.test.ts`.
    test('carries the invitation from the link into the registration and drops it from the address', async ({
      page,
    }) => {
      test.setTimeout(PBKDF2_STEP_TIMEOUT_MS + 60_000);
      const token = 'e2e-Invitation_token-0123456789abcdefghijk';
      const email = testEmail();

      await page.goto(`/register#invite=${token}`);

      await expect(page.getByLabel('Invitation code')).toHaveValue(token);
      await expect.poll(() => page.evaluate(() => window.location.hash)).toBe('');
      expect(page.url()).not.toContain(token);

      await page.getByLabel(/^email$/i).fill(email);
      await page.getByLabel(/^master password$/i).fill(E2E_STRONG_PASSWORD);
      await page.getByLabel(/confirm master password/i).fill(E2E_STRONG_PASSWORD);
      await page.getByRole('checkbox').check();

      const registration = page.waitForRequest(
        (request) =>
          request.method() === 'POST' &&
          new URL(request.url()).pathname === '/api/v1/auth/register',
        { timeout: PBKDF2_STEP_TIMEOUT_MS },
      );
      await page.getByRole('button', { name: /create account/i }).click();

      const sent = (await registration).postDataJSON() as Record<string, unknown>;
      expect(sent.email).toBe(email);
      expect(sent.invitationToken).toBe(token);
      // The master password itself never leaves the page, only its derived proof.
      expect(JSON.stringify(sent)).not.toContain(E2E_STRONG_PASSWORD);
      await expect(page).toHaveURL(/\/login/, { timeout: PBKDF2_STEP_TIMEOUT_MS });
    });
  });

  test.describe('Login', () => {
    test('should show login form', async ({ page }) => {
      await page.goto('/login');
      await expect(page.getByLabel(/email/i)).toBeVisible();
      await expect(page.getByLabel(/master password/i)).toBeVisible();
      await expect(page.getByRole('button', { name: /log in|sign in/i })).toBeVisible();
    });

    test('should reject login with invalid credentials via API', async ({ request }) => {
      // Get a CSRF token first
      const csrfRes = await request.get('/api/v1/csrf-token');
      const csrfData = (await csrfRes.json()) as {
        success: boolean;
        data: { csrfToken: string };
      };

      // Attempt login with non-existent account (bypass client-side PBKDF2)
      const response = await request.post('/api/v1/auth/login', {
        data: { email: 'nonexistent@test.com', authHash: 'fake-auth-hash' },
        headers: {
          'content-type': 'application/json',
          'x-csrf-token': csrfData.data.csrfToken,
        },
      });

      expect(response.status()).toBe(401);
      const body = (await response.json()) as {
        success: boolean;
        error: { message: string };
      };
      expect(body.success).toBe(false);
    });

    test('should show forgot password link', async ({ page }) => {
      await page.goto('/login');
      await expect(page.getByRole('link', { name: /forgot/i })).toBeVisible();
    });

    test('should navigate to registration from login', async ({ page }) => {
      await page.goto('/login');
      await page.getByRole('link', { name: /register|sign up|create/i }).click();
      await expect(page).toHaveURL(/\/register/);
    });
  });

  test.describe('Forgot Password', () => {
    test('should show forgot password form', async ({ page }) => {
      await page.goto('/forgot-password');
      await expect(page.getByLabel(/email/i)).toBeVisible();
      await expect(page.getByRole('button', { name: /reset|send|submit/i })).toBeVisible();
    });

    test('should accept email submission without revealing account existence', async ({ page }) => {
      await page.goto('/forgot-password');
      await page.getByLabel(/email/i).fill('any@example.com');
      await page.getByRole('button', { name: /reset|send|submit/i }).click();

      // Should show a generic success message (prevents email enumeration)
      await expect(page.getByRole('heading', { name: /check your email/i })).toBeVisible({
        timeout: 10_000,
      });
    });
  });

  test.describe('Public Route Protection', () => {
    test('should redirect unauthenticated users from vault to login', async ({ page }) => {
      await page.goto('/vault');
      await expect(page).toHaveURL(/\/login/, { timeout: 10_000 });
    });

    test('should redirect unauthenticated users from settings to login', async ({ page }) => {
      await page.goto('/settings');
      await expect(page).toHaveURL(/\/login/, { timeout: 10_000 });
    });

    test('should redirect unauthenticated users from generator to login', async ({ page }) => {
      await page.goto('/generator');
      await expect(page).toHaveURL(/\/login/, { timeout: 10_000 });
    });
  });
});
