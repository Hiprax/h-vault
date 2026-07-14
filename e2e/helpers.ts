import { type Page, type APIRequestContext, expect } from '@playwright/test';
import { MongoClient } from 'mongodb';

// ─── Constants ───────────────────────────────────────────────────────────────

export const MONGODB_URI = process.env.MONGODB_URI ?? 'mongodb://127.0.0.1:27017/hvault';
export const TEST_PASSWORD = 'E2E-Test-P@ssword-2025!';

/**
 * A high-entropy master password guaranteed to clear the registration gate
 * (zxcvbn score >= 3 and >= 12 characters), used by the full-UI sign-in helper.
 */
export const E2E_STRONG_PASSWORD = 'Gx7!vMq2$Lp9#Rt4&Kw8';

// ─── Shared MongoDB Client ──────────────────────────────────────────────────

let sharedClient: MongoClient | undefined;

/** Returns a shared MongoDB client to avoid connection churn during tests. */
async function getMongoDb() {
  if (!sharedClient) {
    sharedClient = new MongoClient(MONGODB_URI, { maxPoolSize: 5 });
    await sharedClient.connect();
  }
  return sharedClient.db();
}

/**
 * Marks a user's email as verified directly in MongoDB.
 *
 * The E2E harness disables SMTP, so no verification email is ever sent; the
 * server would otherwise reject login with `EMAIL_NOT_VERIFIED`. Flipping the
 * flag directly mirrors {@link createAuthenticatedUser}'s API-level path for the
 * full-UI sign-in flow (which registers and logs in through the real pages).
 */
export async function markEmailVerified(email: string): Promise<void> {
  const db = await getMongoDb();
  await db.collection('users').updateOne({ email }, { $set: { emailVerified: true } });
}

// ─── Types ───────────────────────────────────────────────────────────────────

export interface AuthenticatedUser {
  email: string;
  authHash: string;
  accessToken: string;
}

// ─── CSRF Helper ─────────────────────────────────────────────────────────────

/** Fetches a CSRF token from the server. */
export async function getCsrf(request: APIRequestContext): Promise<string> {
  const res = await request.get('/api/v1/csrf-token');
  const body = (await res.json()) as { data: { csrfToken: string } };
  return body.data.csrfToken;
}

// ─── API-Level Auth Helpers ──────────────────────────────────────────────────

/**
 * Creates and returns an authenticated user via the API.
 * Registers, verifies email directly in MongoDB, and logs in.
 * Each call creates a unique user for test isolation.
 */
export async function createAuthenticatedUser(
  request: APIRequestContext,
  overrides?: {
    email?: string;
    authHash?: string;
    encryptedVaultKey?: string;
    vaultKeyIv?: string;
    vaultKeyTag?: string;
  },
): Promise<AuthenticatedUser> {
  const email = overrides?.email ?? testEmail();
  const authHash = overrides?.authHash ?? 'e2e-test-auth-hash';

  // 1. Register
  const regCsrf = await getCsrf(request);
  const regRes = await request.post('/api/v1/auth/register', {
    data: {
      email,
      authHash,
      encryptedVaultKey: overrides?.encryptedVaultKey ?? 'e2e-encrypted-vault-key-data',
      vaultKeyIv: overrides?.vaultKeyIv ?? 'e2e-vault-key-iv',
      vaultKeyTag: overrides?.vaultKeyTag ?? 'e2e-vault-key-tag',
      kdfIterations: 600_000,
      kdfAlgorithm: 'PBKDF2-SHA256',
    },
    headers: {
      'content-type': 'application/json',
      'x-csrf-token': regCsrf,
    },
  });
  expect(regRes.ok()).toBe(true);

  // 2. Verify email directly in MongoDB (uses shared connection)
  const db = await getMongoDb();
  await db.collection('users').updateOne({ email }, { $set: { emailVerified: true } });

  // 3. Login
  const loginCsrf = await getCsrf(request);
  const loginRes = await request.post('/api/v1/auth/login', {
    data: { email, authHash },
    headers: {
      'content-type': 'application/json',
      'x-csrf-token': loginCsrf,
    },
  });
  expect(loginRes.ok()).toBe(true);

  const loginBody = (await loginRes.json()) as {
    success: boolean;
    data: { accessToken: string };
  };

  return { email, authHash, accessToken: loginBody.data.accessToken };
}

// ─── Authenticated Request Helpers ───────────────────────────────────────────

/** Makes an authenticated GET request. */
export async function authGet(request: APIRequestContext, user: AuthenticatedUser, url: string) {
  return request.get(url, {
    headers: { authorization: `Bearer ${user.accessToken}` },
  });
}

/** Makes an authenticated POST/PUT/DELETE request with CSRF. */
export async function authMutate(
  request: APIRequestContext,
  user: AuthenticatedUser,
  method: 'post' | 'put' | 'delete',
  url: string,
  data?: Record<string, unknown>,
) {
  const csrf = await getCsrf(request);
  const headers: Record<string, string> = {
    authorization: `Bearer ${user.accessToken}`,
    'x-csrf-token': csrf,
  };
  if (data) headers['content-type'] = 'application/json';
  return request[method](url, { ...(data ? { data } : {}), headers });
}

// ─── Data Builders ───────────────────────────────────────────────────────────

/** Creates a sample vault item payload for API tests. */
export function sampleVaultItem(overrides: Record<string, unknown> = {}) {
  return {
    itemType: 'login',
    encryptedData: 'e2e-encrypted-data',
    dataIv: 'e2e-data-iv',
    dataTag: 'e2e-data-tag',
    encryptedName: 'e2e-encrypted-name',
    nameIv: 'e2e-name-iv',
    nameTag: 'e2e-name-tag',
    tags: [],
    favorite: false,
    ...overrides,
  };
}

/** Creates a sample folder payload for API tests. */
export function sampleFolder(overrides: Record<string, unknown> = {}) {
  return {
    encryptedName: 'e2e-folder-name',
    nameIv: 'e2e-folder-iv',
    nameTag: 'e2e-folder-tag',
    ...overrides,
  };
}

// ─── Email Generator ─────────────────────────────────────────────────────────

/** Generates a unique test email for E2E test isolation. */
export function testEmail(): string {
  const id = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  return `e2e-${id}@test.hvault.local`;
}

// ─── UI Helpers ──────────────────────────────────────────────────────────────

/** Registers a new account through the UI. */
export async function registerAccount(
  page: Page,
  email?: string,
  password?: string,
): Promise<{ email: string; password: string }> {
  const userEmail = email ?? testEmail();
  const userPassword = password ?? TEST_PASSWORD;

  await page.goto('/register');
  await page.getByLabel(/email/i).fill(userEmail);
  await page.getByLabel(/^master password$/i).fill(userPassword);
  await page.getByLabel(/confirm master password/i).fill(userPassword);
  await page.getByRole('button', { name: /create account|register|sign up/i }).click();

  return { email: userEmail, password: userPassword };
}

/** Logs in through the UI. */
export async function login(page: Page, email: string, password: string): Promise<void> {
  await page.goto('/login');
  await page.getByLabel(/email/i).fill(email);
  await page.getByLabel(/^master password$/i).fill(password);
  await page.getByRole('button', { name: /log in|sign in/i }).click();
}

/** Waits for the vault page to be visible (authenticated state). */
export async function expectVaultVisible(page: Page): Promise<void> {
  await expect(page).toHaveURL(/\/vault/, { timeout: 15_000 });
}

/**
 * Registers a brand-new account and signs in, entirely through the real UI so
 * the browser runs the genuine client-side PBKDF2 key derivation on both the
 * register and login pages (unlike the API-level {@link createAuthenticatedUser}
 * helper). Between the two steps it flips `emailVerified` directly in MongoDB,
 * since the E2E harness sends no verification email.
 *
 * Leaves the page on `/vault` with a fully unlocked, in-memory session (the
 * vault key lives only in memory), ready to navigate to any protected route.
 */
export async function registerAndSignInViaUI(
  page: Page,
  email: string = testEmail(),
  password: string = E2E_STRONG_PASSWORD,
): Promise<{ email: string; password: string }> {
  // Suppress the first-run onboarding modal so its backdrop never intercepts
  // clicks on the vault shell. Runs before every document load in this context.
  await page.addInitScript(() => {
    localStorage.setItem('hvault_onboarding_completed', 'true');
  });

  // 1. Register through the real UI — the client derives authHash via PBKDF2.
  await page.goto('/register');
  await page.getByLabel(/^email$/i).fill(email);
  await page.getByLabel(/^master password$/i).fill(password);
  await page.getByLabel(/confirm master password/i).fill(password);
  await page.getByRole('checkbox').check();
  await page.getByRole('button', { name: /create account/i }).click();

  // On success the register page navigates to /login.
  await expect(page).toHaveURL(/\/login/, { timeout: 30_000 });

  // 2. Verify the email server-side (no SMTP in E2E).
  await markEmailVerified(email);

  // 3. Sign in through the real UI — the client re-derives the same authHash.
  await page.getByLabel(/^email$/i).fill(email);
  await page.getByLabel(/^master password$/i).fill(password);
  await page.getByRole('button', { name: /sign in/i }).click();

  await expect(page).toHaveURL(/\/vault/, { timeout: 30_000 });

  return { email, password };
}

/**
 * Navigates to the File Encryption tool via the sidebar link (client-side SPA
 * navigation, preserving the in-memory session) and waits for the lazily-loaded
 * Encrypt panel to mount. Call after {@link registerAndSignInViaUI}.
 */
export async function gotoFileEncryptionTool(page: Page): Promise<void> {
  await page.getByRole('link', { name: /file encryption/i }).click();
  await expect(page).toHaveURL(/\/tools\/file-encryption/);
  await expect(page.locator('#file-encrypt-input')).toBeVisible({ timeout: 20_000 });
}

/** Locks the vault via keyboard shortcut. */
export async function lockVault(page: Page): Promise<void> {
  await page.keyboard.press('Control+l');
}

/** Unlocks the vault via the unlock screen. */
export async function unlockVault(page: Page, password: string): Promise<void> {
  await page.getByLabel(/master password/i).fill(password);
  await page.getByRole('button', { name: /unlock/i }).click();
}

/** Navigates to settings page. */
export async function goToSettings(page: Page): Promise<void> {
  await page.goto('/settings');
  await expect(page).toHaveURL(/\/settings/);
}

// ─── Vault Item Helpers ──────────────────────────────────────────────────────

/** Creates a vault item and returns its ID. */
export async function createItem(
  request: APIRequestContext,
  user: AuthenticatedUser,
  overrides: Record<string, unknown> = {},
): Promise<string> {
  const res = await authMutate(
    request,
    user,
    'post',
    '/api/v1/vault/items',
    sampleVaultItem(overrides),
  );
  expect(res.ok()).toBe(true);
  const body = (await res.json()) as { data: { _id: string } };
  return body.data._id;
}

/** Creates a folder and returns its ID. */
export async function createFolder(
  request: APIRequestContext,
  user: AuthenticatedUser,
  overrides: Record<string, unknown> = {},
): Promise<string> {
  const res = await authMutate(request, user, 'post', '/api/v1/folders', sampleFolder(overrides));
  expect(res.ok()).toBe(true);
  const body = (await res.json()) as { data: { _id: string } };
  return body.data._id;
}
