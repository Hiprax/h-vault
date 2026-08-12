import { test, type Page, type APIRequestContext, expect } from '@playwright/test';
import { MongoClient } from 'mongodb';

// ─── Constants ───────────────────────────────────────────────────────────────

const MONGODB_URI = process.env.MONGODB_URI ?? 'mongodb://127.0.0.1:27017/hvault';
export const TEST_PASSWORD = 'E2E-Test-P@ssword-2025!';

/**
 * Budget for a single step that waits on a client-side PBKDF2 key derivation.
 *
 * This number is governed by CPU COST, not by network latency: each register or
 * sign-in step runs a real 600,000-iteration PBKDF2-SHA-256 derivation in the
 * browser (plus server-side bcrypt at 12 rounds on sign-in), and the suite runs
 * `workers: 1` alongside a Vite dev server and an in-memory MongoDB. On a
 * contended machine one derivation alone has been observed past 30 s, which is
 * how the old budget produced intermittent failures in `file-encryption.spec.ts`
 * and `import-export.spec.ts` that passed on a re-run in isolation (the pipeline's
 * `--retries=2` hid them).
 *
 * The two specs failed for DIFFERENT reasons, and it is worth keeping them straight:
 * `file-encryption.spec.ts` already sets its own `test.setTimeout(120_000)`, so for
 * it the binding constraint was this per-assertion budget alone. `import-export.spec.ts`
 * (and `clipboard-hygiene.spec.ts`) set no timeout at all, so for those the test-level
 * floor below is what actually rescues them. Both halves were needed.
 *
 * Do NOT tighten this back towards a "reasonable page-load" number. A derivation
 * that is slow is not a bug the assertion should catch; a genuinely broken sign-in
 * fails on the ASSERTION (wrong URL, visible error), not on the clock.
 */
const PBKDF2_STEP_TIMEOUT_MS = 90_000;

/**
 * Budget for an assertion that gates the FIRST mount of a lazily-loaded route.
 *
 * Bound by Vite's on-demand transform of the route's chunk, not by a key
 * derivation — the same thing `gotoFileEncryptionTool` allows 60 s for. It needs
 * saying because Playwright's default `expect` timeout is 10 s: an unbudgeted
 * gate here would turn every spec that signs in through the UI into a flake on a
 * contended machine, which is the class the constants in this file exist to
 * prevent.
 */
const LAZY_ROUTE_TIMEOUT_MS = 60_000;

/**
 * Floor for the enclosing test's own timeout when a helper performs derivations.
 *
 * Raising {@link PBKDF2_STEP_TIMEOUT_MS} alone would be inert: Playwright's
 * per-test `timeout` (30 s in `playwright.config.ts`) kills the test before a
 * longer assertion budget can ever elapse, so the two must move together. Applied
 * as a FLOOR via `test.info().timeout` rather than a plain `test.setTimeout`,
 * because `setTimeout` SETS the value and an unconditional call here would silently
 * SHORTEN `address-fields.spec.ts`, which asks for 300 s.
 *
 * Note what a floor of 240 s means in the other direction: it RAISES the several
 * specs that ask for 120–150 s of their own. That is intended — those numbers were
 * chosen against the old 30 s assertion budget and are now below what two 90 s
 * derivations can legitimately need. The cost is paid only when something is already
 * wrong: with `workers: 1` and ten call sites, a pathological all-timeout run takes
 * about twice as long to report as it used to.
 *
 * DERIVED from the step budget rather than written as a literal, because the two
 * numbers are not independent: `registerAndSignInViaUI` performs TWO derivations,
 * so a floor below `2 ×` the per-step budget would let the test-level timeout fire
 * first in exactly the contended run the step budget exists for — reintroducing the
 * defect one layer up. The `+ 60 s` covers the non-derivation work in between (the
 * page loads, the direct MongoDB write, and the form fills).
 */
const UI_SIGN_IN_TEST_TIMEOUT_MS = PBKDF2_STEP_TIMEOUT_MS * 2 + 60_000;

/** Raise the current test's timeout to `floor` if it is currently lower. */
function ensureTestTimeoutAtLeast(floor: number): void {
  if (test.info().timeout < floor) test.setTimeout(floor);
}

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
async function markEmailVerified(email: string): Promise<void> {
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

/**
 * Creates one `operations.inserts` entry for `POST /tools/import`.
 *
 * The import contract requires a `searchHash` on every operation — the client
 * recomputes it alongside the encrypted name — so a plain {@link sampleVaultItem}
 * would be rejected by the schema before the endpoint ever runs.
 */
export function sampleImportInsert(overrides: Record<string, unknown> = {}) {
  return { ...sampleVaultItem(), searchHash: 'a'.repeat(64), ...overrides };
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

/**
 * Waits for the vault page to be visible (authenticated state).
 *
 * Derivation-bound: it is normally called straight after a sign-in submit, which
 * runs the full client-side PBKDF2 key derivation in the browser.
 *
 * It raises the test timeout too, for the same reason `registerAndSignInViaUI`
 * does. That is not redundant belt-and-braces: the step budget below is INERT on
 * its own, because Playwright's 30 s per-test timeout fires first, so a caller
 * that reaches this helper by any route other than `registerAndSignInViaUI`
 * would otherwise get an assertion budget that looks generous and is
 * unreachable. One derivation here, so the floor is the single-step budget plus
 * slack.
 */
export async function expectVaultVisible(page: Page): Promise<void> {
  ensureTestTimeoutAtLeast(PBKDF2_STEP_TIMEOUT_MS + 30_000);
  await expect(page).toHaveURL(/\/vault/, { timeout: PBKDF2_STEP_TIMEOUT_MS });
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
 *
 * Costs TWO full PBKDF2 derivations, so it raises the enclosing test's timeout to
 * {@link UI_SIGN_IN_TEST_TIMEOUT_MS} and gives each derivation-bound assertion
 * {@link PBKDF2_STEP_TIMEOUT_MS} — see those constants for why the numbers are
 * what they are and must not be tightened.
 */
export async function registerAndSignInViaUI(
  page: Page,
  email: string = testEmail(),
  password: string = E2E_STRONG_PASSWORD,
): Promise<{ email: string; password: string }> {
  ensureTestTimeoutAtLeast(UI_SIGN_IN_TEST_TIMEOUT_MS);

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

  // On success the register page navigates to /login — after the client has
  // derived the MEK and the auth hash.
  await expect(page).toHaveURL(/\/login/, { timeout: PBKDF2_STEP_TIMEOUT_MS });
  // The URL is NOT enough: every route is `lazy()`, so the address changes as
  // soon as navigation commits and the login chunk mounts some time later. Until
  // it does, the REGISTER page is still in the DOM — and it carries an "Email"
  // label and a "Master Password" label of its own, so the fills below happily
  // land on the page that is about to be unmounted. The observed failure was
  // exactly that, and intermittently: the email went to the register form and
  // was thrown away on the swap, the password (typed a few milliseconds later)
  // reached the real login form, and Sign In failed with "Email is required".
  // `markEmailVerified` below usually hid it by giving the chunk time to load.
  // "Welcome Back" is LoginPage's own heading — the register page's is "Create
  // Account" — so waiting for it is a precise test that the swap has happened.
  await expect(page.getByRole('heading', { name: /welcome back/i })).toBeVisible({
    timeout: LAZY_ROUTE_TIMEOUT_MS,
  });

  // 2. Verify the email server-side (no SMTP in E2E).
  await markEmailVerified(email);

  // 3. Sign in through the real UI — the client re-derives the same authHash.
  await page.getByLabel(/^email$/i).fill(email);
  await page.getByLabel(/^master password$/i).fill(password);
  await page.getByRole('button', { name: /sign in/i }).click();

  // The second derivation, plus server-side bcrypt on the auth hash.
  await expect(page).toHaveURL(/\/vault/, { timeout: PBKDF2_STEP_TIMEOUT_MS });

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
  // Not derivation-bound, but bound by the DEV SERVER: the panel is a lazy chunk,
  // so this is the first request that makes Vite transform it (and `@hiprax/crypto`
  // + hash-wasm) on demand. Same contention as the sign-in steps, different cause.
  await expect(page.locator('#file-encrypt-input')).toBeVisible({
    timeout: LAZY_ROUTE_TIMEOUT_MS,
  });
}

/** Unlocks the vault via the unlock screen. */
export async function unlockVault(page: Page, password: string): Promise<void> {
  await page.getByLabel(/master password/i).fill(password);
  await page.getByRole('button', { name: /unlock/i }).click();
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
