import { test, expect, type APIRequestContext, type Page } from '@playwright/test';
import * as OTPAuth from 'otpauth';
import {
  authMutate,
  getCsrf,
  registerAndSignInViaUI,
  testEmail,
  E2E_STRONG_PASSWORD,
  type AuthenticatedUser,
} from './helpers';

/**
 * Remember-me / trusted-device cold-boot E2E.
 *
 * These prove the cross-navigation reality that unit and integration tests
 * cannot: what a real browser does across a full restart.
 *
 *   (a) A 2FA user who checked "Remember me" and completed 2FA once, after a
 *       browser restart (a fresh context that keeps the persistent cookies +
 *       localStorage but — like a real restart — loses sessionStorage, and with
 *       it the per-session key that decrypts the persisted auth blob), lands on
 *       the Unlock screen (master password only) with NO 2FA prompt and is NOT
 *       bounced to /login. The vault key is never persisted; it is re-derived on
 *       unlock.
 *   (c) A user who did NOT check "Remember me" lands back on /login after the
 *       same restart — the mere presence of a live refresh cookie must not
 *       silently resurrect the session without the opt-in hint.
 *
 * A Playwright context restarted from `context.storageState()` restores cookies
 * and localStorage but not sessionStorage, which is exactly the persistence
 * boundary a real browser restart crosses — see stores/encryptedStorage.ts.
 */

// ─── Helpers ──────────────────────────────────────────────────────────────

/** Builds a TOTP generator matching the server's parameters (see two-factor.spec.ts). */
function createTOTP(secret: string): OTPAuth.TOTP {
  return new OTPAuth.TOTP({
    issuer: 'H-Vault',
    label: 'test',
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: OTPAuth.Secret.fromBase32(secret),
  });
}

/** Logs in at the API level with an already-derived auth hash, returning an access token. */
async function apiLogin(
  request: APIRequestContext,
  email: string,
  authHash: string,
): Promise<AuthenticatedUser> {
  const csrf = await getCsrf(request);
  const res = await request.post('/api/v1/auth/login', {
    data: { email, authHash },
    headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
  });
  expect(res.ok()).toBe(true);
  const body = (await res.json()) as { data: { accessToken: string } };
  return { email, authHash, accessToken: body.data.accessToken };
}

/** Enables 2FA on an account via the API and returns its backup codes. */
async function enable2fa(
  request: APIRequestContext,
  user: AuthenticatedUser,
): Promise<{ backupCodes: string[] }> {
  const setupRes = await authMutate(request, user, 'post', '/api/v1/user/2fa/setup', {
    password: user.authHash,
  });
  expect(setupRes.ok()).toBe(true);
  const secret = ((await setupRes.json()) as { data: { secret: string } }).data.secret;

  const totp = createTOTP(secret);
  const verifyRes = await authMutate(request, user, 'post', '/api/v1/user/2fa/verify', {
    code: totp.generate(),
  });
  expect(verifyRes.ok()).toBe(true);
  const backupCodes = ((await verifyRes.json()) as { data: { backupCodes: string[] } }).data
    .backupCodes;
  expect(backupCodes.length).toBeGreaterThan(0);
  return { backupCodes };
}

/**
 * Runs `action` while recording the `authHash` the client sends to `/auth/login`.
 *
 * The full-UI sign-in derives the auth hash from the master password with real
 * PBKDF2; the test never knows it otherwise, and it is needed to drive the 2FA
 * setup API for an account that was created through the real registration page
 * (so its stored auth hash genuinely matches the master password).
 */
async function captureLoginAuthHash(page: Page, action: () => Promise<void>): Promise<string> {
  let authHash: string | undefined;
  const handler = (req: import('@playwright/test').Request): void => {
    if (req.method() !== 'POST') return;
    if (!/\/auth\/login$/.test(new URL(req.url()).pathname)) return;
    try {
      const body = JSON.parse(req.postData() ?? '{}') as { authHash?: unknown };
      if (typeof body.authHash === 'string') authHash = body.authHash;
    } catch {
      // Not JSON — ignore.
    }
  };
  page.on('request', handler);
  try {
    await action();
  } finally {
    page.off('request', handler);
  }
  if (!authHash) throw new Error('did not observe an authHash on POST /auth/login');
  return authHash;
}

/** Suppresses the first-run onboarding modal for every document load in a context's page. */
async function suppressOnboarding(page: Page): Promise<void> {
  await page.addInitScript(() => {
    localStorage.setItem('hvault_onboarding_completed', 'true');
  });
}

// ─── (a) Remember-me 2FA cold boot ─────────────────────────────────────────

test.describe('Remember-me cold boot (2FA)', () => {
  test('a remembered 2FA login resumes to the Unlock screen after a browser restart, with no 2FA prompt', async ({
    browser,
    request,
  }, testInfo) => {
    testInfo.setTimeout(150_000);

    const email = testEmail();
    const password = E2E_STRONG_PASSWORD;

    // 1. Register through the real UI so the stored auth hash matches the master
    //    password, capturing that auth hash from the login request.
    const setupContext = await browser.newContext();
    const setupPage = await setupContext.newPage();
    await suppressOnboarding(setupPage);
    const authHash = await captureLoginAuthHash(setupPage, () =>
      registerAndSignInViaUI(setupPage, email, password),
    );
    await setupContext.close();

    // 2. Enable 2FA on that account via the API (no 2FA challenge yet).
    const apiUser = await apiLogin(request, email, authHash);
    const { backupCodes } = await enable2fa(request, apiUser);

    // 3. Fresh browser session: log in with "Remember me" checked and clear the
    //    2FA challenge (a backup code — a plain input, sturdier than the OTP
    //    boxes, and it grants the trusted device just the same).
    const liveContext = await browser.newContext();
    const livePage = await liveContext.newPage();
    await suppressOnboarding(livePage);

    await livePage.goto('/login');
    await livePage.getByLabel(/^email$/i).fill(email);
    await livePage.getByLabel(/^master password$/i).fill(password);
    await livePage.getByLabel('Remember me on this device').check();
    await livePage.getByRole('button', { name: /sign in/i }).click();

    await expect(livePage.getByText('Two-Factor Authentication')).toBeVisible({ timeout: 30_000 });
    await livePage.getByRole('button', { name: 'Use a backup code' }).click();
    await livePage.getByLabel('Backup Code').fill(backupCodes[0] ?? '');
    await livePage.getByRole('button', { name: 'Verify' }).click();
    await expect(livePage).toHaveURL(/\/vault/, { timeout: 30_000 });

    // The opt-in hint is the only thing that arms cold-start resume.
    const rememberHint = await livePage.evaluate(() => localStorage.getItem('__hv_remember'));
    expect(rememberHint).toBe('1');

    // 4. Snapshot the persistent state and simulate a full restart: a NEW context
    //    seeded with the cookies + localStorage but NOT sessionStorage.
    const restartedState = await liveContext.storageState();
    await liveContext.close();

    const restartedContext = await browser.newContext({ storageState: restartedState });
    const restartedPage = await restartedContext.newPage();
    await suppressOnboarding(restartedPage);

    // The persisted auth blob is undecryptable now (its sessionStorage key is
    // gone), so nothing rehydrates — resume must re-establish the session from
    // the refresh cookie and stop at the locked vault.
    await restartedPage.goto('/vault');

    await expect(restartedPage.getByText('Vault Locked')).toBeVisible({ timeout: 30_000 });
    await expect(restartedPage.getByRole('button', { name: 'Unlock Vault' })).toBeVisible();

    // No second factor is demanded on resume…
    await expect(restartedPage.getByText('Two-Factor Authentication')).toHaveCount(0);
    await expect(restartedPage.getByLabel('Backup Code')).toHaveCount(0);
    // …and it is the Unlock screen, not the login screen (no email field).
    await expect(restartedPage.getByLabel(/^email$/i)).toHaveCount(0);
    await expect(restartedPage).not.toHaveURL(/\/login/);

    // The vault key was never persisted anywhere — the restart proves it: the
    // master password is required to go further.
    const persisted = await restartedPage.evaluate(() => ({
      local: JSON.stringify(localStorage),
      session: JSON.stringify(sessionStorage),
    }));
    expect(persisted.session).not.toContain('vaultKey');
    expect(persisted.local).not.toContain(password);

    await restartedContext.close();
  });
});

// ─── (c) Not-remembered login does NOT resume ──────────────────────────────

test.describe('Non-remembered login after restart', () => {
  test('a login without "Remember me" lands back on /login after a browser restart', async ({
    browser,
  }, testInfo) => {
    testInfo.setTimeout(120_000);

    // Register + sign in through the real UI WITHOUT checking remember-me. The
    // helper never touches the checkbox, so `login(rememberMe=false)` runs and
    // actively removes any cold-start hint.
    const liveContext = await browser.newContext();
    const livePage = await liveContext.newPage();
    const { password } = await registerAndSignInViaUI(livePage);

    const rememberHint = await livePage.evaluate(() => localStorage.getItem('__hv_remember'));
    expect(rememberHint).toBeNull();

    // Simulate the restart from the persistent state (cookies + localStorage,
    // no sessionStorage). A valid refresh cookie is present, but with no hint
    // the app must not silently resume.
    const restartedState = await liveContext.storageState();
    await liveContext.close();

    const restartedContext = await browser.newContext({ storageState: restartedState });
    const restartedPage = await restartedContext.newPage();
    await restartedPage.goto('/vault');

    await expect(restartedPage).toHaveURL(/\/login/, { timeout: 30_000 });
    await expect(restartedPage.getByLabel(/^email$/i)).toBeVisible();
    await expect(restartedPage.getByRole('button', { name: /sign in/i })).toBeVisible();
    // The vault is not reachable and no unlock screen is shown.
    await expect(restartedPage.getByText('Vault Locked')).toHaveCount(0);

    // No plaintext master password leaked into persistent storage.
    const persisted = await restartedPage.evaluate(() => JSON.stringify(localStorage));
    expect(persisted).not.toContain(password);

    await restartedContext.close();
  });
});
