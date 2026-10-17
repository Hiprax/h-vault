import { createHash, createHmac } from 'node:crypto';
import { test, expect, type Page } from '@playwright/test';
import { ObjectId } from 'mongodb';
import {
  createAuthenticatedUser,
  testDb,
  E2E_STRONG_PASSWORD,
  PBKDF2_STEP_TIMEOUT_MS,
} from './helpers';
import { E2E_JWT_REFRESH_SECRET } from './serverSecrets';

/**
 * One-time links carry their token in the URL FRAGMENT (F-27).
 *
 * A fragment never leaves the browser, so the token is in no request line that
 * either Nginx tier logs and in no `Referer`. The reset page must therefore take
 * it from `location.hash`, remove it from the address bar, and complete the reset
 * exactly as before; for this release a link mailed earlier (`?token=`) must still
 * work, and be stripped the same way.
 *
 * There is no SMTP under E2E, so the spec mints the link the server's mailer would
 * have sent: an HS256 JWT under the server's own purpose key, bound to the
 * account's current credential exactly as `forgotPassword` binds it.
 */

/** `base64url` of a string or buffer. */
function b64url(value: string | Buffer): string {
  return Buffer.from(value).toString('base64url');
}

/** The password-reset token `forgotPassword` would mail for this account right now. */
async function mintResetToken(email: string): Promise<string> {
  const user = await (
    await testDb()
  )
    .collection<{ _id: ObjectId; email: string; authHash: string }>('users')
    .findOne({ email });
  expect(user, `no account for ${email}`).not.toBeNull();
  const key = createHmac('sha256', E2E_JWT_REFRESH_SECRET).update('password_reset').digest('hex');
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = b64url(
    JSON.stringify({
      userId: user!._id.toHexString(),
      purpose: 'password_reset',
      stateHash: createHash('sha256').update(user!.authHash).digest('hex'),
      iat: now,
      exp: now + 3600,
    }),
  );
  const signature = createHmac('sha256', key).update(`${header}.${payload}`).digest('base64url');
  return `${header}.${payload}.${signature}`;
}

/** Fills the reset form with a strong new password and submits it. */
async function resetTo(page: Page, email: string): Promise<void> {
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('New Master Password').fill(E2E_STRONG_PASSWORD);
  await page.getByLabel('Confirm New Password').fill(E2E_STRONG_PASSWORD);
  await page.getByRole('button', { name: /reset password/i }).click();
  await expect(page.getByRole('heading', { name: 'Password Reset Complete' })).toBeVisible({
    timeout: PBKDF2_STEP_TIMEOUT_MS,
  });
}

test.describe('password reset from an emailed link', () => {
  test('completes from a fragment token, which leaves the address bar before the form is used', async ({
    page,
    request,
  }) => {
    const { email } = await createAuthenticatedUser(request);
    const token = await mintResetToken(email);
    const posted: string[] = [];
    const urlsCarryingToken: string[] = [];
    page.on('request', (req) => {
      if (req.url().includes('/api/v1/auth/reset-password')) posted.push(req.postData() ?? '');
      // The property this task exists for: no request LINE ever carries the token,
      // the document request for the page included.
      if (req.url().includes(token)) urlsCarryingToken.push(req.url());
    });

    await test.step('open the link', async () => {
      await page.goto(`/reset-password#token=${token}`);
      await expect(page.getByRole('heading', { name: 'Reset Password' })).toBeVisible({
        timeout: 60_000,
      });
      // Read, then removed: the URL no longer carries the token, in either part.
      await expect(page).toHaveURL(/\/reset-password$/);
      expect(page.url()).not.toContain(token);
    });

    await test.step('reset', async () => {
      await resetTo(page, email);
      // The token reached the server in the POST body, the one place it belongs.
      expect(posted).toHaveLength(1);
      expect(JSON.parse(posted[0]!)).toMatchObject({ token, email });
      expect(urlsCarryingToken).toEqual([]);
    });
  });

  test('still completes from a query token mailed before this release, and strips it', async ({
    page,
    request,
  }) => {
    const { email } = await createAuthenticatedUser(request);
    const token = await mintResetToken(email);

    await page.goto(`/reset-password?token=${token}`);
    await expect(page.getByRole('heading', { name: 'Reset Password' })).toBeVisible({
      timeout: 60_000,
    });
    await expect(page).toHaveURL(/\/reset-password$/);

    await resetTo(page, email);
  });

  test('a link with no token shows the invalid-link state and sends nothing', async ({ page }) => {
    const posted: string[] = [];
    page.on('request', (req) => {
      if (req.url().includes('/api/v1/auth/reset-password')) posted.push(req.url());
    });

    await page.goto('/reset-password');

    await expect(page.getByRole('heading', { name: 'Invalid Link' })).toBeVisible({
      timeout: 60_000,
    });
    await expect(page.getByLabel('New Master Password')).toHaveCount(0);
    expect(posted).toEqual([]);
  });
});
