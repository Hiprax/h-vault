/**
 * The release notes in a real browser, against the real server: the version in
 * the sidebar, "What's new" opening by itself exactly once for an account that is
 * behind, never for a new account, the preference that turns that off, the
 * administrators' notice about a newer release, and the dial's motion honouring
 * a request for reduced motion.
 *
 * The notice is driven through a stubbed `/releases/status` answer: the E2E server
 * runs with `UPDATE_CHECK_ENABLED=false` and never contacts GitHub, so "a newer
 * release exists" can only be staged. Everything else is the real stack.
 */
import { test, expect, type Page } from '@playwright/test';
import {
  expectVaultVisible,
  lockViaUi,
  registerAndSignInViaUI,
  testDb,
  unlockVault,
} from './helpers';

/** Every test here signs in (two derivations) and most lock and unlock again. */
const RELEASE_NOTES_TEST_TIMEOUT_MS = 420_000;

const versionBadge = (page: Page) => page.getByRole('button', { name: /^H-Vault \d+\.\d+\.\d+\./ });
const whatsNew = (page: Page) => page.getByRole('dialog', { name: /What's new in H-Vault/ });

/** The version the server runs, as the sidebar badge states it. */
async function runningVersion(page: Page): Promise<string> {
  await expect(versionBadge(page)).toBeVisible();
  const name = (await versionBadge(page).getAttribute('aria-label')) ?? '';
  const match = /^H-Vault (\d+\.\d+\.\d+)\./.exec(name);
  expect(match, name).not.toBeNull();
  return match![1]!;
}

async function setUser(email: string, fields: Record<string, unknown>): Promise<void> {
  const db = await testDb();
  const result = await db.collection('users').updateOne({ email }, { $set: fields });
  expect(result.matchedCount).toBe(1);
}

async function storedWatermark(email: string): Promise<unknown> {
  const db = await testDb();
  const user = await db.collection('users').findOne({ email });
  return user?.['releaseNotesSeenVersion'];
}

/** Lock and unlock, which re-mounts the app shell exactly as a new visit does. */
async function relock(page: Page, password: string): Promise<void> {
  await lockViaUi(page);
  await unlockVault(page, password);
  await expectVaultVisible(page);
}

test.describe('release notes', () => {
  test.beforeEach(() => {
    test.setTimeout(RELEASE_NOTES_TEST_TIMEOUT_MS);
  });

  test('a new account is not shown the history, but the version in the sidebar opens it', async ({
    page,
  }) => {
    const { email } = await registerAndSignInViaUI(page);
    const version = await runningVersion(page);
    // Registration started the account caught up.
    expect(await storedWatermark(email)).toBe(version);
    await expect(whatsNew(page)).toHaveCount(0);
    await expect(page.getByTestId('release-unseen-dot')).toHaveCount(0);

    await versionBadge(page).click();
    const dialog = whatsNew(page);
    await expect(dialog).toBeVisible();
    await expect(dialog).toHaveAccessibleName(`What's new in H-Vault ${version}`);
    await expect(dialog.getByRole('region', { name: 'Release notes' })).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(whatsNew(page)).toHaveCount(0);

    await page.getByRole('link', { name: 'Settings' }).click();
    await page.getByRole('link', { name: 'About H-Vault' }).click();
    await expect(page.getByRole('heading', { level: 1, name: 'About H-Vault' })).toBeVisible();
    await expect(page.getByRole('heading', { level: 2, name: 'Release history' })).toBeVisible();
    await expect(page.getByRole('article', { name: `Release ${version}` })).toBeVisible();
  });

  test('an account that is behind is shown the notes once, and "Done" records it', async ({
    page,
  }) => {
    const { email, password } = await registerAndSignInViaUI(page);
    const version = await runningVersion(page);
    // As if the account last read the notes long ago.
    await setUser(email, { releaseNotesSeenVersion: '0.0.1' });

    await relock(page, password);
    const dialog = whatsNew(page);
    await expect(dialog).toBeVisible();
    await expect(dialog).toHaveAccessibleDescription(/updates since you last looked\./);

    const saved = page.waitForResponse(
      (response) =>
        response.url().endsWith('/api/v1/releases/seen') && response.request().method() === 'POST',
    );
    await dialog.getByRole('button', { name: 'Done' }).click();
    expect((await saved).status()).toBe(200);
    await expect(whatsNew(page)).toHaveCount(0);
    expect(await storedWatermark(email)).toBe(version);

    // The next visit does not show them again.
    await relock(page, password);
    await expect(versionBadge(page)).toBeVisible();
    await expect(whatsNew(page)).toHaveCount(0);
  });

  test('with the preference off the notes stay closed, and the sidebar still marks them', async ({
    page,
  }) => {
    const { email, password } = await registerAndSignInViaUI(page);
    await setUser(email, { releaseNotesSeenVersion: '0.0.1', 'settings.showReleaseNotes': false });

    await relock(page, password);
    await expect(page.getByTestId('release-unseen-dot')).toBeVisible();
    await expect(whatsNew(page)).toHaveCount(0);
  });

  test('administrators see a newer release until they dismiss it', async ({ page }) => {
    await page.route('**/api/v1/releases/status', async (route) => {
      const response = await route.fetch();
      const body = (await response.json()) as { data: Record<string, unknown> };
      body.data['update'] = {
        state: 'available',
        latestVersion: '99.0.0',
        publishedAt: '2026-10-02T08:00:00.000Z',
        releaseUrl: 'https://github.com/Hiprax/h-vault/releases/tag/v99.0.0',
        lastCheckedAt: '2026-10-02T09:00:00.000Z',
        lastSuccessAt: '2026-10-02T09:00:00.000Z',
        canCheckNow: true,
      };
      await route.fulfill({ response, json: body });
    });
    const { password } = await registerAndSignInViaUI(page);
    await expect(page.getByText('H-Vault 99.0.0 is available.')).toBeVisible();
    await expect(versionBadge(page)).toContainText('New release');

    await page.getByRole('button', { name: 'Dismiss the notice about H-Vault 99.0.0' }).click();
    await expect(page.getByText('H-Vault 99.0.0 is available.')).toHaveCount(0);
    await relock(page, password);
    await expect(versionBadge(page)).toBeVisible();
    await expect(page.getByText('H-Vault 99.0.0 is available.')).toHaveCount(0);
  });

  test('the dial turns into place, and holds still when reduced motion is asked for', async ({
    page,
  }) => {
    await registerAndSignInViaUI(page);
    const animationOf = (selector: string) =>
      page
        .locator(selector)
        .first()
        .evaluate((node) => getComputedStyle(node).animationName);

    await versionBadge(page).click();
    await expect(whatsNew(page)).toBeVisible();
    expect(await animationOf('.release-dial-ring')).toBe('release-dial-turn');
    expect(await animationOf('.release-dial-numerals')).toBe('release-numerals-in');
    await page.keyboard.press('Escape');

    await page.emulateMedia({ reducedMotion: 'reduce' });
    await versionBadge(page).click();
    await expect(whatsNew(page)).toBeVisible();
    expect(await animationOf('.release-dial-ring')).toBe('none');
    expect(await animationOf('.release-dial-numerals')).toBe('none');
  });
});
