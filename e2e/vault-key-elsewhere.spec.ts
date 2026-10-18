import { test, expect, type Browser, type BrowserContext, type Page } from '@playwright/test';
import {
  createNoteViaUI,
  expectVaultVisible,
  lockViaUi,
  registerAndSignInViaUI,
  signInViaUI,
  unlockVault,
  unlockedLayoutMarker,
} from './helpers';

/**
 * A vault key changed in ONE browser, seen from ANOTHER.
 *
 * The defect these pin: a rotation re-wraps a NEW vault key under the same master
 * key and signs no session out. A browser that was signed in at the time cached
 * the old wrapper at its sign-in, and its unlock re-derived the key from that
 * cache — so after a rotation made elsewhere it unlocked onto the superseded key,
 * every entry failed to decrypt, and the vault read as empty on every visit, a
 * reload included. A rotation whose reply was lost left even the rotating tab in
 * that state. Every test here was RED before the fix; the last two are guards on
 * the actions that were suspected and are not the cause.
 *
 * Two browser contexts are two browsers to the account: each has its own storage,
 * its own session and its own cached wrapper.
 */

/** Rotations, unlocks and sign-ins are all real 600,000-iteration derivations. */
const TEST_TIMEOUT_MS = 600_000;
const ROTATION_TIMEOUT_MS = 180_000;
const NOTES = ['Alpha note', 'Beta note'] as const;

/** A second high-entropy master password that clears the strength gate. */
const NEW_MASTER_PASSWORD = 'Qw7!nBv4$Zx8#Lp2&Mt6';

/** Every context a test opens, closed after it so no page outlives its test. */
const openContexts: BrowserContext[] = [];

async function newPage(browser: Browser): Promise<Page> {
  const context = await browser.newContext();
  openContexts.push(context);
  return context.newPage();
}

test.afterEach(async () => {
  await Promise.all(openContexts.splice(0).map((context) => context.close()));
});

/**
 * Navigates through the sidebar and waits for the PAGE, not just the address.
 *
 * Both pages are lazy routes, and a navigation is a transition: the router keeps
 * the previous page on screen until the next one's chunk has loaded. Returning
 * to the vault before Settings had rendered therefore never unmounted the vault
 * page, so it never fetched again, and a test waiting for that fetch waited for
 * nothing. Each page's own control is the proof it is the one mounted.
 */
async function goTo(
  page: Page,
  link: 'Settings' | 'Vault',
  { awaitPage = true }: { awaitPage?: boolean } = {},
): Promise<void> {
  await page.getByRole('link', { name: link, exact: true }).click();
  await expect(page).toHaveURL(link === 'Settings' ? /\/settings$/ : /\/vault$/);
  // A caller expecting the page to be REPLACED at once (the vault locking itself)
  // waits for what replaces it instead.
  if (!awaitPage) return;
  const mounted =
    link === 'Settings'
      ? page.getByRole('button', { name: 'Rotate Key' })
      : page.getByRole('heading', { name: 'Vault', exact: true, level: 1 });
  await expect(mounted).toBeVisible({ timeout: 60_000 });
}

/** Every note is listed, opened under the key this page holds, and none failed. */
async function expectEveryNoteListed(page: Page): Promise<void> {
  for (const name of NOTES) {
    await expect(page.getByTestId('vault-item-name').filter({ hasText: name })).toBeVisible({
      timeout: 60_000,
    });
  }
  // The banner AppLayout raises for undecryptable rows. It is state of the
  // mounted layout, so a toast left over from before a lock cannot satisfy this.
  await expect(page.getByTestId('decryption-failure-banner')).toHaveCount(0);
}

/** Rotates the vault key through Settings and waits for this page's own success toast. */
async function rotateViaSettings(page: Page, password: string): Promise<void> {
  await goTo(page, 'Settings');
  await page.getByRole('button', { name: 'Rotate Key' }).click();
  await expect(page.getByRole('dialog', { name: 'Rotate Vault Key' })).toBeVisible();
  await page.locator('#rotation-password').fill(password);
  await page.getByRole('button', { name: 'Confirm Rotation' }).click();
  await expect(page.getByText('Vault key rotated successfully')).toBeVisible({
    timeout: ROTATION_TIMEOUT_MS,
  });
  // Gone again before the next rotation, so the next wait is about the next one.
  await expect(page.getByText('Vault key rotated successfully')).toHaveCount(0, {
    timeout: 30_000,
  });
}

/** Two browsers on one account with two notes, both unlocked and listing them. */
async function twoBrowsers(
  browser: Browser,
): Promise<{ a: Page; b: Page; email: string; password: string }> {
  const a = await newPage(browser);
  const { email, password } = await registerAndSignInViaUI(a);
  for (const name of NOTES) await createNoteViaUI(a, name);

  const b = await newPage(browser);
  await signInViaUI(b, email, password);
  await expectEveryNoteListed(b);
  return { a, b, email, password };
}

test.describe('a vault key changed in another browser', () => {
  test('is the key every other browser opens the vault with, whether it unlocks, reloads or stayed open', async ({
    browser,
  }) => {
    test.setTimeout(TEST_TIMEOUT_MS);
    const { a, b, password } = await twoBrowsers(browser);

    await test.step('a browser that was LOCKED during the rotation unlocks onto the new key', async () => {
      await lockViaUi(b);
      await rotateViaSettings(a, password);

      await unlockVault(b, password);
      await expectVaultVisible(b);
      await expectEveryNoteListed(b);
    });

    await test.step('a browser that RELOADS after another rotation unlocks onto the new key', async () => {
      await rotateViaSettings(a, password);

      await b.reload();
      await unlockVault(b, password);
      await expectVaultVisible(b);
      await expectEveryNoteListed(b);
    });

    await test.step('a browser left OPEN through a rotation locks itself, then unlocks onto the new key', async () => {
      await rotateViaSettings(a, password);

      // Its next read of the vault cannot open a row under the key it still holds.
      // Settings must be MOUNTED first (see `goTo`), so the vault page remounts and
      // reads again; that read is expected to lock the page, so only the address is
      // awaited before the notice.
      await goTo(b, 'Settings');
      await goTo(b, 'Vault', { awaitPage: false });
      await expect(
        b.getByText(
          'Your vault key was changed in another session, so this vault locked itself. Unlock to load it with the current key.',
        ),
      ).toBeVisible({ timeout: 60_000 });

      await unlockVault(b, password);
      await expectVaultVisible(b);
      await expectEveryNoteListed(b);
    });
  });

  test('changing the master password elsewhere signs this browser out, and the new one opens every entry', async ({
    browser,
  }) => {
    test.setTimeout(TEST_TIMEOUT_MS);
    const { a, b, email, password } = await twoBrowsers(browser);

    await goTo(a, 'Settings');
    await a.getByRole('button', { name: 'Change', exact: true }).click();
    await a.getByPlaceholder('Current master password').fill(password);
    await a.getByPlaceholder('New master password').fill(NEW_MASTER_PASSWORD);
    await a.getByPlaceholder('Confirm new password').fill(NEW_MASTER_PASSWORD);
    await a.getByRole('button', { name: 'Change Password' }).click();
    await expect(a).toHaveURL(/\/login/, { timeout: ROTATION_TIMEOUT_MS });

    // Every session of the account was revoked: this browser's unlock ends it.
    await b.reload();
    await unlockVault(b, NEW_MASTER_PASSWORD);
    await expect(b).toHaveURL(/\/login/, { timeout: ROTATION_TIMEOUT_MS });

    await signInViaUI(b, email, NEW_MASTER_PASSWORD);
    await expectEveryNoteListed(b);
  });

  test('re-sealing elsewhere leaves every entry readable here, open or unlocked again', async ({
    browser,
  }) => {
    test.setTimeout(TEST_TIMEOUT_MS);
    const { a, b, password } = await twoBrowsers(browser);

    await goTo(a, 'Settings');
    await a.getByRole('button', { name: 'Re-seal', exact: true }).click();
    await expect(a.getByRole('dialog', { name: 'Re-seal Vault Entries' })).toBeVisible();
    await a.locator('#rotation-password').fill(password);
    await a.getByRole('button', { name: 'Confirm Re-seal' }).click();
    await expect(a.getByText('Vault entries re-sealed')).toBeVisible({
      timeout: ROTATION_TIMEOUT_MS,
    });

    await goTo(b, 'Settings');
    await goTo(b, 'Vault');
    await expectEveryNoteListed(b);
    await expect(unlockedLayoutMarker(b)).toBeVisible();

    await lockViaUi(b);
    await unlockVault(b, password);
    await expectVaultVisible(b);
    await expectEveryNoteListed(b);
  });
});

test.describe('a vault key rotation whose reply is lost after the server saved it', () => {
  const LOSSES = [
    ['the connection drops', 'abort'],
    ['a proxy gives up with a 504', 'gateway-timeout'],
  ] as const;

  for (const [loss, kind] of LOSSES) {
    test(`still leaves the rotating page on the new key when ${loss}`, async ({ page }) => {
      test.setTimeout(TEST_TIMEOUT_MS);
      const { password } = await registerAndSignInViaUI(page);
      for (const name of NOTES) await createNoteViaUI(page, name);

      // The request reaches the server and COMMITS; only its answer is lost.
      let committed = 0;
      await page.route('**/api/v1/vault/items/bulk-reencrypt', async (route) => {
        const response = await route.fetch();
        if (response.ok()) committed += 1;
        if (kind === 'abort') await route.abort('failed');
        else await route.fulfill({ status: 504, body: 'Gateway Timeout' });
      });

      await goTo(page, 'Settings');
      await page.getByRole('button', { name: 'Rotate Key' }).click();
      await page.locator('#rotation-password').fill(password);
      await page.getByRole('button', { name: 'Confirm Rotation' }).click();

      await expect(
        page.getByText("The server's reply did not arrive, but the rotation was saved."),
      ).toBeVisible({ timeout: ROTATION_TIMEOUT_MS });
      expect(committed, 'the rotation must have reached the server and committed').toBe(1);
      await expect(page.getByText('Failed to rotate vault key')).toHaveCount(0);

      // Still unlocked, and on the key the server committed.
      await goTo(page, 'Vault');
      await expect(unlockedLayoutMarker(page)).toBeVisible();
      await expectEveryNoteListed(page);
    });
  }
});
