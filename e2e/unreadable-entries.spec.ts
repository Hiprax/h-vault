import { test, expect, type Browser, type BrowserContext, type Page } from '@playwright/test';
import {
  createNoteViaUI,
  expectVaultVisible,
  mintResetToken,
  registerAndSignInViaUI,
  signInViaUI,
  submitPasswordReset,
  testDb,
} from './helpers';

/**
 * Entries a master password reset left unreadable: recovered with the backup
 * password, or deleted for good.
 *
 * A reset mints a new vault key and keeps every row, so whatever was sealed
 * before it stays stored, hidden from the vault (nothing opens it) and counted
 * against the storage quota. When backups were set up first, the account still
 * stores a copy of the PREVIOUS key under the backup password, and that copy
 * opens them again; without one, the owner can at least remove them.
 *
 * Each test drives the real browser end to end: register, store entries, reset
 * through a minted link in a second browser, sign in with the new password, and
 * follow the vault banner's Review link to Settings.
 */

/** Sign-ins, resets and the recovery are real 600,000-iteration derivations. */
const TEST_TIMEOUT_MS = 900_000;
const RECOVERY_TIMEOUT_MS = 240_000;
const NOTES = ['Alpha note', 'Beta note'] as const;
const FOLDER = 'Kept folder';
const NEW_NOTE = 'After reset note';
const BACKUP_PASSWORD = 'Bk9!rTz4$Wq7#Mn2&Ld5';
/** A second high-entropy master password that clears the strength gate. */
const NEW_MASTER_PASSWORD = 'Qw7!nBv4$Zx8#Lp2&Mt6';

const openContexts: BrowserContext[] = [];

async function newPage(browser: Browser): Promise<Page> {
  const context = await browser.newContext();
  openContexts.push(context);
  return context.newPage();
}

test.afterEach(async () => {
  await Promise.all(openContexts.splice(0).map((context) => context.close()));
});

async function createFolderViaUI(page: Page, name: string): Promise<void> {
  await page.getByRole('button', { name: 'Create folder' }).click();
  const dialog = page.getByRole('dialog', { name: 'Create new folder' });
  await dialog.getByPlaceholder('Folder name').fill(name);
  await dialog.getByRole('button', { name: 'Create', exact: true }).click();
  await expect(dialog).toBeHidden();
  await expect(page.getByText(name, { exact: true })).toBeVisible();
}

/** Two notes and a folder, sealed under the account's first vault key. */
async function accountWithEntries(page: Page): Promise<{ email: string; password: string }> {
  const account = await registerAndSignInViaUI(page);
  for (const name of NOTES) await createNoteViaUI(page, name);
  await createFolderViaUI(page, FOLDER);
  return account;
}

/** Sets up backup encryption on the Backup page: the account then stores a copy of its key. */
async function setUpBackup(page: Page, masterPassword: string): Promise<void> {
  await page.getByRole('link', { name: 'Settings', exact: true }).click();
  await page.getByRole('link', { name: 'Backup Settings' }).click();
  await expect(page).toHaveURL(/\/settings\/backup$/);
  await page.locator('#backup-password').fill(BACKUP_PASSWORD);
  await page.locator('#confirm-backup-password').fill(BACKUP_PASSWORD);
  await page.locator('#setup-master-password').fill(masterPassword);
  await page.getByRole('button', { name: 'Setup Encryption' }).click();
  await expect(page.getByText('Backup encryption configured')).toBeVisible({
    timeout: 180_000,
  });
}

/**
 * Resets the master password through a minted link in ANOTHER browser, signs in
 * there with the new one, and stores one new entry under the new key.
 */
async function resetAndSignIn(browser: Browser, email: string): Promise<Page> {
  const page = await newPage(browser);
  await page.goto(`/reset-password#token=${await mintResetToken(email)}`);
  await expect(page.getByRole('heading', { name: 'Reset Password' })).toBeVisible({
    timeout: 60_000,
  });
  await submitPasswordReset(page, email, NEW_MASTER_PASSWORD);
  await signInViaUI(page, email, NEW_MASTER_PASSWORD);
  await expectVaultVisible(page);
  await createNoteViaUI(page, NEW_NOTE);
  return page;
}

/**
 * The vault reports what it cannot open and, once the held-key check has proved
 * this session's key is the account's, offers Review; Review opens the Settings
 * card, which checks at once.
 */
async function reviewFromBanner(page: Page): Promise<void> {
  const banner = page.getByTestId('decryption-failure-banner');
  const review = banner.getByRole('link', { name: 'Review', exact: true });
  await expect(review).toBeVisible({ timeout: 60_000 });
  await review.click();
  await expect(page).toHaveURL(/\/settings#unreadable-entries$/);
  await expect(
    page.getByText('3 entries cannot be opened with your current vault key:'),
  ).toBeVisible({ timeout: 120_000 });
}

/** Every named entry is listed in the vault and nothing reports a failure. */
async function expectVaultWhole(page: Page, names: readonly string[]): Promise<void> {
  await page.getByRole('link', { name: 'Vault', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Vault', exact: true, level: 1 })).toBeVisible({
    timeout: 60_000,
  });
  for (const name of names) {
    await expect(page.getByTestId('vault-item-name').filter({ hasText: name })).toBeVisible({
      timeout: 60_000,
    });
  }
  await expect(page.getByTestId('decryption-failure-banner')).toHaveCount(0);
}

/** What the account stores, read from the database itself. */
async function stored(email: string) {
  const db = await testDb();
  const user = await db
    .collection<{
      _id: unknown;
      email: string;
      settings?: { backup?: { bwkEncryptedVaultKey?: string } };
    }>('users')
    .findOne({ email });
  expect(user, `no account for ${email}`).not.toBeNull();
  return {
    copy: user!.settings?.backup?.bwkEncryptedVaultKey,
    items: await db.collection('vault_items').countDocuments({ userId: user!._id }),
    folders: await db.collection('folders').countDocuments({ userId: user!._id }),
  };
}

test.describe('entries a master password reset left unreadable', () => {
  test('are recovered with the backup password, and the backup then holds the current key', async ({
    browser,
  }) => {
    test.setTimeout(TEST_TIMEOUT_MS);
    const first = await newPage(browser);
    const { email, password } = await accountWithEntries(first);
    await setUpBackup(first, password);
    const copyBefore = (await stored(email)).copy;
    expect(copyBefore).toEqual(expect.any(String));

    const page = await resetAndSignIn(browser, email);

    await test.step('the vault offers a review, and the check lists the three lost entries', async () => {
      await reviewFromBanner(page);
      await expect(
        page.getByRole('button', { name: 'Recover with backup password' }),
      ).toBeVisible();
    });

    await test.step('recover them with the backup password', async () => {
      await page.getByRole('button', { name: 'Recover with backup password' }).click();
      const dialog = page.getByRole('dialog', { name: 'Recover Unreadable Entries' });
      await expect(dialog).toBeVisible();
      await dialog.locator('#rotation-password').fill(NEW_MASTER_PASSWORD);
      await dialog.locator('#rotation-backup-password').fill(BACKUP_PASSWORD);
      await dialog.getByRole('button', { name: 'Confirm Recovery' }).click();
      await expect(page.getByText('Recovered 3 unreadable entries')).toBeVisible({
        timeout: RECOVERY_TIMEOUT_MS,
      });
      await expect(page.getByText('Every entry opens with your current key.')).toBeVisible({
        timeout: 120_000,
      });
    });

    await test.step('every entry opens again, and nothing was deleted', async () => {
      await expectVaultWhole(page, [...NOTES, NEW_NOTE]);
      await expect(page.getByText(FOLDER, { exact: true })).toBeVisible();
      await expect
        .poll(async () => stored(email), { timeout: 30_000 })
        .toEqual({ copy: expect.any(String), items: 3, folders: 1 });
      // The backup's copy now holds the CURRENT key, re-sealed after the recovery.
      expect((await stored(email)).copy).not.toBe(copyBefore);
    });
  });

  test('are deleted for good when no backup copy of the earlier key exists', async ({
    browser,
  }) => {
    test.setTimeout(TEST_TIMEOUT_MS);
    const first = await newPage(browser);
    const { email } = await accountWithEntries(first);

    const page = await resetAndSignIn(browser, email);

    await test.step('the check offers no recovery, and says what else may restore them', async () => {
      await reviewFromBanner(page);
      await expect(page.getByRole('button', { name: 'Recover with backup password' })).toHaveCount(
        0,
      );
      await expect(page.getByText(/No backup copy of an earlier key is stored/)).toBeVisible();
    });

    await test.step('delete them with the master password', async () => {
      await page.getByRole('button', { name: 'Delete permanently' }).click();
      const dialog = page.getByRole('dialog', { name: 'Delete Unreadable Entries' });
      await expect(dialog).toBeVisible();
      await dialog.getByLabel('Your master password').fill(NEW_MASTER_PASSWORD);
      await dialog.getByRole('button', { name: 'Delete permanently' }).click();
      await expect(page.getByText('Deleted 3 unreadable entries')).toBeVisible({
        timeout: RECOVERY_TIMEOUT_MS,
      });
      await expect(page.getByText('Every entry opens with your current key.')).toBeVisible({
        timeout: 120_000,
      });
    });

    await test.step('only the entry sealed after the reset remains, and it still opens', async () => {
      await expectVaultWhole(page, [NEW_NOTE]);
      await expect
        .poll(async () => stored(email), { timeout: 30_000 })
        .toEqual({ copy: undefined, items: 1, folders: 0 });
    });
  });
});
