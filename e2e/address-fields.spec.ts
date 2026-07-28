import { test, expect, type Page } from '@playwright/test';
import { registerAndSignInViaUI, unlockVault } from './helpers';

/**
 * An address's second street line and an identity's delivery notes, end to end in a
 * real browser.
 *
 * Two things only this layer can establish:
 *
 * 1. the values make the whole trip through the real form, real Web Crypto and the
 *    server, rather than merely living in component state. Two things prove it: the
 *    backup download is served from the stored ciphertext, and the final assertions run
 *    after a full reload plus a fresh 600k-iteration key derivation.
 * 2. they survive a REAL backup download and restore. That half is proven NEGATIVELY:
 *    the live item is edited to remove both values BEFORE the restore, so afterwards
 *    they can only have come out of the downloaded file.
 * 3. a card's billing address can be filled from an address saved on an identity.
 *    That is folded in here rather than given its own spec because it needs exactly
 *    the fixture this test already builds — an identity with an address, then a card
 *    — and a second spec would cost another registration, i.e. another 600k-iteration
 *    derivation, to assert the same thing. Only this layer can show that the identity
 *    reached the vault STORE (the create dialog refetches on save) and came back
 *    decrypted before anything could be copied out of it.
 *
 * One test and one registration on purpose, matching `login-backup-codes.spec.ts`:
 * PBKDF2 at 600k dominates the wall clock and the suite runs single-worker. Everything
 * provable off the browser (bounds, clamps, the export mapping, the schema strip that
 * keeps delivery notes off a card) is already covered by the jsdom and node suites,
 * and `backup-address-fidelity.test.ts` proves the decrypt-then-re-encrypt invariant
 * that makes the restore lossless in the first place.
 *
 * Locators are `#field-*` ids rather than labels or placeholders: Playwright's
 * getByLabel and getByText are SUBSTRING matchers, so `getByLabel('Street')` would
 * also match "Street 2" and fail strict mode.
 *
 * Navigation is SPA-only (link clicks, never `page.goto`), the same rule
 * `plaintext-export.spec.ts` states: the vault key lives in memory only, so a full
 * document load locks the vault and swaps the whole page for the unlock screen.
 */

/** zxcvbn score >= 3 is required by the backup-encryption setup gate. */
const BACKUP_PASSWORD = 'Bk9-pQ2-vTz7-Lm4-Rx8';
const STREET2 = 'Flat 2, Building C';
const DELIVERY = 'Ring twice, then leave with the concierge';
const CARD_STREET2 = 'Suite 100';

async function openCreateDialog(page: Page) {
  // A freshly registered vault is empty, and in that state VaultList renders only its
  // empty state, so the empty state's own button is the only way in. The alternation
  // keeps this working once items exist and the floating button is mounted.
  await page
    .getByRole('button', { name: /^create (new )?item$/i })
    .first()
    .click();
  const dialog = page.getByRole('dialog', { name: /create new vault item/i });
  await expect(dialog).toBeVisible();
  return dialog;
}

async function openItem(page: Page, name: string): Promise<void> {
  await page.getByRole('link', { name: 'Vault', exact: true }).click();
  await expect(page).toHaveURL(/\/vault$/);
  await page.getByTestId('vault-item-name').filter({ hasText: name }).click();
  await expect(page).toHaveURL(/\/vault\/[0-9a-f]{24}/);
}

/** Settings, then the Backup Settings card. Two link clicks, so the vault stays open. */
async function goToBackupSettings(page: Page): Promise<void> {
  await page.getByRole('link', { name: 'Settings', exact: true }).click();
  await expect(page).toHaveURL(/\/settings$/);
  await page.getByRole('link', { name: 'Backup Settings' }).click();
  await expect(page).toHaveURL(/\/settings\/backup$/);
}

test.describe('address second line, delivery notes and reuse on a card', () => {
  test('reach stored ciphertext and survive a real backup download and restore', async ({
    page,
  }, testInfo) => {
    // Register, sign in, then three separate BEK derivations (setup, download,
    // restore), each 600k iterations of PBKDF2 in the browser.
    testInfo.setTimeout(300_000);
    const { password } = await registerAndSignInViaUI(page);

    // --- An identity carrying both new fields -----------------------------------
    let dialog = await openCreateDialog(page);
    await dialog.getByRole('tab', { name: 'Identity' }).click();
    await dialog.getByPlaceholder('Item name').fill('Home address');
    await dialog.getByPlaceholder('First name').fill('Ada');
    await dialog.getByPlaceholder('Last name').fill('Lovelace');
    await dialog.locator('#field-street').fill('1 Main St');
    await dialog.locator('#field-street2').fill(STREET2);
    await dialog.locator('#field-city').fill('London');
    await dialog.locator('#field-deliveryNotes').fill(DELIVERY);
    await dialog.getByRole('button', { name: 'Create' }).click();
    await expect(dialog).toBeHidden();

    // --- A card whose billing address is FILLED FROM THAT IDENTITY ---------------
    // Filling through the picker rather than typing the fields is what makes this
    // an end-to-end assertion about the feature: the identity has to have made it
    // into the vault store (VaultPage refetches after a create), been decrypted,
    // and been matched by a real search before anything can be copied.
    dialog = await openCreateDialog(page);
    await dialog.getByRole('tab', { name: 'Card' }).click();
    await dialog.getByPlaceholder('Item name').fill('Visa');
    await dialog.getByPlaceholder('Name on card').fill('Ada Lovelace');
    await dialog.getByPlaceholder('1234 5678 9012 3456').fill('4111111111111111');

    await dialog.getByRole('button', { name: 'Use a saved address' }).click();
    // Search by a term that appears only in the address itself, not in the item
    // name — so a match proves the address was read, not just the title.
    await dialog.getByPlaceholder('Search saved addresses').fill('london');
    await dialog.getByRole('option', { name: /Home address/ }).click();

    // The six base fields came across, and the section opened to show them.
    await expect(dialog.locator('#field-billingStreet')).toHaveValue('1 Main St');
    await expect(dialog.locator('#field-billingStreet2')).toHaveValue(STREET2);
    await expect(dialog.locator('#field-billingCity')).toHaveValue('London');
    // Delivery notes are identity-only: there is no control for them on a card,
    // and the value must not have been copied into any of the six.
    await expect(dialog.locator('#field-billingDeliveryNotes')).toHaveCount(0);
    await expect(dialog.getByText(DELIVERY)).toHaveCount(0);

    // The second line is the one part of a billing address that is genuinely
    // card-specific, so override it and keep the rest of the copy.
    await dialog.locator('#field-billingStreet2').fill(CARD_STREET2);
    await dialog.getByRole('button', { name: 'Create' }).click();
    await expect(dialog).toBeHidden();

    // --- Both come back out of ciphertext ---------------------------------------
    await openItem(page, 'Home address');
    await expect(page.getByText(STREET2)).toBeVisible();
    await expect(page.getByText(DELIVERY)).toBeVisible();

    await openItem(page, 'Visa');
    await expect(page.getByText(CARD_STREET2)).toBeVisible();
    // The city arrived via the picker rather than the keyboard, out of stored
    // ciphertext on the way back.
    await expect(page.getByText('London')).toBeVisible();
    // A card has no delivery-notes row: the shared address schema strips the field, so
    // there is nowhere for one to appear even in principle — and the picker never
    // copied the value in the first place.
    await expect(page.getByText(/^delivery notes$/i)).toHaveCount(0);
    await expect(page.getByText(DELIVERY)).toHaveCount(0);

    // --- Configure backup encryption and download a real backup ------------------
    await goToBackupSettings(page);
    await page.locator('#backup-password').fill(BACKUP_PASSWORD);
    await page.locator('#confirm-backup-password').fill(BACKUP_PASSWORD);
    await page.locator('#setup-master-password').fill(password);
    await page.getByRole('button', { name: 'Setup Encryption' }).click();
    // The BEK derivation runs in the browser, so allow for it generously.
    await expect(page.getByText('Backup encryption configured')).toBeVisible({ timeout: 120_000 });
    await expect(page.getByRole('button', { name: 'Download Latest' })).toBeEnabled();

    await page.getByRole('button', { name: 'Download Latest' }).click();
    await page.getByPlaceholder('Backup password').fill(BACKUP_PASSWORD);
    const downloadPromise = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Download', exact: true }).click();
    const backupPath = testInfo.outputPath('vault-backup.enc');
    await (await downloadPromise).saveAs(backupPath);

    // --- Destroy both values on the live item -----------------------------------
    // This is what turns the next step into a proof rather than a coincidence: after
    // this edit, the only copy of either value in existence is inside the file.
    await openItem(page, 'Home address');
    await page.getByRole('button', { name: /^edit$/i }).click();
    await page.locator('#field-street2').fill('');
    await page.locator('#field-deliveryNotes').fill('');
    await page.getByRole('button', { name: 'Update' }).click();
    // Wait for the save to land before navigating: leaving while it is still in flight
    // would let the assertions below run against whichever copy won the race.
    await expect(page.getByText(/item updated/i)).toBeVisible({ timeout: 60_000 });
    await openItem(page, 'Home address');
    await expect(page.getByText(STREET2)).toHaveCount(0);
    await expect(page.getByText(DELIVERY)).toHaveCount(0);

    // --- Restore the downloaded backup over the top -----------------------------
    await goToBackupSettings(page);
    await page.getByRole('button', { name: 'Restore from File' }).click();
    await page.locator('input[type="file"]').setInputFiles(backupPath);
    await page.locator('#restore-password').fill(BACKUP_PASSWORD);
    await page.getByRole('radio', { name: /Overwrite/ }).check();
    await page.getByRole('button', { name: 'Restore', exact: true }).click();
    await expect(page.getByText(/^Backup restored/)).toBeVisible({ timeout: 120_000 });

    // --- Both values are back, out of the backup and nowhere else ----------------
    // A full reload here, unlike everywhere else in this spec, and deliberately: the
    // restore does not refresh the vault store, so without it the assertions below
    // could pass against the STALE decrypted items still held in memory. The reload
    // also forces a fresh key derivation and a fresh fetch, which is what makes this
    // an assertion about stored ciphertext rather than about component state.
    await page.reload();
    await unlockVault(page, password);
    // Unlocking returns to wherever the reload happened (the backup page), not to the
    // vault, so wait for the shell to come back rather than for a URL. The generous
    // timeout covers the 600k-iteration derivation.
    await expect(page.getByRole('link', { name: 'Vault', exact: true })).toBeVisible({
      timeout: 120_000,
    });

    await openItem(page, 'Home address');
    await expect(page.getByText(STREET2)).toBeVisible({ timeout: 30_000 });
    await expect(page.getByText(DELIVERY)).toBeVisible();
    await openItem(page, 'Visa');
    await expect(page.getByText(CARD_STREET2)).toBeVisible();
  });
});
