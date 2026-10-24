import { test, expect, type Page } from '@playwright/test';
import { registerAndSignInViaUI, unlockVault } from './helpers';

/**
 * An identity with several phone numbers (0.22.0), end to end: typed into the real
 * form, sealed with real Web Crypto, stored, and read back after a full reload and
 * a fresh key derivation, so the numbers can only have come out of ciphertext.
 * Then one is removed, and the rest keep their places.
 *
 * One registration: PBKDF2 at 600k iterations dominates the wall clock, and every
 * rule provable off the browser (bounds, the stored shape, the export) is pinned
 * by `packages/client/tests/identity-phones.test.tsx`.
 */

async function openItem(page: Page, name: string): Promise<void> {
  await page.getByRole('link', { name: 'Vault', exact: true }).click();
  await expect(page).toHaveURL(/\/vault$/);
  await page.getByTestId('vault-item-name').filter({ hasText: name }).click();
  await expect(page).toHaveURL(/\/vault\/[0-9a-f]{24}/);
}

test.describe('identity phone numbers', () => {
  test('keeps three labelled numbers through storage, and the rest after one is removed', async ({
    page,
  }, testInfo) => {
    testInfo.setTimeout(300_000);
    const { password } = await registerAndSignInViaUI(page);

    await page
      .getByRole('button', { name: /^create (new )?item$/i })
      .first()
      .click();
    const dialog = page.getByRole('dialog', { name: /create new vault item/i });
    await dialog.getByRole('tab', { name: 'Identity' }).click();
    await dialog.getByPlaceholder('Item name').fill('Ada');
    await dialog.getByPlaceholder('First name').fill('Ada');
    await dialog.getByPlaceholder('Last name').fill('Lovelace');
    await dialog.getByLabel('Phone 1 label').fill('Work');
    await dialog.getByLabel('Phone 1 number').fill('+44 20 7946 0958');
    await dialog.getByRole('button', { name: '+ Add Phone' }).click();
    await dialog.getByLabel('Phone 2 label').fill('Mobile');
    await dialog.getByLabel('Phone 2 number').fill('07700 900123');
    await dialog.getByRole('button', { name: '+ Add Phone' }).click();
    await dialog.getByLabel('Phone 3 number').fill('555 0100');
    await dialog.getByRole('button', { name: 'Create' }).click();
    await expect(dialog).toBeHidden();

    // Out of ciphertext: a full reload drops every key, and unlocking derives them again.
    await page.reload();
    await unlockVault(page, password);
    await openItem(page, 'Ada');
    await expect(page.getByText('Phone (Work)')).toBeVisible({ timeout: 60_000 });
    await expect(page.getByText('+44 20 7946 0958')).toBeVisible();
    await expect(page.getByText('Phone (Mobile)')).toBeVisible();
    await expect(page.getByText('07700 900123')).toBeVisible();
    await expect(page.getByText('Phone 3', { exact: true })).toBeVisible();
    await expect(page.getByText('555 0100')).toBeVisible();

    // Remove the second number; the third moves up to second place.
    await page.getByRole('button', { name: 'Edit', exact: true }).click();
    await page.getByRole('button', { name: 'Remove phone 2' }).click();
    await page.getByRole('button', { name: 'Update' }).click();
    await expect(page.getByText('Phone 2', { exact: true })).toBeVisible({ timeout: 60_000 });
    await expect(page.getByText('555 0100')).toBeVisible();
    await expect(page.getByText('Phone (Mobile)')).toHaveCount(0);
    await expect(page.getByText('07700 900123')).toHaveCount(0);
    await expect(page.getByText('Phone (Work)')).toBeVisible();
  });
});
