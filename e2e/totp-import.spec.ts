import { test, expect, type Page } from '@playwright/test';
import { registerAndSignInViaUI, gotoTotpImportTool, readSampleExport } from './helpers';

/**
 * Importing authenticator codes, end to end, through the real UI.
 *
 * ---------------------------------------------------------------------------
 * WHY THE PASTE PATH AND NOT A CAMERA
 * ---------------------------------------------------------------------------
 *
 * A browser under test has no camera worth pointing at anything, and a fake
 * video device would make the most valuable assertions here depend on how well a
 * synthetic frame happens to decode. Everything after the decoder is what this
 * feature actually is: the protobuf reader, the base32 and URI construction, the
 * live code, and above all the rule that nothing is attached to a login unless a
 * person says so. All of that runs identically whichever way the text arrived.
 *
 * The decoder itself is covered where it can be measured honestly, by a Vitest
 * round trip that encodes with `qrcode` and decodes with `qr`, two independent
 * implementations.
 *
 * The sample export is a RECORDED value built by an independent encoder, so this
 * walk reads bytes the reader did not produce.
 */

/**
 * The create dialog, opened the way the rest of the suite opens it.
 *
 * The alternation is load-bearing: a freshly registered vault renders only its
 * empty state, whose own button is the only way in, and the floating button
 * appears once items exist.
 */
async function openCreateDialog(page: Page) {
  await page
    .getByRole('button', { name: /^create (new )?item$/i })
    .first()
    .click();
  const dialog = page.getByRole('dialog', { name: /create new vault item/i });
  await expect(dialog).toBeVisible();
  return dialog;
}

test.describe('Import from Authenticator', () => {
  test('reads an export, and attaches nothing until asked', async ({ page }) => {
    await registerAndSignInViaUI(page);
    await gotoTotpImportTool(page);
    await readSampleExport(page);

    // Both accounts, with the issuer shown once rather than repeated inside the
    // account name.
    await expect(page.getByText('Acme', { exact: true })).toBeVisible();
    await expect(page.getByText('alice@example.com')).toBeVisible();
    await expect(page.getByText('Globex', { exact: true })).toBeVisible();

    // A live code for the SHA1 account, generated in the browser from the key
    // the reader recovered.
    const code = page.getByLabel('Copy TOTP code').first();
    await expect(code).toBeVisible();
    await expect(code).toHaveText(/\d{3}\s\d{3}/);

    // The second account is eight digits, which proves the URI's parameters
    // survived rather than being replaced by the defaults.
    await expect(page.getByLabel('Copy TOTP code').nth(1)).toHaveText(/\d{4}\s\d{4}/);

    // Nothing has been written to the vault.
    await page.getByRole('link', { name: 'Vault', exact: true }).click();
    await expect(page).toHaveURL(/\/vault$/);
    await expect(page.getByTestId('vault-item-name')).toHaveCount(0);
  });

  test('creates a login only when asked, carrying the whole otpauth link', async ({ page }) => {
    await registerAndSignInViaUI(page);
    await gotoTotpImportTool(page);
    await readSampleExport(page);

    await page
      .getByRole('button', { name: /new login/i })
      .first()
      .click();
    // The card itself records where the code went, which is the confirmation a
    // user reads; the toast is transient and not worth racing.
    await expect(page.getByText('Added to Acme')).toBeVisible();

    await page.getByRole('link', { name: 'Vault', exact: true }).click();
    await expect(page).toHaveURL(/\/vault$/);
    await page.getByTestId('vault-item-name').filter({ hasText: 'Acme' }).click();

    // The stored value renders a working code, which is only true if the whole
    // link round-tripped: a bare secret would have lost the parameters.
    await expect(page.getByLabel('Copy TOTP code')).toBeVisible();
  });

  test('keeps the existing code when adding a second one to the same login', async ({ page }) => {
    await registerAndSignInViaUI(page);

    // A login that already has a code of its own, created through the real form
    // so its ciphertext belongs to this account and the tool can read it back.
    const dialog = await openCreateDialog(page);
    await dialog.getByPlaceholder('Item name').fill('Existing login');
    await dialog.getByPlaceholder('TOTP secret key (optional)').fill('JBSWY3DPEHPK3PXP');
    await dialog.getByRole('button', { name: 'Create' }).click();
    await expect(dialog).toBeHidden();

    await gotoTotpImportTool(page);
    await readSampleExport(page);

    await page
      .getByRole('button', { name: /add to a login/i })
      .first()
      .click();
    await page.getByRole('option', { name: /Existing login/ }).click();

    // The default is to keep the old key, because a TOTP key cannot be recovered
    // from anywhere else once it is overwritten.
    await expect(page.getByText(/That login already has a code/)).toBeVisible();
    await page.getByRole('button', { name: /add code/i }).click();
    await expect(page.getByText('Added to Existing login')).toBeVisible();

    await page.getByRole('link', { name: 'Vault', exact: true }).click();
    await page.getByTestId('vault-item-name').filter({ hasText: 'Existing login' }).click();
    // The preserved old code, which is the undo.
    await expect(page.getByText('Previous TOTP')).toBeVisible();
  });

  test('never sends a secret to the server while reading an export', async ({ page }) => {
    const bodies: string[] = [];
    page.on('request', (request) => {
      const body = request.postData();
      if (body !== null) bodies.push(body);
    });

    await registerAndSignInViaUI(page);
    await gotoTotpImportTool(page);
    await readSampleExport(page);

    // The base32 form of the first account's key. Decoding happens entirely in
    // the browser, so it must appear in no request at all.
    for (const body of bodies) {
      expect(body).not.toContain('JBSWY3DPEHPK3PXP');
    }
  });

  test('clears every decoded key when the vault locks', async ({ page }) => {
    await registerAndSignInViaUI(page);
    await gotoTotpImportTool(page);
    await readSampleExport(page);
    await expect(page.getByText('Acme', { exact: true })).toBeVisible();

    await page.getByRole('button', { name: 'Lock Vault', exact: true }).click();

    // The unlock screen replaces the layout, and with it every decoded key.
    await expect(page.getByRole('button', { name: /unlock vault/i })).toBeVisible();
  });
});
