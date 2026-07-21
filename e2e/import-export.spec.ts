import { test, expect, type Page } from '@playwright/test';
import { registerAndSignInViaUI } from './helpers';

/**
 * End-to-end proof of the zero-knowledge import pipeline: a real browser parses
 * an external export, encrypts every item with the in-memory vault key, and the
 * server stores already-encrypted rows. The items then round-trip back out and
 * render DECRYPTED in the vault — proving parse → encrypt → store → fetch →
 * decrypt → display all work together. No plaintext ever reaches the server.
 */

const IMPORT_PANEL_PLACEHOLDER = 'Paste exported data here...';

// Navigate via the in-app sidebar links (client-side SPA navigation) rather than
// page.goto — a full reload would drop the in-memory vault key and lock the vault.
async function openImportPanel(page: Page): Promise<void> {
  await page.getByRole('link', { name: 'Settings' }).click();
  await expect(page).toHaveURL(/\/settings/);
  await page.getByRole('button', { name: 'Import Vault' }).click();
  await expect(page.getByPlaceholder(IMPORT_PANEL_PLACEHOLDER)).toBeVisible();
}

async function goToVault(page: Page): Promise<void> {
  await page.getByRole('link', { name: 'Vault', exact: true }).click();
  await expect(page).toHaveURL(/\/vault$/);
}

/** Selects the import format by its value (the format <select> is the only one with these options). */
async function selectFormat(page: Page, value: string): Promise<void> {
  const select = page.locator('select').filter({ has: page.locator(`option[value="${value}"]`) });
  await select.selectOption(value);
}

async function runImport(page: Page): Promise<void> {
  await page.getByRole('button', { name: 'Import', exact: true }).click();
}

test.describe('Vault import — external formats (zero-knowledge, end-to-end)', () => {
  test('imports a Firefox CSV and shows the decrypted logins in the vault', async ({ page }) => {
    await registerAndSignInViaUI(page);
    await openImportPanel(page);
    await selectFormat(page, 'firefox');

    const firefoxCsv = [
      'url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged',
      'https://accounts.google.com/signin,alice@example.com,SuperSecret1!,,https://accounts.google.com,{g1},1,2,3',
      'https://github.com/login,octocat,Corr3ctHorse!,,https://github.com,{g2},1,2,3',
    ].join('\n');

    // Capture what actually goes over the wire. The zero-knowledge claim in this
    // file's header is only worth making if something asserts it: record every
    // /tools/import request body and prove no plaintext credential appears in it.
    const importBodies: string[] = [];
    page.on('request', (req) => {
      if (req.method() === 'POST' && req.url().includes('/tools/import')) {
        importBodies.push(req.postData() ?? '');
      }
    });

    await page.getByPlaceholder(IMPORT_PANEL_PLACEHOLDER).fill(firefoxCsv);
    await runImport(page);

    // Success toast (the panel closes on success).
    await expect(page.getByText(/Imported 2 items/i)).toBeVisible({ timeout: 20_000 });

    // The request was made, and it carried ciphertext only — no password, no
    // username, no URL from the source file survives in the payload.
    expect(importBodies.length).toBeGreaterThan(0);
    const wire = importBodies.join('\n');
    expect(wire).not.toContain('SuperSecret1!');
    expect(wire).not.toContain('Corr3ctHorse!');
    expect(wire).not.toContain('alice@example.com');
    expect(wire).not.toContain('octocat');
    expect(wire).not.toContain('accounts.google.com');

    // The names are derived from the URL host and render decrypted in the vault.
    await goToVault(page);
    await expect(page.getByText('accounts.google.com')).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText('github.com')).toBeVisible();
  });

  test('imports a Bitwarden JSON export (login + secure note) and shows them decrypted', async ({
    page,
  }) => {
    await registerAndSignInViaUI(page);
    await openImportPanel(page);
    await selectFormat(page, 'bitwarden');

    const bitwardenJson = JSON.stringify({
      folders: [{ id: 'f1', name: 'Work' }],
      items: [
        {
          type: 1,
          name: 'My GitHub',
          folderId: 'f1',
          login: {
            username: 'octocat',
            password: 'Tr0ub4dour&3',
            uris: [{ uri: 'https://github.com' }],
          },
        },
        { type: 2, name: 'Recovery Codes', notes: 'one two three' },
      ],
    });

    await page.getByPlaceholder(IMPORT_PANEL_PLACEHOLDER).fill(bitwardenJson);
    await runImport(page);

    await expect(page.getByText(/Imported 2 items/i)).toBeVisible({ timeout: 20_000 });

    await goToVault(page);
    await expect(page.getByText('My GitHub')).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText('Recovery Codes')).toBeVisible();
  });
});
