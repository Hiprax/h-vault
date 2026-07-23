import { test, expect, type Page } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { registerAndSignInViaUI } from './helpers';

/**
 * Portable plaintext-export E2E.
 *
 * Proves the "Leave H-Vault" flow end to end in a real browser: a re-auth gate,
 * an explicit confirmation, and a downloaded plaintext file — while nothing
 * decrypted ever crosses the wire or lands in browser storage.
 *
 *   - The dedicated page decrypts the AUTHORITATIVE server export (ciphertext)
 *     in-browser with the in-memory vault key and hands back a plaintext file
 *     via the download API.
 *   - The downloaded file genuinely contains the seeded credential (so the
 *     export is complete, not silently short) and parses as the chosen format.
 *   - No request the browser makes — the import that seeds the item, or the
 *     `/tools/export` re-auth call — carries the plaintext password or username;
 *     the export request sends only an auth HASH plus audit metadata.
 *   - The plaintext is never written to localStorage or sessionStorage.
 *
 * Navigation is SPA-only (link clicks, never page.goto) so the in-memory vault
 * key survives — a full reload would lock the vault and the export could not
 * decrypt.
 */

const IMPORT_PANEL_PLACEHOLDER = 'Paste exported data here...';
const FIREFOX_CSV_HEADER =
  'url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged';

// A credential whose plaintext must appear ONLY in the downloaded file, never
// on the wire and never in browser storage.
const HOST = 'accounts.google.com';
const USERNAME = 'export-witness@example.com';
const SECRET_PASSWORD = 'Export-Only-Secret-9!x';

interface BitwardenExport {
  folders: { id: string; name: string }[];
  items: {
    type: number;
    name: string;
    login?: { username?: string; password?: string };
  }[];
}

/** Records the URL + body of every request the page issues, for a leak assertion. */
function recordRequests(page: Page): { url: string; body: string }[] {
  const log: { url: string; body: string }[] = [];
  page.on('request', (req) => {
    log.push({ url: req.url(), body: req.postData() ?? '' });
  });
  return log;
}

/** Seeds one decryptable login via the proven zero-knowledge import path. */
async function seedOneLogin(page: Page): Promise<void> {
  await page.getByRole('link', { name: 'Settings', exact: true }).click();
  await expect(page).toHaveURL(/\/settings/);
  await page.getByRole('button', { name: 'Import Vault' }).click();
  await expect(page.getByPlaceholder(IMPORT_PANEL_PLACEHOLDER)).toBeVisible();

  const select = page.locator('select').filter({ has: page.locator('option[value="firefox"]') });
  await select.selectOption('firefox');

  const csv = [
    FIREFOX_CSV_HEADER,
    `https://${HOST}/signin,${USERNAME},${SECRET_PASSWORD},,https://${HOST},{g1},1,2,3`,
  ].join('\n');
  await page.getByPlaceholder(IMPORT_PANEL_PLACEHOLDER).fill(csv);
  await page.getByRole('button', { name: 'Import', exact: true }).click();
  await expect(page.getByText(/Imported 1 item/)).toBeVisible({ timeout: 20_000 });
}

test.describe('Portable plaintext export (zero-knowledge, end-to-end)', () => {
  test('exports a Bitwarden JSON file behind the confirmation without leaking plaintext to the server or storage', async ({
    page,
  }, testInfo) => {
    testInfo.setTimeout(120_000);

    const { password } = await registerAndSignInViaUI(page);

    // Record every request from here on — the import AND the export must both
    // carry ciphertext only.
    const requests = recordRequests(page);

    await seedOneLogin(page);

    // Reach the dedicated, physically-separate export page via its distinct
    // Settings entry-point card (SPA navigation preserves the vault key).
    await page.getByRole('link', { name: 'Settings', exact: true }).click();
    await expect(page).toHaveURL(/\/settings/);
    await page.getByRole('link', { name: /Export to another manager/ }).click();
    await expect(page).toHaveURL(/\/settings\/export-data/);
    await expect(page.getByRole('heading', { name: 'Leave H-Vault' })).toBeVisible();

    // Bitwarden (.json) is the default format. Re-enter the master password and
    // prepare — this is the server-side re-auth gate.
    await page.locator('#export-master-password').fill(password);
    await page.getByRole('button', { name: 'Prepare plaintext export' }).click();

    // The confirmation dialog gates the actual download.
    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible({ timeout: 30_000 });
    await expect(dialog.getByText('Download unencrypted plaintext?')).toBeVisible();

    // Nothing has downloaded yet; the file only materializes on confirm.
    const downloadPromise = page.waitForEvent('download');
    await dialog.getByRole('button', { name: 'Download plaintext file' }).click();
    const download = await downloadPromise;

    // The file carries the real plaintext — proving it was decrypted in-browser
    // and the export is COMPLETE, not silently short.
    const filePath = await download.path();
    expect(filePath).toBeTruthy();
    const content = await readFile(filePath, 'utf8');
    expect(content).toContain(SECRET_PASSWORD);
    expect(content).toContain(USERNAME);

    // …and it parses as Bitwarden JSON with exactly the one seeded item.
    const parsed = JSON.parse(content) as BitwardenExport;
    expect(parsed.items).toHaveLength(1);
    expect(parsed.items[0]?.login?.password).toBe(SECRET_PASSWORD);
    expect(parsed.items[0]?.login?.username).toBe(USERNAME);
    expect(download.suggestedFilename()).toMatch(/\.json$/);

    // The success card reports the result; no items were skipped or omitted.
    await expect(page.getByText('Export complete')).toBeVisible();

    // ZERO-KNOWLEDGE: no request the browser made carried the plaintext.
    const wire = requests.map((r) => `${r.url}\n${r.body}`).join('\n');
    expect(wire).not.toContain(SECRET_PASSWORD);
    expect(wire).not.toContain(USERNAME);

    // The export re-auth call was made and carried only an auth HASH + metadata,
    // never the master password or any decrypted field.
    const exportCalls = requests.filter((r) => r.url.includes('/tools/export'));
    expect(exportCalls.length).toBeGreaterThan(0);
    for (const call of exportCalls) {
      expect(call.body).not.toContain(SECRET_PASSWORD);
      expect(call.body).not.toContain(USERNAME);
      expect(call.body).not.toContain(password);
    }

    // The plaintext was never written to browser storage.
    const storage = await page.evaluate(() => {
      const dump = (s: Storage): Record<string, string> => {
        const out: Record<string, string> = {};
        for (let i = 0; i < s.length; i++) {
          const key = s.key(i);
          if (key) out[key] = s.getItem(key) ?? '';
        }
        return out;
      };
      return JSON.stringify({ local: dump(localStorage), session: dump(sessionStorage) });
    });
    expect(storage).not.toContain(SECRET_PASSWORD);
    expect(storage).not.toContain(USERNAME);
  });
});
