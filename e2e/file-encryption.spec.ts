import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { registerAndSignInViaUI, gotoFileEncryptionTool } from './helpers';

/**
 * File Encryption tool E2E tests (real Chromium).
 *
 * Proves the standalone, account-agnostic File Encryption tool works end-to-end
 * through the actual UI: a user authenticates, encrypts a small fixture in the
 * browser, downloads the `.enc` container, re-uploads it, decrypts it, and gets
 * back byte-identical output. This is the ONLY test that exercises the genuine
 * browser stack — `hash-wasm` Argon2id compiled from WebAssembly plus the Web
 * Crypto AES-GCM envelope inside `@hiprax/crypto` container mode — driven purely
 * from the real pages (no crypto mocks).
 *
 * Scope note: the E2E harness (`e2e/start-server.ts`) runs the DEV server
 * (`NODE_ENV=development`), where the SPA document that compiles the WASM is
 * served by Vite, which sets NO Content-Security-Policy header. Express only
 * serves `index.html` (the page the Helmet CSP governs) in production. So this
 * spec does NOT exercise the production CSP and is NOT the `'wasm-unsafe-eval'`
 * regression guard — that guard is the Phase 4 `security-headers.test.ts`
 * (supertest asserting the Helmet header directly). This spec's job is only the
 * real-browser crypto round-trip through the UI.
 */

// A strong file password: clears both `isValidPassword` (>= 20 chars) and the
// zxcvbn score >= 3 gate the encrypt panel enforces.
const FILE_PASSWORD = 'Fj6!nQ3$Vt9#Rp2&Lw7^Zx5';
const WRONG_PASSWORD = 'definitely-not-the-right-one-42';

const FIXTURE_NAME = 'secret-report.bin';
const FIXTURE_MIME = 'application/octet-stream';

/**
 * Deterministic binary fixture spanning every byte value (0-255) so the
 * round-trip genuinely proves binary fidelity, not just text handling.
 */
function makeFixtureBytes(): Buffer {
  const bytes = Buffer.alloc(2048);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = (i * 37 + 13) % 256;
  }
  return bytes;
}

/**
 * Drives the Encrypt panel: sets the file input, fills the password twice, waits
 * for the strength/validity gate to open the submit button, clicks Encrypt, and
 * captures the resulting `.enc` download saved to `savePath`.
 */
async function encryptFixture(
  page: import('@playwright/test').Page,
  original: Buffer,
  savePath: string,
): Promise<Buffer> {
  await page.locator('#file-encrypt-input').setInputFiles({
    name: FIXTURE_NAME,
    mimeType: FIXTURE_MIME,
    buffer: original,
  });
  await page.locator('#file-encrypt-password').fill(FILE_PASSWORD);
  await page.locator('#file-encrypt-confirm').fill(FILE_PASSWORD);

  const encryptButton = page.getByRole('button', { name: /encrypt & download/i });
  // Enablement implies the lazy zxcvbn chunk loaded, the score cleared 3, and
  // `isValidPassword` passed — all in the real browser.
  await expect(encryptButton).toBeEnabled({ timeout: 20_000 });

  const downloadPromise = page.waitForEvent('download');
  await encryptButton.click();
  const download = await downloadPromise;

  expect(download.suggestedFilename()).toBe(`${FIXTURE_NAME}.enc`);
  await download.saveAs(savePath);

  return readFile(savePath);
}

test.describe('File Encryption Tool', () => {
  test('encrypts and decrypts a file back to byte-identical output via the UI', async ({
    page,
  }, testInfo) => {
    // Real-browser Argon2id + two client PBKDF2 derivations (register + login)
    // comfortably exceed the default 30s budget on a cold start.
    test.setTimeout(120_000);

    await registerAndSignInViaUI(page);
    await gotoFileEncryptionTool(page);

    const original = makeFixtureBytes();
    const encPath = testInfo.outputPath('secret-report.bin.enc');
    const encryptedBytes = await encryptFixture(page, original, encPath);

    // Sanity: a genuine `@hiprax/crypto` v2 container (magic "HPCR"), larger than
    // the plaintext, and definitely not the plaintext itself.
    expect(encryptedBytes.subarray(0, 4).toString('latin1')).toBe('HPCR');
    expect(encryptedBytes.length).toBeGreaterThan(original.length);
    expect(encryptedBytes.equals(original)).toBe(false);

    // ── Decrypt: re-upload the `.enc` and recover the original ──────────────
    await page.getByRole('tab', { name: /decrypt/i }).click();
    await expect(page.locator('#file-decrypt-input')).toBeVisible({ timeout: 20_000 });

    await page.locator('#file-decrypt-input').setInputFiles(encPath);
    await page.locator('#file-decrypt-password').fill(FILE_PASSWORD);

    const decryptButton = page.getByRole('button', { name: /decrypt & download/i });
    await expect(decryptButton).toBeEnabled();

    const decDownloadPromise = page.waitForEvent('download');
    await decryptButton.click();
    const decDownload = await decDownloadPromise;

    // The original filename + mime were sealed inside the container and restored.
    expect(decDownload.suggestedFilename()).toBe(FIXTURE_NAME);

    const restoredPath = testInfo.outputPath('restored.bin');
    await decDownload.saveAs(restoredPath);
    const restored = await readFile(restoredPath);

    expect(restored.equals(original)).toBe(true);
  });

  test('shows an error when decrypting with the wrong password', async ({ page }, testInfo) => {
    test.setTimeout(120_000);

    await registerAndSignInViaUI(page);
    await gotoFileEncryptionTool(page);

    const original = makeFixtureBytes();
    const encPath = testInfo.outputPath('wrong-pw.bin.enc');
    await encryptFixture(page, original, encPath);

    await page.getByRole('tab', { name: /decrypt/i }).click();
    await expect(page.locator('#file-decrypt-input')).toBeVisible({ timeout: 20_000 });

    await page.locator('#file-decrypt-input').setInputFiles(encPath);
    await page.locator('#file-decrypt-password').fill(WRONG_PASSWORD);

    const decryptButton = page.getByRole('button', { name: /decrypt & download/i });
    await expect(decryptButton).toBeEnabled();
    await decryptButton.click();

    // Oracle-free failure message shared by wrong-password and tampered files.
    await expect(page.getByText('Incorrect password, or the file is corrupted.')).toBeVisible({
      timeout: 20_000,
    });
  });
});
