import { test, expect, type Page } from '@playwright/test';
import { registerAndSignInViaUI, unlockVault } from './helpers';

/**
 * A login's 2FA backup codes, end to end in a real browser.
 *
 * This is the only layer that can prove the parts jsdom cannot: that a mixed
 * paste reaches the shared parser through the real form, that a copied code lands
 * on the actual OS clipboard as ONE code rather than the whole list, and — the
 * point of the reload below — that the codes were written into real ciphertext and
 * decrypt again after a fresh key derivation.
 *
 * One test and one registration on purpose. `registerAndSignInViaUI` runs PBKDF2
 * at 600k iterations twice, the reload forces a third derivation, and the suite
 * runs single-worker, so registrations dominate the wall clock. Everything that
 * can be proven off the browser (every input format, every error message, the
 * clamps, the CSV mapping) is already covered by the jsdom and node suites.
 *
 * Clipboard writes are asserted through a spy rather than by reading the clipboard
 * back, for the reason `clipboard-hygiene.spec.ts` documents: headless Chromium
 * intermittently reports an empty `readText()` for seconds after a resolved write.
 */

interface ClipboardSpyWindow {
  __hvClipboardWrites?: string[];
}

async function installClipboardSpy(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const spy = window as unknown as ClipboardSpyWindow;
    spy.__hvClipboardWrites = [];
    const original = navigator.clipboard.writeText.bind(navigator.clipboard);
    Object.defineProperty(navigator.clipboard, 'writeText', {
      configurable: true,
      writable: true,
      value: (text: string) => {
        spy.__hvClipboardWrites?.push(text);
        return original(text);
      },
    });
  });
}

function clipboardWrites(page: Page): Promise<string[]> {
  return page.evaluate(() => (window as unknown as ClipboardSpyWindow).__hvClipboardWrites ?? []);
}

/** Obviously fake codes, so the secret scanner has nothing to flag. */
const CODES = ['aaaa-1111', 'bbbb-2222', 'cccc-3333'];

/**
 * Opens a vault item from the list root.
 *
 * Goes through the sidebar link first so the caller never has to know where it
 * currently is; `vault-item-name` is the same handle `import-export.spec.ts`
 * uses, and clicking a row is what proves the item reached the list at all.
 */
async function openItem(page: Page, name: string): Promise<void> {
  await page.getByRole('link', { name: 'Vault', exact: true }).click();
  await expect(page).toHaveURL(/\/vault$/);
  await page.getByTestId('vault-item-name').filter({ hasText: name }).click();
  await expect(page).toHaveURL(/\/vault\/[0-9a-f]{24}/);
}

test.describe('login backup codes', () => {
  test('pasted codes are stored, copied individually, deleted, and survive a reload', async ({
    context,
    page,
  }, testInfo) => {
    // Three PBKDF2 derivations at 600k iterations: register, sign in, unlock.
    testInfo.setTimeout(120_000);
    await context.grantPermissions(['clipboard-write']);
    await installClipboardSpy(page);
    const { password } = await registerAndSignInViaUI(page);

    // --- Create a login with a deliberately mixed-delimiter paste ---------------
    // A freshly registered vault is empty, and in that state `VaultList` returns
    // its empty state and nothing else — the floating "Create new item" button is
    // not mounted at all, so the empty state's own button is the only way in. The
    // alternation keeps this working if the item ever arrives before the click.
    await page
      .getByRole('button', { name: /^create (new )?item$/i })
      .first()
      .click();
    const dialog = page.getByRole('dialog', { name: /create new vault item/i });
    await expect(dialog).toBeVisible();

    await dialog.getByPlaceholder('Item name').fill('GitHub');
    await dialog.getByPlaceholder('Username or email').fill('octocat');
    await dialog.getByPlaceholder('Password').fill('E2E-Item-P@ssword-1');

    await dialog.getByRole('button', { name: '+ Add backup codes' }).click();
    // A space AND a line break in one paste. Auto-detection tries `newline` first
    // (a line break is present), which fails because line 1 holds two codes, then
    // falls through to `space`, which succeeds — so this exercises the fall-through
    // and not just the happy path.
    await dialog
      .getByPlaceholder('Paste your backup codes')
      .fill(`${CODES[0]} ${CODES[1]}\n${CODES[2]}`);
    await expect(dialog.getByText(/3 codes found/)).toBeVisible();
    await dialog.getByRole('button', { name: 'Add codes' }).click();
    // Scoped to the codes list by name: the form renders other lists of its own.
    await expect(
      dialog.getByRole('list', { name: 'Backup codes' }).getByRole('listitem'),
    ).toHaveCount(3);

    await dialog.getByRole('button', { name: 'Create' }).click();
    await expect(dialog).toBeHidden();

    // --- Open the item and check the codes came back ----------------------------
    await openItem(page, 'GitHub');
    const section = page.getByRole('list', { name: 'Backup codes' });
    await expect(section).toBeVisible();
    await expect(section.getByRole('listitem')).toHaveCount(3);
    // Masked: no code text on screen until asked for.
    await expect(page.getByText(CODES[0]!)).toBeHidden();

    // --- Copy ONE code ---------------------------------------------------------
    await page.getByLabel('Copy backup code 2').click();
    await expect(page.getByText(/backup code 2 copied/i)).toBeVisible();
    const writes = await clipboardWrites(page);
    // Exactly the one code, not the whole list: the bug this assertion exists for.
    expect(writes).toEqual([CODES[1]]);

    // --- Copy all, newline-joined ------------------------------------------------
    await page.getByLabel('Copy all backup codes').click();
    await expect(page.getByText(/backup codes copied/i)).toBeVisible();
    expect((await clipboardWrites(page)).at(-1)).toBe(CODES.join('\n'));

    // --- Delete one, which persists immediately ---------------------------------
    await page.getByLabel('Remove backup code 3').click();
    await expect(page.getByText(/backup code 3 removed/i)).toBeVisible();
    await expect(section.getByRole('listitem')).toHaveCount(2);

    // --- Reload, which locks the vault, then unlock -----------------------------
    // The vault key lives only in memory, so this forces a fresh derivation and a
    // real decrypt: it proves the codes reached ciphertext rather than component
    // state.
    await page.reload();
    await unlockVault(page, password);
    // The reload preserved the item's own detail route, so the unlock returns
    // straight to it — no second navigation, and none is possible: while a detail
    // is open the list column is hidden, so there is no row to click.
    const reopened = page.getByRole('list', { name: 'Backup codes' });
    await expect(reopened).toBeVisible({ timeout: 30_000 });
    await expect(reopened.getByRole('listitem')).toHaveCount(2);

    await page.getByRole('button', { name: 'Reveal all' }).click();
    await expect(page.getByText(CODES[0]!)).toBeVisible();
    await expect(page.getByText(CODES[1]!)).toBeVisible();
    // The deleted code is gone for good.
    await expect(page.getByText(CODES[2]!)).toHaveCount(0);
  });
});
