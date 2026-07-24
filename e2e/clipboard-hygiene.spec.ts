import { test, expect, type Page } from '@playwright/test';
import { registerAndSignInViaUI } from './helpers';

/**
 * Clipboard hygiene, in a real browser.
 *
 * This is the layer that can catch the defect these tests exist for: the app used
 * to erase the OS clipboard on every transition to
 * `visibilityState === 'hidden'`, which is exactly the gesture a user makes to go
 * and paste a password. jsdom cannot see it, because it has no real page
 * visibility, no window focus, and a stubbed clipboard.
 *
 * ## Why these assert on writes rather than on clipboard contents
 *
 * Reading the clipboard back was tried first and is unusably flaky here: headless
 * Chromium intermittently reports an empty `readText()` for several seconds after
 * a `writeText()` that already resolved. Asserting on the calls the app makes to
 * `navigator.clipboard.writeText` is deterministic, and it pins the actual
 * invariant more precisely: an erase must not even be ATTEMPTED when the page is
 * merely hidden. An empty string reaching the clipboard is the whole defect, so
 * "no empty-string write happened" is the property worth guarding.
 */

interface ClipboardSpyWindow {
  __hvClipboardWrites?: string[];
}

/**
 * Record every `writeText` the app performs, passing each call through to the real
 * implementation so copying still works. Installed as an init script so it is in
 * place before any application code runs, on every document load.
 */
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

/**
 * Report `visibilityState` as `state` and fire a real `visibilitychange`, which is
 * precisely what the guard's handler reads.
 *
 * Headless Chromium keeps every page "visible" regardless of which one is in
 * front, so `bringToFront()` cannot background a tab here (verified: the
 * backgrounded page still reports `visible`). Overriding the property is the only
 * way to exercise the transition in this harness.
 */
async function emulateVisibility(page: Page, state: 'hidden' | 'visible'): Promise<void> {
  await page.evaluate((value) => {
    Object.defineProperty(document, 'visibilityState', {
      get: () => value,
      configurable: true,
    });
    document.dispatchEvent(new Event('visibilitychange'));
  }, state);
  // Let any handler's async work settle before the spy is inspected.
  await page.waitForTimeout(250);
}

async function copyGeneratedPassword(page: Page): Promise<void> {
  await page.getByRole('link', { name: /password generator/i }).click();
  await expect(page).toHaveURL(/\/generator/);

  const copyButton = page.getByRole('button', { name: 'Copy password' }).first();
  await expect(copyButton).toBeVisible();
  // The first password arrives on a debounced timer; the copy control is disabled
  // until then, so clicking earlier would copy an empty string.
  await expect(copyButton).toBeEnabled();
  await copyButton.click();
  await expect(page.getByText(/password copied to clipboard/i)).toBeVisible();
}

test.describe('clipboard hygiene', () => {
  test('backgrounding the tab never erases a copied password', async ({ context, page }) => {
    await context.grantPermissions(['clipboard-write']);
    await installClipboardSpy(page);
    await registerAndSignInViaUI(page);
    await copyGeneratedPassword(page);

    // The copy itself wrote the secret, and nothing has erased it.
    const afterCopy = await clipboardWrites(page);
    expect(afterCopy).toHaveLength(1);
    expect(afterCopy[0]).not.toBe('');

    // THE regression: the old implementation erased the clipboard right here, so
    // the password the user was on their way to paste was already gone.
    await emulateVisibility(page, 'hidden');
    expect(await clipboardWrites(page)).toEqual(afterCopy);

    // Returning must not erase it early either. `focus` is the retry path, so this
    // also pins that the retry is a no-op while nothing is due.
    await emulateVisibility(page, 'visible');
    await page.evaluate(() => {
      window.dispatchEvent(new Event('focus'));
    });
    await page.waitForTimeout(250);
    expect(await clipboardWrites(page)).toEqual(afterCopy);

    // Repeated hide/show cycles, still untouched.
    for (let cycle = 0; cycle < 3; cycle++) {
      await emulateVisibility(page, 'hidden');
      await emulateVisibility(page, 'visible');
    }
    const writes = await clipboardWrites(page);
    expect(writes).toEqual(afterCopy);
    expect(writes.filter((text) => text === '')).toHaveLength(0);
  });

  test('locking the vault erases a copied password', async ({ context, page }) => {
    await context.grantPermissions(['clipboard-write']);
    await installClipboardSpy(page);
    await registerAndSignInViaUI(page);
    await copyGeneratedPassword(page);
    expect(await clipboardWrites(page)).toHaveLength(1);

    // Ctrl+L locks the vault. The document is focused, so the erase lands.
    await page.keyboard.press('Control+l');
    await expect(page.getByText('Vault Locked')).toBeVisible({ timeout: 30_000 });

    await expect
      .poll(async () => (await clipboardWrites(page)).at(-1), { timeout: 10_000 })
      .toBe('');
  });
});
