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
}

/**
 * The live countdown the guard drives, e.g. "Clipboard will clear in 27s".
 *
 * `useClipboardCountdown` renders it from `subscribeClipboardGuard`, so it is a
 * direct read-out of the guard's own state: it appears when a secret is pending,
 * re-titles once a second from the deadline, and is DISMISSED the moment the
 * erase is confirmed. That makes it the synchronisation signal these tests need.
 */
function countdownToast(page: Page) {
  return page.getByText(/clipboard will clear in \d+s/i);
}

/**
 * Seconds remaining, or `NaN` when no countdown is on screen.
 *
 * The `count()` guard is load-bearing: `textContent()` auto-waits for its
 * element, so on a DISMISSED toast — exactly the state an unwanted erase
 * produces — it would block until the whole test timed out instead of letting
 * the poll below fail with a message that names the countdown.
 */
async function countdownSeconds(page: Page): Promise<number> {
  const toast = countdownToast(page);
  if ((await toast.count()) === 0) return Number.NaN;
  const text = (await toast.first().textContent()) ?? '';
  const match = /clipboard will clear in (\d+)s/i.exec(text);
  return match?.[1] === undefined ? Number.NaN : Number(match[1]);
}

/**
 * Wait for the guard to make observable progress, and assert the deadline is
 * still running while doing it.
 *
 * This replaces a blind 250 ms `waitForTimeout`. Polling for a countdown STRICTLY
 * BELOW the value seen before the transition proves three things a sleep cannot:
 * the guard's handler has run, at least a full second of its deadline has
 * elapsed, and the deadline was neither cancelled nor restarted. An erase would
 * clear `pending` and dismiss the toast entirely, so the poll fails on the very
 * defect these tests exist for instead of silently racing it.
 */
async function expectCountdownStillTicking(page: Page, below: number): Promise<number> {
  await expect.poll(() => countdownSeconds(page), { timeout: 15_000 }).toBeLessThan(below);
  return countdownSeconds(page);
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

    // The deadline is running and visible to the user.
    await expect(countdownToast(page)).toBeVisible();
    const started = await countdownSeconds(page);
    expect(started).toBeGreaterThan(0);

    // THE regression: the old implementation erased the clipboard right here, so
    // the password the user was on their way to paste was already gone.
    await emulateVisibility(page, 'hidden');
    const whileHidden = await expectCountdownStillTicking(page, started);
    expect(await clipboardWrites(page)).toEqual(afterCopy);

    // Returning must not erase it early either. `focus` is the retry path, so this
    // also pins that the retry is a no-op while nothing is due.
    await emulateVisibility(page, 'visible');
    await page.evaluate(() => {
      window.dispatchEvent(new Event('focus'));
    });
    const afterFocus = await expectCountdownStillTicking(page, whileHidden);
    expect(await clipboardWrites(page)).toEqual(afterCopy);

    // Repeated hide/show cycles, still untouched.
    for (let cycle = 0; cycle < 3; cycle++) {
      await emulateVisibility(page, 'hidden');
      await emulateVisibility(page, 'visible');
    }
    await expectCountdownStillTicking(page, afterFocus);
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
