import { test, expect, type Page } from '@playwright/test';
import { registerAndSignInViaUI, unlockVault, expectVaultVisible } from './helpers';

/**
 * Budget for a spec that performs SEVERAL master-password derivations.
 *
 * Every unlock runs PBKDF2 at 600,000 iterations in the browser, which is seconds
 * of real CPU each — so a spec that locks and unlocks four times needs a per-test
 * budget far above Playwright's 30 s default, and above the 120 s that
 * `registerAndSignInViaUI` already claims for the sign-in alone. Do not tighten
 * this: it is bound by key-derivation cost, not by network latency.
 */
const LOCK_CYCLE_TEST_TIMEOUT_MS = 300_000;

/**
 * Auto-lock and unlock, in a real browser.
 *
 * These pin the two halves of a defect that only a real page could show, because
 * both turn on page visibility and on what the app does across it — neither of
 * which jsdom has.
 *
 *  1. Hiding the tab used to arm a lock of `Math.min(30_000, autoLockTimeout / 2)`,
 *     which for any realistic timeout is a flat 30 SECONDS. Switching tabs to look
 *     something up locked the vault, whatever the user had configured.
 *  2. Each surprise lock forced an unlock, and the unlock screen renewed the
 *     session on every attempt and treated ANY failure as an expired session —
 *     signing the user out, revoking a session that had days left, and dropping
 *     them on a login page with no explanation. Together those two produced the
 *     reported symptom: a vault that kept locking, and a login the user could not
 *     complete.
 *
 * Rate limiting cannot be exercised here — the E2E harness runs with
 * `NODE_ENV=development`, where every limiter is a pass-through no-op. The
 * budget-isolation guarantee is asserted against the real, production-configured
 * limiters in `packages/server/tests/auth-limiter-isolation.test.ts`.
 */

/**
 * Lock the vault through the sidebar control, the way a user does.
 *
 * Deliberately NOT the `Ctrl`+`L` keyboard shortcut:
 * `useKeyboardShortcuts` suppresses every shortcut while focus is in an
 * `INPUT`/`TEXTAREA`/`SELECT`, and the vault page holds a focusable search field —
 * so the keypress silently did nothing here and the test failed waiting for a lock
 * screen that was never going to appear. Clicking the real control has no such
 * precondition, and exercises the same `authStore.lock()` path.
 */
async function lockViaUi(page: Page): Promise<void> {
  await page.getByRole('button', { name: /lock vault/i }).click();
}

/**
 * Report `visibilityState` as `state` and fire a real `visibilitychange`.
 *
 * Headless Chromium keeps every page "visible" regardless of which is in front,
 * so `bringToFront()` cannot background a tab here; overriding the property is the
 * only way to exercise the transition in this harness. `document.hidden` is
 * overridden alongside it because `useAutoLock` reads that, not `visibilityState`.
 */
async function emulateVisibility(page: Page, state: 'hidden' | 'visible'): Promise<void> {
  await page.evaluate((value) => {
    Object.defineProperty(document, 'visibilityState', {
      get: () => value,
      configurable: true,
    });
    Object.defineProperty(document, 'hidden', {
      get: () => value === 'hidden',
      configurable: true,
    });
    document.dispatchEvent(new Event('visibilitychange'));
  }, state);
}

test.describe('auto-lock', () => {
  test('backgrounding the tab does not lock the vault', async ({ page }) => {
    await registerAndSignInViaUI(page);
    await expectVaultVisible(page);

    await emulateVisibility(page, 'hidden');

    // Well past the old hardcoded 30-second hidden delay. The configured timeout
    // is 15 minutes, so nothing may lock in this window.
    await page.waitForTimeout(40_000);
    await emulateVisibility(page, 'visible');

    // Still open: no unlock screen, and the vault is usable.
    await expect(page.getByText('Vault Locked')).toHaveCount(0);
    await expectVaultVisible(page);
  });

  test('repeated hide/show cycles never accumulate into a lock', async ({ page }) => {
    await registerAndSignInViaUI(page);
    await expectVaultVisible(page);

    for (let cycle = 0; cycle < 4; cycle++) {
      await emulateVisibility(page, 'hidden');
      await page.waitForTimeout(2_000);
      await emulateVisibility(page, 'visible');
      await page.waitForTimeout(500);
    }

    await expect(page.getByText('Vault Locked')).toHaveCount(0);
    await expectVaultVisible(page);
  });

  test('locking and unlocking keeps you in the vault, never on the login page', async ({
    page,
  }) => {
    test.setTimeout(LOCK_CYCLE_TEST_TIMEOUT_MS);
    const { password } = await registerAndSignInViaUI(page);
    await expectVaultVisible(page);

    await lockViaUi(page);
    await expect(page.getByText('Vault Locked')).toBeVisible({ timeout: 30_000 });

    await unlockVault(page, password);

    // The regression: any hiccup in the unlock screen's session renewal used to
    // land here instead, at /login, with the session already revoked server-side.
    await expectVaultVisible(page);
    await expect(page).not.toHaveURL(/\/login/);
  });

  test('several lock/unlock cycles in a row all succeed', async ({ page }) => {
    // The user's actual report was that this stopped working after a few rounds:
    // each cycle spent two slots of a rate-limit budget shared with logging in,
    // and once it was empty the unlock failed and the forced logout landed on a
    // login page that was itself refused. The budgets are separate now, and each
    // unlock no longer renews the session when the existing token is still good.
    test.setTimeout(LOCK_CYCLE_TEST_TIMEOUT_MS);
    const { password } = await registerAndSignInViaUI(page);
    await expectVaultVisible(page);

    for (let cycle = 0; cycle < 4; cycle++) {
      await lockViaUi(page);
      await expect(page.getByText('Vault Locked')).toBeVisible({ timeout: 30_000 });
      await unlockVault(page, password);
      await expectVaultVisible(page);
      await expect(page).not.toHaveURL(/\/login/);
    }
  });
});
