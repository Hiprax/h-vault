import { test, expect, type Page } from '@playwright/test';
import {
  LOCK_VAULT_LABEL,
  UNLOCK_SUBMIT_LABEL,
  expectVaultVisible,
  lockViaUi,
  registerAndSignInViaUI,
  unlockVault,
  unlockedLayoutMarker,
} from './helpers';

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
 *
 * `lockViaUi` used to live here. It is in `helpers.ts` now, with the locator it
 * is built on, because `zero-knowledge.spec.ts` had written its own copy and
 * both copies used a name matcher that also matches the UNLOCK screen — see
 * `unlockedLayoutMarker` there, and the two assertions in the third test below.
 */

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

/**
 * How far the two backgrounding specs advance the page's clock while the tab is
 * hidden.
 *
 * Two minutes is chosen against three real numbers, not by feel:
 *
 *  - It is FOUR TIMES the old hidden-lock delay of a flat 30 s, and above the
 *    1-minute floor `lockOnHiddenDelay` can be configured to, so any timer that
 *    locks a hidden tab is due and fires during the jump.
 *  - It is under the 5-minute access-token lifetime, so the jump does not turn
 *    an auto-lock test into a token-refresh test.
 *  - It is far under the 15-minute idle timeout, which legitimately locks and
 *    would make a lock here the CORRECT outcome rather than the defect.
 *
 * These specs used to spend 40 s and 10 s of real wall clock waiting this out.
 * `page.clock` jumps it instead, which is both instant and stricter: a real
 * sleep only proves nothing fired within the seconds it was willing to burn.
 */
const HIDDEN_WINDOW = '02:00';

test.describe('auto-lock', () => {
  test('backgrounding the tab does not lock the vault', async ({ page }) => {
    // Installed before sign-in so every timer the app arms is a fake one. Time
    // still flows normally until a jump is requested, so the derivation-bound
    // sign-in below behaves exactly as it does without the clock.
    await page.clock.install();

    await registerAndSignInViaUI(page);
    await expectVaultVisible(page);

    await emulateVisibility(page, 'hidden');

    // Two minutes pass with the tab hidden. `fastForward` fires every due timer,
    // so the old hardcoded 30-second hidden lock would land right here.
    await page.clock.fastForward(HIDDEN_WINDOW);
    await emulateVisibility(page, 'visible');

    // Still open: no unlock screen, and the vault is usable.
    await expect(page.getByText('Vault Locked')).toHaveCount(0);
    await expectVaultVisible(page);
  });

  test('repeated hide/show cycles never accumulate into a lock', async ({ page }) => {
    await page.clock.install();

    await registerAndSignInViaUI(page);
    await expectVaultVisible(page);

    // Four hidden windows of two minutes each. Returning to the tab does NOT
    // reset `lastActivity` (only real input does), so this accumulates just
    // over eight idle minutes — deliberately still inside the 15-minute idle
    // timeout, which would otherwise lock legitimately and prove nothing.
    for (let cycle = 0; cycle < 4; cycle++) {
      await emulateVisibility(page, 'hidden');
      await page.clock.fastForward(HIDDEN_WINDOW);
      await emulateVisibility(page, 'visible');
      await page.clock.fastForward('05');
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

    // The vault is LOCKED here, so the marker every "are we in the vault" check
    // in this suite is built on must be ABSENT. Asserted rather than assumed,
    // because the obvious way to write that marker is not a discriminator at
    // all: Playwright matches a RegExp role-name UNANCHORED, and the unlock
    // screen's submit button is called "Unlock Vault", which `/lock vault/i`
    // matches. `expectVaultVisible` shipped that way — returning immediately on
    // the unlock screen while claiming to prove the opposite — and the
    // four-cycle test below is what paid for it, burning its whole 300 s budget
    // under contention. This line is red against that spelling and green
    // against the exact one.
    await expect(unlockedLayoutMarker(page)).toHaveCount(0);
    // And the collision itself, as a DOM fact rather than a comment, so that a
    // future rename which removes it makes somebody re-read the note instead of
    // quietly making the exactness above look like fussiness. The matcher is
    // BUILT from the same label rather than copied as a regex literal, so it
    // cannot end up asserting about a string nothing renders; and the line under
    // it names which button the loose matcher actually found. Both engines run
    // this file, so both are checked against two accessible-name implementations.
    await expect(page.getByRole('button', { name: new RegExp(LOCK_VAULT_LABEL, 'i') })).toHaveCount(
      1,
    );
    await expect(page.getByRole('button', { name: UNLOCK_SUBMIT_LABEL, exact: true })).toHaveCount(
      1,
    );

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
