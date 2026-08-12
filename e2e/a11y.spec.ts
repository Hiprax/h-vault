import { test, expect, type Page } from '@playwright/test';
import {
  describeA11y,
  registerAndSignInViaUI,
  scanA11y,
  writeA11yScans,
  gotoFileEncryptionTool,
  type A11yScan,
} from './helpers';
import { A11Y_VIEWS, A11Y_VIEW_IDS } from './a11yViews';

/**
 * Automated accessibility scanning of every primary view and modal, in the REAL
 * authenticated DOM.
 *
 * ## What this proves, and what it does not
 *
 * axe-core finds roughly a third of the accessibility defects a manual audit
 * would. That number is not a hedge, it is the reason this file is written the
 * way it is: the gate is a FLOOR, not a compliance claim. Nothing here says the
 * application is WCAG 2.1 AA conformant, and nobody should quote it as though it
 * did. What it does say is that no view in the list below carries a serious or
 * critical machine-detectable violation — a control with no accessible name, an
 * input with no label, text below the contrast threshold, a broken ARIA
 * relationship — and that class of defect is exactly what a refactor
 * reintroduces without anyone noticing.
 *
 * The judgements a machine cannot make are pinned separately, by
 * `a11y-keyboard.spec.ts`: whether focus goes somewhere USEFUL, whether a
 * keyboard user can escape a panel, whether the reading order matches the visual
 * one. Neither file substitutes for the other.
 *
 * ## Why it runs here rather than in jsdom
 *
 * Two reasons, and the first alone would be enough. Colour contrast requires
 * layout and computed style: jsdom has neither, so `color-contrast` — the single
 * most common serious violation in any real application — is silently skipped
 * there and reported here. And the interesting views are all BEHIND a sign-in
 * that involves a 600,000-iteration key derivation, a vault key held only in
 * memory, and ciphertext that has to make a round trip; a scan of the logged-out
 * landing page would cover two of the fifteen views below.
 *
 * ## One test, one registration
 *
 * The same trade `address-fields.spec.ts` records: PBKDF2 at 600k dominates the
 * wall clock and the suite runs single-worker, so the whole authenticated walk
 * shares one account. Each view is a `test.step`, and every scan asserts SOFTLY
 * (`expect.soft`) so one failing view does not hide the state of the other
 * fourteen — an accessibility report that stops at the first finding is a report
 * somebody has to run fifteen times.
 */

test.describe('accessibility: every primary view and modal', () => {
  test('has no serious or critical axe violations', async ({ page }, testInfo) => {
    // Two 600k-iteration derivations for the sign-in, then fifteen axe runs over
    // a fully rendered SPA. `registerAndSignInViaUI` raises the timeout to its
    // own floor; this raises it further for the walk that follows.
    testInfo.setTimeout(300_000);

    // Reduced motion, and it is a DETERMINISM pin rather than a preference.
    // Dialogs and the saved-address picker enter with a 200ms `animate-in`
    // (`styles/globals.css`), during which the browser reports BLENDED colours:
    // the picker's summary line measured 3.99:1 mid-fade against 5.01:1 once
    // settled, so a contrast assertion would pass or fail on how fast the
    // machine was. The class carries its own `prefers-reduced-motion` guard, so
    // asking for reduced motion removes the animation rather than working around
    // it — and it is a supported way to use the application, not a fiction.
    await page.emulateMedia({ reducedMotion: 'reduce' });

    const scans: A11yScan[] = [];

    /**
     * Scans the current DOM and records it.
     *
     * Soft, so the walk continues: fourteen more views are worth more than
     * failing fast on the first, and the run still fails at the end.
     */
    const scan = async (view: string): Promise<void> => {
      const result = await scanA11y(page, view);
      scans.push(result);
      expect.soft(result.blocking, describeA11y(result)).toEqual([]);
    };

    try {
      // --- Signed out ---------------------------------------------------------
      await test.step('login', async () => {
        await page.goto('/login');
        await expect(page.getByRole('heading', { name: /welcome back/i })).toBeVisible({
          timeout: 60_000,
        });
        await scan('login');
      });

      await test.step('register', async () => {
        await page.goto('/register');
        await expect(page.getByRole('heading', { name: /create account/i })).toBeVisible({
          timeout: 60_000,
        });
        await scan('register');
      });

      // --- Signed in ----------------------------------------------------------
      await registerAndSignInViaUI(page);

      // The fixture the rest of the walk needs: an identity carrying an address
      // (without one the saved-address picker is not rendered at all, so the
      // view would silently not exist) and a login (so the vault list, the item
      // detail and the health page have real content rather than empty states).
      await createIdentityWithAddress(page);
      await createLogin(page);

      await test.step('vault list', async () => {
        await gotoVault(page);
        await expect(page.getByTestId('vault-item-name').first()).toBeVisible();
        await scan('vault-list');
      });

      await test.step('item detail', async () => {
        await page.getByTestId('vault-item-name').filter({ hasText: 'Router admin' }).click();
        await expect(page).toHaveURL(/\/vault\/[0-9a-f]{24}/);
        // The URL is NOT the readiness signal, for the reason `helpers.ts`
        // records about the login page: `toHaveURL` passes the instant
        // navigation commits, and every route is `lazy()`, so the chunk may not
        // have mounted yet. A scan of a spinner reports zero violations exactly
        // like a scan of a clean page, and the completeness check downstream
        // proves a scan EXISTS per view, never that the view had rendered. Wait
        // for the item's own heading, as the other fourteen steps do.
        await expect(page.getByRole('heading', { name: 'Router admin', level: 1 })).toBeVisible({
          timeout: 60_000,
        });
        await scan('item-detail');
      });

      // --- The create dialog, once, across all five type tabs -----------------
      await test.step('item form', async () => {
        await gotoVault(page);
        const dialog = await openCreateDialog(page);

        await scan('item-form-login');

        for (const [tab, view] of [
          ['Secret', 'item-form-secret'],
          ['Note', 'item-form-note'],
          ['Card', 'item-form-card'],
        ] as const) {
          await dialog.getByRole('tab', { name: tab }).click();
          await scan(view);
        }

        // Still on the Card tab: expand the billing section, then open the
        // saved-address picker inside it. Both are states no other spec scans,
        // and the picker is the one place in the application that implements the
        // ARIA combobox pattern by hand.
        await dialog.getByText('+ Add billing address').click();
        await expect(dialog.locator('#field-billingStreet')).toBeVisible();
        await scan('item-form-card-billing');

        await dialog.getByRole('button', { name: 'Use a saved address' }).click();
        await expect(dialog.getByRole('listbox', { name: 'Saved addresses' })).toBeVisible();
        await scan('item-form-address-picker');
        // Escape closes the panel and only the panel — the behaviour
        // `a11y-keyboard.spec.ts` pins. Here it is simply how the walk gets the
        // dialog back to a plain state before switching tabs.
        await page.keyboard.press('Escape');
        await expect(dialog.getByRole('listbox', { name: 'Saved addresses' })).toBeHidden();

        await dialog.getByRole('tab', { name: 'Identity' }).click();
        await scan('item-form-identity');

        await dialog.getByRole('button', { name: 'Cancel' }).click();
        await expect(dialog).toBeHidden();
      });

      // --- The remaining pages ------------------------------------------------
      await test.step('settings', async () => {
        await page.getByRole('link', { name: 'Settings', exact: true }).click();
        await expect(page).toHaveURL(/\/settings$/);
        await expect(page.getByRole('heading', { name: /^settings$/i })).toBeVisible({
          timeout: 60_000,
        });
        await scan('settings');
      });

      await test.step('vault health', async () => {
        await page.getByRole('link', { name: 'Vault Health', exact: true }).click();
        await expect(page).toHaveURL(/\/vault\/health$/);
        await expect(page.getByRole('heading', { name: 'Vault Health' })).toBeVisible({
          timeout: 60_000,
        });
        // The weak-password check runs in a worker and streams its result in, so
        // the score cards mount before they are populated. Waiting for the score
        // itself keeps the scan off a half-rendered page — a loading skeleton
        // that happens to be clean is not evidence about the finished page.
        await expect(page.getByText('Health Score')).toBeVisible({ timeout: 60_000 });
        await scan('vault-health');
      });

      await test.step('file encryption tool', async () => {
        await gotoFileEncryptionTool(page);
        await scan('file-encryption');
      });

      // Last, because reaching it locks the vault: the key lives in memory only,
      // so everything above is unreachable afterwards without another derivation.
      await test.step('unlock screen', async () => {
        await page.keyboard.press('Control+l');
        await expect(page.getByText('Vault Locked')).toBeVisible({ timeout: 60_000 });
        await scan('unlock-screen');
      });
    } finally {
      // Written even when a scan failed, and that is the point: the gate turns
      // this into `a11y.json`, and a report that only exists on a green run
      // cannot tell anybody WHICH view regressed.
      writeA11yScans('a11y.spec.ts', scans);
    }

    // The completeness check, and it is not bookkeeping. An axe run over nothing
    // reports zero violations, exactly like an axe run over a clean page — so a
    // step that quietly stopped scanning (a renamed heading, a `return` added
    // while debugging, a view deleted from the walk) would leave this gate
    // reporting success about a surface it no longer covers.
    expect(scans.map((entry) => entry.view)).toEqual([...A11Y_VIEW_IDS]);
    expect(A11Y_VIEWS.length).toBe(A11Y_VIEW_IDS.length);
  });
});

// ─── Fixture helpers ─────────────────────────────────────────────────────────

/** Back to the vault list via the sidebar (SPA navigation keeps the vault open). */
async function gotoVault(page: Page): Promise<void> {
  await page.getByRole('link', { name: 'Vault', exact: true }).click();
  await expect(page).toHaveURL(/\/vault$/);
}

/**
 * Opens the create dialog.
 *
 * The alternation is `address-fields.spec.ts`'s: an empty vault renders only the
 * empty state's button, and once items exist the floating one is mounted too.
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

/** An identity with a postal address — the fixture the saved-address picker needs. */
async function createIdentityWithAddress(page: Page): Promise<void> {
  const dialog = await openCreateDialog(page);
  await dialog.getByRole('tab', { name: 'Identity' }).click();
  await dialog.getByPlaceholder('Item name').fill('Home address');
  await dialog.getByPlaceholder('First name').fill('Ada');
  await dialog.getByPlaceholder('Last name').fill('Lovelace');
  await dialog.locator('#field-street').fill('1 Main St');
  await dialog.locator('#field-city').fill('London');
  await dialog.getByRole('button', { name: 'Create' }).click();
  await expect(dialog).toBeHidden();
}

/** A login item, so the list, the detail view and the health checks have content. */
async function createLogin(page: Page): Promise<void> {
  const dialog = await openCreateDialog(page);
  await dialog.getByPlaceholder('Item name').fill('Router admin');
  await dialog.getByPlaceholder('Username or email').fill('ada@example.com');
  await dialog.getByPlaceholder('Password').first().fill('Vb7!qTn3$Zr8# Km2');
  await dialog.getByRole('button', { name: 'Create' }).click();
  await expect(dialog).toBeHidden();
}
