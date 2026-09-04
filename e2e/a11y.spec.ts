import { test, expect, type Page } from '@playwright/test';
import {
  describeA11y,
  documentFixture,
  documentFixtureBytes,
  gotoDocuments,
  openDocument,
  registerAndSignInViaUI,
  renderInSandboxDirectly,
  scanA11y,
  uploadDocument,
  writeA11yScans,
  gotoFileEncryptionTool,
  type A11yScan,
} from './helpers';
import { A11Y_VIEWS, A11Y_VIEW_IDS } from './a11yViews';

/**
 * The document fixtures this walk stores, named here because three steps read
 * them and one of them twice.
 *
 * The PDF is the one whose preview is DECLINED (`PREVIEW_MODES` names `pdf` as
 * `none`), the markdown document is the one that renders inside the frame, and
 * the JSON document is the one the transform panel rewrites so the review state
 * exists to be scanned.
 */
const DOCUMENT_PDF = 'handbook.pdf';
const DOCUMENT_MARKDOWN = 'README.md';
const DOCUMENT_UGLY_JSON = 'ugly.json';

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
 * landing page would cover two of the twenty views below.
 *
 * ## One test, one registration
 *
 * The same trade `address-fields.spec.ts` records: PBKDF2 at 600k dominates the
 * wall clock and the suite runs single-worker, so the whole authenticated walk
 * shares one account. Each view is a `test.step`, and every scan asserts SOFTLY
 * (`expect.soft`) so one failing view does not hide the state of the other
 * nineteen — an accessibility report that stops at the first finding is a report
 * somebody has to run twenty times.
 */

test.describe('accessibility: every primary view and modal', () => {
  test('has no serious or critical axe violations', async ({ page }, testInfo) => {
    // Two 600k-iteration derivations for the sign-in, twenty axe runs over a
    // fully rendered SPA, and three real documents uploaded through the browser's
    // own AES-GCM to the storage engine the harness starts.
    // `registerAndSignInViaUI` raises the timeout to its own floor; this raises it
    // further for the walk that follows.
    testInfo.setTimeout(600_000);

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
     * Soft, so the walk continues: nineteen more views are worth more than
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
        // for the item's own heading, as every other step does.
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

      // --- The document store -------------------------------------------------
      //
      // Real documents, uploaded through the real path: the harness starts the
      // object-storage engine in a container, so `test:a11y` declares `docker`
      // as a prerequisite exactly as `test:e2e` does. There is no way to scan
      // these four views against an empty store — the list would be its empty
      // state, and the detail views would not exist at all.
      await test.step('documents', async () => {
        await gotoDocuments(page);
        // The PDF first, so the list is not in its empty state when the markdown
        // document lands and the two detail views below have something to open.
        await uploadDocument(page, DOCUMENT_PDF);
        await uploadDocument(page, DOCUMENT_MARKDOWN);
        await scan('documents-list');

        // The upload panel's own controls, which exist only once a file is
        // picked and a transform has produced something to confirm. At rest the
        // panel is already inside the scan above.
        await page
          .locator('#document-upload-input')
          .setInputFiles(documentFixture(DOCUMENT_UGLY_JSON));
        await page.locator('#document-transform-format').check();
        await page.locator('#document-transform-repair').check();
        await page.getByRole('button', { name: 'Prepare and review' }).click();
        await expect(page.getByTestId('transform-review')).toBeVisible({ timeout: 90_000 });
        // Expanded, because a collapsed `<details>` hides the diff from the
        // scanner exactly as it hides it from a reader.
        await page.getByText('Show what changed').click();
        await expect(page.getByTestId('transform-diff')).toBeVisible();
        await scan('document-upload-review');

        // Put the panel back to rest before navigating: an unconfirmed review is
        // a decision this walk has no business leaving open behind it.
        await page.getByTestId('transform-review').getByRole('button', { name: 'Cancel' }).click();
        await page.getByRole('button', { name: 'Clear selected file' }).click();
        await expect(page.getByTestId('transform-review')).toHaveCount(0);

        // The declined half of the detail view: a PDF is download-only, so this
        // is the chrome, the reason and the download button with no frame at all.
        await openDocument(page, DOCUMENT_PDF);
        await expect(page.getByTestId('document-download-to-view')).toBeVisible({
          timeout: 90_000,
        });
        await scan('document-detail');

        // And the rendered half. The wait is on the RENDERER'S OWN shell inside
        // the frame rather than on the frame element, because an iframe is
        // visible the moment it is attached: a scan taken then would cover an
        // empty rectangle and report it clean.
        await page.getByRole('link', { name: 'Back to documents' }).click();
        await expect(page).toHaveURL(/\/documents$/);
        await openDocument(page, DOCUMENT_MARKDOWN);
        await expect(
          page.frameLocator('iframe[title^="Preview of "]').locator('.hv-doc-markdown'),
        ).toBeVisible({ timeout: 90_000 });
        // NOTE FOR ANYONE READING A FAILURE HERE: the frame's CONTENTS are part
        // of this scan. `@axe-core/playwright` reaches a child frame through
        // Playwright's own frame tree rather than through axe's same-origin
        // frameMessenger, so a serious finding inside the isolated document
        // fails this view — which is intended, and is why the frame is not
        // excluded. Excluding it would drop the whole framed document from the
        // run while leaving every number this gate reports unchanged.
        await scan('document-viewer');

        // The expanded state. The wait is on the ROLE rather than on the
        // button's new label, because the class change and the role change land
        // in one commit and only the second is what this view is about.
        await page.getByRole('button', { name: 'Full screen' }).click();
        await expect(page.getByRole('dialog', { name: DOCUMENT_MARKDOWN })).toBeVisible();
        await scan('document-viewer-expanded');
        await page.getByRole('button', { name: 'Exit full screen' }).click();
        await expect(page.getByRole('dialog')).toHaveCount(0);

        // And the trash, which needs something in it. The PDF goes, because the
        // two detail scans above are already done with it.
        await page.getByRole('link', { name: 'Back to documents' }).click();
        await expect(page).toHaveURL(/\/documents$/);
        await openDocument(page, DOCUMENT_PDF);
        await page.getByRole('button', { name: 'Delete', exact: true }).click();
        await page
          .getByRole('dialog', { name: 'Move to trash' })
          .getByRole('button', { name: 'Move to trash' })
          .click();
        await expect(page).toHaveURL(/\/documents$/);
        await page.getByRole('button', { name: /^Trash/ }).click();
        await expect(page.getByRole('button', { name: 'Empty trash' })).toBeVisible();
        await scan('documents-trash');
        // Put the rail back, so the walk does not abandon a filtered view behind
        // the unlock step.
        await page.getByRole('button', { name: /^All Documents/ }).click();
      });

      // Near-last, because reaching it locks the vault: the key lives in memory
      // only, so everything above is unreachable afterwards without another
      // derivation.
      await test.step('unlock screen', async () => {
        await page.keyboard.press('Control+l');
        await expect(page.getByText('Vault Locked')).toBeVisible({ timeout: 60_000 });
        await scan('unlock-screen');
      });

      // Truly last, and it needs no session at all: a top-level navigation to the
      // isolated document, handed a rendered markdown document over a real port.
      // See `a11yViews.ts` for why this is not a second look at the frame the
      // `document-viewer` scan already covered.
      await test.step('sandbox rendered', async () => {
        const replies = await renderInSandboxDirectly(page, {
          mode: 'markdown',
          ext: 'md',
          bytes: documentFixtureBytes(DOCUMENT_MARKDOWN),
        });
        // The document ANSWERED, and answered `rendered`. Without this a scan of
        // a frame that had refused the request would report zero violations
        // about an empty document — the same trap the completeness check exists
        // for, one level down.
        expect(replies).toEqual([{ kind: 'rendered' }]);
        await scan('sandbox-rendered');
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
