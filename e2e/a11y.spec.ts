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
  gotoTotpImportTool,
  readSampleExport,
  testDb,
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
 * The token the three link-landing pages are scanned with.
 *
 * Deliberately NOT a valid JWT, and deliberately not empty either. Empty means
 * `?token` is absent, which is a different branch on all three pages (the
 * missing-token copy, and on `/reset-password` a card instead of the form); a
 * malformed one reaches the server, fails `jwt.verify`, and comes back 400, so
 * `/verify-email` and `/unlock-account` settle on the failure card they show a
 * real user with an expired link. It is only ever SENT by those two — the
 * reset-password step scans the empty form and submits nothing.
 */
const REJECTED_TOKEN = 'e2e-a11y-rejected-token';

/**
 * One audit row per badge colour the log can draw, newest first.
 *
 * Two things make this a fixture rather than a convenience. The audit log pages
 * at twenty rows, so a page-one scan of an account that has merely signed in
 * covers a handful of rows and a pager with both buttons inert — none of the
 * eleven `bg-<hue>-100` / `text-<hue>-800` pairs, and neither pager state. And
 * every one of those pairs is a contrast measurement no other view in this walk
 * makes: the same pairs exist on the vault list and the health page, but the
 * badge there holds a single digit and axe declines to measure one character at
 * all. Here the badge says "Failed Login", so it is measured — see the note on
 * `ACTION_COLORS` in `AuditLogPage.tsx` for what that measurement found and for
 * the one thing it does NOT catch.
 *
 * Written straight into `audit_logs` for the reason `markEmailVerified` writes
 * straight into `users`: these are SERVER-authored rows that the client only
 * ever renders, and producing twenty-four of them through the UI would add
 * minutes of key derivation and dialog work to a walk whose subject is markup.
 * The list is spent twice over (twenty-four rows), which is what carries the log
 * past one page while keeping all twelve distinct actions inside the first twenty
 * that page one shows. The step that reads it asserts that outcome directly
 * rather than trusting the arithmetic — see the numbered checks there for why the
 * arithmetic alone is not enough.
 */
interface SeededAuditRow {
  readonly action: string;
  /**
   * The badge text `AuditLogPage`'s `ACTION_LABELS` renders for this action.
   *
   * Restated here rather than imported — the spec cannot reach client source —
   * and it is what turns "page one carries every badge colour" from arithmetic
   * into an assertion. A label the page renames makes this red, which is the
   * right outcome: the claim is about what is on screen.
   */
  readonly label: string;
  readonly metadata?: Record<string, unknown>;
}

const AUDIT_BADGE_SAMPLE: readonly SeededAuditRow[] = [
  { action: 'logout', label: 'Logout' }, // gray
  { action: 'login_failed', label: 'Failed Login' }, // red
  { action: '2fa_disable', label: '2FA Disabled' }, // orange
  // Amber, and the only action whose `metadata` the page renders: the row shows
  // "3 left" beside the badge, which is a second cell no other row produces.
  { action: '2fa_backup_code_used', label: 'Backup Code Used', metadata: { remaining: 3 } },
  { action: 'password_change', label: 'Password Changed' }, // yellow
  { action: 'login', label: 'Login' }, // green
  { action: 'item_create', label: 'Item Created' }, // emerald
  { action: 'backup_triggered', label: 'Backup Triggered' }, // cyan
  { action: '2fa_enable', label: '2FA Enabled' }, // blue
  { action: 'item_update', label: 'Item Updated' }, // indigo
  { action: 'export', label: 'Vault Exported' }, // purple
  // Not in `ACTION_COLORS` at all, so it exercises the grey fallback branch.
  { action: 'document_create', label: 'Document Uploaded' },
];

/** How many rows the audit log puts on one page (`AuditLogPage`'s `limit`). */
const AUDIT_PAGE_SIZE = 20;

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
 * did. What it does say is that no view in the list below carries a moderate,
 * serious or critical machine-detectable violation — a control with no
 * accessible name, an input with no label, text below the contrast threshold, a
 * broken ARIA relationship, a page with no `main` landmark or no `h1`, content
 * outside every landmark, a heading that skips a level — and that class of
 * defect is exactly what a refactor reintroduces without anyone noticing.
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
 * memory, and ciphertext that has to make a round trip; a suite that scanned only
 * what a signed-out browser can reach would miss most of the thirty-four views below.
 *
 * ## One test, one registration
 *
 * The same trade `address-fields.spec.ts` records: PBKDF2 at 600k dominates the
 * wall clock and the suite runs single-worker, so the whole authenticated walk
 * shares one account. Each view is a `test.step`, and every scan asserts SOFTLY
 * (`expect.soft`) so one failing view does not hide the state of the other
 * thirty-three — an accessibility report that stops at the first finding is a
 * report somebody has to run thirty-four times.
 */

test.describe('accessibility: every primary view and modal', () => {
  test('has no moderate, serious or critical axe violations', async ({ page }, testInfo) => {
    // Two 600k-iteration derivations for the sign-in, thirty-four axe runs over a
    // fully rendered SPA, and three real documents uploaded through the browser's
    // own AES-GCM to the storage engine the harness starts.
    // `registerAndSignInViaUI` raises the timeout to its own floor; this raises it
    // further for the walk that follows.
    //
    // MEASURED at 48.7 s on an idle four-core machine for the whole walk, so this
    // is roughly twelve times the observed cost. It is a CEILING rather than a
    // budget — every step below waits on a named element, so nothing here is
    // synchronised by the clock — and the slack is for a contended machine where
    // one PBKDF2 derivation alone has been seen past 30 s (see
    // `PBKDF2_STEP_TIMEOUT_MS` in `helpers.ts`). It was 600 s for twenty-two
    // views; ten more views measured under two seconds each, so it stays there.
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
     * Soft, so the walk continues: thirty-three more views are worth more than
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

      await test.step('forgot password', async () => {
        await page.goto('/forgot-password');
        await expect(page.getByRole('heading', { name: 'Forgot Password' })).toBeVisible({
          timeout: 60_000,
        });
        await scan('forgot-password');
      });

      await test.step('reset password', async () => {
        // The token is what selects the FORM branch; `ResetPasswordPage` renders
        // an invalid-link card without one. Nothing submits it, so it is never
        // presented to the server and its contents are irrelevant.
        await page.goto(`/reset-password?token=${REJECTED_TOKEN}`);
        await expect(page.getByRole('heading', { name: 'Reset Password' })).toBeVisible({
          timeout: 60_000,
        });
        // The data-loss warning is part of this view and it is the reason the
        // page is worth scanning: it is a `role="alert"` region above three
        // fields, one of which is a master password. Waiting for it also proves
        // the form branch rendered rather than either card branch.
        await expect(page.getByRole('alert')).toContainText('new encryption key');
        await scan('reset-password');
      });

      await test.step('verify email', async () => {
        // Both of the next two pages call their endpoint on mount and settle on
        // one of three cards. The token is rejected — `jwt.verify` throws, the
        // server answers 400 — so the failure card is the SETTLED state, and the
        // wait below is on it rather than on the spinner that precedes it. A scan
        // taken mid-request would cover a `Loader2` and report it clean.
        await page.goto(`/verify-email?token=${REJECTED_TOKEN}`);
        await expect(page.getByRole('heading', { name: 'Verification Failed' })).toBeVisible({
          timeout: 60_000,
        });
        await scan('verify-email');
      });

      await test.step('unlock account', async () => {
        await page.goto(`/unlock-account?token=${REJECTED_TOKEN}`);
        await expect(page.getByRole('heading', { name: 'Unlock Failed' })).toBeVisible({
          timeout: 60_000,
        });
        await scan('unlock-account');
      });

      await test.step('not found', async () => {
        await page.goto('/a-route-that-does-not-exist');
        await expect(page.getByRole('heading', { name: 'Page Not Found' })).toBeVisible({
          timeout: 60_000,
        });
        // Signed out, so the one link on the page points at sign-in. Asserted
        // because it is what the view's description claims, and because the
        // alternative branch would mean the walk had a session it should not.
        await expect(page.getByRole('link', { name: 'Back to Login' })).toBeVisible();
        await scan('not-found');
      });

      // --- Signed in ----------------------------------------------------------
      const account = await registerAndSignInViaUI(page);

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
      await test.step('password generator', async () => {
        await page.getByRole('link', { name: 'Password Generator', exact: true }).click();
        await expect(page).toHaveURL(/\/generator$/);
        await expect(page.getByRole('heading', { name: 'Password Generator' })).toBeVisible({
          timeout: 60_000,
        });
        // The first password is generated behind a 50 ms timeout (the component
        // paints its spinner first), and the strength meter — five bars, an
        // entropy figure and a crack-time line — exists only once it has landed.
        // Waiting for the figure keeps the scan off the half-drawn panel.
        await expect(page.getByText(/^\d+ bits$/)).toBeVisible({ timeout: 60_000 });
        await scan('generator');
      });

      await test.step('settings', async () => {
        await page.getByRole('link', { name: 'Settings', exact: true }).click();
        await expect(page).toHaveURL(/\/settings$/);
        await expect(page.getByRole('heading', { name: /^settings$/i })).toBeVisible({
          timeout: 60_000,
        });
        await scan('settings');
      });

      // --- The four pages behind Settings -------------------------------------
      //
      // Each is reached by clicking its real entry, and each returns through the
      // page's own "Back to settings" control rather than through `page.goto`:
      // a full navigation reloads the SPA, and the vault key lives only in
      // memory, so it would drop the walk onto the unlock screen with most of the
      // list still to scan.
      await test.step('audit log', async () => {
        await seedAuditHistory(account.email);

        // Already on Settings: the scan above left the walk there.
        await page.getByRole('link', { name: /audit log/i }).click();
        await expect(page).toHaveURL(/\/settings\/audit$/);
        await expect(page.getByRole('heading', { name: 'Audit Log' })).toBeVisible({
          timeout: 60_000,
        });
        // Every clause of this view's description, asserted rather than assumed.
        // Without this the view could silently degrade into a scan of an empty
        // state, which is the failure mode the whole completeness check
        // downstream is built around, one level in.
        const auditTable = page.getByRole('table', { name: 'Audit log entries' });
        // 1. The table rendered at all: an empty log draws a placeholder and no
        //    table, and no pager either.
        await expect(auditTable).toBeVisible({ timeout: 60_000 });
        // 2. A FULL page, which is also what makes the arithmetic below hold.
        await expect(auditTable.locator('tbody tr')).toHaveCount(AUDIT_PAGE_SIZE);
        // 3. The pager is in the mixed state the seeding exists to produce —
        //    Prev inert, Next live — rather than the both-inert state a
        //    single-page log gives.
        await expect(page.getByText(/^Page 1 of [2-9]\d*$/)).toBeVisible();
        // 4. And every badge colour really is on THIS page. It would otherwise
        //    rest on an ordering argument, and that argument is fragile in one
        //    specific way: the seeded rows are stamped from `Date.now()` at seed
        //    time descending by a minute, while the account's own real rows
        //    (registration, the sign-in, two item creations) were written seconds
        //    earlier in this same walk — so they are NEWER than every seeded row
        //    but the first, and they interleave at the TOP of page one, pushing
        //    four of the doubled tail off it. Twelve distinct actions plus four
        //    real rows is sixteen of twenty, so the margin is four rows rather
        //    than a page, and a future step that adds more audit rows before this
        //    one would silently push a colour onto page two. Scoped to the table,
        //    because the action filter renders every label as an `<option>` too.
        for (const row of AUDIT_BADGE_SAMPLE) {
          await expect(
            auditTable.getByText(row.label, { exact: true }).first(),
            `no ${row.label} badge on page one`,
          ).toBeVisible();
        }
        // 5. The one row whose `metadata` the page renders.
        await expect(auditTable.getByText('3 left').first()).toBeVisible();
        await scan('audit-log');
      });

      await test.step('sessions', async () => {
        await backToSettings(page);
        await page.getByRole('link', { name: /active sessions/i }).click();
        await expect(page).toHaveURL(/\/settings\/sessions$/);
        await expect(page.getByRole('heading', { name: 'Active Sessions' })).toBeVisible({
          timeout: 60_000,
        });
        // TWO independent fetches back this page, and each has its own spinner:
        // the session list and the trusted-device list. Waiting for one settles
        // half the DOM, so both are waited for — the current-session badge for
        // the first, the trusted-device empty state for the second.
        await expect(page.getByText('Current', { exact: true })).toBeVisible({ timeout: 60_000 });
        await expect(page.getByText(/^No trusted devices\./)).toBeVisible({ timeout: 60_000 });
        await scan('sessions');
      });

      await test.step('backup settings', async () => {
        await backToSettings(page);
        await page.getByRole('link', { name: /backup settings/i }).click();
        await expect(page).toHaveURL(/\/settings\/backup$/);
        // The whole page is behind a `loading` guard that renders a spinner and
        // nothing else, so the heading IS the readiness signal here.
        await expect(page.getByRole('heading', { name: 'Backup Settings' })).toBeVisible({
          timeout: 60_000,
        });
        await expect(page.getByText('No backup history')).toBeVisible({ timeout: 60_000 });
        // The restore panel is collapsed by default. Opening it costs no extra
        // view — it is part of this page — and adds a file input, a password
        // field and a radio group that nothing else in this walk covers.
        await page.getByRole('button', { name: 'Restore from File' }).click();
        await expect(page.locator('#restore-backup-file')).toBeVisible();
        await scan('backup-settings');
      });

      await test.step('export data', async () => {
        await backToSettings(page);
        await page.getByRole('link', { name: /export to another manager/i }).click();
        await expect(page).toHaveURL(/\/settings\/export-data$/);
        await expect(page.getByRole('heading', { name: 'Leave H-Vault' })).toBeVisible({
          timeout: 60_000,
        });
        // No export is prepared and no password is typed: this view is the
        // warning surface, the format radio group and the re-authentication
        // field. Confirming here would download the vault in the clear.
        await scan('export-data');
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

      await test.step('authenticator import tool', async () => {
        // Scanned in its RESULTS state rather than at rest. At rest it is a
        // heading and three buttons; the state worth measuring is the one with
        // the account cards, the countdown rings and the disclosure controls in
        // it, and reading the sample export is how it is reached without a
        // camera.
        await gotoTotpImportTool(page);
        await readSampleExport(page);
        await scan('totp-import');
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

        // The bulk export's summary, driven OFFLINE on purpose.
        //
        // Two things follow from that and both are the point. Every document is
        // refused for one stated reason, so the failure list — the only DOM in
        // this panel the walk does not already cover through `documents-list` —
        // is populated deterministically rather than depending on how many
        // documents happen to be listed. And no browser download is started at
        // all, so this step never touches Chromium's handling of several
        // downloads from one action, which is the one part of the feature a
        // headless run has no business asserting anything about.
        await page.context().setOffline(true);
        await page.getByRole('button', { name: 'Download all' }).click();
        await page.getByRole('button', { name: 'Start download' }).click();
        await expect(page.getByTestId('documents-download-all-failures')).toBeVisible({
          timeout: 60_000,
        });
        await scan('documents-download-all');

        // Back to rest, and back online, before the walk moves on: a summary
        // left standing and a context left offline are both state this step has
        // no business handing to the next one.
        await page.getByRole('button', { name: 'Dismiss' }).click();
        await page.context().setOffline(false);
        await expect(page.getByTestId('documents-offline')).toHaveCount(0, { timeout: 60_000 });
      });

      // Near-last, because reaching it locks the vault: the key lives in memory
      // only, so everything above is unreachable afterwards without another
      // derivation.
      await test.step('unlock screen', async () => {
        // The shortcut, not `lockViaUi`: this walk has just left the rail in its
        // default state and focus on a button, which is the precondition
        // `useKeyboardShortcuts` needs (it suppresses every shortcut while focus
        // is in an `INPUT`/`TEXTAREA`/`SELECT`, and this page carries a search
        // field). The assertion below is what catches it if that ever stops
        // holding, rather than a later step failing unrecognisably.
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

/**
 * Gives the signed-in account an audit history long enough to page.
 *
 * Timestamps descend from now by a minute a row, so all twelve distinct actions
 * are the newest twelve seeded rows and land on page one. They are not the top
 * twenty outright: the account's own real rows (its registration, its sign-in,
 * the two items the walk created) were written seconds ago and are therefore
 * newer than every seeded row but the first, so they interleave at the top and
 * push four of the doubled tail onto page two. The margin is four rows, and the
 * caller asserts the outcome rather than relying on this paragraph.
 */
async function seedAuditHistory(email: string): Promise<void> {
  const db = await testDb();
  const user = await db.collection('users').findOne({ email });
  if (!user) throw new Error(`seedAuditHistory: no user row for ${email}`);

  const now = Date.now();
  const rows = [...AUDIT_BADGE_SAMPLE, ...AUDIT_BADGE_SAMPLE].map((row, index) => ({
    userId: user._id,
    action: row.action,
    ...(row.metadata === undefined ? {} : { metadata: row.metadata }),
    ipAddress: '203.0.113.7',
    userAgent:
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
    timestamp: new Date(now - index * 60_000),
  }));
  await db.collection('audit_logs').insertMany(rows);
}

/**
 * Returns to Settings through the sub-page's own back control.
 *
 * Never `page.goto('/settings')`: that is a full document load, the vault key
 * lives only in memory, and the walk would land on the unlock screen with the
 * rest of the authenticated list still to scan.
 */
async function backToSettings(page: Page): Promise<void> {
  await page.getByRole('button', { name: 'Back to settings' }).click();
  await expect(page).toHaveURL(/\/settings$/);
  await expect(page.getByRole('heading', { name: /^settings$/i })).toBeVisible({
    timeout: 60_000,
  });
}

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
