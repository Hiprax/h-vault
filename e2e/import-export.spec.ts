import { test, expect, type Page } from '@playwright/test';
import { registerAndSignInViaUI } from './helpers';

/**
 * End-to-end proof of the zero-knowledge import pipeline: a real browser parses
 * an external export, encrypts every item with the in-memory vault key, and the
 * server stores already-encrypted rows. The items then round-trip back out and
 * render DECRYPTED in the vault — proving parse → encrypt → store → fetch →
 * decrypt → display all work together. No plaintext ever reaches the server.
 *
 * The later specs prove the three guarantees the import rework exists for, in a
 * real browser rather than in a resolver unit test:
 *   1. ten accounts on one site stay ten items, each individually tellable apart
 *   2. re-importing the same file changes nothing (and sends nothing)
 *   3. an `overwrite` import updates in place and never loses the old password
 */

const IMPORT_PANEL_PLACEHOLDER = 'Paste exported data here...';

const FIREFOX_CSV_HEADER =
  'url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged';

/** One Firefox export row. Firefox has no title column — names are derived. */
function firefoxRow(url: string, username: string, password: string, guid: string): string {
  const origin = new URL(url).origin;
  return `${url},${username},${password},,${origin},{${guid}},1,2,3`;
}

// Navigate via the in-app sidebar links (client-side SPA navigation) rather than
// page.goto — a full reload would drop the in-memory vault key and lock the vault.
async function openImportPanel(page: Page): Promise<void> {
  // `exact` matters here, and only bites when the panel is opened a SECOND time
  // without leaving the page: the settings page itself carries a "Backup
  // Settings" link, which a substring match would tie with the sidebar's.
  await page.getByRole('link', { name: 'Settings', exact: true }).click();
  await expect(page).toHaveURL(/\/settings/);
  await page.getByRole('button', { name: 'Import Vault' }).click();
  await expect(page.getByPlaceholder(IMPORT_PANEL_PLACEHOLDER)).toBeVisible();
}

async function goToVault(page: Page): Promise<void> {
  await page.getByRole('link', { name: 'Vault', exact: true }).click();
  await expect(page).toHaveURL(/\/vault$/);
}

/** Selects the import format by its value (the format <select> is the only one with these options). */
async function selectFormat(page: Page, value: string): Promise<void> {
  const select = page.locator('select').filter({ has: page.locator(`option[value="${value}"]`) });
  await select.selectOption(value);
}

/** Selects the conflict strategy by value, located the same way as the format select. */
async function selectStrategy(
  page: Page,
  value: 'skip' | 'overwrite' | 'keep_both',
): Promise<void> {
  const select = page.locator('select').filter({ has: page.locator(`option[value="${value}"]`) });
  await select.selectOption(value);
}

async function runImport(page: Page): Promise<void> {
  await page.getByRole('button', { name: 'Import', exact: true }).click();
}

/**
 * Waits for the import result toast, matched in FULL.
 *
 * Exact rather than a substring: the toast is the whole accounting for the run
 * ("Imported 0 items, 1 updated, 1 already up to date (2 rows)"), and every
 * outcome count in it has to sum to the rows the file contained. A substring
 * matcher would happily pass on a message that had silently grown an extra
 * bucket — which is the one thing about this message worth asserting.
 */
async function expectImportToast(page: Page, title: string): Promise<void> {
  await expect(page.getByText(title, { exact: true })).toBeVisible({ timeout: 20_000 });
}

/** The rendered NAME of every vault row (never the subtitle). */
function itemNames(page: Page) {
  return page.getByTestId('vault-item-name');
}

/** The rendered SUBTITLE of every vault row (never the name). */
function itemSubtitles(page: Page) {
  return page.getByTestId('vault-item-subtitle');
}

/**
 * Records every `/tools/import` request body so a test can assert both what
 * crossed the wire and — just as importantly — that nothing did.
 */
function recordImportBodies(page: Page): string[] {
  const bodies: string[] = [];
  page.on('request', (req) => {
    if (req.method() === 'POST' && req.url().includes('/tools/import')) {
      bodies.push(req.postData() ?? '');
    }
  });
  return bodies;
}

test.describe('Vault import — external formats (zero-knowledge, end-to-end)', () => {
  test('imports a Firefox CSV and shows the decrypted logins in the vault', async ({ page }) => {
    await registerAndSignInViaUI(page);
    await openImportPanel(page);
    await selectFormat(page, 'firefox');

    const firefoxCsv = [
      FIREFOX_CSV_HEADER,
      firefoxRow('https://accounts.google.com/signin', 'alice@example.com', 'SuperSecret1!', 'g1'),
      firefoxRow('https://github.com/login', 'octocat', 'Corr3ctHorse!', 'g2'),
    ].join('\n');

    // Capture what actually goes over the wire. The zero-knowledge claim in this
    // file's header is only worth making if something asserts it: record every
    // /tools/import request body and prove no plaintext credential appears in it.
    const importBodies = recordImportBodies(page);

    await page.getByPlaceholder(IMPORT_PANEL_PLACEHOLDER).fill(firefoxCsv);
    await runImport(page);

    // Success toast (the panel closes on success). Every row became a new item,
    // so the accounting collapses to the single inserted count.
    await expectImportToast(page, 'Imported 2 items');

    // The request was made, and it carried ciphertext only — no password, no
    // username, no URL from the source file survives in the payload.
    expect(importBodies.length).toBeGreaterThan(0);
    const wire = importBodies.join('\n');
    expect(wire).not.toContain('SuperSecret1!');
    expect(wire).not.toContain('Corr3ctHorse!');
    expect(wire).not.toContain('alice@example.com');
    expect(wire).not.toContain('octocat');
    expect(wire).not.toContain('accounts.google.com');

    // The names are derived from the URL host and render decrypted in the vault.
    // Scoped to the NAME element rather than matched loosely across the row: a
    // login with no username subtitles on its host, so an unscoped text match
    // for a host can resolve to two different elements of the same row.
    await goToVault(page);
    await expect(itemNames(page).filter({ hasText: 'accounts.google.com' })).toHaveCount(1);
    await expect(itemNames(page).filter({ hasText: 'github.com' })).toHaveCount(1);

    // Each row carries the username as its distinguishing subtitle, which is
    // what keeps several accounts on one site tellable apart. Asserted without
    // pinning the row order: the vault's default sort is `dateModified`, so two
    // items imported in one batch can land either way round.
    const subtitles = itemSubtitles(page);
    await expect(subtitles).toHaveCount(2);
    await expect(subtitles.filter({ hasText: 'alice@example.com' })).toHaveCount(1);
    await expect(subtitles.filter({ hasText: 'octocat' })).toHaveCount(1);

    // `VaultList`'s ITEM_HEIGHT is a hand-maintained constant that react-window
    // uses as a FIXED row height — it cannot measure. jsdom does no layout, so a
    // real browser is the only place the constant can be checked against the row
    // it describes; let it drift and the virtualized branch (>50 items) spaces
    // its rows wrongly. Measure the row card itself, not its list wrapper.
    const rowBox = await page
      .getByRole('listitem')
      .first()
      .getByRole('button')
      .first()
      .boundingBox();
    expect(rowBox?.height).toBe(78);
  });

  test('imports a Bitwarden JSON export (login + secure note) and shows them decrypted', async ({
    page,
  }) => {
    await registerAndSignInViaUI(page);
    await openImportPanel(page);
    await selectFormat(page, 'bitwarden');

    const bitwardenJson = JSON.stringify({
      folders: [{ id: 'f1', name: 'Work' }],
      items: [
        {
          type: 1,
          name: 'My GitHub',
          folderId: 'f1',
          login: {
            username: 'octocat',
            password: 'Tr0ub4dour&3',
            uris: [{ uri: 'https://github.com' }],
          },
        },
        { type: 2, name: 'Recovery Codes', notes: 'one two three' },
      ],
    });

    await page.getByPlaceholder(IMPORT_PANEL_PLACEHOLDER).fill(bitwardenJson);
    await runImport(page);

    await expectImportToast(page, 'Imported 2 items');

    await goToVault(page);
    await expect(page.getByText('My GitHub')).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText('Recovery Codes')).toBeVisible();
  });
});

test.describe('Vault import — identity, idempotency and safe overwrite', () => {
  test('keeps ten accounts on one host as ten distinguishable rows, and re-importing changes nothing', async ({
    page,
  }) => {
    // Registration derives a real 600k-iteration PBKDF2 key and this test then
    // runs two full imports, so the default 30s budget is not enough.
    test.setTimeout(120_000);

    const accounts = Array.from({ length: 10 }, (_, i) => ({
      username: `user${String(i + 1).padStart(2, '0')}@example.com`,
      password: `Uniq-P@ssw0rd-${String(i + 1)}`,
    }));
    const firefoxCsv = [
      FIREFOX_CSV_HEADER,
      ...accounts.map((account, i) =>
        firefoxRow(
          'https://accounts.google.com/signin',
          account.username,
          account.password,
          `g${String(i)}`,
        ),
      ),
    ].join('\n');

    await registerAndSignInViaUI(page);
    const importBodies = recordImportBodies(page);

    // ── First import: ten rows, one host, ten different accounts ────────
    await openImportPanel(page);
    await selectFormat(page, 'firefox');
    await selectStrategy(page, 'skip');
    await page.getByPlaceholder(IMPORT_PANEL_PLACEHOLDER).fill(firefoxCsv);
    await runImport(page);
    await expectImportToast(page, 'Imported 10 items');

    const requestsAfterFirstImport = importBodies.length;
    expect(requestsAfterFirstImport).toBeGreaterThan(0);

    // Nothing readable crossed the wire — not one username, not one password.
    const wire = importBodies.join('\n');
    expect(wire).not.toContain('accounts.google.com');
    for (const account of accounts) {
      expect(wire).not.toContain(account.username);
      expect(wire).not.toContain(account.password);
    }

    // Ten items, not one. Matching is on host+username, so the shared host can
    // no longer collapse them, and every row names that host.
    await goToVault(page);
    await expect(itemNames(page)).toHaveCount(10);
    await expect(itemNames(page).filter({ hasText: 'accounts.google.com' })).toHaveCount(10);

    // …and every one of them is individually tellable apart, by the username in
    // its subtitle AND by the username the derived name now carries.
    await expect(itemSubtitles(page)).toHaveCount(10);
    for (const account of accounts) {
      await expect(itemSubtitles(page).filter({ hasText: account.username })).toHaveCount(1);
      await expect(itemNames(page).filter({ hasText: account.username })).toHaveCount(1);
    }
    // No password is ever a name or a subtitle.
    for (const account of accounts) {
      await expect(page.getByText(account.password)).toHaveCount(0);
    }

    // ── Second import: the identical file, default `skip` strategy ──────
    await openImportPanel(page);
    await selectFormat(page, 'firefox');
    await selectStrategy(page, 'skip');
    await page.getByPlaceholder(IMPORT_PANEL_PLACEHOLDER).fill(firefoxCsv);
    await runImport(page);
    await expectImportToast(page, 'Imported 0 items, 10 duplicates skipped (10 rows)');

    // Idempotency is structural, not merely "no duplicates appeared": resolution
    // produced no operations at all, so the client had nothing to send and the
    // server was never asked to write.
    expect(importBodies).toHaveLength(requestsAfterFirstImport);

    await goToVault(page);
    await expect(itemNames(page)).toHaveCount(10);
    await expect(itemSubtitles(page)).toHaveCount(10);
  });

  test('an overwrite import updates in place and keeps the previous password in history', async ({
    page,
  }) => {
    test.setTimeout(120_000);

    const OLD_PASSWORD = 'OldPassw0rd!';
    const NEW_PASSWORD = 'N3wPassw0rd!';
    const csv = (githubPassword: string): string =>
      [
        FIREFOX_CSV_HEADER,
        firefoxRow(
          'https://accounts.google.com/signin',
          'alice@example.com',
          'SuperSecret1!',
          'g1',
        ),
        firefoxRow('https://github.com/login', 'octocat', githubPassword, 'g2'),
      ].join('\n');

    await registerAndSignInViaUI(page);
    const importBodies = recordImportBodies(page);

    // ── Seed the vault ──────────────────────────────────────────────────
    await openImportPanel(page);
    await selectFormat(page, 'firefox');
    await selectStrategy(page, 'skip');
    await page.getByPlaceholder(IMPORT_PANEL_PLACEHOLDER).fill(csv(OLD_PASSWORD));
    await runImport(page);
    await expectImportToast(page, 'Imported 2 items');

    const requestsBeforeOverwrite = importBodies.length;

    // ── Re-import with one password changed, under `overwrite` ──────────
    await openImportPanel(page);
    await selectFormat(page, 'firefox');
    await selectStrategy(page, 'overwrite');
    await page.getByPlaceholder(IMPORT_PANEL_PLACEHOLDER).fill(csv(NEW_PASSWORD));
    await runImport(page);

    // Nothing may be sent until the modification is confirmed. The Google row is
    // byte-identical to what is stored so it resolves to no operation at all;
    // only the GitHub row, whose password moved, becomes an update.
    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible({ timeout: 20_000 });
    await expect(
      dialog.getByText('This import will modify 1 existing item in place.'),
    ).toBeVisible();
    await expect(dialog.getByText(/1 password will change/)).toBeVisible();
    expect(importBodies).toHaveLength(requestsBeforeOverwrite);

    await dialog.getByRole('button', { name: 'Apply Changes' }).click();
    await expectImportToast(page, 'Imported 0 items, 1 updated, 1 already up to date (2 rows)');

    // Updated IN PLACE: still two items, not three.
    await goToVault(page);
    await expect(itemNames(page)).toHaveCount(2);

    // ── The old password is still recoverable ───────────────────────────
    await itemNames(page).filter({ hasText: 'github.com' }).click();
    await expect(page).toHaveURL(/\/vault\/[0-9a-f]{24}/);

    // Before the history is expanded the current password is the only masked
    // field on the page, so the count doubles as a guard that the click below
    // reveals what this test thinks it does.
    const revealButtons = page.getByRole('button', { name: 'Reveal value' });
    await expect(revealButtons).toHaveCount(1);
    await revealButtons.click();
    await expect(page.getByText(NEW_PASSWORD)).toBeVisible();

    // Exactly one prior password was retained by the overwrite.
    await page.getByRole('button', { name: 'Password History (1)' }).click();
    // The current password's control now reads "Hide value", so the single
    // remaining "Reveal value" is the history entry's.
    await expect(revealButtons).toHaveCount(1);
    await revealButtons.click();
    await expect(page.getByText(OLD_PASSWORD)).toBeVisible();

    // Neither password was ever legible to the server.
    const wire = importBodies.join('\n');
    expect(wire).not.toContain(OLD_PASSWORD);
    expect(wire).not.toContain(NEW_PASSWORD);
    expect(wire).not.toContain('octocat');
  });
});
