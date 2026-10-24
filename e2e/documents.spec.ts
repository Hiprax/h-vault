import { test, expect, type Download, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { fromBufferPromise } from 'yauzl';
import {
  disableSaveFilePicker,
  documentFixture,
  documentFixtureBytes,
  gotoDocuments,
  openDocument,
  registerAndSignInViaUI,
  unlockVault,
  uploadDocument,
} from './helpers';

/**
 * The encrypted document store, end to end, against the real object-storage
 * engine.
 *
 * ## What is real here, and what is not
 *
 * Everything is real except the operator's two numbers. `e2e/start-server.ts`
 * starts the engine `docker-compose.yml` pins, in a container, and boots the dev
 * server pointing at it — so every byte below is hashed, sealed with a
 * per-document key in the browser, uploaded as ciphertext, stored by the engine,
 * read back, verified against its authentication tags and its whole-file SHA-256,
 * and decrypted with a vault key the server never sees. Nothing about the
 * document path is stubbed.
 *
 * The two numbers the harness pins are `MAX_DOCUMENT_SIZE_MB=1` and
 * `DOCUMENT_STORAGE_QUOTA_MB_PER_USER=1`, and the reason is written where they
 * are set. The allowance is small because one journey below is a refusal that has
 * to take an account past it, and at the shipped 2048 MB that would mean pushing
 * gigabytes through a browser's AES-GCM to prove an arithmetic comparison; it is
 * the operator's to choose in any deployment, so a small one exercises the same
 * code and the same branch. The per-document cap follows it only because
 * `loadConfig` refuses an allowance smaller than the cap. No journey here is
 * about the cap: that refusal happens in the browser before a byte is read, and
 * it is covered in `packages/client/tests/components/documents-upload.test.tsx`.
 *
 * ## One account per journey
 *
 * A registration is two 600,000-iteration PBKDF2 derivations plus server-side
 * bcrypt, and the suite runs `workers: 1`, so an account is the expensive thing
 * here rather than a document. The journeys that can share one do; the two that
 * cannot are the ones whose whole subject is per-account state — the storage
 * allowance, and a server that never advertised the feature.
 */

/** Every fixture this spec uploads, so a reader can see the whole budget at once. */
const README = 'README.md';
const UGLY_JSON = 'ugly.json';
const BROKEN_JSON = 'broken.json';
const CSV = 'contacts.csv';

/**
 * Half of the harness's one-megabyte allowance, in bytes, plus a margin.
 *
 * Generated rather than committed: a fixture this size would be six hundred
 * kilobytes of noise in the repository to test one comparison. Two of them
 * exceed the allowance while each one stays inside the per-document cap, which
 * is exactly the state the refusal exists for — a file that broke the
 * per-document cap would be refused in the browser and never reach the server's
 * quota check at all.
 */
const HALF_QUOTA_BYTES = 600 * 1024;

/** The allowance `e2e/start-server.ts` pins, and the divisor the client uses for it. */
const QUOTA_MB = 1;
const BYTES_PER_MB = 1024 * 1024;

/** A filler payload of `size` bytes, as a picked file with no committed fixture. */
function filler(name: string, size: number) {
  return {
    name,
    mimeType: 'application/octet-stream',
    // Not zeroes: a run of identical bytes compresses to nothing, and while
    // nothing here compresses today, a buffer whose length is its only property
    // is a fixture that stops meaning what it says the day something does.
    buffer: Buffer.from(Array.from({ length: size }, (_, index) => (index * 31 + 7) % 256)),
  };
}

/**
 * Open `url` with a full page load, then unlock.
 *
 * The unlock is not incidental scaffolding, and it is asserted rather than
 * tolerated: the vault key is a non-extractable `CryptoKey` held in memory and
 * nothing else, so replacing the document destroys it and every route behind
 * `ProtectedRoute` shows the unlock screen. That is the property this
 * application is built on, so a helper that quietly worked around it would be
 * hiding the thing worth pinning.
 *
 * Used only where a real user would also arrive by URL — a trashed document,
 * which has no route of its own, and a bookmark to a page this server no longer
 * offers.
 */
async function reopenByUrl(page: Page, url: string, password: string): Promise<void> {
  await page.goto(url);
  await expect(page.getByText('Vault Locked')).toBeVisible({ timeout: 60_000 });
  await unlockVault(page, password);
}

/** The document id in the address bar, for a route a trashed row is only reachable by. */
function documentIdFromUrl(page: Page): string {
  const id = new URL(page.url()).pathname.split('/').pop() ?? '';
  expect(id, `no document id in ${page.url()}`).toMatch(/^[0-9a-f]{24}$/);
  return id;
}

/**
 * Every entry of a ZIP archive, by name, read by an independent reader opened in
 * its strictest mode (no backslashes, no absolute or climbing paths, sizes
 * checked against the bytes). The archive under test was built by this
 * application's own writer, so reading it with that writer's logic would prove
 * nothing.
 */
async function zipEntries(archive: Buffer): Promise<Map<string, Buffer>> {
  const zip = await fromBufferPromise(archive, {
    lazyEntries: true,
    strictFileNames: true,
    validateEntrySizes: true,
  });
  const entries = new Map<string, Buffer>();
  for await (const entry of zip.eachEntry()) {
    const parts: Buffer[] = [];
    for await (const part of await zip.openReadStreamPromise(entry)) parts.push(part as Buffer);
    entries.set(entry.fileName, Buffer.concat(parts));
  }
  return entries;
}

test.describe('documents: the encrypted document store', () => {
  test('stores a document and gives back exactly the bytes that were uploaded', async ({
    page,
  }) => {
    test.setTimeout(300_000);
    await disableSaveFilePicker(page);
    await registerAndSignInViaUI(page);
    await gotoDocuments(page);

    // The empty state first, so the assertions after the upload are about the
    // upload rather than about whatever was already there.
    await expect(page.getByRole('heading', { name: 'No documents yet' })).toBeVisible();

    await uploadDocument(page, README);

    // The row: its name decrypted back, its type badge and its size. The badge
    // is worth asserting because `ext` lives INSIDE the sealed metadata blob —
    // the server never learns it — so an MD badge is evidence the blob opened.
    const row = page.getByTestId('document-row').filter({ hasText: README });
    await expect(row).toBeVisible();
    await expect(row).toContainText('MD');
    // The size, DERIVED from the file on disk rather than written down, so a
    // future edit to the fixture cannot leave this assertion quietly checking a
    // number that no longer describes it. Under a kilobyte `formatBytes` reports
    // whole bytes, so the unit is exact.
    await expect(row).toContainText(`${String(documentFixtureBytes(README).length)} B`);

    // NEGATIVE, and it is the one that matters most on this path: neither
    // degraded banner appeared. A row whose metadata could not be opened with
    // this vault key, or whose shape did not validate, is reported there rather
    // than by a failure — so a silent key or framing mistake would otherwise
    // leave a listed row and a green test.
    await expect(page.getByTestId('documents-degraded')).toHaveCount(0);

    await openDocument(page, README);

    // The SHA-256 the detail view shows is computed in the browser from the
    // plaintext before it is sealed, and it is what a downloaded copy can be
    // checked against outside this application. Comparing it with the digest of
    // the file on disk is therefore an end-to-end statement about the bytes and
    // not about this client's own bookkeeping.
    const expectedDigest = await digestOf(documentFixtureBytes(README));
    await expect(page.getByText(expectedDigest)).toBeVisible();

    const download = page.waitForEvent('download');
    await page.getByRole('button', { name: /^Download\b/ }).click();
    const saved = await download;
    expect(saved.suggestedFilename()).toBe(README);
    const savedPath = await saved.path();
    expect(readFileSync(savedPath).equals(documentFixtureBytes(README))).toBe(true);
  });

  test('takes a name, tags and a note at upload, records the original name, and renames only the part before the extension', async ({
    page,
  }) => {
    test.setTimeout(300_000);
    await registerAndSignInViaUI(page);
    await gotoDocuments(page);

    // The details are typed BEFORE anything is sent, beside the chosen file.
    await page.locator('#document-upload-input').setInputFiles(documentFixture(CSV));
    const name = page.locator('#document-upload-name');
    await expect(name).toHaveValue('contacts');
    await expect(page.getByTestId('document-upload-suffix')).toHaveText('.csv');
    await name.fill('Team contacts');
    // The vault item editor's tag chips: Enter adds one, and a tag still typed
    // in the box when Upload is pressed goes with the file too.
    const tags = page.locator('#document-upload-tags');
    await tags.fill('people');
    await tags.press('Enter');
    await expect(page.getByRole('button', { name: 'Remove tag people' })).toBeVisible();
    await tags.fill('work');
    await page.locator('#document-upload-note').fill('Exported from the old address book.');
    await page.getByRole('button', { name: 'Upload', exact: true }).click();

    const stored = 'Team contacts.csv';
    await expect(page.getByTestId('document-name').filter({ hasText: stored })).toBeVisible({
      timeout: 60_000,
    });
    // The fields went with the file once the transfer was registered.
    await expect(page.locator('#document-upload-name')).toHaveCount(0);
    // NEGATIVE: listed under the typed name only, never under the picked one.
    // Anchored, because `hasText` matches a substring and the typed name ends
    // with the picked one.
    await expect(
      page.getByTestId('document-name').filter({ hasText: /^contacts\.csv$/ }),
    ).toHaveCount(0);
    await expect(page.getByTestId('document-name')).toHaveCount(1);

    // Everything typed came back out of the sealed blob, and so did the name
    // the file had when it was added.
    await openDocument(page, stored);
    await expect(page.getByTestId('document-original-name')).toHaveText(CSV);
    await expect(page.getByText('Exported from the old address book.')).toBeVisible();
    await expect(page.getByText('people', { exact: true })).toBeVisible();
    await expect(page.getByText('work', { exact: true })).toBeVisible();

    // A rename edits the stem; the extension is fixed beside it.
    await page.getByRole('button', { name: 'Edit details' }).click();
    const editName = page.locator('#document-edit-name');
    await expect(editName).toHaveValue('Team contacts');
    await expect(page.getByTestId('document-edit-suffix')).toHaveText('.csv');
    // The stored tags open as chips, edited as a vault item's are.
    await expect(page.getByRole('button', { name: 'Remove tag people' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Remove tag work' })).toBeVisible();
    await expect(page.getByTestId('document-edit-original-name')).toHaveText(CSV);
    await editName.fill('Contacts 2026');
    await page.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByRole('heading', { name: 'Contacts 2026.csv', level: 1 })).toBeVisible({
      timeout: 60_000,
    });
    // The original name is the one thing a rename never touches.
    await expect(page.getByTestId('document-original-name')).toHaveText(CSV);
  });

  test('pauses an upload that loses its connection, and finishes it when the connection returns', async ({
    page,
    context,
  }) => {
    test.setTimeout(300_000);
    await registerAndSignInViaUI(page);
    await gotoDocuments(page);

    // The first part is refused as a dropped connection and the browser then
    // goes offline, the order a real interface drop produces; every later
    // request goes through untouched.
    const parts = '**/api/v1/documents/uploads/*/parts/*';
    let cut = false;
    await page.route(parts, async (route) => {
      if (cut) {
        await route.fallback();
        return;
      }
      cut = true;
      await route.abort('internetdisconnected');
      await context.setOffline(true);
    });

    await page.locator('#document-upload-input').setInputFiles(documentFixture(README));
    await page.getByRole('button', { name: 'Upload', exact: true }).click();

    // Paused, not failed: the row says what will happen and offers no Retry,
    // because there is nothing for the reader to resume by hand.
    const status = page.getByTestId('upload-status');
    await expect(status).toHaveText(/^You are offline\. The upload is paused/, { timeout: 60_000 });
    await expect(page.getByRole('button', { name: `Retry upload of ${README}` })).toHaveCount(0);
    await expect(
      page.getByRole('button', { name: `Retry now: upload of ${README}` }),
    ).toBeVisible();
    await expect(page.getByTestId('document-name')).toHaveCount(0);

    // Back online: the transfer carries on by itself and commits.
    await context.setOffline(false);
    await expect(page.getByTestId('document-name').filter({ hasText: README })).toBeVisible({
      timeout: 60_000,
    });
    await expect(page.getByTestId('upload-row')).toHaveCount(0);
    // NEGATIVE: one document, and it opens; a resume that re-sealed a part under
    // another key would be listed as unreadable rather than missing.
    await expect(page.getByTestId('document-name')).toHaveCount(1);
    await expect(page.getByTestId('documents-degraded')).toHaveCount(0);
  });

  test('uploads a rewritten document only after its diff is confirmed, and refuses one it cannot repair', async ({
    page,
  }) => {
    test.setTimeout(300_000);
    await disableSaveFilePicker(page);
    await registerAndSignInViaUI(page);
    await gotoDocuments(page);

    // --- The confirmed rewrite -------------------------------------------------
    await page.locator('#document-upload-input').setInputFiles(documentFixture(UGLY_JSON));
    await page.locator('#document-transform-format').check();
    await page.locator('#document-transform-repair').check();

    // The button's LABEL is the guarantee: with a transform ticked it stops
    // saying "Upload" and says what it will actually do first.
    await page.getByRole('button', { name: 'Prepare and review' }).click();

    const review = page.getByTestId('transform-review');
    await expect(review).toBeVisible({ timeout: 60_000 });
    await expect(review).toContainText('Review the changes before uploading');
    // The provenance record names the software that actually ran, both halves of
    // it, and it is what ends up in the sealed metadata.
    await expect(page.getByTestId('transform-summary')).toContainText('jsonrepair+prettier');
    await page.getByText('Show what changed').click();
    await expect(page.getByTestId('transform-diff')).toBeVisible();

    // NEGATIVE, and it is the whole point of the review: nothing has been sent.
    // No transfer is registered and no document is listed, so a panel that
    // uploaded first and reviewed afterwards would fail here rather than
    // silently storing a file the user never approved.
    await expect(page.getByTestId('upload-row')).toHaveCount(0);
    await expect(page.getByTestId('document-name')).toHaveCount(0);

    await page.getByRole('button', { name: 'Upload the formatted file' }).click();
    await expect(page.getByTestId('document-name').filter({ hasText: UGLY_JSON })).toBeVisible({
      timeout: 60_000,
    });

    // What was stored is the REWRITTEN document, under the picked file's name.
    // Downloading it and comparing both ways is what distinguishes "the review
    // ran" from "the reviewed bytes are the stored bytes".
    await openDocument(page, UGLY_JSON);
    const download = page.waitForEvent('download');
    await page.getByRole('button', { name: /^Download\b/ }).click();
    const stored = readFileSync(await (await download).path());
    expect(stored.equals(documentFixtureBytes(UGLY_JSON))).toBe(false);
    // Strict JSON now: the single quotes and the trailing commas are gone, the
    // separators are spaced, and the value is unchanged.
    expect(JSON.parse(stored.toString('utf8'))).toEqual({
      name: 'h-vault',
      tags: ['notes', 'secrets'],
    });
    expect(stored.toString('utf8')).toContain('"name": "h-vault"');

    // --- The refusal -----------------------------------------------------------
    await gotoDocuments(page);
    await page.locator('#document-upload-input').setInputFiles(documentFixture(BROKEN_JSON));
    await page.locator('#document-transform-format').check();
    await page.locator('#document-transform-repair').check();
    await page.getByRole('button', { name: 'Prepare and review' }).click();

    const failure = page.getByTestId('transform-failure');
    await expect(failure).toBeVisible({ timeout: 60_000 });
    await expect(failure).toContainText('it could not be repaired or formatted');
    // The APPLICATION's sentence for the repairer's complaint, the POSITION it
    // reported, and the source line it points at. A refusal that named no line
    // would send the reader back to a file with no idea where to look, which is
    // the difference this assertion pins: `broken.json` carries an elided array
    // element on its third line. The repairer's own wording is never shown —
    // the frame sends a code, and every sentence in this panel is the
    // application's — which the negative below pins through the real frame.
    const message = page.getByTestId('transform-failure-message');
    await expect(message).toHaveText('The repairer expected a colon.');
    await expect(message).not.toContainText('Colon expected');
    await expect(page.getByTestId('transform-failure-position')).toHaveText('Line 3, column 21');
    await expect(page.getByTestId('transform-failure-excerpt')).toContainText('[1, 2,, 3]');

    // NEGATIVE: the upload STOPPED. No transfer, and the list still holds only
    // the document from the first half of this test — so a panel that fell back
    // to sending the original on a failed transform would fail here.
    await expect(page.getByTestId('upload-row')).toHaveCount(0);
    await expect(page.getByTestId('document-name')).toHaveCount(1);
    await expect(page.getByTestId('document-name').filter({ hasText: BROKEN_JSON })).toHaveCount(0);
    // The escape hatch is OFFERED rather than taken: the user can still send the
    // file exactly as it is, which is what makes the refusal a review step and
    // not a wall.
    await expect(page.getByRole('button', { name: 'Upload the original unchanged' })).toBeVisible();
  });

  test('hides "Download your documents" while a file is picked, and Cancel lets the file go', async ({
    page,
  }) => {
    test.setTimeout(300_000);
    await registerAndSignInViaUI(page);
    await gotoDocuments(page);
    await uploadDocument(page, README);
    const downloadSection = page.getByTestId('documents-download-all');
    await expect(downloadSection).toBeVisible();

    // A file picked opens the upload form, and the download section steps aside.
    await page.locator('#document-upload-input').setInputFiles(documentFixture(CSV));
    await expect(page.getByRole('button', { name: 'Upload', exact: true })).toBeVisible();
    await expect(downloadSection).toBeHidden();

    // Cancel lets the file go, gives the focus back to the picker, and uploads nothing.
    await page.getByRole('button', { name: 'Cancel', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Upload', exact: true })).toHaveCount(0);
    await expect(page.locator('#document-upload-input')).toBeFocused();
    await expect(downloadSection).toBeVisible();
    await expect(page.getByTestId('document-name')).toHaveCount(1);
  });

  test('files a document in a folder and favorites it, and both lead somewhere', async ({
    page,
  }) => {
    test.setTimeout(300_000);
    await registerAndSignInViaUI(page);
    await gotoDocuments(page);

    // A folder made from the DOCUMENTS rail. Folders are one collection shared
    // with the vault, so this is the same tree the vault shows.
    await page.getByRole('button', { name: 'Create folder' }).click();
    await page.getByPlaceholder('Folder name').fill('Taxes');
    await page.getByRole('button', { name: 'Create', exact: true }).click();
    await expect(page.getByRole('button', { name: /^Taxes/ })).toBeVisible({ timeout: 60_000 });

    // Selected, so the upload is filed there — the panel says so before it starts.
    await page.getByRole('button', { name: /^Taxes/ }).click();
    await expect(page.getByTestId('upload-target-folder')).toContainText('Taxes');
    await uploadDocument(page, CSV);

    // BUG 2, end to end: the folder now leads somewhere. The row says where it is
    // filed and the rail counts it.
    await expect(page.getByTestId('document-folder')).toContainText('Taxes');
    await expect(page.getByRole('button', { name: /^Taxes/ })).toContainText('1');

    // BUG 1, end to end: a favorite now leads somewhere too.
    await openDocument(page, CSV);
    await page.getByRole('button', { name: 'Favorite' }).click();
    await expect(page.getByRole('button', { name: 'Favorited' })).toBeVisible({ timeout: 60_000 });
    await page.getByRole('link', { name: 'Back to documents' }).click();
    await page.getByRole('button', { name: /^Favorites/ }).click();
    await expect(page.getByTestId('document-name').filter({ hasText: CSV })).toBeVisible({
      timeout: 60_000,
    });

    // The NEGATIVE that makes the filter a filter: a document that is not a
    // favorite is not listed under Favorites.
    await page.getByRole('button', { name: /^All Documents/ }).click();
    await uploadDocument(page, README);
    await page.getByRole('button', { name: /^Favorites/ }).click();
    await expect(page.getByTestId('document-name').filter({ hasText: README })).toHaveCount(0);
    await expect(page.getByTestId('document-name')).toHaveCount(1);
  });

  test('sends a document to the trash, restores it, and then deletes it for good', async ({
    page,
  }) => {
    test.setTimeout(300_000);
    const { password } = await registerAndSignInViaUI(page);
    await gotoDocuments(page);
    await uploadDocument(page, CSV);
    await openDocument(page, CSV);
    // Still captured, because the LAST assertion of this test needs it: only the
    // id route can prove a purged document is gone from BOTH lists.
    const id = documentIdFromUrl(page);

    await page.getByRole('button', { name: 'Delete', exact: true }).click();
    const trashDialog = page.getByRole('dialog', { name: 'Move to trash' });
    await expect(trashDialog).toBeVisible();
    await expect(trashDialog).toContainText('kept for thirty days');
    await trashDialog.getByRole('button', { name: 'Move to trash' }).click();

    await expect(page).toHaveURL(/\/documents$/);
    await expect(page.getByTestId('document-name')).toHaveCount(0);

    // THE SURFACE THE BUG REPORT WAS ABOUT. The message said the document had
    // been moved to the trash; until now there was no trash to move it to, and
    // this walk reached it by reloading its URL from memory.
    await page.getByRole('button', { name: /^Trash/ }).click();
    const trashedRow = page.getByTestId('document-name').filter({ hasText: CSV });
    await expect(trashedRow).toBeVisible({ timeout: 60_000 });
    await expect(page.getByTestId('document-row').filter({ hasText: CSV })).toContainText(
      'Deleted',
    );

    // In the trash: still stored, still counted, and restorable.
    await trashedRow.click();
    await expect(page.getByTestId('document-trashed-note')).toBeVisible({ timeout: 60_000 });
    await expect(page.getByTestId('document-trashed-note')).toContainText('still occupies storage');
    // NEGATIVE: a trashed document offers no way to trash it again, so a UI that
    // simply showed the active toolbar would fail here.
    await expect(page.getByRole('button', { name: 'Delete', exact: true })).toHaveCount(0);

    await page.getByRole('button', { name: 'Restore' }).click();
    await expect(page).toHaveURL(/\/documents$/);
    // Restoring lands the reader where the document now IS, rather than back in
    // the trash it has just left.
    await expect(page.getByTestId('document-name').filter({ hasText: CSV })).toBeVisible({
      timeout: 60_000,
    });

    // Now the irreversible half. Back to the trash, then delete for good.
    await openDocument(page, CSV);
    await page.getByRole('button', { name: 'Delete', exact: true }).click();
    await page
      .getByRole('dialog', { name: 'Move to trash' })
      .getByRole('button', { name: 'Move to trash' })
      .click();
    await expect(page).toHaveURL(/\/documents$/);

    await page.getByRole('button', { name: /^Trash/ }).click();
    await page.getByTestId('document-name').filter({ hasText: CSV }).click();
    await expect(page.getByRole('button', { name: 'Delete Forever' })).toBeVisible({
      timeout: 60_000,
    });
    await page.getByRole('button', { name: 'Delete Forever' }).click();
    const purgeDialog = page.getByRole('dialog', { name: 'Delete this document for good' });
    await expect(purgeDialog).toBeVisible();
    // The copy says what is actually destroyed, and it is the sentence a reader
    // has to be given before an irreversible action: the object AND the server's
    // copy of the key that opens it (a full backup saved earlier still holds both).
    await expect(purgeDialog).toContainText('Nothing on the server can bring it back');
    await purgeDialog.getByRole('button', { name: 'Delete forever' }).click();

    await expect(page).toHaveURL(/\/documents$/);
    // Gone from both lists, which is what the id route proves and the list alone
    // could not: a purge that only cleared the active list would still answer
    // here from the trash.
    await reopenByUrl(page, `/documents/${id}`, password);
    await expect(page.getByTestId('document-not-found')).toBeVisible({ timeout: 60_000 });
  });

  test('selects documents and tags, trashes, restores and deletes them in bulk', async ({
    page,
  }) => {
    test.setTimeout(300_000);
    const { password } = await registerAndSignInViaUI(page);
    await gotoDocuments(page);
    for (const fixture of [README, CSV, UGLY_JSON]) await uploadDocument(page, fixture);

    const row = (fixture: string) => page.getByTestId('document-row').filter({ hasText: fixture });
    const bar = page.getByTestId('documents-selection-bar');
    // The row's own label: the checkbox inside it is visually hidden, so the
    // visible box is what a person presses.
    const tick = (fixture: string) => row(fixture).locator('label').click();
    const rowHeight = async (fixture: string): Promise<number> =>
      (await row(fixture).boundingBox())?.height ?? 0;

    // react-window takes the row height as a constant; the checkbox must not
    // change it, in either mode (jsdom does no layout, so only this can tell).
    expect(await rowHeight(README)).toBe(78);

    // A keyboard user sees where focus is, on a checkbox that is visually hidden.
    const box = page.getByRole('checkbox', { name: `Select ${README}` });
    const icon = box.locator('xpath=following-sibling::span');
    const ringAtRest = await icon.evaluate((el) => getComputedStyle(el).boxShadow);
    await box.focus();
    await page.keyboard.press('Shift+Tab');
    await page.keyboard.press('Tab');
    await expect(box).toBeFocused();
    const ringFocused = await icon.evaluate((el) => getComputedStyle(el).boxShadow);
    expect(ringFocused).not.toBe(ringAtRest);
    expect(ringFocused).not.toBe('none');

    await tick(README);
    await tick(CSV);
    await expect(bar).toContainText('2 selected');
    expect(await rowHeight(README)).toBe(78);
    // While selecting, a row selects instead of opening.
    await expect(row(UGLY_JSON).getByRole('link')).toHaveCount(0);

    // Tag the two.
    await bar.getByRole('button', { name: 'Tag' }).click();
    await page.getByPlaceholder('Enter tag name').fill('batch');
    await page.getByRole('button', { name: 'Apply' }).click();
    await expect(page.getByText('Tag "batch" added to 2 documents')).toBeVisible({
      timeout: 60_000,
    });
    await expect(bar).toHaveCount(0);

    // Sealed into each one's own metadata: it survives a reload, and only the
    // selected ones carry it.
    await reopenByUrl(page, '/documents', password);
    await expect(page.getByTestId('document-name')).toHaveCount(3, { timeout: 60_000 });
    await openDocument(page, README);
    await expect(page.getByText('batch', { exact: true })).toBeVisible();
    await page.goBack();
    await openDocument(page, UGLY_JSON);
    await expect(page.getByRole('heading', { name: UGLY_JSON, level: 1 })).toBeVisible();
    await expect(page.getByText('batch', { exact: true })).toHaveCount(0);
    await page.goBack();
    await expect(page.getByTestId('document-name')).toHaveCount(3, { timeout: 60_000 });

    // Trash the same two.
    await tick(README);
    await tick(CSV);
    await bar.getByRole('button', { name: 'Delete', exact: true }).click();
    const trashDialog = page.getByRole('dialog', { name: 'Move 2 documents to the trash' });
    await trashDialog.getByRole('button', { name: 'Move to trash' }).click();
    await expect(page.getByText('2 documents moved to the trash')).toBeVisible({ timeout: 60_000 });
    await expect(page.getByTestId('document-name')).toHaveCount(1);

    // Restore both from the trash at once.
    await page.getByRole('button', { name: /^Trash/ }).click();
    await expect(page.getByTestId('document-name')).toHaveCount(2, { timeout: 60_000 });
    await tick(README);
    // The select-all box is the bar's first label, pressed like every other box.
    await bar.locator('label').first().click();
    await expect(bar).toContainText('2 selected');
    await bar.getByRole('button', { name: 'Restore' }).click();
    await expect(page.getByText('2 documents restored')).toBeVisible({ timeout: 60_000 });
    await page.getByRole('button', { name: /^All Documents/ }).click();
    await expect(page.getByTestId('document-name')).toHaveCount(3, { timeout: 60_000 });

    // And one for good.
    await tick(UGLY_JSON);
    await bar.getByRole('button', { name: 'Delete', exact: true }).click();
    await page
      .getByRole('dialog', { name: 'Move 1 document to the trash' })
      .getByRole('button', { name: 'Move to trash' })
      .click();
    await page.getByRole('button', { name: /^Trash/ }).click();
    await expect(page.getByTestId('document-name')).toHaveCount(1, { timeout: 60_000 });
    await tick(UGLY_JSON);
    await bar.getByRole('button', { name: 'Delete forever' }).click();
    const purgeDialog = page.getByRole('dialog', { name: 'Delete 1 document for good' });
    await expect(purgeDialog).toContainText('Nothing on the server can bring it back');
    await purgeDialog.getByRole('button', { name: 'Delete forever' }).click();
    await expect(page.getByText('1 document permanently deleted')).toBeVisible({ timeout: 60_000 });
    await expect(page.getByText('The trash is empty')).toBeVisible();
  });

  test('refuses an upload that would take the account past its storage allowance', async ({
    page,
  }) => {
    test.setTimeout(300_000);
    await registerAndSignInViaUI(page);
    await gotoDocuments(page);

    await page
      .locator('#document-upload-input')
      .setInputFiles(filler('first-half.bin', HALF_QUOTA_BYTES));
    await page.getByRole('button', { name: 'Upload', exact: true }).click();
    await expect(
      page.getByTestId('document-name').filter({ hasText: 'first-half.bin' }),
    ).toBeVisible({ timeout: 60_000 });

    // The bar redraws against the allowance the server reports, not against a
    // number this client remembers from sign-in.
    const expectedPercent = String(
      Math.round((HALF_QUOTA_BYTES / (QUOTA_MB * BYTES_PER_MB)) * 100),
    );
    await expect(page.getByRole('progressbar', { name: 'Document storage used' })).toHaveAttribute(
      'aria-valuenow',
      expectedPercent,
    );

    await page
      .locator('#document-upload-input')
      .setInputFiles(filler('second-half.bin', HALF_QUOTA_BYTES));
    await page.getByRole('button', { name: 'Upload', exact: true }).click();

    // The server's own words, with the operator's number in them. It is a 400,
    // so the message survives to the browser — `exposeServerErrors: false`
    // redacts 5xx only — and the panel reports every failure that is not a
    // cancellation.
    await expect(page.getByText('Storage quota exceeded. Your limit is 1 MB.')).toBeVisible({
      timeout: 60_000,
    });

    // NEGATIVE: the refusal happened BEFORE anything was stored. One document is
    // listed, not two, and no transfer is left in the registry — so a refusal
    // raised after the parts had been sent, or one that left a half-finished
    // staging row visible, would fail here.
    await expect(page.getByTestId('document-name')).toHaveCount(1);
    await expect(page.getByTestId('upload-row')).toHaveCount(0);
  });

  test('offers nothing at all when the server says the document store is unconfigured', async ({
    page,
  }) => {
    test.setTimeout(300_000);

    // The one thing this spec stubs, and it is stubbed at the SERVER'S
    // ADVERTISEMENT rather than anywhere inside the client. The harness must
    // configure storage — every other journey here needs it — so the only way to
    // drive the unconfigured state in the same run is to answer `GET /config` the
    // way a server with no `S3_*` answers it. That answer is the entire input to
    // this state: `getDocumentsConfig` collapses "the block says disabled" and
    // "the block is absent" (an older server) into one, because the client does
    // the same thing for both.
    await page.route('**/api/v1/config', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          success: true,
          data: {
            fileEncryption: { maxSizeMB: 100 },
            documents: { enabled: false },
          },
        }),
      });
    });

    // Every request this page makes, so the assertion below is about what was
    // asked rather than about what was rendered.
    const documentRequests: string[] = [];
    page.on('request', (request) => {
      const url = new URL(request.url());
      if (/^\/api\/v1\/documents/.test(url.pathname)) documentRequests.push(url.pathname);
    });

    const { password } = await registerAndSignInViaUI(page);

    // The navigation entry is ABSENT, not disabled: `navItemsFor` drops it
    // entirely for anything but an explicit `enabled: true`.
    await expect(page.getByRole('link', { name: 'Vault', exact: true })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Documents', exact: true })).toHaveCount(0);

    // And the route itself explains, rather than failing: a user who kept a
    // bookmark gets a sentence naming what the operator has not configured.
    await reopenByUrl(page, '/documents', password);
    await expect(page.getByTestId('documents-unavailable')).toBeVisible({ timeout: 60_000 });
    await expect(page.getByTestId('documents-unavailable')).toContainText(
      'needs object storage, which the operator of this server has not configured',
    );

    // NEGATIVE, and it is the reason this state is decided from the public
    // configuration instead of by probing: nothing was requested. Every document
    // endpoint answers 503 behind `requireStorage`, and in production that body
    // is redacted to its status text — so a page that probed would have to
    // interpret an answer carrying no explanation at all.
    expect(documentRequests).toEqual([]);
  });
});

/**
 * The SHA-256 of some bytes, in the lowercase hex the detail view renders.
 *
 * Node's own crypto, deliberately: the digest on screen was computed in the
 * BROWSER by the upload path, and re-deriving it here with the same
 * implementation the application uses would compare that path with itself.
 */
async function digestOf(bytes: Buffer): Promise<string> {
  const { createHash } = await import('node:crypto');
  return createHash('sha256').update(bytes).digest('hex');
}

test.describe('documents: taking the library out as one ZIP archive', () => {
  test('hands the browser ONE archive, with folders mirrored, that opens to the exact bytes uploaded', async ({
    page,
  }) => {
    test.setTimeout(300_000);
    await disableSaveFilePicker(page);
    await registerAndSignInViaUI(page);
    await gotoDocuments(page);

    // One document filed in a folder, one at the root.
    await page.getByRole('button', { name: 'Create folder' }).click();
    await page.getByPlaceholder('Folder name').fill('Taxes');
    await page.getByRole('button', { name: 'Create', exact: true }).click();
    await page.getByRole('button', { name: /^Taxes/ }).click();
    await expect(page.getByTestId('upload-target-folder')).toContainText('Taxes');
    await uploadDocument(page, CSV);
    await page.getByRole('button', { name: /^All Documents/ }).click();
    await uploadDocument(page, README);

    // Every download this page starts, from before the run begins.
    const downloads: Download[] = [];
    page.on('download', (started) => {
      downloads.push(started);
    });
    const first = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Download all' }).click();
    await page.getByRole('button', { name: 'Start download' }).click();
    const archive = await first;
    const archivePath = await archive.path();

    expect(archive.suggestedFilename()).toMatch(/^hvault-documents-\d{4}-\d{2}-\d{2}\.zip$/);
    await expect(page.getByTestId('documents-download-all-status')).toContainText(
      `2 of 2 document(s) verified and handed to your browser's downloads as ${archive.suggestedFilename()}.`,
      { timeout: 120_000 },
    );
    // ONE download for the whole library, however many documents it holds.
    expect(downloads).toHaveLength(1);

    const entries = await zipEntries(readFileSync(archivePath));
    expect([...entries.keys()].sort()).toEqual([README, `Taxes/${CSV}`]);
    expect(entries.get(README)!.equals(documentFixtureBytes(README))).toBe(true);
    expect(entries.get(`Taxes/${CSV}`)!.equals(documentFixtureBytes(CSV))).toBe(true);
  });

  test('writes the archive into the file chosen in the save dialog, opened on the click itself', async ({
    page,
  }) => {
    test.setTimeout(300_000);
    // A save dialog that answers with a file in the browser's own private file
    // system, so the archive is written through a REAL FileSystemWritableFileStream.
    // It records, before its first await, whether the click's transient
    // activation was still live: a dialog opened after an await would be
    // refused by a real browser, and this is how the test can tell.
    await page.addInitScript(() => {
      const record = { activation: [] as boolean[], names: [] as string[] };
      Object.assign(window, {
        __archivePicker: record,
        showSaveFilePicker: async (options: { suggestedName: string }) => {
          record.activation.push(navigator.userActivation.isActive);
          record.names.push(options.suggestedName);
          const root = await navigator.storage.getDirectory();
          return root.getFileHandle(options.suggestedName, { create: true });
        },
      });
    });
    await registerAndSignInViaUI(page);
    await gotoDocuments(page);
    await uploadDocument(page, README);

    const downloads: Download[] = [];
    page.on('download', (started) => {
      downloads.push(started);
    });
    await page.getByRole('button', { name: 'Download all' }).click();
    await page.getByRole('button', { name: 'Start download' }).click();
    await expect(page.getByTestId('documents-download-all-status')).toContainText(
      /^1 of 1 document\(s\) verified and saved as hvault-documents-\d{4}-\d{2}-\d{2}\.zip\.$/,
      { timeout: 120_000 },
    );

    const picked = await page.evaluate(
      () =>
        (window as unknown as { __archivePicker: { activation: boolean[]; names: string[] } })
          .__archivePicker,
    );
    expect(picked.activation).toEqual([true]);
    expect(picked.names).toHaveLength(1);
    const written = await page.evaluate(async (name) => {
      const root = await navigator.storage.getDirectory();
      const file = await (await root.getFileHandle(name)).getFile();
      return Array.from(new Uint8Array(await file.arrayBuffer()));
    }, picked.names[0]!);

    const entries = await zipEntries(Buffer.from(written));
    expect([...entries.keys()]).toEqual([README]);
    expect(entries.get(README)!.equals(documentFixtureBytes(README))).toBe(true);
    // Nothing went through the browser's downloads.
    expect(downloads).toHaveLength(0);
  });
});
