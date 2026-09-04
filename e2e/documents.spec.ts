import { test, expect, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
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
    // The repairer's own words, the POSITION it reported, and the source line it
    // points at. A refusal that named no line would send the reader back to a
    // file with no idea where to look, which is the difference this assertion
    // pins: `broken.json` carries an elided array element on its third line.
    await expect(page.getByTestId('transform-failure-message')).toContainText('Colon expected');
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
    // has to be given before an irreversible action: the object AND the only
    // copy of the key that opens it.
    await expect(purgeDialog).toContainText('Nothing can bring it back');
    await purgeDialog.getByRole('button', { name: 'Delete forever' }).click();

    await expect(page).toHaveURL(/\/documents$/);
    // Gone from both lists, which is what the id route proves and the list alone
    // could not: a purge that only cleared the active list would still answer
    // here from the trash.
    await reopenByUrl(page, `/documents/${id}`, password);
    await expect(page.getByTestId('document-not-found')).toBeVisible({ timeout: 60_000 });
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
