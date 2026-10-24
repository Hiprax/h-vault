import { test, expect, type Download, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import {
  createNoteViaUI,
  disableSaveFilePicker,
  documentFixture,
  gotoDocuments,
  openDocument,
  registerAndSignInViaUI,
  uploadDocument,
} from './helpers';

/**
 * The full backup (0.22.0), end to end: the vault AND every document saved as one
 * encrypted, signed file in the browser, then restored through the same Restore
 * form after the documents were deleted for good.
 *
 * Nothing is stubbed on the document path: every byte goes through the real
 * storage engine `e2e/start-server.ts` starts, is read back and verified while the
 * backup is made, and is uploaded again as new ciphertext when it is restored
 * (the document id is part of every per-document key, and the server mints the
 * new ids). The save dialog is the only thing replaced, in the second journey, by
 * one that answers with a file in the browser's own private file system.
 */

const CSV = 'contacts.csv';
const README = 'README.md';
const BACKUP_PASSWORD = 'Full-Backup-E2E!7Qx#Tz9';
const VAULT_NOTE = 'Kept note';
const FULL_BACKUP_NAME = /^hvault-full-backup-\d{4}-\d{2}-\d{2}\.hvbackup$/;

async function gotoBackupSettings(page: Page): Promise<void> {
  await page.getByRole('link', { name: 'Settings', exact: true }).click();
  await expect(page).toHaveURL(/\/settings$/);
  await page.getByRole('link', { name: 'Backup Settings' }).click();
  await expect(page).toHaveURL(/\/settings\/backup$/);
  await expect(page.getByRole('heading', { name: 'Backup Settings', level: 1 })).toBeVisible({
    timeout: 60_000,
  });
}

/** Set up backup encryption through the page's own form, as a person does. */
async function setUpBackupEncryption(page: Page, masterPassword: string): Promise<void> {
  await page.locator('#backup-password').fill(BACKUP_PASSWORD);
  await page.locator('#confirm-backup-password').fill(BACKUP_PASSWORD);
  await page.locator('#setup-master-password').fill(masterPassword);
  await page.getByRole('button', { name: 'Setup Encryption' }).click();
  await expect(page.getByText('Backup encryption configured')).toBeVisible({ timeout: 180_000 });
}

/** Open the Full Backup panel and get it to its Save step. */
async function prepareFullBackup(page: Page): Promise<void> {
  await page.getByRole('button', { name: 'Full Backup', exact: true }).click();
  await page.getByLabel('Backup password for the full backup').fill(BACKUP_PASSWORD);
  await page.getByRole('button', { name: 'Continue', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Save full backup' })).toBeVisible({
    timeout: 120_000,
  });
}

/** Move a listed document to the trash from its own page. */
async function trashDocument(page: Page, name: string): Promise<void> {
  await openDocument(page, name);
  await page.getByRole('button', { name: 'Delete', exact: true }).click();
  await page
    .getByRole('dialog', { name: 'Move to trash' })
    .getByRole('button', { name: 'Move to trash' })
    .click();
  await expect(page).toHaveURL(/\/documents$/);
}

/** Restore `file` with Skip, and wait for the documents phase to say what it did. */
async function restoreWithSkip(page: Page, file: string): Promise<void> {
  await page.getByRole('button', { name: 'Restore from File' }).click();
  await page.locator('input[type="file"]').setInputFiles(file);
  await page.locator('#restore-password').fill(BACKUP_PASSWORD);
  await page.getByRole('radio', { name: /Skip/ }).check();
  await page.getByRole('button', { name: 'Restore', exact: true }).click();
  await expect(page.getByTestId('document-restore-status')).toContainText('Documents restored:', {
    timeout: 240_000,
  });
}

test.describe('full backup: the vault and every document, in one file', () => {
  test('backs up two documents, brings them back after they were deleted for good, and adds nothing the second time', async ({
    page,
  }, testInfo) => {
    test.setTimeout(900_000);
    await disableSaveFilePicker(page);
    const { password } = await registerAndSignInViaUI(page);
    await createNoteViaUI(page, VAULT_NOTE);

    // One document filed in a folder and favorited; one at the root, tagged and
    // with a note, typed into the upload form itself.
    await gotoDocuments(page);
    await page.getByRole('button', { name: 'Create folder' }).click();
    await page.getByPlaceholder('Folder name').fill('Taxes');
    await page.getByRole('button', { name: 'Create', exact: true }).click();
    await page.getByRole('button', { name: /^Taxes/ }).click();
    await expect(page.getByTestId('upload-target-folder')).toContainText('Taxes');
    await uploadDocument(page, CSV);
    await openDocument(page, CSV);
    await page.getByRole('button', { name: 'Favorite' }).click();
    await expect(page.getByRole('button', { name: 'Favorited' })).toBeVisible({ timeout: 60_000 });
    await page.getByRole('link', { name: 'Back to documents' }).click();
    await page.getByRole('button', { name: /^All Documents/ }).click();
    await page.locator('#document-upload-input').setInputFiles(documentFixture(README));
    await page.getByPlaceholder('Add a tag...').fill('handbook');
    await page.getByPlaceholder('Add a tag...').press('Enter');
    await page.locator('#document-upload-note').fill('Read before onboarding');
    await page.getByRole('button', { name: 'Upload', exact: true }).click();
    await expect(page.getByTestId('document-name').filter({ hasText: README })).toBeVisible({
      timeout: 60_000,
    });

    // The full backup, handed to the browser's downloads (no save dialog here).
    await gotoBackupSettings(page);
    await setUpBackupEncryption(page, password);
    await prepareFullBackup(page);
    const downloaded = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Save full backup' }).click();
    const backup: Download = await downloaded;
    expect(backup.suggestedFilename()).toMatch(FULL_BACKUP_NAME);
    await expect(page.getByTestId('full-backup-status')).toContainText(
      `Full backup handed to your browser's downloads as ${backup.suggestedFilename()}`,
      { timeout: 240_000 },
    );
    await expect(page.getByTestId('full-backup-status')).toContainText('and 2 document(s).');
    const backupPath = testInfo.outputPath('full-backup.hvbackup');
    await backup.saveAs(backupPath);
    // A full backup, by its first eight bytes, never a vault backup.
    expect([...readFileSync(backupPath).subarray(0, 8)]).toEqual([
      0x48, 0x56, 0x46, 0x42, 0x0d, 0x0a, 0x1a, 0x0a,
    ]);

    // Both documents deleted for good: trashed, then the trash emptied.
    await gotoDocuments(page);
    await trashDocument(page, CSV);
    await trashDocument(page, README);
    await page.getByRole('button', { name: /^Trash/ }).click();
    await page.getByRole('button', { name: 'Empty trash' }).click();
    await page.getByRole('button', { name: 'Delete all forever' }).click();
    await expect(page.getByTestId('document-name')).toHaveCount(0, { timeout: 60_000 });
    // Back to the list, which the Documents page reopens on.
    await page.getByRole('button', { name: /^All Documents/ }).click();

    // Restored through the same form, with Skip.
    await gotoBackupSettings(page);
    await restoreWithSkip(page, backupPath);
    await expect(page.getByTestId('document-restore-status')).toContainText(
      'Documents restored: 2 in the backup. 2 uploaded, 0 taken out of the trash, 0 updated, 0 already here.',
    );

    // Every detail is back: the folder, the favorite, the tag and the note.
    await gotoDocuments(page);
    await page.getByRole('button', { name: /^All Documents/ }).click();
    await expect(page.getByTestId('document-name')).toHaveCount(2, { timeout: 60_000 });
    await expect(page.getByTestId('document-row').filter({ hasText: CSV })).toContainText('Taxes');
    await page.getByRole('button', { name: /^Favorites/ }).click();
    await expect(page.getByTestId('document-name')).toHaveCount(1, { timeout: 60_000 });
    await expect(page.getByTestId('document-name').filter({ hasText: CSV })).toBeVisible();
    await page.getByRole('button', { name: /^All Documents/ }).click();
    await openDocument(page, README);
    await expect(page.getByText('handbook', { exact: true })).toBeVisible({ timeout: 60_000 });
    await expect(page.getByText('Read before onboarding')).toBeVisible();
    await page.getByRole('link', { name: 'Back to documents' }).click();

    // The vault rows were never disturbed.
    await page.getByRole('link', { name: 'Vault', exact: true }).click();
    await expect(page.getByTestId('vault-item-name').filter({ hasText: VAULT_NOTE })).toHaveCount(
      1,
      { timeout: 60_000 },
    );

    // Running the same restore again with Skip adds nothing.
    await gotoBackupSettings(page);
    await restoreWithSkip(page, backupPath);
    await expect(page.getByTestId('document-restore-status')).toContainText(
      'Documents restored: 2 in the backup. 0 uploaded, 0 taken out of the trash, 0 updated, 2 already here.',
    );
    await gotoDocuments(page);
    await expect(page.getByTestId('document-name')).toHaveCount(2, { timeout: 60_000 });
  });

  test('writes the file chosen in the save dialog, opened on the Save click itself', async ({
    page,
  }) => {
    test.setTimeout(600_000);
    await page.addInitScript(() => {
      const record = { activation: [] as boolean[], names: [] as string[] };
      Object.assign(window, {
        __fullBackupPicker: record,
        showSaveFilePicker: async (options: { suggestedName: string }) => {
          record.activation.push(navigator.userActivation.isActive);
          record.names.push(options.suggestedName);
          const root = await navigator.storage.getDirectory();
          return root.getFileHandle(options.suggestedName, { create: true });
        },
      });
    });
    const { password } = await registerAndSignInViaUI(page);
    await gotoDocuments(page);
    await uploadDocument(page, README);

    const downloads: Download[] = [];
    page.on('download', (started) => {
      downloads.push(started);
    });
    await gotoBackupSettings(page);
    await setUpBackupEncryption(page, password);
    await prepareFullBackup(page);
    await page.getByRole('button', { name: 'Save full backup' }).click();
    await expect(page.getByTestId('full-backup-status')).toContainText(/Full backup saved as /, {
      timeout: 240_000,
    });

    const picked = await page.evaluate(
      () =>
        (window as unknown as { __fullBackupPicker: { activation: boolean[]; names: string[] } })
          .__fullBackupPicker,
    );
    expect(picked.activation).toEqual([true]);
    expect(picked.names).toHaveLength(1);
    expect(picked.names[0]).toMatch(FULL_BACKUP_NAME);
    const head = await page.evaluate(async (name) => {
      const root = await navigator.storage.getDirectory();
      const file = await (await root.getFileHandle(name)).getFile();
      return {
        size: file.size,
        head: Array.from(new Uint8Array(await file.slice(0, 8).arrayBuffer())),
      };
    }, picked.names[0]!);
    expect(head.head).toEqual([0x48, 0x56, 0x46, 0x42, 0x0d, 0x0a, 0x1a, 0x0a]);
    expect(head.size).toBeGreaterThan(readFileSync(documentFixture(README)).length);
    // Nothing went through the browser's downloads.
    expect(downloads).toHaveLength(0);
  });
});
