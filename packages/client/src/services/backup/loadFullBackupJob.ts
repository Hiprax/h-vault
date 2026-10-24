/** What the Backup page says when the full backup's code could not be fetched. */
const FULL_BACKUP_UNAVAILABLE_MESSAGE =
  'Part of H-Vault needed for full backups did not load. Try again; if it keeps failing, reload the page.';

/** Load the full backup's code (`fullBackupJob.ts`), which is never in the Backup page's chunk. */
export function loadFullBackupJob(): Promise<typeof import('./fullBackupJob.js')> {
  return import('./fullBackupJob.js').catch((error: unknown) => {
    throw new Error(FULL_BACKUP_UNAVAILABLE_MESSAGE, { cause: error });
  });
}
