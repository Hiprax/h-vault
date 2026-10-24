/**
 * Everything the Backup page needs from the full backup, as ONE module the page
 * loads on first use (`loadFullBackupJob.ts`).
 *
 * The engines, the format and the signature live outside the page's own chunk:
 * an account that only ever downloads its vault backup never fetches them, and a
 * vault backup restore (`.enc`) keeps working exactly as before even when this
 * chunk cannot be loaded.
 */
import { openSaveTarget, type ArchiveTarget } from '../documents/archiveTarget.js';
import { getSaveFilePicker } from '../documents/download.js';
import { FULL_BACKUP_FILE, fullBackupFileName } from './fullBackupFormat.js';

export { createFullBackup } from './createFullBackup.js';
export { FullBackupFormatError, openFullBackupFile } from './fullBackupFormat.js';
export { restoreFullBackupDocuments } from './restoreFullBackupDocuments.js';
export {
  deriveFullBackupSigningKey,
  verifyFullBackupManifest,
} from '../crypto/fullBackupCrypto.js';

/**
 * Open the file a full backup is written into, offered under today's name.
 *
 * MUST be called synchronously from the Save click: the save dialog opens only on
 * the click's own activation. Resolves `null` when the person dismisses it.
 */
export function openFullBackupTarget(now: Date): Promise<ArchiveTarget | null> {
  return openSaveTarget(fullBackupFileName(now), FULL_BACKUP_FILE);
}

/**
 * Whether this browser offers a save dialog. Without one the backup is built in
 * memory and handed to the downloads, which caps its size.
 */
export function hasSaveDialog(): boolean {
  return getSaveFilePicker() !== null;
}
