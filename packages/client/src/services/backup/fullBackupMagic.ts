/**
 * The first eight bytes of every full backup, and the one test that reads them.
 *
 * Kept apart from `fullBackupFormat.ts` so the Backup page can tell a full backup
 * from a vault backup (`.enc`) without loading the format module: a vault backup
 * restore must keep working exactly as it did, chunk failures included. The format
 * module imports the same bytes from here, so there is one definition.
 *
 * "HVFB", then CR LF SUB LF: the same line-ending tripwire a PNG signature carries,
 * so a file mangled by a text-mode transfer is refused at its first bytes. Only these
 * eight are compared; the format version after them is the reader's to judge, in its
 * own words, so a file from a newer release is never mistaken for a `.enc` file.
 */
export const FULL_BACKUP_MAGIC: readonly number[] = [
  0x48, 0x56, 0x46, 0x42, 0x0d, 0x0a, 0x1a, 0x0a,
];

/** Whether `file` starts like a full backup. */
export async function isFullBackupFile(file: Blob): Promise<boolean> {
  const head = new Uint8Array(await file.slice(0, FULL_BACKUP_MAGIC.length).arrayBuffer());
  return FULL_BACKUP_MAGIC.every((byte, index) => head[index] === byte);
}
