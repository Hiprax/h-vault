import { useEffect } from 'react';
import { useVaultStore, type DecryptedFolder } from '../stores/vaultStore';

/**
 * The account's folders, read once for a route that does not otherwise use them.
 *
 * Folders are ONE collection shared by vault items and documents — the server
 * applies the same folder update to both — so the documents routes need the same
 * list the vault does, and a reader who arrived straight at `/documents` by URL
 * has never loaded it.
 *
 * Two properties are deliberate:
 *
 *   - It fetches only when the store holds NOTHING. The vault route loads
 *     folders on its own mount, so arriving from there costs no request at all.
 *   - It reports no error. A missing folder list costs the rail its names and
 *     the move menu its options, and nothing else; putting a failure in front of
 *     someone whose documents loaded perfectly well would be worse than the gap
 *     it describes.
 *
 * `enabled` exists because both callers decide whether the document store is
 * available at all before they render anything, and a disabled feature must not
 * issue a request on its way to saying so.
 */
export function useVaultFolders(enabled: boolean): DecryptedFolder[] {
  const folders = useVaultStore((state) => state.folders);
  const fetchFolders = useVaultStore((state) => state.fetchFolders);
  const folderCount = folders.length;

  useEffect(() => {
    if (!enabled || folderCount > 0) return;
    void fetchFolders().catch(() => {
      /* see the docblock: a missing folder list is not this route's failure. */
    });
  }, [enabled, folderCount, fetchFolders]);

  return folders;
}
