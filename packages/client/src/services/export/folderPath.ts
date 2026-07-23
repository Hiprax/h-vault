/**
 * Folder-path resolution for the portable plaintext export.
 *
 * Vault folders form a tree via `parentId` pointers only — there is no stored
 * path anywhere (the sole existing tree builder is the private `buildTree` in
 * `components/vault/FolderSidebar.tsx`). Portable formats (Bitwarden, Chrome)
 * express hierarchy as a slash-joined path string, so this module flattens the
 * pointer graph into `parent/child` paths.
 *
 * Two robustness properties matter here because the input is decrypted,
 * user-controlled data that may be malformed:
 *
 * - **Cycle-safe.** A `parentId` cycle (A→B→A) or a self-parent (X→X) must never
 *   recurse infinitely; the walk stops the moment it revisits a folder, yielding
 *   a truncated path rather than hanging the export.
 * - **Unresolvable parent → root.** A `parentId` pointing at a folder that is not
 *   in the input is treated as a root, exactly as `buildTree` does (it pushes a
 *   node to `roots` when `!map.has(parentId)`).
 *
 * A literal `/` inside a folder name is escaped (as is `\`, so the escape is
 * reversible) so a path segment is never mistaken for a nesting boundary.
 */

import type { DecryptedFolder } from '../../stores/vaultStore.js';

/** Path separator between nesting levels. */
const PATH_SEPARATOR = '/';

/**
 * Escape a folder name so a literal separator inside it cannot be confused with
 * a nesting boundary. Backslash is escaped first so the transformation is
 * unambiguous and reversible: `a/b` → `a\/b`, `a\b` → `a\\b`.
 */
function escapeSegment(name: string): string {
  return name.replace(/\\/g, '\\\\').replace(/\//g, '\\/');
}

/**
 * Build a map of folder id → full slash-joined path, cycle-safe and treating any
 * unresolvable `parentId` as a root.
 *
 * @param folders the decrypted folders to resolve paths for
 * @returns a `Map` keyed by folder id; every input folder has exactly one entry
 */
export function buildFolderPaths(folders: readonly DecryptedFolder[]): Map<string, string> {
  const byId = new Map<string, DecryptedFolder>();
  for (const folder of folders) {
    byId.set(folder.id, folder);
  }

  const paths = new Map<string, string>();
  for (const folder of folders) {
    const segments: string[] = [];
    const visited = new Set<string>();
    let current: DecryptedFolder | undefined = folder;

    // Walk up the parent chain, prepending each ancestor's name. `visited` breaks
    // any cycle (self-parent or longer); an unresolved parent ends the walk.
    while (current && !visited.has(current.id)) {
      visited.add(current.id);
      segments.unshift(escapeSegment(current.name));
      const parentId: string | undefined = current.parentId;
      current = parentId !== undefined && byId.has(parentId) ? byId.get(parentId) : undefined;
    }

    paths.set(folder.id, segments.join(PATH_SEPARATOR));
  }

  return paths;
}
