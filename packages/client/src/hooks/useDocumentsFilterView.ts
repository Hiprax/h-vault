import { useMemo } from 'react';
import { useDocumentsStore, type DecryptedDocument } from '../stores/documentsStore';
import { useVaultFolders } from './useVaultFolders';
import { documentMatchesQuery } from '../lib/documentSearch';
import type { FolderScope } from '../components/folders/FolderRail';

/**
 * Which rows the documents list is showing.
 *
 * The four are mutually exclusive, which is what lets the page render one
 * `switch` and exactly four empty states instead of a matrix of combinations
 * nobody asked for.
 */
export type DocumentListMode =
  { kind: 'all' } | { kind: 'favorites' } | { kind: 'folder'; id: string } | { kind: 'trash' };

export interface DocumentsFilterView {
  scope: FolderScope;
  mode: DocumentListMode;
  /** The rows to render, already filtered and searched. */
  rows: DecryptedDocument[];
  /** Whether the list the current mode reads is still loading. */
  loading: boolean;
  /** Rows the current mode's fetch could not open, and rows it dropped. */
  degradedCount: number;
  invalidCount: number;
  /** Folder id to name, for the row chips and the empty state. */
  folderNames: ReadonlyMap<string, string>;
  /** The folder a new upload should be filed into, with the name to say so. */
  uploadFolder: { id: string; name: string } | undefined;
}

/**
 * `FolderRail`'s scope for the documents route, plus everything the page needs to
 * render the mode that scope selects.
 *
 * One hook rather than two, because the page needs the SAME answer the rail is
 * showing: the folder it has highlighted decides which rows are listed, where a
 * new upload is filed, and what the empty state says. Splitting them would give
 * the page a second, independent reader of one piece of state — which is exactly
 * the arrangement that let a document's folder and favorite change nothing
 * anybody could see.
 */
export function useDocumentsFilterView(enabled: boolean): DocumentsFilterView {
  const folders = useVaultFolders(enabled);
  const documents = useDocumentsStore((s) => s.documents);
  const trashDocuments = useDocumentsStore((s) => s.trashDocuments);
  const documentsLoading = useDocumentsStore((s) => s.documentsLoading);
  const trashLoading = useDocumentsStore((s) => s.trashLoading);
  const degraded = useDocumentsStore((s) => s.degradedCount);
  const invalid = useDocumentsStore((s) => s.invalidCount);
  const trashDegraded = useDocumentsStore((s) => s.trashDegradedCount);
  const trashInvalid = useDocumentsStore((s) => s.trashInvalidCount);
  const selectedFolder = useDocumentsStore((s) => s.selectedFolder);
  const showFavorites = useDocumentsStore((s) => s.showFavorites);
  const showTrash = useDocumentsStore((s) => s.showTrash);
  const searchQuery = useDocumentsStore((s) => s.searchQuery);
  const setSelectedFolder = useDocumentsStore((s) => s.setSelectedFolder);
  const toggleFavorites = useDocumentsStore((s) => s.toggleFavorites);
  const toggleTrash = useDocumentsStore((s) => s.toggleTrash);
  const clearFilters = useDocumentsStore((s) => s.clearFilters);

  const folderNames = useMemo(
    () => new Map(folders.map((folder) => [folder.id, folder.name])),
    [folders],
  );

  // Active rows only. A badge that counted the trash would tell a reader a folder
  // holds five documents and then show them three.
  const perFolder = useMemo(() => {
    const counts = new Map<string, number>();
    for (const doc of documents) {
      if (doc.folderId) counts.set(doc.folderId, (counts.get(doc.folderId) ?? 0) + 1);
    }
    return counts;
  }, [documents]);

  const mode = useMemo<DocumentListMode>(() => {
    if (showTrash) return { kind: 'trash' };
    if (showFavorites) return { kind: 'favorites' };
    if (selectedFolder !== null) return { kind: 'folder', id: selectedFolder };
    return { kind: 'all' };
  }, [showTrash, showFavorites, selectedFolder]);

  const rows = useMemo(() => {
    // One `switch` over the mode rather than a run of `if (x && !showTrash)`
    // guards: the modes are exclusive by construction in the store, so a filter
    // that had to exclude the trash three times would be describing a state that
    // cannot happen.
    const base = ((): DecryptedDocument[] => {
      switch (mode.kind) {
        case 'trash':
          return trashDocuments;
        case 'favorites':
          return documents.filter((doc) => doc.favorite);
        case 'folder':
          return documents.filter((doc) => doc.folderId === mode.id);
        case 'all':
        default:
          return documents;
      }
    })();
    const query = searchQuery.trim().toLowerCase();
    // Lowercased once per keystroke rather than once per row.
    return query === '' ? base : base.filter((doc) => documentMatchesQuery(doc, query));
  }, [mode, documents, trashDocuments, searchQuery]);

  const scope = useMemo<FolderScope>(
    () => ({
      allLabel: 'All Documents',
      counts: {
        all: documents.length,
        favorites: documents.filter((doc) => doc.favorite).length,
        trash: trashDocuments.length,
        perFolder,
      },
      selectedFolder,
      showFavorites,
      showTrash,
      // Documents have no secondary group, so "all" is exactly the absence of the
      // three filters the rail can see. It is still passed rather than inferred,
      // because the rail must not have to know which scope it is rendering.
      showingAll: selectedFolder === null && !showFavorites && !showTrash,
      onSelectAll: clearFilters,
      onSelectFolder: setSelectedFolder,
      onToggleFavorites: toggleFavorites,
      onToggleTrash: toggleTrash,
    }),
    [
      documents,
      trashDocuments,
      perFolder,
      selectedFolder,
      showFavorites,
      showTrash,
      clearFilters,
      setSelectedFolder,
      toggleFavorites,
      toggleTrash,
    ],
  );

  const uploadFolder = useMemo(() => {
    if (selectedFolder === null) return undefined;
    const name = folderNames.get(selectedFolder);
    return name === undefined ? undefined : { id: selectedFolder, name };
  }, [selectedFolder, folderNames]);

  return {
    scope,
    mode,
    rows,
    // Each mode reads its own list, so the skeleton has to follow the fetch that
    // actually feeds it: the trash view spinning on the active list's flag would
    // show rows before they were there and a skeleton after they arrived.
    loading: mode.kind === 'trash' ? trashLoading : documentsLoading,
    degradedCount: mode.kind === 'trash' ? trashDegraded : degraded,
    invalidCount: mode.kind === 'trash' ? trashInvalid : invalid,
    folderNames,
    uploadFolder,
  };
}
