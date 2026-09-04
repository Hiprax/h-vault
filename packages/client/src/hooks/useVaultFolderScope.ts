import { useMemo } from 'react';
import { CreditCard, FileText, Key, Lock, User } from 'lucide-react';
import type { ItemType } from '@hvault/shared';
import { useVaultStore } from '../stores/vaultStore';
import type { FolderScope, FolderScopeOption } from '../components/folders/FolderRail';

/** The vault's secondary filter group: one entry per item type, in reading order. */
const TYPE_FILTERS: { type: ItemType; label: string; icon: FolderScopeOption['icon'] }[] = [
  { type: 'login', label: 'Logins', icon: Key },
  { type: 'secret', label: 'Secrets', icon: Lock },
  { type: 'note', label: 'Notes', icon: FileText },
  { type: 'card', label: 'Cards', icon: CreditCard },
  { type: 'identity', label: 'Identities', icon: User },
];

/**
 * `FolderRail`, bound to the vault.
 *
 * This hook is the ONE place the rail's view of `vaultStore` is assembled, which
 * is the point: the bug this whole change fixes came from two surfaces reading
 * the same filter state independently and disagreeing about it.
 *
 * The vault's own semantics are preserved exactly, including the one place they
 * differ from the documents scope: selecting a folder here does NOT clear the
 * favorites filter, so "favorites, inside this folder" remains reachable. The
 * documents scope is deliberately stricter; keeping the divergence in the two
 * hooks rather than in the rail is what lets both behave as their own users
 * already expect.
 */
export function useVaultFolderScope(): FolderScope {
  const items = useVaultStore((s) => s.items);
  const trashItems = useVaultStore((s) => s.trashItems);
  const selectedFolder = useVaultStore((s) => s.selectedFolder);
  const selectedType = useVaultStore((s) => s.selectedType);
  const showFavorites = useVaultStore((s) => s.showFavorites);
  const showTrash = useVaultStore((s) => s.showTrash);
  const setSelectedFolder = useVaultStore((s) => s.setSelectedFolder);
  const setSelectedType = useVaultStore((s) => s.setSelectedType);
  const setShowFavorites = useVaultStore((s) => s.setShowFavorites);
  const setShowTrash = useVaultStore((s) => s.setShowTrash);
  const toggleFavorites = useVaultStore((s) => s.toggleFavorites);
  const toggleTrash = useVaultStore((s) => s.toggleTrash);

  // Active rows only: `items` no longer carries the trash, and a folder badge
  // that counted trashed rows would promise more than the folder shows.
  const perFolder = useMemo(() => {
    const counts = new Map<string, number>();
    for (const item of items) {
      if (item.folderId) counts.set(item.folderId, (counts.get(item.folderId) ?? 0) + 1);
    }
    return counts;
  }, [items]);

  const typeCounts = useMemo(() => {
    const counts = new Map<ItemType, number>();
    for (const item of items) counts.set(item.itemType, (counts.get(item.itemType) ?? 0) + 1);
    return counts;
  }, [items]);

  const options = useMemo<FolderScopeOption[]>(
    () =>
      TYPE_FILTERS.map(({ type, label, icon }) => ({
        id: type,
        label,
        icon,
        count: typeCounts.get(type) ?? 0,
        selected: selectedType === type,
        onSelect: () => {
          // A second press on the active type clears it, which is how this
          // control has always behaved.
          setSelectedType(selectedType === type ? null : type);
          setSelectedFolder(null);
          setShowFavorites(false);
          setShowTrash(false);
        },
      })),
    [typeCounts, selectedType, setSelectedType, setSelectedFolder, setShowFavorites, setShowTrash],
  );

  return useMemo<FolderScope>(
    () => ({
      allLabel: 'All Items',
      counts: {
        all: items.length,
        favorites: items.filter((item) => item.favorite).length,
        trash: trashItems.length,
        perFolder,
      },
      selectedFolder,
      showFavorites,
      showTrash,
      // A selected TYPE also means "not all", which is why the rail is told this
      // rather than left to work it out from the three fields it can see.
      showingAll: !selectedFolder && !showFavorites && !showTrash && !selectedType,
      onSelectAll: () => {
        setSelectedFolder(null);
        setSelectedType(null);
        setShowFavorites(false);
        setShowTrash(false);
      },
      onSelectFolder: (folderId: string) => {
        setSelectedFolder(folderId);
        setSelectedType(null);
      },
      onToggleFavorites: () => {
        toggleFavorites();
        setSelectedType(null);
      },
      onToggleTrash: () => {
        toggleTrash();
        setSelectedType(null);
      },
      options,
      optionsLabel: 'Types',
    }),
    [
      items,
      trashItems,
      perFolder,
      selectedFolder,
      selectedType,
      showFavorites,
      showTrash,
      options,
      setSelectedFolder,
      setSelectedType,
      setShowFavorites,
      setShowTrash,
      toggleFavorites,
      toggleTrash,
    ],
  );
}
