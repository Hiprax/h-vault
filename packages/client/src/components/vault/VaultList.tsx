import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { List } from 'react-window';
import type { RowComponentProps } from 'react-window';
import {
  Key,
  FileText,
  CreditCard,
  User,
  Lock,
  Star,
  Plus,
  ShieldOff,
  CheckSquare,
  Square,
  Trash2,
  FolderOpen,
  Loader2,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  Tag,
} from 'lucide-react';
import { cn } from '../../lib/utils';
import { itemMatchesSearch } from '../../lib/vaultSearch';
import { VAULT_SEARCH_RESULTS_ID } from './SearchBar';
import {
  useVaultStore,
  type DecryptedVaultItem,
  type SortBy,
  type SortOrder,
} from '../../stores/vaultStore';
import { bulkDeleteApi, bulkMoveApi, permanentDeleteApi } from '../../services/api/vaultApi';
import { useToast } from '../ui/Toast';
import { useInlineDialog } from '../ui/Dialog';
import type { ItemType } from '@hvault/shared';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ITEM_HEIGHT = 72;
const VIRTUALIZATION_THRESHOLD = 50;

const ICON_MAP: Record<ItemType, typeof Key> = {
  login: Key,
  note: FileText,
  card: CreditCard,
  identity: User,
  secret: Lock,
};

const TYPE_LABELS: Record<ItemType, string> = {
  login: 'Login',
  note: 'Note',
  card: 'Card',
  identity: 'Identity',
  secret: 'Secret',
};

const TYPE_BADGE_COLORS: Record<ItemType, string> = {
  login: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  note: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
  card: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300',
  identity: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
  secret: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
};

const SORT_OPTIONS: { value: SortBy; label: string }[] = [
  { value: 'name', label: 'Name' },
  { value: 'dateCreated', label: 'Date Created' },
  { value: 'dateModified', label: 'Date Modified' },
  { value: 'type', label: 'Type' },
];

function sortItems(
  items: DecryptedVaultItem[],
  sortBy: SortBy,
  sortOrder: SortOrder,
): DecryptedVaultItem[] {
  const sorted = [...items].sort((a, b) => {
    let cmp = 0;
    switch (sortBy) {
      case 'name':
        cmp = a.name.localeCompare(b.name);
        break;
      case 'dateCreated':
        cmp = new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
        break;
      case 'dateModified':
        cmp = new Date(a.updatedAt).getTime() - new Date(b.updatedAt).getTime();
        break;
      case 'type':
        cmp = a.itemType.localeCompare(b.itemType);
        break;
    }
    return sortOrder === 'asc' ? cmp : -cmp;
  });
  return sorted;
}

// ---------------------------------------------------------------------------
// Skeleton loader
// ---------------------------------------------------------------------------

const SkeletonRow = memo(function SkeletonRow() {
  return (
    <div className="flex items-center gap-4 rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-4 animate-pulse">
      <div className="h-10 w-10 rounded-lg bg-[hsl(var(--muted))]" />
      <div className="flex-1 space-y-2">
        <div className="h-4 w-1/3 rounded bg-[hsl(var(--muted))]" />
        <div className="h-3 w-1/5 rounded bg-[hsl(var(--muted))]" />
      </div>
      <div className="h-3 w-20 rounded bg-[hsl(var(--muted))]" />
    </div>
  );
});

function LoadingSkeleton() {
  return (
    <div className="space-y-2">
      {Array.from({ length: 6 }, (_, i) => (
        <SkeletonRow key={i} />
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Empty state
// ---------------------------------------------------------------------------

const EmptyState = memo(function EmptyState({
  onCreateNew,
  isTrash,
}: {
  onCreateNew: () => void;
  isTrash: boolean;
}) {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-center">
      <div className="flex h-16 w-16 items-center justify-center rounded-full bg-[hsl(var(--muted))]">
        {isTrash ? (
          <Trash2 className="h-8 w-8 text-[hsl(var(--muted-foreground))]" />
        ) : (
          <ShieldOff className="h-8 w-8 text-[hsl(var(--muted-foreground))]" />
        )}
      </div>
      <h3 className="mt-4 text-lg font-semibold text-[hsl(var(--foreground))]">
        {isTrash ? 'Trash is empty' : 'No items found'}
      </h3>
      <p className="mt-1 max-w-sm text-sm text-[hsl(var(--muted-foreground))]">
        {isTrash
          ? 'Items you delete will appear here. They are permanently removed after 30 days.'
          : 'Your vault is empty. Start by creating your first secure item to keep your passwords, notes, and secrets safe.'}
      </p>
      {!isTrash && (
        <button
          type="button"
          onClick={onCreateNew}
          className="mt-6 inline-flex items-center gap-2 rounded-md bg-[hsl(var(--primary))] px-4 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 transition-opacity"
        >
          <Plus className="h-4 w-4" />
          Create Item
        </button>
      )}
    </div>
  );
});

// ---------------------------------------------------------------------------
// Single list item
// ---------------------------------------------------------------------------

interface VaultListItemProps {
  item: DecryptedVaultItem;
  isSelected: boolean;
  onToggleSelect: (id: string) => void;
  multiSelectMode: boolean;
}

const VaultListItem = memo(function VaultListItem({
  item,
  isSelected,
  onToggleSelect,
  multiSelectMode,
}: VaultListItemProps) {
  const navigate = useNavigate();
  const Icon = ICON_MAP[item.itemType];
  const lastModified = new Date(item.updatedAt).toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });

  const handleClick = useCallback(() => {
    if (multiSelectMode) {
      onToggleSelect(item.id);
    } else {
      void navigate(`/vault/${item.id}`);
    }
  }, [multiSelectMode, item.id, navigate, onToggleSelect]);

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={handleClick}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          handleClick();
        }
      }}
      className={cn(
        'flex items-center gap-4 rounded-lg border bg-[hsl(var(--card))] p-4 transition-colors cursor-pointer',
        isSelected
          ? 'border-[hsl(var(--primary))] bg-[hsl(var(--primary)/0.05)]'
          : 'border-[hsl(var(--border))] hover:bg-[hsl(var(--accent))]',
      )}
      aria-current={isSelected ? 'true' : undefined}
    >
      {/* Checkbox */}
      <label
        className="shrink-0 relative flex items-center cursor-pointer"
        onClick={(e) => e.stopPropagation()}
      >
        <input
          type="checkbox"
          checked={isSelected}
          onChange={() => onToggleSelect(item.id)}
          className="peer sr-only"
          aria-label={isSelected ? 'Deselect item' : 'Select item'}
        />
        <span className="text-[hsl(var(--muted-foreground))] peer-checked:text-[hsl(var(--primary))] hover:text-[hsl(var(--foreground))] transition-colors">
          {isSelected ? <CheckSquare className="h-5 w-5" /> : <Square className="h-5 w-5" />}
        </span>
      </label>

      {/* Icon */}
      <div
        className={cn(
          'flex h-10 w-10 shrink-0 items-center justify-center rounded-lg',
          TYPE_BADGE_COLORS[item.itemType],
        )}
      >
        <Icon className="h-5 w-5" />
      </div>

      {/* Name + type */}
      <div className="flex min-w-0 flex-1 flex-col gap-1">
        <span className="truncate text-sm font-medium text-[hsl(var(--card-foreground))]">
          {item.name || 'Unnamed item'}
        </span>
        <span
          className={cn(
            'inline-flex w-fit rounded-full px-2 py-0.5 text-xs font-medium',
            TYPE_BADGE_COLORS[item.itemType],
          )}
        >
          {TYPE_LABELS[item.itemType]}
        </span>
      </div>

      {/* Favorite star */}
      {item.favorite && <Star className="h-4 w-4 shrink-0 fill-yellow-400 text-yellow-400" />}

      {/* Last modified */}
      <span className="hidden shrink-0 text-xs text-[hsl(var(--muted-foreground))] sm:block">
        {lastModified}
      </span>
    </div>
  );
});

// ---------------------------------------------------------------------------
// Virtualized row wrapper
// ---------------------------------------------------------------------------

interface RowData {
  filteredItems: DecryptedVaultItem[];
  selectedItems: Set<string>;
  onToggleSelect: (id: string) => void;
  multiSelectMode: boolean;
}

function VirtualizedRow(props: RowComponentProps<RowData>) {
  const {
    index,
    style,
    ariaAttributes,
    filteredItems,
    selectedItems,
    onToggleSelect,
    multiSelectMode,
  } = props;
  const item = filteredItems[index];
  if (!item) return null;

  return (
    <div style={{ ...style, paddingBottom: 8 }} {...ariaAttributes}>
      <VaultListItem
        item={item}
        isSelected={selectedItems.has(item.id)}
        onToggleSelect={onToggleSelect}
        multiSelectMode={multiSelectMode}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main list component
// ---------------------------------------------------------------------------

interface VaultListProps {
  onCreateNew: () => void;
}

export function VaultList({ onCreateNew }: VaultListProps) {
  const items = useVaultStore((s) => s.items);
  const trashItems = useVaultStore((s) => s.trashItems);
  const loading = useVaultStore((s) => s.loading);
  const itemsLoading = useVaultStore((s) => s.itemsLoading);
  const itemsLoaded = useVaultStore((s) => s.itemsLoaded);
  const itemsTotal = useVaultStore((s) => s.itemsTotal);
  const searchQuery = useVaultStore((s) => s.searchQuery);
  const selectedFolder = useVaultStore((s) => s.selectedFolder);
  const selectedType = useVaultStore((s) => s.selectedType);
  const showFavorites = useVaultStore((s) => s.showFavorites);
  const showTrash = useVaultStore((s) => s.showTrash);
  const fetchItems = useVaultStore((s) => s.fetchItems);
  const fetchTrashItems = useVaultStore((s) => s.fetchTrashItems);
  const emptyTrash = useVaultStore((s) => s.emptyTrash);
  const folders = useVaultStore((s) => s.folders);
  const sortBy = useVaultStore((s) => s.sortBy);
  const sortOrder = useVaultStore((s) => s.sortOrder);
  const setFilteredItemCount = useVaultStore((s) => s.setFilteredItemCount);
  const setSortBy = useVaultStore((s) => s.setSortBy);
  const setSortOrder = useVaultStore((s) => s.setSortOrder);
  const { toast } = useToast();

  const [showEmptyTrashConfirm, setShowEmptyTrashConfirm] = useState(false);
  const [emptyingTrash, setEmptyingTrash] = useState(false);

  const [selectedItems, setSelectedItems] = useState(() => new Set<string>());
  const [bulkLoading, setBulkLoading] = useState(false);
  const [showMoveMenu, setShowMoveMenu] = useState(false);
  const [showTagMenu, setShowTagMenu] = useState(false);
  const [bulkTagInput, setBulkTagInput] = useState('');
  const [showSortMenu, setShowSortMenu] = useState(false);
  const [showBulkDeleteConfirm, setShowBulkDeleteConfirm] = useState(false);

  const emptyTrashDialogRef = useRef<HTMLDivElement>(null);
  const closeEmptyTrashDialog = useCallback(() => setShowEmptyTrashConfirm(false), []);
  useInlineDialog(emptyTrashDialogRef, showEmptyTrashConfirm, closeEmptyTrashDialog);

  const bulkDeleteDialogRef = useRef<HTMLDivElement>(null);
  const closeBulkDeleteDialog = useCallback(() => setShowBulkDeleteConfirm(false), []);
  useInlineDialog(bulkDeleteDialogRef, showBulkDeleteConfirm, closeBulkDeleteDialog);

  const toggleSelect = useCallback((id: string) => {
    setSelectedItems((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const multiSelectMode = selectedItems.size > 0;

  // Filter items based on store state
  const filteredItems = useMemo(() => {
    // Use trash items when in trash view, regular items otherwise
    let result = showTrash ? trashItems : items;

    // Favorites
    if (showFavorites && !showTrash) {
      result = result.filter((i) => i.favorite);
    }

    // Folder
    if (selectedFolder && !showTrash) {
      result = result.filter((i) => i.folderId === selectedFolder);
    }

    // Type
    if (selectedType && !showTrash) {
      result = result.filter((i) => i.itemType === selectedType);
    }

    // Full-text search across all decrypted fields
    if (searchQuery.trim()) {
      const lq = searchQuery.toLowerCase();
      result = result.filter((item) => itemMatchesSearch(item, lq));
    }

    // Sort
    result = sortItems(result, sortBy, sortOrder);

    return result;
  }, [
    items,
    trashItems,
    searchQuery,
    selectedFolder,
    selectedType,
    showFavorites,
    showTrash,
    sortBy,
    sortOrder,
  ]);

  // Sync filtered count to store so SearchBar can read it without duplicating
  // the filtering logic.
  useEffect(() => {
    setFilteredItemCount(searchQuery.trim().length > 0 ? filteredItems.length : null);
  }, [filteredItems.length, searchQuery, setFilteredItemCount]);

  // Progressive loading badge: visible while items are still being fetched
  // and decrypted but at least one row has arrived in the store. This lets
  // the user see rows render before the entire vault is decrypted.
  const showProgressBadge =
    !showTrash && itemsLoading && items.length > 0 && itemsTotal !== null && itemsTotal > 0;
  const progressLabel = showProgressBadge
    ? `Loading ${String(itemsLoaded)} / ${String(itemsTotal)}`
    : null;

  // Announce item count changes to screen readers
  const liveAnnouncement = useMemo(() => {
    if (loading && filteredItems.length === 0) return 'Loading items...';
    if (progressLabel !== null) return progressLabel;
    if (filteredItems.length === 0) {
      return showTrash ? 'Trash is empty.' : 'No items found.';
    }
    const context = showTrash ? 'trash' : 'vault';
    return `${String(filteredItems.length)} item${filteredItems.length === 1 ? '' : 's'} in ${context}.`;
  }, [filteredItems.length, loading, progressLabel, showTrash]);

  // Show the skeleton only on the initial load (no rows yet). Once rows
  // start arriving, switch to the progressive list rendering with a badge
  // so the user gets immediate feedback.
  if (loading && filteredItems.length === 0) {
    return (
      <>
        <div aria-live="polite" className="sr-only">
          {liveAnnouncement}
        </div>
        <LoadingSkeleton />
      </>
    );
  }

  if (filteredItems.length === 0) {
    return (
      <>
        <div aria-live="polite" className="sr-only">
          {liveAnnouncement}
        </div>
        <EmptyState onCreateNew={onCreateNew} isTrash={showTrash} />
      </>
    );
  }

  const useVirtualization = filteredItems.length > VIRTUALIZATION_THRESHOLD;

  const rowData: RowData = {
    filteredItems,
    selectedItems,
    onToggleSelect: toggleSelect,
    multiSelectMode,
  };

  return (
    <div className="relative">
      <div aria-live="polite" className="sr-only">
        {liveAnnouncement}
      </div>
      {/* Progressive loading badge — visible while later pages are decrypting */}
      {showProgressBadge && (
        <div
          data-testid="vault-loading-progress"
          className="mb-2 flex items-center gap-2 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--muted))] px-3 py-2 text-sm text-[hsl(var(--muted-foreground))]"
        >
          <Loader2 className="h-4 w-4 animate-spin" />
          <span>{progressLabel}</span>
        </div>
      )}
      {/* Selection bar */}
      {multiSelectMode && (
        <div className="mb-3 flex items-center gap-3 rounded-lg border border-[hsl(var(--primary)/0.3)] bg-[hsl(var(--primary)/0.05)] p-3">
          {/* Select All checkbox */}
          <label className="shrink-0 relative flex items-center cursor-pointer">
            <input
              type="checkbox"
              checked={selectedItems.size === filteredItems.length}
              onChange={() => {
                if (selectedItems.size === filteredItems.length) {
                  setSelectedItems(new Set());
                } else {
                  setSelectedItems(new Set(filteredItems.map((i) => i.id)));
                }
              }}
              className="peer sr-only"
              aria-label={
                selectedItems.size === filteredItems.length ? 'Deselect all' : 'Select all'
              }
            />
            <span className="text-[hsl(var(--primary))]">
              {selectedItems.size === filteredItems.length ? (
                <CheckSquare className="h-5 w-5" />
              ) : (
                <Square className="h-5 w-5" />
              )}
            </span>
          </label>
          <span className="text-sm font-medium text-[hsl(var(--foreground))]">
            {selectedItems.size} selected
          </span>
          <button
            type="button"
            onClick={() => setSelectedItems(new Set())}
            className="text-sm text-[hsl(var(--primary))] hover:underline"
          >
            Clear
          </button>

          <div className="ml-auto flex items-center gap-2">
            {bulkLoading && (
              <Loader2 className="h-4 w-4 animate-spin text-[hsl(var(--muted-foreground))]" />
            )}
            {/* Bulk Delete */}
            <button
              type="button"
              disabled={bulkLoading}
              onClick={() => setShowBulkDeleteConfirm(true)}
              className="inline-flex items-center gap-1.5 rounded-md border border-[hsl(var(--destructive)/0.3)] px-3 py-1.5 text-sm font-medium text-[hsl(var(--destructive))] hover:bg-[hsl(var(--destructive)/0.1)] transition-colors disabled:opacity-50"
            >
              <Trash2 className="h-4 w-4" />
              {showTrash ? 'Delete Forever' : 'Delete'}
            </button>
            {/* Bulk Move - hidden in trash view */}
            {!showTrash && (
              <div
                className="relative"
                onBlur={(e) => {
                  if (!e.currentTarget.contains(e.relatedTarget)) setShowMoveMenu(false);
                }}
              >
                <button
                  type="button"
                  disabled={bulkLoading}
                  onClick={() => setShowMoveMenu((p) => !p)}
                  aria-haspopup="true"
                  aria-expanded={showMoveMenu}
                  className="inline-flex items-center gap-1.5 rounded-md border border-[hsl(var(--input))] px-3 py-1.5 text-sm font-medium text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors disabled:opacity-50"
                >
                  <FolderOpen className="h-4 w-4" />
                  Move
                </button>
                {showMoveMenu && (
                  <div
                    className="absolute right-0 top-full z-20 mt-1 w-48 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--popover))] p-1 shadow-lg"
                    role="menu"
                    aria-label="Move to folder"
                  >
                    <button
                      type="button"
                      role="menuitem"
                      onClick={() => {
                        void (async () => {
                          setBulkLoading(true);
                          setShowMoveMenu(false);
                          try {
                            await bulkMoveApi([...selectedItems], null);
                            toast({ title: 'Items moved', type: 'success' });
                            setSelectedItems(new Set());
                            void fetchItems();
                          } catch {
                            toast({ title: 'Failed to move items', type: 'error' });
                          } finally {
                            setBulkLoading(false);
                          }
                        })();
                      }}
                      className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-sm text-[hsl(var(--popover-foreground))] hover:bg-[hsl(var(--accent))]"
                    >
                      No folder
                    </button>
                    {folders.map((folder) => (
                      <button
                        key={folder.id}
                        type="button"
                        role="menuitem"
                        onClick={() => {
                          void (async () => {
                            setBulkLoading(true);
                            setShowMoveMenu(false);
                            try {
                              await bulkMoveApi([...selectedItems], folder.id);
                              toast({ title: `Items moved to ${folder.name}`, type: 'success' });
                              setSelectedItems(new Set());
                              void fetchItems();
                            } catch {
                              toast({ title: 'Failed to move items', type: 'error' });
                            } finally {
                              setBulkLoading(false);
                            }
                          })();
                        }}
                        className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-sm text-[hsl(var(--popover-foreground))] hover:bg-[hsl(var(--accent))]"
                      >
                        {folder.name}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            )}
            {/* Bulk Tag */}
            {!showTrash && (
              <div
                className="relative"
                onBlur={(e) => {
                  if (!e.currentTarget.contains(e.relatedTarget)) setShowTagMenu(false);
                }}
              >
                <button
                  type="button"
                  disabled={bulkLoading}
                  onClick={() => setShowTagMenu((p) => !p)}
                  aria-haspopup="true"
                  aria-expanded={showTagMenu}
                  className="inline-flex items-center gap-1.5 rounded-md border border-[hsl(var(--input))] px-3 py-1.5 text-sm font-medium text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors disabled:opacity-50"
                >
                  <Tag className="h-4 w-4" />
                  Tag
                </button>
                {showTagMenu && (
                  <div className="absolute right-0 top-full z-20 mt-1 w-64 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--popover))] p-3 shadow-lg">
                    <div className="space-y-2">
                      <input
                        type="text"
                        value={bulkTagInput}
                        onChange={(e) => setBulkTagInput(e.target.value)}
                        placeholder="Enter tag name"
                        maxLength={50}
                        className="w-full rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] px-2 py-1.5 text-sm text-[hsl(var(--foreground))] placeholder:text-[hsl(var(--muted-foreground))] focus:outline-none focus:ring-1 focus:ring-[hsl(var(--ring))]"
                      />
                      <button
                        type="button"
                        disabled={!bulkTagInput.trim() || bulkLoading}
                        onClick={() => {
                          void (async () => {
                            const tag = bulkTagInput.trim();
                            if (!tag) return;
                            setBulkLoading(true);
                            setShowTagMenu(false);
                            try {
                              const sourceItems = items;
                              await Promise.all(
                                [...selectedItems].map((id) => {
                                  const item = sourceItems.find((i) => i.id === id);
                                  if (!item) return Promise.resolve();
                                  const newTags = item.tags.includes(tag)
                                    ? item.tags
                                    : [...item.tags, tag];
                                  // Tags are metadata: updateItemMeta sends them
                                  // alone and re-encrypts nothing. updateItem()
                                  // would encrypt JSON.stringify(item.data) over
                                  // the item's real ciphertext — and for an item
                                  // that failed to decode, item.data is only a
                                  // placeholder wrapper, so this bulk action
                                  // could destroy every selected broken item at
                                  // once.
                                  return useVaultStore
                                    .getState()
                                    .updateItemMeta(id, { tags: newTags });
                                }),
                              );
                              toast({
                                title: `Tag "${tag}" applied to ${selectedItems.size} items`,
                                type: 'success',
                              });
                              setSelectedItems(new Set());
                              setBulkTagInput('');
                            } catch {
                              toast({ title: 'Failed to apply tags', type: 'error' });
                            } finally {
                              setBulkLoading(false);
                            }
                          })();
                        }}
                        className="w-full rounded-md bg-[hsl(var(--primary))] px-3 py-1.5 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 disabled:opacity-50"
                      >
                        Apply
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Sort controls */}
      <div className="mb-3 flex items-center justify-end gap-2">
        <div
          className="relative"
          onBlur={(e) => {
            if (!e.currentTarget.contains(e.relatedTarget)) setShowSortMenu(false);
          }}
        >
          <button
            type="button"
            onClick={() => setShowSortMenu((p) => !p)}
            aria-haspopup="true"
            aria-expanded={showSortMenu}
            className="inline-flex items-center gap-1.5 rounded-md border border-[hsl(var(--input))] px-3 py-1.5 text-sm font-medium text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors"
          >
            <ArrowUpDown className="h-4 w-4" />
            {SORT_OPTIONS.find((o) => o.value === sortBy)?.label ?? 'Sort'}
          </button>
          {showSortMenu && (
            <div
              className="absolute right-0 top-full z-20 mt-1 w-44 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--popover))] p-1 shadow-lg"
              role="menu"
              aria-label="Sort options"
            >
              {SORT_OPTIONS.map((option) => (
                <button
                  key={option.value}
                  type="button"
                  role="menuitem"
                  onClick={() => {
                    setSortBy(option.value);
                    setShowSortMenu(false);
                  }}
                  className={cn(
                    'flex w-full items-center gap-2 rounded px-2 py-1.5 text-sm hover:bg-[hsl(var(--accent))]',
                    sortBy === option.value
                      ? 'font-medium text-[hsl(var(--primary))]'
                      : 'text-[hsl(var(--popover-foreground))]',
                  )}
                >
                  {option.label}
                </button>
              ))}
            </div>
          )}
        </div>
        <button
          type="button"
          onClick={() => setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')}
          className="inline-flex items-center gap-1 rounded-md border border-[hsl(var(--input))] px-2 py-1.5 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors"
          aria-label={sortOrder === 'asc' ? 'Sort descending' : 'Sort ascending'}
        >
          {sortOrder === 'asc' ? (
            <ArrowUp className="h-4 w-4" />
          ) : (
            <ArrowDown className="h-4 w-4" />
          )}
        </button>
      </div>

      {useVirtualization ? (
        <List<RowData>
          id={VAULT_SEARCH_RESULTS_ID}
          aria-label="Vault items list"
          style={{ height: 'calc(100vh - 220px)', minHeight: 300, maxHeight: 800 }}
          rowComponent={VirtualizedRow}
          rowCount={filteredItems.length}
          rowHeight={ITEM_HEIGHT + 8}
          rowProps={rowData}
          overscanCount={5}
          role="list"
        />
      ) : (
        <div
          id={VAULT_SEARCH_RESULTS_ID}
          className="space-y-2"
          role="list"
          aria-label="Vault items list"
        >
          {filteredItems.map((item, index) => (
            <div
              key={item.id}
              role="listitem"
              aria-setsize={filteredItems.length}
              aria-posinset={index + 1}
            >
              <VaultListItem
                item={item}
                isSelected={selectedItems.has(item.id)}
                onToggleSelect={toggleSelect}
                multiSelectMode={multiSelectMode}
              />
            </div>
          ))}
        </div>
      )}

      {/* Trash action bar */}
      {showTrash && filteredItems.length > 0 && (
        <div className="mt-4 flex justify-center">
          <button
            type="button"
            onClick={() => setShowEmptyTrashConfirm(true)}
            disabled={emptyingTrash}
            className="inline-flex items-center gap-2 rounded-md border border-[hsl(var(--destructive)/0.3)] px-4 py-2 text-sm font-medium text-[hsl(var(--destructive))] hover:bg-[hsl(var(--destructive)/0.1)] transition-colors disabled:opacity-50"
          >
            <Trash2 className="h-4 w-4" />
            {emptyingTrash ? 'Emptying...' : 'Empty Trash'}
          </button>
        </div>
      )}

      {/* Empty trash confirmation dialog */}
      {showEmptyTrashConfirm && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
          onClick={(e) => {
            if (e.target === e.currentTarget) closeEmptyTrashDialog();
          }}
        >
          <div
            ref={emptyTrashDialogRef}
            className="w-full max-w-sm rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-6 shadow-lg"
            role="alertdialog"
            aria-modal="true"
            aria-label="Empty trash confirmation"
          >
            <h3 className="text-lg font-semibold text-[hsl(var(--destructive))]">Empty Trash</h3>
            <p className="mt-2 text-sm text-[hsl(var(--muted-foreground))]">
              This will <strong>permanently delete all {filteredItems.length} items</strong> in the
              trash. This action cannot be undone.
            </p>
            <div className="mt-4 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setShowEmptyTrashConfirm(false)}
                className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => {
                  void (async () => {
                    setEmptyingTrash(true);
                    try {
                      await emptyTrash();
                      toast({ title: 'Trash emptied', type: 'success' });
                      setShowEmptyTrashConfirm(false);
                    } catch {
                      toast({ title: 'Failed to empty trash', type: 'error' });
                    } finally {
                      setEmptyingTrash(false);
                    }
                  })();
                }}
                disabled={emptyingTrash}
                className="inline-flex items-center gap-2 rounded-md bg-[hsl(var(--destructive))] px-3 py-2 text-sm font-medium text-[hsl(var(--destructive-foreground))] hover:opacity-90 transition-opacity disabled:opacity-50"
              >
                {emptyingTrash && <Loader2 className="h-4 w-4 animate-spin" />}
                Delete All Forever
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Bulk delete confirmation dialog */}
      {showBulkDeleteConfirm && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
          onClick={(e) => {
            if (e.target === e.currentTarget) closeBulkDeleteDialog();
          }}
        >
          <div
            ref={bulkDeleteDialogRef}
            className="w-full max-w-sm rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-6 shadow-lg"
            role="alertdialog"
            aria-modal="true"
            aria-label="Bulk delete confirmation"
          >
            <h3 className="text-lg font-semibold text-[hsl(var(--destructive))]">
              {showTrash ? 'Permanently Delete Items' : 'Delete Items'}
            </h3>
            <p className="mt-2 text-sm text-[hsl(var(--muted-foreground))]">
              {showTrash ? (
                <>
                  This will <strong>permanently delete {selectedItems.size} item(s)</strong>. This
                  action cannot be undone.
                </>
              ) : (
                <>
                  This will move <strong>{selectedItems.size} item(s)</strong> to the trash.
                </>
              )}
            </p>
            <div className="mt-4 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setShowBulkDeleteConfirm(false)}
                disabled={bulkLoading}
                className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => {
                  void (async () => {
                    setBulkLoading(true);
                    try {
                      if (showTrash) {
                        await Promise.all([...selectedItems].map((id) => permanentDeleteApi(id)));
                        toast({
                          title: `${selectedItems.size} items permanently deleted`,
                          type: 'success',
                        });
                        setSelectedItems(new Set());
                        void fetchTrashItems();
                      } else {
                        await bulkDeleteApi([...selectedItems]);
                        toast({ title: `${selectedItems.size} items deleted`, type: 'success' });
                        setSelectedItems(new Set());
                        void fetchItems();
                      }
                    } catch {
                      toast({ title: 'Failed to delete items', type: 'error' });
                    } finally {
                      setBulkLoading(false);
                      setShowBulkDeleteConfirm(false);
                    }
                  })();
                }}
                disabled={bulkLoading}
                className="inline-flex items-center gap-2 rounded-md bg-[hsl(var(--destructive))] px-3 py-2 text-sm font-medium text-[hsl(var(--destructive-foreground))] hover:opacity-90 transition-opacity disabled:opacity-50"
              >
                {bulkLoading && <Loader2 className="h-4 w-4 animate-spin" />}
                {showTrash ? 'Delete Forever' : 'Delete'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Floating action button - hidden in trash view */}
      {!showTrash && (
        <button
          type="button"
          onClick={onCreateNew}
          className="fixed bottom-20 right-6 z-30 flex h-14 w-14 items-center justify-center rounded-full bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))] shadow-lg hover:opacity-90 transition-opacity focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))] focus:ring-offset-2 sm:bottom-6"
          aria-label="Create new item"
        >
          <Plus className="h-6 w-6" />
        </button>
      )}
    </div>
  );
}
