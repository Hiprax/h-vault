import { useCallback, useMemo, useState, useRef, useEffect } from 'react';
import {
  Folder,
  FolderPlus,
  Star,
  Trash2,
  Key,
  FileText,
  CreditCard,
  User,
  Lock,
  ChevronRight,
  Inbox,
  Pencil,
  Palette,
  GripVertical,
  Loader2,
} from 'lucide-react';
import { cn } from '../../lib/utils';
import { useVaultStore, type DecryptedFolder } from '../../stores/vaultStore';
import { reorderFolderApi } from '../../services/api/vaultApi';
import { useToast } from '../ui/Toast';
import { useInlineDialog } from '../ui/Dialog';
import type { ItemType } from '@hvault/shared';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface FolderTreeNode extends DecryptedFolder {
  children: FolderTreeNode[];
}

interface ContextMenuState {
  folderId: string;
  x: number;
  y: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const TYPE_FILTERS: { type: ItemType; label: string; icon: typeof Key }[] = [
  { type: 'login', label: 'Logins', icon: Key },
  { type: 'secret', label: 'Secrets', icon: Lock },
  { type: 'note', label: 'Notes', icon: FileText },
  { type: 'card', label: 'Cards', icon: CreditCard },
  { type: 'identity', label: 'Identities', icon: User },
];

const FOLDER_COLORS = [
  '#3b82f6',
  '#ef4444',
  '#22c55e',
  '#f59e0b',
  '#8b5cf6',
  '#ec4899',
  '#06b6d4',
  '#f97316',
];

// ---------------------------------------------------------------------------
// Helper: build tree
// ---------------------------------------------------------------------------

function buildTree(folders: DecryptedFolder[]): FolderTreeNode[] {
  const map = new Map<string, FolderTreeNode>();
  const roots: FolderTreeNode[] = [];

  for (const f of folders) {
    map.set(f.id, { ...f, children: [] });
  }

  for (const f of folders) {
    const node = map.get(f.id);
    if (!node) continue;
    if (f.parentId && map.has(f.parentId)) {
      map.get(f.parentId)?.children.push(node);
    } else {
      roots.push(node);
    }
  }

  return roots.sort((a, b) => a.sortOrder - b.sortOrder);
}

// ---------------------------------------------------------------------------
// Folder tree item component
// ---------------------------------------------------------------------------

interface FolderTreeItemProps {
  node: FolderTreeNode;
  depth: number;
  selectedFolder: string | null;
  onSelect: (id: string) => void;
  onContextMenu: (e: React.MouseEvent, id: string) => void;
  itemCounts: Map<string, number>;
  onDragStart: (e: React.DragEvent, id: string) => void;
  onDragOver: (e: React.DragEvent, id: string) => void;
  onDrop: (e: React.DragEvent, id: string) => void;
  dragOverId: string | null;
  onKeyboardReorder: (id: string, direction: 'up' | 'down') => void;
}

function FolderTreeItem({
  node,
  depth,
  selectedFolder,
  onSelect,
  onContextMenu,
  itemCounts,
  onDragStart,
  onDragOver,
  onDrop,
  dragOverId,
  onKeyboardReorder,
}: FolderTreeItemProps) {
  const [expanded, setExpanded] = useState(true);
  const hasChildren = node.children.length > 0;
  const isActive = selectedFolder === node.id;
  const isDragOver = dragOverId === node.id;
  const count = itemCounts.get(node.id) ?? 0;

  return (
    <div>
      <button
        type="button"
        onClick={() => onSelect(node.id)}
        onContextMenu={(e) => onContextMenu(e, node.id)}
        onKeyDown={(e) => {
          if ((e.ctrlKey || e.metaKey) && e.key === 'ArrowUp') {
            e.preventDefault();
            onKeyboardReorder(node.id, 'up');
          } else if ((e.ctrlKey || e.metaKey) && e.key === 'ArrowDown') {
            e.preventDefault();
            onKeyboardReorder(node.id, 'down');
          }
        }}
        draggable
        onDragStart={(e) => onDragStart(e, node.id)}
        onDragOver={(e) => onDragOver(e, node.id)}
        onDrop={(e) => onDrop(e, node.id)}
        className={cn(
          'group flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-sm transition-colors',
          isActive
            ? 'bg-[hsl(var(--accent))] text-[hsl(var(--accent-foreground))]'
            : 'text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]',
          isDragOver && 'ring-2 ring-[hsl(var(--primary))] bg-[hsl(var(--primary)/0.1)]',
        )}
        style={{
          paddingLeft: `${depth * 16 + 8}px`,
          ...(node.color ? { borderLeft: `3px solid ${node.color}` } : {}),
        }}
        aria-current={isActive ? 'page' : undefined}
        aria-description="Use Ctrl+Up or Ctrl+Down to reorder"
      >
        {/* Drag handle */}
        <GripVertical className="h-3 w-3 shrink-0 opacity-0 group-hover:opacity-40 transition-opacity cursor-grab" />

        {/* Expand/collapse */}
        {hasChildren ? (
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              setExpanded((prev) => !prev);
            }}
            className="shrink-0 rounded p-0.5 hover:bg-[hsl(var(--muted))]"
            aria-label={expanded ? 'Collapse folder' : 'Expand folder'}
          >
            <ChevronRight className={cn('h-3 w-3 transition-transform', expanded && 'rotate-90')} />
          </button>
        ) : (
          <span className="w-4 shrink-0" />
        )}

        <Folder
          className="h-4 w-4 shrink-0"
          style={node.color ? { color: node.color } : undefined}
        />
        <span className="flex-1 truncate text-left">{node.name}</span>
        {count > 0 && (
          <span className="shrink-0 rounded-full bg-[hsl(var(--muted))] px-1.5 py-0.5 text-xs text-[hsl(var(--muted-foreground))]">
            {count}
          </span>
        )}
      </button>

      {hasChildren && expanded && (
        <div>
          {node.children
            .sort((a, b) => a.sortOrder - b.sortOrder)
            .map((child) => (
              <FolderTreeItem
                key={child.id}
                node={child}
                depth={depth + 1}
                selectedFolder={selectedFolder}
                onSelect={onSelect}
                onContextMenu={onContextMenu}
                itemCounts={itemCounts}
                onDragStart={onDragStart}
                onDragOver={onDragOver}
                onDrop={onDrop}
                dragOverId={dragOverId}
                onKeyboardReorder={onKeyboardReorder}
              />
            ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main sidebar component
// ---------------------------------------------------------------------------

interface FolderSidebarProps {
  className?: string;
  onClose?: () => void;
}

export function FolderSidebar({ className, onClose }: FolderSidebarProps) {
  const folders = useVaultStore((s) => s.folders);
  const items = useVaultStore((s) => s.items);
  const trashItems = useVaultStore((s) => s.trashItems);
  const selectedFolder = useVaultStore((s) => s.selectedFolder);
  const selectedType = useVaultStore((s) => s.selectedType);
  const showFavorites = useVaultStore((s) => s.showFavorites);
  const showTrash = useVaultStore((s) => s.showTrash);
  const setSelectedFolder = useVaultStore((s) => s.setSelectedFolder);
  const setSelectedType = useVaultStore((s) => s.setSelectedType);
  const toggleFavorites = useVaultStore((s) => s.toggleFavorites);
  const toggleTrash = useVaultStore((s) => s.toggleTrash);
  const createFolder = useVaultStore((s) => s.createFolder);
  const updateFolder = useVaultStore((s) => s.updateFolder);
  const deleteFolder = useVaultStore((s) => s.deleteFolder);
  const { toast } = useToast();

  const [contextMenu, setContextMenu] = useState<ContextMenuState | null>(null);
  const [showNewFolderDialog, setShowNewFolderDialog] = useState(false);
  const [newFolderName, setNewFolderName] = useState('');
  const [renamingFolder, setRenamingFolder] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState('');
  const [creatingFolder, setCreatingFolder] = useState(false);
  const [savingRename, setSavingRename] = useState(false);
  const [deletingFolderId, setDeletingFolderId] = useState<string | null>(null);
  const [deletingFolder, setDeletingFolder] = useState(false);
  const [deleteFolderAction, setDeleteFolderAction] = useState<'move' | 'delete'>('move');
  const contextMenuRef = useRef<HTMLDivElement>(null);

  const newFolderDialogRef = useRef<HTMLDivElement>(null);
  const closeNewFolderDialog = useCallback(() => {
    setShowNewFolderDialog(false);
    setNewFolderName('');
  }, []);
  useInlineDialog(newFolderDialogRef, showNewFolderDialog, closeNewFolderDialog);

  const renameDialogRef = useRef<HTMLDivElement>(null);
  const closeRenameDialog = useCallback(() => {
    setRenamingFolder(null);
    setRenameValue('');
  }, []);
  useInlineDialog(renameDialogRef, renamingFolder !== null, closeRenameDialog);

  const deleteFolderDialogRef = useRef<HTMLDivElement>(null);
  const closeDeleteFolderDialog = useCallback(() => setDeletingFolderId(null), []);
  useInlineDialog(deleteFolderDialogRef, deletingFolderId !== null, closeDeleteFolderDialog);

  // Build folder tree
  const tree = useMemo(() => buildTree(folders), [folders]);

  // Count items per folder (items no longer contain trash items)
  const itemCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const item of items) {
      if (item.folderId) {
        counts.set(item.folderId, (counts.get(item.folderId) ?? 0) + 1);
      }
    }
    return counts;
  }, [items]);

  // Count items per type
  const typeCounts = useMemo(() => {
    const counts = new Map<ItemType, number>();
    for (const item of items) {
      counts.set(item.itemType, (counts.get(item.itemType) ?? 0) + 1);
    }
    return counts;
  }, [items]);

  const favoriteCount = useMemo(() => items.filter((i) => i.favorite).length, [items]);

  const trashCount = useMemo(() => trashItems.length, [trashItems]);

  const allItemCount = useMemo(() => items.length, [items]);

  // Close context menu on outside click
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (contextMenuRef.current && !contextMenuRef.current.contains(e.target as Node)) {
        setContextMenu(null);
      }
    }
    if (contextMenu) {
      document.addEventListener('mousedown', handleClick);
      return () => document.removeEventListener('mousedown', handleClick);
    }
    return undefined;
  }, [contextMenu]);

  // Auto-focus first menu item when context menu opens
  useEffect(() => {
    if (contextMenu && contextMenuRef.current) {
      const firstItem = contextMenuRef.current.querySelector<HTMLElement>('[role="menuitem"]');
      firstItem?.focus();
    }
  }, [contextMenu]);

  const setShowFavorites = useVaultStore((s) => s.setShowFavorites);
  const setShowTrash = useVaultStore((s) => s.setShowTrash);

  const handleSelectAllItems = useCallback(() => {
    setSelectedFolder(null);
    setSelectedType(null);
    setShowFavorites(false);
    setShowTrash(false);
    onClose?.();
  }, [setSelectedFolder, setSelectedType, setShowFavorites, setShowTrash, onClose]);

  const handleSelectFolder = useCallback(
    (id: string) => {
      setSelectedFolder(id);
      setSelectedType(null);
      onClose?.();
    },
    [setSelectedFolder, setSelectedType, onClose],
  );

  const handleSelectType = useCallback(
    (type: ItemType) => {
      setSelectedType(selectedType === type ? null : type);
      setSelectedFolder(null);
      setShowFavorites(false);
      setShowTrash(false);
      onClose?.();
    },
    [setSelectedType, setSelectedFolder, setShowFavorites, setShowTrash, selectedType, onClose],
  );

  const handleToggleFavorites = useCallback(() => {
    toggleFavorites();
    setSelectedType(null);
    onClose?.();
  }, [toggleFavorites, setSelectedType, onClose]);

  const handleToggleTrash = useCallback(() => {
    toggleTrash();
    setSelectedType(null);
    onClose?.();
  }, [toggleTrash, setSelectedType, onClose]);

  const handleContextMenu = useCallback((e: React.MouseEvent, folderId: string) => {
    e.preventDefault();
    setContextMenu({ folderId, x: e.clientX, y: e.clientY });
  }, []);

  const handleCreateFolder = useCallback(async () => {
    const name = newFolderName.trim();
    if (!name) return;
    if (folders.some((f) => f.name.toLowerCase() === name.toLowerCase())) {
      toast({ title: 'A folder with this name already exists', type: 'error' });
      return;
    }
    setCreatingFolder(true);
    try {
      await createFolder(name);
      setNewFolderName('');
      setShowNewFolderDialog(false);
      toast({ title: 'Folder created', type: 'success' });
    } catch {
      toast({ title: 'Failed to create folder', type: 'error' });
    } finally {
      setCreatingFolder(false);
    }
  }, [newFolderName, createFolder, folders, toast]);

  const handleRenameFolder = useCallback(async () => {
    if (!renamingFolder || !renameValue.trim()) return;
    const name = renameValue.trim();
    if (
      folders.some((f) => f.id !== renamingFolder && f.name.toLowerCase() === name.toLowerCase())
    ) {
      toast({ title: 'A folder with this name already exists', type: 'error' });
      return;
    }
    setSavingRename(true);
    try {
      await updateFolder(renamingFolder, name);
      setRenamingFolder(null);
      setRenameValue('');
      toast({ title: 'Folder renamed', type: 'success' });
    } catch {
      toast({ title: 'Failed to rename folder', type: 'error' });
    } finally {
      setSavingRename(false);
    }
  }, [renamingFolder, renameValue, updateFolder, folders, toast]);

  const handleRequestDeleteFolder = useCallback((id: string) => {
    setDeletingFolderId(id);
    setContextMenu(null);
  }, []);

  const handleConfirmDeleteFolder = useCallback(async () => {
    if (!deletingFolderId) return;
    setDeletingFolder(true);
    try {
      await deleteFolder(deletingFolderId, deleteFolderAction);
      if (selectedFolder === deletingFolderId) setSelectedFolder(null);
      toast({ title: 'Folder deleted', type: 'success' });
    } catch {
      toast({ title: 'Failed to delete folder', type: 'error' });
    } finally {
      setDeletingFolder(false);
      setDeletingFolderId(null);
      setDeleteFolderAction('move');
    }
  }, [
    deletingFolderId,
    deleteFolderAction,
    deleteFolder,
    selectedFolder,
    setSelectedFolder,
    toast,
  ]);

  // Drag and drop state
  const [dragOverId, setDragOverId] = useState<string | null>(null);
  const dragSourceIdRef = useRef<string | null>(null);

  const handleDragStart = useCallback((e: React.DragEvent, id: string) => {
    dragSourceIdRef.current = id;
    e.dataTransfer.effectAllowed = 'move';
  }, []);

  const handleDragOver = useCallback((e: React.DragEvent, id: string) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    if (dragSourceIdRef.current !== id) {
      setDragOverId(id);
    }
  }, []);

  const handleDrop = useCallback(
    async (e: React.DragEvent, targetId: string) => {
      e.preventDefault();
      setDragOverId(null);
      const sourceId = dragSourceIdRef.current;
      dragSourceIdRef.current = null;
      if (!sourceId || sourceId === targetId) return;

      const sourceFolder = folders.find((f) => f.id === sourceId);
      const targetFolder = folders.find((f) => f.id === targetId);
      if (!sourceFolder || !targetFolder) return;

      // Get sibling folders (same parent) sorted by current sortOrder
      const siblings = folders
        .filter((f) => f.parentId === sourceFolder.parentId)
        .sort((a, b) => a.sortOrder - b.sortOrder);

      // Determine drag direction to fix insertion index
      const sourceIdx = siblings.findIndex((f) => f.id === sourceId);
      const targetIdx = siblings.findIndex((f) => f.id === targetId);
      const isDraggingDown = sourceIdx < targetIdx;

      // Remove source from its current position
      const reordered = siblings.filter((f) => f.id !== sourceId);
      const newTargetIndex = reordered.findIndex((f) => f.id === targetId);
      if (newTargetIndex === -1) return;

      // Insert after target when dragging down, before target when dragging up
      const insertIndex = isDraggingDown ? newTargetIndex + 1 : newTargetIndex;
      reordered.splice(insertIndex, 0, sourceFolder);

      try {
        // Update sortOrder for all folders whose position changed
        const updates: Promise<unknown>[] = [];
        for (let i = 0; i < reordered.length; i++) {
          const folder = reordered[i];
          if (folder && folder.sortOrder !== i) {
            updates.push(reorderFolderApi(folder.id, i));
          }
        }
        await Promise.all(updates);
        await useVaultStore.getState().fetchFolders();
        toast({ title: 'Folder reordered', type: 'success' });
      } catch {
        toast({ title: 'Failed to reorder', type: 'error' });
      }
    },
    [folders, toast],
  );

  const handleDragEnd = useCallback(() => {
    setDragOverId(null);
    dragSourceIdRef.current = null;
  }, []);

  // Keyboard alternative for folder reordering (Ctrl+ArrowUp/Down)
  const handleKeyboardReorder = useCallback(
    async (folderId: string, direction: 'up' | 'down') => {
      const folder = folders.find((f) => f.id === folderId);
      if (!folder) return;

      // Get sibling folders (same parent) sorted by current sortOrder
      const siblings = folders
        .filter((f) => f.parentId === folder.parentId)
        .sort((a, b) => a.sortOrder - b.sortOrder);

      const currentIndex = siblings.findIndex((f) => f.id === folderId);
      if (currentIndex === -1) return;

      const swapIndex = direction === 'up' ? currentIndex - 1 : currentIndex + 1;
      if (swapIndex < 0 || swapIndex >= siblings.length) return;

      const swapFolder = siblings[swapIndex];
      if (!swapFolder) return;

      try {
        // Swap sortOrder values
        await Promise.all([
          reorderFolderApi(folderId, swapFolder.sortOrder),
          reorderFolderApi(swapFolder.id, folder.sortOrder),
        ]);
        await useVaultStore.getState().fetchFolders();
        toast({ title: 'Folder reordered', type: 'success' });
      } catch {
        toast({ title: 'Failed to reorder', type: 'error' });
      }
    },
    [folders, toast],
  );

  const handleChangeColor = useCallback(
    async (id: string, color: string) => {
      const folder = folders.find((f) => f.id === id);
      if (!folder) return;
      try {
        await updateFolder(id, folder.name, { color });
        toast({ title: 'Color updated', type: 'success' });
      } catch {
        toast({ title: 'Failed to update color', type: 'error' });
      }
      setContextMenu(null);
    },
    [folders, updateFolder, toast],
  );

  const isAllActive = !selectedFolder && !showFavorites && !showTrash && !selectedType;

  return (
    <div className={cn('flex flex-col h-full overflow-y-auto', className)}>
      {/* All Items */}
      <div className="space-y-1 p-3">
        <button
          type="button"
          onClick={handleSelectAllItems}
          className={cn(
            'flex w-full items-center gap-2 rounded-md px-3 py-2 text-sm transition-colors',
            isAllActive
              ? 'bg-[hsl(var(--accent))] text-[hsl(var(--accent-foreground))]'
              : 'text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]',
          )}
          aria-current={isAllActive ? 'page' : undefined}
        >
          <Inbox className="h-4 w-4" />
          <span className="flex-1 text-left">All Items</span>
          <span className="rounded-full bg-[hsl(var(--muted))] px-1.5 py-0.5 text-xs text-[hsl(var(--muted-foreground))]">
            {allItemCount}
          </span>
        </button>

        {/* Favorites */}
        <button
          type="button"
          onClick={handleToggleFavorites}
          className={cn(
            'flex w-full items-center gap-2 rounded-md px-3 py-2 text-sm transition-colors',
            showFavorites
              ? 'bg-[hsl(var(--accent))] text-[hsl(var(--accent-foreground))]'
              : 'text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]',
          )}
          aria-current={showFavorites ? 'page' : undefined}
        >
          <Star className="h-4 w-4" />
          <span className="flex-1 text-left">Favorites</span>
          {favoriteCount > 0 && (
            <span className="rounded-full bg-[hsl(var(--muted))] px-1.5 py-0.5 text-xs text-[hsl(var(--muted-foreground))]">
              {favoriteCount}
            </span>
          )}
        </button>

        {/* Trash */}
        <button
          type="button"
          onClick={handleToggleTrash}
          className={cn(
            'flex w-full items-center gap-2 rounded-md px-3 py-2 text-sm transition-colors',
            showTrash
              ? 'bg-[hsl(var(--accent))] text-[hsl(var(--accent-foreground))]'
              : 'text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]',
          )}
          aria-current={showTrash ? 'page' : undefined}
        >
          <Trash2 className="h-4 w-4" />
          <span className="flex-1 text-left">Trash</span>
          {trashCount > 0 && (
            <span className="rounded-full bg-[hsl(var(--muted))] px-1.5 py-0.5 text-xs text-[hsl(var(--muted-foreground))]">
              {trashCount}
            </span>
          )}
        </button>
      </div>

      {/* Divider */}
      <div className="mx-3 border-t border-[hsl(var(--border))]" />

      {/* Type filters */}
      <div className="space-y-1 p-3">
        <p className="px-3 text-xs font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
          Types
        </p>
        {TYPE_FILTERS.map(({ type, label, icon: Icon }) => {
          const isActive = selectedType === type;
          const count = typeCounts.get(type) ?? 0;
          return (
            <button
              key={type}
              type="button"
              onClick={() => handleSelectType(type)}
              className={cn(
                'flex w-full items-center gap-2 rounded-md px-3 py-1.5 text-sm transition-colors',
                isActive
                  ? 'bg-[hsl(var(--accent))] text-[hsl(var(--accent-foreground))]'
                  : 'text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]',
              )}
              aria-current={isActive ? 'page' : undefined}
            >
              <Icon className="h-4 w-4" />
              <span className="flex-1 text-left">{label}</span>
              {count > 0 && (
                <span className="rounded-full bg-[hsl(var(--muted))] px-1.5 py-0.5 text-xs text-[hsl(var(--muted-foreground))]">
                  {count}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Divider */}
      <div className="mx-3 border-t border-[hsl(var(--border))]" />

      {/* Folders */}
      <div className="flex-1 space-y-1 p-3" onDragEnd={handleDragEnd}>
        <div className="flex items-center justify-between px-3">
          <p className="text-xs font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
            Folders
          </p>
          <button
            type="button"
            onClick={() => setShowNewFolderDialog(true)}
            className="rounded p-1 text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors"
            aria-label="Create folder"
          >
            <FolderPlus className="h-4 w-4" />
          </button>
        </div>

        {tree.map((node) => (
          <FolderTreeItem
            key={node.id}
            node={node}
            depth={0}
            selectedFolder={selectedFolder}
            onSelect={handleSelectFolder}
            onContextMenu={handleContextMenu}
            itemCounts={itemCounts}
            onDragStart={handleDragStart}
            onDragOver={handleDragOver}
            onDrop={(e, id) => void handleDrop(e, id)}
            dragOverId={dragOverId}
            onKeyboardReorder={(id, dir) => void handleKeyboardReorder(id, dir)}
          />
        ))}

        {folders.length === 0 && (
          <p className="px-3 py-2 text-xs text-[hsl(var(--muted-foreground))]">No folders yet</p>
        )}
      </div>

      {/* New folder dialog */}
      {showNewFolderDialog && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
          onClick={(e) => {
            if (e.target === e.currentTarget) closeNewFolderDialog();
          }}
        >
          <div
            ref={newFolderDialogRef}
            className="w-full max-w-sm rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-6 shadow-lg"
            role="dialog"
            aria-modal="true"
            aria-label="Create new folder"
          >
            <h3 className="mb-4 text-lg font-semibold text-[hsl(var(--card-foreground))]">
              New Folder
            </h3>
            <input
              type="text"
              value={newFolderName}
              onChange={(e) => setNewFolderName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') void handleCreateFolder();
                if (e.key === 'Escape') setShowNewFolderDialog(false);
              }}
              placeholder="Folder name"
              maxLength={100}
              className="w-full rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] px-3 py-2 text-sm text-[hsl(var(--foreground))] placeholder:text-[hsl(var(--muted-foreground))] focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))]"
              autoFocus
            />
            <div className="mt-4 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => {
                  setShowNewFolderDialog(false);
                  setNewFolderName('');
                }}
                className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => void handleCreateFolder()}
                disabled={creatingFolder || !newFolderName.trim()}
                className="rounded-md bg-[hsl(var(--primary))] px-3 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 transition-opacity disabled:opacity-50"
              >
                {creatingFolder ? 'Creating...' : 'Create'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Rename dialog */}
      {renamingFolder && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
          onClick={(e) => {
            if (e.target === e.currentTarget) closeRenameDialog();
          }}
        >
          <div
            ref={renameDialogRef}
            className="w-full max-w-sm rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-6 shadow-lg"
            role="dialog"
            aria-modal="true"
            aria-label="Rename folder"
          >
            <h3 className="mb-4 text-lg font-semibold text-[hsl(var(--card-foreground))]">
              Rename Folder
            </h3>
            <input
              type="text"
              value={renameValue}
              onChange={(e) => setRenameValue(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') void handleRenameFolder();
                if (e.key === 'Escape') {
                  setRenamingFolder(null);
                  setRenameValue('');
                }
              }}
              placeholder="New name"
              maxLength={100}
              className="w-full rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] px-3 py-2 text-sm text-[hsl(var(--foreground))] placeholder:text-[hsl(var(--muted-foreground))] focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))]"
              autoFocus
            />
            <div className="mt-4 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => {
                  setRenamingFolder(null);
                  setRenameValue('');
                }}
                className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => void handleRenameFolder()}
                disabled={savingRename || !renameValue.trim()}
                className="rounded-md bg-[hsl(var(--primary))] px-3 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 transition-opacity disabled:opacity-50"
              >
                {savingRename ? 'Renaming...' : 'Rename'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete folder confirmation dialog */}
      {deletingFolderId && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
          onClick={(e) => {
            if (e.target === e.currentTarget) closeDeleteFolderDialog();
          }}
        >
          <div
            ref={deleteFolderDialogRef}
            className="w-full max-w-sm rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-6 shadow-lg"
            role="alertdialog"
            aria-modal="true"
            aria-label="Delete folder confirmation"
          >
            <h3 className="text-lg font-semibold text-[hsl(var(--destructive))]">Delete Folder</h3>
            <p className="mt-2 text-sm text-[hsl(var(--muted-foreground))]">
              Are you sure you want to delete the folder{' '}
              <strong>&quot;{folders.find((f) => f.id === deletingFolderId)?.name}&quot;</strong>?
            </p>
            <fieldset className="mt-3 space-y-2">
              <legend className="text-sm font-medium text-[hsl(var(--foreground))]">
                What should happen to items in this folder?
              </legend>
              <label className="flex items-center gap-2 cursor-pointer text-sm text-[hsl(var(--foreground))]">
                <input
                  type="radio"
                  name="deleteFolderAction"
                  value="move"
                  checked={deleteFolderAction === 'move'}
                  onChange={() => setDeleteFolderAction('move')}
                  className="accent-[hsl(var(--primary))]"
                />
                Move items to root (no folder)
              </label>
              <label className="flex items-center gap-2 cursor-pointer text-sm text-[hsl(var(--destructive))]">
                <input
                  type="radio"
                  name="deleteFolderAction"
                  value="delete"
                  checked={deleteFolderAction === 'delete'}
                  onChange={() => setDeleteFolderAction('delete')}
                  className="accent-[hsl(var(--destructive))]"
                />
                Delete items with the folder
              </label>
            </fieldset>
            <div className="mt-4 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setDeletingFolderId(null)}
                disabled={deletingFolder}
                className="rounded-md px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => void handleConfirmDeleteFolder()}
                disabled={deletingFolder}
                className="inline-flex items-center gap-2 rounded-md bg-[hsl(var(--destructive))] px-3 py-2 text-sm font-medium text-[hsl(var(--destructive-foreground))] hover:opacity-90 transition-opacity disabled:opacity-50"
              >
                {deletingFolder && <Loader2 className="h-4 w-4 animate-spin" />}
                Delete
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Context menu */}
      {contextMenu && (
        <div
          ref={contextMenuRef}
          className="fixed z-[60] min-w-[160px] rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--popover))] p-1 shadow-lg"
          style={{ left: contextMenu.x, top: contextMenu.y }}
          role="menu"
          onKeyDown={(e) => {
            const items =
              contextMenuRef.current?.querySelectorAll<HTMLElement>('[role="menuitem"]');
            if (!items?.length) return;
            const active = document.activeElement as HTMLElement;
            const currentIndex = Array.from(items).indexOf(active);

            if (e.key === 'ArrowDown') {
              e.preventDefault();
              const next = currentIndex < items.length - 1 ? currentIndex + 1 : 0;
              items[next]?.focus();
            } else if (e.key === 'ArrowUp') {
              e.preventDefault();
              const prev = currentIndex > 0 ? currentIndex - 1 : items.length - 1;
              items[prev]?.focus();
            } else if (e.key === 'Escape') {
              setContextMenu(null);
            }
          }}
        >
          <button
            type="button"
            role="menuitem"
            onClick={() => {
              const folder = folders.find((f) => f.id === contextMenu.folderId);
              if (folder) {
                setRenamingFolder(folder.id);
                setRenameValue(folder.name);
              }
              setContextMenu(null);
            }}
            className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-sm text-[hsl(var(--popover-foreground))] hover:bg-[hsl(var(--accent))] transition-colors"
          >
            <Pencil className="h-3.5 w-3.5" />
            Rename
          </button>

          {/* Color submenu */}
          <div className="px-2 py-1.5">
            <div className="flex items-center gap-1 text-sm text-[hsl(var(--popover-foreground))]">
              <Palette className="h-3.5 w-3.5 mr-1" />
              Color
            </div>
            <div className="mt-1 flex gap-1">
              {FOLDER_COLORS.map((color) => (
                <button
                  key={color}
                  type="button"
                  onClick={() => void handleChangeColor(contextMenu.folderId, color)}
                  className="h-5 w-5 rounded-full border border-[hsl(var(--border))] transition-transform hover:scale-110"
                  style={{ backgroundColor: color }}
                  aria-label={`Set folder color to ${color}`}
                />
              ))}
            </div>
          </div>

          <div className="my-1 border-t border-[hsl(var(--border))]" />

          <button
            type="button"
            role="menuitem"
            onClick={() => handleRequestDeleteFolder(contextMenu.folderId)}
            className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-sm text-[hsl(var(--destructive))] hover:bg-[hsl(var(--destructive)/0.1)] transition-colors"
          >
            <Trash2 className="h-3.5 w-3.5" />
            Delete
          </button>
        </div>
      )}
    </div>
  );
}
